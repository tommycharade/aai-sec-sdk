"""Independent probe boundary for the Regional dependency-fault workflow.

The witness-Region Lambda verifies live journal, templates, execution paths and
routing before mutation. Later phases directly invoke a code-owned canary in
the exact target handler role. Cognito remains unsupported and fails closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

try:
    import boto3
except ImportError:  # pragma: no cover - AWS Lambda provides boto3.
    boto3 = None

from scripts import regional_fault_preconditions as preconditions
from scripts.regional_fault_controller_lambda import (
    RegionalFaultControllerError,
    _parse_event,
)


class RegionalFaultProbeError(RuntimeError):
    """Report that real target-only probe evidence is unavailable."""


_FIELDS = {"schemaVersion", "phase", "manifest", "faultAuthority"}
_PHASES = {
    "preconditions",
    "dependency-unavailable",
    "execution-denied-no-bypass",
    "dependency-and-target-recovered",
}


def probe(event: object, *, now: int | None = None) -> dict[str, Any]:
    """Validate authority and return only independently observed AWS evidence."""
    if (
        not isinstance(event, dict)
        or set(event) != _FIELDS
        or event.get("schemaVersion") != 1
        or event.get("phase") not in _PHASES
    ):
        raise RegionalFaultProbeError("fault probe event schema is invalid")
    try:
        _, manifest, authority = _parse_event(
            {
                "schemaVersion": 1,
                "operation": "acquire",
                "manifest": event.get("manifest"),
                "faultAuthority": event.get("faultAuthority"),
            },
            now=now,
        )
    except RegionalFaultControllerError as error:
        raise RegionalFaultProbeError("fault probe authority is invalid") from error
    prefix = "PRIMARY" if authority.target_cell_role == "primary" else "RECOVERY"
    function_arn = os.environ.get(f"{prefix}_FAULT_TARGET_FUNCTION_ARN", "").strip()
    if not function_arn:
        raise RegionalFaultProbeError("target probe function authority is unavailable")
    if boto3 is None:
        raise RegionalFaultProbeError("AWS provider is unavailable")
    if event["phase"] == "preconditions":
        hosted_zone_id = os.environ.get("FAULT_ROUTE53_HOSTED_ZONE_ID", "").strip()

        def provider(service: str, region: str) -> Any:
            """Create a region-bound read-only client for live preconditions."""
            return boto3.client(service, region_name=region)

        try:
            return preconditions.verify(
                manifest,
                authority,
                target_function_arn=function_arn,
                hosted_zone_id=hosted_zone_id,
                client=provider,
                now=now if now is not None else int(time.time()),
            )
        except preconditions.RegionalFaultPreconditionError as error:
            raise RegionalFaultProbeError("live Regional preconditions failed") from error
    if authority.dependency == "cognito":
        raise RegionalFaultProbeError("Cognito has no safe target-role probe boundary")
    request = {
        "source": "aai.regional-fault-target-probe",
        "schemaVersion": 1,
        "phase": event["phase"],
        "faultId": authority.fault_id,
        "authoritySha256": authority.sha256(),
        "dependency": authority.dependency,
    }
    try:
        response = boto3.client("lambda", region_name=authority.target_region).invoke(
            FunctionName=function_arn,
            InvocationType="RequestResponse",
            Payload=json.dumps(request, sort_keys=True, separators=(",", ":")).encode(),
        )
        payload = response.get("Payload").read(16_385)
    except Exception as error:
        raise RegionalFaultProbeError("target provider probe invocation failed") from error
    if (
        response.get("StatusCode") != 200
        or response.get("FunctionError") is not None
        or len(payload) > 16_384
    ):
        raise RegionalFaultProbeError("target provider probe did not complete safely")
    try:
        observed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegionalFaultProbeError("target provider probe response is invalid") from error
    required = {
        "authoritySha256",
        "dependency",
        "faultId",
        "operationCount",
        "phase",
        "providerStatus",
        "evidenceSha256",
    }
    if isinstance(observed, dict) and observed.get("providerStatus") == "denied":
        required.add("errorCode")
    if not isinstance(observed, dict) or set(observed) != required:
        raise RegionalFaultProbeError("target provider probe evidence schema is invalid")
    digest_input = {key: value for key, value in observed.items() if key != "evidenceSha256"}
    expected_digest = hashlib.sha256(
        json.dumps(digest_input, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expected_status = (
        "available" if event["phase"] == "dependency-and-target-recovered" else "denied"
    )
    if (
        observed.get("authoritySha256") != authority.sha256()
        or observed.get("dependency") != authority.dependency
        or observed.get("faultId") != authority.fault_id
        or observed.get("phase") != event["phase"]
        or observed.get("providerStatus") != expected_status
        or observed.get("evidenceSha256") != expected_digest
        or isinstance(observed.get("operationCount"), bool)
        or not isinstance(observed.get("operationCount"), int)
        or not 0 <= observed["operationCount"] <= 4
        or (
            expected_status == "denied"
            and observed.get("errorCode") not in {"AccessDenied", "AccessDeniedException"}
        )
    ):
        raise RegionalFaultProbeError("target provider probe evidence differs from live authority")
    return {
        "schemaVersion": 1,
        "phase": event["phase"],
        "dependency": authority.dependency,
        "status": (
            "verified-target-provider-denied"
            if expected_status == "denied"
            else "verified-target-provider-recovered"
        ),
        "evidenceSha256": observed["evidenceSha256"],
    }


def handler(event: object, _context: object) -> dict[str, Any]:
    """Run one exact live precondition, denial or recovery probe phase."""
    return probe(event)

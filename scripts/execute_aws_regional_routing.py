#!/usr/bin/env python3
"""Verify and atomically move stable API/UI aliases under journal authority.

This component is deliberately narrower than the runtime transition executor.
It verifies Regional ingress and live runtime evidence, performs one exact
Route 53 change batch, and completes one journal generation. Compute activation
and restoration remain separate journal-governed commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import deploy_aws_active_cell as active  # noqa: E402
from scripts import deploy_aws_evidence_continuity as continuity  # noqa: E402
from scripts import deploy_aws_passive_cell as passive  # noqa: E402
from scripts import deploy_aws_regional_ingress as ingress  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import manage_aws_transition_journal as journal  # noqa: E402
from scripts import plan_aws_regional_activation as preflight  # noqa: E402
from scripts import verify_aws_regional_activation as activation  # noqa: E402


class RegionalRoutingError(RuntimeError):
    """Report routing state that cannot prove exact, exclusive authority."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
Clock = Callable[[], float]
Sleeper = Callable[[float], None]
HttpProbe = Callable[[str, str | None], dict[str, Any]]
RuntimeGuard = Callable[[], dict[str, Any]]
_STACK_STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
_CHANGE_ID = re.compile(r"^/change/[A-Z0-9]+$")
_ROLE_ARN = re.compile(
    r"^arn:(?P<partition>aws|aws-us-gov|aws-cn):iam::(?P<account>\d{12}):"
    r"role/(?:[A-Za-z0-9+=,.@_-]+/)*(?P<name>[A-Za-z0-9+=,.@_-]+)$"
)


@dataclass(frozen=True)
class AliasTarget:
    """One exact API Gateway Regional alias destination."""

    dns_name: str
    hosted_zone_id: str

    def record(self, name: str) -> dict[str, Any]:
        """Return the exact simple A-alias record used in Route 53 CAS."""
        return {
            "Name": f"{name}.",
            "Type": "A",
            "AliasTarget": {
                "DNSName": f"{self.dns_name.rstrip('.')}.",
                "EvaluateTargetHealth": False,
                "HostedZoneId": self.hosted_zone_id,
            },
        }


@dataclass(frozen=True)
class IngressCell:
    """Provider-verified stable and canary ingress for one Region."""

    role: str
    region: str
    stack_name: str
    stable_api: AliasTarget
    stable_ui: AliasTarget
    canary_api_domain: str
    canary_ui_domain: str
    evidence_sha256: str


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Call the shared bounded AWS CLI boundary and normalize failures."""
    try:
        return recovery._aws(arguments, profile=profile, region=region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise RegionalRoutingError(str(error)) from error


def require_routing_role(
    manifest: activation.ActivationManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Require an STS session for the exact schema-v3-or-v4 routing role."""
    manifest.require_routing_authority()
    role_arn = manifest.routing_role_arn
    if role_arn is None:
        raise RegionalRoutingError("routing role authority is unavailable")
    expected = _ROLE_ARN.fullmatch(role_arn)
    if expected is None:
        raise RegionalRoutingError("routing role authority is malformed")
    caller = _aws(
        ["sts", "get-caller-identity"],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    arn = caller.get("Arn")
    account = caller.get("Account")
    expected_caller = re.compile(
        rf"^arn:{re.escape(expected.group('partition'))}:sts::{expected.group('account')}:"
        rf"assumed-role/{re.escape(expected.group('name'))}/[A-Za-z0-9+=,.@_-]{{2,128}}$"
    )
    if (
        account != expected.group("account")
        or not isinstance(arn, str)
        or not expected_caller.fullmatch(arn)
    ):
        raise RegionalRoutingError("caller is not the dedicated routing role")
    return {"account": account, "callerArn": arn, "roleArn": role_arn}


def _stack(
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Return exact outputs and resources from one stable ingress stack."""
    response = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack_name],
        profile=profile,
        region=region,
        runner=runner,
    )
    stacks = response.get("Stacks")
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or not isinstance(stacks[0], dict)
        or stacks[0].get("StackStatus") not in _STACK_STABLE
    ):
        raise RegionalRoutingError("regional ingress stack is not stable")
    raw_outputs = stacks[0].get("Outputs")
    if not isinstance(raw_outputs, list) or len(raw_outputs) > 32:
        raise RegionalRoutingError("regional ingress outputs are malformed")
    outputs: dict[str, str] = {}
    for item in raw_outputs:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("OutputKey"), str)
            or not isinstance(item.get("OutputValue"), str)
            or item["OutputKey"] in outputs
        ):
            raise RegionalRoutingError("regional ingress output is malformed or duplicated")
        outputs[item["OutputKey"]] = item["OutputValue"]
    resources_response = _aws(
        ["cloudformation", "list-stack-resources", "--stack-name", stack_name],
        profile=profile,
        region=region,
        runner=runner,
    )
    resources = resources_response.get("StackResourceSummaries")
    if (
        not isinstance(resources, list)
        or len(resources) > 100
        or resources_response.get("NextToken") is not None
    ):
        raise RegionalRoutingError("regional ingress resources are malformed")
    return outputs, resources


def _domain(
    name: str,
    expected_target: AliasTarget,
    certificate_arn: str,
    *,
    profile: str,
    region: str,
    runner: Runner,
) -> None:
    """Require one available IPv4/TLS1.2/API-mapping-only Regional domain."""
    value = _aws(
        ["apigatewayv2", "get-domain-name", "--domain-name", name],
        profile=profile,
        region=region,
        runner=runner,
    )
    configurations = value.get("DomainNameConfigurations")
    required_configuration = {
        "ApiGatewayDomainName": expected_target.dns_name,
        "CertificateArn": certificate_arn,
        "DomainNameStatus": "AVAILABLE",
        "EndpointType": "REGIONAL",
        "HostedZoneId": expected_target.hosted_zone_id,
        "IpAddressType": "ipv4",
        "SecurityPolicy": "TLS_1_2",
    }
    # API Gateway adds provider-owned timestamps and optional status text. Those
    # fields do not grant authority; every authority-bearing field stays exact.
    allowed_configuration_fields = set(required_configuration) | {
        "CertificateUploadDate",
        "DomainNameStatusMessage",
        "OwnershipVerificationCertificateArn",
    }
    configuration = (
        configurations[0] if isinstance(configurations, list) and len(configurations) == 1 else None
    )
    if (
        value.get("DomainName") != name
        or value.get("RoutingMode", "API_MAPPING_ONLY") != "API_MAPPING_ONLY"
        or not isinstance(configuration, dict)
        or set(configuration) - allowed_configuration_fields
        or any(
            configuration.get(key) != expected for key, expected in required_configuration.items()
        )
    ):
        raise RegionalRoutingError("live custom-domain identity or TLS posture differs")


def _mappings(
    domain: str,
    expected_api_id: str,
    *,
    profile: str,
    region: str,
    runner: Runner,
) -> None:
    """Require one default-stage mapping to the exact provider-derived API."""
    value = _aws(
        ["apigatewayv2", "get-api-mappings", "--domain-name", domain],
        profile=profile,
        region=region,
        runner=runner,
    )
    items = value.get("Items")
    if (
        not isinstance(items, list)
        or value.get("NextToken") is not None
        or len(items) != 1
        or not isinstance(items[0], dict)
        or set(items[0]) - {"ApiId", "ApiMappingId", "ApiMappingKey", "Stage"}
        or items[0].get("ApiId") != expected_api_id
        or items[0].get("Stage") != "$default"
        or items[0].get("ApiMappingKey") not in {None, ""}
        or not isinstance(items[0].get("ApiMappingId"), str)
    ):
        raise RegionalRoutingError("live API mapping differs from reviewed authority")


def discover_ingress_cell(
    manifest: activation.ActivationManifest,
    *,
    role: str,
    profile: str,
    runner: Runner = subprocess.run,
) -> IngressCell:
    """Derive and verify one Region's complete live ingress contract."""
    manifest.require_routing_authority()
    if role == "primary":
        region = manifest.primary_region
        stack_name = manifest.primary_ingress_stack_name
        canary_api = manifest.primary_canary_api_domain
        canary_ui = manifest.primary_canary_ui_domain
    elif role == "recovery":
        region = manifest.recovery_region
        stack_name = manifest.recovery_ingress_stack_name
        canary_api = manifest.recovery_canary_api_domain
        canary_ui = manifest.recovery_canary_ui_domain
    else:
        raise RegionalRoutingError("ingress role must be primary or recovery")
    if not all(isinstance(value, str) for value in (stack_name, canary_api, canary_ui)):
        raise RegionalRoutingError("ingress authority is incomplete")
    parameter = _aws(
        [
            "ssm",
            "get-parameter",
            "--name",
            f"/aai-sec/{stack_name}/regional-ingress",
            "--with-decryption",
        ],
        profile=profile,
        region=region,
        runner=runner,
    ).get("Parameter")
    payload = parameter.get("Value") if isinstance(parameter, dict) else None
    if not isinstance(payload, str):
        raise RegionalRoutingError("persisted ingress authority is unavailable")
    try:
        authority = ingress.RegionalIngressManifest.parse(payload)
    except ingress.RegionalIngressDeploymentError as error:
        raise RegionalRoutingError(str(error)) from error
    if (
        authority.stack_name != stack_name
        or authority.cell_role != role
        or authority.region != region
        or authority.stable_api_domain != manifest.stable_api_domain
        or authority.stable_ui_domain != manifest.stable_ui_domain
        or authority.canary_api_domain != canary_api
        or authority.canary_ui_domain != canary_ui
    ):
        raise RegionalRoutingError("persisted ingress authority differs from transition")
    _account, control_api_id, _bucket = ingress.provider_identities(
        authority, profile=profile, runner=runner
    )
    outputs, resources = _stack(stack_name, profile=profile, region=region, runner=runner)
    if (
        outputs.get("RegionalIngressStatus") != "custom-domains-unrouted"
        or outputs.get("RegionalIngressCellRole") != role
    ):
        raise RegionalRoutingError("ingress stack claims unexpected routing authority")
    try:
        stable_api = AliasTarget(
            outputs["StableApiRegionalDomainName"],
            outputs["StableApiRegionalHostedZoneId"],
        )
        stable_ui = AliasTarget(
            outputs["StableUiRegionalDomainName"],
            outputs["StableUiRegionalHostedZoneId"],
        )
        canary_api_target = AliasTarget(
            outputs["CanaryApiRegionalDomainName"],
            outputs["CanaryApiRegionalHostedZoneId"],
        )
        canary_ui_target = AliasTarget(
            outputs["CanaryUiRegionalDomainName"],
            outputs["CanaryUiRegionalHostedZoneId"],
        )
    except KeyError as error:
        raise RegionalRoutingError("ingress alias outputs are incomplete") from error
    ui_apis = [
        item.get("PhysicalResourceId")
        for item in resources
        if isinstance(item, dict) and item.get("ResourceType") == "AWS::ApiGatewayV2::Api"
    ]
    if len(ui_apis) != 1 or not isinstance(ui_apis[0], str):
        raise RegionalRoutingError("regional UI API identity is ambiguous")
    ui_api_id = ui_apis[0]
    ui_api = _aws(
        ["apigatewayv2", "get-api", "--api-id", ui_api_id],
        profile=profile,
        region=region,
        runner=runner,
    )
    if (
        ui_api.get("ApiId") != ui_api_id
        or ui_api.get("ProtocolType") != "HTTP"
        or ui_api.get("DisableExecuteApiEndpoint") is not True
    ):
        raise RegionalRoutingError("regional UI raw endpoint is not disabled")
    for domain, target, api_id in (
        (manifest.stable_api_domain, stable_api, control_api_id),
        (canary_api, canary_api_target, control_api_id),
        (manifest.stable_ui_domain, stable_ui, ui_api_id),
        (canary_ui, canary_ui_target, ui_api_id),
    ):
        _domain(
            domain,
            target,
            authority.certificate_arn,
            profile=profile,
            region=region,
            runner=runner,
        )
        _mappings(domain, api_id, profile=profile, region=region, runner=runner)
    evidence = {
        "authoritySha256": hashlib.sha256(authority.canonical_json().encode()).hexdigest(),
        "canaryApiDomain": canary_api,
        "canaryApiTarget": canary_api_target.record(canary_api),
        "canaryUiDomain": canary_ui,
        "canaryUiTarget": canary_ui_target.record(canary_ui),
        "cellRole": role,
        "controlApiId": control_api_id,
        "region": region,
        "stackName": stack_name,
        "stableApi": stable_api.record(manifest.stable_api_domain),
        "stableUi": stable_ui.record(manifest.stable_ui_domain),
        "uiApiId": ui_api_id,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return IngressCell(
        role, region, stack_name, stable_api, stable_ui, canary_api, canary_ui, digest
    )


def _http_probe(url: str, token: str | None) -> dict[str, Any]:
    """Perform one bounded HTTPS GET without logging bearer material."""
    if not url.startswith("https://"):
        raise RegionalRoutingError("ingress probe requires HTTPS")
    headers = {"accept": "application/json, text/html;q=0.9"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, method="GET", headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            body = response.read(1_048_577)
            status = response.status
            response_headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        body = error.read(1_048_577)
        status = error.code
        response_headers = {key.lower(): value for key, value in error.headers.items()}
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise RegionalRoutingError("HTTPS ingress probe failed") from error
    if len(body) > 1_048_576:
        raise RegionalRoutingError("HTTPS ingress probe response exceeds 1 MiB")
    json_valid = False
    if "application/json" in response_headers.get("content-type", ""):
        try:
            json.loads(body, object_pairs_hook=activation._strict_object)
            json_valid = True
        except (
            UnicodeError,
            json.JSONDecodeError,
            activation.RegionalActivationVerificationError,
        ):
            json_valid = False
    return {
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "contentType": response_headers.get("content-type", ""),
        "jsonValid": json_valid,
        "status": status,
        "strictTransportSecurity": response_headers.get("strict-transport-security", ""),
    }


def smoke_ingress(
    api_domain: str,
    ui_domain: str,
    token: str,
    *,
    probe: HttpProbe = _http_probe,
) -> dict[str, Any]:
    """Prove JWT rejection/acceptance and secure UI delivery on one ingress pair."""
    if not isinstance(token, str) or not 32 <= len(token) <= 16_384 or token != token.strip():
        raise RegionalRoutingError("operator smoke token is missing or malformed")
    denied = probe(f"https://{api_domain}/configuration", "invalid-routing-smoke-token")
    allowed = probe(f"https://{api_domain}/configuration", token)
    ui = probe(f"https://{ui_domain}/", None)
    if denied.get("status") not in {401, 403}:
        raise RegionalRoutingError("canary API did not reject invalid authentication")
    if (
        allowed.get("status") != 200
        or "application/json" not in str(allowed.get("contentType", ""))
        or allowed.get("jsonValid") is not True
    ):
        raise RegionalRoutingError("authenticated canary API read failed")
    if (
        ui.get("status") != 200
        or "text/html" not in str(ui.get("contentType", ""))
        or ui.get("strictTransportSecurity") != "max-age=31536000; includeSubDomains"
    ):
        raise RegionalRoutingError("canary UI security delivery failed")
    return {"apiAllowed": allowed, "apiDenied": denied, "ui": ui}


def marker_record(
    manifest: activation.ActivationManifest,
    *,
    generation: int,
    active_region: str,
    transition_id: str,
) -> dict[str, Any]:
    """Return one bounded TXT generation witness mirrored into Route 53."""
    manifest.require_routing_authority()
    if manifest.routing_marker_name is None or not 0 <= generation <= 1_000_000_001:
        raise RegionalRoutingError("routing marker authority is invalid")
    transition = transition_id or "none"
    value = f'"aai-sec:v1:g={generation}:r={active_region}:t={transition}"'
    return {
        "Name": f"{manifest.routing_marker_name}.",
        "Type": "TXT",
        "TTL": 60,
        "ResourceRecords": [{"Value": value}],
    }


def read_route_state(
    manifest: activation.ActivationManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Read exact stable/marker record sets and reject parallel routing records."""
    manifest.require_routing_authority()
    if manifest.routing_marker_name is None:
        raise RegionalRoutingError("routing marker authority is unavailable")
    zone = _aws(
        ["route53", "get-hosted-zone", "--id", manifest.hosted_zone_id],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    ).get("HostedZone")
    zone_name = zone.get("Name") if isinstance(zone, dict) else None
    if (
        not isinstance(zone, dict)
        or zone.get("Id") not in {manifest.hosted_zone_id, f"/hostedzone/{manifest.hosted_zone_id}"}
        or zone.get("Config", {}).get("PrivateZone") is not False
        or not isinstance(zone_name, str)
        or any(
            not f"{name}.".endswith(zone_name)
            for name in (
                manifest.stable_api_domain,
                manifest.stable_ui_domain,
                manifest.routing_marker_name,
            )
        )
    ):
        raise RegionalRoutingError("Route 53 hosted-zone authority differs")
    records: list[dict[str, Any]] = []
    start: list[str] = []
    pages = 0
    while True:
        response = _aws(
            [
                "route53",
                "list-resource-record-sets",
                "--hosted-zone-id",
                manifest.hosted_zone_id,
                *start,
            ],
            profile=profile,
            region=manifest.primary_region,
            runner=runner,
        )
        page = response.get("ResourceRecordSets")
        if not isinstance(page, list) or len(page) > 300:
            raise RegionalRoutingError("Route 53 record inventory is malformed")
        records.extend(page)
        pages += 1
        if pages > 34 or len(records) > 10_000:
            raise RegionalRoutingError("Route 53 record inventory exceeds its bound")
        if response.get("IsTruncated") is not True:
            break
        next_name = response.get("NextRecordName")
        next_type = response.get("NextRecordType")
        if not isinstance(next_name, str) or not isinstance(next_type, str):
            raise RegionalRoutingError("Route 53 pagination authority is malformed")
        start = ["--start-record-name", next_name, "--start-record-type", next_type]
        identifier = response.get("NextRecordIdentifier")
        if identifier is not None:
            if not isinstance(identifier, str) or not identifier:
                raise RegionalRoutingError("Route 53 pagination identifier is malformed")
            start.extend(["--start-record-identifier", identifier])
    names = {
        f"{manifest.stable_api_domain}.",
        f"{manifest.stable_ui_domain}.",
        f"{manifest.routing_marker_name}.",
    }
    selected: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in records:
        if not isinstance(raw, dict) or raw.get("Name") not in names:
            continue
        record_type = raw.get("Type")
        if record_type not in {"A", "TXT"}:
            raise RegionalRoutingError("stable name has a parallel or unsupported record type")
        key = (raw["Name"], record_type)
        if key in selected:
            raise RegionalRoutingError("stable Route 53 record is duplicated")
        selected[key] = raw
    return selected


def canonical_records(records: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    """Return DNS evidence in deterministic JSON-safe order."""
    return [records[key] for key in sorted(records)]


def expected_route_state(
    manifest: activation.ActivationManifest,
    cell: IngressCell,
    *,
    generation: int,
    transition_id: str,
    marker_required: bool,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Return the only acceptable source or target Route 53 state."""
    records = [
        cell.stable_api.record(manifest.stable_api_domain),
        cell.stable_ui.record(manifest.stable_ui_domain),
    ]
    if marker_required:
        records.append(
            marker_record(
                manifest,
                generation=generation,
                active_region=cell.region,
                transition_id=transition_id,
            )
        )
    return {(record["Name"], record["Type"]): record for record in records}


def verify_target_ingress_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    target: IngressCell,
    token: str,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    probe: HttpProbe = _http_probe,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Journal and prove provider/live canary target ingress before routing."""
    require_routing_role(manifest, profile=profile, runner=runner)
    state = journal.read_state(witness, manifest)
    if state.phase == "TARGET_INGRESS_VERIFIED_NOT_ROUTED":
        claimed = {"claim": "already-completed", "journal": state.evidence()}
    else:
        claimed = journal.advance_phase(
            witness,
            manifest,
            expected_phase="TARGET_JOBS_RECONCILED_NOT_ROUTED",
            next_phase="VERIFYING_TARGET_INGRESS",
            now=int(clock()),
        )
    smoke = smoke_ingress(target.canary_api_domain, target.canary_ui_domain, token, probe=probe)
    evidence = {"ingressEvidenceSha256": target.evidence_sha256, "smoke": smoke}
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="VERIFYING_TARGET_INGRESS",
        next_phase="TARGET_INGRESS_VERIFIED_NOT_ROUTED",
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "journalClaim": claimed,
        "journal": completed["journal"],
        "stepEvidenceSha256": digest,
        "trafficRouted": False,
    }


def prove_pre_route_runtime(
    lambda_client: Any,
    manifest: activation.ActivationManifest,
    source_resources: active.SourceResources,
    target_resources: active.TargetResources,
    expected_environment: dict[str, str],
    *,
    profile: str,
    runner: Runner = subprocess.run,
    runtime_verifier: Callable[..., dict[str, Any]] = active.verify_target_runtime,
) -> dict[str, Any]:
    """Re-prove source fencing, target immutability, and zero pending jobs."""
    source_fence = active.verify_source_fence(
        source_resources,
        profile=profile,
        region=manifest.source_region,
        runner=runner,
    )
    runtime_before = runtime_verifier(
        target_resources,
        manifest,
        expected_environment,
        profile=profile,
        runner=runner,
    )
    reconciliation = active.invoke_target_reconciliation(
        lambda_client,
        target_resources.handler,
        manifest,
        mode="check",
    )
    if reconciliation.get("plannedActions") != 0:
        raise RegionalRoutingError("target has pending reconciliation actions before routing")
    runtime_after = runtime_verifier(
        target_resources,
        manifest,
        expected_environment,
        profile=profile,
        runner=runner,
    )
    if runtime_after != runtime_before:
        raise RegionalRoutingError("target runtime changed during the pre-route proof")
    evidence = {
        "reconciliation": reconciliation,
        "runtimeAfter": runtime_after,
        "runtimeBefore": runtime_before,
        "sourceFence": source_fence,
    }
    return {
        "evidence": evidence,
        "sha256": hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "status": "fresh-runtime-and-zero-action-proof",
    }


def route_target_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    source: IngressCell,
    target: IngressCell,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    clock: Clock = time.time,
    sleeper: Sleeper = time.sleep,
    attempts: int = 60,
    runtime_guard: RuntimeGuard | None = None,
) -> dict[str, Any]:
    """Move both aliases and generation marker in one exact Route 53 batch."""
    if isinstance(attempts, bool) or not 1 <= attempts <= 120:
        raise RegionalRoutingError("Route 53 wait attempts must be 1 through 120")
    if (
        source.region != manifest.source_region
        or target.region != manifest.target_region
        or source.region == target.region
        or source.stable_api == target.stable_api
        or source.stable_ui == target.stable_ui
    ):
        raise RegionalRoutingError("source and target ingress do not match transition direction")
    role = require_routing_role(manifest, profile=profile, runner=runner)
    state = journal.read_state(witness, manifest)
    if state.phase == "VERIFYING_STABLE_ROUTE":
        expected_generation = manifest.expected_routing_generation
        if expected_generation is None:
            raise RegionalRoutingError("routing generation authority is unavailable")
        target_state = expected_route_state(
            manifest,
            target,
            generation=expected_generation + 1,
            transition_id=manifest.transition_id,
            marker_required=True,
        )
        if read_route_state(manifest, profile=profile, runner=runner) != target_state:
            raise RegionalRoutingError("completed route journal disagrees with Route 53")
        return {
            "changeId": None,
            "journalClaim": {"claim": "already-completed", "journal": state.evidence()},
            "journal": state.evidence(),
            "records": canonical_records(target_state),
            "trafficRouted": True,
        }
    if runtime_guard is None:
        raise RegionalRoutingError("fresh pre-route runtime proof is required")
    runtime_proof = runtime_guard()
    if (
        not isinstance(runtime_proof, dict)
        or set(runtime_proof) != {"evidence", "sha256", "status"}
        or runtime_proof.get("status") != "fresh-runtime-and-zero-action-proof"
        or not isinstance(runtime_proof.get("evidence"), dict)
        or not isinstance(runtime_proof.get("sha256"), str)
        or hashlib.sha256(
            json.dumps(runtime_proof["evidence"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        != runtime_proof["sha256"]
    ):
        raise RegionalRoutingError("fresh pre-route runtime proof is malformed")
    claimed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="TARGET_INGRESS_VERIFIED_NOT_ROUTED",
        next_phase="ROUTING_TARGET",
        now=int(clock()),
    )
    state = journal.read_state(witness, manifest)
    marker_required = state.generation > 0
    source_state = expected_route_state(
        manifest,
        source,
        generation=state.generation,
        transition_id=state.last_completed_transition_id,
        marker_required=marker_required,
    )
    target_state = expected_route_state(
        manifest,
        target,
        generation=state.generation + 1,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    observed = read_route_state(manifest, profile=profile, runner=runner)
    change_id: str | None = None
    if observed == source_state:
        changes = [
            {"Action": "DELETE", "ResourceRecordSet": record} for record in source_state.values()
        ] + [{"Action": "CREATE", "ResourceRecordSet": record} for record in target_state.values()]
        response = _aws(
            [
                "route53",
                "change-resource-record-sets",
                "--hosted-zone-id",
                manifest.hosted_zone_id,
                "--change-batch",
                json.dumps(
                    {
                        "Changes": changes,
                        "Comment": f"AAI Security transition {manifest.transition_id}",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ],
            profile=profile,
            region=manifest.primary_region,
            runner=runner,
        )
        info = response.get("ChangeInfo")
        change_id = info.get("Id") if isinstance(info, dict) else None
        if (
            not isinstance(info, dict)
            or not isinstance(change_id, str)
            or not _CHANGE_ID.fullmatch(change_id)
            or info.get("Status") not in {"PENDING", "INSYNC"}
        ):
            raise RegionalRoutingError("Route 53 change identity is malformed")
        for attempt in range(attempts):
            change = _aws(
                ["route53", "get-change", "--id", change_id],
                profile=profile,
                region=manifest.primary_region,
                runner=runner,
            ).get("ChangeInfo")
            if (
                isinstance(change, dict)
                and change.get("Id") == change_id
                and change.get("Status") == "INSYNC"
            ):
                break
            if attempt + 1 == attempts:
                raise RegionalRoutingError("Route 53 change did not become INSYNC")
            sleeper(5.0)
    elif observed != target_state:
        raise RegionalRoutingError(
            "stable Route 53 records differ from source and target authority"
        )
    final_records = read_route_state(manifest, profile=profile, runner=runner)
    if final_records != target_state:
        raise RegionalRoutingError("stable Route 53 records did not converge on target")
    evidence = {
        "changeId": change_id or "recovered-from-target-records",
        "records": canonical_records(final_records),
        "runtimeProofSha256": runtime_proof["sha256"],
        "routingRole": role,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="ROUTING_TARGET",
        next_phase="VERIFYING_STABLE_ROUTE",
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "changeId": change_id,
        "journalClaim": claimed,
        "journal": completed["journal"],
        "records": canonical_records(final_records),
        "stepEvidenceSha256": digest,
        "trafficRouted": True,
    }


def verify_stable_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    target: IngressCell,
    token: str,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    probe: HttpProbe = _http_probe,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Verify stable API/UI and commit one new journal routing generation."""
    require_routing_role(manifest, profile=profile, runner=runner)
    expected_generation = manifest.expected_routing_generation
    if expected_generation is None:
        raise RegionalRoutingError("routing generation authority is unavailable")
    expected = expected_route_state(
        manifest,
        target,
        generation=expected_generation + 1,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    observed = read_route_state(manifest, profile=profile, runner=runner)
    if observed != expected:
        raise RegionalRoutingError("stable aliases or generation marker changed before smoke")
    smoke = smoke_ingress(manifest.stable_api_domain, manifest.stable_ui_domain, token, probe=probe)
    evidence = {
        "ingressEvidenceSha256": target.evidence_sha256,
        "records": canonical_records(observed),
        "smoke": smoke,
        # Keep retry evidence stable after complete_transition changes the phase.
        "transitionPhase": "VERIFYING_STABLE_ROUTE",
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.complete_transition(
        witness,
        manifest,
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "journal": completed["journal"],
        "stableSmoke": smoke,
        "stepEvidenceSha256": digest,
        "trafficRouted": True,
    }


def fence_failed_target_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    target_resources: active.SourceResources,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Fence every failed-target execution path before source reactivation."""
    manifest.require_reactivation_authority()
    require_routing_role(manifest, profile=profile, runner=runner)
    state = journal.read_state(witness, manifest)
    if state.phase == "FAILED_TARGET_FENCED":
        claimed = {"claim": "resume-completed", "journal": state.evidence()}
        target_fence = active.verify_source_fence(
            target_resources,
            profile=profile,
            region=manifest.target_region,
            runner=runner,
        )
    else:
        claimed = journal.advance_phase(
            witness,
            manifest,
            expected_phase="VERIFYING_STABLE_ROUTE",
            next_phase="FENCING_FAILED_TARGET",
            now=int(clock()),
        )
        target_fence = active.fence_source(
            target_resources,
            profile=profile,
            region=manifest.target_region,
            runner=runner,
        )
    digest = hashlib.sha256(
        json.dumps(target_fence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="FENCING_FAILED_TARGET",
        next_phase="FAILED_TARGET_FENCED",
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "journalClaim": claimed,
        "journal": completed["journal"],
        "stepEvidenceSha256": digest,
        "targetFence": target_fence,
        "trafficRouted": True,
    }


def reactivate_source_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    target_resources: active.SourceResources,
    source_plan: active.SourceReactivationPlan,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Re-prove target fencing and restore the exact approved source runtime."""
    manifest.require_reactivation_authority()
    require_routing_role(manifest, profile=profile, runner=runner)
    expected_stack = (
        manifest.primary_runtime_stack_name
        if manifest.source_region == manifest.primary_region
        else manifest.recovery_runtime_stack_name
    )
    expected_template = (
        manifest.primary_runtime_template_sha256
        if manifest.source_region == manifest.primary_region
        else manifest.recovery_runtime_template_sha256
    )
    if (
        source_plan.region != manifest.source_region
        or source_plan.stack_name != expected_stack
        or source_plan.template_sha256 != expected_template
    ):
        raise RegionalRoutingError("source reactivation plan differs from approved authority")
    state = journal.read_state(witness, manifest)
    completed_retry = state.phase == "SOURCE_REACTIVATED_NOT_ROUTED"
    fresh_reactivation = state.phase == "FAILED_TARGET_FENCED"
    if completed_retry:
        claimed = {"claim": "resume-completed", "journal": state.evidence()}
    else:
        claimed = journal.advance_phase(
            witness,
            manifest,
            expected_phase="FAILED_TARGET_FENCED",
            next_phase="REACTIVATING_SOURCE",
            now=int(clock()),
        )
    target_fence = active.verify_source_fence(
        target_resources,
        profile=profile,
        region=manifest.target_region,
        runner=runner,
    )
    if completed_retry:
        source_fence = source_plan.resources().fence_evidence()
        source_runtime = active.verify_source_reactivation(
            source_plan, profile=profile, runner=runner
        )
    else:
        if fresh_reactivation:
            source_fence = active.verify_source_fence(
                source_plan.resources(),
                profile=profile,
                region=manifest.source_region,
                runner=runner,
            )
        else:
            # A crash after the REACTIVATING_SOURCE claim may leave a mixture
            # of fenced and restored values. The target is re-proved fenced
            # above; replay the bounded approved plan instead of deadlocking.
            source_fence = source_plan.resources().fence_evidence()
        source_runtime = active.reactivate_source(source_plan, profile=profile, runner=runner)
    evidence = {
        "sourceFenceBeforeRestore": source_fence,
        "sourceRuntime": source_runtime,
        "targetFence": target_fence,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="REACTIVATING_SOURCE",
        next_phase="SOURCE_REACTIVATED_NOT_ROUTED",
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "journalClaim": claimed,
        "journal": completed["journal"],
        "reactivation": evidence,
        "stepEvidenceSha256": digest,
        "trafficRouted": True,
    }


def verify_source_ingress_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    source: IngressCell,
    token: str,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    probe: HttpProbe = _http_probe,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Prove reactivated source canaries before rollback routing."""
    manifest.require_reactivation_authority()
    require_routing_role(manifest, profile=profile, runner=runner)
    state = journal.read_state(witness, manifest)
    if state.phase == "SOURCE_INGRESS_VERIFIED_NOT_ROUTED":
        # A crash may occur after the completion CAS but before returning output.
        # Re-probe below and bind the retry to the immutable completion event.
        claimed = {"claim": "resume-completed", "journal": state.evidence()}
    else:
        claimed = journal.advance_phase(
            witness,
            manifest,
            expected_phase="SOURCE_REACTIVATED_NOT_ROUTED",
            next_phase="VERIFYING_SOURCE_INGRESS",
            now=int(clock()),
        )
    smoke = smoke_ingress(source.canary_api_domain, source.canary_ui_domain, token, probe=probe)
    evidence = {"ingressEvidenceSha256": source.evidence_sha256, "smoke": smoke}
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="VERIFYING_SOURCE_INGRESS",
        next_phase="SOURCE_INGRESS_VERIFIED_NOT_ROUTED",
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "journalClaim": claimed,
        "journal": completed["journal"],
        "sourceSmoke": smoke,
        "stepEvidenceSha256": digest,
        "trafficRouted": True,
    }


def route_source_rollback_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    source: IngressCell,
    target: IngressCell,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    clock: Clock = time.time,
    sleeper: Sleeper = time.sleep,
    attempts: int = 60,
) -> dict[str, Any]:
    """Move stable aliases from failed target to reactivated source atomically."""
    manifest.require_reactivation_authority()
    if isinstance(attempts, bool) or not 1 <= attempts <= 120:
        raise RegionalRoutingError("Route 53 wait attempts must be 1 through 120")
    role = require_routing_role(manifest, profile=profile, runner=runner)
    state = journal.read_state(witness, manifest)
    if state.phase == "VERIFYING_SOURCE_ROLLBACK":
        # Route 53 may have converged and the journal may have advanced before
        # the operator received output. Exact DNS/evidence checks below make
        # this recovery path idempotent without issuing another mutation.
        claimed = {"claim": "resume-completed", "journal": state.evidence()}
    else:
        claimed = journal.advance_phase(
            witness,
            manifest,
            expected_phase="SOURCE_INGRESS_VERIFIED_NOT_ROUTED",
            next_phase="ROUTING_SOURCE_ROLLBACK",
            now=int(clock()),
        )
    generation = manifest.expected_routing_generation
    if generation is None:
        raise RegionalRoutingError("routing generation authority is unavailable")
    target_state = expected_route_state(
        manifest,
        target,
        generation=generation + 1,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    source_state = expected_route_state(
        manifest,
        source,
        generation=generation + 2,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    observed = read_route_state(manifest, profile=profile, runner=runner)
    change_id: str | None = None
    if observed == target_state:
        changes = [
            {"Action": "DELETE", "ResourceRecordSet": record} for record in target_state.values()
        ] + [{"Action": "CREATE", "ResourceRecordSet": record} for record in source_state.values()]
        response = _aws(
            [
                "route53",
                "change-resource-record-sets",
                "--hosted-zone-id",
                manifest.hosted_zone_id,
                "--change-batch",
                json.dumps(
                    {
                        "Changes": changes,
                        "Comment": f"AAI Security rollback {manifest.transition_id}",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ],
            profile=profile,
            region=manifest.primary_region,
            runner=runner,
        )
        info = response.get("ChangeInfo")
        change_id = info.get("Id") if isinstance(info, dict) else None
        if (
            not isinstance(info, dict)
            or not isinstance(change_id, str)
            or not _CHANGE_ID.fullmatch(change_id)
            or info.get("Status") not in {"PENDING", "INSYNC"}
        ):
            raise RegionalRoutingError("Route 53 rollback change identity is malformed")
        for attempt in range(attempts):
            change = _aws(
                ["route53", "get-change", "--id", change_id],
                profile=profile,
                region=manifest.primary_region,
                runner=runner,
            ).get("ChangeInfo")
            if (
                isinstance(change, dict)
                and change.get("Id") == change_id
                and change.get("Status") == "INSYNC"
            ):
                break
            if attempt + 1 == attempts:
                raise RegionalRoutingError("Route 53 rollback did not become INSYNC")
            sleeper(5.0)
    elif observed != source_state:
        raise RegionalRoutingError("stable records differ from failed target and rollback source")
    final_records = read_route_state(manifest, profile=profile, runner=runner)
    if final_records != source_state:
        raise RegionalRoutingError("stable records did not converge on rollback source")
    evidence = {
        "changeId": change_id or "recovered-from-source-records",
        "records": canonical_records(final_records),
        "routingRole": role,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="ROUTING_SOURCE_ROLLBACK",
        next_phase="VERIFYING_SOURCE_ROLLBACK",
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "changeId": change_id,
        "journalClaim": claimed,
        "journal": completed["journal"],
        "records": canonical_records(final_records),
        "stepEvidenceSha256": digest,
        "trafficRouted": True,
    }


def verify_source_rollback_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    source: IngressCell,
    token: str,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    probe: HttpProbe = _http_probe,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Verify stable source service and seal a rolled-back generation."""
    manifest.require_reactivation_authority()
    require_routing_role(manifest, profile=profile, runner=runner)
    generation = manifest.expected_routing_generation
    if generation is None:
        raise RegionalRoutingError("routing generation authority is unavailable")
    expected = expected_route_state(
        manifest,
        source,
        generation=generation + 2,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    observed = read_route_state(manifest, profile=profile, runner=runner)
    if observed != expected:
        raise RegionalRoutingError("stable rollback aliases or marker changed before smoke")
    smoke = smoke_ingress(manifest.stable_api_domain, manifest.stable_ui_domain, token, probe=probe)
    evidence = {
        "ingressEvidenceSha256": source.evidence_sha256,
        "outcome": "ROLLED_BACK",
        "records": canonical_records(observed),
        "smoke": smoke,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.complete_rollback(
        witness,
        manifest,
        now=int(clock()),
        step_evidence_sha256=digest,
    )
    return {
        "journal": completed["journal"],
        "outcome": "ROLLED_BACK",
        "stableSmoke": smoke,
        "stepEvidenceSha256": digest,
        "trafficRouted": True,
    }


def _read_token(path: Path) -> str:
    """Read a bounded owner-only smoke token without exposing it in output."""
    try:
        stat = path.stat()
        if stat.st_mode & 0o077:
            raise RegionalRoutingError("operator token file must not permit group or other access")
        token = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RegionalRoutingError("operator token file is unavailable") from error
    if token.endswith("\n"):
        token = token[:-1]
    if not 32 <= len(token) <= 16_384 or token != token.strip():
        raise RegionalRoutingError("operator token file content is malformed")
    return token


def _parser() -> argparse.ArgumentParser:
    """Build the explicit one-step routing command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "verify-ingress",
            "route-target",
            "verify-stable",
            "fence-failed-target",
            "reactivate-source",
            "verify-source-ingress",
            "route-source-rollback",
            "verify-source-rollback",
        ),
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--evidence-continuity-config", type=Path, required=True)
    parser.add_argument("--passive-cell-config", type=Path, required=True)
    parser.add_argument("--operator-token-file", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-journal-ingress", action="store_true")
    parser.add_argument("--confirm-route53-cutover", action="store_true")
    parser.add_argument("--confirm-stable-completion", action="store_true")
    parser.add_argument("--confirm-failed-target-fence", action="store_true")
    parser.add_argument("--confirm-source-reactivation", action="store_true")
    parser.add_argument("--confirm-source-ingress", action="store_true")
    parser.add_argument("--confirm-rollback-route53", action="store_true")
    parser.add_argument("--confirm-rollback-completion", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Repeat provider preflight and execute exactly one confirmed route step."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = activation.ActivationManifest.parse(
            arguments.manifest.read_text(encoding="utf-8")
        )
        manifest.require_routing_authority()
        regional = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        evidence = continuity.EvidenceContinuityManifest.parse(
            arguments.evidence_continuity_config.read_text(encoding="utf-8")
        )
        passive_cell = passive.PassiveCellManifest.parse(
            arguments.passive_cell_config.read_text(encoding="utf-8")
        )
        token = _read_token(arguments.operator_token_file)
        import boto3

        session = boto3.Session(profile_name=arguments.profile)
        checked = preflight.provider_preflight(
            manifest,
            regional,
            evidence,
            passive_cell,
            profile=arguments.profile,
            s3_factory=lambda region: session.client("s3", region_name=region),
            expected_cell_status="active-not-routed",
        )
        verified = checked.get("verified")
        if (
            not isinstance(verified, dict)
            or verified.get("authoritySha256") != manifest.authority_sha256()
            or verified.get("approverPrincipalIds")
            != [approval.principal_id for approval in manifest.approvals]
        ):
            raise RegionalRoutingError("provider preflight did not bind routing authority")
        witness = session.client("dynamodb", region_name=manifest.coordination_region)
        journal_posture = journal.verify_table_posture(witness, manifest)
        primary = discover_ingress_cell(manifest, role="primary", profile=arguments.profile)
        recovery_cell = discover_ingress_cell(manifest, role="recovery", profile=arguments.profile)
        source_cell = (
            primary if manifest.source_region == manifest.primary_region else recovery_cell
        )
        target_cell = (
            primary if manifest.target_region == manifest.primary_region else recovery_cell
        )
        source_stack_name = (
            regional.stack_name
            if manifest.source_region == manifest.primary_region
            else passive_cell.stack_name
        )
        target_stack_name = (
            regional.stack_name
            if manifest.target_region == manifest.primary_region
            else passive_cell.stack_name
        )
        result: dict[str, Any] = {
            "command": arguments.command,
            "journalPosture": journal_posture,
            "preflightStatus": checked["status"],
            "trafficRouted": False,
        }
        if arguments.command == "verify-ingress":
            if not arguments.confirm_journal_ingress:
                raise RegionalRoutingError("--confirm-journal-ingress is required")
            result.update(
                verify_target_ingress_step(
                    witness,
                    manifest,
                    target_cell,
                    token,
                    profile=arguments.profile,
                )
            )
            result["status"] = "target-ingress-verified-not-routed"
        elif arguments.command == "route-target":
            if not arguments.confirm_route53_cutover:
                raise RegionalRoutingError("--confirm-route53-cutover is required")
            if manifest.direction == "failover":
                environment = active.active_environment(
                    manifest,
                    regional,
                    passive_cell,
                    verified,
                    profile=arguments.profile,
                )
                target_resources = active.discover_target_resources(
                    stack_name=target_stack_name,
                    target_region=manifest.target_region,
                    profile=arguments.profile,
                )
                runtime_verifier = active.verify_target_runtime
            else:
                environment = active.primary_target_environment(
                    manifest,
                    regional,
                    verified,
                    profile=arguments.profile,
                )
                target_resources = active.discover_primary_target_resources(
                    stack_name=target_stack_name,
                    target_region=manifest.target_region,
                    profile=arguments.profile,
                )
                runtime_verifier = active.verify_primary_target_runtime
            source_resources = active.discover_source_resources(
                regional,
                stack_name=source_stack_name,
                source_region=manifest.source_region,
                profile=arguments.profile,
            )
            lambda_client = session.client("lambda", region_name=manifest.target_region)
            result.update(
                route_target_step(
                    witness,
                    manifest,
                    source_cell,
                    target_cell,
                    profile=arguments.profile,
                    runtime_guard=lambda: prove_pre_route_runtime(
                        lambda_client,
                        manifest,
                        source_resources,
                        target_resources,
                        environment,
                        profile=arguments.profile,
                        runtime_verifier=runtime_verifier,
                    ),
                )
            )
            result["status"] = "target-routed-awaiting-stable-verification"
        elif arguments.command == "verify-stable":
            if not arguments.confirm_stable_completion:
                raise RegionalRoutingError("--confirm-stable-completion is required")
            result.update(
                verify_stable_step(
                    witness,
                    manifest,
                    target_cell,
                    token,
                    profile=arguments.profile,
                )
            )
            result["status"] = "target-stable-generation-completed"
        elif arguments.command == "fence-failed-target":
            if not arguments.confirm_failed_target_fence:
                raise RegionalRoutingError("--confirm-failed-target-fence is required")
            rollback_target_resources = active.discover_source_resources(
                regional,
                stack_name=target_stack_name,
                source_region=manifest.target_region,
                profile=arguments.profile,
            )
            result.update(
                fence_failed_target_step(
                    witness,
                    manifest,
                    rollback_target_resources,
                    profile=arguments.profile,
                )
            )
            result["status"] = "failed-target-fenced-before-source-reactivation"
        elif arguments.command == "reactivate-source":
            if not arguments.confirm_source_reactivation:
                raise RegionalRoutingError("--confirm-source-reactivation is required")
            rollback_target_resources = active.discover_source_resources(
                regional,
                stack_name=target_stack_name,
                source_region=manifest.target_region,
                profile=arguments.profile,
            )
            source_resources = active.discover_source_resources(
                regional,
                stack_name=source_stack_name,
                source_region=manifest.source_region,
                profile=arguments.profile,
            )
            source_plan = active.discover_source_reactivation_plan(
                source_resources,
                stack_name=source_stack_name,
                region=manifest.source_region,
                profile=arguments.profile,
            )
            result.update(
                reactivate_source_step(
                    witness,
                    manifest,
                    rollback_target_resources,
                    source_plan,
                    profile=arguments.profile,
                )
            )
            result["status"] = "source-reactivated-target-fenced-not-routed"
        elif arguments.command == "verify-source-ingress":
            if not arguments.confirm_source_ingress:
                raise RegionalRoutingError("--confirm-source-ingress is required")
            result.update(
                verify_source_ingress_step(
                    witness,
                    manifest,
                    source_cell,
                    token,
                    profile=arguments.profile,
                )
            )
            result["status"] = "source-ingress-verified-before-rollback"
        elif arguments.command == "route-source-rollback":
            if not arguments.confirm_rollback_route53:
                raise RegionalRoutingError("--confirm-rollback-route53 is required")
            result.update(
                route_source_rollback_step(
                    witness,
                    manifest,
                    source_cell,
                    target_cell,
                    profile=arguments.profile,
                )
            )
            result["status"] = "source-routed-awaiting-rollback-verification"
        else:
            if not arguments.confirm_rollback_completion:
                raise RegionalRoutingError("--confirm-rollback-completion is required")
            result.update(
                verify_source_rollback_step(
                    witness,
                    manifest,
                    source_cell,
                    token,
                    profile=arguments.profile,
                )
            )
            result["status"] = "source-stable-transition-rolled-back"
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        OSError,
        ValueError,
        activation.RegionalActivationVerificationError,
        recovery.RecoveryConfigurationError,
        continuity.EvidenceContinuityDeploymentError,
        passive.PassiveCellDeploymentError,
        active.ActiveCellDeploymentError,
        journal.TransitionJournalError,
        RegionalRoutingError,
    ) as error:
        print(f"regional routing refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

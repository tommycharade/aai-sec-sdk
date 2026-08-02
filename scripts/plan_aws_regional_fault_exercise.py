#!/usr/bin/env python3
"""Validate exact Regional dependency-fault authority and emit a safe plan.

This command is read-only. It binds one short-lived dependency exercise to an
existing schema-v4 transition, exact target runtime template, two approvers and
routing generation. It deliberately has no IAM, Lambda, Scheduler or Step
Functions mutation operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import verify_aws_regional_activation as activation  # noqa: E402


class RegionalFaultAuthorityError(RuntimeError):
    """Report dependency-fault authority that is unsafe or ambiguous."""


_FIELDS = {
    "schemaVersion",
    "faultId",
    "transitionId",
    "transitionAuthoritySha256",
    "direction",
    "targetRegion",
    "targetCellRole",
    "targetRuntimeStackName",
    "targetRuntimeTemplateSha256",
    "coordinationRegion",
    "expectedRoutingGeneration",
    "dependency",
    "maximumFaultSeconds",
    "approvalSha256",
    "approverPrincipalIds",
    "activationEvidenceRef",
    "expiresAt",
    "faultPermitted",
    "automaticFaultInjection",
}
_DEPENDENCIES = frozenset({"audit", "cognito", "dynamodb", "kms", "queue"})
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_STACK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_EVIDENCE_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON fields before authority interpretation."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegionalFaultAuthorityError(f"duplicate fault authority field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class RegionalFaultAuthority:
    """One time-bounded dependency fault bound to exact transition authority."""

    fault_id: str
    transition_id: str
    transition_authority_sha256: str
    direction: str
    target_region: str
    target_cell_role: str
    target_runtime_stack_name: str
    target_runtime_template_sha256: str
    coordination_region: str
    expected_routing_generation: int
    dependency: str
    maximum_fault_seconds: int
    approval_sha256: str
    approver_principal_ids: tuple[str, str]
    activation_evidence_ref: str
    expires_at: int

    def canonical(self) -> dict[str, Any]:
        """Return the complete immutable authority representation."""
        return {
            "activationEvidenceRef": self.activation_evidence_ref,
            "approvalSha256": self.approval_sha256,
            "approverPrincipalIds": list(self.approver_principal_ids),
            "coordinationRegion": self.coordination_region,
            "dependency": self.dependency,
            "direction": self.direction,
            "expectedRoutingGeneration": self.expected_routing_generation,
            "expiresAt": self.expires_at,
            "faultId": self.fault_id,
            "maximumFaultSeconds": self.maximum_fault_seconds,
            "targetCellRole": self.target_cell_role,
            "targetRegion": self.target_region,
            "targetRuntimeStackName": self.target_runtime_stack_name,
            "targetRuntimeTemplateSha256": self.target_runtime_template_sha256,
            "transitionAuthoritySha256": self.transition_authority_sha256,
            "transitionId": self.transition_id,
        }

    @classmethod
    def parse(
        cls,
        payload: str,
        manifest: activation.ActivationManifest,
        *,
        now: int | None = None,
    ) -> RegionalFaultAuthority:
        """Parse and bind one exact fault request to schema-v4 authority."""
        if len(payload.encode()) > 32_768:
            raise RegionalFaultAuthorityError("fault authority exceeds 32 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise RegionalFaultAuthorityError("fault authority is not JSON") from error
        if not isinstance(value, dict) or set(value) != _FIELDS or value["schemaVersion"] != 1:
            raise RegionalFaultAuthorityError("fault authority schema is invalid")
        manifest.require_reactivation_authority()
        current = int(time.time()) if now is None else now
        expires = value.get("expiresAt")
        duration = value.get("maximumFaultSeconds")
        generation = value.get("expectedRoutingGeneration")
        approvers = value.get("approverPrincipalIds")
        expected_role = "recovery" if manifest.direction == "failover" else "primary"
        expected_stack = (
            manifest.recovery_runtime_stack_name
            if manifest.direction == "failover"
            else manifest.primary_runtime_stack_name
        )
        expected_template = (
            manifest.recovery_runtime_template_sha256
            if manifest.direction == "failover"
            else manifest.primary_runtime_template_sha256
        )
        expected_evidence_ref = activation_evidence_ref(manifest.evidence)
        if (
            value.get("faultPermitted") is not True
            or value.get("automaticFaultInjection") is not False
            or value.get("transitionId") != manifest.transition_id
            or value.get("transitionAuthoritySha256") != manifest.authority_sha256()
            or value.get("direction") != manifest.direction
            or value.get("targetRegion") != manifest.target_region
            or value.get("targetCellRole") != expected_role
            or value.get("targetRuntimeStackName") != expected_stack
            or value.get("targetRuntimeTemplateSha256") != expected_template
            or value.get("coordinationRegion") != manifest.coordination_region
            or generation != manifest.expected_routing_generation
            or value.get("approvalSha256") != manifest.approval_sha256()
            or approvers != [item.principal_id for item in manifest.approvals]
            or value.get("activationEvidenceRef") != expected_evidence_ref
        ):
            raise RegionalFaultAuthorityError("fault authority differs from transition authority")
        fault_id = value.get("faultId")
        dependency = value.get("dependency")
        evidence_ref = value.get("activationEvidenceRef")
        target_region = value.get("targetRegion")
        coordination_region = value.get("coordinationRegion")
        stack_name = value.get("targetRuntimeStackName")
        template_sha256 = value.get("targetRuntimeTemplateSha256")
        approval_sha256 = value.get("approvalSha256")
        transition_digest = value.get("transitionAuthoritySha256")
        if (
            not isinstance(fault_id, str)
            or not _UUID.fullmatch(fault_id)
            or not isinstance(dependency, str)
            or dependency not in _DEPENDENCIES
            or isinstance(duration, bool)
            or not isinstance(duration, int)
            or not 30 <= duration <= 300
            or isinstance(expires, bool)
            or not isinstance(expires, int)
            or not current < expires <= min(current + 900, manifest.expires_at)
            or not isinstance(evidence_ref, str)
            or not _EVIDENCE_REF.fullmatch(evidence_ref)
            or not isinstance(target_region, str)
            or not _REGION.fullmatch(target_region)
            or not isinstance(coordination_region, str)
            or not _REGION.fullmatch(coordination_region)
            or not isinstance(stack_name, str)
            or not _STACK.fullmatch(stack_name)
            or not isinstance(template_sha256, str)
            or not _SHA256.fullmatch(template_sha256)
            or not isinstance(approval_sha256, str)
            or not _SHA256.fullmatch(approval_sha256)
            or not isinstance(transition_digest, str)
            or not _SHA256.fullmatch(transition_digest)
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
            or not isinstance(approvers, list)
            or len(approvers) != 2
            or any(not isinstance(item, str) or not _UUID.fullmatch(item) for item in approvers)
        ):
            raise RegionalFaultAuthorityError("fault authority values are invalid")
        return cls(
            fault_id,
            manifest.transition_id,
            transition_digest,
            manifest.direction,
            target_region,
            expected_role,
            stack_name,
            template_sha256,
            coordination_region,
            generation,
            dependency,
            duration,
            approval_sha256,
            (approvers[0], approvers[1]),
            evidence_ref,
            expires,
        )

    def sha256(self) -> str:
        """Return a canonical digest for workflow execution and evidence."""
        return hashlib.sha256(
            json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def activation_evidence_ref(reference: activation.EvidenceReference) -> str:
    """Bind the exact retained S3 object version without exposing its location."""
    canonical = {
        "bucketArn": reference.bucket_arn,
        "key": reference.key,
        "sha256": reference.sha256,
        "versionId": reference.version_id,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"sha256:{digest}"


def fault_plan(authority: RegionalFaultAuthority) -> list[dict[str, Any]]:
    """Return the required server-managed compensation sequence."""
    common = {
        "dependency": authority.dependency,
        "faultId": authority.fault_id,
        "targetRegion": authority.target_region,
    }
    return [
        {"order": 1, "action": "verify-target-not-routed-and-source-fenced", **common},
        {
            "order": 2,
            "action": "create-independent-cleanup-watchdog",
            "maximumFaultSeconds": authority.maximum_fault_seconds,
            **common,
        },
        {"order": 3, "action": "apply-exact-target-role-deny", **common},
        {"order": 4, "action": "verify-dependency-unavailable", **common},
        {"order": 5, "action": "verify-execution-denied-without-bypass", **common},
        {"order": 6, "action": "remove-exact-target-role-deny", **common},
        {"order": 7, "action": "verify-dependency-and-target-recovered", **common},
        {"order": 8, "action": "remove-cleanup-watchdog", **common},
        {"order": 9, "action": "seal-content-free-fault-evidence", **common},
    ]


def _parser() -> argparse.ArgumentParser:
    """Build the read-only fault-authority planning command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--fault-authority", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Print one validated plan without performing any mutation."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = activation.ActivationManifest.parse(
            arguments.manifest.read_text(encoding="utf-8")
        )
        authority = RegionalFaultAuthority.parse(
            arguments.fault_authority.read_text(encoding="utf-8"), manifest
        )
        print(
            json.dumps(
                {
                    "authoritySha256": authority.sha256(),
                    "faultExecuted": False,
                    "plan": fault_plan(authority),
                    "status": "fault-authority-verified-read-only",
                },
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeError,
        activation.RegionalActivationVerificationError,
        RegionalFaultAuthorityError,
    ) as error:
        print(f"Regional fault planning failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

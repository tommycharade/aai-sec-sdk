#!/usr/bin/env python3
"""Verify content-addressed regional activation evidence and emit an ordered plan.

This verifier is intentionally non-mutating. It validates the complete
activation authority and every required measurement, then emits the exact
failover or failback state-machine order. A later executor must repeat provider
checks and condition every transition; this tool never changes compute or DNS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID


class RegionalActivationVerificationError(ValueError):
    """Raised when authority or evidence cannot prove a safe transition."""


_MANIFEST_FIELDS = {
    "schemaVersion",
    "transitionId",
    "direction",
    "primaryRegion",
    "recoveryRegion",
    "sourceRegion",
    "targetRegion",
    "stableApiDomain",
    "stableUiDomain",
    "route53HostedZoneId",
    "targetFleetSize",
    "rtoMinutes",
    "rpoSeconds",
    "evidenceBundle",
    "approvalEvidenceRef",
    "expiresAt",
    "activationPermitted",
    "automaticActivation",
}
_BUNDLE_FIELDS = {
    "schemaVersion",
    "transitionId",
    "authoritySha256",
    "generatedAt",
    "expiresAt",
    "sourceRegion",
    "targetRegion",
    "targetFleetSize",
    "rtoMinutes",
    "rpoSeconds",
    "storage",
    "identity",
    "signer",
    "audit",
    "jobs",
    "routing",
    "load",
    "dependency",
    "consistency",
    "backup",
    "operations",
}
_REFERENCE_FIELDS = {"bucketArn", "key", "versionId", "sha256"}
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ZONE = re.compile(r"^Z[A-Z0-9]{1,31}$")
_S3_ARN = re.compile(r"^arn:(?:aws|aws-us-gov|aws-cn):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_KEY = re.compile(r"^regional-activation/[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\.json$")
_VERSION = re.compile(r"^[A-Za-z0-9._-]{1,1024}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{7,511}$")
_ENTRA_ISSUER = re.compile(
    r"^https://login\.microsoftonline\.com/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/v2\.0$",
    re.IGNORECASE,
)
_KMS_ARN = re.compile(r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key/mrk-[0-9a-f]{32}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before they create ambiguous authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegionalActivationVerificationError(f"duplicate activation field: {key}")
        result[key] = value
    return result


def _object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    """Require one exact object schema."""
    if not isinstance(value, dict) or set(value) != fields:
        raise RegionalActivationVerificationError(f"{label} fields do not match schema 1")
    return value


def _uuid(value: object, label: str) -> str:
    """Return one canonical UUID or reject aliases."""
    if not isinstance(value, str):
        raise RegionalActivationVerificationError(f"{label} must be a UUID")
    try:
        canonical = str(UUID(value))
    except ValueError as error:
        raise RegionalActivationVerificationError(f"{label} must be a UUID") from error
    if value != canonical:
        raise RegionalActivationVerificationError(f"{label} must be canonical")
    return canonical


def _integer(value: object, label: str, *, minimum: int, maximum: int) -> int:
    """Return one bounded integer without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RegionalActivationVerificationError(f"{label} is outside its safe bound")
    return value


def _number(value: object, label: str, *, minimum: float, maximum: float) -> float:
    """Return one bounded finite numeric measurement."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RegionalActivationVerificationError(f"{label} must be numeric")
    result = float(value)
    if result != result or not minimum <= result <= maximum:
        raise RegionalActivationVerificationError(f"{label} is outside its safe bound")
    return result


@dataclass(frozen=True)
class EvidenceReference:
    """Exact immutable S3 version containing one activation evidence bundle."""

    bucket_arn: str
    key: str
    version_id: str
    sha256: str

    @classmethod
    def parse(cls, value: object) -> EvidenceReference:
        """Parse a content-addressed retained-version reference."""
        item = _object(value, _REFERENCE_FIELDS, "evidenceBundle")
        bucket, key = item["bucketArn"], item["key"]
        version, digest = item["versionId"], item["sha256"]
        if not isinstance(bucket, str) or not _S3_ARN.fullmatch(bucket):
            raise RegionalActivationVerificationError("evidence bucket ARN is invalid")
        if not isinstance(key, str) or not _KEY.fullmatch(key) or ".." in key:
            raise RegionalActivationVerificationError("evidence key is invalid")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise RegionalActivationVerificationError("evidence version is invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RegionalActivationVerificationError("evidence SHA-256 is invalid")
        return cls(bucket, key, version, digest)


@dataclass(frozen=True)
class ActivationManifest:
    """Reviewed authority for one manual failover or failback transition."""

    transition_id: str
    direction: str
    primary_region: str
    recovery_region: str
    source_region: str
    target_region: str
    stable_api_domain: str
    stable_ui_domain: str
    hosted_zone_id: str
    target_fleet_size: int
    rto_minutes: int
    rpo_seconds: int
    evidence: EvidenceReference
    approval_evidence_ref: str
    expires_at: int

    def authority_sha256(self) -> str:
        """Bind all transition authority except the circular evidence reference."""
        authority = {
            "activationPermitted": True,
            "approvalEvidenceRef": self.approval_evidence_ref,
            "automaticActivation": False,
            "direction": self.direction,
            "expiresAt": self.expires_at,
            "primaryRegion": self.primary_region,
            "recoveryRegion": self.recovery_region,
            "route53HostedZoneId": self.hosted_zone_id,
            "rpoSeconds": self.rpo_seconds,
            "rtoMinutes": self.rto_minutes,
            "schemaVersion": 1,
            "sourceRegion": self.source_region,
            "stableApiDomain": self.stable_api_domain,
            "stableUiDomain": self.stable_ui_domain,
            "targetFleetSize": self.target_fleet_size,
            "targetRegion": self.target_region,
            "transitionId": self.transition_id,
        }
        payload = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def parse(cls, payload: str, *, now: int | None = None) -> ActivationManifest:
        """Parse exact, time-bounded, explicitly manual activation authority."""
        if len(payload.encode()) > 32_768:
            raise RegionalActivationVerificationError("activation manifest exceeds 32 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise RegionalActivationVerificationError("activation manifest is not JSON") from error
        item = _object(value, _MANIFEST_FIELDS, "activation manifest")
        if (
            item["schemaVersion"] != 1
            or item["activationPermitted"] is not True
            or item["automaticActivation"] is not False
        ):
            raise RegionalActivationVerificationError(
                "activation must be explicitly permitted and automatic activation prohibited"
            )
        transition_id = _uuid(item["transitionId"], "transitionId")
        direction = item["direction"]
        if direction not in {"failover", "failback"}:
            raise RegionalActivationVerificationError("direction is unsupported")
        primary, recovery = item["primaryRegion"], item["recoveryRegion"]
        source, target = item["sourceRegion"], item["targetRegion"]
        if not all(
            isinstance(region, str) and _REGION.fullmatch(region)
            for region in (primary, recovery, source, target)
        ):
            raise RegionalActivationVerificationError("activation Region is malformed")
        expected = (primary, recovery) if direction == "failover" else (recovery, primary)
        if primary == recovery or (source, target) != expected:
            raise RegionalActivationVerificationError(
                "direction and source/target Regions disagree"
            )
        api_domain, ui_domain = item["stableApiDomain"], item["stableUiDomain"]
        if (
            not isinstance(api_domain, str)
            or not _DOMAIN.fullmatch(api_domain)
            or not isinstance(ui_domain, str)
            or not _DOMAIN.fullmatch(ui_domain)
            or api_domain == ui_domain
        ):
            raise RegionalActivationVerificationError("stable domains are invalid")
        zone = item["route53HostedZoneId"]
        if not isinstance(zone, str) or not _ZONE.fullmatch(zone):
            raise RegionalActivationVerificationError("Route 53 hosted zone ID is invalid")
        fleet = _integer(item["targetFleetSize"], "targetFleetSize", minimum=1, maximum=100_000)
        rto = _integer(item["rtoMinutes"], "rtoMinutes", minimum=1, maximum=240)
        rpo = _integer(item["rpoSeconds"], "rpoSeconds", minimum=1, maximum=300)
        evidence_ref = item["approvalEvidenceRef"]
        if not isinstance(evidence_ref, str) or not _EVIDENCE.fullmatch(evidence_ref):
            raise RegionalActivationVerificationError("approvalEvidenceRef is invalid")
        expires = _integer(item["expiresAt"], "expiresAt", minimum=1, maximum=4_102_444_800)
        current = int(time.time()) if now is None else now
        if not current < expires <= current + 3600:
            raise RegionalActivationVerificationError("activation authority is expired or too long")
        return cls(
            transition_id,
            direction,
            primary,
            recovery,
            source,
            target,
            api_domain,
            ui_domain,
            zone,
            fleet,
            rto,
            rpo,
            EvidenceReference.parse(item["evidenceBundle"]),
            evidence_ref,
            expires,
        )


def _section(bundle: dict[str, Any], name: str, fields: set[str]) -> dict[str, Any]:
    """Return one exact evidence section."""
    return _object(bundle.get(name), fields, f"{name} evidence")


def verify_bundle(
    manifest: ActivationManifest, payload: bytes, *, now: int | None = None
) -> dict[str, Any]:
    """Verify content, freshness and every P0-11 activation measurement."""
    if len(payload) > 1_048_576:
        raise RegionalActivationVerificationError("activation evidence exceeds 1 MiB")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != manifest.evidence.sha256:
        raise RegionalActivationVerificationError("activation evidence digest differs")
    try:
        value = json.loads(payload, object_pairs_hook=_strict_object)
    except json.JSONDecodeError as error:
        raise RegionalActivationVerificationError("activation evidence is not JSON") from error
    bundle = _object(value, _BUNDLE_FIELDS, "activation evidence")
    if (
        bundle["schemaVersion"] != 1
        or bundle["transitionId"] != manifest.transition_id
        or bundle["authoritySha256"] != manifest.authority_sha256()
    ):
        raise RegionalActivationVerificationError("activation evidence identity differs")
    current = int(time.time()) if now is None else now
    generated = _integer(bundle["generatedAt"], "generatedAt", minimum=1, maximum=current)
    expires = _integer(bundle["expiresAt"], "bundle expiresAt", minimum=1, maximum=4_102_444_800)
    if not generated <= current < expires <= manifest.expires_at or expires - generated > 3600:
        raise RegionalActivationVerificationError("activation evidence is stale or overlong")
    if (
        bundle["sourceRegion"] != manifest.source_region
        or bundle["targetRegion"] != manifest.target_region
        or bundle["targetFleetSize"] != manifest.target_fleet_size
        or bundle["rtoMinutes"] != manifest.rto_minutes
        or bundle["rpoSeconds"] != manifest.rpo_seconds
    ):
        raise RegionalActivationVerificationError("activation targets differ from evidence")

    storage = _section(
        bundle,
        "storage",
        {
            "tableCount",
            "allActive",
            "pitrEnabled",
            "deletionProtected",
            "maxReplicationSeconds",
        },
    )
    table_count = _integer(storage["tableCount"], "storage table count", minimum=0, maximum=100)
    replication_seconds = _number(
        storage["maxReplicationSeconds"],
        "storage replication",
        minimum=0,
        maximum=manifest.rpo_seconds,
    )
    if (
        table_count != 4
        or storage["allActive"] is not True
        or storage["pitrEnabled"] is not True
        or storage["deletionProtected"] is not True
        or replication_seconds > manifest.rpo_seconds
    ):
        raise RegionalActivationVerificationError("storage recovery evidence failed")

    identity = _section(
        bundle,
        "identity",
        {
            "provider",
            "tenantIssuer",
            "recoveryPoolId",
            "signInPassed",
            "scimLifecyclePassed",
            "strongAuthenticationPassed",
        },
    )
    if (
        identity["provider"] != "microsoft-entra"
        or not isinstance(identity["tenantIssuer"], str)
        or not _ENTRA_ISSUER.fullmatch(identity["tenantIssuer"])
        or not isinstance(identity["recoveryPoolId"], str)
        or not identity["recoveryPoolId"].startswith(f"{manifest.recovery_region}_")
        or identity["signInPassed"] is not True
        or identity["scimLifecyclePassed"] is not True
        or identity["strongAuthenticationPassed"] is not True
    ):
        raise RegionalActivationVerificationError("identity recovery evidence failed")

    signer = _section(
        bundle,
        "signer",
        {
            "targetKeyArn",
            "trustConvergencePercent",
            "signingPassed",
            "verificationPassed",
        },
    )
    convergence = _number(
        signer["trustConvergencePercent"],
        "signer trust convergence",
        minimum=0,
        maximum=100,
    )
    if (
        not isinstance(signer["targetKeyArn"], str)
        or not _KMS_ARN.fullmatch(signer["targetKeyArn"])
        or convergence != 100
        or signer["signingPassed"] is not True
        or signer["verificationPassed"] is not True
    ):
        raise RegionalActivationVerificationError("signer recovery evidence failed")

    audit = _section(
        bundle,
        "audit",
        {
            "directionCount",
            "complianceObjectLock",
            "bidirectionalPassed",
            "replicaModificationPassed",
        },
    )
    direction_count = _integer(
        audit["directionCount"], "audit direction count", minimum=0, maximum=2
    )
    if (
        direction_count != 2
        or audit["complianceObjectLock"] is not True
        or audit["bidirectionalPassed"] is not True
        or audit["replicaModificationPassed"] is not True
    ):
        raise RegionalActivationVerificationError("audit continuity evidence failed")

    jobs = _section(bundle, "jobs", {"queueSource", "conflicts", "plannedActions", "checkPassed"})
    conflicts = _integer(jobs["conflicts"], "job conflicts", minimum=0, maximum=100_000)
    planned_actions = _integer(
        jobs["plannedActions"], "planned job actions", minimum=0, maximum=100_000
    )
    if (
        jobs["queueSource"] != "authoritative-dynamodb-job-records"
        or conflicts != 0
        or jobs["checkPassed"] is not True
    ):
        raise RegionalActivationVerificationError("job reconciliation evidence failed")

    routing = _section(
        bundle,
        "routing",
        {
            "stableApiDomain",
            "stableUiDomain",
            "sourceDirectOriginDisabled",
            "targetDirectOriginDisabled",
            "currentTargetRegion",
        },
    )
    if (
        routing["stableApiDomain"] != manifest.stable_api_domain
        or routing["stableUiDomain"] != manifest.stable_ui_domain
        or routing["sourceDirectOriginDisabled"] is not True
        or routing["targetDirectOriginDisabled"] is not True
        or routing["currentTargetRegion"] != manifest.source_region
    ):
        raise RegionalActivationVerificationError("routing or origin-fencing evidence failed")

    load = _section(
        bundle,
        "load",
        {
            "simulatedAgents",
            "p99HeartbeatMs",
            "p99PolicyReadMs",
            "p99DecisionWriteMs",
            "errorRate",
        },
    )
    simulated_agents = _integer(
        load["simulatedAgents"], "simulated agents", minimum=1, maximum=100_000
    )
    if (
        simulated_agents < manifest.target_fleet_size
        or _number(load["p99HeartbeatMs"], "heartbeat p99", minimum=0, maximum=1_000) > 1_000
        or _number(load["p99PolicyReadMs"], "policy-read p99", minimum=0, maximum=1_000) > 1_000
        or _number(load["p99DecisionWriteMs"], "decision-write p99", minimum=0, maximum=2_000)
        > 2_000
        or _number(load["errorRate"], "load error rate", minimum=0, maximum=0.01) > 0.01
    ):
        raise RegionalActivationVerificationError("target-fleet load evidence failed")

    dependency = _section(
        bundle,
        "dependency",
        {
            "testedDependencies",
            "failClosedPassed",
            "bypassObserved",
            "recoveryPassed",
        },
    )
    tested_dependencies = dependency["testedDependencies"]
    required_dependencies = ["audit", "cognito", "dynamodb", "kms", "queue"]
    if (
        tested_dependencies != required_dependencies
        or dependency["failClosedPassed"] is not True
        or dependency["bypassObserved"] is not False
        or dependency["recoveryPassed"] is not True
    ):
        raise RegionalActivationVerificationError("dependency-failure recovery evidence failed")

    consistency = _section(
        bundle,
        "consistency",
        {
            "policyPassed",
            "identityPassed",
            "approvalReplayDenied",
            "idempotencyReplaySafe",
            "auditPassed",
            "authorityWideningObserved",
        },
    )
    if (
        consistency["policyPassed"] is not True
        or consistency["identityPassed"] is not True
        or consistency["approvalReplayDenied"] is not True
        or consistency["idempotencyReplaySafe"] is not True
        or consistency["auditPassed"] is not True
        or consistency["authorityWideningObserved"] is not False
    ):
        raise RegionalActivationVerificationError("failover authority-consistency evidence failed")

    backup = _section(
        bundle,
        "backup",
        {
            "tableRestorePassed",
            "objectRecoveryPassed",
            "keyRecoveryPassed",
            "withinRtoMinutes",
        },
    )
    restore_minutes = _integer(
        backup["withinRtoMinutes"],
        "backup recovery time",
        minimum=0,
        maximum=manifest.rto_minutes,
    )
    if (
        backup["tableRestorePassed"] is not True
        or backup["objectRecoveryPassed"] is not True
        or backup["keyRecoveryPassed"] is not True
        or restore_minutes > manifest.rto_minutes
    ):
        raise RegionalActivationVerificationError("backup or key recovery evidence failed")

    operations = _section(
        bundle,
        "operations",
        {
            "independentApproverCount",
            "breakGlassRehearsed",
            "sourceFencePrepared",
            "failbackPlanPassed",
        },
    )
    approver_count = _integer(
        operations["independentApproverCount"],
        "independent approver count",
        minimum=0,
        maximum=20,
    )
    if (
        approver_count < 2
        or operations["breakGlassRehearsed"] is not True
        or operations["sourceFencePrepared"] is not True
        or operations["failbackPlanPassed"] is not True
    ):
        raise RegionalActivationVerificationError("operational recovery evidence failed")
    return {
        "status": "verified-ready-for-manual-transition",
        "transitionId": manifest.transition_id,
        "direction": manifest.direction,
        "evidenceSha256": digest,
        "targetFleetSize": manifest.target_fleet_size,
        "plannedJobActions": planned_actions,
        "entraTenantId": identity["tenantIssuer"].split("/")[3],
        "targetSigningKeyArn": signer["targetKeyArn"],
    }


def transition_plan(manifest: ActivationManifest, evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the irreversible manual state-machine order with exact gates."""
    if (
        evidence.get("transitionId") != manifest.transition_id
        or evidence.get("status") != "verified-ready-for-manual-transition"
    ):
        raise RegionalActivationVerificationError("verified evidence is required before planning")
    return [
        {"order": 1, "action": "freeze-change-window", "requires": "two-independent-approvers"},
        {"order": 2, "action": "fence-source-compute", "region": manifest.source_region},
        {"order": 3, "action": "verify-source-non-serving", "requires": "direct-origins-disabled"},
        {
            "order": 4,
            "action": "activate-target-runtime-authority",
            "region": manifest.target_region,
        },
        {
            "order": 5,
            "action": "reconcile-region-local-jobs",
            "requires": "exact-dynamodb-revisions",
        },
        {
            "order": 6,
            "action": "run-target-smoke-and-consistency",
            "requires": "zero-authority-widening",
        },
        {
            "order": 7,
            "action": "compare-and-swap-stable-routing",
            "hostedZoneId": manifest.hosted_zone_id,
        },
        {
            "order": 8,
            "action": "verify-agent-and-operator-convergence",
            "targetFleetSize": manifest.target_fleet_size,
        },
        {
            "order": 9,
            "action": "seal-transition-evidence",
            "requires": "immutable-audit-counterparts",
        },
    ]


def main() -> int:
    """Verify local manifest/bundle files and print a non-mutating plan."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--now", type=int)
    arguments = parser.parse_args()
    manifest = ActivationManifest.parse(
        arguments.manifest.read_text(encoding="utf-8"), now=arguments.now
    )
    payload = arguments.evidence.read_bytes()
    verified = verify_bundle(manifest, payload, now=arguments.now)
    print(
        json.dumps(
            {"verified": verified, "plan": transition_plan(manifest, verified)},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

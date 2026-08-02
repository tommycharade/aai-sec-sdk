"""Adversarial contracts for manual regional activation authority."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_aws_regional_activation.py"
    spec = importlib.util.spec_from_file_location("aai_regional_activation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_TRANSITION = "12345678-1234-4234-8234-123456789abc"


def _authority_digest() -> str:
    authority = {
        "activationPermitted": True,
        "approvalEvidenceRef": "change/DR-123456",
        "automaticActivation": False,
        "direction": "failover",
        "expiresAt": 1200,
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "route53HostedZoneId": "Z1234567890ABC",
        "rpoSeconds": 60,
        "rtoMinutes": 30,
        "schemaVersion": 1,
        "sourceRegion": "eu-west-2",
        "stableApiDomain": "api.security.example.com",
        "stableUiDomain": "security.example.com",
        "targetFleetSize": 1000,
        "targetRegion": "eu-west-1",
        "transitionId": _TRANSITION,
    }
    return hashlib.sha256(
        json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _bundle() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "transitionId": _TRANSITION,
        "authoritySha256": _authority_digest(),
        "generatedAt": 900,
        "expiresAt": 1100,
        "sourceRegion": "eu-west-2",
        "targetRegion": "eu-west-1",
        "targetFleetSize": 1000,
        "rtoMinutes": 30,
        "rpoSeconds": 60,
        "storage": {
            "tableCount": 4,
            "allActive": True,
            "pitrEnabled": True,
            "deletionProtected": True,
            "maxReplicationSeconds": 12.5,
        },
        "identity": {
            "provider": "microsoft-entra",
            "tenantIssuer": (
                "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0"
            ),
            "recoveryPoolId": "eu-west-1_AbCdEf123",
            "signInPassed": True,
            "scimLifecyclePassed": True,
            "strongAuthenticationPassed": True,
        },
        "signer": {
            "targetKeyArn": (
                "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
            ),
            "trustConvergencePercent": 100,
            "signingPassed": True,
            "verificationPassed": True,
        },
        "audit": {
            "directionCount": 2,
            "complianceObjectLock": True,
            "bidirectionalPassed": True,
            "replicaModificationPassed": True,
        },
        "jobs": {
            "queueSource": "authoritative-dynamodb-job-records",
            "conflicts": 0,
            "plannedActions": 3,
            "checkPassed": True,
        },
        "routing": {
            "stableApiDomain": "api.security.example.com",
            "stableUiDomain": "security.example.com",
            "sourceDirectOriginDisabled": True,
            "targetDirectOriginDisabled": True,
            "currentTargetRegion": "eu-west-2",
        },
        "load": {
            "simulatedAgents": 1000,
            "p99HeartbeatMs": 400,
            "p99PolicyReadMs": 350,
            "p99DecisionWriteMs": 700,
            "errorRate": 0.001,
        },
        "dependency": {
            "testedDependencies": ["audit", "cognito", "dynamodb", "kms", "queue"],
            "failClosedPassed": True,
            "bypassObserved": False,
            "recoveryPassed": True,
        },
        "consistency": {
            "policyPassed": True,
            "identityPassed": True,
            "approvalReplayDenied": True,
            "idempotencyReplaySafe": True,
            "auditPassed": True,
            "authorityWideningObserved": False,
        },
        "backup": {
            "tableRestorePassed": True,
            "objectRecoveryPassed": True,
            "keyRecoveryPassed": True,
            "withinRtoMinutes": 22,
        },
        "operations": {
            "independentApproverCount": 2,
            "breakGlassRehearsed": True,
            "sourceFencePrepared": True,
            "failbackPlanPassed": True,
        },
    }


def _payload(value: dict[str, Any] | None = None) -> bytes:
    return json.dumps(value or _bundle(), sort_keys=True, separators=(",", ":")).encode()


def _manifest(payload: bytes, **updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "transitionId": _TRANSITION,
        "direction": "failover",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "sourceRegion": "eu-west-2",
        "targetRegion": "eu-west-1",
        "stableApiDomain": "api.security.example.com",
        "stableUiDomain": "security.example.com",
        "route53HostedZoneId": "Z1234567890ABC",
        "targetFleetSize": 1000,
        "rtoMinutes": 30,
        "rpoSeconds": 60,
        "evidenceBundle": {
            "bucketArn": "arn:aws:s3:::retained-activation-evidence",
            "key": f"regional-activation/{_TRANSITION}.json",
            "versionId": "version-123",
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
        "approvalEvidenceRef": "change/DR-123456",
        "expiresAt": 1200,
        "activationPermitted": True,
        "automaticActivation": False,
    }
    value.update(updates)
    return value


def _parsed(module: Any, payload: bytes | None = None) -> tuple[Any, bytes]:
    evidence = payload or _payload()
    manifest = module.ActivationManifest.parse(json.dumps(_manifest(evidence)), now=1000)
    return manifest, evidence


def test_complete_bundle_produces_manual_ordered_transition() -> None:
    module = _load()
    manifest, payload = _parsed(module)
    verified = module.verify_bundle(manifest, payload, now=1000)
    assert verified == {
        "status": "verified-ready-for-manual-transition",
        "transitionId": _TRANSITION,
        "direction": "failover",
        "evidenceSha256": hashlib.sha256(payload).hexdigest(),
        "targetFleetSize": 1000,
        "plannedJobActions": 3,
        "entraTenantId": "12345678-1234-1234-1234-123456789abc",
        "targetSigningKeyArn": (
            "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
        ),
        "authoritySha256": manifest.authority_sha256(),
        "approverPrincipalIds": [],
    }
    plan = module.transition_plan(manifest, verified)
    assert [step["order"] for step in plan] == list(range(1, 10))
    assert plan[1] == {
        "order": 2,
        "action": "fence-source-compute",
        "region": "eu-west-2",
    }
    assert plan[6]["action"] == "compare-and-swap-stable-routing"


def test_schema_v2_bundle_binds_witness_generation_and_two_approvers() -> None:
    module = _load()
    bundle = _bundle()
    v2_fields = {
        "schemaVersion": 2,
        "coordinationRegion": "eu-central-1",
        "journalTableName": "AaiSecRegionalTransitionJournal",
        "expectedRoutingGeneration": 0,
        "approvals": [
            {
                "principalId": "22345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-operator-a",
                "approvedAt": 990,
                "strongAuthAt": 970,
            },
            {
                "principalId": "32345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-operator-b",
                "approvedAt": 995,
                "strongAuthAt": 980,
            },
        ],
    }
    provisional_payload = _payload(bundle)
    manifest_value = _manifest(provisional_payload, **v2_fields)
    provisional = module.ActivationManifest.parse(json.dumps(manifest_value), now=1000)
    bundle["operations"].update(
        {
            "approverPrincipalIds": [approval.principal_id for approval in provisional.approvals],
            "approvalSha256": provisional.approval_sha256(),
        }
    )
    bundle["authoritySha256"] = provisional.authority_sha256()
    payload = _payload(bundle)
    manifest_value["evidenceBundle"]["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest = module.ActivationManifest.parse(json.dumps(manifest_value), now=1000)
    verified = module.verify_bundle(manifest, payload, now=1000)
    assert verified["authoritySha256"] == manifest.authority_sha256()
    assert verified["approverPrincipalIds"] == [
        "22345678-1234-4234-8234-123456789abc",
        "32345678-1234-4234-8234-123456789abc",
    ]
    substituted = copy.deepcopy(manifest_value)
    substituted["approvals"][0]["principalId"] = "42345678-1234-4234-8234-123456789abc"
    with pytest.raises(module.RegionalActivationVerificationError, match="identity differs"):
        module.verify_bundle(
            module.ActivationManifest.parse(json.dumps(substituted), now=1000),
            payload,
            now=1000,
        )
    replaced_bundle = copy.deepcopy(bundle)
    replaced_bundle["operations"]["approverPrincipalIds"][0] = (
        "42345678-1234-4234-8234-123456789abc"
    )
    replaced_payload = _payload(replaced_bundle)
    replaced_manifest = copy.deepcopy(manifest_value)
    replaced_manifest["evidenceBundle"]["sha256"] = hashlib.sha256(replaced_payload).hexdigest()
    with pytest.raises(module.RegionalActivationVerificationError, match="operational"):
        module.verify_bundle(
            module.ActivationManifest.parse(json.dumps(replaced_manifest), now=1000),
            replaced_payload,
            now=1000,
        )


def test_schema_v3_binds_exact_ingress_canaries_marker_and_routing_role() -> None:
    module = _load()
    payload = _payload()
    v3 = {
        "schemaVersion": 3,
        "coordinationRegion": "eu-central-1",
        "journalTableName": "AaiSecRegionalTransitionJournal",
        "expectedRoutingGeneration": 0,
        "approvals": [
            {
                "principalId": "22345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-operator-a",
                "approvedAt": 990,
                "strongAuthAt": 970,
            },
            {
                "principalId": "32345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-operator-b",
                "approvedAt": 995,
                "strongAuthAt": 980,
            },
        ],
        "primaryIngressStackName": "AaiSecPrimaryRegionalIngress",
        "recoveryIngressStackName": "AaiSecRecoveryRegionalIngress",
        "primaryCanaryApiDomain": "api-primary.security.example.com",
        "primaryCanaryUiDomain": "primary.security.example.com",
        "recoveryCanaryApiDomain": "api-recovery.security.example.com",
        "recoveryCanaryUiDomain": "recovery.security.example.com",
        "routingMarkerName": "routing-generation.security.example.com",
        "routingRoleArn": "arn:aws:iam::111111111111:role/AaiSecRegionalRouting",
        "routingAuthorityEvidenceRef": "change/ROUTING-AUTHORITY-123",
    }
    manifest = module.ActivationManifest.parse(json.dumps(_manifest(payload, **v3)), now=1000)
    manifest.require_routing_authority()
    original = manifest.authority_sha256()
    substituted = copy.deepcopy(v3)
    substituted["recoveryCanaryApiDomain"] = "api-other.security.example.com"
    changed = module.ActivationManifest.parse(
        json.dumps(_manifest(payload, **substituted)), now=1000
    )
    assert changed.authority_sha256() != original
    for field, value, message in [
        ("routingRoleArn", "arn:aws:iam::222222222222:user/attacker", "role ARN"),
        ("primaryIngressStackName", "AttackerStack", "stack identities"),
        ("routingMarkerName", "security.example.com", "marker"),
    ]:
        invalid = copy.deepcopy(v3)
        invalid[field] = value
        with pytest.raises(module.RegionalActivationVerificationError, match=message):
            module.ActivationManifest.parse(json.dumps(_manifest(payload, **invalid)), now=1000)


def test_schema_v4_binds_both_runtime_templates_for_reactivation() -> None:
    module = _load()
    payload = _payload()
    authority = {
        "schemaVersion": 4,
        "coordinationRegion": "eu-central-1",
        "journalTableName": "AaiSecRegionalTransitionJournal",
        "expectedRoutingGeneration": 0,
        "approvals": [
            {
                "principalId": "22345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-operator-a",
                "approvedAt": 990,
                "strongAuthAt": 970,
            },
            {
                "principalId": "32345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-operator-b",
                "approvedAt": 995,
                "strongAuthAt": 980,
            },
        ],
        "primaryIngressStackName": "AaiSecPrimaryRegionalIngress",
        "recoveryIngressStackName": "AaiSecRecoveryRegionalIngress",
        "primaryCanaryApiDomain": "api-primary.security.example.com",
        "primaryCanaryUiDomain": "primary.security.example.com",
        "recoveryCanaryApiDomain": "api-recovery.security.example.com",
        "recoveryCanaryUiDomain": "recovery.security.example.com",
        "routingMarkerName": "routing-generation.security.example.com",
        "routingRoleArn": "arn:aws:iam::111111111111:role/AaiSecRegionalRouting",
        "routingAuthorityEvidenceRef": "change/ROUTING-AUTHORITY-123",
        "primaryRuntimeStackName": "AaiSecControlPlane",
        "primaryRuntimeTemplateSha256": "b" * 64,
        "recoveryRuntimeStackName": "AaiSecPassiveRegionalCell",
        "recoveryRuntimeTemplateSha256": "c" * 64,
    }
    manifest = module.ActivationManifest.parse(
        json.dumps(_manifest(payload, **authority)), now=1000
    )
    manifest.require_reactivation_authority()
    bundle = _bundle()
    bundle["operations"].update(
        {
            "approverPrincipalIds": [approval.principal_id for approval in manifest.approvals],
            "approvalSha256": manifest.approval_sha256(),
        }
    )
    bundle["authoritySha256"] = manifest.authority_sha256()
    bound_payload = _payload(bundle)
    bound_manifest_value = _manifest(bound_payload, **authority)
    bound_manifest = module.ActivationManifest.parse(json.dumps(bound_manifest_value), now=1000)
    assert module.verify_bundle(bound_manifest, bound_payload, now=1000)[
        "approverPrincipalIds"
    ] == [approval.principal_id for approval in bound_manifest.approvals]
    forged_bundle = copy.deepcopy(bundle)
    forged_bundle["operations"]["approvalSha256"] = "0" * 64
    forged_payload = _payload(forged_bundle)
    forged_manifest_value = _manifest(forged_payload, **authority)
    with pytest.raises(module.RegionalActivationVerificationError, match="operational"):
        module.verify_bundle(
            module.ActivationManifest.parse(json.dumps(forged_manifest_value), now=1000),
            forged_payload,
            now=1000,
        )
    original = manifest.authority_sha256()
    changed_authority = copy.deepcopy(authority)
    changed_authority["primaryRuntimeTemplateSha256"] = "d" * 64
    changed = module.ActivationManifest.parse(
        json.dumps(_manifest(payload, **changed_authority)), now=1000
    )
    assert changed.authority_sha256() != original
    invalid = copy.deepcopy(authority)
    invalid["recoveryRuntimeStackName"] = "AaiSecOtherCell"
    with pytest.raises(module.RegionalActivationVerificationError, match="stack identities"):
        module.ActivationManifest.parse(json.dumps(_manifest(payload, **invalid)), now=1000)


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("storage", "maxReplicationSeconds", 61, "storage"),
        ("identity", "signInPassed", False, "identity"),
        (
            "identity",
            "tenantIssuer",
            "https://login.microsoftonline.com/common/v2.0",
            "identity",
        ),
        ("signer", "trustConvergencePercent", 99, "signer"),
        ("audit", "replicaModificationPassed", False, "audit"),
        ("jobs", "conflicts", 1, "job"),
        ("routing", "sourceDirectOriginDisabled", False, "routing"),
        ("load", "simulatedAgents", 999, "load"),
        ("load", "errorRate", 0.011, "load"),
        ("dependency", "bypassObserved", True, "dependency"),
        ("consistency", "approvalReplayDenied", False, "consistency"),
        ("backup", "keyRecoveryPassed", False, "backup"),
        ("operations", "independentApproverCount", 1, "operational"),
    ],
)
def test_bundle_fails_closed_on_each_missing_recovery_gate(
    section: str, field: str, value: object, message: str
) -> None:
    module = _load()
    bundle = copy.deepcopy(_bundle())
    bundle[section][field] = value
    payload = _payload(bundle)
    manifest, _ = _parsed(module, payload)
    with pytest.raises(module.RegionalActivationVerificationError, match=message):
        module.verify_bundle(manifest, payload, now=1000)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"automaticActivation": True}, "automatic activation prohibited"),
        ({"activationPermitted": False}, "explicitly permitted"),
        ({"sourceRegion": "eu-west-1", "targetRegion": "eu-west-2"}, "disagree"),
        ({"expiresAt": 1000}, "expired"),
        ({"expiresAt": 5000}, "too long"),
    ],
)
def test_manifest_rejects_automatic_stale_or_direction_confused_authority(
    updates: dict[str, Any], message: str
) -> None:
    module = _load()
    payload = _payload()
    with pytest.raises(module.RegionalActivationVerificationError, match=message):
        module.ActivationManifest.parse(json.dumps(_manifest(payload, **updates)), now=1000)


def test_evidence_is_exact_version_and_content_bound() -> None:
    module = _load()
    manifest, payload = _parsed(module)
    with pytest.raises(module.RegionalActivationVerificationError, match="digest differs"):
        module.verify_bundle(manifest, payload + b" ", now=1000)
    with pytest.raises(module.RegionalActivationVerificationError, match="duplicate"):
        module.ActivationManifest.parse('{"schemaVersion":1,"schemaVersion":1}', now=1000)
    bad = _manifest(payload)
    bad["evidenceBundle"]["key"] = "../unretained.json"
    with pytest.raises(module.RegionalActivationVerificationError, match="key is invalid"):
        module.ActivationManifest.parse(json.dumps(bad), now=1000)


@pytest.mark.parametrize(
    "updates",
    [
        {"approvalEvidenceRef": "change/SUBSTITUTED-999"},
        {"route53HostedZoneId": "ZATTACKER123456"},
        {"stableApiDomain": "api.attacker.example.com"},
    ],
)
def test_retained_bundle_binds_local_manifest_authority(
    updates: dict[str, Any],
) -> None:
    module = _load()
    payload = _payload()
    manifest = module.ActivationManifest.parse(json.dumps(_manifest(payload, **updates)), now=1000)
    with pytest.raises(module.RegionalActivationVerificationError, match="identity differs"):
        module.verify_bundle(manifest, payload, now=1000)


def test_failback_reverses_exact_source_and_target_regions() -> None:
    module = _load()
    payload = _payload()
    value = _manifest(
        payload,
        direction="failback",
        sourceRegion="eu-west-1",
        targetRegion="eu-west-2",
    )
    manifest = module.ActivationManifest.parse(json.dumps(value), now=1000)
    assert manifest.direction == "failback"
    assert manifest.source_region == "eu-west-1"
    assert manifest.target_region == "eu-west-2"


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("storage", "tableCount", True, "storage table count"),
        ("jobs", "plannedActions", True, "planned job actions"),
        ("load", "simulatedAgents", "1000", "simulated agents"),
        ("backup", "withinRtoMinutes", True, "backup recovery time"),
        (
            "operations",
            "independentApproverCount",
            True,
            "independent approver count",
        ),
    ],
)
def test_measurement_types_fail_closed_without_runtime_type_errors(
    section: str, field: str, value: object, message: str
) -> None:
    module = _load()
    bundle = copy.deepcopy(_bundle())
    bundle[section][field] = value
    payload = _payload(bundle)
    manifest, _ = _parsed(module, payload)
    with pytest.raises(module.RegionalActivationVerificationError, match=message):
        module.verify_bundle(manifest, payload, now=1000)

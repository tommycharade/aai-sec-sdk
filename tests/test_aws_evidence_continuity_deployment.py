"""Adversarial contracts for the evidence-continuity deployment guard."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "deploy_aws_evidence_continuity.py"
    spec = importlib.util.spec_from_file_location("aai_continuity_deploy", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(**updates: Any) -> dict[str, Any]:
    value = {
        "schemaVersion": 1,
        "primaryStackName": "AaiSecControlPlane",
        "recoveryStackName": "AaiSecAuditReplica",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "approvalEvidenceRef": "change/CONTINUITY-123",
        "activationPermitted": False,
    }
    value.update(updates)
    return value


def _completed(value: dict[str, Any] | None = None, *, error: str = "") -> Any:
    return subprocess.CompletedProcess([], 1 if error else 0, json.dumps(value or {}), error)


def test_manifest_is_exact_canonical_and_cannot_activate() -> None:
    module = _load()
    manifest = module.EvidenceContinuityManifest.parse(json.dumps(_manifest()))
    assert json.loads(manifest.canonical_json()) == _manifest()
    assert module.parameter_name(manifest.primary_stack_name).endswith("/evidence-continuity")
    with pytest.raises(module.EvidenceContinuityDeploymentError, match="duplicate"):
        module.EvidenceContinuityManifest.parse('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(module.EvidenceContinuityDeploymentError, match="prohibit activation"):
        module.EvidenceContinuityManifest.parse(json.dumps(_manifest(activationPermitted=True)))
    with pytest.raises(module.EvidenceContinuityDeploymentError, match="unreviewed stack"):
        module.EvidenceContinuityManifest.parse(
            json.dumps(_manifest(recoveryStackName="AttackerStack"))
        )


def test_deployment_environment_strips_ambient_bucket_and_identity_authority(
    monkeypatch: Any,
) -> None:
    module = _load()
    manifest = module.EvidenceContinuityManifest.parse(json.dumps(_manifest()))
    monkeypatch.setenv("PRIMARY_AUDIT_BUCKET_ARN", "arn:aws:s3:::attacker")
    monkeypatch.setenv("AUDIT_REPLICA_BUCKET_ARN", "arn:aws:s3:::attacker")
    monkeypatch.setenv("ENTRA_TENANT_ID", "attacker")
    audit = module.control_deploy.AuditRecoveryManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "replicaBucketArn": "arn:aws:s3:::recovery-audit",
                "replicaRegion": "eu-west-1",
                "recoveryEvidenceRef": "change/AUDIT-123",
            }
        )
    )
    primary, replica = module.deployment_environments(
        manifest,
        {
            "account": "111111111111",
            "primaryBucketArn": "arn:aws:s3:::primary-audit",
        },
        profile="synthetic",
        entra=None,
        audit=audit,
    )
    assert primary["AUDIT_REPLICA_BUCKET_ARN"] == "arn:aws:s3:::recovery-audit"
    assert "ENTRA_TENANT_ID" not in primary
    assert replica["PRIMARY_AUDIT_BUCKET_ARN"] == "arn:aws:s3:::primary-audit"
    assert replica["CDK_DEFAULT_ACCOUNT"] == "111111111111"


def _live_runner(rule: dict[str, Any]) -> Any:
    def runner(command: list[str], **_: Any) -> Any:
        if "get-bucket-versioning" in command:
            return _completed({"Status": "Enabled"})
        if "get-object-lock-configuration" in command:
            return _completed(
                {
                    "ObjectLockConfiguration": {
                        "ObjectLockEnabled": "Enabled",
                        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}},
                    }
                }
            )
        if "get-bucket-replication" in command:
            return _completed({"ReplicationConfiguration": {"Role": "arn:role", "Rules": [rule]}})
        raise AssertionError(command)

    return runner


def _live_rule() -> dict[str, Any]:
    return {
        "ID": "reverse",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "SourceSelectionCriteria": {"ReplicaModifications": {"Status": "Enabled"}},
        "Status": "Enabled",
        "Destination": {"Bucket": "arn:aws:s3:::primary"},
    }


def test_live_verifier_requires_exact_replica_modification_rule() -> None:
    module = _load()
    rule = _live_rule()
    assert (
        module.verify_live_direction(
            source_bucket="recovery",
            source_region="eu-west-1",
            destination_arn="arn:aws:s3:::primary",
            rule_id="reverse",
            profile="synthetic",
            runner=_live_runner(rule),
        )["status"]
        == "verified-live-immutable-replication"
    )
    rule["DeleteMarkerReplication"] = {"Status": "Enabled"}
    with pytest.raises(module.EvidenceContinuityDeploymentError, match="differs"):
        module.verify_live_direction(
            source_bucket="recovery",
            source_region="eu-west-1",
            destination_arn="arn:aws:s3:::primary",
            rule_id="reverse",
            profile="synthetic",
            runner=_live_runner(rule),
        )


def test_exact_assembly_deployment_refuses_template_change(tmp_path: Path) -> None:
    module = _load()
    template = tmp_path / "Stack.template.json"
    template.write_text("{}", encoding="utf-8")
    digest = hashlib.sha256(b"{}").hexdigest()
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        return _completed()

    module._deploy_assembly("Stack", tmp_path, template, digest, {}, runner=runner)
    assert calls[0][3:5] == [str(tmp_path), "deploy"]
    template.write_text('{"changed":true}', encoding="utf-8")
    with pytest.raises(module.EvidenceContinuityDeploymentError, match="changed"):
        module._deploy_assembly("Stack", tmp_path, template, digest, {}, runner=runner)


def test_persisted_authority_must_match_exactly() -> None:
    module = _load()
    manifest = module.EvidenceContinuityManifest.parse(json.dumps(_manifest()))
    stored = manifest.canonical_json()

    def runner(command: list[str], **_: Any) -> Any:
        if "get-parameter" in command:
            return _completed({"Parameter": {"Value": stored}})
        return _completed()

    module.persist_manifest(manifest, profile="synthetic", runner=runner)
    module.require_persisted_manifest(manifest, profile="synthetic", runner=runner)
    stored = module.EvidenceContinuityManifest.parse(
        json.dumps(_manifest(approvalEvidenceRef="change/DIFFERENT-456"))
    ).canonical_json()
    with pytest.raises(module.EvidenceContinuityDeploymentError, match="differs"):
        module.require_persisted_manifest(manifest, profile="synthetic", runner=runner)

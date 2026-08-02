"""Adversarial contracts for the AWS regional-recovery storage foundation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "manage_aws_regional_recovery.py"
    spec = importlib.util.spec_from_file_location("aai_manage_aws_regional_recovery", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "stackName": "AaiSecControlPlane",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "targetFleetSize": 1000,
        "rtoMinutes": 30,
        "rpoSeconds": 60,
        "recoveryMode": "fail-closed-active-passive",
        "approvalEvidenceRef": "DR-REVIEW-1234",
    }
    value.update(updates)
    return value


def _completed(value: dict[str, Any] | None = None, *, error: str = "") -> Any:
    return subprocess.CompletedProcess(
        [],
        1 if error else 0,
        json.dumps(value or {}),
        error,
    )


def _region(command: list[str]) -> str:
    return command[command.index("--region") + 1]


def _active_table(name: str, *, replica: bool = True, protected: bool = True) -> dict[str, Any]:
    table: dict[str, Any] = {
        "TableName": name,
        "TableStatus": "ACTIVE",
        "DeletionProtectionEnabled": protected,
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "StreamSpecification": {
            "StreamEnabled": True,
            "StreamViewType": "NEW_AND_OLD_IMAGES",
        },
    }
    if replica:
        table["Replicas"] = [{"RegionName": "eu-west-1", "ReplicaStatus": "ACTIVE"}]
    return table


def test_manifest_is_exact_bounded_and_canonical() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    assert json.loads(manifest.canonical_json()) == _manifest()
    assert module.parameter_name("AaiSecControlPlane") == (
        "/aai-sec/AaiSecControlPlane/regional-recovery"
    )
    with pytest.raises(module.RecoveryConfigurationError, match="duplicate"):
        module.RegionalRecoveryManifest.parse('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(module.RecoveryConfigurationError, match="distinct"):
        module.RegionalRecoveryManifest.parse(json.dumps(_manifest(recoveryRegion="eu-west-2")))
    with pytest.raises(module.RecoveryConfigurationError, match="recoveryMode"):
        module.RegionalRecoveryManifest.parse(json.dumps(_manifest(recoveryMode="active-active")))
    with pytest.raises(module.RecoveryConfigurationError, match="rpoSeconds"):
        module.RegionalRecoveryManifest.parse(json.dumps(_manifest(rpoSeconds=0)))
    with pytest.raises(module.RecoveryConfigurationError, match="non-secret"):
        module.RegionalRecoveryManifest.parse(
            json.dumps(_manifest(approvalEvidenceRef="review secret value"))
        )


def test_stack_outputs_require_every_recovery_identity() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    outputs = {
        "ControlTableName": "synthetic-control",
        "PresenceTableName": "synthetic-presence",
        "IdempotencyTableName": "synthetic-idempotency",
        "ScimLifecycleTableName": "synthetic-scim",
        "AuditBucketName": "synthetic-audit",
        "AuditReplicaBucketArn": "arn:aws:s3:::synthetic-replica",
        "AuditReplicaRegion": "eu-west-1",
        "RegionalPolicySigningKeyArn": (
            "arn:aws:kms:eu-west-2:111122223333:key/mrk-1234567890abcdef"
        ),
        "PolicySigningKeyArn": (
            "arn:aws:kms:eu-west-2:111122223333:key/12345678-1234-1234-1234-123456789abc"
        ),
    }

    def runner(_command: list[str], **_: Any) -> Any:
        return _completed(
            {
                "Stacks": [
                    {
                        "Outputs": [
                            {"OutputKey": key, "OutputValue": value}
                            for key, value in outputs.items()
                        ]
                    }
                ]
            }
        )

    assert module.stack_outputs(manifest, profile="synthetic", runner=runner) == outputs
    del outputs["PresenceTableName"]
    with pytest.raises(module.RecoveryConfigurationError, match="PresenceTableName"):
        module.stack_outputs(manifest, profile="synthetic", runner=runner)


def test_table_posture_requires_stream_pitr_protection_and_active_replica() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))

    def runner(command: list[str], **_: Any) -> Any:
        if "describe-table" in command:
            return _completed({"Table": _active_table("synthetic-control")})
        if "describe-continuous-backups" in command:
            return _completed(
                {
                    "ContinuousBackupsDescription": {
                        "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}
                    }
                }
            )
        raise AssertionError(command)

    assert (
        module.verify_table_posture(
            "control", "synthetic-control", manifest, profile="synthetic", runner=runner
        )["replicaStatus"]
        == "ACTIVE"
    )

    def unprotected(command: list[str], **_: Any) -> Any:
        if "describe-table" in command:
            return _completed({"Table": _active_table("synthetic-control", protected=False)})
        return runner(command)

    with pytest.raises(module.RecoveryConfigurationError, match="not recovery-ready"):
        module.verify_table_posture(
            "control", "synthetic-control", manifest, profile="synthetic", runner=unprotected
        )


def test_prepare_replica_is_bounded_and_repairs_recovery_protection() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    calls: list[list[str]] = []
    primary_describes = 0
    recovery_protected = False
    recovery_pitr = False

    def runner(command: list[str], **_: Any) -> Any:
        nonlocal primary_describes, recovery_pitr, recovery_protected
        calls.append(command)
        region = _region(command)
        if "describe-continuous-backups" in command:
            status = "ENABLED" if region == "eu-west-2" or recovery_pitr else "DISABLED"
            return _completed(
                {
                    "ContinuousBackupsDescription": {
                        "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": status}
                    }
                }
            )
        if "describe-table" in command and region == "eu-west-2":
            primary_describes += 1
            return _completed(
                {"Table": _active_table("synthetic-control", replica=primary_describes >= 2)}
            )
        if "describe-table" in command and region == "eu-west-1":
            return _completed(
                {"Table": _active_table("synthetic-control", protected=recovery_protected)}
            )
        if "update-table" in command:
            if "--deletion-protection-enabled" in command:
                recovery_protected = True
            return _completed()
        if "update-continuous-backups" in command:
            recovery_pitr = True
            return _completed()
        raise AssertionError(command)

    module.prepare_table_replica(
        "control",
        "synthetic-control",
        manifest,
        profile="synthetic",
        runner=runner,
        sleeper=lambda _seconds: None,
        clock=iter([0.0, 1.0]).__next__,
    )
    rendered = [" ".join(call) for call in calls]
    assert any("--replica-updates" in call for call in rendered)
    assert any("--deletion-protection-enabled" in call for call in rendered)
    assert any("update-continuous-backups" in call for call in rendered)


def test_canary_binds_exact_content_and_proves_create_and_delete() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    stored: dict[str, Any] = {}
    deleted = False

    def runner(command: list[str], **_: Any) -> Any:
        nonlocal deleted
        if "put-item" in command:
            stored.update(json.loads(command[command.index("--item") + 1]))
            return _completed()
        if "delete-item" in command:
            values = json.loads(command[command.index("--expression-attribute-values") + 1])
            assert values[":digest"] == stored["digest"]
            deleted = True
            return _completed()
        if "get-item" in command:
            return _completed({} if deleted else {"Item": stored})
        raise AssertionError(command)

    clock = iter([0.0, 0.25, 0.25, 0.5]).__next__
    result = module.replication_canary(
        "control",
        "synthetic-control",
        manifest,
        profile="synthetic",
        runner=runner,
        sleeper=lambda _seconds: None,
        clock=clock,
    )
    assert result["createReplicationSeconds"] == 0.25
    assert result["deleteReplicationSeconds"] == 0.25
    assert stored["kind"] == {"S": "regional-recovery-canary"}
    assert stored["sk"] == {"S": "CANARY"}


def test_staged_signing_key_must_not_be_single_region_or_active_authority() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    arn = "arn:aws:kms:eu-west-2:111122223333:key/mrk-1234567890abcdef"

    def runner(_command: list[str], **_: Any) -> Any:
        return _completed(
            {
                "KeyMetadata": {
                    "Arn": arn,
                    "MultiRegion": True,
                    "KeySpec": "ECC_NIST_P256",
                    "KeyUsage": "SIGN_VERIFY",
                    "KeyState": "Enabled",
                    "MultiRegionConfiguration": {"MultiRegionKeyType": "PRIMARY"},
                }
            }
        )

    assert module.verify_staged_signing_key(arn, manifest, profile="synthetic", runner=runner) == {
        "keyArn": arn,
        "status": "STAGED_NOT_ACTIVE",
    }

    def regional(_command: list[str], **_: Any) -> Any:
        value = runner([], **_).stdout
        payload = json.loads(value)
        payload["KeyMetadata"]["MultiRegion"] = False
        return _completed(payload)

    with pytest.raises(module.RecoveryConfigurationError, match="invalid"):
        module.verify_staged_signing_key(arn, manifest, profile="synthetic", runner=regional)


def test_signing_replica_shares_key_material_and_remains_staged() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    key_id = "mrk-1234567890abcdef1234567890abcdef"
    primary_arn = f"arn:aws:kms:eu-west-2:111122223333:key/{key_id}"
    replica_arn = f"arn:aws:kms:eu-west-1:111122223333:key/{key_id}"

    def metadata(arn: str, key_type: str) -> dict[str, Any]:
        configuration: dict[str, Any] = {
            "MultiRegionKeyType": key_type,
            "PrimaryKey": {"Arn": primary_arn, "Region": "eu-west-2"},
            "ReplicaKeys": [{"Arn": replica_arn, "Region": "eu-west-1"}],
        }
        return {
            "KeyMetadata": {
                "Arn": arn,
                "KeyId": key_id,
                "KeySpec": "ECC_NIST_P256",
                "KeyUsage": "SIGN_VERIFY",
                "KeyState": "Enabled",
                "MultiRegionConfiguration": configuration,
            }
        }

    def runner(command: list[str], **_: Any) -> Any:
        return _completed(
            metadata(
                primary_arn if _region(command) == "eu-west-2" else replica_arn,
                "PRIMARY" if _region(command) == "eu-west-2" else "REPLICA",
            )
        )

    result = module.verify_signing_replica(
        primary_arn, replica_arn, manifest, profile="synthetic", runner=runner
    )
    assert result["keyId"] == key_id
    assert result["status"] == "STAGED_NOT_ACTIVE"

    def wrong_material(command: list[str], **_: Any) -> Any:
        value = runner(command)
        payload = json.loads(value.stdout)
        if _region(command) == "eu-west-1":
            payload["KeyMetadata"]["KeyId"] = "mrk-ffffffffffffffffffffffffffffffff"
        return _completed(payload)

    with pytest.raises(module.RecoveryConfigurationError, match="inconsistent"):
        module.verify_signing_replica(
            primary_arn,
            replica_arn,
            manifest,
            profile="synthetic",
            runner=wrong_material,
        )

    def malformed_relationship(command: list[str], **_: Any) -> Any:
        value = runner(command)
        payload = json.loads(value.stdout)
        if _region(command) == "eu-west-1":
            payload["KeyMetadata"]["MultiRegionConfiguration"]["PrimaryKey"] = "forged"
        return _completed(payload)

    with pytest.raises(module.RecoveryConfigurationError, match="inconsistent"):
        module.verify_signing_replica(
            primary_arn,
            replica_arn,
            manifest,
            profile="synthetic",
            runner=malformed_relationship,
        )


def test_trust_deployer_strips_ambient_authority(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))
    key_arn = "arn:aws:kms:eu-west-2:111122223333:key/mrk-1234567890abcdef1234567890abcdef"
    monkeypatch.setenv("REGIONAL_POLICY_SIGNING_KEY_ARN", "unsafe-ambient")
    calls: list[tuple[list[str], dict[str, str]]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        calls.append((command, kwargs["env"]))
        return _completed()

    module.deploy_signing_replica(key_arn, manifest, profile="synthetic", runner=runner)
    assert [call[0][:2] for call in calls] == [["npm", "run"], ["npx", "cdk"]]
    assert all(
        environment["REGIONAL_POLICY_SIGNING_KEY_ARN"] == key_arn for _, environment in calls
    )
    assert all(environment["CDK_DEFAULT_REGION"] == "eu-west-1" for _, environment in calls)


def test_later_trust_phase_requires_exact_persisted_authority() -> None:
    module = _load()
    manifest = module.RegionalRecoveryManifest.parse(json.dumps(_manifest()))

    def runner(_command: list[str], **_: Any) -> Any:
        return _completed({"Parameter": {"Value": manifest.canonical_json()}})

    assert module.load_persisted_manifest(manifest, profile="synthetic", runner=runner) == manifest
    changed = module.RegionalRecoveryManifest.parse(
        json.dumps(_manifest(approvalEvidenceRef="DR-REVIEW-CHANGED"))
    )
    with pytest.raises(module.RecoveryConfigurationError, match="differs"):
        module.load_persisted_manifest(changed, profile="synthetic", runner=runner)


def test_lambda_policy_signer_accepts_exact_multi_region_key_arn() -> None:
    path = (
        Path(__file__).parents[1] / "infra" / "aws-control-plane" / "lambda" / "policy_signing.py"
    )
    spec = importlib.util.spec_from_file_location("aai_policy_signing_mrk", path)
    assert spec and spec.loader
    signing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signing)
    key_arn = "arn:aws:kms:eu-west-2:111122223333:key/mrk-1234567890abcdef1234567890abcdef"

    class Kms:
        def sign(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["KeyId"] == key_arn
            return {
                "KeyId": key_arn,
                "SigningAlgorithm": "ECDSA_SHA_256",
                "Signature": b"synthetic-signature",
            }

    bundle = signing.sign_policy_bundle(Kms(), key_arn, "tenant-a", "policy-a", 1, {"tools": {}}, 1)
    assert bundle["integrity"]["keyId"] == key_arn


def test_iac_stages_global_table_prerequisites_without_switching_signer() -> None:
    stack = (
        Path(__file__).parents[1]
        / "infra"
        / "aws-control-plane"
        / "lib"
        / "aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert stack.count("stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES") == 4
    assert stack.count("deletionProtection: true") >= 4
    assert 'new kms.Key(this, "RegionalPolicySigningKey"' in stack
    assert "multiRegion: true" in stack
    assert "POLICY_SIGNING_KEY_ARN: policySigningKey.keyArn" in stack
    assert not any(
        line.strip() == "POLICY_SIGNING_KEY_ARN: regionalPolicySigningKey.keyArn,"
        for line in stack.splitlines()
    )
    recovery_stack = (
        Path(__file__).parents[1]
        / "infra"
        / "aws-control-plane"
        / "lib"
        / "regional-recovery-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'new kms.CfnReplicaKey(this, "RegionalPolicySigningReplica"' in recovery_stack
    assert 'value: "staged-not-active"' in recovery_stack
    assert 'value: "false"' in recovery_stack

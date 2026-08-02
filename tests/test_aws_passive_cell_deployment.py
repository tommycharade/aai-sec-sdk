"""Adversarial contracts for the passive-cell provider-state deployment guard."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    scripts = Path(__file__).parents[1] / "scripts"
    sys.path.insert(0, str(scripts))
    path = scripts / "deploy_aws_passive_cell.py"
    spec = importlib.util.spec_from_file_location("aai_deploy_passive_cell", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "passiveStackName": "AaiSecPassiveRegionalCell",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "recoveryUserPoolId": "eu-west-1_AbCdEf123",
        "recoveryUserPoolClientId": "abcdefghij1234567890",
        "approvalEvidenceRef": "DR-PASSIVE-123",
        "identityAcceptanceEvidenceRef": "ENTRA-RECOVERY-123",
        "activationPermitted": False,
    }
    value.update(updates)
    return value


def _regional(module: Any) -> Any:
    return module.recovery.RegionalRecoveryManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "stackName": "AaiSecControlPlane",
                "primaryRegion": "eu-west-2",
                "recoveryRegion": "eu-west-1",
                "targetFleetSize": 1000,
                "rtoMinutes": 30,
                "rpoSeconds": 60,
                "recoveryMode": "fail-closed-active-passive",
                "approvalEvidenceRef": "DR-RECOVERY-123",
            }
        )
    )


def _completed(value: dict[str, Any] | None = None, *, error: str = "") -> Any:
    return subprocess.CompletedProcess([], 1 if error else 0, json.dumps(value or {}), error)


def test_manifest_is_exact_canonical_and_prohibits_activation() -> None:
    module = _load()
    manifest = module.PassiveCellManifest.parse(json.dumps(_manifest()))
    assert json.loads(manifest.canonical_json()) == _manifest()
    assert module.parameter_name(manifest.stack_name) == (
        "/aai-sec/AaiSecPassiveRegionalCell/passive-cell"
    )
    with pytest.raises(module.PassiveCellDeploymentError, match="duplicate"):
        module.PassiveCellManifest.parse('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(module.PassiveCellDeploymentError, match="prohibit activation"):
        module.PassiveCellManifest.parse(json.dumps(_manifest(activationPermitted=True)))
    with pytest.raises(module.PassiveCellDeploymentError, match="wrong Region"):
        module.PassiveCellManifest.parse(
            json.dumps(_manifest(recoveryUserPoolId="eu-west-2_AbCdEf123"))
        )
    with pytest.raises(module.PassiveCellDeploymentError, match="reviewed passive stack"):
        module.PassiveCellManifest.parse(json.dumps(_manifest(passiveStackName="OtherStack")))


def test_recovery_identity_requires_protected_pool_entra_client_and_tenant_issuer() -> None:
    module = _load()
    manifest = module.PassiveCellManifest.parse(json.dumps(_manifest()))
    state = {"entra": "configured", "scim": "configured", "issuer": True}

    def runner(command: list[str], **_: Any) -> Any:
        if "describe-stacks" in command:
            return _completed(
                {
                    "Stacks": [
                        {
                            "Outputs": [
                                {
                                    "OutputKey": "MicrosoftEntraIdStatus",
                                    "OutputValue": state["entra"],
                                },
                                {
                                    "OutputKey": "MicrosoftEntraScimStatus",
                                    "OutputValue": state["scim"],
                                },
                                {
                                    "OutputKey": "UserPoolId",
                                    "OutputValue": "eu-west-2_Primary123",
                                },
                            ]
                        }
                    ]
                }
            )
        if "describe-user-pool-client" in command:
            return _completed(
                {
                    "UserPoolClient": {
                        "ClientId": manifest.user_pool_client_id,
                        "SupportedIdentityProviders": ["MicrosoftEntraID"],
                    }
                }
            )
        if "describe-user-pool" in command:
            pool_id = command[command.index("--user-pool-id") + 1]
            return _completed(
                {
                    "UserPool": {
                        "Id": pool_id,
                        "DeletionProtection": "ACTIVE",
                        "MfaConfiguration": "ON",
                        "Policies": {"PasswordPolicy": {"MinimumLength": 16}},
                        "UsernameConfiguration": {"CaseSensitive": False},
                    }
                }
            )
        if "describe-identity-provider" in command:
            issuer = (
                "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0"
                if state["issuer"]
                else "https://login.microsoftonline.com/common/v2.0"
            )
            return _completed(
                {
                    "IdentityProvider": {
                        "ProviderType": "OIDC",
                        "ProviderDetails": {"oidc_issuer": issuer},
                    }
                }
            )
        raise AssertionError(command)

    evidence = module.verify_recovery_identity(
        manifest, primary_stack_name="AaiSecControlPlane", profile="synthetic", runner=runner
    )
    assert evidence["status"] == "configured-not-activated"
    state["issuer"] = False
    with pytest.raises(module.PassiveCellDeploymentError, match="tenant-specific"):
        module.verify_recovery_identity(
            manifest,
            primary_stack_name="AaiSecControlPlane",
            profile="synthetic",
            runner=runner,
        )
    state["issuer"] = True
    state["entra"] = "not-configured"
    with pytest.raises(module.PassiveCellDeploymentError, match="not configured"):
        module.verify_recovery_identity(
            manifest,
            primary_stack_name="AaiSecControlPlane",
            profile="synthetic",
            runner=runner,
        )


def test_deployment_environment_ignores_ambient_authority(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.PassiveCellManifest.parse(json.dumps(_manifest()))
    regional = _regional(module)
    monkeypatch.setenv("RECOVERY_CONTROL_TABLE", "attacker-table")
    monkeypatch.setenv("RECOVERY_POLICY_SIGNING_KEY_ARN", "arn:attacker")
    monkeypatch.setenv("RECOVERY_CELL_MODE", "active")
    monkeypatch.setenv("RECOVERY_ACTIVATION_EVIDENCE_SHA256", "a" * 64)
    monkeypatch.setenv("ENTRA_TENANT_ID", "12345678-1234-4234-8234-123456789abc")
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", "attacker")
    monkeypatch.setenv("ENTRA_STRONG_AUTH_ENFORCED", "true")
    outputs = {
        "ControlTableName": "control",
        "PresenceTableName": "presence",
        "IdempotencyTableName": "idempotency",
        "ScimLifecycleTableName": "scim",
        "AuditReplicaBucketArn": "arn:aws:s3:::audit-replica",
    }
    trust = {
        "RegionalPolicySigningReplicaKeyArn": (
            "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
        )
    }
    environment = module._deployment_environment(manifest, regional, outputs, trust, "111111111111")
    assert environment["RECOVERY_CONTROL_TABLE"] == "control"
    assert environment["RECOVERY_AUDIT_BUCKET"] == "audit-replica"
    assert (
        environment["RECOVERY_POLICY_SIGNING_KEY_ARN"]
        == trust["RegionalPolicySigningReplicaKeyArn"]
    )
    assert "CDK_DEFAULT_ACCOUNT" not in environment
    assert environment["RECOVERY_CELL_MODE"] == "standby"
    assert "RECOVERY_ACTIVATION_EVIDENCE_SHA256" not in environment
    assert "ENTRA_TENANT_ID" not in environment


def test_persisted_authority_must_match_exactly() -> None:
    module = _load()
    manifest = module.PassiveCellManifest.parse(json.dumps(_manifest()))
    stored = manifest.canonical_json()
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        if "get-parameter" in command:
            return _completed({"Parameter": {"Value": stored}})
        return _completed()

    module.persist_manifest(manifest, profile="synthetic", runner=runner)
    module.require_persisted_manifest(manifest, profile="synthetic", runner=runner)
    assert any("put-parameter" in command for command in calls)
    stored = module.PassiveCellManifest.parse(
        json.dumps(_manifest(approvalEvidenceRef="DIFFERENT"))
    ).canonical_json()
    with pytest.raises(module.PassiveCellDeploymentError, match="differs"):
        module.require_persisted_manifest(manifest, profile="synthetic", runner=runner)


def test_deploy_invokes_only_the_verified_passive_assembly(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.PassiveCellManifest.parse(json.dumps(_manifest()))
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        return _completed()

    template = b'{"verified":true}'
    digest = module.hashlib.sha256(template).hexdigest()
    monkeypatch.setattr(module.Path, "read_bytes", lambda *_args, **_kw: template)
    module.deploy(
        manifest,
        {"RECOVERY_REGION": "eu-west-1"},
        digest,
        runner=runner,
    )
    rendered = " ".join(calls[0])
    assert "cdk.out" in rendered
    assert "ts-node" not in rendered
    assert "AaiSecPassiveRegionalCell" in calls[0]
    assert "destroy" not in calls[0]
    with pytest.raises(module.PassiveCellDeploymentError, match="changed after verification"):
        module.deploy(
            manifest,
            {"RECOVERY_REGION": "eu-west-1"},
            "0" * 64,
            runner=runner,
        )


def test_prepare_synth_derives_provider_state_and_runs_independent_verifier(
    monkeypatch: Any,
) -> None:
    module = _load()
    manifest = module.PassiveCellManifest.parse(json.dumps(_manifest()))
    regional = _regional(module)
    outputs = {
        "ControlTableName": "control",
        "PresenceTableName": "presence",
        "IdempotencyTableName": "idempotency",
        "ScimLifecycleTableName": "scim",
        "AuditReplicaBucketArn": "arn:aws:s3:::audit-replica",
        "RegionalPolicySigningKeyArn": (
            "arn:aws:kms:eu-west-2:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
        ),
    }
    trust = {
        "RegionalPolicySigningReplicaKeyArn": (
            "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
        )
    }
    posture: list[str] = []
    monkeypatch.setattr(module.recovery, "load_persisted_manifest", lambda *_args, **_kw: regional)
    monkeypatch.setattr(module.recovery, "stack_outputs", lambda *_args, **_kw: outputs)
    monkeypatch.setattr(module.recovery, "recovery_stack_outputs", lambda *_args, **_kw: trust)
    monkeypatch.setattr(
        module.recovery,
        "verify_table_posture",
        lambda role, *_args, **_kw: posture.append(role),
    )
    monkeypatch.setattr(module.recovery, "verify_signing_replica", lambda *_args, **_kw: {})
    monkeypatch.setattr(
        module,
        "verify_recovery_identity",
        lambda *_args, **_kw: {"status": "configured-not-activated"},
    )
    monkeypatch.setattr(module.Path, "read_bytes", lambda *_args, **_kw: b"{}")
    monkeypatch.setattr(
        module.template_verifier,
        "verify",
        lambda value: {"status": "verified-not-serving", "size": len(value)},
    )

    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        if "get-caller-identity" in command:
            return _completed({"Account": "111111111111"})
        return _completed()

    evidence = module.prepare_synth(manifest, regional, profile="synthetic", runner=runner)
    assert sorted(posture) == ["control", "idempotency", "presence", "scim"]
    assert evidence["template"]["status"] == "verified-not-serving"
    assert evidence["template"]["templateSha256"] == module.hashlib.sha256(b"{}").hexdigest()
    assert evidence["environment"]["AWS_PROFILE"] == "synthetic"
    assert evidence["environment"]["AWS_REGION"] == "eu-west-1"
    assert any(command[:3] == ["npm", "run", "synth:passive"] for command in calls)

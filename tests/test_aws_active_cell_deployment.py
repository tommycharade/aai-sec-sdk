"""Adversarial contracts for the one-step AWS regional transition guard."""

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
    path = Path(__file__).parents[1] / "scripts" / "deploy_aws_active_cell.py"
    spec = importlib.util.spec_from_file_location("aai_deploy_active_cell", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _completed(value: dict[str, Any] | None = None, *, error: str = "") -> Any:
    return subprocess.CompletedProcess([], 1 if error else 0, json.dumps(value or {}), error)


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
                "approvalEvidenceRef": "change/RECOVERY-123",
            }
        )
    )


def test_source_discovery_is_stable_paginated_bounded_and_digest_bound() -> None:
    module = _load()
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        if "describe-stacks" in command:
            return _completed({"Stacks": [{"StackStatus": "UPDATE_COMPLETE"}]})
        if "--next-token" not in command:
            return _completed(
                {
                    "StackResourceSummaries": [
                        {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "fn-b"},
                        {
                            "ResourceType": "AWS::Lambda::EventSourceMapping",
                            "PhysicalResourceId": "map-a",
                        },
                        {"ResourceType": "AWS::S3::Bucket", "PhysicalResourceId": "ignored"},
                    ],
                    "NextToken": "page-2",
                }
            )
        return _completed(
            {
                "StackResourceSummaries": [
                    {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "fn-a"},
                    {"ResourceType": "AWS::Events::Rule", "PhysicalResourceId": "rule-a"},
                ]
            }
        )

    resources = module.discover_source_resources(
        _regional(module), profile="synthetic", runner=runner
    )
    assert resources.functions == ("fn-a", "fn-b")
    assert resources.event_source_mappings == ("map-a",)
    assert resources.event_rules == ("rule-a",)
    assert resources.sha256() == hashlib.sha256(resources.canonical_json().encode()).hexdigest()
    assert any("--next-token" in call for call in calls)


def test_source_discovery_rejects_unstable_or_duplicate_authority() -> None:
    module = _load()

    def unstable(command: list[str], **_: Any) -> Any:
        assert "describe-stacks" in command
        return _completed({"Stacks": [{"StackStatus": "UPDATE_IN_PROGRESS"}]})

    with pytest.raises(module.ActiveCellDeploymentError, match="not stable"):
        module.discover_source_resources(_regional(module), profile="synthetic", runner=unstable)

    def duplicate(command: list[str], **_: Any) -> Any:
        if "describe-stacks" in command:
            return _completed({"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]})
        return _completed(
            {
                "StackResourceSummaries": [
                    {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "fn-a"},
                    {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "fn-a"},
                ]
            }
        )

    with pytest.raises(module.ActiveCellDeploymentError, match="duplicated"):
        module.discover_source_resources(_regional(module), profile="synthetic", runner=duplicate)


def test_fence_orders_ingress_before_concurrency_and_independently_verifies() -> None:
    module = _load()
    resources = module.SourceResources(("fn-a",), ("map-a",), ("rule-a",))
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        if "describe-rule" in command:
            return _completed({"State": "DISABLED"})
        if "get-event-source-mapping" in command:
            return _completed({"UUID": "map-a", "State": "Disabled"})
        if "get-function-concurrency" in command:
            return _completed({"ReservedConcurrentExecutions": 0})
        return _completed()

    result = module.fence_source(resources, profile="synthetic", region="eu-west-2", runner=runner)
    mutations = [
        call
        for call in calls
        if any(
            operation in call
            for operation in (
                "disable-rule",
                "update-event-source-mapping",
                "put-function-concurrency",
            )
        )
    ]
    assert [
        next(
            item
            for item in call
            if item in {"disable-rule", "update-event-source-mapping", "put-function-concurrency"}
        )
        for call in mutations
    ] == [
        "disable-rule",
        "update-event-source-mapping",
        "put-function-concurrency",
    ]
    assert result["status"] == "source-fence-verified"
    assert result["resourceSetSha256"] == resources.sha256()


def test_partial_fence_attempts_bounded_set_but_never_claims_success() -> None:
    module = _load()
    resources = module.SourceResources(("fn-a", "fn-b"), ("map-a",), ("rule-a",))
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        if "update-event-source-mapping" in command:
            return _completed(error="synthetic mutation failure")
        return _completed()

    with pytest.raises(module.ActiveCellDeploymentError, match="mapping:map-a"):
        module.fence_source(resources, profile="synthetic", region="eu-west-2", runner=runner)
    assert sum("put-function-concurrency" in call for call in calls) == 2
    assert not any("get-function-concurrency" in call for call in calls)


def test_active_environment_uses_persisted_identity_and_rejects_substitution(
    monkeypatch: Any,
) -> None:
    module = _load()
    regional = _regional(module)
    passive_cell = type("Passive", (), {})()
    manifest = type("Activation", (), {"evidence": type("Evidence", (), {"sha256": "a" * 64})()})()
    key = "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
    entra = module.control_plane.EntraDeploymentManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "entraTenantId": "12345678-1234-1234-1234-123456789abc",
                "entraClientId": "22345678-1234-1234-1234-123456789abc",
                "entraClientSecretName": "synthetic/oidc",
                "aaiTenantId": "synthetic-enterprise",
                "entraScimTokenSecretName": "synthetic/scim",
                "strongAuthenticationEnforced": True,
                "conditionalAccessEvidenceRef": "test/CA-123",
            }
        )
    )
    monkeypatch.setattr(module.recovery, "stack_outputs", lambda *_args, **_kw: {"x": "y"})
    monkeypatch.setattr(
        module.recovery,
        "recovery_stack_outputs",
        lambda *_args, **_kw: {"RegionalPolicySigningReplicaKeyArn": key},
    )
    monkeypatch.setattr(
        module.control_plane, "load_persisted_manifest", lambda *_args, **_kw: entra
    )
    monkeypatch.setattr(
        module.passive,
        "_deployment_environment",
        lambda *_args, **_kw: {"RECOVERY_POLICY_SIGNING_KEY_ARN": key},
    )
    monkeypatch.setattr(module, "_aws", lambda *_args, **_kw: {"Account": "111111111111"})
    verified = {"entraTenantId": entra.entra_tenant_id, "targetSigningKeyArn": key}
    environment = module.active_environment(
        manifest, regional, passive_cell, verified, profile="synthetic"
    )
    assert environment["RECOVERY_CELL_MODE"] == "active"
    assert environment["RECOVERY_ACTIVATION_EVIDENCE_SHA256"] == "a" * 64
    assert environment["ENTRA_TENANT_ID"] == entra.entra_tenant_id
    with pytest.raises(module.ActiveCellDeploymentError, match="Entra tenant differs"):
        module.active_environment(
            manifest,
            regional,
            passive_cell,
            {**verified, "entraTenantId": "32345678-1234-1234-1234-123456789abc"},
            profile="synthetic",
        )


def test_target_deploy_uses_only_exact_verified_assembly(monkeypatch: Any) -> None:
    module = _load()
    calls: list[list[str]] = []
    payload = b'{"verified":true}'
    monkeypatch.setattr(module.Path, "read_bytes", lambda *_args, **_kw: payload)

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        return _completed()

    module.deploy_active_template(
        "AaiSecPassiveRegionalCell",
        {"RECOVERY_CELL_MODE": "active"},
        hashlib.sha256(payload).hexdigest(),
        runner=runner,
    )
    assert "cdk.out" in calls[0]
    assert "deploy" in calls[0]
    assert "ts-node" not in calls[0]
    assert not any(term in calls[0] for term in ("route53", "cloudfront", "globalaccelerator"))
    with pytest.raises(module.ActiveCellDeploymentError, match="changed after verification"):
        module.deploy_active_template(
            "AaiSecPassiveRegionalCell",
            {},
            "0" * 64,
            runner=runner,
        )


def test_command_surface_exposes_no_routing_or_combined_failover() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "deploy_aws_active_cell.py").read_text(
        encoding="utf-8"
    )
    assert 'choices=("check", "fence-source", "activate-target")' in source
    assert "route53" not in source.lower()
    assert "provider_preflight(" in source
    assert source.index("provider_preflight(") < source.index(
        "fence_source(", source.index("def main")
    )

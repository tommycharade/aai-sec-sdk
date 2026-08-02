"""Adversarial contracts for the one-step AWS regional transition guard."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
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


def _activation(module: Any) -> Any:
    return module.activation.ActivationManifest.parse(
        json.dumps(
            {
                "schemaVersion": 2,
                "transitionId": "12345678-1234-4234-8234-123456789abc",
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
                    "bucketArn": "arn:aws:s3:::synthetic-retained-evidence",
                    "key": "regional-activation/transition.json",
                    "versionId": "version-1",
                    "sha256": "a" * 64,
                },
                "approvalEvidenceRef": "change/DR-1234",
                "expiresAt": 1200,
                "activationPermitted": True,
                "automaticActivation": False,
                "coordinationRegion": "eu-central-1",
                "journalTableName": "AaiSecRegionalTransitionJournal",
                "expectedRoutingGeneration": 0,
                "approvals": [
                    {
                        "principalId": "22345678-1234-4234-8234-123456789abc",
                        "evidenceRef": "entra/operator-a",
                        "approvedAt": 990,
                        "strongAuthAt": 970,
                    },
                    {
                        "principalId": "32345678-1234-4234-8234-123456789abc",
                        "evidenceRef": "entra/operator-b",
                        "approvedAt": 995,
                        "strongAuthAt": 980,
                    },
                ],
            }
        ),
        now=1000,
    )


def _active_environment() -> dict[str, str]:
    return {
        "RECOVERY_ACTIVATION_EVIDENCE_SHA256": "a" * 64,
        "RECOVERY_POLICY_SIGNING_KEY_ARN": (
            "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
        ),
        "ENTRA_TENANT_ID": "12345678-1234-4234-8234-123456789abc",
        "ENTRA_AAI_TENANT_ID": "synthetic-enterprise",
    }


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


def test_source_reactivation_plan_is_template_bound_and_exactly_restored() -> None:
    module = _load()
    resources = module.SourceResources(
        ("fn-default", "fn-reserved"),
        ("map-enabled", "map-disabled"),
        ("rule-enabled", "rule-disabled"),
    )
    template = {
        "Resources": {
            "DefaultFunction": {"Type": "AWS::Lambda::Function", "Properties": {}},
            "ReservedFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {"ReservedConcurrentExecutions": 7},
            },
            "EnabledMapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {},
            },
            "DisabledMapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {"Enabled": False},
            },
            "EnabledRule": {"Type": "AWS::Events::Rule", "Properties": {}},
            "DisabledRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {"State": "DISABLED"},
            },
        }
    }
    identities = [
        ("DefaultFunction", "AWS::Lambda::Function", "fn-default"),
        ("ReservedFunction", "AWS::Lambda::Function", "fn-reserved"),
        ("EnabledMapping", "AWS::Lambda::EventSourceMapping", "map-enabled"),
        ("DisabledMapping", "AWS::Lambda::EventSourceMapping", "map-disabled"),
        ("EnabledRule", "AWS::Events::Rule", "rule-enabled"),
        ("DisabledRule", "AWS::Events::Rule", "rule-disabled"),
    ]
    mutations: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        if "get-template" in command:
            return _completed(
                {"TemplateBody": template, "StagesAvailable": ["Original", "Processed"]}
            )
        if "list-stack-resources" in command:
            return _completed(
                {
                    "StackResourceSummaries": [
                        {
                            "LogicalResourceId": logical,
                            "ResourceType": kind,
                            "PhysicalResourceId": physical,
                        }
                        for logical, kind, physical in identities
                    ]
                }
            )
        if any(
            operation in command
            for operation in (
                "delete-function-concurrency",
                "put-function-concurrency",
                "update-event-source-mapping",
                "enable-rule",
                "disable-rule",
            )
        ):
            mutations.append(command)
            return _completed()
        if "get-function-concurrency" in command:
            name = command[command.index("--function-name") + 1]
            return _completed({} if name == "fn-default" else {"ReservedConcurrentExecutions": 7})
        if "get-event-source-mapping" in command:
            mapping = command[command.index("--uuid") + 1]
            return _completed(
                {"UUID": mapping, "State": "Enabled" if mapping == "map-enabled" else "Disabled"}
            )
        if "describe-rule" in command:
            rule = command[command.index("--name") + 1]
            return _completed(
                {"Name": rule, "State": "ENABLED" if rule == "rule-enabled" else "DISABLED"}
            )
        raise AssertionError(command)

    plan = module.discover_source_reactivation_plan(
        resources,
        stack_name="AaiSecControlPlane",
        region="eu-west-2",
        profile="synthetic",
        runner=runner,
    )
    result = module.reactivate_source(plan, profile="synthetic", runner=runner)
    assert result["status"] == "source-runtime-reactivated"
    assert len(plan.sha256()) == 64
    assert "delete-function-concurrency" in mutations[0]
    assert "put-function-concurrency" in mutations[1]
    assert "--enabled" in mutations[2]
    assert "--no-enabled" in mutations[3]
    assert "enable-rule" in mutations[4]
    assert "disable-rule" in mutations[5]


def test_source_reactivation_rejects_dynamic_or_substituted_template_state() -> None:
    module = _load()
    resources = module.SourceResources(("fn",), (), ())

    def runner(command: list[str], **_: Any) -> Any:
        if "get-template" in command:
            return _completed(
                {
                    "TemplateBody": {
                        "Resources": {
                            "Function": {
                                "Type": "AWS::Lambda::Function",
                                "Properties": {"ReservedConcurrentExecutions": {"Ref": "Limit"}},
                            }
                        }
                    },
                    "StagesAvailable": ["Processed"],
                }
            )
        return _completed(
            {
                "StackResourceSummaries": [
                    {
                        "LogicalResourceId": "Function",
                        "ResourceType": "AWS::Lambda::Function",
                        "PhysicalResourceId": "fn",
                    }
                ]
            }
        )

    with pytest.raises(module.ActiveCellDeploymentError, match="safe literal"):
        module.discover_source_reactivation_plan(
            resources,
            stack_name="AaiSecControlPlane",
            region="eu-west-2",
            profile="synthetic",
            runner=runner,
        )


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
    manifest = type(
        "Activation",
        (),
        {
            "evidence": type("Evidence", (), {"sha256": "a" * 64})(),
            "stable_ui_domain": "security.example.com",
        },
    )()
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
    assert environment["RECOVERY_STABLE_UI_ORIGIN"] == "https://security.example.com"
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


def test_target_deployment_failure_leaves_journal_in_progress(monkeypatch: Any) -> None:
    module = _load()
    phases: list[tuple[str, str]] = []

    def advance(*_args: Any, expected_phase: str, next_phase: str, **_kwargs: Any) -> Any:
        phases.append((expected_phase, next_phase))
        return {"claim": "advanced", "journal": {"phase": next_phase}}

    monkeypatch.setattr(module.journal, "advance_phase", advance)
    monkeypatch.setattr(
        module,
        "verify_source_fence",
        lambda *_args, **_kwargs: {"status": "source-fence-verified"},
    )
    monkeypatch.setattr(
        module,
        "deploy_active_template",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            module.ActiveCellDeploymentError("synthetic deployment failure")
        ),
    )
    with pytest.raises(module.ActiveCellDeploymentError, match="synthetic deployment"):
        module.activate_target_step(
            object(),
            SimpleNamespace(source_region="eu-west-2"),
            module.SourceResources(("fn",), (), ()),
            SimpleNamespace(stack_name="AaiSecPassiveRegionalCell"),
            {},
            "a" * 64,
            profile="synthetic",
            clock=lambda: 1000.0,
        )
    assert phases == [("SOURCE_FENCED", "ACTIVATING_TARGET")]


def test_target_discovery_and_live_runtime_are_exact_and_provider_verified() -> None:
    module = _load()
    resources = [
        ("PassiveControlPlaneHandlerABC", "AWS::Lambda::Function", "handler-fn"),
        ("PassiveEvidenceWorkerABC", "AWS::Lambda::Function", "evidence-fn"),
        ("PassiveRetentionWorkerABC", "AWS::Lambda::Function", "retention-fn"),
        ("EvidenceMapping", "AWS::Lambda::EventSourceMapping", "map-a"),
        ("RetentionMapping", "AWS::Lambda::EventSourceMapping", "map-b"),
        *[(f"Schedule{index}", "AWS::Events::Rule", f"rule-{index}") for index in range(4)],
    ]
    expected_environment = _active_environment()
    actual_environment = {
        "ACTIVATION_EVIDENCE_SHA256": expected_environment["RECOVERY_ACTIVATION_EVIDENCE_SHA256"],
        "POLICY_SIGNING_KEY_ARN": expected_environment["RECOVERY_POLICY_SIGNING_KEY_ARN"],
        "REGIONAL_POLICY_SIGNING_KEY_ARN": expected_environment["RECOVERY_POLICY_SIGNING_KEY_ARN"],
        "ENTRA_TENANT_ID": expected_environment["ENTRA_TENANT_ID"],
        "ENTRA_AAI_TENANT_ID": expected_environment["ENTRA_AAI_TENANT_ID"],
        "PASSIVE_CELL_MODE": "active",
        "RECOVERY_JOB_RECONCILIATION_ENABLED": "true",
        "ENTRA_PROVIDER_ENABLED": "true",
        "ENTRA_STRONG_AUTH_ENFORCED": "true",
    }

    def runner(command: list[str], **_: Any) -> Any:
        if "describe-stacks" in command:
            return _completed(
                {
                    "Stacks": [
                        {
                            "StackStatus": "UPDATE_COMPLETE",
                            "Outputs": [
                                {
                                    "OutputKey": "PassiveCellStatus",
                                    "OutputValue": "active-not-routed",
                                }
                            ],
                        }
                    ]
                }
            )
        if "list-stack-resources" in command:
            return _completed(
                {
                    "StackResourceSummaries": [
                        {
                            "LogicalResourceId": logical,
                            "ResourceType": kind,
                            "PhysicalResourceId": physical,
                        }
                        for logical, kind, physical in resources
                    ]
                }
            )
        if "get-function-configuration" in command:
            name = command[command.index("--function-name") + 1]
            handlers = {
                "handler-fn": ("handler.handler", 512, 15),
                "evidence-fn": ("evidence_worker.handler", 1024, 60),
                "retention-fn": ("retention_worker.handler", 1024, 60),
            }
            handler, memory, timeout = handlers[name]
            return _completed(
                {
                    "FunctionName": name,
                    "State": "Active",
                    "LastUpdateStatus": "Successful",
                    "Runtime": "python3.13",
                    "Handler": handler,
                    "MemorySize": memory,
                    "Timeout": timeout,
                    "Architectures": ["arm64"],
                    "PackageType": "Zip",
                    "TracingConfig": {"Mode": "PassThrough"},
                    "CodeSha256": "A" * 43 + "=",
                    "RevisionId": "42345678-1234-4234-8234-123456789abc",
                    "ReservedConcurrentExecutions": 100 if name == "handler-fn" else 5,
                    "Environment": {"Variables": actual_environment},
                }
            )
        if "get-event-source-mapping" in command:
            return _completed({"UUID": command[command.index("--uuid") + 1], "State": "Enabled"})
        if "describe-rule" in command:
            return _completed({"Name": command[command.index("--name") + 1], "State": "ENABLED"})
        raise AssertionError(command)

    discovered = module.discover_target_resources(
        stack_name="AaiSecPassiveRegionalCell",
        target_region="eu-west-1",
        profile="synthetic",
        runner=runner,
    )
    verified = module.verify_target_runtime(
        discovered,
        _activation(module),
        expected_environment,
        profile="synthetic",
        runner=runner,
    )
    assert discovered.handler == "handler-fn"
    assert verified["status"] == "target-runtime-live-not-routed"
    assert len(verified["resourceSetSha256"]) == 64

    resources.append(("UnknownFunction", "AWS::Lambda::Function", "unknown-fn"))
    with pytest.raises(module.ActiveCellDeploymentError, match="unknown Lambda"):
        module.discover_target_resources(
            stack_name="AaiSecPassiveRegionalCell",
            target_region="eu-west-1",
            profile="synthetic",
            runner=runner,
        )


def test_reconciliation_invocation_rejects_runtime_failure_and_inconsistent_counts() -> None:
    module = _load()
    manifest = _activation(module)

    class Client:
        def __init__(self, result: dict[str, Any], *, failed: bool = False) -> None:
            self.result = result
            self.failed = failed

        def invoke(self, **kwargs: Any) -> dict[str, Any]:
            event = json.loads(kwargs["Payload"])
            assert event["source"] == "aai.regional-recovery-jobs"
            return {
                "StatusCode": 200,
                **({"FunctionError": "Unhandled"} if self.failed else {}),
                "Payload": io.BytesIO(json.dumps(self.result).encode()),
            }

    evidence_ref = module._reconciliation_evidence_ref(manifest)
    result = {
        "mode": "apply",
        "activationEvidenceRefSha256": hashlib.sha256(evidence_ref.encode()).hexdigest(),
        "processedTenants": 1,
        "plannedActions": 2,
        "dispatchedJobs": 2,
        "failedStaleJobs": 0,
        "deferredJobs": 0,
        "queueSource": "authoritative-dynamodb-job-records",
    }
    assert (
        module.invoke_target_reconciliation(Client(result), "handler-fn", manifest, mode="apply")[
            "dispatchedJobs"
        ]
        == 2
    )
    with pytest.raises(module.ActiveCellDeploymentError, match="reported failure"):
        module.invoke_target_reconciliation(
            Client(result, failed=True), "handler-fn", manifest, mode="apply"
        )
    with pytest.raises(module.ActiveCellDeploymentError, match="inconsistent"):
        module.invoke_target_reconciliation(
            Client({**result, "dispatchedJobs": 1}),
            "handler-fn",
            manifest,
            mode="apply",
        )


def test_target_reconciliation_completes_only_after_zero_action_check(monkeypatch: Any) -> None:
    module = _load()
    manifest = _activation(module)
    resources = module.TargetResources(
        "handler-fn",
        ("evidence-fn", "retention-fn"),
        ("map-a", "map-b"),
        ("rule-a", "rule-b", "rule-c", "rule-d"),
    )
    phases: list[tuple[str, str, str | None]] = []

    def advance(
        *_args: Any,
        expected_phase: str,
        next_phase: str,
        step_evidence_sha256: str | None = None,
        **_kwargs: Any,
    ) -> Any:
        phases.append((expected_phase, next_phase, step_evidence_sha256))
        return {"claim": "advanced", "journal": {"phase": next_phase}}

    monkeypatch.setattr(module.journal, "advance_phase", advance)
    monkeypatch.setattr(module, "verify_source_fence", lambda *_a, **_k: {"status": "fenced"})
    monkeypatch.setattr(module, "verify_target_runtime", lambda *_a, **_k: {"status": "live"})
    results = iter(
        [
            {"mode": "check", "plannedActions": 1},
            {"mode": "apply", "plannedActions": 1, "dispatchedJobs": 1},
            {"mode": "check", "plannedActions": 1},
            {"mode": "check", "plannedActions": 0},
        ]
    )
    monkeypatch.setattr(module, "invoke_target_reconciliation", lambda *_a, **_k: next(results))
    sleeps: list[float] = []
    result = module.reconcile_target_step(
        object(),
        object(),
        manifest,
        module.SourceResources(("source",), (), ()),
        resources,
        _active_environment(),
        profile="synthetic",
        clock=lambda: 1001.0,
        sleeper=sleeps.append,
        attempts=2,
    )
    assert sleeps == [10.0]
    assert result["trafficRouted"] is False
    assert len(result["stepEvidenceSha256"]) == 64
    assert phases[0] == (
        "TARGET_ACTIVE_NOT_ROUTED",
        "RECONCILING_TARGET_JOBS",
        None,
    )
    assert phases[1][:2] == (
        "RECONCILING_TARGET_JOBS",
        "TARGET_JOBS_RECONCILED_NOT_ROUTED",
    )
    assert phases[1][2] == result["stepEvidenceSha256"]


def test_target_reconciliation_timeout_leaves_journal_in_progress(monkeypatch: Any) -> None:
    module = _load()
    phases: list[tuple[str, str]] = []

    def advance(*_args: Any, expected_phase: str, next_phase: str, **_kwargs: Any) -> Any:
        phases.append((expected_phase, next_phase))
        return {"claim": "advanced", "journal": {"phase": next_phase}}

    monkeypatch.setattr(
        module.journal,
        "advance_phase",
        advance,
    )
    monkeypatch.setattr(module, "verify_source_fence", lambda *_a, **_k: {})
    monkeypatch.setattr(module, "verify_target_runtime", lambda *_a, **_k: {})
    monkeypatch.setattr(
        module,
        "invoke_target_reconciliation",
        lambda *_a, mode, **_k: {
            "mode": mode,
            "plannedActions": 1,
            "dispatchedJobs": 1 if mode == "apply" else 0,
        },
    )
    with pytest.raises(module.ActiveCellDeploymentError, match="bounded window"):
        module.reconcile_target_step(
            object(),
            object(),
            _activation(module),
            module.SourceResources(("source",), (), ()),
            module.TargetResources(
                "handler",
                ("worker-a", "worker-b"),
                ("map-a", "map-b"),
                ("rule-a", "rule-b", "rule-c", "rule-d"),
            ),
            _active_environment(),
            profile="synthetic",
            attempts=1,
        )
    assert phases == [("TARGET_ACTIVE_NOT_ROUTED", "RECONCILING_TARGET_JOBS")]


def test_command_surface_exposes_no_routing_or_combined_failover() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "deploy_aws_active_cell.py").read_text(
        encoding="utf-8"
    )
    assert '"reconcile-target"' in source
    assert "--confirm-target-reconciliation" in source
    assert "route53" not in source.lower()
    assert "provider_preflight(" in source
    assert source.index("provider_preflight(") < source.index(
        "fence_source(", source.index("def main")
    )
    target_step = source[source.index("def activate_target_step") : source.index("def _parser")]
    target_claim = target_step.index('next_phase="ACTIVATING_TARGET"')
    deployment = target_step.index("deploy_active_template(", target_claim)
    target_completion = target_step.index('next_phase="TARGET_ACTIVE_NOT_ROUTED"')
    assert target_claim < deployment < target_completion

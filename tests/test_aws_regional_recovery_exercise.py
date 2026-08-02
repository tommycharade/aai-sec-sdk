"""Adversarial contracts for live AWS target load measurement."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest


def _load(name: str, relative: str) -> Any:
    path = Path(__file__).parents[1] / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _activation() -> Any:
    return _load(
        "aai_aws_exercise_activation",
        "scripts/verify_aws_regional_activation.py",
    )


def _adapter() -> Any:
    return _load(
        "aai_aws_regional_exercise",
        "scripts/run_aws_regional_recovery_exercise.py",
    )


def _fault_planner() -> Any:
    return _load(
        "aai_aws_regional_fault_planner",
        "scripts/plan_aws_regional_fault_exercise.py",
    )


def _manifest(module: Any) -> Any:
    value = {
        "schemaVersion": 4,
        "transitionId": "12345678-1234-4234-8234-123456789abc",
        "direction": "failover",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "sourceRegion": "eu-west-2",
        "targetRegion": "eu-west-1",
        "stableApiDomain": "api.security.example.com",
        "stableUiDomain": "security.example.com",
        "route53HostedZoneId": "Z1234567890ABC",
        "targetFleetSize": 100,
        "rtoMinutes": 30,
        "rpoSeconds": 60,
        "evidenceBundle": {
            "bucketArn": "arn:aws:s3:::synthetic-evidence",
            "key": "regional-activation/synthetic.json",
            "versionId": "version-1",
            "sha256": "a" * 64,
        },
        "approvalEvidenceRef": "change/DR-123",
        "expiresAt": 1200,
        "activationPermitted": True,
        "automaticActivation": False,
        "coordinationRegion": "eu-central-1",
        "journalTableName": "AaiSecRegionalTransitionJournal",
        "expectedRoutingGeneration": 0,
        "approvals": [
            {
                "principalId": "22345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-a",
                "approvedAt": 990,
                "strongAuthAt": 970,
            },
            {
                "principalId": "32345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-b",
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
        "routingAuthorityEvidenceRef": "change/ROUTING-123",
        "primaryRuntimeStackName": "AaiSecControlPlane",
        "primaryRuntimeTemplateSha256": "b" * 64,
        "recoveryRuntimeStackName": "AaiSecPassiveRegionalCell",
        "recoveryRuntimeTemplateSha256": "c" * 64,
    }
    return replace(
        module.ActivationManifest.parse(json.dumps(value), now=1000),
        target_fleet_size=2,
    )


def _fleet_payload(manifest: Any) -> str:
    return json.dumps(
        {
            "schemaVersion": 1,
            "transitionId": manifest.transition_id,
            "authoritySha256": manifest.authority_sha256(),
            "targetRegion": manifest.target_region,
            "apiBaseUrl": "https://api-recovery.security.example.com",
            "agents": [
                {
                    "agentNumber": number,
                    "deploymentId": f"deployment-{number}",
                    "agentId": f"agent-{number}",
                    "accessToken": f"synthetic-token-{number}-" + ("x" * 32),
                    "projectRootSha256": f"{number + 1:064x}",
                    "heartbeat": {},
                }
                for number in range(2)
            ],
        },
        sort_keys=True,
    )


def _fault_authority(manifest: Any, **updates: Any) -> dict[str, Any]:
    value = {
        "schemaVersion": 1,
        "faultId": "42345678-1234-4234-8234-123456789abc",
        "transitionId": manifest.transition_id,
        "transitionAuthoritySha256": manifest.authority_sha256(),
        "direction": manifest.direction,
        "targetRegion": manifest.target_region,
        "targetCellRole": "recovery",
        "targetRuntimeStackName": manifest.recovery_runtime_stack_name,
        "targetRuntimeTemplateSha256": manifest.recovery_runtime_template_sha256,
        "coordinationRegion": manifest.coordination_region,
        "expectedRoutingGeneration": manifest.expected_routing_generation,
        "dependency": "dynamodb",
        "maximumFaultSeconds": 120,
        "approvalSha256": manifest.approval_sha256(),
        "approverPrincipalIds": [item.principal_id for item in manifest.approvals],
        "activationEvidenceRef": _fault_planner().activation_evidence_ref(manifest.evidence),
        "expiresAt": 1150,
        "faultPermitted": True,
        "automaticFaultInjection": False,
    }
    value.update(updates)
    return value


def test_fleet_secret_is_exactly_bound_to_transition_and_target_canary() -> None:
    activation = _activation()
    module = _adapter()
    manifest = _manifest(activation)
    fleet = module.SyntheticFleetAuthority.parse(_fleet_payload(manifest), manifest)
    assert fleet.api_base_url == "https://api-recovery.security.example.com"
    assert [item.agent_number for item in fleet.agents] == [0, 1]

    changed = json.loads(_fleet_payload(manifest))
    changed["apiBaseUrl"] = "https://api-primary.security.example.com"
    with pytest.raises(module.AwsRegionalExerciseError, match="target canary"):
        module.SyntheticFleetAuthority.parse(json.dumps(changed), manifest)
    changed = json.loads(_fleet_payload(manifest))
    changed["agents"][1]["agentNumber"] = 0
    with pytest.raises(module.AwsRegionalExerciseError, match="duplicated or incomplete"):
        module.SyntheticFleetAuthority.parse(json.dumps(changed), manifest)
    changed = json.loads(_fleet_payload(manifest))
    changed["apiBaseUrl"] = "https://api-recovery.security.example.com:invalid"
    with pytest.raises(module.AwsRegionalExerciseError, match="malformed"):
        module.SyntheticFleetAuthority.parse(json.dumps(changed), manifest)


def test_adapter_measures_real_agent_routes_and_renews_session_token() -> None:
    activation = _activation()
    module = _adapter()
    manifest = _manifest(activation)
    fleet = module.SyntheticFleetAuthority.parse(_fleet_payload(manifest), manifest)
    calls: list[tuple[str, str, dict[str, str], dict[str, Any] | None]] = []

    def requester(
        url: str,
        method: str,
        body: bytes | None,
        headers: dict[str, str],
        _timeout: float,
    ) -> tuple[int, bytes]:
        parsed = json.loads(body) if body is not None else None
        calls.append((url, method, headers, parsed))
        if url.endswith("/heartbeat"):
            return 200, json.dumps(
                {"status": "connected", "accessToken": "renewed-token-" + ("y" * 32)}
            ).encode()
        if url.endswith("/effective-policy"):
            return 200, b'{"policyId":"synthetic-policy","version":1}'
        assert parsed is not None
        return 202, json.dumps(
            {"accepted": True, "duplicate": False, "decisionId": parsed["decisionId"]}
        ).encode()

    ticks = iter([0.0, 0.1, 0.2, 0.3, 0.4, 0.5])
    adapter = module.AwsAgentLoadAdapter(
        fleet,
        requester=requester,
        clock=lambda: next(ticks),
    )
    observation = adapter.measure_agent(0)
    assert observation.succeeded is True
    assert observation.heartbeat_ms == pytest.approx(100)
    assert observation.policy_read_ms == pytest.approx(100)
    assert observation.decision_write_ms == pytest.approx(100)
    assert [call[1] for call in calls] == ["POST", "GET", "POST"]
    assert calls[1][2]["Authorization"].startswith("Bearer renewed-token-")
    decision_body = calls[2][3]
    assert decision_body is not None
    assert decision_body["decisionId"] == decision_body["actionDigest"]
    assert "synthetic-token" not in repr(observation)


def test_load_adapter_cannot_self_certify_unimplemented_fault_controls() -> None:
    activation = _activation()
    module = _adapter()
    fleet = module.SyntheticFleetAuthority.parse(
        _fleet_payload(_manifest(activation)), _manifest(activation)
    )
    adapter = module.AwsAgentLoadAdapter(fleet, requester=lambda *_: (500, b"{}"))
    with pytest.raises(module.AwsRegionalExerciseError, match="not implemented"):
        adapter.exercise_dependency("kms")
    with pytest.raises(module.AwsRegionalExerciseError, match="not implemented"):
        adapter.exercise_consistency("policy")


def test_failed_heartbeat_stops_before_policy_or_decision_calls() -> None:
    activation = _activation()
    module = _adapter()
    manifest = _manifest(activation)
    fleet = module.SyntheticFleetAuthority.parse(_fleet_payload(manifest), manifest)
    calls = 0

    def requester(*_: Any) -> tuple[int, bytes]:
        nonlocal calls
        calls += 1
        return 403, b'{"error":"denied"}'

    adapter = module.AwsAgentLoadAdapter(
        fleet,
        requester=requester,
        clock=iter([0.0, 0.1]).__next__,
    )
    observation = adapter.measure_agent(0)
    assert observation.succeeded is False
    assert observation.policy_read_ms == 60_000
    assert calls == 1


def test_http_redirect_handler_never_forwards_the_request() -> None:
    module = _adapter()
    assert (
        module._NoRedirect().redirect_request(
            object(), object(), 302, "redirect", {}, "https://attacker.example"
        )
        is None
    )


def test_secret_loader_requires_exact_arn_and_never_returns_unbound_secret() -> None:
    activation = _activation()
    module = _adapter()
    manifest = _manifest(activation)
    secret_arn = (
        "arn:aws:secretsmanager:eu-west-1:111111111111:secret:"  # noqa: S105
        "aai/regional/synthetic-fleet-AbCdEf"
    )

    class Client:
        def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {"SecretId": secret_arn, "VersionStage": "AWSCURRENT"}
            return {"ARN": secret_arn, "SecretString": _fleet_payload(manifest)}

    assert len(module.load_fleet_secret(Client(), secret_arn, manifest).agents) == 2
    with pytest.raises(module.AwsRegionalExerciseError, match="ARN"):
        module.load_fleet_secret(Client(), "not-an-arn", manifest)
    wrong_region = secret_arn.replace("eu-west-1", "eu-west-2")
    with pytest.raises(module.AwsRegionalExerciseError, match="ARN"):
        module.load_fleet_secret(Client(), wrong_region, manifest)


def test_fault_authority_binds_exact_transition_and_compensation_order() -> None:
    activation = _activation()
    planner = _fault_planner()
    manifest = _manifest(activation)
    authority = planner.RegionalFaultAuthority.parse(
        json.dumps(_fault_authority(manifest)), manifest, now=1000
    )
    plan = planner.fault_plan(authority)
    assert [item["order"] for item in plan] == list(range(1, 10))
    assert plan[1]["action"] == "create-independent-cleanup-watchdog"
    assert plan[5]["action"] == "remove-exact-target-role-deny"
    assert plan[-1]["action"] == "seal-content-free-fault-evidence"
    assert len(authority.sha256()) == 64


def test_failback_fault_authority_targets_only_primary_runtime() -> None:
    activation = _activation()
    planner = _fault_planner()
    failover = _manifest(activation)
    manifest = replace(
        failover,
        direction="failback",
        source_region=failover.recovery_region,
        target_region=failover.primary_region,
    )
    value = _fault_authority(
        manifest,
        targetCellRole="primary",
        targetRuntimeStackName=manifest.primary_runtime_stack_name,
        targetRuntimeTemplateSha256=manifest.primary_runtime_template_sha256,
    )
    authority = planner.RegionalFaultAuthority.parse(json.dumps(value), manifest, now=1000)
    assert authority.target_cell_role == "primary"
    assert authority.target_runtime_stack_name == "AaiSecControlPlane"


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"automaticFaultInjection": True}, "differs"),
        ({"targetCellRole": "primary"}, "differs"),
        ({"targetRuntimeTemplateSha256": "d" * 64}, "differs"),
        ({"dependency": "route53"}, "values"),
        ({"maximumFaultSeconds": 301}, "values"),
        ({"expiresAt": 1201}, "values"),
        ({"expiresAt": 1149}, "cleanup window"),
        ({"approvalSha256": "0" * 64}, "differs"),
    ],
)
def test_fault_authority_rejects_widening_replay_and_unsafe_duration(
    updates: dict[str, Any], message: str
) -> None:
    activation = _activation()
    planner = _fault_planner()
    manifest = _manifest(activation)
    with pytest.raises(planner.RegionalFaultAuthorityError, match=message):
        planner.RegionalFaultAuthority.parse(
            json.dumps(_fault_authority(manifest, **updates)), manifest, now=1000
        )


def test_fault_authority_rejects_substituted_activation_evidence() -> None:
    activation = _activation()
    planner = _fault_planner()
    manifest = _manifest(activation)
    with pytest.raises(planner.RegionalFaultAuthorityError, match="differs"):
        planner.RegionalFaultAuthority.parse(
            json.dumps(
                _fault_authority(
                    manifest,
                    activationEvidenceRef="sha256:" + ("0" * 64),
                )
            ),
            manifest,
            now=1000,
        )


def test_fault_planner_rejects_duplicate_json_authority() -> None:
    activation = _activation()
    planner = _fault_planner()
    manifest = _manifest(activation)
    payload = json.dumps(_fault_authority(manifest))
    payload = payload.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1')
    with pytest.raises(planner.RegionalFaultAuthorityError, match="duplicate"):
        planner.RegionalFaultAuthority.parse(payload, manifest, now=1000)

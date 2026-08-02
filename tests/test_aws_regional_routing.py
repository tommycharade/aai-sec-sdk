"""Adversarial contracts for journal-governed Regional API/UI routing."""

from __future__ import annotations

import hashlib
import json
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest
from scripts import deploy_aws_active_cell as active
from scripts import execute_aws_regional_routing as routing
from scripts import manage_aws_transition_journal as journal
from scripts import verify_aws_regional_activation as activation


def _manifest(**updates: Any) -> activation.ActivationManifest:
    value: dict[str, Any] = {
        "schemaVersion": 3,
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
            "bucketArn": "arn:aws:s3:::retained-transition-evidence",
            "key": "regional-activation/evidence.json",
            "versionId": "version-1",
            "sha256": "a" * 64,
        },
        "approvalEvidenceRef": "change/DR-123456",
        "expiresAt": 2000,
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
                "strongAuthAt": 980,
            },
            {
                "principalId": "32345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/operator-b",
                "approvedAt": 995,
                "strongAuthAt": 985,
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
    value.update(updates)
    return activation.ActivationManifest.parse(json.dumps(value), now=1000)


def _cell(role: str) -> routing.IngressCell:
    primary = role == "primary"
    return routing.IngressCell(
        role=role,
        region="eu-west-2" if primary else "eu-west-1",
        stack_name=("AaiSecPrimaryRegionalIngress" if primary else "AaiSecRecoveryRegionalIngress"),
        stable_api=routing.AliasTarget(
            f"api-{'primary' if primary else 'recovery'}.execute-api.example",
            "ZAPI1" if primary else "ZAPI2",
        ),
        stable_ui=routing.AliasTarget(
            f"ui-{'primary' if primary else 'recovery'}.execute-api.example",
            "ZUI1" if primary else "ZUI2",
        ),
        canary_api_domain=(
            "api-primary.security.example.com" if primary else "api-recovery.security.example.com"
        ),
        canary_ui_domain=(
            "primary.security.example.com" if primary else "recovery.security.example.com"
        ),
        evidence_sha256=("1" if primary else "2") * 64,
    )


def _reactivation_manifest() -> activation.ActivationManifest:
    return _manifest(
        schemaVersion=4,
        primaryRuntimeStackName="AaiSecControlPlane",
        primaryRuntimeTemplateSha256="b" * 64,
        recoveryRuntimeStackName="AaiSecPassiveRegionalCell",
        recoveryRuntimeTemplateSha256="c" * 64,
    )


def _reactivation_plan() -> active.SourceReactivationPlan:
    return active.SourceReactivationPlan(
        "AaiSecControlPlane",
        "eu-west-2",
        "b" * 64,
        (active.FunctionRestoreState("source-function", 10),),
        (active.MappingRestoreState("source-mapping", True),),
        (active.RuleRestoreState("source-rule", True),),
    )


def _completed(value: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, json.dumps(value), "")


def _runtime_proof() -> dict[str, Any]:
    evidence = {"plannedActions": 0, "sourceFenced": True, "targetStable": True}
    return {
        "evidence": evidence,
        "sha256": hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "status": "fresh-runtime-and-zero-action-proof",
    }


def _successful_probe(url: str, token: str | None) -> dict[str, Any]:
    """Return the exact synthetic responses required by ingress smoke tests."""
    if token == "invalid-routing-smoke-token":  # noqa: S105 - synthetic denial input
        return {"status": 401}
    if token is not None:
        return {"status": 200, "contentType": "application/json", "jsonValid": True}
    return {
        "status": 200,
        "contentType": "text/html; charset=utf-8",
        "strictTransportSecurity": "max-age=31536000; includeSubDomains",
    }


def test_smoke_requires_rejection_authenticated_json_and_hsts() -> None:
    calls: list[tuple[str, str | None]] = []

    def probe(url: str, token: str | None) -> dict[str, Any]:
        calls.append((url, token))
        if token == "invalid-routing-smoke-token":  # noqa: S105 - synthetic denial input
            return {"status": 401}
        if token is not None:
            return {"status": 200, "contentType": "application/json", "jsonValid": True}
        return {
            "status": 200,
            "contentType": "text/html; charset=utf-8",
            "strictTransportSecurity": "max-age=31536000; includeSubDomains",
        }

    result = routing.smoke_ingress("api.example.com", "ui.example.com", "x" * 32, probe=probe)
    assert result["apiDenied"]["status"] == 401
    assert calls[1][1] == "x" * 32


@pytest.mark.parametrize(
    ("responses", "message"),
    [
        (
            (
                {"status": 200},
                {"status": 200, "contentType": "application/json", "jsonValid": True},
                {
                    "status": 200,
                    "contentType": "text/html",
                    "strictTransportSecurity": "max-age=31536000; includeSubDomains",
                },
            ),
            "did not reject",
        ),
        (
            (
                {"status": 401},
                {"status": 403, "contentType": "application/json", "jsonValid": True},
                {
                    "status": 200,
                    "contentType": "text/html",
                    "strictTransportSecurity": "max-age=31536000; includeSubDomains",
                },
            ),
            "read failed",
        ),
        (
            (
                {"status": 401},
                {"status": 200, "contentType": "application/json", "jsonValid": True},
                {"status": 200, "contentType": "text/html", "strictTransportSecurity": ""},
            ),
            "security delivery failed",
        ),
    ],
)
def test_smoke_fails_closed_for_auth_or_transport_posture(
    responses: tuple[dict[str, Any], ...], message: str
) -> None:
    values = iter(responses)
    with pytest.raises(routing.RegionalRoutingError, match=message):
        routing.smoke_ingress(
            "api.example.com", "ui.example.com", "x" * 32, probe=lambda *_: next(values)
        )


def test_routing_role_rejects_an_ordinary_session() -> None:
    def runner(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        return _completed(
            {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:user/admin"}
        )

    with pytest.raises(routing.RegionalRoutingError, match="dedicated routing role"):
        routing.require_routing_role(_manifest(), profile="p1", runner=runner)


def test_every_journal_routing_step_requires_the_dedicated_role() -> None:
    def runner(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        return _completed(
            {
                "Account": "111111111111",
                "Arn": "arn:aws:iam::111111111111:user/admin",
            }
        )

    with pytest.raises(routing.RegionalRoutingError, match="dedicated routing role"):
        routing.verify_target_ingress_step(
            object(),
            _manifest(),
            _cell("recovery"),
            "x" * 32,
            profile="p1",
            runner=runner,
        )
    with pytest.raises(routing.RegionalRoutingError, match="dedicated routing role"):
        routing.verify_stable_step(
            object(),
            _manifest(),
            _cell("recovery"),
            "x" * 32,
            profile="p1",
            runner=runner,
        )


def test_route_state_rejects_parallel_aaaa_record() -> None:
    manifest = _manifest()

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if "get-hosted-zone" in command:
            return _completed(
                {
                    "HostedZone": {
                        "Id": manifest.hosted_zone_id,
                        "Name": "security.example.com.",
                        "Config": {"PrivateZone": False},
                    }
                }
            )
        return _completed(
            {
                "IsTruncated": False,
                "ResourceRecordSets": [
                    {
                        "Name": "api.security.example.com.",
                        "Type": "AAAA",
                        "ResourceRecords": [{"Value": "::1"}],
                    }
                ],
            }
        )

    with pytest.raises(routing.RegionalRoutingError, match="parallel or unsupported"):
        routing.read_route_state(manifest, profile="p1", runner=runner)


def test_route_state_follows_bounded_pagination() -> None:
    manifest = _manifest()
    pages = 0

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        nonlocal pages
        if "get-hosted-zone" in command:
            return _completed(
                {
                    "HostedZone": {
                        "Id": manifest.hosted_zone_id,
                        "Name": "security.example.com.",
                        "Config": {"PrivateZone": False},
                    }
                }
            )
        pages += 1
        if pages == 1:
            return _completed(
                {
                    "IsTruncated": True,
                    "NextRecordName": "next.security.example.com.",
                    "NextRecordType": "A",
                    "ResourceRecordSets": [],
                }
            )
        assert "--start-record-name" in command
        return _completed({"IsTruncated": False, "ResourceRecordSets": []})

    assert routing.read_route_state(manifest, profile="p1", runner=runner) == {}
    assert pages == 2


def test_route_target_uses_one_transactional_delete_create_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    source, target = _cell("primary"), _cell("recovery")
    source_state = routing.expected_route_state(
        manifest, source, generation=0, transition_id="", marker_required=False
    )
    target_state = routing.expected_route_state(
        manifest, target, generation=1, transition_id=manifest.transition_id, marker_required=True
    )
    observed = iter((source_state, target_state))
    calls: list[list[str]] = []
    state = SimpleNamespace(
        phase="TARGET_INGRESS_VERIFIED_NOT_ROUTED",
        generation=0,
        last_completed_transition_id="",
        evidence=lambda: {"phase": "TARGET_INGRESS_VERIFIED_NOT_ROUTED"},
    )
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    monkeypatch.setattr(
        journal,
        "advance_phase",
        lambda *_, **__: {"claim": "advanced", "journal": {"phase": "VERIFYING_STABLE_ROUTE"}},
    )
    monkeypatch.setattr(routing, "read_route_state", lambda *_, **__: next(observed))

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "get-caller-identity" in command:
            return _completed(
                {
                    "Account": "111111111111",
                    "Arn": "arn:aws:sts::111111111111:assumed-role/AaiSecRegionalRouting/operator",
                }
            )
        if "change-resource-record-sets" in command:
            batch = json.loads(command[command.index("--change-batch") + 1])
            assert [change["Action"] for change in batch["Changes"]] == [
                "DELETE",
                "DELETE",
                "CREATE",
                "CREATE",
                "CREATE",
            ]
            return _completed({"ChangeInfo": {"Id": "/change/ABC123", "Status": "PENDING"}})
        return _completed({"ChangeInfo": {"Id": "/change/ABC123", "Status": "INSYNC"}})

    result = routing.route_target_step(
        object(),
        manifest,
        source,
        target,
        profile="p1",
        runner=runner,
        sleeper=lambda _: None,
        runtime_guard=_runtime_proof,
    )
    assert result["trafficRouted"] is True
    assert len(result["records"]) == 3
    assert sum("change-resource-record-sets" in call for call in calls) == 1


def test_route_target_rejects_mixed_or_reversed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = _manifest()
    source, target = _cell("primary"), _cell("recovery")
    monkeypatch.setattr(routing, "require_routing_role", lambda *_, **__: {})
    state = SimpleNamespace(
        phase="TARGET_INGRESS_VERIFIED_NOT_ROUTED",
        generation=0,
        last_completed_transition_id="",
        evidence=lambda: {},
    )
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    monkeypatch.setattr(journal, "advance_phase", lambda *_, **__: {})
    monkeypatch.setattr(
        routing,
        "read_route_state",
        lambda *_, **__: {
            ("api.security.example.com.", "A"): source.stable_api.record(manifest.stable_api_domain)
        },
    )
    with pytest.raises(routing.RegionalRoutingError, match="differ from source and target"):
        routing.route_target_step(
            object(),
            manifest,
            source,
            target,
            profile="p1",
            runtime_guard=_runtime_proof,
        )
    with pytest.raises(routing.RegionalRoutingError, match="transition direction"):
        routing.route_target_step(object(), manifest, target, source, profile="p1")


def test_route_refuses_missing_or_forged_fresh_runtime_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    source, target = _cell("primary"), _cell("recovery")
    monkeypatch.setattr(routing, "require_routing_role", lambda *_, **__: {})
    state = SimpleNamespace(
        phase="TARGET_INGRESS_VERIFIED_NOT_ROUTED",
        generation=0,
        last_completed_transition_id="",
        evidence=lambda: {},
    )
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    with pytest.raises(routing.RegionalRoutingError, match="proof is required"):
        routing.route_target_step(object(), manifest, source, target, profile="p1")
    forged = _runtime_proof()
    forged["sha256"] = "0" * 64
    with pytest.raises(routing.RegionalRoutingError, match="proof is malformed"):
        routing.route_target_step(
            object(),
            manifest,
            source,
            target,
            profile="p1",
            runtime_guard=lambda: forged,
        )


def test_rollback_routes_failed_target_to_source_at_generation_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _reactivation_manifest()
    source, target = _cell("primary"), _cell("recovery")
    target_state = routing.expected_route_state(
        manifest,
        target,
        generation=1,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    source_state = routing.expected_route_state(
        manifest,
        source,
        generation=2,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    observed = iter((target_state, source_state))
    monkeypatch.setattr(
        routing,
        "require_routing_role",
        lambda *_, **__: {"roleArn": manifest.routing_role_arn},
    )
    monkeypatch.setattr(
        journal,
        "read_state",
        lambda *_: SimpleNamespace(
            phase="SOURCE_INGRESS_VERIFIED_NOT_ROUTED",
            evidence=lambda: {"phase": "SOURCE_INGRESS_VERIFIED_NOT_ROUTED"},
        ),
    )
    monkeypatch.setattr(
        journal,
        "advance_phase",
        lambda *_, **__: {"claim": "advanced", "journal": {"phase": "VERIFYING_SOURCE_ROLLBACK"}},
    )
    monkeypatch.setattr(routing, "read_route_state", lambda *_, **__: next(observed))
    batches: list[dict[str, Any]] = []

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if "change-resource-record-sets" in command:
            batches.append(json.loads(command[command.index("--change-batch") + 1]))
            return _completed({"ChangeInfo": {"Id": "/change/ROLLBACK1", "Status": "PENDING"}})
        return _completed({"ChangeInfo": {"Id": "/change/ROLLBACK1", "Status": "INSYNC"}})

    result = routing.route_source_rollback_step(
        object(),
        manifest,
        source,
        target,
        profile="p1",
        runner=runner,
        sleeper=lambda _: None,
    )
    assert result["trafficRouted"] is True
    assert [change["Action"] for change in batches[0]["Changes"]] == [
        "DELETE",
        "DELETE",
        "DELETE",
        "CREATE",
        "CREATE",
        "CREATE",
    ]
    marker = next(record for record in result["records"] if record["Type"] == "TXT")
    assert ":g=2:" in marker["ResourceRecords"][0]["Value"]


def test_completed_source_ingress_retry_reprobes_and_reuses_exact_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _reactivation_manifest()
    source = _cell("primary")
    state = SimpleNamespace(
        phase="SOURCE_INGRESS_VERIFIED_NOT_ROUTED",
        evidence=lambda: {"phase": "SOURCE_INGRESS_VERIFIED_NOT_ROUTED"},
    )
    monkeypatch.setattr(routing, "require_routing_role", lambda *_, **__: {})
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    advances: list[dict[str, Any]] = []

    def advance(*_: Any, **kwargs: Any) -> dict[str, Any]:
        advances.append(kwargs)
        return {"claim": "already-completed", "journal": state.evidence()}

    monkeypatch.setattr(journal, "advance_phase", advance)
    result = routing.verify_source_ingress_step(
        object(),
        manifest,
        source,
        "x" * 32,
        profile="p1",
        probe=_successful_probe,
    )
    assert result["journalClaim"]["claim"] == "resume-completed"
    assert advances[0]["expected_phase"] == "VERIFYING_SOURCE_INGRESS"
    assert advances[0]["next_phase"] == "SOURCE_INGRESS_VERIFIED_NOT_ROUTED"
    assert len(advances[0]["step_evidence_sha256"]) == 64


def test_completed_failed_target_fence_retry_verifies_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _reactivation_manifest()
    resources = active.SourceResources(("target-function",), (), ())
    state = SimpleNamespace(
        phase="FAILED_TARGET_FENCED",
        evidence=lambda: {"phase": "FAILED_TARGET_FENCED"},
    )
    monkeypatch.setattr(routing, "require_routing_role", lambda *_, **__: {})
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    monkeypatch.setattr(
        active,
        "verify_source_fence",
        lambda *_, **__: resources.fence_evidence(),
    )
    monkeypatch.setattr(
        active,
        "fence_source",
        lambda *_, **__: pytest.fail("completed retry must not repeat mutations"),
    )
    advances: list[dict[str, Any]] = []

    def advance(*_: Any, **kwargs: Any) -> dict[str, Any]:
        advances.append(kwargs)
        return {"claim": "already-completed", "journal": state.evidence()}

    monkeypatch.setattr(journal, "advance_phase", advance)
    result = routing.fence_failed_target_step(object(), manifest, resources, profile="p1")
    assert result["journalClaim"]["claim"] == "resume-completed"
    assert advances[0]["next_phase"] == "FAILED_TARGET_FENCED"


def test_completed_source_reactivation_retry_only_reverifies_active_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _reactivation_manifest()
    plan = _reactivation_plan()
    target = active.SourceResources(("target-function",), (), ())
    state = SimpleNamespace(
        phase="SOURCE_REACTIVATED_NOT_ROUTED",
        evidence=lambda: {"phase": "SOURCE_REACTIVATED_NOT_ROUTED"},
    )
    monkeypatch.setattr(routing, "require_routing_role", lambda *_, **__: {})
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    monkeypatch.setattr(
        active,
        "verify_source_fence",
        lambda *_, **__: target.fence_evidence(),
    )
    monkeypatch.setattr(
        active,
        "verify_source_reactivation",
        lambda *_, **__: {
            "planSha256": plan.sha256(),
            "resourceCount": 3,
            "status": "source-runtime-reactivated",
            "templateSha256": plan.template_sha256,
        },
    )
    monkeypatch.setattr(
        active,
        "reactivate_source",
        lambda *_, **__: pytest.fail("completed retry must not repeat mutations"),
    )
    advances: list[dict[str, Any]] = []

    def advance(*_: Any, **kwargs: Any) -> dict[str, Any]:
        advances.append(kwargs)
        return {"claim": "already-completed", "journal": state.evidence()}

    monkeypatch.setattr(journal, "advance_phase", advance)
    result = routing.reactivate_source_step(object(), manifest, target, plan, profile="p1")
    assert result["journalClaim"]["claim"] == "resume-completed"
    assert advances[0]["next_phase"] == "SOURCE_REACTIVATED_NOT_ROUTED"


def test_partial_source_reactivation_retry_reapplies_plan_with_target_fenced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _reactivation_manifest()
    plan = _reactivation_plan()
    target = active.SourceResources(("target-function",), (), ())
    state = SimpleNamespace(
        phase="REACTIVATING_SOURCE",
        evidence=lambda: {"phase": "REACTIVATING_SOURCE"},
    )
    monkeypatch.setattr(routing, "require_routing_role", lambda *_, **__: {})
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    verified_resources: list[active.SourceResources] = []

    def verify_fence(resources: active.SourceResources, **_: Any) -> dict[str, Any]:
        verified_resources.append(resources)
        return resources.fence_evidence()

    monkeypatch.setattr(active, "verify_source_fence", verify_fence)
    reapplications: list[str] = []

    def reactivate(*_: Any, **__: Any) -> dict[str, Any]:
        reapplications.append(plan.sha256())
        return {
            "planSha256": plan.sha256(),
            "resourceCount": 3,
            "status": "source-runtime-reactivated",
            "templateSha256": plan.template_sha256,
        }

    monkeypatch.setattr(active, "reactivate_source", reactivate)
    monkeypatch.setattr(
        journal,
        "advance_phase",
        lambda *_, **__: {"claim": "already-completed", "journal": state.evidence()},
    )
    routing.reactivate_source_step(object(), manifest, target, plan, profile="p1")
    assert verified_resources == [target]
    assert reapplications == [plan.sha256()]


def test_completed_rollback_route_retry_does_not_mutate_route53(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _reactivation_manifest()
    source, target = _cell("primary"), _cell("recovery")
    source_state = routing.expected_route_state(
        manifest,
        source,
        generation=2,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    state = SimpleNamespace(
        phase="VERIFYING_SOURCE_ROLLBACK",
        evidence=lambda: {"phase": "VERIFYING_SOURCE_ROLLBACK"},
    )
    monkeypatch.setattr(
        routing,
        "require_routing_role",
        lambda *_, **__: {"roleArn": manifest.routing_role_arn},
    )
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    monkeypatch.setattr(routing, "read_route_state", lambda *_, **__: source_state)
    advances: list[dict[str, Any]] = []

    def advance(*_: Any, **kwargs: Any) -> dict[str, Any]:
        advances.append(kwargs)
        return {"claim": "already-completed", "journal": state.evidence()}

    monkeypatch.setattr(journal, "advance_phase", advance)

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"unexpected Route 53 mutation: {command}")

    result = routing.route_source_rollback_step(
        object(), manifest, source, target, profile="p1", runner=runner
    )
    assert result["journalClaim"]["claim"] == "resume-completed"
    assert result["changeId"] is None
    assert advances[0]["expected_phase"] == "ROUTING_SOURCE_ROLLBACK"
    assert advances[0]["next_phase"] == "VERIFYING_SOURCE_ROLLBACK"


def test_planned_failback_routes_recovery_to_primary_at_next_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(
        direction="failback",
        sourceRegion="eu-west-1",
        targetRegion="eu-west-2",
        expectedRoutingGeneration=1,
    )
    source, target = _cell("recovery"), _cell("primary")
    previous_transition = "42345678-1234-4234-8234-123456789abc"
    source_state = routing.expected_route_state(
        manifest,
        source,
        generation=1,
        transition_id=previous_transition,
        marker_required=True,
    )
    target_state = routing.expected_route_state(
        manifest,
        target,
        generation=2,
        transition_id=manifest.transition_id,
        marker_required=True,
    )
    observed = iter((source_state, target_state))
    state = SimpleNamespace(
        phase="TARGET_INGRESS_VERIFIED_NOT_ROUTED",
        generation=1,
        last_completed_transition_id=previous_transition,
        evidence=lambda: {"phase": "TARGET_INGRESS_VERIFIED_NOT_ROUTED"},
    )
    monkeypatch.setattr(journal, "read_state", lambda *_: state)
    monkeypatch.setattr(
        journal,
        "advance_phase",
        lambda *_, **__: {"claim": "advanced", "journal": {"phase": "VERIFYING_STABLE_ROUTE"}},
    )
    monkeypatch.setattr(routing, "read_route_state", lambda *_, **__: next(observed))
    batches: list[dict[str, Any]] = []

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if "get-caller-identity" in command:
            return _completed(
                {
                    "Account": "111111111111",
                    "Arn": "arn:aws:sts::111111111111:assumed-role/AaiSecRegionalRouting/operator",
                }
            )
        if "change-resource-record-sets" in command:
            batches.append(json.loads(command[command.index("--change-batch") + 1]))
            return _completed({"ChangeInfo": {"Id": "/change/FAILBACK1", "Status": "PENDING"}})
        return _completed({"ChangeInfo": {"Id": "/change/FAILBACK1", "Status": "INSYNC"}})

    result = routing.route_target_step(
        object(),
        manifest,
        source,
        target,
        profile="p1",
        runner=runner,
        sleeper=lambda _: None,
        runtime_guard=_runtime_proof,
    )
    assert result["trafficRouted"] is True
    assert len(batches) == 1
    marker = next(record for record in result["records"] if record["Type"] == "TXT")
    assert ":g=2:" in marker["ResourceRecords"][0]["Value"]

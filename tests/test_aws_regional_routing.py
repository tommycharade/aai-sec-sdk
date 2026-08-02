"""Adversarial contracts for journal-governed Regional API/UI routing."""

from __future__ import annotations

import hashlib
import json
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest
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


def test_unsafe_rollback_is_explicitly_refused() -> None:
    with pytest.raises(routing.RegionalRoutingError, match="independently reactivated"):
        routing.refuse_unsafe_rollback()

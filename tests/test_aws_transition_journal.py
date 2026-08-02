"""Adversarial contracts for the single-writer regional transition journal."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "manage_aws_transition_journal.py"
    spec = importlib.util.spec_from_file_location("aai_transition_journal", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(module: Any, **updates: Any) -> Any:
    value: dict[str, Any] = {
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
            "bucketArn": "arn:aws:s3:::retained-transition-evidence",
            "key": "regional-activation/12345678-1234-4234-8234-123456789abc.json",
            "versionId": "version-1",
            "sha256": "a" * 64,
        },
        "approvalEvidenceRef": "change/DR-123456",
        "expiresAt": 1200,
        "activationPermitted": True,
        "automaticActivation": False,
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
    value.update(updates)
    return module.activation.ActivationManifest.parse(json.dumps(value), now=1000)


def _attribute(value: str | int) -> dict[str, str]:
    return {"N": str(value)} if isinstance(value, int) else {"S": value}


def _stable(*, generation: int = 0, active_region: str = "eu-west-2") -> dict[str, Any]:
    value: dict[str, str | int] = {
        "pk": "AUTHORITY",
        "sk": "CURRENT",
        "schemaVersion": 1,
        "generation": generation,
        "activeRegion": active_region,
        "phase": "STABLE",
        "revision": 7,
        "updatedAt": 900,
        "lastCompletedTransitionId": "",
    }
    return {key: _attribute(item) for key, item in value.items()}


class _ConditionalError(RuntimeError):
    response = {"Error": {"Code": "TransactionCanceledException"}}


class _Client:
    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self.state = copy.deepcopy(state or _stable())
        self.events: dict[tuple[str, str], dict[str, Any]] = {}
        self.transactions: list[list[dict[str, Any]]] = []
        self.fail_next = False
        self.table_updates: dict[str, Any] = {}
        self.backup_status = "ENABLED"

    def describe_table(self, **_: Any) -> dict[str, Any]:
        table = {
            "TableName": "AaiSecRegionalTransitionJournal",
            "TableStatus": "ACTIVE",
            "TableArn": (
                "arn:aws:dynamodb:eu-central-1:111111111111:table/AaiSecRegionalTransitionJournal"
            ),
            "DeletionProtectionEnabled": True,
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "SSEDescription": {"Status": "ENABLED"},
        }
        table.update(self.table_updates)
        return {"Table": table}

    def describe_continuous_backups(self, **_: Any) -> dict[str, Any]:
        return {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": self.backup_status}
            }
        }

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["ConsistentRead"] is True
        return {"Item": copy.deepcopy(self.state)}

    def transact_write_items(self, *, TransactItems: list[dict[str, Any]]) -> None:
        self.transactions.append(TransactItems)
        if self.fail_next:
            self.fail_next = False
            raise _ConditionalError("synthetic race")
        if "Put" in TransactItems[0]:
            self.state = copy.deepcopy(TransactItems[0]["Put"]["Item"])
            event = copy.deepcopy(TransactItems[1]["Put"]["Item"])
            self.events[(event["pk"]["S"], event["sk"]["S"])] = event
            return
        update = TransactItems[0]["Update"]
        values = update["ExpressionAttributeValues"]
        current_phase = self.state["phase"]["S"]
        expected = values.get(":stable", values.get(":expected"))["S"]
        expected_revision = int(values[":revision"]["N"])
        if current_phase != expected or int(self.state["revision"]["N"]) != expected_revision:
            raise _ConditionalError("stale")
        if ":stable" in values:
            if (
                int(self.state["generation"]["N"]) != int(values[":generation"]["N"])
                or self.state["activeRegion"]["S"] != values[":source"]["S"]
            ):
                raise _ConditionalError("stale authority")
            for field, token in (
                ("activeTransitionId", ":transition"),
                ("direction", ":direction"),
                ("sourceRegion", ":source"),
                ("targetRegion", ":target"),
                ("authoritySha256", ":authority"),
                ("evidenceSha256", ":evidence"),
                ("approvalSha256", ":approval"),
                ("expiresAt", ":expires"),
            ):
                self.state[field] = copy.deepcopy(values[token])
        else:
            for field, token in (
                ("activeTransitionId", ":transition"),
                ("authoritySha256", ":authority"),
                ("evidenceSha256", ":evidence"),
                ("approvalSha256", ":approval"),
                ("expiresAt", ":expires"),
            ):
                if self.state[field] != values[token]:
                    raise _ConditionalError("substituted authority")
        self.state["phase"] = copy.deepcopy(values[":next"])
        self.state["revision"] = {"N": str(expected_revision + 1)}
        self.state["updatedAt"] = copy.deepcopy(values[":now"])
        event = copy.deepcopy(TransactItems[1]["Put"]["Item"])
        key = (event["pk"]["S"], event["sk"]["S"])
        if key in self.events:
            raise _ConditionalError("event replay")
        self.events[key] = event


def test_schema_v2_binds_distinct_witness_generation_and_two_people() -> None:
    module = _load()
    manifest = _manifest(module)
    manifest.require_journal_authority()
    assert manifest.coordination_region == "eu-central-1"
    assert manifest.expected_routing_generation == 0
    assert len(manifest.approvals) == 2
    assert len(module.approval_sha256(manifest)) == 64
    first = manifest.authority_sha256()
    changed = _manifest(module, expectedRoutingGeneration=1)
    assert changed.authority_sha256() != first


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"coordinationRegion": "eu-west-2"}, "distinct witness"),
        ({"journalTableName": "?"}, "journalTableName"),
        ({"approvals": []}, "exactly two"),
        (
            {
                "approvals": [
                    {
                        "principalId": "22345678-1234-4234-8234-123456789abc",
                        "evidenceRef": "entra/approval-operator-a",
                        "approvedAt": 990,
                        "strongAuthAt": 970,
                    },
                    {
                        "principalId": "22345678-1234-4234-8234-123456789abc",
                        "evidenceRef": "entra/approval-operator-b",
                        "approvedAt": 995,
                        "strongAuthAt": 980,
                    },
                ]
            },
            "not independent",
        ),
    ],
)
def test_schema_v2_rejects_weak_or_ambiguous_authority(
    updates: dict[str, Any], message: str
) -> None:
    module = _load()
    with pytest.raises(module.activation.RegionalActivationVerificationError, match=message):
        _manifest(module, **updates)


def test_table_posture_requires_single_region_encryption_pitr_and_protection() -> None:
    module = _load()
    client = _Client()
    result = module.verify_table_posture(client, _manifest(module))
    assert result["status"] == "verified-single-writer-witness"
    client.table_updates = {"Replicas": [{"RegionName": "eu-west-1"}]}
    with pytest.raises(module.TransitionJournalError, match="posture is unsafe"):
        module.verify_table_posture(client, _manifest(module))
    client.table_updates = {}
    client.backup_status = "DISABLED"
    with pytest.raises(module.TransitionJournalError, match="recovery is disabled"):
        module.verify_table_posture(client, _manifest(module))


def test_transition_claim_and_phases_are_cas_ordered_and_retry_safe() -> None:
    module = _load()
    client = _Client()
    manifest = _manifest(module)
    claimed = module.claim_source_fence(client, manifest, now=1001)
    assert claimed["claim"] == "created"
    assert claimed["journal"]["phase"] == "FENCING_SOURCE"
    resumed = module.claim_source_fence(client, manifest, now=1002)
    assert resumed["claim"] == "resumed"
    fenced = module.advance_phase(
        client,
        manifest,
        expected_phase="FENCING_SOURCE",
        next_phase="SOURCE_FENCED",
        now=1003,
    )
    assert fenced["journal"]["phase"] == "SOURCE_FENCED"
    assert (
        module.advance_phase(
            client,
            manifest,
            expected_phase="FENCING_SOURCE",
            next_phase="SOURCE_FENCED",
            now=1004,
        )["claim"]
        == "already-completed"
    )
    module.advance_phase(
        client,
        manifest,
        expected_phase="SOURCE_FENCED",
        next_phase="ACTIVATING_TARGET",
        now=1005,
    )
    completed = module.advance_phase(
        client,
        manifest,
        expected_phase="ACTIVATING_TARGET",
        next_phase="TARGET_ACTIVE_NOT_ROUTED",
        now=1006,
    )
    assert completed["journal"]["phase"] == "TARGET_ACTIVE_NOT_ROUTED"
    assert len(client.events) == 4


def test_initialization_is_primary_generation_zero_and_two_person_bound() -> None:
    module = _load()
    client = _Client()
    client.state = {}
    manifest = _manifest(module)
    initialized = module.initialize_state(client, manifest, now=1001)
    assert initialized["journal"] == {
        "activeRegion": "eu-west-2",
        "activeTransitionId": None,
        "generation": 0,
        "phase": "STABLE",
        "revision": 0,
        "updatedAt": 1001,
    }
    event = next(iter(client.events.values()))
    assert event["approvalSha256"] == {"S": module.approval_sha256(manifest)}
    with pytest.raises(module.TransitionJournalError, match="generation-zero"):
        module.initialize_state(client, _manifest(module, expectedRoutingGeneration=1), now=1002)


def test_stale_generation_wrong_source_and_competing_transition_fail_before_write() -> None:
    module = _load()
    for client in (_Client(_stable(generation=1)), _Client(_stable(active_region="eu-west-1"))):
        with pytest.raises(module.TransitionJournalError, match="stale generation or source"):
            module.claim_source_fence(client, _manifest(module), now=1001)
        assert client.transactions == []
    client = _Client()
    manifest = _manifest(module)
    module.claim_source_fence(client, manifest, now=1001)
    competing = _manifest(
        module,
        transitionId="42345678-1234-4234-8234-123456789abc",
        evidenceBundle={
            "bucketArn": "arn:aws:s3:::retained-transition-evidence",
            "key": "regional-activation/42345678-1234-4234-8234-123456789abc.json",
            "versionId": "version-2",
            "sha256": "b" * 64,
        },
    )
    with pytest.raises(module.TransitionJournalError, match="another transition"):
        module.claim_source_fence(client, competing, now=1002)


def test_provider_race_and_out_of_order_step_never_advance_authority() -> None:
    module = _load()
    manifest = _manifest(module)
    client = _Client()
    client.fail_next = True
    with pytest.raises(module.TransitionJournalError, match="changed concurrently"):
        module.claim_source_fence(client, manifest, now=1001)
    assert client.state["phase"] == {"S": "STABLE"}
    module.claim_source_fence(client, manifest, now=1002)
    with pytest.raises(module.TransitionJournalError, match="stale or out of order"):
        module.advance_phase(
            client,
            manifest,
            expected_phase="SOURCE_FENCED",
            next_phase="ACTIVATING_TARGET",
            now=1003,
        )


def test_legacy_authority_and_malformed_journal_fail_closed() -> None:
    module = _load()
    legacy = replace(
        _manifest(module),
        schema_version=1,
        coordination_region=None,
        journal_table_name=None,
        expected_routing_generation=None,
        approvals=(),
    )
    with pytest.raises(module.activation.RegionalActivationVerificationError, match="schema-v2"):
        legacy.require_journal_authority()
    client = _Client()
    client.state["unexpected"] = {"S": "widened"}
    with pytest.raises(module.TransitionJournalError, match="fields are malformed"):
        module.read_state(client, _manifest(module))

"""Contract tests for the optional AWS persistence adapter."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from agentic_security import (
    AwsScopePolicy,
    AwsStsCredentialBroker,
    DynamoDbIdempotencyStore,
    IdempotencyClaimStatus,
    IdempotencyState,
)
from agentic_security.idempotency import new_record
from agentic_security.types import ExecutionResult, ExecutionStatus, Resource


class ConditionalFailure(Exception):
    """Minimal boto-compatible conditional-write failure."""

    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeDynamoTable:
    """Small conditional table model used without requiring boto3 in tests."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}

    def get_item(self, *, Key: dict[str, str], ConsistentRead: bool) -> dict[str, Any]:
        assert ConsistentRead is True
        item = self.items.get(Key["pk"])
        return {} if item is None else {"Item": dict(item)}

    def put_item(self, *, Item: dict[str, Any], ConditionExpression: str, **kwargs: Any) -> None:
        key = Item["pk"]
        existing = self.items.get(key)
        if ConditionExpression == "attribute_not_exists(pk)" and existing is not None:
            raise ConditionalFailure()
        if ConditionExpression.startswith("#state ="):
            values = kwargs["ExpressionAttributeValues"]
            if (
                existing is None
                or existing["state"] != values[":completed"]
                or existing["expires_at"] > values[":now"]
            ):
                raise ConditionalFailure()
        if ConditionExpression.startswith("attribute_exists(pk)"):
            values = kwargs["ExpressionAttributeValues"]
            if existing is None or existing["action_fingerprint"] != values[":fingerprint"]:
                raise ConditionalFailure()
        self.items[key] = dict(Item)

    def scan(self, *, ConsistentRead: bool) -> dict[str, Any]:
        assert ConsistentRead is True
        return {"Items": [dict(item) for item in self.items.values()]}

    def delete_item(self, *, Key: dict[str, str], **kwargs: Any) -> None:
        existing = self.items.get(Key["pk"])
        values = kwargs["ExpressionAttributeValues"]
        if (
            existing is None
            or existing["state"] != values[":completed"]
            or existing["expires_at"] > values[":now"]
        ):
            raise ConditionalFailure()
        del self.items[Key["pk"]]


def _record(key: str, *, fingerprint: str = "hash", ttl: int | None = 60) -> Any:
    return new_record(
        operation_key=key,
        action_fingerprint=fingerprint,
        tenant="tenant-a",
        principal_id="principal-a",
        tool_name="write",
        resource_ids=("resource-a",),
        ttl_seconds=ttl,
        now=datetime.now(UTC),
    )


def test_dynamodb_claim_is_atomic_and_survives_new_adapter_instance() -> None:
    table = FakeDynamoTable()
    first = DynamoDbIdempotencyStore(table)
    record = _record("operation-a")

    assert first.claim(record).status is IdempotencyClaimStatus.CLAIMED
    replay = DynamoDbIdempotencyStore(table).claim(record)
    assert replay.status is IdempotencyClaimStatus.EXISTING
    assert replay.record.state is IdempotencyState.IN_PROGRESS

    conflict = first.claim(_record("operation-a", fingerprint="different"))
    assert conflict.status is IdempotencyClaimStatus.CONFLICT


def test_dynamodb_terminal_result_and_uncertain_record_are_restart_safe() -> None:
    table = FakeDynamoTable()
    store = DynamoDbIdempotencyStore(table)
    record = _record("operation-b", ttl=None)
    store.claim(record)
    completed = store.complete(record.operation_key, {"accepted": True})
    assert completed.state is IdempotencyState.COMPLETED
    assert DynamoDbIdempotencyStore(table).lookup(record.operation_key) == completed

    uncertain_record = _record("operation-c", ttl=None)
    store.claim(uncertain_record)
    uncertain = DynamoDbIdempotencyStore(table).mark_uncertain(
        uncertain_record.operation_key, {"reconcile": True}
    )
    assert uncertain.state is IdempotencyState.UNCERTAIN
    assert DynamoDbIdempotencyStore(table).lookup(uncertain_record.operation_key) == uncertain


def test_dynamodb_gc_removes_only_expired_completed_records() -> None:
    table = FakeDynamoTable()
    now = datetime.now(UTC)
    store = DynamoDbIdempotencyStore(table, now=lambda: now)
    expired = new_record(
        operation_key="expired",
        action_fingerprint="hash",
        tenant="tenant-a",
        principal_id="principal-a",
        tool_name="write",
        resource_ids=(),
        ttl_seconds=1,
        now=now - timedelta(seconds=10),
    )
    active = _record("active", ttl=None)
    store.claim(expired)
    store.complete("expired", {"ok": True})
    store.claim(active)
    report = store.gc(now)
    assert report.scanned == 2
    assert report.removed_completed == 1
    assert report.retained_active == 1
    assert store.lookup("expired") is None
    assert store.lookup("active") is not None


def test_dynamodb_rejects_non_json_terminal_results() -> None:
    table = FakeDynamoTable()
    store = DynamoDbIdempotencyStore(table)
    record = _record("operation-d")
    store.claim(record)
    with pytest.raises(TypeError):
        store.complete(record.operation_key, object())


def test_dynamodb_reclaims_expired_completed_key_and_rejects_unknown_terminal_key() -> None:
    table = FakeDynamoTable()
    now = datetime.now(UTC)
    store = DynamoDbIdempotencyStore(table, now=lambda: now)
    expired = new_record(
        operation_key="reclaim",
        action_fingerprint="hash",
        tenant="tenant-a",
        principal_id="principal-a",
        tool_name="write",
        resource_ids=(),
        ttl_seconds=1,
        now=now - timedelta(seconds=10),
    )
    store.claim(expired)
    store.complete(expired.operation_key, {"old": True})
    fresh = _record("reclaim")
    assert store.claim(fresh).status is IdempotencyClaimStatus.CLAIMED
    with pytest.raises(KeyError):
        store.complete("never-claimed", {"ok": False})


def test_dynamodb_rejects_blank_operation_key() -> None:
    table = FakeDynamoTable()
    store = DynamoDbIdempotencyStore(table)
    with pytest.raises(ValueError):
        store.claim(replace(_record("valid"), operation_key=" "))


def test_aws_sts_broker_passes_exact_scope_and_hides_temporary_material() -> None:
    class FakeSts:
        def __init__(self) -> None:
            self.request: dict[str, Any] = {}

        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            self.request = kwargs
            return {
                "Credentials": {
                    "AccessKeyId": "synthetic-access",
                    "SecretAccessKey": "synthetic-secret",
                    "SessionToken": "synthetic-session",
                    "Expiration": datetime.now(UTC) + timedelta(minutes=15),
                }
            }

    sts = FakeSts()
    scope = AwsScopePolicy(
        "write",
        ("bucket/object",),
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "bucket/object"}]},
    )
    broker = AwsStsCredentialBroker(sts, "arn:aws:iam::123456789012:role/scoped", lambda *_: scope)
    resource = Resource("bucket/object", "s3", "tenant-a")
    credential = broker.mint(
        SimpleNamespace(task_id="task-a"), SimpleNamespace(name="write"), (resource,), 900
    )
    assert sts.request["RoleSessionName"].startswith("aai-")
    assert json.loads(sts.request["Policy"])["Statement"][0]["Resource"] == "bucket/object"
    captured: list[str] = []
    credential.with_secret(lambda value: captured.append(value))
    assert "synthetic-secret" in captured[0]
    assert not hasattr(credential, "secret")


def test_aws_sts_broker_rejects_scope_mismatch_and_incomplete_response() -> None:
    resource = Resource("bucket/object", "s3", "tenant-a")
    with pytest.raises(ValueError):
        AwsStsCredentialBroker(
            SimpleNamespace(assume_role=lambda **_: {"Credentials": {}}),
            "arn:aws:iam::123456789012:role/scoped",
            lambda *_: AwsScopePolicy(
                "other",
                ("bucket/object",),
                {"Version": "2012-10-17", "Statement": []},
            ),
        ).mint(SimpleNamespace(task_id="task"), SimpleNamespace(name="write"), (resource,), 900)


def test_aws_sts_broker_rechecks_live_revocation_before_credential_use() -> None:
    """A server revocation epoch can invalidate already-issued STS material."""
    resource = Resource("bucket/object", "s3", "tenant-a")
    policy = AwsScopePolicy(
        "write",
        (resource.id,),
        {"Version": "2012-10-17", "Statement": []},
    )
    active = {"value": True}
    observed_grants: list[str] = []

    def checker(grant_id: str) -> bool:
        observed_grants.append(grant_id)
        return active["value"]

    broker = AwsStsCredentialBroker(
        SimpleNamespace(
            assume_role=lambda **_: {
                "Credentials": {
                    "AccessKeyId": "synthetic-key",
                    "SecretAccessKey": "synthetic-secret",
                    "SessionToken": "synthetic-session",
                    "Expiration": datetime.now(UTC) + timedelta(minutes=15),
                }
            }
        ),
        "arn:aws:iam::123456789012:role/scoped",
        lambda *_: policy,
        checker,
    )
    credential = broker.mint(
        SimpleNamespace(task_id="task"), SimpleNamespace(name="write"), (resource,), 900
    )
    credential.with_secret(lambda _: None)
    assert len(set(observed_grants)) == 1

    active["value"] = False
    assert not credential.valid_for("write", (resource,))
    with pytest.raises(ValueError, match="revoked"):
        credential.with_secret(lambda _: None)


def test_aws_scope_policy_and_sts_input_validation() -> None:
    valid_document = {"Version": "2012-10-17", "Statement": []}
    with pytest.raises(ValueError, match="identity"):
        AwsScopePolicy(" ", ("resource",), valid_document)
    with pytest.raises(ValueError, match="mapping"):
        AwsScopePolicy("write", ("resource",), [])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Version"):
        AwsScopePolicy("write", ("resource",), {"Statement": []})
    with pytest.raises(ValueError, match="ARN"):
        AwsStsCredentialBroker(SimpleNamespace(), "not-an-arn", lambda *_: None)

    resource = Resource("bucket/object", "s3", "tenant-a")
    policy = AwsScopePolicy("write", ("bucket/object",), valid_document)
    broker = AwsStsCredentialBroker(
        SimpleNamespace(
            assume_role=lambda **_: {
                "Credentials": {
                    "AccessKeyId": "key",
                    "SecretAccessKey": "secret",
                    "SessionToken": "session",
                    "Expiration": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
                }
            }
        ),
        "arn:aws:iam::123456789012:role/scoped",
        lambda *_: policy,
    )
    with pytest.raises(ValueError, match="between 900 and 3600"):
        broker.mint(SimpleNamespace(task_id="task"), SimpleNamespace(name="write"), (resource,), 0)
    with pytest.raises(ValueError, match="between 900 and 3600"):
        broker.mint(
            SimpleNamespace(task_id="task"),
            SimpleNamespace(name="write"),
            (resource,),
            3601,
        )
    credential = broker.mint(
        SimpleNamespace(task_id="task"), SimpleNamespace(name="write"), (resource,), 900
    )
    assert credential.tool_name == "write"

    overlong = AwsStsCredentialBroker(
        SimpleNamespace(
            assume_role=lambda **_: {
                "Credentials": {
                    "AccessKeyId": "key",
                    "SecretAccessKey": "secret",
                    "SessionToken": "session",
                    "Expiration": datetime.now(UTC) + timedelta(minutes=20),
                }
            }
        ),
        "arn:aws:iam::123456789012:role/scoped",
        lambda *_: policy,
    )
    with pytest.raises(ValueError, match="exceeding the requested lifetime"):
        overlong.mint(
            SimpleNamespace(task_id="task"), SimpleNamespace(name="write"), (resource,), 900
        )

    with pytest.raises(ValueError):
        AwsStsCredentialBroker(
            SimpleNamespace(assume_role=lambda **_: {"Credentials": {}}),
            "arn:aws:iam::123456789012:role/scoped",
            lambda *_: AwsScopePolicy(
                "write",
                ("bucket/object",),
                {"Version": "2012-10-17", "Statement": []},
            ),
        ).mint(SimpleNamespace(task_id="task"), SimpleNamespace(name="write"), (resource,), 900)


def test_dynamodb_adapter_rehydrates_runtime_execution_results() -> None:
    table = FakeDynamoTable()
    store = DynamoDbIdempotencyStore(table)
    record = _record("execution-result", ttl=None)
    store.claim(record)
    result = ExecutionResult(ExecutionStatus.EXECUTED, "write", "request-1", output={"ok": True})
    store.complete(record.operation_key, result)
    restored = DynamoDbIdempotencyStore(table).lookup(record.operation_key)
    assert restored is not None
    assert restored.result == result

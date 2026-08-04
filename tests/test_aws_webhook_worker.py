"""Contract tests for the isolated signed-webhook delivery worker."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any, cast

import pytest

from agentic_security import WebhookVerificationStatus, verify_webhook


class Table:
    """Minimal conditional table used by the worker contract."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def get_item(self, *, Key: dict[str, str], **_: Any) -> dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> None:
        key = (Item["pk"], Item["sk"])
        current = self.items.get(key, {})
        values = kwargs.get("ExpressionAttributeValues", {})
        if kwargs.get("ConditionExpression") and (
            current.get("attempt_count", 0) != values.get(":attempt_count")
            or current.get("status", "pending") != values.get(":status")
        ):
            raise RuntimeError("synthetic conditional conflict")
        self.items[key] = dict(Item)


class Secrets:
    """Exact-version secret store for overlapping signing keys."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_secret_value(self, **value: str) -> dict[str, str]:
        return {"SecretString": self.values[(value["SecretId"], value["VersionId"])]}


class S3:
    """Capture terminal immutable evidence writes."""

    def __init__(self) -> None:
        self.objects: list[dict[str, Any]] = []

    def put_object(self, **value: Any) -> dict[str, str]:
        self.objects.append(dict(value))
        return {"VersionId": f"version-{len(self.objects)}"}


class Replay:
    """Atomic replay double for independent receiver verification."""

    def __init__(self) -> None:
        self.ids: set[str] = set()

    def claim(self, delivery_id: str, expires_at: int) -> bool:
        del expires_at
        if delivery_id in self.ids:
            return False
        self.ids.add(delivery_id)
        return True


def _load(monkeypatch: Any) -> tuple[Any, Table, Secrets, S3]:
    table, secrets, s3 = Table(), Secrets(), S3()
    boto3 = types.ModuleType("boto3")
    boto3.resource = lambda *_args, **_kwargs: types.SimpleNamespace(  # type: ignore[attr-defined]
        Table=lambda _name: table
    )
    boto3.client = lambda service, *_args, **_kwargs: (  # type: ignore[attr-defined]
        secrets if service == "secretsmanager" else s3
    )
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setenv("CONTROL_TABLE", "control")
    monkeypatch.setenv("AUDIT_BUCKET", "audit")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/webhook_worker.py"
    spec = importlib.util.spec_from_file_location("aai_webhook_worker", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, table, secrets, s3


def _records(tenant: str, delivery_id: str, receive_count: int = 1) -> dict[str, Any]:
    return {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "attributes": {"ApproximateReceiveCount": str(receive_count)},
                "body": json.dumps(
                    {
                        "schemaVersion": 1,
                        "tenantId": tenant,
                        "deliveryId": delivery_id,
                    }
                ),
            }
        ]
    }


def _seed(table: Table, secrets: Secrets, *, tenant: str = "tenant-a") -> tuple[str, bytes, bytes]:
    delivery_id = "delivery-a"
    old, new = b"o" * 32, b"n" * 32
    resource_arn = "arn:aws:secretsmanager:eu-west-2:111111111111:secret:aai-sec/webhooks/test"
    secrets.values[(resource_arn, "version-new")] = json.dumps(
        {"schemaVersion": 1, "keyId": "new-key", "secret": new.decode()}
    )
    secrets.values[(resource_arn, "version-old")] = json.dumps(
        {"schemaVersion": 1, "keyId": "old-key", "secret": old.decode()}
    )
    table.items[(f"TENANT#{tenant}", "WEBHOOK#destination-a")] = {
        "pk": f"TENANT#{tenant}",
        "sk": "WEBHOOK#destination-a",
        "id": "destination-a",
        "status": "active",
        "endpoint": "https://hooks.example.test/events",
        "secret_arn": resource_arn,
        "active_key_id": "new-key",
        "active_secret_version": "version-new",
        "previous_key_id": "old-key",
        "previous_secret_version": "version-old",
        "previous_key_valid_until": 2_000,
    }
    payload = json.dumps(
        {
            "schemaVersion": 1,
            "id": delivery_id,
            "type": "webhook.test",
            "createdAt": 1_000,
            "tenantId": tenant,
            "data": {"message": "test"},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    table.items[(f"TENANT#{tenant}", f"WEBHOOK_DELIVERY#{delivery_id}")] = {
        "pk": f"TENANT#{tenant}",
        "sk": f"WEBHOOK_DELIVERY#{delivery_id}",
        "tenant_id": tenant,
        "id": delivery_id,
        "destination_id": "destination-a",
        "event_type": "webhook.test",
        "payload": payload,
        "status": "queued",
        "attempt_count": 0,
        "created_at": 1_000,
        "webhook_outbox_pk": f"WEBHOOK_OUTBOX#{tenant}",
        "webhook_outbox_sk": f"0000001000#{delivery_id}",
    }
    return delivery_id, old, new


def test_worker_sends_exact_bytes_with_overlapping_signatures_and_audits(
    monkeypatch: Any,
) -> None:
    module, table, secrets, s3 = _load(monkeypatch)
    delivery_id, old, _new = _seed(table, secrets)
    monkeypatch.setattr(module.time, "time", lambda: 1_100)
    monkeypatch.setattr(
        module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("8.8.8.8", 443))],
    )
    captured: dict[str, Any] = {}

    class Response:
        status = 202

        def read(self, size: int) -> bytes:
            assert size == 4_097
            return b"accepted"

    class Opener:
        def open(self, request: Any, timeout: float) -> Response:
            captured.update({"request": request, "timeout": timeout})
            return Response()

    monkeypatch.setattr(module, "build_opener", lambda *_handlers: Opener())

    result = module.handler(_records("tenant-a", delivery_id), None)

    assert result["status"] == "delivered"
    assert result["response_status"] == 202
    request = captured["request"]
    headers = {name: value for name, value in request.header_items()}
    verified = verify_webhook(
        cast(bytes, request.data),
        headers,
        keys={"old-key": old},
        replay_store=Replay(),
        now=lambda: 1_100,
    )
    assert verified.status is WebhookVerificationStatus.VERIFIED
    assert verified.key_id == "old-key"
    assert captured["timeout"] == 5.0
    assert len(s3.objects) == 1
    audit = json.loads(s3.objects[0]["Body"])
    assert audit["status"] == "delivered"
    assert "secret" not in json.dumps(audit)
    health = table.items[("TENANT#tenant-a", "WEBHOOK_HEALTH#destination-a")]
    assert health["last_delivery_status"] == "delivered"
    assert health["delivery_id"] == delivery_id
    stored = table.items[("TENANT#tenant-a", f"WEBHOOK_DELIVERY#{delivery_id}")]
    assert "webhook_outbox_pk" not in stored


def test_worker_rejects_private_resolution_and_records_terminal_failure(
    monkeypatch: Any,
) -> None:
    module, table, secrets, s3 = _load(monkeypatch)
    delivery_id, _old, _new = _seed(table, secrets)
    monkeypatch.setattr(module.time, "time", lambda: 1_100)
    monkeypatch.setattr(
        module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("10.0.0.8", 443))],
    )

    with pytest.raises(RuntimeError, match="webhook delivery failed"):
        module.handler(_records("tenant-a", delivery_id, receive_count=5), None)

    stored = table.items[("TENANT#tenant-a", f"WEBHOOK_DELIVERY#{delivery_id}")]
    assert stored["status"] == "failed"
    assert stored["failure_code"] == "destination_invalid"
    assert len(s3.objects) == 1
    health = table.items[("TENANT#tenant-a", "WEBHOOK_HEALTH#destination-a")]
    assert health["last_delivery_status"] == "failed"


def test_worker_repairs_health_without_redelivering_terminal_event(
    monkeypatch: Any,
) -> None:
    module, table, secrets, _s3 = _load(monkeypatch)
    delivery_id, _old, _new = _seed(table, secrets)
    delivery = table.items[("TENANT#tenant-a", f"WEBHOOK_DELIVERY#{delivery_id}")]
    delivery.update({"status": "delivered", "attempt_count": 1, "last_attempt_at": 1_100})

    class NoNetwork:
        def open(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("terminal delivery must not be sent again")

    monkeypatch.setattr(module, "build_opener", lambda *_handlers: NoNetwork())

    result = module.handler(_records("tenant-a", delivery_id, receive_count=2), None)

    assert result["status"] == "delivered"
    assert (
        table.items[("TENANT#tenant-a", "WEBHOOK_HEALTH#destination-a")]["last_delivery_at"]
        == 1_100
    )


@pytest.mark.parametrize(
    "event",
    [
        {},
        {"Records": []},
        _records("tenant-a", "delivery-a", receive_count=0),
        {"Records": [{"eventSource": "aws:sns", "body": "{}"}]},
    ],
)
def test_worker_rejects_malformed_or_unauthorized_invocation(
    monkeypatch: Any, event: dict[str, Any]
) -> None:
    module, _table, _secrets, _s3 = _load(monkeypatch)
    with pytest.raises(ValueError):
        module.handler(event, None)


def test_webhook_worker_infrastructure_is_isolated_and_monitored() -> None:
    """Keep queue, key, least-privilege worker and DLQ alarms in the stack."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")

    assert 'new sqs.Queue(this, "WebhookDeliveryQueue"' in stack
    assert 'new sqs.Queue(this, "WebhookDeliveryDlq"' in stack
    assert "deadLetterQueue: { queue: webhookDeliveryDlq, maxReceiveCount: 5 }" in stack
    assert 'new kms.Key(this, "WebhookSecretKey"' in stack
    assert 'indexName: "WebhookOutbox"' in stack
    assert 'new lambda.Function(this, "WebhookDeliveryWorker"' in stack
    assert 'handler: "webhook_worker.handler"' in stack
    assert "webhookSecretKey.grantDecrypt(webhookWorker)" in stack
    assert "webhookSecretKey.grantEncrypt(handler)" in stack
    assert 'resourceName: "aai-sec/webhooks/*"' in stack
    assert 'source: "aai.webhook-dispatch"' in stack
    assert '"WebhookDeliveryDeadLetters"' in stack
    assert '"WebhookDispatchDeadLetters"' in stack

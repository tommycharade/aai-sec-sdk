"""Security and provider-contract tests for the isolated workflow worker."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest


class Table:
    """Minimal optimistic DynamoDB double for workflow delivery contracts."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def get_item(self, *, Key: dict[str, str], **_: Any) -> dict[str, Any]:
        value = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(value)} if value else {}

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> None:
        key = (Item["pk"], Item["sk"])
        values = kwargs.get("ExpressionAttributeValues", {})
        current = self.items.get(key, {})
        if kwargs.get("ConditionExpression") and (
            current.get("attempt_count", 0) != values.get(":attempt")
            or current.get("status", "pending") != values.get(":status")
        ):
            raise RuntimeError("synthetic conditional conflict")
        self.items[key] = dict(Item)


class Secrets:
    """Capture secret access while returning synthetic provider credentials."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.requests: list[dict[str, str]] = []

    def get_secret_value(self, **value: str) -> dict[str, str]:
        self.requests.append(dict(value))
        return {"SecretString": self.values[value["SecretId"]]}


class S3:
    """Capture immutable terminal audit evidence."""

    def __init__(self) -> None:
        self.objects: list[dict[str, Any]] = []

    def put_object(self, **value: Any) -> dict[str, str]:
        self.objects.append(dict(value))
        return {"VersionId": "synthetic-version"}


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
    monkeypatch.setenv("WORKFLOW_SECRET_PREFIX", "aai-sec/workflows/")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/workflow_worker.py"
    spec = importlib.util.spec_from_file_location("aai_workflow_worker", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, table, secrets, s3


def _event(delivery_id: str = "delivery-a", receive_count: int = 1) -> dict[str, Any]:
    return {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "attributes": {"ApproximateReceiveCount": str(receive_count)},
                "body": json.dumps({"tenantId": "tenant-a", "deliveryId": delivery_id}),
            }
        ]
    }


def _payload() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "eventType": "case.opened",
        "occurredAt": 1_000,
        "case": {
            "id": "case-a",
            "revision": 1,
            "status": "open",
            "severity": "high",
            "title": "Synthetic verification incident",
            "source": "synthetic",
            "reasonCode": "test_signal",
            "host": "synthetic-host",
            "agentId": "agent-a",
        },
    }


def _seed(
    table: Table,
    secrets: Secrets,
    *,
    provider: str = "pagerduty",
    status: str = "active",
    verification: bool = False,
) -> str:
    connection_id = "connection-a"
    delivery_id = "delivery-a"
    arn = (
        "arn:aws:secretsmanager:eu-west-2:111111111111:"
        "secret:aai-sec/workflows/tenant-a/connection-a-AbCdEf"
    )
    configurations = {
        "pagerduty": {"serviceLabel": "AAI production"},
        "jira": {
            "baseUrl": "https://synthetic.atlassian.net",
            "projectKey": "SEC",
            "issueType": "Incident",
        },
        "servicenow": {
            "baseUrl": "https://synthetic.service-now.com",
            "assignmentGroup": "Security Operations",
        },
    }
    credentials = {
        "pagerduty": {"schemaVersion": 1, "routingKey": "r" * 32},
        "jira": {
            "schemaVersion": 1,
            "email": "synthetic@example.invalid",
            "apiToken": "synthetic-token",
        },
        "servicenow": {
            "schemaVersion": 1,
            "clientId": "synthetic-client",
            "clientSecret": "synthetic-secret",
        },
    }
    secrets.values[arn] = json.dumps(credentials[provider])
    table.items[("TENANT#tenant-a", f"WORKFLOW_CONNECTION#{connection_id}")] = {
        "pk": "TENANT#tenant-a",
        "sk": f"WORKFLOW_CONNECTION#{connection_id}",
        "id": connection_id,
        "tenant_id": "tenant-a",
        "provider": provider,
        "configuration": configurations[provider],
        "credential_secret_arn": arn,
        "status": status,
        "revision": 3,
    }
    table.items[("TENANT#tenant-a", f"WORKFLOW_DELIVERY#{delivery_id}")] = {
        "pk": "TENANT#tenant-a",
        "sk": f"WORKFLOW_DELIVERY#{delivery_id}",
        "tenant_id": "tenant-a",
        "id": delivery_id,
        "connection_id": connection_id,
        "connection_revision": 3,
        "provider": provider,
        "event_type": "case.opened",
        "case_id": "case-a",
        "case_revision": 1,
        "verification": verification,
        "payload": _payload(),
        "status": "queued",
        "attempt_count": 0,
        "created_at": 1_000,
    }
    return delivery_id


def _public_dns(module: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("8.8.8.8", 443))],
    )


def test_pagerduty_delivery_uses_case_dedup_key_and_records_secret_free_evidence(
    monkeypatch: Any,
) -> None:
    module, table, secrets, s3 = _load(monkeypatch)
    delivery_id = _seed(table, secrets)
    captured: dict[str, Any] = {}

    class Response:
        status = 202

        def read(self, _size: int) -> bytes:
            return json.dumps({"status": "success", "dedup_key": "case-a"}).encode()

    class Opener:
        def open(self, request: Any, timeout: float) -> Response:
            captured.update({"request": request, "timeout": timeout})
            return Response()

    monkeypatch.setattr(module, "build_opener", lambda *_handlers: Opener())
    monkeypatch.setattr(module.time, "time", lambda: 1_100)
    _public_dns(module, monkeypatch)

    result = module.handler(_event(delivery_id), None)

    assert result["status"] == "delivered"
    assert result["external_reference"] == "case-a"
    assert captured["request"].full_url == "https://events.pagerduty.com/v2/enqueue"
    outbound = json.loads(captured["request"].data)
    assert outbound["dedup_key"] == "case-a"
    assert outbound["event_action"] == "trigger"
    assert captured["timeout"] == 5.0
    assert secrets.requests == [{"SecretId": next(iter(secrets.values))}]
    assert len(s3.objects) == 1
    evidence = json.loads(s3.objects[0]["Body"])
    assert evidence["externalReference"] == "case-a"
    assert "routingKey" not in json.dumps(evidence)
    health = table.items[("TENANT#tenant-a", "WORKFLOW_HEALTH#connection-a")]
    assert health["last_delivery_status"] == "delivered"


@pytest.mark.parametrize("provider", ["jira", "servicenow"])
def test_saas_adapters_reconcile_before_create(monkeypatch: Any, provider: str) -> None:
    module, table, secrets, _s3 = _load(monkeypatch)
    _seed(table, secrets, provider=provider)
    _public_dns(module, monkeypatch)
    requests: list[Any] = []

    responses: list[tuple[int, dict[str, Any]]] = (
        [
            (200, {"issues": []}),
            (201, {"key": "SEC-101"}),
        ]
        if provider == "jira"
        else [
            (200, {"access_token": "synthetic-access"}),
            (200, {"result": []}),
            (201, {"result": {"sys_id": "sys-a", "number": "INC001"}}),
        ]
    )

    class Response:
        def __init__(self, status: int, body: dict[str, Any]) -> None:
            self.status = status
            self.body = body

        def read(self, _size: int) -> bytes:
            return json.dumps(self.body).encode()

    class Opener:
        def open(self, request: Any, timeout: float) -> Response:
            assert timeout == 5.0
            requests.append(request)
            status, body = responses[len(requests) - 1]
            return Response(status, body)

    monkeypatch.setattr(module, "build_opener", lambda *_handlers: Opener())
    _public_dns(module, monkeypatch)

    result = module.handler(_event(), None)

    assert result["status"] == "delivered"
    assert result["external_reference"] == ("SEC-101" if provider == "jira" else "INC001")
    methods = [request.method for request in requests]
    assert methods == (["POST", "POST"] if provider == "jira" else ["POST", "GET", "POST"])


def test_worker_fails_closed_before_secret_access_when_authority_changes(
    monkeypatch: Any,
) -> None:
    module, table, secrets, s3 = _load(monkeypatch)
    _seed(table, secrets)
    table.items[("TENANT#tenant-a", "WORKFLOW_CONNECTION#connection-a")]["revision"] = 4

    result = module.handler(_event(), None)

    assert result["status"] == "failed"
    assert result["failure_code"] == "connection_authority_changed"
    assert secrets.requests == []
    assert len(s3.objects) == 1


def test_worker_fails_closed_before_secret_access_when_payload_identity_changes(
    monkeypatch: Any,
) -> None:
    module, table, secrets, s3 = _load(monkeypatch)
    _seed(table, secrets)
    table.items[("TENANT#tenant-a", "WORKFLOW_DELIVERY#delivery-a")]["payload"]["case"]["id"] = (
        "case-forged"
    )

    result = module.handler(_event(), None)

    assert result["status"] == "failed"
    assert result["failure_code"] == "payload_invalid"
    assert secrets.requests == []
    assert len(s3.objects) == 1


def test_worker_rejects_cross_tenant_secret_and_private_provider_resolution(
    monkeypatch: Any,
) -> None:
    module, table, secrets, _s3 = _load(monkeypatch)
    _seed(table, secrets, provider="jira")
    connection = table.items[("TENANT#tenant-a", "WORKFLOW_CONNECTION#connection-a")]
    connection["credential_secret_arn"] = connection["credential_secret_arn"].replace(
        "/tenant-a/", "/tenant-b/"
    )

    with pytest.raises(RuntimeError, match="workflow delivery failed"):
        module.handler(_event(receive_count=1), None)
    assert secrets.requests == []

    connection["credential_secret_arn"] = next(iter(secrets.values))
    monkeypatch.setattr(
        module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("10.0.0.8", 443))],
    )
    delivery = table.items[("TENANT#tenant-a", "WORKFLOW_DELIVERY#delivery-a")]
    delivery.update({"status": "queued", "attempt_count": 1})
    with pytest.raises(RuntimeError, match="workflow delivery failed"):
        module.handler(_event(receive_count=2), None)


def test_verification_delivery_can_run_while_pending_and_marks_exact_revision(
    monkeypatch: Any,
) -> None:
    module, table, secrets, _s3 = _load(monkeypatch)
    _seed(table, secrets, status="pending_verification", verification=True)

    class Response:
        status = 202

        def read(self, _size: int) -> bytes:
            return json.dumps({"dedup_key": "case-a"}).encode()

    class Opener:
        def open(self, _request: Any, timeout: float) -> Response:
            assert timeout == 5.0
            return Response()

    monkeypatch.setattr(module, "build_opener", lambda *_handlers: Opener())

    module.handler(_event(), None)

    health = table.items[("TENANT#tenant-a", "WORKFLOW_HEALTH#connection-a")]
    assert health["last_verification_status"] == "delivered"
    assert health["verified_revision"] == 3


def test_worker_infrastructure_is_isolated_and_monitored() -> None:
    """Keep queue, worker, credential and alarm isolation reviewable in IaC."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text()
    assert 'new sqs.Queue(this, "WorkflowDeliveryQueue"' in stack
    assert 'new sqs.Queue(this, "WorkflowDeliveryDlq"' in stack
    assert "deadLetterQueue: { queue: workflowDeliveryDlq, maxReceiveCount: 5 }" in stack
    assert 'new lambda.Function(this, "WorkflowDeliveryWorker"' in stack
    assert 'handler: "workflow_worker.handler"' in stack
    assert "workflowCredentialKey.grantDecrypt(workflowWorker)" in stack
    assert "workflowCredentialKey.grantEncrypt(handler)" not in stack
    assert 'resourceName: "aai-sec/workflows/*"' in stack
    assert 'source: "aai.workflow-dispatch"' in stack
    assert '"WorkflowDeliveryDeadLetters"' in stack
    assert 'indexName: "WorkflowOutbox"' in stack

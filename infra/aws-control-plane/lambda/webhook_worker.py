"""Deliver tenant-managed webhooks through a bounded, credential-owning worker.

The API Lambda persists an outbox record before queueing its identity. This
worker reloads destination authority and exact secret versions for every
attempt, signs the exact stored bytes, rejects private network destinations,
and records content-minimised delivery evidence. It never accepts endpoint or
key material from the SQS message.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import boto3

TABLE_NAME = os.environ["CONTROL_TABLE"]
TABLE = boto3.resource("dynamodb").Table(TABLE_NAME)
SECRETS = boto3.client("secretsmanager")
S3 = boto3.client("s3")
_MAX_RECEIVE_COUNT = 5
_MAX_RESPONSE_BYTES = 4_096


class _NoRedirects(HTTPRedirectHandler):
    """Reject redirects so signed content and credentials never change origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Return no redirected request; urllib then reports the 3xx response."""
        return None


def _key(tenant: str, kind: str, identifier: str) -> dict[str, str]:
    """Return one tenant-scoped DynamoDB key."""
    return {"pk": f"TENANT#{tenant}", "sk": f"{kind}#{identifier}"}


def _identifier(value: object, field: str) -> str:
    """Validate a bounded routing identifier from the queue lookup message."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for character in value
        )
    ):
        raise ValueError(f"{field} is invalid")
    return value


def _destination_url(value: object) -> str:
    """Repeat the API URL checks at the outbound network boundary."""
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("stored webhook endpoint is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise ValueError("stored webhook endpoint is invalid")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("stored webhook endpoint is not public")
    # Resolve immediately before connection and reject the entire destination
    # if any answer is not globally routable. Deployment-owned egress controls
    # remain required to eliminate the residual DNS-rebinding interval.
    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if result[4]
    }
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("stored webhook endpoint resolved outside the public network")
    return value


def _secret(record: dict[str, object], version_field: str, key_field: str) -> tuple[str, bytes]:
    """Load and validate one exact Secrets Manager version selected by DynamoDB."""
    version = record.get(version_field)
    expected_key = record.get(key_field)
    arn = record.get("secret_arn")
    if not all(isinstance(value, str) and value for value in (version, expected_key, arn)):
        raise RuntimeError("webhook key authority is incomplete")
    response = SECRETS.get_secret_value(SecretId=arn, VersionId=version)
    try:
        value = json.loads(response.get("SecretString", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("webhook key material is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "keyId", "secret"}
        or value.get("schemaVersion") != 1
        or value.get("keyId") != expected_key
        or not isinstance(value.get("secret"), str)
        or len(value["secret"].encode()) < 32
    ):
        raise RuntimeError("webhook key material does not match destination authority")
    return expected_key, value["secret"].encode()


def _signature(secret: bytes, timestamp: int, delivery_id: str, payload: bytes) -> str:
    """Return the version-one HMAC over exact timestamp, identity, and bytes."""
    signed = str(timestamp).encode() + b"." + delivery_id.encode() + b"." + payload
    return "v1=" + hmac.new(secret, signed, hashlib.sha256).hexdigest()


def _record_attempt(
    delivery: dict[str, object],
    *,
    status: str,
    attempt: int,
    response_status: int | None = None,
    failure_code: str | None = None,
) -> dict[str, object]:
    """Persist one optimistic delivery transition without response content."""
    now = int(time.time())
    updated = {
        **{
            key: value
            for key, value in delivery.items()
            if key not in {"webhook_outbox_pk", "webhook_outbox_sk"}
        },
        "status": status,
        "attempt_count": attempt,
        "last_attempt_at": now,
        "response_status": response_status,
        "failure_code": failure_code,
    }
    if status == "delivered":
        updated["delivered_at"] = now
    TABLE.put_item(
        Item=updated,
        ConditionExpression="attempt_count = :attempt_count AND #status = :status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":attempt_count": int(delivery.get("attempt_count", 0)),
            ":status": delivery.get("status", "pending"),
        },
    )
    return updated


def _record_destination_health(tenant: str, delivery: dict[str, object]) -> None:
    """Materialize content-free destination posture without touching config authority.

    Health has its own item so a worker can never overwrite an administrator's
    concurrent endpoint, key, event, status, or revision update. Delivery
    records and immutable audit remain the source evidence; this record is only
    the bounded list-page projection.
    """
    observed_at = int(delivery.get("last_attempt_at") or time.time())
    TABLE.put_item(
        Item={
            **_key(tenant, "WEBHOOK_HEALTH", str(delivery.get("destination_id", ""))),
            "tenant_id": tenant,
            "destination_id": delivery.get("destination_id"),
            "delivery_id": delivery.get("id"),
            "last_delivery_at": observed_at,
            "last_delivery_status": delivery.get("status", "unknown"),
            "updated_at": observed_at,
        }
    )


def _audit_terminal(tenant: str, delivery: dict[str, object]) -> None:
    """Write immutable content-minimised terminal evidence to Object Lock storage."""
    bucket = os.environ.get("AUDIT_BUCKET", "")
    if not bucket:
        raise RuntimeError("webhook audit bucket is not configured")
    payload = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "eventType": "webhook_delivery_terminal",
        "deliveryId": delivery.get("id"),
        "destinationId": delivery.get("destination_id"),
        "webhookEventType": delivery.get("event_type"),
        "status": delivery.get("status"),
        "attemptCount": int(delivery.get("attempt_count", 0)),
        "responseStatus": delivery.get("response_status"),
        "failureCode": delivery.get("failure_code"),
        "recordedAt": int(time.time()),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    S3.put_object(
        Bucket=bucket,
        Key=f"tenant={tenant}/webhooks/{delivery.get('id')}.json",
        Body=encoded,
        ContentType="application/json",
        Metadata={"sha256": hashlib.sha256(encoded).hexdigest()},
    )


def _terminal_attempt(
    tenant: str,
    delivery: dict[str, object],
    *,
    status: str,
    attempt: int,
    response_status: int | None = None,
    failure_code: str | None = None,
) -> dict[str, object]:
    """Commit immutable audit before mutable terminal delivery posture."""
    candidate = {
        **delivery,
        "status": status,
        "attempt_count": attempt,
        "response_status": response_status,
        "failure_code": failure_code,
    }
    _audit_terminal(tenant, candidate)
    updated = _record_attempt(
        delivery,
        status=status,
        attempt=attempt,
        response_status=response_status,
        failure_code=failure_code,
    )
    _record_destination_health(tenant, updated)
    return updated


def _deliver(tenant: str, delivery_id: str, receive_count: int) -> dict[str, object]:
    """Execute one retry-safe delivery attempt from live server-owned state."""
    delivery = TABLE.get_item(
        Key=_key(tenant, "WEBHOOK_DELIVERY", delivery_id), ConsistentRead=True
    ).get("Item")
    if not delivery:
        raise ValueError("webhook delivery not found")
    if delivery.get("status") in {"delivered", "failed"}:
        # A previous attempt may have committed terminal evidence before a
        # transient health-projection failure. Repair the projection without
        # sending the event again.
        _record_destination_health(tenant, delivery)
        return delivery
    destination_id = _identifier(delivery.get("destination_id"), "destinationId")
    destination = TABLE.get_item(
        Key=_key(tenant, "WEBHOOK", destination_id), ConsistentRead=True
    ).get("Item")
    if not destination or destination.get("status") != "active":
        return _terminal_attempt(
            tenant,
            delivery,
            status="failed",
            attempt=receive_count,
            failure_code="destination_inactive",
        )
    try:
        endpoint = _destination_url(destination.get("endpoint"))
    except Exception as error:
        if receive_count >= _MAX_RECEIVE_COUNT:
            _terminal_attempt(
                tenant,
                delivery,
                status="failed",
                attempt=receive_count,
                failure_code="destination_invalid",
            )
        else:
            _record_attempt(
                delivery,
                status="retrying",
                attempt=receive_count,
                failure_code="destination_invalid",
            )
        raise RuntimeError("webhook delivery failed") from error
    payload_text = delivery.get("payload")
    if not isinstance(payload_text, str):
        raise RuntimeError("webhook payload is unavailable")
    payload = payload_text.encode()
    if len(payload) > 16_384:
        raise RuntimeError("webhook payload exceeds worker bound")
    timestamp = int(time.time())
    try:
        active_key_id, active_secret = _secret(
            destination, "active_secret_version", "active_key_id"
        )
        previous = None
        previous_until = destination.get("previous_key_valid_until")
        if isinstance(previous_until, int) and previous_until > timestamp:
            previous = _secret(destination, "previous_secret_version", "previous_key_id")
    except Exception as error:
        if receive_count >= _MAX_RECEIVE_COUNT:
            _terminal_attempt(
                tenant,
                delivery,
                status="failed",
                attempt=receive_count,
                failure_code="signing_key_invalid",
            )
        else:
            _record_attempt(
                delivery,
                status="retrying",
                attempt=receive_count,
                failure_code="signing_key_invalid",
            )
        raise RuntimeError("webhook delivery failed") from error
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "aai-sec-webhooks/1",
        "AAI-Webhook-Version": "1",
        "AAI-Webhook-Id": delivery_id,
        "AAI-Webhook-Timestamp": str(timestamp),
        "AAI-Webhook-Key-Id": active_key_id,
        "AAI-Webhook-Signature": _signature(active_secret, timestamp, delivery_id, payload),
    }
    if previous is not None:
        previous_key_id, previous_secret = previous
        headers["AAI-Webhook-Previous-Key-Id"] = previous_key_id
        headers["AAI-Webhook-Previous-Signature"] = _signature(
            previous_secret, timestamp, delivery_id, payload
        )
    request = Request(  # noqa: S310 - exact HTTPS URL is validated immediately above.
        endpoint, data=payload, headers=headers, method="POST"
    )
    try:
        response = build_opener(_NoRedirects()).open(request, timeout=5.0)
        status = int(getattr(response, "status", 0))
        # Bound and discard the body so a receiver cannot turn its response
        # into retained content or unbounded worker memory.
        response.read(_MAX_RESPONSE_BYTES + 1)
        if not 200 <= status < 300:
            raise HTTPError(endpoint, status, "non-success", {}, None)
    except Exception as error:
        code = "http_error" if isinstance(error, HTTPError) else "transport_error"
        if receive_count >= _MAX_RECEIVE_COUNT:
            _terminal_attempt(
                tenant,
                delivery,
                status="failed",
                attempt=receive_count,
                response_status=error.code if isinstance(error, HTTPError) else None,
                failure_code=code,
            )
        else:
            _record_attempt(
                delivery,
                status="retrying",
                attempt=receive_count,
                response_status=error.code if isinstance(error, HTTPError) else None,
                failure_code=code,
            )
        raise RuntimeError("webhook delivery failed") from error
    return _terminal_attempt(
        tenant,
        delivery,
        status="delivered",
        attempt=receive_count,
        response_status=status,
    )


def handler(event, context):  # noqa: ANN001, ANN201
    """Process one SQS delivery identity; ``context`` is intentionally unused."""
    records = event.get("Records") if isinstance(event, dict) else None
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("webhook worker requires exactly one SQS record")
    record = records[0]
    if record.get("eventSource") not in {"aws:sqs", None}:
        raise ValueError("webhook worker event source is invalid")
    try:
        body = json.loads(record.get("body", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("webhook worker message is invalid") from error
    if (
        not isinstance(body, dict)
        or set(body) != {"schemaVersion", "tenantId", "deliveryId"}
        or body.get("schemaVersion") != 1
    ):
        raise ValueError("webhook worker message schema is invalid")
    tenant = _identifier(body.get("tenantId"), "tenantId")
    delivery_id = _identifier(body.get("deliveryId"), "deliveryId")
    receive_count = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
    if not 1 <= receive_count <= _MAX_RECEIVE_COUNT:
        raise ValueError("webhook worker receive count is invalid")
    return _deliver(tenant, delivery_id, receive_count)

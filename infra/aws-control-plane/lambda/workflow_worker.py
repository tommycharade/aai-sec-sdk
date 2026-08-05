"""Deliver governed incident workflows through isolated provider adapters.

The control-plane API stores only a tenant-scoped Secrets Manager ARN and
queues an opaque delivery identity. This worker reloads live connection
authority and credential material for every attempt, validates outbound
destinations immediately before use, reconciles deterministic external
references before creation, and records only content-minimised evidence.
Provider responses and credentials never enter the API process or audit log.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import socket
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import boto3

TABLE = boto3.resource("dynamodb").Table(os.environ["CONTROL_TABLE"])
SECRETS = boto3.client("secretsmanager")
S3 = boto3.client("s3")
_MAX_RECEIVE_COUNT = 5
_MAX_RESPONSE_BYTES = 16_384
_PROVIDERS = frozenset({"servicenow", "jira", "pagerduty"})


class _NoRedirects(HTTPRedirectHandler):
    """Reject redirects so credentials can never cross an origin boundary."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Return no redirected request; urllib exposes the 3xx response."""
        return None


def _key(tenant: str, kind: str, identifier: str) -> dict[str, str]:
    """Return one tenant-scoped DynamoDB key."""
    return {"pk": f"TENANT#{tenant}", "sk": f"{kind}#{identifier}"}


def _identifier(value: object, field: str) -> str:
    """Validate one bounded lookup identifier controlled by persisted state."""
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


def _public_origin(value: object, provider: str) -> str:
    """Validate and resolve a provider-owned HTTPS origin at the egress boundary."""
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("stored provider origin is invalid")
    parsed = urlsplit(value)
    expected = ".service-now.com" if provider == "servicenow" else ".atlassian.net"
    host = (parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme != "https"
        or not host.endswith(expected)
        or host == expected[1:]
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port not in {None, 443}
    ):
        raise ValueError("stored provider origin is invalid")
    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if result[4]
    }
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("stored provider origin resolved outside the public network")
    return f"https://{host}"


def _secret_arn(tenant: str, value: object) -> str:
    """Revalidate the exact tenant credential namespace before secret access."""
    prefix = os.environ.get("WORKFLOW_SECRET_PREFIX", "")
    parts = value.split(":", 6) if isinstance(value, str) else []
    expected_resource = f"{prefix}{tenant}/"
    if (
        not prefix
        or not prefix.endswith("/")
        or not isinstance(value, str)
        or len(value) > 512
        or len(parts) != 7
        or parts[0] != "arn"
        or parts[2] != "secretsmanager"
        or not parts[3]
        or not parts[4]
        or parts[5] != "secret"
        or not parts[6].startswith(expected_resource)
        or len(parts[6]) <= len(expected_resource)
    ):
        raise ValueError("stored workflow credential ARN is outside the tenant namespace")
    return value


def _pagerduty_endpoint() -> str:
    """Resolve PagerDuty's fixed Events API host at the egress boundary."""
    host = "events.pagerduty.com"
    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if result[4]
    }
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("PagerDuty endpoint resolved outside the public network")
    return f"https://{host}/v2/enqueue"


def _credentials(tenant: str, connection: dict[str, object]) -> dict[str, str]:
    """Load and strictly validate provider credentials from Secrets Manager."""
    provider = connection.get("provider")
    expected = {
        "servicenow": {"schemaVersion", "clientId", "clientSecret"},
        "jira": {"schemaVersion", "email", "apiToken"},
        "pagerduty": {"schemaVersion", "routingKey"},
    }.get(provider)
    if expected is None:
        raise ValueError("stored workflow provider is unsupported")
    response = SECRETS.get_secret_value(
        SecretId=_secret_arn(tenant, connection.get("credential_secret_arn"))
    )
    try:
        value = json.loads(response.get("SecretString", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("workflow credential is malformed") from error
    if not isinstance(value, dict) or set(value) != expected or value.get("schemaVersion") != 1:
        raise ValueError("workflow credential schema does not match its provider")
    for key in expected - {"schemaVersion"}:
        item = value.get(key)
        if not isinstance(item, str) or not item or len(item.encode()) > 4_096:
            raise ValueError("workflow credential contains an invalid value")
    return value


def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    body: dict[str, object] | None = None,
    encoded_body: bytes | None = None,
) -> tuple[int, dict[str, object]]:
    """Send one bounded no-redirect request and parse a bounded JSON response."""
    data = encoded_body
    request_headers = {"Accept": "application/json", "User-Agent": "aai-sec-workflows/1", **headers}
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=request_headers, method=method)  # noqa: S310
    response = build_opener(_NoRedirects()).open(request, timeout=5.0)
    status = int(getattr(response, "status", 0))
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("provider response exceeds the worker bound")
    if not 200 <= status < 300:
        raise HTTPError(url, status, "non-success", {}, None)
    if not raw:
        return status, {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("provider response is not valid JSON") from error
    if not isinstance(parsed, dict):
        raise RuntimeError("provider response must be a JSON object")
    return status, parsed


def _case(payload: object) -> dict[str, object]:
    """Validate the fixed content-minimised payload created by the API."""
    if not isinstance(payload, dict) or set(payload) != {
        "schemaVersion", "eventType", "occurredAt", "case"
    } or payload.get("schemaVersion") != 1:
        raise ValueError("stored workflow payload schema is invalid")
    case = payload.get("case")
    if not isinstance(case, dict) or set(case) != {
        "id", "revision", "status", "severity", "title", "source", "reasonCode", "host", "agentId"
    }:
        raise ValueError("stored workflow case schema is invalid")
    _identifier(case.get("id"), "caseId")
    if not isinstance(case.get("revision"), int) or not 1 <= case["revision"] <= 1_000_000:
        raise ValueError("stored workflow case revision is invalid")
    for field in ("status", "severity", "title", "source", "reasonCode"):
        if not isinstance(case.get(field), str) or len(case[field]) > 240:
            raise ValueError("stored workflow case content is invalid")
    for field in ("host", "agentId"):
        if case.get(field) is not None and (
            not isinstance(case[field], str) or len(case[field]) > 240
        ):
            raise ValueError("stored workflow case binding is invalid")
    return case


def _description(case: dict[str, object], event_type: str) -> str:
    """Return a fixed, content-minimised provider description."""
    return "\n".join(
        (
            "AAI Security managed incident",
            f"Case: {case['id']}",
            f"Lifecycle event: {event_type}",
            f"Severity: {case['severity']}",
            f"Reason code: {case['reasonCode']}",
            f"Agent: {case.get('agentId') or 'not bound'}",
            f"Host: {case.get('host') or 'not bound'}",
        )
    )


def _servicenow(
    connection: dict[str, object], credentials: dict[str, str], payload: dict[str, object]
) -> tuple[int, str]:
    """Reconcile and idempotently create or update one ServiceNow incident."""
    configuration = connection.get("configuration")
    if not isinstance(configuration, dict) or set(configuration) != {"baseUrl", "assignmentGroup"}:
        raise ValueError("stored ServiceNow configuration is invalid")
    base_url = configuration.get("baseUrl")
    token_status, token = _request_json(
        "POST",
        f"{_public_origin(base_url, 'servicenow')}/oauth_token.do",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        encoded_body=urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": credentials["clientId"],
                "client_secret": credentials["clientSecret"],
            }
        ).encode(),
    )
    access_token = token.get("access_token")
    if token_status != 200 or not isinstance(access_token, str) or not access_token:
        raise RuntimeError("ServiceNow did not return an access token")
    case = _case(payload)
    correlation = f"aai:{case['id']}"
    headers = {"Authorization": f"Bearer {access_token}"}
    query = quote(f"correlation_id={correlation}", safe="")
    _, search = _request_json(
        "GET",
        f"{_public_origin(base_url, 'servicenow')}/api/now/table/incident"
        f"?sysparm_query={query}&sysparm_fields=sys_id,number&sysparm_limit=2",
        headers=headers,
    )
    results = search.get("result")
    if not isinstance(results, list) or len(results) > 2:
        raise RuntimeError("ServiceNow reconciliation response is invalid")
    if len(results) > 1:
        raise RuntimeError("ServiceNow returned ambiguous external references")
    event_type = str(payload["eventType"])
    fields: dict[str, object] = {
        "short_description": f"[AAI {case['severity']}] {case['title']}"[:240],
        "description": _description(case, event_type),
        "correlation_id": correlation,
    }
    if configuration["assignmentGroup"]:
        fields["assignment_group"] = configuration["assignmentGroup"]
    if event_type == "case.resolved":
        fields.update(
            {
                "state": "6",
                "close_code": "Solved (Permanently)",
                "close_notes": "Resolved by AAI Security",
            }
        )
    elif event_type == "case.closed":
        fields.update({"state": "7", "close_notes": "Closed by AAI Security"})
    if results:
        existing = results[0]
        if not isinstance(existing, dict) or not isinstance(existing.get("sys_id"), str):
            raise RuntimeError("ServiceNow external reference is invalid")
        status, response = _request_json(
            "PATCH",
            f"{_public_origin(base_url, 'servicenow')}/api/now/table/incident/"
            f"{quote(existing['sys_id'], safe='')}",
            headers=headers,
            body=fields,
        )
        reference = existing.get("number") or existing["sys_id"]
    else:
        status, response = _request_json(
            "POST",
            f"{_public_origin(base_url, 'servicenow')}/api/now/table/incident",
            headers=headers,
            body=fields,
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("ServiceNow creation response is invalid")
        reference = result.get("number") or result.get("sys_id")
    if not isinstance(reference, str) or not reference or len(reference) > 128:
        raise RuntimeError("ServiceNow external reference is invalid")
    return status, reference


def _jira(
    connection: dict[str, object], credentials: dict[str, str], payload: dict[str, object]
) -> tuple[int, str]:
    """Reconcile and idempotently create or update one Jira issue."""
    configuration = connection.get("configuration")
    if not isinstance(configuration, dict) or set(configuration) != {
        "baseUrl",
        "projectKey",
        "issueType",
    }:
        raise ValueError("stored Jira configuration is invalid")
    base_url = configuration.get("baseUrl")
    authorization = base64.b64encode(
        f"{credentials['email']}:{credentials['apiToken']}".encode()
    ).decode()
    headers = {"Authorization": f"Basic {authorization}"}
    case = _case(payload)
    label = "aai-case-" + hashlib.sha256(str(case["id"]).encode()).hexdigest()[:24]
    _, search = _request_json(
        "POST",
        f"{_public_origin(base_url, 'jira')}/rest/api/3/search/jql",
        headers=headers,
        body={
            "jql": (
                f'project = "{configuration["projectKey"]}" AND labels = "{label}"'
            ),
            "maxResults": 2,
            "fields": ["key"],
        },
    )
    issues = search.get("issues")
    if not isinstance(issues, list) or len(issues) > 2:
        raise RuntimeError("Jira reconciliation response is invalid")
    if len(issues) > 1:
        raise RuntimeError("Jira returned ambiguous external references")
    event_type = str(payload["eventType"])
    event_label = "aai-state-" + event_type.split(".", 1)[-1]
    fields: dict[str, object] = {
        "summary": f"[AAI {case['severity']}] {case['title']}"[:240],
        "labels": [label, event_label],
        "description": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": _description(case, event_type)}
                    ],
                }
            ],
        },
    }
    if issues:
        issue = issues[0]
        if not isinstance(issue, dict) or not isinstance(issue.get("key"), str):
            raise RuntimeError("Jira external reference is invalid")
        reference = issue["key"]
        status, _ = _request_json(
            "PUT",
            f"{_public_origin(base_url, 'jira')}/rest/api/3/issue/"
            f"{quote(reference, safe='')}",
            headers=headers,
            body={"fields": fields},
        )
    else:
        fields.update(
            {
                "project": {"key": configuration["projectKey"]},
                "issuetype": {"name": configuration["issueType"]},
            }
        )
        status, response = _request_json(
            "POST",
            f"{_public_origin(base_url, 'jira')}/rest/api/3/issue",
            headers=headers,
            body={"fields": fields},
        )
        reference = response.get("key")
    if not isinstance(reference, str) or not reference or len(reference) > 128:
        raise RuntimeError("Jira external reference is invalid")
    return status, reference


def _pagerduty(
    connection: dict[str, object], credentials: dict[str, str], payload: dict[str, object]
) -> tuple[int, str]:
    """Use the case identity as PagerDuty's retry-safe deduplication key."""
    configuration = connection.get("configuration")
    if not isinstance(configuration, dict) or set(configuration) != {"serviceLabel"}:
        raise ValueError("stored PagerDuty configuration is invalid")
    case = _case(payload)
    event_type = str(payload["eventType"])
    action = "resolve" if event_type in {"case.resolved", "case.closed"} else "trigger"
    body: dict[str, object] = {
        "routing_key": credentials["routingKey"],
        "event_action": action,
        "dedup_key": str(case["id"]),
    }
    if action == "trigger":
        severity = {"critical": "critical", "high": "error", "medium": "warning"}.get(
            str(case["severity"]), "info"
        )
        body["payload"] = {
            "summary": f"[AAI {case['severity']}] {case['title']}"[:240],
            "source": configuration["serviceLabel"],
            "severity": severity,
            "custom_details": {
                "case_id": case["id"],
                "event_type": event_type,
                "reason_code": case["reasonCode"],
                "agent_id": case.get("agentId") or "not bound",
            },
        }
    status, response = _request_json(
        "POST", _pagerduty_endpoint(), headers={}, body=body
    )
    reference = response.get("dedup_key") or case["id"]
    if not isinstance(reference, str) or not reference or len(reference) > 128:
        raise RuntimeError("PagerDuty external reference is invalid")
    return status, reference


def _record_attempt(
    delivery: dict[str, object], *, status: str, attempt: int,
    response_status: int | None = None, failure_code: str | None = None,
    external_reference: str | None = None,
) -> dict[str, object]:
    """Persist an optimistic delivery transition without provider content."""
    now = int(time.time())
    updated = {
        **{
            key: value
            for key, value in delivery.items()
            if key not in {"workflow_outbox_pk", "workflow_outbox_sk"}
        },
        "status": status,
        "attempt_count": attempt,
        "updated_at": now,
        "last_attempt_at": now,
        "response_status": response_status,
        "failure_code": failure_code,
        "external_reference": external_reference,
    }
    if status == "delivered":
        updated["delivered_at"] = now
    TABLE.put_item(
        Item=updated,
        ConditionExpression="attempt_count = :attempt AND #status = :status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":attempt": int(delivery.get("attempt_count", 0)),
            ":status": delivery.get("status", "pending"),
        },
    )
    return updated


def _record_health(tenant: str, delivery: dict[str, object]) -> None:
    """Materialize secret-free provider posture without mutating configuration."""
    now = int(delivery.get("updated_at") or time.time())
    current = TABLE.get_item(
        Key=_key(tenant, "WORKFLOW_HEALTH", str(delivery.get("connection_id", ""))),
        ConsistentRead=True,
    ).get("Item") or {}
    health = {
        **current,
        **_key(tenant, "WORKFLOW_HEALTH", str(delivery.get("connection_id", ""))),
        "tenant_id": tenant,
        "connection_id": delivery.get("connection_id"),
        "last_delivery_at": now,
        "last_delivery_status": delivery.get("status"),
        "last_external_reference": delivery.get("external_reference"),
        "updated_at": now,
    }
    if delivery.get("verification") is True:
        health.update(
            {
                "last_verification_at": now,
                "last_verification_status": delivery.get("status"),
                "verified_revision": (
                    delivery.get("connection_revision")
                    if delivery.get("status") == "delivered"
                    else current.get("verified_revision")
                ),
            }
        )
    TABLE.put_item(Item=health)


def _audit_terminal(tenant: str, delivery: dict[str, object]) -> None:
    """Write immutable content-minimised terminal evidence before mutable posture."""
    bucket = os.environ.get("AUDIT_BUCKET", "")
    if not bucket:
        raise RuntimeError("workflow audit bucket is not configured")
    payload = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "eventType": "workflow_delivery_terminal",
        "deliveryId": delivery.get("id"),
        "connectionId": delivery.get("connection_id"),
        "provider": delivery.get("provider"),
        "workflowEventType": delivery.get("event_type"),
        "verification": delivery.get("verification") is True,
        "status": delivery.get("status"),
        "attemptCount": int(delivery.get("attempt_count", 0)),
        "responseStatus": delivery.get("response_status"),
        "failureCode": delivery.get("failure_code"),
        "externalReference": delivery.get("external_reference"),
        "recordedAt": int(time.time()),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    S3.put_object(
        Bucket=bucket,
        Key=f"tenant={tenant}/workflows/{delivery.get('id')}.json",
        Body=encoded,
        ContentType="application/json",
        Metadata={"sha256": hashlib.sha256(encoded).hexdigest()},
    )


def _terminal(
    tenant: str, delivery: dict[str, object], *, status: str, attempt: int,
    response_status: int | None = None, failure_code: str | None = None,
    external_reference: str | None = None,
) -> dict[str, object]:
    """Commit immutable evidence before the mutable terminal projection."""
    candidate = {
        **delivery, "status": status, "attempt_count": attempt,
        "response_status": response_status, "failure_code": failure_code,
        "external_reference": external_reference,
    }
    _audit_terminal(tenant, candidate)
    updated = _record_attempt(
        delivery, status=status, attempt=attempt, response_status=response_status,
        failure_code=failure_code, external_reference=external_reference,
    )
    _record_health(tenant, updated)
    return updated


def _failure_code(error: Exception) -> str:
    """Map provider exceptions to a closed, non-sensitive operator code."""
    message = str(error).lower()
    if "credential" in message or "access token" in message:
        return "credential_invalid"
    if "ambiguous" in message:
        return "ambiguous_external_reference"
    if "origin" in message or "public network" in message:
        return "destination_invalid"
    if isinstance(error, HTTPError):
        return "provider_http_error"
    return "provider_transport_error"


def _deliver(tenant: str, delivery_id: str, receive_count: int) -> dict[str, object]:
    """Execute one retry-safe attempt using live server-owned authority."""
    delivery = TABLE.get_item(
        Key=_key(tenant, "WORKFLOW_DELIVERY", delivery_id), ConsistentRead=True
    ).get("Item")
    if not delivery:
        raise ValueError("workflow delivery not found")
    if delivery.get("status") in {"delivered", "failed"}:
        _record_health(tenant, delivery)
        return delivery
    connection_id = _identifier(delivery.get("connection_id"), "connectionId")
    connection = TABLE.get_item(
        Key=_key(tenant, "WORKFLOW_CONNECTION", connection_id), ConsistentRead=True
    ).get("Item")
    verification = delivery.get("verification") is True
    allowed_statuses = {"pending_verification", "paused", "active"} if verification else {"active"}
    if (
        not connection
        or delivery.get("tenant_id") != tenant
        or connection.get("tenant_id") != tenant
        or connection.get("status") not in allowed_statuses
        or connection.get("provider") not in _PROVIDERS
        or delivery.get("provider") != connection.get("provider")
        or int(connection.get("revision", 0)) != int(delivery.get("connection_revision", -1))
    ):
        return _terminal(
            tenant, delivery, status="failed", attempt=receive_count,
            failure_code="connection_authority_changed",
        )
    payload = delivery.get("payload")
    try:
        case = _case(payload)
        if (
            payload.get("eventType") != delivery.get("event_type")
            or case.get("id") != delivery.get("case_id")
            or int(case.get("revision", -1)) != int(delivery.get("case_revision", -2))
        ):
            raise ValueError("stored workflow payload identity does not match delivery authority")
    except Exception:
        return _terminal(
            tenant,
            delivery,
            status="failed",
            attempt=receive_count,
            failure_code="payload_invalid",
        )
    provider = str(connection["provider"])
    try:
        credentials = _credentials(tenant, connection)
        adapter = {"servicenow": _servicenow, "jira": _jira, "pagerduty": _pagerduty}[provider]
        response_status, external_reference = adapter(connection, credentials, payload)
    except Exception as error:
        failure_code = _failure_code(error)
        if receive_count >= _MAX_RECEIVE_COUNT:
            _terminal(
                tenant, delivery, status="failed", attempt=receive_count,
                response_status=error.code if isinstance(error, HTTPError) else None,
                failure_code=failure_code,
            )
        else:
            updated = _record_attempt(
                delivery, status="retrying", attempt=receive_count,
                response_status=error.code if isinstance(error, HTTPError) else None,
                failure_code=failure_code,
            )
            _record_health(tenant, updated)
        raise RuntimeError("workflow delivery failed") from error
    return _terminal(
        tenant, delivery, status="delivered", attempt=receive_count,
        response_status=response_status, external_reference=external_reference,
    )


def handler(event, context):  # noqa: ANN001, ANN201
    """Process exactly one opaque SQS delivery identity."""
    records = event.get("Records") if isinstance(event, dict) else None
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("workflow worker requires exactly one SQS record")
    record = records[0]
    if record.get("eventSource") not in {"aws:sqs", None}:
        raise ValueError("workflow worker event source is invalid")
    try:
        body = json.loads(record.get("body", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("workflow worker message is invalid") from error
    if not isinstance(body, dict) or set(body) != {"tenantId", "deliveryId"}:
        raise ValueError("workflow worker message schema is invalid")
    tenant = _identifier(body.get("tenantId"), "tenantId")
    delivery_id = _identifier(body.get("deliveryId"), "deliveryId")
    try:
        receive_count = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
    except (TypeError, ValueError) as error:
        raise ValueError("workflow worker receive count is invalid") from error
    if not 1 <= receive_count <= _MAX_RECEIVE_COUNT:
        raise ValueError("workflow worker receive count is invalid")
    return _deliver(tenant, delivery_id, receive_count)

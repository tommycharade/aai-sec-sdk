"""Run one bounded AWS-managed discovery collection and atomic publication.

The scheduler invocation is not authority by itself. This Lambda validates the
exact event against the live tenant job record, reads only tagged/namespaced
Secrets Manager values, contacts a closed provider endpoint set, and publishes
through the existing source-scoped ingestion credential. Failures update only
job health and never refresh discovery evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from decimal import Decimal
from typing import Any

import boto3

TABLE = boto3.resource("dynamodb").Table(os.environ["CONTROL_TABLE"])
SECRETS = boto3.client("secretsmanager")

_EVENT_FIELDS = frozenset(
    {
        "schemaVersion",
        "tenantId",
        "sourceId",
        "provider",
        "providerSecretArn",
        "connectorSecretArn",
        "jobRevision",
        "validitySeconds",
        "configurationDigest",
    }
)
_IDENTIFIER_PATTERN = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)
_MAX_PROVIDER_PAGES = 20
_MAX_USERS_PER_PAGE = 100
_MAX_OBSERVATIONS = 2_000
_MAX_RESPONSE_BYTES = 1_000_000
_REQUEST_TIMEOUT_SECONDS = 10.0
_ERROR_CODES = frozenset(
    {
        "configuration_invalid",
        "provider_secret_unavailable",
        "connector_secret_unavailable",
        "provider_authentication_failed",
        "provider_transport_failed",
        "provider_response_invalid",
        "provider_inventory_too_large",
        "source_revision_conflict",
        "ingestion_rejected",
        "internal_error",
    }
)


class ManagedDiscoveryError(RuntimeError):
    """Carry one content-free operational code across the collector boundary."""

    def __init__(self, code: str) -> None:
        """Create an error from the fixed, non-sensitive reason vocabulary."""
        if code not in _ERROR_CODES:
            code = "internal_error"
        super().__init__(code)
        self.code = code


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    """Reject every redirect so credentials never leave an approved endpoint."""

    def redirect_request(
        self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str
    ) -> None:
        """Return no follow-up request for every HTTP redirect response."""
        return None


def _identifier(value: Any, label: str) -> str:
    """Validate one bounded identifier before using it in keys or URL paths."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value[0] not in _IDENTIFIER_PATTERN
        or any(character not in _IDENTIFIER_PATTERN for character in value)
    ):
        raise ManagedDiscoveryError("configuration_invalid")
    return value


def _integer(value: Any, *, minimum: int, maximum: int) -> int:
    """Return one exact bounded integer while rejecting booleans and coercion."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ManagedDiscoveryError("configuration_invalid")
    result = int(value)
    if result < minimum or result > maximum:
        raise ManagedDiscoveryError("configuration_invalid")
    return result


def _canonical_digest(value: dict[str, Any]) -> str:
    """Hash canonical schedule input for comparison with server-owned state."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validated_event(event: Any) -> dict[str, Any]:
    """Validate the exact scheduler contract before any external operation."""
    if not isinstance(event, dict) or set(event) != _EVENT_FIELDS:
        raise ManagedDiscoveryError("configuration_invalid")
    if event.get("schemaVersion") != 1 or event.get("provider") != "entra":
        raise ManagedDiscoveryError("configuration_invalid")
    tenant_id = _identifier(event.get("tenantId"), "tenantId")
    source_id = _identifier(event.get("sourceId"), "sourceId")
    job_revision = _integer(event.get("jobRevision"), minimum=1, maximum=1_000_000)
    validity_seconds = _integer(event.get("validitySeconds"), minimum=300, maximum=86_400)
    for field in ("providerSecretArn", "connectorSecretArn"):
        if not isinstance(event.get(field), str) or len(event[field]) > 1_024:
            raise ManagedDiscoveryError("configuration_invalid")
    supplied_digest = event.get("configurationDigest")
    if (
        not isinstance(supplied_digest, str)
        or len(supplied_digest) != 64
        or any(character not in "0123456789abcdef" for character in supplied_digest)
    ):
        raise ManagedDiscoveryError("configuration_invalid")
    digest_input = {key: event[key] for key in sorted(_EVENT_FIELDS - {"configurationDigest"})}
    if not hmac.compare_digest(_canonical_digest(digest_input), supplied_digest):
        raise ManagedDiscoveryError("configuration_invalid")
    return {
        **event,
        "tenantId": tenant_id,
        "sourceId": source_id,
        "jobRevision": job_revision,
        "validitySeconds": validity_seconds,
    }


def _job_key(tenant_id: str, source_id: str) -> dict[str, str]:
    """Return the tenant-partitioned key for one managed discovery job."""
    return {
        "pk": f"TENANT#{tenant_id}",
        "sk": f"DISCOVERY_JOB#{source_id}",
    }


def _load_live_job(configuration: dict[str, Any]) -> dict[str, Any]:
    """Bind a scheduler event to current server-owned job configuration."""
    item = TABLE.get_item(
        Key=_job_key(configuration["tenantId"], configuration["sourceId"]),
        ConsistentRead=True,
    ).get("Item")
    if not item:
        raise ManagedDiscoveryError("configuration_invalid")
    if (
        int(item.get("revision", 0)) != configuration["jobRevision"]
        or item.get("status") == "disabled"
        or item.get("provider") != "entra"
        or item.get("providerSecretArn") != configuration["providerSecretArn"]
        or item.get("connectorSecretArn") != configuration["connectorSecretArn"]
        or item.get("configurationDigest") != configuration["configurationDigest"]
    ):
        # Stale or tampered schedules are denied before secret retrieval.
        raise ManagedDiscoveryError("configuration_invalid")
    return item


def _update_job_attempt(
    configuration: dict[str, Any], *, now: int, status: str, error_code: str | None = None
) -> None:
    """Persist bounded operational posture without provider or secret content."""
    values: dict[str, Any] = {
        ":revision": configuration["jobRevision"],
        ":disabled": "disabled",
        ":status": status,
        ":now": now,
        ":zero": 0,
        ":one": 1,
    }
    names = {"#status": "status", "#revision": "revision"}
    if status == "running":
        expression = "SET #status = :status, lastAttemptAt = :now"
    elif status == "healthy":
        expression = (
            "SET #status = :status, lastSuccessAt = :now, "
            "consecutiveFailures = :zero REMOVE lastErrorCode"
        )
    else:
        values[":error"] = error_code or "internal_error"
        expression = (
            "SET #status = :status, lastErrorCode = :error, "
            "consecutiveFailures = if_not_exists(consecutiveFailures, :zero) + :one"
        )
    try:
        TABLE.update_item(
            Key=_job_key(configuration["tenantId"], configuration["sourceId"]),
            UpdateExpression=expression,
            ConditionExpression="#revision = :revision AND #status <> :disabled",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except Exception as error:
        # Job posture is security evidence. A failed state write must fail the
        # invocation instead of allowing silent collection/publication.
        raise ManagedDiscoveryError("internal_error") from error


def _secret_json(arn: str, expected_fields: frozenset[str], *, error_code: str) -> dict[str, str]:
    """Read and validate one current JSON secret without exposing its values."""
    try:
        response = SECRETS.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    except Exception as error:
        raise ManagedDiscoveryError(error_code) from error
    raw = response.get("SecretString")
    if not isinstance(raw, str) or len(raw) > 65_536:
        raise ManagedDiscoveryError(error_code)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ManagedDiscoveryError(error_code) from error
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or not all(isinstance(item, str) and item for item in value.values())
    ):
        raise ManagedDiscoveryError(error_code)
    return value


def _read_json_response(response: Any, *, error_code: str) -> Any:
    """Decode one bounded HTTP response and reject oversized or malformed JSON."""
    payload = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise ManagedDiscoveryError(error_code)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        raise ManagedDiscoveryError(error_code) from error


def _open_json(request: urllib.request.Request, *, error_code: str) -> Any:
    """Perform one TLS-verified bounded provider request with a fixed timeout."""
    try:
        # URLs are constructed or validated against the closed provider hosts
        # before this call; no caller-controlled egress target reaches urlopen.
        with _urlopen(request) as response:
            return _read_json_response(response, error_code=error_code)
    except urllib.error.HTTPError as error:
        if error.code in {400, 401, 403}:
            raise ManagedDiscoveryError("provider_authentication_failed") from error
        raise ManagedDiscoveryError("provider_transport_failed") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ManagedDiscoveryError("provider_transport_failed") from error


def _urlopen(request: urllib.request.Request) -> Any:
    """Open one TLS request with redirects disabled and a bounded timeout."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _RejectRedirect(),
    )
    return opener.open(request, timeout=_REQUEST_TIMEOUT_SECONDS)  # noqa: S310


def _entra_access_token(credentials: dict[str, str]) -> str:
    """Exchange deployment-owned Entra client credentials for a short token."""
    tenant_id = credentials["tenantId"]
    client_id = credentials["clientId"]
    if not _uuid_like(tenant_id) or not _uuid_like(client_id):
        raise ManagedDiscoveryError("provider_secret_unavailable")
    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": credentials["clientSecret"],
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }
    ).encode()
    tenant_path = urllib.parse.quote(tenant_id, safe="")
    request = urllib.request.Request(  # noqa: S310
        f"https://login.microsoftonline.com/{tenant_path}/oauth2/v2.0/token",
        data=body,
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    value = _open_json(request, error_code="provider_response_invalid")
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("access_token"), str)
        or not value["access_token"]
        or value.get("token_type") != "Bearer"
    ):
        raise ManagedDiscoveryError("provider_response_invalid")
    return value["access_token"]


def _uuid_like(value: str) -> bool:
    """Return whether a value is a canonical UUID without retaining identity."""
    try:
        return str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def _validated_graph_url(value: str) -> str:
    """Constrain Graph pagination to the exact users collection endpoint."""
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "graph.microsoft.com"
        or parsed.path != "/v1.0/users"
        or parsed.fragment
    ):
        raise ManagedDiscoveryError("provider_response_invalid")
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if (
        set(query) - {"$select", "$top", "$skiptoken"}
        or query.get("$select") != ["id,accountEnabled,department"]
        or query.get("$top") != ["100"]
        or len(query.get("$skiptoken", [])) > 1
        or any(len(value) > 1_024 for value in query.get("$skiptoken", []))
    ):
        raise ManagedDiscoveryError("provider_response_invalid")
    return value


def _collect_entra_users(token: str) -> list[dict[str, Any]]:
    """Collect at most 2,000 content-minimised Entra identity observations."""
    url: str | None = (
        "https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled,department&$top=100"
    )
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(_MAX_PROVIDER_PAGES):
        if url is None:
            return observations
        request = urllib.request.Request(  # noqa: S310
            _validated_graph_url(url),
            headers={"authorization": f"Bearer {token}"},
        )
        page = _open_json(request, error_code="provider_response_invalid")
        if not isinstance(page, dict) or set(page) - {"value", "@odata.nextLink"}:
            raise ManagedDiscoveryError("provider_response_invalid")
        users = page.get("value")
        if not isinstance(users, list) or len(users) > _MAX_USERS_PER_PAGE:
            raise ManagedDiscoveryError("provider_response_invalid")
        for user in users:
            if not isinstance(user, dict) or set(user) - {
                "id",
                "accountEnabled",
                "department",
            }:
                raise ManagedDiscoveryError("provider_response_invalid")
            identifier = user.get("id")
            active = user.get("accountEnabled")
            if (
                not isinstance(identifier, str)
                or not identifier
                or len(identifier) > 128
                or not isinstance(active, bool)
                or identifier in seen
            ):
                raise ManagedDiscoveryError("provider_response_invalid")
            seen.add(identifier)
            observation: dict[str, Any] = {
                "kind": "identity",
                "id": identifier,
                "active": active,
            }
            department = user.get("department")
            if isinstance(department, str) and department.strip():
                if len(department.strip()) > 256:
                    raise ManagedDiscoveryError("provider_response_invalid")
                observation["businessUnit"] = department.strip()
            observations.append(observation)
            if len(observations) > _MAX_OBSERVATIONS:
                raise ManagedDiscoveryError("provider_inventory_too_large")
        next_url = page.get("@odata.nextLink")
        if next_url is not None and not isinstance(next_url, str):
            raise ManagedDiscoveryError("provider_response_invalid")
        url = _validated_graph_url(next_url) if next_url else None
    if url is not None:
        raise ManagedDiscoveryError("provider_inventory_too_large")
    return observations


def _source_revision(tenant_id: str, source_id: str) -> int:
    """Strongly read the live source revision for optimistic publication."""
    item = TABLE.get_item(
        Key={
            "pk": f"TENANT#{tenant_id}",
            "sk": f"DISCOVERY_SOURCE#{source_id}",
        },
        ConsistentRead=True,
    ).get("Item")
    return int(item.get("revision", 0)) if item else 0


def _control_plane_endpoint(tenant_id: str, source_id: str) -> str:
    """Build the fixed API Gateway connector endpoint from deployment state."""
    base = os.environ["CONTROL_PLANE_API_URL"].rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ManagedDiscoveryError("configuration_invalid")
    return (
        f"{base}/discovery-ingest/"
        f"{urllib.parse.quote(tenant_id, safe='')}/"
        f"{urllib.parse.quote(source_id, safe='')}/generations"
    )


def _ingestion_request(url: str, method: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
    """Send one bounded ingestion phase without logging token or observations."""
    request = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
        method=method,
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "aai-sec-managed-discovery/1",
        },
    )
    try:
        with _urlopen(request) as response:
            value = _read_json_response(response, error_code="ingestion_rejected")
    except urllib.error.HTTPError as error:
        if error.code == 409:
            raise ManagedDiscoveryError("source_revision_conflict") from error
        raise ManagedDiscoveryError("ingestion_rejected") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ManagedDiscoveryError("ingestion_rejected") from error
    if not isinstance(value, dict):
        raise ManagedDiscoveryError("ingestion_rejected")
    return value


def _publish(
    configuration: dict[str, Any], token: str, observations: list[dict[str, Any]], *, now: int
) -> dict[str, Any]:
    """Upload bounded pages and atomically commit one generation."""
    if not observations:
        # Empty identity evidence cannot establish a safe population and is not
        # published as fresh assurance.
        raise ManagedDiscoveryError("provider_response_invalid")
    revision = _source_revision(configuration["tenantId"], configuration["sourceId"])
    base = _control_plane_endpoint(configuration["tenantId"], configuration["sourceId"])
    generation = f"entra-{now}-{uuid.uuid4().hex}"
    pages = [
        observations[index : index + _MAX_USERS_PER_PAGE]
        for index in range(0, len(observations), _MAX_USERS_PER_PAGE)
    ]
    _ingestion_request(
        base,
        "POST",
        token,
        {
            "generation": generation,
            "expectedRevision": revision,
            "observedAt": now,
            "expiresAt": now + configuration["validitySeconds"],
            "pageCount": len(pages),
        },
    )
    page_hashes = []
    for page_number, page in enumerate(pages):
        result = _ingestion_request(
            f"{base}/{generation}/pages/{page_number}",
            "PUT",
            token,
            {"observations": page},
        )
        page_hash = result.get("pageHash")
        if (
            not isinstance(page_hash, str)
            or len(page_hash) != 64
            or any(character not in "0123456789abcdef" for character in page_hash)
        ):
            raise ManagedDiscoveryError("ingestion_rejected")
        page_hashes.append(page_hash)
    committed = _ingestion_request(
        f"{base}/{generation}/commit",
        "POST",
        token,
        {"pageHashes": page_hashes},
    )
    committed_revision = committed.get("revision")
    if (
        isinstance(committed_revision, bool)
        or not isinstance(committed_revision, (int, Decimal))
        or int(committed_revision) != revision + 1
    ):
        raise ManagedDiscoveryError("ingestion_rejected")
    return {
        "generation": generation,
        "revision": int(committed_revision),
        "observationCount": len(observations),
    }


def handler(event: Any, context: Any) -> dict[str, Any]:
    """Collect and publish one scheduled Entra generation.

    The return value contains operational metadata only. Any expected failure is
    persisted as a fixed reason code and then raised so Lambda metrics, Scheduler
    retry policy, and the dead-letter queue remain truthful.
    """
    del context
    configuration: dict[str, Any] | None = None
    live_job_bound = False
    now = int(time.time())
    try:
        configuration = _validated_event(event)
        _load_live_job(configuration)
        live_job_bound = True
        _update_job_attempt(configuration, now=now, status="running")
        provider = _secret_json(
            configuration["providerSecretArn"],
            frozenset({"tenantId", "clientId", "clientSecret"}),
            error_code="provider_secret_unavailable",
        )
        connector = _secret_json(
            configuration["connectorSecretArn"],
            frozenset({"token"}),
            error_code="connector_secret_unavailable",
        )
        access_token = _entra_access_token(provider)
        observations = _collect_entra_users(access_token)
        result = _publish(configuration, connector["token"], observations, now=now)
        _update_job_attempt(configuration, now=now, status="healthy")
        return {"status": "healthy", **result}
    except ManagedDiscoveryError as error:
        if configuration is not None and live_job_bound:
            try:
                _update_job_attempt(
                    configuration,
                    now=now,
                    status="degraded",
                    error_code=error.code,
                )
            except ManagedDiscoveryError:
                error = ManagedDiscoveryError("internal_error")
        # Never include exception text from providers, AWS, or HTTP responses.
        print(json.dumps({"event": "managed_discovery_failed", "code": error.code}))
        raise RuntimeError(error.code) from error
    except Exception as error:
        if configuration is not None and live_job_bound:
            try:
                _update_job_attempt(
                    configuration,
                    now=now,
                    status="degraded",
                    error_code="internal_error",
                )
            except ManagedDiscoveryError:
                pass
        print(json.dumps({"event": "managed_discovery_failed", "code": "internal_error"}))
        raise RuntimeError("internal_error") from error

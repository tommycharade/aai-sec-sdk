"""Tenant-aware fleet control-plane primitives.

This module provides the durable, provider-neutral foundation used by an
enterprise control plane.  It deliberately stores metadata and references to
configuration rather than secrets or executable policy.  Authentication and
runtime authority remain deployment-owned adapters, while this layer enforces
organization, project, and deployment scope before returning data or changing
state.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from ._command_patterns import compile_command_patterns
from .audit import AuditSink
from .managed_deployment import ManagedDeploymentPackage

_MAX_TEXT = 256
_MAX_PAGE_SIZE = 200
_MAX_MANAGED_PACKAGE_BYTES = 280 * 1024
_COMMAND_PATTERN_FIELDS = frozenset(
    {"allowedCommandPatterns", "deniedCommandPatterns", "approvalCommandPatterns"}
)
_AGENT_TELEMETRY_FIELDS = frozenset(
    {
        "actionsTotal",
        "actionsAdmitted",
        "allowed",
        "denied",
        "approvalRequired",
        "executed",
        "failed",
        "timedOut",
        "cancelled",
        "resultRejected",
        "runtimeErrors",
        "costUnits",
        "averageLatencyMs",
        "maxLatencyMs",
    }
)
_AGENT_TELEMETRY_INTEGER_FIELDS = _AGENT_TELEMETRY_FIELDS - {
    "averageLatencyMs",
    "maxLatencyMs",
}
_FLEET_GOVERNANCE_KEYS: dict[str, frozenset[str]] = {
    "policy": frozenset({"provider", "endpoint", "allowedPrincipals", "denyByDefault"}),
    "approvals": frozenset({"provider", "endpoint", "ttlSeconds", "requiredFor"}),
    "tools": frozenset({"allowed", "denied", "builtIn", "fileTools"}),
    "budgets": frozenset(
        {
            "maxActions",
            "maxConcurrent",
            "maxFanOut",
            "maxCostUnits",
            "maxDelegationDepth",
            "maxActionsPerSecond",
            "executionTimeoutSeconds",
            "maxTimedOutWorkers",
        }
    ),
    "credentials": frozenset({"enabled", "brokerEndpoint", "scopes", "mode"}),
    "isolation": frozenset({"verifier", "requiredForHighRisk", "mode"}),
    "audit": frozenset(
        {"provider", "path", "replicaEndpoint", "redactSensitiveData", "captureToolContent"}
    ),
    "telemetry": frozenset(
        {"enabled", "endpoint", "exporter", "redactSensitiveData", "captureToolContent"}
    ),
    "runtime": frozenset(
        {
            "policyProvider",
            "approvalProvider",
            "auditProvider",
            "policyEndpoint",
            "approvalEndpoint",
            "auditPath",
            "auditReplicaEndpoint",
            "credentialBrokerEndpoint",
            "isolationVerifier",
            "telemetryEnabled",
            "allowedTools",
            "allowedPrincipals",
            "maxActions",
            "maxConcurrent",
            "maxFanOut",
            "maxCostUnits",
            "maxDelegationDepth",
            "maxActionsPerSecond",
            "executionTimeoutSeconds",
            "maxTimedOutWorkers",
            "idempotencyTtlSeconds",
            "approvalTtlSeconds",
            "credentialsEnabled",
            "isolationRequiredForHighRisk",
            "redactSensitiveData",
            "captureToolContent",
        }
    ),
    "claudeCode": frozenset(
        {
            "enabled",
            "allowedBuiltInTools",
            "deniedCommandPatterns",
            "approvalCommandPatterns",
            "allowedCommandPatterns",
            "fileTools",
            "allowedSkills",
            "allowedMcpServers",
        }
    ),
    "managedHost": frozenset(
        {
            "host",
            "hostVersion",
            "platform",
            "bundleHash",
            "policyId",
            "policyVersion",
        }
    ),
}

_MANAGED_HOSTS = frozenset({"claude-code", "codex-cli"})
_MANAGED_PLATFORMS = frozenset({"macos", "linux", "windows"})
_MANAGED_SOURCES = frozenset(
    {
        "claude-server-managed",
        "endpoint-managed-file",
        "mdm",
        "codex-system",
        "codex-cloud",
        "codex-mdm",
    }
)
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_POLICY_VERSION_STATES = frozenset(
    {"draft", "review", "approved", "staged", "active", "rejected", "retired"}
)
_POLICY_PENDING_STATES = frozenset({"draft", "review", "approved", "staged"})


class FleetConfigurationError(ValueError):
    """Raised when an enterprise fleet request is malformed or out of scope."""


class FleetAuthorizationError(PermissionError):
    """Raised when an identity lacks authority for a tenant-scoped action."""


class FleetNotFoundError(LookupError):
    """Raised when a requested organization, project, deployment, or agent is absent."""


class FleetConflictError(RuntimeError):
    """Raised when live fleet state no longer matches an expected revision."""


@dataclass(frozen=True, slots=True)
class FleetIdentity:
    """Authenticated enterprise identity and its organization/project scope."""

    subject: str
    organization_id: str
    roles: frozenset[str]
    project_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Reject empty identity data before it can influence authorization."""
        if not self.subject.strip() or not self.organization_id.strip() or not self.roles:
            raise ValueError("fleet identity requires subject, organization, and roles")


@dataclass(frozen=True, slots=True)
class FleetSecretReference:
    """Opaque reference to a deployment-owned secret, never the secret value."""

    reference: str

    def __post_init__(self) -> None:
        """Reject empty or oversized references before they reach a resolver."""
        if not isinstance(self.reference, str) or not self.reference.strip():
            raise FleetConfigurationError("secret reference must be non-empty text")
        if len(self.reference) > 512 or any(char.isspace() for char in self.reference):
            raise FleetConfigurationError("secret reference is malformed")


class FleetSecretResolver(Protocol):
    """Deployment-owned secret manager boundary for ephemeral credential use."""

    def resolve(self, reference: FleetSecretReference, purpose: str) -> str:
        """Resolve one reference for one purpose without persisting or returning metadata."""


class CallbackFleetSecretResolver:
    """Adapt a deployment secret manager callback with fail-closed validation."""

    def __init__(self, resolver: Callable[[FleetSecretReference, str], str]) -> None:
        """Create a resolver around an application-owned secret manager client."""
        self._resolver = resolver

    def resolve(self, reference: FleetSecretReference, purpose: str) -> str:
        """Resolve one bounded reference and reject empty or malformed results."""
        if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > _MAX_TEXT:
            raise FleetConfigurationError("secret purpose must be bounded non-empty text")
        try:
            value = self._resolver(reference, purpose)
        except Exception as exc:
            raise FleetConfigurationError("secret resolution failed") from exc
        if not isinstance(value, str) or not value:
            raise FleetConfigurationError("secret manager returned no credential")
        return value


class FleetPersistenceAdapter(Protocol):
    """Provider-neutral persistence boundary for fleet state and migrations."""

    name: str
    supports_high_availability: bool

    def connect(self, path: str, busy_timeout_ms: int) -> Any:
        """Open a transaction-capable connection or raise before serving traffic."""


class SQLiteFleetPersistenceAdapter:
    """Reference SQLite adapter with WAL and bounded lock contention settings."""

    name = "sqlite-reference"
    supports_high_availability = False

    def connect(self, path: str, busy_timeout_ms: int) -> sqlite3.Connection:
        """Open and configure the reference connection; no credentials are involved."""
        connection = sqlite3.connect(path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection


class _PostgresFleetConnection:
    """Small DB-API compatibility layer for the bounded fleet SQL surface."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    @staticmethod
    def _statement(sql: str) -> str:
        """Translate only the SQLite constructs used by the fleet migrations."""
        sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.I)
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
        return sql.replace("?", "%s")

    def execute(self, sql: str, params: Any = ()) -> Any:
        """Execute translated SQL and normalize uniqueness failures."""
        stripped = sql.strip()
        ignore_insert = bool(re.match(r"INSERT\s+OR\s+IGNORE\s+INTO\b", stripped, flags=re.I))
        if stripped.upper().startswith("PRAGMA FOREIGN_KEYS"):
            return self._connection.execute("SELECT 1 AS pragma_ignored")
        table_info = re.fullmatch(r"PRAGMA\s+table_info\((\w+)\)", stripped, flags=re.I)
        if table_info:
            return self._connection.execute(
                "SELECT column_name AS name FROM information_schema.columns "
                "WHERE table_schema=current_schema() AND table_name=%s "
                "ORDER BY ordinal_position",
                (table_info.group(1),),
            )
        statement = self._statement(sql)
        if ignore_insert:
            statement = f"{statement} ON CONFLICT DO NOTHING"
        try:
            return self._connection.execute(statement, params)
        except Exception as exc:
            if exc.__class__.__name__ == "UniqueViolation":
                self._connection.rollback()
                raise sqlite3.IntegrityError(str(exc)) from exc
            raise

    def executescript(self, script: str) -> None:
        """Execute the reference migration script statement by statement."""
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self) -> None:
        """Commit one migration or control-plane transaction."""
        self._connection.commit()

    def rollback(self) -> None:
        """Rollback a failed transaction."""
        self._connection.rollback()

    def close(self) -> None:
        """Close the managed database connection."""
        self._connection.close()


class PostgresFleetPersistenceAdapter:
    """Optional PostgreSQL adapter for managed HA fleet persistence.

    Install the optional ``postgres`` extra. The DSN must be supplied by the
    deployment, normally through its secret/configuration system; it is never
    stored in fleet state or returned by capability APIs.
    """

    name = "postgresql-psycopg"
    supports_high_availability = True

    def connect(self, path: str, busy_timeout_ms: int) -> _PostgresFleetConnection:
        """Open PostgreSQL with dictionary rows and fail before serving on error."""
        del busy_timeout_ms
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - optional dependency branch.
            raise FleetConfigurationError(
                "PostgreSQL persistence requires the optional 'postgres' extra"
            ) from exc
        try:
            return _PostgresFleetConnection(psycopg.connect(path, row_factory=dict_row))
        except Exception as exc:
            raise FleetConfigurationError("PostgreSQL fleet persistence connection failed") from exc


class FleetAuthenticator(Protocol):
    """Deployment-owned authentication boundary for enterprise API requests."""

    def authenticate(self, authorization: object) -> FleetIdentity | None:
        """Authenticate a request and return no identity on failure."""

    def authorize(self, identity: FleetIdentity, action: str) -> bool:
        """Return whether the identity may perform the coarse-grained action."""


class FleetIdentityVerifier(Protocol):
    """Deployment-owned verifier for an OIDC/JWT/IAM authorization header."""

    def verify(self, authorization: object) -> FleetIdentity | None:
        """Validate signature, issuer, audience, expiry, and claims externally."""


class CallbackFleetAuthenticator:
    """Bridge a verified enterprise IAM adapter into the fleet API.

    The SDK deliberately does not implement key discovery, issuer policy, or
    JWT algorithm selection. The callback must perform those checks and return
    only a normalized :class:`FleetIdentity`; authorization remains a separate
    callback so tenant and role policy cannot be inferred from browser input.
    """

    def __init__(
        self,
        verifier: Callable[[object], FleetIdentity | None],
        authorizer: Callable[[FleetIdentity, str], bool],
    ) -> None:
        """Create an authenticator around deployment-owned verification policy."""
        self._verifier = verifier
        self._authorizer = authorizer

    def authenticate(self, authorization: object) -> FleetIdentity | None:
        """Return the verifier's identity or fail closed on verifier errors."""
        try:
            identity = self._verifier(authorization)
        except Exception:
            return None
        return identity if isinstance(identity, FleetIdentity) else None

    def authorize(self, identity: FleetIdentity, action: str) -> bool:
        """Delegate authorization to the deployment IAM policy boundary."""
        try:
            return self._authorizer(identity, action) is True
        except Exception:
            return False


class FleetDeploymentAuthority(Protocol):
    """Runtime adapter that applies controls to one independently deployed SDK."""

    def apply_configuration(self, configuration: Mapping[str, Any]) -> None:
        """Atomically apply validated configuration or raise without claiming success."""

    def emergency_stop(self) -> None:
        """Stop consequential actions for the deployment."""

    def clear_emergency_stop(self) -> None:
        """Clear the deployment stop after incident controls permit it."""


class FleetAlertSink(Protocol):
    """Provider-neutral delivery boundary for redacted fleet alerts."""

    def publish(self, alert: Mapping[str, Any]) -> None:
        """Deliver one redacted alert or raise without changing fleet state."""


class WebhookFleetAlertSink:
    """Deliver redacted fleet alerts to an HTTPS webhook.

    The endpoint should be injected from a deployment secret manager and is
    never included in fleet configuration, audit payloads, or exceptions.
    Delivery is bounded and any transport or non-2xx response raises so the
    caller does not claim that an alert was delivered when it was not.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float = 5.0,
        opener: Callable[..., Any] | None = None,
        allow_http: bool = False,
    ) -> None:
        """Create a bounded webhook adapter with an explicit local HTTP escape hatch."""
        if not isinstance(endpoint, str):
            raise FleetConfigurationError("alert webhook must be an HTTPS URL without credentials")
        parsed = urlsplit(endpoint)
        if (
            len(endpoint) > 2048
            or parsed.scheme not in ({"https", "http"} if allow_http else {"https"})
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise FleetConfigurationError("alert webhook must be an HTTPS URL without credentials")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
            raise FleetConfigurationError("alert webhook timeout must be numeric")
        if not 0.1 <= timeout_seconds <= 30:
            raise FleetConfigurationError(
                "alert webhook timeout must be between 0.1 and 30 seconds"
            )
        self._endpoint = endpoint
        self._timeout_seconds = float(timeout_seconds)
        self._opener = opener or urlopen

    def publish(self, alert: Mapping[str, Any]) -> None:
        """POST one bounded redacted alert and fail on transport/non-2xx errors."""
        payload = json.dumps(dict(alert), separators=(",", ":")).encode("utf-8")
        if len(payload) > 32_768:
            raise FleetConfigurationError("fleet alert payload is too large")
        request = Request(  # noqa: S310 - endpoint scheme is validated above.
            self._endpoint,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "aai-sec-sdk-fleet"},
            method="POST",
        )
        try:
            response = self._opener(request, timeout=self._timeout_seconds)
            status = getattr(response, "status", getattr(response, "code", None))
        except Exception as exc:
            raise FleetConfigurationError("fleet alert delivery failed") from exc
        if not isinstance(status, int) or not 200 <= status < 300:
            raise FleetConfigurationError("fleet alert delivery returned a non-success status")


class StaticFleetAuthenticator:
    """Bounded bearer authenticator for local tests and reference deployments."""

    def __init__(self, credentials: Mapping[str, FleetIdentity]) -> None:
        """Create a synthetic credential map; production uses an IdP adapter."""
        if not credentials or any(not token or len(token) < 16 for token in credentials):
            raise ValueError("fleet credentials require tokens of at least 16 characters")
        self._credentials = dict(credentials)

    def authenticate(self, authorization: object) -> FleetIdentity | None:
        """Authenticate only a Bearer header using constant-time comparison."""
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None
        supplied = authorization[7:].strip()
        for token, identity in self._credentials.items():
            if hmac.compare_digest(supplied, token):
                return identity
        return None

    def authorize(self, identity: FleetIdentity, action: str) -> bool:
        """Apply the reference role matrix; deployments should use their IdP policy."""
        if action == "read":
            return bool(identity.roles & {"viewer", "operator", "admin", "incident_commander"})
        if action in {"manage_inventory", "manage_configuration"}:
            return bool(identity.roles & {"operator", "admin"})
        if action == "approve_configuration":
            return "admin" in identity.roles
        if action == "agent_presence":
            return bool(identity.roles & {"agent", "admin"})
        if action == "emergency_stop":
            return bool(identity.roles & {"incident_commander", "admin"})
        if action in {"manage_alerts", "dispatch_alerts"}:
            return bool(identity.roles & {"incident_commander", "admin"})
        return False


@dataclass(frozen=True, slots=True)
class FleetPage:
    """Stable paginated result for fleet inventory APIs."""

    items: tuple[dict[str, Any], ...]
    next_cursor: str | None


def _paginate(items: Sequence[dict[str, Any]], cursor: str | None, limit: int) -> FleetPage:
    """Return a bounded page using an opaque offset cursor.

    The reference adapter keeps cursors intentionally stateless: they contain
    no authority or tenant data, and are only used to continue a read within
    the same authenticated query. The API validates their shape and bounds so
    a caller cannot request an unbounded response.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise FleetConfigurationError("limit must be an integer between 1 and 200")
    if cursor is None or cursor == "":
        offset = 0
    elif isinstance(cursor, str) and cursor.isdecimal():
        offset = int(cursor)
    else:
        raise FleetConfigurationError("cursor must be a non-negative integer token")
    if offset > len(items):
        raise FleetConfigurationError("cursor is outside the result set")
    page = tuple(items[offset : offset + limit])
    next_offset = offset + len(page)
    next_cursor = str(next_offset) if next_offset < len(items) else None
    return FleetPage(page, next_cursor)


def _collect_pages(fetch: Callable[[str | None], FleetPage]) -> tuple[dict[str, Any], ...]:
    """Collect a bounded paginated read without silently dropping records."""
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    seen: set[str] = set()
    for _ in range(1000):
        page = fetch(cursor)
        items.extend(page.items)
        if page.next_cursor is None:
            return tuple(items)
        if page.next_cursor in seen:
            raise FleetConfigurationError("fleet pagination returned a repeated cursor")
        seen.add(page.next_cursor)
        cursor = page.next_cursor
    raise FleetConfigurationError("fleet pagination exceeded the safety limit")


def _text(value: object, name: str) -> str:
    """Validate bounded non-empty metadata without interpreting it as authority."""
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise FleetConfigurationError(f"{name} must be bounded non-empty text")
    return value.strip()


def _command_pattern(value: object, name: str) -> str:
    """Accept only bounded regex syntax screened against common ReDoS forms."""
    try:
        compile_command_patterns([value])
    except ValueError as exc:
        raise FleetConfigurationError(f"{name} is unsafe or invalid: {exc}") from exc
    assert isinstance(value, str)
    return value


def _optional_text(value: object, name: str) -> str | None:
    """Validate optional bounded metadata."""
    if value is None or value == "":
        return None
    return _text(value, name)


def _positive_version(value: object) -> int:
    """Validate an externally supplied positive policy version number."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FleetConfigurationError("policy version must be a positive integer")
    return value


def _json_object(value: Mapping[str, Any] | None, name: str) -> str:
    """Serialize bounded metadata while rejecting secret-like fields."""
    safe_keys = {
        "environment",
        "region",
        "team",
        "labels",
        "version",
        "telemetry",
        "managedConfiguration",
    }
    data = dict(value or {})
    if len(data) > 20 or any(str(key) not in safe_keys for key in data):
        raise FleetConfigurationError(f"{name} contains unsupported metadata")
    for key, item in data.items():
        if key == "telemetry":
            data[key] = _normalize_agent_telemetry(item, name)
            continue
        if key == "managedConfiguration":
            data[key] = _normalize_managed_configuration_report(item)
            continue
        if not isinstance(key, str) or not isinstance(item, (str, int, float, bool, list)):
            raise FleetConfigurationError(f"{name} must contain JSON scalar metadata")
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _normalize_managed_host(value: object, name: str = "managedHost") -> dict[str, Any]:
    """Validate desired managed-host identity without treating it as observed state."""
    if not isinstance(value, Mapping) or set(value) != _FLEET_GOVERNANCE_KEYS["managedHost"]:
        raise FleetConfigurationError(f"{name} must contain the complete managed-host schema")
    host = _text(value.get("host"), f"{name}.host")
    platform = _text(value.get("platform"), f"{name}.platform")
    bundle_hash = _text(value.get("bundleHash"), f"{name}.bundleHash")
    version = value.get("policyVersion")
    if host not in _MANAGED_HOSTS:
        raise FleetConfigurationError(f"{name}.host is unsupported")
    if platform not in _MANAGED_PLATFORMS:
        raise FleetConfigurationError(f"{name}.platform is unsupported")
    if _SHA256_HEX.fullmatch(bundle_hash) is None:
        raise FleetConfigurationError(f"{name}.bundleHash must be lowercase SHA-256")
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise FleetConfigurationError(f"{name}.policyVersion must be positive")
    return {
        "host": host,
        "hostVersion": _text(value.get("hostVersion"), f"{name}.hostVersion"),
        "platform": platform,
        "bundleHash": bundle_hash,
        "policyId": _text(value.get("policyId"), f"{name}.policyId"),
        "policyVersion": version,
    }


def _normalize_managed_configuration_report(value: object) -> dict[str, Any]:
    """Validate content-minimised endpoint evidence carried by a heartbeat."""
    required = _FLEET_GOVERNANCE_KEYS["managedHost"] | frozenset(
        {"source", "verifiedAt", "expiresAt"}
    )
    if not isinstance(value, Mapping) or set(value) != required:
        raise FleetConfigurationError("managedConfiguration has an invalid schema")
    result = _normalize_managed_host(
        {key: value.get(key) for key in _FLEET_GOVERNANCE_KEYS["managedHost"]},
        "managedConfiguration",
    )
    source = _text(value.get("source"), "managedConfiguration.source")
    verified_at, expires_at = value.get("verifiedAt"), value.get("expiresAt")
    if source not in _MANAGED_SOURCES:
        raise FleetConfigurationError("managedConfiguration.source is unsupported")
    if (
        isinstance(verified_at, bool)
        or not isinstance(verified_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(float(verified_at))
        or not math.isfinite(float(expires_at))
        or verified_at < 0
        or expires_at <= verified_at
    ):
        raise FleetConfigurationError("managedConfiguration timestamps are invalid")
    result.update({"source": source, "verifiedAt": verified_at, "expiresAt": expires_at})
    return result


def _normalize_agent_telemetry(value: object, name: str = "telemetry") -> dict[str, int | float]:
    """Validate the fixed aggregate telemetry schema stored with an agent."""
    if not isinstance(value, Mapping) or len(value) > len(_AGENT_TELEMETRY_FIELDS):
        raise FleetConfigurationError(f"{name} must be a bounded telemetry object")
    result: dict[str, int | float] = {}
    for key, item in value.items():
        if key not in _AGENT_TELEMETRY_FIELDS:
            raise FleetConfigurationError(f"{name} contains an unsupported field")
        if key in _AGENT_TELEMETRY_INTEGER_FIELDS:
            if not isinstance(item, int) or isinstance(item, bool):
                raise FleetConfigurationError(f"{name} count fields must be integers")
        elif isinstance(item, bool) or not isinstance(item, (int, float)):
            raise FleetConfigurationError(f"{name} latency fields must be numeric")
        if not math.isfinite(float(item)) or item < 0 or item > 1_000_000_000:
            raise FleetConfigurationError(f"{name} contains an out-of-bounds value")
        result[key] = item
    return result


def _agent_telemetry(metadata: object) -> dict[str, int | float] | None:
    """Read only the validated telemetry projection from stored agent metadata."""
    if not isinstance(metadata, str):
        return None
    try:
        value = json.loads(metadata)
    except (TypeError, ValueError):
        return None
    telemetry = value.get("telemetry") if isinstance(value, Mapping) else None
    if not isinstance(telemetry, Mapping):
        return None
    try:
        return _normalize_agent_telemetry(telemetry)
    except FleetConfigurationError:
        return None


def _agent_inventory_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project an agent row without returning the free-form metadata column."""
    result = dict(row)
    telemetry = _agent_telemetry(result.pop("metadata", None))
    if telemetry is not None:
        result["telemetry"] = telemetry
    return result


def validate_fleet_configuration(configuration: Mapping[str, Any]) -> dict[str, Any]:
    """Validate typed enterprise governance sections without accepting authority.

    Templates remain backward compatible with small legacy objects, but any
    recognized governance section is a closed schema. This makes policy,
    approvals, tools, budgets, credentials, isolation, audit, telemetry, and
    Claude Code controls discoverable and rejects configuration typos before a
    template can be rolled out. Endpoint values are references only; secrets
    are rejected by the common recursive validator below.
    """
    if not isinstance(configuration, Mapping):
        raise FleetConfigurationError("configuration must be an object")
    normalized: dict[str, Any] = {}
    for key, value in configuration.items():
        key_text = _text(key, "configuration section")
        if key_text in _FLEET_GOVERNANCE_KEYS:
            if not isinstance(value, Mapping):
                raise FleetConfigurationError(f"{key_text} must be an object")
            unknown = set(value) - _FLEET_GOVERNANCE_KEYS[key_text]
            if unknown:
                fields = ", ".join(sorted(map(str, unknown)))
                raise FleetConfigurationError(f"{key_text} contains unsupported fields: {fields}")
            section = dict(value)
            if key_text == "claudeCode":
                for field in _COMMAND_PATTERN_FIELDS:
                    patterns = section.get(field)
                    if patterns is None:
                        continue
                    if not isinstance(patterns, list) or len(patterns) > 100:
                        raise FleetConfigurationError(f"claudeCode.{field} must be a bounded list")
                    section[field] = [
                        _command_pattern(pattern, f"claudeCode.{field}") for pattern in patterns
                    ]
            elif key_text == "managedHost":
                section = _normalize_managed_host(section)
            normalized[key_text] = section
        else:
            # Preserve legacy extension sections; the recursive bounded and
            # secret-safe serializer remains the final storage boundary.
            normalized[key_text] = value
    return normalized


class EnterpriseFleetStore:
    """SQLite-backed tenant inventory and authenticated agent presence store.

    SQLite is a reference persistence adapter, not a claim that every
    enterprise should use SQLite. WAL mode and a bounded busy timeout improve
    local multi-process behavior; the schema and method contracts remain the
    portable boundary for a PostgreSQL or managed database adapter.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        audit: AuditSink | None = None,
        now: Callable[[], float] | None = None,
        heartbeat_ttl_seconds: int = 90,
        sqlite_busy_timeout_ms: int = 5_000,
        persistence: FleetPersistenceAdapter | None = None,
        require_high_availability: bool = False,
        slo_window_seconds: int = 86_400,
        slo_target: float = 0.99,
        authorities: Mapping[str, FleetDeploymentAuthority] | None = None,
        alert_sink: FleetAlertSink | None = None,
    ) -> None:
        """Open or create a migrated fleet database with bounded heartbeat TTL."""
        if heartbeat_ttl_seconds < 15 or heartbeat_ttl_seconds > 86_400:
            raise FleetConfigurationError("heartbeat TTL must be between 15 and 86400 seconds")
        if (
            isinstance(sqlite_busy_timeout_ms, bool)
            or not isinstance(sqlite_busy_timeout_ms, int)
            or not 100 <= sqlite_busy_timeout_ms <= 60_000
        ):
            raise FleetConfigurationError("SQLite busy timeout must be between 100 and 60000 ms")
        self.persistence = persistence or SQLiteFleetPersistenceAdapter()
        if require_high_availability and not self.persistence.supports_high_availability:
            raise FleetConfigurationError(
                "configured fleet persistence adapter does not provide high availability"
            )
        if slo_window_seconds < 300 or slo_window_seconds > 31_536_000:
            raise FleetConfigurationError("SLO window must be between 300 and 31536000 seconds")
        if not 0.5 <= slo_target <= 1.0:
            raise FleetConfigurationError("SLO target must be between 0.5 and 1.0")
        self.path = str(path)
        self.audit = audit
        self._now = now or time.time
        self.heartbeat_ttl_seconds = heartbeat_ttl_seconds
        self.slo_window_seconds = slo_window_seconds
        self.slo_target = slo_target
        self.authorities = dict(authorities or {})
        self.alert_sink = alert_sink
        self._lock = RLock()
        self._connection = self.persistence.connect(self.path, sqlite_busy_timeout_ms)
        self._migrate()

    def persistence_capabilities(self) -> dict[str, Any]:
        """Return safe adapter metadata so deployment checks can prove HA selection."""
        return {
            "adapter": self.persistence.name,
            "highAvailability": self.persistence.supports_high_availability,
            "schemaVersion": 7,
        }

    def close(self) -> None:
        """Close the persistence connection after callers stop serving requests."""
        with self._lock:
            self._connection.close()

    def reconcile_authorities(self) -> None:
        """Reconcile persisted controls into live authorities before serving traffic.

        The database is not an execution authority. On restart, every bound
        deployment is brought to its persisted stop state and active rollout
        configuration first; any adapter failure aborts reconciliation and
        callers must keep the API out of service.
        """
        with self._lock:
            rows = self._connection.execute(
                "SELECT d.id,c.desired_configuration,c.rollout_state,"
                "COALESCE(ctrl.emergency_stop,0) AS emergency_stop "
                "FROM deployments d LEFT JOIN deployment_configs c ON c.deployment_id=d.id "
                "LEFT JOIN deployment_controls ctrl ON ctrl.deployment_id=d.id"
            ).fetchall()
            rows = [row for row in rows if row["id"] in self.authorities]
            try:
                for row in rows:
                    authority = self.authorities[row["id"]]
                    if bool(row["emergency_stop"]):
                        authority.emergency_stop()
                    else:
                        authority.clear_emergency_stop()
                    if row["desired_configuration"] is not None and row["rollout_state"] in {
                        "canary",
                        "active",
                        "rollback",
                    }:
                        authority.apply_configuration(json.loads(row["desired_configuration"]))
            except Exception as exc:
                raise FleetConfigurationError(
                    "live deployment authority reconciliation failed"
                ) from exc

    def __del__(self) -> None:
        """Best-effort cleanup for short-lived reference applications and tests."""
        connection = getattr(self, "_connection", None)
        if connection is not None:
            try:
                connection.close()
            except Exception:  # pragma: no cover  # noqa: S110
                pass

    def create_organization(self, organization_id: str, name: str) -> dict[str, Any]:
        """Create an organization root for tenant isolation."""
        organization_id, name = _text(organization_id, "organizationId"), _text(name, "name")
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO organizations(id,name,created_at) VALUES(?,?,?)",
                    (organization_id, name, self._now()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("organization already exists") from exc
        return {"id": organization_id, "name": name}

    def create_project(self, organization_id: str, project_id: str, name: str) -> dict[str, Any]:
        """Create a project within an existing organization."""
        organization_id, project_id, name = (
            _text(organization_id, "organizationId"),
            _text(project_id, "projectId"),
            _text(name, "name"),
        )
        with self._lock:
            self._require_org(organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO projects(id,organization_id,name,created_at) VALUES(?,?,?,?)",
                    (project_id, organization_id, name, self._now()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("project already exists") from exc
        return {"id": project_id, "organizationId": organization_id, "name": name}

    def create_deployment(
        self,
        organization_id: str,
        project_id: str,
        deployment_id: str,
        name: str,
        *,
        environment: str,
        region: str,
        sdk_version: str | None = None,
        team: str | None = None,
    ) -> dict[str, Any]:
        """Register one independently managed SDK control-plane deployment."""
        values = tuple(
            _text(value, label)
            for value, label in (
                (organization_id, "organizationId"),
                (project_id, "projectId"),
                (deployment_id, "deploymentId"),
                (name, "name"),
                (environment, "environment"),
                (region, "region"),
            )
        )
        sdk_version = _optional_text(sdk_version, "sdkVersion")
        team = _optional_text(team, "team") or ""
        with self._lock:
            self._require_project(values[0], values[1])
            try:
                self._connection.execute(
                    """INSERT INTO deployments
                    (id,organization_id,project_id,name,environment,region,sdk_version,team,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        values[2],
                        values[0],
                        values[1],
                        values[3],
                        values[4],
                        values[5],
                        sdk_version,
                        team,
                        self._now(),
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("deployment already exists") from exc
        return self._deployment(values[2])

    def list_inventory(
        self,
        identity: FleetIdentity,
        resource: str,
        *,
        organization_id: str | None = None,
        cursor: str | None = None,
        limit: int = 200,
    ) -> FleetPage:
        """Return tenant-scoped inventory without exposing agent session secrets."""
        if resource not in {"organizations", "projects", "deployments", "agents", "sessions"}:
            raise FleetConfigurationError("unknown inventory resource")
        org = organization_id or identity.organization_id
        if org != identity.organization_id and "admin" not in identity.roles:
            raise FleetAuthorizationError("organization scope is not permitted")
        with self._lock:
            if resource == "organizations":
                rows = self._connection.execute(
                    "SELECT id,name,created_at FROM organizations WHERE id=?", (org,)
                ).fetchall()
            elif resource == "projects":
                if identity.project_ids and "admin" not in identity.roles:
                    placeholders = ",".join("?" for _ in identity.project_ids)
                    project_query = (  # noqa: S608 - placeholders are generated from a set length.
                        "SELECT id,organization_id,name,created_at FROM projects "  # noqa: S608
                        f"WHERE organization_id=? AND id IN ({placeholders})"  # noqa: S608
                    )
                    rows = self._connection.execute(
                        project_query,
                        (org, *identity.project_ids),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        "SELECT id,organization_id,name,created_at FROM projects "
                        "WHERE organization_id=?",
                        (org,),
                    ).fetchall()
            elif resource == "deployments":
                query = (
                    "SELECT id,organization_id,project_id,name,environment,region,sdk_version,team,"
                    "created_at FROM deployments WHERE organization_id=?"
                )
                params: tuple[Any, ...] = (org,)
                if identity.project_ids and "admin" not in identity.roles:
                    placeholders = ",".join("?" for _ in identity.project_ids)
                    query += f" AND project_id IN ({placeholders})"
                    params += tuple(identity.project_ids)
                rows = self._connection.execute(query, params).fetchall()
            elif resource == "agents":
                self._expire_agents()
                rows = self._connection.execute(
                    "SELECT id,organization_id,project_id,deployment_id,host,project_root,"
                    "environment,region,status,last_heartbeat,expires_at,metadata FROM agents "
                    "WHERE organization_id=? ORDER BY last_heartbeat DESC",
                    (org,),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT s.agent_id,s.deployment_id,a.organization_id,a.project_id,"
                    "s.created_at,s.expires_at,"
                    "CASE WHEN s.expires_at<=? THEN 'expired' ELSE 'active' END AS status "
                    "FROM agent_sessions s JOIN agents a ON a.id=s.agent_id "
                    "AND a.deployment_id=s.deployment_id WHERE a.organization_id=? "
                    "ORDER BY s.created_at DESC",
                    (self._now(), org),
                ).fetchall()
                rows = [
                    row
                    for row in rows
                    if not identity.project_ids or row["project_id"] in identity.project_ids
                ]
            if resource == "agents":
                projected = []
                for row in rows:
                    item = _agent_inventory_projection(row)
                    item["managed_configuration"] = self._managed_configuration_posture(
                        row["deployment_id"], row["host"], row["metadata"]
                    )
                    projected.append(item)
                items = tuple(projected)
            else:
                items = tuple(_agent_inventory_projection(row) for row in rows)
        return _paginate(items, cursor, limit)

    def create_template(
        self,
        identity: FleetIdentity,
        *,
        template_id: str,
        name: str,
        configuration: Mapping[str, Any],
        parent_template_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a tenant-scoped configuration template with optional inheritance."""
        template_id, name = _text(template_id, "templateId"), _text(name, "name")
        configuration_json = self._configuration_json(configuration)
        with self._lock:
            if parent_template_id is not None:
                parent = self._template(parent_template_id)
                if parent["organizationId"] != identity.organization_id:
                    raise FleetAuthorizationError("organization scope is not permitted")
                self._assert_no_template_cycle(parent_template_id, template_id)
            self._assert_identity_org(identity, identity.organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO templates(id,organization_id,name,parent_id,configuration,version,"
                    "created_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (
                        template_id,
                        identity.organization_id,
                        name,
                        parent_template_id,
                        configuration_json,
                        1,
                        self._now(),
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("template already exists") from exc
        return self._template(template_id)

    def list_templates(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return tenant-scoped templates without exposing secret material."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM templates WHERE organization_id=? ORDER BY name, id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(self._template(row["id"]) for row in rows)
        return _paginate(items, cursor, limit)

    def create_skill(
        self,
        identity: FleetIdentity,
        *,
        skill_id: str,
        name: str,
        description: str,
        version: str,
        content: str,
        enabled: bool,
    ) -> dict[str, Any]:
        """Register reviewed project-scoped Skill content without executable authority."""
        skill_id, name, description, version = (
            _text(skill_id, "skillId"),
            _text(name, "name"),
            _text(description, "description"),
            _text(version, "version"),
        )
        if not isinstance(content, str) or not content.strip():
            raise FleetConfigurationError("content must be bounded non-empty text")
        if len(content) > 100_000:
            raise FleetConfigurationError("skill content is too large")
        digest = f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
        with self._lock:
            self._assert_identity_org(identity, identity.organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO skills(id,organization_id,name,description,version,"
                    "content,digest,enabled,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        skill_id,
                        identity.organization_id,
                        name,
                        description,
                        version,
                        content,
                        digest,
                        int(enabled),
                        self._now(),
                        identity.subject,
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("skill already exists") from exc
        result = self._skill(skill_id)
        self._audit(
            "fleet_skill_created",
            identity.subject,
            {**result, "content": "redacted"},
            identity.organization_id,
        )
        return result

    def list_skills(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return tenant-scoped Skill metadata and content for deployment reconciliation."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM skills WHERE organization_id=? ORDER BY name,id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(self._skill(row["id"]) for row in rows)
        return _paginate(items, cursor, limit)

    def create_mcp_server(
        self,
        identity: FleetIdentity,
        *,
        server_id: str,
        name: str,
        description: str,
        version: str,
        transport: str,
        command: str | None,
        args: Sequence[str],
        url: str | None,
        environment_references: Sequence[str],
        enabled: bool,
    ) -> dict[str, Any]:
        """Register an MCP definition; secret values and credentials remain deployment-owned."""
        server_id, name, description, version, transport = (
            _text(server_id, "serverId"),
            _text(name, "name"),
            _text(description, "description"),
            _text(version, "version"),
            _text(transport, "transport"),
        )
        if transport not in {"stdio", "http"}:
            raise FleetConfigurationError("unsupported MCP transport")
        if transport == "stdio" and not command:
            raise FleetConfigurationError("stdio MCP servers require a command")
        if transport == "http" and not url:
            raise FleetConfigurationError("HTTP MCP servers require a URL")
        with self._lock:
            self._assert_identity_org(identity, identity.organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO mcp_servers(id,organization_id,name,description,version,"
                    "transport,command,args,url,environment_references,enabled,created_at,"
                    "created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        server_id,
                        identity.organization_id,
                        name,
                        description,
                        version,
                        transport,
                        command,
                        json.dumps(list(args)),
                        url,
                        json.dumps(list(environment_references)),
                        int(enabled),
                        self._now(),
                        identity.subject,
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("MCP server already exists") from exc
        result = self._mcp_server(server_id)
        self._audit("fleet_mcp_server_created", identity.subject, result, identity.organization_id)
        return result

    def list_mcp_servers(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return tenant-scoped MCP metadata without secret values."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM mcp_servers WHERE organization_id=? ORDER BY name,id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(self._mcp_server(row["id"]) for row in rows)
        return _paginate(items, cursor, limit)

    def create_policy(
        self,
        identity: FleetIdentity,
        *,
        policy_id: str,
        name: str,
        configuration: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Create a tenant-scoped policy and its first non-active draft.

        New policy content cannot become group authority until another subject
        approves it and the version completes staging and activation.
        """
        policy_id, name = _text(policy_id, "policyId"), _text(name, "name")
        configuration_json = self._configuration_json(configuration)
        now = self._now()
        with self._lock:
            self._assert_identity_org(identity, identity.organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO policies(id,organization_id,name,configuration,version,"
                    "created_at,created_by) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        policy_id,
                        identity.organization_id,
                        name,
                        "{}",
                        0,
                        now,
                        identity.subject,
                    ),
                )
                self._insert_policy_version(
                    policy_id=policy_id,
                    organization_id=identity.organization_id,
                    version=1,
                    base_version=0,
                    name=name,
                    configuration_json=configuration_json,
                    state="draft",
                    author=identity.subject,
                    created_at=now,
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise FleetConfigurationError("policy already exists") from exc
        result = self._policy(policy_id)
        self._audit(
            "fleet_policy_draft_created",
            identity.subject,
            self._policy_version(policy_id, 1),
            identity.organization_id,
        )
        return result

    def update_policy(
        self,
        identity: FleetIdentity,
        *,
        policy_id: str,
        name: str,
        configuration: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Create an immutable-numbered draft from the current active policy."""
        policy_id, name = _text(policy_id, "policyId"), _text(name, "name")
        configuration_json = self._configuration_json(configuration)
        with self._lock:
            current = self._policy(policy_id)
            if current["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            self._assert_identity_org(identity, identity.organization_id)
            pending = self._connection.execute(
                "SELECT version FROM policy_versions WHERE policy_id=? AND state IN "
                "('draft','review','approved','staged') ORDER BY version DESC LIMIT 1",
                (policy_id,),
            ).fetchone()
            if pending is not None:
                raise FleetConflictError("policy already has a pending governed version")
            row = self._connection.execute(
                "SELECT COALESCE(MAX(version),0) AS latest FROM policy_versions WHERE policy_id=?",
                (policy_id,),
            ).fetchone()
            version = int(row["latest"]) + 1
            self._insert_policy_version(
                policy_id=policy_id,
                organization_id=identity.organization_id,
                version=version,
                base_version=int(current["version"]),
                name=name,
                configuration_json=configuration_json,
                state="draft",
                author=identity.subject,
                created_at=self._now(),
            )
            self._connection.commit()
        result = self._policy_version(policy_id, version)
        self._audit(
            "fleet_policy_draft_created", identity.subject, result, identity.organization_id
        )
        return result

    def list_policy_versions(
        self,
        identity: FleetIdentity,
        policy_id: str,
        *,
        cursor: str | None = None,
        limit: int = 200,
    ) -> FleetPage:
        """Return the tenant-scoped immutable version ledger for one policy."""
        policy_id = _text(policy_id, "policyId")
        with self._lock:
            policy = self._policy(policy_id)
            if policy["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            rows = self._connection.execute(
                "SELECT version FROM policy_versions WHERE policy_id=? ORDER BY version DESC",
                (policy_id,),
            ).fetchall()
            items = tuple(self._policy_version(policy_id, int(row["version"])) for row in rows)
        return _paginate(items, cursor, limit)

    def policy_version(
        self, identity: FleetIdentity, policy_id: str, version: int
    ) -> dict[str, Any]:
        """Return one exact policy version after tenant and version validation."""
        policy_id, version = _text(policy_id, "policyId"), _positive_version(version)
        with self._lock:
            result = self._policy_version(policy_id, version)
            if result["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            return result

    def submit_policy_version(
        self, identity: FleetIdentity, policy_id: str, version: int
    ) -> dict[str, Any]:
        """Freeze a draft and submit it for independent review."""
        return self._transition_policy_version(
            identity,
            policy_id,
            version,
            expected_state="draft",
            next_state="review",
            fields={"submitted_by": identity.subject, "submitted_at": self._now()},
            event="fleet_policy_submitted",
        )

    def decide_policy_version(
        self,
        identity: FleetIdentity,
        policy_id: str,
        version: int,
        *,
        decision: str,
        reason: str,
    ) -> dict[str, Any]:
        """Approve or reject a review while enforcing two-subject separation."""
        decision, reason = _text(decision, "decision"), _text(reason, "reason")
        if decision not in {"approved", "rejected"}:
            raise FleetConfigurationError("policy decision must be approved or rejected")
        policy_id, version = _text(policy_id, "policyId"), _positive_version(version)
        with self._lock:
            current = self._policy_version(policy_id, version)
            if current["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            if current["state"] != "review":
                raise FleetConflictError("policy version is not awaiting review")
            if decision == "approved" and hmac.compare_digest(current["author"], identity.subject):
                raise FleetAuthorizationError("policy authors cannot approve their own version")
            now = self._now()
            changed = self._connection.execute(
                "UPDATE policy_versions SET state=?,decided_by=?,decided_at=?,decision_reason=? "
                "WHERE policy_id=? AND version=? AND state='review'",
                (decision, identity.subject, now, reason, policy_id, version),
            )
            if changed.rowcount != 1:
                self._connection.rollback()
                raise FleetConflictError("policy decision was already recorded")
            self._connection.commit()
            result = self._policy_version(policy_id, version)
        self._audit("fleet_policy_decided", identity.subject, result, identity.organization_id)
        return result

    def stage_policy_version(
        self, identity: FleetIdentity, policy_id: str, version: int
    ) -> dict[str, Any]:
        """Stage an independently approved version against its exact active base."""
        policy_id, version = _text(policy_id, "policyId"), _positive_version(version)
        with self._lock:
            current = self._policy_version(policy_id, version)
            policy = self._policy(policy_id)
            if current["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            if current["state"] != "approved":
                raise FleetConflictError("policy version is not approved")
            if current["approvedBy"] == current["author"] or current["approvedBy"] is None:
                raise FleetAuthorizationError("policy version lacks independent approval")
            if current["baseVersion"] != policy["version"]:
                raise FleetConflictError("policy active version changed before staging")
        return self._transition_policy_version(
            identity,
            policy_id,
            version,
            expected_state="approved",
            next_state="staged",
            fields={"staged_by": identity.subject, "staged_at": self._now()},
            event="fleet_policy_staged",
        )

    def activate_policy_version(
        self,
        identity: FleetIdentity,
        policy_id: str,
        version: int,
        *,
        expected_active_version: int,
    ) -> dict[str, Any]:
        """Atomically promote a staged version and retire prior active authority."""
        policy_id, version = _text(policy_id, "policyId"), _positive_version(version)
        if isinstance(expected_active_version, bool) or not isinstance(
            expected_active_version, int
        ):
            raise FleetConfigurationError("expectedActiveVersion must be an integer")
        if expected_active_version < 0:
            raise FleetConfigurationError("expectedActiveVersion cannot be negative")
        with self._lock:
            candidate = self._policy_version(policy_id, version)
            policy = self._policy(policy_id)
            if candidate["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            if candidate["state"] != "staged":
                raise FleetConflictError("policy version is not staged")
            if candidate["approvedBy"] in {None, candidate["author"]}:
                raise FleetAuthorizationError("policy version lacks independent approval")
            if (
                policy["version"] != expected_active_version
                or candidate["baseVersion"] != expected_active_version
            ):
                raise FleetConflictError("policy active version changed before activation")
            now = self._now()
            try:
                changed = self._connection.execute(
                    "UPDATE policy_versions SET state='active',activated_by=?,activated_at=? "
                    "WHERE policy_id=? AND version=? AND state='staged'",
                    (identity.subject, now, policy_id, version),
                )
                if changed.rowcount != 1:
                    raise FleetConflictError("policy version activation was already attempted")
                if expected_active_version > 0:
                    self._connection.execute(
                        "UPDATE policy_versions SET state='retired' WHERE policy_id=? "
                        "AND version=? AND state='active'",
                        (policy_id, expected_active_version),
                    )
                updated = self._connection.execute(
                    "UPDATE policies SET name=?,configuration=?,version=? WHERE id=? AND version=?",
                    (
                        candidate["name"],
                        json.dumps(
                            candidate["configuration"], sort_keys=True, separators=(",", ":")
                        ),
                        version,
                        policy_id,
                        expected_active_version,
                    ),
                )
                if updated.rowcount != 1:
                    raise FleetConflictError("policy active version changed before activation")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            result = self._policy(policy_id)
        self._audit("fleet_policy_activated", identity.subject, result, identity.organization_id)
        return result

    def list_policies(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return tenant-scoped configuration policies without secret material."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM policies WHERE organization_id=? ORDER BY name,id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(self._policy(row["id"]) for row in rows)
        return _paginate(items, cursor, limit)

    def create_group(
        self,
        identity: FleetIdentity,
        *,
        group_id: str,
        name: str,
        policy_id: str,
    ) -> dict[str, Any]:
        """Create a tenant-scoped agent group bound to one configuration policy."""
        group_id, name, policy_id = (
            _text(group_id, "groupId"),
            _text(name, "name"),
            _text(policy_id, "policyId"),
        )
        with self._lock:
            policy = self._policy(policy_id)
            if policy["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            if policy["activeVersion"] is None:
                raise FleetConflictError("group policies must have an active governed version")
            self._assert_identity_org(identity, identity.organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO agent_groups(id,organization_id,name,policy_id,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (group_id, identity.organization_id, name, policy_id, self._now()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("group already exists") from exc
        result = self._group(group_id)
        self._audit("fleet_group_created", identity.subject, result, identity.organization_id)
        return result

    def list_groups(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return groups with redacted agent membership for enterprise management."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM agent_groups WHERE organization_id=? ORDER BY name,id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(self._group(row["id"]) for row in rows)
        return _paginate(items, cursor, limit)

    def update_group_policy(
        self, identity: FleetIdentity, *, group_id: str, policy_id: str
    ) -> dict[str, Any]:
        """Change a group's policy assignment as an audited control operation.

        Policies remain immutable records. Reassigning a group therefore
        preserves policy history while making the new effective policy
        explicit for every enrolled runtime on its next refresh.
        """
        group_id, policy_id = _text(group_id, "groupId"), _text(policy_id, "policyId")
        with self._lock:
            group = self._group(group_id)
            policy = self._policy(policy_id)
            if group["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            if policy["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            if policy["activeVersion"] is None:
                raise FleetConflictError("group policies must have an active governed version")
            self._assert_identity_org(identity, identity.organization_id)
            self._connection.execute(
                "UPDATE agent_groups SET policy_id=? WHERE id=?",
                (policy_id, group_id),
            )
            self._connection.commit()
        result = self._group(group_id)
        self._audit(
            "fleet_group_policy_changed",
            identity.subject,
            {
                "groupId": group_id,
                "policyId": policy_id,
                "previousPolicyId": group["policyId"],
            },
            identity.organization_id,
        )
        return result

    def add_agent_to_group(
        self, identity: FleetIdentity, *, group_id: str, deployment_id: str, agent_id: str
    ) -> dict[str, Any]:
        """Enroll an existing tenant agent in a group without changing its session."""
        group_id, deployment_id, agent_id = (
            _text(group_id, "groupId"),
            _text(deployment_id, "deploymentId"),
            _text(agent_id, "agentId"),
        )
        with self._lock:
            group = self._group(group_id)
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, group["organizationId"], agent["projectId"])
            if agent["organizationId"] != group["organizationId"]:
                raise FleetAuthorizationError("organization scope is not permitted")
            try:
                self._connection.execute(
                    "INSERT INTO agent_group_members(group_id,deployment_id,agent_id) "
                    "VALUES(?,?,?)",
                    (group_id, deployment_id, agent_id),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("agent is already in this group") from exc
        result = self._group(group_id)
        self._audit(
            "fleet_group_agent_added",
            identity.subject,
            {"groupId": group_id, "deploymentId": deployment_id, "agentId": agent_id},
            identity.organization_id,
        )
        return result

    def remove_agent_from_group(
        self, identity: FleetIdentity, *, group_id: str, deployment_id: str, agent_id: str
    ) -> dict[str, Any]:
        """Remove an agent from a group while leaving its enrollment intact."""
        group_id, deployment_id, agent_id = (
            _text(group_id, "groupId"),
            _text(deployment_id, "deploymentId"),
            _text(agent_id, "agentId"),
        )
        with self._lock:
            group = self._group(group_id)
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, group["organizationId"], agent["projectId"])
            if agent["organizationId"] != group["organizationId"]:
                raise FleetAuthorizationError("organization scope is not permitted")
            deleted = self._connection.execute(
                "DELETE FROM agent_group_members WHERE group_id=? AND deployment_id=? "
                "AND agent_id=?",
                (group_id, deployment_id, agent_id),
            ).rowcount
            if deleted != 1:
                raise FleetNotFoundError("agent group membership not found")
            self._connection.commit()
        result = self._group(group_id)
        self._audit(
            "fleet_group_agent_removed",
            identity.subject,
            {"groupId": group_id, "deploymentId": deployment_id, "agentId": agent_id},
            identity.organization_id,
        )
        return result

    def effective_agent_policy(
        self, identity: FleetIdentity, *, deployment_id: str, agent_id: str
    ) -> dict[str, Any]:
        """Return the one policy currently effective for an enrolled agent.

        The lookup is authenticated and tenant-scoped. An agent must have
        exactly one group membership; duplicate memberships fail closed even
        when they reference the same policy. The returned
        policy is configuration data; the deployment-owned runtime remains
        responsible for translating it into its typed policy and adapters.
        """
        deployment_id, agent_id = _text(deployment_id, "deploymentId"), _text(agent_id, "agentId")
        with self._lock:
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, agent["organizationId"], agent["projectId"])
            self._assert_agent_identity(identity, agent_id)
            managed_configuration = agent["managed_configuration"]
            if (
                managed_configuration["desired"] is not None
                and managed_configuration["status"] != "enforced"
            ):
                raise FleetConfigurationError("managed host configuration is not freshly enforced")
            rows = self._connection.execute(
                "SELECT g.id,g.name,g.policy_id FROM agent_group_members m "
                "JOIN agent_groups g ON g.id=m.group_id "
                "WHERE m.deployment_id=? AND m.agent_id=? ORDER BY g.id",
                (deployment_id, agent_id),
            ).fetchall()
            if not rows:
                raise FleetNotFoundError("agent is not assigned to a policy group")
            if len(rows) != 1:
                raise FleetConfigurationError("agent must belong to exactly one policy group")
            policy_ids = {str(row["policy_id"]) for row in rows}
            if len(policy_ids) != 1:
                raise FleetConfigurationError("agent belongs to groups with conflicting policies")
            policy = self._policy(next(iter(policy_ids)))
            configuration = json.loads(json.dumps(policy["configuration"]))
            claude_value = configuration.get("claudeCode")
            if isinstance(claude_value, Mapping):
                claude = dict(claude_value)
                configuration["claudeCode"] = claude
                resolved_skills = []
                for resource_id in claude.get("allowedSkills", []):
                    resource = self._skill(_text(resource_id, "skillId"))
                    if not resource["enabled"]:
                        raise FleetConfigurationError("policy references a disabled Skill")
                    resolved_skills.append(resource)
                resolved_mcp = []
                for resource_id in claude.get("allowedMcpServers", []):
                    resource = self._mcp_server(_text(resource_id, "serverId"))
                    if not resource["enabled"]:
                        raise FleetConfigurationError("policy references a disabled MCP server")
                    resolved_mcp.append(resource)
                claude["managedSkills"] = resolved_skills
                claude["managedMcpServers"] = resolved_mcp
                policy = {**policy, "configuration": configuration}
            result = {
                "agentId": agent_id,
                "deploymentId": deployment_id,
                "groupId": rows[0]["id"],
                "groupName": rows[0]["name"],
                "emergencyStop": self._agent_emergency_stop(deployment_id, agent_id),
                "policy": policy,
            }
        self._audit(
            "fleet_effective_policy_read",
            identity.subject,
            {"agentId": agent_id, "deploymentId": deployment_id, "policyId": policy["id"]},
            identity.organization_id,
        )
        return result

    def verify_agent(
        self, identity: FleetIdentity, *, deployment_id: str, agent_id: str
    ) -> dict[str, Any]:
        """Verify enrollment, liveness, policy assignment, and stop state.

        This is an operational read, not a trust grant.  It reports each
        prerequisite independently so an operator can distinguish an offline
        process from a missing policy or an intentionally stopped agent.
        """
        deployment_id, agent_id = _text(deployment_id, "deploymentId"), _text(agent_id, "agentId")
        with self._lock:
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, agent["organizationId"], agent["projectId"])
            groups = self._connection.execute(
                "SELECT g.id,g.name,g.policy_id FROM agent_group_members m "
                "JOIN agent_groups g ON g.id=m.group_id "
                "WHERE m.deployment_id=? AND m.agent_id=? ORDER BY g.id",
                (deployment_id, agent_id),
            ).fetchall()
            policy_ids = {str(row["policy_id"]) for row in groups}
            assigned_policy = None
            if len(groups) == 1 and len(policy_ids) == 1:
                try:
                    assigned_policy = self._policy(next(iter(policy_ids)))
                except FleetNotFoundError:
                    assigned_policy = None
            stopped = self._agent_emergency_stop(deployment_id, agent_id)
            now = float(self._now())
            checks = {
                "registered": {"passed": True, "detail": "Agent is registered to this deployment."},
                "heartbeat": {
                    "passed": agent["status"] == "connected" and agent["expiresAt"] > now,
                    "detail": (
                        "Heartbeat is current."
                        if agent["status"] == "connected" and agent["expiresAt"] > now
                        else "Heartbeat is expired or the agent is offline."
                    ),
                },
                "projectRoot": {
                    "passed": bool(agent["projectRoot"]),
                    "detail": (
                        "Project root is recorded."
                        if agent["projectRoot"]
                        else "Project root is missing."
                    ),
                },
                "policyAssignment": {
                    "passed": assigned_policy is not None,
                    "detail": (
                        "Exactly one valid policy group is assigned."
                        if assigned_policy is not None
                        else "Agent must belong to exactly one group with a valid policy."
                    ),
                },
                "managedConfiguration": {
                    "passed": agent["managed_configuration"]["status"] == "enforced",
                    "detail": (
                        "Exact managed host bundle is freshly observed."
                        if agent["managed_configuration"]["status"] == "enforced"
                        else "Managed host configuration is not freshly proven."
                    ),
                },
                "emergencyStop": {
                    "passed": not stopped,
                    "detail": (
                        "No emergency stop is active."
                        if not stopped
                        else "An emergency stop is active."
                    ),
                },
            }
            result = {
                "agentId": agent_id,
                "deploymentId": deployment_id,
                "verified": all(item["passed"] for item in checks.values()),
                "checkedAt": now,
                "checks": checks,
                "host": agent["host"],
                "status": agent["status"],
                "groups": [row["id"] for row in groups],
                "policyId": assigned_policy["id"] if assigned_policy is not None else None,
                "policyVersion": (
                    assigned_policy["version"] if assigned_policy is not None else None
                ),
            }
        self._audit(
            "fleet_agent_verification_read",
            identity.subject,
            {"agentId": agent_id, "deploymentId": deployment_id, "verified": result["verified"]},
            identity.organization_id,
        )
        return result

    def validate_template_configuration(
        self, identity: FleetIdentity, configuration: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate a proposed template without persisting it or changing authority."""
        self._assert_identity_org(identity, identity.organization_id)
        normalized = json.loads(self._configuration_json(configuration))
        return {
            "valid": True,
            "configuration": normalized,
            "configurationHash": self._configuration_hash(normalized),
        }

    def assign_template(
        self, identity: FleetIdentity, deployment_id: str, template_id: str
    ) -> dict[str, Any]:
        """Set a deployment's desired configuration and stage it for rollout."""
        deployment_id, template_id = (
            _text(deployment_id, "deploymentId"),
            _text(template_id, "templateId"),
        )
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            effective = self._effective_template(template_id)
            if effective["organizationId"] != deployment["organizationId"]:
                raise FleetAuthorizationError("organization scope is not permitted")
            desired_hash = self._configuration_hash(effective["configuration"])
            existing = self._connection.execute(
                "SELECT version,template_id,desired_configuration,desired_hash,applied_hash,"
                "rollout_state,rollout_percentage FROM deployment_configs WHERE deployment_id=?",
                (deployment_id,),
            ).fetchone()
            version = int(existing["version"] if existing else 0) + 1
            if existing is not None:
                self._connection.execute(
                    "INSERT INTO deployment_config_history(deployment_id,version,template_id,"
                    "desired_configuration,desired_hash,applied_hash,rollout_state,"
                    "rollout_percentage,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        deployment_id,
                        existing["version"],
                        existing["template_id"],
                        existing["desired_configuration"],
                        existing["desired_hash"],
                        existing["applied_hash"],
                        existing["rollout_state"],
                        existing["rollout_percentage"],
                        self._now(),
                    ),
                )
            self._connection.execute(
                """INSERT INTO deployment_configs
                (deployment_id,template_id,desired_configuration,desired_hash,applied_hash,
                 rollout_state,rollout_percentage,version,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(deployment_id) DO UPDATE SET template_id=excluded.template_id,
                desired_configuration=excluded.desired_configuration,desired_hash=excluded.desired_hash,
                rollout_state='staged',rollout_percentage=0,version=excluded.version,updated_at=excluded.updated_at""",
                (
                    deployment_id,
                    template_id,
                    json.dumps(effective["configuration"], sort_keys=True, separators=(",", ":")),
                    desired_hash,
                    existing["applied_hash"] if existing else None,
                    "staged",
                    0,
                    version,
                    self._now(),
                ),
            )
            self._connection.commit()
            result = self._deployment_configuration(deployment_id)
        self._audit(
            "fleet_configuration_staged", identity.subject, result, identity.organization_id
        )
        return result

    def publish_managed_deployment_package(
        self,
        identity: FleetIdentity,
        deployment_id: str,
        encoded: bytes,
        *,
        expected_package_sha256: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Publish one canonical package bound to current deployment desired state.

        Publication stores credential-free configuration bytes only. The caller
        must provide the package digest and current revision; package parsing,
        desired-state binding and compare-and-swap happen before the new
        revision becomes visible. No endpoint is changed by this method.
        """
        deployment_id = _text(deployment_id, "deploymentId")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise FleetConfigurationError("managed package revision must be non-negative")
        if (
            not isinstance(encoded, bytes)
            or not encoded
            or len(encoded) > _MAX_MANAGED_PACKAGE_BYTES
        ):
            raise FleetConfigurationError("managed package exceeds the control-plane size limit")
        try:
            package = ManagedDeploymentPackage.from_json(
                encoded, expected_package_sha256=expected_package_sha256
            )
        except (TypeError, ValueError) as exc:
            raise FleetConfigurationError("managed package is invalid") from exc
        canonical = package.to_json()
        package_base64 = base64.b64encode(canonical).decode("ascii")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            desired = self._desired_managed_host(deployment_id)
            self._require_package_matches_desired(package, desired)
            host_rows = self._connection.execute(
                "SELECT DISTINCT host FROM agents WHERE deployment_id=?", (deployment_id,)
            ).fetchall()
            if any(row["host"] != package.host.value for row in host_rows):
                raise FleetConfigurationError(
                    "managed package host conflicts with an enrolled deployment agent"
                )
            current = self._connection.execute(
                "SELECT revision FROM deployment_managed_packages WHERE deployment_id=?",
                (deployment_id,),
            ).fetchone()
            current_revision = int(current["revision"]) if current is not None else 0
            if current_revision != expected_revision:
                raise FleetConfigurationError("managed package revision is stale")
            next_revision = current_revision + 1
            values = (
                next_revision,
                package_base64,
                package.package_sha256,
                package.bundle_hash,
                package.host.value,
                package.host_version,
                package.platform.value,
                package.policy_id,
                package.policy_version,
                self._now(),
                identity.subject,
            )
            try:
                if current is None:
                    self._connection.execute(
                        "INSERT INTO deployment_managed_packages(deployment_id,revision,"
                        "package_base64,package_sha256,bundle_hash,host,host_version,platform,"
                        "policy_id,policy_version,published_at,published_by) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (deployment_id, *values),
                    )
                else:
                    updated = self._connection.execute(
                        "UPDATE deployment_managed_packages SET revision=?,package_base64=?,"
                        "package_sha256=?,bundle_hash=?,host=?,host_version=?,platform=?,"
                        "policy_id=?,policy_version=?,published_at=?,published_by=? "
                        "WHERE deployment_id=? AND revision=?",
                        (*values, deployment_id, expected_revision),
                    )
                    if updated.rowcount != 1:
                        self._connection.rollback()
                        raise FleetConfigurationError("managed package revision is stale")
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise FleetConfigurationError("managed package revision is stale") from exc
            result = self._managed_deployment_package_metadata(deployment_id)
        self._audit(
            "managed_deployment_package_published",
            identity.subject,
            {
                "deploymentId": deployment_id,
                "revision": result["revision"],
                "packageSha256": result["packageSha256"],
                "bundleHash": result["bundleHash"],
                "host": result["host"],
                "platform": result["platform"],
            },
            identity.organization_id,
        )
        return result

    def managed_deployment_package_metadata(
        self, identity: FleetIdentity, deployment_id: str
    ) -> dict[str, Any]:
        """Return browser-safe package metadata without embedded configuration."""
        deployment_id = _text(deployment_id, "deploymentId")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            return self._managed_deployment_package_metadata(deployment_id)

    def agent_managed_deployment_package(
        self, identity: FleetIdentity, *, deployment_id: str, agent_id: str
    ) -> dict[str, Any]:
        """Return an exact package to its authenticated rollout-selected agent.

        Missing or conflicting managed-configuration evidence does not block
        this repair route. Agent identity, project scope, emergency-stop state,
        desired state, package integrity and deterministic rollout selection
        are still checked on every request.
        """
        deployment_id, agent_id = _text(deployment_id, "deploymentId"), _text(agent_id, "agentId")
        with self._lock:
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, agent["organizationId"], agent["projectId"])
            self._assert_agent_identity(identity, agent_id)
            if agent["emergencyStop"]:
                raise FleetConfigurationError("agent emergency stop blocks package retrieval")
            configuration = self._require_configuration(deployment_id)
            if configuration["rolloutState"] not in {"canary", "active", "rollback"}:
                raise FleetConfigurationError("managed package rollout is not active")
            percentage = int(configuration["rolloutPercentage"])
            bucket = (
                int(hashlib.sha256(f"{deployment_id}:{agent_id}".encode()).hexdigest()[:8], 16)
                % 100
            )
            if percentage <= bucket:
                raise FleetConfigurationError("agent is not selected for managed package rollout")
            metadata = self._managed_deployment_package_metadata(deployment_id)
            if metadata["status"] != "current" or metadata["host"] != agent["host"]:
                raise FleetConfigurationError("managed package does not match current agent state")
            row = self._connection.execute(
                "SELECT package_base64 FROM deployment_managed_packages WHERE deployment_id=?",
                (deployment_id,),
            ).fetchone()
            if row is None:
                raise FleetNotFoundError("managed deployment package not found")
            return {
                "schemaVersion": 1,
                "deploymentId": deployment_id,
                "agentId": agent_id,
                **metadata,
                "packageBase64": row["package_base64"],
            }

    def set_rollout(
        self,
        identity: FleetIdentity,
        deployment_id: str,
        *,
        state: str,
        percentage: int,
    ) -> dict[str, Any]:
        """Advance or pause one deployment rollout with bounded percentage."""
        deployment_id, state = _text(deployment_id, "deploymentId"), _text(state, "state")
        if state not in {"staged", "canary", "active", "paused", "rollback"}:
            raise FleetConfigurationError("unknown rollout state")
        if (
            not isinstance(percentage, int)
            or isinstance(percentage, bool)
            or not 0 <= percentage <= 100
        ):
            raise FleetConfigurationError("rollout percentage must be between 0 and 100")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            configuration = self._require_configuration(deployment_id)
            authority = self.authorities.get(deployment_id)
            if authority is not None and state in {"canary", "active"}:
                try:
                    authority.apply_configuration(configuration["desiredConfiguration"])
                except Exception as exc:
                    raise FleetConfigurationError(
                        "deployment runtime rejected the configuration rollout"
                    ) from exc
            self._connection.execute(
                "UPDATE deployment_configs SET rollout_state=?,rollout_percentage=?,updated_at=? "
                "WHERE deployment_id=?",
                (state, percentage, self._now(), deployment_id),
            )
            self._connection.commit()
            result = self._deployment_configuration(deployment_id)
        self._audit(
            "fleet_configuration_rollout_changed",
            identity.subject,
            result,
            identity.organization_id,
        )
        return result

    def rollout_deployments(
        self,
        identity: FleetIdentity,
        deployment_ids: Sequence[str],
        *,
        state: str,
        percentage: int,
    ) -> FleetPage:
        """Apply one bounded rollout command to multiple scoped deployments."""
        if not deployment_ids or len(deployment_ids) > 200:
            raise FleetConfigurationError("rollout must target between 1 and 200 deployments")
        normalized = tuple(dict.fromkeys(_text(item, "deploymentId") for item in deployment_ids))
        results = tuple(
            self.set_rollout(identity, deployment_id, state=state, percentage=percentage)
            for deployment_id in normalized
        )
        self._audit(
            "fleet_batch_rollout_changed",
            identity.subject,
            {"deploymentIds": list(normalized), "state": state, "percentage": percentage},
            identity.organization_id,
        )
        return FleetPage(results, None)

    def rollback_deployment(
        self, identity: FleetIdentity, deployment_id: str, version: int
    ) -> dict[str, Any]:
        """Restore a prior desired configuration as a new staged version."""
        deployment_id = _text(deployment_id, "deploymentId")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise FleetConfigurationError("rollback version must be a positive integer")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            previous = self._connection.execute(
                "SELECT template_id,desired_configuration,desired_hash,applied_hash FROM "
                "deployment_config_history WHERE deployment_id=? AND version=?",
                (deployment_id, version),
            ).fetchone()
            if previous is None:
                raise FleetNotFoundError("deployment configuration version not found")
            current = self._require_configuration(deployment_id)
            next_version = int(current["version"]) + 1
            authority = self.authorities.get(deployment_id)
            if authority is not None:
                try:
                    authority.apply_configuration(json.loads(previous["desired_configuration"]))
                except Exception as exc:
                    raise FleetConfigurationError(
                        "deployment runtime rejected the configuration rollback"
                    ) from exc
            self._connection.execute(
                "INSERT INTO deployment_config_history(deployment_id,version,template_id,"
                "desired_configuration,desired_hash,applied_hash,rollout_state,"
                "rollout_percentage,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    deployment_id,
                    current["version"],
                    current["templateId"],
                    json.dumps(
                        current["desiredConfiguration"], sort_keys=True, separators=(",", ":")
                    ),
                    current["desiredHash"],
                    current["appliedHash"],
                    current["rolloutState"],
                    current["rolloutPercentage"],
                    self._now(),
                ),
            )
            self._connection.execute(
                "UPDATE deployment_configs SET template_id=?,desired_configuration=?,"
                "desired_hash=?,applied_hash=?,rollout_state='rollback',rollout_percentage=0,"
                "version=?,updated_at=? "
                "WHERE deployment_id=?",
                (
                    previous["template_id"],
                    previous["desired_configuration"],
                    previous["desired_hash"],
                    previous["applied_hash"],
                    next_version,
                    self._now(),
                    deployment_id,
                ),
            )
            self._connection.commit()
            result = self._deployment_configuration(deployment_id)
        self._audit(
            "fleet_configuration_rollback", identity.subject, result, identity.organization_id
        )
        return result

    def list_configurations(
        self,
        identity: FleetIdentity,
        deployment_id: str | None = None,
        *,
        cursor: str | None = None,
        limit: int = 200,
    ) -> FleetPage:
        """Return desired/applied configuration state for scoped deployments."""
        with self._lock:
            query = (
                "SELECT d.id AS deployment_id, d.project_id FROM deployments d "
                "JOIN deployment_configs c ON c.deployment_id=d.id "
                "WHERE d.organization_id=?"
            )
            params: list[Any] = [identity.organization_id]
            if deployment_id is not None:
                query += " AND d.id=?"
                params.append(_text(deployment_id, "deploymentId"))
            rows = self._connection.execute(query, params).fetchall()
            items = tuple(
                self._deployment_configuration(row["deployment_id"])
                for row in rows
                if not identity.project_ids or row["project_id"] in identity.project_ids
            )
        return _paginate(items, cursor, limit)

    def list_configuration_history(
        self,
        identity: FleetIdentity,
        deployment_id: str | None = None,
        *,
        cursor: str | None = None,
        limit: int = 200,
    ) -> FleetPage:
        """Return bounded, tenant-scoped prior configuration versions."""
        with self._lock:
            query = (
                "SELECT h.deployment_id,h.version,h.template_id,h.desired_hash,"
                "h.applied_hash,h.rollout_state,h.rollout_percentage,h.created_at,"
                "d.project_id FROM deployment_config_history h "
                "JOIN deployments d ON d.id=h.deployment_id WHERE d.organization_id=?"
            )
            params: list[Any] = [identity.organization_id]
            if deployment_id is not None:
                query += " AND h.deployment_id=?"
                params.append(_text(deployment_id, "deploymentId"))
            query += " ORDER BY h.created_at DESC LIMIT 2000"
            rows = self._connection.execute(query, params).fetchall()
        items = tuple(
            {
                "deploymentId": row["deployment_id"],
                "version": row["version"],
                "templateId": row["template_id"],
                "desiredHash": row["desired_hash"],
                "appliedHash": row["applied_hash"],
                "rolloutState": row["rollout_state"],
                "rolloutPercentage": row["rollout_percentage"],
                "createdAt": row["created_at"],
            }
            for row in rows
            if not identity.project_ids or row["project_id"] in identity.project_ids
        )
        return _paginate(items, cursor, limit)

    def record_applied_configuration(
        self, identity: FleetIdentity, deployment_id: str, configuration_hash: str
    ) -> dict[str, Any]:
        """Record an agent-reported applied hash only when it matches desired state."""
        deployment_id, configuration_hash = (
            _text(deployment_id, "deploymentId"),
            _text(configuration_hash, "configurationHash"),
        )
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            desired = self._require_configuration(deployment_id)
            if not hmac.compare_digest(configuration_hash, desired["desiredHash"]):
                raise FleetConfigurationError("applied configuration does not match desired state")
            self._connection.execute(
                "UPDATE deployment_configs SET applied_hash=?,updated_at=? WHERE deployment_id=?",
                (configuration_hash, self._now(), deployment_id),
            )
            self._connection.commit()
            return self._deployment_configuration(deployment_id)

    def list_drift(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return deployments whose applied configuration differs from desired state."""
        with self._lock:
            rows = self._connection.execute(
                """SELECT d.id,d.organization_id,d.project_id,d.name,d.environment,d.region,
                c.template_id,c.desired_hash,c.applied_hash,c.rollout_state,c.rollout_percentage,c.version
                FROM deployments d JOIN deployment_configs c ON c.deployment_id=d.id
                WHERE d.organization_id=? AND (c.applied_hash IS NULL OR c.applied_hash<>?)""",
                (identity.organization_id, ""),
            ).fetchall()
        items = tuple(
            dict(row)
            for row in rows
            if identity.project_ids == frozenset() or row["project_id"] in identity.project_ids
        )
        return _paginate(items, cursor, limit)

    def set_emergency_stop(
        self, identity: FleetIdentity, deployment_id: str, *, active: bool
    ) -> dict[str, Any]:
        """Activate or clear one deployment's stop state through tenant scope."""
        if not isinstance(active, bool):
            raise FleetConfigurationError("emergency stop state must be boolean")
        deployment_id = _text(deployment_id, "deploymentId")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            authority = self.authorities.get(deployment_id)
            if authority is not None:
                try:
                    authority.emergency_stop() if active else authority.clear_emergency_stop()
                except Exception as exc:
                    raise FleetConfigurationError(
                        "deployment runtime rejected the emergency-stop change"
                    ) from exc
            self._connection.execute(
                "INSERT INTO deployment_controls(deployment_id,emergency_stop,updated_at) "
                "VALUES(?,?,?) "
                "ON CONFLICT(deployment_id) DO UPDATE SET emergency_stop=excluded.emergency_stop,"
                "updated_at=excluded.updated_at",
                (deployment_id, int(active), self._now()),
            )
            self._connection.commit()
            result = self._deployment_health(deployment_id)
        self._audit(
            "fleet_deployment_emergency_stop_changed",
            identity.subject,
            result,
            identity.organization_id,
        )
        return result

    def set_agent_emergency_stop(
        self, identity: FleetIdentity, *, deployment_id: str, agent_id: str, active: bool
    ) -> dict[str, Any]:
        """Stop or release one agent without revoking its enrollment session."""
        if not isinstance(active, bool):
            raise FleetConfigurationError("emergency stop state must be boolean")
        deployment_id, agent_id = _text(deployment_id, "deploymentId"), _text(agent_id, "agentId")
        with self._lock:
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, agent["organizationId"], agent["projectId"])
            self._connection.execute(
                "INSERT INTO agent_controls(deployment_id,agent_id,emergency_stop,updated_at) "
                "VALUES(?,?,?,?) ON CONFLICT(deployment_id,agent_id) DO UPDATE SET "
                "emergency_stop=excluded.emergency_stop,updated_at=excluded.updated_at",
                (deployment_id, agent_id, int(active), self._now()),
            )
            self._connection.commit()
            result = self._agent(deployment_id, agent_id)
        self._audit(
            "fleet_agent_emergency_stop_changed",
            identity.subject,
            result,
            identity.organization_id,
        )
        return result

    def set_group_emergency_stop(
        self, identity: FleetIdentity, *, group_id: str, active: bool
    ) -> dict[str, Any]:
        """Stop or release all agents assigned to one tenant-scoped group."""
        if not isinstance(active, bool):
            raise FleetConfigurationError("emergency stop state must be boolean")
        group_id = _text(group_id, "groupId")
        with self._lock:
            group = self._group(group_id)
            self._assert_identity_org(identity, group["organizationId"])
            self._connection.execute(
                "INSERT INTO group_controls(group_id,emergency_stop,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(group_id) DO UPDATE SET emergency_stop=excluded.emergency_stop,"
                "updated_at=excluded.updated_at",
                (group_id, int(active), self._now()),
            )
            self._connection.commit()
            result = self._group(group_id)
        self._audit(
            "fleet_group_emergency_stop_changed",
            identity.subject,
            {"groupId": group_id, "emergencyStop": active, "agentCount": len(result["agents"])},
            identity.organization_id,
        )
        return result

    def health(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return deployment health and bounded operational SLO indicators."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM deployments WHERE organization_id=? ORDER BY id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(
                self._deployment_health(row["id"])
                for row in rows
                if not identity.project_ids
                or identity.project_ids & {self._deployment(row["id"])["projectId"]}
            )
        return _paginate(items, cursor, limit)

    def record_slo_sample(self, identity: FleetIdentity, deployment_id: str) -> dict[str, Any]:
        """Persist a redaction-safe health sample for one authorized deployment.

        Samples are explicit rather than hidden inside ``health`` reads so a
        scheduler or telemetry adapter controls sampling frequency and the
        read path remains side-effect free.
        """
        deployment = self._deployment(_text(deployment_id, "deploymentId"))
        self._assert_identity_scope(identity, deployment["organizationId"], deployment["projectId"])
        with self._lock:
            sample = self._deployment_health(deployment_id)
            observed_at = self._now()
            self._connection.execute(
                "INSERT INTO fleet_health_samples(deployment_id,observed_at,status,"
                "connected_agents,offline_agents,drifted,emergency_stop) VALUES(?,?,?,?,?,?,?)",
                (
                    deployment_id,
                    observed_at,
                    sample["status"],
                    sample["connectedAgents"],
                    sample["offlineAgents"],
                    int(sample["drifted"]),
                    int(sample["emergencyStop"]),
                ),
            )
            self._connection.commit()
        result = {"deploymentId": deployment_id, "observedAt": observed_at, **sample}
        self._audit(
            "fleet_health_sample_recorded", identity.subject, result, identity.organization_id
        )
        return result

    def slo(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return bounded sample-based availability for each visible deployment."""
        cutoff = self._now() - self.slo_window_seconds
        with self._lock:
            rows = self._connection.execute(
                "SELECT d.id,d.project_id,COUNT(s.observed_at) AS samples,"
                "SUM(CASE WHEN s.status='healthy' THEN 1 ELSE 0 END) AS healthy_samples "
                "FROM deployments d LEFT JOIN fleet_health_samples s "
                "ON s.deployment_id=d.id AND s.observed_at>=? "
                "WHERE d.organization_id=? GROUP BY d.id,d.project_id ORDER BY d.id",
                (cutoff, identity.organization_id),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            if identity.project_ids and row["project_id"] not in identity.project_ids:
                continue
            samples = int(row["samples"])
            healthy = int(row["healthy_samples"] or 0)
            availability = healthy / samples if samples else None
            items.append(
                {
                    "deploymentId": row["id"],
                    "windowSeconds": self.slo_window_seconds,
                    "sampleCount": samples,
                    "healthySamples": healthy,
                    "availability": availability,
                    "target": self.slo_target,
                    "status": (
                        "no_data"
                        if availability is None
                        else "meeting"
                        if availability >= self.slo_target
                        else "breach"
                    ),
                }
            )
        return _paginate(items, cursor, limit)

    def compliance_evidence(self, identity: FleetIdentity) -> dict[str, Any]:
        """Build a redacted tenant-scoped evidence summary for review/export.

        The bundle contains identifiers, hashes, states, counts, and audit
        metadata only. It intentionally excludes desired configuration values,
        credentials, opaque sessions, and raw audit payloads.
        """
        inventory = _collect_pages(
            lambda cursor: self.list_inventory(identity, "deployments", cursor=cursor)
        )
        configurations = {
            item["deploymentId"]: item
            for item in _collect_pages(
                lambda cursor: self.list_configurations(identity, cursor=cursor)
            )
        }
        health = {
            item["deploymentId"]: item
            for item in _collect_pages(lambda cursor: self.health(identity, cursor=cursor))
        }
        slo = {
            item["deploymentId"]: item
            for item in _collect_pages(lambda cursor: self.slo(identity, cursor=cursor))
        }
        with self._lock:
            audit_rows = self._connection.execute(
                "SELECT event_type,COUNT(*) AS count,MAX(occurred_at) AS last_occurred "
                "FROM fleet_audit_evidence WHERE organization_id=? GROUP BY event_type "
                "ORDER BY event_type",
                (identity.organization_id,),
            ).fetchall()
            sessions = self._connection.execute(
                "SELECT COUNT(*) AS count FROM agent_sessions s JOIN agents a "
                "ON a.id=s.agent_id AND a.deployment_id=s.deployment_id "
                "WHERE a.organization_id=? AND s.expires_at>?",
                (identity.organization_id, self._now()),
            ).fetchone()["count"]
        deployments: list[dict[str, Any]] = []
        for deployment in inventory:
            if identity.project_ids and deployment["project_id"] not in identity.project_ids:
                continue
            deployment_id = deployment["id"]
            config = configurations.get(deployment_id)
            deployments.append(
                {
                    "id": deployment_id,
                    "projectId": deployment["project_id"],
                    "team": deployment["team"],
                    "environment": deployment["environment"],
                    "region": deployment["region"],
                    "sdkVersion": deployment["sdk_version"],
                    "configuration": (
                        {
                            "templateId": config["templateId"],
                            "desiredHash": config["desiredHash"],
                            "appliedHash": config["appliedHash"],
                            "version": config["version"],
                            "rolloutState": config["rolloutState"],
                            "rolloutPercentage": config["rolloutPercentage"],
                        }
                        if config
                        else None
                    ),
                    "health": health.get(deployment_id),
                    "slo": slo.get(deployment_id),
                }
            )
        return {
            "schemaVersion": 1,
            "organizationId": identity.organization_id,
            "generatedAt": self._now(),
            "activeSessionCount": int(sessions),
            "deploymentCount": len(deployments),
            "deployments": deployments,
            "audit": [dict(row) for row in audit_rows],
            "redaction": {
                "configurationValuesIncluded": False,
                "sessionTokensIncluded": False,
                "credentialMaterialIncluded": False,
                "rawAuditPayloadsIncluded": False,
            },
        }

    def audit_evidence(
        self,
        identity: FleetIdentity,
        *,
        cursor: str | None = None,
        limit: int = 200,
        event_type: str | None = None,
    ) -> FleetPage:
        """Return bounded, redaction-safe lifecycle evidence for investigations.

        Raw audit payloads and credential material remain in the deployment's
        immutable audit sink. This endpoint exposes only the evidence index
        needed to scope an investigation and correlate an external record.
        """
        query = (
            "SELECT event_type,actor,deployment_id,payload_hash,occurred_at "
            "FROM fleet_audit_evidence WHERE organization_id=?"
        )
        values: list[Any] = [identity.organization_id]
        if event_type:
            query += " AND event_type=?"
            values.append(_text(event_type, "eventType"))
        query += " ORDER BY occurred_at DESC, rowid DESC"
        with self._lock:
            rows = self._connection.execute(query, values).fetchall()
        items = tuple(
            {
                "eventType": row["event_type"],
                "actor": row["actor"],
                "deploymentId": row["deployment_id"],
                "payloadHash": row["payload_hash"],
                "occurredAt": row["occurred_at"],
            }
            for row in rows
        )
        return _paginate(items, cursor, limit)

    def alerts(
        self, identity: FleetIdentity, *, cursor: str | None = None, limit: int = 200
    ) -> FleetPage:
        """Return deterministic alerts derived from authoritative fleet state."""
        alerts: list[dict[str, Any]] = []
        for health in _collect_pages(lambda cursor: self.health(identity, cursor=cursor)):
            deployment_id = health["deploymentId"]
            if health["emergencyStop"]:
                alerts.append(
                    {
                        "id": f"stop:{deployment_id}",
                        "severity": "critical",
                        "type": "emergency_stop",
                        "deploymentId": deployment_id,
                        "message": "Deployment emergency stop is active",
                    }
                )
            if health["drifted"]:
                alerts.append(
                    {
                        "id": f"drift:{deployment_id}",
                        "severity": "high",
                        "type": "configuration_drift",
                        "deploymentId": deployment_id,
                        "message": "Applied configuration differs from desired state",
                    }
                )
            if health["offlineAgents"] > 0:
                alerts.append(
                    {
                        "id": f"offline:{deployment_id}",
                        "severity": "medium",
                        "type": "agent_offline",
                        "deploymentId": deployment_id,
                        "message": f"{health['offlineAgents']} agent(s) are offline",
                    }
                )
        with self._lock:
            acknowledged = {
                row["alert_id"]
                for row in self._connection.execute(
                    "SELECT alert_id FROM fleet_alert_acknowledgements WHERE organization_id=?",
                    (identity.organization_id,),
                ).fetchall()
            }
        for alert in alerts:
            alert["acknowledged"] = alert["id"] in acknowledged
        return _paginate(alerts, cursor, limit)

    def acknowledge_alert(self, identity: FleetIdentity, alert_id: str) -> dict[str, Any]:
        """Acknowledge one current alert without deleting or hiding its evidence."""
        alert_id = _text(alert_id, "alertId")
        current = {
            item["id"]: item
            for item in _collect_pages(lambda cursor: self.alerts(identity, cursor=cursor))
        }
        if alert_id not in current:
            raise FleetNotFoundError("fleet alert not found")
        with self._lock:
            self._connection.execute(
                "INSERT INTO fleet_alert_acknowledgements"
                "(organization_id,alert_id,subject,acknowledged_at) VALUES(?,?,?,?) "
                "ON CONFLICT(organization_id,alert_id) DO UPDATE SET subject=excluded.subject,"
                "acknowledged_at=excluded.acknowledged_at",
                (identity.organization_id, alert_id, identity.subject, self._now()),
            )
            self._connection.commit()
        result = {**current[alert_id], "acknowledged": True, "acknowledgedBy": identity.subject}
        self._audit("fleet_alert_acknowledged", identity.subject, result, identity.organization_id)
        return result

    def dispatch_alerts(self, identity: FleetIdentity) -> FleetPage:
        """Deliver current unacknowledged alerts through the injected alert adapter."""
        if self.alert_sink is None:
            raise FleetConfigurationError("no fleet alert sink is configured")
        delivered: list[dict[str, Any]] = []
        for alert in _collect_pages(lambda cursor: self.alerts(identity, cursor=cursor)):
            if alert["acknowledged"]:
                continue
            redacted = dict(alert)
            try:
                self.alert_sink.publish(redacted)
            except Exception as exc:
                raise FleetConfigurationError("fleet alert delivery failed") from exc
            delivered.append({**redacted, "delivered": True})
        self._audit(
            "fleet_alerts_dispatched",
            identity.subject,
            {"count": len(delivered)},
            identity.organization_id,
        )
        return FleetPage(tuple(delivered), None)

    def register_agent(
        self,
        identity: FleetIdentity,
        *,
        deployment_id: str,
        agent_id: str,
        host: str,
        project_root: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Bind one authenticated agent process to a deployment and issue a session."""
        values = tuple(
            _text(value, label)
            for value, label in (
                (deployment_id, "deploymentId"),
                (agent_id, "agentId"),
                (host, "host"),
                (project_root, "projectRoot"),
            )
        )
        metadata_json = _json_object(metadata, "metadata")
        with self._lock:
            deployment = self._deployment(values[0])
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            self._assert_agent_identity(identity, values[1])
            now = float(self._now())
            expires = now + self.heartbeat_ttl_seconds
            session_id = secrets.token_urlsafe(32)
            self._connection.execute(
                """INSERT INTO agents
                (id,organization_id,project_id,deployment_id,host,project_root,environment,region,
                 status,last_heartbeat,expires_at,metadata)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(deployment_id,id) DO UPDATE SET
                host=excluded.host,project_root=excluded.project_root,status='connected',
                last_heartbeat=excluded.last_heartbeat,expires_at=excluded.expires_at,
                metadata=excluded.metadata""",
                (
                    values[1],
                    deployment["organizationId"],
                    deployment["projectId"],
                    values[0],
                    values[2],
                    values[3],
                    deployment["environment"],
                    deployment["region"],
                    "connected",
                    now,
                    expires,
                    metadata_json,
                ),
            )
            self._connection.execute(
                "INSERT INTO agent_sessions(agent_id,deployment_id,session_id,created_at,"
                "expires_at)"
                " VALUES(?,?,?,?,?)",
                (values[1], values[0], session_id, now, expires),
            )
            self._connection.commit()
            result = self._agent(values[0], values[1])
        self._audit("fleet_agent_registered", identity.subject, result, identity.organization_id)
        result["sessionId"] = session_id
        return result

    def heartbeat(
        self,
        identity: FleetIdentity,
        deployment_id: str,
        agent_id: str,
        session_id: str,
        telemetry: Mapping[str, int | float] | None = None,
        managed_configuration: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Refresh a session and persist bounded telemetry and managed evidence."""
        deployment_id, agent_id, session_id = (
            _text(deployment_id, "deploymentId"),
            _text(agent_id, "agentId"),
            _text(session_id, "sessionId"),
        )
        with self._lock:
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, agent["organizationId"], agent["projectId"])
            self._assert_agent_identity(identity, agent_id)
            row = self._connection.execute(
                "SELECT session_id,expires_at FROM agent_sessions "
                "WHERE deployment_id=? AND agent_id=?"
                " AND session_id=? AND expires_at>?",
                (deployment_id, agent_id, session_id, self._now()),
            ).fetchone()
            if row is None or not hmac.compare_digest(row["session_id"], session_id):
                raise FleetAuthorizationError("agent session is invalid or expired")
            now = float(self._now())
            expires = now + self.heartbeat_ttl_seconds
            metadata_row = self._connection.execute(
                "SELECT metadata FROM agents WHERE deployment_id=? AND id=?",
                (deployment_id, agent_id),
            ).fetchone()
            metadata: dict[str, Any] = {}
            if metadata_row is not None:
                try:
                    stored = json.loads(metadata_row["metadata"] or "{}")
                    if isinstance(stored, Mapping):
                        metadata = dict(stored)
                except (TypeError, ValueError):
                    metadata = {}
            if telemetry is not None:
                metadata["telemetry"] = _normalize_agent_telemetry(telemetry)
            if managed_configuration is not None:
                metadata["managedConfiguration"] = _normalize_managed_configuration_report(
                    managed_configuration
                )
            metadata_json = _json_object(metadata, "metadata")
            self._connection.execute(
                "UPDATE agents SET status='connected',last_heartbeat=?,expires_at=?,metadata=? "
                "WHERE deployment_id=? AND id=?",
                (now, expires, metadata_json, deployment_id, agent_id),
            )
            self._connection.execute(
                "UPDATE agent_sessions SET expires_at=? WHERE deployment_id=? "
                "AND agent_id=? AND session_id=?",
                (expires, deployment_id, agent_id, session_id),
            )
            self._connection.commit()
            result = self._agent(deployment_id, agent_id)
        self._audit("fleet_agent_heartbeat", identity.subject, result, identity.organization_id)
        return result

    def disconnect(
        self, identity: FleetIdentity, deployment_id: str, agent_id: str, session_id: str
    ) -> dict[str, Any]:
        """Mark an agent offline after validating its current opaque session."""
        self.heartbeat(identity, deployment_id, agent_id, session_id)
        with self._lock:
            self._connection.execute(
                "UPDATE agents SET status='offline' WHERE deployment_id=? AND id=?",
                (deployment_id, agent_id),
            )
            self._connection.commit()
            result = self._agent(deployment_id, agent_id)
        self._audit("fleet_agent_disconnected", identity.subject, result, identity.organization_id)
        return result

    def _migrate(self) -> None:
        """Apply idempotent schema migrations before the store serves traffic."""
        with self._lock:
            self._connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS organizations(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS projects(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, created_at REAL NOT NULL,
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS deployments(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL,
                    environment TEXT NOT NULL, region TEXT NOT NULL, sdk_version TEXT,
                    team TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL, UNIQUE(project_id,name));
                CREATE TABLE IF NOT EXISTS agents(
                    id TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    project_id TEXT NOT NULL REFERENCES projects(id), deployment_id TEXT NOT NULL
                    REFERENCES deployments(id), host TEXT NOT NULL, project_root TEXT NOT NULL,
                    environment TEXT NOT NULL, region TEXT NOT NULL, status TEXT NOT NULL,
                    last_heartbeat REAL NOT NULL, expires_at REAL NOT NULL, metadata TEXT NOT NULL,
                    PRIMARY KEY(deployment_id,id));
                CREATE TABLE IF NOT EXISTS agent_sessions(
                    agent_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
                    session_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS templates(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, parent_id TEXT REFERENCES templates(id),
                    configuration TEXT NOT NULL, version INTEGER NOT NULL, created_at REAL NOT NULL,
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS policies(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, configuration TEXT NOT NULL, version INTEGER NOT NULL,
                    created_at REAL NOT NULL, created_by TEXT NOT NULL DEFAULT 'system',
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS policy_versions(
                    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    version INTEGER NOT NULL, base_version INTEGER NOT NULL,
                    name TEXT NOT NULL, configuration TEXT NOT NULL,
                    content_hash TEXT NOT NULL, state TEXT NOT NULL,
                    author TEXT NOT NULL, created_at REAL NOT NULL,
                    submitted_by TEXT, submitted_at REAL,
                    decided_by TEXT, decided_at REAL, decision_reason TEXT,
                    staged_by TEXT, staged_at REAL,
                    activated_by TEXT, activated_at REAL,
                    PRIMARY KEY(policy_id,version));
                CREATE INDEX IF NOT EXISTS idx_policy_versions_org_state
                    ON policy_versions(organization_id,state,created_at);
                CREATE TABLE IF NOT EXISTS skills(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, description TEXT NOT NULL, version TEXT NOT NULL,
                    content TEXT NOT NULL, digest TEXT NOT NULL, enabled INTEGER NOT NULL,
                    created_at REAL NOT NULL, created_by TEXT NOT NULL DEFAULT 'system',
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS mcp_servers(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, description TEXT NOT NULL, version TEXT NOT NULL,
                    transport TEXT NOT NULL, command TEXT, args TEXT, url TEXT,
                    environment_references TEXT NOT NULL, enabled INTEGER NOT NULL,
                    created_at REAL NOT NULL, created_by TEXT NOT NULL DEFAULT 'system',
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS agent_groups(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, policy_id TEXT NOT NULL REFERENCES policies(id),
                    created_at REAL NOT NULL, UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS agent_group_members(
                    group_id TEXT NOT NULL REFERENCES agent_groups(id) ON DELETE CASCADE,
                    deployment_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    PRIMARY KEY(group_id,deployment_id,agent_id),
                    FOREIGN KEY(deployment_id,agent_id) REFERENCES agents(deployment_id,id)
                        ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS deployment_configs(
                    deployment_id TEXT PRIMARY KEY REFERENCES deployments(id),
                    template_id TEXT NOT NULL REFERENCES templates(id),
                    desired_configuration TEXT NOT NULL, desired_hash TEXT NOT NULL,
                    applied_hash TEXT, rollout_state TEXT NOT NULL,
                    rollout_percentage INTEGER NOT NULL, version INTEGER NOT NULL,
                    updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS deployment_managed_packages(
                    deployment_id TEXT PRIMARY KEY REFERENCES deployments(id),
                    revision INTEGER NOT NULL, package_base64 TEXT NOT NULL,
                    package_sha256 TEXT NOT NULL, bundle_hash TEXT NOT NULL,
                    host TEXT NOT NULL, host_version TEXT NOT NULL, platform TEXT NOT NULL,
                    policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL,
                    published_at REAL NOT NULL, published_by TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS deployment_controls(
                    deployment_id TEXT PRIMARY KEY REFERENCES deployments(id),
                    emergency_stop INTEGER NOT NULL, updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS group_controls(
                    group_id TEXT PRIMARY KEY REFERENCES agent_groups(id) ON DELETE CASCADE,
                    emergency_stop INTEGER NOT NULL, updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS agent_controls(
                    deployment_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    emergency_stop INTEGER NOT NULL, updated_at REAL NOT NULL,
                    PRIMARY KEY(deployment_id,agent_id),
                    FOREIGN KEY(deployment_id,agent_id) REFERENCES agents(deployment_id,id)
                        ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS deployment_config_history(
                    deployment_id TEXT NOT NULL REFERENCES deployments(id),
                    version INTEGER NOT NULL, template_id TEXT NOT NULL,
                    desired_configuration TEXT NOT NULL, desired_hash TEXT NOT NULL,
                    applied_hash TEXT, rollout_state TEXT NOT NULL,
                    rollout_percentage INTEGER NOT NULL, created_at REAL NOT NULL,
                    PRIMARY KEY(deployment_id,version));
                CREATE TABLE IF NOT EXISTS fleet_alert_acknowledgements(
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    alert_id TEXT NOT NULL, subject TEXT NOT NULL,
                    acknowledged_at REAL NOT NULL,
                    PRIMARY KEY(organization_id,alert_id));
                CREATE TABLE IF NOT EXISTS fleet_health_samples(
                    deployment_id TEXT NOT NULL REFERENCES deployments(id),
                    observed_at REAL NOT NULL, status TEXT NOT NULL,
                    connected_agents INTEGER NOT NULL, offline_agents INTEGER NOT NULL,
                    drifted INTEGER NOT NULL, emergency_stop INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_fleet_health_samples_window
                    ON fleet_health_samples(deployment_id,observed_at);
                CREATE TABLE IF NOT EXISTS fleet_audit_evidence(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    event_type TEXT NOT NULL, actor TEXT NOT NULL,
                    deployment_id TEXT, payload_hash TEXT NOT NULL,
                    occurred_at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_fleet_audit_evidence_org
                    ON fleet_audit_evidence(organization_id,occurred_at);
                INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);
                INSERT OR IGNORE INTO schema_migrations(version) VALUES(5);
                INSERT OR IGNORE INTO schema_migrations(version) VALUES(6);
                INSERT OR IGNORE INTO schema_migrations(version) VALUES(7);
                """
            )
            deployment_columns = {
                row["name"] for row in self._connection.execute("PRAGMA table_info(deployments)")
            }
            if "team" not in deployment_columns:
                self._connection.execute(
                    "ALTER TABLE deployments ADD COLUMN team TEXT NOT NULL DEFAULT ''"
                )
            policy_columns = {
                row["name"] for row in self._connection.execute("PRAGMA table_info(policies)")
            }
            if "created_by" not in policy_columns:
                self._connection.execute(
                    "ALTER TABLE policies ADD COLUMN created_by TEXT NOT NULL DEFAULT 'system'"
                )
            existing_policies = self._connection.execute(
                "SELECT id,organization_id,name,configuration,version,created_at,created_by "
                "FROM policies WHERE version > 0"
            ).fetchall()
            for policy in existing_policies:
                configuration_json = policy["configuration"]
                self._connection.execute(
                    "INSERT OR IGNORE INTO policy_versions(policy_id,organization_id,version,"
                    "base_version,name,configuration,content_hash,state,author,created_at,"
                    "activated_by,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        policy["id"],
                        policy["organization_id"],
                        policy["version"],
                        max(0, int(policy["version"]) - 1),
                        policy["name"],
                        configuration_json,
                        hashlib.sha256(configuration_json.encode()).hexdigest(),
                        "active",
                        policy["created_by"],
                        policy["created_at"],
                        policy["created_by"],
                        policy["created_at"],
                    ),
                )
            self._connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(2)")
            self._connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(3)")
            self._connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(4)")
            self._connection.commit()

    @staticmethod
    def _configuration_json(configuration: Mapping[str, Any]) -> str:
        """Validate a bounded configuration and reject secret-bearing fields."""
        secret_names = {
            "token",
            "secret",
            "password",
            "privatekey",
            "private_key",
            "clientsecret",
            "access_token",
            "refresh_token",
            "authorization",
        }

        def visit(value: Any, depth: int = 0) -> Any:
            if depth > 8:
                raise FleetConfigurationError("configuration nesting is too deep")
            if isinstance(value, Mapping):
                result: dict[str, Any] = {}
                for key, item in value.items():
                    key_text = _text(key, "configuration key")
                    if key_text.lower().replace("-", "_") in secret_names:
                        raise FleetConfigurationError("configuration must not contain secrets")
                    result[key_text] = visit(item, depth + 1)
                return result
            if isinstance(value, list):
                if len(value) > 10_000:
                    raise FleetConfigurationError("configuration list is too large")
                return [visit(item, depth + 1) for item in value]
            if value is None or isinstance(value, (str, int, float, bool)):
                return value
            raise FleetConfigurationError("configuration contains unsupported data")

        normalized = visit(validate_fleet_configuration(configuration))
        if not isinstance(normalized, dict):
            raise FleetConfigurationError("configuration must be an object")
        serialized = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if len(serialized) > 1_000_000:
            raise FleetConfigurationError("configuration is too large")
        return serialized

    @staticmethod
    def _configuration_hash(configuration: Mapping[str, Any]) -> str:
        """Create a stable content hash for desired/applied drift comparison."""
        serialized = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(serialized).hexdigest()

    def _template(self, template_id: str) -> dict[str, Any]:
        """Load a template without exposing raw bearer or credential material."""
        row = self._connection.execute(
            "SELECT id,organization_id,name,parent_id,configuration,version,created_at "
            "FROM templates WHERE id=?",
            (template_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("template not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "name": row["name"],
            "parentId": row["parent_id"],
            "configuration": json.loads(row["configuration"]),
            "version": row["version"],
            "createdAt": row["created_at"],
        }

    def _insert_policy_version(
        self,
        *,
        policy_id: str,
        organization_id: str,
        version: int,
        base_version: int,
        name: str,
        configuration_json: str,
        state: str,
        author: str,
        created_at: float,
    ) -> None:
        """Insert one content-hashed policy ledger entry inside the caller's transaction."""
        if state not in _POLICY_VERSION_STATES:
            raise FleetConfigurationError("policy version state is invalid")
        self._connection.execute(
            "INSERT INTO policy_versions(policy_id,organization_id,version,base_version,name,"
            "configuration,content_hash,state,author,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                policy_id,
                organization_id,
                version,
                base_version,
                name,
                configuration_json,
                hashlib.sha256(configuration_json.encode()).hexdigest(),
                state,
                author,
                created_at,
            ),
        )

    def _transition_policy_version(
        self,
        identity: FleetIdentity,
        policy_id: str,
        version: int,
        *,
        expected_state: str,
        next_state: str,
        fields: Mapping[str, Any],
        event: str,
    ) -> dict[str, Any]:
        """Apply one compare-and-swap lifecycle transition and audit its actor."""
        policy_id, version = _text(policy_id, "policyId"), _positive_version(version)
        if expected_state not in _POLICY_VERSION_STATES or next_state not in _POLICY_VERSION_STATES:
            raise FleetConfigurationError("policy transition is invalid")
        # Keep transition SQL static. Even though callers are internal, lifecycle
        # metadata must never be able to influence SQL syntax at this trust boundary.
        if set(fields) == {"submitted_by", "submitted_at"}:
            statement = (
                "UPDATE policy_versions SET state=?,submitted_by=?,submitted_at=? "
                "WHERE policy_id=? AND version=? AND state=?"
            )
            metadata = (fields["submitted_by"], fields["submitted_at"])
        elif set(fields) == {"staged_by", "staged_at"}:
            statement = (
                "UPDATE policy_versions SET state=?,staged_by=?,staged_at=? "
                "WHERE policy_id=? AND version=? AND state=?"
            )
            metadata = (fields["staged_by"], fields["staged_at"])
        else:
            raise FleetConfigurationError("policy transition metadata is invalid")
        with self._lock:
            current = self._policy_version(policy_id, version)
            if current["organizationId"] != identity.organization_id:
                raise FleetAuthorizationError("organization scope is not permitted")
            changed = self._connection.execute(
                statement,
                (next_state, *metadata, policy_id, version, expected_state),
            )
            if changed.rowcount != 1:
                self._connection.rollback()
                raise FleetConflictError(
                    f"policy version must be {expected_state} before it can become {next_state}"
                )
            self._connection.commit()
            result = self._policy_version(policy_id, version)
        self._audit(event, identity.subject, result, identity.organization_id)
        return result

    def _policy_version(self, policy_id: str, version: int) -> dict[str, Any]:
        """Load one immutable-numbered policy ledger entry with safe review metadata."""
        row = self._connection.execute(
            "SELECT policy_id,organization_id,version,base_version,name,configuration,"
            "content_hash,state,author,created_at,submitted_by,submitted_at,decided_by,"
            "decided_at,decision_reason,staged_by,staged_at,activated_by,activated_at "
            "FROM policy_versions WHERE policy_id=? AND version=?",
            (policy_id, version),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("policy version not found")
        configuration = json.loads(row["configuration"])
        base_configuration: dict[str, Any] = {}
        if int(row["base_version"]) > 0:
            base = self._connection.execute(
                "SELECT configuration FROM policy_versions WHERE policy_id=? AND version=?",
                (policy_id, row["base_version"]),
            ).fetchone()
            if base is not None:
                base_configuration = json.loads(base["configuration"])
        changed_sections = sorted(set(configuration) | set(base_configuration))
        changed_sections = [
            section
            for section in changed_sections
            if configuration.get(section) != base_configuration.get(section)
        ]
        state = row["state"]
        return {
            "policyId": row["policy_id"],
            "organizationId": row["organization_id"],
            "version": row["version"],
            "baseVersion": row["base_version"],
            "name": row["name"],
            "configuration": configuration,
            "contentHash": row["content_hash"],
            "state": state,
            "author": row["author"],
            "createdAt": row["created_at"],
            "submittedBy": row["submitted_by"],
            "submittedAt": row["submitted_at"],
            "decidedBy": row["decided_by"],
            "decidedAt": row["decided_at"],
            "decisionReason": row["decision_reason"],
            "approvedBy": row["decided_by"]
            if state in {"approved", "staged", "active", "retired"}
            else None,
            "stagedBy": row["staged_by"],
            "stagedAt": row["staged_at"],
            "activatedBy": row["activated_by"],
            "activatedAt": row["activated_at"],
            "changeSummary": {"changedSections": changed_sections},
        }

    def _policy(self, policy_id: str) -> dict[str, Any]:
        """Load one policy without exposing credentials or bearer material."""
        row = self._connection.execute(
            "SELECT id,organization_id,name,configuration,version,created_at,created_by "
            "FROM policies WHERE id=?",
            (policy_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("policy not found")
        latest_row = self._connection.execute(
            "SELECT version,state,author,created_at FROM policy_versions WHERE policy_id=? "
            "ORDER BY version DESC LIMIT 1",
            (policy_id,),
        ).fetchone()
        active_configuration = json.loads(row["configuration"])
        if int(row["version"]) == 0 and latest_row is not None:
            latest_version = self._policy_version(policy_id, int(latest_row["version"]))
            active_configuration = latest_version["configuration"]
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "name": row["name"],
            "configuration": active_configuration,
            "version": row["version"],
            "activeVersion": row["version"] if int(row["version"]) > 0 else None,
            "latestVersion": latest_row["version"] if latest_row is not None else row["version"],
            "governanceState": latest_row["state"] if latest_row is not None else "active",
            "pendingVersion": (
                latest_row["version"]
                if latest_row is not None and latest_row["state"] in _POLICY_PENDING_STATES
                else None
            ),
            "pendingAuthor": latest_row["author"] if latest_row is not None else None,
            "createdAt": row["created_at"],
            "author": row["created_by"],
            "updatedAt": latest_row["created_at"] if latest_row is not None else row["created_at"],
        }

    def _skill(self, skill_id: str) -> dict[str, Any]:
        """Load one Skill and preserve its content digest for deployment verification."""
        row = self._connection.execute(
            "SELECT id,organization_id,name,description,version,content,digest,enabled,"
            "created_at,created_by FROM skills WHERE id=?",
            (skill_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("skill not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "name": row["name"],
            "description": row["description"],
            "version": row["version"],
            "content": row["content"],
            "digest": row["digest"],
            "enabled": bool(row["enabled"]),
            "createdAt": row["created_at"],
            "author": row["created_by"],
        }

    def _mcp_server(self, server_id: str) -> dict[str, Any]:
        """Load one MCP definition without resolving deployment-owned secrets."""
        row = self._connection.execute(
            "SELECT id,organization_id,name,description,version,transport,command,args,"
            "url,environment_references,enabled,created_at,created_by FROM mcp_servers WHERE id=?",
            (server_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("MCP server not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "name": row["name"],
            "description": row["description"],
            "version": row["version"],
            "transport": row["transport"],
            "command": row["command"],
            "args": json.loads(row["args"] or "[]"),
            "url": row["url"],
            "environmentReferences": json.loads(row["environment_references"]),
            "enabled": bool(row["enabled"]),
            "createdAt": row["created_at"],
            "author": row["created_by"],
        }

    def _group(self, group_id: str) -> dict[str, Any]:
        """Load one group and its non-secret enrolled agent summaries."""
        row = self._connection.execute(
            "SELECT id,organization_id,name,policy_id,created_at FROM agent_groups WHERE id=?",
            (group_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("group not found")
        members = self._connection.execute(
            "SELECT a.id,a.organization_id,a.project_id,a.deployment_id,a.host,a.project_root,"
            "a.environment,a.region,a.status,a.last_heartbeat,a.expires_at,a.metadata "
            "FROM agent_group_members m JOIN agents a ON a.deployment_id=m.deployment_id "
            "AND a.id=m.agent_id WHERE m.group_id=? ORDER BY a.id",
            (group_id,),
        ).fetchall()
        policy = self._policy(row["policy_id"])
        control = self._connection.execute(
            "SELECT emergency_stop FROM group_controls WHERE group_id=?", (group_id,)
        ).fetchone()
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "name": row["name"],
            "policyId": row["policy_id"],
            "policyName": policy["name"],
            "createdAt": row["created_at"],
            "emergencyStop": bool(control is not None and control["emergency_stop"]),
            "agents": [_agent_inventory_projection(member) for member in members],
        }

    def _effective_template(self, template_id: str) -> dict[str, Any]:
        """Resolve bounded parent inheritance and merge child values over parents."""
        chain: list[dict[str, Any]] = []
        current = template_id
        while current:
            if len(chain) >= 8 or current in {item["id"] for item in chain}:
                raise FleetConfigurationError("template inheritance is cyclic or too deep")
            template = self._template(current)
            chain.append(template)
            current = template["parentId"]
        configuration: dict[str, Any] = {}
        for template in reversed(chain):
            configuration = self._merge_configuration(configuration, template["configuration"])
        result = self._template(template_id)
        result["configuration"] = configuration
        return result

    @staticmethod
    def _merge_configuration(base: Mapping[str, Any], child: Mapping[str, Any]) -> dict[str, Any]:
        """Deep-merge JSON objects while treating lists as explicit replacements."""
        merged = dict(base)
        for key, value in child.items():
            if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
                merged[key] = EnterpriseFleetStore._merge_configuration(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _assert_no_template_cycle(self, parent_id: str, child_id: str) -> None:
        """Reject a new parent link that would create a cycle."""
        current = parent_id
        for _ in range(8):
            if current == child_id:
                raise FleetConfigurationError("template inheritance is cyclic")
            parent = self._template(current)
            current = parent["parentId"]
            if current is None:
                return
        raise FleetConfigurationError("template inheritance is too deep")

    def _deployment_configuration(self, deployment_id: str) -> dict[str, Any]:
        """Return desired/applied rollout state for one deployment."""
        row = self._connection.execute(
            "SELECT deployment_id,template_id,desired_configuration,desired_hash,applied_hash,"
            "rollout_state,rollout_percentage,version,updated_at FROM deployment_configs "
            "WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("deployment configuration not found")
        return {
            "deploymentId": row["deployment_id"],
            "templateId": row["template_id"],
            "desiredConfiguration": json.loads(row["desired_configuration"]),
            "desiredHash": row["desired_hash"],
            "appliedHash": row["applied_hash"],
            "drifted": row["applied_hash"] != row["desired_hash"],
            "rolloutState": row["rollout_state"],
            "rolloutPercentage": row["rollout_percentage"],
            "version": row["version"],
            "updatedAt": row["updated_at"],
        }

    def _desired_managed_host(self, deployment_id: str) -> dict[str, Any]:
        """Return the server-owned managed-host target or fail closed."""
        configuration = self._require_configuration(deployment_id)["desiredConfiguration"]
        candidate = configuration.get("managedHost") if isinstance(configuration, Mapping) else None
        if not isinstance(candidate, Mapping):
            raise FleetConfigurationError("deployment has no managed-host desired state")
        return _normalize_managed_host(candidate)

    @staticmethod
    def _require_package_matches_desired(
        package: ManagedDeploymentPackage, desired: Mapping[str, Any]
    ) -> None:
        """Bind every package target field to current server-owned desired state."""
        actual = {
            "host": package.host.value,
            "hostVersion": package.host_version,
            "platform": package.platform.value,
            "bundleHash": package.bundle_hash,
            "policyId": package.policy_id,
            "policyVersion": package.policy_version,
        }
        if actual != dict(desired):
            raise FleetConfigurationError("managed package does not match deployment desired state")

    def _managed_deployment_package_metadata(self, deployment_id: str) -> dict[str, Any]:
        """Load package metadata and derive current/stale state live."""
        row = self._connection.execute(
            "SELECT revision,package_sha256,bundle_hash,host,host_version,platform,policy_id,"
            "policy_version,published_at,published_by FROM deployment_managed_packages "
            "WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("managed deployment package not found")
        desired = self._desired_managed_host(deployment_id)
        package_target = {
            "host": row["host"],
            "hostVersion": row["host_version"],
            "platform": row["platform"],
            "bundleHash": row["bundle_hash"],
            "policyId": row["policy_id"],
            "policyVersion": row["policy_version"],
        }
        return {
            "revision": row["revision"],
            "status": "current" if package_target == desired else "stale",
            "packageSha256": row["package_sha256"],
            "bundleHash": row["bundle_hash"],
            "host": row["host"],
            "hostVersion": row["host_version"],
            "platform": row["platform"],
            "policyId": row["policy_id"],
            "policyVersion": row["policy_version"],
            "publishedAt": row["published_at"],
            "publishedBy": row["published_by"],
        }

    def _require_configuration(self, deployment_id: str) -> dict[str, Any]:
        """Load deployment configuration or fail without silently creating state."""
        return self._deployment_configuration(deployment_id)

    def _deployment_health(self, deployment_id: str) -> dict[str, Any]:
        """Compute one deployment's health without exposing session credentials."""
        deployment = self._deployment(deployment_id)
        self._expire_agents()
        counts = self._connection.execute(
            "SELECT status,COUNT(*) AS count FROM agents WHERE deployment_id=? GROUP BY status",
            (deployment_id,),
        ).fetchall()
        by_status = {row["status"]: int(row["count"]) for row in counts}
        control = self._connection.execute(
            "SELECT emergency_stop FROM deployment_controls WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        configuration = self._connection.execute(
            "SELECT desired_hash,applied_hash,rollout_state,rollout_percentage "
            "FROM deployment_configs WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        emergency_stop = bool(control and control["emergency_stop"])
        drifted = bool(
            configuration and configuration["desired_hash"] != configuration["applied_hash"]
        )
        status = (
            "critical"
            if emergency_stop
            else "attention"
            if drifted or by_status.get("offline", 0)
            else "healthy"
        )
        return {
            "deploymentId": deployment_id,
            "projectId": deployment["projectId"],
            "team": deployment["team"],
            "environment": deployment["environment"],
            "region": deployment["region"],
            "status": status,
            "emergencyStop": emergency_stop,
            "connectedAgents": by_status.get("connected", 0),
            "offlineAgents": by_status.get("offline", 0),
            "drifted": drifted,
            "rolloutState": configuration["rollout_state"] if configuration else "unmanaged",
            "rolloutPercentage": configuration["rollout_percentage"] if configuration else 0,
        }

    @staticmethod
    def _assert_identity_org(identity: FleetIdentity, organization_id: str) -> None:
        """Require an identity to operate only in its authenticated organization."""
        if identity.organization_id != organization_id:
            raise FleetAuthorizationError("organization scope is not permitted")

    def _require_org(self, organization_id: str) -> None:
        """Require an organization without revealing cross-tenant details."""
        row = self._connection.execute(
            "SELECT 1 FROM organizations WHERE id=?", (organization_id,)
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("organization not found")

    def _require_project(self, organization_id: str, project_id: str) -> None:
        """Require a project under the supplied organization."""
        row = self._connection.execute(
            "SELECT 1 FROM projects WHERE id=? AND organization_id=?", (project_id, organization_id)
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("project not found")

    def _deployment(self, deployment_id: str) -> dict[str, Any]:
        """Return a normalized deployment or a generic not-found error."""
        row = self._connection.execute(
            "SELECT id,organization_id,project_id,name,environment,region,sdk_version,team,"
            "created_at"
            " FROM deployments WHERE id=?",
            (deployment_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("deployment not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "projectId": row["project_id"],
            "name": row["name"],
            "environment": row["environment"],
            "region": row["region"],
            "sdkVersion": row["sdk_version"],
            "team": row["team"],
            "createdAt": row["created_at"],
        }

    def _agent(self, deployment_id: str, agent_id: str) -> dict[str, Any]:
        """Return a non-secret agent snapshot without session credentials."""
        row = self._connection.execute(
            "SELECT id,organization_id,project_id,deployment_id,host,project_root,"
            "environment,region,"
            "status,last_heartbeat,expires_at,metadata FROM agents WHERE deployment_id=? AND id=?",
            (deployment_id, agent_id),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("agent not found")
        emergency_stop = self._agent_emergency_stop(deployment_id, agent_id)
        result = {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "projectId": row["project_id"],
            "deploymentId": row["deployment_id"],
            "host": row["host"],
            "projectRoot": row["project_root"],
            "environment": row["environment"],
            "region": row["region"],
            "status": row["status"],
            "lastHeartbeat": row["last_heartbeat"],
            "expiresAt": row["expires_at"],
            "emergencyStop": emergency_stop,
        }
        telemetry = _agent_telemetry(row["metadata"])
        if telemetry is not None:
            result["telemetry"] = telemetry
        result["managed_configuration"] = self._managed_configuration_posture(
            row["deployment_id"], row["host"], row["metadata"]
        )
        return result

    def _managed_configuration_posture(
        self, deployment_id: str, host: str, metadata: object
    ) -> dict[str, Any]:
        """Compare desired managed policy with fresh endpoint-reported evidence."""
        desired_row = self._connection.execute(
            "SELECT desired_configuration FROM deployment_configs WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        desired: dict[str, Any] | None = None
        if desired_row is not None:
            try:
                configuration = json.loads(desired_row["desired_configuration"])
                candidate = (
                    configuration.get("managedHost") if isinstance(configuration, Mapping) else None
                )
                if isinstance(candidate, Mapping):
                    desired = _normalize_managed_host(candidate)
            except (FleetConfigurationError, TypeError, ValueError):
                desired = None
        report: dict[str, Any] | None = None
        if isinstance(metadata, str):
            try:
                value = json.loads(metadata)
                candidate = (
                    value.get("managedConfiguration") if isinstance(value, Mapping) else None
                )
                if isinstance(candidate, Mapping):
                    report = _normalize_managed_configuration_report(candidate)
            except (FleetConfigurationError, TypeError, ValueError):
                report = None
        if desired is None:
            return {"status": "not_configured", "desired": None, "observed": report}
        if report is None:
            return {"status": "missing", "desired": desired, "observed": None}
        identity_fields = (
            "host",
            "hostVersion",
            "platform",
            "bundleHash",
            "policyId",
            "policyVersion",
        )
        if host != desired["host"] or any(report[key] != desired[key] for key in identity_fields):
            status = "conflict"
        elif report["verifiedAt"] > self._now() or report["expiresAt"] <= self._now():
            status = "stale"
        else:
            status = "enforced"
        return {"status": status, "desired": desired, "observed": report}

    def _agent_emergency_stop(self, deployment_id: str, agent_id: str) -> bool:
        """Resolve the effective stop from agent, group and deployment scopes."""
        agent_stop = self._connection.execute(
            "SELECT emergency_stop FROM agent_controls WHERE deployment_id=? AND agent_id=?",
            (deployment_id, agent_id),
        ).fetchone()
        deployment_stop = self._connection.execute(
            "SELECT emergency_stop FROM deployment_controls WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        group_stop = self._connection.execute(
            "SELECT 1 FROM agent_group_members m JOIN group_controls c ON c.group_id=m.group_id "
            "WHERE m.deployment_id=? AND m.agent_id=? AND c.emergency_stop=1 LIMIT 1",
            (deployment_id, agent_id),
        ).fetchone()
        return bool(
            (agent_stop is not None and agent_stop["emergency_stop"])
            or (deployment_stop is not None and deployment_stop["emergency_stop"])
            or group_stop is not None
        )

    def _expire_agents(self) -> None:
        """Make heartbeat expiry visible before any inventory read."""
        self._connection.execute(
            "UPDATE agents SET status='offline' WHERE status='connected' AND expires_at<=?",
            (self._now(),),
        )
        self._connection.commit()

    @staticmethod
    def _assert_identity_scope(
        identity: FleetIdentity, organization_id: str, project_id: str
    ) -> None:
        """Enforce organization and optional project scope on every object access."""
        if identity.organization_id != organization_id:
            raise FleetAuthorizationError("organization scope is not permitted")
        if (
            identity.project_ids
            and project_id not in identity.project_ids
            and "admin" not in identity.roles
        ):
            raise FleetAuthorizationError("project scope is not permitted")

    @staticmethod
    def _assert_agent_identity(identity: FleetIdentity, agent_id: str) -> None:
        """Prevent an agent bearer from registering or controlling another agent ID."""
        if (
            "agent" in identity.roles
            and "admin" not in identity.roles
            and identity.subject != agent_id
        ):
            raise FleetAuthorizationError("agent identity does not match the authenticated subject")

    def _audit(
        self,
        event_type: str,
        actor: str,
        payload: Mapping[str, Any],
        organization_id: str | None = None,
    ) -> None:
        """Write only redaction-safe lifecycle metadata when an audit sink exists."""
        organization_id = organization_id or payload.get("organizationId")
        if isinstance(organization_id, str):
            with self._lock:
                self._connection.execute(
                    "INSERT INTO fleet_audit_evidence(organization_id,event_type,actor,"
                    "deployment_id,payload_hash,occurred_at) VALUES(?,?,?,?,?,?)",
                    (
                        organization_id,
                        event_type,
                        actor,
                        payload.get("deploymentId"),
                        self._configuration_hash(payload),
                        self._now(),
                    ),
                )
                self._connection.commit()
        if self.audit is not None:
            self.audit.append(
                event_type, f"fleet-{secrets.token_hex(8)}", {"actor": actor, **dict(payload)}
            )


class EnterpriseFleetApplication:
    """Authenticated WSGI API for enterprise fleet inventory and agent presence."""

    def __init__(
        self,
        store: EnterpriseFleetStore,
        *,
        authenticator: FleetAuthenticator,
        allowed_origin: str | None = None,
    ) -> None:
        """Bind a fleet store to an external authenticator and browser origin."""
        self.store = store
        self.authenticator = authenticator
        self.allowed_origin = allowed_origin
        # Startup is fail-closed: persisted state must reach live authorities
        # before this WSGI application can accept an authenticated request.
        self.store.reconcile_authorities()

    def __call__(self, environ: Mapping[str, Any], start_response: Any) -> list[bytes]:
        """Handle one bounded JSON request and return a JSON response."""
        method = str(environ.get("REQUEST_METHOD", "GET"))
        path = str(environ.get("PATH_INFO", "/"))
        # Browser preflight carries no bearer token. It is only a transport
        # negotiation; the actual request below still authenticates and
        # authorizes against the live identity and route.
        if method == "OPTIONS":
            return self._respond(start_response, 204, {}, preflight=True)
        identity = self.authenticator.authenticate(environ.get("HTTP_AUTHORIZATION"))
        if identity is None:
            return self._respond(start_response, 401, {"error": "authentication required"})
        try:
            inventory_prefix = "/api/enterprise/"
            if method == "GET" and path.startswith(inventory_prefix):
                resource = path[len(inventory_prefix) :]
                effective_prefix = "/api/enterprise/agents/"
                if resource == "identity":
                    self._authorize(identity, "read")
                    return self._respond(
                        start_response, 200, self._development_identity_access(identity)
                    )
                if resource == "integrations":
                    self._authorize(identity, "read")
                    return self._respond(start_response, 200, self._development_integrations())
                if resource.startswith("deployments/") and resource.endswith("/managed-package"):
                    self._authorize(identity, "read")
                    parts = resource.split("/")
                    if len(parts) != 3:
                        raise FleetConfigurationError(
                            "managed package route must include one deployment"
                        )
                    return self._respond(
                        start_response,
                        200,
                        self.store.managed_deployment_package_metadata(
                            identity, _text(parts[1], "deploymentId")
                        ),
                    )
                if resource.startswith("policies/") and "/versions" in resource:
                    self._authorize(identity, "read")
                    parts = resource.split("/")
                    if len(parts) == 3 and parts[2] == "versions":
                        query = parse_qs(str(environ.get("QUERY_STRING", "")))
                        page = self.store.list_policy_versions(
                            identity,
                            _text(parts[1], "policyId"),
                            cursor=query.get("cursor", [None])[0],
                            limit=int(query.get("limit", ["200"])[0]),
                        )
                        return self._respond(
                            start_response,
                            200,
                            {"items": list(page.items), "nextCursor": page.next_cursor},
                        )
                    if len(parts) == 4 and parts[2] == "versions":
                        try:
                            version = int(parts[3])
                        except ValueError as exc:
                            raise FleetConfigurationError(
                                "policy version must be an integer"
                            ) from exc
                        return self._respond(
                            start_response,
                            200,
                            self.store.policy_version(
                                identity, _text(parts[1], "policyId"), version
                            ),
                        )
                    raise FleetConfigurationError("policy version route is invalid")
                if resource.startswith("agents/") and resource.endswith("/verify"):
                    self._authorize(identity, "read")
                    deployment_id, agent_id = self._agent_route(path, effective_prefix, "/verify")
                    return self._respond(
                        start_response,
                        200,
                        self.store.verify_agent(
                            identity, deployment_id=deployment_id, agent_id=agent_id
                        ),
                    )
                if resource.startswith("agents/") and resource.endswith("/effective-policy"):
                    self._authorize_any(identity, {"read", "agent_presence"})
                    deployment_id, agent_id = self._agent_route(
                        path, effective_prefix, "/effective-policy"
                    )
                    return self._respond(
                        start_response,
                        200,
                        self.store.effective_agent_policy(
                            identity, deployment_id=deployment_id, agent_id=agent_id
                        ),
                    )
                if resource.startswith("agents/") and resource.endswith("/managed-package"):
                    self._authorize_any(identity, {"read", "agent_presence"})
                    deployment_id, agent_id = self._agent_route(
                        path, effective_prefix, "/managed-package"
                    )
                    return self._respond(
                        start_response,
                        200,
                        self.store.agent_managed_deployment_package(
                            identity, deployment_id=deployment_id, agent_id=agent_id
                        ),
                    )
                if resource in {"health", "slo", "alerts"}:
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    requested_cursor = query.get("cursor", [None])[0]
                    requested_limit = int(query.get("limit", ["200"])[0])
                    page = (
                        self.store.health(identity, cursor=requested_cursor, limit=requested_limit)
                        if resource == "health"
                        else self.store.slo(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                        if resource == "slo"
                        else self.store.alerts(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource == "compliance/evidence":
                    self._authorize(identity, "read")
                    return self._respond(
                        start_response, 200, self.store.compliance_evidence(identity)
                    )
                if resource == "audit":
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    page = self.store.audit_evidence(
                        identity,
                        cursor=query.get("cursor", [None])[0],
                        limit=int(query.get("limit", ["200"])[0]),
                        event_type=query.get("eventType", [None])[0],
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource == "capabilities":
                    self._authorize(identity, "read")
                    return self._respond(start_response, 200, self.store.persistence_capabilities())
                if resource == "drift":
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    page = self.store.list_drift(
                        identity,
                        cursor=query.get("cursor", [None])[0],
                        limit=int(query.get("limit", ["200"])[0]),
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource in {"templates", "deployment-config", "deployment-config/history"}:
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    requested_deployment = query.get("deploymentId", [None])[0]
                    requested_cursor = query.get("cursor", [None])[0]
                    requested_limit = int(query.get("limit", ["200"])[0])
                    page = (
                        self.store.list_templates(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                        if resource == "templates"
                        else self.store.list_configuration_history(
                            identity,
                            requested_deployment,
                            cursor=requested_cursor,
                            limit=requested_limit,
                        )
                        if resource == "deployment-config/history"
                        else self.store.list_configurations(
                            identity,
                            requested_deployment,
                            cursor=requested_cursor,
                            limit=requested_limit,
                        )
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource in {"policies", "groups", "skills", "mcp-servers"}:
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    requested_cursor = query.get("cursor", [None])[0]
                    requested_limit = int(query.get("limit", ["200"])[0])
                    page = (
                        self.store.list_policies(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                        if resource == "policies"
                        else self.store.list_groups(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                        if resource == "groups"
                        else self.store.list_skills(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                        if resource == "skills"
                        else self.store.list_mcp_servers(
                            identity, cursor=requested_cursor, limit=requested_limit
                        )
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource in {"organizations", "projects", "deployments", "agents", "sessions"}:
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    requested_org = query.get("organizationId", [None])[0]
                    requested_cursor = query.get("cursor", [None])[0]
                    requested_limit = int(query.get("limit", ["200"])[0])
                    page = self.store.list_inventory(
                        identity,
                        resource,
                        organization_id=requested_org,
                        cursor=requested_cursor,
                        limit=requested_limit,
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
            body = self._body(environ)
            managed_package_prefix = "/api/enterprise/deployments/"
            if (
                method == "PUT"
                and path.startswith(managed_package_prefix)
                and path.endswith("/managed-package")
            ):
                self._authorize(identity, "manage_configuration")
                if set(body) != {"expectedRevision", "packageBase64", "packageSha256"}:
                    raise FleetConfigurationError("managed package request schema is invalid")
                encoded_value = body.get("packageBase64")
                if not isinstance(encoded_value, str) or len(encoded_value) > (
                    (_MAX_MANAGED_PACKAGE_BYTES * 4 // 3) + 8
                ):
                    raise FleetConfigurationError("managed package base64 is invalid")
                try:
                    encoded = base64.b64decode(encoded_value, validate=True)
                except (ValueError, TypeError) as exc:
                    raise FleetConfigurationError("managed package base64 is invalid") from exc
                expected_revision = body.get("expectedRevision")
                if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
                    raise FleetConfigurationError("managed package revision must be an integer")
                deployment_id = path[len(managed_package_prefix) : -len("/managed-package")].strip(
                    "/"
                )
                return self._respond(
                    start_response,
                    201,
                    self.store.publish_managed_deployment_package(
                        identity,
                        _text(deployment_id, "deploymentId"),
                        encoded,
                        expected_package_sha256=_text(body.get("packageSha256"), "packageSha256"),
                        expected_revision=expected_revision,
                    ),
                )
            if method == "POST" and path == "/api/enterprise/slo/sample":
                self._authorize(identity, "manage_inventory")
                deployment_id = _text(body.get("deploymentId"), "deploymentId")
                return self._respond(
                    start_response, 201, self.store.record_slo_sample(identity, deployment_id)
                )
            if method == "POST" and path == "/api/enterprise/templates/validate":
                self._authorize(identity, "manage_configuration")
                configuration = body.get("configuration")
                if not isinstance(configuration, Mapping):
                    raise FleetConfigurationError("configuration must be an object")
                return self._respond(
                    start_response,
                    200,
                    self.store.validate_template_configuration(identity, configuration),
                )
            if (
                method == "POST"
                and path.startswith("/api/enterprise/alerts/")
                and path.endswith("/ack")
            ):
                self._authorize(identity, "manage_alerts")
                alert_id = path[len("/api/enterprise/alerts/") : -len("/ack")].strip("/")
                return self._respond(
                    start_response, 200, self.store.acknowledge_alert(identity, alert_id)
                )
            if method == "POST" and path == "/api/enterprise/alerts/dispatch":
                self._authorize(identity, "dispatch_alerts")
                page = self.store.dispatch_alerts(identity)
                return self._respond(
                    start_response,
                    200,
                    {"items": list(page.items), "nextCursor": page.next_cursor},
                )
            if method == "POST" and path == "/api/enterprise/organizations":
                self._authorize(identity, "manage_inventory")
                organization_id = _text(body.get("organizationId"), "organizationId")
                if organization_id != identity.organization_id:
                    raise FleetAuthorizationError("organization scope is not permitted")
                result = self.store.create_organization(
                    organization_id, _text(body.get("name"), "name")
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/projects":
                self._authorize(identity, "manage_inventory")
                organization_id = _text(body.get("organizationId"), "organizationId")
                project_id = _text(body.get("projectId"), "projectId")
                self.store._assert_identity_scope(identity, organization_id, project_id)
                result = self.store.create_project(
                    organization_id, project_id, _text(body.get("name"), "name")
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/deployments":
                self._authorize(identity, "manage_inventory")
                organization_id = _text(body.get("organizationId"), "organizationId")
                project_id = _text(body.get("projectId"), "projectId")
                self.store._assert_identity_scope(identity, organization_id, project_id)
                result = self.store.create_deployment(
                    organization_id,
                    project_id,
                    _text(body.get("deploymentId"), "deploymentId"),
                    _text(body.get("name"), "name"),
                    environment=_text(body.get("environment"), "environment"),
                    region=_text(body.get("region"), "region"),
                    sdk_version=_optional_text(body.get("sdkVersion"), "sdkVersion"),
                    team=_optional_text(body.get("team"), "team"),
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/agents/register":
                self._authorize_any(identity, {"manage_inventory", "agent_presence"})
                result = self.store.register_agent(
                    identity,
                    deployment_id=_text(body.get("deploymentId"), "deploymentId"),
                    agent_id=_text(body.get("agentId"), "agentId"),
                    host=_text(body.get("host"), "host"),
                    project_root=_text(body.get("projectRoot"), "projectRoot"),
                    metadata=(
                        body.get("metadata") if isinstance(body.get("metadata"), Mapping) else None
                    ),
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/templates":
                self._authorize(identity, "manage_configuration")
                configuration = body.get("configuration")
                if not isinstance(configuration, Mapping):
                    raise FleetConfigurationError("configuration must be an object")
                result = self.store.create_template(
                    identity,
                    template_id=_text(body.get("templateId"), "templateId"),
                    name=_text(body.get("name"), "name"),
                    configuration=configuration,
                    parent_template_id=_optional_text(
                        body.get("parentTemplateId"), "parentTemplateId"
                    ),
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/policies":
                self._authorize(identity, "manage_configuration")
                configuration = body.get("configuration")
                if not isinstance(configuration, Mapping):
                    raise FleetConfigurationError("configuration must be an object")
                result = self.store.create_policy(
                    identity,
                    policy_id=_text(body.get("policyId"), "policyId"),
                    name=_text(body.get("name"), "name"),
                    configuration=configuration,
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/skills":
                self._authorize(identity, "manage_configuration")
                skill_content = body.get("content")
                if not isinstance(skill_content, str):
                    raise FleetConfigurationError("content must be bounded non-empty text")
                result = self.store.create_skill(
                    identity,
                    skill_id=_text(body.get("skillId"), "skillId"),
                    name=_text(body.get("name"), "name"),
                    description=_text(body.get("description", ""), "description"),
                    version=_text(body.get("version", "1.0.0"), "version"),
                    # Content is validated by the store so the size limit can
                    # produce a useful error instead of the generic field limit.
                    content=skill_content,
                    enabled=body.get("enabled", True) is True,
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/mcp-servers":
                self._authorize(identity, "manage_configuration")
                args = body.get("args", [])
                environment_references = body.get("environmentReferences", [])
                if not isinstance(args, list) or not isinstance(environment_references, list):
                    raise FleetConfigurationError(
                        "MCP args and environmentReferences must be arrays"
                    )
                result = self.store.create_mcp_server(
                    identity,
                    server_id=_text(body.get("serverId"), "serverId"),
                    name=_text(body.get("name"), "name"),
                    description=_text(body.get("description", ""), "description"),
                    version=_text(body.get("version", "1.0.0"), "version"),
                    transport=_text(body.get("transport"), "transport"),
                    command=_optional_text(body.get("command"), "command"),
                    args=[_text(item, "arg") for item in args],
                    url=_optional_text(body.get("url"), "url"),
                    environment_references=[
                        _text(item, "environmentReference") for item in environment_references
                    ],
                    enabled=body.get("enabled", True) is True,
                )
                return self._respond(start_response, 201, result)
            policy_versions_prefix = "/api/enterprise/policies/"
            if method == "POST" and path.startswith(policy_versions_prefix):
                policy_parts = path[len(policy_versions_prefix) :].split("/")
                if len(policy_parts) == 4 and policy_parts[1] == "versions":
                    policy_id = _text(policy_parts[0], "policyId")
                    try:
                        version = int(policy_parts[2])
                    except ValueError as exc:
                        raise FleetConfigurationError("policy version must be an integer") from exc
                    action = policy_parts[3]
                    if action == "submit":
                        self._authorize(identity, "manage_configuration")
                        return self._respond(
                            start_response,
                            200,
                            self.store.submit_policy_version(identity, policy_id, version),
                        )
                    self._authorize(identity, "approve_configuration")
                    if action == "decision":
                        return self._respond(
                            start_response,
                            200,
                            self.store.decide_policy_version(
                                identity,
                                policy_id,
                                version,
                                decision=_text(body.get("decision"), "decision"),
                                reason=_text(body.get("reason"), "reason"),
                            ),
                        )
                    if action == "stage":
                        return self._respond(
                            start_response,
                            200,
                            self.store.stage_policy_version(identity, policy_id, version),
                        )
                    if action == "activate":
                        expected = body.get("expectedActiveVersion")
                        if not isinstance(expected, int) or isinstance(expected, bool):
                            raise FleetConfigurationError(
                                "expectedActiveVersion must be an integer"
                            )
                        return self._respond(
                            start_response,
                            200,
                            self.store.activate_policy_version(
                                identity,
                                policy_id,
                                version,
                                expected_active_version=expected,
                            ),
                        )
                    raise FleetConfigurationError("policy transition is unsupported")
            if (
                method == "POST"
                and path.startswith(policy_versions_prefix)
                and path.endswith("/versions")
            ):
                self._authorize(identity, "manage_configuration")
                configuration = body.get("configuration")
                if not isinstance(configuration, Mapping):
                    raise FleetConfigurationError("configuration must be an object")
                policy_id = path[len(policy_versions_prefix) : -len("/versions")].strip("/")
                result = self.store.update_policy(
                    identity,
                    policy_id=_text(policy_id, "policyId"),
                    name=_text(body.get("name"), "name"),
                    configuration=configuration,
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/groups":
                self._authorize(identity, "manage_inventory")
                result = self.store.create_group(
                    identity,
                    group_id=_text(body.get("groupId"), "groupId"),
                    name=_text(body.get("name"), "name"),
                    policy_id=_text(body.get("policyId"), "policyId"),
                )
                return self._respond(start_response, 201, result)
            membership_prefix = "/api/enterprise/groups/"
            if (
                method == "POST"
                and path.startswith(membership_prefix)
                and path.endswith("/emergency-stop")
            ):
                self._authorize(identity, "emergency_stop")
                group_id = path[len(membership_prefix) : -len("/emergency-stop")].strip("/")
                active = body.get("active")
                if not isinstance(active, bool):
                    raise FleetConfigurationError("active must be boolean")
                result = self.store.set_group_emergency_stop(
                    identity, group_id=_text(group_id, "groupId"), active=active
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path.startswith(membership_prefix) and path.endswith("/policy"):
                self._authorize(identity, "manage_configuration")
                group_id = path[len(membership_prefix) : -len("/policy")].strip("/")
                result = self.store.update_group_policy(
                    identity,
                    group_id=_text(group_id, "groupId"),
                    policy_id=_text(body.get("policyId"), "policyId"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path.startswith(membership_prefix) and path.endswith("/agents"):
                self._authorize(identity, "manage_inventory")
                group_id = _text(
                    path[len(membership_prefix) : -len("/agents")].strip("/"), "groupId"
                )
                result = self.store.add_agent_to_group(
                    identity,
                    group_id=group_id,
                    deployment_id=_text(body.get("deploymentId"), "deploymentId"),
                    agent_id=_text(body.get("agentId"), "agentId"),
                )
                return self._respond(start_response, 201, result)
            if method == "DELETE" and path.startswith(membership_prefix) and "/agents/" in path:
                self._authorize(identity, "manage_inventory")
                group_id, member = path[len(membership_prefix) :].strip("/").split("/agents/", 1)
                deployment_id, agent_id = member.split("/", 1)
                result = self.store.remove_agent_from_group(
                    identity,
                    group_id=_text(group_id, "groupId"),
                    deployment_id=_text(deployment_id, "deploymentId"),
                    agent_id=_text(agent_id, "agentId"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config":
                self._authorize(identity, "manage_configuration")
                result = self.store.assign_template(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    _text(body.get("templateId"), "templateId"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config/rollout":
                self._authorize(identity, "manage_configuration")
                percentage = body.get("percentage")
                if not isinstance(percentage, int) or isinstance(percentage, bool):
                    raise FleetConfigurationError("percentage must be an integer")
                result = self.store.set_rollout(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    state=_text(body.get("state"), "state"),
                    percentage=percentage,
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config/batch-rollout":
                self._authorize(identity, "manage_configuration")
                deployment_ids = body.get("deploymentIds")
                if not isinstance(deployment_ids, list):
                    raise FleetConfigurationError("deploymentIds must be a list")
                percentage = body.get("percentage")
                if not isinstance(percentage, int) or isinstance(percentage, bool):
                    raise FleetConfigurationError("percentage must be an integer")
                batch_result = self.store.rollout_deployments(
                    identity,
                    deployment_ids,
                    state=_text(body.get("state"), "state"),
                    percentage=percentage,
                )
                return self._respond(
                    start_response,
                    200,
                    {"items": list(batch_result.items), "nextCursor": batch_result.next_cursor},
                )
            if method == "POST" and path == "/api/enterprise/deployment-config/rollback":
                self._authorize(identity, "manage_configuration")
                rollback_version = body.get("version")
                if not isinstance(rollback_version, int) or isinstance(rollback_version, bool):
                    raise FleetConfigurationError("version must be an integer")
                result = self.store.rollback_deployment(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    rollback_version,
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config/applied":
                self._authorize_any(identity, {"manage_configuration", "agent_presence"})
                result = self.store.record_applied_configuration(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    _text(body.get("configurationHash"), "configurationHash"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/emergency-stop":
                self._authorize(identity, "emergency_stop")
                active = body.get("active")
                if not isinstance(active, bool):
                    raise FleetConfigurationError("active must be boolean")
                result = self.store.set_emergency_stop(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    active=active,
                )
                return self._respond(start_response, 200, result)
            prefix = "/api/enterprise/agents/"
            if method == "POST" and path.startswith(prefix) and path.endswith("/emergency-stop"):
                self._authorize(identity, "emergency_stop")
                deployment_id, agent_id = self._agent_route(path, prefix, "/emergency-stop")
                active = body.get("active")
                if not isinstance(active, bool):
                    raise FleetConfigurationError("active must be boolean")
                result = self.store.set_agent_emergency_stop(
                    identity,
                    deployment_id=deployment_id,
                    agent_id=agent_id,
                    active=active,
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path.startswith(prefix) and path.endswith("/heartbeat"):
                self._authorize_any(identity, {"manage_inventory", "agent_presence"})
                deployment_id, agent_id = self._agent_route(path, prefix, "/heartbeat")
                result = self.store.heartbeat(
                    identity,
                    deployment_id,
                    agent_id,
                    _text(body.get("sessionId"), "sessionId"),
                    body.get("telemetry"),
                    body.get("managedConfiguration"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path.startswith(prefix) and path.endswith("/disconnect"):
                self._authorize_any(identity, {"manage_inventory", "agent_presence"})
                deployment_id, agent_id = self._agent_route(path, prefix, "/disconnect")
                result = self.store.disconnect(
                    identity,
                    deployment_id,
                    agent_id,
                    _text(body.get("sessionId"), "sessionId"),
                )
                return self._respond(start_response, 200, result)
            return self._respond(start_response, 404, {"error": "not found"})
        except FleetAuthorizationError as exc:
            return self._respond(start_response, 403, {"error": str(exc)})
        except FleetNotFoundError as exc:
            return self._respond(start_response, 404, {"error": str(exc)})
        except FleetConflictError as exc:
            return self._respond(start_response, 409, {"error": str(exc)})
        except (FleetConfigurationError, TypeError, ValueError) as exc:
            return self._respond(start_response, 400, {"error": str(exc)})
        except sqlite3.IntegrityError:
            return self._respond(start_response, 409, {"error": "fleet resource already exists"})

    def _authorize(self, identity: FleetIdentity, action: str) -> None:
        """Require the injected authenticator to approve an operation."""
        if not self.authenticator.authorize(identity, action):
            raise FleetAuthorizationError("forbidden")

    @staticmethod
    def _development_identity_access(identity: FleetIdentity) -> dict[str, Any]:
        """Describe local authentication without pretending it is enterprise SSO."""
        role_mapping = {
            "admin": "platform-admin",
            "operator": "fleet-operator",
            "viewer": "auditor",
            "incident_commander": "incident-responder",
        }
        capabilities = {
            "platform-admin": ["*"],
            "security-operator": ["approval_decision", "incident_response"],
            "policy-author": ["policy_write"],
            "policy-approver": ["approval_decision", "policy_approval"],
            "fleet-operator": ["fleet_write"],
            "incident-responder": ["incident_response"],
            "auditor": ["access_certification_read"],
        }
        active_roles = sorted(
            {role_mapping[role] for role in identity.roles if role in role_mapping}
        )
        return {
            "provider": "development_static",
            "providerLabel": "Development static bearer",
            "protocol": "static_bearer",
            "status": "development_only",
            "tenantHint": identity.organization_id,
            "tenantBinding": "server_owned",
            "roleSource": "deployment_authenticator",
            "strongAuthentication": {
                "status": "not_configured",
                "maxAuthenticationAgeSeconds": 600,
            },
            "subject": identity.subject,
            "scimStatus": "not_configured",
            "scim": {
                "status": "not_configured",
                "lifecycleEnforced": False,
                "users": {"total": 0, "active": 0, "disabled": 0},
                "groups": {"total": 0, "mapped": 0, "unmapped": 0},
                "groupMappings": [],
                "lastProvisionedAt": None,
            },
            "activeRoles": active_roles,
            "roleMatrix": [
                {"role": role, "capabilities": role_capabilities}
                for role, role_capabilities in capabilities.items()
            ],
        }

    @staticmethod
    def _development_integrations() -> dict[str, Any]:
        """Report the Splunk placeholder without claiming local delivery."""
        return {
            "splunk": {
                "provider": "splunk_hec",
                "status": "stub",
                "deliveryVerified": False,
                "description": (
                    "Schema and operator workflow placeholder only; "
                    "no event delivery is configured."
                ),
            }
        }

    def _authorize_any(self, identity: FleetIdentity, actions: set[str]) -> None:
        """Permit one of several explicit role actions without broadening scope."""
        if not any(self.authenticator.authorize(identity, action) for action in actions):
            raise FleetAuthorizationError("forbidden")

    @staticmethod
    def _body(environ: Mapping[str, Any]) -> dict[str, Any]:
        """Decode one bounded JSON object without accepting arbitrary request data."""
        length = int(str(environ.get("CONTENT_LENGTH", "0") or "0"))
        if length < 0 or length > 1_000_000:
            raise FleetConfigurationError("request body is too large")
        stream = environ.get("wsgi.input")
        raw = stream.read(length) if stream is not None else b""
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise FleetConfigurationError("request body must be an object")
        return value

    @staticmethod
    def _agent_route(path: str, prefix: str, suffix: str) -> tuple[str, str]:
        """Parse ``deployment/agent/action`` without trusting body identity fields."""
        parts = path[len(prefix) : -len(suffix)].strip("/").split("/")
        if len(parts) != 2:
            raise FleetConfigurationError("agent route must include deployment and agent")
        return _text(parts[0], "deploymentId"), _text(parts[1], "agentId")

    def _respond(
        self,
        start_response: Any,
        status_code: int,
        payload: Mapping[str, Any],
        *,
        preflight: bool = False,
    ) -> list[bytes]:
        """Return compact JSON with explicit browser-origin headers."""
        statuses = {
            204: "No Content",
            200: "OK",
            201: "Created",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            409: "Conflict",
        }
        body = json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        if self.allowed_origin is not None:
            headers.extend(
                [("Access-Control-Allow-Origin", self.allowed_origin), ("Vary", "Origin")]
            )
            if preflight:
                headers.extend(
                    [
                        ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"),
                        ("Access-Control-Allow-Headers", "Authorization, Content-Type"),
                    ]
                )
        start_response(f"{status_code} {statuses[status_code]}", headers)
        return [body]


__all__ = [
    "EnterpriseFleetStore",
    "FleetAuthenticator",
    "FleetIdentityVerifier",
    "CallbackFleetAuthenticator",
    "FleetSecretReference",
    "FleetSecretResolver",
    "CallbackFleetSecretResolver",
    "FleetPersistenceAdapter",
    "SQLiteFleetPersistenceAdapter",
    "PostgresFleetPersistenceAdapter",
    "FleetAuthorizationError",
    "FleetConfigurationError",
    "FleetDeploymentAuthority",
    "FleetAlertSink",
    "WebhookFleetAlertSink",
    "FleetIdentity",
    "FleetNotFoundError",
    "FleetPage",
    "StaticFleetAuthenticator",
    "EnterpriseFleetApplication",
]

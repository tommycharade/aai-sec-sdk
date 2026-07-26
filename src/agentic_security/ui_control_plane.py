"""Authenticated control-plane adapter for the optional AAI Security UI.

This module is deliberately small and dependency-free.  It provides the
configuration and operational API consumed by ``aai-sec-ui``; it does not
invent application identity, policy decisions, credentials, or sandbox
attestation.  A deployment must still construct :class:`GuardedRuntime` with
its own authenticated providers and bind this adapter behind an appropriate
TLS-terminating web server.

The included WSGI application is suitable for local development and as a
reference adapter.  It is not a complete production control plane: operators
must add durable authentication, authorization, audit retention, deployment
hardening, and runtime reconciliation before exposing it beyond a trusted
development host.
"""

from __future__ import annotations

import hmac
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Final

JsonObject = dict[str, Any]
_RUNTIME_KEYS: Final[frozenset[str]] = frozenset(
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
)
_CLAUDE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "enabled",
        "projectRoot",
        "hookCommand",
        "hookConfigPath",
        "mcpServerName",
        "mcpGatewayCommand",
        "allowedBuiltInTools",
        "deniedCommandPatterns",
        "approvalCommandPatterns",
        "fileTools",
    }
)
_POLICY_PROVIDERS: Final[frozenset[str]] = frozenset({"local_allow_list", "opa", "cedar"})
_APPROVAL_PROVIDERS: Final[frozenset[str]] = frozenset({"in_memory", "http"})
_AUDIT_PROVIDERS: Final[frozenset[str]] = frozenset(
    {"memory", "jsonl", "replicated", "opentelemetry"}
)
_ISOLATION_MODES: Final[frozenset[str]] = frozenset({"disabled", "deployment_attested"})


class ControlPlaneConfigurationError(ValueError):
    """Raised when a UI configuration is malformed or unsafe."""


def _now() -> str:
    """Return an explicit UTC timestamp for control-plane state."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    """Require a JSON object at a named configuration boundary."""
    if not isinstance(value, Mapping):
        raise ControlPlaneConfigurationError(f"{name} must be an object")
    return value


def _text(value: object, name: str, *, allow_empty: bool = True) -> str:
    """Validate bounded text without interpreting it as authority."""
    if not isinstance(value, str) or len(value) > 4_096:
        raise ControlPlaneConfigurationError(f"{name} must be text of at most 4096 characters")
    if not allow_empty and not value.strip():
        raise ControlPlaneConfigurationError(f"{name} must be non-empty")
    return value


def _bool(value: object, name: str) -> bool:
    """Require a real JSON boolean instead of truthy coercion."""
    if not isinstance(value, bool):
        raise ControlPlaneConfigurationError(f"{name} must be boolean")
    return value


def _positive_int(value: object, name: str, *, allow_zero: bool = False) -> int:
    """Require a bounded integer for a runtime safety limit."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ControlPlaneConfigurationError(f"{name} must be an integer")
    if value < 0 or (value == 0 and not allow_zero):
        raise ControlPlaneConfigurationError(f"{name} must be positive")
    if value > 10_000_000:
        raise ControlPlaneConfigurationError(f"{name} is above the safe configuration limit")
    return value


def _number(value: object, name: str) -> float:
    """Require a finite positive JSON number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ControlPlaneConfigurationError(f"{name} must be numeric")
    result = float(value)
    if result <= 0 or result != result or result in {float("inf"), float("-inf")}:
        raise ControlPlaneConfigurationError(f"{name} must be finite and positive")
    if result > 10_000_000:
        raise ControlPlaneConfigurationError(f"{name} is above the safe configuration limit")
    return result


def _list_of_text(value: object, name: str) -> list[str]:
    """Validate a list of bounded strings without accepting implicit coercion."""
    if not isinstance(value, list) or len(value) > 10_000:
        raise ControlPlaneConfigurationError(f"{name} must be a bounded list")
    return [_text(item, f"{name} entry", allow_empty=False) for item in value]


def validate_configuration(value: object) -> JsonObject:
    """Validate and normalize a complete UI configuration replacement.

    The API accepts a complete replacement rather than a patch so an omitted
    safety setting cannot silently retain an unsafe value.  Unknown keys are
    rejected to make frontend/backend schema drift visible during development.
    """
    root = _mapping(value, "configuration")
    runtime = _mapping(root.get("runtime"), "runtime")
    claude = _mapping(root.get("claudeCode"), "claudeCode")
    if set(runtime) != _RUNTIME_KEYS:
        raise ControlPlaneConfigurationError("runtime must contain exactly the documented fields")
    if set(claude) != _CLAUDE_KEYS:
        raise ControlPlaneConfigurationError(
            "claudeCode must contain exactly the documented fields"
        )

    policy_provider = _text(runtime["policyProvider"], "policyProvider", allow_empty=False)
    if policy_provider not in _POLICY_PROVIDERS:
        raise ControlPlaneConfigurationError("unknown policy provider")
    approval_provider = _text(runtime["approvalProvider"], "approvalProvider", allow_empty=False)
    if approval_provider not in _APPROVAL_PROVIDERS:
        raise ControlPlaneConfigurationError("unknown approval provider")
    audit_provider = _text(runtime["auditProvider"], "auditProvider", allow_empty=False)
    if audit_provider not in _AUDIT_PROVIDERS:
        raise ControlPlaneConfigurationError("unknown audit provider")
    isolation_verifier = _text(runtime["isolationVerifier"], "isolationVerifier", allow_empty=False)
    if isolation_verifier not in _ISOLATION_MODES:
        raise ControlPlaneConfigurationError("unknown isolation verifier")

    max_rate = runtime["maxActionsPerSecond"]
    normalized_rate: float | None = (
        None if max_rate is None else _number(max_rate, "maxActionsPerSecond")
    )
    normalized_runtime: JsonObject = {
        "policyProvider": policy_provider,
        "approvalProvider": approval_provider,
        "auditProvider": audit_provider,
        "policyEndpoint": _text(runtime["policyEndpoint"], "policyEndpoint"),
        "approvalEndpoint": _text(runtime["approvalEndpoint"], "approvalEndpoint"),
        "auditPath": _text(runtime["auditPath"], "auditPath"),
        "auditReplicaEndpoint": _text(runtime["auditReplicaEndpoint"], "auditReplicaEndpoint"),
        "credentialBrokerEndpoint": _text(
            runtime["credentialBrokerEndpoint"], "credentialBrokerEndpoint"
        ),
        "isolationVerifier": isolation_verifier,
        "telemetryEnabled": _bool(runtime["telemetryEnabled"], "telemetryEnabled"),
        "allowedTools": _list_of_text(runtime["allowedTools"], "allowedTools"),
        "allowedPrincipals": _list_of_text(runtime["allowedPrincipals"], "allowedPrincipals"),
        "maxActions": _positive_int(runtime["maxActions"], "maxActions"),
        "maxConcurrent": _positive_int(runtime["maxConcurrent"], "maxConcurrent"),
        "maxFanOut": _positive_int(runtime["maxFanOut"], "maxFanOut"),
        "maxCostUnits": _positive_int(runtime["maxCostUnits"], "maxCostUnits"),
        "maxDelegationDepth": _positive_int(
            runtime["maxDelegationDepth"], "maxDelegationDepth", allow_zero=True
        ),
        "maxActionsPerSecond": normalized_rate,
        "executionTimeoutSeconds": _number(
            runtime["executionTimeoutSeconds"], "executionTimeoutSeconds"
        ),
        "maxTimedOutWorkers": _positive_int(runtime["maxTimedOutWorkers"], "maxTimedOutWorkers"),
        "idempotencyTtlSeconds": _positive_int(
            runtime["idempotencyTtlSeconds"], "idempotencyTtlSeconds"
        ),
        "approvalTtlSeconds": _positive_int(runtime["approvalTtlSeconds"], "approvalTtlSeconds"),
        "credentialsEnabled": _bool(runtime["credentialsEnabled"], "credentialsEnabled"),
        "isolationRequiredForHighRisk": _bool(
            runtime["isolationRequiredForHighRisk"], "isolationRequiredForHighRisk"
        ),
        "redactSensitiveData": _bool(runtime["redactSensitiveData"], "redactSensitiveData"),
        "captureToolContent": _bool(runtime["captureToolContent"], "captureToolContent"),
    }
    if normalized_runtime["captureToolContent"] and not normalized_runtime["redactSensitiveData"]:
        raise ControlPlaneConfigurationError(
            "tool content capture requires sensitive-data redaction"
        )

    normalized_claude: JsonObject = {
        "enabled": _bool(claude["enabled"], "claudeCode.enabled"),
        "projectRoot": _text(claude["projectRoot"], "claudeCode.projectRoot", allow_empty=False),
        "hookCommand": _text(claude["hookCommand"], "claudeCode.hookCommand", allow_empty=False),
        "hookConfigPath": _text(
            claude["hookConfigPath"], "claudeCode.hookConfigPath", allow_empty=False
        ),
        "mcpServerName": _text(
            claude["mcpServerName"], "claudeCode.mcpServerName", allow_empty=False
        ),
        "mcpGatewayCommand": _text(
            claude["mcpGatewayCommand"], "claudeCode.mcpGatewayCommand", allow_empty=False
        ),
        "allowedBuiltInTools": _list_of_text(
            claude["allowedBuiltInTools"], "claudeCode.allowedBuiltInTools"
        ),
        "deniedCommandPatterns": _list_of_text(
            claude["deniedCommandPatterns"], "claudeCode.deniedCommandPatterns"
        ),
        "approvalCommandPatterns": _list_of_text(
            claude["approvalCommandPatterns"], "claudeCode.approvalCommandPatterns"
        ),
        "fileTools": _list_of_text(claude["fileTools"], "claudeCode.fileTools"),
    }
    return {"runtime": normalized_runtime, "claudeCode": normalized_claude}


def _default_configuration() -> JsonObject:
    """Return restrictive synthetic defaults for local development."""
    return {
        "runtime": {
            "policyProvider": "local_allow_list",
            "approvalProvider": "in_memory",
            "auditProvider": "jsonl",
            "policyEndpoint": "https://policy.example.test/decide",
            "approvalEndpoint": "https://approval.example.test/consume",
            "auditPath": "/var/lib/agentic-security/audit.jsonl",
            "auditReplicaEndpoint": "https://audit.example.test/events",
            "credentialBrokerEndpoint": "https://iam.example.test/mint",
            "isolationVerifier": "deployment_attested",
            "telemetryEnabled": False,
            "allowedTools": ["read_repository", "run_tests"],
            "allowedPrincipals": ["developer-local"],
            "maxActions": 20,
            "maxConcurrent": 1,
            "maxFanOut": 1,
            "maxCostUnits": 20,
            "maxDelegationDepth": 1,
            "maxActionsPerSecond": None,
            "executionTimeoutSeconds": 30,
            "maxTimedOutWorkers": 32,
            "idempotencyTtlSeconds": 86_400,
            "approvalTtlSeconds": 120,
            "credentialsEnabled": False,
            "isolationRequiredForHighRisk": True,
            "redactSensitiveData": True,
            "captureToolContent": False,
        },
        "claudeCode": {
            "enabled": True,
            "projectRoot": "/workspace/example-project",
            "hookCommand": "python examples/claude_code_hook.py",
            "hookConfigPath": ".claude/settings.json",
            "mcpServerName": "agentic-security-gateway",
            "mcpGatewayCommand": "python examples/mcp_gateway.py",
            "allowedBuiltInTools": ["Read", "Glob", "Grep"],
            "deniedCommandPatterns": [r"rm\s+-rf", r"curl\s+.*\|\s*sh"],
            "approvalCommandPatterns": [r"git\s+push", r"npm\s+publish"],
            "fileTools": ["Read", "Edit", "Write", "Glob", "Grep"],
        },
    }


class ControlPlaneStore:
    """Bounded JSON-backed state store for the UI control-plane adapter."""

    def __init__(self, path: str | Path) -> None:
        """Load validated state from ``path`` or create restrictive defaults."""
        self.path = Path(path)
        self._lock = RLock()
        self._emergency_stop = False
        self._state = self._load()

    def _load(self) -> JsonObject:
        """Load and validate persisted configuration; reject corruption."""
        if not self.path.exists():
            state = _default_configuration()
            self._persist(state)
            return state
        try:
            with self.path.open(encoding="utf-8") as source:
                value = json.load(source)
            normalized = validate_configuration(value)
            emergency_stop = (
                value.get("emergencyStop", False) if isinstance(value, Mapping) else False
            )
            if not isinstance(emergency_stop, bool):
                raise ControlPlaneConfigurationError("persisted emergencyStop must be boolean")
            self._emergency_stop = emergency_stop
            normalized["emergencyStop"] = emergency_stop
            normalized["lastSavedAt"] = _text(value.get("lastSavedAt", _now()), "lastSavedAt")
            return normalized
        except (OSError, json.JSONDecodeError, ControlPlaneConfigurationError) as exc:
            raise ControlPlaneConfigurationError("persisted UI configuration is invalid") from exc

    def snapshot(self) -> JsonObject:
        """Return a redacted, immutable-by-convention control-plane snapshot."""
        with self._lock:
            return {
                "dashboard": self._dashboard(),
                "runtime": json.loads(json.dumps(self._state["runtime"])),
                "claudeCode": json.loads(json.dumps(self._state["claudeCode"])),
                "lastSavedAt": self._state.get("lastSavedAt", _now()),
            }

    def save(self, value: object) -> JsonObject:
        """Validate and atomically persist a complete configuration replacement."""
        normalized = validate_configuration(value)
        with self._lock:
            normalized["lastSavedAt"] = _now()
            normalized["emergencyStop"] = self._emergency_stop
            self._persist(normalized)
            self._state = normalized
            return self.snapshot()

    def emergency_stop(self) -> JsonObject:
        """Activate the persistent stop state and return the critical dashboard."""
        with self._lock:
            self._emergency_stop = True
            self._state["emergencyStop"] = True
            self._persist(self._state)
            return self._dashboard()

    def _dashboard(self) -> JsonObject:
        """Build non-sensitive synthetic operational state for the reference API."""
        stopped = self._emergency_stop
        return {
            "generatedAt": _now(),
            "posture": "critical" if stopped else "healthy",
            "activeSessions": 0 if stopped else 1,
            "decisionsToday": 0,
            "deniedToday": 0,
            "approvalQueue": 0,
            "timedOutWorkers": 0,
            "emergencyStop": stopped,
            "agents": [],
            "recentAudit": [],
        }

    def _persist(self, value: Mapping[str, Any]) -> None:
        """Atomically replace the config file and fsync its contents."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
                json.dump(value, destination, indent=2, sort_keys=True)
                destination.write("\n")
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, self.path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


class ControlPlaneApplication:
    """Authenticated WSGI application implementing the UI HTTP contract."""

    def __init__(
        self,
        store: ControlPlaneStore,
        token: str,
        *,
        allowed_origin: str | None = "http://localhost:5173",
        max_body_bytes: int = 1_000_000,
    ) -> None:
        """Create an API requiring one configured bearer token per request."""
        if not token or len(token) < 16:
            raise ValueError("control-plane token must contain at least 16 characters")
        if max_body_bytes <= 0:
            raise ValueError("maximum request size must be positive")
        self.store = store
        self.token = token
        self.allowed_origin = allowed_origin
        self.max_body_bytes = max_body_bytes

    def __call__(
        self, environ: Mapping[str, Any], start_response: Callable[..., Any]
    ) -> list[bytes]:
        """Handle one bounded authenticated request."""
        origin = environ.get("HTTP_ORIGIN")
        cors = self._cors_headers(origin)
        method = environ.get("REQUEST_METHOD")
        if method == "OPTIONS":
            return self._respond(start_response, 204, {}, cors)
        if method not in {"GET", "PUT", "POST"}:
            return self._respond(start_response, 405, {"error": "method not allowed"}, cors)
        if not self._authorized(environ.get("HTTP_AUTHORIZATION")):
            return self._respond(start_response, 401, {"error": "authentication required"}, cors)

        path = str(environ.get("PATH_INFO", ""))
        try:
            if method == "GET" and path in {"/api/dashboard", "/dashboard"}:
                return self._respond(start_response, 200, self.store.snapshot()["dashboard"], cors)
            if method == "GET" and path in {"/api/configuration", "/configuration"}:
                return self._respond(start_response, 200, self.store.snapshot(), cors)
            if method == "POST" and path in {"/api/emergency-stop", "/emergency-stop"}:
                return self._respond(start_response, 200, self.store.emergency_stop(), cors)
            if method == "PUT" and path in {"/api/configuration", "/configuration"}:
                body = self._body(environ)
                return self._respond(start_response, 200, self.store.save(body), cors)
        except ControlPlaneConfigurationError as exc:
            return self._respond(start_response, 400, {"error": str(exc)}, cors)
        except (OSError, ValueError, json.JSONDecodeError):
            return self._respond(start_response, 400, {"error": "invalid JSON request"}, cors)
        return self._respond(start_response, 404, {"error": "endpoint not found"}, cors)

    def _body(self, environ: Mapping[str, Any]) -> JsonObject:
        """Read exactly one bounded JSON object from the WSGI body."""
        try:
            length = int(environ.get("CONTENT_LENGTH", "-1"))
        except (TypeError, ValueError) as exc:
            raise ControlPlaneConfigurationError("content length is required") from exc
        if length < 0 or length > self.max_body_bytes:
            raise ControlPlaneConfigurationError("request exceeds configured size limit")
        stream = environ.get("wsgi.input")
        if stream is None or not hasattr(stream, "read"):
            raise ControlPlaneConfigurationError("request body is required")
        raw = stream.read(length)
        if not isinstance(raw, bytes) or len(raw) != length:
            raise ControlPlaneConfigurationError("request body is incomplete")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ControlPlaneConfigurationError("request is not valid JSON") from exc
        return dict(_mapping(value, "request"))

    def _authorized(self, value: object) -> bool:
        """Accept only an exact bearer token; never accept credentials in JSON."""
        if not isinstance(value, str) or not value.startswith("Bearer "):
            return False
        supplied = value[7:].strip()
        return bool(supplied) and hmac.compare_digest(supplied, self.token)

    def _cors_headers(self, origin: object) -> list[tuple[str, str]]:
        """Allow only the explicitly configured development origin."""
        if self.allowed_origin is not None and origin == self.allowed_origin:
            return [
                ("Access-Control-Allow-Origin", self.allowed_origin),
                ("Access-Control-Allow-Headers", "Authorization, Content-Type"),
                ("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS"),
                ("Vary", "Origin"),
            ]
        return []

    @staticmethod
    def _respond(
        start_response: Callable[..., Any],
        status: int,
        value: JsonObject,
        headers: list[tuple[str, str]],
    ) -> list[bytes]:
        """Return a compact JSON response without leaking server internals."""
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        reason = {
            200: "OK",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            404: "Not Found",
            405: "Method Not Allowed",
        }.get(status, "Error")
        start_response(
            f"{status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body))), *headers],
        )
        return [] if status == 204 else [body]


__all__ = [
    "ControlPlaneApplication",
    "ControlPlaneConfigurationError",
    "ControlPlaneStore",
    "validate_configuration",
]

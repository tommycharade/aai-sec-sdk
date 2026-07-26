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
import re
import shlex
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

try:  # pragma: no cover - platform branch; control-plane reference targets Unix hosts.
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl equivalent in the stdlib.
    fcntl = None  # type: ignore[assignment]

from .audit import AuditSink

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
_COMMAND_EXECUTABLES: Final[frozenset[str]] = frozenset({"python", "python3"})
_SHELL_METACHARACTERS: Final[frozenset[str]] = frozenset(";&|<>$`")


class ControlPlaneConfigurationError(ValueError):
    """Raised when a UI configuration is malformed or unsafe."""


class ControlPlaneDependencyError(RuntimeError):
    """Raised when a live runtime or authoritative audit dependency is unavailable."""


@dataclass(frozen=True, slots=True)
class OperatorIdentity:
    """Authenticated control-plane operator identity and coarse-grained roles."""

    subject: str
    roles: frozenset[str]

    def __post_init__(self) -> None:
        """Reject ambiguous identities before authorization decisions."""
        if not self.subject.strip() or not self.roles:
            raise ValueError("operator identity requires a subject and at least one role")


class OperatorAuthenticator(Protocol):
    """Deployment-owned authentication and authorization boundary."""

    def authenticate(self, authorization: object) -> OperatorIdentity | None:
        """Authenticate a request header or return ``None`` without raising."""

    def authorize(self, identity: OperatorIdentity, action: str) -> bool:
        """Return whether the authenticated operator may perform ``action``."""


class StaticBearerAuthenticator:
    """Explicit localhost-only bearer authenticator for tests and development.

    Production services should implement :class:`OperatorAuthenticator` using
    their identity provider and short-lived operator sessions. This class is
    intentionally not a general production authentication system.
    """

    def __init__(self, credentials: Mapping[str, OperatorIdentity]) -> None:
        """Create a bounded token map without accepting empty credentials."""
        if not credentials or any(not token or len(token) < 16 for token in credentials):
            raise ValueError("static bearer credentials require tokens of at least 16 characters")
        self._credentials = dict(credentials)

    def authenticate(self, authorization: object) -> OperatorIdentity | None:
        """Compare bearer tokens without accepting alternate auth schemes."""
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None
        supplied = authorization[7:].strip()
        for token, identity in self._credentials.items():
            if hmac.compare_digest(supplied, token):
                return identity
        return None

    def authorize(self, identity: OperatorIdentity, action: str) -> bool:
        """Apply the reference role matrix for read, configuration, and stop actions."""
        if action == "read":
            return bool(identity.roles & {"viewer", "operator", "admin", "incident_commander"})
        if action == "configure":
            return bool(identity.roles & {"operator", "admin"})
        if action == "emergency_stop":
            return bool(identity.roles & {"incident_commander", "admin"})
        return False


class ControlPlaneAuthority(Protocol):
    """Application-owned authority that applies controls to live runtimes."""

    def apply_configuration(self, configuration: Mapping[str, Any]) -> None:
        """Atomically activate validated configuration or raise."""

    def emergency_stop(self) -> None:
        """Stop every runtime covered by this control-plane instance."""

    def clear_emergency_stop(self) -> None:
        """Clear the stop only after the deployment's incident controls allow it."""

    def status(self) -> Mapping[str, Any]:
        """Return non-sensitive live runtime status for the dashboard."""


@dataclass(frozen=True, slots=True)
class CallbackControlPlaneAuthority:
    """Adapter for an application-owned runtime registry and configuration manager.

    The SDK cannot safely reconstruct application tools, providers, identity,
    or credentials from browser JSON. Applications therefore provide these
    callbacks after validating the operator change in their own deployment.
    """

    apply_callback: Callable[[Mapping[str, Any]], None]
    stop_callback: Callable[[], None]
    clear_stop_callback: Callable[[], None]
    status_callback: Callable[[], Mapping[str, Any]]

    def apply_configuration(self, configuration: Mapping[str, Any]) -> None:
        """Delegate activation to the application-owned runtime manager."""
        self.apply_callback(configuration)

    def emergency_stop(self) -> None:
        """Delegate the kill switch to the live runtime registry."""
        self.stop_callback()

    def clear_emergency_stop(self) -> None:
        """Delegate controlled stop clearance to the application."""
        self.clear_stop_callback()

    def status(self) -> Mapping[str, Any]:
        """Return application-owned live runtime status."""
        return self.status_callback()


class InMemoryControlPlaneAuthority:
    """Synthetic authority for tests and the localhost reference runner only."""

    def __init__(self) -> None:
        """Create a non-production authority with observable state."""
        self._stopped = False
        self._configuration: JsonObject | None = None

    def apply_configuration(self, configuration: Mapping[str, Any]) -> None:
        """Record a validated configuration without executing application code."""
        self._configuration = json.loads(json.dumps(configuration))

    def emergency_stop(self) -> None:
        """Activate the synthetic stop state."""
        self._stopped = True

    def clear_emergency_stop(self) -> None:
        """Clear the synthetic stop state for tests only."""
        self._stopped = False

    def status(self) -> Mapping[str, Any]:
        """Return synthetic status and whether configuration was activated."""
        return {"stopped": self._stopped, "configuration_active": self._configuration is not None}


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


def _endpoint(value: object, name: str, *, required: bool = False) -> str:
    """Validate a provider endpoint without allowing embedded credentials."""
    text = _text(value, name)
    if required and not text.strip():
        raise ControlPlaneConfigurationError(f"{name} is required for the selected provider")
    if not text:
        return text
    parsed = urlsplit(text)
    if parsed.username or parsed.password:
        raise ControlPlaneConfigurationError(f"{name} must not contain embedded credentials")
    if parsed.scheme != "https":
        raise ControlPlaneConfigurationError(f"{name} must use HTTPS")
    return text


def _command(value: object, name: str) -> str:
    """Allow only an argv-like Python command, never a shell expression."""
    text = _text(value, name, allow_empty=False)
    if any(character in text for character in _SHELL_METACHARACTERS):
        raise ControlPlaneConfigurationError(f"{name} must not contain shell metacharacters")
    try:
        argv = shlex.split(text)
    except ValueError as exc:
        raise ControlPlaneConfigurationError(f"{name} is not a valid command") from exc
    if not argv or Path(argv[0]).name not in _COMMAND_EXECUTABLES:
        raise ControlPlaneConfigurationError(f"{name} must invoke python or python3 directly")
    if any(argument in {"-c", "--command", "-m"} for argument in argv[1:]):
        raise ControlPlaneConfigurationError(f"{name} must execute a file, not inline code")
    return text


def _pattern(value: str, name: str) -> str:
    """Validate bounded command matching syntax before it reaches ``re``."""
    if len(value) > 256:
        raise ControlPlaneConfigurationError(f"{name} pattern is too long")
    nested_quantifier = re.search(r"\([^)]*[+*][^)]*\)[+*]", value)
    if "\\1" in value or "(?" in value or nested_quantifier:
        raise ControlPlaneConfigurationError(f"{name} pattern uses unsupported backtracking syntax")
    try:
        re.compile(value)
    except re.error as exc:
        raise ControlPlaneConfigurationError(f"{name} pattern is invalid") from exc
    return value


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
    policy_endpoint = _endpoint(
        runtime["policyEndpoint"],
        "policyEndpoint",
        required=policy_provider in {"opa", "cedar"},
    )
    approval_endpoint = _endpoint(
        runtime["approvalEndpoint"],
        "approvalEndpoint",
        required=approval_provider == "http",
    )
    audit_replica_endpoint = _endpoint(
        runtime["auditReplicaEndpoint"],
        "auditReplicaEndpoint",
        required=audit_provider == "replicated",
    )
    credential_endpoint = _endpoint(
        runtime["credentialBrokerEndpoint"],
        "credentialBrokerEndpoint",
        required=bool(runtime.get("credentialsEnabled")),
    )
    if runtime.get("isolationRequiredForHighRisk") and isolation_verifier == "disabled":
        raise ControlPlaneConfigurationError(
            "high-risk isolation requires deployment attestation evidence"
        )

    max_rate = runtime["maxActionsPerSecond"]
    normalized_rate: float | None = (
        None if max_rate is None else _number(max_rate, "maxActionsPerSecond")
    )
    normalized_runtime: JsonObject = {
        "policyProvider": policy_provider,
        "approvalProvider": approval_provider,
        "auditProvider": audit_provider,
        "policyEndpoint": policy_endpoint,
        "approvalEndpoint": approval_endpoint,
        "auditPath": _text(runtime["auditPath"], "auditPath"),
        "auditReplicaEndpoint": audit_replica_endpoint,
        "credentialBrokerEndpoint": credential_endpoint,
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
        "hookCommand": _command(claude["hookCommand"], "claudeCode.hookCommand"),
        "hookConfigPath": _text(
            claude["hookConfigPath"], "claudeCode.hookConfigPath", allow_empty=False
        ),
        "mcpServerName": _text(
            claude["mcpServerName"], "claudeCode.mcpServerName", allow_empty=False
        ),
        "mcpGatewayCommand": _command(claude["mcpGatewayCommand"], "claudeCode.mcpGatewayCommand"),
        "allowedBuiltInTools": _list_of_text(
            claude["allowedBuiltInTools"], "claudeCode.allowedBuiltInTools"
        ),
        "deniedCommandPatterns": [
            _pattern(pattern, "claudeCode.deniedCommandPatterns")
            for pattern in _list_of_text(
                claude["deniedCommandPatterns"], "claudeCode.deniedCommandPatterns"
            )
        ],
        "approvalCommandPatterns": [
            _pattern(pattern, "claudeCode.approvalCommandPatterns")
            for pattern in _list_of_text(
                claude["approvalCommandPatterns"], "claudeCode.approvalCommandPatterns"
            )
        ],
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
        "configVersion": 1,
    }


class ControlPlaneStore:
    """Bounded JSON-backed state store for the UI control-plane adapter."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority: ControlPlaneAuthority | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        """Load state and optionally bind mutations to a live runtime authority."""
        self.path = Path(path)
        self.authority = authority
        self.audit = audit
        self._lock = RLock()
        self._emergency_stop = False
        self._state = self._load()
        self._reconcile_authority()

    def _load(self) -> JsonObject:
        """Load and validate persisted configuration; reject corruption."""
        if not self.path.exists():
            state = _default_configuration()
            self._persist(state)
            return state
        try:
            with self._file_lock():
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
            normalized["configVersion"] = _positive_int(
                value.get("configVersion", 1), "configVersion"
            )
            normalized["history"] = self._validate_history(value.get("history", []))
            return normalized
        except (OSError, json.JSONDecodeError, ControlPlaneConfigurationError) as exc:
            raise ControlPlaneConfigurationError("persisted UI configuration is invalid") from exc

    def snapshot(self) -> JsonObject:
        """Return a redacted, immutable-by-convention control-plane snapshot."""
        with self._lock:
            dashboard = self._dashboard()
            return {
                "dashboard": dashboard,
                "runtime": json.loads(json.dumps(self._state["runtime"])),
                "claudeCode": json.loads(json.dumps(self._state["claudeCode"])),
                "lastSavedAt": self._state.get("lastSavedAt", _now()),
                "configVersion": self._state.get("configVersion", 1),
                "history": [
                    {
                        "configVersion": entry["configVersion"],
                        "lastSavedAt": entry["lastSavedAt"],
                    }
                    for entry in self._state.get("history", [])
                ],
            }

    def save(self, value: object, *, actor_id: str = "control-plane-operator") -> JsonObject:
        """Activate and persist a complete replacement or fail closed.

        A browser write is never treated as an active security change unless
        the application-owned authority accepts it and an audit sink records
        the requested and activated transitions.
        """
        normalized = validate_configuration(value)
        with self._lock:
            self._require_mutation_dependencies()
            authority, audit = self._mutation_dependencies()
            version = int(self._state.get("configVersion", 1)) + 1
            audit.append(
                "control_plane_configuration_requested",
                f"config:{version}",
                {"actor_id": actor_id, "config_version": version},
            )
            authority.apply_configuration(normalized)
            history = list(self._state.get("history", []))
            history.append(self._history_entry(self._state))
            normalized["lastSavedAt"] = _now()
            normalized["emergencyStop"] = self._emergency_stop
            normalized["configVersion"] = version
            normalized["history"] = history[-20:]
            self._persist(normalized)
            self._state = normalized
            audit.append(
                "control_plane_configuration_activated",
                f"config:{version}",
                {"actor_id": actor_id, "config_version": version},
            )
            return self.snapshot()

    def rollback(self, version: int, *, actor_id: str = "control-plane-operator") -> JsonObject:
        """Activate one bounded prior version through the live authority."""
        if not isinstance(version, int) or isinstance(version, bool):
            raise ControlPlaneConfigurationError("rollback version must be an integer")
        with self._lock:
            self._require_mutation_dependencies()
            authority, audit = self._mutation_dependencies()
            entry = next(
                (
                    candidate
                    for candidate in self._state.get("history", [])
                    if candidate.get("configVersion") == version
                ),
                None,
            )
            if entry is None:
                raise ControlPlaneConfigurationError(
                    "requested configuration version is unavailable"
                )
            normalized = validate_configuration(
                {"runtime": entry["runtime"], "claudeCode": entry["claudeCode"]}
            )
            new_version = int(self._state.get("configVersion", 1)) + 1
            audit.append(
                "control_plane_configuration_rollback_requested",
                f"config:{new_version}",
                {
                    "actor_id": actor_id,
                    "config_version": new_version,
                    "rollback_from": version,
                },
            )
            authority.apply_configuration(normalized)
            history = list(self._state.get("history", []))
            history.append(self._history_entry(self._state))
            normalized["lastSavedAt"] = _now()
            normalized["emergencyStop"] = self._emergency_stop
            normalized["configVersion"] = new_version
            normalized["history"] = history[-20:]
            self._persist(normalized)
            self._state = normalized
            audit.append(
                "control_plane_configuration_rollback_activated",
                f"config:{new_version}",
                {
                    "actor_id": actor_id,
                    "config_version": new_version,
                    "rollback_from": version,
                },
            )
            return self.snapshot()

    def emergency_stop(self, *, actor_id: str = "control-plane-operator") -> JsonObject:
        """Stop the live authority before recording the persistent stop state."""
        with self._lock:
            self._require_mutation_dependencies()
            authority, audit = self._mutation_dependencies()
            audit.append(
                "control_plane_emergency_stop_requested",
                "control-plane",
                {"actor_id": actor_id},
            )
            authority.emergency_stop()
            self._emergency_stop = True
            self._state["emergencyStop"] = True
            self._persist(self._state)
            audit.append(
                "control_plane_emergency_stop_activated",
                "control-plane",
                {"actor_id": actor_id},
            )
            return self._dashboard()

    def _require_mutation_dependencies(self) -> None:
        """Reject reference-only mutation when live authority or audit is absent."""
        if self.authority is None:
            raise ControlPlaneDependencyError("live runtime authority is required for mutation")
        if self.audit is None:
            raise ControlPlaneDependencyError("audit sink is required for mutation")

    def _mutation_dependencies(self) -> tuple[ControlPlaneAuthority, AuditSink]:
        """Return dependencies after the fail-closed mutation check."""
        if self.authority is None or self.audit is None:
            raise ControlPlaneDependencyError("live mutation dependencies are unavailable")
        return self.authority, self.audit

    def _reconcile_authority(self) -> None:
        """Restore persisted controls into the live authority before serving reads.

        A restart must not leave the dashboard reporting durable policy while the
        runtime still has its pre-restart configuration. Failure to reconcile is
        fatal to startup so the deployment cannot silently run stale controls.
        """
        if self.authority is None:
            return
        try:
            self.authority.apply_configuration(self._state)
            if self._emergency_stop:
                self.authority.emergency_stop()
        except (OSError, RuntimeError) as exc:
            raise ControlPlaneDependencyError(
                "persisted control-plane state could not be applied to the live runtime"
            ) from exc

    @staticmethod
    def _history_entry(state: Mapping[str, Any]) -> JsonObject:
        """Copy only validated configuration data into bounded history."""
        return {
            "configVersion": state.get("configVersion", 1),
            "lastSavedAt": state.get("lastSavedAt", _now()),
            "runtime": json.loads(json.dumps(state["runtime"])),
            "claudeCode": json.loads(json.dumps(state["claudeCode"])),
        }

    @staticmethod
    def _validate_history(value: object) -> list[JsonObject]:
        """Validate persisted rollback entries and cap their count."""
        if not isinstance(value, list) or len(value) > 20:
            raise ControlPlaneConfigurationError("configuration history is invalid or unbounded")
        history: list[JsonObject] = []
        for entry in value:
            item = _mapping(entry, "configuration history entry")
            version = _positive_int(item.get("configVersion"), "history.configVersion")
            timestamp = _text(item.get("lastSavedAt"), "history.lastSavedAt", allow_empty=False)
            configuration = validate_configuration(
                {"runtime": item.get("runtime"), "claudeCode": item.get("claudeCode")}
            )
            history.append(
                {
                    "configVersion": version,
                    "lastSavedAt": timestamp,
                    **configuration,
                }
            )
        return history

    def _dashboard(self) -> JsonObject:
        """Build non-sensitive synthetic operational state for the reference API."""
        stopped = self._emergency_stop
        authority_status: Mapping[str, Any] = {}
        if self.authority is not None:
            authority_status = self.authority.status()
            stopped = stopped or bool(authority_status.get("stopped", False))
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
            "runtimeStatus": dict(authority_status),
        }

    def _persist(self, value: Mapping[str, Any]) -> None:
        """Atomically replace the config file and fsync its contents."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._file_lock():
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{self.path.name}.", dir=self.path.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
                    os.chmod(temporary, 0o600)
                    json.dump(value, destination, indent=2, sort_keys=True)
                    destination.write("\n")
                    destination.flush()
                    os.fsync(destination.fileno())
                os.replace(temporary, self.path)
                os.chmod(self.path, 0o600)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        """Serialize multi-process config reads and writes on Unix hosts."""
        if fcntl is None:
            raise ControlPlaneDependencyError("control-plane file locking is unavailable")
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class ControlPlaneApplication:
    """Authenticated WSGI application implementing the UI HTTP contract."""

    def __init__(
        self,
        store: ControlPlaneStore,
        token: str | None = None,
        *,
        authenticator: OperatorAuthenticator | None = None,
        allowed_origin: str | None = "http://localhost:5173",
        max_body_bytes: int = 1_000_000,
    ) -> None:
        """Create an API with deployment-owned operator authentication.

        ``token`` is retained only as a localhost reference shortcut. Supply
        ``authenticator`` for every deployed service so requests carry a
        verified operator identity and role rather than a shared admin token.
        """
        if authenticator is not None and token is not None:
            raise ValueError("provide authenticator or token, not both")
        if authenticator is None:
            if not token or len(token) < 16:
                raise ValueError("control-plane token must contain at least 16 characters")
            if allowed_origin not in {"http://localhost:5173", "http://127.0.0.1:5173"}:
                raise ValueError("static bearer authentication is permitted only for localhost")
            authenticator = StaticBearerAuthenticator(
                {token: OperatorIdentity("local-operator", frozenset({"admin"}))}
            )
        if max_body_bytes <= 0:
            raise ValueError("maximum request size must be positive")
        self.store = store
        self.authenticator = authenticator
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
        identity = self.authenticator.authenticate(environ.get("HTTP_AUTHORIZATION"))
        if identity is None:
            return self._respond(start_response, 401, {"error": "authentication required"}, cors)

        path = str(environ.get("PATH_INFO", ""))
        try:
            if method == "GET" and path in {"/api/dashboard", "/dashboard"}:
                if not self.authenticator.authorize(identity, "read"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                return self._respond(start_response, 200, self.store.snapshot()["dashboard"], cors)
            if method == "GET" and path in {"/api/configuration", "/configuration"}:
                if not self.authenticator.authorize(identity, "read"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                return self._respond(start_response, 200, self.store.snapshot(), cors)
            if method == "POST" and path in {"/api/emergency-stop", "/emergency-stop"}:
                if not self.authenticator.authorize(identity, "emergency_stop"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                return self._respond(
                    start_response, 200, self.store.emergency_stop(actor_id=identity.subject), cors
                )
            if method == "PUT" and path in {"/api/configuration", "/configuration"}:
                if not self.authenticator.authorize(identity, "configure"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                body = self._body(environ)
                return self._respond(
                    start_response, 200, self.store.save(body, actor_id=identity.subject), cors
                )
            if method == "POST" and path in {
                "/api/configuration/rollback",
                "/configuration/rollback",
            }:
                if not self.authenticator.authorize(identity, "configure"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                body = self._body(environ)
                version = body.get("configVersion")
                if not isinstance(version, int) or isinstance(version, bool):
                    raise ControlPlaneConfigurationError(
                        "rollback configVersion must be an integer"
                    )
                return self._respond(
                    start_response,
                    200,
                    self.store.rollback(version, actor_id=identity.subject),
                    cors,
                )
        except ControlPlaneConfigurationError as exc:
            return self._respond(start_response, 400, {"error": str(exc)}, cors)
        except (ControlPlaneDependencyError, OSError, RuntimeError) as exc:
            return self._respond(start_response, 503, {"error": str(exc)}, cors)
        except ValueError:
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
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            503: "Service Unavailable",
        }.get(status, "Error")
        start_response(
            f"{status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body))), *headers],
        )
        return [] if status == 204 else [body]


__all__ = [
    "ControlPlaneApplication",
    "ControlPlaneAuthority",
    "ControlPlaneDependencyError",
    "ControlPlaneConfigurationError",
    "ControlPlaneStore",
    "InMemoryControlPlaneAuthority",
    "OperatorAuthenticator",
    "OperatorIdentity",
    "StaticBearerAuthenticator",
    "validate_configuration",
]

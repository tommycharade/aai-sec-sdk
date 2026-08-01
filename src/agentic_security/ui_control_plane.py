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

import base64
import hmac
import json
import math
import os
import re
import secrets
import shlex
import ssl
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any, Final, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

import certifi

from ._command_patterns import compile_command_patterns
from .agent_sessions import AgentSessionCredential, AgentSessionStore
from .audit import AuditEvent, AuditSink
from .integrations import AgentHost
from .managed_configuration import ManagedConfigurationEvidence, ManagedPlatform
from .managed_deployment import ManagedDeploymentPackage
from .runtime_attestation import RuntimeAttestor
from .signed_policy import (
    PolicyBundleVerificationError,
    PolicyTrustStore,
    SignedPolicyBundle,
)

try:  # pragma: no cover - platform branch; control-plane reference targets Unix hosts.
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl equivalent in the stdlib.
    fcntl = None  # type: ignore[assignment]

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

JsonObject = dict[str, Any]


def _open_https(request: Request, timeout: float) -> Any:
    """Open an HTTPS request with the packaged Mozilla CA bundle."""
    return urlopen(  # noqa: S310 - callers validate the endpoint scheme.
        request,
        timeout=timeout,
        context=ssl.create_default_context(cafile=certifi.where()),
    )


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
        "allowedCommandPatterns",
        "fileTools",
    }
)
_CLAUDE_OPTIONAL_KEYS: Final[frozenset[str]] = frozenset({"allowedCommandPatterns"})
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
        if action in {"agent_register", "agent_heartbeat", "agent_disconnect"}:
            return bool(identity.roles & {"agent", "admin"})
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


@dataclass(slots=True)
class AgentPresence:
    """Authenticated Claude Code or Codex CLI presence tracked by the control plane."""

    agent_id: str
    host: str
    project_root: str
    principal_id: str
    session_id: str
    connected_at: float
    last_heartbeat: float
    expires_at: float
    status: str = "connected"


class AgentPresenceStore:
    """Bounded live agent registry with heartbeat expiry and audit events."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 90,
        clock: Callable[[], float] = time.time,
        audit: AuditSink | None = None,
        max_agents: int = 1_000,
    ) -> None:
        """Create a registry that fails closed when heartbeats expire."""
        if ttl_seconds <= 0 or max_agents <= 0:
            raise ValueError("agent presence limits must be positive")
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self.audit = audit
        self.max_agents = max_agents
        self._agents: dict[str, AgentPresence] = {}
        self._lock = RLock()

    def register(
        self,
        *,
        agent_id: str,
        host: str,
        project_root: str,
        principal_id: str,
        actor_id: str,
    ) -> JsonObject:
        """Register one authenticated agent and return its opaque session."""
        self._validate_text(agent_id, "agent_id")
        self._validate_text(host, "host")
        self._validate_text(project_root, "project_root")
        self._validate_text(principal_id, "principal_id")
        self._validate_text(actor_id, "actor_id")
        with self._lock:
            self.reap()
            if agent_id not in self._agents and len(self._agents) >= self.max_agents:
                raise ControlPlaneDependencyError("agent presence capacity is exhausted")
            now = self.clock()
            previous = self._agents.get(agent_id)
            if previous is not None and previous.status == "connected":
                self._audit("agent_disconnected", previous.agent_id, {"reason": "replaced"})
            presence = AgentPresence(
                agent_id=agent_id,
                host=host,
                project_root=project_root,
                principal_id=principal_id,
                session_id=secrets.token_urlsafe(24),
                connected_at=now,
                last_heartbeat=now,
                expires_at=now + self.ttl_seconds,
            )
            self._agents[agent_id] = presence
            self._audit(
                "agent_registered",
                agent_id,
                {"actor_id": actor_id, "host": host, "project_root": project_root},
            )
            return self._snapshot_entry(presence, include_session=True)

    def heartbeat(self, *, agent_id: str, session_id: str, actor_id: str) -> JsonObject:
        """Refresh one session only when its opaque registration token matches."""
        self._validate_text(agent_id, "agent_id")
        self._validate_text(session_id, "session_id")
        self._validate_text(actor_id, "actor_id")
        with self._lock:
            self.reap()
            presence = self._agents.get(agent_id)
            if presence is None or presence.status != "connected":
                raise ControlPlaneConfigurationError("agent session is not connected")
            if not hmac.compare_digest(presence.session_id, session_id):
                raise ControlPlaneConfigurationError("agent session is invalid")
            now = self.clock()
            presence.last_heartbeat = now
            presence.expires_at = now + self.ttl_seconds
            self._audit("agent_heartbeat", agent_id, {"actor_id": actor_id})
            return self._snapshot_entry(presence, include_session=True)

    def reap(self) -> int:
        """Mark expired sessions offline and audit each lifecycle transition."""
        now = self.clock()
        expired = 0
        for presence in self._agents.values():
            if presence.status == "connected" and presence.expires_at <= now:
                presence.status = "offline"
                expired += 1
                self._audit(
                    "agent_disconnected", presence.agent_id, {"reason": "heartbeat_expired"}
                )
        return expired

    def disconnect(self, *, agent_id: str, session_id: str, actor_id: str) -> JsonObject:
        """Mark a matching session offline and record an explicit disconnect."""
        self._validate_text(agent_id, "agent_id")
        self._validate_text(session_id, "session_id")
        self._validate_text(actor_id, "actor_id")
        with self._lock:
            presence = self._agents.get(agent_id)
            if presence is None or presence.status != "connected":
                raise ControlPlaneConfigurationError("agent session is not connected")
            if not hmac.compare_digest(presence.session_id, session_id):
                raise ControlPlaneConfigurationError("agent session is invalid")
            presence.status = "offline"
            self._audit("agent_disconnected", agent_id, {"actor_id": actor_id, "reason": "client"})
            return self._snapshot_entry(presence, include_session=True)

    def snapshot(self) -> list[JsonObject]:
        """Return bounded, non-secret agent presence records."""
        with self._lock:
            self.reap()
            return [self._snapshot_entry(presence) for presence in self._agents.values()]

    def _audit(self, event_type: str, subject: str, metadata: Mapping[str, Any]) -> None:
        """Record lifecycle evidence without exposing the session bearer."""
        if self.audit is not None:
            self.audit.append(event_type, subject, dict(metadata))

    @staticmethod
    def _validate_text(value: str, name: str) -> None:
        """Reject empty or oversized identity and project metadata."""
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise ControlPlaneConfigurationError(f"{name} must be bounded non-empty text")

    @staticmethod
    def _snapshot_entry(presence: AgentPresence, *, include_session: bool = False) -> JsonObject:
        """Expose status metadata and return the bearer only to its agent."""
        snapshot: JsonObject = {
            "id": presence.agent_id,
            "name": (
                f"{presence.host} / {Path(presence.project_root).name or presence.project_root}"
            ),
            "host": presence.host,
            "projectRoot": presence.project_root,
            "principalId": presence.principal_id,
            "connectedAt": datetime.fromtimestamp(presence.connected_at, UTC).isoformat(),
            "lastHeartbeat": datetime.fromtimestamp(presence.last_heartbeat, UTC).isoformat(),
            "expiresAt": datetime.fromtimestamp(presence.expires_at, UTC).isoformat(),
            "status": presence.status,
            "lastSeen": datetime.fromtimestamp(presence.last_heartbeat, UTC).isoformat(),
            "tools": 0,
        }
        if include_session:
            snapshot["sessionId"] = presence.session_id
        return snapshot


class ControlPlaneAgentClient:
    """Minimal authenticated client for an MCP process presence lifecycle."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        agent_id: str,
        project_root: str,
        deployment_id: str | None = None,
        aws_agent_session: bool = False,
        session_store: AgentSessionStore | None = None,
        attestor: RuntimeAttestor | None = None,
        managed_configuration_provider: Callable[[], ManagedConfigurationEvidence] | None = None,
        policy_trust_store: PolicyTrustStore | None = None,
        tenant_id: str | None = None,
        host: AgentHost | str = AgentHost.CLAUDE_CODE,
        timeout_seconds: float = 5,
    ) -> None:
        """Bind one agent token to one explicit project and host registration.

        ``session_store`` is an optional user-private host cache used to share
        heartbeat rotations with short-lived native hook processes. It never
        supplies identity or authority and performs no I/O in this constructor.
        ``attestor`` measures the live host only after an authenticated AWS
        session obtains a one-time challenge; it makes no network call itself.
        ``managed_configuration_provider`` must be a deployment-owned callback
        that re-measures administrator-owned host files for every heartbeat.
        The client accepts only typed evidence for its bound host identity.
        ``policy_trust_store`` and ``tenant_id`` are deployment-owned trust
        context used to verify AWS policy bundles before they become runtime
        authority. They are required when :meth:`effective_policy` is called
        for an AWS agent session, but heartbeat-only clients may omit them.
        """
        parsed = urlsplit(base_url.rstrip("/"))
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        if not parsed.hostname or parsed.scheme != "https" and not local_http:
            raise ValueError("control-plane agent URL must use HTTPS outside localhost")
        if (
            not token
            or len(token) < 16
            or not agent_id
            or not project_root
            or not Path(project_root).is_absolute()
        ):
            raise ValueError("agent client requires a token, agent ID, and project root")
        if timeout_seconds <= 0:
            raise ValueError("agent client timeout must be positive")
        try:
            self.host = host if isinstance(host, AgentHost) else AgentHost(host)
        except ValueError as exc:
            raise ValueError("agent client host is not supported") from exc
        normalized_project_root = str(Path(project_root).resolve(strict=False))
        if normalized_project_root == Path(normalized_project_root).anchor:
            raise ValueError("agent client project root must not be the filesystem root")
        if session_store is not None and (
            not aws_agent_session
            or deployment_id is None
            or session_store.base_url != base_url.rstrip("/")
            or session_store.deployment_id != deployment_id
            or session_store.agent_id != agent_id
            or session_store.project_root != normalized_project_root
        ):
            raise ValueError("agent session store identity must match the AWS agent client")
        if attestor is not None and not aws_agent_session:
            raise ValueError("runtime attestation requires an AWS agent session")
        if managed_configuration_provider is not None and not aws_agent_session:
            raise ValueError("managed configuration evidence requires an AWS agent session")
        if (policy_trust_store is None) != (tenant_id is None):
            raise ValueError("policy trust store and tenant ID must be supplied together")
        if policy_trust_store is not None and not aws_agent_session:
            raise ValueError("signed policy trust context requires an AWS agent session")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.agent_id = agent_id
        self.project_root = normalized_project_root
        self.project_root_digest = sha256(self.project_root.encode("utf-8")).hexdigest()
        self.deployment_id = deployment_id
        self.aws_agent_session = aws_agent_session
        self.session_store = session_store
        self.attestor = attestor
        self.managed_configuration_provider = managed_configuration_provider
        self.policy_trust_store = policy_trust_store
        self.tenant_id = tenant_id
        self.timeout_seconds = timeout_seconds

    def register(self) -> str:
        """Register the MCP process and return its opaque heartbeat session."""
        if self.aws_agent_session:
            # The AWS enrollment exchange has already consumed a one-time
            # bootstrap secret and issued this bearer session. Do not replay
            # enrollment or send an AWS agent token to the operator route. An
            # immediate heartbeat proves that the running MCP process, rather
            # than enrollment alone, is present before it serves tools.
            self.heartbeat(self.token)
            return self.token
        response = self._request(
            "/enterprise/agents/register" if self.deployment_id else "/agents/register",
            {
                "agentId": self.agent_id,
                "host": self.host.value,
                "projectRoot": self.project_root,
                **({"deploymentId": self.deployment_id} if self.deployment_id else {}),
            },
        )
        session_id = response.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise ControlPlaneDependencyError("control plane returned no agent session")
        return session_id

    def heartbeat(
        self,
        session_id: str,
        telemetry: Mapping[str, int | float] | None = None,
    ) -> JsonObject:
        """Refresh presence and optionally report bounded aggregate metrics.

        Telemetry is operational evidence only. It cannot alter identity,
        policy, approvals, credentials, or execution state, and the client
        rejects unknown or unbounded fields before they leave the host.
        """
        body: JsonObject = {"sessionId": session_id}
        if telemetry is not None:
            body["telemetry"] = _bounded_agent_telemetry(telemetry)
        if self.managed_configuration_provider is not None:
            evidence = self.managed_configuration_provider()
            if not isinstance(evidence, ManagedConfigurationEvidence):
                raise ControlPlaneConfigurationError(
                    "managed configuration provider returned invalid evidence"
                )
            if evidence.host is not self.host:
                raise ControlPlaneConfigurationError(
                    "managed configuration evidence does not match the agent host"
                )
            body["managedConfiguration"] = evidence.to_wire()
        if self.attestor is not None:
            challenge = self._request(self._agent_path("attestation/challenge"), {})
            nonce = challenge.get("nonce")
            if not isinstance(nonce, str) or not 32 <= len(nonce) <= 256:
                raise ControlPlaneDependencyError(
                    "control plane returned no valid runtime attestation challenge"
                )
            body["attestation"] = self.attestor.attest(nonce).to_wire()
        response = self._request(self._agent_path("heartbeat"), body)
        refreshed = response.get("accessToken")
        if isinstance(refreshed, str) and len(refreshed) >= 16:
            self.token = refreshed
        if self.session_store is not None:
            expires_at = response.get("expiresAt")
            if isinstance(expires_at, bool) or not isinstance(expires_at, int):
                raise ControlPlaneDependencyError(
                    "control-plane heartbeat returned no valid session expiry"
                )
            try:
                self.session_store.save(AgentSessionCredential(self.token, expires_at))
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise ControlPlaneDependencyError(
                    "rotated agent session could not be secured on this host"
                ) from exc
        if self.aws_agent_session:
            control_state = response.get("controlState")
            if not isinstance(control_state, Mapping) or not isinstance(
                control_state.get("executionAllowed"), bool
            ):
                raise ControlPlaneDependencyError(
                    "control-plane heartbeat returned no valid execution authority state"
                )
            if control_state["executionAllowed"] is False:
                # The heartbeat has already delivered fresh evidence. Failing
                # after that boundary lets incident response retain visibility
                # while preventing the caller from continuing normal service.
                raise ControlPlaneDependencyError(
                    "server-owned response control withholds agent execution"
                )
        return response

    def report_decision(
        self,
        *,
        decision_id: str,
        source: str,
        tool_name: str,
        decision: str,
        resource_kind: str,
        reason_code: str,
        action_digest: str | None = None,
    ) -> JsonObject:
        """Report one content-minimised decision from this enrolled process.

        This is authenticated operational evidence, not authorization input.
        The API deliberately excludes prompts, tool arguments, command text,
        paths, outputs, principals and policy claims; the server binds the
        report to the live session and derives tenant/policy metadata itself.
        """
        if not self.aws_agent_session or not self.deployment_id:
            raise ControlPlaneDependencyError(
                "decision reporting requires an enrolled AWS agent session"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", decision_id):
            raise ControlPlaneConfigurationError("decision ID must be a SHA-256 event digest")
        if action_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", action_digest):
            raise ControlPlaneConfigurationError("decision action digest must be SHA-256")
        vocabularies = {
            "source": ({"claude_native", "codex_native", "mcp", "sdk_runtime"}, source),
            "decision": ({"allowed", "denied", "approval_required"}, decision),
            "resource kind": (
                {"project_file", "shell_command", "mcp_tool", "sdk_tool", "unknown"},
                resource_kind,
            ),
            "reason code": (
                {
                    "explicit_allow",
                    "deny_by_default",
                    "blocked_command",
                    "outside_project",
                    "approval_rule",
                    "invalid_configuration",
                    "audit_failure",
                    "policy_error",
                },
                reason_code,
            ),
        }
        for name, (allowed, value) in vocabularies.items():
            if value not in allowed:
                raise ControlPlaneConfigurationError(f"decision {name} is unsupported")
        if not isinstance(tool_name, str) or not tool_name.strip() or len(tool_name) > 128:
            raise ControlPlaneConfigurationError(
                "decision tool name must be non-empty text up to 128 characters"
            )
        report = {
            "decisionId": decision_id,
            "source": source,
            "toolName": tool_name.strip(),
            "decision": decision,
            "resourceKind": resource_kind,
            "reasonCode": reason_code,
        }
        if action_digest is not None:
            report["actionDigest"] = action_digest
        response = self._request(self._agent_path("decisions"), report)
        if response.get("accepted") is not True:
            raise ControlPlaneDependencyError("control plane did not acknowledge decision evidence")
        return response

    def disconnect(self, session_id: str) -> JsonObject:
        """Mark the agent offline during an orderly MCP process shutdown."""
        if self.aws_agent_session:
            # The AWS presence record expires conservatively after missed
            # heartbeats; there is intentionally no agent-authorized stop or
            # disconnect mutation on this route.
            return {"status": "disconnect_pending_expiry"}
        return self._request(self._agent_path("disconnect"), {"sessionId": session_id})

    def effective_policy(self) -> JsonObject:
        """Fetch the authenticated agent's centrally assigned policy.

        A deployment should call this after registration and before serving
        tools. Missing or conflicting group policy is a dependency failure and
        must prevent the runtime from starting.
        """
        if not self.deployment_id:
            raise ControlPlaneDependencyError(
                "effective policy requires a deployment-scoped agent client"
            )
        request = Request(  # noqa: S310 - URL scheme is validated above.
            f"{self.base_url}{self._agent_path('effective-policy')}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                **(
                    {"X-AAI-Project-Root-Digest": self.project_root_digest}
                    if self.aws_agent_session
                    else {}
                ),
            },
            method="GET",
        )
        try:
            with _open_https(request, self.timeout_seconds) as response:
                value = json.loads(response.read(1_000_000))
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
            raise ControlPlaneDependencyError("effective policy lookup failed") from exc
        response = dict(_mapping(value, "effective policy response"))
        if self.aws_agent_session:
            if self.policy_trust_store is None or self.tenant_id is None:
                raise ControlPlaneDependencyError(
                    "AWS effective policy requires deployment-pinned signing trust"
                )
            try:
                bundle = SignedPolicyBundle.from_wire(response.get("policyBundle"))
                verified = self.policy_trust_store.verify(bundle, expected_tenant_id=self.tenant_id)
            except PolicyBundleVerificationError as exc:
                raise ControlPlaneDependencyError(
                    "effective policy signature verification failed"
                ) from exc
            emergency_stop = response.get("emergencyStop", False)
            if not isinstance(emergency_stop, bool):
                raise ControlPlaneDependencyError(
                    "effective policy returned invalid emergency-stop state"
                )
            return {
                "emergencyStop": emergency_stop,
                "policy": {
                    "id": verified.policy_id,
                    "version": verified.version,
                    "configuration": dict(verified.configuration),
                    "integrity": {
                        "status": "verified",
                        "contentHash": verified.content_hash,
                        "keyId": verified.key_id,
                        "algorithm": verified.algorithm,
                        "signedAt": verified.signed_at,
                    },
                },
            }
        return response

    def managed_deployment_package(
        self, *, platform: ManagedPlatform | str
    ) -> ManagedDeploymentPackage:
        """Fetch and verify the current rollout-selected endpoint package.

        The endpoint response is authenticated transport metadata, not trusted
        Python state. This method verifies its exact schema, bounded canonical
        bytes, out-of-band digest, agent identity, host, platform, bundle and
        package metadata before returning a typed package. It performs no file
        writes and does not invoke the privileged installer.
        """
        if not self.deployment_id:
            raise ControlPlaneDependencyError(
                "managed package requires a deployment-scoped agent client"
            )
        try:
            expected_platform = (
                platform if isinstance(platform, ManagedPlatform) else ManagedPlatform(platform)
            )
        except ValueError as exc:
            raise ControlPlaneConfigurationError("managed package platform is unsupported") from exc
        request = Request(  # noqa: S310 - URL scheme is validated above.
            f"{self.base_url}{self._agent_path('managed-package')}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                **(
                    {"X-AAI-Project-Root-Digest": self.project_root_digest}
                    if self.aws_agent_session
                    else {}
                ),
            },
            method="GET",
        )
        try:
            with _open_https(request, self.timeout_seconds) as response:
                value = json.loads(response.read(1_000_000))
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
            raise ControlPlaneDependencyError("managed package lookup failed") from exc
        result = dict(_mapping(value, "managed package response"))
        fields = {
            "schemaVersion",
            "deploymentId",
            "agentId",
            "revision",
            "status",
            "packageSha256",
            "bundleHash",
            "host",
            "hostVersion",
            "platform",
            "policyId",
            "policyVersion",
            "publishedAt",
            "publishedBy",
            "packageBase64",
        }
        if set(result) != fields or result.get("schemaVersion") != 1:
            raise ControlPlaneDependencyError("managed package response schema is invalid")
        if (
            result.get("deploymentId") != self.deployment_id
            or result.get("agentId") != self.agent_id
            or result.get("status") != "current"
            or isinstance(result.get("revision"), bool)
            or not isinstance(result.get("revision"), int)
            or result["revision"] <= 0
        ):
            raise ControlPlaneDependencyError("managed package response identity is invalid")
        encoded_value = result.get("packageBase64")
        if not isinstance(encoded_value, str) or len(encoded_value) > 410_000:
            raise ControlPlaneDependencyError("managed package content is invalid")
        try:
            encoded = base64.b64decode(encoded_value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ControlPlaneDependencyError("managed package content is invalid") from exc
        digest = result.get("packageSha256")
        bundle_hash = result.get("bundleHash")
        if not isinstance(digest, str) or not isinstance(bundle_hash, str):
            raise ControlPlaneDependencyError("managed package digests are invalid")
        try:
            package = ManagedDeploymentPackage.from_json(encoded, expected_package_sha256=digest)
            package.require_target(
                host=self.host, platform=expected_platform, bundle_hash=bundle_hash
            )
        except (TypeError, ValueError) as exc:
            raise ControlPlaneDependencyError("managed package verification failed") from exc
        metadata = {
            "host": package.host.value,
            "hostVersion": package.host_version,
            "platform": package.platform.value,
            "policyId": package.policy_id,
            "policyVersion": package.policy_version,
            "bundleHash": package.bundle_hash,
            "packageSha256": package.package_sha256,
        }
        if any(result.get(key) != expected for key, expected in metadata.items()):
            raise ControlPlaneDependencyError("managed package metadata does not match content")
        return package

    def request_approval(
        self,
        *,
        approval_id: str,
        tool_name: str,
        proposal_id: str,
        task_id: str,
        principal_id: str,
        action_hash: str,
        risk_class: str = "unspecified",
        resource_ids: tuple[str, ...] = (),
        review_ttl_seconds: int = 900,
        grant_ttl_seconds: int = 120,
    ) -> JsonObject:
        """Submit one exact-action request to the central operator queue.

        The agent bearer supplies deployment and agent identity. The caller
        supplies only the runtime-owned approval binding and bounded resource
        identifiers; tool arguments, outputs, prompts, and credentials must
        never be placed in this request. Submission grants no authority. A
        separate authorized operator decision is required before the matching
        approval provider can consume the grant once.

        Raises:
            ControlPlaneConfigurationError: If a field is malformed or exceeds
                the content-minimised request bounds.
            ControlPlaneDependencyError: If this is not an AWS enrolled-agent
                session or the control plane does not durably accept the
                request.
        """
        if not self.aws_agent_session or not self.deployment_id:
            raise ControlPlaneDependencyError(
                "central approval requests require an enrolled AWS agent session"
            )

        def bounded(value: str, name: str, maximum: int = 256) -> str:
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise ControlPlaneConfigurationError(
                    f"{name} must be non-empty text up to {maximum} characters"
                )
            return value.strip()

        allowed_risks = {
            "write",
            "destructive",
            "external_egress",
            "code_execution",
            "secret_read",
            "unspecified",
        }
        if risk_class not in allowed_risks:
            raise ControlPlaneConfigurationError("approval risk class is unsupported")
        if not isinstance(resource_ids, tuple) or len(resource_ids) > 20:
            raise ControlPlaneConfigurationError(
                "approval resource IDs must be a tuple of at most 20 identifiers"
            )
        resources = [bounded(value, "resource ID") for value in resource_ids]
        if (
            isinstance(review_ttl_seconds, bool)
            or not isinstance(review_ttl_seconds, int)
            or not 60 <= review_ttl_seconds <= 3600
        ):
            raise ControlPlaneConfigurationError(
                "approval review TTL must be between 60 and 3600 seconds"
            )
        if (
            isinstance(grant_ttl_seconds, bool)
            or not isinstance(grant_ttl_seconds, int)
            or not 1 <= grant_ttl_seconds <= 600
        ):
            raise ControlPlaneConfigurationError(
                "approval grant TTL must be between 1 and 600 seconds"
            )
        return self._request(
            self._agent_path("approvals/request"),
            {
                "approval_id": bounded(approval_id, "approval ID"),
                "tool_name": bounded(tool_name, "tool name"),
                "proposal_id": bounded(proposal_id, "proposal ID"),
                "task_id": bounded(task_id, "task ID"),
                "principal_id": bounded(principal_id, "principal ID"),
                "action_hash": bounded(action_hash, "action hash", 128),
                "risk_class": risk_class,
                "resource_ids": resources,
                "review_ttl_seconds": review_ttl_seconds,
                "grant_ttl_seconds": grant_ttl_seconds,
            },
        )

    def _agent_path(self, action: str) -> str:
        """Build a deployment-scoped or legacy agent lifecycle path."""
        if self.aws_agent_session:
            if not self.deployment_id:
                raise ControlPlaneDependencyError(
                    "AWS agent session requires a deployment identifier"
                )
            return (
                f"/agent/{quote(self.deployment_id, safe='')}/"
                f"{quote(self.agent_id, safe='')}/{action}"
            )
        if self.deployment_id:
            return (
                f"/enterprise/agents/{quote(self.deployment_id, safe='')}/"
                f"{quote(self.agent_id, safe='')}/{action}"
            )
        return f"/agents/{quote(self.agent_id, safe='')}/{action}"

    def _request(self, path: str, body: JsonObject) -> JsonObject:
        """Send one bounded JSON request without logging the bearer token."""
        if self.aws_agent_session and path.endswith("/heartbeat"):
            request = Request(  # noqa: S310 - URL scheme is validated above.
                f"{self.base_url}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "X-AAI-Project-Root-Digest": self.project_root_digest,
                },
                method="POST",
            )
            try:
                with _open_https(request, self.timeout_seconds) as response:
                    value = json.loads(response.read(1_000_000))
            except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
                raise ControlPlaneDependencyError("control-plane heartbeat failed") from exc
            return dict(_mapping(value, "control-plane heartbeat response"))
        request = Request(  # noqa: S310 - URL scheme is validated above.
            f"{self.base_url}{path}",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                **(
                    {"X-AAI-Project-Root-Digest": self.project_root_digest}
                    if self.aws_agent_session
                    else {}
                ),
            },
            method="POST",
        )
        try:
            with _open_https(request, self.timeout_seconds) as response:
                value = json.loads(response.read(1_000_000))
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
            raise ControlPlaneDependencyError("control-plane agent request failed") from exc
        return dict(_mapping(value, "control-plane agent response"))


class ControlPlaneDecisionExporter:
    """Export redacted decision metadata through an enrolled agent session.

    Tool arguments, command text, paths, prompts, outputs and free-form reasons
    are deliberately discarded. The control plane receives only a closed
    vocabulary suitable for operational proof and derives identity/policy
    metadata from the authenticated session.
    """

    def __init__(self, client: ControlPlaneAgentClient, *, source: str) -> None:
        """Bind one exporter to its authenticated host evidence source."""
        if source not in {"claude_native", "codex_native", "mcp", "sdk_runtime"}:
            raise ControlPlaneConfigurationError("decision source is unsupported")
        self.client = client
        self.source = source

    @staticmethod
    def _decision(event: AuditEvent) -> str | None:
        """Normalize host and runtime outcomes into the dashboard vocabulary."""
        if event.event_type in {"claude_pre_tool_decision", "codex_pre_tool_decision"}:
            value = event.payload.get("decision")
            return {"allow": "allowed", "deny": "denied", "ask": "approval_required"}.get(
                value if isinstance(value, str) else ""
            )
        return {
            "action_executed": "allowed",
            "action_denied": "denied",
            "approval_required": "approval_required",
        }.get(event.event_type)

    @staticmethod
    def _reason(event: AuditEvent, decision: str) -> str:
        """Map free-form local explanations to non-sensitive reason codes."""
        reason = str(event.payload.get("reason", "")).lower()
        if decision == "approval_required":
            return "approval_rule"
        if "outside" in reason and "project" in reason:
            return "outside_project"
        if "dangerous" in reason or "command" in reason and "blocked" in reason:
            return "blocked_command"
        if "configuration" in reason and "invalid" in reason:
            return "invalid_configuration"
        if "audit" in reason and ("failed" in reason or "persistence" in reason):
            return "audit_failure"
        if "evaluation" in reason or "policy" in reason and "failed" in reason:
            return "policy_error"
        return "explicit_allow" if decision == "allowed" else "deny_by_default"

    def export(self, event: AuditEvent) -> None:
        """Report one recognized decision and ignore non-decision lifecycle events."""
        decision = self._decision(event)
        if decision is None:
            return
        tool_name = event.payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ControlPlaneConfigurationError("decision event has no valid tool name")
        is_native_hook = (
            self.source == "claude_native" and event.event_type == "claude_pre_tool_decision"
        ) or (self.source == "codex_native" and event.event_type == "codex_pre_tool_decision")
        action_digest = None
        if is_native_hook:
            correlated_digest = event.payload.get("action_digest")
            if correlated_digest is not None and (
                not isinstance(correlated_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", correlated_digest)
            ):
                raise ControlPlaneConfigurationError(
                    "native decision event has an invalid action correlation digest"
                )
            tool_input_hash = event.payload.get("tool_input_hash")
            cwd_hash = event.payload.get("cwd_hash")
            if not isinstance(tool_input_hash, str) or not re.fullmatch(
                r"[0-9a-f]{64}", tool_input_hash
            ):
                raise ControlPlaneConfigurationError(
                    "native decision event has no valid action digest"
                )
            if not isinstance(cwd_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", cwd_hash):
                raise ControlPlaneConfigurationError(
                    "native decision event has no valid working-directory digest"
                )
            action_digest = correlated_digest or _native_action_digest(
                tool_name, tool_input_hash, cwd_hash
            )
            if tool_name == "Bash":
                resource_kind = "shell_command"
            elif tool_name.startswith("mcp__"):
                resource_kind = "mcp_tool"
            else:
                resource_kind = "project_file"
        elif self.source == "mcp":
            resource_kind = "mcp_tool"
        else:
            resource_kind = "sdk_tool"
        self.client.report_decision(
            decision_id=event.event_hash,
            source=self.source,
            tool_name=tool_name,
            decision=decision,
            resource_kind=resource_kind,
            reason_code=self._reason(event, decision),
            action_digest=action_digest,
        )


def _native_action_digest(tool_name: str, tool_input_hash: str, cwd_hash: str) -> str:
    """Bind redacted native action evidence to tool, arguments, and project scope.

    The inputs are already content-minimised hashes produced at the host trust
    boundary. Canonical JSON makes the version-one correlation algorithm
    deterministic across Python and browser clients without exporting raw
    commands, paths, prompts, or arguments.
    """
    encoded = json.dumps(
        {
            "cwd_hash": cwd_hash,
            "tool_input_hash": tool_input_hash,
            "tool_name": tool_name,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _now() -> str:
    """Return an explicit UTC timestamp for control-plane state."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    """Require a JSON object at a named configuration boundary."""
    if not isinstance(value, Mapping):
        raise ControlPlaneConfigurationError(f"{name} must be an object")
    return value


def _bounded_agent_telemetry(value: Mapping[str, int | float]) -> dict[str, int | float]:
    """Validate the fixed, non-sensitive metric schema at the client boundary."""
    if not isinstance(value, Mapping) or len(value) > len(_AGENT_TELEMETRY_FIELDS):
        raise ControlPlaneConfigurationError("agent telemetry must be a bounded object")
    result: dict[str, int | float] = {}
    for key, item in value.items():
        if key not in _AGENT_TELEMETRY_FIELDS or isinstance(item, bool):
            raise ControlPlaneConfigurationError("agent telemetry contains an unsupported field")
        if not isinstance(item, (int, float)) or not math.isfinite(float(item)):
            raise ControlPlaneConfigurationError("agent telemetry values must be finite numbers")
        if item < 0 or item > 1_000_000_000:
            raise ControlPlaneConfigurationError("agent telemetry values are out of bounds")
        result[key] = item
    return result


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
    try:
        compile_command_patterns([value])
    except ValueError as exc:
        raise ControlPlaneConfigurationError(f"{name} pattern is unsafe or invalid: {exc}") from exc
    return value


def _pattern_list(value: object, name: str) -> list[str]:
    """Validate one complete decision-class pattern list with shared limits."""
    patterns = _list_of_text(value, name)
    try:
        compile_command_patterns(patterns)
    except ValueError as exc:
        raise ControlPlaneConfigurationError(f"{name} is unsafe or invalid: {exc}") from exc
    return patterns


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
    if not set(claude).issubset(_CLAUDE_KEYS) or not (
        _CLAUDE_KEYS - _CLAUDE_OPTIONAL_KEYS
    ).issubset(claude):
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
        "deniedCommandPatterns": _pattern_list(
            claude["deniedCommandPatterns"], "claudeCode.deniedCommandPatterns"
        ),
        "approvalCommandPatterns": _pattern_list(
            claude["approvalCommandPatterns"], "claudeCode.approvalCommandPatterns"
        ),
        "allowedCommandPatterns": _pattern_list(
            claude.get("allowedCommandPatterns", []), "claudeCode.allowedCommandPatterns"
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
            "deniedCommandPatterns": [r"rm\s+-rf", r"curl[^|]+\|\s*sh"],
            "approvalCommandPatterns": [r"git\s+push", r"npm\s+publish"],
            "allowedCommandPatterns": [r"^(pwd|git[ \t]+status)([ \t]|$)"],
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
        presence: AgentPresenceStore | None = None,
    ) -> None:
        """Load state and optionally bind mutations to a live runtime authority."""
        self.path = Path(path)
        self.authority = authority
        self.audit = audit
        self.presence = presence
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
        agents = self.presence.snapshot() if self.presence is not None else []
        active_sessions = sum(1 for agent in agents if agent.get("status") == "connected")
        return {
            "generatedAt": _now(),
            "posture": "critical" if stopped else "healthy",
            "activeSessions": 0 if stopped else active_sessions,
            "decisionsToday": 0,
            "deniedToday": 0,
            "approvalQueue": 0,
            "timedOutWorkers": 0,
            "emergencyStop": stopped,
            "agents": agents,
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
            parsed_origin = urlsplit(allowed_origin or "")
            if (
                parsed_origin.scheme != "http"
                or parsed_origin.hostname not in {"localhost", "127.0.0.1", "::1"}
                or parsed_origin.path not in {"", "/"}
                or parsed_origin.username is not None
                or parsed_origin.password is not None
            ):
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
            if method == "GET" and path in {"/api/agents", "/agents"}:
                if not self.authenticator.authorize(identity, "read"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                return self._respond(start_response, 200, {"agents": self._agents()}, cors)
            if method == "POST" and path in {"/api/agents/register", "/agents/register"}:
                if not self.authenticator.authorize(identity, "agent_register"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                body = self._body(environ)
                agent_id = _text(body.get("agentId"), "agentId", allow_empty=False)
                if agent_id != identity.subject:
                    raise ControlPlaneConfigurationError(
                        "agentId must match the authenticated agent identity"
                    )
                host = _text(body.get("host"), "host", allow_empty=False)
                if host not in {AgentHost.CLAUDE_CODE.value, AgentHost.CODEX_CLI.value}:
                    raise ControlPlaneConfigurationError("host must be claude-code or codex-cli")
                return self._respond(
                    start_response,
                    200,
                    self._presence().register(
                        agent_id=agent_id,
                        host=host,
                        project_root=_text(
                            body.get("projectRoot"), "projectRoot", allow_empty=False
                        ),
                        principal_id=identity.subject,
                        actor_id=identity.subject,
                    ),
                    cors,
                )
            if method == "POST" and path.startswith("/api/agents/") and path.endswith("/heartbeat"):
                if not self.authenticator.authorize(identity, "agent_heartbeat"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                agent_id = path[len("/api/agents/") : -len("/heartbeat")].strip("/")
                if not agent_id or agent_id != identity.subject:
                    raise ControlPlaneConfigurationError("agent identity does not match the route")
                body = self._body(environ)
                session_id = _text(body.get("sessionId"), "sessionId", allow_empty=False)
                return self._respond(
                    start_response,
                    200,
                    self._presence().heartbeat(
                        agent_id=agent_id,
                        session_id=session_id,
                        actor_id=identity.subject,
                    ),
                    cors,
                )
            if (
                method == "POST"
                and path.startswith("/api/agents/")
                and path.endswith("/disconnect")
            ):
                if not self.authenticator.authorize(identity, "agent_disconnect"):
                    return self._respond(start_response, 403, {"error": "forbidden"}, cors)
                agent_id = path[len("/api/agents/") : -len("/disconnect")].strip("/")
                if not agent_id or agent_id != identity.subject:
                    raise ControlPlaneConfigurationError("agent identity does not match the route")
                body = self._body(environ)
                session_id = _text(body.get("sessionId"), "sessionId", allow_empty=False)
                return self._respond(
                    start_response,
                    200,
                    self._presence().disconnect(
                        agent_id=agent_id,
                        session_id=session_id,
                        actor_id=identity.subject,
                    ),
                    cors,
                )
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

    def _presence(self) -> AgentPresenceStore:
        """Require a live agent registry for registration and heartbeat calls."""
        if self.store.presence is None:
            raise ControlPlaneDependencyError("agent presence registry is unavailable")
        return self.store.presence

    def _agents(self) -> list[JsonObject]:
        """Return the current non-secret agent presence snapshot."""
        return self._presence().snapshot()

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
    "AgentPresence",
    "AgentPresenceStore",
    "ControlPlaneAgentClient",
    "InMemoryControlPlaneAuthority",
    "OperatorAuthenticator",
    "OperatorIdentity",
    "StaticBearerAuthenticator",
    "validate_configuration",
]

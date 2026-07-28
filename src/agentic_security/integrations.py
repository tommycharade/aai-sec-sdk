"""Host integration primitives for agentic-security SDK deployments.

The security runtime is intentionally independent of any particular agent
product.  This module provides the small amount of protocol glue needed to
connect hosts to that runtime without moving authorization into model output.

The :class:`McpGateway` is a dependency-free implementation of the MCP
``tools/list`` and ``tools/call`` surfaces.  It is suitable for stdio or HTTP
wrappers supplied by an application.  The gateway owns proposal construction;
the caller owns the :class:`~agentic_security.types.ExecutionContext` and the
configured :class:`~agentic_security.runtime.GuardedRuntime`.

MCP protects only calls routed through the gateway.  Hosts must use their
pre-tool hooks, plugins, or a sandbox when their built-in shell or filesystem
tools also need to be governed.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, TextIO

from .runtime import GuardedRuntime
from .types import ActionProposal, ExecutionResult, ExecutionStatus

JsonObject = dict[str, Any]
_JSON_RPC_VERSION: Final[str] = "2.0"
_MCP_PROTOCOL_VERSION: Final[str] = "2024-11-05"


class AgentHost(StrEnum):
    """Supported host profiles.

    Profiles are labels used for audit correlation and configuration.  They
    do not grant authority and are never accepted as the authenticated
    principal.
    """

    OPENCODE = "opencode"
    OPENHANDS = "openhands"
    CLAUDE_CODE = "claude-code"
    CLINE = "cline"
    GEMINI_CLI = "gemini-cli"
    GITHUB_COPILOT = "github-copilot"
    CODEX_CLI = "codex-cli"


@dataclass(frozen=True, slots=True)
class HostProfile:
    """Integration metadata and configuration guidance for one host."""

    host: AgentHost
    display_name: str
    supports_mcp: bool = True
    supports_pre_tool_hooks: bool = False
    configuration_file: str = ""


HOST_PROFILES: Final[Mapping[AgentHost, HostProfile]] = {
    AgentHost.OPENCODE: HostProfile(
        AgentHost.OPENCODE, "OpenCode", configuration_file="opencode.json"
    ),
    AgentHost.OPENHANDS: HostProfile(AgentHost.OPENHANDS, "OpenHands self-hosted"),
    AgentHost.CLAUDE_CODE: HostProfile(
        AgentHost.CLAUDE_CODE, "Claude Code", supports_pre_tool_hooks=True
    ),
    AgentHost.CLINE: HostProfile(AgentHost.CLINE, "Cline"),
    AgentHost.GEMINI_CLI: HostProfile(AgentHost.GEMINI_CLI, "Gemini CLI"),
    AgentHost.GITHUB_COPILOT: HostProfile(AgentHost.GITHUB_COPILOT, "GitHub Copilot"),
    AgentHost.CODEX_CLI: HostProfile(
        AgentHost.CODEX_CLI, "Codex CLI", supports_pre_tool_hooks=False
    ),
}


class IntegrationProtocolError(ValueError):
    """Raised when a host sends malformed protocol input."""


@dataclass(frozen=True, slots=True)
class RuntimeSession:
    """Application-authenticated runtime session with an absolute expiry."""

    session_id: str
    runtime: GuardedRuntime
    expires_at: float


class RuntimeSessionStore:
    """Bounded in-memory session registry for a single gateway process.

    The application must create a session only after authenticating the
    principal through its own IAM boundary. Session identifiers are bearer
    secrets and must never be accepted from an MCP request body. Multi-process
    deployments should replace this store with a shared authenticated session
    service.
    """

    def __init__(
        self, *, max_sessions: int = 1_000, clock: Callable[[], float] = time.monotonic
    ) -> None:
        """Create a bounded store with an injectable monotonic clock."""
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        self.max_sessions = max_sessions
        self._clock = clock
        self._sessions: dict[str, RuntimeSession] = {}

    def register(
        self, session_id: str, runtime: GuardedRuntime, *, ttl_seconds: float = 3_600
    ) -> None:
        """Register an application-authenticated runtime until its expiry."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be non-empty")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.reap()
        if session_id not in self._sessions and len(self._sessions) >= self.max_sessions:
            raise RuntimeError("runtime session capacity is exhausted")
        self._sessions[session_id] = RuntimeSession(
            session_id, runtime, self._clock() + ttl_seconds
        )

    def resolve(self, session_id: str) -> GuardedRuntime | None:
        """Return an unexpired runtime, or fail closed for an unknown session."""
        self.reap()
        session = self._sessions.get(session_id)
        return session.runtime if session is not None else None

    def revoke(self, session_id: str) -> None:
        """Revoke a session and activate its runtime emergency stop."""
        session = self._sessions.pop(session_id, None)
        if session is not None:
            session.runtime.stop()

    def reap(self) -> int:
        """Remove expired sessions and stop their runtimes."""
        now = self._clock()
        expired = [key for key, value in self._sessions.items() if value.expires_at <= now]
        for key in expired:
            self.revoke(key)
        return len(expired)


class McpHttpApplication:
    """Bounded WSGI application for authenticated MCP JSON-RPC requests.

    TLS termination, reverse-proxy limits, and deployment network policy are
    still responsibilities of the web server. This application enforces POST,
    bearer-session authentication, content-length limits, JSON object input,
    and bounded JSON responses before dispatching to :class:`McpGateway`.
    """

    def __init__(
        self,
        sessions: RuntimeSessionStore,
        host: AgentHost,
        *,
        max_body_bytes: int = 1_000_000,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        """Create an HTTP boundary backed by an application-owned session store."""
        if max_body_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("HTTP body and response limits must be positive")
        self.sessions = sessions
        self.host = host
        self.max_body_bytes = max_body_bytes
        self.max_response_bytes = max_response_bytes

    def handle(self, body: bytes, authorization: str | None) -> tuple[int, JsonObject]:
        """Handle one authenticated request without requiring a web framework."""
        if len(body) > self.max_body_bytes:
            return 413, McpGateway._error(None, -32600, "request exceeds configured size limit")
        session_id = self._bearer_token(authorization)
        if session_id is None:
            return 401, McpGateway._error(None, -32600, "bearer authentication is required")
        runtime = self.sessions.resolve(session_id)
        if runtime is None:
            return 401, McpGateway._error(None, -32600, "session is unknown or expired")
        try:
            message = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, McpGateway._error(None, -32700, "request is not valid JSON")
        if not isinstance(message, Mapping):
            return 400, McpGateway._error(None, -32600, "MCP message must be an object")
        response = McpGateway(
            runtime,
            self.host,
            max_message_bytes=self.max_body_bytes,
            max_response_bytes=self.max_response_bytes,
        ).handle(message)
        if response is None:
            return 204, {}
        encoded = json.dumps(response, separators=(",", ":"), default=str).encode("utf-8")
        if len(encoded) > self.max_response_bytes:
            return 500, McpGateway._error(
                message.get("id"), -32603, "response exceeds configured size limit"
            )
        return 200, response

    def __call__(
        self, environ: Mapping[str, Any], start_response: Callable[..., Any]
    ) -> list[bytes]:
        """Serve one WSGI request with no framework dependency."""
        if environ.get("REQUEST_METHOD") != "POST":
            response = McpGateway._error(None, -32600, "POST is required")
            return self._wsgi_response(start_response, 405, response)
        raw_length = environ.get("CONTENT_LENGTH", "")
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            return self._wsgi_response(
                start_response, 400, McpGateway._error(None, -32600, "content length is required")
            )
        if length < 0 or length > self.max_body_bytes:
            return self._wsgi_response(
                start_response,
                413,
                McpGateway._error(None, -32600, "request exceeds configured size limit"),
            )
        stream = environ.get("wsgi.input")
        if stream is None or not hasattr(stream, "read"):
            return self._wsgi_response(
                start_response, 400, McpGateway._error(None, -32600, "request body is required")
            )
        body = stream.read(length)
        if not isinstance(body, bytes) or len(body) != length:
            return self._wsgi_response(
                start_response, 400, McpGateway._error(None, -32600, "request body is incomplete")
            )
        status, response = self.handle(body, environ.get("HTTP_AUTHORIZATION"))
        return self._wsgi_response(start_response, status, response)

    @staticmethod
    def _bearer_token(authorization: str | None) -> str | None:
        """Parse exactly one bearer token without accepting alternate schemes."""
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:].strip()
        return token if token and " " not in token else None

    @staticmethod
    def _wsgi_response(
        start_response: Callable[..., Any], status: int, response: JsonObject
    ) -> list[bytes]:
        """Serialize a small JSON HTTP response for a WSGI server."""
        body = json.dumps(response, separators=(",", ":")).encode("utf-8")
        reason = {
            200: "OK",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            405: "Method Not Allowed",
            413: "Request Entity Too Large",
            500: "Internal Server Error",
        }.get(status, "Error")
        start_response(
            f"{status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [] if status == 204 else [body]


class McpGateway:
    """Expose a :class:`GuardedRuntime` as an MCP tool server.

    The implementation intentionally supports the small, stable MCP surface
    needed for tool mediation.  Unknown methods, malformed calls, unknown
    tools, and all runtime failures return structured errors; no host input
    can replace the runtime's identity, policy, approval, or credential
    dependencies.
    """

    def __init__(
        self,
        runtime: GuardedRuntime,
        host: AgentHost,
        *,
        server_name: str = "agentic-security-gateway",
        server_version: str = "1.1.0",
        max_message_bytes: int = 1_000_000,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        """Create a gateway bound to one host-owned runtime and context."""
        if not isinstance(server_name, str) or not server_name.strip():
            raise ValueError("server_name must be non-empty")
        if not isinstance(server_version, str) or not server_version.strip():
            raise ValueError("server_version must be non-empty")
        if max_message_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("message and response limits must be positive")
        self.runtime = runtime
        self.host = host
        self.server_name = server_name
        self.server_version = server_version
        self.max_message_bytes = max_message_bytes
        self.max_response_bytes = max_response_bytes

    def handle(self, message: Mapping[str, Any]) -> JsonObject | None:
        """Handle one JSON-RPC request and return its response.

        Notifications return ``None`` as required by JSON-RPC.  Requests are
        never executed until the runtime has constructed and authorized an
        :class:`ActionProposal` from the call.
        """
        if not isinstance(message, Mapping):
            raise IntegrationProtocolError("MCP message must be an object")
        request_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return self._error(request_id, -32600, "method is required")
        if request_id is None and method.startswith("notifications/"):
            return None
        if method == "initialize":
            params = message.get("params", {})
            if not isinstance(params, Mapping):
                return self._error(request_id, -32602, "initialize params must be an object")
            return self._result(
                request_id,
                {
                    "protocolVersion": _MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.server_name, "version": self.server_version},
                },
            )
        if method == "tools/list":
            return self._result(request_id, {"tools": self._tool_manifest()})
        if method == "tools/call":
            return self._call_tool(request_id, message.get("params"))
        if method == "ping":
            return self._result(request_id, {})
        return self._error(request_id, -32601, "method not supported")

    def serve_stdio(
        self, input_stream: TextIO | None = None, output_stream: TextIO | None = None
    ) -> None:
        """Serve newline-delimited JSON-RPC over stdio until EOF.

        The stream boundary has a byte limit so an agent cannot make the
        integration process buffer an unbounded request.  Applications that
        need HTTP transport should pass the same parsed objects to
        :meth:`handle` from their authenticated web server.
        """
        source = input_stream or sys.stdin
        destination = output_stream or sys.stdout
        for line in source:
            response: JsonObject | None
            encoded = line.encode("utf-8")
            if len(encoded) > self.max_message_bytes:
                response = self._error(None, -32600, "message exceeds configured size limit")
            else:
                try:
                    decoded = json.loads(line)
                    if not isinstance(decoded, Mapping):
                        response = self._error(None, -32600, "MCP message must be an object")
                    else:
                        response = self.handle(decoded)
                except (
                    IntegrationProtocolError,
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                ) as exc:
                    response = self._error(None, -32600, str(exc))
            if response is not None:
                encoded_response = json.dumps(response, separators=(",", ":")).encode("utf-8")
                if len(encoded_response) > self.max_response_bytes:
                    response = self._error(None, -32603, "response exceeds configured size limit")
                destination.write(json.dumps(response, separators=(",", ":")) + "\n")
                destination.flush()

    def _tool_manifest(self) -> list[JsonObject]:
        """Return a deterministic manifest for the explicit tool allow-list."""
        return [
            {
                "name": name,
                "description": self.runtime.registry.get(name).description,  # type: ignore[union-attr]
                "inputSchema": self.runtime.registry.get(name).input_schema  # type: ignore[union-attr]
                or {"type": "object"},
            }
            for name in sorted(self.runtime.registry.names())
        ]

    def _call_tool(self, request_id: Any, params: Any) -> JsonObject:
        """Translate an MCP call into one guarded proposal."""
        if not isinstance(params, Mapping):
            return self._error(request_id, -32602, "tools/call params must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name.strip():
            return self._error(request_id, -32602, "tool name is required")
        if not isinstance(arguments, Mapping):
            return self._error(request_id, -32602, "tool arguments must be an object")
        proposal = ActionProposal(
            tool_name=name,
            arguments=dict(arguments),
            proposal_id=(
                f"{self.host.value}:{request_id if request_id is not None else uuid.uuid4()}"
            ),
            operation_key=self._operation_key(params),
        )
        try:
            result = self.runtime.execute(proposal)
        except Exception:
            # Adapter code must not turn an unexpected exception into an
            # authorization success or leak provider/credential details.
            return self._error(request_id, -32603, "guarded execution failed")
        return self._result(request_id, self._mcp_result(result))

    @staticmethod
    def _operation_key(params: Mapping[str, Any]) -> str | None:
        """Accept a caller key only as a retry key, never as authorization."""
        value = params.get("_meta", {})
        if not isinstance(value, Mapping):
            return None
        operation_key = value.get("operationKey")
        return operation_key if isinstance(operation_key, str) and operation_key.strip() else None

    @staticmethod
    def _mcp_result(result: ExecutionResult) -> JsonObject:
        """Serialize an execution result without exposing credentials."""
        payload: JsonObject = {
            "status": result.status.value,
            "toolName": result.tool_name,
            "requestId": result.request_id,
            "reason": result.reason,
            "approvalId": result.approval_id,
            "auditRecorded": result.audit_recorded,
            "idempotencyRecorded": result.idempotency_recorded,
        }
        if result.reconciliation_state is not None:
            payload["reconciliationState"] = result.reconciliation_state.value
        if result.status is ExecutionStatus.EXECUTED:
            payload["output"] = result.output
        return {
            "isError": result.status is not ExecutionStatus.EXECUTED,
            "content": [{"type": "text", "text": json.dumps(payload, default=str)}],
            "structuredContent": payload,
        }

    @staticmethod
    def _result(request_id: Any, result: JsonObject) -> JsonObject:
        """Build a JSON-RPC success response."""
        return {"jsonrpc": _JSON_RPC_VERSION, "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> JsonObject:
        """Build a JSON-RPC error response."""
        return {
            "jsonrpc": _JSON_RPC_VERSION,
            "id": request_id,
            "error": {"code": code, "message": message},
        }


class HostIntegration:
    """Convenience factory for the supported host profiles."""

    def __init__(
        self,
        runtime: GuardedRuntime,
        host: AgentHost,
        *,
        server_name: str = "agentic-security-gateway",
    ) -> None:
        """Bind one explicit runtime to one host profile."""
        if host not in HOST_PROFILES:
            raise ValueError(f"unsupported host profile: {host}")
        self.profile = HOST_PROFILES[host]
        self.gateway = McpGateway(runtime, host, server_name=server_name)

    def handle(self, message: Mapping[str, Any]) -> JsonObject | None:
        """Forward a protocol message to the host-independent gateway."""
        return self.gateway.handle(message)

    def serve_stdio(
        self, input_stream: TextIO | None = None, output_stream: TextIO | None = None
    ) -> None:
        """Run this host integration over stdio."""
        self.gateway.serve_stdio(input_stream, output_stream)


def integration_for(host: AgentHost | str, runtime: GuardedRuntime) -> HostIntegration:
    """Create a plug-and-play integration for a supported host name."""
    try:
        selected = host if isinstance(host, AgentHost) else AgentHost(host)
    except ValueError as exc:
        raise ValueError(f"unsupported host profile: {host!r}") from exc
    return HostIntegration(runtime, selected)


def opencode_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the OpenCode MCP integration."""
    return integration_for(AgentHost.OPENCODE, runtime)


def openhands_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the OpenHands self-hosted MCP integration."""
    return integration_for(AgentHost.OPENHANDS, runtime)


def claude_code_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the Claude Code MCP integration."""
    return integration_for(AgentHost.CLAUDE_CODE, runtime)


def cline_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the Cline MCP integration."""
    return integration_for(AgentHost.CLINE, runtime)


def gemini_cli_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the Gemini CLI MCP integration."""
    return integration_for(AgentHost.GEMINI_CLI, runtime)


def github_copilot_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the GitHub Copilot CLI/cloud-agent MCP integration."""
    return integration_for(AgentHost.GITHUB_COPILOT, runtime)


def codex_cli_integration(runtime: GuardedRuntime) -> HostIntegration:
    """Create the Codex CLI MCP integration."""
    return integration_for(AgentHost.CODEX_CLI, runtime)


def main() -> None:
    """Explain how to launch a configured application gateway.

    A generic executable cannot safely invent an application context, policy,
    tool registry, or credentials.  Applications should create their runtime
    and call ``integration_for(...).serve_stdio()`` from their entry point.
    """
    raise SystemExit(
        "Create a GuardedRuntime in your application, then call "
        "integration_for('codex-cli', runtime).serve_stdio()."
    )


__all__ = [
    "AgentHost",
    "HOST_PROFILES",
    "HostIntegration",
    "HostProfile",
    "IntegrationProtocolError",
    "McpGateway",
    "McpHttpApplication",
    "RuntimeSession",
    "RuntimeSessionStore",
    "claude_code_integration",
    "cline_integration",
    "codex_cli_integration",
    "gemini_cli_integration",
    "github_copilot_integration",
    "integration_for",
    "openhands_integration",
    "opencode_integration",
]

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from agentic_security import (
    AgentHost,
    ExecutionContext,
    ExecutionStatus,
    GuardedRuntime,
    InMemoryAuditSink,
    InMemoryIdempotencyStore,
    McpGateway,
    McpHttpApplication,
    Principal,
    Resource,
    RuntimeSessionStore,
    ToolDefinition,
    ToolRegistry,
    claude_code_integration,
    cline_integration,
    codex_cli_integration,
    gemini_cli_integration,
    github_copilot_integration,
    integration_for,
    opencode_integration,
    openhands_integration,
)
from agentic_security.policies import AllowListPolicy
from agentic_security.runtime import RuntimeConfig


def make_runtime(calls: list[Any] | None = None) -> GuardedRuntime:
    calls = calls if calls is not None else []

    def handler(_context: ExecutionContext, arguments: Any) -> dict[str, str]:
        calls.append(arguments)
        return {"value": "synthetic"}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "read_record",
            handler,
            lambda arguments: {"id": arguments["id"]},
            resources=lambda _arguments: (Resource("record:1", "record", "tenant:test"),),
            description="Read one synthetic record.",
            input_schema={
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
                "additionalProperties": False,
            },
        )
    )
    context = ExecutionContext(
        "agent:host",
        Principal("principal:test", tenant="tenant:test"),
        "task:host",
        "integration test",
        tenant="tenant:test",
    )
    return GuardedRuntime(
        context,
        registry,
        AllowListPolicy({"read_record"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(idempotency_store=InMemoryIdempotencyStore()),
    )


def test_mcp_gateway_lists_explicit_tools_and_executes_through_runtime() -> None:
    calls: list[Any] = []
    gateway = McpGateway(make_runtime(calls), AgentHost.CLAUDE_CODE)

    listed = gateway.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert listed is not None
    assert listed["result"]["tools"][0]["name"] == "read_record"

    response = gateway.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_record", "arguments": {"id": "record:1"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["status"] == ExecutionStatus.EXECUTED
    assert calls == [{"id": "record:1"}]


def test_mcp_gateway_preserves_fail_closed_unknown_tool() -> None:
    gateway = McpGateway(make_runtime(), AgentHost.CODEX_CLI)
    response = gateway.handle(
        {
            "jsonrpc": "2.0",
            "id": "unknown",
            "method": "tools/call",
            "params": {"name": "delete_everything", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert response["result"]["structuredContent"]["status"] == ExecutionStatus.DENIED


def test_mcp_gateway_does_not_accept_model_supplied_identity() -> None:
    calls: list[Any] = []
    runtime = make_runtime(calls)
    gateway = McpGateway(runtime, AgentHost.OPENCODE)
    response = gateway.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_record",
                "arguments": {"id": "record:1", "principal": "attacker"},
                "_meta": {"principal": "attacker", "tenant": "other"},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert runtime.context.principal.id == "principal:test"
    assert runtime.context.tenant == "tenant:test"


def test_stdio_gateway_bounds_messages_and_handles_notifications() -> None:
    gateway = McpGateway(make_runtime(), AgentHost.GEMINI_CLI, max_message_bytes=80)
    source = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        + "\n"
    )
    destination = io.StringIO()
    gateway.serve_stdio(source, destination)
    assert json.loads(destination.getvalue())["result"] == {}


@pytest.mark.parametrize("host", list(AgentHost))
def test_all_supported_hosts_share_the_same_extensible_gateway(host: AgentHost) -> None:
    integration = integration_for(host, make_runtime())
    assert integration.profile.host is host
    assert integration.handle({"jsonrpc": "2.0", "id": 1, "method": "ping"}) == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {},
    }


def test_invalid_mcp_arguments_fail_before_handler() -> None:
    calls: list[Any] = []
    gateway = McpGateway(make_runtime(calls), AgentHost.CLINE)
    response = gateway.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "read_record", "arguments": []},
        }
    )
    assert response is not None
    assert response["error"]["code"] == -32602
    assert calls == []


def test_gateway_rejects_invalid_configuration_and_protocol_shapes() -> None:
    runtime = make_runtime()
    with pytest.raises(ValueError):
        McpGateway(runtime, AgentHost.CLINE, server_name=" ")
    with pytest.raises(ValueError):
        McpGateway(runtime, AgentHost.CLINE, server_version=" ")
    with pytest.raises(ValueError):
        McpGateway(runtime, AgentHost.CLINE, max_message_bytes=0)

    gateway = McpGateway(runtime, AgentHost.CLINE)
    initialized = gateway.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    malformed_initialize = gateway.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": []}
    )
    unsupported = gateway.handle({"jsonrpc": "2.0", "id": 3, "method": "unsupported"})
    missing_method = gateway.handle({"jsonrpc": "2.0", "id": 4})
    assert initialized is not None
    assert malformed_initialize is not None
    assert unsupported is not None
    assert missing_method is not None
    assert initialized["result"]["capabilities"] == {"tools": {}}
    assert malformed_initialize["error"]["code"] == -32602
    assert unsupported["error"]["code"] == -32601
    assert missing_method["error"]["code"] == -32600
    assert gateway.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_stdio_gateway_reports_non_object_and_oversized_messages() -> None:
    gateway = McpGateway(make_runtime(), AgentHost.CLINE, max_message_bytes=20)
    source = io.StringIO("[]\n" + '{"jsonrpc":"2.0","id":1}\n')
    destination = io.StringIO()
    gateway.serve_stdio(source, destination)
    responses = [json.loads(line) for line in destination.getvalue().splitlines()]
    assert responses[0]["error"]["code"] == -32600
    assert responses[1]["error"]["code"] == -32600


def test_integration_for_rejects_unknown_host() -> None:
    with pytest.raises(ValueError, match="unsupported host profile"):
        integration_for("unknown-agent", make_runtime())


def test_runtime_sessions_expire_revoke_and_bound_capacity() -> None:
    now = [100.0]
    store = RuntimeSessionStore(max_sessions=1, clock=lambda: now[0])
    runtime = make_runtime()
    store.register("session-1", runtime, ttl_seconds=5)
    assert store.resolve("session-1") is runtime
    with pytest.raises(RuntimeError, match="capacity"):
        store.register("session-2", make_runtime())
    now[0] = 106.0
    assert store.resolve("session-1") is None
    assert runtime.is_stopped()
    store.register("session-2", make_runtime())
    store.revoke("session-2")


def test_http_application_requires_bearer_session_and_dispatches_mcp() -> None:
    store = RuntimeSessionStore()
    runtime = make_runtime()
    store.register("secret-session", runtime)
    app = McpHttpApplication(store, AgentHost.CLAUDE_CODE)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    assert app.handle(request, None)[0] == 401
    assert app.handle(request, "Bearer wrong")[0] == 401
    status, response = app.handle(request, "Bearer secret-session")
    assert status == 200
    assert response["result"] == {}
    assert app.handle(b"not-json", "Bearer secret-session")[0] == 400
    assert app.handle(request + b"x" * 2_000_000, "Bearer secret-session")[0] == 413


def test_http_wsgi_boundary_rejects_non_post_and_incomplete_body() -> None:
    store = RuntimeSessionStore()
    store.register("session", make_runtime())
    app = McpHttpApplication(store, AgentHost.CODEX_CLI)
    statuses: list[str] = []

    def start_response(status: str, _headers: list[tuple[str, str]]) -> None:
        statuses.append(status)

    assert app({"REQUEST_METHOD": "GET"}, start_response) == [
        b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"POST is required"}}'
    ]
    assert statuses[-1].startswith("405")
    assert app(
        {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": "5", "wsgi.input": io.BytesIO(b"{}")},
        start_response,
    )
    assert statuses[-1].startswith("400")


def test_session_and_http_configuration_reject_unsafe_values() -> None:
    with pytest.raises(ValueError):
        RuntimeSessionStore(max_sessions=0)
    store = RuntimeSessionStore()
    with pytest.raises(ValueError):
        store.register("", make_runtime())
    with pytest.raises(ValueError):
        store.register("session", make_runtime(), ttl_seconds=0)
    with pytest.raises(ValueError):
        McpHttpApplication(store, AgentHost.CLINE, max_body_bytes=0)
    with pytest.raises(ValueError):
        McpHttpApplication(store, AgentHost.CLINE, max_response_bytes=0)
    assert McpHttpApplication._bearer_token("Basic secret") is None
    assert McpHttpApplication._bearer_token("Bearer two words") is None


def test_http_wsgi_boundary_rejects_invalid_length_and_missing_stream() -> None:
    app = McpHttpApplication(RuntimeSessionStore(), AgentHost.CLINE)
    statuses: list[str] = []

    def start_response(status: str, _headers: list[tuple[str, str]]) -> None:
        statuses.append(status)

    app({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": "bad"}, start_response)
    assert statuses[-1].startswith("400")
    app({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": "0"}, start_response)
    assert statuses[-1].startswith("400")


@pytest.mark.parametrize(
    "factory",
    [
        opencode_integration,
        openhands_integration,
        claude_code_integration,
        cline_integration,
        gemini_cli_integration,
        github_copilot_integration,
        codex_cli_integration,
    ],
)
def test_named_host_factories_create_integrations(factory: Any) -> None:
    assert factory(make_runtime()).profile.host in AgentHost

"""Runnable MCP gateway bootstrap using synthetic data only.

Run from the repository root and configure the process as an MCP stdio server
in any supported host. The host profile can be changed to another
``AgentHost`` without changing the security runtime.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agentic_security import (
    AgentHost,
    AuditSink,
    ControlPlaneAgentClient,
    ControlPlaneDecisionExporter,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    Principal,
    ReplicatedAuditSink,
    ToolDefinition,
    ToolRegistry,
    integration_for,
)
from agentic_security.policies import AllowListPolicy


def validate_lookup(arguments: Mapping[str, Any]) -> dict[str, str]:
    """Validate a synthetic record identifier before policy evaluation."""
    record_id = arguments.get("record_id")
    if not isinstance(record_id, str) or not record_id.startswith("record_"):
        raise ValueError("record_id must be a synthetic record identifier")
    return {"record_id": record_id}


def lookup_record(context: ExecutionContext, arguments: Any) -> dict[str, str]:
    """Return synthetic data using only host-owned identity."""
    return {"record_id": arguments["record_id"], "principal": context.principal.id}


def build_runtime(
    allowed_tools: set[str] | None = None,
    audit: AuditSink | None = None,
) -> GuardedRuntime:
    """Build the runtime using the centrally assigned allow-list when present."""
    context = ExecutionContext(
        "example-agent",
        Principal("user:example", tenant="tenant:example"),
        "task:mcp-example",
        "demonstrate MCP guarded lookup",
        tenant="tenant:example",
    )
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="lookup_record",
            handler=lookup_record,
            validator=validate_lookup,
            description="Read one synthetic record.",
            input_schema={
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
                "additionalProperties": False,
            },
        )
    )
    policy_tools = allowed_tools if allowed_tools is not None else {"lookup_record"}
    return GuardedRuntime(
        context,
        registry,
        AllowListPolicy(policy_tools),
        audit or InMemoryAuditSink(),
    )


def effective_allowed_tools(client: ControlPlaneAgentClient) -> tuple[set[str], str]:
    """Read and validate the central tool allow-list and policy version."""
    effective = client.effective_policy()
    if effective.get("emergencyStop") is True:
        raise SystemExit("effective enterprise emergency stop is active")
    policy = effective.get("policy")
    configuration = policy.get("configuration") if isinstance(policy, Mapping) else None
    tools = configuration.get("tools") if isinstance(configuration, Mapping) else None
    allowed = tools.get("allowed") if isinstance(tools, Mapping) else None
    if allowed is None and isinstance(configuration, Mapping):
        runtime = configuration.get("runtime")
        allowed = runtime.get("allowedTools") if isinstance(runtime, Mapping) else None
    policy_id = policy.get("id") if isinstance(policy, Mapping) else None
    version = policy.get("version") if isinstance(policy, Mapping) else None
    if (
        not isinstance(allowed, list)
        or any(not isinstance(item, str) or not item.strip() for item in allowed)
        or not isinstance(policy_id, str)
        or not isinstance(version, int)
    ):
        raise SystemExit("effective enterprise policy has no valid tools allow-list or version")
    return set(allowed), f"{policy_id}@{version}"


if __name__ == "__main__":
    try:
        agent_host = AgentHost(os.environ.get("AAI_SEC_AGENT_HOST", AgentHost.CLAUDE_CODE))
    except ValueError as exc:
        raise SystemExit("AAI_SEC_AGENT_HOST must name a supported SDK host") from exc
    control_plane_url = os.environ.get("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL") or os.environ.get(
        "AAI_SEC_CONTROL_PLANE_URL"
    )
    heartbeat_stop = threading.Event()
    heartbeat_thread: threading.Thread | None = None
    client: ControlPlaneAgentClient | None = None
    session_id: str | None = None
    session_state: dict[str, str] | None = None
    runtime: GuardedRuntime | None = None
    try:
        if control_plane_url:
            agent_token = os.environ.get("AAI_SEC_AGENT_TOKEN")
            if not agent_token:
                raise SystemExit(
                    "AAI_SEC_AGENT_TOKEN is required when agent registration is enabled"
                )
            agent_client = ControlPlaneAgentClient(
                control_plane_url,
                agent_token,
                agent_id=os.environ.get("AAI_SEC_AGENT_ID", "claude-code-local"),
                project_root=os.environ.get("CLAUDE_PROJECT_DIR", str(Path.cwd())),
                deployment_id=os.environ.get("AAI_SEC_DEPLOYMENT_ID"),
                aws_agent_session=os.environ.get("AAI_SEC_AGENT_SESSION_MODE") == "aws",
                host=agent_host,
            )
            session_state = {"token": agent_client.register()}
            client = agent_client
            session_id = session_state["token"]
            allowed, _policy_version = effective_allowed_tools(agent_client)
            runtime = build_runtime(
                allowed,
                (
                    ReplicatedAuditSink(
                        InMemoryAuditSink(),
                        ControlPlaneDecisionExporter(agent_client, source="mcp"),
                    )
                    if agent_client.aws_agent_session
                    else InMemoryAuditSink()
                ),
            )
            if runtime is None:
                raise SystemExit("security runtime was not initialized")
            managed_runtime = runtime
            interval = float(os.environ.get("AAI_SEC_AGENT_HEARTBEAT_SECONDS", "30"))
            if interval <= 0:
                raise SystemExit("AAI_SEC_AGENT_HEARTBEAT_SECONDS must be positive")

            def heartbeat() -> None:
                """Keep presence live and stop the runtime if the control plane is lost."""
                while not heartbeat_stop.wait(interval):
                    try:
                        assert session_state is not None
                        heartbeat_result = agent_client.heartbeat(
                            session_state["token"],
                            managed_runtime.telemetry(),
                        )
                        session_state["token"] = agent_client.token
                        if heartbeat_result.get("emergencyStop") is True:
                            managed_runtime.stop()
                            return
                        refreshed_tools, refreshed_version = effective_allowed_tools(agent_client)
                        managed_runtime.replace_policy(AllowListPolicy(refreshed_tools))
                        del refreshed_version
                    except Exception:
                        if runtime is not None:
                            runtime.stop()
                        return

            heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
            heartbeat_thread.start()
        else:
            runtime = build_runtime()
        if runtime is None:
            raise SystemExit("security runtime was not initialized")
        integration_for(agent_host, runtime).serve_stdio()
    finally:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=2)
        if client is not None and session_state is not None:
            try:
                client.disconnect(session_state["token"])
            except Exception:
                if runtime is not None:
                    runtime.stop()

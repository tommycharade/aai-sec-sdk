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
    ControlPlaneAgentClient,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    Principal,
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


def build_runtime() -> GuardedRuntime:
    """Build the application-owned runtime for one authenticated task."""
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
    return GuardedRuntime(
        context,
        registry,
        AllowListPolicy({"lookup_record"}),
        InMemoryAuditSink(),
    )


if __name__ == "__main__":
    runtime = build_runtime()
    control_plane_url = os.environ.get("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL") or os.environ.get(
        "AAI_SEC_CONTROL_PLANE_URL"
    )
    heartbeat_stop = threading.Event()
    heartbeat_thread: threading.Thread | None = None
    client: ControlPlaneAgentClient | None = None
    session_id: str | None = None
    if control_plane_url:
        agent_token = os.environ.get("AAI_SEC_AGENT_TOKEN")
        if not agent_token:
            raise SystemExit("AAI_SEC_AGENT_TOKEN is required when agent registration is enabled")
        agent_client = ControlPlaneAgentClient(
            control_plane_url,
            agent_token,
            agent_id=os.environ.get("AAI_SEC_AGENT_ID", "claude-code-local"),
            project_root=os.environ.get("CLAUDE_PROJECT_DIR", str(Path.cwd())),
            deployment_id=os.environ.get("AAI_SEC_DEPLOYMENT_ID"),
        )
        registered_session = agent_client.register()
        client = agent_client
        session_id = registered_session
        interval = float(os.environ.get("AAI_SEC_AGENT_HEARTBEAT_SECONDS", "30"))
        if interval <= 0:
            raise SystemExit("AAI_SEC_AGENT_HEARTBEAT_SECONDS must be positive")

        def heartbeat() -> None:
            """Keep presence live and stop the runtime if the control plane is lost."""
            while not heartbeat_stop.wait(interval):
                try:
                    agent_client.heartbeat(registered_session)
                except Exception:
                    runtime.stop()
                    return

        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
        heartbeat_thread.start()
    try:
        integration_for(AgentHost.CLAUDE_CODE, runtime).serve_stdio()
    finally:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=2)
        if client is not None and session_id is not None:
            try:
                client.disconnect(session_id)
            except Exception:
                runtime.stop()

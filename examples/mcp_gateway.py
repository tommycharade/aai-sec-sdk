"""Runnable MCP gateway bootstrap using synthetic data only.

Run from the repository root and configure the process as an MCP stdio server
in any supported host. The host profile can be changed to another
``AgentHost`` without changing the security runtime.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentic_security import (
    AgentHost,
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
    integration_for(AgentHost.CLAUDE_CODE, build_runtime()).serve_stdio()

"""Small, runnable example of the fail-closed execution boundary.

Run with ``python examples/guarded_runtime.py`` from the repository root.
The example uses only synthetic data and an in-memory audit/approval provider.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentic_security import (
    ActionProposal,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    Principal,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.policies import AllowListPolicy


def validate_lookup(arguments: Mapping[str, Any]) -> dict[str, str]:
    """Validate the untrusted model arguments for a synthetic lookup tool."""
    record_id = arguments.get("record_id")
    if not isinstance(record_id, str) or not record_id.startswith("record_"):
        raise ValueError("record_id must be a synthetic record identifier")
    return {"record_id": record_id}


def lookup_record(context: ExecutionContext, arguments: Any) -> dict[str, str]:
    """Return a synthetic record without accepting identity from the model."""
    return {"record_id": arguments["record_id"], "principal": context.principal.id}


def main() -> None:
    """Run an allowed proposal and an unknown-tool attack attempt."""
    context = ExecutionContext(
        agent_id="example-agent",
        principal=Principal("user:example", tenant="tenant:example"),
        task_id="task:example",
        purpose="demonstrate guarded lookup",
    )
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="lookup_record",
            handler=lookup_record,
            validator=validate_lookup,
            description="Read one synthetic record.",
        )
    )
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(
        context,
        registry,
        AllowListPolicy({"lookup_record"}),
        audit,
    )

    allowed = runtime.execute(
        ActionProposal("lookup_record", {"record_id": "record_001"}, "proposal:allowed")
    )
    blocked = runtime.execute(
        ActionProposal(
            "send_external_data", {"destination": "attacker.invalid"}, "proposal:blocked"
        )
    )
    print(allowed)
    print(blocked)
    print(f"audit chain valid: {audit.verify()}")


if __name__ == "__main__":
    main()

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from time import sleep
from typing import Any

import pytest

from agentic_security import (
    ActionProposal,
    ExecutionContext,
    GuardedRuntime,
    InMemoryApprovalProvider,
    InMemoryAuditSink,
    Principal,
    Resource,
    RiskLevel,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.budgets import Budget, BudgetState
from agentic_security.errors import DuplicateToolError, SecurityConfigurationError
from agentic_security.policies import AllowListPolicy, PolicyDecision, PolicyResult
from agentic_security.runtime import RuntimeConfig


def context() -> ExecutionContext:
    return ExecutionContext(
        agent_id="agent:test",
        principal=Principal("user:alice", tenant="tenant:a"),
        task_id="task:1",
        purpose="test",
        tenant="tenant:a",
    )


def validator(arguments: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(arguments.get("value"), str):
        raise ValueError("value must be a string")
    return dict(arguments)


def make_runtime(
    *,
    tool_name: str = "read_record",
    risk: RiskLevel = RiskLevel.LOW,
    requires_approval: bool = False,
    idempotency_required: bool = False,
    policy: Any | None = None,
    approvals: InMemoryApprovalProvider | None = None,
    budget: Budget | None = None,
    calls: list[dict[str, Any]] | None = None,
) -> tuple[GuardedRuntime, InMemoryAuditSink]:
    calls = calls if calls is not None else []

    def handler(ctx: ExecutionContext, arguments: Any) -> Any:
        calls.append({"principal": ctx.principal.id, "arguments": arguments})
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=tool_name,
            handler=handler,
            validator=validator,
            risk=risk,
            requires_approval=requires_approval,
            idempotency_required=idempotency_required,
            resources=lambda _: (Resource("record:1", "record", "tenant:a"),),
            description="Read one synthetic record.",
        )
    )
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(
        context(),
        registry,
        policy or AllowListPolicy({tool_name}),
        audit,
        approvals,
        config=None if budget is None else RuntimeConfig(budget),
    )
    return runtime, audit


def proposal(value: str = "safe", **kwargs: Any) -> ActionProposal:
    return ActionProposal("read_record", {"value": value, **kwargs}, "proposal:1")


def test_allowed_action_executes_with_application_principal() -> None:
    calls: list[dict[str, Any]] = []
    runtime, audit = make_runtime(calls=calls)

    result = runtime.execute(proposal())

    assert result.status == "executed"
    assert calls == [{"principal": "user:alice", "arguments": {"value": "safe"}}]
    assert audit.verify()


def test_unknown_tool_is_denied_without_side_effect() -> None:
    runtime, audit = make_runtime()

    result = runtime.execute(ActionProposal("delete_everything", {}, "proposal:2"))

    assert result.status == "denied"
    assert result.reason == "unknown tool"
    assert audit.events()[0].event_type == "action_denied"


def test_invalid_arguments_are_denied_before_policy_and_handler() -> None:
    calls: list[dict[str, Any]] = []
    runtime, audit = make_runtime(calls=calls)

    result = runtime.execute(ActionProposal("read_record", {"value": 7}, "proposal:3"))

    assert result.status == "denied"
    assert "invalid tool arguments" in (result.reason or "")
    assert calls == []
    assert audit.verify()


def test_policy_is_evaluated_per_action_with_live_resource() -> None:
    observed: list[tuple[str, str]] = []

    class RecordingPolicy:
        def decide(
            self, ctx: Any, tool: Any, args: Any, resources: tuple[Resource, ...]
        ) -> PolicyResult:
            observed.append((ctx.principal.id, resources[0].id))
            return PolicyResult(PolicyDecision.DENY, "test policy denial")

    runtime, _ = make_runtime(policy=RecordingPolicy())
    result = runtime.execute(proposal())

    assert result.status == "denied"
    assert observed == [("user:alice", "record:1")]


def test_default_policy_denies_cross_tenant_resource() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="cross_tenant_lookup",
            handler=lambda *_: {"unexpected": True},
            validator=validator,
            resources=lambda _: (Resource("record:other", "record", "tenant:other"),),
            description="Synthetic cross-tenant lookup.",
        )
    )
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(context(), registry, AllowListPolicy({"cross_tenant_lookup"}), audit)

    result = runtime.execute(
        ActionProposal("cross_tenant_lookup", {"value": "safe"}, "proposal:tenant")
    )

    assert result.status == "denied"
    assert result.reason == "resource is outside the task tenant"


def test_high_impact_tool_requires_approval_at_configuration_time() -> None:
    with pytest.raises(SecurityConfigurationError):
        ToolDefinition(
            name="move_funds",
            handler=lambda *_: None,
            validator=validator,
            risk=RiskLevel.HIGH,
            description="Synthetic funds movement.",
        )


def test_approval_is_scoped_single_use_and_not_replayable() -> None:
    approvals = InMemoryApprovalProvider()
    runtime, _ = make_runtime(
        risk=RiskLevel.HIGH,
        requires_approval=True,
        approvals=approvals,
    )
    grant = approvals.issue("approval:1", context(), "read_record", "proposal:1", "approver:1")

    first = runtime.execute(
        ActionProposal("read_record", {"value": "safe"}, "proposal:1", grant.approval_id)
    )
    replay = runtime.execute(
        ActionProposal("read_record", {"value": "safe"}, "proposal:1", grant.approval_id)
    )

    assert first.status == "executed"
    assert replay.status == "denied"
    assert "approval" in (replay.reason or "")


def test_expired_approval_is_denied() -> None:
    now = [datetime.now(UTC)]
    approvals = InMemoryApprovalProvider(lambda: now[0])
    runtime, _ = make_runtime(risk=RiskLevel.HIGH, requires_approval=True, approvals=approvals)
    grant = approvals.issue("approval:2", context(), "read_record", "proposal:1", "approver:1", 1)
    now[0] += timedelta(seconds=2)

    result = runtime.execute(
        ActionProposal("read_record", {"value": "safe"}, "proposal:1", grant.approval_id)
    )

    assert result.status == "denied"


def test_idempotency_returns_original_result_without_second_side_effect() -> None:
    calls: list[dict[str, Any]] = []
    runtime, _ = make_runtime(idempotency_required=True, calls=calls)

    first = runtime.execute(proposal())
    second = runtime.execute(proposal())

    assert first == second
    assert len(calls) == 1


def test_idempotency_prevents_concurrent_duplicate_side_effects() -> None:
    calls: list[dict[str, Any]] = []

    def slow_handler(ctx: ExecutionContext, arguments: Any) -> Any:
        calls.append({"principal": ctx.principal.id, "arguments": arguments})
        sleep(0.01)
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="idempotent_action",
            handler=slow_handler,
            validator=validator,
            idempotency_required=True,
            description="Synthetic action with one side effect.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"idempotent_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(Budget(max_actions=2, max_concurrent=2)),
    )
    action = ActionProposal("idempotent_action", {"value": "safe"}, "proposal:concurrent")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(runtime.execute, [action, action]))

    assert results[0] == results[1]
    assert len(calls) == 1


def test_stop_switch_denies_future_actions() -> None:
    calls: list[dict[str, Any]] = []
    runtime, _ = make_runtime(calls=calls)
    runtime.stop()

    result = runtime.execute(proposal())

    assert result.status == "denied"
    assert calls == []


def test_budget_is_fail_closed() -> None:
    runtime, _ = make_runtime(budget=Budget(max_actions=1))

    assert runtime.execute(proposal()).status == "executed"
    assert (
        runtime.execute(ActionProposal("read_record", {"value": "next"}, "proposal:2")).status
        == "denied"
    )


def test_audit_redacts_secret_keys_and_emails() -> None:
    audit = InMemoryAuditSink()
    event = audit.append(
        "test",
        "request:1",
        {"token": "secret-value", "message": "contact alice@example.com"},
    )

    assert event.payload == {"token": "[REDACTED]", "message": "contact [EMAIL]"}
    assert "secret-value" not in str(event.payload)
    assert audit.verify()


def test_registry_rejects_duplicate_tool_names() -> None:
    registry = ToolRegistry()
    tool = ToolDefinition("one", lambda *_: None, validator, description="One tool.")
    registry.register(tool)

    with pytest.raises(DuplicateToolError):
        registry.register(tool)


def test_budget_state_rejects_concurrent_over_allocation() -> None:
    state = BudgetState(Budget(max_actions=2, max_concurrent=1))

    assert state.acquire()
    assert not state.acquire()
    state.release()
    assert state.acquire()

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from time import sleep
from typing import Any

import pytest

from agentic_security import (
    ActionProposal,
    ExecutionContext,
    ExecutionStatus,
    GuardedRuntime,
    InMemoryApprovalProvider,
    InMemoryAuditSink,
    Principal,
    Resource,
    RiskLevel,
    ToolDefinition,
    ToolRegistry,
    action_hash,
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
            reconciliation=(lambda _context, _arguments: None)
            if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            else None,
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


def test_tool_results_are_redacted_before_crossing_runtime_boundary() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="secret_result",
            handler=lambda *_: {"access_token": "synthetic", "value": "safe"},
            validator=validator,
            description="Synthetic result containing a secret-shaped field.",
        )
    )
    runtime = GuardedRuntime(
        context(), registry, AllowListPolicy({"secret_result"}), InMemoryAuditSink()
    )

    result = runtime.execute(ActionProposal("secret_result", {"value": "safe"}, "proposal:result"))

    assert result.status is ExecutionStatus.EXECUTED
    assert result.output == {"access_token": "[REDACTED]", "value": "safe"}


def test_custom_audit_sink_receives_redacted_arguments() -> None:
    class RecordingAudit:
        def __init__(self) -> None:
            self.payloads: list[dict[str, Any]] = []

        def append(self, _event_type: str, _request_id: str, payload: dict[str, Any]) -> None:
            self.payloads.append(payload)

    audit = RecordingAudit()
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "audit_secret",
            lambda *_: {"ok": True},
            lambda arguments: dict(arguments),
            description="Synthetic audit-redaction test.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"audit_secret"}),
        audit,  # type: ignore[arg-type]
    )

    result = runtime.execute(
        ActionProposal(
            "audit_secret",
            {"value": "safe", "access_token": "synthetic-token"},
            "proposal:audit-redaction",
        )
    )

    assert result.status is ExecutionStatus.EXECUTED
    assert audit.payloads[0]["arguments"]["access_token"] == "[REDACTED]"  # noqa: S105
    assert "synthetic-token" not in str(audit.payloads)


def test_policy_timeout_fails_closed() -> None:
    blocked = Event()
    release = Event()

    class SlowPolicy:
        def decide(self, *_: Any) -> PolicyResult:
            blocked.set()
            release.wait(1)
            return PolicyResult(PolicyDecision.ALLOW, "late")

    runtime, _ = make_runtime(policy=SlowPolicy())
    runtime.config = RuntimeConfig(execution_timeout_seconds=0.005)
    result = runtime.execute(proposal("safe", secret="synthetic"))  # noqa: S106

    assert blocked.is_set()
    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "policy evaluation timed out"
    release.set()


def test_credential_timeout_fails_closed_before_handler() -> None:
    blocked = Event()
    release = Event()

    class SlowBroker:
        def mint(self, *_: Any) -> Any:
            blocked.set()
            release.wait(1)
            raise AssertionError("credential mint should have timed out")

    calls: list[bool] = []
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "credential_action",
            lambda *_: calls.append(True),
            validator,
            requires_credential=True,
            description="Synthetic credential timeout test.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"credential_action"}),
        InMemoryAuditSink(),
        credentials=SlowBroker(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )

    result = runtime.execute(
        ActionProposal("credential_action", {"value": "safe"}, "proposal:cred-timeout")
    )

    assert blocked.is_set()
    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "credential minting timed out"
    assert calls == []
    release.set()


def test_audit_timeout_reports_unrecorded_execution() -> None:
    blocked = Event()
    release = Event()

    class SlowAudit:
        def append(self, *_: Any) -> None:
            blocked.set()
            release.wait(1)

    runtime, _ = make_runtime()
    runtime.audit = SlowAudit()  # type: ignore[assignment]
    runtime.config = RuntimeConfig(execution_timeout_seconds=0.005)

    result = runtime.execute(proposal())

    assert blocked.is_set()
    assert result.status is ExecutionStatus.EXECUTED_UNRECORDED
    assert result.audit_recorded is False
    release.set()


def test_oversized_tool_results_are_rejected_after_side_effect() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="large_result",
            handler=lambda *_: {"value": "x" * 100},
            validator=validator,
            max_output_bytes=10,
            description="Synthetic oversized result.",
        )
    )
    runtime = GuardedRuntime(
        context(), registry, AllowListPolicy({"large_result"}), InMemoryAuditSink()
    )

    result = runtime.execute(ActionProposal("large_result", {"value": "safe"}, "proposal:large"))

    assert result.status is ExecutionStatus.EXECUTED_RESULT_REJECTED
    assert result.output is None


def test_unknown_tool_is_denied_without_side_effect() -> None:
    runtime, audit = make_runtime()

    result = runtime.execute(ActionProposal("delete_everything", {}, "proposal:2"))

    assert result.status == "denied"
    assert result.reason == "unknown tool"
    assert audit.events()[0].event_type == "action_denied"


def test_malformed_tool_and_arguments_fail_closed_without_audit_crash() -> None:
    runtime, audit = make_runtime()

    malformed_tool = runtime.execute(ActionProposal([], {}, "proposal:bad-tool"))  # type: ignore[arg-type]
    malformed_arguments = runtime.execute(
        ActionProposal("read_record", "not-a-mapping", "proposal:bad-args")  # type: ignore[arg-type]
    )

    assert malformed_tool.status == "denied"
    assert malformed_tool.reason == "malformed tool"
    assert malformed_arguments.status == "denied"
    assert malformed_arguments.reason == "invalid tool arguments"
    assert audit.verify()


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


def test_malformed_policy_decision_fails_closed() -> None:
    calls: list[dict[str, Any]] = []

    class MalformedPolicy:
        def decide(self, *_: Any) -> Any:
            return PolicyResult("deny", "malformed decision")  # type: ignore[arg-type]

    runtime, _ = make_runtime(policy=MalformedPolicy(), calls=calls)

    result = runtime.execute(proposal())

    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "policy returned an invalid decision"
    assert calls == []


def test_audit_failure_returns_explicit_unrecorded_outcome_after_handler() -> None:
    class BrokenAudit:
        def append(self, *_: Any) -> Any:
            raise RuntimeError("audit unavailable")

    calls: list[bool] = []
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="write_record",
            handler=lambda *_: calls.append(True),
            validator=validator,
            description="Synthetic write for audit failure testing.",
        )
    )
    runtime = GuardedRuntime(context(), registry, AllowListPolicy({"write_record"}), BrokenAudit())

    result = runtime.execute(
        ActionProposal("write_record", {"value": "safe"}, "proposal:audit-failure")
    )

    assert result.status is ExecutionStatus.EXECUTED_UNRECORDED
    assert result.audit_recorded is False
    assert calls == [True]


def test_handler_timeout_is_structured_and_signals_cancellation() -> None:
    observed = Event()

    def slow_handler(ctx: ExecutionContext, _: Any) -> Any:
        observed.set()
        sleep(0.05)
        return {"cancelled": ctx.cancellation.is_cancelled() if ctx.cancellation else False}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="slow_action",
            handler=slow_handler,
            validator=validator,
            description="Synthetic slow action.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"slow_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )

    result = runtime.execute(ActionProposal("slow_action", {"value": "safe"}, "proposal:timeout"))

    assert observed.is_set()
    assert result.status is ExecutionStatus.TIMED_OUT


def test_timed_out_handler_keeps_concurrency_slot_until_worker_exits() -> None:
    started = Event()
    release = Event()
    calls: list[str] = []

    def slow_handler(_context: ExecutionContext, _arguments: Any) -> dict[str, bool]:
        started.set()
        release.wait(1)
        calls.append("slow-finished")
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "slow_action",
            slow_handler,
            validator,
            description="Synthetic non-cooperative timeout test.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"slow_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(Budget(max_actions=3, max_concurrent=1), 0.005),
    )

    first = runtime.execute(ActionProposal("slow_action", {"value": "safe"}, "proposal:slow-1"))
    assert first.status is ExecutionStatus.TIMED_OUT
    assert started.is_set()

    second = runtime.execute(ActionProposal("slow_action", {"value": "safe"}, "proposal:slow-2"))
    assert second.status is ExecutionStatus.DENIED
    assert "concurrency" in (second.reason or "")

    release.set()
    for _ in range(100):
        if calls:
            break
        sleep(0.001)
    assert calls == ["slow-finished"]


def test_stop_requests_cancellation_for_cooperative_handler() -> None:
    started = Event()

    def cancellable_handler(ctx: ExecutionContext, _: Any) -> Any:
        started.set()
        while True:
            if ctx.cancellation is not None:
                ctx.cancellation.raise_if_cancelled()
            sleep(0.001)

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="cancellable_action",
            handler=cancellable_handler,
            validator=validator,
            description="Synthetic cancellable action.",
        )
    )
    runtime = GuardedRuntime(
        context(), registry, AllowListPolicy({"cancellable_action"}), InMemoryAuditSink()
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runtime.execute,
            ActionProposal("cancellable_action", {"value": "safe"}, "proposal:cancel"),
        )
        assert started.wait(1)
        runtime.stop()
        result = future.result(timeout=1)

    assert result.status is ExecutionStatus.CANCELLED


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


def test_tenant_context_rejects_missing_tenant_metadata() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="unscoped_lookup",
            handler=lambda *_: {"unexpected": True},
            validator=validator,
            resources=lambda _: (Resource("record:unscoped", "record", "tenant:a"),),
            description="Synthetic unscoped lookup.",
        )
    )
    with pytest.raises(SecurityConfigurationError, match="principal tenant is required"):
        Principal("user:alice")
    with pytest.raises(SecurityConfigurationError, match="task tenant is required"):
        ExecutionContext(
            "agent:test",
            Principal("user:alice", tenant="tenant:a"),
            "task:1",
            "test",
        )


def test_high_impact_tool_requires_approval_at_configuration_time() -> None:
    with pytest.raises(SecurityConfigurationError):
        ToolDefinition(
            name="move_funds",
            handler=lambda *_: None,
            validator=validator,
            risk=RiskLevel.HIGH,
            description="Synthetic funds movement.",
        )


def test_high_impact_tool_requires_idempotency_or_reconciliation() -> None:
    with pytest.raises(SecurityConfigurationError, match="idempotency or declare reconciliation"):
        ToolDefinition(
            name="non_idempotent_funds",
            handler=lambda *_: None,
            validator=validator,
            risk=RiskLevel.HIGH,
            requires_approval=True,
            description="Synthetic non-idempotent high-impact action.",
        )

    ToolDefinition(
        name="reconciled_funds",
        handler=lambda *_: None,
        validator=validator,
        risk=RiskLevel.HIGH,
        requires_approval=True,
        reconciliation=lambda _context, _arguments: None,
        description="Synthetic reconciled high-impact action.",
    )


def test_incomplete_host_identity_is_rejected() -> None:
    with pytest.raises(SecurityConfigurationError):
        Principal("")
    with pytest.raises(SecurityConfigurationError):
        ExecutionContext("", Principal("user:test"), "task:1", "test")


def test_approval_is_scoped_single_use_and_not_replayable() -> None:
    approvals = InMemoryApprovalProvider()
    runtime, _ = make_runtime(
        risk=RiskLevel.HIGH,
        requires_approval=True,
        approvals=approvals,
    )
    grant = approvals.issue(
        "approval:1",
        context(),
        "read_record",
        "proposal:1",
        "approver:1",
        action_hash(
            context(),
            "read_record",
            {"value": "safe"},
            (Resource("record:1", "record", "tenant:a"),),
        ),
    )

    first = runtime.execute(
        ActionProposal("read_record", {"value": "safe"}, "proposal:1", grant.approval_id)
    )
    replay = runtime.execute(
        ActionProposal("read_record", {"value": "safe"}, "proposal:1", grant.approval_id)
    )

    assert first.status == "executed"
    assert replay.status == "denied"
    assert "approval" in (replay.reason or "")


def test_approval_is_bound_to_validated_arguments() -> None:
    approvals = InMemoryApprovalProvider()
    runtime, _ = make_runtime(risk=RiskLevel.HIGH, requires_approval=True, approvals=approvals)
    grant = approvals.issue(
        "approval:bound",
        context(),
        "read_record",
        "proposal:bound",
        "approver:1",
        action_hash(
            context(),
            "read_record",
            {"value": "safe"},
            (Resource("record:1", "record", "tenant:a"),),
        ),
    )

    result = runtime.execute(
        ActionProposal("read_record", {"value": "changed"}, "proposal:bound", grant.approval_id)
    )

    assert result.status == "denied"
    assert "approval" in (result.reason or "")


def test_expired_approval_is_denied() -> None:
    now = [datetime.now(UTC)]
    approvals = InMemoryApprovalProvider(lambda: now[0])
    runtime, _ = make_runtime(risk=RiskLevel.HIGH, requires_approval=True, approvals=approvals)
    grant = approvals.issue(
        "approval:2",
        context(),
        "read_record",
        "proposal:1",
        "approver:1",
        action_hash(
            context(),
            "read_record",
            {"value": "safe"},
            (Resource("record:1", "record", "tenant:a"),),
        ),
        1,
    )
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


def test_idempotency_key_includes_tool_and_arguments() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="first_action",
            handler=lambda *_: {"tool": "first"},
            validator=validator,
            idempotency_required=True,
            description="First synthetic action.",
        )
    )
    registry.register(
        ToolDefinition(
            name="second_action",
            handler=lambda *_: {"tool": "second"},
            validator=validator,
            idempotency_required=True,
            description="Second synthetic action.",
        )
    )
    runtime = GuardedRuntime(
        context(), registry, AllowListPolicy({"first_action", "second_action"}), InMemoryAuditSink()
    )

    first = runtime.execute(ActionProposal("first_action", {"value": "safe"}, "proposal:same"))
    second = runtime.execute(ActionProposal("second_action", {"value": "safe"}, "proposal:same"))

    assert first.output == {"tool": "first"}
    assert second.output == {"tool": "second"}


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


def test_external_egress_requires_approval() -> None:
    with pytest.raises(SecurityConfigurationError):
        ToolDefinition(
            name="send_data",
            handler=lambda *_: None,
            validator=validator,
            external_egress=True,
            description="Synthetic external send.",
        )


def test_budget_state_rejects_concurrent_over_allocation() -> None:
    state = BudgetState(Budget(max_actions=2, max_concurrent=1))

    assert state.acquire()
    assert not state.acquire()
    state.release()
    assert state.acquire()

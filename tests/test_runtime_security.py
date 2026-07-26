from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from math import inf, nan
from threading import Event
from time import sleep
from typing import Any
from uuid import UUID

import pytest

from agentic_security import (
    ActionProposal,
    ApprovalOutcome,
    CancellationToken,
    ExecutionContext,
    ExecutionStatus,
    GuardedRuntime,
    InMemoryApprovalProvider,
    InMemoryAuditSink,
    InMemoryIdempotencyStore,
    Principal,
    Resource,
    RiskLevel,
    SideEffectState,
    TimeoutPhase,
    ToolDefinition,
    ToolRegistry,
    action_hash,
)
from agentic_security.approvals import ApprovalConsumption
from agentic_security.budgets import Budget, BudgetState
from agentic_security.components import ActionBudgetLease, ActionFacts
from agentic_security.errors import (
    DuplicateToolError,
    RuntimeOperationTimeoutError,
    SecurityConfigurationError,
)
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


@pytest.fixture(autouse=True)
def host_denials_always_have_request_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every host denial must retain the UUID created at the execution boundary."""
    original = GuardedRuntime._deny

    def deny_with_identity(
        runtime: GuardedRuntime,
        request_id: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        assert isinstance(request_id, str) and UUID(request_id)
        return original(runtime, request_id, *args, **kwargs)

    monkeypatch.setattr(GuardedRuntime, "_deny", deny_with_identity)


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
            reconciliation=(lambda _context, _arguments: True)
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
        config=RuntimeConfig(
            budget or Budget(),
            idempotency_store=InMemoryIdempotencyStore(),
        ),
    )
    return runtime, audit


def test_run_handler_contract_passes_bounded_handler_metadata_and_timeout_hooks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The handler boundary must preserve its phase, request, and cancellation hooks."""
    calls: list[Any] = []
    runtime, _ = make_runtime(calls=calls)
    tool = runtime.registry.get("read_record")
    assert tool is not None
    facts = ActionFacts(
        runtime.context,
        ActionProposal("read_record", {"value": "safe"}, "proposal:direct-handler"),
        tool,
        {"value": "safe"},
        (Resource("record:1", "record", "tenant:a"),),
        "fingerprint:direct-handler",
    )
    permit = runtime._authorizer.issue_permit(
        facts,
        PolicyResult(PolicyDecision.ALLOW, "allowed"),
        None,
        None,
        False,
        runtime.context,
        CancellationToken(),
    )
    state = ActionBudgetLease()

    def bounded(
        operation: Any,
        operation_name: str,
        *,
        on_timeout: Any,
        request_id: str | None,
        on_timeout_observed: Any,
        timeout_phase: TimeoutPhase | None,
    ) -> Any:
        calls.extend([operation_name, request_id, on_timeout, on_timeout_observed, timeout_phase])
        return operation()

    monkeypatch.setattr(runtime, "_run_bounded", bounded)
    assert runtime._run_handler(permit, "request:handler", state) == {"ok": True}
    assert calls[0] == "handler execution"
    assert calls[1] == "request:handler"
    assert calls[2] is not None
    assert calls[3] is not None
    assert calls[4] is TimeoutPhase.HANDLER


def test_consume_approval_contract_passes_live_binding_and_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Approval consumption must receive the exact live action binding."""
    runtime, _ = make_runtime()
    seen: list[Any] = []

    class Provider:
        def consume(self, *args: Any) -> ApprovalConsumption:
            seen.extend(args)
            return ApprovalConsumption(ApprovalOutcome.CONSUMED, "consumed")

    def bounded(
        operation: Any,
        operation_name: str,
        *,
        on_timeout: Any,
        request_id: str | None,
        on_timeout_observed: Any,
        timeout_phase: TimeoutPhase | None,
    ) -> Any:
        assert operation_name == "approval consumption"
        assert request_id == "request:approval"
        assert on_timeout is not None
        assert on_timeout_observed is not None
        assert timeout_phase is TimeoutPhase.APPROVAL
        return operation()

    monkeypatch.setattr(runtime, "_run_bounded", bounded)
    result = runtime._consume_approval_bounded(
        Provider(),
        "approval:1",
        "read_record",
        "proposal:1",
        "hash:live",
        "request:approval",
        ActionBudgetLease(),
    )
    assert result.outcome is ApprovalOutcome.CONSUMED
    assert seen == [
        "approval:1",
        runtime.context,
        "read_record",
        "proposal:1",
        "hash:live",
    ]


def proposal(
    value: Any = "safe", operation_key: str | None = None, **kwargs: Any
) -> ActionProposal:
    return ActionProposal(
        "read_record", {"value": value, **kwargs}, "proposal:1", operation_key=operation_key
    )


def test_allowed_action_executes_with_application_principal() -> None:
    calls: list[dict[str, Any]] = []
    runtime, audit = make_runtime(calls=calls)

    result = runtime.execute(proposal())

    assert result.status == "executed"
    assert calls == [{"principal": "user:alice", "arguments": {"value": "safe"}}]
    assert audit.verify()


def _stopped_runtime_case() -> tuple[GuardedRuntime, ActionProposal]:
    runtime, _ = make_runtime()
    runtime.stop()
    return runtime, proposal()


def _exhausted_runtime_case() -> tuple[GuardedRuntime, ActionProposal]:
    runtime, _ = make_runtime(budget=Budget(max_actions=1))
    assert runtime.execute(proposal()).status in {
        ExecutionStatus.EXECUTED,
        ExecutionStatus.EXECUTED_UNRECORDED,
    }
    return runtime, proposal()


@pytest.mark.parametrize(
    ("case", "build"),
    [
        ("unknown tool", lambda: (make_runtime()[0], ActionProposal("missing", {}, "p:1"))),
        (
            "invalid arguments",
            lambda: (make_runtime()[0], proposal(value=42)),
        ),
        (
            "policy denial",
            lambda: (make_runtime(policy=AllowListPolicy({"other"}))[0], proposal()),
        ),
        (
            "approval missing",
            lambda: (
                make_runtime(requires_approval=True)[0],
                proposal(),
            ),
        ),
        ("emergency stop", _stopped_runtime_case),
        ("budget exhausted", _exhausted_runtime_case),
    ],
)
def test_every_early_denial_keeps_a_host_request_identity(
    case: str,
    build: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every denial branch must preserve the host-generated request identity."""
    runtime, action = build()
    original_deny = runtime._deny

    def deny_with_identity(request_id: str, *args: Any, **kwargs: Any) -> Any:
        assert isinstance(request_id, str) and UUID(request_id), case
        return original_deny(request_id, *args, **kwargs)

    monkeypatch.setattr(runtime, "_deny", deny_with_identity)
    runtime.execute(action)


def test_runtime_bounded_stages_preserve_live_request_and_phase_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Policy and handler workers retain host request, phase, and callbacks."""
    runtime, _ = make_runtime()
    calls: list[tuple[str, str | None, TimeoutPhase | None, bool, bool]] = []
    original = runtime._run_bounded

    def bounded(
        operation: Any,
        operation_name: str,
        *,
        on_timeout: Any,
        request_id: str | None,
        on_timeout_observed: Any,
        timeout_phase: TimeoutPhase | None,
    ) -> Any:
        calls.append(
            (
                operation_name,
                request_id,
                timeout_phase,
                on_timeout is not None,
                on_timeout_observed is not None,
            )
        )
        return original(
            operation,
            operation_name,
            on_timeout=on_timeout,
            request_id=request_id,
            on_timeout_observed=on_timeout_observed,
            timeout_phase=timeout_phase,
        )

    monkeypatch.setattr(runtime, "_run_bounded", bounded)
    assert runtime.execute(proposal()).status in {
        ExecutionStatus.EXECUTED,
        ExecutionStatus.EXECUTED_UNRECORDED,
    }
    assert [call[0] for call in calls] == ["policy evaluation", "handler execution"]
    for operation_name, request_id, phase, has_timeout, observed in calls:
        assert UUID(request_id or "")
        assert phase is (
            TimeoutPhase.POLICY if operation_name == "policy evaluation" else TimeoutPhase.HANDLER
        )
        assert has_timeout and observed


def test_health_reports_host_stop_and_bounded_lifecycle_state() -> None:
    runtime, _ = make_runtime()

    live = runtime.health()
    assert live["stopped"] is False
    assert live["active_actions"] == 0
    assert live["bounded_workers"] == 0
    assert live["timed_out_workers"] == 0

    runtime.stop()
    assert runtime.health()["stopped"] is True


def test_denial_request_ids_and_reasons_are_auditable() -> None:
    """Every host denial keeps one request identity and its exact reason."""
    runtime, audit = make_runtime()
    unknown = runtime.execute(ActionProposal("missing", {"value": "safe"}, "proposal:unknown"))

    assert unknown.status is ExecutionStatus.DENIED
    UUID(unknown.request_id)
    unknown_event = audit.events()[-1]
    assert unknown_event.request_id == unknown.request_id
    assert unknown_event.payload["reason"] == "unknown tool"

    runtime.stop()
    stopped = runtime.execute(proposal())

    assert stopped.status is ExecutionStatus.DENIED
    stopped_event = audit.events()[-1]
    assert stopped_event.request_id == stopped.request_id
    assert stopped_event.payload["reason"] == "runtime emergency stop is active"


def test_malformed_tool_denial_preserves_reason_and_request_identity() -> None:
    """Malformed model-selected tool names are distinct from unknown tools."""
    runtime, audit = make_runtime()

    malformed = object.__new__(ActionProposal)
    object.__setattr__(malformed, "tool_name", 123)
    object.__setattr__(malformed, "arguments", {"value": "safe"})
    object.__setattr__(malformed, "proposal_id", "proposal:malformed")
    object.__setattr__(malformed, "approval_id", None)
    object.__setattr__(malformed, "operation_key", None)
    result = runtime.execute(malformed)

    assert result.status is ExecutionStatus.DENIED
    UUID(result.request_id)
    event = audit.events()[-1]
    assert event.request_id == result.request_id
    assert event.payload["reason"] == "malformed tool"


def test_approval_required_result_and_audit_are_host_bound() -> None:
    """An approval request is non-executing and retains its approval binding."""
    runtime, audit = make_runtime(
        risk=RiskLevel.HIGH,
        requires_approval=True,
    )
    candidate = ActionProposal(
        "read_record",
        {"value": "safe"},
        "proposal:approval-required",
        approval_id="approval:1",
    )

    result = runtime.execute(candidate)

    assert result.status is ExecutionStatus.APPROVAL_REQUIRED
    assert result.approval_id == "approval:1"
    assert result.handler_started is False
    event = audit.events()[-1]
    assert event.event_type == "approval_required"
    assert event.request_id == result.request_id
    assert event.payload["reason"] == "explicit approval is required"


def test_runtime_passes_the_complete_approval_binding_to_the_provider() -> None:
    seen: dict[str, Any] = {}

    class RecordingApproval:
        def consume(
            self,
            approval_id: str,
            ctx: ExecutionContext,
            tool_name: str,
            proposal_id: str,
            fingerprint: str,
        ) -> ApprovalConsumption:
            seen.update(
                approval_id=approval_id,
                context=ctx,
                tool_name=tool_name,
                proposal_id=proposal_id,
                fingerprint=fingerprint,
            )
            return ApprovalConsumption(ApprovalOutcome.NOT_CONSUMED, "synthetic denial")

    runtime, audit = make_runtime(
        risk=RiskLevel.HIGH,
        requires_approval=True,
        approvals=RecordingApproval(),  # type: ignore[arg-type]
    )
    candidate = ActionProposal(
        "read_record",
        {"value": "safe"},
        "proposal:approval-binding",
        approval_id="approval:binding",
    )

    result = runtime.execute(candidate)

    assert result.status is ExecutionStatus.DENIED
    assert seen["approval_id"] == "approval:binding"
    assert seen["context"] is runtime.context
    assert seen["tool_name"] == "read_record"
    assert seen["proposal_id"] == "proposal:approval-binding"
    assert isinstance(seen["fingerprint"], str) and seen["fingerprint"]
    assert audit.verify()


def test_success_audit_binds_request_and_live_policy_provenance() -> None:
    """Execution evidence includes the host decision and its provenance."""

    class VersionedPolicy:
        def decide(self, *_: Any) -> PolicyResult:
            return PolicyResult(PolicyDecision.ALLOW, "approved", "policy-7", "test-policy")

    runtime, audit = make_runtime(policy=VersionedPolicy())
    result = runtime.execute(proposal())

    assert result.status is ExecutionStatus.EXECUTED
    event = audit.events()[-1]
    assert event.event_type == "action_executed"
    assert event.request_id == result.request_id
    assert event.payload["status"] == ExecutionStatus.EXECUTED.value
    assert event.payload["policy_decision"] == PolicyDecision.ALLOW.value
    assert event.payload["policy_version"] == "policy-7"
    assert event.payload["policy_provenance"] == "test-policy"


def test_success_audit_contains_complete_host_identity_context() -> None:
    """Audit records retain every host-owned identity field used for review."""
    runtime, audit = make_runtime()

    result = runtime.execute(proposal("audited"))

    event = audit.events()[-1]
    assert result.status is ExecutionStatus.EXECUTED
    assert event.payload["agent_id"] == "agent:test"
    assert event.payload["principal_id"] == "user:alice"
    assert event.payload["task_id"] == "task:1"
    assert event.payload["purpose"] == "test"
    assert event.payload["tool_name"] == "read_record"
    assert event.payload["proposal_id"] == "proposal:1"
    assert event.payload["arguments"] == {"value": "audited"}


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
    assert result.timeout_phase is TimeoutPhase.POLICY
    assert result.handler_started is False
    assert result.side_effect_state is SideEffectState.NOT_STARTED
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
    assert result.timeout_phase is TimeoutPhase.CREDENTIAL
    assert result.handler_started is False
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
    assert result.timeout_phase is TimeoutPhase.AUDIT
    assert result.handler_started is True
    assert result.side_effect_state is SideEffectState.EXECUTED
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
    assert result.handler_started is True
    assert result.side_effect_state is SideEffectState.EXECUTED


def test_output_at_the_configured_byte_limit_is_accepted() -> None:
    output = {"value": "x"}
    encoded_size = len(b'{"value":"x"}')
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="exact_limit",
            handler=lambda *_: output,
            validator=validator,
            max_output_bytes=encoded_size,
            description="Synthetic exact output limit action.",
        )
    )
    runtime = GuardedRuntime(
        context(), registry, AllowListPolicy({"exact_limit"}), InMemoryAuditSink()
    )

    result = runtime.execute(ActionProposal("exact_limit", {"value": "safe"}, "proposal:limit"))

    assert result.status is ExecutionStatus.EXECUTED
    assert result.output == output


def test_unknown_tool_is_denied_without_side_effect() -> None:
    runtime, audit = make_runtime()

    result = runtime.execute(ActionProposal("delete_everything", {}, "proposal:2"))

    assert result.status == "denied"
    assert result.reason == "unknown tool"
    assert audit.events()[0].event_type == "action_denied"


def test_malformed_tool_and_arguments_fail_closed_without_audit_crash() -> None:
    runtime, audit = make_runtime()

    with pytest.raises(SecurityConfigurationError):
        ActionProposal([], {}, "proposal:bad-tool")  # type: ignore[arg-type]
    with pytest.raises(SecurityConfigurationError):
        ActionProposal("read_record", "not-a-mapping", "proposal:bad-args")  # type: ignore[arg-type]
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


def test_policy_denial_audit_preserves_live_decision_metadata_and_resources() -> None:
    class VersionedDeny:
        def decide(self, *_: Any) -> PolicyResult:
            return PolicyResult(PolicyDecision.DENY, "blocked", "policy-9", "deny-test")

    runtime, audit = make_runtime(policy=VersionedDeny())
    result = runtime.execute(proposal())

    event = audit.events()[-1]
    assert result.status is ExecutionStatus.DENIED
    assert event.payload["resources"] == [
        {"id": "record:1", "kind": "record", "tenant": "tenant:a"}
    ]
    assert event.payload["policy_decision"] == "deny"
    assert event.payload["policy_version"] == "policy-9"
    assert event.payload["policy_provenance"] == "deny-test"


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
    assert result.timeout_phase is TimeoutPhase.HANDLER
    assert result.handler_started is True
    assert result.side_effect_state is SideEffectState.UNCERTAIN


def test_runtime_bounded_timeout_preserves_callback_and_phase() -> None:
    callback = Event()
    runtime, _ = make_runtime()
    runtime.config = RuntimeConfig(execution_timeout_seconds=0.005)

    with pytest.raises(RuntimeOperationTimeoutError) as raised:
        runtime._run_bounded(
            lambda: sleep(0.05),
            "synthetic policy operation",
            on_timeout=callback.set,
            timeout_phase=TimeoutPhase.POLICY,
        )

    assert raised.value.phase is TimeoutPhase.POLICY  # type: ignore[attr-defined]
    assert callback.wait(1)


def test_handler_always_receives_host_cancellation_capability() -> None:
    """The permit path must not silently omit cooperative cancellation."""
    observed: list[bool] = []

    def handler(ctx: ExecutionContext, _: Any) -> dict[str, bool]:
        observed.append(ctx.cancellation is not None)
        return {"cancel-capability": observed[-1]}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="cancellation_contract",
            handler=handler,
            validator=validator,
            description="Synthetic cancellation contract action.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"cancellation_contract"}),
        InMemoryAuditSink(),
    )

    result = runtime.execute(
        ActionProposal("cancellation_contract", {"value": "safe"}, "proposal:cancel-contract")
    )

    assert result.status is ExecutionStatus.EXECUTED
    assert observed == [True]
    assert result.output == {"cancel-capability": True}


def test_handler_contract_rejects_missing_cancellation_capability() -> None:
    """A handler must never be invoked with a permit lacking host cancellation."""
    observed: list[bool] = []

    def handler(ctx: ExecutionContext, _: Any) -> dict[str, bool]:
        if ctx.cancellation is None:
            raise AssertionError("host cancellation capability is required")
        observed.append(True)
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="strict_cancellation_contract",
            handler=handler,
            validator=validator,
            description="Synthetic strict cancellation contract action.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"strict_cancellation_contract"}),
        InMemoryAuditSink(),
    )

    result = runtime.execute(
        ActionProposal(
            "strict_cancellation_contract",
            {"value": "safe"},
            "proposal:strict-cancel-contract",
        )
    )

    assert result.status is ExecutionStatus.EXECUTED
    assert observed == [True]


def test_runtime_authorizes_the_live_tool_and_arguments_in_action_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A permit cannot be issued from facts missing the live action identity."""
    runtime, _ = make_runtime()
    captured: dict[str, Any] = {}
    original = runtime._authorizer.issue_permit

    def issue_permit(*args: Any, **kwargs: Any) -> Any:
        facts = args[0]
        captured["facts"] = facts
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime._authorizer, "issue_permit", issue_permit)
    result = runtime.execute(proposal("live-value"))

    assert result.status is ExecutionStatus.EXECUTED
    facts = captured["facts"]
    assert facts.tool is runtime.registry.get("read_record")
    assert facts.arguments == {"value": "live-value"}


def test_runtime_rejects_non_finite_timeout_configuration() -> None:
    with pytest.raises(SecurityConfigurationError, match="finite and positive"):
        RuntimeConfig(execution_timeout_seconds=inf)
    with pytest.raises(SecurityConfigurationError, match="finite and positive"):
        RuntimeConfig(execution_timeout_seconds=nan)


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


def test_stop_after_policy_returns_prevents_handler_invocation() -> None:
    policy_ready = Event()
    allow_policy = AllowListPolicy({"stoppable_action"})

    class SlowPolicy:
        def decide(self, *args: Any, **kwargs: Any) -> Any:
            policy_ready.set()
            sleep(0.05)
            return allow_policy.decide(*args, **kwargs)

    calls: list[bool] = []
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="stoppable_action",
            handler=lambda *_: calls.append(True),
            validator=validator,
            description="Synthetic stop-race action.",
        )
    )
    runtime = GuardedRuntime(context(), registry, SlowPolicy(), InMemoryAuditSink())
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runtime.execute,
            ActionProposal("stoppable_action", {"value": "safe"}, "proposal:stop-race"),
        )
        assert policy_ready.wait(1)
        runtime.stop()
        result = future.result(timeout=1)

    assert result.status is ExecutionStatus.DENIED
    assert calls == []


def test_stop_after_credential_mint_returns_prevents_handler_invocation() -> None:
    """A stop during credential minting must block the subsequent permit path."""
    credential_ready = Event()
    release = Event()
    calls: list[bool] = []

    class Credential:
        def valid_for(self, *_: Any) -> bool:
            return True

    class SlowBroker:
        def mint(self, *_: Any) -> Credential:
            credential_ready.set()
            release.wait(1)
            return Credential()

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="credential_stop_action",
            handler=lambda *_: calls.append(True),
            validator=validator,
            requires_credential=True,
            description="Synthetic credential stop-race action.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"credential_stop_action"}),
        InMemoryAuditSink(),
        credentials=SlowBroker(),  # type: ignore[arg-type]
        config=RuntimeConfig(execution_timeout_seconds=0.05),
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runtime.execute,
            ActionProposal("credential_stop_action", {"value": "safe"}, "proposal:stop-credential"),
        )
        assert credential_ready.wait(1)
        runtime.stop()
        release.set()
        result = future.result(timeout=1)

    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "runtime emergency stop is active"
    assert calls == []


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
        reconciliation=lambda _context, _arguments: True,
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

    first = runtime.execute(proposal(operation_key="operation:read:1"))
    second = runtime.execute(proposal(operation_key="operation:read:1"))

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
        config=RuntimeConfig(
            Budget(max_actions=2, max_concurrent=2),
            idempotency_store=InMemoryIdempotencyStore(),
        ),
    )
    action = ActionProposal(
        "idempotent_action",
        {"value": "safe"},
        "proposal:concurrent",
        operation_key="operation:concurrent",
    )

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
        context(),
        registry,
        AllowListPolicy({"first_action", "second_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(idempotency_store=InMemoryIdempotencyStore()),
    )

    first = runtime.execute(
        ActionProposal(
            "first_action", {"value": "safe"}, "proposal:same", operation_key="operation:same"
        )
    )
    second = runtime.execute(
        ActionProposal(
            "second_action", {"value": "safe"}, "proposal:same", operation_key="operation:same"
        )
    )

    assert first.output == {"tool": "first"}
    assert second.status is ExecutionStatus.DENIED


def test_in_memory_approval_rejects_each_binding_dimension_and_expiry() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    approvals = InMemoryApprovalProvider(now=lambda: now)
    grant = approvals.issue(
        "approval:matrix",
        context(),
        "read_record",
        "proposal:matrix",
        "approver:test",
        "hash:matrix",
        ttl_seconds=2,
    )
    cases = [
        ("task:other", "task:other", "read_record", "proposal:matrix", "hash:matrix"),
        ("tool:other", context().task_id, "other", "proposal:matrix", "hash:matrix"),
        ("proposal:other", context().task_id, "read_record", "other", "hash:matrix"),
        ("hash:other", context().task_id, "read_record", "proposal:matrix", "hash:other"),
    ]
    for label, task_id, tool_name, proposal_id, action in cases:
        altered = replace(context(), task_id=task_id)
        outcome = approvals.consume(grant.approval_id, altered, tool_name, proposal_id, action)
        assert outcome.outcome is ApprovalOutcome.NOT_CONSUMED, label
    now += timedelta(seconds=3)
    assert (
        approvals.consume(
            grant.approval_id, context(), "read_record", "proposal:matrix", "hash:matrix"
        ).outcome
        is ApprovalOutcome.NOT_CONSUMED
    )


def test_approval_boundaries_and_reasons_are_explicit() -> None:
    """Approval state and public reason text remain distinguishable at boundaries."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    approvals = InMemoryApprovalProvider(now=lambda: now)
    grant = approvals.issue(
        "approval:reasons",
        context(),
        "read_record",
        "proposal:reasons",
        "approver:test",
        "hash:reasons",
        ttl_seconds=1,
    )

    missing = approvals.consume(
        "approval:missing", context(), "read_record", "proposal:reasons", "hash:reasons"
    )
    assert (missing.outcome, missing.reason) == (
        ApprovalOutcome.NOT_CONSUMED,
        "missing, used, or expired",
    )
    binding = approvals.consume(
        grant.approval_id, context(), "other", "proposal:reasons", "hash:reasons"
    )
    assert (binding.outcome, binding.reason) == (
        ApprovalOutcome.NOT_CONSUMED,
        "action binding mismatch",
    )
    mismatch = approvals.consume(
        grant.approval_id, context(), "read_record", "proposal:reasons", "wrong-hash"
    )
    assert (mismatch.outcome, mismatch.reason) == (
        ApprovalOutcome.NOT_CONSUMED,
        "action hash mismatch",
    )
    now += timedelta(seconds=1)
    expired = approvals.consume(
        grant.approval_id, context(), "read_record", "proposal:reasons", "hash:reasons"
    )
    assert (expired.outcome, expired.reason) == (
        ApprovalOutcome.NOT_CONSUMED,
        "missing, used, or expired",
    )


def test_approval_issue_and_action_hash_have_strict_boundaries() -> None:
    """Zero TTL and canonical action identity cannot silently weaken approval scope."""
    approvals = InMemoryApprovalProvider(now=lambda: datetime(2026, 1, 1, tzinfo=UTC))
    with pytest.raises(ValueError, match="positive"):
        approvals.issue(
            "approval:zero",
            context(),
            "read_record",
            "proposal:zero",
            "approver:test",
            "hash:zero",
            ttl_seconds=0,
        )
    assert (
        action_hash(
            context(),
            "read_record",
            {"value": "safe"},
            (Resource("record:test", "record", "tenant:test"),),
        )
        == "ca4243e9fcf2041606a24cc808ef993584afab6b58b32383b1e5dfeaecb87ff8"
    )


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


def test_strict_redaction_masks_tokens_in_arbitrary_nested_content() -> None:
    audit = InMemoryAuditSink()
    event = audit.append(
        "test",
        "request:strict",
        {"value": ["sk-live-123456789", {"content": "Bearer abcdefghijklmnop"}]},
    )

    assert event.payload == {"value": ["[REDACTED]", {"content": "[REDACTED]"}]}


def test_runtime_invariants_cannot_be_bypassed_by_permissive_policy() -> None:
    class AlwaysAllow:
        def decide(self, *_: Any) -> PolicyResult:
            return PolicyResult(PolicyDecision.ALLOW, "unsafe allow")

    mismatched_context = ExecutionContext(
        "agent:test",
        Principal("user:alice", tenant="tenant:b"),
        "task:1",
        "test",
        tenant="tenant:a",
    )
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "read_record",
            lambda *_: {"unexpected": True},
            validator,
            requires_approval=True,
            resources=lambda _: (Resource("record:1", "record", "tenant:a"),),
            description="Invariant bypass test.",
        )
    )
    runtime = GuardedRuntime(mismatched_context, registry, AlwaysAllow(), InMemoryAuditSink())

    result = runtime.execute(proposal())

    assert result.status is ExecutionStatus.DENIED
    assert "tenant" in (result.reason or "")


def test_tool_approval_cannot_be_bypassed_by_allow_policy() -> None:
    class AlwaysAllow:
        def decide(self, *_: Any) -> PolicyResult:
            return PolicyResult(PolicyDecision.ALLOW, "unsafe allow")

    runtime, _ = make_runtime(requires_approval=True, policy=AlwaysAllow())
    result = runtime.execute(proposal())

    assert result.status is ExecutionStatus.APPROVAL_REQUIRED


def test_reconciliation_runs_after_timeout_and_reports_reconciled() -> None:
    release = Event()
    reconciled: list[bool] = []

    def slow(_ctx: ExecutionContext, _args: Any) -> dict[str, bool]:
        release.wait(1)
        return {"ok": True}

    def reconcile(_ctx: ExecutionContext, _args: Any) -> bool:
        reconciled.append(True)
        return True

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "reconcile_action",
            slow,
            validator,
            reconciliation=reconcile,
            description="Synthetic reconciliation test.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"reconcile_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )

    result = runtime.execute(
        ActionProposal("reconcile_action", {"value": "safe"}, "proposal:reconcile")
    )
    release.set()

    assert result.status is ExecutionStatus.TIMED_OUT
    assert result.timeout_phase is TimeoutPhase.HANDLER
    assert result.side_effect_state is SideEffectState.UNCERTAIN
    assert reconciled == [True]


def test_isolation_requirement_rejects_in_process_handler() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "isolated_action",
            lambda *_: {"unexpected": True},
            validator,
            requires_isolation=True,
            description="Synthetic isolation test.",
        )
    )
    runtime = GuardedRuntime(
        context(), registry, AllowListPolicy({"isolated_action"}), InMemoryAuditSink()
    )

    result = runtime.execute(
        ActionProposal("isolated_action", {"value": "safe"}, "proposal:isolation")
    )

    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "tool requires a verifier-backed isolation attestation"


def test_runtime_reports_timed_out_worker_health_until_release() -> None:
    started = Event()
    release = Event()

    def slow(_ctx: ExecutionContext, _args: Any) -> dict[str, bool]:
        started.set()
        release.wait(1)
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(ToolDefinition("health_action", slow, validator, description="Health test."))
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"health_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )

    result = runtime.execute(ActionProposal("health_action", {"value": "safe"}, "proposal:health"))
    assert result.status is ExecutionStatus.TIMED_OUT
    assert started.is_set()
    for _ in range(100):
        if runtime.health()["timed_out_workers"] == 1:
            break
        sleep(0.001)
    assert runtime.health()["timed_out_workers"] == 1
    release.set()
    for _ in range(100):
        if runtime.health()["timed_out_workers"] == 0:
            break
        sleep(0.001)
    assert runtime.health()["timed_out_workers"] == 0


def test_runtime_caps_bounded_workers_under_concurrent_timeouts() -> None:
    release = Event()

    def slow(_ctx: ExecutionContext, _args: Any) -> dict[str, bool]:
        release.wait(1)
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(ToolDefinition("bounded_action", slow, validator, description="Bound test."))
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"bounded_action"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(execution_timeout_seconds=0.005, max_timed_out_workers=1),
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                runtime.execute,
                ActionProposal("bounded_action", {"value": str(index)}, f"proposal:{index}"),
            )
            for index in range(2)
        ]
        results = [future.result(timeout=1) for future in futures]
    release.set()

    assert runtime.health()["timed_out_workers"] <= 1
    assert sum(result.status is ExecutionStatus.TIMED_OUT for result in results) <= 1


def test_budget_rejects_cost_and_rate_overruns() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "expensive",
            lambda *_: {"ok": True},
            validator,
            cost_units=2,
            description="Budget test.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"expensive"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(Budget(max_actions=4, max_cost_units=2, max_actions_per_second=1)),
    )
    first = runtime.execute(ActionProposal("expensive", {"value": "safe"}, "proposal:cost-1"))
    second = runtime.execute(ActionProposal("expensive", {"value": "safe"}, "proposal:cost-2"))

    assert first.status is ExecutionStatus.EXECUTED
    assert second.status is ExecutionStatus.DENIED


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


def test_budget_release_fails_closed_when_lease_counters_disagree() -> None:
    """A partially corrupted lease must not decrement either counter."""
    state = BudgetState(Budget(max_actions=2, max_concurrent=2, max_fan_out=2))
    assert state.acquire()
    state._fan_out = 0  # adversarial invariant test

    assert state.release() is False
    assert state._active == 1
    assert state._fan_out == 0


def test_budget_state_rejects_invalid_cost_and_rate_configuration() -> None:
    with pytest.raises(ValueError):
        BudgetState(Budget(max_actions_per_second=0))
    state = BudgetState(Budget(max_actions=2, max_cost_units=1))
    assert not state.acquire(0)
    assert not state.acquire(2)


def test_budget_rate_window_is_strictly_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rate limits reject bursts, expire exactly at one second, and retain counts."""
    now = iter((0.0, 0.0, 1.0))
    monkeypatch.setattr("agentic_security.budgets.monotonic", lambda: next(now))
    state = BudgetState(
        Budget(
            max_actions=4,
            max_concurrent=4,
            max_fan_out=4,
            max_cost_units=4,
            max_actions_per_second=1,
        )
    )
    assert state.acquire()
    assert not state.acquire()
    assert state.acquire()
    assert state.actions == 2


def test_budget_rate_window_does_not_expire_on_clock_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backwards clock jump must not erase a still-live rate reservation."""
    now = iter((0.8, 0.5))
    monkeypatch.setattr("agentic_security.budgets.monotonic", lambda: next(now))
    state = BudgetState(
        Budget(
            max_actions=3,
            max_concurrent=3,
            max_fan_out=3,
            max_cost_units=3,
            max_actions_per_second=1,
        )
    )
    assert state.acquire() is True
    assert state.acquire() is False


def test_budget_capacity_uses_each_concurrency_dimension(monkeypatch: pytest.MonkeyPatch) -> None:
    """A full active or fan-out dimension independently denies admission."""
    monkeypatch.setattr("agentic_security.budgets.monotonic", lambda: 0.0)
    active_limited = BudgetState(Budget(max_actions=3, max_concurrent=1, max_fan_out=2))
    assert active_limited.acquire()
    assert not active_limited.acquire()
    fanout_limited = BudgetState(Budget(max_actions=3, max_concurrent=2, max_fan_out=1))
    assert fanout_limited.acquire()
    assert not fanout_limited.acquire()


def test_budget_counters_accumulate_across_released_actions() -> None:
    """Release frees concurrency but never rewinds consumed actions or cost."""
    state = BudgetState(Budget(max_actions=3, max_cost_units=3, max_concurrent=1))
    assert state.acquire()
    assert state.release()
    assert state.acquire()
    assert state.actions == 2
    assert state._cost == 2


@pytest.mark.parametrize(
    "budget",
    [
        Budget(max_actions=0),
        Budget(max_concurrent=0),
        Budget(max_fan_out=0),
        Budget(max_cost_units=0),
        Budget(max_delegation_depth=-1),
    ],
)
def test_budget_state_rejects_each_non_positive_limit(budget: Budget) -> None:
    with pytest.raises(ValueError, match="positive"):
        BudgetState(budget)


def test_delegation_depth_is_enforced_by_runtime() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "delegated",
            lambda *_: {"unexpected": True},
            validator,
            delegation_depth=2,
            description="Synthetic delegation test.",
        )
    )
    runtime = GuardedRuntime(
        context(),
        registry,
        AllowListPolicy({"delegated"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(Budget(max_delegation_depth=1)),
    )
    result = runtime.execute(ActionProposal("delegated", {"value": "safe"}, "proposal:delegated"))
    assert result.status is ExecutionStatus.DENIED
    assert "delegation" in (result.reason or "")

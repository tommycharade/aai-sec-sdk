"""Adversarial acceptance tests for SEC-001 through SEC-005."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Thread
from time import sleep
from typing import Any

from agentic_security import (
    ActionProposal,
    AllowListPolicy,
    ApprovalConsumption,
    ApprovalOutcome,
    CallbackIsolationVerifier,
    ExecutionContext,
    ExecutionStatus,
    GuardedRuntime,
    IdempotencyState,
    InMemoryAuditSink,
    InMemoryIdempotencyStore,
    IsolationAttestation,
    Principal,
    ReconciliationResult,
    ReconciliationState,
    Resource,
    RuntimeConfig,
    SideEffectState,
    TimeoutPhase,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.approvals import normalize_approval_result
from agentic_security.budgets import Budget, BudgetState
from agentic_security.idempotency import IdempotencyClaimStatus, new_record
from agentic_security.isolation import validate_attestation
from agentic_security.policies import PolicyDecision, PolicyResult
from agentic_security.runtime import _ActionBudgetReleaseState


def _context() -> ExecutionContext:
    return ExecutionContext(
        "agent:test",
        Principal("user:test", tenant="tenant:test"),
        "task:test",
        "test",
        tenant="tenant:test",
    )


def _tool(name: str, handler: Any, **kwargs: Any) -> ToolDefinition:
    return ToolDefinition(
        name,
        handler,
        lambda arguments: dict(arguments),
        resources=lambda _: (Resource("resource:test", "record", "tenant:test"),),
        description="Synthetic backlog acceptance tool.",
        **kwargs,
    )


def test_reconciliation_cannot_finalize_a_live_timed_out_worker() -> None:
    release = Event()

    def handler(_context: ExecutionContext, _arguments: Any) -> dict[str, bool]:
        release.wait(1)
        return {"complete": True}

    registry = ToolRegistry()
    registry.register(
        _tool(
            "uncertain",
            handler,
            reconciliation=lambda *_: ReconciliationResult(
                ReconciliationState.CONFIRMED_COMPLETE, "remote lookup says complete"
            ),
        )
    )
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"uncertain"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )

    result = runtime.execute(ActionProposal("uncertain", {}, "proposal:1"))
    release.set()

    assert result.status is ExecutionStatus.TIMED_OUT
    assert result.reconciliation_state is ReconciliationState.STILL_RUNNING


def test_reconciliation_timeout_is_typed_and_remains_uncertain() -> None:
    """A reconciliation deadline is observable without implying side-effect success."""
    handler_release = Event()
    reconciliation_release = Event()

    def handler(_context: ExecutionContext, _arguments: Any) -> dict[str, bool]:
        handler_release.wait(1)
        return {"complete": True}

    def reconciliation(_context: ExecutionContext, _arguments: Any) -> ReconciliationResult:
        reconciliation_release.wait(1)
        return ReconciliationResult(ReconciliationState.CONFIRMED_COMPLETE)

    registry = ToolRegistry()
    registry.register(_tool("reconcile_timeout", handler, reconciliation=reconciliation))
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"reconcile_timeout"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )

    result = runtime.execute(ActionProposal("reconcile_timeout", {}, "proposal:reconcile-timeout"))
    handler_release.set()
    reconciliation_release.set()

    assert result.status is ExecutionStatus.TIMED_OUT
    assert result.timeout_phase is TimeoutPhase.RECONCILIATION
    assert result.handler_started is True
    assert result.side_effect_state is SideEffectState.UNCERTAIN
    assert result.reconciliation_state is ReconciliationState.FAILED


def test_isolation_requires_verifier_bound_attestation_not_a_boolean_marker() -> None:
    class ClaimedWorker:
        def __call__(self, _context: ExecutionContext, _arguments: Any) -> dict[str, bool]:
            return {"ok": True}

        def get_isolation_attestation(
            self,
            context: ExecutionContext,
            tool_name: str,
            _resources: tuple[Resource, ...],
            nonce: str,
        ) -> IsolationAttestation:
            return IsolationAttestation(
                "test-provider",
                "workload:test",
                "profile:restricted",
                datetime.now(UTC) + timedelta(minutes=1),
                nonce,
                tool_name,
                context.tenant or "",
                {"network": False, "filesystem": False},
            )

    registry = ToolRegistry()
    registry.register(_tool("isolated", ClaimedWorker(), requires_isolation=True))
    verifier = CallbackIsolationVerifier(
        lambda attestation, *_: attestation.profile == "profile:restricted"
    )
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"isolated"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(isolation_verifier=verifier),
    )

    assert (
        runtime.execute(ActionProposal("isolated", {}, "proposal:1")).status
        is ExecutionStatus.EXECUTED
    )

    forged = GuardedRuntime(
        _context(),
        ToolRegistry(),
        AllowListPolicy(set()),
        InMemoryAuditSink(),
    )
    assert (
        forged.execute(ActionProposal("isolated", {}, "proposal:2")).status
        is ExecutionStatus.DENIED
    )


def test_idempotency_is_stable_across_proposals_and_rejects_collisions() -> None:
    store = InMemoryIdempotencyStore()
    calls: list[int] = []

    def write(_context: ExecutionContext, arguments: Any) -> dict[str, bool]:
        calls.append(arguments["value"])
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        _tool(
            "write",
            write,
            idempotency_required=True,
        )
    )
    config = RuntimeConfig(idempotency_store=store)
    first_runtime = GuardedRuntime(
        _context(), registry, AllowListPolicy({"write"}), InMemoryAuditSink(), config=config
    )
    first = first_runtime.execute(
        ActionProposal("write", {"value": 1}, "proposal:first", operation_key="op:1")
    )
    second_runtime = GuardedRuntime(
        _context(), registry, AllowListPolicy({"write"}), InMemoryAuditSink(), config=config
    )
    replay = second_runtime.execute(
        ActionProposal("write", {"value": 1}, "proposal:new", operation_key="op:1")
    )
    collision = second_runtime.execute(
        ActionProposal("write", {"value": 2}, "proposal:changed", operation_key="op:1")
    )

    assert first.status is ExecutionStatus.EXECUTED
    assert replay == first
    assert collision.status is ExecutionStatus.DENIED
    assert calls == [1]
    assert store.lookup("op:1") is not None
    assert store.lookup("op:1").state is IdempotencyState.COMPLETED  # type: ignore[union-attr]


def test_missing_idempotency_store_fails_closed() -> None:
    registry = ToolRegistry()
    registry.register(_tool("write", lambda *_: {"ok": True}, idempotency_required=True))
    runtime = GuardedRuntime(_context(), registry, AllowListPolicy({"write"}), InMemoryAuditSink())

    result = runtime.execute(
        ActionProposal("write", {}, "proposal:1", operation_key="op:missing-store")
    )

    assert result.status is ExecutionStatus.DENIED
    assert "store" in (result.reason or "")


def test_policy_timeout_retains_action_capacity_until_worker_exit() -> None:
    release = Event()

    class SlowPolicy:
        def decide(self, *_: Any) -> PolicyResult:
            release.wait(1)
            return PolicyResult(PolicyDecision.ALLOW, "late")

    registry = ToolRegistry()
    registry.register(_tool("read", lambda *_: {"ok": True}))
    runtime = GuardedRuntime(
        _context(),
        registry,
        SlowPolicy(),
        InMemoryAuditSink(),
        config=RuntimeConfig(
            Budget(max_concurrent=1), execution_timeout_seconds=0.005, max_timed_out_workers=4
        ),
    )

    timed_out = runtime.execute(ActionProposal("read", {}, "proposal:1"))
    blocked = runtime.execute(ActionProposal("read", {}, "proposal:2"))
    release.set()

    assert timed_out.status is ExecutionStatus.DENIED
    assert "timed out" in (timed_out.reason or "")
    assert blocked.status is ExecutionStatus.DENIED
    assert timed_out.timeout_phase is TimeoutPhase.POLICY
    assert timed_out.handler_started is False
    assert timed_out.side_effect_state is SideEffectState.NOT_STARTED


def test_approval_timeout_is_typed_and_does_not_start_handler() -> None:
    release = Event()

    class SlowApproval:
        def consume(self, *_: Any) -> bool:
            release.wait(1)
            return True

    calls: list[bool] = []
    registry = ToolRegistry()
    registry.register(_tool("approved", lambda *_: calls.append(True), requires_approval=True))
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"approved"}),
        InMemoryAuditSink(),
        approvals=SlowApproval(),
        config=RuntimeConfig(execution_timeout_seconds=0.005),
    )
    result = runtime.execute(
        ActionProposal("approved", {}, "proposal:approval", approval_id="approval:1")
    )
    release.set()

    assert result.status is ExecutionStatus.DENIED
    assert result.timeout_phase is TimeoutPhase.APPROVAL
    assert result.handler_started is False
    assert result.side_effect_state is SideEffectState.NOT_STARTED
    assert calls == []


def test_stop_during_approval_denies_without_starting_handler() -> None:
    started = Event()
    release = Event()
    calls: list[bool] = []

    class SlowApproval:
        def consume(self, *_: Any) -> bool:
            started.set()
            release.wait(1)
            return True

    registry = ToolRegistry()
    registry.register(_tool("approved", lambda *_: calls.append(True), requires_approval=True))
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"approved"}),
        audit,
        approvals=SlowApproval(),
        config=RuntimeConfig(execution_timeout_seconds=0.05),
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runtime.execute,
            ActionProposal("approved", {}, "proposal:stop-approval", approval_id="approval:1"),
        )
        assert started.wait(1)
        runtime.stop()
        release.set()
        result = future.result(timeout=1)

    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "runtime emergency stop is active"
    assert calls == []
    event = audit.events()[-1]
    assert event.payload["approval_outcome"] == ApprovalOutcome.CONSUMED.value
    assert event.payload["approval_stop_after_consume"] is True
    assert event.payload["approval_action_hash"]


def test_approval_outcomes_are_typed_and_unknown_fails_closed() -> None:
    assert normalize_approval_result(True).outcome is ApprovalOutcome.CONSUMED
    assert normalize_approval_result(False).outcome is ApprovalOutcome.NOT_CONSUMED
    assert normalize_approval_result(object()).outcome is ApprovalOutcome.UNKNOWN

    calls: list[bool] = []

    class UnknownApproval:
        def consume(self, *_: Any) -> ApprovalConsumption:
            return ApprovalConsumption(ApprovalOutcome.UNKNOWN, "commit uncertain")

    registry = ToolRegistry()
    registry.register(_tool("unknown", lambda *_: calls.append(True), requires_approval=True))
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"unknown"}),
        audit,
        approvals=UnknownApproval(),
        config=RuntimeConfig(execution_timeout_seconds=0.05),
    )
    result = runtime.execute(
        ActionProposal("unknown", {}, "proposal:unknown", approval_id="approval:unknown")
    )

    assert result.status is ExecutionStatus.DENIED
    assert result.reason == "approval outcome is unknown; reconcile before retrying"
    assert result.handler_started is False
    assert calls == []
    assert audit.events()[-1].payload["approval_outcome"] == ApprovalOutcome.UNKNOWN.value


def test_zero_delegation_budget_is_valid_and_denies_delegating_tools() -> None:
    state = BudgetState(Budget(max_delegation_depth=0))
    assert state.budget.max_delegation_depth == 0

    registry = ToolRegistry()
    registry.register(_tool("delegated", lambda *_: {"ok": True}, delegation_depth=1))
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"delegated"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(Budget(max_delegation_depth=0)),
    )
    result = runtime.execute(ActionProposal("delegated", {}, "proposal:1"))

    assert result.status is ExecutionStatus.DENIED
    assert "delegation" in (result.reason or "")


def test_idempotency_store_claim_update_and_invalid_inputs_fail_closed() -> None:
    store = InMemoryIdempotencyStore()
    record = new_record(
        operation_key="op:store",
        action_fingerprint="fingerprint",
        tenant="tenant:test",
        principal_id="user:test",
        tool_name="write",
        resource_ids=("resource:test",),
        ttl_seconds=30,
    )
    claimed = store.claim(record)
    assert claimed.status is IdempotencyClaimStatus.CLAIMED
    assert store.claim(record).status is IdempotencyClaimStatus.EXISTING
    conflict = store.claim(
        new_record(
            operation_key="op:store",
            action_fingerprint="different",
            tenant="tenant:test",
            principal_id="user:test",
            tool_name="write",
            resource_ids=("resource:test",),
        )
    )
    assert conflict.status is IdempotencyClaimStatus.CONFLICT
    assert store.complete("op:store", {"done": True}).state is IdempotencyState.COMPLETED
    assert store.mark_uncertain("op:store", {"unknown": True}).state is IdempotencyState.UNCERTAIN

    try:
        store.claim(
            new_record(
                operation_key=" ",
                action_fingerprint="fingerprint",
                tenant="tenant:test",
                principal_id="user:test",
                tool_name="write",
                resource_ids=(),
            )
        )
    except ValueError:
        pass
    else:
        raise AssertionError("blank operation keys must fail closed")

    try:
        store.complete("op:unknown", {"bad": True})
    except KeyError:
        pass
    else:
        raise AssertionError("unknown operation keys must not be created by completion")


def test_isolation_attestation_rejects_expiry_and_verifier_errors() -> None:
    context = _context()
    resource = (Resource("resource:test", "record", "tenant:test"),)
    expired = IsolationAttestation(
        "provider",
        "workload",
        "profile",
        datetime.now(UTC) + timedelta(seconds=1),
        "nonce",
        "tool",
        "tenant:test",
        {},
    )
    assert validate_attestation(expired, context, "tool", resource, "wrong-nonce") is False
    assert (
        CallbackIsolationVerifier(lambda *_: (_ for _ in ()).throw(RuntimeError())).verify(
            expired, context, "tool", resource, "nonce"
        )
        is False
    )

    try:
        IsolationAttestation(
            "",
            "workload",
            "profile",
            datetime.now(UTC) + timedelta(minutes=1),
            "nonce",
            "tool",
            "tenant:test",
            {},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("incomplete attestations must fail closed")

    try:
        IsolationAttestation(
            "provider",
            "workload",
            "profile",
            datetime.now(UTC) - timedelta(seconds=1),
            "nonce",
            "tool",
            "tenant:test",
            {},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("expired attestations must fail closed")


def test_idempotent_tool_requires_explicit_operation_key() -> None:
    registry = ToolRegistry()
    registry.register(_tool("write", lambda *_: {"ok": True}, idempotency_required=True))
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"write"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(idempotency_store=InMemoryIdempotencyStore()),
    )

    result = runtime.execute(ActionProposal("write", {}, "proposal:no-key"))

    assert result.status is ExecutionStatus.DENIED
    assert "operation key" in (result.reason or "")


def test_idempotency_claim_failure_and_worker_limit_are_fail_closed() -> None:
    try:
        RuntimeConfig(max_timed_out_workers=0)
    except ValueError:
        pass
    else:
        raise AssertionError("zero worker capacity must be rejected")

    class BrokenStore:
        def lookup(self, _operation_key: str) -> None:
            return None

        def claim(self, _record: Any) -> Any:
            raise RuntimeError("store unavailable")

        def complete(self, _operation_key: str, _result: Any) -> Any:
            raise AssertionError("unreachable")

        def mark_uncertain(self, _operation_key: str, _result: Any) -> Any:
            raise AssertionError("unreachable")

        def gc(self, now: Any = None) -> Any:
            raise AssertionError("unreachable")

    registry = ToolRegistry()
    registry.register(_tool("write", lambda *_: {"ok": True}, idempotency_required=True))
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"write"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(idempotency_store=BrokenStore()),
    )
    result = runtime.execute(
        ActionProposal("write", {}, "proposal:broken-store", operation_key="op:broken")
    )
    assert result.status is ExecutionStatus.DENIED
    assert "store" in (result.reason or "")


def test_action_budget_release_is_idempotent() -> None:
    runtime = GuardedRuntime(
        _context(), ToolRegistry(), AllowListPolicy(set()), InMemoryAuditSink()
    )
    assert runtime._budget.acquire() is True
    state = _ActionBudgetReleaseState()
    assert runtime._release_action_budget_once(state) is True
    assert runtime._release_action_budget_once(state) is False
    assert state.released is True
    assert runtime._budget._active == 0
    assert runtime._budget._fan_out == 0


def test_action_budget_release_callbacks_are_atomic_under_concurrency() -> None:
    """Timeout and reconciliation callbacks cannot double-release one lease."""
    runtime = GuardedRuntime(
        _context(), ToolRegistry(), AllowListPolicy(set()), InMemoryAuditSink()
    )
    assert runtime._budget.acquire() is True
    state = _ActionBudgetReleaseState()
    runtime._defer_action_budget_release(state)
    barrier = Barrier(64)

    def release_from_callback(_: int) -> bool:
        barrier.wait()
        return runtime._release_action_budget_once(state)

    with ThreadPoolExecutor(max_workers=64) as executor:
        releases = list(executor.map(release_from_callback, range(64)))

    assert sum(releases) == 1
    assert state.released is True
    assert state.deferred is True
    assert runtime._budget._active == 0
    assert runtime._budget._fan_out == 0
    assert runtime._budget.acquire() is True
    assert runtime._budget.acquire() is False
    assert runtime._budget.release() is True


def test_budget_release_rejects_concurrent_duplicate_releases_without_underflow() -> None:
    """The primitive itself remains safe even if callers violate lease ownership."""
    state = BudgetState(Budget(max_concurrent=1))
    assert state.acquire() is True
    barrier = Barrier(64)

    def release(_: int) -> bool:
        barrier.wait()
        return state.release()

    with ThreadPoolExecutor(max_workers=64) as executor:
        releases = list(executor.map(release, range(64)))

    assert sum(releases) == 1
    assert state._active == 0
    assert state._fan_out == 0
    assert state.release() is False
    assert state.acquire() is True


def test_handler_completion_is_local_and_stress_timeouts_do_not_retain_registry() -> None:
    release = Event()

    def slow(_context: ExecutionContext, _arguments: Any) -> dict[str, bool]:
        release.wait(1)
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(_tool("slow", slow))
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"slow"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(
            Budget(max_concurrent=8), execution_timeout_seconds=0.01, max_timed_out_workers=32
        ),
    )

    proposals = [ActionProposal("slow", {}, f"proposal:{index}") for index in range(8)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(runtime.execute, proposals))
    release.set()
    sleep(0.05)

    assert any(result.timeout_phase is TimeoutPhase.HANDLER for result in results)
    assert all(
        result.status in {ExecutionStatus.TIMED_OUT, ExecutionStatus.DENIED} for result in results
    )
    assert not hasattr(runtime, "_handler_completion")
    assert runtime.health()["bounded_workers"] == 0


def test_idempotency_ttl_expiry_and_gc_never_delete_uncertain_records() -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = InMemoryIdempotencyStore(lambda: now[0])
    completed = new_record(
        operation_key="op:completed",
        action_fingerprint="fingerprint:1",
        tenant="tenant:test",
        principal_id="user:test",
        tool_name="write",
        resource_ids=(),
        ttl_seconds=10,
        now=now[0],
    )
    uncertain = new_record(
        operation_key="op:uncertain",
        action_fingerprint="fingerprint:2",
        tenant="tenant:test",
        principal_id="user:test",
        tool_name="write",
        resource_ids=(),
        ttl_seconds=10,
        now=now[0],
    )
    store.claim(completed)
    store.complete("op:completed", {"ok": True})
    store.claim(uncertain)
    store.mark_uncertain("op:uncertain", {"unknown": True})
    now[0] += timedelta(seconds=11)

    report = store.gc()

    assert report.scanned == 2
    assert report.removed_completed == 1
    assert report.retained_active == 1
    assert store.lookup("op:completed") is None
    assert store.lookup("op:uncertain") is not None
    retry = store.claim(uncertain)
    assert retry.status is IdempotencyClaimStatus.EXPIRED


def test_expired_in_progress_claims_are_consistently_rejected_under_concurrency() -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = InMemoryIdempotencyStore(lambda: now[0])
    record = new_record(
        operation_key="op:active",
        action_fingerprint="fingerprint",
        tenant="tenant:test",
        principal_id="user:test",
        tool_name="write",
        resource_ids=(),
        ttl_seconds=1,
        now=now[0],
    )
    store.claim(record)
    now[0] += timedelta(seconds=2)
    barrier = Barrier(6)
    statuses: list[IdempotencyClaimStatus] = []

    def retry() -> None:
        barrier.wait()
        statuses.append(store.claim(record).status)

    threads = [Thread(target=retry) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses == [IdempotencyClaimStatus.EXPIRED] * 6


def test_timed_out_audit_for_pre_admission_denial_never_releases_missing_lease() -> None:
    class SlowAudit:
        def append(self, *_: Any) -> None:
            sleep(0.03)

    runtime = GuardedRuntime(
        _context(),
        ToolRegistry(),
        AllowListPolicy(set()),
        SlowAudit(),  # type: ignore[arg-type]
        config=RuntimeConfig(execution_timeout_seconds=0.001),
    )

    result = runtime.execute(ActionProposal("not-registered", {}, "proposal:denied"))
    sleep(0.05)

    assert result.status is ExecutionStatus.DENIED
    assert runtime._budget._active == 0
    assert runtime._budget._fan_out == 0


def test_idempotency_terminal_store_failure_is_not_reported_as_success() -> None:
    class BrokenCompletionStore(InMemoryIdempotencyStore):
        def complete(self, *_: Any) -> Any:
            raise RuntimeError("durable store unavailable")

    calls: list[int] = []

    def write(_context: ExecutionContext, arguments: Any) -> dict[str, bool]:
        calls.append(arguments["value"])
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        _tool(
            "write",
            write,
            idempotency_required=True,
        )
    )
    store = BrokenCompletionStore()
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"write"}),
        InMemoryAuditSink(),
        config=RuntimeConfig(idempotency_store=store),
    )

    result = runtime.execute(
        ActionProposal(
            "write",
            {"value": 1},
            "proposal:store-failure",
            operation_key="op:store-failure",
        )
    )

    assert result.status is ExecutionStatus.EXECUTED_UNRECORDED
    assert "idempotency" in (result.reason or "")
    assert calls == [1]
    assert store.lookup("op:store-failure") is not None
    assert store.lookup("op:store-failure").state is IdempotencyState.IN_PROGRESS  # type: ignore[union-attr]


def test_idempotency_claim_is_atomic_under_concurrent_race() -> None:
    store = InMemoryIdempotencyStore()
    record = new_record(
        operation_key="op:race",
        action_fingerprint="fingerprint",
        tenant="tenant:test",
        principal_id="user:test",
        tool_name="write",
        resource_ids=("resource:test",),
    )
    barrier = Barrier(8)
    statuses: list[IdempotencyClaimStatus] = []

    def claim() -> None:
        barrier.wait()
        statuses.append(store.claim(record).status)

    threads = [Thread(target=claim) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses.count(IdempotencyClaimStatus.CLAIMED) == 1
    assert statuses.count(IdempotencyClaimStatus.EXISTING) == 7

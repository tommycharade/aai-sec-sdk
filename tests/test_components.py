"""Contract tests for the typed security-boundary components."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any

import pytest

from agentic_security import (
    ActionBudgetLease,
    ActionFacts,
    ActionProposal,
    BoundedOperationExecutor,
    BoundedOperationTimeout,
    BoundedOperationTracker,
    CancellationToken,
    ExecutionContext,
    ExecutionLifecycle,
    ExecutionResult,
    ExecutionStatus,
    IdempotencyState,
    InMemoryIdempotencyStore,
    Principal,
    Resource,
    SecurityConfigurationError,
    TerminalRecorder,
    TerminalRecorderError,
    TimeoutPhase,
    ToolDefinition,
)
from agentic_security.approvals import ApprovalConsumption, ApprovalOutcome
from agentic_security.components import (
    ActionPreparation,
    ApprovalPreparation,
    CredentialPreparation,
    ExecutionPermit,
    PolicyPreparation,
    PreExecutionAuthorizationError,
    PreExecutionAuthorizer,
)
from agentic_security.credentials import ScopedCredential
from agentic_security.errors import WorkerCapacityError
from agentic_security.isolation import CallbackIsolationVerifier, IsolationAttestation
from agentic_security.policies import PolicyDecision, PolicyResult


def _context() -> ExecutionContext:
    return ExecutionContext(
        "agent:test",
        Principal("user:test", tenant="tenant:test"),
        "task:test",
        "component contract",
        tenant="tenant:test",
    )


def _tool(handler: Any) -> ToolDefinition:
    return ToolDefinition(
        "component_action",
        handler,
        lambda value: dict(value),
        resources=lambda _: (Resource("resource:test", "record", "tenant:test"),),
        description="Synthetic component contract action.",
    )


def _facts(handler: Any) -> ActionFacts:
    context = _context()
    proposal = ActionProposal("component_action", {"value": "safe"}, "proposal:component")
    return ActionFacts(
        context=context,
        proposal=proposal,
        tool=_tool(handler),
        arguments={"value": "safe"},
        resources=(Resource("resource:test", "record", "tenant:test"),),
        action_fingerprint="hash:component",
    )


def test_action_preparation_owns_live_identity_and_resource_validation() -> None:
    """The preparation phase rejects host scope drift before provider calls."""
    context = _context()
    tool = _tool(lambda *_: {"ok": True})
    resources = (Resource("resource:test", "record", "tenant:test"),)
    assert ActionPreparation.resolve_resources(tool, {"value": "safe"}) == resources
    ActionPreparation.validate_identity(context, tool, resources, 0)
    with pytest.raises(PreExecutionAuthorizationError, match="outside"):
        ActionPreparation.validate_identity(
            context, tool, (Resource("foreign", "record", "tenant:other"),), 0
        )
    mismatched = replace(context, tenant="tenant:other")
    with pytest.raises(
        PreExecutionAuthorizationError, match="principal tenant does not match task tenant"
    ) as principal_error:
        ActionPreparation.validate_identity(mismatched, tool, resources, 0)
    assert str(principal_error.value) == "principal tenant does not match task tenant"
    with pytest.raises(
        PreExecutionAuthorizationError, match="delegation depth exceeds configured limit"
    ) as delegation_error:
        ActionPreparation.validate_identity(
            context, replace(tool, delegation_depth=1), resources, 0
        )
    assert str(delegation_error.value) == "delegation depth exceeds configured limit"


def test_policy_and_credential_preparation_preserve_restrictive_contracts() -> None:
    """Provider output cannot remove a tool approval or widen credential scope."""
    tool = _tool(lambda *_: {"ok": True})
    requiring_approval = replace(tool, requires_approval=True)
    normalized = PolicyPreparation.apply_tool_approval_requirement(
        requiring_approval, PolicyResult(PolicyDecision.ALLOW, "provider allow")
    )
    assert normalized.decision is PolicyDecision.APPROVAL_REQUIRED
    assert normalized.reason == "tool declaration requires explicit approval"
    with pytest.raises(PreExecutionAuthorizationError, match="scope"):
        CredentialPreparation.validate_scope(
            ScopedCredential(
                "synthetic",
                "other_tool",
                (),
                datetime.now(UTC),
                datetime.now(UTC) + timedelta(minutes=1),
                lambda: "synthetic-secret",
            ),
            tool,
            (Resource("resource:test", "record", "tenant:test"),),
        )


def test_approval_preparation_accepts_only_consumed_typed_outcomes() -> None:
    consumed = ApprovalConsumption(ApprovalOutcome.CONSUMED, "synthetic")
    assert ApprovalPreparation.require_consumed(consumed) is consumed
    with pytest.raises(PreExecutionAuthorizationError, match="not consumed") as unknown_error:
        ApprovalPreparation.require_consumed(ApprovalConsumption(ApprovalOutcome.UNKNOWN))
    assert str(unknown_error.value) == "approval is required and was not consumed"
    with pytest.raises(PreExecutionAuthorizationError, match="not consumed") as missing_error:
        ApprovalPreparation.require_consumed(None)
    assert str(missing_error.value) == "approval is required and was not consumed"


def test_isolation_preparation_passes_the_complete_live_binding_to_verifier() -> None:
    """Isolation verification must receive the same context, tool, resources, and nonce."""
    seen: list[tuple[Any, Any, Any, Any, Any]] = []
    nonce = "nonce:component"
    context = _context()
    resources = (Resource("resource:test", "record", "tenant:test"),)
    attestation = IsolationAttestation(
        "synthetic",
        "workload:test",
        "strict",
        datetime.now(UTC) + timedelta(minutes=1),
        nonce,
        "component_action",
        "tenant:test",
        {},
    )

    class Handler:
        seen: list[tuple[Any, ...]] = []

        def __call__(self, *_: Any) -> dict[str, bool]:
            return {"ok": True}

        def get_isolation_attestation(self, *_: Any) -> IsolationAttestation:
            self.seen.append(_)
            return attestation

    def verify(*args: Any) -> bool:
        seen.append(args)
        return True

    handler = Handler()
    tool = replace(_tool(handler), requires_isolation=True)
    assert ActionPreparation.verify_isolation(
        tool, context, resources, CallbackIsolationVerifier(verify), nonce
    )
    assert seen == [(attestation, context, "component_action", resources, nonce)]
    assert handler.seen == [(context, "component_action", resources, nonce)]
    with pytest.raises(PreExecutionAuthorizationError, match="verifier-backed"):
        ActionPreparation.verify_isolation(tool, context, resources, None, nonce)


def test_authorizer_issues_immutable_permit_only_for_consumed_approval() -> None:
    facts = _facts(lambda *_: {"ok": True})
    authorizer = PreExecutionAuthorizer(max_delegation_depth=0)
    policy = PolicyResult(PolicyDecision.APPROVAL_REQUIRED, "approval required")
    approval = ApprovalConsumption(ApprovalOutcome.CONSUMED, "synthetic approval")
    token = CancellationToken()

    permit = authorizer.issue_permit(
        facts,
        policy,
        approval,
        None,
        False,
        _context(),
        token,
    )

    assert isinstance(permit, ExecutionPermit)
    assert permit.facts is facts
    assert permit.evidence.policy is policy
    assert permit.evidence.approval is approval
    assert permit.evidence.credential_attested is False
    assert permit.evidence.isolation_attested is False
    with pytest.raises(FrozenInstanceError):
        permit.facts = facts  # type: ignore[misc]
    with pytest.raises(PreExecutionAuthorizationError, match="not consumed"):
        authorizer.issue_permit(
            facts,
            policy,
            ApprovalConsumption(ApprovalOutcome.UNKNOWN),
            None,
            False,
            _context(),
            token,
        )


def test_authorizer_preserves_all_host_authorization_evidence() -> None:
    """A permit must carry the exact policy, approval, and attestation evidence."""
    facts = _facts(lambda *_: {"ok": True})
    isolated_facts = replace(facts, tool=replace(facts.tool, requires_isolation=True))
    authorizer = PreExecutionAuthorizer(max_delegation_depth=0)
    policy = PolicyResult(PolicyDecision.APPROVAL_REQUIRED, "approval required")
    approval = ApprovalConsumption(ApprovalOutcome.CONSUMED, "synthetic approval")

    permit = authorizer.issue_permit(
        isolated_facts,
        policy,
        approval,
        None,
        True,
        _context(),
        CancellationToken(),
    )

    assert permit.evidence.policy is policy
    assert permit.evidence.approval is approval
    assert permit.evidence.credential_attested is False
    assert permit.evidence.isolation_attested is True

    with pytest.raises(PreExecutionAuthorizationError) as error:
        authorizer.issue_permit(
            isolated_facts,
            policy,
            ApprovalConsumption(ApprovalOutcome.NOT_CONSUMED, "rejected"),
            None,
            True,
            _context(),
            CancellationToken(),
        )
    assert str(error.value) == "approval is required and was not consumed"


def test_authorizer_preserves_exact_host_scope_failure_reasons() -> None:
    facts = _facts(lambda *_: {"ok": True})
    changed = ActionFacts(
        facts.context,
        facts.proposal,
        facts.tool,
        facts.arguments,
        (Resource("other", "record", "other"),),
        facts.action_fingerprint,
    )
    with pytest.raises(
        PreExecutionAuthorizationError, match=r"^resource is outside the task tenant$"
    ):
        PreExecutionAuthorizer(0).issue_permit(
            changed,
            PolicyResult(PolicyDecision.ALLOW, "allow"),
            None,
            None,
            False,
            _context(),
            CancellationToken(),
        )


def test_lifecycle_stop_gate_prevents_permit_handler_invocation() -> None:
    calls: list[str] = []
    authorizer = PreExecutionAuthorizer(0)
    facts = _facts(lambda *_: calls.append("called"))
    permit = authorizer.issue_permit(
        facts,
        PolicyResult(PolicyDecision.ALLOW, "allow"),
        None,
        None,
        False,
        _context(),
        CancellationToken(),
    )
    lifecycle = ExecutionLifecycle(lambda: True, authorizer._authority)

    with pytest.raises(PreExecutionAuthorizationError) as error:
        lifecycle.invoke_handler(permit)
    assert str(error.value) == "runtime emergency stop is active"
    assert calls == []


def test_authorizer_owns_lifecycle_authority_construction() -> None:
    """Callers receive a typed lifecycle without accessing issuer internals."""
    authorizer = PreExecutionAuthorizer(0)
    lifecycle = authorizer.lifecycle(lambda: True)

    assert isinstance(lifecycle, ExecutionLifecycle)
    assert not hasattr(lifecycle, "issuer")


def test_permits_cannot_be_forged_replayed_or_crossed_between_lifecycles() -> None:
    facts = _facts(lambda *_: {"ok": True})
    authorizer = PreExecutionAuthorizer(0)
    permit = authorizer.issue_permit(
        facts,
        PolicyResult(PolicyDecision.ALLOW, "allow"),
        None,
        None,
        False,
        _context(),
        CancellationToken(),
    )
    with pytest.raises(TypeError):
        ExecutionPermit(  # type: ignore[call-arg]
            facts, _context(), CancellationToken(), permit.evidence
        )
    assert not hasattr(ExecutionPermit, "_issue")
    forged = object.__new__(ExecutionPermit)
    for field in ("facts", "handler_context", "cancellation", "evidence"):
        object.__setattr__(forged, field, getattr(permit, field))
    with pytest.raises(PreExecutionAuthorizationError) as error:
        ExecutionLifecycle(lambda: False, authorizer._authority).invoke_handler(forged)
    assert str(error.value) == "execution permit was not issued by this runtime"
    with pytest.raises(PreExecutionAuthorizationError, match="not issued"):
        ExecutionLifecycle(lambda: False, PreExecutionAuthorizer(0)._authority).invoke_handler(
            permit
        )
    assert ExecutionLifecycle(lambda: False, authorizer._authority).invoke_handler(permit) == {
        "ok": True
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda facts: facts.context.__class__(
                facts.context.agent_id,
                Principal("other", tenant="other"),
                facts.context.task_id,
                facts.context.purpose,
                tenant="other",
            ),
            "tenant",
        ),
        (lambda facts: (Resource("other", "record", "other"),), "resource"),
    ],
)
def test_authorizer_rejects_host_scope_mismatches(mutate: Any, message: str) -> None:
    facts = _facts(lambda *_: {"ok": True})
    changed = facts
    if message == "tenant":
        changed = ActionFacts(
            mutate(facts),
            facts.proposal,
            facts.tool,
            facts.arguments,
            facts.resources,
            facts.action_fingerprint,
        )
    else:
        changed = ActionFacts(
            facts.context,
            facts.proposal,
            facts.tool,
            facts.arguments,
            mutate(facts),
            facts.action_fingerprint,
        )
    with pytest.raises(PreExecutionAuthorizationError, match=message):
        PreExecutionAuthorizer(0).issue_permit(
            changed,
            PolicyResult(PolicyDecision.ALLOW, "allow"),
            None,
            None,
            False,
            _context(),
            CancellationToken(),
        )


def test_authorizer_rejects_policy_approval_credential_isolation_and_delegation_failures() -> None:
    facts = _facts(lambda *_: {"ok": True})
    authorizer = PreExecutionAuthorizer(0)
    token = CancellationToken()
    with pytest.raises(PreExecutionAuthorizationError, match="denied"):
        authorizer.issue_permit(
            facts, PolicyResult(PolicyDecision.DENY, "denied"), None, None, False, _context(), token
        )
    approval_policy = PolicyResult(PolicyDecision.APPROVAL_REQUIRED, "approval")
    with pytest.raises(PreExecutionAuthorizationError, match="approval"):
        authorizer.issue_permit(facts, approval_policy, None, None, False, _context(), token)
    credential_tool_facts = ActionFacts(
        facts.context,
        facts.proposal,
        _tool(lambda *_: None).__class__(
            "credential_action",
            lambda *_: None,
            lambda value: dict(value),
            requires_credential=True,
            description="Synthetic credential action.",
        ),
        facts.arguments,
        facts.resources,
        facts.action_fingerprint,
    )
    with pytest.raises(PreExecutionAuthorizationError) as credential_error:
        authorizer.issue_permit(
            credential_tool_facts,
            PolicyResult(PolicyDecision.ALLOW, "allow"),
            None,
            None,
            False,
            _context(),
            token,
        )
    assert str(credential_error.value) == "credential scope is invalid"
    isolated_tool = ToolDefinition(
        "isolated_action",
        lambda *_: None,
        lambda value: dict(value),
        requires_isolation=True,
        description="Synthetic isolated action.",
    )
    with pytest.raises(PreExecutionAuthorizationError) as isolation_error:
        authorizer.issue_permit(
            ActionFacts(
                facts.context,
                facts.proposal,
                isolated_tool,
                facts.arguments,
                facts.resources,
                facts.action_fingerprint,
            ),
            PolicyResult(PolicyDecision.ALLOW, "allow"),
            None,
            None,
            False,
            _context(),
            token,
        )
    assert str(isolation_error.value) == "isolation attestation is invalid"


def test_action_facts_reject_missing_fingerprint() -> None:
    facts = _facts(lambda *_: None)
    with pytest.raises(SecurityConfigurationError, match="fingerprint"):
        ActionFacts(
            facts.context,
            facts.proposal,
            facts.tool,
            facts.arguments,
            facts.resources,
            "",
        )


def test_bounded_operation_tracker_retains_capacity_until_completion() -> None:
    """Timeout accounting is idempotent and never releases a live worker early."""
    tracker = BoundedOperationTracker(1)
    lease = tracker.admit("policy evaluation")
    with pytest.raises(WorkerCapacityError):
        tracker.admit("credential minting")
    lease.mark_timeout()
    lease.mark_timeout()
    assert tracker.snapshot() == {
        "timed_out_workers": 1,
        "bounded_workers": 1,
        "active_policy_evaluation": 1,
        "timed_out_policy_evaluation": 1,
    }
    assert lease.complete() is True
    assert lease.complete() is False
    assert tracker.snapshot() == {"timed_out_workers": 0, "bounded_workers": 0}


def test_action_budget_lease_release_is_atomic_under_callback_race() -> None:
    """Concurrent timeout and reconciliation callbacks cannot double-release."""
    lease = ActionBudgetLease()
    calls: list[bool] = []

    def release() -> None:
        calls.append(True)

    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(lambda _: lease.release_once(release), range(64)))
    assert sum(outcomes) == 1
    assert len(calls) == 1


def test_bounded_operation_executor_classifies_phase_and_defers_capacity_release() -> None:
    """The extracted executor preserves phase and live-worker accounting."""
    release = Event()
    observed = Event()
    cleaned = Event()
    executor = BoundedOperationExecutor(0.005, BoundedOperationTracker(1))

    def operation() -> str:
        release.wait(1)
        return "late"

    with pytest.raises(BoundedOperationTimeout) as caught:
        executor.run(
            operation,
            "policy evaluation",
            on_timeout=cleaned.set,
            on_timeout_observed=observed.set,
            timeout_phase=TimeoutPhase.POLICY,
        )
    assert caught.value.phase is TimeoutPhase.POLICY
    assert observed.is_set()
    assert not cleaned.is_set()
    release.set()
    assert cleaned.wait(1)


def test_terminal_recorder_preserves_fail_closed_persistence_behavior() -> None:
    tool = ToolDefinition(
        "component_write",
        lambda *_: {"ok": True},
        lambda value: dict(value),
        idempotency_required=True,
        description="Synthetic terminal recorder action.",
    )
    proposal = ActionProposal(
        "component_write", {"value": "safe"}, "proposal:terminal", operation_key="op:terminal"
    )
    result = ExecutionResult(ExecutionStatus.EXECUTED, tool.name, "request:terminal")
    store = InMemoryIdempotencyStore()
    recorder = TerminalRecorder(store)
    claim = recorder.claim(
        tool,
        proposal,
        _context(),
        "hash:component",
        (),
        60,
        datetime.now(UTC),
    )
    assert claim.status.value == "claimed"
    assert recorder.lookup(tool, proposal, _context(), "hash:component", ()) is not None
    assert recorder.record(tool, proposal, result) is True
    assert store.lookup("op:terminal") is not None
    assert recorder.replay_completed(tool, proposal, _context(), "hash:component", ()) == result
    assert (
        recorder.claim(
            tool,
            proposal,
            _context(),
            "hash:component",
            (),
            60,
            datetime.now(UTC),
        ).status.value
        == "existing"
    )
    with pytest.raises(TerminalRecorderError, match="conflicts"):
        recorder.lookup(tool, proposal, _context(), "hash:changed", ())
    assert recorder.gc().scanned == 1

    class BrokenStore:
        def claim(self, *_: Any) -> Any:
            raise RuntimeError("synthetic store failure")

        def lookup(self, *_: Any) -> Any:
            raise RuntimeError("synthetic store failure")

        def complete(self, *_: Any) -> Any:
            raise RuntimeError("synthetic store failure")

        def mark_uncertain(self, *_: Any) -> Any:
            raise RuntimeError("synthetic store failure")

        def gc(self, *_: Any) -> Any:
            raise RuntimeError("synthetic store failure")

    assert TerminalRecorder(BrokenStore()).record(tool, proposal, result) is False


def test_terminal_recorder_requires_claim_and_preserves_uncertain_terminal_state() -> None:
    """Only claimed keys may transition; uncertain outcomes remain non-replayable."""
    tool = ToolDefinition(
        "component_write",
        lambda *_: {"ok": True},
        lambda value: dict(value),
        idempotency_required=True,
        description="Synthetic terminal recorder lifecycle action.",
    )
    proposal = ActionProposal(
        "component_write", {"value": "safe"}, "proposal:uncertain", operation_key="op:uncertain"
    )
    result = ExecutionResult(ExecutionStatus.TIMED_OUT, tool.name, "request:uncertain")
    store = InMemoryIdempotencyStore()
    recorder = TerminalRecorder(store)
    assert recorder.record(tool, proposal, result) is False
    claim = recorder.claim(tool, proposal, _context(), "hash:uncertain", (), 60, datetime.now(UTC))
    assert claim.record.state is IdempotencyState.IN_PROGRESS
    assert recorder.record(tool, proposal, result, uncertain=True) is True
    stored = store.lookup("op:uncertain")
    assert stored is not None and stored.state is IdempotencyState.UNCERTAIN
    assert (
        recorder.claim(
            tool, proposal, _context(), "hash:uncertain", (), 60, datetime.now(UTC)
        ).status.value
        == "existing"
    )

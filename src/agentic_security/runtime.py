"""The fail-closed action mediation runtime."""

from __future__ import annotations

import json
import math
import uuid
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from threading import Event, RLock
from typing import Any

from .approvals import (
    ApprovalConsumption,
    ApprovalOutcome,
    ApprovalProvider,
    action_hash,
    normalize_approval_result,
)
from .audit import AuditSink, Redactor, redact
from .budgets import Budget, BudgetState
from .components import (
    ActionBudgetLease,
    ActionFacts,
    ActionPreparation,
    ApprovalPreparation,
    BoundedOperationExecutor,
    BoundedOperationTimeout,
    BoundedOperationTracker,
    CredentialPreparation,
    ExecutionPermit,
    PolicyPreparation,
    PreExecutionAuthorizationError,
    PreExecutionAuthorizer,
    TerminalRecorder,
    TerminalRecorderError,
    thaw_value,
)
from .credentials import CredentialBroker
from .errors import (
    RuntimeCancelledError,
    SecurityConfigurationError,
    WorkerCapacityError,
)
from .idempotency import (
    IdempotencyClaimStatus,
    IdempotencyState,
    IdempotencyStore,
)
from .isolation import IsolationVerifier
from .policies import PolicyDecision, PolicyEngine, PolicyResult
from .tools import ToolRegistry
from .types import (
    ActionProposal,
    CancellationToken,
    ExecutionContext,
    ExecutionResult,
    ExecutionStatus,
    ReconciliationResult,
    ReconciliationState,
    Resource,
    SideEffectState,
    TimeoutPhase,
)

_PhaseTimeout = BoundedOperationTimeout


@dataclass(frozen=True, slots=True)
class _AuditOutcome:
    """Internal audit write result that distinguishes timeout from other failure."""

    recorded: bool
    timed_out: bool = False

    def __bool__(self) -> bool:
        """Preserve the historical truthiness contract for private callers."""
        return self.recorded


_ActionBudgetReleaseState = ActionBudgetLease


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Runtime-wide safety settings."""

    budget: Budget = Budget()
    execution_timeout_seconds: float = 30.0
    max_timed_out_workers: int = 32
    redactor: Redactor = field(default=redact, repr=False, compare=False)
    idempotency_store: IdempotencyStore | None = field(default=None, repr=False, compare=False)
    isolation_verifier: IsolationVerifier | None = field(default=None, repr=False, compare=False)
    idempotency_ttl_seconds: int = 86_400
    clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC), repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Reject an unbounded or non-positive handler wait configuration."""
        if not math.isfinite(self.execution_timeout_seconds) or self.execution_timeout_seconds <= 0:
            raise SecurityConfigurationError("execution timeout must be finite and positive")
        if self.max_timed_out_workers <= 0:
            raise SecurityConfigurationError("maximum timed-out workers must be positive")
        if self.idempotency_ttl_seconds <= 0:
            raise SecurityConfigurationError("idempotency TTL must be positive")


class GuardedRuntime:
    """Execute only actions that pass every configured security control.

    The runtime accepts a proposal, but the application-owned context supplies
    identity and purpose. A handler is called only after explicit registry,
    validation, policy, approval, budget, idempotency, and kill-switch checks.
    """

    def __init__(
        self,
        context: ExecutionContext,
        registry: ToolRegistry,
        policy: PolicyEngine,
        audit: AuditSink,
        approvals: ApprovalProvider | None = None,
        config: RuntimeConfig | None = None,
        credentials: CredentialBroker | None = None,
    ) -> None:
        """Create a runtime with all required security dependencies explicit."""
        self.context = context
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.config = config or RuntimeConfig()
        self.credentials = credentials
        self._budget = BudgetState(self.config.budget)
        self._authorizer = PreExecutionAuthorizer(self.config.budget.max_delegation_depth)
        self._preparation = ActionPreparation()
        self._lifecycle = self._authorizer.lifecycle(self.is_stopped)
        self._terminal_recorder = TerminalRecorder(self.config.idempotency_store)
        self._stopped = False
        self._stop_lock = RLock()
        self._active_tokens: dict[str, CancellationToken] = {}
        self._budget_states: dict[str, _ActionBudgetReleaseState] = {}
        self._operation_tracker = BoundedOperationTracker(self.config.max_timed_out_workers)
        self._bounded_executor = BoundedOperationExecutor(
            lambda: self.config.execution_timeout_seconds, self._operation_tracker
        )
        # A re-entrant lock makes the check-and-execute sequence atomic for
        # idempotent tools. This is intentionally conservative: a later
        # adapter can provide per-key locks without weakening the invariant.
        self._idempotency_lock = RLock()

    def stop(self) -> None:
        """Activate the emergency stop and request cooperative cancellation."""
        with self._stop_lock:
            self._stopped = True
            for token in self._active_tokens.values():
                token.cancel()

    def is_stopped(self) -> bool:
        """Return whether the emergency stop is active."""
        with self._stop_lock:
            return self._stopped

    def health(self) -> dict[str, int | bool]:
        """Return non-sensitive lifecycle counters for operational monitoring.

        ``timed_out_workers`` counts workers that outlived the caller wait.
        They remain tracked until their underlying operation returns because
        Python cannot safely terminate an arbitrary running thread.
        """
        with self._stop_lock:
            return {
                "stopped": self._stopped,
                "active_actions": len(self._active_tokens),
                **self._operation_tracker.snapshot(),
            }

    def execute(self, proposal: ActionProposal) -> ExecutionResult:
        """Mediate and, if allowed, execute one untrusted action proposal."""
        tool = self.registry.get(proposal.tool_name)
        guard = (
            self._idempotency_lock
            if tool is not None and tool.idempotency_required
            else nullcontext()
        )
        with guard:
            return self._execute_unlocked(proposal)

    def _execute_unlocked(self, proposal: ActionProposal) -> ExecutionResult:
        """Run one proposal while the caller owns any required idempotency lock."""
        request_id = str(uuid.uuid4())
        validated_arguments: Any = None
        tool = self.registry.get(proposal.tool_name)
        if tool is None:
            reason = "unknown tool" if isinstance(proposal.tool_name, str) else "malformed tool"
            return self._deny(request_id, proposal, reason)
        if self.is_stopped():
            return self._deny(request_id, proposal, "runtime emergency stop is active")
        if not self._budget.acquire(tool.cost_units):
            return self._deny(
                request_id, proposal, "task budget exhausted or concurrency limit reached"
            )
        cancellation = CancellationToken()
        # Mutable because timeout callbacks run after the caller returns. A
        # timed-out bounded operation owns the action lease until its worker
        # exits, regardless of whether it is policy, credential, audit, or
        # handler work.
        budget_release_state = _ActionBudgetReleaseState()
        with self._stop_lock:
            if self._stopped:
                self._budget.release()
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            self._active_tokens[request_id] = cancellation
            self._budget_states[request_id] = budget_release_state
        try:
            try:
                arguments = self._preparation.validate_arguments(tool, proposal)
                validated_arguments = arguments
            except Exception:
                return self._deny(request_id, proposal, "invalid tool arguments")
            try:
                resources = self._preparation.resolve_resources(tool, arguments)
            except Exception:
                return self._deny(request_id, proposal, "invalid action resource")
            try:
                self._preparation.validate_identity(
                    self.context,
                    tool,
                    resources,
                    self.config.budget.max_delegation_depth,
                )
            except PreExecutionAuthorizationError as exc:
                return self._deny(request_id, proposal, str(exc))
            isolation_attested = False
            if tool.requires_isolation:
                isolation_nonce = str(uuid.uuid4())
                try:
                    isolation_attested = self._preparation.verify_isolation(
                        tool,
                        self.context,
                        resources,
                        self.config.isolation_verifier,
                        isolation_nonce,
                    )
                except PreExecutionAuthorizationError as exc:
                    return self._deny(request_id, proposal, str(exc))
                except Exception:
                    return self._deny(request_id, proposal, "isolation attestation is invalid")
            else:
                isolation_nonce = None
            if self.is_stopped():
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            try:
                policy_result = self._run_bounded(
                    lambda: self.policy.decide(self.context, tool, arguments, resources),
                    "policy evaluation",
                    request_id=request_id,
                    on_timeout_observed=lambda: self._defer_action_budget_release(
                        budget_release_state
                    ),
                    on_timeout=lambda: self._release_action_budget_once(budget_release_state),
                    timeout_phase=TimeoutPhase.POLICY,
                )
            except _PhaseTimeout:
                return self._deny(
                    request_id,
                    proposal,
                    "policy evaluation timed out",
                    timeout_phase=TimeoutPhase.POLICY,
                )
            except Exception:
                return self._deny(request_id, proposal, "policy evaluation failed")
            if not isinstance(policy_result, PolicyResult) or not isinstance(
                policy_result.decision, PolicyDecision
            ):
                return self._deny(request_id, proposal, "policy returned an invalid decision")
            policy_result = PolicyPreparation.apply_tool_approval_requirement(tool, policy_result)
            try:
                fingerprint = action_hash(self.context, tool.name, arguments, resources)
            except Exception:
                return self._deny(request_id, proposal, "action could not be fingerprinted")
            if self.is_stopped():
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            if tool.idempotency_required and proposal.operation_key is not None:
                try:
                    prior = self._terminal_recorder.replay_completed(
                        tool,
                        proposal,
                        self.context,
                        fingerprint,
                        resources,
                    )
                except TerminalRecorderError as exc:
                    return self._deny(request_id, proposal, str(exc))
                if prior is not None:
                    return prior
            # An approval request is a non-executing response. Do not create an
            # idempotency claim until the exact approval has been consumed.
            if policy_result.decision is PolicyDecision.APPROVAL_REQUIRED and (
                self.approvals is None or proposal.approval_id is None
            ):
                return self._approval_required(request_id, proposal, policy_result.reason)
            if tool.idempotency_required:
                if proposal.operation_key is None:
                    return self._deny(
                        request_id,
                        proposal,
                        "stable operation key is required for this tool",
                    )
                try:
                    claim = self._terminal_recorder.claim(
                        tool,
                        proposal,
                        self.context,
                        fingerprint,
                        resources,
                        self.config.idempotency_ttl_seconds,
                        self.config.clock(),
                    )
                except TerminalRecorderError as exc:
                    return self._deny(request_id, proposal, str(exc))
                if claim.status is IdempotencyClaimStatus.CONFLICT:
                    return self._deny(
                        request_id,
                        proposal,
                        "operation key conflicts with another action",
                    )
                if claim.status is IdempotencyClaimStatus.EXPIRED:
                    return self._deny(
                        request_id,
                        proposal,
                        "expired in-progress or uncertain operation requires reconciliation",
                    )
                if claim.status is IdempotencyClaimStatus.EXISTING:
                    if claim.record.state is IdempotencyState.COMPLETED:
                        prior = claim.record.result
                        if isinstance(prior, ExecutionResult):
                            return prior
                        return self._deny(request_id, proposal, "idempotency record is malformed")
                    return self._deny(
                        request_id,
                        proposal,
                        "operation outcome is still in progress or uncertain; "
                        "reconcile before retrying",
                    )
            if policy_result.decision is PolicyDecision.DENY:
                return self._deny(
                    request_id,
                    proposal,
                    policy_result.reason,
                    {
                        "resources": [asdict(resource) for resource in resources],
                        "policy_decision": policy_result.decision.value,
                        "policy_version": policy_result.policy_version,
                        "policy_provenance": policy_result.provenance,
                    },
                )
            approval_result: ApprovalConsumption | None = None
            if policy_result.decision is PolicyDecision.APPROVAL_REQUIRED:
                if self.approvals is None or proposal.approval_id is None:
                    return self._approval_required(request_id, proposal, policy_result.reason)
                approval_provider = self.approvals
                approval_details = {
                    "approval_id": proposal.approval_id,
                    "approval_action_hash": fingerprint,
                }
                try:
                    approval_result = self._consume_approval_bounded(
                        approval_provider,
                        proposal.approval_id,
                        tool.name,
                        proposal.proposal_id,
                        fingerprint,
                        request_id,
                        budget_release_state,
                    )
                except _PhaseTimeout:
                    return self._deny(
                        request_id,
                        proposal,
                        "approval consumption timed out",
                        details={
                            **approval_details,
                            "approval_outcome": ApprovalOutcome.UNKNOWN.value,
                        },
                        timeout_phase=TimeoutPhase.APPROVAL,
                    )
                except Exception:
                    approval_result = ApprovalConsumption(
                        ApprovalOutcome.UNKNOWN, "approval provider failed"
                    )
                approval_details["approval_outcome"] = approval_result.outcome.value
                if self.is_stopped():
                    return self._deny(
                        request_id,
                        proposal,
                        "runtime emergency stop is active",
                        details={
                            **approval_details,
                            "approval_stop_after_consume": approval_result.outcome
                            is ApprovalOutcome.CONSUMED,
                        },
                    )
                if approval_result.outcome is ApprovalOutcome.UNKNOWN:
                    return self._deny(
                        request_id,
                        proposal,
                        "approval outcome is unknown; reconcile before retrying",
                        details=approval_details,
                    )
                if approval_result.outcome is not ApprovalOutcome.CONSUMED:
                    return self._deny(
                        request_id,
                        proposal,
                        "approval missing, expired, or out of scope",
                        details=approval_details,
                    )
                try:
                    ApprovalPreparation.require_consumed(approval_result)
                except PreExecutionAuthorizationError as exc:
                    return self._deny(request_id, proposal, str(exc), details=approval_details)
            # Policy and approval calls can be slow. Re-check the host-owned
            # kill switch immediately before any credential capability is
            # minted; model or adapter output cannot override this boundary.
            if self.is_stopped():
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            handler_context = replace(self.context, cancellation=cancellation)
            if tool.requires_credential:
                broker = self.credentials
                if broker is None:
                    return self._deny(request_id, proposal, "credential broker is not configured")
                try:
                    credential = self._run_bounded(
                        lambda: broker.mint(
                            self.context,
                            tool,
                            resources,
                            tool.credential_ttl_seconds,
                        ),
                        "credential minting",
                        request_id=request_id,
                        on_timeout_observed=lambda: self._defer_action_budget_release(
                            budget_release_state
                        ),
                        on_timeout=lambda: self._release_action_budget_once(budget_release_state),
                        timeout_phase=TimeoutPhase.CREDENTIAL,
                    )
                    CredentialPreparation.validate_scope(credential, tool, resources)
                except PreExecutionAuthorizationError as exc:
                    return self._deny(request_id, proposal, str(exc))
                except _PhaseTimeout:
                    return self._deny(
                        request_id,
                        proposal,
                        "credential minting timed out",
                        timeout_phase=TimeoutPhase.CREDENTIAL,
                    )
                except Exception:
                    return self._deny(request_id, proposal, "credential broker failed")
                handler_context = replace(handler_context, credential=credential)
            # Credential minting is another externally controlled wait. Stop
            # may have been activated while it was running, so do not invoke a
            # side-effecting handler until the host state is checked again.
            if self.is_stopped():
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            facts = ActionFacts(
                context=self.context,
                proposal=proposal,
                tool=tool,
                arguments=arguments,
                resources=resources,
                action_fingerprint=fingerprint,
            )
            try:
                permit = self._authorizer.issue_permit(
                    facts,
                    policy_result,
                    approval_result,
                    credential if tool.requires_credential else None,
                    isolation_attested,
                    handler_context,
                    cancellation,
                )
            except PreExecutionAuthorizationError as exc:
                return self._deny(request_id, proposal, str(exc))
            output = self._run_handler(
                permit,
                request_id,
                budget_release_state,
            )
            try:
                normalized_output = (
                    tool.output_validator(output) if tool.output_validator is not None else output
                )
                safe_output = redact(self.config.redactor(normalized_output))
                encoded_output = json.dumps(
                    safe_output, sort_keys=True, separators=(",", ":")
                ).encode()
                if len(encoded_output) > tool.max_output_bytes:
                    raise ValueError("tool output exceeds configured size limit")
            except Exception as exc:
                result = ExecutionResult(
                    ExecutionStatus.EXECUTED_RESULT_REJECTED,
                    tool.name,
                    request_id,
                    reason=f"side effect executed but result was rejected: {type(exc).__name__}",
                    handler_started=True,
                    side_effect_state=SideEffectState.EXECUTED,
                )
                recorded = self._record(
                    "action_result_rejected",
                    request_id,
                    proposal,
                    {"error_type": type(exc).__name__},
                )
                if not recorded:
                    result = replace(result, audit_recorded=False)
                if recorded.timed_out:
                    result = replace(result, timeout_phase=TimeoutPhase.AUDIT)
                if not self._store_terminal(tool, proposal, result, uncertain=True):
                    result = replace(
                        result,
                        status=ExecutionStatus.EXECUTED_UNRECORDED,
                        reason="side effect result could not be durably recorded",
                        audit_recorded=False,
                        idempotency_recorded=False,
                    )
                return result
            result = ExecutionResult(
                ExecutionStatus.EXECUTED,
                tool.name,
                request_id,
                output=safe_output,
                handler_started=True,
                side_effect_state=SideEffectState.EXECUTED,
            )
            recorded = self._record(
                "action_executed",
                request_id,
                proposal,
                {
                    "status": result.status.value,
                    "resources": [asdict(resource) for resource in resources],
                    "policy_decision": policy_result.decision.value,
                    "policy_version": policy_result.policy_version,
                    "policy_provenance": policy_result.provenance,
                },
            )
            if not recorded:
                result = replace(
                    result,
                    status=ExecutionStatus.EXECUTED_UNRECORDED,
                    reason="action executed but audit recording failed",
                    audit_recorded=False,
                )
            if recorded.timed_out:
                result = replace(result, timeout_phase=TimeoutPhase.AUDIT)
            if not self._store_terminal(tool, proposal, result):
                # The handler has already run, so denying the action would be
                # false. Do not claim successful durable idempotency: a retry
                # must be treated as unsafe until the store is repaired.
                result = replace(
                    result,
                    status=ExecutionStatus.EXECUTED_UNRECORDED,
                    reason="side effect executed but idempotency result was not recorded",
                    audit_recorded=False,
                    idempotency_recorded=False,
                )
            return result
        except WorkerCapacityError:
            return self._deny(request_id, proposal, "bounded worker capacity exhausted")
        except _PhaseTimeout as timeout_error:
            cancellation.cancel()
            # A non-cooperative handler may still be performing a side effect
            # after the caller receives TIMED_OUT. Keep its concurrency slot
            # reserved until the worker exits so a timeout cannot create
            # overlapping side effects.
            self._defer_action_budget_release(budget_release_state)
            result = ExecutionResult(
                ExecutionStatus.TIMED_OUT,
                tool.name,
                request_id,
                reason="handler exceeded execution timeout; side-effect status is uncertain",
                timeout_phase=timeout_error.phase,
                handler_started=True,
                side_effect_state=SideEffectState.UNCERTAIN,
            )
            reconciliation_state = ReconciliationState.STILL_RUNNING
            completion = timeout_error.completion
            if tool.reconciliation is not None and validated_arguments is not None:
                reconciliation = tool.reconciliation
                try:
                    reconciled = self._run_bounded(
                        lambda: reconciliation(handler_context, thaw_value(validated_arguments)),
                        "side-effect reconciliation",
                        request_id=request_id,
                        on_timeout_observed=lambda: self._defer_action_budget_release(
                            budget_release_state
                        ),
                        on_timeout=lambda: self._release_action_budget_once(budget_release_state),
                        timeout_phase=TimeoutPhase.RECONCILIATION,
                    )
                    if isinstance(reconciled, ReconciliationResult):
                        if completion is not None and completion.is_set():
                            reconciliation_state = reconciled.state
                        else:
                            # A reconciliation service cannot finalize an action
                            # while its original worker is still capable of commit.
                            reconciliation_state = ReconciliationState.STILL_RUNNING
                    elif isinstance(reconciled, bool):
                        # Compatibility with the old boolean callback: a boolean
                        # cannot establish a safe final state while the worker lives.
                        reconciliation_state = ReconciliationState.STILL_RUNNING
                    else:
                        reconciliation_state = ReconciliationState.FAILED
                except Exception as exc:
                    reconciliation_state = ReconciliationState.FAILED
                    result = replace(result, timeout_phase=TimeoutPhase.RECONCILIATION)
                    self._record(
                        "reconciliation_failed",
                        request_id,
                        proposal,
                        {"error_type": type(exc).__name__},
                    )
            result = replace(result, reconciliation_state=reconciliation_state)
            recorded = self._record(
                "action_timed_out", request_id, proposal, {"reason": result.reason}
            )
            if not recorded:
                result = replace(result, audit_recorded=False)
            if not self._store_terminal(tool, proposal, result, uncertain=True):
                result = replace(
                    result,
                    idempotency_recorded=False,
                    reason=(
                        "handler timed out with uncertain side-effect state and "
                        "idempotency outcome could not be durably recorded"
                    ),
                )
            return result
        except RuntimeCancelledError:
            result = ExecutionResult(
                ExecutionStatus.CANCELLED,
                tool.name,
                request_id,
                reason="handler observed runtime cancellation",
                handler_started=True,
                side_effect_state=SideEffectState.UNCERTAIN,
            )
            recorded = self._record(
                "action_cancelled", request_id, proposal, {"reason": result.reason}
            )
            if not recorded:
                result = replace(result, audit_recorded=False)
            if not self._store_terminal(tool, proposal, result, uncertain=True):
                result = replace(
                    result,
                    idempotency_recorded=False,
                    reason=(
                        "handler cancellation was uncertain and idempotency outcome "
                        "could not be durably recorded"
                    ),
                )
            return result
        except Exception as exc:  # pragma: no cover - exercised by integration tests
            recorded = self._record(
                "action_failed", request_id, proposal, {"error_type": type(exc).__name__}
            )
            result = ExecutionResult(
                ExecutionStatus.FAILED,
                tool.name,
                request_id,
                reason="tool execution failed",
                audit_recorded=bool(recorded),
                handler_started=True,
                side_effect_state=SideEffectState.UNCERTAIN,
            )
            if not self._store_terminal(tool, proposal, result, uncertain=True):
                result = replace(
                    result,
                    idempotency_recorded=False,
                    reason=(
                        "tool execution failed and idempotency outcome could not be "
                        "durably recorded"
                    ),
                )
            return result
        finally:
            with self._stop_lock:
                self._active_tokens.pop(request_id, None)
                self._budget_states.pop(request_id, None)
            deferred = budget_release_state.is_deferred()
            if not deferred:
                self._release_action_budget_once(budget_release_state)

    def _run_handler(
        self,
        permit: ExecutionPermit,
        request_id: str,
        budget_release_state: _ActionBudgetReleaseState,
    ) -> Any:
        """Run a handler with a bounded wait and cooperative timeout signal."""
        completion = Event()

        def operation() -> Any:
            try:
                return self._lifecycle.invoke_handler(permit)
            finally:
                completion.set()

        def release_handler_budget() -> None:
            self._release_action_budget_once(budget_release_state)

        try:
            return self._run_bounded(
                operation,
                "handler execution",
                on_timeout=release_handler_budget,
                request_id=request_id,
                on_timeout_observed=lambda: self._defer_action_budget_release(budget_release_state),
                timeout_phase=TimeoutPhase.HANDLER,
            )
        except _PhaseTimeout as exc:
            permit.cancellation.cancel()
            raise _PhaseTimeout("handler execution", TimeoutPhase.HANDLER, completion) from exc

    def _consume_approval_bounded(
        self,
        provider: ApprovalProvider,
        approval_id: str,
        tool_name: str,
        proposal_id: str,
        fingerprint: str,
        request_id: str,
        budget_release_state: _ActionBudgetReleaseState,
    ) -> ApprovalConsumption:
        """Consume approval through the bounded worker and host stop boundary.

        Approval services are external security dependencies. They must have
        the same deadline, worker-capacity, action-lease, and lifecycle
        accounting as policy and credential providers. The pre-call stop check
        prevents a queued approval operation from starting after emergency
        stop; the caller rechecks stop again before any handler invocation.
        """
        if self.is_stopped():
            return ApprovalConsumption(ApprovalOutcome.NOT_CONSUMED, "runtime stopped")
        return normalize_approval_result(
            self._run_bounded(
                lambda: provider.consume(
                    approval_id,
                    self.context,
                    tool_name,
                    proposal_id,
                    fingerprint,
                ),
                "approval consumption",
                request_id=request_id,
                on_timeout_observed=lambda: self._defer_action_budget_release(budget_release_state),
                on_timeout=lambda: self._release_action_budget_once(budget_release_state),
                timeout_phase=TimeoutPhase.APPROVAL,
            )
        )

    def _run_bounded(
        self,
        operation: Callable[[], Any],
        operation_name: str,
        on_timeout: Callable[[], Any] | None = None,
        request_id: str | None = None,
        on_timeout_observed: Callable[[], None] | None = None,
        timeout_phase: TimeoutPhase | None = None,
    ) -> Any:
        """Run an operation with a bounded caller wait and lifecycle tracking.

        The wait is not a hard termination guarantee: Python cannot safely
        kill an arbitrary running thread. Timed-out workers remain accounted
        for until they return, preventing unbounded accumulation.
        """
        del request_id  # operation counters provide aggregate lifecycle evidence
        return self._bounded_executor.run(
            operation,
            operation_name,
            on_timeout=on_timeout,
            on_timeout_observed=on_timeout_observed,
            timeout_phase=timeout_phase,
        )

    @staticmethod
    def _defer_action_budget_release(state: _ActionBudgetReleaseState) -> None:
        """Mark the action lease for release only when the timed-out worker exits."""
        state.defer()

    def _release_action_budget_once(self, state: _ActionBudgetReleaseState) -> bool:
        """Release one action lease exactly once after its worker exits."""
        return state.release_once(self._budget.release)

    def _store_terminal(
        self, tool: Any, proposal: ActionProposal, result: ExecutionResult, uncertain: bool = False
    ) -> bool:
        """Persist idempotent outcomes and report whether persistence succeeded."""
        return self._terminal_recorder.record(tool, proposal, result, uncertain)

    def _validate_runtime_invariants(
        self, tool: Any, resources: tuple[Resource, ...]
    ) -> str | None:
        """Enforce identity, tenant, and delegation invariants independently of policy."""
        if self.context.principal.tenant != self.context.tenant:
            return "principal tenant does not match task tenant"
        if any(resource.tenant != self.context.tenant for resource in resources):
            return "resource is outside the task tenant"
        if tool.delegation_depth > self.config.budget.max_delegation_depth:
            return "delegation depth exceeds configured limit"
        return None

    def _deny(
        self,
        request_id: str,
        proposal: ActionProposal,
        reason: str,
        details: Mapping[str, Any] | None = None,
        timeout_phase: TimeoutPhase | None = None,
    ) -> ExecutionResult:
        """Record and return a safe denial without executing a handler."""
        recorded = self._record(
            "action_denied", request_id, proposal, {"reason": reason, **(details or {})}
        )
        tool_name = proposal.tool_name if isinstance(proposal.tool_name, str) else "<invalid>"
        return ExecutionResult(
            ExecutionStatus.DENIED,
            tool_name,
            request_id,
            reason=reason,
            audit_recorded=bool(recorded),
            timeout_phase=timeout_phase or (TimeoutPhase.AUDIT if recorded.timed_out else None),
        )

    def _approval_required(
        self, request_id: str, proposal: ActionProposal, reason: str
    ) -> ExecutionResult:
        """Record a non-executing approval request."""
        recorded = self._record("approval_required", request_id, proposal, {"reason": reason})
        tool_name = proposal.tool_name if isinstance(proposal.tool_name, str) else "<invalid>"
        return ExecutionResult(
            ExecutionStatus.APPROVAL_REQUIRED,
            tool_name,
            request_id,
            reason=reason,
            approval_id=proposal.approval_id,
            audit_recorded=bool(recorded),
            timeout_phase=TimeoutPhase.AUDIT if recorded.timed_out else None,
        )

    def _record(
        self, event_type: str, request_id: str, proposal: ActionProposal, payload: Mapping[str, Any]
    ) -> _AuditOutcome:
        """Write a redaction-aware audit event and report whether it was stored."""
        if isinstance(proposal.arguments, Mapping):
            try:
                safe_arguments: object = dict(proposal.arguments)
            except Exception:
                safe_arguments = {"[invalid_arguments]": type(proposal.arguments).__name__}
        else:
            safe_arguments = {"[invalid_arguments_type]": type(proposal.arguments).__name__}
        safe_payload = redact(
            self.config.redactor(
                {
                    "agent_id": self.context.agent_id,
                    "principal_id": self.context.principal.id,
                    "task_id": self.context.task_id,
                    "purpose": self.context.purpose,
                    "tool_name": proposal.tool_name,
                    "proposal_id": proposal.proposal_id,
                    "arguments": safe_arguments,
                    **dict(payload),
                }
            )
        )
        try:
            budget_state = self._budget_states.get(request_id)
            # Denials before action admission still need bounded audit work,
            # but they do not own an action budget lease. Never release a
            # missing lease when that audit worker eventually exits.
            release_budget = (
                (lambda: self._release_action_budget_once(budget_state))
                if budget_state is not None
                else None
            )
            self._run_bounded(
                lambda: self.audit.append(event_type, request_id, safe_payload),
                "audit persistence",
                on_timeout_observed=(
                    (lambda: self._defer_action_budget_release(budget_state))
                    if budget_state is not None
                    else None
                ),
                on_timeout=release_budget,
                timeout_phase=TimeoutPhase.AUDIT,
            )
        except _PhaseTimeout:
            return _AuditOutcome(False, timed_out=True)
        except Exception:
            return _AuditOutcome(False)
        return _AuditOutcome(True)

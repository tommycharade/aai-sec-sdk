"""The fail-closed action mediation runtime."""

from __future__ import annotations

import json
import math
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from threading import Event, Lock, RLock
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
from .credentials import CredentialBroker
from .errors import (
    RuntimeCancelledError,
    RuntimeOperationTimeoutError,
    SecurityConfigurationError,
    WorkerCapacityError,
)
from .idempotency import (
    IdempotencyClaimStatus,
    IdempotencyState,
    IdempotencyStore,
    new_record,
)
from .isolation import IsolationVerifier, validate_attestation
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


class _PhaseTimeout(RuntimeOperationTimeoutError):
    """Internal timeout carrying the public phase and optional completion event."""

    def __init__(
        self, operation_name: str, phase: TimeoutPhase, completion: Event | None = None
    ) -> None:
        super().__init__(f"{operation_name} timed out")
        self.phase = phase
        self.completion = completion


@dataclass(frozen=True, slots=True)
class _AuditOutcome:
    """Internal audit write result that distinguishes timeout from other failure."""

    recorded: bool
    timed_out: bool = False

    def __bool__(self) -> bool:
        """Preserve the historical truthiness contract for private callers."""
        return self.recorded


@dataclass(slots=True)
class _ActionBudgetReleaseState:
    """Thread-safe lease state shared by timeout and worker-exit callbacks.

    A single action can have several bounded workers over its lifetime, such
    as a timed-out handler followed by reconciliation. Their callbacks may
    race on different threads, so release and defer state are synchronized.
    """

    deferred: bool = False
    released: bool = False
    lock: Lock = field(default_factory=Lock, repr=False)


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
        self._stopped = False
        self._stop_lock = RLock()
        self._active_tokens: dict[str, CancellationToken] = {}
        self._budget_states: dict[str, _ActionBudgetReleaseState] = {}
        self._worker_lock = RLock()
        self._timed_out_workers = 0
        self._bounded_workers = 0
        self._active_operations: dict[str, int] = {}
        self._timed_out_by_operation: dict[str, int] = {}
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
        with self._stop_lock, self._worker_lock:
            return {
                "stopped": self._stopped,
                "active_actions": len(self._active_tokens),
                "timed_out_workers": self._timed_out_workers,
                "bounded_workers": self._bounded_workers,
                **{
                    f"active_{name.replace(' ', '_')}": count
                    for name, count in self._active_operations.items()
                },
                **{
                    f"timed_out_{name.replace(' ', '_')}": count
                    for name, count in self._timed_out_by_operation.items()
                },
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
                arguments = tool.validator(proposal.arguments)
                validated_arguments = arguments
            except Exception:
                return self._deny(request_id, proposal, "invalid tool arguments")
            try:
                resources = tool.resources(arguments)
                if not isinstance(resources, tuple) or not all(
                    isinstance(resource, Resource) for resource in resources
                ):
                    raise TypeError("resources must be a tuple of Resource objects")
            except Exception:
                return self._deny(request_id, proposal, "invalid action resource")
            invariant_failure = self._validate_runtime_invariants(tool, resources)
            if invariant_failure is not None:
                return self._deny(request_id, proposal, invariant_failure)
            isolation_nonce: str | None = None
            if tool.requires_isolation:
                isolation_nonce = str(uuid.uuid4())
                verifier = self.config.isolation_verifier
                provider = getattr(tool.handler, "get_isolation_attestation", None)
                if verifier is None or not callable(provider):
                    return self._deny(
                        request_id,
                        proposal,
                        "tool requires a verifier-backed isolation attestation",
                    )
                try:
                    attestation = provider(self.context, tool.name, resources, isolation_nonce)
                    if not validate_attestation(
                        attestation, self.context, tool.name, resources, isolation_nonce
                    ) or not verifier.verify(
                        attestation,
                        self.context,
                        tool.name,
                        resources,
                        isolation_nonce,
                    ):
                        return self._deny(request_id, proposal, "isolation attestation is invalid")
                except Exception:
                    return self._deny(request_id, proposal, "isolation attestation is invalid")
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
            if tool.requires_approval and policy_result.decision is PolicyDecision.ALLOW:
                policy_result = replace(
                    policy_result,
                    decision=PolicyDecision.APPROVAL_REQUIRED,
                    reason="tool declaration requires explicit approval",
                )
            try:
                fingerprint = action_hash(self.context, tool.name, arguments, resources)
            except Exception:
                return self._deny(request_id, proposal, "action could not be fingerprinted")
            if self.is_stopped():
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            if tool.idempotency_required and proposal.operation_key is not None:
                store = self.config.idempotency_store
                if store is None:
                    return self._deny(request_id, proposal, "idempotency store is not configured")
                try:
                    existing = store.lookup(proposal.operation_key)
                except Exception:
                    return self._deny(request_id, proposal, "idempotency store failed")
                if existing is not None:
                    same_action = (
                        existing.action_fingerprint == fingerprint
                        and existing.tenant == self.context.tenant
                        and existing.principal_id == self.context.principal.id
                        and existing.tool_name == tool.name
                        and existing.resource_ids == tuple(resource.id for resource in resources)
                    )
                    if not same_action:
                        return self._deny(
                            request_id, proposal, "operation key conflicts with another action"
                        )
                    if existing.state is IdempotencyState.COMPLETED:
                        if isinstance(existing.result, ExecutionResult):
                            return existing.result
                        return self._deny(request_id, proposal, "idempotency record is malformed")
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
                store = self.config.idempotency_store
                if store is None:
                    return self._deny(request_id, proposal, "idempotency store is not configured")
                try:
                    idempotency_record = new_record(
                        operation_key=proposal.operation_key,
                        action_fingerprint=fingerprint,
                        tenant=self.context.tenant or "",
                        principal_id=self.context.principal.id,
                        tool_name=tool.name,
                        resource_ids=tuple(resource.id for resource in resources),
                        ttl_seconds=self.config.idempotency_ttl_seconds,
                        now=self.config.clock(),
                    )
                    claim = store.claim(idempotency_record)
                except Exception:
                    return self._deny(request_id, proposal, "idempotency store failed")
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
                    if not credential.valid_for(tool.name, resources):
                        return self._deny(request_id, proposal, "credential scope is invalid")
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
            output = self._run_handler(
                tool.handler,
                handler_context,
                arguments,
                cancellation,
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
                        lambda: reconciliation(handler_context, validated_arguments),
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
            self._store_terminal(tool, proposal, result, uncertain=True)
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
            self._store_terminal(tool, proposal, result, uncertain=True)
            return result
        finally:
            with self._stop_lock:
                self._active_tokens.pop(request_id, None)
                self._budget_states.pop(request_id, None)
            with budget_release_state.lock:
                deferred = budget_release_state.deferred
            if not deferred:
                self._release_action_budget_once(budget_release_state)

    def _run_handler(
        self,
        handler: Any,
        context: ExecutionContext,
        arguments: Any,
        cancellation: CancellationToken,
        request_id: str,
        budget_release_state: _ActionBudgetReleaseState,
    ) -> Any:
        """Run a handler with a bounded wait and cooperative timeout signal."""
        completion = Event()

        def operation() -> Any:
            try:
                return handler(context, arguments)
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
            cancellation.cancel()
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
        with self._worker_lock:
            # Every bounded operation occupies a tracked slot. This is
            # intentionally conservative: Python cannot kill a timed-out
            # thread, so admission must reserve capacity before a race can
            # create more lingering workers than the configured maximum.
            if self._bounded_workers >= self.config.max_timed_out_workers:
                raise WorkerCapacityError("bounded worker capacity exhausted")
            self._bounded_workers += 1
            self._active_operations[operation_name] = (
                self._active_operations.get(operation_name, 0) + 1
            )
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="agentic-security")
        future = executor.submit(operation)
        timed_out = False
        callback_called = False

        def on_done(_future: Any) -> None:
            nonlocal callback_called
            if callback_called:
                return
            callback_called = True
            with self._worker_lock:
                self._bounded_workers -= 1
                self._active_operations[operation_name] -= 1
                if self._active_operations[operation_name] == 0:
                    del self._active_operations[operation_name]
                if timed_out:
                    self._timed_out_workers -= 1
                    self._timed_out_by_operation[operation_name] -= 1
                    if self._timed_out_by_operation[operation_name] == 0:
                        del self._timed_out_by_operation[operation_name]
            if timed_out and on_timeout is not None:
                on_timeout()

        try:
            return future.result(timeout=self.config.execution_timeout_seconds)
        except FutureTimeoutError as exc:
            timed_out = True
            with self._worker_lock:
                self._timed_out_workers += 1
                self._timed_out_by_operation[operation_name] = (
                    self._timed_out_by_operation.get(operation_name, 0) + 1
                )
            if on_timeout_observed is not None:
                on_timeout_observed()
            future.add_done_callback(on_done)
            future.cancel()
            if timeout_phase is None:
                raise RuntimeOperationTimeoutError(f"{operation_name} timed out") from exc
            raise _PhaseTimeout(operation_name, timeout_phase) from exc
        finally:
            if not timed_out:
                future.add_done_callback(on_done)
            executor.shutdown(wait=not timed_out, cancel_futures=True)

    @staticmethod
    def _defer_action_budget_release(state: _ActionBudgetReleaseState) -> None:
        """Mark the action lease for release only when the timed-out worker exits."""
        with state.lock:
            state.deferred = True

    def _release_action_budget_once(self, state: _ActionBudgetReleaseState) -> bool:
        """Release one action lease exactly once after its worker exits."""
        with state.lock:
            if state.released:
                return False
            state.released = True
            self._budget.release()
            return True

    def _store_terminal(
        self, tool: Any, proposal: ActionProposal, result: ExecutionResult, uncertain: bool = False
    ) -> bool:
        """Persist idempotent outcomes and report whether persistence succeeded."""
        if not tool.idempotency_required or proposal.operation_key is None:
            return True
        store = self.config.idempotency_store
        if store is None:
            return False
        try:
            if uncertain:
                store.mark_uncertain(proposal.operation_key, result)
            else:
                store.complete(proposal.operation_key, result)
        except Exception:
            # The side effect has already happened; the caller must not receive
            # an apparently successful result that can be replayed safely.
            return False
        return True

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

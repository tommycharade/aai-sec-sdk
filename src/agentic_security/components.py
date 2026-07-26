"""Typed, immutable components for the security execution boundary.

These objects deliberately contain facts and evidence only. They do not make
network calls, read model output, or discover credentials. External decisions
are collected by the runtime and passed into :class:`PreExecutionAuthorizer`,
which is the single place that turns those decisions into an execution permit.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field, replace
from threading import Event, Lock
from typing import Any
from weakref import WeakKeyDictionary

from .approvals import ApprovalConsumption, ApprovalOutcome
from .credentials import ScopedCredential
from .errors import RuntimeOperationTimeoutError, SecurityConfigurationError, WorkerCapacityError
from .idempotency import (
    IdempotencyClaim,
    IdempotencyGCReport,
    IdempotencyRecord,
    IdempotencyState,
    IdempotencyStore,
    new_record,
)
from .policies import PolicyDecision, PolicyResult
from .tools import ToolDefinition
from .types import (
    ActionProposal,
    CancellationToken,
    ExecutionContext,
    ExecutionResult,
    Resource,
    TimeoutPhase,
)


class ActionPreparation:
    """Own deterministic validation and isolation checks before policy.

    This component deliberately accepts only host-selected dependencies and
    returns typed facts. It never invokes a handler or makes an authorization
    decision; the runtime cannot accidentally treat malformed model input as
    validated action data.
    """

    @staticmethod
    def validate_arguments(tool: ToolDefinition, proposal: ActionProposal) -> Any:
        """Validate proposal arguments with the registered tool schema."""
        return tool.validator(proposal.arguments)

    @staticmethod
    def resolve_resources(tool: ToolDefinition, arguments: Any) -> tuple[Resource, ...]:
        """Resolve and type-check the resources used by authorization."""
        resources = tool.resources(arguments)
        if not isinstance(resources, tuple) or not all(
            isinstance(resource, Resource) for resource in resources
        ):
            raise TypeError("resources must be a tuple of Resource objects")
        return resources

    @staticmethod
    def validate_identity(
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        max_delegation_depth: int,
    ) -> None:
        """Reject tenant, resource, and delegation mismatches before policy."""
        if context.principal.tenant != context.tenant:
            raise PreExecutionAuthorizationError("principal tenant does not match task tenant")
        if any(resource.tenant != context.tenant for resource in resources):
            raise PreExecutionAuthorizationError("resource is outside the task tenant")
        if tool.delegation_depth > max_delegation_depth:
            raise PreExecutionAuthorizationError("delegation depth exceeds configured limit")

    @staticmethod
    def verify_isolation(
        tool: ToolDefinition,
        context: ExecutionContext,
        resources: tuple[Resource, ...],
        verifier: Any,
        nonce: str,
    ) -> bool:
        """Verify a nonce-bound attestation supplied by the registered handler."""
        if not tool.requires_isolation:
            return False
        provider = getattr(tool.handler, "get_isolation_attestation", None)
        if verifier is None or not callable(provider):
            raise PreExecutionAuthorizationError(
                "tool requires a verifier-backed isolation attestation"
            )
        attestation = provider(context, tool.name, resources, nonce)
        from .isolation import validate_attestation

        if not validate_attestation(attestation, context, tool.name, resources, nonce):
            raise PreExecutionAuthorizationError("isolation attestation is invalid")
        if not verifier.verify(attestation, context, tool.name, resources, nonce):
            raise PreExecutionAuthorizationError("isolation attestation is invalid")
        return True


class PolicyPreparation:
    """Own policy evaluation normalization before approval consumption."""

    @staticmethod
    def apply_tool_approval_requirement(tool: ToolDefinition, policy: PolicyResult) -> PolicyResult:
        """Turn a tool-declared approval requirement into a policy outcome."""
        if tool.requires_approval and policy.decision is PolicyDecision.ALLOW:
            return replace(
                policy,
                decision=PolicyDecision.APPROVAL_REQUIRED,
                reason="tool declaration requires explicit approval",
            )
        return policy


class ApprovalPreparation:
    """Own the final typed approval gate before a capability is issued."""

    @staticmethod
    def require_consumed(approval: ApprovalConsumption | None) -> ApprovalConsumption:
        """Return only a consumed approval; unknown outcomes never authorize."""
        if approval is None or approval.outcome is not ApprovalOutcome.CONSUMED:
            raise PreExecutionAuthorizationError("approval is required and was not consumed")
        return approval


class CredentialPreparation:
    """Own credential broker calls and exact scope validation."""

    @staticmethod
    def validate_scope(
        credential: ScopedCredential, tool: ToolDefinition, resources: tuple[Resource, ...]
    ) -> ScopedCredential:
        """Return a credential only when it is scoped to this exact action."""
        if not credential.valid_for(tool.name, resources):
            raise PreExecutionAuthorizationError("credential scope is invalid")
        return credential


@dataclass(frozen=True, slots=True)
class ActionFacts:
    """Immutable, host-derived facts for one exact proposed action.

    The proposal is retained for audit correlation, while ``arguments`` and
    ``resources`` are the validated values used for every authorization check.
    The model cannot alter these facts after the runtime constructs them.
    """

    context: ExecutionContext
    proposal: ActionProposal
    tool: ToolDefinition
    arguments: Any
    resources: tuple[Resource, ...]
    action_fingerprint: str

    def __post_init__(self) -> None:
        """Reject incomplete facts before they can become a permit."""
        if not self.action_fingerprint:
            raise SecurityConfigurationError("action fingerprint is required")
        if not isinstance(self.resources, tuple) or not all(
            isinstance(resource, Resource) for resource in self.resources
        ):
            raise SecurityConfigurationError("action resources must be typed and immutable")


@dataclass(frozen=True, slots=True)
class AuthorizationEvidence:
    """Typed evidence proving the checks used to issue an execution permit."""

    policy: PolicyResult
    approval: ApprovalConsumption | None
    credential_attested: bool
    isolation_attested: bool


@dataclass(frozen=True, slots=True, init=False, eq=False, weakref_slot=True)
class ExecutionPermit:
    """Immutable capability to invoke exactly one registered handler action.

    A permit binds the handler context, validated arguments, cancellation token,
    and authorization evidence to :class:`ActionFacts`. Runtime handler calls
    must receive a permit; a proposal alone is never an execution capability.
    """

    facts: ActionFacts
    handler_context: ExecutionContext
    cancellation: CancellationToken
    evidence: AuthorizationEvidence


# This registry is intentionally not represented as a field on the public
# permit.  It records only permits issued by a live authorizer and disappears
# automatically when a permit is no longer referenced.
_PERMIT_AUTHORITIES: WeakKeyDictionary[ExecutionPermit, object] = WeakKeyDictionary()


class PreExecutionAuthorizationError(Exception):
    """Expected fail-closed authorization rejection while issuing a permit."""


class PreExecutionAuthorizer:
    """Centralize the final checks that convert provider evidence into a permit."""

    def __init__(self, max_delegation_depth: int) -> None:
        """Create an authorizer with the host-selected delegation ceiling."""
        if max_delegation_depth < 0:
            raise SecurityConfigurationError("maximum delegation depth cannot be negative")
        self._max_delegation_depth = max_delegation_depth
        self._authority = object()

    def lifecycle(self, is_stopped: Callable[[], bool]) -> ExecutionLifecycle:
        """Create the permit gate owned by this authorizer.

        The authority token never crosses the component boundary. Callers get
        a typed lifecycle object, while issuer authentication remains an
        implementation detail of the authorizer and permit registry.
        """
        return ExecutionLifecycle(is_stopped, self._authority)

    def issue_permit(
        self,
        facts: ActionFacts,
        policy: PolicyResult,
        approval: ApprovalConsumption | None,
        credential: ScopedCredential | None,
        isolation_attested: bool,
        handler_context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ExecutionPermit:
        """Issue a permit only when every action-bound check is satisfied."""
        context = facts.context
        if context.principal.tenant != context.tenant:
            raise PreExecutionAuthorizationError("principal tenant does not match task tenant")
        if any(resource.tenant != context.tenant for resource in facts.resources):
            raise PreExecutionAuthorizationError("resource is outside the task tenant")
        if facts.tool.delegation_depth > self._max_delegation_depth:
            raise PreExecutionAuthorizationError("delegation depth exceeds configured limit")
        if policy.decision is PolicyDecision.DENY:
            raise PreExecutionAuthorizationError(policy.reason)
        if policy.decision is PolicyDecision.APPROVAL_REQUIRED and (
            approval is None or approval.outcome is not ApprovalOutcome.CONSUMED
        ):
            raise PreExecutionAuthorizationError("approval is required and was not consumed")
        credential_attested = credential is not None
        if facts.tool.requires_credential and (
            credential is None or not credential.valid_for(facts.tool.name, facts.resources)
        ):
            raise PreExecutionAuthorizationError("credential scope is invalid")
        if facts.tool.requires_isolation and not isolation_attested:
            raise PreExecutionAuthorizationError("isolation attestation is invalid")
        evidence = AuthorizationEvidence(
            policy=policy,
            approval=approval,
            credential_attested=credential_attested,
            isolation_attested=isolation_attested,
        )
        # Construct and register the capability only after every mandatory
        # host-owned authorization check above has passed. There is no separate
        # helper or public constructor that can mint a registry-valid permit.
        permit = object.__new__(ExecutionPermit)
        object.__setattr__(permit, "facts", facts)
        object.__setattr__(permit, "handler_context", handler_context)
        object.__setattr__(permit, "cancellation", cancellation)
        object.__setattr__(permit, "evidence", evidence)
        _PERMIT_AUTHORITIES[permit] = self._authority
        return permit


class ExecutionLifecycle:
    """Own the final kill-switch check and permit-gated handler invocation."""

    def __init__(self, is_stopped: Callable[[], bool], authority: object) -> None:
        """Create a lifecycle gate backed by the host-owned stop control."""
        self._is_stopped = is_stopped
        self._authority = authority

    def invoke_handler(self, permit: ExecutionPermit) -> Any:
        """Invoke only the handler bound to ``permit`` after a stop re-check."""
        if self._is_stopped():
            raise PreExecutionAuthorizationError("runtime emergency stop is active")
        if _PERMIT_AUTHORITIES.get(permit) is not self._authority:
            raise PreExecutionAuthorizationError("execution permit was not issued by this runtime")
        return permit.facts.tool.handler(permit.handler_context, permit.facts.arguments)

    @staticmethod
    def completion_event() -> Event:
        """Return a local completion event for late-worker lifecycle tracking."""
        return Event()


class TerminalRecorderError(RuntimeError):
    """Fail-closed terminal/idempotency recorder error."""


@dataclass(slots=True)
class ActionBudgetLease:
    """Thread-safe one-shot lease for an admitted consequential action.

    Timeout and worker-exit callbacks may race, including across handler and
    reconciliation workers. The lease owns the invariant that the underlying
    action budget is released at most once; the runtime supplies the actual
    budget release operation so this component remains provider-neutral.
    """

    deferred: bool = False
    released: bool = False
    _lock: Lock = field(default_factory=Lock, repr=False)

    def defer(self) -> None:
        """Mark the lease for release after the timed-out worker exits."""
        with self._lock:
            self.deferred = True

    def release_once(self, release: Callable[[], object]) -> bool:
        """Run ``release`` exactly once and report whether this call won."""
        with self._lock:
            if self.released:
                return False
            self.released = True
            release()
            return True

    def is_deferred(self) -> bool:
        """Return the synchronized deferred-release state."""
        with self._lock:
            return self.deferred


@dataclass(slots=True)
class BoundedOperationLease:
    """One tracked bounded operation with idempotent timeout completion."""

    tracker: BoundedOperationTracker
    operation_name: str
    timed_out: bool = False
    completed: bool = False
    _lock: Lock = field(default_factory=Lock, repr=False)

    def mark_timeout(self) -> None:
        """Record that the caller wait timed out before worker completion."""
        with self._lock:
            if self.completed or self.timed_out:
                return
            self.timed_out = True
            self.tracker._mark_timeout(self.operation_name)

    def complete(self) -> bool:
        """Release lifecycle counters once and return the first-call result."""
        with self._lock:
            if self.completed:
                return False
            self.completed = True
            timed_out = self.timed_out
        self.tracker._complete(self.operation_name, timed_out)
        return True


class BoundedOperationTracker:
    """Thread-safe admission and observability for bounded worker operations.

    This tracker does not execute or cancel work. It owns only the security
    accounting invariant: a timed-out worker retains a capacity slot until it
    exits, and every slot/counter transition is applied at most once.
    """

    def __init__(self, maximum: int) -> None:
        """Create a tracker with a positive maximum number of live workers."""
        if maximum <= 0:
            raise SecurityConfigurationError("maximum timed-out workers must be positive")
        self._maximum = maximum
        self._lock = Lock()
        self._bounded_workers = 0
        self._timed_out_workers = 0
        self._active_operations: dict[str, int] = {}
        self._timed_out_by_operation: dict[str, int] = {}

    def admit(self, operation_name: str) -> BoundedOperationLease:
        """Reserve one worker slot or fail closed when capacity is exhausted."""
        with self._lock:
            if self._bounded_workers >= self._maximum:
                raise WorkerCapacityError("bounded worker capacity exhausted")
            self._bounded_workers += 1
            self._active_operations[operation_name] = (
                self._active_operations.get(operation_name, 0) + 1
            )
        return BoundedOperationLease(self, operation_name)

    def _mark_timeout(self, operation_name: str) -> None:
        """Account for a caller timeout while retaining the worker slot."""
        with self._lock:
            self._timed_out_workers += 1
            self._timed_out_by_operation[operation_name] = (
                self._timed_out_by_operation.get(operation_name, 0) + 1
            )

    def _complete(self, operation_name: str, timed_out: bool) -> None:
        """Remove one worker and, when applicable, its timeout counters."""
        with self._lock:
            self._bounded_workers -= 1
            self._active_operations[operation_name] -= 1
            if self._active_operations[operation_name] == 0:
                del self._active_operations[operation_name]
            if timed_out:
                self._timed_out_workers -= 1
                self._timed_out_by_operation[operation_name] -= 1
                if self._timed_out_by_operation[operation_name] == 0:
                    del self._timed_out_by_operation[operation_name]

    def snapshot(self) -> dict[str, int]:
        """Return a copy of aggregate lifecycle counters for health reporting."""
        with self._lock:
            return {
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


class BoundedOperationTimeout(RuntimeOperationTimeoutError):
    """Typed timeout raised by the bounded execution component."""

    def __init__(
        self, operation_name: str, phase: TimeoutPhase | None, completion: Event | None = None
    ) -> None:
        """Bind the timeout to its security phase and optional worker completion."""
        super().__init__(f"{operation_name} timed out")
        self.phase = phase
        self.completion = completion


class BoundedOperationExecutor:
    """Execute provider operations with bounded waits and lifecycle accounting.

    The executor owns timeout classification and worker admission. The runtime
    remains responsible for ordering policy, approval, credential, handler,
    reconciliation, and audit calls around this component.
    """

    def __init__(
        self, timeout_seconds: float | Callable[[], float], tracker: BoundedOperationTracker
    ) -> None:
        """Create an executor with an explicit caller wait and tracker."""
        self._timeout_seconds = timeout_seconds
        self._tracker = tracker

    def _timeout(self) -> float:
        """Read the live host timeout, supporting runtime configuration updates."""
        return self._timeout_seconds() if callable(self._timeout_seconds) else self._timeout_seconds

    def run(
        self,
        operation: Callable[[], Any],
        operation_name: str,
        on_timeout: Callable[[], Any] | None = None,
        on_timeout_observed: Callable[[], None] | None = None,
        timeout_phase: TimeoutPhase | None = None,
    ) -> Any:
        """Run one operation and retain capacity until a timed-out worker exits."""
        lease = self._tracker.admit(operation_name)
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="agentic-security")
        future = executor.submit(operation)
        callback_called = False

        def on_done(_future: Any) -> None:
            nonlocal callback_called
            if callback_called:
                return
            callback_called = True
            timed_out = lease.timed_out
            lease.complete()
            if timed_out and on_timeout is not None:
                on_timeout()

        try:
            return future.result(timeout=self._timeout())
        except FutureTimeoutError as exc:
            lease.mark_timeout()
            if on_timeout_observed is not None:
                on_timeout_observed()
            future.add_done_callback(on_done)
            future.cancel()
            raise BoundedOperationTimeout(operation_name, timeout_phase) from exc
        finally:
            if not lease.timed_out:
                future.add_done_callback(on_done)
            executor.shutdown(wait=not lease.timed_out, cancel_futures=True)


class TerminalRecorder:
    """Own idempotency lookup, claim, terminal persistence, and safe GC."""

    def __init__(self, store: IdempotencyStore | None) -> None:
        """Create a recorder with an explicit optional idempotency store."""
        self._store = store

    def _require_store(self) -> IdempotencyStore:
        """Return the configured store or fail closed."""
        if self._store is None:
            raise TerminalRecorderError("idempotency store is not configured")
        return self._store

    @staticmethod
    def _same_action(
        record: IdempotencyRecord,
        tool: ToolDefinition,
        context: ExecutionContext,
        fingerprint: str,
        resources: tuple[Resource, ...],
    ) -> bool:
        """Check the complete host-owned identity tuple for replay safety."""
        return (
            record.action_fingerprint == fingerprint
            and record.tenant == context.tenant
            and record.principal_id == context.principal.id
            and record.tool_name == tool.name
            and record.resource_ids == tuple(resource.id for resource in resources)
        )

    def lookup(
        self,
        tool: ToolDefinition,
        proposal: ActionProposal,
        context: ExecutionContext,
        fingerprint: str,
        resources: tuple[Resource, ...],
    ) -> IdempotencyRecord | None:
        """Lookup a prior operation and reject collisions before approval use."""
        if not tool.idempotency_required or proposal.operation_key is None:
            return None
        try:
            record = self._require_store().lookup(proposal.operation_key)
        except TerminalRecorderError:
            raise
        except Exception as exc:
            raise TerminalRecorderError("idempotency store failed") from exc
        if record is not None and not self._same_action(
            record, tool, context, fingerprint, resources
        ):
            raise TerminalRecorderError("operation key conflicts with another action")
        return record

    def replay_completed(
        self,
        tool: ToolDefinition,
        proposal: ActionProposal,
        context: ExecutionContext,
        fingerprint: str,
        resources: tuple[Resource, ...],
    ) -> ExecutionResult | None:
        """Return a valid completed result, or ``None`` for live operations.

        Identity collision and malformed terminal records fail closed here so
        the runtime cannot accidentally implement a second replay policy.
        In-progress and uncertain records remain available to ``claim`` for
        their explicit no-replay outcome.
        """
        record = self.lookup(tool, proposal, context, fingerprint, resources)
        if record is None or record.state is not IdempotencyState.COMPLETED:
            return None
        if isinstance(record.result, ExecutionResult):
            return record.result
        raise TerminalRecorderError("idempotency record is malformed")

    def claim(
        self,
        tool: ToolDefinition,
        proposal: ActionProposal,
        context: ExecutionContext,
        fingerprint: str,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
        now: Any,
    ) -> IdempotencyClaim:
        """Atomically claim the exact action or return replay/expiry evidence."""
        if not tool.idempotency_required or proposal.operation_key is None:
            raise TerminalRecorderError("stable operation key is required for this tool")
        try:
            record = new_record(
                operation_key=proposal.operation_key,
                action_fingerprint=fingerprint,
                tenant=context.tenant or "",
                principal_id=context.principal.id,
                tool_name=tool.name,
                resource_ids=tuple(resource.id for resource in resources),
                ttl_seconds=ttl_seconds,
                now=now,
            )
            return self._require_store().claim(record)
        except TerminalRecorderError:
            raise
        except Exception as exc:
            raise TerminalRecorderError("idempotency store failed") from exc

    def gc(self, now: Any = None) -> IdempotencyGCReport:
        """Run observable store GC; adapters retain their safe-state semantics."""
        try:
            return self._require_store().gc(now)
        except TerminalRecorderError:
            raise
        except Exception as exc:
            raise TerminalRecorderError("idempotency store failed") from exc

    def record(
        self,
        tool: ToolDefinition,
        proposal: ActionProposal,
        result: ExecutionResult,
        uncertain: bool = False,
    ) -> bool:
        """Record an outcome, returning ``False`` when durable persistence fails."""
        if not tool.idempotency_required or proposal.operation_key is None:
            return True
        if self._store is None:
            return False
        try:
            if uncertain:
                self._store.mark_uncertain(proposal.operation_key, result)
            else:
                self._store.complete(proposal.operation_key, result)
        except Exception:
            # The side effect may already exist. Never turn a terminal store
            # failure into an apparently replay-safe success.
            return False
        return True

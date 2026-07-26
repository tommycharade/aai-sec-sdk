"""Typed objects used across the guarded execution boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Event
from typing import Any

from .errors import SecurityConfigurationError


class RiskLevel(StrEnum):
    """Impact classification used to select policy and approval controls."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(StrEnum):
    """Structured outcome values returned by the guarded runtime."""

    EXECUTED = "executed"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    FAILED = "failed"
    EXECUTED_UNRECORDED = "executed_unrecorded"
    EXECUTED_RESULT_REJECTED = "executed_result_rejected"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    RECONCILED = "reconciled"


class TimeoutPhase(StrEnum):
    """Bounded operation phase that exceeded its caller deadline."""

    POLICY = "policy"
    APPROVAL = "approval"
    CREDENTIAL = "credential"
    AUDIT = "audit"
    HANDLER = "handler"
    RECONCILIATION = "reconciliation"


class SideEffectState(StrEnum):
    """Safety-relevant knowledge about whether a handler side effect is settled."""

    NOT_STARTED = "not_started"
    EXECUTED = "executed"
    UNCERTAIN = "uncertain"


class ReconciliationState(StrEnum):
    """Independent evidence state for a timed-out side effect."""

    UNKNOWN = "unknown"
    CONFIRMED_COMPLETE = "confirmed_complete"
    CONFIRMED_ABSENT = "confirmed_absent"
    STILL_RUNNING = "still_running"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """Typed reconciliation evidence; it is not permission to ignore a live worker."""

    state: ReconciliationState
    reason: str = ""

    def __post_init__(self) -> None:
        """Require a structured state rather than an ambiguous boolean."""
        if not isinstance(self.reason, str):
            raise SecurityConfigurationError("reconciliation reason must be text")


class CancellationToken:
    """Thread-safe cooperative cancellation signal for a running handler."""

    def __init__(self) -> None:
        """Create a token that is initially active."""
        self._event = Event()

    def cancel(self) -> None:
        """Signal the handler to stop at its next cooperative checkpoint."""
        self._event.set()

    def is_cancelled(self) -> bool:
        """Return whether cancellation has been requested."""
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        """Raise ``RuntimeCancelledError`` if cancellation has been requested."""
        if self.is_cancelled():
            from .errors import RuntimeCancelledError

            raise RuntimeCancelledError("runtime cancellation requested")


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity on whose behalf an action is requested.

    The runtime accepts this object from application authentication context,
    never from a model proposal. Tenant identity is mandatory so authorization
    cannot silently run without an isolation boundary.
    """

    id: str
    kind: str = "user"
    tenant: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete authenticated identity supplied by the host."""
        if (
            not isinstance(self.id, str)
            or not self.id.strip()
            or not isinstance(self.kind, str)
            or not self.kind.strip()
        ):
            raise SecurityConfigurationError("principal id and kind are required")
        if not isinstance(self.tenant, str) or not self.tenant.strip():
            raise SecurityConfigurationError("principal tenant is required")


@dataclass(frozen=True, slots=True)
class Resource:
    """Resource targeted by an action with a mandatory tenant association."""

    id: str
    kind: str
    tenant: str | None = None

    def __post_init__(self) -> None:
        """Reject resources that cannot be unambiguously authorized."""
        if (
            not isinstance(self.id, str)
            or not self.id.strip()
            or not isinstance(self.kind, str)
            or not self.kind.strip()
        ):
            raise SecurityConfigurationError("resource id and kind are required")
        if not isinstance(self.tenant, str) or not self.tenant.strip():
            raise SecurityConfigurationError("resource tenant is required")


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Immutable security context for one agent task.

    ``principal`` and ``agent_id`` are application-owned identity values. The
    model cannot change them by returning different tool-call arguments.
    """

    agent_id: str
    principal: Principal
    task_id: str
    purpose: str
    tenant: str | None = None
    environment: str = "production"
    metadata: Mapping[str, str] = field(default_factory=dict)
    # The runtime attaches a broker-issued credential only after authorization;
    # it is never populated from an untrusted action proposal.
    credential: Any = field(default=None, repr=False, compare=False)
    cancellation: CancellationToken | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject incomplete host-owned context before it reaches policy."""
        if (
            not isinstance(self.agent_id, str)
            or not self.agent_id.strip()
            or not isinstance(self.task_id, str)
            or not self.task_id.strip()
            or not isinstance(self.purpose, str)
            or not self.purpose.strip()
        ):
            raise SecurityConfigurationError("agent id, task id, and purpose are required")
        if not isinstance(self.tenant, str) or not self.tenant.strip():
            raise SecurityConfigurationError("task tenant is required")


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """Untrusted action proposed by a model or orchestrator."""

    tool_name: str
    arguments: Mapping[str, Any]
    proposal_id: str
    approval_id: str | None = None
    operation_key: str | None = None

    def __post_init__(self) -> None:
        """Reject malformed model-originated proposals before registry lookup."""
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise SecurityConfigurationError("proposal tool name is required")
        if not isinstance(self.arguments, Mapping):
            raise SecurityConfigurationError("proposal arguments must be a mapping")
        if not isinstance(self.proposal_id, str) or not self.proposal_id.strip():
            raise SecurityConfigurationError("proposal id is required")
        if self.approval_id is not None and (
            not isinstance(self.approval_id, str) or not self.approval_id.strip()
        ):
            raise SecurityConfigurationError("approval id must be a non-empty string")
        if self.operation_key is not None and (
            not isinstance(self.operation_key, str) or not self.operation_key.strip()
        ):
            raise SecurityConfigurationError("operation key must be a non-empty string")


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Structured outcome of an attempted action.

    ``audit_recorded`` and ``idempotency_recorded`` are independent signals.
    An action can be auditable while its replay-prevention result is not
    durable, or vice versa; callers must treat either false value as an
    operational failure requiring repair before retrying a side effect.
    """

    status: ExecutionStatus
    tool_name: str
    request_id: str
    reason: str | None = None
    output: Any = None
    approval_id: str | None = None
    audit_recorded: bool = True
    idempotency_recorded: bool = True
    reconciliation_state: ReconciliationState | None = None
    timeout_phase: TimeoutPhase | None = None
    handler_started: bool = False
    side_effect_state: SideEffectState = SideEffectState.NOT_STARTED

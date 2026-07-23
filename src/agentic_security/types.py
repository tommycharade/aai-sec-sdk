"""Typed objects used across the guarded execution boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
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


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity on whose behalf an action is requested.

    The runtime accepts this object from application authentication context,
    never from a model proposal. ``tenant`` is optional for single-tenant
    deployments but should be supplied whenever tenant isolation matters.
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
        if self.tenant is not None and (
            not isinstance(self.tenant, str) or not self.tenant.strip()
        ):
            raise SecurityConfigurationError("principal tenant cannot be empty")


@dataclass(frozen=True, slots=True)
class Resource:
    """Resource targeted by an action, with an optional tenant association."""

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
        if self.tenant is not None and (
            not isinstance(self.tenant, str) or not self.tenant.strip()
        ):
            raise SecurityConfigurationError("resource tenant cannot be empty")


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
        if self.tenant is not None and (
            not isinstance(self.tenant, str) or not self.tenant.strip()
        ):
            raise SecurityConfigurationError("task tenant cannot be empty")


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """Untrusted action proposed by a model or orchestrator."""

    tool_name: str
    arguments: Mapping[str, Any]
    proposal_id: str
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Structured outcome of an attempted action."""

    status: ExecutionStatus
    tool_name: str
    request_id: str
    reason: str | None = None
    output: Any = None
    approval_id: str | None = None

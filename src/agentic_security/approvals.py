"""Approval contracts with scoped, expiring in-memory implementation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Protocol

from .types import ExecutionContext


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    """Single-action approval bound to task, tool, and proposal."""

    approval_id: str
    task_id: str
    tool_name: str
    proposal_id: str
    approver_id: str
    expires_at: datetime
    used: bool = False


class ApprovalProvider(Protocol):
    """Interface for human approval systems or enterprise approval services."""

    def consume(
        self, approval_id: str, context: ExecutionContext, tool_name: str, proposal_id: str
    ) -> bool:
        """Atomically consume a valid, scoped approval."""


class InMemoryApprovalProvider:
    """Thread-safe approval provider for tests and local development.

    Production deployments should supply an adapter backed by an authenticated
    approval service. This class intentionally does not prompt or contact a
    network from inside the runtime.
    """

    def __init__(self, now: Callable[[], datetime] | None = None) -> None:
        """Create an empty provider with an injectable clock for deterministic tests."""
        self._now = now or (lambda: datetime.now(UTC))
        self._grants: dict[str, ApprovalGrant] = {}
        self._lock = Lock()

    def issue(
        self,
        approval_id: str,
        context: ExecutionContext,
        tool_name: str,
        proposal_id: str,
        approver_id: str,
        ttl_seconds: int = 120,
    ) -> ApprovalGrant:
        """Issue a scoped approval for a future proposal, with a bounded TTL."""
        if ttl_seconds <= 0:
            raise ValueError("approval TTL must be positive")
        grant = ApprovalGrant(
            approval_id,
            context.task_id,
            tool_name,
            proposal_id,
            approver_id,
            self._now() + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._grants[approval_id] = grant
        return grant

    def consume(
        self, approval_id: str, context: ExecutionContext, tool_name: str, proposal_id: str
    ) -> bool:
        """Consume exactly one valid, unexpired approval matching the action."""
        with self._lock:
            grant = self._grants.get(approval_id)
            if grant is None or grant.used or self._now() >= grant.expires_at:
                return False
            if (grant.task_id, grant.tool_name, grant.proposal_id) != (
                context.task_id,
                tool_name,
                proposal_id,
            ):
                return False
            self._grants[approval_id] = replace(grant, used=True)
            return True

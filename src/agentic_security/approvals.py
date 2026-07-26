"""Approval contracts with scoped, expiring in-memory implementation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import Protocol

from .types import ExecutionContext, Resource


class ApprovalOutcome(StrEnum):
    """Authoritative state returned by an approval consumption attempt."""

    CONSUMED = "consumed"
    NOT_CONSUMED = "not_consumed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ApprovalConsumption:
    """Typed approval result with safe boolean compatibility."""

    outcome: ApprovalOutcome
    reason: str = ""

    def __bool__(self) -> bool:
        """Preserve legacy truthiness without treating unknown as success."""
        return self.outcome is ApprovalOutcome.CONSUMED


def normalize_approval_result(
    value: ApprovalConsumption | bool | object,
) -> ApprovalConsumption:
    """Normalize typed providers and legacy booleans without unsafe inference."""
    if isinstance(value, ApprovalConsumption):
        return value
    if value is True:
        return ApprovalConsumption(ApprovalOutcome.CONSUMED, "legacy provider consumed approval")
    if value is False:
        return ApprovalConsumption(ApprovalOutcome.NOT_CONSUMED, "legacy provider did not consume")
    return ApprovalConsumption(
        ApprovalOutcome.UNKNOWN, "approval provider returned invalid outcome"
    )


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    """Single-action approval bound to task, tool, and proposal."""

    approval_id: str
    task_id: str
    tool_name: str
    proposal_id: str
    approver_id: str
    action_hash: str
    expires_at: datetime
    used: bool = False


class ApprovalProvider(Protocol):
    """Interface for human approval systems or enterprise approval services."""

    def consume(
        self,
        approval_id: str,
        context: ExecutionContext,
        tool_name: str,
        proposal_id: str,
        action_hash: str,
    ) -> ApprovalConsumption | bool:
        """Atomically consume a valid approval bound to exact action data.

        Legacy providers may return ``bool``; new providers should return
        :class:`ApprovalConsumption` so unknown commit state is explicit.
        """


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
        action_hash: str,
        ttl_seconds: int = 120,
    ) -> ApprovalGrant:
        """Issue a scoped approval for a future proposal, with a bounded TTL."""
        if ttl_seconds <= 0:
            raise ValueError("approval TTL must be positive")
        if not action_hash:
            raise ValueError("approval action hash is required")
        grant = ApprovalGrant(
            approval_id,
            context.task_id,
            tool_name,
            proposal_id,
            approver_id,
            action_hash,
            self._now() + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._grants[approval_id] = grant
        return grant

    def consume(
        self,
        approval_id: str,
        context: ExecutionContext,
        tool_name: str,
        proposal_id: str,
        action_hash: str,
    ) -> ApprovalConsumption:
        """Consume one approval matching the exact validated action fingerprint."""
        with self._lock:
            grant = self._grants.get(approval_id)
            if grant is None or grant.used or self._now() >= grant.expires_at:
                return ApprovalConsumption(
                    ApprovalOutcome.NOT_CONSUMED, "missing, used, or expired"
                )
            if (grant.task_id, grant.tool_name, grant.proposal_id) != (
                context.task_id,
                tool_name,
                proposal_id,
            ):
                return ApprovalConsumption(ApprovalOutcome.NOT_CONSUMED, "action binding mismatch")
            if grant.action_hash != action_hash:
                return ApprovalConsumption(ApprovalOutcome.NOT_CONSUMED, "action hash mismatch")
            self._grants[approval_id] = replace(grant, used=True)
            return ApprovalConsumption(ApprovalOutcome.CONSUMED, "approval consumed")


def action_hash(
    context: ExecutionContext,
    tool_name: str,
    arguments: object,
    resources: tuple[Resource, ...],
) -> str:
    """Hash host-owned identity and the exact validated action for approval binding."""

    def json_ready(value: object) -> object:
        """Convert immutable authorization containers to JSON primitives."""
        if isinstance(value, Mapping):
            return {key: json_ready(child) for key, child in value.items()}
        if isinstance(value, (tuple, list)):
            return [json_ready(child) for child in value]
        return value

    canonical = json.dumps(
        {
            "agent_id": context.agent_id,
            "principal_id": context.principal.id,
            "principal_kind": context.principal.kind,
            "principal_tenant": context.principal.tenant,
            "task_id": context.task_id,
            "purpose": context.purpose,
            "tenant": context.tenant,
            "environment": context.environment,
            "tool_name": tool_name,
            "arguments": json_ready(arguments),
            "resources": [asdict(resource) for resource in resources],
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()

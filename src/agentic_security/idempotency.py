"""Idempotency contracts for side-effecting tools.

The core deliberately provides only an in-memory reference implementation.
Production deployments must provide an authenticated, durable implementation
whose claim operation is atomic across processes and survives restarts.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import Any, Protocol


class IdempotencyState(StrEnum):
    """Lifecycle states stored for one caller-owned operation key."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    UNCERTAIN = "uncertain"


class IdempotencyClaimStatus(StrEnum):
    """Result of an atomic idempotency claim."""

    CLAIMED = "claimed"
    EXISTING = "existing"
    CONFLICT = "conflict"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class IdempotencyGCReport:
    """Observable result of a safe garbage-collection pass."""

    scanned: int
    removed_completed: int
    retained_active: int
    at: datetime


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    """Stored identity and outcome for a caller-supplied operation key."""

    operation_key: str
    action_fingerprint: str
    tenant: str
    principal_id: str
    tool_name: str
    resource_ids: tuple[str, ...]
    state: IdempotencyState
    result: Any = None
    created_at: datetime = datetime.min.replace(tzinfo=UTC)
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IdempotencyClaim:
    """Atomic claim response returned by an idempotency store."""

    status: IdempotencyClaimStatus
    record: IdempotencyRecord


class IdempotencyStore(Protocol):
    """Provider-neutral durable idempotency contract.

    ``claim`` must be atomic for the complete identity tuple. A store must
    never return a record for a different action fingerprint under the same
    operation key; it must return ``CONFLICT`` instead.
    """

    def claim(self, record: IdempotencyRecord) -> IdempotencyClaim:
        """Atomically claim ``record.operation_key`` or return its prior state."""

    def lookup(self, operation_key: str) -> IdempotencyRecord | None:
        """Return a prior record without creating or changing a claim."""

    def complete(self, operation_key: str, result: Any) -> IdempotencyRecord:
        """Persist a successful or terminal result for a claimed operation."""

    def mark_uncertain(self, operation_key: str, result: Any) -> IdempotencyRecord:
        """Persist an outcome that requires reconciliation before retry."""

    def gc(self, now: datetime | None = None) -> IdempotencyGCReport:
        """Remove only expired completed records and report retained records."""


class InMemoryIdempotencyStore:
    """Thread-safe local reference store for tests and development only.

    This implementation is process-local and loses state on restart. It is
    intentionally exported so applications can make that limitation explicit;
    it must not be presented as durable production idempotency.
    """

    def __init__(self, now: Callable[[], datetime] | None = None) -> None:
        """Create an empty process-local store."""
        self._records: dict[str, IdempotencyRecord] = {}
        self._lock = Lock()
        self._now = now or (lambda: datetime.now(UTC))

    def claim(self, record: IdempotencyRecord) -> IdempotencyClaim:
        """Atomically claim a key, detect identity collisions, and reuse state."""
        if not record.operation_key.strip():
            raise ValueError("operation key is required")
        with self._lock:
            existing = self._records.get(record.operation_key)
            if existing is None:
                self._records[record.operation_key] = record
                return IdempotencyClaim(IdempotencyClaimStatus.CLAIMED, record)
            now = self._now()
            if existing.expires_at is not None and existing.expires_at <= now:
                if existing.state is IdempotencyState.COMPLETED:
                    del self._records[record.operation_key]
                    self._records[record.operation_key] = record
                    return IdempotencyClaim(IdempotencyClaimStatus.CLAIMED, record)
                return IdempotencyClaim(IdempotencyClaimStatus.EXPIRED, existing)
            identity = (
                existing.action_fingerprint,
                existing.tenant,
                existing.principal_id,
                existing.tool_name,
                existing.resource_ids,
            )
            requested = (
                record.action_fingerprint,
                record.tenant,
                record.principal_id,
                record.tool_name,
                record.resource_ids,
            )
            if identity != requested:
                return IdempotencyClaim(IdempotencyClaimStatus.CONFLICT, existing)
            return IdempotencyClaim(IdempotencyClaimStatus.EXISTING, existing)

    def lookup(self, operation_key: str) -> IdempotencyRecord | None:
        """Return a snapshot for replay detection before approval consumption."""
        with self._lock:
            existing = self._records.get(operation_key)
            if (
                existing is not None
                and existing.state is IdempotencyState.COMPLETED
                and existing.expires_at is not None
                and existing.expires_at <= self._now()
            ):
                del self._records[operation_key]
                return None
            return existing

    def _update(
        self, operation_key: str, state: IdempotencyState, result: Any
    ) -> IdempotencyRecord:
        """Update a claimed record without allowing an unknown key to appear."""
        with self._lock:
            existing = self._records.get(operation_key)
            if existing is None:
                raise KeyError("operation key was not claimed")
            updated = IdempotencyRecord(
                operation_key=existing.operation_key,
                action_fingerprint=existing.action_fingerprint,
                tenant=existing.tenant,
                principal_id=existing.principal_id,
                tool_name=existing.tool_name,
                resource_ids=existing.resource_ids,
                state=state,
                result=result,
                created_at=existing.created_at,
                expires_at=existing.expires_at,
            )
            self._records[operation_key] = updated
            return updated

    def complete(self, operation_key: str, result: Any) -> IdempotencyRecord:
        """Store a terminal result."""
        return self._update(operation_key, IdempotencyState.COMPLETED, result)

    def mark_uncertain(self, operation_key: str, result: Any) -> IdempotencyRecord:
        """Store an uncertain result that must not be blindly retried."""
        return self._update(operation_key, IdempotencyState.UNCERTAIN, result)

    def gc(self, now: datetime | None = None) -> IdempotencyGCReport:
        """Remove expired completed records, retaining active/uncertain records."""
        at = now or self._now()
        with self._lock:
            records = tuple(self._records.values())
            removed = 0
            retained_active = 0
            for record in records:
                if (
                    record.state is IdempotencyState.COMPLETED
                    and record.expires_at is not None
                    and record.expires_at <= at
                ):
                    del self._records[record.operation_key]
                    removed += 1
                else:
                    retained_active += 1
            return IdempotencyGCReport(len(records), removed, retained_active, at)


def new_record(
    *,
    operation_key: str,
    action_fingerprint: str,
    tenant: str,
    principal_id: str,
    tool_name: str,
    resource_ids: tuple[str, ...],
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> IdempotencyRecord:
    """Build a normalized record for a live action."""
    if not operation_key.strip() or not action_fingerprint.strip():
        raise ValueError("operation and action fingerprint are required")
    created_at = now or datetime.now(UTC)
    return IdempotencyRecord(
        operation_key=operation_key,
        action_fingerprint=action_fingerprint,
        tenant=tenant,
        principal_id=principal_id,
        tool_name=tool_name,
        resource_ids=resource_ids,
        state=IdempotencyState.IN_PROGRESS,
        created_at=created_at,
        expires_at=(None if ttl_seconds is None else created_at + timedelta(seconds=ttl_seconds)),
    )


__all__ = [
    "IdempotencyClaim",
    "IdempotencyClaimStatus",
    "IdempotencyGCReport",
    "IdempotencyRecord",
    "IdempotencyState",
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "new_record",
]

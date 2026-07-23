"""Redaction-aware structured audit events."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Protocol

_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_SECRET_KEYS = {"password", "secret", "token", "api_key", "authorization"}


def redact(value: Any) -> Any:
    """Return a JSON-shaped copy with common secrets and email addresses masked."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _SECRET_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _EMAIL.sub("[EMAIL]", value)
    return value


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Tamper-evident event describing one runtime decision or execution."""

    event_type: str
    request_id: str
    payload: dict[str, Any]
    timestamp: str
    previous_hash: str
    event_hash: str


class AuditSink(Protocol):
    """Destination for already-redacted audit events."""

    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> AuditEvent:
        """Append and return an immutable audit event."""


class InMemoryAuditSink:
    """Thread-safe hash-chain sink for tests and local development."""

    def __init__(self, now: Callable[[], datetime] | None = None) -> None:
        """Create an empty audit chain with an injectable clock."""
        self._now = now or (lambda: datetime.now(UTC))
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> AuditEvent:
        """Redact, hash, and append one event atomically."""
        with self._lock:
            safe_payload = redact(payload)
            previous_hash = self._events[-1].event_hash if self._events else "0" * 64
            timestamp = self._now().isoformat()
            canonical = json.dumps(
                [event_type, request_id, safe_payload, timestamp, previous_hash],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            event_hash = hashlib.sha256(canonical).hexdigest()
            event = AuditEvent(
                event_type, request_id, safe_payload, timestamp, previous_hash, event_hash
            )
            self._events.append(event)
            return event

    def events(self) -> tuple[AuditEvent, ...]:
        """Return a snapshot of the event chain."""
        with self._lock:
            return tuple(self._events)

    def verify(self) -> bool:
        """Verify the hash chain and return ``False`` if any event was altered."""
        previous_hash = "0" * 64
        for event in self.events():
            canonical = json.dumps(
                [event.event_type, event.request_id, event.payload, event.timestamp, previous_hash],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            if (
                event.previous_hash != previous_hash
                or hashlib.sha256(canonical).hexdigest() != event.event_hash
            ):
                return False
            previous_hash = event.event_hash
        return True

"""Redaction-aware structured audit events."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Protocol

_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
)
_SECRET_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "cookie",
    "session",
    "bearer_token",
    "authorization",
    "authorization_header",
}


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Tamper-evident event describing one runtime decision or execution."""

    event_type: str
    request_id: str
    payload: dict[str, Any]
    timestamp: str
    previous_hash: str
    event_hash: str


class Redactor(Protocol):
    """Provider-neutral contract for redacting data before persistence."""

    def __call__(self, value: Any) -> Any:
        """Return a safe JSON-shaped representation of ``value``."""


def _redact_string(value: str) -> str:
    """Mask common secret formats even when they occur under innocuous keys."""
    value = _EMAIL.sub("[EMAIL]", value)
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def redact(value: Any) -> Any:
    """Return a JSON-shaped copy with key and content secret detection."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _SECRET_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"[UNSERIALIZABLE:{type(value).__name__}]"


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

"""Optional observability adapters for guarded audit events.

The core runtime depends only on the small :class:`AuditSink` protocol. This
module provides a provider-neutral fan-out sink and an OpenTelemetry adapter
without making OpenTelemetry a mandatory runtime dependency.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from contextlib import AbstractContextManager
from typing import Any, Protocol

from .audit import AuditEvent, AuditSink, redact


class Span(Protocol):
    """Minimal span surface required by the OpenTelemetry adapter."""

    def __enter__(self) -> Span:
        """Enter the span context."""

    def __exit__(self, *args: Any) -> None:
        """Exit the span context."""


class Tracer(Protocol):
    """Minimal tracer surface compatible with OpenTelemetry tracers."""

    def start_as_current_span(
        self, name: str, attributes: dict[str, str]
    ) -> AbstractContextManager[Span]:
        """Create a span around one audit event."""


class CompositeAuditSink:
    """Append to a primary sink and zero or more secondary exporters.

    The primary sink is authoritative. Secondary exporter failures are
    isolated by default because an observability outage must not turn an
    already-recorded audit event into a second side effect.
    """

    def __init__(self, primary: AuditSink, secondary: Sequence[AuditSink] = ()) -> None:
        """Create a fan-out sink with one authoritative primary sink."""
        self.primary = primary
        self.secondary = tuple(secondary)
        self.export_errors: list[str] = []

    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> AuditEvent:
        """Append to the primary sink, then best-effort export to secondary sinks."""
        safe_payload = redact(payload)
        event = self.primary.append(event_type, request_id, safe_payload)
        for sink in self.secondary:
            try:
                sink.append(event_type, request_id, safe_payload)
            except Exception as exc:  # pragma: no cover - adapter-specific failure
                self.export_errors.append(type(exc).__name__)
        return event


class OpenTelemetryAuditSink:
    """Export redacted audit events as OpenTelemetry spans.

    Install ``opentelemetry-api`` in the application and pass its tracer to
    this adapter. The wrapped sink remains the authoritative audit store;
    payload content is already redacted by the SDK audit implementation before
    it is serialized into span attributes.
    """

    def __init__(self, tracer: Tracer, wrapped: AuditSink) -> None:
        """Create an exporter around an existing authoritative audit sink."""
        self.tracer = tracer
        self.wrapped = wrapped

    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> AuditEvent:
        """Persist an event and emit one observability span for it."""
        event = self.wrapped.append(event_type, request_id, redact(payload))
        attributes = {
            "agentic_security.event_type": event.event_type,
            "agentic_security.request_id": event.request_id,
            "agentic_security.event_hash": event.event_hash,
            "agentic_security.payload": json.dumps(event.payload, sort_keys=True),
        }
        with self.tracer.start_as_current_span("agentic_security.audit", attributes=attributes):
            pass
        return event

from __future__ import annotations

from typing import Any

from agentic_security.audit import InMemoryAuditSink
from agentic_security.telemetry import CompositeAuditSink, OpenTelemetryAuditSink


class FakeSpan:
    def __enter__(self) -> FakeSpan:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class FakeTracer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    def start_as_current_span(self, name: str, attributes: dict[str, str]) -> FakeSpan:
        self.calls.append((name, attributes))
        return FakeSpan()


class FailingSink:
    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> Any:
        raise RuntimeError("synthetic exporter failure")


def test_opentelemetry_adapter_exports_redacted_event() -> None:
    tracer = FakeTracer()
    primary = InMemoryAuditSink()
    sink = OpenTelemetryAuditSink(tracer, primary)

    event = sink.append("action_denied", "request:1", {"token": "secret"})

    assert event.payload == {"token": "[REDACTED]"}
    assert tracer.calls[0][0] == "agentic_security.audit"
    assert "secret" not in tracer.calls[0][1]["agentic_security.payload"]
    assert primary.verify()


def test_composite_sink_keeps_primary_event_when_exporter_fails() -> None:
    primary = InMemoryAuditSink()
    sink = CompositeAuditSink(primary, [FailingSink()])

    event = sink.append("action_executed", "request:2", {"message": "ok"})

    assert event.event_type == "action_executed"
    assert primary.verify()
    assert sink.export_errors == ["RuntimeError"]

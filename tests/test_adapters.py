from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from math import inf, nan
from pathlib import Path

import pytest

from agentic_security import (
    ApprovalOutcome,
    HttpApprovalProvider,
    HttpCedarPolicyEngine,
    HttpOpaPolicyEngine,
    JsonlAuditSink,
    Principal,
    ProviderToken,
    SubprocessToolHandler,
    TokenCredentialBroker,
)
from agentic_security.http import JsonHttpClient
from agentic_security.policies import PolicyDecision
from agentic_security.tools import ToolDefinition
from agentic_security.types import ExecutionContext, Resource


def context() -> ExecutionContext:
    return ExecutionContext(
        "agent:adapter",
        Principal("user:adapter", tenant="tenant:test"),
        "task:adapter",
        "adapter test",
        tenant="tenant:test",
    )


def tool() -> ToolDefinition:
    return ToolDefinition("read", lambda *_: None, lambda value: value, description="Read data.")


def test_http_policy_and_approval_adapters_use_authenticated_transport() -> None:
    calls: list[dict[str, object]] = []

    class FakeClient:
        def __init__(self, cedar: bool = False) -> None:
            self.cedar = cedar

        def post(self, payload: dict[str, object]) -> dict[str, object]:
            calls.append(payload)
            if "approval_id" in payload:
                return {"approved": True}
            if self.cedar:
                return {"decision": "Allow", "version": "policy-1"}
            return {"result": {"decision": "Allow", "version": "policy-1"}}

    client = FakeClient()
    cedar_client = FakeClient(cedar=True)
    opa = HttpOpaPolicyEngine(client)  # type: ignore[arg-type]
    cedar = HttpCedarPolicyEngine(cedar_client)  # type: ignore[arg-type]
    approval = HttpApprovalProvider(client)  # type: ignore[arg-type]
    resources = (Resource("record:1", "record", "tenant:test"),)

    assert (
        opa.decide(context(), tool(), {"id": "record:1"}, resources).decision
        is PolicyDecision.ALLOW
    )
    assert (
        cedar.decide(context(), tool(), {"id": "record:1"}, resources).decision
        is PolicyDecision.ALLOW
    )
    assert approval.consume("approval:1", context(), "read", "proposal:1", "hash")
    assert calls[-1]["action_hash"] == "hash"


@pytest.mark.parametrize(
    ("response", "outcome", "reason"),
    [
        ({"approved": True}, ApprovalOutcome.CONSUMED, "approval service consumed grant"),
        ({"approved": False}, ApprovalOutcome.NOT_CONSUMED, "approval service rejected grant"),
        ({}, ApprovalOutcome.UNKNOWN, "approval service returned no decision"),
        ({"approved": "yes"}, ApprovalOutcome.UNKNOWN, "approval service returned no decision"),
    ],
)
def test_http_approval_adapter_has_typed_fail_closed_outcomes(
    response: dict[str, object], outcome: ApprovalOutcome, reason: str
) -> None:
    """Only explicit boolean service decisions can consume an approval."""

    class Client:
        def post(self, _payload: dict[str, object]) -> dict[str, object]:
            return response

    result = HttpApprovalProvider(Client()).consume(  # type: ignore[arg-type]
        "approval:typed", context(), "read", "proposal:typed", "hash:typed"
    )
    assert (result.outcome, result.reason) == (outcome, reason)


def test_http_client_requires_https_or_explicit_localhost_test_mode() -> None:
    with pytest.raises(ValueError):
        JsonHttpClient("http://example.invalid/policy")
    with pytest.raises(ValueError, match="finite and positive"):
        JsonHttpClient("https://policy.example.test", timeout_seconds=inf)
    with pytest.raises(ValueError, match="finite and positive"):
        JsonHttpClient("https://policy.example.test", timeout_seconds=nan)
    JsonHttpClient("http://127.0.0.1:8080/policy", allow_insecure_localhost=True)


def test_http_client_posts_json_and_rejects_invalid_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"ok": true}'

    monkeypatch.setattr("agentic_security.http.urlopen", lambda *_args, **_kwargs: Response())
    client = JsonHttpClient("https://policy.example.test/decide")
    assert client.post({"input": {"value": "safe"}}) == {"ok": True}

    class BadResponse(Response):
        def read(self) -> bytes:
            return b"[]"

    monkeypatch.setattr("agentic_security.http.urlopen", lambda *_args, **_kwargs: BadResponse())
    with pytest.raises(ValueError, match="JSON object"):
        client.post({"input": {}})


def test_jsonl_audit_sink_is_durable_redacted_and_restartable(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = JsonlAuditSink(path)
    event = first.append("action_denied", "request:1", {"access_token": "synthetic"})
    second = JsonlAuditSink(path)
    next_event = second.append("action_denied", "request:2", {"value": "safe"})

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["payload"]["access_token"] == "[REDACTED]"  # noqa: S105
    assert next_event.previous_hash == event.event_hash
    assert second.verify()
    path.write_text(path.read_text() + "not-json\n")
    with pytest.raises(json.JSONDecodeError):
        JsonlAuditSink(path)


def test_jsonl_audit_sink_fails_closed_when_full(tmp_path: Path) -> None:
    path = tmp_path / "limited.jsonl"
    sink = JsonlAuditSink(path, max_bytes=1)
    with pytest.raises(RuntimeError, match="full"):
        sink.append("action_denied", "request:full", {"value": "safe"})


def test_jsonl_audit_sink_refuses_to_extend_a_corrupt_chain(tmp_path: Path) -> None:
    """Appending cannot hide tampering that occurred before the chain head."""
    path = tmp_path / "corrupt.jsonl"
    sink = JsonlAuditSink(path)
    sink.append("action_denied", "request:1", {"value": "safe"})
    sink.append("action_denied", "request:2", {"value": "safe"})
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["payload"]["value"] = "tampered"
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash chain is corrupt"):
        JsonlAuditSink(path)


def test_jsonl_audit_verification_rejects_each_hash_chain_link_failure(tmp_path: Path) -> None:
    path = tmp_path / "hash-links.jsonl"
    sink = JsonlAuditSink(path)
    sink.append("event", "request:1", {"value": "safe"})
    sink.append("event", "request:2", {"value": "safe"})
    lines = [json.loads(line) for line in path.read_text().splitlines()]

    for index, field, value in (
        (0, "previous_hash", "f" * 64),
        (1, "event_hash", "not-a-hash"),
    ):
        altered = [dict(line) for line in lines]
        altered[index][field] = value
        path.write_text("\n".join(json.dumps(line, sort_keys=True) for line in altered) + "\n")
        with pytest.raises(ValueError, match="hash chain is corrupt"):
            JsonlAuditSink(path)


def test_jsonl_audit_restart_reads_empty_and_utf8_chain_heads(tmp_path: Path) -> None:
    """The restart path must distinguish an empty file from a non-empty chain."""
    path = tmp_path / "restart.jsonl"
    path.write_text("", encoding="utf-8")
    empty = JsonlAuditSink(path)
    first = empty.append("event", "request:empty", {"value": "safe"})

    restarted = JsonlAuditSink(path)
    second = restarted.append("event", "request:utf8", {"value": "café"})
    assert second.previous_hash == first.event_hash
    assert restarted.verify()


def test_jsonl_audit_sink_refreshes_chain_head_under_lock(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.jsonl"
    first = JsonlAuditSink(path)
    second = JsonlAuditSink(path)
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(
            executor.map(
                lambda item: item[0].append("event", item[1], {"value": item[1]}),
                ((first, "request:1"), (second, "request:2")),
            )
        )
    assert first.verify()
    assert second.verify()


def test_token_credential_broker_keeps_material_out_of_credential_attributes() -> None:
    broker = TokenCredentialBroker(
        lambda *_: ProviderToken(
            "synthetic-token",
            "read",
            (Resource("record:1", "record", "tenant:test"),),
            datetime.now(UTC) + timedelta(seconds=30),
        )
    )
    credential = broker.mint(
        context(), tool(), (Resource("record:1", "record", "tenant:test"),), 30
    )

    assert not hasattr(credential, "_secret")
    with pytest.raises(ValueError, match="must not return"):
        credential.with_secret(lambda value: value)


def test_token_credential_broker_rejects_provider_scope_mismatch() -> None:
    broker = TokenCredentialBroker(
        lambda *_: ProviderToken(
            "synthetic-token",
            "other",
            (Resource("record:1", "record", "tenant:test"),),
            datetime.now(UTC) + timedelta(seconds=30),
        )
    )
    with pytest.raises(ValueError, match="invalid scope"):
        broker.mint(context(), tool(), (Resource("record:1", "record", "tenant:test"),), 30)


def test_provider_token_rejects_empty_or_expired_attestation() -> None:
    with pytest.raises(ValueError, match="value and scope"):
        ProviderToken(
            "",
            "read",
            (Resource("record:1", "record", "tenant:test"),),
            datetime.now(UTC) + timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match="expired"):
        ProviderToken(
            "token",
            "read",
            (Resource("record:1", "record", "tenant:test"),),
            datetime.now(UTC) - timedelta(seconds=1),
        )


def test_subprocess_handler_uses_json_boundary_and_no_shell() -> None:
    command = (
        sys.executable,
        "-c",
        "import json,sys; value=json.load(sys.stdin); "
        "print(json.dumps({'tenant': value['tenant'], 'ok': True}))",
    )
    handler = SubprocessToolHandler(command)

    result = handler(context(), {"value": "safe"})

    assert result == {"tenant": "tenant:test", "ok": True}


def test_subprocess_handler_rejects_failure_and_oversized_output() -> None:
    failing = SubprocessToolHandler((sys.executable, "-c", "raise SystemExit(2)"))
    with pytest.raises(RuntimeError, match="worker failed"):
        failing(context(), {})

    oversized = SubprocessToolHandler((sys.executable, "-c", "print('x' * 20)"), max_output_bytes=5)
    with pytest.raises(ValueError, match="output exceeds"):
        oversized(context(), {})

    with pytest.raises(ValueError, match="finite and positive"):
        SubprocessToolHandler((sys.executable, "-c", "pass"), timeout_seconds=inf)
    with pytest.raises(ValueError, match="finite and positive"):
        SubprocessToolHandler((sys.executable, "-c", "pass"), timeout_seconds=nan)
    with pytest.raises(ValueError, match="non-empty"):
        SubprocessToolHandler(())
    with pytest.raises(ValueError, match="positive"):
        SubprocessToolHandler((sys.executable, "-c", "pass"), max_output_bytes=0)


def test_subprocess_handler_bounds_large_input_to_worker_that_does_not_read() -> None:
    handler = SubprocessToolHandler(
        (sys.executable, "-c", "import time; time.sleep(1)"), timeout_seconds=0.05
    )
    with pytest.raises(TimeoutError, match="timed out"):
        handler(context(), {"value": "x" * 2_000_000})

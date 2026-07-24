from __future__ import annotations

import json
import sys
from math import inf, nan
from pathlib import Path

import pytest

from agentic_security import (
    HttpApprovalProvider,
    HttpCedarPolicyEngine,
    HttpOpaPolicyEngine,
    JsonlAuditSink,
    Principal,
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


def test_token_credential_broker_keeps_material_out_of_credential_attributes() -> None:
    broker = TokenCredentialBroker(lambda *_: "synthetic-token")
    credential = broker.mint(
        context(), tool(), (Resource("record:1", "record", "tenant:test"),), 30
    )

    assert not hasattr(credential, "_secret")
    assert credential.with_secret(lambda value: value) == "synthetic-token"


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

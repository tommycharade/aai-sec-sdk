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
    DockerSandboxToolHandler,
    HttpApprovalProvider,
    HttpCedarPolicyEngine,
    HttpOpaPolicyEngine,
    JsonlAuditSink,
    Principal,
    ProviderToken,
    SubprocessToolHandler,
    TokenCredentialBroker,
)
from agentic_security.audit import AuditEvent, AuditReplicationError, ReplicatedAuditSink
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


def test_jsonl_audit_scales_default_reserve_for_small_explicit_limits(tmp_path: Path) -> None:
    """A small pre-existing max_bytes value retains ordinary event capacity."""
    path = tmp_path / "small-audit.jsonl"
    sink = JsonlAuditSink(path, max_bytes=4_096)

    event = sink.append("decision", "request:small", {"decision": "deny"})

    assert sink.emergency_reserve_bytes == 2_048
    assert sink.normal_capacity_bytes == 2_048
    assert event.payload["decision"] == "deny"
    assert sink.verify()


def test_jsonl_audit_reserves_space_for_replication_failure_compensation(
    tmp_path: Path,
) -> None:
    """A provisional allow cannot consume its linked effective-denial capacity."""

    class BrokenExporter:
        def export(self, _event: AuditEvent) -> None:
            raise OSError("synthetic collector outage")

    path = tmp_path / "replication-outage.jsonl"
    primary = JsonlAuditSink(path, max_bytes=1_500, emergency_reserve_bytes=750)
    replicated = ReplicatedAuditSink(primary, BrokenExporter())
    with pytest.raises(AuditReplicationError) as failure:
        replicated.append("decision", "request:reserve", {"decision": "allow"})

    compensation = replicated.record_local_replication_failure(
        "effective_decision",
        "request:reserve",
        {"decision": "deny", "reason": "required replication failed"},
        failure.value.local_event,
    )

    assert path.stat().st_size > primary.normal_capacity_bytes
    assert compensation.payload["decision"] == "deny"
    assert compensation.payload["supersedes_event_hash"] == failure.value.local_event.event_hash
    assert primary.verify()


def test_jsonl_audit_rejects_a_provisional_event_too_large_for_compensation(
    tmp_path: Path,
) -> None:
    """An oversized provisional record cannot consume unserviceable authority."""
    path = tmp_path / "oversized-provisional.jsonl"
    sink = JsonlAuditSink(path, max_bytes=2_000, emergency_reserve_bytes=800)

    with pytest.raises(RuntimeError, match="bounded record size"):
        sink.append("decision", "request:oversized", {"value": "x" * 800})

    assert not path.exists() or path.stat().st_size == 0


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


def test_jsonl_audit_rejects_symlinked_file_directory_and_lock(tmp_path: Path) -> None:
    """Local evidence cannot be redirected into another same-user file."""
    target = tmp_path / "target.txt"
    target.write_text("unchanged", encoding="utf-8")

    linked_file = tmp_path / "audit.jsonl"
    linked_file.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        JsonlAuditSink(linked_file)

    real_directory = tmp_path / "real-audit"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked-audit"
    linked_directory.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="directory"):
        JsonlAuditSink(linked_directory / "audit.jsonl")

    safe_path = tmp_path / "safe-audit.jsonl"
    lock_path = safe_path.with_suffix(".jsonl.lock")
    lock_path.symlink_to(target)
    with pytest.raises(ValueError, match="lock"):
        JsonlAuditSink(safe_path)
    assert target.read_text(encoding="utf-8") == "unchanged"


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


def test_docker_sandbox_handler_constructs_restrictive_container_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    class FakeWorker:
        def __call__(self, _context: ExecutionContext, _arguments: object) -> dict[str, bool]:
            return {"ok": True}

    def fake_subprocess(command: tuple[str, ...], **_: object) -> FakeWorker:
        calls.append(command)
        return FakeWorker()

    import agentic_security.adapters as adapters

    monkeypatch.setattr(adapters, "which", lambda _name: "/usr/local/bin/docker")
    monkeypatch.setattr(adapters, "SubprocessToolHandler", fake_subprocess)
    result = DockerSandboxToolHandler(
        "registry.example.test/worker@sha256:" + "a" * 64, pids_limit=32
    )(context(), {"value": "safe"})
    assert result == {"ok": True}
    assert calls == [
        (
            "/usr/local/bin/docker",
            "run",
            "--interactive",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=65532:65532",
            "--memory=256m",
            "--pids-limit=32",
            "--cpus=1.000",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            "registry.example.test/worker@sha256:" + "a" * 64,
        )
    ]
    with pytest.raises(ValueError, match="image"):
        DockerSandboxToolHandler("image with spaces")
    with pytest.raises(ValueError, match="sha256"):
        DockerSandboxToolHandler("registry.example.test/worker:latest")
    with pytest.raises(ValueError, match="positive"):
        DockerSandboxToolHandler(
            "registry.example.test/worker@sha256:" + "a" * 64,
            timeout_seconds=float("inf"),
        )
    with pytest.raises(ValueError, match="positive m or g"):
        DockerSandboxToolHandler(
            "registry.example.test/worker@sha256:" + "a" * 64,
            memory_limit="256mb",
        )
    with pytest.raises(ValueError, match="safety bound"):
        DockerSandboxToolHandler(
            "registry.example.test/worker@sha256:" + "a" * 64,
            memory_limit="257g",
        )


def test_docker_sandbox_handler_fails_closed_when_runtime_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentic_security.adapters as adapters

    monkeypatch.setattr(adapters, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="Docker executable"):
        DockerSandboxToolHandler("image@sha256:" + "a" * 64)(context(), {})


def test_docker_sandbox_handler_accepts_immutable_local_image_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A content-addressed local build can be tested without a registry push."""
    calls: list[tuple[str, ...]] = []

    class FakeWorker:
        def __call__(self, _context: ExecutionContext, _arguments: object) -> dict[str, bool]:
            return {"ok": True}

    def fake_subprocess(command: tuple[str, ...], **_: object) -> FakeWorker:
        calls.append(command)
        return FakeWorker()

    import agentic_security.adapters as adapters

    monkeypatch.setattr(adapters, "which", lambda _name: "/usr/local/bin/docker")
    monkeypatch.setattr(adapters, "SubprocessToolHandler", fake_subprocess)
    image_id = "sha256:" + "b" * 64

    result = DockerSandboxToolHandler(image_id)(context(), {})

    assert result == {"ok": True}
    assert calls[0][-1] == image_id

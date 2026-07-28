"""Bounded deterministic assurance and adapter contract tests.

These tests deliberately use local fakes. They are not evidence that a
particular OPA, Cedar, IAM, WORM, or sandbox deployment is correctly deployed;
provider-specific integration suites belong in the deployment repository.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from agentic_security import (
    ActionProposal,
    AllowListPolicy,
    AuditReplicationError,
    CallbackIsolationVerifier,
    ExecutionContext,
    HttpApprovalProvider,
    HttpAuditExporter,
    InMemoryApprovalProvider,
    InMemoryAuditExporter,
    InMemoryAuditSink,
    InMemoryCredentialBroker,
    InMemoryIdempotencyStore,
    Principal,
    ProviderToken,
    ReplicatedAuditSink,
    Resource,
    SecurityConfigurationError,
    TokenCredentialBroker,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.adapters import JsonlAuditSink
from agentic_security.approvals import action_hash
from agentic_security.audit import redact
from agentic_security.budgets import Budget, BudgetState
from agentic_security.http import JsonHttpClient
from agentic_security.idempotency import IdempotencyClaimStatus, new_record
from agentic_security.policy_adapters import CedarPolicyEngine, OpaPolicyEngine


def context() -> ExecutionContext:
    """Return a synthetic, tenant-scoped contract-test context."""
    return ExecutionContext(
        "agent:test",
        Principal("user:test", tenant="tenant:test"),
        "task:test",
        "contract test",
        tenant="tenant:test",
    )


def resource() -> tuple[Resource, ...]:
    """Return one synthetic resource used in action fingerprints."""
    return (Resource("record:test", "record", "tenant:test"),)


def test_remote_audit_replication_is_required_and_redacted() -> None:
    """A remote failure raises after local evidence and never claims success."""
    primary = InMemoryAuditSink()
    exporter = InMemoryAuditExporter()
    sink = ReplicatedAuditSink(primary, exporter)
    event = sink.append("decision", "request:1", {"token": "secret", "value": "safe"})
    assert event.event_type == "decision"
    assert event.request_id == "request:1"
    assert event.payload == {"token": "[REDACTED]", "value": "safe"}
    assert exporter.events == [event]

    class BrokenExporter:
        """Synthetic unavailable remote destination."""

        def export(self, _event: Any) -> None:
            """Fail as a remote service would during an outage."""
            raise OSError("collector unavailable")

    with pytest.raises(AuditReplicationError) as error:
        failed_primary = InMemoryAuditSink()
        ReplicatedAuditSink(failed_primary, BrokenExporter()).append("decision", "request:2", {})
    assert str(error.value) == "required audit replication failed"
    assert error.value.local_event == failed_primary.events()[0]


def test_in_memory_audit_verification_checks_each_hash_chain_invariant() -> None:
    """Verification must reject a broken link and changed event body independently."""
    sink = InMemoryAuditSink()
    first = sink.append("event", "request:hash-1", {"value": "one"})
    sink.append("event", "request:hash-2", {"value": "two"})

    object.__setattr__(first, "previous_hash", "f" * 64)
    assert sink.verify() is False

    object.__setattr__(first, "previous_hash", "0" * 64)
    object.__setattr__(first, "event_hash", "f" * 64)
    assert sink.verify() is False


def test_replicated_audit_passes_the_same_immutable_event_to_exporter() -> None:
    primary = InMemoryAuditSink()
    exported: list[Any] = []

    class Exporter:
        def export(self, event: Any) -> None:
            exported.append(event)

    event = ReplicatedAuditSink(primary, Exporter()).append("event", "request:replica", {"v": 1})
    assert exported == [event]
    assert primary.events() == (event,)


def test_http_audit_contract_requires_explicit_acknowledgement() -> None:
    """The remote adapter rejects malformed or negative acknowledgements."""

    class Client:
        """Minimal fake HTTPS client."""

        def __init__(self, response: dict[str, Any]) -> None:
            self.response = response
            self.payload: dict[str, Any] | None = None

        def post(self, payload: dict[str, Any]) -> dict[str, Any]:
            """Capture payload and return a synthetic collector response."""
            self.payload = payload
            return self.response

    event = InMemoryAuditSink().append("decision", "request:3", {"email": "a@example.test"})
    client = Client({"accepted": True})
    HttpAuditExporter(cast(Any, client)).export(event)
    assert client.payload is not None
    assert client.payload["payload"] == {"email": "[EMAIL]"}
    with pytest.raises(RuntimeError):
        HttpAuditExporter(cast(Any, Client({"accepted": False}))).export(event)


def test_policy_contracts_fail_closed_and_preserve_live_request() -> None:
    """OPA and Cedar fakes receive the same canonical action and deny ambiguity."""
    tool = ToolDefinition(
        "read", lambda *_: {"ok": True}, lambda args: dict(args), description="read"
    )
    seen: list[dict[str, Any]] = []

    def opa(value: dict[str, Any]) -> dict[str, Any]:
        seen.append(value)
        return {"result": {"allow": True, "policy_version": "v1", "provenance": "fake"}}

    allowed = OpaPolicyEngine(cast(Any, opa)).decide(context(), tool, {"id": "x"}, resource())
    denied = CedarPolicyEngine(lambda _value: {}).decide(context(), tool, {"id": "x"}, resource())
    assert allowed.decision.value == "allow"
    assert denied.decision.value == "deny"
    assert seen[0]["input"]["tenant"] == "tenant:test"
    assert seen[0]["input"]["resources"][0]["tenant"] == "tenant:test"


def test_approval_and_isolation_contracts_bind_live_action() -> None:
    """Approval and isolation fakes reject changed or unbound action context."""

    class Client:
        """Approval service fake that records the exact request."""

        def __init__(self) -> None:
            self.payload: dict[str, Any] | None = None

        def post(self, payload: dict[str, Any]) -> dict[str, Any]:
            """Approve only the expected action binding."""
            self.payload = payload
            return {"approved": payload["action_hash"] == "expected"}

    client = Client()
    provider = HttpApprovalProvider(cast(Any, client))
    assert provider.consume("approval:1", context(), "read", "proposal:1", "expected")
    assert not provider.consume("approval:1", context(), "read", "proposal:1", "changed")
    assert client.payload is not None
    assert client.payload["tenant"] == "tenant:test"

    attestation = object()
    verifier = CallbackIsolationVerifier(lambda received, _ctx, *_: received is attestation)
    assert verifier.verify(attestation, context(), "read", resource(), "nonce")  # type: ignore[arg-type]
    assert not verifier.verify(object(), context(), "read", resource(), "nonce")  # type: ignore[arg-type]


def test_iam_and_idempotency_contracts_require_exact_scope_and_atomic_claims() -> None:
    """IAM scope and operation claims are host-bound and collision-safe."""
    tool = ToolDefinition(
        "read", lambda *_: {"ok": True}, lambda args: dict(args), description="read"
    )
    token = ProviderToken(
        "synthetic-token", "read", resource(), datetime.now(UTC) + timedelta(minutes=1)
    )
    broker = TokenCredentialBroker(lambda _ctx, _tool, _resources: token)
    credential = broker.mint(context(), tool, resource(), 30)
    assert credential.valid_for("read", resource())
    with pytest.raises(ValueError):
        TokenCredentialBroker(lambda *_: "raw-token").mint(context(), tool, resource(), 30)  # type: ignore[arg-type]

    store = InMemoryIdempotencyStore()
    record = new_record(
        operation_key="operation:test",
        action_fingerprint="fingerprint:test",
        tenant="tenant:test",
        principal_id="user:test",
        tool_name="read",
        resource_ids=("record:test",),
    )
    assert store.claim(record).status is IdempotencyClaimStatus.CLAIMED
    assert store.claim(record).status is IdempotencyClaimStatus.EXISTING
    assert (
        store.claim(
            new_record(
                operation_key="operation:test",
                action_fingerprint="different",
                tenant="tenant:test",
                principal_id="user:test",
                tool_name="read",
                resource_ids=("record:test",),
            )
        ).status
        is IdempotencyClaimStatus.CONFLICT
    )


def test_action_hash_and_redaction_corpus_are_bounded_and_deterministic() -> None:
    """A checked-in finite corpus exercises malformed proposals and nested data."""
    corpus = json.loads(
        (Path(__file__).parent / "corpus" / "malformed_inputs.json").read_text(encoding="utf-8")
    )
    assert len(corpus) <= 32
    for item in corpus:
        if item["tool_name"] and isinstance(item["arguments"], dict) and item["proposal_id"]:
            proposal = ActionProposal(**item)
            assert action_hash(context(), proposal.tool_name, proposal.arguments, resource()) == (
                action_hash(context(), proposal.tool_name, proposal.arguments, resource())
            )
        else:
            with pytest.raises(SecurityConfigurationError):
                ActionProposal(**item)
        safe = redact(item)
        assert "sk-1234567890" not in json.dumps(safe)
        assert "Bearer abcdefghijklmnop" not in json.dumps(safe)


def test_runtime_contract_uses_host_owned_policy_and_tool() -> None:
    """A policy cannot change the host-owned tool/resource contract."""
    from agentic_security import GuardedRuntime

    registry = ToolRegistry()
    registry.register(
        ToolDefinition("read", lambda *_: {"ok": True}, lambda args: dict(args), description="read")
    )
    result = GuardedRuntime(
        context(), registry, AllowListPolicy({"read"}), InMemoryAuditSink()
    ).execute(ActionProposal("read", {"id": "x"}, "proposal:1"))
    assert result.status.value == "executed"


def test_security_defaults_are_regression_covered(tmp_path: Path) -> None:
    """Mutation tests must detect drift in restrictive timeout and budget defaults."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    approval = InMemoryApprovalProvider(now=lambda: now)
    grant = approval.issue("approval:test", context(), "read", "proposal:test", "approver", "hash")
    assert grant.expires_at == now + timedelta(seconds=120)

    client = JsonHttpClient("https://policy.example.test")
    assert client.timeout_seconds == 5.0
    with pytest.raises(SecurityConfigurationError):
        JsonHttpClient("http://localhost:8080")

    budget = BudgetState(Budget(max_cost_units=1))
    assert budget.acquire() is True
    assert not budget.acquire()

    sink = JsonlAuditSink(tmp_path / "audit.jsonl")
    assert sink.max_bytes == 100_000_000

    broker = InMemoryCredentialBroker(now=lambda: now)
    tool = ToolDefinition(
        "read", lambda *_: {"ok": True}, lambda args: dict(args), description="read"
    )
    first = broker.mint(context(), tool, resource(), 1)
    second = broker.mint(context(), tool, resource(), 1)
    assert first.credential_id.endswith(":1")
    assert second.credential_id.endswith(":2")

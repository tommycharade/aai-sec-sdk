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
    InMemoryAuditExporter,
    InMemoryAuditSink,
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
from agentic_security.approvals import action_hash
from agentic_security.audit import redact
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
    assert event.payload == {"token": "[REDACTED]", "value": "safe"}
    assert exporter.events == [event]

    class BrokenExporter:
        """Synthetic unavailable remote destination."""

        def export(self, _event: Any) -> None:
            """Fail as a remote service would during an outage."""
            raise OSError("collector unavailable")

    with pytest.raises(AuditReplicationError):
        ReplicatedAuditSink(InMemoryAuditSink(), BrokenExporter()).append(
            "decision", "request:2", {}
        )


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

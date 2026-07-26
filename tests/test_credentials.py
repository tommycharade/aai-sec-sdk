from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from agentic_security import (
    ActionProposal,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    InMemoryCredentialBroker,
    Principal,
    Resource,
    ScopedCredential,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.policies import AllowListPolicy


def _context() -> ExecutionContext:
    return ExecutionContext(
        agent_id="agent:test",
        principal=Principal("user:alice", tenant="tenant:a"),
        task_id="task:credentials",
        purpose="credential test",
        tenant="tenant:a",
    )


def _validator(arguments: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(arguments.get("value"), str):
        raise ValueError("value must be a string")
    return dict(arguments)


def _runtime(
    *,
    broker: Any | None,
    handler: Any,
    resources: tuple[Resource, ...] = (Resource("record:1", "record", "tenant:a"),),
) -> tuple[GuardedRuntime, InMemoryAuditSink]:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="read_record",
            handler=handler,
            validator=_validator,
            resources=lambda _: resources,
            requires_credential=True,
            description="Read one synthetic record with a scoped credential.",
        )
    )
    audit = InMemoryAuditSink()
    return (
        GuardedRuntime(
            _context(),
            registry,
            AllowListPolicy({"read_record"}),
            audit,
            credentials=broker,
        ),
        audit,
    )


def test_runtime_mints_scoped_credential_only_after_authorization() -> None:
    seen: list[ScopedCredential] = []
    broker = InMemoryCredentialBroker()
    runtime, audit = _runtime(broker=broker, handler=lambda ctx, _: seen.append(ctx.credential))

    result = runtime.execute(ActionProposal("read_record", {"value": "safe"}, "proposal:1"))

    assert result.status == "executed"
    assert len(seen) == 1
    assert seen[0].valid_for("read_record", (Resource("record:1", "record", "tenant:a"),))
    assert "_secret" not in repr(seen[0])
    assert "secret" not in str(audit.events()).lower()
    assert broker.issued()[0].credential_id == seen[0].credential_id
    assert not hasattr(broker.issued()[0], "secret")


def test_missing_broker_fails_closed_without_handler() -> None:
    calls: list[bool] = []
    runtime, _ = _runtime(broker=None, handler=lambda *_: calls.append(True))

    result = runtime.execute(ActionProposal("read_record", {"value": "safe"}, "proposal:2"))

    assert result.status == "denied"
    assert result.reason == "credential broker is not configured"
    assert calls == []


def test_broker_is_not_called_when_policy_denies() -> None:
    class RecordingBroker(InMemoryCredentialBroker):
        def mint(self, *args: Any, **kwargs: Any) -> ScopedCredential:
            raise AssertionError("credential mint must follow policy")

    runtime, _ = _runtime(
        broker=RecordingBroker(),
        handler=lambda *_: None,
        resources=(Resource("record:other", "record", "tenant:other"),),
    )

    result = runtime.execute(ActionProposal("read_record", {"value": "safe"}, "proposal:3"))

    assert result.status == "denied"
    assert result.reason == "resource is outside the task tenant"


def test_invalid_broker_scope_is_denied_without_handler() -> None:
    class WrongScopeBroker(InMemoryCredentialBroker):
        def mint(
            self, context: ExecutionContext, tool: ToolDefinition, resources: Any, ttl_seconds: int
        ) -> ScopedCredential:
            now = datetime.now(UTC)
            return ScopedCredential(
                "wrong",
                "different_tool",
                (),
                now,
                now + timedelta(minutes=1),
                lambda: "synthetic",
            )

    calls: list[bool] = []
    runtime, _ = _runtime(broker=WrongScopeBroker(), handler=lambda *_: calls.append(True))

    result = runtime.execute(ActionProposal("read_record", {"value": "safe"}, "proposal:4"))

    assert result.status == "denied"
    assert result.reason == "credential scope is invalid"
    assert calls == []


def test_scoped_credential_expiry_is_enforced() -> None:
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    credential = ScopedCredential(
        "cred:test",
        "read_record",
        (),
        issued,
        issued + timedelta(seconds=10),
        lambda: "synthetic",
    )

    assert credential.valid_for("read_record", (), issued + timedelta(seconds=9))
    assert not credential.valid_for("read_record", (), issued + timedelta(seconds=10))


def test_credential_material_is_only_available_inside_live_callback() -> None:
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    credential = ScopedCredential(
        "cred:test",
        "read_record",
        (),
        issued,
        issued + timedelta(seconds=10),
        _secret_provider=lambda: "synthetic-token",  # noqa: S106 - synthetic test material
    )

    with pytest.raises(ValueError, match="must not return"):
        credential.with_secret(lambda value: value, issued)
    seen: list[str] = []
    credential.with_secret(lambda value: seen.append(value), issued)
    assert seen == ["synthetic-token"]
    assert not hasattr(credential, "_secret")
    assert not hasattr(credential, "_secret_provider")
    with pytest.raises(ValueError):
        credential.with_secret(lambda value: seen.append(value), issued + timedelta(seconds=10))


def test_credential_capabilities_are_identity_keyed() -> None:
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    first = ScopedCredential(
        "same-id", "read_record", (), issued, issued + timedelta(seconds=10), lambda: "first"
    )
    second = ScopedCredential(
        "same-id", "read_record", (), issued, issued + timedelta(seconds=10), lambda: "second"
    )
    seen: list[str] = []

    first.with_secret(lambda value: seen.append(value), issued)
    second.with_secret(lambda value: seen.append(value), issued)

    assert seen == ["first", "second"]


def test_credential_brokers_reject_invalid_ttl_and_token() -> None:
    broker = InMemoryCredentialBroker()
    with pytest.raises(ValueError, match=r"^credential TTL must be positive$"):
        broker.mint(
            _context(),
            ToolDefinition("read", lambda *_: None, _validator, description="Read."),
            (),
            0,
        )

    from agentic_security.credentials import TokenCredentialBroker

    token_broker = TokenCredentialBroker(lambda *_: cast(Any, ""))
    with pytest.raises(ValueError, match="scope attestation"):
        token_broker.mint(
            _context(),
            ToolDefinition("read", lambda *_: None, _validator, description="Read."),
            (),
            30,
        )

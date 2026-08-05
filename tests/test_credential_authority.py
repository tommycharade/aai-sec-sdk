"""Adversarial tests for incident-aware credential authority composition."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentic_security import (
    CredentialAuthorityDecision,
    CredentialAuthorityRequest,
    CredentialAuthorityState,
    ExecutionContext,
    Principal,
    Resource,
    RevocationAwareCredentialBroker,
    ScopedCredential,
    ToolDefinition,
)

RESOURCE = Resource("vault:synthetic", "vault", "tenant:a")


def _context() -> ExecutionContext:
    """Return fixed host-owned identity for one synthetic action."""
    return ExecutionContext(
        agent_id="agent:claude-01",
        principal=Principal("user:alice", tenant="tenant:a"),
        task_id="task:incident-authority",
        purpose="test incident credential revocation",
        tenant="tenant:a",
    )


def _tool() -> ToolDefinition:
    """Return one credential-requiring synthetic tool."""
    return ToolDefinition(
        name="read_metadata",
        description="Read synthetic metadata.",
        handler=lambda *_: None,
        validator=lambda value: value,
        resources=lambda _: (RESOURCE,),
        requires_credential=True,
    )


class RecordingBroker:
    """Issue one synthetic capability and retain trusted mint arguments."""

    def __init__(self) -> None:
        self.requests: list[tuple[ExecutionContext, ToolDefinition, tuple[Resource, ...], int]] = []
        self.provider_active = True

    def mint(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
    ) -> ScopedCredential:
        """Return a callback-protected synthetic credential."""
        self.requests.append((context, tool, resources, ttl_seconds))
        issued = datetime.now(UTC) - timedelta(seconds=1)
        return ScopedCredential(
            credential_id="grant:synthetic-1",
            tool_name=tool.name,
            resources=resources,
            issued_at=issued,
            expires_at=issued + timedelta(minutes=10),
            _secret_provider=lambda: "synthetic-provider-token",  # noqa: S106
            _validity_provider=lambda: self.provider_active,
        )


def test_wrapper_binds_host_facts_and_rechecks_incident_authority_before_use() -> None:
    """A later case revocation withholds an already-minted provider capability."""
    delegate = RecordingBroker()
    requests: list[CredentialAuthorityRequest] = []
    state = {"value": CredentialAuthorityState.ACTIVE}

    def authority(request: CredentialAuthorityRequest) -> CredentialAuthorityDecision:
        requests.append(request)
        if state["value"] is CredentialAuthorityState.REVOKED:
            return CredentialAuthorityDecision(
                state["value"], "incident_case_revoked", 3, "case:synthetic"
            )
        return CredentialAuthorityDecision(state["value"], "no_active_incident_control")

    broker = RevocationAwareCredentialBroker("azure-read", delegate, authority)
    context = _context()
    tool = _tool()
    credential = broker.mint(context, tool, (RESOURCE,), 300)

    assert delegate.requests == [(context, tool, (RESOURCE,), 300)]
    assert requests == [
        CredentialAuthorityRequest(
            broker_id="azure-read",
            tenant="tenant:a",
            agent_id="agent:claude-01",
            principal_id="user:alice",
            task_id="task:incident-authority",
            tool_name="read_metadata",
            resource_ids=("vault:synthetic",),
        ),
        CredentialAuthorityRequest(
            broker_id="azure-read",
            tenant="tenant:a",
            agent_id="agent:claude-01",
            principal_id="user:alice",
            task_id="task:incident-authority",
            tool_name="read_metadata",
            resource_ids=("vault:synthetic",),
            credential_id="grant:synthetic-1",
        ),
    ]
    captured: list[str] = []
    credential.with_secret(lambda value: captured.append(value))
    assert captured == ["synthetic-provider-token"]
    assert requests[-1] == CredentialAuthorityRequest(
        broker_id="azure-read",
        tenant="tenant:a",
        agent_id="agent:claude-01",
        principal_id="user:alice",
        task_id="task:incident-authority",
        tool_name="read_metadata",
        resource_ids=("vault:synthetic",),
        credential_id="grant:synthetic-1",
    )

    state["value"] = CredentialAuthorityState.REVOKED
    assert not credential.valid_for("read_metadata", (RESOURCE,))
    with pytest.raises(ValueError, match="expired, revoked"):
        credential.with_secret(lambda _: None)
    assert "synthetic-provider-token" not in repr(credential)


def test_revoked_or_unavailable_authority_prevents_provider_mint() -> None:
    """No provider token is requested when central authority is not explicitly active."""
    for checker in (
        lambda _: CredentialAuthorityDecision(
            CredentialAuthorityState.REVOKED, "incident_case_revoked", 1, "case:one"
        ),
        lambda _: CredentialAuthorityDecision(
            CredentialAuthorityState.UNAVAILABLE, "authority_unavailable"
        ),
    ):
        delegate = RecordingBroker()
        broker = RevocationAwareCredentialBroker("aws-read", delegate, checker)
        with pytest.raises(ValueError) as error:
            broker.mint(_context(), _tool(), (RESOURCE,), 300)
        assert str(error.value) == "credential authority is revoked or unavailable"
        assert delegate.requests == []


def test_authority_failure_and_malformed_result_fail_closed() -> None:
    """Timeouts and untyped responses never fall back to cached allow state."""

    def timeout(_: CredentialAuthorityRequest) -> CredentialAuthorityDecision:
        raise TimeoutError("synthetic control-plane outage")

    for checker, message in (
        (timeout, "credential authority is unavailable"),
        (lambda _: True, "credential authority returned an invalid decision"),
    ):
        delegate = RecordingBroker()
        broker = RevocationAwareCredentialBroker("gcp-read", delegate, checker)  # type: ignore[arg-type]
        with pytest.raises(ValueError) as error:
            broker.mint(_context(), _tool(), (RESOURCE,), 300)
        assert str(error.value) == message
        assert delegate.requests == []


def test_post_mint_revocation_never_exposes_new_provider_material() -> None:
    """A race after exchange returns no usable credential to the runtime."""
    delegate = RecordingBroker()
    calls = {"count": 0}

    def authority(_: CredentialAuthorityRequest) -> CredentialAuthorityDecision:
        calls["count"] += 1
        if calls["count"] == 1:
            return CredentialAuthorityDecision(
                CredentialAuthorityState.ACTIVE, "no_active_incident_control"
            )
        return CredentialAuthorityDecision(
            CredentialAuthorityState.REVOKED, "incident_case_revoked", 2, "case:race"
        )

    broker = RevocationAwareCredentialBroker("azure-read", delegate, authority)
    with pytest.raises(ValueError) as error:
        broker.mint(_context(), _tool(), (RESOURCE,), 300)
    assert str(error.value) == "credential authority is revoked or unavailable"
    assert len(delegate.requests) == 1


def test_delegate_must_return_a_scoped_capability() -> None:
    """Untyped provider output cannot cross the credential boundary."""

    class InvalidBroker:
        def mint(self, *_: object) -> object:
            return object()

    authority = lambda _: CredentialAuthorityDecision(  # noqa: E731
        CredentialAuthorityState.ACTIVE, "no_active_incident_control"
    )
    broker = RevocationAwareCredentialBroker(
        "invalid-provider",
        InvalidBroker(),  # type: ignore[arg-type]
        authority,
    )
    with pytest.raises(ValueError) as error:
        broker.mint(_context(), _tool(), (RESOURCE,), 300)
    assert str(error.value) == "credential broker returned no scoped capability"


def test_scoped_credential_restriction_can_only_remove_authority() -> None:
    """A restriction preserves identity/scope/lifetime and composes with provider revocation."""
    delegate = RecordingBroker()
    original = delegate.mint(_context(), _tool(), (RESOURCE,), 300)
    incident_active = {"value": True}
    restricted = original.restrict(lambda: incident_active["value"])

    assert (
        restricted.credential_id,
        restricted.tool_name,
        restricted.resources,
        restricted.issued_at,
        restricted.expires_at,
    ) == (
        original.credential_id,
        original.tool_name,
        original.resources,
        original.issued_at,
        original.expires_at,
    )
    assert restricted.valid_for("read_metadata", (RESOURCE,))
    incident_active["value"] = False
    assert not restricted.valid_for("read_metadata", (RESOURCE,))
    incident_active["value"] = True
    delegate.provider_active = False
    assert not restricted.valid_for("read_metadata", (RESOURCE,))


def test_authority_types_reject_ambiguous_evidence() -> None:
    """Incomplete bindings and revoked decisions without case evidence are invalid."""
    with pytest.raises(ValueError, match="binding fields"):
        CredentialAuthorityRequest("broker", "tenant", "", "principal", "task", "tool", ())
    with pytest.raises(ValueError, match="must not contain duplicates"):
        CredentialAuthorityRequest(
            "broker", "tenant", "agent", "principal", "task", "tool", ("r", "r")
        )
    with pytest.raises(ValueError, match="identifier must be non-empty"):
        CredentialAuthorityRequest(
            "broker", "tenant", "agent", "principal", "task", "tool", (), " "
        )
    with pytest.raises(ValueError, match="state is invalid"):
        CredentialAuthorityDecision("active", "active")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="reason code is invalid"):
        CredentialAuthorityDecision(CredentialAuthorityState.ACTIVE, "")
    with pytest.raises(ValueError, match="revision is invalid"):
        CredentialAuthorityDecision(CredentialAuthorityState.ACTIVE, "active", True)
    with pytest.raises(ValueError, match="requires case evidence"):
        CredentialAuthorityDecision(
            CredentialAuthorityState.REVOKED, "incident_case_revoked", 0, None
        )


def test_use_time_authority_outage_invalidates_existing_capability() -> None:
    """A checker outage after mint blocks provider material on its next use."""
    calls = {"count": 0}

    def authority(_: CredentialAuthorityRequest) -> CredentialAuthorityDecision:
        calls["count"] += 1
        if calls["count"] > 2:
            raise TimeoutError("synthetic use-time authority outage")
        return CredentialAuthorityDecision(
            CredentialAuthorityState.ACTIVE, "no_active_incident_control"
        )

    credential = RevocationAwareCredentialBroker("azure-read", RecordingBroker(), authority).mint(
        _context(), _tool(), (RESOURCE,), 300
    )

    assert not credential.valid_for("read_metadata", (RESOURCE,))
    with pytest.raises(ValueError, match="expired, revoked"):
        credential.with_secret(lambda _: None)


def test_wrapper_configuration_rejects_missing_authority() -> None:
    """A deployment cannot construct an incident-aware broker without all boundaries."""
    delegate = RecordingBroker()
    authority = lambda _: CredentialAuthorityDecision(  # noqa: E731
        CredentialAuthorityState.ACTIVE, "no_active_incident_control"
    )
    with pytest.raises(ValueError, match="broker id"):
        RevocationAwareCredentialBroker("", delegate, authority)
    with pytest.raises(TypeError, match="must provide mint"):
        RevocationAwareCredentialBroker("broker", object(), authority)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be callable"):
        RevocationAwareCredentialBroker("broker", delegate, None)  # type: ignore[arg-type]

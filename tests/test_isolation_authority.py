"""Adversarial tests for production isolation profile authority."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from agentic_security import (
    ActionProposal,
    AllowListPolicy,
    DockerSandboxToolHandler,
    ExecutionContext,
    ExecutionStatus,
    GuardedRuntime,
    InMemoryAuditSink,
    IsolationAttestation,
    IsolationBoundary,
    IsolationConstraints,
    IsolationCredentialMode,
    IsolationNetworkMode,
    IsolationProfile,
    IsolationRequirement,
    IsolationVerification,
    Principal,
    ProductionIsolationVerifier,
    Resource,
    RuntimeConfig,
    ToolDefinition,
    ToolRegistry,
    isolation_action_binding,
    isolation_attestation_payload,
)
from agentic_security.isolation import validate_attestation


def _context() -> ExecutionContext:
    return ExecutionContext(
        "agent:test",
        Principal("user:test", tenant="tenant:test"),
        "task:test",
        "compile untrusted source",
        tenant="tenant:test",
    )


def _resources() -> tuple[Resource, ...]:
    return (Resource("repo:test", "repository", "tenant:test"),)


def _constraints() -> IsolationConstraints:
    return IsolationConstraints(
        filesystem_read_only=True,
        network_mode=IsolationNetworkMode.NONE,
        allowed_network_destinations=(),
        process_namespace=True,
        max_memory_mib=256,
        max_pids=64,
        cpu_limit_millicores=1_000,
        max_duration_seconds=30,
        credential_mode=IsolationCredentialMode.NONE,
        no_new_privileges=True,
        capabilities_dropped=True,
    )


def _profile() -> IsolationProfile:
    return IsolationProfile(
        profile_id="profile:docker-restricted",
        provider="docker-engine",
        boundary=IsolationBoundary.CONTAINER,
        workload_ref="sha256:" + "a" * 64,
        revision=1,
        constraints=_constraints(),
    )


def _attestation(now: datetime, profile: IsolationProfile) -> IsolationAttestation:
    context = _context()
    nonce = "nonce:test"
    return IsolationAttestation(
        provider=profile.provider,
        workload_id="workload:test",
        profile=profile.profile_id,
        expires_at=now + timedelta(seconds=60),
        nonce=nonce,
        tool_name="compile",
        tenant=cast(str, context.tenant),
        capabilities={"filesystem": True, "network": True, "process": True},
        issued_at=now,
        evidence_id="evidence:test",
        profile_digest=profile.configuration_digest,
        workload_ref=profile.workload_ref,
        action_binding=isolation_action_binding(context, "compile", _resources(), nonce),
        signature="synthetic-signature",
        key_id="key:test",
    )


def _verifier(
    now: datetime,
    profile: IsolationProfile,
    *,
    signature_valid: bool = True,
    authority_live: bool = True,
) -> ProductionIsolationVerifier:
    requirement = IsolationRequirement(
        accepted_profile_digests=frozenset({profile.configuration_digest}),
        allowed_boundaries=frozenset({IsolationBoundary.CONTAINER}),
        max_evidence_age_seconds=60,
        max_evidence_ttl_seconds=120,
    )
    return ProductionIsolationVerifier(
        {profile.configuration_digest: profile},
        requirement,
        lambda _evidence: signature_valid,
        lambda _evidence_id, _profile_digest: authority_live,
        now=lambda: now,
    )


def test_production_verifier_preserves_immutable_boundary_identity() -> None:
    """A valid result retains only the identifiers needed for audit correlation."""
    now = datetime.now(UTC)
    profile = _profile()
    attestation = _attestation(now, profile)

    result = _verifier(now, profile).verify(
        attestation, _context(), "compile", _resources(), "nonce:test"
    )

    assert result.verified is True
    assert result.boundary is IsolationBoundary.CONTAINER
    assert result.profile_digest == profile.configuration_digest
    assert result.workload_ref == profile.workload_ref
    assert result.audit_fields() == {
        "boundary": "container",
        "evidence_id": "evidence:test",
        "expires_at": attestation.expires_at.isoformat(),
        "profile_digest": profile.configuration_digest,
        "provider": "docker-engine",
        "verified_at": now.isoformat(),
        "workload_ref": profile.workload_ref,
    }
    assert "signature" not in result.audit_fields()


def test_attestation_signing_payload_is_canonical_and_covers_authority_fields() -> None:
    """Issuer and verifier receive stable bytes covering every mutable claim."""
    now = datetime.now(UTC)
    profile = _profile()
    attestation = _attestation(now, profile)

    first = isolation_attestation_payload(attestation)

    assert first == isolation_attestation_payload(attestation)
    assert b'"signature"' not in first
    assert attestation.action_binding.encode() in first
    assert attestation.profile_digest.encode() in first
    assert (
        isolation_attestation_payload(replace(attestation, workload_id="workload:substituted"))
        != first
    )


def test_action_binding_and_signing_payload_match_the_wire_contract_exactly() -> None:
    """Cross-language adapters can rely on one byte-for-byte protocol fixture."""
    binding = isolation_action_binding(_context(), "compile", _resources(), "nonce:test")
    assert binding == "sha256:675f578f7b004dd69bba9d01d84db252fa36b4d74157d0ae84a81db323bd59d7"
    issued_at = datetime(2099, 1, 1, tzinfo=UTC)
    attestation = replace(_attestation(issued_at, _profile()), action_binding=binding)
    expected = (
        '{"actionBinding":"sha256:675f578f7b004dd69bba9d01d84db252fa36b4d74157d0ae84a81db323bd59d7",'
        '"capabilities":{"filesystem":true,"network":true,"process":true},'
        '"evidenceId":"evidence:test","expiresAt":"2099-01-01T00:01:00+00:00",'
        '"issuedAt":"2099-01-01T00:00:00+00:00","keyId":"key:test",'
        '"nonce":"nonce:test",'
        '"profileDigest":"sha256:c5054d1917f28b48a45591ee8d520f7c9269f6e8f1a450dcd3e8f6bdb39db3f9",'
        '"profileId":"profile:docker-restricted","provider":"docker-engine",'
        '"schemaVersion":1,"tenant":"tenant:test","toolName":"compile",'
        '"workloadId":"workload:test",'
        '"workloadRef":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    )
    assert isolation_attestation_payload(attestation).decode("utf-8") == expected


def test_attestation_signing_payload_rejects_legacy_evidence() -> None:
    """Unsigned compatibility evidence cannot enter a production signing flow."""
    now = datetime.now(UTC)
    legacy = IsolationAttestation(
        provider="legacy",
        workload_id="workload:legacy",
        profile="profile:legacy",
        expires_at=now + timedelta(seconds=30),
        nonce="nonce:legacy",
        tool_name="compile",
        tenant="tenant:test",
        capabilities={},
    )

    with pytest.raises(ValueError, match="complete production evidence"):
        isolation_attestation_payload(legacy)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("nonce", "nonce:changed", "isolation evidence action binding is invalid"),
        ("tool_name", "shell", "isolation evidence action binding is invalid"),
        ("tenant", "tenant:other", "isolation evidence action binding is invalid"),
        (
            "action_binding",
            "sha256:" + "b" * 64,
            "isolation evidence does not bind the live action",
        ),
        (
            "profile_digest",
            "sha256:" + "b" * 64,
            "isolation profile is not accepted by policy",
        ),
        (
            "workload_ref",
            "sha256:" + "b" * 64,
            "isolation evidence does not match the reviewed profile",
        ),
        (
            "provider",
            "untrusted-runtime",
            "isolation evidence does not match the reviewed profile",
        ),
        (
            "profile",
            "profile:weaker",
            "isolation evidence does not match the reviewed profile",
        ),
    ],
)
def test_production_verifier_rejects_every_live_binding_mismatch(
    field: str, value: str, reason: str
) -> None:
    """Changing any action or immutable profile identity fails closed."""
    now = datetime.now(UTC)
    profile = _profile()
    result = _verifier(now, profile).verify(
        replace(_attestation(now, profile), **cast(Any, {field: value})),
        _context(),
        "compile",
        _resources(),
        "nonce:test",
    )
    assert result.verified is False
    assert result.reason == reason


def test_production_verifier_rejects_stale_future_long_lived_and_expired_evidence() -> None:
    """Clock manipulation cannot turn stale or over-broad evidence into authority."""
    now = datetime.now(UTC)
    profile = _profile()
    verifier = _verifier(now, profile)
    fresh = _attestation(now, profile)

    stale = replace(
        fresh,
        issued_at=now - timedelta(seconds=61),
        expires_at=now + timedelta(seconds=1),
    )
    future = replace(fresh, issued_at=now + timedelta(seconds=1))
    too_long = replace(fresh, expires_at=now + timedelta(seconds=121))
    assert verifier.verify(stale, _context(), "compile", _resources(), "nonce:test").reason == (
        "isolation evidence is stale"
    )
    assert verifier.verify(future, _context(), "compile", _resources(), "nonce:test").reason == (
        "isolation evidence was issued in the future"
    )
    assert verifier.verify(too_long, _context(), "compile", _resources(), "nonce:test").reason == (
        "isolation evidence lifetime is too long"
    )
    with pytest.raises(ValueError, match="expired"):
        replace(fresh, expires_at=now - timedelta(seconds=1))

    boundary_age = replace(
        fresh,
        issued_at=now - timedelta(seconds=60),
        expires_at=now + timedelta(seconds=60),
    )
    boundary_ttl = replace(fresh, expires_at=now + timedelta(seconds=120))
    assert verifier.verify(boundary_age, _context(), "compile", _resources(), "nonce:test").verified
    assert verifier.verify(boundary_ttl, _context(), "compile", _resources(), "nonce:test").verified


def test_validation_uses_the_verifier_clock_and_expiry_is_exclusive() -> None:
    """Injected deployment time controls expiry, and equality is already expired."""
    issued_at = datetime.now(UTC)
    evidence = _attestation(issued_at, _profile())
    assert not validate_attestation(
        evidence,
        _context(),
        "compile",
        _resources(),
        "nonce:test",
        now=evidence.expires_at,
    )
    result = _verifier(evidence.expires_at, _profile()).verify(
        evidence, _context(), "compile", _resources(), "nonce:test"
    )
    assert result.reason == "isolation evidence action binding is invalid"


def test_production_verifier_rejects_signature_revocation_and_dependency_outage() -> None:
    """Forgery, revoked authority, and verifier outages all deny execution."""
    now = datetime.now(UTC)
    profile = _profile()
    attestation = _attestation(now, profile)
    assert (
        _verifier(now, profile, signature_valid=False)
        .verify(attestation, _context(), "compile", _resources(), "nonce:test")
        .reason
        == "isolation evidence signature is invalid"
    )
    assert (
        _verifier(now, profile, authority_live=False)
        .verify(attestation, _context(), "compile", _resources(), "nonce:test")
        .reason
        == "isolation evidence or profile is revoked"
    )

    def signature_verifier(received: IsolationAttestation) -> bool:
        assert received is attestation
        return True

    def revocation_checker(evidence_id: str, profile_digest: str) -> bool:
        assert (evidence_id, profile_digest) == (
            attestation.evidence_id,
            attestation.profile_digest,
        )
        return True

    exact_verifier = ProductionIsolationVerifier(
        {profile.configuration_digest: profile},
        IsolationRequirement(
            frozenset({profile.configuration_digest}), frozenset({IsolationBoundary.CONTAINER})
        ),
        signature_verifier,
        revocation_checker,
        now=lambda: now,
    )
    assert (
        exact_verifier.verify(attestation, _context(), "compile", _resources(), "nonce:test").reason
        == "signed isolation evidence matches the live reviewed profile"
    )

    verifier = ProductionIsolationVerifier(
        {profile.configuration_digest: profile},
        IsolationRequirement(
            frozenset({profile.configuration_digest}), frozenset({IsolationBoundary.CONTAINER})
        ),
        lambda _evidence: (_ for _ in ()).throw(RuntimeError("provider unavailable")),
        lambda *_: True,
        now=lambda: now,
    )
    assert (
        verifier.verify(attestation, _context(), "compile", _resources(), "nonce:test").reason
        == "isolation authority verification failed"
    )


def test_profiles_reject_mutable_workloads_and_ambiguous_network_or_limits() -> None:
    """A profile cannot hide mutable code, open networking, or unbounded resources."""
    with pytest.raises(ValueError, match="immutable"):
        replace(_profile(), workload_ref="worker:latest")
    with pytest.raises(ValueError, match="cannot declare"):
        replace(_constraints(), allowed_network_destinations=("api.example.test:443",))
    with pytest.raises(ValueError, match="requires at least"):
        replace(_constraints(), network_mode=IsolationNetworkMode.ALLOWLIST)
    with pytest.raises(ValueError, match="positive"):
        replace(_constraints(), max_pids=0)
    with pytest.raises(ValueError, match="safety bounds"):
        replace(_constraints(), max_memory_mib=262_145)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"network_mode": "none"}, "closed enum"),
        ({"allowed_network_destinations": ["api.example.test:443"]}, "unique bounded"),
        ({"allowed_network_destinations": ("",)}, "unique bounded"),
        (
            {"allowed_network_destinations": ("api.example.test:443",) * 2},
            "unique bounded",
        ),
        ({"cpu_limit_millicores": True}, "positive integers"),
        ({"max_duration_seconds": 86_401}, "safety bounds"),
    ],
)
def test_constraints_reject_malformed_closed_schema(
    changes: dict[str, object], message: str
) -> None:
    """Wrong types, duplicate destinations, and excessive limits fail closed."""
    with pytest.raises(ValueError, match=message):
        replace(_constraints(), **cast(Any, changes))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"profile_id": ""}, "identity fields"),
        ({"boundary": "container"}, "unsupported"),
        ({"revision": 0}, "positive integer"),
    ],
)
def test_profile_rejects_malformed_identity(changes: dict[str, object], message: str) -> None:
    """Profiles require typed immutable identity and a positive revision."""
    with pytest.raises(ValueError, match=message):
        replace(_profile(), **cast(Any, changes))


def test_attestation_rejects_malformed_provider_evidence() -> None:
    """Malformed identity, capability, time, and digest claims never reach verification."""
    now = datetime.now(UTC)
    profile = _profile()
    valid = _attestation(now, profile)
    with pytest.raises(ValueError, match="identity fields"):
        replace(valid, evidence_id="", provider="")
    with pytest.raises(ValueError, match="map names to booleans"):
        replace(valid, capabilities={"filesystem": "yes"})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="issued time"):
        replace(valid, issued_at=now.replace(tzinfo=None))
    with pytest.raises(ValueError, match="expire before"):
        replace(valid, issued_at=valid.expires_at + timedelta(seconds=1))
    with pytest.raises(ValueError, match="incomplete"):
        replace(valid, signature="")
    with pytest.raises(ValueError, match="digests"):
        replace(valid, profile_digest="sha256:not-a-digest")


def test_verifier_rejects_untrusted_profile_boundary_and_forged_incomplete_evidence() -> None:
    """Every defensive verifier branch denies even objects altered after construction."""
    now = datetime.now(UTC)
    profile = _profile()
    evidence = _attestation(now, profile)
    other = replace(profile, profile_id="profile:other")
    accepted = IsolationRequirement(
        frozenset({profile.configuration_digest}), frozenset({IsolationBoundary.CONTAINER})
    )
    verifier = ProductionIsolationVerifier(
        {other.configuration_digest: other},
        accepted,
        lambda _: True,
        lambda *_: True,
        now=lambda: now,
    )
    assert (
        verifier.verify(evidence, _context(), "compile", _resources(), "nonce:test").reason
        == "isolation profile is not trusted by this deployment"
    )

    boundary_verifier = ProductionIsolationVerifier(
        {profile.configuration_digest: profile},
        IsolationRequirement(
            frozenset({profile.configuration_digest}), frozenset({IsolationBoundary.MICROVM})
        ),
        lambda _: True,
        lambda *_: True,
        now=lambda: now,
    )
    assert (
        boundary_verifier.verify(evidence, _context(), "compile", _resources(), "nonce:test").reason
        == "isolation boundary is not accepted by policy"
    )

    for field in (
        "evidence_id",
        "profile_digest",
        "workload_ref",
        "action_binding",
        "signature",
        "key_id",
    ):
        incomplete = _attestation(now, profile)
        object.__setattr__(incomplete, field, "")
        assert (
            _verifier(now, profile)
            .verify(incomplete, _context(), "compile", _resources(), "nonce:test")
            .reason
            == "production isolation evidence is incomplete"
        )


def test_verifier_configuration_and_empty_audit_result_fail_closed() -> None:
    """A verifier cannot start without exact map keys, and denied evidence audits nothing."""
    profile = _profile()
    requirement = IsolationRequirement(
        frozenset({profile.configuration_digest}), frozenset({IsolationBoundary.CONTAINER})
    )
    with pytest.raises(ValueError) as empty_error:
        ProductionIsolationVerifier({}, requirement, lambda _: True, lambda *_: True)
    assert str(empty_error.value) == "production isolation requires trusted profiles"
    with pytest.raises(ValueError) as key_error:
        ProductionIsolationVerifier(
            {"sha256:" + "b" * 64: profile}, requirement, lambda _: True, lambda *_: True
        )
    assert str(key_error.value) == "isolation profile map keys must match configuration digests"
    assert IsolationVerification(False, "denied").audit_fields() == {}


def test_requirement_rejects_unknown_profiles_and_open_ended_boundaries() -> None:
    """Policy must select reviewed profiles rather than accept arbitrary sandboxes."""
    with pytest.raises(ValueError, match="reviewed profile"):
        IsolationRequirement(frozenset(), frozenset({IsolationBoundary.CONTAINER}))
    with pytest.raises(ValueError, match="boundary"):
        IsolationRequirement(frozenset({"sha256:" + "a" * 64}), frozenset())
    with pytest.raises(ValueError, match="lifetime"):
        IsolationRequirement(
            frozenset({"sha256:" + "a" * 64}),
            frozenset({IsolationBoundary.CONTAINER}),
            max_evidence_age_seconds=301,
        )


def test_docker_handler_binds_attestation_provider_to_exact_launch_profile() -> None:
    """The live adapter cannot attest one profile and launch different controls."""
    now = datetime.now(UTC)
    profile = replace(
        _profile(),
        constraints=replace(
            _constraints(),
            max_duration_seconds=10,
        ),
    )
    calls: list[tuple[str, str]] = []

    def issue(
        received: IsolationProfile,
        context: ExecutionContext,
        tool_name: str,
        resources: tuple[Resource, ...],
        nonce: str,
    ) -> IsolationAttestation:
        calls.append((received.configuration_digest, nonce))
        return replace(
            _attestation(now, received),
            tool_name=tool_name,
            tenant=cast(str, context.tenant),
            nonce=nonce,
            action_binding=isolation_action_binding(context, tool_name, resources, nonce),
        )

    handler = DockerSandboxToolHandler(
        "registry.example.test/worker@" + profile.workload_ref,
        timeout_seconds=10,
        isolation_profile=profile,
        attestation_provider=issue,
    )
    evidence = handler.get_isolation_attestation(
        _context(), "compile", _resources(), "nonce:docker"
    )
    assert evidence.profile_digest == profile.configuration_digest
    assert calls == [(profile.configuration_digest, "nonce:docker")]

    with pytest.raises(ValueError, match="do not match"):
        replace(handler, pids_limit=65)
    with pytest.raises(ValueError, match="both profile and provider"):
        DockerSandboxToolHandler(
            "registry.example.test/worker@" + profile.workload_ref,
            isolation_profile=profile,
        )


def test_unattested_docker_handler_cannot_satisfy_runtime_isolation_request() -> None:
    """A restrictive command alone is not provider-issued execution evidence."""
    handler = DockerSandboxToolHandler("sha256:" + "a" * 64)
    with pytest.raises(RuntimeError, match="not configured"):
        handler.get_isolation_attestation(_context(), "compile", _resources(), "nonce:test")


def test_runtime_audits_immutable_isolation_identity_without_signature() -> None:
    """Execution evidence records boundary identity while excluding provider proof material."""
    now = datetime.now(UTC)
    profile = _profile()

    class Handler:
        """Synthetic deployment adapter that issues exact action-bound evidence."""

        def get_isolation_attestation(
            self,
            context: ExecutionContext,
            tool_name: str,
            resources: tuple[Resource, ...],
            nonce: str,
        ) -> IsolationAttestation:
            """Return provider evidence for the live host-owned action."""
            return replace(
                _attestation(now, profile),
                nonce=nonce,
                tool_name=tool_name,
                tenant=cast(str, context.tenant),
                action_binding=isolation_action_binding(context, tool_name, resources, nonce),
            )

        def __call__(self, _context: ExecutionContext, _arguments: object) -> dict[str, bool]:
            """Return a synthetic bounded worker result."""
            return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "compile",
            Handler(),
            lambda value: dict(value),
            resources=lambda _: _resources(),
            requires_isolation=True,
            description="Compile synthetic untrusted source in an attested boundary.",
        )
    )
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(
        _context(),
        registry,
        AllowListPolicy({"compile"}),
        audit,
        config=RuntimeConfig(isolation_verifier=_verifier(now, profile)),
    )

    result = runtime.execute(ActionProposal("compile", {"source": "synthetic"}, "proposal:1"))

    assert result.status is ExecutionStatus.EXECUTED
    isolation = audit.events()[-1].payload["isolation"]
    assert isolation["profile_digest"] == profile.configuration_digest
    assert isolation["workload_ref"] == profile.workload_ref
    assert isolation["boundary"] == "container"
    assert "signature" not in isolation

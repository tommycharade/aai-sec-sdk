"""Adversarial contracts for Azure and GCP workload-identity brokers."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from agentic_security import (
    AzureWorkloadIdentityCredentialBroker,
    CloudCredentialProvider,
    CloudProviderGrant,
    CloudScopePolicy,
    CloudWorkloadCredentialBroker,
    ExecutionContext,
    GcpWorkloadIdentityCredentialBroker,
    Principal,
    Resource,
    ToolDefinition,
)

NOW = datetime(2026, 8, 5, 9, 0, tzinfo=UTC)
TENANT_ID = "11111111-2222-4333-8444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
AZURE_PRINCIPAL = f"{TENANT_ID}/{CLIENT_ID}"
GCP_PRINCIPAL = "broker-agent@secure-platform.iam.gserviceaccount.com"
RESOURCE = Resource("vault:synthetic", "vault", "tenant:a")


def _context() -> ExecutionContext:
    return ExecutionContext(
        agent_id="agent:cloud",
        principal=Principal("user:alice", tenant="tenant:a"),
        task_id="task:cloud",
        purpose="cloud credential contract test",
        tenant="tenant:a",
    )


def _tool() -> ToolDefinition:
    return ToolDefinition(
        name="read_secret_metadata",
        description="Read synthetic metadata without secret content.",
        handler=lambda *_: None,
        validator=lambda value: value,
        resources=lambda _: (RESOURCE,),
        requires_credential=True,
    )


class ExchangeClient:
    """Synthetic token exchange client recording exact requested authority."""

    def __init__(self, grant: CloudProviderGrant) -> None:
        self.grant = grant
        self.requests: list[tuple[CloudScopePolicy, int]] = []

    def exchange(self, policy: CloudScopePolicy, ttl_seconds: int) -> CloudProviderGrant:
        """Return configured synthetic evidence and record the trusted request."""
        self.requests.append((policy, ttl_seconds))
        return self.grant


def _policy(provider: CloudCredentialProvider, principal: str) -> CloudScopePolicy:
    return CloudScopePolicy(
        provider=provider,
        principal=principal,
        audience="https://vault.example.test",
        scopes=("metadata.read",),
        tool_name="read_secret_metadata",
        resources=(RESOURCE.id,),
    )


def _grant(policy: CloudScopePolicy) -> CloudProviderGrant:
    return CloudProviderGrant(
        provider=policy.provider,
        grant_id="grant-synthetic-1",
        principal=policy.principal,
        audience=policy.audience,
        scopes=policy.scopes,
        tool_name=policy.tool_name,
        resources=policy.resources,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=299),
        value="synthetic-provider-token",  # noqa: S106 - synthetic test material
    )


@pytest.mark.parametrize(
    ("provider", "principal", "factory"),
    [
        (
            CloudCredentialProvider.AZURE,
            AZURE_PRINCIPAL,
            lambda client, builder, checker: AzureWorkloadIdentityCredentialBroker(
                TENANT_ID,
                CLIENT_ID,
                client,
                builder,
                checker,
                now=lambda: NOW,
            ),
        ),
        (
            CloudCredentialProvider.GCP,
            GCP_PRINCIPAL,
            lambda client, builder, checker: GcpWorkloadIdentityCredentialBroker(
                GCP_PRINCIPAL,
                client,
                builder,
                checker,
                now=lambda: NOW,
            ),
        ),
    ],
)
def test_cloud_brokers_bind_grants_and_recheck_revocation_before_use(
    provider: CloudCredentialProvider,
    principal: str,
    factory: Any,
) -> None:
    """A valid grant works once, then live revocation withholds its material."""
    policy = _policy(provider, principal)
    client = ExchangeClient(_grant(policy))
    active = {"value": True}
    broker = factory(client, lambda *_: policy, lambda *_: active["value"])

    credential = broker.mint(_context(), _tool(), (RESOURCE,), 300)

    assert client.requests == [(policy, 300)]
    assert credential.valid_for(_tool().name, (RESOURCE,), NOW)
    captured: list[str] = []
    credential.with_secret(lambda value: captured.append(value), NOW)
    assert captured == ["synthetic-provider-token"]
    assert "synthetic-provider-token" not in repr(credential)

    active["value"] = False
    assert not credential.valid_for(_tool().name, (RESOURCE,), NOW)
    with pytest.raises(ValueError, match="revoked"):
        credential.with_secret(lambda _: None, NOW)


@pytest.mark.parametrize(
    "mutation",
    [
        {"provider": CloudCredentialProvider.GCP},
        {"principal": "attacker@example.test"},
        {"audience": "https://other.example.test"},
        {"scopes": ("metadata.write",)},
        {"tool_name": "write_secret"},
        {"resources": ("vault:other",)},
        {"issued_at": NOW + timedelta(seconds=1)},
        {"expires_at": NOW},
        {"expires_at": NOW + timedelta(minutes=10)},
    ],
)
def test_azure_broker_rejects_every_grant_binding_mismatch(mutation: dict[str, Any]) -> None:
    """Provider output cannot widen or substitute any live action dimension."""
    policy = _policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL)
    grant = replace(_grant(policy), **mutation)
    broker = AzureWorkloadIdentityCredentialBroker(
        TENANT_ID,
        CLIENT_ID,
        ExchangeClient(grant),
        lambda *_: policy,
        lambda *_: True,
        now=lambda: NOW,
    )

    with pytest.raises(ValueError, match="invalid scope or lifetime"):
        broker.mint(_context(), _tool(), (RESOURCE,), 300)


def test_cloud_broker_rejects_policy_widening_before_token_exchange() -> None:
    """A trusted policy callback must still bind exact provider/action scope."""
    policy = _policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL)
    client = ExchangeClient(_grant(policy))
    widened = replace(policy, resources=(RESOURCE.id, "vault:other"))
    broker = AzureWorkloadIdentityCredentialBroker(
        TENANT_ID,
        CLIENT_ID,
        client,
        lambda *_: widened,
        lambda *_: True,
        now=lambda: NOW,
    )

    with pytest.raises(ValueError, match="invalid action binding"):
        broker.mint(_context(), _tool(), (RESOURCE,), 300)
    assert client.requests == []


def test_cloud_broker_fails_closed_when_revocation_authority_errors() -> None:
    """Revocation lookup failure never falls back to a cached active grant."""
    policy = _policy(CloudCredentialProvider.GCP, GCP_PRINCIPAL)

    def revocation(*_: Any) -> bool:
        raise TimeoutError("synthetic authority timeout")

    broker = GcpWorkloadIdentityCredentialBroker(
        GCP_PRINCIPAL,
        ExchangeClient(_grant(policy)),
        lambda *_: policy,
        revocation,
        now=lambda: NOW,
    )

    with pytest.raises(TimeoutError, match="authority timeout"):
        broker.mint(_context(), _tool(), (RESOURCE,), 300)


@pytest.mark.parametrize("ttl", [0, 3601])
def test_cloud_broker_rejects_unbounded_ttl(ttl: int) -> None:
    """Provider token lifetime is bounded independently of tool configuration."""
    policy = _policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL)
    client = ExchangeClient(_grant(policy))
    broker = AzureWorkloadIdentityCredentialBroker(
        TENANT_ID,
        CLIENT_ID,
        client,
        lambda *_: policy,
        lambda *_: True,
        now=lambda: NOW,
    )
    with pytest.raises(ValueError, match="between 1 and 3600"):
        broker.mint(_context(), _tool(), (RESOURCE,), ttl)
    assert client.requests == []


def test_cloud_identity_configuration_rejects_ambiguous_principals() -> None:
    """Malformed Azure/GCP identities cannot reach a token client."""
    with pytest.raises(ValueError, match="UUIDs"):
        AzureWorkloadIdentityCredentialBroker(
            "tenant",
            "client",
            ExchangeClient(_grant(_policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL))),
            lambda *_: _policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL),
            lambda *_: True,
        )
    with pytest.raises(ValueError, match="service account"):
        GcpWorkloadIdentityCredentialBroker(
            "owner@example.test",
            ExchangeClient(_grant(_policy(CloudCredentialProvider.GCP, GCP_PRINCIPAL))),
            lambda *_: _policy(CloudCredentialProvider.GCP, GCP_PRINCIPAL),
            lambda *_: True,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"principal": ""},
        {"scopes": ("metadata.read", "metadata.read")},
        {"scopes": ()},
    ],
)
def test_cloud_scope_policy_rejects_empty_or_ambiguous_scope(changes: dict[str, Any]) -> None:
    """Policy construction rejects scope that cannot identify one exact grant."""
    with pytest.raises(ValueError, match="non-empty|duplicates|required"):
        replace(_policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"value": ""},
        {"issued_at": datetime(2026, 8, 5, 9, 0)},
        {"expires_at": NOW - timedelta(seconds=2)},
    ],
)
def test_cloud_provider_grant_rejects_malformed_evidence(changes: dict[str, Any]) -> None:
    """A provider response must contain usable material and coherent aware timestamps."""
    policy = _policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL)
    with pytest.raises(ValueError, match="non-empty|timezone-aware|expiry"):
        replace(_grant(policy), **changes)


def test_generic_cloud_broker_rejects_empty_principal_and_missing_evidence() -> None:
    """Generic adapter construction and malformed exchange responses fail closed."""
    policy = _policy(CloudCredentialProvider.AZURE, AZURE_PRINCIPAL)
    with pytest.raises(ValueError, match="principal is required"):
        CloudWorkloadCredentialBroker(
            CloudCredentialProvider.AZURE,
            "",
            ExchangeClient(_grant(policy)),
            lambda *_: policy,
            lambda *_: True,
        )

    client = ExchangeClient(_grant(policy))
    client.grant = None  # type: ignore[assignment]  # adversarial provider response
    broker = CloudWorkloadCredentialBroker(
        CloudCredentialProvider.AZURE,
        AZURE_PRINCIPAL,
        client,
        lambda *_: policy,
        lambda *_: True,
        now=lambda: NOW,
    )
    with pytest.raises(ValueError, match="no scope evidence"):
        broker.mint(_context(), _tool(), (RESOURCE,), 300)


def test_cloud_broker_denies_explicit_revocation_at_mint() -> None:
    """A provider grant marked inactive never becomes a handler capability."""
    policy = _policy(CloudCredentialProvider.GCP, GCP_PRINCIPAL)
    broker = GcpWorkloadIdentityCredentialBroker(
        GCP_PRINCIPAL,
        ExchangeClient(_grant(policy)),
        lambda *_: policy,
        lambda *_: False,
        now=lambda: NOW,
    )
    with pytest.raises(ValueError, match="not active"):
        broker.mint(_context(), _tool(), (RESOURCE,), 300)

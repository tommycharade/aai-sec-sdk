"""Exact-scope workload-identity adapters for Azure and Google Cloud.

The module deliberately injects provider token clients instead of importing a
cloud SDK. Deployments can use their approved Azure Identity or Google Auth
client while the security-critical binding and fail-closed checks remain small,
deterministic, and independently testable.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from .credentials import ScopedCredential
from .tools import ToolDefinition
from .types import ExecutionContext, Resource


class CloudCredentialProvider(StrEnum):
    """Supported cloud workload-identity token authorities."""

    AZURE = "azure_workload_identity"
    GCP = "gcp_workload_identity"


@dataclass(frozen=True, slots=True)
class CloudScopePolicy:
    """Deployment-owned exact scope requested from a cloud token service.

    ``resources`` are normalized application resource identities, while
    ``audience`` and ``scopes`` are provider token constraints. The model never
    constructs this object; a trusted policy builder derives it from the live
    tool definition and validated resources.
    """

    provider: CloudCredentialProvider
    principal: str
    audience: str
    scopes: tuple[str, ...]
    tool_name: str
    resources: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject empty, duplicate, or ambiguous provider scope."""
        values = (self.principal, self.audience, self.tool_name, *self.scopes, *self.resources)
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("cloud credential scope fields must be non-empty")
        if len(set(self.scopes)) != len(self.scopes) or len(set(self.resources)) != len(
            self.resources
        ):
            raise ValueError("cloud credential scope must not contain duplicates")
        if not self.scopes or not self.resources:
            raise ValueError("cloud credential scopes and resources are required")


@dataclass(frozen=True, slots=True)
class CloudProviderGrant:
    """Trusted token-client response with provider-enforced scope evidence.

    ``value`` is sensitive provider material. It is consumed immediately by
    the broker and retained only behind :class:`ScopedCredential`'s callback
    capability; applications must never log or serialize this response.
    """

    provider: CloudCredentialProvider
    grant_id: str
    principal: str
    audience: str
    scopes: tuple[str, ...]
    tool_name: str
    resources: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    value: str

    def __post_init__(self) -> None:
        """Reject malformed provider evidence before scope comparison."""
        values = (
            self.grant_id,
            self.principal,
            self.audience,
            self.tool_name,
            self.value,
            *self.scopes,
            *self.resources,
        )
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("cloud provider grant fields must be non-empty")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("cloud provider grant timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("cloud provider grant expiry must follow issuance")


class CloudTokenExchangeClient(Protocol):
    """Deployment adapter that exchanges workload identity for one grant."""

    def exchange(self, policy: CloudScopePolicy, ttl_seconds: int) -> CloudProviderGrant:
        """Return provider evidence for exactly ``policy`` or raise an error."""


CloudScopeBuilder = Callable[[str, tuple[str, ...]], CloudScopePolicy]
"""Trusted callback deriving cloud scope from one tool and resource set."""

GrantRevocationChecker = Callable[[CloudCredentialProvider, str, str], bool]
"""Live callback deciding whether a provider grant remains active."""


class CloudWorkloadCredentialBroker:
    """Mint exact-scope cloud credentials and check revocation before use.

    The token client and policy builder are deployment-owned trust boundaries.
    The broker independently compares every returned grant field with the
    request and fails closed on mismatch, stale evidence, or revocation lookup
    failure. Provider IAM still determines whether the represented scope is
    actually enforced in Azure or Google Cloud.
    """

    def __init__(
        self,
        provider: CloudCredentialProvider,
        principal: str,
        token_client: CloudTokenExchangeClient,
        policy_builder: CloudScopeBuilder,
        revocation_checker: GrantRevocationChecker,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        """Create a broker with explicit provider identity and live revocation."""
        if not principal.strip():
            raise ValueError("cloud workload principal is required")
        self._provider = provider
        self._principal = principal
        self._client = token_client
        self._policy_builder = policy_builder
        self._revocation_checker = revocation_checker
        self._now = now or (lambda: datetime.now(UTC))

    def mint(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
    ) -> ScopedCredential:
        """Exchange workload identity only for the exact authorized action."""
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("cloud credential TTL must be between 1 and 3600 seconds")
        resource_ids = tuple(resource.id for resource in resources)
        policy = self._policy_builder(tool.name, resource_ids)
        if (
            not isinstance(policy, CloudScopePolicy)
            or policy.provider is not self._provider
            or policy.principal != self._principal
            or policy.tool_name != tool.name
            or policy.resources != resource_ids
        ):
            raise ValueError("cloud scope builder returned an invalid action binding")
        grant = self._client.exchange(policy, ttl_seconds)
        if not isinstance(grant, CloudProviderGrant):
            raise ValueError("cloud token service returned no scope evidence")
        expected = (
            policy.provider,
            policy.principal,
            policy.audience,
            policy.scopes,
            policy.tool_name,
            policy.resources,
        )
        observed = (
            grant.provider,
            grant.principal,
            grant.audience,
            grant.scopes,
            grant.tool_name,
            grant.resources,
        )
        now = self._now()
        if (
            observed != expected
            or grant.issued_at > now
            or grant.expires_at <= now
            or grant.expires_at - grant.issued_at > timedelta(seconds=ttl_seconds)
        ):
            raise ValueError("cloud token service returned an invalid scope or lifetime")
        if self._revocation_checker(grant.provider, grant.principal, grant.grant_id) is not True:
            raise ValueError("cloud provider grant is not active")

        def provider(value: str = grant.value) -> str:
            return value

        def remains_active(
            provider_name: CloudCredentialProvider = grant.provider,
            principal: str = grant.principal,
            grant_id: str = grant.grant_id,
        ) -> bool:
            return self._revocation_checker(provider_name, principal, grant_id) is True

        return ScopedCredential(
            credential_id=f"{grant.provider.value}:{context.task_id}:{grant.grant_id}",
            tool_name=tool.name,
            resources=resources,
            issued_at=now,
            expires_at=min(now + timedelta(seconds=ttl_seconds), grant.expires_at),
            _secret_provider=provider,
            _validity_provider=remains_active,
        )


class AzureWorkloadIdentityCredentialBroker(CloudWorkloadCredentialBroker):
    """Azure workload-identity broker bound to one Entra tenant/application."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        token_client: CloudTokenExchangeClient,
        policy_builder: CloudScopeBuilder,
        revocation_checker: GrantRevocationChecker,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        """Create an Azure broker without accepting a client secret."""
        uuid_pattern = (
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
        )
        if not re.fullmatch(uuid_pattern, tenant_id) or not re.fullmatch(uuid_pattern, client_id):
            raise ValueError("Azure tenant and client IDs must be UUIDs")
        super().__init__(
            CloudCredentialProvider.AZURE,
            f"{tenant_id.lower()}/{client_id.lower()}",
            token_client,
            policy_builder,
            revocation_checker,
            now=now,
        )


class GcpWorkloadIdentityCredentialBroker(CloudWorkloadCredentialBroker):
    """Google Cloud workload-identity broker bound to one service account."""

    def __init__(
        self,
        service_account_email: str,
        token_client: CloudTokenExchangeClient,
        policy_builder: CloudScopeBuilder,
        revocation_checker: GrantRevocationChecker,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        """Create a GCP broker for an exact service-account principal."""
        principal = service_account_email.strip().lower()
        service_account_pattern = (
            r"[a-z][a-z0-9-]{4,28}@"
            r"[a-z][a-z0-9-]{4,28}\.iam\.gserviceaccount\.com"
        )
        if not re.fullmatch(service_account_pattern, principal):
            raise ValueError("GCP service account email is invalid")
        super().__init__(
            CloudCredentialProvider.GCP,
            principal,
            token_client,
            policy_builder,
            revocation_checker,
            now=now,
        )


__all__ = [
    "AzureWorkloadIdentityCredentialBroker",
    "CloudCredentialProvider",
    "CloudProviderGrant",
    "CloudScopeBuilder",
    "CloudScopePolicy",
    "CloudTokenExchangeClient",
    "CloudWorkloadCredentialBroker",
    "GcpWorkloadIdentityCredentialBroker",
    "GrantRevocationChecker",
]

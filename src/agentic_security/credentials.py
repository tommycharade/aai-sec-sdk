"""Scoped credential broker contracts and a development implementation."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import InitVar, dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Protocol
from weakref import WeakKeyDictionary

from .tools import ToolDefinition
from .types import ExecutionContext, Resource


@dataclass(frozen=True, slots=True)
class ProviderToken:
    """Provider attestation for token material and its effective scope.

    A token callback must return this object rather than a bare string. The
    provider, not the model or SDK caller, attests the actual audience and
    resource scope it granted. The runtime independently checks the requested
    scope matches this attestation.
    """

    value: str
    tool_name: str
    resources: tuple[Resource, ...]
    expires_at: datetime

    def __post_init__(self) -> None:
        """Reject incomplete provider scope attestations."""
        if not self.value or not self.tool_name or not self.resources:
            raise ValueError("provider token value and scope are required")
        if self.expires_at <= datetime.now(UTC):
            raise ValueError("provider token is expired")


TokenMinter = Callable[[ExecutionContext, ToolDefinition, tuple[Resource, ...]], ProviderToken]
"""Callback that obtains an authenticated provider token with scope evidence."""

_PROVIDER_REGISTRY: WeakKeyDictionary[object, Callable[[], str]] = WeakKeyDictionary()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ScopedCredential:
    """Short-lived credential bound to one tool and resource set.

    Provider material is held behind a callback capability and can only be
    passed to a short-lived callback through :meth:`with_secret`. Production
    brokers should return an audience-bound token with equivalent scope and
    lifetime guarantees. No raw secret is stored as a readable credential
    attribute.
    """

    credential_id: str
    tool_name: str
    resources: tuple[Resource, ...]
    issued_at: datetime
    expires_at: datetime
    # InitVar accepts provider material during construction but does not store
    # the callback on the credential object. The weak registry keeps it out of
    # the handler-visible object graph while allowing expiry checks here.
    _secret_provider: InitVar[Callable[[], str]]

    def __post_init__(self, _secret_provider: Callable[[], str]) -> None:
        """Prevent credentials with empty scopes or non-positive lifetimes."""
        if not self.credential_id or not self.tool_name:
            raise ValueError("credential identity and tool scope are required")
        if self.expires_at <= self.issued_at:
            raise ValueError("credential expiry must be after issue time")
        _PROVIDER_REGISTRY[self] = _secret_provider

    def valid_for(
        self,
        tool_name: str,
        resources: tuple[Resource, ...],
        now: datetime | None = None,
    ) -> bool:
        """Return whether this credential is live and exactly scope-matched."""
        current = now or datetime.now(UTC)
        return (
            self.issued_at <= current
            and current < self.expires_at
            and tool_name == self.tool_name
            and resources == self.resources
        )

    def with_secret(self, operation: Callable[[str], object], now: datetime | None = None) -> None:
        """Pass live provider material to a non-returning provider operation.

        The callback must pass the material directly to the intended provider
        client and must not log, persist, return, or capture it. Returning a
        value is rejected so a handler cannot accidentally place the secret in
        a tool result. This is an in-process trust boundary: hostile handlers
        still require :class:`~agentic_security.adapters.SubprocessToolHandler`
        or a stronger OS/container sandbox.
        """
        current = now or datetime.now(UTC)
        if not self.issued_at <= current < self.expires_at:
            raise ValueError("credential is expired or not yet valid")
        provider = _PROVIDER_REGISTRY.get(self)
        if provider is None:
            raise ValueError("credential material is unavailable")
        result = operation(provider())
        if result is not None:
            raise ValueError("credential operation must not return provider material")


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    """Non-secret record describing a credential issued during a test run."""

    credential_id: str
    tool_name: str
    resources: tuple[Resource, ...]
    issued_at: datetime
    expires_at: datetime


class CredentialBroker(Protocol):
    """Contract for just-in-time credential providers."""

    def mint(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
    ) -> ScopedCredential:
        """Mint a credential scoped to this authenticated action."""
        raise NotImplementedError


class InMemoryCredentialBroker:
    """Development broker that creates synthetic, short-lived credentials."""

    def __init__(self, now: Callable[[], datetime] | None = None) -> None:
        """Create a broker with an injectable clock for deterministic tests."""
        self._now = now or (lambda: datetime.now(UTC))
        self._issued: list[ScopedCredential] = []
        self._sequence = 0
        self._lock = Lock()

    def mint(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
    ) -> ScopedCredential:
        """Issue one synthetic token without accepting scope from model output."""
        if ttl_seconds <= 0:
            raise ValueError("credential TTL must be positive")
        issued_at = self._now()
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        secret = secrets.token_urlsafe(24)

        def provider(value: str = secret) -> str:
            return value

        credential = ScopedCredential(
            credential_id=f"cred:{context.task_id}:{sequence}",
            tool_name=tool.name,
            resources=resources,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
            _secret_provider=provider,
        )
        with self._lock:
            self._issued.append(credential)
        return credential

    def issued(self) -> tuple[CredentialMetadata, ...]:
        """Return issued credential metadata without exposing any secret."""
        with self._lock:
            return tuple(
                CredentialMetadata(
                    credential.credential_id,
                    credential.tool_name,
                    credential.resources,
                    credential.issued_at,
                    credential.expires_at,
                )
                for credential in self._issued
            )


class TokenCredentialBroker:
    """Credential broker for an authenticated IAM/token-service callback.

    The callback is responsible for provider authentication and must return a
    :class:`ProviderToken` attestation scoped to the supplied tool and
    resources. A bare token string is rejected because the SDK cannot verify
    provider-side scope from an opaque string.
    """

    def __init__(self, mint_token: TokenMinter) -> None:
        """Create a broker around a deployment-owned token service callback."""
        self._mint_token = mint_token

    def mint(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
    ) -> ScopedCredential:
        """Mint one short-lived credential for the exact live action scope."""
        if ttl_seconds <= 0:
            raise ValueError("credential TTL must be positive")
        provider_token = self._mint_token(context, tool, resources)
        if not isinstance(provider_token, ProviderToken):
            raise ValueError("token service returned no scope attestation")
        if provider_token.tool_name != tool.name or provider_token.resources != resources:
            raise ValueError("token service returned an invalid scope")
        issued_at = datetime.now(UTC)

        def provider(value: str = provider_token.value) -> str:
            return value

        return ScopedCredential(
            f"cred:{context.task_id}:{secrets.token_urlsafe(8)}",
            tool.name,
            resources,
            issued_at,
            min(issued_at + timedelta(seconds=ttl_seconds), provider_token.expires_at),
            provider,
        )

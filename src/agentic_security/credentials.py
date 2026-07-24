"""Scoped credential broker contracts and a development implementation."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Protocol, TypeVar

from .tools import ToolDefinition
from .types import ExecutionContext, Resource

T = TypeVar("T")
TokenMinter = Callable[[ExecutionContext, ToolDefinition, tuple[Resource, ...]], str]
"""Callback that obtains an already-authenticated provider token."""


@dataclass(frozen=True, slots=True)
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
    _secret_provider: Callable[[], str] = field(default=lambda: "", repr=False, compare=False)

    def __post_init__(self) -> None:
        """Prevent credentials with empty scopes or non-positive lifetimes."""
        if not self.credential_id or not self.tool_name:
            raise ValueError("credential identity and tool scope are required")
        if self.expires_at <= self.issued_at:
            raise ValueError("credential expiry must be after issue time")

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

    def with_secret(self, operation: Callable[[str], T], now: datetime | None = None) -> T:
        """Invoke ``operation`` with live provider material without exposing it in results.

        The callback must pass the material directly to the intended provider
        client and must not log, persist, return, or capture it. This method
        checks expiry immediately before use.
        """
        current = now or datetime.now(UTC)
        if not self.issued_at <= current < self.expires_at:
            raise ValueError("credential is expired or not yet valid")
        return operation(self._secret_provider())


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
    token scoped to the supplied tool and resources. The broker adds the SDK's
    expiry and scope checks without exposing token material as a credential
    attribute.
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
        token = self._mint_token(context, tool, resources)
        if not isinstance(token, str) or not token:
            raise ValueError("token service returned no token")
        issued_at = datetime.now(UTC)

        def provider(value: str = token) -> str:
            return value

        return ScopedCredential(
            f"cred:{context.task_id}:{secrets.token_urlsafe(8)}",
            tool.name,
            resources,
            issued_at,
            issued_at + timedelta(seconds=ttl_seconds),
            provider,
        )

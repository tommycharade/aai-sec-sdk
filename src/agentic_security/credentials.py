"""Scoped credential broker contracts and a development implementation."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Protocol

from .tools import ToolDefinition
from .types import ExecutionContext, Resource


@dataclass(frozen=True, slots=True)
class ScopedCredential:
    """Short-lived credential bound to one tool and resource set.

    ``secret`` is excluded from representations and equality so normal logs,
    debugging, and comparisons cannot accidentally expose or depend on it.
    Production brokers should return an audience-bound token with equivalent
    scope and lifetime guarantees.
    """

    credential_id: str
    tool_name: str
    resources: tuple[Resource, ...]
    issued_at: datetime
    expires_at: datetime
    secret: str = field(default="", repr=False, compare=False)

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
            current < self.expires_at
            and tool_name == self.tool_name
            and resources == self.resources
        )


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
            sequence = len(self._issued) + 1
        credential = ScopedCredential(
            credential_id=f"cred:{context.task_id}:{sequence}",
            tool_name=tool.name,
            resources=resources,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
            secret=secrets.token_urlsafe(24),
        )
        with self._lock:
            self._issued.append(credential)
        return credential

    def issued(self) -> tuple[ScopedCredential, ...]:
        """Return issued credential metadata for tests, excluding secret values."""
        with self._lock:
            return tuple(self._issued)

"""Incident-aware, fail-closed credential authority composition.

This module lets a deployment add central incident-response revocation to any
SDK credential broker.  It does not trust model output or handler arguments for
identity: every request is built from the host-owned :class:`ExecutionContext`,
the registered tool and its validated resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .credentials import CredentialBroker, ScopedCredential
from .tools import ToolDefinition
from .types import ExecutionContext, Resource


class CredentialAuthorityState(StrEnum):
    """Structured result from a deployment-owned credential authority."""

    ACTIVE = "active"
    REVOKED = "revoked"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class CredentialAuthorityRequest:
    """Exact host-derived action binding checked by central authority.

    ``credential_id`` is absent for the pre-mint check and present for the
    post-mint and use-time checks.  It is an opaque correlation identifier,
    never provider material.
    """

    broker_id: str
    tenant: str
    agent_id: str
    principal_id: str
    task_id: str
    tool_name: str
    resource_ids: tuple[str, ...]
    credential_id: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete or ambiguous action authority."""
        required = (
            self.broker_id,
            self.tenant,
            self.agent_id,
            self.principal_id,
            self.task_id,
            self.tool_name,
            *self.resource_ids,
        )
        if not all(isinstance(value, str) and value.strip() for value in required):
            raise ValueError("credential authority binding fields must be non-empty")
        if len(set(self.resource_ids)) != len(self.resource_ids):
            raise ValueError("credential authority resources must not contain duplicates")
        if self.credential_id is not None and (
            not isinstance(self.credential_id, str) or not self.credential_id.strip()
        ):
            raise ValueError("credential authority identifier must be non-empty when present")


@dataclass(frozen=True, slots=True)
class CredentialAuthorityDecision:
    """Content-minimised decision returned by central credential authority."""

    state: CredentialAuthorityState
    reason_code: str
    control_revision: int = 0
    case_id: str | None = None

    def __post_init__(self) -> None:
        """Require coherent, non-free-form decision evidence."""
        if not isinstance(self.state, CredentialAuthorityState):
            raise ValueError("credential authority state is invalid")
        if (
            not isinstance(self.reason_code, str)
            or not self.reason_code.strip()
            or len(self.reason_code) > 128
        ):
            raise ValueError("credential authority reason code is invalid")
        if (
            not isinstance(self.control_revision, int)
            or isinstance(self.control_revision, bool)
            or self.control_revision < 0
        ):
            raise ValueError("credential authority revision is invalid")
        if self.state is CredentialAuthorityState.REVOKED and (
            self.control_revision < 1
            or not isinstance(self.case_id, str)
            or not self.case_id.strip()
        ):
            raise ValueError("revoked credential authority requires case evidence")


class CredentialAuthorityChecker(Protocol):
    """Deployment adapter that checks one exact credential action binding."""

    def __call__(self, request: CredentialAuthorityRequest, /) -> CredentialAuthorityDecision:
        """Return current central authority or raise when it cannot be established."""


class RevocationAwareCredentialBroker:
    """Narrow any credential broker with central incident-response authority.

    Authority is checked before minting, immediately after minting, and every
    time provider material is requested.  A timeout, malformed decision or
    non-active state denies the operation.  The wrapped broker and checker are
    deployment-owned objects and must not be exposed to model or tool code.
    """

    def __init__(
        self,
        broker_id: str,
        broker: CredentialBroker,
        authority: CredentialAuthorityChecker,
    ) -> None:
        """Create a narrowing wrapper around one registered broker identity."""
        if not isinstance(broker_id, str) or not broker_id.strip():
            raise ValueError("credential broker id is required")
        if not callable(getattr(broker, "mint", None)):
            raise TypeError("credential broker must provide mint")
        if not callable(authority):
            raise TypeError("credential authority checker must be callable")
        self._broker_id = broker_id.strip()
        self._broker = broker
        self._authority = authority

    def _decision(self, request: CredentialAuthorityRequest) -> CredentialAuthorityDecision:
        """Return only explicit active authority; every unknown state fails closed."""
        try:
            decision = self._authority(request)
        except Exception as error:
            raise ValueError("credential authority is unavailable") from error
        if not isinstance(decision, CredentialAuthorityDecision):
            raise ValueError("credential authority returned an invalid decision")
        if decision.state is not CredentialAuthorityState.ACTIVE:
            raise ValueError("credential authority is revoked or unavailable")
        return decision

    def mint(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        resources: tuple[Resource, ...],
        ttl_seconds: int,
    ) -> ScopedCredential:
        """Mint only while central authority remains active for this exact action."""
        request = CredentialAuthorityRequest(
            broker_id=self._broker_id,
            tenant=str(context.tenant),
            agent_id=context.agent_id,
            principal_id=context.principal.id,
            task_id=context.task_id,
            tool_name=tool.name,
            resource_ids=tuple(resource.id for resource in resources),
        )
        self._decision(request)
        credential = self._broker.mint(context, tool, resources, ttl_seconds)
        if not isinstance(credential, ScopedCredential):
            raise ValueError("credential broker returned no scoped capability")
        # Rebuild the live request explicitly so the post-mint trust binding is
        # visible at this boundary.  No provider object, model value or mutable
        # copy operation may supply identity or scope for the second check.
        live_request = CredentialAuthorityRequest(
            broker_id=request.broker_id,
            tenant=request.tenant,
            agent_id=request.agent_id,
            principal_id=request.principal_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            resource_ids=request.resource_ids,
            credential_id=credential.credential_id,
        )
        self._decision(live_request)

        def remains_active() -> bool:
            try:
                self._decision(live_request)
            except ValueError:
                return False
            return True

        return credential.restrict(remains_active)


__all__ = [
    "CredentialAuthorityChecker",
    "CredentialAuthorityDecision",
    "CredentialAuthorityRequest",
    "CredentialAuthorityState",
    "RevocationAwareCredentialBroker",
]

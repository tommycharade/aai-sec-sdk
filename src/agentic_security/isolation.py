"""Typed isolation-attestation contracts.

The runtime verifies an attestation; it does not create a sandbox. A trusted
deployment verifier must bind the attestation to the current action and prove
the platform-specific isolation properties.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .types import ExecutionContext, Resource


@dataclass(frozen=True, slots=True)
class IsolationAttestation:
    """Provider-issued evidence for one isolated workload invocation."""

    provider: str
    workload_id: str
    profile: str
    expires_at: datetime
    nonce: str
    tool_name: str
    tenant: str
    capabilities: Mapping[str, bool]

    def __post_init__(self) -> None:
        """Reject incomplete evidence before it reaches a verifier."""
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.provider,
                self.workload_id,
                self.profile,
                self.nonce,
                self.tool_name,
                self.tenant,
            )
        ):
            raise ValueError("isolation attestation identity fields are required")
        if self.expires_at.tzinfo is None or self.expires_at <= datetime.now(UTC):
            raise ValueError("isolation attestation must not be expired")


class IsolationVerifier(Protocol):
    """Trusted deployment contract for validating platform evidence."""

    def verify(
        self,
        attestation: IsolationAttestation,
        context: ExecutionContext,
        tool_name: str,
        resources: tuple[Resource, ...],
        nonce: str,
    ) -> bool:
        """Return true only when evidence is current and action-bound."""


class CallbackIsolationVerifier:
    """Reference verifier adapter around a deployment-owned verification callback."""

    def __init__(
        self,
        callback: Callable[
            [IsolationAttestation, ExecutionContext, str, tuple[Resource, ...], str], bool
        ],
    ) -> None:
        """Create a verifier; the callback remains a trusted deployment boundary."""
        self._callback = callback

    def verify(
        self,
        attestation: IsolationAttestation,
        context: ExecutionContext,
        tool_name: str,
        resources: tuple[Resource, ...],
        nonce: str,
    ) -> bool:
        """Delegate verification and fail closed on callback errors."""
        try:
            return self._callback(attestation, context, tool_name, resources, nonce) is True
        except Exception:
            return False


def validate_attestation(
    attestation: IsolationAttestation,
    context: ExecutionContext,
    tool_name: str,
    resources: tuple[Resource, ...],
    nonce: str,
) -> bool:
    """Apply provider-neutral binding checks before a custom verifier runs."""
    return (
        attestation.expires_at > datetime.now(UTC)
        and attestation.nonce == nonce
        and attestation.tool_name == tool_name
        and attestation.tenant == context.tenant
        and all(resource.tenant == context.tenant for resource in resources)
    )


__all__ = [
    "CallbackIsolationVerifier",
    "IsolationAttestation",
    "IsolationVerifier",
    "validate_attestation",
]

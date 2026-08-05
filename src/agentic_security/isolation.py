"""Typed isolation profiles, attestations, and production verification.

The SDK never treats a model claim or a handler boolean as proof of isolation.
Deployments register immutable profiles, obtain action-bound evidence from a
trusted platform adapter, and verify that evidence immediately before issuing
an execution permit.  The sandbox itself remains a deployment responsibility.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from .types import ExecutionContext, Resource

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class IsolationBoundary(StrEnum):
    """Closed set of independently meaningful isolation boundaries."""

    CONTAINER = "container"
    MICROVM = "microvm"
    WASM = "wasm"
    ENDPOINT_SANDBOX = "endpoint_sandbox"


class IsolationNetworkMode(StrEnum):
    """Network policy applied inside an isolation profile."""

    NONE = "none"
    ALLOWLIST = "allowlist"


class IsolationCredentialMode(StrEnum):
    """How credentials may be made available to an isolated workload."""

    NONE = "none"
    BROKERED = "brokered"


@dataclass(frozen=True, slots=True)
class IsolationConstraints:
    """Explicit, bounded controls enforced by one isolation profile.

    The values describe platform enforcement, not desired policy. A trusted
    evidence issuer must attest that the exact controls were applied.
    """

    filesystem_read_only: bool
    network_mode: IsolationNetworkMode
    allowed_network_destinations: tuple[str, ...]
    process_namespace: bool
    max_memory_mib: int
    max_pids: int
    cpu_limit_millicores: int
    max_duration_seconds: int
    credential_mode: IsolationCredentialMode
    no_new_privileges: bool
    capabilities_dropped: bool

    def __post_init__(self) -> None:
        """Reject ambiguous, duplicated, or effectively unbounded controls."""
        if not isinstance(self.network_mode, IsolationNetworkMode) or not isinstance(
            self.credential_mode, IsolationCredentialMode
        ):
            raise ValueError("isolation constraint modes must use closed enum values")
        destinations = self.allowed_network_destinations
        if (
            not isinstance(destinations, tuple)
            or len(destinations) > 50
            or any(not isinstance(value, str) or not value.strip() for value in destinations)
            or len(set(destinations)) != len(destinations)
        ):
            raise ValueError("isolation network destinations must be unique bounded text")
        if self.network_mode is IsolationNetworkMode.NONE and destinations:
            raise ValueError("network-disabled isolation cannot declare destinations")
        if self.network_mode is IsolationNetworkMode.ALLOWLIST and not destinations:
            raise ValueError("allowlisted isolation requires at least one destination")
        limits = (
            self.max_memory_mib,
            self.max_pids,
            self.cpu_limit_millicores,
            self.max_duration_seconds,
        )
        if any(type(value) is not int or value <= 0 for value in limits):
            raise ValueError("isolation resource limits must be positive integers")
        if (
            self.max_memory_mib > 262_144
            or self.max_pids > 32_768
            or self.cpu_limit_millicores > 64_000
            or self.max_duration_seconds > 86_400
        ):
            raise ValueError("isolation resource limits exceed supported safety bounds")

    def canonical(self) -> dict[str, object]:
        """Return a deterministic, secret-free representation for hashing."""
        return {
            "allowedNetworkDestinations": list(self.allowed_network_destinations),
            "capabilitiesDropped": self.capabilities_dropped,
            "credentialMode": self.credential_mode.value,
            "filesystemReadOnly": self.filesystem_read_only,
            "cpuLimitMillicores": self.cpu_limit_millicores,
            "maxDurationSeconds": self.max_duration_seconds,
            "maxMemoryMib": self.max_memory_mib,
            "maxPids": self.max_pids,
            "networkMode": self.network_mode.value,
            "noNewPrivileges": self.no_new_privileges,
            "processNamespace": self.process_namespace,
        }


@dataclass(frozen=True, slots=True)
class IsolationProfile:
    """Deployment-owned immutable workload and sandbox configuration."""

    profile_id: str
    provider: str
    boundary: IsolationBoundary
    workload_ref: str
    revision: int
    constraints: IsolationConstraints

    def __post_init__(self) -> None:
        """Require stable identity and an immutable workload content digest."""
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.profile_id, self.provider, self.workload_ref)
        ):
            raise ValueError("isolation profile identity fields are required")
        if not isinstance(self.boundary, IsolationBoundary):
            raise ValueError("isolation profile boundary is unsupported")
        if not _DIGEST.fullmatch(self.workload_ref):
            raise ValueError("isolation workload must use an immutable sha256 reference")
        if type(self.revision) is not int or self.revision <= 0:
            raise ValueError("isolation profile revision must be a positive integer")

    @property
    def configuration_digest(self) -> str:
        """Return the digest that binds every execution-affecting profile field."""
        payload = {
            "boundary": self.boundary.value,
            "constraints": self.constraints.canonical(),
            "profileId": self.profile_id,
            "provider": self.provider,
            "revision": self.revision,
            "workloadRef": self.workload_ref,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class IsolationRequirement:
    """Policy-selected isolation profiles and evidence freshness constraints.

    Accepted profile digests are explicit because container, microVM, WASM,
    and endpoint sandboxes are not safely represented by one ordinal strength.
    Policy chooses reviewed configurations rather than assuming one boundary is
    universally stronger than another.
    """

    accepted_profile_digests: frozenset[str]
    allowed_boundaries: frozenset[IsolationBoundary]
    max_evidence_age_seconds: int = 60
    max_evidence_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        """Reject open-ended requirements that could authorize an unknown profile."""
        if (
            not self.accepted_profile_digests
            or len(self.accepted_profile_digests) > 50
            or any(not _DIGEST.fullmatch(value) for value in self.accepted_profile_digests)
        ):
            raise ValueError("isolation requirement needs reviewed profile digests")
        if not self.allowed_boundaries or not all(
            isinstance(value, IsolationBoundary) for value in self.allowed_boundaries
        ):
            raise ValueError("isolation requirement needs allowed boundary kinds")
        if (
            type(self.max_evidence_age_seconds) is not int
            or type(self.max_evidence_ttl_seconds) is not int
            or not 1 <= self.max_evidence_age_seconds <= 300
            or not 1 <= self.max_evidence_ttl_seconds <= 900
        ):
            raise ValueError("isolation evidence lifetime exceeds supported bounds")


@dataclass(frozen=True, slots=True)
class IsolationAttestation:
    """Provider-issued evidence for one isolated workload invocation.

    The first eight fields retain the original callback-adapter contract.
    Production verification additionally requires every field from
    ``issued_at`` onward and rejects legacy evidence.
    """

    provider: str
    workload_id: str
    profile: str
    expires_at: datetime
    nonce: str
    tool_name: str
    tenant: str
    capabilities: Mapping[str, bool]
    issued_at: datetime | None = None
    evidence_id: str = ""
    profile_digest: str = ""
    workload_ref: str = ""
    action_binding: str = ""
    signature: str = ""
    key_id: str = ""

    def __post_init__(self) -> None:
        """Reject incomplete or already expired evidence at construction."""
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
        if not isinstance(self.capabilities, Mapping) or any(
            not isinstance(key, str) or type(value) is not bool
            for key, value in self.capabilities.items()
        ):
            raise ValueError("isolation capabilities must map names to booleans")
        production_values = (
            self.issued_at,
            self.evidence_id,
            self.profile_digest,
            self.workload_ref,
            self.action_binding,
            self.signature,
            self.key_id,
        )
        if any(value not in (None, "") for value in production_values):
            if self.issued_at is None or self.issued_at.tzinfo is None:
                raise ValueError("production isolation evidence requires an issued time")
            if self.issued_at > self.expires_at:
                raise ValueError("isolation evidence cannot expire before it is issued")
            if not all(isinstance(value, str) and value.strip() for value in production_values[1:]):
                raise ValueError("production isolation evidence fields are incomplete")
            if not _DIGEST.fullmatch(self.profile_digest) or not _DIGEST.fullmatch(
                self.workload_ref
            ):
                raise ValueError("isolation evidence digests are invalid")


@dataclass(frozen=True, slots=True)
class IsolationVerification:
    """Structured result retained in an execution permit and safe audit event."""

    verified: bool
    reason: str
    evidence_id: str = ""
    provider: str = ""
    boundary: IsolationBoundary | None = None
    profile_digest: str = ""
    workload_ref: str = ""
    verified_at: datetime | None = None
    expires_at: datetime | None = None

    def __bool__(self) -> bool:
        """Allow existing gates to treat only an explicit verified result as true."""
        return self.verified is True

    def audit_fields(self) -> dict[str, str]:
        """Return content-minimised immutable identity without signatures or secrets."""
        if not self.verified:
            return {}
        return {
            "boundary": self.boundary.value if self.boundary is not None else "legacy",
            "evidence_id": self.evidence_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else "",
            "profile_digest": self.profile_digest,
            "provider": self.provider,
            "verified_at": self.verified_at.isoformat() if self.verified_at else "",
            "workload_ref": self.workload_ref,
        }


class IsolationVerifier(Protocol):
    """Trusted deployment contract for validating platform evidence."""

    def verify(
        self,
        attestation: IsolationAttestation,
        context: ExecutionContext,
        tool_name: str,
        resources: tuple[Resource, ...],
        nonce: str,
    ) -> bool | IsolationVerification:
        """Return verified structured evidence or an explicit legacy boolean."""


class CallbackIsolationVerifier:
    """Reference verifier around a deployment-owned compatibility callback.

    This adapter preserves the original SDK contract but cannot satisfy a
    production :class:`IsolationRequirement`; use
    :class:`ProductionIsolationVerifier` for reviewed profile enforcement.
    """

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


class ProductionIsolationVerifier:
    """Verify signed, fresh evidence against reviewed immutable profiles."""

    def __init__(
        self,
        profiles: Mapping[str, IsolationProfile],
        requirement: IsolationRequirement,
        signature_verifier: Callable[[IsolationAttestation], bool],
        revocation_checker: Callable[[str, str], bool],
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """Create a fail-closed verifier from host-owned trust dependencies.

        ``signature_verifier`` validates provider evidence without exposing a
        signing key to the model or worker. ``revocation_checker`` returns true
        only while the evidence and profile remain live; outages must raise or
        return false, both of which deny execution.
        """
        if not profiles:
            raise ValueError("production isolation requires trusted profiles")
        self._profiles = dict(profiles)
        if any(key != profile.configuration_digest for key, profile in self._profiles.items()):
            raise ValueError("isolation profile map keys must match configuration digests")
        self._requirement = requirement
        self._signature_verifier = signature_verifier
        self._revocation_checker = revocation_checker
        self._now = now

    def verify(
        self,
        attestation: IsolationAttestation,
        context: ExecutionContext,
        tool_name: str,
        resources: tuple[Resource, ...],
        nonce: str,
    ) -> IsolationVerification:
        """Verify exact action binding, profile, freshness, signature, and revocation."""
        now = self._now()

        def deny(reason: str) -> IsolationVerification:
            return IsolationVerification(False, reason)

        if not validate_attestation(attestation, context, tool_name, resources, nonce, now=now):
            return deny("isolation evidence action binding is invalid")
        if (
            attestation.issued_at is None
            or not attestation.evidence_id
            or not attestation.profile_digest
            or not attestation.workload_ref
            or not attestation.action_binding
            or not attestation.signature
            or not attestation.key_id
        ):
            return deny("production isolation evidence is incomplete")
        if attestation.issued_at > now:
            return deny("isolation evidence was issued in the future")
        evidence_age = (now - attestation.issued_at).total_seconds()
        if evidence_age > self._requirement.max_evidence_age_seconds:
            return deny("isolation evidence is stale")
        if (
            attestation.expires_at - attestation.issued_at
        ).total_seconds() > self._requirement.max_evidence_ttl_seconds:
            return deny("isolation evidence lifetime is too long")
        expected_binding = isolation_action_binding(context, tool_name, resources, nonce)
        if attestation.action_binding != expected_binding:
            return deny("isolation evidence does not bind the live action")
        if attestation.profile_digest not in self._requirement.accepted_profile_digests:
            return deny("isolation profile is not accepted by policy")
        profile = self._profiles.get(attestation.profile_digest)
        if profile is None:
            return deny("isolation profile is not trusted by this deployment")
        if profile.boundary not in self._requirement.allowed_boundaries:
            return deny("isolation boundary is not accepted by policy")
        if (
            profile.provider != attestation.provider
            or profile.profile_id != attestation.profile
            or profile.workload_ref != attestation.workload_ref
        ):
            return deny("isolation evidence does not match the reviewed profile")
        try:
            signature_valid = self._signature_verifier(attestation) is True
            authority_live = (
                self._revocation_checker(attestation.evidence_id, attestation.profile_digest)
                is True
            )
        except Exception:
            return deny("isolation authority verification failed")
        if not signature_valid:
            return deny("isolation evidence signature is invalid")
        if not authority_live:
            return deny("isolation evidence or profile is revoked")
        return IsolationVerification(
            True,
            "signed isolation evidence matches the live reviewed profile",
            evidence_id=attestation.evidence_id,
            provider=attestation.provider,
            boundary=profile.boundary,
            profile_digest=attestation.profile_digest,
            workload_ref=attestation.workload_ref,
            verified_at=now,
            expires_at=attestation.expires_at,
        )


def isolation_action_binding(
    context: ExecutionContext,
    tool_name: str,
    resources: tuple[Resource, ...],
    nonce: str,
) -> str:
    """Hash every live authority dimension into one provider-neutral binding."""
    payload = {
        "agentId": context.agent_id,
        "nonce": nonce,
        "principalId": context.principal.id,
        "purpose": context.purpose,
        "resources": [
            {"id": resource.id, "kind": resource.kind, "tenant": resource.tenant}
            for resource in resources
        ],
        "taskId": context.task_id,
        "tenant": context.tenant,
        "toolName": tool_name,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def isolation_attestation_payload(attestation: IsolationAttestation) -> bytes:
    """Return the canonical bytes a production evidence issuer signs.

    Every authority-bearing field is included and the signature itself is
    excluded. Providers and verifiers must use these exact UTF-8 bytes so a
    field cannot be reinterpreted, omitted, or substituted after issuance.
    Legacy attestations are rejected because they are not production evidence.
    """
    if attestation.issued_at is None or not all(
        (
            attestation.evidence_id,
            attestation.profile_digest,
            attestation.workload_ref,
            attestation.action_binding,
            attestation.key_id,
        )
    ):
        raise ValueError("canonical signing requires complete production evidence")
    payload = {
        "actionBinding": attestation.action_binding,
        "capabilities": dict(attestation.capabilities),
        "evidenceId": attestation.evidence_id,
        "expiresAt": attestation.expires_at.isoformat(),
        "issuedAt": attestation.issued_at.isoformat(),
        "keyId": attestation.key_id,
        "nonce": attestation.nonce,
        "profileDigest": attestation.profile_digest,
        "profileId": attestation.profile,
        "provider": attestation.provider,
        "schemaVersion": 1,
        "tenant": attestation.tenant,
        "toolName": attestation.tool_name,
        "workloadId": attestation.workload_id,
        "workloadRef": attestation.workload_ref,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_attestation(
    attestation: IsolationAttestation,
    context: ExecutionContext,
    tool_name: str,
    resources: tuple[Resource, ...],
    nonce: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Apply provider-neutral binding checks before a custom verifier runs."""
    current = now or datetime.now(UTC)
    return (
        isinstance(attestation, IsolationAttestation)
        and attestation.expires_at > current
        and attestation.nonce == nonce
        and attestation.tool_name == tool_name
        and attestation.tenant == context.tenant
        and all(resource.tenant == context.tenant for resource in resources)
    )


__all__ = [
    "CallbackIsolationVerifier",
    "IsolationAttestation",
    "IsolationBoundary",
    "IsolationConstraints",
    "IsolationCredentialMode",
    "IsolationNetworkMode",
    "IsolationProfile",
    "IsolationRequirement",
    "IsolationVerification",
    "IsolationVerifier",
    "ProductionIsolationVerifier",
    "isolation_action_binding",
    "isolation_attestation_payload",
    "validate_attestation",
]

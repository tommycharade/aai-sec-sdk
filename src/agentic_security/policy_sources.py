"""Verify and canonicalize policy-as-code sources without granting Git authority.

Git providers are untrusted transport. A deployment-owned verifier retrieves an
exact immutable revision and returns server-observed review and signature facts.
This module validates those facts and the closed policy source schema before a
control plane may create an ordinary, non-active policy draft.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import SecurityConfigurationError

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[a-z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SOURCE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_./-]{1,512}$")
_MAX_SOURCE_BYTES = 1_048_576
_MAX_COMPONENTS = 8


class PolicySourceVerificationError(SecurityConfigurationError):
    """Report malformed, unreviewed, unsigned, stale, or ambiguous policy source."""


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before they can obscure reviewed authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicySourceVerificationError("policy source JSON contains duplicate keys")
        result[key] = value
    return result


def _bounded_json(value: Any, *, depth: int = 0) -> None:
    """Reject structurally unbounded or non-canonical JSON values."""
    if depth > 12:
        raise PolicySourceVerificationError("policy source nesting is too deep")
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PolicySourceVerificationError("policy source contains a non-finite number")
        return
    if isinstance(value, list):
        if len(value) > 10_000:
            raise PolicySourceVerificationError("policy source collection is too large")
        for item in value:
            _bounded_json(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 2_000:
            raise PolicySourceVerificationError("policy source object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise PolicySourceVerificationError("policy source object key is invalid")
            _bounded_json(item, depth=depth + 1)
        return
    raise PolicySourceVerificationError("policy source contains a non-JSON value")


@dataclass(frozen=True, slots=True)
class PolicySourceDocument:
    """Closed schema-v1 policy-as-code document normalized to canonical JSON."""

    policy_id: str
    organization_id: str
    name: str
    component_refs: tuple[dict[str, Any], ...]
    local_configuration: dict[str, Any]

    @classmethod
    def from_bytes(cls, content: bytes) -> PolicySourceDocument:
        """Parse bounded UTF-8 JSON while rejecting duplicates and unknown fields.

        Args:
            content: Exact provider-returned blob bytes.

        Returns:
            A normalized immutable document suitable for composition.

        Raises:
            PolicySourceVerificationError: If encoding, JSON, schema, identity,
                component references, or configuration bounds are invalid.

        Side effects:
            None. Parsing never persists or activates policy authority.
        """
        if not isinstance(content, bytes) or not content or len(content) > _MAX_SOURCE_BYTES:
            raise PolicySourceVerificationError("policy source must be between 1 byte and 1 MiB")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicySourceVerificationError("policy source must be UTF-8 JSON") from exc
        try:
            value = json.loads(text, object_pairs_hook=_duplicate_rejector)
        except PolicySourceVerificationError:
            raise
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicySourceVerificationError("policy source is not valid JSON") from exc
        expected = {
            "schemaVersion",
            "policyId",
            "organizationId",
            "name",
            "componentRefs",
            "localConfiguration",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schemaVersion") != 1
        ):
            raise PolicySourceVerificationError("policy source schema is invalid")
        policy_id, organization_id, name = (
            value.get("policyId"),
            value.get("organizationId"),
            value.get("name"),
        )
        if not isinstance(policy_id, str) or _IDENTIFIER.fullmatch(policy_id) is None:
            raise PolicySourceVerificationError("policy source policy ID is invalid")
        if not isinstance(organization_id, str) or _IDENTIFIER.fullmatch(organization_id) is None:
            raise PolicySourceVerificationError("policy source organization ID is invalid")
        if not isinstance(name, str) or not name.strip() or len(name) > 256:
            raise PolicySourceVerificationError("policy source name is invalid")
        references = value.get("componentRefs")
        if not isinstance(references, list) or len(references) > _MAX_COMPONENTS:
            raise PolicySourceVerificationError("policy source componentRefs is invalid")
        normalized_refs: list[dict[str, Any]] = []
        identities: set[tuple[str, int, str]] = set()
        for reference in references:
            if not isinstance(reference, Mapping) or set(reference) != {
                "policyId",
                "version",
                "contentHash",
            }:
                raise PolicySourceVerificationError("policy source component reference is invalid")
            ref_id, version, content_hash = (
                reference.get("policyId"),
                reference.get("version"),
                reference.get("contentHash"),
            )
            if not isinstance(ref_id, str) or _IDENTIFIER.fullmatch(ref_id) is None:
                raise PolicySourceVerificationError("policy source component policy ID is invalid")
            if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
                raise PolicySourceVerificationError("policy source component version is invalid")
            if not isinstance(content_hash, str) or _SHA256.fullmatch(content_hash) is None:
                raise PolicySourceVerificationError(
                    "policy source component content hash is invalid"
                )
            identity = (ref_id, version, content_hash)
            if identity in identities:
                raise PolicySourceVerificationError(
                    "policy source component references must be unique"
                )
            identities.add(identity)
            normalized_refs.append(
                {"policyId": ref_id, "version": version, "contentHash": content_hash}
            )
        local = value.get("localConfiguration")
        if not isinstance(local, Mapping):
            raise PolicySourceVerificationError(
                "policy source localConfiguration must be an object"
            )
        _bounded_json(local)
        # A frozen dataclass does not freeze nested caller-owned mappings. A
        # canonical JSON round trip gives this trust boundary a defensive copy
        # so later mutation cannot change the bytes that were reviewed.
        copied_local = json.loads(
            json.dumps(local, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        )
        return cls(
            policy_id=policy_id,
            organization_id=organization_id,
            name=name.strip(),
            component_refs=tuple(normalized_refs),
            local_configuration=copied_local,
        )

    def wire(self) -> dict[str, Any]:
        """Return the exact public schema without provider or signing metadata."""
        copied_local = json.loads(
            json.dumps(
                self.local_configuration,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
        return {
            "schemaVersion": 1,
            "policyId": self.policy_id,
            "organizationId": self.organization_id,
            "name": self.name,
            "componentRefs": [dict(reference) for reference in self.component_refs],
            "localConfiguration": copied_local,
        }

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 JSON bytes used for hashes and signatures."""
        return json.dumps(
            self.wire(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @property
    def content_digest(self) -> str:
        """Return the SHA-256 of the canonical source document."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class PolicySourceRequest:
    """Browser-safe locator for one exact provider-owned Git blob."""

    repository: str
    commit_sha: str
    path: str

    def __post_init__(self) -> None:
        """Reject mutable revisions, ambiguous repositories, and path traversal."""
        if not isinstance(self.repository, str) or _REPOSITORY.fullmatch(self.repository) is None:
            raise PolicySourceVerificationError("policy source repository is invalid")
        if (
            not isinstance(self.commit_sha, str)
            or _GIT_OBJECT_ID.fullmatch(self.commit_sha) is None
        ):
            raise PolicySourceVerificationError("policy source commit must be a full object ID")
        if not isinstance(self.path, str) or _SOURCE_PATH.fullmatch(self.path) is None:
            raise PolicySourceVerificationError("policy source path is invalid")

    def wire(self) -> dict[str, str]:
        """Return the non-secret request representation retained for idempotency."""
        return {"repository": self.repository, "commitSha": self.commit_sha, "path": self.path}

    @property
    def request_digest(self) -> str:
        """Return a stable digest binding an import ID to one exact locator."""
        encoded = json.dumps(self.wire(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedPolicySource:
    """Server-observed provider evidence plus the exact retrieved source bytes."""

    provider: str
    repository: str
    commit_sha: str
    blob_sha: str
    path: str
    content: bytes
    pull_request: str
    reviewed_by: tuple[str, ...]
    signer_identity: str
    retrieved_at: int
    review_verified: bool = True
    signature_verified: bool = True

    def __post_init__(self) -> None:
        """Fail closed unless review, signature, location, and content are exact."""
        request = PolicySourceRequest(self.repository, self.commit_sha, self.path)
        del request
        if not isinstance(self.provider, str) or not self.provider or len(self.provider) > 64:
            raise PolicySourceVerificationError("policy source provider is invalid")
        if not isinstance(self.blob_sha, str) or _GIT_OBJECT_ID.fullmatch(self.blob_sha) is None:
            raise PolicySourceVerificationError("policy source blob ID is invalid")
        if self.review_verified is not True or self.signature_verified is not True:
            raise PolicySourceVerificationError(
                "policy source review and signature must be verified"
            )
        if (
            not isinstance(self.pull_request, str)
            or not self.pull_request
            or len(self.pull_request) > 512
        ):
            raise PolicySourceVerificationError("policy source pull request evidence is invalid")
        if (
            not isinstance(self.reviewed_by, tuple)
            or not self.reviewed_by
            or len(self.reviewed_by) > 50
            or any(
                not isinstance(item, str) or not item or len(item) > 256
                for item in self.reviewed_by
            )
            or len(set(self.reviewed_by)) != len(self.reviewed_by)
        ):
            raise PolicySourceVerificationError("policy source reviewers are invalid")
        if (
            not isinstance(self.signer_identity, str)
            or not self.signer_identity
            or len(self.signer_identity) > 256
        ):
            raise PolicySourceVerificationError("policy source signer identity is invalid")
        if (
            isinstance(self.retrieved_at, bool)
            or not isinstance(self.retrieved_at, int)
            or self.retrieved_at <= 0
        ):
            raise PolicySourceVerificationError("policy source retrieval time is invalid")
        PolicySourceDocument.from_bytes(self.content)

    @property
    def raw_content_digest(self) -> str:
        """Return the exact provider blob-byte SHA-256."""
        return hashlib.sha256(self.content).hexdigest()

    def evidence(self) -> dict[str, Any]:
        """Return bounded non-secret facts retained with the imported draft."""
        return {
            "schemaVersion": 1,
            "provider": self.provider,
            "repository": self.repository,
            "commitSha": self.commit_sha,
            "blobSha": self.blob_sha,
            "path": self.path,
            "rawContentDigest": self.raw_content_digest,
            "pullRequest": self.pull_request,
            "reviewedBy": list(self.reviewed_by),
            "signerIdentity": self.signer_identity,
            "reviewVerified": True,
            "signatureVerified": True,
            "retrievedAt": self.retrieved_at,
        }

    @property
    def evidence_digest(self) -> str:
        """Return a digest over every retained provider fact."""
        encoded = json.dumps(
            self.evidence(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


class PolicySourceVerifier(Protocol):
    """Deployment-owned adapter that retrieves and verifies one exact Git source."""

    def verify(self, request: PolicySourceRequest) -> VerifiedPolicySource:
        """Return server-observed content/evidence or raise without side effects."""


@dataclass(frozen=True, slots=True)
class PolicyExportSignature:
    """Deployment-owned signature over one canonical export provenance payload."""

    key_id: str
    algorithm: str
    signature: bytes
    signed_at: int

    def __post_init__(self) -> None:
        """Reject empty or structurally unsafe signing evidence."""
        if not isinstance(self.key_id, str) or not self.key_id or len(self.key_id) > 512:
            raise PolicySourceVerificationError("policy export signing key ID is invalid")
        if not isinstance(self.algorithm, str) or not self.algorithm or len(self.algorithm) > 64:
            raise PolicySourceVerificationError("policy export signing algorithm is invalid")
        if not isinstance(self.signature, bytes) or not 1 <= len(self.signature) <= 8_192:
            raise PolicySourceVerificationError("policy export signature is invalid")
        if (
            isinstance(self.signed_at, bool)
            or not isinstance(self.signed_at, int)
            or self.signed_at <= 0
        ):
            raise PolicySourceVerificationError("policy export signing time is invalid")

    def wire(self) -> dict[str, Any]:
        """Return the JSON-safe signing evidence without exposing private material."""
        return {
            "keyId": self.key_id,
            "algorithm": self.algorithm,
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "signedAt": self.signed_at,
        }


class PolicyExportSigner(Protocol):
    """Deployment-owned signer for canonical policy source export provenance."""

    def sign(self, payload: bytes) -> PolicyExportSignature:
        """Sign exact canonical bytes without returning private key material."""


class CallbackPolicyExportSigner:
    """Adapt an application-owned KMS/HSM callback to the export signer protocol."""

    def __init__(self, signer: Callable[[bytes], PolicyExportSignature]) -> None:
        """Create a signer without performing network or credential work."""
        self._signer = signer

    def sign(self, payload: bytes) -> PolicyExportSignature:
        """Sign bounded bytes and normalize all provider failures to fail closed."""
        if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_SOURCE_BYTES:
            raise PolicySourceVerificationError("policy export signing payload is invalid")
        try:
            result = self._signer(payload)
        except Exception as exc:
            raise PolicySourceVerificationError("policy export signing failed") from exc
        if not isinstance(result, PolicyExportSignature):
            raise PolicySourceVerificationError("policy export signer returned invalid evidence")
        return result


def constant_digest_equal(left: str, right: str) -> bool:
    """Compare externally supplied digests without data-dependent early exit."""
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


__all__ = [
    "CallbackPolicyExportSigner",
    "PolicyExportSignature",
    "PolicyExportSigner",
    "PolicySourceDocument",
    "PolicySourceRequest",
    "PolicySourceVerificationError",
    "PolicySourceVerifier",
    "VerifiedPolicySource",
    "constant_digest_equal",
]

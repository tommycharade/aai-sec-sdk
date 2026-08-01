"""Verify tenant-bound policy bundles before they become runtime authority.

The control plane may transport policy bytes, but transport authentication is
not the runtime trust anchor. This module verifies an immutable ECDSA signature
against deployment-pinned public keys and returns a typed bundle only after the
tenant, identity, version, content hash and configuration agree.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .errors import SecurityConfigurationError

_ALGORITHM: Final[str] = "ECDSA_SHA_256"
_SHA256: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KMS_KEY_ARN: Final[re.Pattern[str]] = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$"
)
_MAX_POLICY_BYTES: Final[int] = 1_000_000
_MAX_TRUST_BYTES: Final[int] = 128_000
_MAX_KEYS: Final[int] = 8
_MAX_DEPTH: Final[int] = 12
_MAX_COLLECTION_ITEMS: Final[int] = 2_000


class PolicyBundleVerificationError(SecurityConfigurationError):
    """Report an unsigned, altered, malformed or untrusted policy bundle.

    This exception intentionally carries no policy content, signature or public
    key material. Callers should stop or retain their last independently
    verified authority according to their documented outage policy.
    """


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Decode one JSON object while rejecting authority-confusing duplicates."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyBundleVerificationError("signed policy JSON contains duplicate keys")
        result[key] = value
    return result


def _bounded_json(value: object, *, depth: int = 0) -> None:
    """Reject non-JSON or structurally unbounded policy content before hashing."""
    if depth > _MAX_DEPTH:
        raise PolicyBundleVerificationError("signed policy nesting is too deep")
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
            raise PolicyBundleVerificationError("signed policy contains a non-finite number")
        return
    if isinstance(value, list):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise PolicyBundleVerificationError("signed policy collection is too large")
        for item in value:
            _bounded_json(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise PolicyBundleVerificationError("signed policy object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise PolicyBundleVerificationError("signed policy object key is invalid")
            _bounded_json(item, depth=depth + 1)
        return
    raise PolicyBundleVerificationError("signed policy contains a non-JSON value")


def canonical_policy_payload(
    *,
    tenant_id: str,
    policy_id: str,
    version: int,
    configuration: Mapping[str, Any],
) -> tuple[bytes, str]:
    """Return the canonical signed payload and its configuration SHA-256.

    Args:
        tenant_id: Constructor-owned tenant identity expected by the runtime.
        policy_id: Stable tenant-scoped policy identifier.
        version: Positive immutable policy version.
        configuration: Exact effective policy configuration to authorize.

    Returns:
        Canonical payload bytes and the canonical configuration hash.

    Raises:
        PolicyBundleVerificationError: If any identity or content is malformed,
            non-JSON, oversized or structurally unbounded.

    Side effects:
        None. This function never signs, persists or executes policy content.
    """
    if not isinstance(tenant_id, str) or _IDENTIFIER.fullmatch(tenant_id) is None:
        raise PolicyBundleVerificationError("signed policy tenant ID is invalid")
    if not isinstance(policy_id, str) or _IDENTIFIER.fullmatch(policy_id) is None:
        raise PolicyBundleVerificationError("signed policy ID is invalid")
    if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
        raise PolicyBundleVerificationError("signed policy version must be positive")
    if not isinstance(configuration, Mapping):
        raise PolicyBundleVerificationError("signed policy configuration must be an object")
    normalized = dict(configuration)
    _bounded_json(normalized)
    configuration_bytes = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    if len(configuration_bytes) > _MAX_POLICY_BYTES:
        raise PolicyBundleVerificationError("signed policy configuration is too large")
    content_hash = hashlib.sha256(configuration_bytes).hexdigest()
    payload = json.dumps(
        {
            "configuration": normalized,
            "contentHash": content_hash,
            "policyId": policy_id,
            "schemaVersion": 1,
            "tenantId": tenant_id,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return payload, content_hash


@dataclass(frozen=True, slots=True)
class TrustedPolicyKey:
    """One administrator-pinned P-256 policy verification key.

    The key is public but authority-sensitive. A process that can replace it
    can choose a different signer, so deployments must protect the trust-bundle
    file with administrator ownership and non-writable permissions.
    """

    key_id: str
    public_key_pem: str
    algorithm: str = _ALGORITHM

    def __post_init__(self) -> None:
        """Reject unknown identities, algorithms and non-P-256 public keys."""
        if not isinstance(self.key_id, str) or _KMS_KEY_ARN.fullmatch(self.key_id) is None:
            raise PolicyBundleVerificationError("policy trust key ID is not a KMS key ARN")
        if self.algorithm != _ALGORITHM:
            raise PolicyBundleVerificationError("policy trust key algorithm is unsupported")
        if not isinstance(self.public_key_pem, str) or not 1 <= len(self.public_key_pem) <= 16_384:
            raise PolicyBundleVerificationError("policy trust public key is invalid")
        try:
            key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError) as exc:
            raise PolicyBundleVerificationError("policy trust public key is malformed") from exc
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise PolicyBundleVerificationError("policy trust key must use P-256")

    def wire(self) -> dict[str, str]:
        """Return the bounded public representation suitable for JSON export."""
        return {
            "keyId": self.key_id,
            "algorithm": self.algorithm,
            "publicKeyPem": self.public_key_pem,
        }


@dataclass(frozen=True, slots=True)
class SignedPolicyBundle:
    """One verified-shape policy envelope returned by the control plane.

    Construction validates shape and hashes but does not establish authenticity.
    Call :meth:`PolicyTrustStore.verify` before using ``configuration`` as
    runtime authority.
    """

    tenant_id: str
    policy_id: str
    version: int
    configuration: dict[str, Any]
    content_hash: str
    key_id: str
    algorithm: str
    signature: bytes
    signed_at: int

    @classmethod
    def from_wire(cls, value: object) -> SignedPolicyBundle:
        """Parse one exact wire envelope without performing signature verification."""
        if not isinstance(value, Mapping) or set(value) != {
            "schemaVersion",
            "tenantId",
            "policyId",
            "version",
            "configuration",
            "contentHash",
            "integrity",
        }:
            raise PolicyBundleVerificationError("signed policy envelope schema is invalid")
        integrity = value.get("integrity")
        if not isinstance(integrity, Mapping) or set(integrity) != {
            "algorithm",
            "keyId",
            "signature",
            "signedAt",
        }:
            raise PolicyBundleVerificationError("signed policy integrity schema is invalid")
        if value.get("schemaVersion") != 1:
            raise PolicyBundleVerificationError("signed policy schema version is unsupported")
        payload, calculated_hash = canonical_policy_payload(
            tenant_id=value.get("tenantId"),  # type: ignore[arg-type]
            policy_id=value.get("policyId"),  # type: ignore[arg-type]
            version=value.get("version"),  # type: ignore[arg-type]
            configuration=value.get("configuration"),  # type: ignore[arg-type]
        )
        del payload
        content_hash = value.get("contentHash")
        if (
            not isinstance(content_hash, str)
            or _SHA256.fullmatch(content_hash) is None
            or not _constant_text_equal(content_hash, calculated_hash)
        ):
            raise PolicyBundleVerificationError("signed policy content hash is invalid")
        signature_value = integrity.get("signature")
        if not isinstance(signature_value, str) or not 1 <= len(signature_value) <= 1_024:
            raise PolicyBundleVerificationError("signed policy signature is invalid")
        try:
            signature = base64.b64decode(signature_value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise PolicyBundleVerificationError("signed policy signature is malformed") from exc
        signed_at = integrity.get("signedAt")
        if isinstance(signed_at, bool) or not isinstance(signed_at, int) or signed_at <= 0:
            raise PolicyBundleVerificationError("signed policy signing time is invalid")
        key_id, algorithm = integrity.get("keyId"), integrity.get("algorithm")
        if not isinstance(key_id, str) or _KMS_KEY_ARN.fullmatch(key_id) is None:
            raise PolicyBundleVerificationError("signed policy key ID is invalid")
        if algorithm != _ALGORITHM:
            raise PolicyBundleVerificationError("signed policy algorithm is unsupported")
        return cls(
            tenant_id=str(value["tenantId"]),
            policy_id=str(value["policyId"]),
            version=int(value["version"]),
            configuration=dict(value["configuration"]),
            content_hash=content_hash,
            key_id=key_id,
            algorithm=algorithm,
            signature=signature,
            signed_at=signed_at,
        )


def _constant_text_equal(left: str, right: str) -> bool:
    """Compare public digests without introducing inconsistent equality paths."""
    return hmac.compare_digest(left, right)


class PolicyTrustStore:
    """Bounded set of administrator-pinned policy verification keys."""

    def __init__(self, keys: tuple[TrustedPolicyKey, ...]) -> None:
        """Create an in-memory trust store without filesystem or network I/O."""
        if (
            not isinstance(keys, tuple)
            or not 1 <= len(keys) <= _MAX_KEYS
            or not all(isinstance(key, TrustedPolicyKey) for key in keys)
        ):
            raise PolicyBundleVerificationError("policy trust store requires one to eight keys")
        identities = [key.key_id for key in keys]
        if len(identities) != len(set(identities)):
            raise PolicyBundleVerificationError("policy trust key IDs must be unique")
        self._keys = {key.key_id: key for key in keys}

    @classmethod
    def from_json(cls, raw: str | bytes) -> PolicyTrustStore:
        """Parse one exact trust-bundle document without accepting duplicate keys."""
        encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
        if not isinstance(encoded, bytes) or not 1 <= len(encoded) <= _MAX_TRUST_BYTES:
            raise PolicyBundleVerificationError("policy trust bundle size is invalid")
        try:
            value = json.loads(encoded, object_pairs_hook=_duplicate_rejector)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PolicyBundleVerificationError("policy trust bundle is not valid JSON") from exc
        if not isinstance(value, dict) or set(value) != {"schemaVersion", "keys"}:
            raise PolicyBundleVerificationError("policy trust bundle schema is invalid")
        if value.get("schemaVersion") != 1 or not isinstance(value.get("keys"), list):
            raise PolicyBundleVerificationError("policy trust bundle version or keys are invalid")
        keys = []
        for item in value["keys"]:
            if not isinstance(item, dict) or set(item) != {"keyId", "algorithm", "publicKeyPem"}:
                raise PolicyBundleVerificationError("policy trust key schema is invalid")
            keys.append(
                TrustedPolicyKey(
                    key_id=item["keyId"],
                    algorithm=item["algorithm"],
                    public_key_pem=item["publicKeyPem"],
                )
            )
        return cls(tuple(keys))

    @classmethod
    def from_file(cls, path: str | Path, *, required_owner_id: int = 0) -> PolicyTrustStore:
        """Read a non-symlinked, administrator-owned trust bundle once.

        Args:
            path: Absolute deployment-owned trust-bundle path.
            required_owner_id: Required POSIX owner, root by default. Tests or
                explicitly user-owned pilots may pass the current numeric UID;
                production managed deployments must retain the default.

        Raises:
            PolicyBundleVerificationError: If path ownership, type, mode, size
                or content cannot be verified exactly.

        Side effects:
            Opens and closes one local file. It performs no network or writes.
        """
        trust_path = Path(path)
        if not trust_path.is_absolute() or not isinstance(required_owner_id, int):
            raise PolicyBundleVerificationError("policy trust path or owner is invalid")
        descriptor = -1
        try:
            no_follow = getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(trust_path, os.O_RDONLY | no_follow)
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != required_owner_id
                or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 1 <= details.st_size <= _MAX_TRUST_BYTES
            ):
                raise PolicyBundleVerificationError("policy trust file is not protected")
            encoded = os.read(descriptor, _MAX_TRUST_BYTES + 1)
        except OSError as exc:
            raise PolicyBundleVerificationError("policy trust file could not be read") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(encoded) > _MAX_TRUST_BYTES:
            raise PolicyBundleVerificationError("policy trust bundle is too large")
        return cls.from_json(encoded)

    def to_json(self) -> str:
        """Return deterministic public trust-bundle JSON for deployment tooling."""
        return json.dumps(
            {
                "schemaVersion": 1,
                "keys": [self._keys[key_id].wire() for key_id in sorted(self._keys)],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def verify(self, bundle: SignedPolicyBundle, *, expected_tenant_id: str) -> SignedPolicyBundle:
        """Verify one bundle locally and return it only after every check passes.

        The expected tenant is constructor-owned application context. It is not
        inferred from the response, model or project repository.
        """
        if not isinstance(bundle, SignedPolicyBundle):
            raise TypeError("bundle must be a SignedPolicyBundle")
        if (
            not isinstance(expected_tenant_id, str)
            or _IDENTIFIER.fullmatch(expected_tenant_id) is None
        ):
            raise PolicyBundleVerificationError("expected policy tenant is invalid")
        if bundle.tenant_id != expected_tenant_id:
            raise PolicyBundleVerificationError("signed policy tenant does not match this runtime")
        trusted = self._keys.get(bundle.key_id)
        if trusted is None or trusted.algorithm != bundle.algorithm:
            raise PolicyBundleVerificationError("signed policy key is not trusted")
        payload, content_hash = canonical_policy_payload(
            tenant_id=bundle.tenant_id,
            policy_id=bundle.policy_id,
            version=bundle.version,
            configuration=bundle.configuration,
        )
        if not _constant_text_equal(content_hash, bundle.content_hash):
            raise PolicyBundleVerificationError("signed policy content hash changed")
        key = serialization.load_pem_public_key(trusted.public_key_pem.encode("ascii"))
        assert isinstance(key, ec.EllipticCurvePublicKey)  # validated at trust-store construction
        digest = hashlib.sha256(payload).digest()
        try:
            key.verify(bundle.signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except InvalidSignature as exc:
            raise PolicyBundleVerificationError(
                "signed policy signature verification failed"
            ) from exc
        return bundle

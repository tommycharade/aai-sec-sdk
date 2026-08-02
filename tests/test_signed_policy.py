"""Adversarial tests for deployment-pinned signed policy authority."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentic_security import (
    PolicyBundleVerificationError,
    PolicyTrustStore,
    SignedPolicyBundle,
    TrustedPolicyKey,
    canonical_policy_payload,
)

KEY_ID = "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc"
MRK_ID = "arn:aws:kms:eu-west-2:123456789012:key/mrk-1234567890abcdef1234567890abcdef"
TENANT_ID = "tenant-a"


def _key_material() -> tuple[ec.EllipticCurvePrivateKey, TrustedPolicyKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_key, TrustedPolicyKey(key_id=KEY_ID, public_key_pem=public_pem)


def _wire_bundle(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    tenant_id: str = TENANT_ID,
    configuration: dict[str, object] | None = None,
) -> dict[str, object]:
    policy = configuration or {"runtime": {"allowedTools": ["read_repository"]}}
    payload, content_hash = canonical_policy_payload(
        tenant_id=tenant_id,
        policy_id="policy-safe",
        version=3,
        configuration=policy,
    )
    signature = private_key.sign(
        hashlib.sha256(payload).digest(),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    return {
        "schemaVersion": 1,
        "tenantId": tenant_id,
        "policyId": "policy-safe",
        "version": 3,
        "configuration": policy,
        "contentHash": content_hash,
        "integrity": {
            "algorithm": "ECDSA_SHA_256",
            "keyId": KEY_ID,
            "signature": base64.b64encode(signature).decode("ascii"),
            "signedAt": 1_786_000_000,
        },
    }


def test_valid_bundle_verifies_and_returns_exact_configuration() -> None:
    private_key, trusted_key = _key_material()
    bundle = SignedPolicyBundle.from_wire(_wire_bundle(private_key))

    verified = PolicyTrustStore((trusted_key,)).verify(bundle, expected_tenant_id=TENANT_ID)

    assert verified.configuration == {"runtime": {"allowedTools": ["read_repository"]}}
    assert verified.content_hash == bundle.content_hash


def test_multi_region_kms_identity_is_valid_trust_authority() -> None:
    private_key, trusted_key = _key_material()
    regional_key = TrustedPolicyKey(MRK_ID, trusted_key.public_key_pem)
    wire = _wire_bundle(private_key)
    integrity = wire["integrity"]
    assert isinstance(integrity, dict)
    integrity["keyId"] = MRK_ID
    bundle = SignedPolicyBundle.from_wire(wire)
    verified = PolicyTrustStore((regional_key,)).verify(bundle, expected_tenant_id=TENANT_ID)
    assert verified.key_id == MRK_ID


@pytest.mark.parametrize("field", ["tenantId", "policyId", "version", "configuration"])
def test_signed_authority_mutation_fails_closed(field: str) -> None:
    private_key, trusted_key = _key_material()
    wire = _wire_bundle(private_key)
    replacements: dict[str, object] = {
        "tenantId": "tenant-b",
        "policyId": "policy-other",
        "version": 4,
        "configuration": {"runtime": {"allowedTools": ["shell"]}},
    }
    wire[field] = replacements[field]
    if field == "configuration":
        _, wire["contentHash"] = canonical_policy_payload(
            tenant_id=TENANT_ID,
            policy_id="policy-safe",
            version=3,
            configuration=wire[field],  # type: ignore[arg-type]
        )

    with pytest.raises(PolicyBundleVerificationError):
        PolicyTrustStore((trusted_key,)).verify(
            SignedPolicyBundle.from_wire(wire), expected_tenant_id=TENANT_ID
        )


def test_response_tenant_cannot_choose_runtime_tenant() -> None:
    private_key, trusted_key = _key_material()
    bundle = SignedPolicyBundle.from_wire(_wire_bundle(private_key, tenant_id="tenant-b"))

    with pytest.raises(PolicyBundleVerificationError, match="does not match"):
        PolicyTrustStore((trusted_key,)).verify(bundle, expected_tenant_id=TENANT_ID)


def test_unknown_key_and_algorithm_are_rejected() -> None:
    private_key, _ = _key_material()
    _, generated_key = _key_material()
    other_key = TrustedPolicyKey(
        key_id=("arn:aws:kms:eu-west-2:123456789012:key/87654321-4321-4321-4321-cba987654321"),
        public_key_pem=generated_key.public_key_pem,
    )
    wire = _wire_bundle(private_key)

    with pytest.raises(PolicyBundleVerificationError, match="not trusted"):
        PolicyTrustStore((other_key,)).verify(
            SignedPolicyBundle.from_wire(wire), expected_tenant_id=TENANT_ID
        )

    wire["integrity"]["algorithm"] = "RSASSA_PSS_SHA_256"  # type: ignore[index]
    with pytest.raises(PolicyBundleVerificationError, match="unsupported"):
        SignedPolicyBundle.from_wire(wire)


def test_trust_store_rejects_duplicate_json_and_non_p256_key() -> None:
    _, trusted_key = _key_material()
    duplicate = (
        '{"schemaVersion":1,"schemaVersion":1,"keys":[' + json.dumps(trusted_key.wire()) + "]}"
    )
    with pytest.raises(PolicyBundleVerificationError, match="duplicate"):
        PolicyTrustStore.from_json(duplicate)

    rsa_like = (
        ec.generate_private_key(ec.SECP384R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    with pytest.raises(PolicyBundleVerificationError, match="P-256"):
        TrustedPolicyKey(key_id=KEY_ID, public_key_pem=rsa_like)


def test_configuration_rejects_non_finite_deep_and_oversized_content() -> None:
    with pytest.raises(PolicyBundleVerificationError, match="non-finite"):
        canonical_policy_payload(
            tenant_id=TENANT_ID,
            policy_id="policy-safe",
            version=1,
            configuration={"value": float("nan")},
        )

    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(14):
        nested: dict[str, object] = {}
        cursor["nested"] = nested
        cursor = nested
    with pytest.raises(PolicyBundleVerificationError, match="too deep"):
        canonical_policy_payload(
            tenant_id=TENANT_ID,
            policy_id="policy-safe",
            version=1,
            configuration=deep,
        )

    with pytest.raises(PolicyBundleVerificationError, match="too large"):
        canonical_policy_payload(
            tenant_id=TENANT_ID,
            policy_id="policy-safe",
            version=1,
            configuration={"value": "x" * 1_000_001},
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"tenant_id": "bad tenant"}, "tenant ID"),
        ({"policy_id": "bad/policy"}, "policy ID"),
        ({"version": True}, "version"),
        ({"configuration": []}, "configuration"),
    ],
)
def test_canonical_payload_rejects_malformed_authority(
    changes: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "policy_id": "policy-safe",
        "version": 1,
        "configuration": {},
    }
    values.update(changes)
    with pytest.raises(PolicyBundleVerificationError, match=message):
        canonical_policy_payload(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(schemaVersion=2), "schema version"),
        (lambda value: value.update(extra=True), "envelope schema"),
        (lambda value: value["integrity"].update(extra=True), "integrity schema"),
        (lambda value: value["integrity"].update(signature="%%%"), "malformed"),
        (lambda value: value["integrity"].update(signedAt=True), "signing time"),
        (lambda value: value["integrity"].update(keyId="alias/untrusted"), "key ID"),
    ],
)
def test_wire_envelope_rejects_ambiguous_or_malformed_metadata(
    mutation: Callable[[dict[str, Any]], None], message: str
) -> None:
    private_key, _ = _key_material()
    wire = _wire_bundle(private_key)
    mutation(wire)
    with pytest.raises(PolicyBundleVerificationError, match=message):
        SignedPolicyBundle.from_wire(wire)


def test_trusted_key_and_store_reject_invalid_construction() -> None:
    _, trusted_key = _key_material()
    with pytest.raises(PolicyBundleVerificationError, match="KMS key ARN"):
        TrustedPolicyKey("alias/not-a-key", trusted_key.public_key_pem)
    with pytest.raises(PolicyBundleVerificationError, match="unsupported"):
        TrustedPolicyKey(KEY_ID, trusted_key.public_key_pem, "unknown")
    with pytest.raises(PolicyBundleVerificationError, match="malformed"):
        TrustedPolicyKey(KEY_ID, "not pem")
    with pytest.raises(PolicyBundleVerificationError, match="one to eight"):
        PolicyTrustStore(())
    with pytest.raises(PolicyBundleVerificationError, match="unique"):
        PolicyTrustStore((trusted_key, trusted_key))


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"{}",
        b'{"schemaVersion":2,"keys":[]}',
        b'{"schemaVersion":1,"keys":[{}]}',
    ],
)
def test_trust_json_rejects_invalid_document(raw: bytes) -> None:
    with pytest.raises(PolicyBundleVerificationError):
        PolicyTrustStore.from_json(raw)


def test_verifier_rejects_invalid_expected_tenant() -> None:
    private_key, trusted_key = _key_material()
    bundle = SignedPolicyBundle.from_wire(_wire_bundle(private_key))
    with pytest.raises(PolicyBundleVerificationError, match="expected policy tenant"):
        PolicyTrustStore((trusted_key,)).verify(bundle, expected_tenant_id="bad tenant")


def test_trust_file_must_be_absolute_regular_and_not_writable(tmp_path: Path) -> None:
    _, trusted_key = _key_material()
    trust_path = tmp_path / "policy-trust.json"
    trust_path.write_text(PolicyTrustStore((trusted_key,)).to_json(), encoding="utf-8")
    trust_path.chmod(0o600)

    loaded = PolicyTrustStore.from_file(trust_path, required_owner_id=os.getuid())
    assert loaded.to_json() == PolicyTrustStore((trusted_key,)).to_json()

    trust_path.chmod(0o620)
    with pytest.raises(PolicyBundleVerificationError, match="not protected"):
        PolicyTrustStore.from_file(trust_path, required_owner_id=os.getuid())

    trust_path.chmod(0o600)
    symlink = tmp_path / "trust-link.json"
    symlink.symlink_to(trust_path)
    with pytest.raises(PolicyBundleVerificationError, match="could not be read"):
        PolicyTrustStore.from_file(symlink, required_owner_id=os.getuid())

    with pytest.raises(PolicyBundleVerificationError, match="path or owner"):
        PolicyTrustStore.from_file(Path("relative.json"), required_owner_id=os.getuid())

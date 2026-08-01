"""Contract tests for deployment-owned KMS public trust export."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from scripts.export_policy_trust_bundle import export_trust_bundle

from agentic_security import PolicyTrustStore

KEY_ID = "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc"


class FakeKms:
    """Return one exact synthetic AWS KMS GetPublicKey contract."""

    def __init__(self, public_key: bytes) -> None:
        self.public_key = public_key

    def get_public_key(self, *, KeyId: str) -> dict[str, object]:  # noqa: N803 - AWS shape.
        return {
            "KeyId": KeyId,
            "KeyUsage": "SIGN_VERIFY",
            "CustomerMasterKeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": self.public_key,
        }


def _public_der() -> bytes:
    return (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_exported_bundle_is_valid_deterministic_trust_material(tmp_path: Path) -> None:
    output = tmp_path / "policy-trust.json"

    fingerprint = export_trust_bundle(
        kms_client=FakeKms(_public_der()), key_id=KEY_ID, output=output
    )

    assert len(fingerprint) == 64
    assert output.stat().st_mode & 0o777 == 0o600
    trust = PolicyTrustStore.from_file(output, required_owner_id=os.getuid())
    assert KEY_ID in trust.to_json()
    with pytest.raises(FileExistsError):
        export_trust_bundle(kms_client=FakeKms(_public_der()), key_id=KEY_ID, output=output)


def test_export_rejects_wrong_kms_key_usage_without_writing(tmp_path: Path) -> None:
    class WrongUsage(FakeKms):
        def get_public_key(self, *, KeyId: str) -> dict[str, object]:  # noqa: N803
            value = super().get_public_key(KeyId=KeyId)
            value["KeyUsage"] = "ENCRYPT_DECRYPT"
            return value

    output = tmp_path / "policy-trust.json"
    with pytest.raises(RuntimeError, match="incompatible"):
        export_trust_bundle(kms_client=WrongUsage(_public_der()), key_id=KEY_ID, output=output)
    assert not output.exists()

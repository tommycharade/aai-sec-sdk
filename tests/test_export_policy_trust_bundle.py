"""Contract tests for deployment-owned KMS public trust export."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from scripts.export_policy_trust_bundle import export_trust_bundle

from agentic_security import PolicyTrustStore

KEY_ID = "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc"
# Synthetic P-256 public key derived from private scalar 1. A fixed public-only
# fixture keeps this contract deterministic and avoids involving key generation.
PUBLIC_DER = base64.b64decode(
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="
)
P384_PUBLIC_DER = base64.b64decode(
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f"
)


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
    return PUBLIC_DER


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


def test_export_rejects_public_key_with_wrong_actual_curve(tmp_path: Path) -> None:
    output = tmp_path / "policy-trust.json"

    with pytest.raises(RuntimeError, match="not P-256"):
        export_trust_bundle(kms_client=FakeKms(P384_PUBLIC_DER), key_id=KEY_ID, output=output)

    assert not output.exists()

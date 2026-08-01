"""Export the AWS KMS policy-signing public key for administrator installation.

The output contains public material only, but it is authority-sensitive: an
enrolled runtime trusts whichever keys an administrator installs. This command
never edits a project and refuses to overwrite an existing bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from agentic_security import PolicyTrustStore, TrustedPolicyKey  # noqa: E402


def export_trust_bundle(
    *,
    kms_client: object,
    key_id: str,
    output: Path,
) -> str:
    """Fetch, validate, and atomically write one non-secret public trust key.

    Returns:
        SHA-256 fingerprint of the DER SubjectPublicKeyInfo bytes.

    Side effects:
        Performs one KMS ``GetPublicKey`` request and creates one new file.
        It never requests signing or private key operations.
    """
    if not output.is_absolute():
        raise ValueError("policy trust output path must be absolute")
    if output.exists() or output.is_symlink():
        raise FileExistsError("policy trust output already exists")
    response = kms_client.get_public_key(KeyId=key_id)  # type: ignore[attr-defined]
    public_der = response.get("PublicKey")
    if (
        response.get("KeyId") != key_id
        or response.get("KeyUsage") != "SIGN_VERIFY"
        or response.get("KeySpec", response.get("CustomerMasterKeySpec")) != "ECC_NIST_P256"
        or response.get("SigningAlgorithms") != ["ECDSA_SHA_256"]
        or not isinstance(public_der, bytes)
    ):
        raise RuntimeError("KMS returned incompatible policy verification key metadata")
    key = serialization.load_der_public_key(public_der)
    curve = getattr(key, "curve", None)
    if (
        not isinstance(key, ec.EllipticCurvePublicKey)
        or getattr(curve, "name", None) != "secp256r1"
        or getattr(curve, "key_size", None) != 256
    ):
        raise RuntimeError("KMS policy verification key is not P-256")
    public_pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    content = PolicyTrustStore((TrustedPolicyKey(key_id, public_pem),)).to_json() + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temporary_name, output)
        os.unlink(temporary_name)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return hashlib.sha256(public_der).hexdigest()


def main() -> int:
    """Export one stack signing key using an explicitly selected AWS profile."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--key-arn", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import boto3

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    fingerprint = export_trust_bundle(
        kms_client=session.client("kms"),
        key_id=args.key_arn,
        output=args.output.expanduser().resolve(),
    )
    print(f"Exported policy trust bundle: {args.output.expanduser().resolve()}")
    print(f"Public key SHA-256: {fingerprint}")
    print("Install it with administrator ownership before onboarding, for example:")
    print("  sudo install -o root -g wheel -m 0644 <exported-file> <managed-path>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

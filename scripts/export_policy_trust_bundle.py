"""Export the AWS KMS policy-signing public key for administrator installation.

The output contains public material only, but it is authority-sensitive: an
enrolled runtime trusts whichever keys an administrator installs. This command
never edits a project and refuses to overwrite an existing bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from agentic_security import PolicyTrustStore, TrustedPolicyKey  # noqa: E402

_KEY_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):[0-9]{12}:key/"
    r"(?:[0-9a-f-]{36}|mrk-[0-9a-f]{32})$"
)


def _trusted_key(kms_client: object, key_id: str) -> tuple[TrustedPolicyKey, str]:
    """Fetch and validate one exact public KMS signing identity."""
    if not isinstance(key_id, str) or _KEY_ARN.fullmatch(key_id) is None:
        raise ValueError("policy trust key ID must be one exact KMS key ARN")
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
    return TrustedPolicyKey(key_id, public_pem), hashlib.sha256(public_der).hexdigest()


def export_trust_bundle_set(
    *,
    kms_keys: Sequence[tuple[object, str]],
    output: Path,
) -> dict[str, str]:
    """Atomically export one bounded overlapping set of public signing keys.

    Args:
        kms_keys: One to eight `(regional KMS client, exact key ARN)` pairs.
        output: New absolute administrator-managed destination.

    Returns:
        Mapping from exact key ARN to SHA-256 public-key fingerprint.

    Side effects:
        Performs one `GetPublicKey` request per key and creates one mode-0600
        file. It never requests a private operation or overwrites trust.
    """
    if not output.is_absolute():
        raise ValueError("policy trust output path must be absolute")
    if output.exists() or output.is_symlink():
        raise FileExistsError("policy trust output already exists")
    if not isinstance(kms_keys, Sequence) or not 1 <= len(kms_keys) <= 8:
        raise ValueError("policy trust export requires one to eight keys")
    identities = [key_id for _client, key_id in kms_keys]
    if len(identities) != len(set(identities)):
        raise ValueError("policy trust export key IDs must be unique")
    trusted: list[TrustedPolicyKey] = []
    fingerprints: dict[str, str] = {}
    for client, key_id in kms_keys:
        key, fingerprint = _trusted_key(client, key_id)
        trusted.append(key)
        fingerprints[key_id] = fingerprint
    content = PolicyTrustStore(tuple(trusted)).to_json() + "\n"
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
    return fingerprints


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
    return export_trust_bundle_set(kms_keys=((kms_client, key_id),), output=output)[key_id]


def main() -> int:
    """Export one stack signing key using an explicitly selected AWS profile."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument(
        "--region",
        help="Deprecated single-key Region check; each key ARN now selects its own KMS Region",
    )
    parser.add_argument("--key-arn", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import boto3

    session = boto3.Session(profile_name=args.profile)
    pairs: list[tuple[object, str]] = []
    for key_id in args.key_arn:
        match = _KEY_ARN.fullmatch(key_id)
        if match is None:
            parser.error("--key-arn must be one exact KMS key ARN")
        if args.region and len(args.key_arn) == 1 and args.region != match.group(1):
            parser.error("--region does not match the key ARN")
        pairs.append((session.client("kms", region_name=match.group(1)), key_id))
    fingerprints = export_trust_bundle_set(
        kms_keys=tuple(pairs),
        output=args.output.expanduser().resolve(),
    )
    print(f"Exported policy trust bundle: {args.output.expanduser().resolve()}")
    for key_id, fingerprint in fingerprints.items():
        print(f"Public key SHA-256 ({key_id}): {fingerprint}")
    print("Install it with administrator ownership before onboarding, for example:")
    print("  sudo install -o root -g wheel -m 0644 <exported-file> <managed-path>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

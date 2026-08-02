#!/usr/bin/env python3
"""Create a schema-v2 managed package with reviewed policy-signing trust.

The input package and trust bundle remain immutable. Both expected SHA-256
values are supplied out of band, and the output is a new mode-0600 file. This
operator tool performs no network calls, installation, publication or signer
cutover.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from agentic_security import (  # noqa: E402
    ManagedDeploymentPackage,
    PolicyTrustStore,
    SecurityConfigurationError,
)

_MAX_PACKAGE_BYTES = 3_000_000
_MAX_TRUST_BYTES = 128_000


class ManagedTrustUpgradeError(RuntimeError):
    """Report unsafe input or ambiguous output without changing authority."""


def _read_protected(path: Path, maximum: int, label: str) -> bytes:
    """Read one current-user-owned, non-writable regular file without links."""
    if not path.is_absolute() or path.is_symlink():
        raise ManagedTrustUpgradeError(f"{label} path is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or metadata.st_size > maximum
            ):
                raise ManagedTrustUpgradeError(f"{label} is not protected")
            encoded = stream.read(maximum + 1)
    except OSError as error:
        raise ManagedTrustUpgradeError(f"{label} cannot be read") from error
    if not encoded or len(encoded) > maximum:
        raise ManagedTrustUpgradeError(f"{label} exceeds its safe bound")
    return encoded


def upgrade_package(
    *,
    package_path: Path,
    expected_package_sha256: str,
    trust_path: Path,
    expected_trust_sha256: str,
    output: Path,
) -> ManagedDeploymentPackage:
    """Verify both inputs and exclusively write one canonical schema-v2 package."""
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ManagedTrustUpgradeError("output must be a new absolute path")
    package_bytes = _read_protected(package_path, _MAX_PACKAGE_BYTES, "managed package")
    trust_bytes = _read_protected(trust_path, _MAX_TRUST_BYTES, "policy trust bundle")
    if hashlib.sha256(trust_bytes).hexdigest() != expected_trust_sha256:
        raise ManagedTrustUpgradeError("policy trust digest does not match")
    try:
        package = ManagedDeploymentPackage.from_json(
            package_bytes, expected_package_sha256=expected_package_sha256
        )
        trust = PolicyTrustStore.from_json(trust_bytes.decode("utf-8"))
        upgraded = package.with_policy_trust(trust)
    except (UnicodeDecodeError, SecurityConfigurationError, TypeError, ValueError) as error:
        raise ManagedTrustUpgradeError("managed package trust upgrade failed") from error
    encoded = upgraded.to_json()
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ManagedTrustUpgradeError("schema-v2 package could not be created") from error
    return upgraded


def main() -> int:
    """Parse explicit digest-bound inputs and print non-secret rollout metadata."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--trust-bundle", type=Path, required=True)
    parser.add_argument("--expected-trust-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    upgraded = upgrade_package(
        package_path=arguments.package.expanduser().resolve(),
        expected_package_sha256=arguments.expected_package_sha256,
        trust_path=arguments.trust_bundle.expanduser().resolve(),
        expected_trust_sha256=arguments.expected_trust_sha256,
        output=arguments.output.expanduser().resolve(),
    )
    print(f"Schema-v2 package: {arguments.output.expanduser().resolve()}")
    print(f"Package SHA-256: {upgraded.package_sha256}")
    print(f"Policy trust SHA-256: {upgraded.policy_trust_bundle_sha256}")
    print("Signer authority was not changed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManagedTrustUpgradeError as error:
        print(f"Managed trust upgrade failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error

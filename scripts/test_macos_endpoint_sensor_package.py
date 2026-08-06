#!/usr/bin/env python3
"""Run disposable macOS package assembly acceptance with the real pkgbuild tool.

The command uses only checked-in sensor source copied into a temporary executable
and creates an unsigned package that is deleted before exit. It proves package
assembly and payload confinement, not release provenance, code signing, MDM
installation, sensor execution or enterprise coverage.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from scripts import build_macos_endpoint_sensor_package as package  # noqa: E402

_EXPECTED_PAYLOAD = {
    "Library/Application Support/AAI Security/bin/aai-endpoint-evidence",
    "Library/Application Support/AAI Security/package-metadata.json",
    "Library/LaunchDaemons/com.aai-security.endpoint-evidence.plist",
}


def main() -> int:
    """Build and inspect one disposable package without retaining local paths."""
    if platform.system() != "Darwin":
        print("macOS endpoint package acceptance skipped: a macOS host is required.")
        return 77
    source = Path(__file__).with_name("collect_endpoint_evidence.py")
    with tempfile.TemporaryDirectory(prefix="aai-macos-package-acceptance-") as name:
        root = Path(name)
        sensor = root / "aai-endpoint-evidence"
        encoded = source.read_bytes()
        sensor.write_bytes(encoded)
        sensor.chmod(0o700)
        output_root = root / "output"
        output_root.mkdir(mode=0o700)
        output = output_root / "aai-endpoint-evidence.pkg"
        result = package.build_package(
            sensor_executable=sensor,
            expected_sensor_sha256=hashlib.sha256(encoded).hexdigest(),
            version="1.0.0",
            output=output,
            allow_unsigned=True,
        )
        try:
            # The executable path is fixed; only the validated temporary package
            # path is variable at this real-tool acceptance boundary.
            inspection = subprocess.run(  # noqa: S603
                ["/usr/sbin/pkgutil", "--payload-files", str(output)],
                check=False,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("macOS package payload inspection could not run") from error
        if inspection.returncode != 0:
            raise RuntimeError("macOS package payload inspection failed")
        payload = {
            line.strip().removeprefix("./").rstrip("/")
            for line in inspection.stdout.splitlines()
            if line
        }
        if not _EXPECTED_PAYLOAD.issubset(payload) or any(
            marker in item.lower() for item in payload for marker in ("secret", "key-id")
        ):
            raise RuntimeError("macOS package payload was incomplete or contained credentials")
        if result.signed or result.package_size_bytes <= 0:
            raise RuntimeError("macOS package acceptance returned an invalid result")
        if output.stat().st_uid != os.getuid() or output.stat().st_mode & 0o022:
            raise RuntimeError("macOS package output protection was invalid")
    print(
        "macOS endpoint package acceptance passed: real pkgbuild assembly, fixed launchd "
        "payload, credential exclusion, protected output and disposable unsigned test posture."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

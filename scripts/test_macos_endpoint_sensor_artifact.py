#!/usr/bin/env python3
"""Build and verify one disposable real macOS endpoint sensor executable.

The command requires the exact dependencies in ``requirements-sensor-build.txt``
and uses ad-hoc signing plus the measured test-only library-validation
entitlement. It proves local freezing, architecture, signature and command
behavior; it does not create a production release or Developer ID evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import sys
import tempfile
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from scripts import build_macos_endpoint_sensor_artifact as artifact  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    """Build the explicit source-revision acceptance command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--version", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Build, execute and independently verify one disposable native artifact."""
    arguments = _parser().parse_args(argv)
    if platform.system() != "Darwin" or platform.machine() not in {"arm64", "x86_64"}:
        print("macOS sensor artifact acceptance skipped: supported macOS hardware is required.")
        return 77
    source = Path(__file__).with_name("collect_endpoint_evidence.py")
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="aai-sensor-artifact-acceptance-") as temporary_name:
        output = Path(temporary_name) / f"sensor-{platform.machine()}"
        built = artifact.build_artifact(
            source=source,
            expected_source_sha256=source_sha256,
            expected_python_version=platform.python_version(),
            version=arguments.version,
            source_commit=arguments.source_commit,
            architecture=platform.machine(),
            output_directory=output,
            allow_adhoc=True,
        )
        verified = artifact.verify_artifact(
            artifact_directory=output,
            expected_manifest_sha256=built.manifest_sha256,
            expected_version=arguments.version,
            expected_source_commit=arguments.source_commit,
            expected_source_sha256=source_sha256,
            expected_python_version=platform.python_version(),
            expected_architecture=platform.machine(),
            allow_adhoc=True,
        )
        if verified != built:
            raise RuntimeError("macOS sensor artifact verification result changed")
    print(
        "macOS sensor artifact acceptance passed: pinned real PyInstaller build, exact "
        "architecture, measured ad-hoc test signature, protected extraction, frozen CLI "
        "execution and independent manifest verification."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

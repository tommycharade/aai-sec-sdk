"""Regression tests for release evidence bundle construction."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


def test_checksum_manifest_covers_evidence_files_and_excludes_itself(tmp_path: Path) -> None:
    """Every bundle file present before checksum generation receives a digest."""
    files = {
        "agentic_security_sdk-1.1.0-py3-none-any.whl": b"wheel",
        "agentic_security_sdk-1.1.0.tar.gz": b"source",
        "evidence.json": b'{"status":"verified"}\n',
        "results.txt": b"mutation evidence\n",
        "RELEASE-METADATA.json": b'{"tag":"v1.1.0"}\n',
        "SBOM-MANIFEST.json": b'{"subjects":[]}\n',
    }
    for name, contents in files.items():
        (tmp_path / name).write_bytes(contents)

    subprocess.run(  # noqa: S603 - test invokes the checked-in script with a temp directory
        [sys.executable, "scripts/write_checksums.py", str(tmp_path)],
        check=True,
    )

    entries = {}
    for line in (tmp_path / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        entries[name] = digest
    assert set(entries) == set(files)
    assert "SHA256SUMS" not in entries
    for name, contents in files.items():
        assert entries[name] == hashlib.sha256(contents).hexdigest()

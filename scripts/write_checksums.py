"""Write a deterministic checksum manifest without self-inclusion."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> int:
    """Hash every release evidence file except the checksum manifest itself."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory
    files = sorted(
        path for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    )
    if not files:
        raise ValueError("no release evidence files found")
    manifest = (
        "\n".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in files)
        + "\n"
    )
    (directory / "SHA256SUMS").write_text(manifest, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

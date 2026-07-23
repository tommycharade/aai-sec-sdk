"""Validate that built distributions contain required legal metadata."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


def names(path: Path) -> list[str]:
    """Return member names from a wheel or source archive."""
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    with tarfile.open(path) as archive:
        return archive.getnames()


def main() -> int:
    """Fail when no artifacts or required license files are present."""
    artifacts = list(Path("dist").glob("*.whl")) + list(Path("dist").glob("*.tar.gz"))
    if not artifacts:
        print("No distribution artifacts found.")
        return 1
    required = ("LICENSE", "NOTICE")
    for artifact in artifacts:
        members = names(artifact)
        if not all(any(member.endswith(item) for member in members) for item in required):
            print(f"{artifact} is missing LICENSE or NOTICE")
            return 1
    print(f"Validated legal metadata in {len(artifacts)} distribution artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

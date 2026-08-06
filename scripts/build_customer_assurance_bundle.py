"""Build a deterministic, self-describing customer assurance release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import date
from pathlib import Path

from scripts.check_customer_assurance_pack import (
    ROOT,
    load_customer_assurance_pack,
    validate_customer_assurance_pack,
)

BUNDLE_NAME = "customer-assurance-pack.zip"
MANIFEST_NAME = "BUNDLE-MANIFEST.json"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _digest(contents: bytes) -> str:
    """Return the SHA-256 digest used by the bundle's internal manifest."""
    return hashlib.sha256(contents).hexdigest()


def build_bundle(output: Path, *, repository_root: Path = ROOT) -> Path:
    """Write the canonical pack and evidence docs with reproducible ZIP metadata."""
    pack_path = repository_root / "assurance/customer-assurance-pack.json"
    pack = load_customer_assurance_pack(pack_path)
    validate_customer_assurance_pack(pack, repository_root=repository_root, today=date.today())

    relative_paths = {"assurance/customer-assurance-pack.json"}
    relative_paths.update(document["path"] for document in pack["documents"])
    payload = {
        relative_path: (repository_root / relative_path).read_bytes()
        for relative_path in sorted(relative_paths)
    }
    bundle_manifest = {
        "schema_version": 1,
        "pack_id": pack["pack_id"],
        "approved_at": pack["approval"]["approved_at"],
        "next_review_due": pack["approval"]["next_review_due"],
        "files": [
            {"path": path, "sha256": _digest(contents)} for path, contents in payload.items()
        ],
    }
    payload[MANIFEST_NAME] = (json.dumps(bundle_manifest, indent=2, sort_keys=True) + "\n").encode()

    output.mkdir(parents=True, exist_ok=True)
    destination = output / BUNDLE_NAME
    with zipfile.ZipFile(destination, "w") as archive:
        for name, contents in sorted(payload.items()):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            # Stored entries avoid zlib-version variance while fixed metadata
            # prevents host timestamps and permissions changing the release hash.
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, contents)
    return destination


def main() -> int:
    """Build the assurance archive in the requested release directory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    destination = build_bundle(args.directory)
    print(f"Built deterministic customer assurance bundle: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

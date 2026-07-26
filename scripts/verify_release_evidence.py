"""Independently verify checksums, SBOM bindings, and release source identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    """Return the SHA-256 digest of one evidence file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    """Raise a consistent fail-closed verification error."""
    raise ValueError(message)


def main() -> int:
    """Verify every release subject and its associated evidence."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--allow-untagged", action="store_true")
    args = parser.parse_args()
    directory = args.directory
    artifacts = sorted(
        path
        for path in directory.iterdir()
        if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    if len(artifacts) < 2:
        fail("wheel and source archive subjects are required")

    checksum_file = directory / "SHA256SUMS"
    manifest_file = directory / "SBOM-MANIFEST.json"
    metadata_file = directory / "RELEASE-METADATA.json"
    for path in (checksum_file, manifest_file, metadata_file):
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"missing or empty evidence file: {path.name}")

    checksums: dict[str, str] = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or match.group(2) in checksums:
            fail("malformed or duplicate checksum entry")
        assert match is not None
        checksums[match.group(2)] = match.group(1)
    evidence_files = {path.name for path in directory.iterdir() if path.name != checksum_file.name}
    if set(checksums) != evidence_files:
        fail("checksum manifest is stale, truncated, or contains unexpected files")
    for name, expected in checksums.items():
        if digest(directory / name) != expected:
            fail(f"checksum mismatch: {name}")

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    entries = {entry["artifact"]: entry for entry in manifest.get("subjects", [])}
    if set(entries) != {path.name for path in artifacts}:
        fail("SBOM manifest does not cover exactly the release subjects")
    sbom_files = {path.name for path in directory.iterdir() if path.name.endswith(".sbom.json")}
    if {entry["sbom"] for entry in entries.values()} != sbom_files:
        fail("SBOM manifest has missing or unassociated SBOM files")
    for artifact in artifacts:
        entry = entries[artifact.name]
        sbom = directory / entry["sbom"]
        if sbom.parent != directory:
            fail(f"SBOM path escapes release directory: {sbom.name}")
        if not sbom.is_file() or entry["artifact_sha256"] != digest(artifact):
            fail(f"SBOM subject hash mismatch: {artifact.name}")
        if entry["sbom_sha256"] != digest(sbom):
            fail(f"SBOM hash mismatch: {sbom.name}")
        document = json.loads(sbom.read_text(encoding="utf-8"))
        if document.get("bomFormat") != "CycloneDX" or not document.get("specVersion"):
            fail(f"SBOM is not a complete CycloneDX document: {sbom.name}")
        if not isinstance(document.get("components"), list):
            fail(f"SBOM has no component inventory: {sbom.name}")
        properties = document.get("metadata", {}).get("properties", [])
        bound = {item.get("name"): item.get("value") for item in properties}
        if bound.get("release:artifact-filename") != artifact.name:
            fail(f"SBOM is not bound to artifact: {artifact.name}")
        if bound.get("release:artifact-sha256") != digest(artifact):
            fail(f"SBOM artifact binding hash mismatch: {artifact.name}")

    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    if metadata.get("commit") != args.commit or metadata.get("tag") != args.tag:
        fail("release metadata commit/tag does not match the verification inputs")
    if sorted(metadata.get("subjects", [])) != [path.name for path in artifacts]:
        fail("release metadata subject list is incomplete or stale")
    head = subprocess.run(  # noqa: S603, S607 - fixed local git argv
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    tag = args.tag
    if not args.allow_untagged:
        tag = subprocess.run(  # noqa: S603, S607 - fixed local git argv
            ["git", "describe", "--exact-match", "--tags", args.tag],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    if head != args.commit or (not args.allow_untagged and tag != args.tag):
        fail("checked-out source is not the declared clean commit/tag")
    if subprocess.run(  # noqa: S603, S607 - fixed local git argv
        ["git", "status", "--porcelain"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout:
        fail("source checkout is dirty")
    print(f"Verified {len(artifacts)} artifact subjects, SBOM bindings, checksums, and tag {tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

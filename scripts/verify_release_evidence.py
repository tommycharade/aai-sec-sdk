"""Independently verify checksums, SBOM bindings, and release source identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any

ASSURANCE_BUNDLE = "customer-assurance-pack.zip"
ASSURANCE_MANIFEST = "BUNDLE-MANIFEST.json"
ASSURANCE_PACK = "assurance/customer-assurance-pack.json"
ROOT = Path(__file__).resolve().parents[1]
MAX_ASSURANCE_FILES = 64
MAX_ASSURANCE_FILE_BYTES = 2 * 1024 * 1024
MAX_ASSURANCE_TOTAL_BYTES = 8 * 1024 * 1024


def digest(path: Path) -> str:
    """Return the SHA-256 digest of one evidence file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    """Raise a consistent fail-closed verification error."""
    raise ValueError(message)


def _strict_json(contents: bytes, label: str) -> Any:
    """Parse bounded release JSON without duplicate keys or non-finite values."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate field: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        fail(f"{label} contains non-finite number: {value}")

    try:
        return json.loads(
            contents,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSON")
        raise AssertionError("unreachable") from error


def verify_assurance_bundle(path: Path, *, repository_root: Path = ROOT) -> None:
    """Verify bounded membership, hashes, claims, and exact tagged-source bytes."""
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"missing or empty evidence file: {path.name}")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ASSURANCE_FILES:
            fail("assurance bundle contains too many files")
        if any(member.file_size > MAX_ASSURANCE_FILE_BYTES for member in members):
            fail("assurance bundle contains an oversized file")
        if sum(member.file_size for member in members) > MAX_ASSURANCE_TOTAL_BYTES:
            fail("assurance bundle exceeds the uncompressed size limit")
        names = [member.filename for member in members]
        if len(names) != len(set(names)) or ASSURANCE_MANIFEST not in names:
            fail("assurance bundle has duplicate files or no internal manifest")
        if any(
            Path(name).is_absolute() or ".." in Path(name).parts or name.endswith("/")
            for name in names
        ):
            fail("assurance bundle contains an unsafe path")
        manifest = _strict_json(archive.read(ASSURANCE_MANIFEST), "assurance bundle manifest")
        if (
            manifest.get("schema_version") != 1
            or manifest.get("pack_id") != "aai-security-customer-assurance"
        ):
            fail("assurance bundle identity is invalid")
        entries = manifest.get("files")
        if not isinstance(entries, list):
            fail("assurance bundle file manifest is invalid")
        expected: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                fail("assurance bundle file entry is invalid")
            name = entry["path"]
            checksum = entry["sha256"]
            if (
                not isinstance(name, str)
                or name in expected
                or not isinstance(checksum, str)
                or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
            ):
                fail("assurance bundle file entry is malformed or duplicated")
            expected[name] = checksum
        if set(names) != set(expected) | {ASSURANCE_MANIFEST}:
            fail("assurance bundle membership does not match its manifest")
        if ASSURANCE_PACK not in expected:
            fail("assurance bundle omits the canonical pack")
        for name, expected_digest in expected.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected_digest:
                fail(f"assurance bundle hash mismatch: {name}")
        pack = _strict_json(archive.read(ASSURANCE_PACK), "customer assurance pack")
        if (
            not isinstance(pack, dict)
            or pack.get("schema_version") != 2
            or pack.get("pack_id") != "aai-security-customer-assurance"
        ):
            fail("customer assurance pack identity is invalid")
        documents = pack.get("documents")
        if not isinstance(documents, list):
            fail("customer assurance pack document inventory is invalid")
        source_paths = {ASSURANCE_PACK}
        for document in documents:
            if not isinstance(document, dict) or set(document) != {"id", "path", "status"}:
                fail("customer assurance pack document entry is invalid")
            source_path = document["path"]
            if not isinstance(source_path, str) or source_path in source_paths:
                fail("customer assurance pack document path is malformed or duplicated")
            source_paths.add(source_path)
        if source_paths != set(expected):
            fail("assurance bundle does not match the pack document inventory")
        vulnerability = pack.get("vulnerability_management")
        if not isinstance(vulnerability, dict) or set(vulnerability) != {
            "policy_path",
            "synthetic_rehearsal_path",
        }:
            fail("customer assurance vulnerability authority is invalid")
        if not set(vulnerability.values()).issubset(source_paths):
            fail("customer assurance vulnerability authority is absent from the bundle")
        for name in source_paths:
            source = repository_root / name
            if not source.is_file() or source.read_bytes() != archive.read(name):
                fail(f"assurance bundle source mismatch: {name}")


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
    verify_assurance_bundle(directory / ASSURANCE_BUNDLE)

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

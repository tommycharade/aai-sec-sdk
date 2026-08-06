"""Tests for immutable customer assurance release evidence."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from scripts.build_customer_assurance_bundle import build_bundle
from scripts.verify_release_evidence import verify_assurance_bundle


def test_assurance_bundle_is_reproducible_and_verifiable(tmp_path: Path) -> None:
    first = build_bundle(tmp_path / "first")
    second = build_bundle(tmp_path / "second")
    assert (
        hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    )
    verify_assurance_bundle(first)
    with zipfile.ZipFile(first) as archive:
        assert {
            "security/vulnerability-management-policy.json",
            "security/vulnerability-rehearsal.example.json",
            "docs/enterprise-trust-pack.md",
            "docs/production-readiness.md",
        }.issubset(archive.namelist())


def test_assurance_bundle_tampering_is_rejected(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    replacement = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(replacement, "w") as target:
        for name in source.namelist():
            contents = source.read(name)
            if name == "SECURITY.md":
                contents += b"tampered\n"
            target.writestr(name, contents)
    with pytest.raises(ValueError, match="hash mismatch: SECURITY.md"):
        verify_assurance_bundle(replacement)


def test_assurance_bundle_unknown_file_is_rejected(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    with zipfile.ZipFile(bundle, "a") as archive:
        archive.writestr("unreviewed.txt", "not in the manifest")
    with pytest.raises(ValueError, match="membership does not match"):
        verify_assurance_bundle(bundle)


def test_self_consistent_substitution_is_rejected_against_tagged_source(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    replacement = tmp_path / "substituted.zip"
    with zipfile.ZipFile(bundle) as source:
        payload = {name: source.read(name) for name in source.namelist()}
    changed_name = "docs/customer-assurance-pack.md"
    payload[changed_name] += b"\nsubstituted claim\n"
    internal = json.loads(payload["BUNDLE-MANIFEST.json"])
    for entry in internal["files"]:
        if entry["path"] == changed_name:
            entry["sha256"] = hashlib.sha256(payload[changed_name]).hexdigest()
    payload["BUNDLE-MANIFEST.json"] = (
        json.dumps(internal, indent=2, sort_keys=True) + "\n"
    ).encode()
    with zipfile.ZipFile(replacement, "w") as archive:
        for name, contents in payload.items():
            archive.writestr(name, contents)
    with pytest.raises(ValueError, match=f"source mismatch: {changed_name}"):
        verify_assurance_bundle(replacement)


def test_duplicate_internal_manifest_field_is_rejected(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    replacement = tmp_path / "duplicate-manifest.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(replacement, "w") as target:
        for name in source.namelist():
            contents = source.read(name)
            if name == "BUNDLE-MANIFEST.json":
                contents = contents.replace(
                    b'"schema_version": 1',
                    b'"schema_version": 1, "schema_version": 1',
                    1,
                )
            target.writestr(name, contents)
    with pytest.raises(ValueError, match="duplicate field: schema_version"):
        verify_assurance_bundle(replacement)


def test_oversized_assurance_member_is_rejected_before_read(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    with zipfile.ZipFile(bundle, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("oversized.txt", b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="oversized file"):
        verify_assurance_bundle(bundle)

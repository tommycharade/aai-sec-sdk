"""Tests for immutable customer assurance release evidence."""

from __future__ import annotations

import hashlib
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

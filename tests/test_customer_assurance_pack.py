"""Adversarial tests for buyer-facing assurance claims and review expiry."""

from __future__ import annotations

from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from scripts.check_customer_assurance_pack import (
    AssurancePackError,
    load_customer_assurance_pack,
    validate_customer_assurance_pack,
)


def _repository_root() -> Path:
    """Locate the checkout under normal and mutation-test paths."""
    for candidate in Path(__file__).resolve().parents:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("repository root containing .git was not found")


ROOT = _repository_root()
TODAY = date(2026, 8, 5)


def _manifest() -> dict[str, Any]:
    """Return an isolated copy of the reviewed manifest."""
    return deepcopy(load_customer_assurance_pack(ROOT / "assurance/customer-assurance-pack.json"))


def test_checked_in_customer_assurance_pack_is_current_and_honest() -> None:
    validate_customer_assurance_pack(_manifest(), repository_root=ROOT, today=TODAY)


def test_expired_review_fails_closed() -> None:
    manifest = _manifest()
    manifest["approval"]["next_review_due"] = "2026-08-04"
    with pytest.raises(AssurancePackError, match="review is overdue"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_weakened_critical_remediation_target_is_rejected() -> None:
    manifest = _manifest()
    manifest["vulnerability_management"]["severities"]["critical"]["remediation_days"] = 30
    with pytest.raises(AssurancePackError, match="critical SLA exceeds"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_false_certification_without_reviewed_evidence_is_rejected() -> None:
    manifest = _manifest()
    manifest["independent_assurance"]["soc2_type_ii"]["status"] = "certified"
    with pytest.raises(AssurancePackError, match="requires a reviewed evidence document"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_missing_assurance_document_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    with pytest.raises(AssurancePackError, match="assurance document is missing"):
        validate_customer_assurance_pack(manifest, repository_root=tmp_path, today=TODAY)


def test_unknown_claim_field_cannot_bypass_review() -> None:
    manifest = _manifest()
    manifest["approval"]["self_attested_certified"] = True
    with pytest.raises(AssurancePackError, match="approval keys"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_nested_path_traversal_is_rejected() -> None:
    manifest = _manifest()
    manifest["documents"][0]["path"] = "docs/../../outside.md"
    with pytest.raises(AssurancePackError, match="path is unsafe"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_published_sla_cannot_drift_from_machine_readable_commitment(tmp_path: Path) -> None:
    manifest = _manifest()
    for document in manifest["documents"]:
        source = ROOT / document["path"]
        target = tmp_path / document["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    for evidence in manifest["guarantees"]:
        source = ROOT / evidence["evidence"]
        target = tmp_path / evidence["evidence"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(source.read_bytes())
    security = tmp_path / "SECURITY.md"
    security.write_text(
        security.read_text(encoding="utf-8").replace(
            "| Critical | 24 hours |", "| Critical | 72 hours |"
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssurancePackError, match="does not match the assurance SLA"):
        validate_customer_assurance_pack(manifest, repository_root=tmp_path, today=TODAY)

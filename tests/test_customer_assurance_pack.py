"""Adversarial tests for buyer-facing assurance claims and review expiry."""

from __future__ import annotations

import json
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


def _copy_pack_inputs(manifest: dict[str, Any], destination: Path) -> None:
    """Copy only reviewed pack inputs into an isolated adversarial fixture."""
    paths = {document["path"] for document in manifest["documents"]}
    paths.update(evidence["evidence"] for evidence in manifest["guarantees"])
    for relative_path in paths:
        source = ROOT / relative_path
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


def test_checked_in_customer_assurance_pack_is_current_and_honest() -> None:
    validate_customer_assurance_pack(_manifest(), repository_root=ROOT, today=TODAY)


def test_expired_review_fails_closed() -> None:
    manifest = _manifest()
    manifest["approval"]["next_review_due"] = "2026-08-04"
    with pytest.raises(AssurancePackError, match="review is overdue"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_weakened_critical_remediation_target_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    _copy_pack_inputs(manifest, tmp_path)
    policy_path = tmp_path / manifest["vulnerability_management"]["policy_path"]
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["serviceLevels"]["critical"]["remediationDays"] = 30
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(AssurancePackError, match="code-owned maximum"):
        validate_customer_assurance_pack(manifest, repository_root=tmp_path, today=TODAY)


def test_false_certification_without_reviewed_evidence_is_rejected() -> None:
    manifest = _manifest()
    manifest["independent_assurance"]["soc2_type_ii"]["status"] = "certified"
    with pytest.raises(AssurancePackError, match="requires independent evidence"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_technical_document_cannot_masquerade_as_independent_evidence() -> None:
    manifest = _manifest()
    manifest["independent_assurance"]["penetration_test"] = {
        "status": "completed",
        "evidence_document": "docs/security-model.md",
    }
    with pytest.raises(AssurancePackError, match="requires independent evidence"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_legal_approval_requires_separate_reviewed_evidence() -> None:
    manifest = _manifest()
    manifest["approval"]["legal_status"] = "approved"
    with pytest.raises(AssurancePackError, match="assurance/legal"):
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
    _copy_pack_inputs(manifest, tmp_path)
    security = tmp_path / "SECURITY.md"
    security.write_text(
        security.read_text(encoding="utf-8").replace(
            "| Critical | 4 hours |", "| Critical | 72 hours |"
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssurancePackError, match="does not match the canonical"):
        validate_customer_assurance_pack(manifest, repository_root=tmp_path, today=TODAY)


def test_assurance_and_vulnerability_review_dates_cannot_diverge(tmp_path: Path) -> None:
    manifest = _manifest()
    _copy_pack_inputs(manifest, tmp_path)
    policy_path = tmp_path / manifest["vulnerability_management"]["policy_path"]
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["nextReviewDate"] = "2026-11-02"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(AssurancePackError, match="must use the same dates"):
        validate_customer_assurance_pack(manifest, repository_root=tmp_path, today=TODAY)


def test_vulnerability_authority_must_be_reviewed_pack_content() -> None:
    manifest = _manifest()
    manifest["vulnerability_management"]["policy_path"] = "SECURITY.md"
    with pytest.raises(AssurancePackError, match="canonical reviewed documents"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_guarantee_evidence_must_ship_in_the_pack() -> None:
    manifest = _manifest()
    manifest["guarantees"][0]["evidence"] = "docs/testing.md"
    with pytest.raises(AssurancePackError, match="must be technically reviewed pack content"):
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=TODAY)


def test_duplicate_manifest_field_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":2,"schema_version":2}', encoding="utf-8")
    with pytest.raises(AssurancePackError, match="duplicate field"):
        load_customer_assurance_pack(manifest)

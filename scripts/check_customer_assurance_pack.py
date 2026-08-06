"""Validate the buyer-facing assurance pack, review clock, and public commitments."""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any

# Direct execution starts with ``scripts/`` on the import path. Add only the
# repository root so direct and package execution load the same verifier.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_vulnerability_management import (
    VulnerabilityManagementVerificationError,
    load_json_document,
    parse_policy,
    verify_exercise,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "assurance/customer-assurance-pack.json"
SEVERITIES = ("critical", "high", "medium", "low")


class AssurancePackError(ValueError):
    """Raised when assurance claims are incomplete, stale, or misleading."""


def _closed_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    """Require an exact object schema so new claims cannot bypass review."""
    if set(value) != expected:
        raise AssurancePackError(
            f"{label} keys must be {sorted(expected)}; observed {sorted(value)}"
        )


def _parse_date(value: Any, label: str) -> date:
    """Parse one required ISO date without accepting datetimes or coercion."""
    if not isinstance(value, str):
        raise AssurancePackError(f"{label} must be an ISO date string")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise AssurancePackError(f"{label} must be YYYY-MM-DD") from error


def _resolve_repository_file(repository_root: Path, value: Any, label: str) -> Path:
    """Resolve a repository-relative evidence path without permitting traversal."""
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise AssurancePackError(f"{label} is unsafe")
    root = repository_root.resolve()
    resolved = (root / value).resolve()
    if resolved == root or root not in resolved.parents:
        raise AssurancePackError(f"{label} is unsafe")
    return resolved


def validate_customer_assurance_pack(
    manifest: dict[str, Any], *, repository_root: Path, today: date
) -> None:
    """Validate pack ownership, evidence, claim status, and bounded SLA promises."""
    _closed_keys(
        manifest,
        {
            "schema_version",
            "pack_id",
            "product",
            "owner",
            "approval",
            "documents",
            "independent_assurance",
            "vulnerability_management",
            "guarantees",
            "non_guarantees",
        },
        "manifest",
    )
    if manifest["schema_version"] != 2:
        raise AssurancePackError("schema_version must be 2")
    if manifest["pack_id"] != "aai-security-customer-assurance":
        raise AssurancePackError("pack_id is not canonical")
    if not isinstance(manifest["product"], str) or not manifest["product"].strip():
        raise AssurancePackError("product is required")

    owner = manifest["owner"]
    if not isinstance(owner, dict):
        raise AssurancePackError("owner must be an object")
    _closed_keys(owner, {"team", "contact_route"}, "owner")
    if not all(isinstance(owner[key], str) and owner[key].strip() for key in owner):
        raise AssurancePackError("owner team and contact_route are required")
    if owner["contact_route"] != (
        "https://github.com/tommycharade/aai-sec-sdk/security/advisories/new"
    ):
        raise AssurancePackError("contact_route must be the canonical private-reporting route")

    approval = manifest["approval"]
    if not isinstance(approval, dict):
        raise AssurancePackError("approval must be an object")
    _closed_keys(
        approval,
        {"technical_status", "legal_status", "approved_at", "next_review_due"},
        "approval",
    )
    if approval["technical_status"] != "approved":
        raise AssurancePackError("technical_status must be approved")
    if approval["legal_status"] not in {"approved", "review_required"}:
        raise AssurancePackError("legal_status is invalid")
    approved_at = _parse_date(approval["approved_at"], "approved_at")
    review_due = _parse_date(approval["next_review_due"], "next_review_due")
    if approved_at > today:
        raise AssurancePackError("approved_at cannot be in the future")
    if review_due < today:
        raise AssurancePackError("customer assurance pack review is overdue")
    if review_due > approved_at + timedelta(days=120):
        raise AssurancePackError("review interval cannot exceed 120 days")

    documents = manifest["documents"]
    if not isinstance(documents, list) or not documents:
        raise AssurancePackError("documents must be a non-empty list")
    document_ids: set[str] = set()
    document_paths: set[str] = set()
    document_statuses: dict[str, str] = {}
    document_paths_by_id: dict[str, str] = {}
    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            raise AssurancePackError(f"documents[{index}] must be an object")
        _closed_keys(document, {"id", "path", "status"}, f"documents[{index}]")
        identifier = document["id"]
        path = document["path"]
        if not isinstance(identifier, str) or not identifier:
            raise AssurancePackError(f"documents[{index}].id is required")
        resolved_path = _resolve_repository_file(repository_root, path, f"documents[{index}].path")
        if document["status"] not in {
            "technical_reviewed",
            "legal_review_required",
            "legal_reviewed",
            "independent_reviewed",
        }:
            raise AssurancePackError(f"documents[{index}].status is invalid")
        if identifier in document_ids or path in document_paths:
            raise AssurancePackError("document IDs and paths must be unique")
        if not resolved_path.is_file():
            raise AssurancePackError(f"assurance document is missing: {path}")
        document_ids.add(identifier)
        document_paths.add(path)
        document_statuses[path] = document["status"]
        document_paths_by_id[identifier] = path

    required_documents = {
        "customer_assurance_pack",
        "vulnerability_management",
        "enterprise_trust_statement",
        "vulnerability_policy",
        "vulnerability_rehearsal",
        "data_processing_and_subprocessors",
        "compliance_roadmap",
        "security_policy",
        "security_model",
        "release_process",
        "production_readiness",
    }
    if not required_documents.issubset(document_ids):
        raise AssurancePackError("required assurance documents are missing")
    legal_evidence = [
        path
        for path, status in document_statuses.items()
        if status == "legal_reviewed" and path.startswith("assurance/legal/")
    ]
    if approval["legal_status"] == "approved" and not legal_evidence:
        raise AssurancePackError("legal approval requires reviewed evidence under assurance/legal")

    independent = manifest["independent_assurance"]
    if not isinstance(independent, dict):
        raise AssurancePackError("independent_assurance must be an object")
    _closed_keys(
        independent, {"penetration_test", "soc2_type_ii", "iso_27001"}, "independent_assurance"
    )
    allowed_statuses = {
        "penetration_test": {"not_completed", "completed"},
        "soc2_type_ii": {"not_certified", "certified"},
        "iso_27001": {"not_certified", "certified"},
    }
    for control, allowed in allowed_statuses.items():
        record = independent[control]
        if not isinstance(record, dict):
            raise AssurancePackError(f"{control} must be an object")
        _closed_keys(record, {"status", "evidence_document"}, control)
        if record["status"] not in allowed:
            raise AssurancePackError(f"{control} status is invalid")
        completed = record["status"] in {"completed", "certified"}
        evidence = record["evidence_document"]
        if completed:
            if (
                not isinstance(evidence, str)
                or evidence not in document_paths
                or document_statuses[evidence] != "independent_reviewed"
                or not evidence.startswith("assurance/independent/")
            ):
                raise AssurancePackError(
                    f"{control} requires independent evidence under assurance/independent"
                )
        elif evidence is not None:
            raise AssurancePackError(f"{control} cannot cite evidence before completion")

    vulnerability = manifest["vulnerability_management"]
    if not isinstance(vulnerability, dict):
        raise AssurancePackError("vulnerability_management must be an object")
    _closed_keys(
        vulnerability,
        {"policy_path", "synthetic_rehearsal_path"},
        "vulnerability_management",
    )
    policy_value = vulnerability["policy_path"]
    exercise_value = vulnerability["synthetic_rehearsal_path"]
    policy_path = _resolve_repository_file(repository_root, policy_value, "policy_path")
    exercise_path = _resolve_repository_file(
        repository_root, exercise_value, "synthetic_rehearsal_path"
    )
    for path_value, label in (
        (policy_value, "vulnerability policy"),
        (exercise_value, "vulnerability rehearsal"),
    ):
        if (
            path_value not in document_paths
            or document_statuses[path_value] != "technical_reviewed"
        ):
            raise AssurancePackError(f"{label} must be a technically reviewed pack document")
    if (
        policy_value != document_paths_by_id["vulnerability_policy"]
        or exercise_value != document_paths_by_id["vulnerability_rehearsal"]
    ):
        raise AssurancePackError(
            "vulnerability authority must reference its canonical reviewed documents"
        )
    try:
        policy = parse_policy(load_json_document(policy_path, "vulnerability policy"), as_of=today)
        rehearsal = verify_exercise(
            load_json_document(exercise_path, "vulnerability rehearsal"), policy
        )
    except VulnerabilityManagementVerificationError as error:
        raise AssurancePackError(f"vulnerability authority is invalid: {error}") from error
    if policy.effective_date != approved_at or policy.next_review_date != review_due:
        raise AssurancePackError(
            "assurance and vulnerability review authority must use the same dates"
        )
    if policy.owner != owner["team"]:
        raise AssurancePackError(
            "assurance and vulnerability authority must have the same named owner"
        )
    if (
        rehearsal.get("status") != "verified-synthetic-rehearsal"
        or rehearsal.get("synthetic") is not True
    ):
        raise AssurancePackError("vulnerability rehearsal must remain explicitly synthetic")

    published_sla_rows = []
    for severity in SEVERITIES:
        level = policy.service_levels[severity]
        published_sla_rows.append(
            f"| {severity.title()} | {level.acknowledge_hours} hours | "
            f"{level.triage_hours} hours | {level.mitigation_hours} hours | "
            f"{level.remediation_days} days | {level.customer_notification_hours} hours |"
        )
    for published_path in ("SECURITY.md", "docs/vulnerability-management.md"):
        published_text = (repository_root / published_path).read_text(encoding="utf-8")
        if any(row not in published_text for row in published_sla_rows):
            raise AssurancePackError(
                f"{published_path} does not match the canonical vulnerability policy"
            )

    pack_text = (repository_root / "docs/customer-assurance-pack.md").read_text(encoding="utf-8")
    for required_value in (
        owner["team"],
        approval["approved_at"],
        approval["next_review_due"],
        "Not completed",
        "Not certified",
    ):
        if required_value not in pack_text:
            raise AssurancePackError(
                "customer assurance index does not match the reviewed manifest"
            )

    for collection_name in ("guarantees", "non_guarantees"):
        collection = manifest[collection_name]
        if not isinstance(collection, list) or not collection:
            raise AssurancePackError(f"{collection_name} must be a non-empty list")
        identifiers: set[str] = set()
        for index, statement in enumerate(collection):
            expected = (
                {"id", "statement", "evidence"}
                if collection_name == "guarantees"
                else {"id", "statement"}
            )
            if not isinstance(statement, dict):
                raise AssurancePackError(f"{collection_name}[{index}] must be an object")
            _closed_keys(statement, expected, f"{collection_name}[{index}]")
            if not isinstance(statement["id"], str) or not statement["id"]:
                raise AssurancePackError(f"{collection_name}[{index}].id is required")
            if statement["id"] in identifiers:
                raise AssurancePackError(f"duplicate {collection_name} ID")
            if not isinstance(statement["statement"], str) or not statement["statement"].strip():
                raise AssurancePackError(f"{collection_name}[{index}].statement is required")
            if collection_name == "guarantees":
                evidence = statement["evidence"]
                resolved_evidence = _resolve_repository_file(
                    repository_root, evidence, f"{collection_name}[{index}].evidence"
                )
                if not resolved_evidence.is_file():
                    raise AssurancePackError(f"guarantee evidence is missing: {evidence}")
                if (
                    evidence not in document_paths
                    or document_statuses[evidence] != "technical_reviewed"
                ):
                    raise AssurancePackError(
                        "guarantee evidence must be technically reviewed pack content"
                    )
            identifiers.add(statement["id"])


def load_customer_assurance_pack(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load a bounded assurance manifest with duplicate-key rejection."""
    try:
        value = load_json_document(path, "customer assurance manifest")
    except VulnerabilityManagementVerificationError as error:
        raise AssurancePackError(f"customer assurance manifest is invalid: {error}") from error
    if not isinstance(value, dict):
        raise AssurancePackError("assurance manifest root must be an object")
    return value


def main() -> int:
    """Fail CI when the checked-in customer assurance pack is stale or invalid."""
    try:
        manifest = load_customer_assurance_pack()
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=date.today())
    except (AssurancePackError, OSError) as error:
        print(f"Customer assurance pack invalid: {error}")
        return 1
    print(
        "Customer assurance pack is current: technical approval present, "
        f"next review {manifest['approval']['next_review_due']}, legal status "
        f"{manifest['approval']['legal_status']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

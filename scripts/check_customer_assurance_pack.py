"""Validate the buyer-facing assurance pack, review clock, and public commitments."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "assurance/customer-assurance-pack.json"
SEVERITIES = ("critical", "high", "medium", "low")
MAXIMUM_SLA = {
    "critical": (24, 48, 48, 7),
    "high": (48, 120, 120, 30),
    "medium": (120, 240, None, 90),
    "low": (240, 480, None, 180),
}


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


def _positive_integer(value: Any, label: str) -> int:
    """Reject booleans, fractions, and non-positive SLA values."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AssurancePackError(f"{label} must be a positive integer")
    return value


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
    if manifest["schema_version"] != 1:
        raise AssurancePackError("schema_version must be 1")
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
    if not owner["contact_route"].startswith("https://github.com/"):
        raise AssurancePackError("contact_route must be an HTTPS private-reporting route")

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
    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            raise AssurancePackError(f"documents[{index}] must be an object")
        _closed_keys(document, {"id", "path", "status"}, f"documents[{index}]")
        identifier = document["id"]
        path = document["path"]
        if not isinstance(identifier, str) or not identifier:
            raise AssurancePackError(f"documents[{index}].id is required")
        resolved_path = _resolve_repository_file(repository_root, path, f"documents[{index}].path")
        if document["status"] not in {"technical_reviewed", "legal_review_required"}:
            raise AssurancePackError(f"documents[{index}].status is invalid")
        if identifier in document_ids or path in document_paths:
            raise AssurancePackError("document IDs and paths must be unique")
        if not resolved_path.is_file():
            raise AssurancePackError(f"assurance document is missing: {path}")
        document_ids.add(identifier)
        document_paths.add(path)
        document_statuses[path] = document["status"]

    required_documents = {
        "customer_assurance_pack",
        "vulnerability_management",
        "data_processing_and_subprocessors",
        "compliance_roadmap",
        "security_policy",
        "security_model",
        "release_process",
    }
    if not required_documents.issubset(document_ids):
        raise AssurancePackError("required assurance documents are missing")

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
                or document_statuses[evidence] != "technical_reviewed"
            ):
                raise AssurancePackError(f"{control} requires a reviewed evidence document")
        elif evidence is not None:
            raise AssurancePackError(f"{control} cannot cite evidence before completion")

    vulnerability = manifest["vulnerability_management"]
    if not isinstance(vulnerability, dict):
        raise AssurancePackError("vulnerability_management must be an object")
    _closed_keys(
        vulnerability, {"clock", "severity_source", "severities"}, "vulnerability_management"
    )
    if vulnerability["clock"] != "calendar_hours":
        raise AssurancePackError("SLA clock must be calendar_hours")
    if (
        not isinstance(vulnerability["severity_source"], str)
        or not vulnerability["severity_source"]
    ):
        raise AssurancePackError("severity_source is required")
    severities = vulnerability["severities"]
    if not isinstance(severities, dict) or set(severities) != set(SEVERITIES):
        raise AssurancePackError("severities must be critical, high, medium, low")
    previous: tuple[int, int, int, int] | None = None
    for severity in SEVERITIES:
        record = severities[severity]
        if not isinstance(record, dict):
            raise AssurancePackError(f"{severity} SLA must be an object")
        _closed_keys(
            record,
            {
                "acknowledge_hours",
                "initial_assessment_hours",
                "affected_customer_notification_hours",
                "remediation_days",
            },
            f"{severity} SLA",
        )
        acknowledge = _positive_integer(
            record["acknowledge_hours"], f"{severity}.acknowledge_hours"
        )
        assessment = _positive_integer(
            record["initial_assessment_hours"], f"{severity}.initial_assessment_hours"
        )
        notification_value = record["affected_customer_notification_hours"]
        if severity in {"critical", "high"}:
            notification = _positive_integer(
                notification_value, f"{severity}.affected_customer_notification_hours"
            )
        elif notification_value is not None:
            raise AssurancePackError(f"{severity} customer notification must be null")
        else:
            notification = assessment
        remediation = _positive_integer(record["remediation_days"], f"{severity}.remediation_days")
        observed = (acknowledge, assessment, notification, remediation)
        maximum = MAXIMUM_SLA[severity]
        for value, limit in zip(observed, maximum, strict=True):
            if limit is not None and value > limit:
                raise AssurancePackError(f"{severity} SLA exceeds the approved maximum")
        if previous is not None and any(
            current < earlier for current, earlier in zip(observed, previous, strict=True)
        ):
            raise AssurancePackError("lower severities cannot have shorter SLA targets")
        previous = observed

    published_sla_rows = []
    for severity in SEVERITIES:
        record = severities[severity]
        notification = record["affected_customer_notification_hours"]
        notification_text = f"{notification} hours" if notification is not None else "Case-by-case"
        published_sla_rows.append(
            f"| {severity.title()} | {record['acknowledge_hours']} hours | "
            f"{record['initial_assessment_hours']} hours | {notification_text} | "
            f"{record['remediation_days']} days |"
        )
    for published_path in ("SECURITY.md", "docs/vulnerability-management.md"):
        published_text = (repository_root / published_path).read_text(encoding="utf-8")
        if any(row not in published_text for row in published_sla_rows):
            raise AssurancePackError(f"{published_path} does not match the assurance SLA manifest")

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
            identifiers.add(statement["id"])


def load_customer_assurance_pack(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load the assurance manifest without accepting a non-object root."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssurancePackError("assurance manifest root must be an object")
    return value


def main() -> int:
    """Fail CI when the checked-in customer assurance pack is stale or invalid."""
    try:
        manifest = load_customer_assurance_pack()
        validate_customer_assurance_pack(manifest, repository_root=ROOT, today=date.today())
    except (AssurancePackError, OSError, json.JSONDecodeError) as error:
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

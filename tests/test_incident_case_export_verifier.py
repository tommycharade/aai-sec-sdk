"""Adversarial tests for the offline incident-case export verifier."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest
from scripts.verify_incident_case_export import canonical_content, verify_artifact


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _artifact() -> dict[str, Any]:
    payload = {"reason": "Synthetic containment evidence."}
    event = {
        "id": "event-1",
        "eventType": "case_created",
        "actor": "synthetic-auditor",
        "occurredAt": 1_700_000_001,
        "sequence": 1,
        "payload": payload,
        "payloadHash": _digest(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
    }
    content = {
        "artifactType": "aai.incident-case",
        "tenantId": "tenant-synthetic",
        "caseId": "case-synthetic",
        "caseRevision": 3,
        "generatedAt": 1_700_000_100,
        "generatedBy": "synthetic-auditor",
        "correlationWindow": {
            "startAt": 1_699_913_600,
            "endAt": 1_700_000_099,
            "basis": "24_hours_before_first_alert_observation",
        },
        "case": {"id": "case-synthetic", "alertId": "alert-synthetic"},
        "alert": {"id": "alert-synthetic"},
        "timeline": [event],
        "decisions": [{"id": "decision-synthetic"}],
        "approvals": [
            {
                "id": "approval-synthetic",
                "status": "approved",
                "decisionReasonIncluded": False,
            }
        ],
        "evidence": {"endpointReportDigest": "a" * 64},
        "completeness": {
            "complete": True,
            "decisionsTruncated": False,
            "rawContentIncluded": False,
            "credentialsIncluded": False,
            "approvalDecisionReasonsIncluded": False,
            "counts": {"timelineEvents": 1, "decisions": 1, "approvals": 1},
            "recordLimitPerCollection": 500,
        },
    }
    content_hash = _digest(canonical_content(content))
    receipt_payload = {
        "event_type": "incident_case_exported",
        "actor": "synthetic-auditor",
        "tenant_id": "tenant-synthetic",
        "occurred_at": 1_700_000_101,
        "payload": {
            "case_id": "case-synthetic",
            "case_revision": 3,
            "content_hash": content_hash,
        },
    }
    return {
        "schemaVersion": 1,
        "content": content,
        "integrity": {
            "algorithm": "SHA-256",
            "canonicalization": "AAI canonical JSON v1",
            "contentHash": content_hash,
        },
        "auditReceipt": {
            "event_type": "incident_case_exported",
            "actor": "synthetic-auditor",
            "tenant_id": "tenant-synthetic",
            "occurred_at": 1_700_000_101,
            "payload_hash": _digest(json.dumps(receipt_payload, sort_keys=True).encode()),
        },
    }


def test_verifier_accepts_unchanged_complete_artifact() -> None:
    """An unchanged bounded package verifies with useful evidence counts."""
    result = verify_artifact(_artifact())
    assert result["caseId"] == "case-synthetic"
    assert result["timelineEvents"] == 1
    assert result["approvals"] == 1


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda value: value["content"]["case"].update({"status": "closed"}), "content integrity"),
        (
            lambda value: value["content"]["timeline"][0]["payload"].update(
                {"reason": "Changed after export."}
            ),
            "content integrity",
        ),
        (
            lambda value: value["content"]["completeness"].update({"rawContentIncluded": True}),
            "content integrity",
        ),
    ],
)
def test_verifier_rejects_post_export_changes(
    mutation: Callable[[dict[str, Any]], None], expected: str
) -> None:
    """Any content mutation invalidates the package before it is trusted."""
    artifact = copy.deepcopy(_artifact())
    mutation(artifact)
    with pytest.raises(ValueError, match=expected):
        verify_artifact(artifact)


def test_verifier_rejects_rehashed_timeline_tampering() -> None:
    """Rehashing the outer content cannot conceal an invalid event digest."""
    artifact = copy.deepcopy(_artifact())
    content = artifact["content"]
    content["timeline"][0]["payload"]["reason"] = "Tampered event."
    artifact["integrity"]["contentHash"] = _digest(canonical_content(content))
    with pytest.raises(ValueError, match="timeline payload integrity"):
        verify_artifact(artifact)


def test_verifier_rejects_free_form_approval_reason_even_if_rehashed() -> None:
    """Portable packages may not add unapproved operator narrative."""
    artifact = copy.deepcopy(_artifact())
    content = artifact["content"]
    content["approvals"][0]["decisionReason"] = "Copied sensitive investigation text."
    artifact["integrity"]["contentHash"] = _digest(canonical_content(content))
    with pytest.raises(ValueError, match="decision reasons must not be portable"):
        verify_artifact(artifact)

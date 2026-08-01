#!/usr/bin/env python3
"""Verify an AAI Security incident-case evidence package offline."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_FIELDS = {"schemaVersion", "content", "integrity", "auditReceipt"}


def _object(value: Any, field: str) -> dict[str, Any]:
    """Return a required JSON object or reject the malformed artifact."""
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _array(value: Any, field: str) -> list[Any]:
    """Return a required JSON array or reject the malformed artifact."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return value


def canonical_content(value: dict[str, Any]) -> bytes:
    """Encode content using the version-one AAI canonical JSON contract."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    """Return a lower-case SHA-256 digest."""
    return hashlib.sha256(value).hexdigest()


def _verify_timeline(events: list[Any]) -> None:
    """Verify event ordering, uniqueness and every stored payload digest."""
    previous_sequence = 0
    identifiers: set[str] = set()
    for index, raw_event in enumerate(events):
        event = _object(raw_event, f"content.timeline[{index}]")
        identifier = event.get("id")
        sequence = event.get("sequence")
        payload_hash = event.get("payloadHash")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("timeline event identifiers must be non-empty and unique")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence <= previous_sequence
        ):
            raise ValueError("timeline event sequences must be strictly increasing")
        if not isinstance(payload_hash, str) or not _HEX_DIGEST.fullmatch(payload_hash):
            raise ValueError("timeline payloadHash must be a lower-case SHA-256 digest")
        payload = _object(event.get("payload"), f"content.timeline[{index}].payload")
        # Timeline records predate AAI canonical JSON v1 and intentionally use
        # Python's default escaped-Unicode JSON representation. Preserve that
        # contract so offline verification matches the retained event digest.
        expected = _digest(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        if not hmac.compare_digest(payload_hash, expected):
            raise ValueError(f"timeline payload integrity failed at sequence {sequence}")
        identifiers.add(identifier)
        previous_sequence = sequence


def _verify_receipt(receipt: dict[str, Any], content: dict[str, Any], content_hash: str) -> None:
    """Verify the content-minimised immutable-audit receipt binding."""
    if receipt.get("event_type") != "incident_case_exported":
        raise ValueError("audit receipt has the wrong event type")
    if receipt.get("actor") != content.get("generatedBy"):
        raise ValueError("audit receipt actor does not match the export")
    if receipt.get("tenant_id") != content.get("tenantId"):
        raise ValueError("audit receipt tenant does not match the export")
    occurred_at = receipt.get("occurred_at")
    payload_hash = receipt.get("payload_hash")
    if not isinstance(occurred_at, int) or isinstance(occurred_at, bool) or occurred_at <= 0:
        raise ValueError("audit receipt occurred_at must be a positive integer")
    if not isinstance(payload_hash, str) or not _HEX_DIGEST.fullmatch(payload_hash):
        raise ValueError("audit receipt payload_hash must be a lower-case SHA-256 digest")
    redacted = {
        "event_type": "incident_case_exported",
        "actor": content["generatedBy"],
        "tenant_id": content["tenantId"],
        "occurred_at": occurred_at,
        "payload": {
            "case_id": content["caseId"],
            "case_revision": content["caseRevision"],
            "content_hash": content_hash,
        },
    }
    expected = _digest(json.dumps(redacted, sort_keys=True).encode("utf-8"))
    if not hmac.compare_digest(payload_hash, expected):
        raise ValueError("audit receipt does not bind this export digest")


def verify_artifact(artifact: Any) -> dict[str, Any]:
    """Validate a complete incident-case export and return a concise summary.

    Raises:
        ValueError: If the package is malformed, incomplete or has failed an
            integrity check.
    """
    document = _object(artifact, "artifact")
    if set(document) != _TOP_LEVEL_FIELDS or document.get("schemaVersion") != 1:
        raise ValueError("unsupported incident-case export schema")
    content = _object(document.get("content"), "content")
    integrity = _object(document.get("integrity"), "integrity")
    receipt = _object(document.get("auditReceipt"), "auditReceipt")
    if content.get("artifactType") != "aai.incident-case":
        raise ValueError("content has the wrong artifact type")
    if integrity.get("algorithm") != "SHA-256":
        raise ValueError("unsupported content hash algorithm")
    if integrity.get("canonicalization") != "AAI canonical JSON v1":
        raise ValueError("unsupported canonical JSON version")
    content_hash = integrity.get("contentHash")
    if not isinstance(content_hash, str) or not _HEX_DIGEST.fullmatch(content_hash):
        raise ValueError("integrity.contentHash must be a lower-case SHA-256 digest")
    expected_hash = _digest(canonical_content(content))
    if not hmac.compare_digest(content_hash, expected_hash):
        raise ValueError("incident-case content integrity verification failed")

    case = _object(content.get("case"), "content.case")
    alert = _object(content.get("alert"), "content.alert")
    if content.get("caseId") != case.get("id"):
        raise ValueError("case identifier does not match the case snapshot")
    if case.get("alertId") != alert.get("id"):
        raise ValueError("source alert does not match the case snapshot")
    timeline = _array(content.get("timeline"), "content.timeline")
    decisions = _array(content.get("decisions"), "content.decisions")
    approvals = _array(content.get("approvals"), "content.approvals")
    completeness = _object(content.get("completeness"), "content.completeness")
    required_flags = {
        "complete": True,
        "decisionsTruncated": False,
        "rawContentIncluded": False,
        "credentialsIncluded": False,
        "approvalDecisionReasonsIncluded": False,
    }
    if any(completeness.get(name) is not expected for name, expected in required_flags.items()):
        raise ValueError("export completeness or content-minimisation flags are unsafe")
    limit = completeness.get("recordLimitPerCollection")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
        raise ValueError("recordLimitPerCollection is invalid")
    if any(len(collection) > limit for collection in (timeline, decisions, approvals)):
        raise ValueError("an evidence collection exceeds its declared bound")
    counts = _object(completeness.get("counts"), "content.completeness.counts")
    expected_counts = {
        "timelineEvents": len(timeline),
        "decisions": len(decisions),
        "approvals": len(approvals),
    }
    if counts != expected_counts:
        raise ValueError("declared evidence counts do not match the package")
    if any("decisionReason" in _object(item, "content.approvals item") for item in approvals):
        raise ValueError("approval decision reasons must not be portable")
    _verify_timeline(timeline)
    _verify_receipt(receipt, content, content_hash)
    return {
        "caseId": content["caseId"],
        "contentHash": content_hash,
        **expected_counts,
    }


def main(argv: list[str] | None = None) -> int:
    """Load and verify one JSON artifact from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="incident-case export JSON file")
    arguments = parser.parse_args(argv)
    try:
        artifact = json.loads(arguments.artifact.read_text(encoding="utf-8"))
        result = verify_artifact(artifact)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "VERIFIED: "
        f"case={result['caseId']} hash={result['contentHash']} "
        f"timeline={result['timelineEvents']} decisions={result['decisions']} "
        f"approvals={result['approvals']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

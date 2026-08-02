#!/usr/bin/env python3
"""Verify the independent regional-transition witness CloudFormation template."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


class TransitionJournalStackVerificationError(ValueError):
    """Raised when witness infrastructure weakens single-writer CAS authority."""


_TABLE = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_ALLOWED_TYPES = {
    "AWS::DynamoDB::Table",
    "AWS::KMS::Key",
    "AWS::KMS::Alias",
    "AWS::CDK::Metadata",
}


def _object(value: object, label: str) -> dict[str, Any]:
    """Return one object or reject ambiguous template structure."""
    if not isinstance(value, dict):
        raise TransitionJournalStackVerificationError(f"{label} must be an object")
    return value


def verify(template: dict[str, Any], *, expected_table_name: str) -> dict[str, Any]:
    """Require one retained, encrypted, unreplicated DynamoDB witness table."""
    if not _TABLE.fullmatch(expected_table_name):
        raise TransitionJournalStackVerificationError("expected table name is invalid")
    resources = _object(template.get("Resources"), "template Resources")
    by_type: dict[str, list[dict[str, Any]]] = {}
    for raw in resources.values():
        resource = _object(raw, "CloudFormation resource")
        resource_type = resource.get("Type")
        if not isinstance(resource_type, str) or resource_type not in _ALLOWED_TYPES:
            raise TransitionJournalStackVerificationError(
                "witness stack contains runtime, routing, IAM, or unexpected resources"
            )
        by_type.setdefault(resource_type, []).append(resource)
    if (
        len(by_type.get("AWS::DynamoDB::Table", [])) != 1
        or len(by_type.get("AWS::KMS::Key", [])) != 1
        or len(by_type.get("AWS::KMS::Alias", [])) != 1
    ):
        raise TransitionJournalStackVerificationError(
            "witness stack requires one table and one customer-managed key"
        )
    table = by_type["AWS::DynamoDB::Table"][0]
    properties = _object(table.get("Properties"), "witness table properties")
    expected_keys = [
        {"AttributeName": "pk", "KeyType": "HASH"},
        {"AttributeName": "sk", "KeyType": "RANGE"},
    ]
    expected_attributes = [
        {"AttributeName": "pk", "AttributeType": "S"},
        {"AttributeName": "sk", "AttributeType": "S"},
    ]
    encryption = _object(properties.get("SSESpecification"), "table encryption")
    if (
        properties.get("TableName") != expected_table_name
        or properties.get("BillingMode") != "PAY_PER_REQUEST"
        or properties.get("DeletionProtectionEnabled") is not True
        or properties.get("KeySchema") != expected_keys
        or properties.get("AttributeDefinitions") != expected_attributes
        or properties.get("PointInTimeRecoverySpecification")
        != {"PointInTimeRecoveryEnabled": True}
        or "Replicas" in properties
        or encryption.get("SSEEnabled") is not True
        or encryption.get("SSEType") != "KMS"
        or not isinstance(encryption.get("KMSMasterKeyId"), dict)
        or table.get("DeletionPolicy") != "Retain"
        or table.get("UpdateReplacePolicy") != "Retain"
    ):
        raise TransitionJournalStackVerificationError(
            "witness table is mutable, replicated, unprotected, or weakly encrypted"
        )
    tags = properties.get("Tags")
    if not isinstance(tags, list):
        raise TransitionJournalStackVerificationError("witness identity tags are incomplete")
    tag_map = {item.get("Key"): item.get("Value") for item in tags if isinstance(item, dict)}
    if (
        tag_map.get("aai-sec:purpose") != "regional-transition-single-writer-witness"
        or tag_map.get("aai-sec:replicated") != "false"
    ):
        raise TransitionJournalStackVerificationError("witness identity tags are incomplete")
    key = by_type["AWS::KMS::Key"][0]
    key_properties = _object(key.get("Properties"), "witness KMS key")
    if (
        key_properties.get("EnableKeyRotation") is not True
        or key_properties.get("PendingWindowInDays") != 30
        or key.get("DeletionPolicy") != "Retain"
        or key.get("UpdateReplacePolicy") != "Retain"
    ):
        raise TransitionJournalStackVerificationError("witness KMS key lifecycle is unsafe")
    outputs = _object(template.get("Outputs"), "template Outputs")
    status = _object(outputs.get("TransitionJournalStatus"), "journal status output")
    if status.get("Value") != "uninitialized-single-writer-witness" or any(
        any(term in name.lower() for term in ("url", "endpoint", "domain")) for name in outputs
    ):
        raise TransitionJournalStackVerificationError(
            "witness stack advertises execution or initialized authority"
        )
    return {
        "status": "verified-uninitialized-single-writer-witness",
        "tableName": expected_table_name,
        "customerManagedKeyCount": 1,
        "replicaCount": 0,
    }


def main() -> int:
    """Verify one bounded JSON template from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--table-name", required=True)
    arguments = parser.parse_args()
    if arguments.template.stat().st_size > 2_000_000:
        raise TransitionJournalStackVerificationError("witness template exceeds 2 MiB")
    try:
        value = json.loads(arguments.template.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TransitionJournalStackVerificationError("witness template is unreadable") from error
    print(json.dumps(verify(_object(value, "template"), expected_table_name=arguments.table_name)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

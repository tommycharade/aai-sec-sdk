"""Verify one synthesized half of bidirectional immutable S3 evidence continuity.

The verifier reads CloudFormation only. It independently proves Object Lock,
versioning, replica-modification sync, deletion exclusion, the exact destination
and bounded S3 replication authority before a template may be deployed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class EvidenceContinuityVerificationError(ValueError):
    """Raised when a synthesized replication boundary is missing or unsafe."""


_SOURCE_ACTIONS = {
    "s3:GetReplicationConfiguration",
    "s3:ListBucket",
    "s3:GetObjectVersionForReplication",
    "s3:GetObjectVersionAcl",
    "s3:GetObjectVersionTagging",
    "s3:GetObjectRetention",
    "s3:GetObjectLegalHold",
}
_DESTINATION_ACTIONS = {"s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"}
_FORBIDDEN_ACTIONS = {
    "s3:DeleteBucket",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:PutBucketPolicy",
    "s3:PutReplicationConfiguration",
}


def _object(value: object, label: str) -> dict[str, Any]:
    """Return one unambiguous JSON object."""
    if not isinstance(value, dict):
        raise EvidenceContinuityVerificationError(f"{label} must be an object")
    return value


def _actions(value: object) -> set[str]:
    """Return explicit actions without accepting wildcard authority."""
    if isinstance(value, str):
        actions = {value}
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        actions = set(value)
    else:
        raise EvidenceContinuityVerificationError("IAM Action must contain explicit strings")
    if any("*" in action for action in actions):
        raise EvidenceContinuityVerificationError("replication role contains wildcard authority")
    return actions


def verify(
    template: dict[str, Any], *, destination_bucket_arn: str, expected_rule_id: str
) -> dict[str, str | int]:
    """Prove one exact, non-deleting Object Lock replication direction."""
    resources = _object(template.get("Resources"), "template Resources")
    buckets = [
        _object(resource, "S3 bucket")
        for resource in resources.values()
        if isinstance(resource, dict)
        and resource.get("Type") == "AWS::S3::Bucket"
        and isinstance(resource.get("Properties"), dict)
        and "ReplicationConfiguration" in resource["Properties"]
    ]
    if len(buckets) != 1:
        raise EvidenceContinuityVerificationError(
            "template must contain exactly one replicated source bucket"
        )
    properties = _object(buckets[0].get("Properties"), "bucket properties")
    lock = _object(properties.get("ObjectLockConfiguration"), "Object Lock configuration")
    retention = _object(
        _object(lock.get("Rule"), "Object Lock rule").get("DefaultRetention"),
        "default retention",
    )
    if (
        properties.get("VersioningConfiguration") != {"Status": "Enabled"}
        or properties.get("ObjectLockEnabled") is not True
        or lock.get("ObjectLockEnabled") != "Enabled"
        or retention.get("Mode") != "COMPLIANCE"
        or not isinstance(retention.get("Days"), int)
        or retention["Days"] < 365
    ):
        raise EvidenceContinuityVerificationError(
            "replicated source must be versioned with 365-day COMPLIANCE Object Lock"
        )
    replication = _object(properties.get("ReplicationConfiguration"), "replication config")
    role_reference = _object(replication.get("Role"), "replication role reference").get(
        "Fn::GetAtt"
    )
    if (
        not isinstance(role_reference, list)
        or len(role_reference) != 2
        or not isinstance(role_reference[0], str)
        or role_reference[1] != "Arn"
    ):
        raise EvidenceContinuityVerificationError("replication role reference is ambiguous")
    role_id = role_reference[0]
    role = _object(resources.get(role_id), "replication IAM role")
    trust = _object(
        _object(role.get("Properties"), "replication role properties").get(
            "AssumeRolePolicyDocument"
        ),
        "replication trust policy",
    )
    if trust.get("Statement") != [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
        }
    ]:
        raise EvidenceContinuityVerificationError("replication role trust is not S3-only")
    rules = replication.get("Rules")
    if not isinstance(rules, list) or len(rules) != 1:
        raise EvidenceContinuityVerificationError("exactly one replication rule is required")
    rule = _object(rules[0], "replication rule")
    destination = _object(rule.get("Destination"), "replication destination")
    selection = _object(rule.get("SourceSelectionCriteria"), "source selection criteria")
    if (
        rule.get("Id") != expected_rule_id
        or rule.get("Status") != "Enabled"
        or rule.get("Priority") != 1
        or rule.get("Filter") != {"Prefix": ""}
        or rule.get("DeleteMarkerReplication") != {"Status": "Disabled"}
        or selection.get("ReplicaModifications") != {"Status": "Enabled"}
        or destination.get("Bucket") != destination_bucket_arn
        or destination.get("StorageClass") != "STANDARD"
        or destination.get("Metrics") != {"Status": "Enabled"}
    ):
        raise EvidenceContinuityVerificationError(
            "replication rule does not match the reviewed continuity contract"
        )

    allowed_actions: set[str] = set()
    attached_policy_count = 0
    for resource in resources.values():
        if not isinstance(resource, dict) or resource.get("Type") != "AWS::IAM::Policy":
            continue
        policy_properties = _object(resource.get("Properties"), "IAM policy properties")
        if {"Ref": role_id} not in policy_properties.get("Roles", []):
            continue
        attached_policy_count += 1
        document = _object(
            policy_properties.get("PolicyDocument"),
            "IAM policy document",
        )
        statements = document.get("Statement")
        if not isinstance(statements, list):
            raise EvidenceContinuityVerificationError("IAM statements must be a list")
        for statement in statements:
            value = _object(statement, "IAM statement")
            if value.get("Effect") == "Allow":
                if "NotAction" in value:
                    raise EvidenceContinuityVerificationError("replication role uses NotAction")
                allowed_actions.update(_actions(value.get("Action")))
    if attached_policy_count != 1 or allowed_actions != _SOURCE_ACTIONS | _DESTINATION_ACTIONS:
        raise EvidenceContinuityVerificationError(
            "replication role actions do not match the reviewed least-privilege set"
        )
    if allowed_actions & _FORBIDDEN_ACTIONS:
        raise EvidenceContinuityVerificationError("replication role has destructive authority")
    return {
        "status": "verified-immutable-replication",
        "ruleId": expected_rule_id,
        "retentionDays": retention["Days"],
    }


def main() -> int:
    """Verify a bounded synthesized template and emit minimal evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--destination-bucket-arn", required=True)
    parser.add_argument("--rule-id", required=True)
    arguments = parser.parse_args()
    if arguments.template.stat().st_size > 5_000_000:
        raise EvidenceContinuityVerificationError("CloudFormation template exceeds 5 MB")
    template = json.loads(arguments.template.read_text(encoding="utf-8"))
    print(
        json.dumps(
            verify(
                _object(template, "template"),
                destination_bucket_arn=arguments.destination_bucket_arn,
                expected_rule_id=arguments.rule_id,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

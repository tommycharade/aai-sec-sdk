"""Adversarial contracts for bidirectional immutable audit continuity."""

from __future__ import annotations

import copy
import importlib.util
import io
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_aws_evidence_continuity.py"
    spec = importlib.util.spec_from_file_location("aai_evidence_continuity", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_canary() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "test_aws_bidirectional_audit_continuity.py"
    spec = importlib.util.spec_from_file_location("aai_bidirectional_canary", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeS3:
    """Synchronous two-way S3 replication double with exact versions."""

    def __init__(self) -> None:
        self.peer: _FakeS3 | None = None
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}

    def put_object(self, **value: Any) -> dict[str, str]:
        version = "version-" + value["Key"].rsplit("/", 1)[-1]
        tags = dict(part.split("=", 1) for part in value["Tagging"].split("&"))
        record = {
            "body": value["Body"],
            "metadata": value["Metadata"],
            "mode": value["ObjectLockMode"],
            "retain": value["ObjectLockRetainUntilDate"],
            "tags": tags,
            "status": "COMPLETED",
        }
        self.objects[(value["Key"], version)] = copy.deepcopy(record)
        assert self.peer is not None
        replica = copy.deepcopy(record)
        replica["status"] = "REPLICA"
        self.peer.objects[(value["Key"], version)] = replica
        return {"VersionId": version}

    def get_object(self, **value: Any) -> dict[str, Any]:
        record = self.objects[(value["Key"], value["VersionId"])]
        return {
            "Body": io.BytesIO(record["body"]),
            "Metadata": record["metadata"],
            "ObjectLockMode": record["mode"],
            "ObjectLockRetainUntilDate": record["retain"],
            "ReplicationStatus": record["status"],
        }

    def put_object_retention(self, **value: Any) -> None:
        key = (value["Key"], value["VersionId"])
        self.objects[key]["retain"] = value["Retention"]["RetainUntilDate"]
        assert self.peer is not None
        self.peer.objects[key]["retain"] = value["Retention"]["RetainUntilDate"]

    def put_object_tagging(self, **value: Any) -> None:
        key = (value["Key"], value["VersionId"])
        tags = {item["Key"]: item["Value"] for item in value["Tagging"]["TagSet"]}
        self.objects[key]["tags"] = tags
        assert self.peer is not None
        self.peer.objects[key]["tags"] = dict(tags)

    def get_object_retention(self, **value: Any) -> dict[str, Any]:
        record = self.objects[(value["Key"], value["VersionId"])]
        return {"Retention": {"Mode": record["mode"], "RetainUntilDate": record["retain"]}}

    def get_object_tagging(self, **value: Any) -> dict[str, Any]:
        record = self.objects[(value["Key"], value["VersionId"])]
        return {
            "TagSet": [
                {"Key": key, "Value": value} for key, value in sorted(record["tags"].items())
            ]
        }


def _template() -> dict[str, Any]:
    source_actions = [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket",
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectVersionTagging",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold",
    ]
    return {
        "Resources": {
            "Audit": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "ObjectLockEnabled": True,
                    "ObjectLockConfiguration": {
                        "ObjectLockEnabled": "Enabled",
                        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}},
                    },
                    "ReplicationConfiguration": {
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Rules": [
                            {
                                "Id": "reverse",
                                "Priority": 1,
                                "Filter": {"Prefix": ""},
                                "DeleteMarkerReplication": {"Status": "Disabled"},
                                "SourceSelectionCriteria": {
                                    "ReplicaModifications": {"Status": "Enabled"}
                                },
                                "Status": "Enabled",
                                "Destination": {
                                    "Bucket": "arn:aws:s3:::primary-audit",
                                    "StorageClass": "STANDARD",
                                    "Metrics": {"Status": "Enabled"},
                                },
                            }
                        ],
                    },
                },
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Action": "sts:AssumeRole",
                                "Effect": "Allow",
                                "Principal": {"Service": "s3.amazonaws.com"},
                            }
                        ]
                    }
                },
            },
            "Policy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "Roles": [{"Ref": "Role"}],
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": source_actions},
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:ReplicateObject",
                                    "s3:ReplicateDelete",
                                    "s3:ReplicateTags",
                                ],
                            },
                        ]
                    },
                },
            },
        }
    }


def test_verifies_exact_non_deleting_replication_contract() -> None:
    module = _load()
    assert module.verify(
        _template(),
        destination_bucket_arn="arn:aws:s3:::primary-audit",
        expected_rule_id="reverse",
    ) == {
        "status": "verified-immutable-replication",
        "ruleId": "reverse",
        "retentionDays": 365,
    }


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("ObjectLockEnabled",), False, "Object Lock"),
        (("VersioningConfiguration",), {"Status": "Suspended"}, "Object Lock"),
        (
            ("ReplicationConfiguration", "Rules", 0, "DeleteMarkerReplication"),
            {"Status": "Enabled"},
            "contract",
        ),
        (("ReplicationConfiguration", "Rules", 0, "SourceSelectionCriteria"), {}, "contract"),
        (
            ("ReplicationConfiguration", "Rules", 0, "Destination", "Bucket"),
            "arn:aws:s3:::other",
            "contract",
        ),
    ],
)
def test_rejects_missing_immutability_controls(
    path: tuple[str | int, ...], value: object, message: str
) -> None:
    module = _load()
    template = copy.deepcopy(_template())
    target: Any = template["Resources"]["Audit"]["Properties"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(module.EvidenceContinuityVerificationError, match=message):
        module.verify(
            template,
            destination_bucket_arn="arn:aws:s3:::primary-audit",
            expected_rule_id="reverse",
        )


@pytest.mark.parametrize("action", ["s3:DeleteObject", "s3:*", "s3:PutBucketPolicy"])
def test_rejects_destructive_or_broad_replication_authority(action: str) -> None:
    module = _load()
    template = _template()
    template["Resources"]["Policy"]["Properties"]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": action}
    )
    with pytest.raises(module.EvidenceContinuityVerificationError):
        module.verify(
            template,
            destination_bucket_arn="arn:aws:s3:::primary-audit",
            expected_rule_id="reverse",
        )


def test_both_stack_sources_enable_replica_modification_sync() -> None:
    root = Path(__file__).parents[1] / "infra/aws-control-plane/lib"
    primary = (root / "aws-control-plane-stack.ts").read_text(encoding="utf-8")
    recovery = (root / "audit-replica-stack.ts").read_text(encoding="utf-8")
    assert "replicate-audit-to-recovery-region" in primary
    assert "replicate-recovery-audit-to-primary-region" in recovery
    assert 'replicaModifications: { status: "Enabled" }' in primary
    assert 'replicaModifications: { status: "Enabled" }' in recovery
    assert "s3:DeleteObject" not in recovery


def test_canary_proves_both_write_directions_and_returned_modifications() -> None:
    module = _load_canary()
    primary, recovery = _FakeS3(), _FakeS3()
    primary.peer, recovery.peer = recovery, primary
    forward = module.exercise_direction(
        primary,
        recovery,
        source_bucket="primary",
        destination_bucket="recovery",
        direction="primary-to-recovery",
        timeout_seconds=1,
        sleep=lambda _seconds: None,
    )
    reverse = module.exercise_direction(
        recovery,
        primary,
        source_bucket="recovery",
        destination_bucket="primary",
        direction="recovery-to-primary",
        timeout_seconds=1,
        sleep=lambda _seconds: None,
    )
    assert forward["key"].startswith("continuity-canary/primary-to-recovery/")
    assert reverse["key"].startswith("continuity-canary/recovery-to-primary/")
    assert len(primary.objects) == len(recovery.objects) == 2
    for key in primary.objects:
        assert primary.objects[key]["body"] == recovery.objects[key]["body"]
        assert primary.objects[key]["retain"] == recovery.objects[key]["retain"]
        assert primary.objects[key]["tags"] == recovery.objects[key]["tags"]
        assert "replica-modification-proof" in primary.objects[key]["tags"]


def test_canary_rejects_replica_byte_divergence(monkeypatch: Any) -> None:
    module = _load_canary()
    primary, recovery = _FakeS3(), _FakeS3()
    primary.peer, recovery.peer = recovery, primary
    original = recovery.get_object

    def corrupt(**value: Any) -> dict[str, Any]:
        response = original(**value)
        response["Body"] = io.BytesIO(b"tampered")
        return response

    monkeypatch.setattr(recovery, "get_object", corrupt)
    with pytest.raises(RuntimeError, match="bytes, metadata or retention differ"):
        module.exercise_direction(
            primary,
            recovery,
            source_bucket="primary",
            destination_bucket="recovery",
            direction="primary-to-recovery",
            timeout_seconds=1,
            sleep=lambda _seconds: None,
        )

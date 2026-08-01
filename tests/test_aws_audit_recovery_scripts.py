"""Contracts for bounded cross-region immutable audit recovery tooling."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest


def _load(name: str) -> Any:
    path = Path(__file__).parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"aai_{name}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self.pages


class _S3:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def get_paginator(self, name: str) -> _Paginator:
        assert name == "list_object_versions"
        return _Paginator(self.pages)


def test_backfill_count_is_cutoff_bound_and_fails_before_unbounded_work() -> None:
    module = _load("backfill_aws_audit_replication")
    cutoff = datetime.now(UTC)
    s3 = _S3(
        [
            {
                "Versions": [
                    {"LastModified": cutoff - timedelta(seconds=1)},
                    {"LastModified": cutoff + timedelta(seconds=1)},
                ]
            }
        ]
    )
    assert module.count_versions_before(s3, "synthetic", cutoff, 1) == 1
    with pytest.raises(RuntimeError, match="safety bound"):
        module.count_versions_before(
            _S3([{"Versions": [{"LastModified": cutoff - timedelta(seconds=1)}] * 2}]),
            "synthetic",
            cutoff,
            1,
        )


def test_backfill_wait_rejects_provider_partial_failure() -> None:
    module = _load("backfill_aws_audit_replication")

    class Control:
        def describe_job(self, **_: Any) -> dict[str, Any]:
            return {
                "Job": {
                    "Status": "Complete",
                    "ProgressSummary": {"NumberOfTasksFailed": 1},
                }
            }

    with pytest.raises(RuntimeError, match="failed tasks"):
        module.wait_for_job(Control(), "111122223333", "job", 1)


def _item(key: str, *, digest: str, retain_days: int, status: str | None) -> dict[str, Any]:
    return {
        "key": key,
        "versionId": "version-1",
        "sha256": digest,
        "contentSha256": digest,
        "mode": "COMPLIANCE",
        "retainUntil": (datetime.now(UTC) + timedelta(days=retain_days)).isoformat(),
        "replicationStatus": status,
    }


def test_recovery_verifier_binds_identity_bytes_retention_and_provenance() -> None:
    module = _load("verify_aws_audit_recovery")
    digest = hashlib.sha256(b"synthetic").hexdigest()
    source = [
        _item("tenant=synthetic/event.json", digest=digest, retain_days=365, status="COMPLETED")
    ]
    replica = [
        _item("tenant=synthetic/event.json", digest=digest, retain_days=365, status="REPLICA")
    ]
    assert len(module.verify(source, replica)) == 64
    shorter = [
        _item("tenant=synthetic/event.json", digest=digest, retain_days=364, status="REPLICA")
    ]
    with pytest.raises(RuntimeError, match="retention is shorter"):
        module.verify(source, shorter)
    forged = [
        _item("tenant=synthetic/event.json", digest="0" * 64, retain_days=365, status="REPLICA")
    ]
    with pytest.raises(RuntimeError, match="content digest differs"):
        module.verify(source, forged)
    no_provenance = [
        _item("tenant=synthetic/event.json", digest=digest, retain_days=365, status=None)
    ]
    with pytest.raises(RuntimeError, match="provenance"):
        module.verify(source, no_provenance)


def test_version_inspection_hashes_exact_version_and_lock_state() -> None:
    module = _load("verify_aws_audit_recovery")

    class S3:
        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["VersionId"] == "version-1"
            return {
                "Body": io.BytesIO(b"synthetic"),
                "Metadata": {"content-sha256": "metadata-digest"},
                "ObjectLockMode": "COMPLIANCE",
                "ObjectLockRetainUntilDate": datetime.now(UTC) + timedelta(days=365),
                "ReplicationStatus": "REPLICA",
            }

    item = module.inspect_version(
        S3(), "synthetic", {"Key": "event.json", "VersionId": "version-1"}
    )
    assert item["sha256"] == hashlib.sha256(b"synthetic").hexdigest()
    assert item["contentSha256"] == "metadata-digest"
    assert item["replicationStatus"] == "REPLICA"


def test_recovery_iac_exposes_operator_inputs_and_separates_roles() -> None:
    """The runbook must not require guessed resource names or merged authority."""
    stack = (
        Path(__file__).parents[1]
        / "infra"
        / "aws-control-plane"
        / "lib"
        / "aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'CfnOutput(this, "AuditBucketName"' in stack
    assert 'CfnOutput(this, "EvidenceReportBucketName"' in stack
    assert 'CfnOutput(this, "AuditBatchReplicationRoleArn"' in stack
    assert 'ServicePrincipal("batchoperations.s3.amazonaws.com")' in stack
    assert 'ServicePrincipal("s3.amazonaws.com")' in stack
    assert 'metrics: { status: "Enabled" }' in stack
    assert "priority: 1" in stack
    assert 'filter: { prefix: "" }' in stack
    assert 'deleteMarkerReplication: { status: "Disabled" }' in stack
    assert "REPLICATION_OPERATION_FAILED_REPLICATION" in stack
    assert "REPLICATION_OPERATION_NOT_TRACKED" in stack

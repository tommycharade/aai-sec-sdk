"""Provider-state contracts for the read-only AWS regional activation preflight."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "plan_aws_regional_activation.py"
    spec = importlib.util.spec_from_file_location("aai_activation_preflight", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _activation(module: Any, payload: bytes = b'{"synthetic":true}') -> Any:
    digest = hashlib.sha256(payload).hexdigest()
    return module.activation.ActivationManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "transitionId": "12345678-1234-4234-8234-123456789abc",
                "direction": "failover",
                "primaryRegion": "eu-west-2",
                "recoveryRegion": "eu-west-1",
                "sourceRegion": "eu-west-2",
                "targetRegion": "eu-west-1",
                "stableApiDomain": "api.security.example.com",
                "stableUiDomain": "security.example.com",
                "route53HostedZoneId": "Z1234567890ABC",
                "targetFleetSize": 1000,
                "rtoMinutes": 30,
                "rpoSeconds": 60,
                "evidenceBundle": {
                    "bucketArn": "arn:aws:s3:::primary-audit",
                    "key": ("regional-activation/12345678-1234-4234-8234-123456789abc.json"),
                    "versionId": "version-1",
                    "sha256": digest,
                },
                "approvalEvidenceRef": "change/DR-123456",
                "expiresAt": 1200,
                "activationPermitted": True,
                "automaticActivation": False,
            }
        ),
        now=1000,
    )


def _regional(module: Any) -> Any:
    return module.recovery.RegionalRecoveryManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "stackName": "AaiSecControlPlane",
                "primaryRegion": "eu-west-2",
                "recoveryRegion": "eu-west-1",
                "targetFleetSize": 1000,
                "rtoMinutes": 30,
                "rpoSeconds": 60,
                "recoveryMode": "fail-closed-active-passive",
                "approvalEvidenceRef": "change/RECOVERY-123",
            }
        )
    )


def _continuity(module: Any) -> Any:
    return module.continuity.EvidenceContinuityManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "primaryStackName": "AaiSecControlPlane",
                "recoveryStackName": "AaiSecAuditReplica",
                "primaryRegion": "eu-west-2",
                "recoveryRegion": "eu-west-1",
                "approvalEvidenceRef": "change/CONTINUITY-123",
                "activationPermitted": False,
            }
        )
    )


def _passive(module: Any) -> Any:
    return module.passive.PassiveCellManifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "passiveStackName": "AaiSecPassiveRegionalCell",
                "primaryRegion": "eu-west-2",
                "recoveryRegion": "eu-west-1",
                "recoveryUserPoolId": "eu-west-1_AbCdEf123",
                "recoveryUserPoolClientId": "client1234567890",
                "approvalEvidenceRef": "change/PASSIVE-123",
                "identityAcceptanceEvidenceRef": "test/IDENTITY-123",
                "activationPermitted": False,
            }
        )
    )


class _S3:
    def __init__(self, payload: bytes, **updates: Any) -> None:
        digest = hashlib.sha256(payload).hexdigest()
        self.response: dict[str, Any] = {
            "Body": io.BytesIO(payload),
            "Metadata": {"content-sha256": digest},
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": datetime.fromtimestamp(1300, tz=UTC),
            "VersionId": "version-1",
        }
        self.response.update(updates)
        self.calls: list[dict[str, str]] = []

    def get_object(self, **kwargs: str) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.response


def _completed(value: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, json.dumps(value), "")


def test_retained_evidence_is_exact_version_digest_metadata_and_lock_bound() -> None:
    module = _load()
    payload = b'{"synthetic":true}'
    manifest = _activation(module, payload)
    s3 = _S3(payload)
    assert (
        module.read_retained_evidence(
            manifest,
            expected_bucket_arn="arn:aws:s3:::primary-audit",
            s3_client=s3,
            now=datetime.fromtimestamp(1000, tz=UTC),
        )
        == payload
    )
    assert s3.calls == [
        {
            "Bucket": "primary-audit",
            "Key": manifest.evidence.key,
            "VersionId": "version-1",
        }
    ]


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"VersionId": "substitute"}, "content-bound"),
        ({"Metadata": {"content-sha256": "0" * 64}}, "content-bound"),
        ({"ObjectLockMode": "GOVERNANCE"}, "content-bound"),
        (
            {
                "ObjectLockRetainUntilDate": datetime.fromtimestamp(1100, tz=UTC),
            },
            "content-bound",
        ),
    ],
)
def test_retained_evidence_rejects_substitution_or_weak_retention(
    updates: dict[str, Any], message: str
) -> None:
    module = _load()
    payload = b'{"synthetic":true}'
    with pytest.raises(module.RegionalActivationPreflightError, match=message):
        module.read_retained_evidence(
            _activation(module, payload),
            expected_bucket_arn="arn:aws:s3:::primary-audit",
            s3_client=_S3(payload, **updates),
            now=datetime.fromtimestamp(1000, tz=UTC),
        )


def test_authority_alignment_rejects_target_widening() -> None:
    module = _load()
    regional = _regional(module)
    widened = module.recovery.RegionalRecoveryManifest(
        regional.stack_name,
        regional.primary_region,
        regional.recovery_region,
        2000,
        regional.rto_minutes,
        regional.rpo_seconds,
        regional.approval_evidence_ref,
    )
    with pytest.raises(module.RegionalActivationPreflightError, match="targets disagree"):
        module.verify_authority_alignment(
            _activation(module), widened, _continuity(module), _passive(module)
        )


def test_passive_stack_and_both_direct_origins_must_be_provider_verified() -> None:
    module = _load()

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if "describe-stacks" in command:
            return _completed(
                {
                    "Stacks": [
                        {
                            "StackStatus": "CREATE_COMPLETE",
                            "Outputs": [
                                {
                                    "OutputKey": "PassiveCellStatus",
                                    "OutputValue": "staged-not-serving",
                                },
                                {
                                    "OutputKey": "PassiveControlPlaneApiId",
                                    "OutputValue": "target123",
                                },
                            ],
                        }
                    ]
                }
            )
        if "get-api" in command:
            api_id = command[command.index("--api-id") + 1]
            return _completed({"ApiId": api_id, "DisableExecuteApiEndpoint": True})
        raise AssertionError(command)

    assert module.verify_passive_stack(_passive(module), profile="synthetic", runner=runner)
    result = module.verify_api_origin_fencing(
        primary_api_url="https://source123.execute-api.eu-west-2.amazonaws.com",
        passive_api_id="target123",
        primary_region="eu-west-2",
        recovery_region="eu-west-1",
        profile="synthetic",
        runner=runner,
    )
    assert result == {"sourceApiId": "source123", "targetApiId": "target123"}


def test_post_activation_preflight_requires_active_not_routed_exactly() -> None:
    module = _load()

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        assert "describe-stacks" in command
        return _completed(
            {
                "Stacks": [
                    {
                        "StackStatus": "UPDATE_COMPLETE",
                        "Outputs": [
                            {
                                "OutputKey": "PassiveCellStatus",
                                "OutputValue": "active-not-routed",
                            },
                            {
                                "OutputKey": "PassiveControlPlaneApiId",
                                "OutputValue": "target123",
                            },
                        ],
                    }
                ]
            }
        )

    assert (
        module.verify_passive_stack(
            _passive(module),
            profile="synthetic",
            expected_status="active-not-routed",
            runner=runner,
        )
        == "target123"
    )
    with pytest.raises(module.RegionalActivationPreflightError, match="staged-not-serving"):
        module.verify_passive_stack(_passive(module), profile="synthetic", runner=runner)


def test_origin_fencing_fails_when_provider_exposes_either_raw_api() -> None:
    module = _load()

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        api_id = command[command.index("--api-id") + 1]
        return _completed({"ApiId": api_id, "DisableExecuteApiEndpoint": api_id != "target123"})

    with pytest.raises(module.RegionalActivationPreflightError, match="target direct"):
        module.verify_api_origin_fencing(
            primary_api_url="https://source123.execute-api.eu-west-2.amazonaws.com",
            passive_api_id="target123",
            primary_region="eu-west-2",
            recovery_region="eu-west-1",
            profile="synthetic",
            runner=runner,
        )


def test_dns_requires_both_stable_names() -> None:
    module = _load()

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        assert "list-resource-record-sets" in command
        return _completed(
            {
                "ResourceRecordSets": [
                    {"Name": "api.security.example.com.", "Type": "A"},
                    {"Name": "security.example.com.", "Type": "AAAA"},
                ]
            }
        )

    module.verify_stable_dns_records(_activation(module), profile="synthetic", runner=runner)


def test_expired_datetime_is_not_confused_by_local_timezone() -> None:
    module = _load()
    payload = b'{"synthetic":true}'
    s3 = _S3(
        payload,
        ObjectLockRetainUntilDate=datetime.now(UTC) - timedelta(seconds=1),
    )
    with pytest.raises(module.RegionalActivationPreflightError, match="content-bound"):
        module.read_retained_evidence(
            _activation(module, payload),
            expected_bucket_arn="arn:aws:s3:::primary-audit",
            s3_client=s3,
            now=datetime.now(UTC),
        )


def test_provider_preflight_repeats_all_boundaries_without_activation(
    monkeypatch: Any,
) -> None:
    module = _load()
    payload = json.dumps(
        {"identity": {"recoveryPoolId": "eu-west-1_AbCdEf123"}},
        separators=(",", ":"),
    ).encode()
    manifest = _activation(module, payload)
    regional = _regional(module)
    evidence_continuity = _continuity(module)
    passive_cell = _passive(module)
    calls: list[str] = []

    def passive_stack(*args: Any, **kwargs: Any) -> str:
        calls.append("passive-stack")
        return "target123"

    def origin_fencing(**kwargs: Any) -> dict[str, str]:
        calls.append("origin-fencing")
        return {"sourceApiId": "source123", "targetApiId": "target123"}

    monkeypatch.setattr(
        module.recovery,
        "load_persisted_manifest",
        lambda *args, **kwargs: calls.append("regional-authority"),
    )
    monkeypatch.setattr(
        module.continuity,
        "require_persisted_manifest",
        lambda *args, **kwargs: calls.append("continuity-authority"),
    )
    monkeypatch.setattr(
        module.passive,
        "require_persisted_manifest",
        lambda *args, **kwargs: calls.append("passive-authority"),
    )
    monkeypatch.setattr(
        module.continuity,
        "discover",
        lambda *args, **kwargs: {
            "primaryBucket": "primary-audit",
            "primaryBucketArn": "arn:aws:s3:::primary-audit",
            "recoveryBucket": "recovery-audit",
            "recoveryBucketArn": "arn:aws:s3:::recovery-audit",
        },
    )
    monkeypatch.setattr(
        module.passive,
        "verify_recovery_identity",
        lambda *args, **kwargs: {"status": "configured-not-activated"},
    )
    monkeypatch.setattr(
        module.recovery,
        "stack_outputs",
        lambda *args, **kwargs: {"ApiUrl": "https://source123.execute-api.eu-west-2.amazonaws.com"},
    )
    monkeypatch.setattr(
        module,
        "verify_passive_stack",
        passive_stack,
    )
    monkeypatch.setattr(
        module,
        "verify_api_origin_fencing",
        origin_fencing,
    )
    monkeypatch.setattr(
        module,
        "verify_stable_dns_records",
        lambda *args, **kwargs: calls.append("stable-dns"),
    )
    monkeypatch.setattr(
        module.continuity,
        "verify_live_direction",
        lambda **kwargs: {"status": "verified-live-immutable-replication"},
    )
    verified = {
        "status": "verified-ready-for-manual-transition",
        "transitionId": manifest.transition_id,
    }
    monkeypatch.setattr(
        module.activation,
        "verify_bundle",
        lambda current, body, now: verified,
    )
    monkeypatch.setattr(
        module.activation,
        "transition_plan",
        lambda current, evidence: [{"order": 1}],
    )

    result = module.provider_preflight(
        manifest,
        regional,
        evidence_continuity,
        passive_cell,
        profile="synthetic",
        s3_factory=lambda region: _S3(payload),
        now_epoch=1000,
    )
    assert result["activationExecuted"] is False
    assert result["status"] == "provider-state-verified-ready-for-manual-transition"
    assert result["plan"] == [{"order": 1}]
    assert calls == [
        "regional-authority",
        "continuity-authority",
        "passive-authority",
        "passive-stack",
        "origin-fencing",
        "stable-dns",
    ]

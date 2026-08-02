#!/usr/bin/env python3
"""Validate and retain one exact regional activation evidence bundle.

This command does not manufacture exercise results. It accepts a complete
bundle produced by independent probes, validates every claim against schema-v4
transition authority, writes one digest-addressed COMPLIANCE-locked S3 version,
reads the exact bytes back, and prints the finalized manifest. The mutation
requires an explicit operator confirmation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import deploy_aws_evidence_continuity as continuity  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import verify_aws_regional_activation as activation  # noqa: E402


class RegionalEvidenceRetentionError(RuntimeError):
    """Report evidence that cannot be safely retained as transition authority."""


def _read_exact(response: dict[str, Any]) -> bytes:
    """Read at most one MiB from one untrusted S3 response body."""
    body = response.get("Body")
    if body is None or not hasattr(body, "read"):
        raise RegionalEvidenceRetentionError("retained evidence body is unavailable")
    try:
        payload = body.read(1_048_577)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes) or len(payload) > 1_048_576:
        raise RegionalEvidenceRetentionError("retained evidence exceeds one MiB")
    return payload


def _verify_version(
    client: Any,
    *,
    bucket: str,
    key: str,
    version_id: str,
    digest: str,
    minimum_retention: datetime,
) -> None:
    """Prove exact bytes, metadata and immutable retention on one S3 version."""
    try:
        response = client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    except Exception as error:
        raise RegionalEvidenceRetentionError(
            "exact retained evidence version cannot be read"
        ) from error
    payload = _read_exact(response)
    metadata = response.get("Metadata")
    retained_until = response.get("ObjectLockRetainUntilDate")
    if (
        response.get("VersionId") != version_id
        or hashlib.sha256(payload).hexdigest() != digest
        or not isinstance(metadata, dict)
        or metadata.get("content-sha256") != digest
        or metadata.get("transition-id") != key.split("/")[1]
        or response.get("ObjectLockMode") != "COMPLIANCE"
        or not isinstance(retained_until, datetime)
        or retained_until.tzinfo is None
        or retained_until < minimum_retention
    ):
        raise RegionalEvidenceRetentionError(
            "retained evidence bytes or COMPLIANCE authority differ"
        )


def _existing_version(
    client: Any,
    *,
    bucket: str,
    key: str,
    digest: str,
    minimum_retention: datetime,
) -> str | None:
    """Return one exact prior version or reject ambiguous retry authority."""
    try:
        response = client.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=3)
    except Exception as error:
        raise RegionalEvidenceRetentionError(
            "existing evidence versions cannot be enumerated"
        ) from error
    versions = [
        item
        for item in response.get("Versions", [])
        if isinstance(item, dict) and item.get("Key") == key
    ]
    delete_markers = [
        item
        for item in response.get("DeleteMarkers", [])
        if isinstance(item, dict) and item.get("Key") == key
    ]
    if response.get("IsTruncated") is True or delete_markers or len(versions) > 1:
        raise RegionalEvidenceRetentionError("retained evidence version history is ambiguous")
    if not versions:
        return None
    version_id = versions[0].get("VersionId")
    if not isinstance(version_id, str) or not version_id or len(version_id) > 1024:
        raise RegionalEvidenceRetentionError("retained evidence version identity is malformed")
    _verify_version(
        client,
        bucket=bucket,
        key=key,
        version_id=version_id,
        digest=digest,
        minimum_retention=minimum_retention,
    )
    return version_id


def retain_evidence(
    manifest: activation.ActivationManifest,
    manifest_document: dict[str, Any],
    payload: bytes,
    *,
    expected_bucket_arn: str,
    s3_client: Any,
    now: datetime,
    retention_days: int = 365,
) -> dict[str, Any]:
    """Validate, retain, read back and return one finalized activation manifest."""
    manifest.require_reactivation_authority()
    if now.tzinfo is None:
        raise RegionalEvidenceRetentionError("retention clock must be timezone-aware")
    if not 365 <= retention_days <= 3650:
        raise RegionalEvidenceRetentionError("retention must be between 365 and 3650 days")
    if not isinstance(payload, bytes) or len(payload) > 1_048_576:
        raise RegionalEvidenceRetentionError("activation evidence exceeds one MiB")
    bucket = expected_bucket_arn.removeprefix("arn:aws:s3:::")
    digest = hashlib.sha256(payload).hexdigest()
    key = f"regional-activation/{manifest.transition_id}/{digest}.json"
    if (
        not bucket
        or bucket == expected_bucket_arn
        or manifest.evidence.bucket_arn != expected_bucket_arn
        or manifest.evidence.key != key
    ):
        raise RegionalEvidenceRetentionError(
            "draft evidence bucket or digest-addressed key differs from provider authority"
        )
    # The evidence digest is excluded from authority_sha256 to avoid a circular
    # reference. Replace only that field for validation; all actual transition
    # authority remains bound by the parsed schema-v4 manifest.
    verified_manifest = replace(
        manifest,
        evidence=activation.EvidenceReference(
            expected_bucket_arn,
            key,
            manifest.evidence.version_id,
            digest,
        ),
    )
    activation.verify_bundle(verified_manifest, payload, now=int(now.timestamp()))
    minimum_retention = max(
        now + timedelta(days=retention_days),
        datetime.fromtimestamp(manifest.expires_at, tz=UTC) + timedelta(days=1),
    )
    version_id = _existing_version(
        s3_client,
        bucket=bucket,
        key=key,
        digest=digest,
        minimum_retention=minimum_retention,
    )
    if version_id is None:
        try:
            created = s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=payload,
                ContentType="application/json",
                Metadata={
                    "content-sha256": digest,
                    "transition-id": manifest.transition_id,
                },
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=minimum_retention,
                Tagging="evidence-class=regional-activation",
                IfNoneMatch="*",
            )
            version_id = created.get("VersionId")
            if not isinstance(version_id, str) or not version_id or len(version_id) > 1024:
                raise RegionalEvidenceRetentionError("retained evidence has no version identity")
            _verify_version(
                s3_client,
                bucket=bucket,
                key=key,
                version_id=version_id,
                digest=digest,
                minimum_retention=minimum_retention,
            )
        except RegionalEvidenceRetentionError:
            raise
        except Exception as error:
            # A response can be lost after S3 commits the immutable version.
            # Recover only one exact read-back-verified version; never write a
            # second version or choose among ambiguous history.
            version_id = _existing_version(
                s3_client,
                bucket=bucket,
                key=key,
                digest=digest,
                minimum_retention=minimum_retention,
            )
            if version_id is None:
                raise RegionalEvidenceRetentionError(
                    "activation evidence retention failed"
                ) from error
    final_manifest = dict(manifest_document)
    final_manifest["evidenceBundle"] = {
        "bucketArn": expected_bucket_arn,
        "key": key,
        "versionId": version_id,
        "sha256": digest,
    }
    # Reparse the emitted document so output cannot bypass manifest validation.
    activation.ActivationManifest.parse(
        json.dumps(final_manifest, sort_keys=True, separators=(",", ":")),
        now=int(now.timestamp()),
    )
    return {
        "evidenceReference": final_manifest["evidenceBundle"],
        "finalManifest": final_manifest,
        "retainedUntil": minimum_retention.isoformat(),
        "status": "activation-evidence-retained-and-read-back",
    }


def _parser() -> argparse.ArgumentParser:
    """Build the explicit evidence-retention command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--evidence-continuity-config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--retention-days", type=int, default=365)
    parser.add_argument("--confirm-retain-evidence", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Retain exact evidence only after validation and explicit confirmation."""
    arguments = _parser().parse_args(argv)
    try:
        if not arguments.confirm_retain_evidence:
            raise RegionalEvidenceRetentionError(
                "--confirm-retain-evidence is required for the immutable S3 write"
            )
        manifest_text = arguments.manifest.read_text(encoding="utf-8")
        manifest_document = json.loads(manifest_text, object_pairs_hook=activation._strict_object)
        if not isinstance(manifest_document, dict):
            raise RegionalEvidenceRetentionError("activation manifest must be an object")
        manifest = activation.ActivationManifest.parse(manifest_text)
        regional = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        continuity_manifest = continuity.EvidenceContinuityManifest.parse(
            arguments.evidence_continuity_config.read_text(encoding="utf-8")
        )
        resources = continuity.discover(continuity_manifest, regional, profile=arguments.profile)
        import boto3

        session = boto3.Session(profile_name=arguments.profile)
        result = retain_evidence(
            manifest,
            manifest_document,
            arguments.evidence.read_bytes(),
            expected_bucket_arn=resources["primaryBucketArn"],
            s3_client=session.client("s3", region_name=regional.primary_region),
            now=datetime.now(UTC),
            retention_days=arguments.retention_days,
        )
        print(json.dumps(result, sort_keys=True))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        activation.RegionalActivationVerificationError,
        recovery.RecoveryConfigurationError,
        continuity.EvidenceContinuityDeploymentError,
        RegionalEvidenceRetentionError,
    ) as error:
        print(f"Regional evidence retention failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

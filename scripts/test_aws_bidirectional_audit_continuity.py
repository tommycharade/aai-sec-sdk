#!/usr/bin/env python3
"""Exercise immutable S3 audit continuity in both regional directions.

The canary leaves two synthetic COMPLIANCE-locked versions in place. It proves
exact bytes, metadata, version identity and provenance, then modifies retention
and tags on each replica and requires those changes to synchronize back to the
origin. It never creates or deletes an evidence marker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any


def _missing(error: Exception) -> bool:
    """Return whether one provider error represents an absent version."""
    return getattr(error, "response", {}).get("Error", {}).get("Code") in {
        "404",
        "NoSuchKey",
        "NoSuchVersion",
    }


def _tags(response: dict[str, Any]) -> dict[str, str]:
    """Normalize an exact S3 tag response without accepting duplicate keys."""
    result: dict[str, str] = {}
    tag_set = response.get("TagSet")
    if not isinstance(tag_set, list):
        raise RuntimeError("S3 version tags are malformed")
    for item in tag_set:
        if not isinstance(item, dict) or set(item) != {"Key", "Value"}:
            raise RuntimeError("S3 version tag is malformed")
        key, value = item["Key"], item["Value"]
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise RuntimeError("S3 version tag identity is malformed")
        result[key] = value
    return result


def _wait(
    probe: Callable[[], bool], *, timeout_seconds: int, sleep: Callable[[float], None]
) -> None:
    """Poll one bounded provider invariant or fail without weakening it."""
    deadline = time.monotonic() + max(timeout_seconds, 1)
    while time.monotonic() < deadline:
        if probe():
            return
        sleep(min(5.0, max(deadline - time.monotonic(), 0.01)))
    raise RuntimeError("evidence continuity condition was not met before timeout")


def exercise_direction(
    source: Any,
    destination: Any,
    *,
    source_bucket: str,
    destination_bucket: str,
    direction: str,
    timeout_seconds: int,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, str]:
    """Write and verify one direction plus reverse replica-modification sync."""
    nonce = uuid.uuid4().hex
    key = f"continuity-canary/{direction}/{nonce}.json"
    body = json.dumps(
        {"purpose": "bidirectional-audit-continuity", "synthetic": True, "nonce": nonce},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(body).hexdigest()
    original_retention = datetime.now(UTC) + timedelta(days=366)
    created = source.put_object(
        Bucket=source_bucket,
        Key=key,
        Body=body,
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=original_retention,
        Metadata={"content-sha256": digest, "synthetic": "true"},
        Tagging=f"continuity-direction={direction}",
    )
    version_id = created.get("VersionId")
    if not isinstance(version_id, str) or not version_id:
        raise RuntimeError("source canary did not receive a version identity")

    def destination_present() -> bool:
        try:
            response = destination.get_object(
                Bucket=destination_bucket, Key=key, VersionId=version_id
            )
        except Exception as error:
            if _missing(error):
                return False
            raise
        payload = response.get("Body")
        replicated_body = payload.read() if hasattr(payload, "read") else payload
        retain_until = response.get("ObjectLockRetainUntilDate")
        if (
            replicated_body != body
            or response.get("Metadata") != {"content-sha256": digest, "synthetic": "true"}
            or response.get("ObjectLockMode") != "COMPLIANCE"
            or not isinstance(retain_until, datetime)
            or retain_until < original_retention - timedelta(seconds=1)
        ):
            raise RuntimeError("replicated canary bytes, metadata or retention differ")
        return bool(response.get("ReplicationStatus") == "REPLICA")

    _wait(destination_present, timeout_seconds=timeout_seconds, sleep=sleep)

    extended_retention = original_retention + timedelta(days=1)
    sync_token = f"return-{nonce[:16]}"
    destination.put_object_retention(
        Bucket=destination_bucket,
        Key=key,
        VersionId=version_id,
        Retention={"Mode": "COMPLIANCE", "RetainUntilDate": extended_retention},
    )
    destination.put_object_tagging(
        Bucket=destination_bucket,
        Key=key,
        VersionId=version_id,
        Tagging={
            "TagSet": [
                {"Key": "continuity-direction", "Value": direction},
                {"Key": "replica-modification-proof", "Value": sync_token},
            ]
        },
    )

    def modification_returned() -> bool:
        retention = source.get_object_retention(
            Bucket=source_bucket, Key=key, VersionId=version_id
        ).get("Retention", {})
        retain_until = retention.get("RetainUntilDate")
        tags = _tags(source.get_object_tagging(Bucket=source_bucket, Key=key, VersionId=version_id))
        return bool(
            retention.get("Mode") == "COMPLIANCE"
            and isinstance(retain_until, datetime)
            and retain_until >= extended_retention - timedelta(seconds=1)
            and tags.get("replica-modification-proof") == sync_token
            and tags.get("continuity-direction") == direction
        )

    _wait(modification_returned, timeout_seconds=timeout_seconds, sleep=sleep)
    return {"key": key, "versionId": version_id, "contentSha256": digest}


def main() -> int:
    """Create clients and require both regional directions to pass."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary-bucket", required=True)
    parser.add_argument("--primary-region", required=True)
    parser.add_argument("--recovery-bucket", required=True)
    parser.add_argument("--recovery-region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    arguments = parser.parse_args()
    if arguments.primary_region == arguments.recovery_region:
        raise ValueError("primary and recovery Regions must be distinct")

    import boto3

    primary = boto3.Session(
        profile_name=arguments.profile, region_name=arguments.primary_region
    ).client("s3")
    recovery = boto3.Session(
        profile_name=arguments.profile, region_name=arguments.recovery_region
    ).client("s3")
    forward = exercise_direction(
        primary,
        recovery,
        source_bucket=arguments.primary_bucket,
        destination_bucket=arguments.recovery_bucket,
        direction="primary-to-recovery",
        timeout_seconds=arguments.timeout_seconds,
    )
    reverse = exercise_direction(
        recovery,
        primary,
        source_bucket=arguments.recovery_bucket,
        destination_bucket=arguments.primary_bucket,
        direction="recovery-to-primary",
        timeout_seconds=arguments.timeout_seconds,
    )
    print(
        json.dumps(
            {
                "status": "bidirectional-evidence-continuity-passed",
                "primaryToRecovery": forward,
                "recoveryToPrimary": reverse,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

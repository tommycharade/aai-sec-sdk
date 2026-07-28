#!/usr/bin/env python3
"""Verify cross-region S3 audit replication and retention metadata.

The test intentionally leaves its synthetic object retained in both buckets;
Object Lock is the control being verified and a compliant object cannot be
deleted before its retention date.
"""

from __future__ import annotations

import argparse
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any


def main() -> int:
    """Create one locked source object and require a locked replica."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-bucket", required=True)
    parser.add_argument("--source-region", required=True)
    parser.add_argument("--replica-bucket", required=True)
    parser.add_argument("--replica-region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()

    import boto3  # type: ignore[import-untyped]

    source_session = boto3.Session(profile_name=args.profile, region_name=args.source_region)
    replica_session = boto3.Session(profile_name=args.profile, region_name=args.replica_region)
    source = source_session.client("s3")
    replica = replica_session.client("s3")
    key = f"replication-smoke/{uuid.uuid4().hex}.json"
    retain_until = datetime.now(UTC) + timedelta(days=365)
    body = b'{"synthetic":true,"purpose":"cross-region-audit-replication"}'
    source.put_object(
        Bucket=args.source_bucket,
        Key=key,
        Body=body,
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retain_until,
        Metadata={"synthetic": "true"},
    )
    deadline = time.monotonic() + max(args.timeout_seconds, 1)
    replica_head: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            candidate = replica.head_object(Bucket=args.replica_bucket, Key=key)
        except replica.exceptions.NoSuchKey:
            candidate = None
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") in {
                "404",
                "NoSuchKey",
            }:
                candidate = None
            else:
                raise
        if candidate and candidate.get("ReplicationStatus") == "REPLICA":
            replica_head = candidate
            break
        time.sleep(5)
    if replica_head is None:
        raise RuntimeError(f"replica was not received before timeout: {key}")
    if replica_head.get("ObjectLockMode") != "COMPLIANCE":
        raise RuntimeError("replica did not retain COMPLIANCE Object Lock mode")
    if replica_head.get(
        "ObjectLockRetainUntilDate", datetime.min.replace(tzinfo=UTC)
    ) <= datetime.now(UTC):
        raise RuntimeError("replica retention date is already expired")
    if replica_head.get("Metadata", {}).get("synthetic") != "true":
        raise RuntimeError("replica metadata was not preserved")
    print(f"AWS audit replication passed: {args.source_region} -> {args.replica_region}, key={key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

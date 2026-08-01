#!/usr/bin/env python3
"""Verify complete immutable audit recovery across two AWS Regions."""

from __future__ import annotations

import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any


def list_versions(s3: Any, bucket: str, maximum: int) -> list[dict[str, Any]]:
    """Return an exact, deterministic and bounded list of retained object versions."""
    versions: list[dict[str, Any]] = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions.extend(page.get("Versions", []))
        if len(versions) > maximum:
            raise RuntimeError(f"bucket exceeds the {maximum}-version verification bound")
    return sorted(versions, key=lambda item: (item["Key"], item["VersionId"]))


def inspect_version(s3: Any, bucket: str, version: dict[str, Any]) -> dict[str, Any]:
    """Hash one exact version and bind its immutable retention and metadata."""
    response = s3.get_object(Bucket=bucket, Key=version["Key"], VersionId=version["VersionId"])
    digest = hashlib.sha256(response["Body"].read()).hexdigest()
    return {
        "key": version["Key"],
        "versionId": version["VersionId"],
        "sha256": digest,
        "contentSha256": response.get("Metadata", {}).get("content-sha256"),
        "mode": response.get("ObjectLockMode"),
        "retainUntil": response.get("ObjectLockRetainUntilDate", datetime.min.replace(tzinfo=UTC))
        .astimezone(UTC)
        .isoformat(),
        "replicationStatus": response.get("ReplicationStatus"),
    }


def inspect_all(s3: Any, bucket: str, versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Inspect versions with bounded concurrency while preserving canonical order."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(lambda version: inspect_version(s3, bucket, version), versions))


def verify(source_items: list[dict[str, Any]], replica_items: list[dict[str, Any]]) -> str:
    """Require exact identity, bytes, metadata, compliance retention and replica provenance."""
    if len(source_items) != len(replica_items):
        raise RuntimeError(
            f"version count differs: source={len(source_items)}, replica={len(replica_items)}"
        )
    for source, replica in zip(source_items, replica_items, strict=True):
        if (source["key"], source["versionId"]) != (replica["key"], replica["versionId"]):
            raise RuntimeError("canonical object/version ordering differs")
        if source["sha256"] != replica["sha256"]:
            raise RuntimeError(f"content digest differs for {source['key']}")
        if source["contentSha256"] != replica["contentSha256"]:
            raise RuntimeError(f"content metadata differs for {source['key']}")
        if source["mode"] != "COMPLIANCE" or replica["mode"] != "COMPLIANCE":
            raise RuntimeError(f"COMPLIANCE retention is missing for {source['key']}")
        if replica["retainUntil"] < source["retainUntil"]:
            raise RuntimeError(f"replica retention is shorter for {source['key']}")
        if replica["replicationStatus"] != "REPLICA":
            raise RuntimeError(f"replica provenance is missing for {source['key']}")
    canonical = json.dumps(source_items, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    """Enumerate both buckets and emit an independently computed recovery digest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-bucket", required=True)
    parser.add_argument("--source-region", required=True)
    parser.add_argument("--replica-bucket", required=True)
    parser.add_argument("--replica-region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--max-versions", type=int, default=100_000)
    args = parser.parse_args()

    import boto3

    source = boto3.Session(profile_name=args.profile, region_name=args.source_region).client("s3")
    replica = boto3.Session(profile_name=args.profile, region_name=args.replica_region).client("s3")
    source_versions = list_versions(source, args.source_bucket, args.max_versions)
    replica_versions = list_versions(replica, args.replica_bucket, args.max_versions)
    source_items = inspect_all(source, args.source_bucket, source_versions)
    replica_items = inspect_all(replica, args.replica_bucket, replica_versions)
    digest = verify(source_items, replica_items)
    print(
        json.dumps(
            {
                "canonicalManifestSha256": digest,
                "replicaRegion": args.replica_region,
                "sourceRegion": args.source_region,
                "verifiedVersions": len(source_items),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

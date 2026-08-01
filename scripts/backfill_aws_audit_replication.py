#!/usr/bin/env python3
"""Run one bounded S3 Batch Replication repair for immutable audit versions.

The source bucket must already have live replication configured. Amazon S3
generates an exact, version-aware manifest for objects whose replication status
is NONE or FAILED as of a fixed cutoff. The script refuses an unexpectedly
large source before creating a chargeable Batch Operations job.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any, cast


def count_versions_before(s3: Any, bucket: str, cutoff: datetime, maximum: int) -> int:
    """Count bounded source versions at the job cutoff or fail before mutation."""
    count = 0
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for version in page.get("Versions", []):
            if version["LastModified"] < cutoff:
                count += 1
                if count > maximum:
                    raise RuntimeError(f"source exceeds the {maximum}-version safety bound")
    return count


def wait_for_job(s3control: Any, account_id: str, job_id: str, timeout: int) -> dict[str, Any]:
    """Wait for one exact job and reject timeout, cancellation or partial failure."""
    deadline = time.monotonic() + max(timeout, 1)
    while time.monotonic() < deadline:
        job = cast(
            dict[str, Any],
            s3control.describe_job(AccountId=account_id, JobId=job_id)["Job"],
        )
        status = job.get("Status")
        if status == "Complete":
            progress = job.get("ProgressSummary", {})
            if progress.get("NumberOfTasksFailed", 0) != 0:
                raise RuntimeError("batch replication completed with failed tasks")
            return job
        if status in {"Cancelled", "Cancelling", "Failed", "Failing", "Suspended"}:
            raise RuntimeError(f"batch replication entered terminal status {status}")
        time.sleep(10)
    raise RuntimeError(f"batch replication did not complete within {timeout} seconds")


def main() -> int:
    """Create, monitor and report one bounded historical replication job."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-bucket", required=True)
    parser.add_argument("--report-bucket", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--max-versions", type=int, default=100_000)
    parser.add_argument("--timeout-seconds", type=int, default=3_600)
    args = parser.parse_args()
    if not 1 <= args.max_versions <= 1_000_000:
        raise RuntimeError("max-versions must be between 1 and 1,000,000")

    import boto3

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    source = session.client("s3")
    control = session.client("s3control")
    cutoff = datetime.now(UTC)
    source_count = count_versions_before(source, args.source_bucket, cutoff, args.max_versions)
    token = str(uuid.uuid4())
    response = control.create_job(
        AccountId=account_id,
        ConfirmationRequired=False,
        Operation={"S3ReplicateObject": {}},
        Report={
            "Bucket": f"arn:aws:s3:::{args.report_bucket}",
            "Prefix": f"replication-reports/{token}",
            "Format": "Report_CSV_20180820",
            "Enabled": True,
            "ReportScope": "AllTasks",
            "ExpectedBucketOwner": account_id,
        },
        ManifestGenerator={
            "S3JobManifestGenerator": {
                "ExpectedBucketOwner": account_id,
                "SourceBucket": f"arn:aws:s3:::{args.source_bucket}",
                "EnableManifestOutput": False,
                "Filter": {
                    "EligibleForReplication": True,
                    "ObjectReplicationStatuses": ["NONE", "FAILED"],
                    "CreatedBefore": cutoff,
                },
            }
        },
        Priority=10,
        RoleArn=args.role_arn,
        ClientRequestToken=token,
        Description=f"AAI immutable audit recovery backfill before {cutoff.isoformat()}",
        Tags=[{"Key": "aai-sec-purpose", "Value": "audit-recovery"}],
    )
    job_id = response["JobId"]
    job = wait_for_job(control, account_id, job_id, args.timeout_seconds)
    progress = job.get("ProgressSummary", {})
    if progress.get("TotalNumberOfTasks", 0) > args.max_versions:
        raise RuntimeError("provider-generated job exceeded the configured safety bound")
    print(
        json.dumps(
            {
                "cutoff": cutoff.isoformat(),
                "jobId": job_id,
                "sourceVersionsAtCutoff": source_count,
                "tasksFailed": progress.get("NumberOfTasksFailed", 0),
                "tasksSucceeded": progress.get("NumberOfTasksSucceeded", 0),
                "totalTasks": progress.get("TotalNumberOfTasks", 0),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

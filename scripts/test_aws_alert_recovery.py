#!/usr/bin/env python3
"""Verify that an unacknowledged synthetic alert reaches the SQS DLQ."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from typing import Any


def _message_for_marker(message: dict[str, Any], marker: str) -> bool:
    """Match only the synthetic body used by this run."""
    return marker in str(message.get("Body", ""))


def main() -> int:
    """Send one synthetic alert, force redrive, and require DLQ delivery."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue-url", required=True)
    parser.add_argument("--dlq-url", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default=None)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()

    import boto3

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sqs = session.client("sqs")
    marker = f"aai-sec-alert-recovery-{uuid.uuid4().hex}"
    sqs.send_message(
        QueueUrl=args.queue_url,
        MessageBody=json.dumps({"synthetic": True, "marker": marker}),
    )
    deadline = time.monotonic() + max(args.timeout_seconds, 1)
    dlq_message: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        response = sqs.receive_message(
            QueueUrl=args.queue_url,
            MaxNumberOfMessages=10,
            VisibilityTimeout=0,
            WaitTimeSeconds=2,
            AttributeNames=["All"],
        )
        for message in response.get("Messages", []):
            if _message_for_marker(message, marker):
                continue
            # Do not interfere with unrelated operational messages.
            sqs.change_message_visibility(
                QueueUrl=args.queue_url,
                ReceiptHandle=message["ReceiptHandle"],
                VisibilityTimeout=0,
            )
        dlq_response = sqs.receive_message(
            QueueUrl=args.dlq_url,
            MaxNumberOfMessages=10,
            VisibilityTimeout=30,
            WaitTimeSeconds=2,
            AttributeNames=["All"],
        )
        for message in dlq_response.get("Messages", []):
            if _message_for_marker(message, marker):
                dlq_message = message
                break
        if dlq_message is not None:
            break
        time.sleep(2)
    if dlq_message is None:
        raise RuntimeError("synthetic alert did not reach the configured DLQ")
    sqs.delete_message(QueueUrl=args.dlq_url, ReceiptHandle=dlq_message["ReceiptHandle"])
    print("AWS alert recovery passed: unacknowledged synthetic alert reached the SQS DLQ")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

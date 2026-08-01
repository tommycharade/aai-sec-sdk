"""Asynchronous durable-evidence worker entry point.

The worker is invoked only by the deployment-owned SQS event-source mapping.
It delegates to the shared control-plane implementation, which reloads every
tenant/job identity and optimistic revision from DynamoDB before touching S3.
"""

from handler import process_evidence_queue_event


def handler(event, context):
    """Process one bounded FIFO evidence page; ``context`` is intentionally unused."""
    return process_evidence_queue_event(event)

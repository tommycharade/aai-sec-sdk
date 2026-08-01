"""Dedicated asynchronous evidence-retention Lambda entry point.

SQS is invocation authority only. The shared handler reloads the exact
tenant/job/revision from DynamoDB before any Object Lock mutation.
"""

from handler import process_retention_queue_event


def handler(event, context):
    """Process one bounded, revision-bound retention queue event."""
    return process_retention_queue_event(event)

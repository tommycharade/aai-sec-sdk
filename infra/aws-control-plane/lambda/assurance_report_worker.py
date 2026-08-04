"""Dedicated asynchronous signed-assurance report worker.

Only the deployment-owned SQS event-source mapping may invoke this adapter.
The shared handler reloads the tenant schedule and requires the exact pending
occurrence revision before it derives, signs, or stores report evidence.
"""

from handler import process_assurance_report_queue_event


def handler(event, context):
    """Process one revision-bound report job; ``context`` is intentionally unused."""
    return process_assurance_report_queue_event(event)

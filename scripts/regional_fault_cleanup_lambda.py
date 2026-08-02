"""Perform expiry-safe cleanup for one exact Regional dependency fault.

EventBridge Scheduler invokes this Lambda independently of Step Functions. It
does not require an unexpired activation approval: cleanup authority is the
matching durable lock, exact authority digest, UUID-derived policy name and
deployment-owned target role. It can only delete that one inline deny.
"""

from __future__ import annotations

import re
from typing import Any

import boto3
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from scripts.regional_fault_controller_lambda import (
    ControllerConfig,
    RegionalFaultControllerError,
    _policy_name,
    _role_name,
)

_FIELDS = {"schemaVersion", "faultId", "authoritySha256", "targetCellRole"}
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _parse(event: object) -> tuple[str, str, str]:
    """Parse only the immutable fields needed to remove one exact deny."""
    if not isinstance(event, dict) or set(event) != _FIELDS or event.get("schemaVersion") != 1:
        raise RegionalFaultControllerError("fault cleanup event schema is invalid")
    fault_id = event.get("faultId")
    digest = event.get("authoritySha256")
    cell_role = event.get("targetCellRole")
    if (
        not isinstance(fault_id, str)
        or not _UUID.fullmatch(fault_id)
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or cell_role not in {"primary", "recovery"}
    ):
        raise RegionalFaultControllerError("fault cleanup event values are invalid")
    return fault_id, digest, cell_role


def cleanup(event: object, *, config: ControllerConfig, dynamodb: Any, iam: Any) -> dict[str, Any]:
    """Delete one exact policy only when its durable lock digest matches."""
    fault_id, digest, cell_role = _parse(event)
    key = {"pk": {"S": "REGIONAL_FAULT"}, "sk": {"S": f"TARGET#{cell_role}"}}
    lock = dynamodb.get_item(
        TableName=config.journal_table_name,
        Key=key,
        ConsistentRead=True,
    ).get("Item")
    if lock is None:
        evidence = dynamodb.get_item(
            TableName=config.journal_table_name,
            Key={
                "pk": {"S": "REGIONAL_FAULT_EVIDENCE"},
                "sk": {"S": f"FAULT#{fault_id}"},
            },
            ConsistentRead=True,
        ).get("Item")
        if (
            isinstance(evidence, dict)
            and evidence.get("authoritySha256") == {"S": digest}
            and evidence.get("targetCellRole") == {"S": cell_role}
            and evidence.get("status") == {"S": "WATCHDOG_CLEANED"}
        ):
            return {
                "schemaVersion": 1,
                "faultId": fault_id,
                "authoritySha256": digest,
                "status": "already-watchdog-cleaned",
            }
    if (
        not isinstance(lock, dict)
        or lock.get("faultId") != {"S": fault_id}
        or lock.get("authoritySha256") != {"S": digest}
        or lock.get("state")
        not in (
            {"S": "LOCKED"},
            {"S": "WATCHDOG_ARMED"},
            {"S": "DENY_APPLIED"},
            {"S": "DENY_REMOVED"},
        )
    ):
        raise RegionalFaultControllerError("fault cleanup lock authority differs")
    role_name = _role_name(config.target(cell_role).role_arn)
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=_policy_name(fault_id))
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    dynamodb.transact_write_items(
        TransactItems=[
            {
                "Put": {
                    "TableName": config.journal_table_name,
                    "Item": {
                        "pk": {"S": "REGIONAL_FAULT_EVIDENCE"},
                        "sk": {"S": f"FAULT#{fault_id}"},
                        "authoritySha256": {"S": digest},
                        "targetCellRole": {"S": cell_role},
                        "status": {"S": "WATCHDOG_CLEANED"},
                    },
                    "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                }
            },
            {
                "Delete": {
                    "TableName": config.journal_table_name,
                    "Key": key,
                    "ConditionExpression": "faultId = :fault AND authoritySha256 = :digest",
                    "ExpressionAttributeValues": {
                        ":fault": {"S": fault_id},
                        ":digest": {"S": digest},
                    },
                }
            },
        ]
    )
    return {
        "schemaVersion": 1,
        "faultId": fault_id,
        "authoritySha256": digest,
        "status": "watchdog-cleaned",
    }


def handler(event: object, _context: object) -> dict[str, Any]:
    """AWS Lambda cleanup entry point with no create or attach authority."""
    return cleanup(
        event,
        config=ControllerConfig.from_environment(),
        dynamodb=boto3.client("dynamodb"),
        iam=boto3.client("iam"),
    )

"""Execute bounded Regional dependency-fault workflow operations in AWS Lambda.

This module is not an HTTP handler. Step Functions invokes it with an exact
activation manifest and fault authority. Every mutating operation reparses the
authority, derives the target role and IAM boundary from deployment-owned
configuration, and conditions writes on the independent transition journal.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

try:
    import boto3
except ImportError:  # pragma: no cover - AWS Lambda provides boto3.
    boto3 = None

from scripts import plan_aws_regional_fault_exercise as fault
from scripts import verify_aws_regional_activation as activation


class RegionalFaultControllerError(RuntimeError):
    """Report unsafe, stale, ambiguous or failed workflow operations."""


_EVENT_FIELDS = {"schemaVersion", "operation", "manifest", "faultAuthority"}
_OPERATIONS = {
    "acquire",
    "release-unarmed-lock",
    "arm-watchdog",
    "apply-deny",
    "remove-deny",
    "disarm-watchdog",
    "seal-evidence",
}
_ROLE_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/"
    r"(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+$"
)
_RESOURCE_ARN = re.compile(r"^arn:(?:aws|aws-us-gov|aws-cn):[a-z0-9-]+:[^\s]{3,1010}$")
_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")


def _required(name: str) -> str:
    """Return one non-empty deployment value without ambient fallback."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise RegionalFaultControllerError(f"{name} is required")
    return value


def _role_name(role_arn: str) -> str:
    """Return the exact IAM role name portion accepted by IAM APIs."""
    if not _ROLE_ARN.fullmatch(role_arn):
        raise RegionalFaultControllerError("fault target role ARN is invalid")
    return role_arn.rsplit("/", 1)[1]


def _arns(name: str, *, minimum: int = 1, maximum: int = 8) -> tuple[str, ...]:
    """Parse a bounded deployment-owned JSON list of exact AWS ARNs."""
    try:
        value = json.loads(_required(name))
    except json.JSONDecodeError as error:
        raise RegionalFaultControllerError(f"{name} is not JSON") from error
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or len(set(value)) != len(value)
        or any(not isinstance(item, str) or not _RESOURCE_ARN.fullmatch(item) for item in value)
    ):
        raise RegionalFaultControllerError(f"{name} must contain distinct exact ARNs")
    return tuple(value)


@dataclass(frozen=True)
class CellBoundary:
    """Exact deployment-owned resources for one Regional runtime cell."""

    role_arn: str
    audit_bucket_arn: str
    table_arns: tuple[str, ...]
    signing_key_arn: str
    queue_arns: tuple[str, ...]


@dataclass(frozen=True)
class ControllerConfig:
    """Deployment-owned cell identities used to derive every mutation target."""

    primary: CellBoundary
    recovery: CellBoundary
    journal_table_name: str
    schedule_group_name: str
    scheduler_role_arn: str
    cleanup_function_arn: str

    @staticmethod
    def _cell(prefix: str) -> CellBoundary:
        """Load one complete cell map without cross-Region fallback."""
        role = _required(f"{prefix}_FAULT_TARGET_ROLE_ARN")
        audit = _required(f"{prefix}_FAULT_AUDIT_BUCKET_ARN")
        signing = _required(f"{prefix}_FAULT_SIGNING_KEY_ARN")
        _role_name(role)
        for item in (audit, signing):
            if not _RESOURCE_ARN.fullmatch(item):
                raise RegionalFaultControllerError("fault dependency resource ARN is invalid")
        return CellBoundary(
            role,
            audit,
            _arns(f"{prefix}_FAULT_DYNAMODB_TABLE_ARNS", minimum=4, maximum=4),
            signing,
            _arns(f"{prefix}_FAULT_QUEUE_ARNS", minimum=1, maximum=4),
        )

    @classmethod
    def from_environment(cls) -> ControllerConfig:
        """Load strict deployment authority; malformed values fail closed."""
        primary = cls._cell("PRIMARY")
        recovery = cls._cell("RECOVERY")
        if primary.role_arn == recovery.role_arn:
            raise RegionalFaultControllerError("primary and recovery target roles must differ")
        table = _required("TRANSITION_JOURNAL_TABLE_NAME")
        group = _required("FAULT_WATCHDOG_SCHEDULE_GROUP")
        scheduler_role = _required("FAULT_WATCHDOG_ROLE_ARN")
        cleanup = _required("FAULT_CLEANUP_FUNCTION_ARN")
        if not _NAME.fullmatch(table) or not _NAME.fullmatch(group):
            raise RegionalFaultControllerError("journal or schedule group name is invalid")
        if not _ROLE_ARN.fullmatch(scheduler_role):
            raise RegionalFaultControllerError("watchdog role ARN is invalid")
        if not _RESOURCE_ARN.fullmatch(cleanup):
            raise RegionalFaultControllerError("fault cleanup function ARN is invalid")
        return cls(primary, recovery, table, group, scheduler_role, cleanup)

    def target(self, cell_role: str) -> CellBoundary:
        """Resolve one reviewed cell map without accepting caller resources."""
        if cell_role == "primary":
            return self.primary
        if cell_role == "recovery":
            return self.recovery
        raise RegionalFaultControllerError("target cell role is unsupported")


def _policy_name(fault_id: str) -> str:
    """Return the only inline policy identity this controller may mutate."""
    return f"AaiSecRegionalFault-{fault_id}"


def _boundary(authority: fault.RegionalFaultAuthority, config: ControllerConfig) -> dict[str, Any]:
    """Build a deny from a code-owned dependency map and exact deployment ARNs."""
    cell = config.target(authority.target_cell_role)
    if authority.dependency == "audit":
        actions, resources = ["s3:PutObject"], [f"{cell.audit_bucket_arn}/*"]
    elif authority.dependency == "dynamodb":
        actions = [
            "dynamodb:BatchGetItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:ConditionCheckItem",
            "dynamodb:DeleteItem",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:TransactWriteItems",
            "dynamodb:UpdateItem",
        ]
        # DynamoDB index ARNs are distinct IAM resources. Omitting them would
        # let an indexed query bypass a purported table dependency failure.
        resources = [item for arn in cell.table_arns for item in (arn, f"{arn}/index/*")]
    elif authority.dependency == "kms":
        actions, resources = ["kms:GetPublicKey", "kms:Sign"], [cell.signing_key_arn]
    elif authority.dependency == "queue":
        actions = [
            "sqs:ChangeMessageVisibility",
            "sqs:DeleteMessage",
            "sqs:ReceiveMessage",
            "sqs:SendMessage",
        ]
        resources = list(cell.queue_arns)
    else:
        # Cognito authentication is not performed by the handler execution
        # role. Pretending an inline IAM deny tests it would create false proof.
        raise RegionalFaultControllerError("dependency has no safe target-role boundary")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExactRegionalExerciseDependency",
                "Effect": "Deny",
                "Action": actions,
                "Resource": resources,
            }
        ],
    }


def _parse_event(
    event: object, *, now: int | None = None
) -> tuple[str, activation.ActivationManifest, fault.RegionalFaultAuthority]:
    """Parse one exact internal workflow event and repeat authority checks."""
    if (
        not isinstance(event, dict)
        or set(event) != _EVENT_FIELDS
        or event.get("schemaVersion") != 1
    ):
        raise RegionalFaultControllerError("fault controller event schema is invalid")
    operation = event.get("operation")
    manifest_value = event.get("manifest")
    authority_value = event.get("faultAuthority")
    if (
        operation not in _OPERATIONS
        or not isinstance(manifest_value, dict)
        or not isinstance(authority_value, dict)
    ):
        raise RegionalFaultControllerError("fault controller event values are invalid")
    try:
        manifest = activation.ActivationManifest.parse(
            json.dumps(manifest_value, sort_keys=True, separators=(",", ":")), now=now
        )
        authority = fault.RegionalFaultAuthority.parse(
            json.dumps(authority_value, sort_keys=True, separators=(",", ":")),
            manifest,
            now=now,
        )
    except (
        activation.RegionalActivationVerificationError,
        fault.RegionalFaultAuthorityError,
    ) as error:
        raise RegionalFaultControllerError("fault controller authority is invalid") from error
    return operation, manifest, authority


def _lock_key(authority: fault.RegionalFaultAuthority) -> dict[str, str]:
    """Return the single-writer lock key shared by all target-cell faults."""
    return {"pk": "REGIONAL_FAULT", "sk": f"TARGET#{authority.target_cell_role}"}


def _cleanup_payload(authority: fault.RegionalFaultAuthority) -> dict[str, Any]:
    """Return the minimum non-secret authority needed for expiry-safe cleanup."""
    return {
        "schemaVersion": 1,
        "faultId": authority.fault_id,
        "authoritySha256": authority.sha256(),
        "targetCellRole": authority.target_cell_role,
    }


def _aws_error_code(error: BaseException) -> str:
    """Read a botocore-shaped error code without requiring botocore locally."""
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return ""
    details = response.get("Error")
    if not isinstance(details, dict):
        return ""
    return str(details.get("Code", ""))


def _condition_failure(error: BaseException) -> bool:
    """Identify one DynamoDB conditional conflict without hiding other errors."""
    return _aws_error_code(error) in {
        "ConditionalCheckFailedException",
        "TransactionCanceledException",
    }


def _missing_entity(error: BaseException) -> bool:
    """Identify an already-absent exact IAM policy for idempotent cleanup."""
    return _aws_error_code(error) == "NoSuchEntity"


def execute(
    event: object,
    *,
    config: ControllerConfig,
    dynamodb: Any,
    iam: Any,
    scheduler: Any,
    now: int | None = None,
) -> dict[str, Any]:
    """Execute one idempotent workflow step against exact AWS resources."""
    current = int(time.time()) if now is None else now
    operation, _manifest, authority = _parse_event(event, now=current)
    role_arn = config.target(authority.target_cell_role).role_arn
    role_name = _role_name(role_arn)
    policy_name = _policy_name(authority.fault_id)
    key = _lock_key(authority)
    digest = authority.sha256()
    schedule_name = f"aai-sec-fault-{authority.fault_id}"

    if operation == "acquire":
        try:
            dynamodb.put_item(
                TableName=config.journal_table_name,
                Item={
                    "pk": {"S": key["pk"]},
                    "sk": {"S": key["sk"]},
                    "faultId": {"S": authority.fault_id},
                    "authoritySha256": {"S": digest},
                    "state": {"S": "LOCKED"},
                    "expiresAt": {"N": str(authority.expires_at)},
                },
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except Exception as error:
            if _condition_failure(error):
                existing = dynamodb.get_item(
                    TableName=config.journal_table_name,
                    Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
                    ConsistentRead=True,
                ).get("Item")
                if not isinstance(existing, dict) or existing.get("authoritySha256") != {
                    "S": digest
                }:
                    raise RegionalFaultControllerError(
                        "another target-cell fault is active"
                    ) from error
                # A lost response followed by a Step Functions retry must not
                # turn the same authority into a conflicting second fault.
                if existing.get("state") not in (
                    {"S": "LOCKED"},
                    {"S": "WATCHDOG_ARMED"},
                    {"S": "DENY_APPLIED"},
                ):
                    raise RegionalFaultControllerError("fault lock is not retryable") from error
                return {
                    "schemaVersion": 1,
                    "operation": operation,
                    "faultId": authority.fault_id,
                    "authoritySha256": digest,
                    "status": "already-completed",
                }
            raise
    elif operation == "release-unarmed-lock":
        dynamodb.delete_item(
            TableName=config.journal_table_name,
            Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
            ConditionExpression="authoritySha256 = :digest AND #state = :locked",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":digest": {"S": digest},
                ":locked": {"S": "LOCKED"},
            },
        )
    elif operation == "arm-watchdog":
        cleanup_at = datetime.fromtimestamp(
            current + authority.maximum_fault_seconds + 60, tz=UTC
        ).strftime("%Y-%m-%dT%H:%M:%S")
        scheduler.create_schedule(
            Name=schedule_name,
            GroupName=config.schedule_group_name,
            ScheduleExpression=f"at({cleanup_at})",
            FlexibleTimeWindow={"Mode": "OFF"},
            ActionAfterCompletion="DELETE",
            Target={
                "Arn": config.cleanup_function_arn,
                "RoleArn": config.scheduler_role_arn,
                "Input": json.dumps(
                    _cleanup_payload(authority), sort_keys=True, separators=(",", ":")
                ),
                "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 5},
            },
            ClientToken=digest,
        )
        dynamodb.update_item(
            TableName=config.journal_table_name,
            Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
            UpdateExpression="SET #state = :armed, watchdogName = :watchdog",
            ConditionExpression="authoritySha256 = :digest AND #state = :locked",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":armed": {"S": "WATCHDOG_ARMED"},
                ":locked": {"S": "LOCKED"},
                ":digest": {"S": digest},
                ":watchdog": {"S": schedule_name},
            },
        )
    elif operation == "apply-deny":
        lock = dynamodb.get_item(
            TableName=config.journal_table_name,
            Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
            ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(lock, dict)
            or lock.get("authoritySha256") != {"S": digest}
            or lock.get("state") != {"S": "WATCHDOG_ARMED"}
        ):
            raise RegionalFaultControllerError("independent cleanup watchdog is not armed")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                _boundary(authority, config), sort_keys=True, separators=(",", ":")
            ),
        )
        dynamodb.update_item(
            TableName=config.journal_table_name,
            Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
            UpdateExpression="SET #state = :applied",
            ConditionExpression="authoritySha256 = :digest AND #state = :armed",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":applied": {"S": "DENY_APPLIED"},
                ":armed": {"S": "WATCHDOG_ARMED"},
                ":digest": {"S": digest},
            },
        )
    elif operation == "remove-deny":
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except Exception as error:
            if not _missing_entity(error):
                raise
        dynamodb.update_item(
            TableName=config.journal_table_name,
            Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
            UpdateExpression="SET #state = :removed",
            ConditionExpression="authoritySha256 = :digest",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":removed": {"S": "DENY_REMOVED"},
                ":digest": {"S": digest},
            },
        )
    elif operation == "disarm-watchdog":
        scheduler.delete_schedule(Name=schedule_name, GroupName=config.schedule_group_name)
        dynamodb.update_item(
            TableName=config.journal_table_name,
            Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
            UpdateExpression="SET #state = :disarmed",
            ConditionExpression="authoritySha256 = :digest AND #state = :removed",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":disarmed": {"S": "WATCHDOG_DISARMED"},
                ":removed": {"S": "DENY_REMOVED"},
                ":digest": {"S": digest},
            },
        )
    elif operation == "seal-evidence":
        evidence_item = {
            "pk": {"S": "REGIONAL_FAULT_EVIDENCE"},
            "sk": {"S": f"FAULT#{authority.fault_id}"},
            "authoritySha256": {"S": digest},
            "targetCellRole": {"S": authority.target_cell_role},
            "dependency": {"S": authority.dependency},
            "status": {"S": "COMPLETE"},
            "completedAt": {"N": str(current)},
        }
        try:
            dynamodb.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": config.journal_table_name,
                            "Item": evidence_item,
                            "ConditionExpression": (
                                "attribute_not_exists(pk) AND attribute_not_exists(sk)"
                            ),
                        }
                    },
                    {
                        "Delete": {
                            "TableName": config.journal_table_name,
                            "Key": {"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
                            "ConditionExpression": (
                                "authoritySha256 = :digest AND #state = :disarmed"
                            ),
                            "ExpressionAttributeNames": {"#state": "state"},
                            "ExpressionAttributeValues": {
                                ":disarmed": {"S": "WATCHDOG_DISARMED"},
                                ":digest": {"S": digest},
                            },
                        }
                    },
                ]
            )
        except Exception as error:
            if not _condition_failure(error):
                raise
            existing = dynamodb.get_item(
                TableName=config.journal_table_name,
                Key={"pk": evidence_item["pk"], "sk": evidence_item["sk"]},
                ConsistentRead=True,
            ).get("Item")
            if (
                not isinstance(existing, dict)
                or existing.get("authoritySha256") != {"S": digest}
                or existing.get("status") != {"S": "COMPLETE"}
            ):
                raise RegionalFaultControllerError("fault completion evidence differs") from error
            return {
                "schemaVersion": 1,
                "operation": operation,
                "faultId": authority.fault_id,
                "authoritySha256": digest,
                "status": "already-completed",
            }
    return {
        "schemaVersion": 1,
        "operation": operation,
        "faultId": authority.fault_id,
        "authoritySha256": digest,
        "status": "completed",
    }


def handler(event: object, _context: object) -> dict[str, Any]:
    """AWS Lambda entry point using ambient credentials only after validation."""
    if boto3 is None:
        raise RegionalFaultControllerError("boto3 is required in the AWS Lambda runtime")
    return execute(
        event,
        config=ControllerConfig.from_environment(),
        dynamodb=boto3.client("dynamodb"),
        iam=boto3.client("iam"),
        scheduler=boto3.client("scheduler"),
    )

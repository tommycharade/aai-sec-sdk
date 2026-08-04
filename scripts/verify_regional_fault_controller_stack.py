#!/usr/bin/env python3
"""Verify the Regional fault controller is private, compensated and probe-bound."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


class RegionalFaultStackVerificationError(ValueError):
    """Report infrastructure that exceeds the reviewed fault-controller boundary."""


_COUNTS = {
    "AWS::CDK::Metadata": 1,
    "AWS::CloudWatch::Alarm": 5,
    "AWS::IAM::Policy": 5,
    "AWS::IAM::Role": 5,
    "AWS::Lambda::Function": 3,
    "AWS::Logs::LogGroup": 1,
    "AWS::Scheduler::ScheduleGroup": 1,
    "AWS::SQS::Queue": 1,
    "AWS::SQS::QueuePolicy": 1,
    "AWS::StepFunctions::StateMachine": 1,
}
_HANDLERS = {
    "scripts.regional_fault_probe_lambda.handler",
    "scripts.regional_fault_controller_lambda.handler",
    "scripts.regional_fault_cleanup_lambda.handler",
}
_PROBE_PHASES = {
    "preconditions",
    "dependency-unavailable",
    "execution-denied-no-bypass",
    "dependency-and-target-recovered",
}
_CONTROLLER_OPERATIONS = {
    "acquire",
    "release-unarmed-lock",
    "arm-watchdog",
    "apply-deny",
    "remove-deny",
    "disarm-watchdog",
    "seal-evidence",
}
_ASSET_FILES = {
    "scripts/__init__.py",
    "scripts/verify_aws_regional_activation.py",
    "scripts/manage_aws_transition_journal.py",
    "scripts/plan_aws_regional_fault_exercise.py",
    "scripts/regional_fault_controller_lambda.py",
    "scripts/regional_fault_cleanup_lambda.py",
    "scripts/regional_fault_probe_lambda.py",
    "scripts/regional_fault_preconditions.py",
}
_READ_ONLY_PRECONDITION_ACTIONS = {
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListStackResources",
    "events:DescribeRule",
    "lambda:GetEventSourceMapping",
    "lambda:GetFunctionConcurrency",
    "lambda:GetFunctionConfiguration",
    "route53:GetHostedZone",
    "route53:ListResourceRecordSets",
}


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegionalFaultStackVerificationError(f"{label} must be an object")
    return value


def _items(resources: dict[str, Any], kind: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        (logical_id, _object(raw, "resource"))
        for logical_id, raw in resources.items()
        if _object(raw, "resource").get("Type") == kind
    ]


def _actions(statement: dict[str, Any]) -> set[str]:
    value = statement.get("Action")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    raise RegionalFaultStackVerificationError("IAM action shape is invalid")


def _logical_id(value: object, intrinsic: str, label: str) -> str:
    """Return the logical ID from one exact Ref or Fn::GetAtt expression."""
    item = _object(value, label).get(intrinsic)
    if intrinsic == "Ref" and isinstance(item, str):
        return item
    if (
        intrinsic == "Fn::GetAtt"
        and isinstance(item, list)
        and len(item) == 2
        and isinstance(item[0], str)
        and item[1] == "Arn"
    ):
        return item[0]
    raise RegionalFaultStackVerificationError(f"{label} identity is not exact")


def verify(
    template: dict[str, Any],
    *,
    journal_table_name: str,
    journal_table_arn: str,
    primary_role_arn: str,
    recovery_role_arn: str,
    alert_topic_arn: str,
    asset_files: set[str] | None = None,
) -> dict[str, Any]:
    """Require exact resources, workflow order, compensation and least privilege."""
    resources = _object(template.get("Resources"), "template Resources")
    counts = Counter(_object(value, "resource").get("Type") for value in resources.values())
    if dict(counts) != _COUNTS:
        raise RegionalFaultStackVerificationError("fault-controller resource cardinality changed")

    functions = _items(resources, "AWS::Lambda::Function")
    observed_handlers: set[str] = set()
    code_assets: set[str] = set()
    by_handler: dict[str, tuple[str, dict[str, Any]]] = {}
    for logical_id, function in functions:
        props = _object(function.get("Properties"), "Lambda properties")
        handler = props.get("Handler")
        code = _object(props.get("Code"), "Lambda code")
        if (
            not isinstance(handler, str)
            or props.get("Runtime") != "python3.13"
            or props.get("Architectures") != ["arm64"]
            or props.get("MemorySize") != 256
            or props.get("Timeout") != 30
            or props.get("ReservedConcurrentExecutions") != 1
            or set(code) != {"S3Bucket", "S3Key"}
        ):
            raise RegionalFaultStackVerificationError("fault Lambda runtime is not bounded")
        observed_handlers.add(handler)
        code_assets.add(json.dumps(code, sort_keys=True))
        by_handler[handler] = (logical_id, props)
    if observed_handlers != _HANDLERS or len(code_assets) != 1:
        raise RegionalFaultStackVerificationError("fault Lambda identity or package differs")
    if asset_files is not None and asset_files != _ASSET_FILES:
        raise RegionalFaultStackVerificationError("fault Lambda asset file set differs")
    function_roles = {
        handler: _logical_id(props.get("Role"), "Fn::GetAtt", f"{handler} role")
        for handler, (_, props) in by_handler.items()
    }
    probe_props = by_handler["scripts.regional_fault_probe_lambda.handler"][1]
    probe_environment = _object(
        _object(probe_props.get("Environment"), "probe environment").get("Variables"),
        "probe variables",
    )
    if set(probe_environment) != {
        "PRIMARY_FAULT_TARGET_FUNCTION_ARN",
        "RECOVERY_FAULT_TARGET_FUNCTION_ARN",
        "FAULT_ROUTE53_HOSTED_ZONE_ID",
    }:
        raise RegionalFaultStackVerificationError("probe has ambient configuration")

    controller_environment = _object(
        _object(
            by_handler["scripts.regional_fault_controller_lambda.handler"][1].get("Environment"),
            "controller environment",
        ).get("Variables"),
        "controller variables",
    )
    cleanup_environment = _object(
        _object(
            by_handler["scripts.regional_fault_cleanup_lambda.handler"][1].get("Environment"),
            "cleanup environment",
        ).get("Variables"),
        "cleanup variables",
    )
    if controller_environment != cleanup_environment:
        raise RegionalFaultStackVerificationError("controller and cleanup resource maps differ")
    if (
        controller_environment.get("TRANSITION_JOURNAL_TABLE_NAME") != journal_table_name
        or controller_environment.get("PRIMARY_FAULT_TARGET_ROLE_ARN") != primary_role_arn
        or controller_environment.get("RECOVERY_FAULT_TARGET_ROLE_ARN") != recovery_role_arn
        or set(controller_environment)
        != {
            "PRIMARY_FAULT_TARGET_ROLE_ARN",
            "PRIMARY_FAULT_TARGET_FUNCTION_ARN",
            "PRIMARY_FAULT_AUDIT_BUCKET_ARN",
            "PRIMARY_FAULT_DYNAMODB_TABLE_ARNS",
            "PRIMARY_FAULT_SIGNING_KEY_ARN",
            "PRIMARY_FAULT_QUEUE_ARNS",
            "RECOVERY_FAULT_TARGET_ROLE_ARN",
            "RECOVERY_FAULT_TARGET_FUNCTION_ARN",
            "RECOVERY_FAULT_AUDIT_BUCKET_ARN",
            "RECOVERY_FAULT_DYNAMODB_TABLE_ARNS",
            "RECOVERY_FAULT_SIGNING_KEY_ARN",
            "RECOVERY_FAULT_QUEUE_ARNS",
            "TRANSITION_JOURNAL_TABLE_NAME",
            "FAULT_WATCHDOG_SCHEDULE_GROUP",
            "FAULT_WATCHDOG_ROLE_ARN",
            "FAULT_CLEANUP_FUNCTION_ARN",
            "FAULT_WATCHDOG_DLQ_ARN",
        }
    ):
        raise RegionalFaultStackVerificationError("fault Lambda resource map is incomplete")
    for key in ("PRIMARY_FAULT_DYNAMODB_TABLE_ARNS", "RECOVERY_FAULT_DYNAMODB_TABLE_ARNS"):
        value = json.loads(controller_environment[key])
        if not isinstance(value, list) or len(value) != 4 or len(set(value)) != 4:
            raise RegionalFaultStackVerificationError("cell DynamoDB map is not exact")
    for key in ("PRIMARY_FAULT_QUEUE_ARNS", "RECOVERY_FAULT_QUEUE_ARNS"):
        value = json.loads(controller_environment[key])
        if not isinstance(value, list) or not 1 <= len(value) <= 4 or len(set(value)) != len(value):
            raise RegionalFaultStackVerificationError("cell queue map is not bounded")

    schedule_group = _items(resources, "AWS::Scheduler::ScheduleGroup")[0][1]
    if _object(schedule_group.get("Properties"), "schedule group").get("Name") != (
        "aai-sec-regional-fault-watchdogs"
    ):
        raise RegionalFaultStackVerificationError("watchdog schedule group identity changed")
    queue_resource = _items(resources, "AWS::SQS::Queue")[0][1]
    queue = _object(queue_resource.get("Properties"), "DLQ")
    if queue != {"MessageRetentionPeriod": 1_209_600, "SqsManagedSseEnabled": True}:
        raise RegionalFaultStackVerificationError("watchdog DLQ posture changed")
    if (
        queue_resource.get("DeletionPolicy") != "Retain"
        or queue_resource.get("UpdateReplacePolicy") != "Retain"
    ):
        raise RegionalFaultStackVerificationError("watchdog DLQ is not retained")
    queue_policy = _object(
        _items(resources, "AWS::SQS::QueuePolicy")[0][1].get("Properties"), "DLQ policy"
    )
    queue_statements = _object(queue_policy.get("PolicyDocument"), "DLQ policy document").get(
        "Statement"
    )
    if (
        not isinstance(queue_statements, list)
        or len(queue_statements) != 1
        or _object(queue_statements[0], "DLQ policy statement").get("Effect") != "Deny"
        or _object(queue_statements[0], "DLQ policy statement").get("Action") != "sqs:*"
        or _object(queue_statements[0], "DLQ policy statement").get("Condition")
        != {"Bool": {"aws:SecureTransport": "false"}}
        or _object(queue_statements[0], "DLQ policy statement").get("Principal") != {"AWS": "*"}
    ):
        raise RegionalFaultStackVerificationError("watchdog DLQ does not deny insecure transport")

    service_counts: Counter[str] = Counter()
    for _, role in _items(resources, "AWS::IAM::Role"):
        role_props = _object(role.get("Properties"), "role properties")
        assume = _object(role_props.get("AssumeRolePolicyDocument"), "assume-role policy").get(
            "Statement"
        )
        if not isinstance(assume, list) or len(assume) != 1:
            raise RegionalFaultStackVerificationError("role trust is ambiguous")
        trust = _object(assume[0], "trust statement")
        principal = _object(trust.get("Principal"), "trust principal").get("Service")
        if (
            trust.get("Effect") != "Allow"
            or trust.get("Action") != "sts:AssumeRole"
            or principal
            not in {"lambda.amazonaws.com", "scheduler.amazonaws.com", "states.amazonaws.com"}
        ):
            raise RegionalFaultStackVerificationError("role trust exceeds service principals")
        service_counts[principal] += 1
        managed = role_props.get("ManagedPolicyArns", [])
        if principal == "lambda.amazonaws.com":
            if (
                not isinstance(managed, list)
                or len(managed) != 1
                or "AWSLambdaBasicExecutionRole" not in json.dumps(managed)
            ):
                raise RegionalFaultStackVerificationError("Lambda role baseline policy changed")
        elif managed:
            raise RegionalFaultStackVerificationError("workflow or watchdog has managed policy")
    if service_counts != Counter(
        {
            "lambda.amazonaws.com": 3,
            "scheduler.amazonaws.com": 1,
            "states.amazonaws.com": 1,
        }
    ):
        raise RegionalFaultStackVerificationError("fault role service cardinality changed")

    state_machine = _items(resources, "AWS::StepFunctions::StateMachine")[0][1]
    if (
        state_machine.get("DeletionPolicy") != "Retain"
        or state_machine.get("UpdateReplacePolicy") != "Retain"
    ):
        raise RegionalFaultStackVerificationError("fault workflow is not retained")
    state_props = _object(state_machine.get("Properties"), "state machine")
    logging = _object(state_props.get("LoggingConfiguration"), "workflow logging")
    if (
        state_props.get("StateMachineName") != "aai-sec-regional-fault-controller"
        or state_props.get("StateMachineType") != "STANDARD"
        or logging.get("IncludeExecutionData") is not False
        or logging.get("Level") != "ERROR"
        or set(_object(state_props.get("DefinitionSubstitutions"), "substitutions"))
        != {"ProbeArn", "ControllerArn", "CleanupArn"}
    ):
        raise RegionalFaultStackVerificationError("workflow privacy or identity changed")
    definition_raw = state_props.get("DefinitionString")
    if not isinstance(definition_raw, str):
        raise RegionalFaultStackVerificationError("workflow definition is not literal JSON")
    definition = _object(json.loads(definition_raw), "workflow definition")
    states = _object(definition.get("States"), "workflow states")
    if (
        definition.get("StartAt") != "VerifyPreconditions"
        or definition.get("TimeoutSeconds") != 1200
    ):
        raise RegionalFaultStackVerificationError("workflow does not fail closed at preconditions")
    expected_names = {
        "VerifyPreconditions",
        "AcquireFaultLock",
        "ReleaseUnarmedLock",
        "ArmWatchdog",
        "ApplyDeny",
        "VerifyDependencyUnavailable",
        "VerifyExecutionDenied",
        "RemoveDeny",
        "VerifyRecovery",
        "DisarmWatchdog",
        "SealEvidence",
        "Compensate",
        "ExerciseComplete",
        "PreconditionFailed",
        "AcquireFailed",
        "ExerciseFailed",
        "CompensationFailed",
        "CompletionFailed",
    }
    if set(states) != expected_names:
        raise RegionalFaultStackVerificationError("workflow state set changed")
    phases: set[str] = set()
    operations: set[str] = set()
    expected_retry = [
        {
            "ErrorEquals": [
                "Lambda.ServiceException",
                "Lambda.AWSLambdaException",
                "Lambda.SdkClientException",
                "Lambda.TooManyRequestsException",
            ],
            "IntervalSeconds": 2,
            "BackoffRate": 2,
            "MaxAttempts": 3,
        }
    ]
    for name, raw_state in states.items():
        state = _object(raw_state, f"state {name}")
        if state.get("Type") != "Task":
            continue
        parameters = _object(state.get("Parameters"), f"state {name} parameters")
        payload = _object(parameters.get("Payload"), f"state {name} payload")
        if payload.get("phase") is not None:
            phases.add(payload["phase"])
        if payload.get("operation") is not None:
            operations.add(payload["operation"])
        if state.get("Resource") != "arn:aws:states:::lambda:invoke":
            raise RegionalFaultStackVerificationError("workflow invokes a non-Lambda integration")
        if state.get("Retry") != expected_retry:
            raise RegionalFaultStackVerificationError("workflow retry boundary changed")
    if phases != _PROBE_PHASES or operations != _CONTROLLER_OPERATIONS:
        raise RegionalFaultStackVerificationError("workflow phase or operation coverage changed")
    if _object(states["VerifyPreconditions"], "preconditions").get("Next") != "AcquireFaultLock":
        raise RegionalFaultStackVerificationError("mutation can precede preconditions")
    expected_next = {
        "AcquireFaultLock": "ArmWatchdog",
        "ReleaseUnarmedLock": "AcquireFailed",
        "ArmWatchdog": "ApplyDeny",
        "ApplyDeny": "VerifyDependencyUnavailable",
        "VerifyDependencyUnavailable": "VerifyExecutionDenied",
        "VerifyExecutionDenied": "RemoveDeny",
        "RemoveDeny": "VerifyRecovery",
        "VerifyRecovery": "DisarmWatchdog",
        "DisarmWatchdog": "SealEvidence",
        "SealEvidence": "ExerciseComplete",
        "Compensate": "ExerciseFailed",
    }
    if any(
        _object(states[name], name).get("Next") != target for name, target in expected_next.items()
    ):
        raise RegionalFaultStackVerificationError("workflow normal or cleanup order changed")
    for name in (
        "ArmWatchdog",
        "ApplyDeny",
        "VerifyDependencyUnavailable",
        "VerifyExecutionDenied",
        "RemoveDeny",
        "VerifyRecovery",
        "DisarmWatchdog",
    ):
        catches = _object(states[name], name).get("Catch")
        if catches != [
            {"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "Compensate"}
        ]:
            raise RegionalFaultStackVerificationError(f"{name} lacks exact compensation")
    if (
        _object(states["Compensate"], "compensation").get("Parameters", {}).get("FunctionName")
        != "${CleanupArn}"
    ):
        raise RegionalFaultStackVerificationError(
            "compensation does not invoke independent cleanup"
        )

    all_actions: set[str] = set()
    policy_statements: list[dict[str, Any]] = []
    policy_roles: dict[str, set[str]] = {}
    for _, policy in _items(resources, "AWS::IAM::Policy"):
        policy_props = _object(policy.get("Properties"), "IAM policy")
        roles = policy_props.get("Roles")
        if not isinstance(roles, list) or len(roles) != 1:
            raise RegionalFaultStackVerificationError("IAM policy role binding is ambiguous")
        role_id = _logical_id(roles[0], "Ref", "IAM policy role")
        document = _object(policy_props.get("PolicyDocument"), "policy document")
        statements = document.get("Statement")
        if not isinstance(statements, list):
            raise RegionalFaultStackVerificationError("IAM statements are invalid")
        for raw in statements:
            statement = _object(raw, "IAM statement")
            actions = _actions(statement)
            all_actions.update(actions)
            for action in actions:
                policy_roles.setdefault(action, set()).add(role_id)
            policy_statements.append(statement)
            if statement.get("Effect") != "Allow" or any(
                action == "*" or action.endswith(":*") for action in actions
            ):
                raise RegionalFaultStackVerificationError(
                    "IAM contains wildcard or non-allow authority"
                )
            if statement.get("Resource") == "*" and not actions <= (
                {
                    "logs:CreateLogDelivery",
                    "logs:DeleteLogDelivery",
                    "logs:DescribeLogGroups",
                    "logs:DescribeResourcePolicies",
                    "logs:GetLogDelivery",
                    "logs:ListLogDeliveries",
                    "logs:PutResourcePolicy",
                    "logs:UpdateLogDelivery",
                }
                | _READ_ONLY_PRECONDITION_ACTIONS
            ):
                raise RegionalFaultStackVerificationError(
                    "IAM wildcard resource exceeds log delivery"
                )
    if (
        "states:StartExecution" in all_actions
        or not {"iam:ListRolePolicies", "iam:PutRolePolicy"} <= all_actions
    ):
        raise RegionalFaultStackVerificationError(
            "workflow is public or lacks exact fault authority"
        )
    controller_role = function_roles["scripts.regional_fault_controller_lambda.handler"]
    if policy_roles.get("iam:PutRolePolicy") != {controller_role} or policy_roles.get(
        "dynamodb:PutItem"
    ) != {controller_role}:
        raise RegionalFaultStackVerificationError("fault mutation policy is on the wrong role")
    cleanup_role = function_roles["scripts.regional_fault_cleanup_lambda.handler"]
    if cleanup_role not in policy_roles.get("iam:DeleteRolePolicy", set()):
        raise RegionalFaultStackVerificationError("cleanup role lacks exact delete authority")
    probe_role = function_roles["scripts.regional_fault_probe_lambda.handler"]
    if (
        policy_roles.get("lambda:InvokeFunction") is None
        or probe_role not in policy_roles["lambda:InvokeFunction"]
    ):
        raise RegionalFaultStackVerificationError("probe lacks exact target invocation authority")
    probe_invoke = [
        item
        for item in policy_statements
        if _actions(item) == {"lambda:InvokeFunction"}
        and item.get("Resource")
        == [
            probe_environment["PRIMARY_FAULT_TARGET_FUNCTION_ARN"],
            probe_environment["RECOVERY_FAULT_TARGET_FUNCTION_ARN"],
        ]
    ]
    if len(probe_invoke) != 1:
        raise RegionalFaultStackVerificationError("probe target invocation authority differs")
    if probe_role not in policy_roles.get("dynamodb:GetItem", set()):
        raise RegionalFaultStackVerificationError("probe lacks journal read authority")
    if any(policy_roles.get(action) != {probe_role} for action in _READ_ONLY_PRECONDITION_ACTIONS):
        raise RegionalFaultStackVerificationError(
            "precondition read authority is on the wrong role"
        )
    put_statements = [item for item in policy_statements if "iam:PutRolePolicy" in _actions(item)]
    if len(put_statements) != 1 or set(put_statements[0].get("Resource", [])) != {
        primary_role_arn,
        recovery_role_arn,
    }:
        raise RegionalFaultStackVerificationError("IAM fault mutation roles differ")
    journal_statements = [
        item
        for item in policy_statements
        if _actions(item)
        & {
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:TransactWriteItems",
        }
    ]
    if not journal_statements or any(
        item.get("Resource") != journal_table_arn for item in journal_statements
    ):
        raise RegionalFaultStackVerificationError("journal authority is not exact")

    alarms = _items(resources, "AWS::CloudWatch::Alarm")
    if any(
        _object(item.get("Properties"), "alarm").get("AlarmActions") != [alert_topic_arn]
        for _, item in alarms
    ):
        raise RegionalFaultStackVerificationError("fault alarm is not wired to security alerts")
    outputs = _object(template.get("Outputs"), "outputs")
    if _object(outputs.get("RegionalFaultControllerStatus"), "status").get("Value") != (
        "manual-noncognito-probes-enabled-not-live-accepted"
    ):
        raise RegionalFaultStackVerificationError("stack probe readiness disclosure differs")
    return {
        "status": "verified-manual-noncognito-probes",
        "stateCount": len(states),
        "compensatedStateCount": 7,
        "publicExecutionGrantCount": 0,
        "alarmCount": len(alarms),
        "assetFileCount": len(_ASSET_FILES),
    }


def main() -> int:
    """Verify one bounded synthesized stack from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--journal-table-name", required=True)
    parser.add_argument("--journal-table-arn", required=True)
    parser.add_argument("--primary-role-arn", required=True)
    parser.add_argument("--recovery-role-arn", required=True)
    parser.add_argument("--alert-topic-arn", required=True)
    args = parser.parse_args()
    if args.template.stat().st_size > 2_000_000:
        raise RegionalFaultStackVerificationError("template exceeds 2 MiB")
    value = json.loads(args.template.read_text(encoding="utf-8"))
    template = _object(value, "template")
    functions = _items(
        _object(template.get("Resources"), "template Resources"), "AWS::Lambda::Function"
    )
    first_code = _object(
        _object(functions[0][1].get("Properties"), "Lambda properties").get("Code"),
        "Lambda code",
    )
    s3_key = first_code.get("S3Key")
    if not isinstance(s3_key, str) or not s3_key.endswith(".zip"):
        raise RegionalFaultStackVerificationError("Lambda asset key is invalid")
    asset_root = args.template.parent / f"asset.{s3_key.removesuffix('.zip')}"
    if not asset_root.is_dir():
        raise RegionalFaultStackVerificationError("synthesized Lambda asset directory is missing")
    asset_files = {
        path.relative_to(asset_root).as_posix() for path in asset_root.rglob("*") if path.is_file()
    }
    result = verify(
        template,
        journal_table_name=args.journal_table_name,
        journal_table_arn=args.journal_table_arn,
        primary_role_arn=args.primary_role_arn,
        recovery_role_arn=args.recovery_role_arn,
        alert_topic_arn=args.alert_topic_arn,
        asset_files=asset_files,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Adversarial contracts for the private Regional fault-controller stack."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

JOURNAL_NAME = "AaiSecRegionalTransitionJournal"
JOURNAL_ARN = f"arn:aws:dynamodb:eu-central-1:111111111111:table/{JOURNAL_NAME}"
PRIMARY_ROLE = "arn:aws:iam::111111111111:role/AaiPrimaryHandler"
RECOVERY_ROLE = "arn:aws:iam::111111111111:role/AaiRecoveryHandler"
ALERT_TOPIC = "arn:aws:sns:eu-central-1:111111111111:aai-sec-security-alerts"


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_regional_fault_controller_stack.py"
    spec = importlib.util.spec_from_file_location("aai_verify_regional_fault_stack", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _trust(service: str, *, managed: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {
        "AssumeRolePolicyDocument": {
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                }
            ]
        }
    }
    if managed:
        value["ManagedPolicyArns"] = ["AWSLambdaBasicExecutionRole"]
    return {"Type": "AWS::IAM::Role", "Properties": value}


def _task(function: str, payload: dict[str, Any], next_state: str) -> dict[str, Any]:
    return {
        "Type": "Task",
        "Resource": "arn:aws:states:::lambda:invoke",
        "Parameters": {"FunctionName": function, "Payload": payload},
        "Retry": [
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
        ],
        "ResultPath": None,
        "Next": next_state,
    }


def _controller_payload(operation: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "operation": operation,
        "manifest.$": "$.manifest",
        "faultAuthority.$": "$.faultAuthority",
    }


def _probe_payload(phase: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "phase": phase,
        "manifest.$": "$.manifest",
        "faultAuthority.$": "$.faultAuthority",
    }


def _definition() -> dict[str, Any]:
    compensate = [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "Compensate"}]
    states: dict[str, Any] = {
        "VerifyPreconditions": _task(
            "${ProbeArn}", _probe_payload("preconditions"), "AcquireFaultLock"
        ),
        "AcquireFaultLock": _task(
            "${ControllerArn}", _controller_payload("acquire"), "ArmWatchdog"
        ),
        "ReleaseUnarmedLock": _task(
            "${ControllerArn}", _controller_payload("release-unarmed-lock"), "AcquireFailed"
        ),
        "ArmWatchdog": _task("${ControllerArn}", _controller_payload("arm-watchdog"), "ApplyDeny"),
        "ApplyDeny": _task(
            "${ControllerArn}", _controller_payload("apply-deny"), "VerifyDependencyUnavailable"
        ),
        "VerifyDependencyUnavailable": _task(
            "${ProbeArn}", _probe_payload("dependency-unavailable"), "VerifyExecutionDenied"
        ),
        "VerifyExecutionDenied": _task(
            "${ProbeArn}", _probe_payload("execution-denied-no-bypass"), "RemoveDeny"
        ),
        "RemoveDeny": _task(
            "${ControllerArn}", _controller_payload("remove-deny"), "VerifyRecovery"
        ),
        "VerifyRecovery": _task(
            "${ProbeArn}", _probe_payload("dependency-and-target-recovered"), "DisarmWatchdog"
        ),
        "DisarmWatchdog": _task(
            "${ControllerArn}", _controller_payload("disarm-watchdog"), "SealEvidence"
        ),
        "SealEvidence": _task(
            "${ControllerArn}", _controller_payload("seal-evidence"), "ExerciseComplete"
        ),
        "Compensate": _task(
            "${CleanupArn}",
            {
                "schemaVersion": 1,
                "faultId.$": "$.faultAuthority.faultId",
                "authoritySha256.$": "$.controller.authoritySha256",
                "targetCellRole.$": "$.faultAuthority.targetCellRole",
            },
            "ExerciseFailed",
        ),
        "ExerciseComplete": {"Type": "Succeed"},
        "PreconditionFailed": {"Type": "Fail"},
        "AcquireFailed": {"Type": "Fail"},
        "ExerciseFailed": {"Type": "Fail"},
        "CompensationFailed": {"Type": "Fail"},
        "CompletionFailed": {"Type": "Fail"},
    }
    states["VerifyPreconditions"]["Catch"] = [
        {"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "PreconditionFailed"}
    ]
    states["AcquireFaultLock"]["ResultSelector"] = {
        "authoritySha256.$": "$.Payload.authoritySha256"
    }
    states["AcquireFaultLock"]["ResultPath"] = "$.controller"
    states["AcquireFaultLock"]["Catch"] = [
        {"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "ReleaseUnarmedLock"}
    ]
    states["ReleaseUnarmedLock"]["Catch"] = [
        {
            "ErrorEquals": ["States.ALL"],
            "ResultPath": "$.cleanupFailure",
            "Next": "CompensationFailed",
        }
    ]
    for name in (
        "ArmWatchdog",
        "ApplyDeny",
        "VerifyDependencyUnavailable",
        "VerifyExecutionDenied",
        "RemoveDeny",
        "VerifyRecovery",
        "DisarmWatchdog",
    ):
        states[name]["Catch"] = compensate
    states["SealEvidence"]["Catch"] = [
        {"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "CompletionFailed"}
    ]
    states["Compensate"]["Catch"] = [
        {
            "ErrorEquals": ["States.ALL"],
            "ResultPath": "$.cleanupFailure",
            "Next": "CompensationFailed",
        }
    ]
    return {"StartAt": "VerifyPreconditions", "TimeoutSeconds": 1200, "States": states}


def _environment() -> dict[str, Any]:
    return {
        "PRIMARY_FAULT_TARGET_ROLE_ARN": PRIMARY_ROLE,
        "PRIMARY_FAULT_TARGET_FUNCTION_ARN": (
            "arn:aws:lambda:eu-west-2:111111111111:function:AaiPrimaryHandler"
        ),
        "PRIMARY_FAULT_AUDIT_BUCKET_ARN": "arn:aws:s3:::aai-primary-audit-111111",
        "PRIMARY_FAULT_DYNAMODB_TABLE_ARNS": json.dumps(
            [f"arn:aws:dynamodb:eu-west-2:111111111111:table/Primary{i}" for i in range(4)]
        ),
        "PRIMARY_FAULT_SIGNING_KEY_ARN": (
            "arn:aws:kms:eu-west-2:111111111111:key/mrk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "PRIMARY_FAULT_QUEUE_ARNS": json.dumps(["arn:aws:sqs:eu-west-2:111111111111:primary"]),
        "RECOVERY_FAULT_TARGET_ROLE_ARN": RECOVERY_ROLE,
        "RECOVERY_FAULT_TARGET_FUNCTION_ARN": (
            "arn:aws:lambda:eu-west-1:111111111111:function:AaiRecoveryHandler"
        ),
        "RECOVERY_FAULT_AUDIT_BUCKET_ARN": "arn:aws:s3:::aai-recovery-audit-111111",
        "RECOVERY_FAULT_DYNAMODB_TABLE_ARNS": json.dumps(
            [f"arn:aws:dynamodb:eu-west-1:111111111111:table/Recovery{i}" for i in range(4)]
        ),
        "RECOVERY_FAULT_SIGNING_KEY_ARN": (
            "arn:aws:kms:eu-west-1:111111111111:key/mrk-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ),
        "RECOVERY_FAULT_QUEUE_ARNS": json.dumps(["arn:aws:sqs:eu-west-1:111111111111:recovery"]),
        "TRANSITION_JOURNAL_TABLE_NAME": JOURNAL_NAME,
        "FAULT_WATCHDOG_SCHEDULE_GROUP": "aai-sec-regional-fault-watchdogs",
        "FAULT_WATCHDOG_ROLE_ARN": {"Fn::GetAtt": ["WatchdogRole", "Arn"]},
        "FAULT_CLEANUP_FUNCTION_ARN": {"Fn::GetAtt": ["Cleanup", "Arn"]},
        "FAULT_WATCHDOG_DLQ_ARN": {"Fn::GetAtt": ["Dlq", "Arn"]},
    }


def _function(handler: str, *, environment: bool) -> dict[str, Any]:
    role = {
        "scripts.regional_fault_probe_lambda.handler": "ProbeRole",
        "scripts.regional_fault_cleanup_lambda.handler": "CleanupRole",
        "scripts.regional_fault_controller_lambda.handler": "ControllerRole",
    }[handler]
    props: dict[str, Any] = {
        "Architectures": ["arm64"],
        "Code": {"S3Bucket": "asset", "S3Key": "same.zip"},
        "Handler": handler,
        "MemorySize": 256,
        "ReservedConcurrentExecutions": 1,
        "Runtime": "python3.13",
        "Role": {"Fn::GetAtt": [role, "Arn"]},
        "Timeout": 30,
    }
    if environment:
        props["Environment"] = {"Variables": _environment()}
    elif handler == "scripts.regional_fault_probe_lambda.handler":
        props["Environment"] = {
            "Variables": {
                "PRIMARY_FAULT_TARGET_FUNCTION_ARN": _environment()[
                    "PRIMARY_FAULT_TARGET_FUNCTION_ARN"
                ],
                "RECOVERY_FAULT_TARGET_FUNCTION_ARN": _environment()[
                    "RECOVERY_FAULT_TARGET_FUNCTION_ARN"
                ],
            }
        }
    return {"Type": "AWS::Lambda::Function", "Properties": props}


def _template() -> dict[str, Any]:
    resources: dict[str, Any] = {
        "Dlq": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"MessageRetentionPeriod": 1209600, "SqsManagedSseEnabled": True},
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
        },
        "DlqPolicy": {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sqs:*",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                            "Effect": "Deny",
                            "Principal": {"AWS": "*"},
                            "Resource": {"Fn::GetAtt": ["Dlq", "Arn"]},
                        }
                    ]
                },
            },
        },
        "ScheduleGroup": {
            "Type": "AWS::Scheduler::ScheduleGroup",
            "Properties": {"Name": "aai-sec-regional-fault-watchdogs"},
        },
        "ProbeRole": _trust("lambda.amazonaws.com", managed=True),
        "CleanupRole": _trust("lambda.amazonaws.com", managed=True),
        "ControllerRole": _trust("lambda.amazonaws.com", managed=True),
        "WatchdogRole": _trust("scheduler.amazonaws.com"),
        "WorkflowRole": _trust("states.amazonaws.com"),
        "Probe": _function("scripts.regional_fault_probe_lambda.handler", environment=False),
        "Cleanup": _function("scripts.regional_fault_cleanup_lambda.handler", environment=True),
        "Controller": _function(
            "scripts.regional_fault_controller_lambda.handler", environment=True
        ),
        "ProbePolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "Roles": [{"Ref": "ProbeRole"}],
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": "lambda:InvokeFunction",
                            "Effect": "Allow",
                            "Resource": [
                                _environment()["PRIMARY_FAULT_TARGET_FUNCTION_ARN"],
                                _environment()["RECOVERY_FAULT_TARGET_FUNCTION_ARN"],
                            ],
                        }
                    ]
                },
            },
        },
        "ControllerPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "Roles": [{"Ref": "ControllerRole"}],
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": [
                                "dynamodb:GetItem",
                                "dynamodb:PutItem",
                                "dynamodb:UpdateItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:TransactWriteItems",
                            ],
                            "Effect": "Allow",
                            "Resource": JOURNAL_ARN,
                        },
                        {
                            "Action": [
                                "iam:PutRolePolicy",
                                "iam:DeleteRolePolicy",
                                "iam:ListRolePolicies",
                            ],
                            "Effect": "Allow",
                            "Resource": [PRIMARY_ROLE, RECOVERY_ROLE],
                        },
                    ]
                },
            },
        },
        "CleanupPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "Roles": [{"Ref": "CleanupRole"}],
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": ["dynamodb:GetItem", "dynamodb:TransactWriteItems"],
                            "Effect": "Allow",
                            "Resource": JOURNAL_ARN,
                        },
                        {
                            "Action": "iam:DeleteRolePolicy",
                            "Effect": "Allow",
                            "Resource": [PRIMARY_ROLE, RECOVERY_ROLE],
                        },
                    ]
                },
            },
        },
        "WatchdogPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "Roles": [{"Ref": "WatchdogRole"}],
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": "lambda:InvokeFunction",
                            "Effect": "Allow",
                            "Resource": {"Fn::GetAtt": ["Cleanup", "Arn"]},
                        },
                        {
                            "Action": "sqs:SendMessage",
                            "Effect": "Allow",
                            "Resource": {"Fn::GetAtt": ["Dlq", "Arn"]},
                        },
                    ]
                },
            },
        },
        "WorkflowPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "Roles": [{"Ref": "WorkflowRole"}],
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": "lambda:InvokeFunction",
                            "Effect": "Allow",
                            "Resource": [
                                {"Fn::GetAtt": ["Probe", "Arn"]},
                                {"Fn::GetAtt": ["Controller", "Arn"]},
                                {"Fn::GetAtt": ["Cleanup", "Arn"]},
                            ],
                        },
                        {
                            "Action": [
                                "logs:CreateLogDelivery",
                                "logs:DeleteLogDelivery",
                                "logs:DescribeLogGroups",
                                "logs:DescribeResourcePolicies",
                                "logs:GetLogDelivery",
                                "logs:ListLogDeliveries",
                                "logs:PutResourcePolicy",
                                "logs:UpdateLogDelivery",
                            ],
                            "Effect": "Allow",
                            "Resource": "*",
                        },
                    ]
                },
            },
        },
        "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {}},
        "StateMachine": {
            "Type": "AWS::StepFunctions::StateMachine",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "DefinitionString": json.dumps(_definition()),
                "DefinitionSubstitutions": {"ProbeArn": {}, "ControllerArn": {}, "CleanupArn": {}},
                "LoggingConfiguration": {
                    "Destinations": [{}],
                    "IncludeExecutionData": False,
                    "Level": "ERROR",
                },
                "StateMachineName": "aai-sec-regional-fault-controller",
                "StateMachineType": "STANDARD",
            },
        },
        "Metadata": {"Type": "AWS::CDK::Metadata", "Properties": {}},
    }
    for index in range(5):
        resources[f"Alarm{index}"] = {
            "Type": "AWS::CloudWatch::Alarm",
            "Properties": {"AlarmActions": [ALERT_TOPIC]},
        }
    return {
        "Resources": resources,
        "Outputs": {
            "RegionalFaultControllerStatus": {"Value": "probes-disabled-no-fault-authority"}
        },
    }


def _verify(module: Any, template: dict[str, Any]) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        module.verify(
            template,
            journal_table_name=JOURNAL_NAME,
            journal_table_arn=JOURNAL_ARN,
            primary_role_arn=PRIMARY_ROLE,
            recovery_role_arn=RECOVERY_ROLE,
            alert_topic_arn=ALERT_TOPIC,
        ),
    )


def test_exact_disabled_compensated_stack_is_verified() -> None:
    module = _load()
    assert _verify(module, _template()) == {
        "status": "verified-probes-disabled",
        "stateCount": 18,
        "compensatedStateCount": 7,
        "publicExecutionGrantCount": 0,
        "alarmCount": 5,
        "assetFileCount": 6,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["Resources"].update({"Api": {"Type": "AWS::ApiGatewayV2::Api"}}),
            "cardinality",
        ),
        (
            lambda value: value["Resources"]["Probe"]["Properties"].update(
                {"Environment": {"Variables": {"PROBES_ENABLED": "true"}}}
            ),
            "ambient",
        ),
        (
            lambda value: value["Resources"]["StateMachine"]["Properties"][
                "LoggingConfiguration"
            ].update({"IncludeExecutionData": True}),
            "privacy",
        ),
        (
            lambda value: value["Resources"]["WorkflowPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ].append({"Action": "states:StartExecution", "Effect": "Allow", "Resource": "*"}),
            "wildcard resource",
        ),
        (
            lambda value: value["Resources"]["ControllerPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ][1].update({"Resource": "*"}),
            "wildcard resource",
        ),
        (
            lambda value: value["Resources"]["Dlq"]["Properties"].update(
                {"MessageRetentionPeriod": 60}
            ),
            "DLQ posture",
        ),
        (
            lambda value: value["Resources"]["Dlq"].update({"DeletionPolicy": "Delete"}),
            "DLQ is not retained",
        ),
        (
            lambda value: value["Resources"]["DlqPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ][0]["Condition"]["Bool"].update({"aws:SecureTransport": "true"}),
            "insecure transport",
        ),
        (
            lambda value: value["Outputs"]["RegionalFaultControllerStatus"].update(
                {"Value": "ready"}
            ),
            "disabled probes",
        ),
    ],
)
def test_verifier_rejects_public_broad_or_falsely_ready_stack(mutation: Any, message: str) -> None:
    module = _load()
    value = copy.deepcopy(_template())
    mutation(value)
    with pytest.raises(module.RegionalFaultStackVerificationError, match=message):
        _verify(module, value)


def test_verifier_rejects_precondition_bypass_and_missing_compensation() -> None:
    module = _load()
    mutations: list[tuple[Callable[[dict[str, Any]], Any], str]] = [
        (
            lambda states: states["VerifyPreconditions"].update({"Next": "ApplyDeny"}),
            "preconditions",
        ),
        (
            lambda states: states["ApplyDeny"].pop("Catch"),
            "compensation",
        ),
        (
            lambda states: states["ArmWatchdog"]["Retry"][0].update({"MaxAttempts": 99}),
            "retry",
        ),
    ]
    for mutate, message in mutations:
        value = _template()
        definition = json.loads(
            value["Resources"]["StateMachine"]["Properties"]["DefinitionString"]
        )
        mutate(definition["States"])
        value["Resources"]["StateMachine"]["Properties"]["DefinitionString"] = json.dumps(
            definition
        )
        with pytest.raises(module.RegionalFaultStackVerificationError, match=message):
            _verify(module, value)

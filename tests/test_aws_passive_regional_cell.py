"""Adversarial contracts for the non-serving AWS recovery cell."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_passive_regional_cell.py"
    spec = importlib.util.spec_from_file_location("aai_verify_passive_cell", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _template() -> dict[str, Any]:
    resources: dict[str, Any] = {
        "Api": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {"DisableExecuteApiEndpoint": True},
        },
        "RuleA": {"Type": "AWS::Events::Rule", "Properties": {"State": "DISABLED"}},
        "RuleB": {"Type": "AWS::Events::Rule", "Properties": {"State": "DISABLED"}},
        "RuleC": {"Type": "AWS::Events::Rule", "Properties": {"State": "DISABLED"}},
        "RuleD": {"Type": "AWS::Events::Rule", "Properties": {"State": "DISABLED"}},
        "MappingA": {
            "Type": "AWS::Lambda::EventSourceMapping",
            "Properties": {"Enabled": False},
        },
        "MappingB": {
            "Type": "AWS::Lambda::EventSourceMapping",
            "Properties": {"Enabled": False},
        },
        "Ui": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
                "BucketEncryption": {
                    "ServerSideEncryptionConfiguration": [
                        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                    ]
                },
                "VersioningConfiguration": {"Status": "Enabled"},
            },
        },
        "UiPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "Ui"},
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "s3:*",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ]
                },
            },
        },
        "Policy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Action": ["dynamodb:GetItem"]}]
                }
            },
        },
        "RuntimeRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "ManagedPolicyArns": [
                    {
                        "Fn::Join": [
                            "",
                            [
                                "arn:",
                                {"Ref": "AWS::Partition"},
                                ":iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                            ],
                        ]
                    }
                ]
            },
        },
    }
    for index in range(3):
        resources[f"Function{index}"] = {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "ReservedConcurrentExecutions": 0,
                "Environment": {
                    "Variables": {
                        "PASSIVE_CELL_MODE": "standby",
                        "RECOVERY_JOB_RECONCILIATION_ENABLED": "false",
                        "POLICY_SIGNING_KEY_ARN": "",
                    }
                },
            },
        }
    return {
        "Resources": resources,
        "Outputs": {"PassiveCellStatus": {"Value": "staged-not-serving"}},
    }


def test_passive_template_requires_every_independent_disable_control() -> None:
    module = _load()
    evidence = module.verify(_template())
    assert evidence == {
        "status": "verified-not-serving",
        "lambdaCount": 3,
        "disabledScheduleCount": 4,
        "disabledEventSourceCount": 2,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["Resources"]["Api"]["Properties"].clear(), "execute-api"),
        (
            lambda value: value["Resources"]["Function0"]["Properties"].update(
                {"ReservedConcurrentExecutions": 1}
            ),
            "executable authority",
        ),
        (
            lambda value: value["Resources"]["Function0"]["Properties"]["Environment"][
                "Variables"
            ].update({"POLICY_SIGNING_KEY_ARN": "arn:active"}),
            "executable authority",
        ),
        (
            lambda value: value["Resources"]["RuleA"]["Properties"].update({"State": "ENABLED"}),
            "schedule",
        ),
        (
            lambda value: value["Resources"]["MappingA"]["Properties"].update({"Enabled": True}),
            "queue mapping",
        ),
        (
            lambda value: value["Resources"]["Policy"]["Properties"]["PolicyDocument"]["Statement"][
                0
            ].update({"Action": ["dynamodb:PutItem"]}),
            "forbidden authority",
        ),
        (
            lambda value: value["Resources"].update(
                {
                    "InlineRole": {
                        "Type": "AWS::IAM::Role",
                        "Properties": {
                            "Policies": [
                                {
                                    "PolicyName": "bypass",
                                    "PolicyDocument": {
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "kms:Sign",
                                            }
                                        ]
                                    },
                                }
                            ]
                        },
                    }
                }
            ),
            "forbidden authority",
        ),
        (
            lambda value: value["Resources"]["Ui"]["Properties"].pop("BucketEncryption"),
            "encryption",
        ),
        (
            lambda value: value["Resources"].pop("UiPolicy"),
            "TLS-only",
        ),
        (
            lambda value: value["Resources"]["UiPolicy"]["Properties"].update(
                {"Bucket": {"Ref": "DifferentBucket"}}
            ),
            "TLS-only",
        ),
        (
            lambda value: value["Resources"]["RuntimeRole"]["Properties"].update(
                {"ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]}
            ),
            "unapproved managed policy",
        ),
        (
            lambda value: value["Resources"].update(
                {"Distribution": {"Type": "AWS::CloudFront::Distribution", "Properties": {}}}
            ),
            "traffic-serving",
        ),
        (
            lambda value: value["Outputs"].update({"ApiUrl": {"Value": "https://invalid"}}),
            "serving origin",
        ),
    ],
)
def test_passive_template_rejects_bypass_authority(mutation: Any, message: str) -> None:
    module = _load()
    value = _template()
    mutation(value)
    with pytest.raises(module.PassiveCellVerificationError, match=message):
        module.verify(value)


def test_passive_stack_source_has_no_activation_or_routing_construct() -> None:
    root = Path(__file__).parents[1]
    stack = (root / "infra/aws-control-plane/lib/passive-regional-cell-stack.ts").read_text()
    assert "disableExecuteApiEndpoint: true" in stack
    assert "reservedConcurrentExecutions: active ? 100 : 0" in stack
    assert stack.count("reservedConcurrentExecutions: active ? 5 : 0") == 2
    # Two queue mappings plus one schedule-loop declaration synthesize to six
    # separately verified disabled resources.
    assert stack.count("enabled: active") == 3
    assert 'POLICY_SIGNING_KEY_ARN: active ? props.policySigningReplicaKeyArn : ""' in stack
    assert 'RECOVERY_JOB_RECONCILIATION_ENABLED: active ? "true" : "false"' in stack
    assert ".grantReadData(target)" in stack
    assert 'actions: ["s3:GetObject", "s3:GetObjectVersion"]' in stack
    assert "if (active && evidenceReports)" in stack
    assert "cloudfront" not in stack.lower()
    assert "route53" not in stack.lower()

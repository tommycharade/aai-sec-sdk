"""Adversarial contracts for active-but-not-routed recovery infrastructure."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_active_regional_cell.py"
    spec = importlib.util.spec_from_file_location("aai_verify_active_cell", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_DIGEST = "a" * 64
_KEY = "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"
_ENTRA = "12345678-1234-1234-1234-123456789abc"
_TENANT = "synthetic-enterprise"


def _variables() -> dict[str, Any]:
    return {
        "PASSIVE_CELL_MODE": "active",
        "RECOVERY_JOB_RECONCILIATION_ENABLED": "true",
        "REGIONAL_CELL_ROLE": "recovery",
        "REGIONAL_JOB_RECONCILIATION_ENABLED": "true",
        "ACTIVATION_EVIDENCE_SHA256": _DIGEST,
        "POLICY_SIGNING_KEY_ARN": _KEY,
        "REGIONAL_POLICY_SIGNING_KEY_ARN": _KEY,
        "ENTRA_PROVIDER_ENABLED": "true",
        "ENTRA_TENANT_ID": _ENTRA,
        "ENTRA_AAI_TENANT_ID": _TENANT,
        "ENTRA_STRONG_AUTH_ENFORCED": "true",
        "SCIM_ENABLED": "false",
        "EVIDENCE_REPORT_BUCKET": {"Ref": "EvidenceReports"},
        "RUNTIME_ATTESTATION_MANIFESTS_SHA256": "b" * 64,
        "RUNTIME_ATTESTATION_APPROVALS_SHA256": "c" * 64,
    }


def _bucket() -> dict[str, Any]:
    return {
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
    }


def _bucket_policy(bucket: str) -> dict[str, Any]:
    return {
        "Type": "AWS::S3::BucketPolicy",
        "Properties": {
            "Bucket": {"Ref": bucket},
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
    }


def _template() -> dict[str, Any]:
    resources: dict[str, Any] = {
        "RuntimeRole": {"Type": "AWS::IAM::Role", "Properties": {}},
        "Api": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {
                "DisableExecuteApiEndpoint": True,
                "CorsConfiguration": {"AllowOrigins": ["https://security.example.com"]},
            },
        },
        "Ui": _bucket(),
        "EvidenceReports": _bucket(),
        "UiPolicy": _bucket_policy("Ui"),
        "EvidencePolicy": _bucket_policy("EvidenceReports"),
        "HandlerPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "dynamodb:TransactWriteItems",
                                "dynamodb:UpdateItem",
                                "s3:GetObjectRetention",
                                "s3:PutObject",
                                "s3:PutObjectRetention",
                                "sns:Publish",
                                "sqs:SendMessage",
                            ],
                            "Resource": "arn:aws:synthetic:eu-west-1:111111111111:resource/a",
                        },
                        {
                            "Effect": "Allow",
                            "Action": ["kms:Sign", "kms:Verify", "kms:GetPublicKey"],
                            "Resource": _KEY,
                        },
                    ]
                }
            },
        },
        "WorkerPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::synthetic/*",
                        }
                    ]
                }
            },
        },
        "RetentionPolicy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sqs:ReceiveMessage",
                            "Resource": "arn:aws:sqs:eu-west-1:111111111111:synthetic",
                        }
                    ]
                }
            },
        },
    }
    for index, concurrency in enumerate((100, 5, 5)):
        resources[f"Function{index}"] = {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                **({"Role": {"Fn::GetAtt": ["RuntimeRole", "Arn"]}} if index == 0 else {}),
                "ReservedConcurrentExecutions": concurrency,
                "Environment": {"Variables": _variables()},
            },
        }
    for index in range(2):
        resources[f"Mapping{index}"] = {
            "Type": "AWS::Lambda::EventSourceMapping",
            "Properties": {"Enabled": True},
        }
    for index in range(5):
        resources[f"Rule{index}"] = {
            "Type": "AWS::Events::Rule",
            "Properties": {"State": "ENABLED"},
        }
    return {
        "Resources": resources,
        "Outputs": {
            "PassiveCellStatus": {"Value": "active-not-routed"},
            "RegionalFaultTargetExecutionRoleArn": {
                "Value": {"Fn::GetAtt": ["RuntimeRole", "Arn"]}
            },
        },
    }


def test_complete_active_template_is_bounded_and_not_routed() -> None:
    module = _load()
    assert module.verify(
        _template(),
        activation_evidence_sha256=_DIGEST,
        signing_key_arn=_KEY,
        entra_tenant_id=_ENTRA,
        aai_tenant_id=_TENANT,
        stable_ui_origin="https://security.example.com",
    ) == {
        "status": "verified-active-not-routed",
        "lambdaConcurrency": [5, 5, 100],
        "enabledScheduleCount": 5,
        "enabledEventSourceCount": 2,
        "privateBucketCount": 2,
        "iamActionCount": 12,
        "activationEvidenceSha256": _DIGEST,
        "signingKeyArn": _KEY,
        "entraTenantId": _ENTRA,
        "aaiTenantId": _TENANT,
        "faultTargetRoleLogicalId": "RuntimeRole",
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["Resources"]["Api"]["Properties"].clear(), "execute-api"),
        (
            lambda value: value["Resources"]["Function0"]["Properties"].update(
                {"ReservedConcurrentExecutions": 0}
            ),
            "concurrency",
        ),
        (
            lambda value: value["Resources"]["Function0"]["Properties"]["Environment"][
                "Variables"
            ].update({"ACTIVATION_EVIDENCE_SHA256": "0" * 64}),
            "authority binding",
        ),
        (
            lambda value: value["Resources"]["Function1"]["Properties"]["Environment"][
                "Variables"
            ].update({"POLICY_SIGNING_KEY_ARN": ""}),
            "authority binding",
        ),
        (
            lambda value: value["Resources"]["Function2"]["Properties"]["Environment"][
                "Variables"
            ].update({"ENTRA_STRONG_AUTH_ENFORCED": "false"}),
            "authority binding",
        ),
        (
            lambda value: value["Resources"]["Mapping0"]["Properties"].update({"Enabled": False}),
            "queue mappings",
        ),
        (
            lambda value: value["Resources"]["Rule0"]["Properties"].update({"State": "DISABLED"}),
            "schedules",
        ),
        (
            lambda value: value["Resources"].update(
                {"Dns": {"Type": "AWS::Route53::RecordSet", "Properties": {}}}
            ),
            "must not route",
        ),
        (
            lambda value: value["Outputs"].update({"ApiUrl": {"Value": "unsafe"}}),
            "advertises traffic",
        ),
        (
            lambda value: value["Outputs"].pop("RegionalFaultTargetExecutionRoleArn"),
            "fault target role output",
        ),
        (
            lambda value: value["Outputs"]["RegionalFaultTargetExecutionRoleArn"].update(
                {"Value": {"Fn::GetAtt": ["DifferentRole", "Arn"]}}
            ),
            "fault target role",
        ),
        (
            lambda value: value["Resources"]["HandlerPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ].append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}),
            "unreviewed IAM authority",
        ),
        (
            lambda value: value["Resources"]["HandlerPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ].append(
                {
                    "Effect": "Allow",
                    "Action": "logs:PutLogEvents",
                    "Resource": "arn:aws:logs:eu-west-1:111111111111:log-group:synthetic",
                }
            ),
            "unreviewed IAM authority",
        ),
        (
            lambda value: value["Resources"]["HandlerPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ][1].update({"Action": ["kms:Sign", "kms:Decrypt"]}),
            "unreviewed IAM authority",
        ),
        (
            lambda value: value["Resources"]["HandlerPolicy"]["Properties"]["PolicyDocument"][
                "Statement"
            ][1].update({"Resource": "arn:aws:kms:eu-west-1:111:key/other"}),
            "different key",
        ),
        (
            lambda value: value["Resources"]["EvidenceReports"]["Properties"].pop(
                "BucketEncryption"
            ),
            "encryption",
        ),
        (
            lambda value: value["Resources"]["EvidencePolicy"]["Properties"].update(
                {"Bucket": {"Ref": "Ui"}}
            ),
            "cover each active bucket",
        ),
    ],
)
def test_active_template_rejects_missing_or_widened_authority(mutation: Any, message: str) -> None:
    module = _load()
    value = copy.deepcopy(_template())
    mutation(value)
    with pytest.raises(module.ActiveCellVerificationError, match=message):
        module.verify(
            value,
            activation_evidence_sha256=_DIGEST,
            signing_key_arn=_KEY,
            entra_tenant_id=_ENTRA,
            aai_tenant_id=_TENANT,
            stable_ui_origin="https://security.example.com",
        )


def test_active_stack_source_keeps_runtime_and_routing_separate() -> None:
    root = Path(__file__).parents[1]
    stack = (root / "infra/aws-control-plane/lib/passive-regional-cell-stack.ts").read_text(
        encoding="utf-8"
    )
    deployment = (root / "scripts/deploy_aws_passive_cell.py").read_text(encoding="utf-8")
    assert 'readonly cellMode: "standby" | "active"' in stack
    assert 'active ? "active-not-routed" : "staged-not-serving"' in stack
    assert "active ? 100 : 0" in stack
    assert "active ? 5 : 0" in stack
    assert "route53" not in stack.lower()
    assert '"RECOVERY_CELL_MODE": "standby"' in deployment

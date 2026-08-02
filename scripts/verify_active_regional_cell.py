#!/usr/bin/env python3
"""Verify a synthesized recovery cell is active-capable but still unrouted.

The verifier consumes CloudFormation JSON only and independently checks the
exact runtime gates, bounded concurrency, identity/signing binding, delivery
paths and IAM service envelope. It rejects routing resources: activation of
runtime authority and movement of stable traffic remain separate steps.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


class ActiveCellVerificationError(ValueError):
    """Raised when a recovery template is unsafe, incomplete or already routed."""


_ROUTING_TYPES = (
    "AWS::Route53::",
    "AWS::GlobalAccelerator::",
    "AWS::ARCZonalShift::",
    "AWS::Route53RecoveryControl::",
    "AWS::CloudFront::",
)
_REQUIRED_ACTIONS = {
    "dynamodb:TransactWriteItems",
    "dynamodb:UpdateItem",
    "kms:GetPublicKey",
    "kms:Sign",
    "s3:GetObjectRetention",
    "s3:PutObject",
    "s3:PutObjectRetention",
    "sns:Publish",
    "sqs:SendMessage",
}
_ALLOWED_ACTIONS = {
    "dynamodb:BatchGetItem",
    "dynamodb:BatchWriteItem",
    "dynamodb:ConditionCheckItem",
    "dynamodb:DeleteItem",
    "dynamodb:DescribeTable",
    "dynamodb:GetItem",
    "dynamodb:GetRecords",
    "dynamodb:GetShardIterator",
    "dynamodb:PutItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:TransactWriteItems",
    "dynamodb:UpdateItem",
    "kms:GetPublicKey",
    "kms:Sign",
    "s3:Abort*",
    "s3:DeleteObject*",
    "s3:GetBucket*",
    "s3:GetBucketLocation",
    "s3:GetObject",
    "s3:GetObject*",
    "s3:GetObjectLegalHold",
    "s3:GetObjectRetention",
    "s3:GetObjectVersion",
    "s3:List*",
    "s3:ListBucket",
    "s3:PutObject",
    "s3:PutObjectLegalHold",
    "s3:PutObjectRetention",
    "s3:PutObjectTagging",
    "s3:PutObjectVersionTagging",
    "sns:Publish",
    "sqs:ChangeMessageVisibility",
    "sqs:DeleteMessage",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ReceiveMessage",
    "sqs:SendMessage",
    "xray:PutTelemetryRecords",
    "xray:PutTraceSegments",
}
_FORBIDDEN_ACTION_PREFIXES = (
    "cloudformation:",
    "cloudfront:",
    "iam:",
    "organizations:",
    "route53:",
    "secretsmanager:",
    "ssm:",
)
_MRK_ARN = re.compile(r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key/mrk-[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _object(value: object, label: str) -> dict[str, Any]:
    """Return one object or reject ambiguous template structure."""
    if not isinstance(value, dict):
        raise ActiveCellVerificationError(f"{label} must be an object")
    return value


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    """Return all exact CloudFormation resources of one type."""
    resources = _object(template.get("Resources"), "template Resources")
    return [
        _object(resource, "CloudFormation resource")
        for resource in resources.values()
        if isinstance(resource, dict) and resource.get("Type") == resource_type
    ]


def _actions(value: object) -> set[str]:
    """Normalize one IAM action field without accepting malformed values."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return set(value)
    raise ActiveCellVerificationError("IAM Action must be one string or non-empty string list")


def _policy_statements(template: dict[str, Any]) -> list[dict[str, Any]]:
    """Return bounded inline statements from every synthesized IAM policy."""
    policies = [
        *_resources(template, "AWS::IAM::Policy"),
        *_resources(template, "AWS::IAM::ManagedPolicy"),
    ]
    if not 3 <= len(policies) <= 6:
        raise ActiveCellVerificationError("active cell runtime policy count is unexpected")
    statements: list[dict[str, Any]] = []
    for policy in policies:
        properties = _object(policy.get("Properties"), "IAM policy properties")
        document = _object(properties.get("PolicyDocument"), "IAM policy document")
        raw = document.get("Statement")
        if not isinstance(raw, list) or not raw or len(raw) > 100:
            raise ActiveCellVerificationError("IAM policy statements are malformed or unbounded")
        statements.extend(_object(item, "IAM statement") for item in raw)
    return statements


def _verify_iam(template: dict[str, Any], signing_key_arn: str) -> set[str]:
    """Require the runtime service envelope and reject administrative authority."""
    observed: set[str] = set()
    for statement in _policy_statements(template):
        if statement.get("Effect") != "Allow":
            continue
        if "NotAction" in statement or "NotResource" in statement:
            raise ActiveCellVerificationError("active runtime IAM cannot use NotAction/NotResource")
        actions = _actions(statement.get("Action"))
        observed.update(actions)
        for action in actions:
            if action not in _ALLOWED_ACTIONS:
                raise ActiveCellVerificationError(
                    f"active runtime contains unreviewed IAM authority: {action}"
                )
            lowered = action.lower()
            if lowered == "*" or any(
                lowered.startswith(prefix) for prefix in _FORBIDDEN_ACTION_PREFIXES
            ):
                raise ActiveCellVerificationError(
                    f"active runtime contains administrative authority: {action}"
                )
            if lowered.startswith("kms:") and action not in {"kms:Sign", "kms:GetPublicKey"}:
                raise ActiveCellVerificationError(
                    "active runtime contains unapproved KMS authority"
                )
            if lowered.startswith("lambda:") or lowered == "sts:assumerole":
                raise ActiveCellVerificationError("active runtime can mutate or assume authority")
        if actions.intersection({"kms:Sign", "kms:GetPublicKey"}):
            resource = statement.get("Resource")
            if resource != signing_key_arn:
                raise ActiveCellVerificationError("KMS signing authority names a different key")
        if statement.get("Resource") == "*" and actions != {
            "xray:PutTelemetryRecords",
            "xray:PutTraceSegments",
        }:
            raise ActiveCellVerificationError("active runtime contains unscoped resource authority")
    missing = _REQUIRED_ACTIONS - observed
    if missing:
        raise ActiveCellVerificationError(
            f"active runtime is missing required authority: {sorted(missing)[0]}"
        )
    return observed


def _verify_private_buckets(template: dict[str, Any]) -> int:
    """Require private, encrypted, versioned and TLS-only active buckets."""
    resources = _object(template.get("Resources"), "template Resources")
    bucket_names = {
        name
        for name, resource in resources.items()
        if isinstance(resource, dict) and resource.get("Type") == "AWS::S3::Bucket"
    }
    buckets = _resources(template, "AWS::S3::Bucket")
    policies = _resources(template, "AWS::S3::BucketPolicy")
    if len(buckets) != 2 or len(policies) != 2:
        raise ActiveCellVerificationError("active cell requires UI and evidence-report buckets")
    for bucket in buckets:
        properties = _object(bucket.get("Properties"), "S3 bucket properties")
        public = _object(properties.get("PublicAccessBlockConfiguration"), "S3 public-access block")
        encryption = _object(properties.get("BucketEncryption"), "S3 encryption")
        rules = encryption.get("ServerSideEncryptionConfiguration")
        if (
            set(public.values()) != {True}
            or properties.get("VersioningConfiguration") != {"Status": "Enabled"}
            or not isinstance(rules, list)
            or not rules
        ):
            raise ActiveCellVerificationError(
                "active buckets must be private, encrypted and versioned"
            )
    protected: set[str] = set()
    for policy in policies:
        properties = _object(policy.get("Properties"), "bucket policy properties")
        bucket_ref = properties.get("Bucket")
        if (
            not isinstance(bucket_ref, dict)
            or set(bucket_ref) != {"Ref"}
            or bucket_ref.get("Ref") not in bucket_names
        ):
            raise ActiveCellVerificationError("TLS policy names an unknown active bucket")
        protected.add(str(bucket_ref["Ref"]))
        document = _object(
            properties.get("PolicyDocument"),
            "bucket policy document",
        )
        statements = document.get("Statement")
        if not isinstance(statements, list) or not any(
            isinstance(item, dict)
            and item.get("Effect") == "Deny"
            and item.get("Condition") == {"Bool": {"aws:SecureTransport": "false"}}
            for item in statements
        ):
            raise ActiveCellVerificationError("active bucket is not TLS-only")
    if protected != bucket_names:
        raise ActiveCellVerificationError("TLS policies do not cover each active bucket exactly")
    return len(buckets)


def verify(
    template: dict[str, Any],
    *,
    activation_evidence_sha256: str,
    signing_key_arn: str,
    entra_tenant_id: str,
    aai_tenant_id: str,
) -> dict[str, Any]:
    """Verify one exact active-but-not-routed recovery CloudFormation template."""
    if not _SHA256.fullmatch(activation_evidence_sha256):
        raise ActiveCellVerificationError("expected activation evidence SHA-256 is invalid")
    if not _MRK_ARN.fullmatch(signing_key_arn):
        raise ActiveCellVerificationError("expected recovery signing-key ARN is invalid")
    resources = _object(template.get("Resources"), "template Resources")
    for resource in resources.values():
        item = _object(resource, "CloudFormation resource")
        resource_type = item.get("Type")
        if not isinstance(resource_type, str):
            raise ActiveCellVerificationError("CloudFormation resource type is malformed")
        if resource_type.startswith(_ROUTING_TYPES):
            raise ActiveCellVerificationError("active runtime template must not route traffic")

    apis = _resources(template, "AWS::ApiGatewayV2::Api")
    if (
        len(apis) != 1
        or _object(apis[0].get("Properties"), "API properties").get("DisableExecuteApiEndpoint")
        is not True
    ):
        raise ActiveCellVerificationError("active cell raw execute-api endpoint must be disabled")

    functions = _resources(template, "AWS::Lambda::Function")
    if len(functions) != 3:
        raise ActiveCellVerificationError("active cell must contain exactly three functions")
    concurrency: list[int] = []
    for function in functions:
        properties = _object(function.get("Properties"), "Lambda properties")
        current = properties.get("ReservedConcurrentExecutions")
        if isinstance(current, bool) or not isinstance(current, int) or not 1 <= current <= 100:
            raise ActiveCellVerificationError("active Lambda concurrency is missing or unbounded")
        concurrency.append(current)
        variables = _object(
            _object(properties.get("Environment"), "Lambda environment").get("Variables"),
            "Lambda variables",
        )
        if (
            variables.get("PASSIVE_CELL_MODE") != "active"
            or variables.get("RECOVERY_JOB_RECONCILIATION_ENABLED") != "true"
            or variables.get("ACTIVATION_EVIDENCE_SHA256") != activation_evidence_sha256
            or variables.get("POLICY_SIGNING_KEY_ARN") != signing_key_arn
            or variables.get("REGIONAL_POLICY_SIGNING_KEY_ARN") != signing_key_arn
            or variables.get("ENTRA_PROVIDER_ENABLED") != "true"
            or variables.get("ENTRA_TENANT_ID") != entra_tenant_id
            or variables.get("ENTRA_AAI_TENANT_ID") != aai_tenant_id
            or variables.get("ENTRA_STRONG_AUTH_ENFORCED") != "true"
            or variables.get("SCIM_ENABLED") != "false"
            or not isinstance(variables.get("EVIDENCE_REPORT_BUCKET"), dict)
            or not _SHA256.fullmatch(str(variables.get("RUNTIME_ATTESTATION_MANIFESTS_SHA256", "")))
            or not _SHA256.fullmatch(str(variables.get("RUNTIME_ATTESTATION_APPROVALS_SHA256", "")))
        ):
            raise ActiveCellVerificationError("active Lambda authority binding is incomplete")
    if sorted(concurrency) != [5, 5, 100]:
        raise ActiveCellVerificationError("active Lambda concurrency differs from reviewed bounds")

    mappings = _resources(template, "AWS::Lambda::EventSourceMapping")
    rules = _resources(template, "AWS::Events::Rule")
    if len(mappings) != 2 or any(
        _object(item.get("Properties"), "event mapping").get("Enabled") is not True
        for item in mappings
    ):
        raise ActiveCellVerificationError("active queue mappings are incomplete")
    if len(rules) != 4 or any(
        _object(item.get("Properties"), "schedule").get("State") != "ENABLED" for item in rules
    ):
        raise ActiveCellVerificationError("active schedules are incomplete")

    bucket_count = _verify_private_buckets(template)
    observed_actions = _verify_iam(template, signing_key_arn)
    outputs = _object(template.get("Outputs"), "template Outputs")
    status = _object(outputs.get("PassiveCellStatus"), "PassiveCellStatus output")
    if status.get("Value") != "active-not-routed" or any(
        any(term in name.lower() for term in ("url", "endpoint", "domain")) for name in outputs
    ):
        raise ActiveCellVerificationError("active template advertises traffic or wrong status")
    return {
        "status": "verified-active-not-routed",
        "lambdaConcurrency": sorted(concurrency),
        "enabledScheduleCount": len(rules),
        "enabledEventSourceCount": len(mappings),
        "privateBucketCount": bucket_count,
        "iamActionCount": len(observed_actions),
        "activationEvidenceSha256": activation_evidence_sha256,
        "signingKeyArn": signing_key_arn,
        "entraTenantId": entra_tenant_id,
        "aaiTenantId": aai_tenant_id,
    }


def main() -> int:
    """Read, bound and verify one synthesized active recovery template."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--activation-evidence-sha256", required=True)
    parser.add_argument("--signing-key-arn", required=True)
    parser.add_argument("--entra-tenant-id", required=True)
    parser.add_argument("--aai-tenant-id", required=True)
    arguments = parser.parse_args()
    if arguments.template.stat().st_size > 5_000_000:
        raise ActiveCellVerificationError("CloudFormation template exceeds 5 MiB")
    try:
        value = json.loads(arguments.template.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ActiveCellVerificationError("active template is unreadable") from error
    print(
        json.dumps(
            verify(
                _object(value, "CloudFormation template"),
                activation_evidence_sha256=arguments.activation_evidence_sha256,
                signing_key_arn=arguments.signing_key_arn,
                entra_tenant_id=arguments.entra_tenant_id,
                aai_tenant_id=arguments.aai_tenant_id,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

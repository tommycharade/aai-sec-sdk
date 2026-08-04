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
    "kms:Verify",
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
    "kms:Verify",
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


def _resource_items(
    template: dict[str, Any], resource_type: str
) -> list[tuple[str, dict[str, Any]]]:
    """Return logical IDs with exact resources of one CloudFormation type."""
    resources = _object(template.get("Resources"), "template Resources")
    return [
        (logical_id, _object(resource, "CloudFormation resource"))
        for logical_id, resource in resources.items()
        if isinstance(resource, dict) and resource.get("Type") == resource_type
    ]


def _fault_target_role(template: dict[str, Any], outputs: dict[str, Any]) -> str:
    """Require one output bound to the exact active recovery handler role."""
    if "RegionalFaultTargetExecutionRoleArn" not in outputs:
        raise ActiveCellVerificationError("fault target role output is missing")
    output = _object(
        outputs.get("RegionalFaultTargetExecutionRoleArn"),
        "RegionalFaultTargetExecutionRoleArn output",
    )
    value = output.get("Value")
    if (
        not isinstance(value, dict)
        or set(value) != {"Fn::GetAtt"}
        or not isinstance(value["Fn::GetAtt"], list)
        or len(value["Fn::GetAtt"]) != 2
        or value["Fn::GetAtt"][1] != "Arn"
        or not isinstance(value["Fn::GetAtt"][0], str)
    ):
        raise ActiveCellVerificationError("fault target role output is not one exact role ARN")
    role_id = value["Fn::GetAtt"][0]
    resources = _object(template.get("Resources"), "template Resources")
    role = _object(resources.get(role_id), "fault target role")
    if role.get("Type") != "AWS::IAM::Role":
        raise ActiveCellVerificationError("fault target output does not reference an IAM role")
    role_reference = {"Fn::GetAtt": [role_id, "Arn"]}
    matches = []
    for function in _resources(template, "AWS::Lambda::Function"):
        properties = _object(function.get("Properties"), "Lambda properties")
        environment = _object(properties.get("Environment"), "Lambda environment")
        variables = _object(environment.get("Variables"), "Lambda variables")
        if (
            properties.get("Role") == role_reference
            and variables.get("REGIONAL_CELL_ROLE") == "recovery"
        ):
            matches.append(function)
    if len(matches) != 1:
        raise ActiveCellVerificationError("fault target role must identify one recovery handler")
    return role_id


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


def _verify_iam(
    template: dict[str, Any],
    signing_key_arn: str,
    assurance_signing_key_arn: str,
    historical_assurance_key_arns: list[str],
) -> set[str]:
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
            if lowered.startswith("kms:") and action not in {
                "kms:Sign",
                "kms:Verify",
                "kms:GetPublicKey",
            }:
                raise ActiveCellVerificationError(
                    "active runtime contains unapproved KMS authority"
                )
            if lowered.startswith("lambda:") or lowered == "sts:assumerole":
                raise ActiveCellVerificationError("active runtime can mutate or assume authority")
        if actions.intersection({"kms:Sign", "kms:Verify", "kms:GetPublicKey"}):
            resource = statement.get("Resource")
            if resource not in {
                signing_key_arn,
                assurance_signing_key_arn,
                *historical_assurance_key_arns,
            }:
                raise ActiveCellVerificationError("KMS signing authority names a different key")
            if resource == assurance_signing_key_arn and actions != {"kms:Sign", "kms:Verify"}:
                raise ActiveCellVerificationError(
                    "assurance signer contains executable-policy key authority"
                )
            if resource in historical_assurance_key_arns and actions != {"kms:Verify"}:
                raise ActiveCellVerificationError("historical assurance key can sign new evidence")
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


def _verify_assurance_worker_authority(
    template: dict[str, Any],
    assurance_signing_key_arn: str,
    historical_assurance_key_arns: list[str],
) -> None:
    """Require the dedicated report worker's exact write and signing envelope."""
    matches = [
        (logical_id, resource)
        for logical_id, resource in _resource_items(template, "AWS::Lambda::Function")
        if _object(resource.get("Properties"), "Lambda properties").get("Handler")
        == "assurance_report_worker.handler"
    ]
    if len(matches) != 1:
        raise ActiveCellVerificationError("active cell assurance worker identity is ambiguous")
    _, worker = matches[0]
    properties = _object(worker.get("Properties"), "assurance worker properties")
    role = properties.get("Role")
    if (
        not isinstance(role, dict)
        or not isinstance(role.get("Fn::GetAtt"), list)
        or len(role["Fn::GetAtt"]) != 2
        or role["Fn::GetAtt"][1] != "Arn"
    ):
        raise ActiveCellVerificationError("assurance worker role binding is malformed")
    role_id = role["Fn::GetAtt"][0]
    policies = []
    for policy in _resources(template, "AWS::IAM::Policy"):
        policy_properties = _object(policy.get("Properties"), "IAM policy properties")
        if {"Ref": role_id} in policy_properties.get("Roles", []):
            policies.append(policy_properties)
    if len(policies) != 1:
        raise ActiveCellVerificationError("assurance worker policy binding is ambiguous")
    document = _object(policies[0].get("PolicyDocument"), "assurance worker policy")
    statements = document.get("Statement")
    if not isinstance(statements, list) or not statements:
        raise ActiveCellVerificationError("assurance worker policy is empty")
    variables = _object(
        _object(properties.get("Environment"), "assurance worker environment").get("Variables"),
        "assurance worker variables",
    )
    control_binding = variables.get("CONTROL_TABLE")
    saw_scoped_write = False
    saw_assurance_signer = False
    observed_historical_keys: set[str] = set()
    for raw in statements:
        statement = _object(raw, "assurance worker IAM statement")
        if statement.get("Effect") != "Allow":
            continue
        actions = _actions(statement.get("Action"))
        resource_text = json.dumps(statement.get("Resource"), sort_keys=True)
        if any(action.startswith("dynamodb:") for action in actions):
            if json.dumps(control_binding, sort_keys=True).strip('"') not in resource_text:
                raise ActiveCellVerificationError("assurance worker can read an unrelated table")
            writes = actions.intersection(
                {
                    "dynamodb:BatchWriteItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:PutItem",
                    "dynamodb:TransactWriteItems",
                    "dynamodb:UpdateItem",
                }
            )
            if writes:
                if writes != {"dynamodb:PutItem"} or statement.get("Condition") != {
                    "ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["ASSURANCE#*"]}
                }:
                    raise ActiveCellVerificationError(
                        "assurance worker table write is not partition-confined"
                    )
                saw_scoped_write = True
        if any(action.startswith("s3:") for action in actions):
            allowed_prefixes = (
                "tenant=*/assurance-snapshots/*",
                "tenant=*/year=*/month=*/idempotent-*",
            )
            if not all(prefix in resource_text for prefix in allowed_prefixes):
                raise ActiveCellVerificationError(
                    "assurance worker S3 authority is not prefix-bound"
                )
            if any(action.startswith("s3:Delete") for action in actions):
                raise ActiveCellVerificationError("assurance worker can delete retained evidence")
        if any(action.startswith("kms:") for action in actions):
            resource = statement.get("Resource")
            if resource == assurance_signing_key_arn and actions == {"kms:Sign", "kms:Verify"}:
                saw_assurance_signer = True
            elif resource in historical_assurance_key_arns and actions == {"kms:Verify"}:
                observed_historical_keys.add(resource)
            else:
                raise ActiveCellVerificationError("assurance worker KMS authority is not dedicated")
    if (
        not saw_scoped_write
        or not saw_assurance_signer
        or observed_historical_keys != set(historical_assurance_key_arns)
    ):
        raise ActiveCellVerificationError("assurance worker authority is incomplete")


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
    assurance_signing_key_arn: str,
    historical_assurance_key_arns: list[str],
    entra_tenant_id: str,
    aai_tenant_id: str,
    stable_ui_origin: str,
) -> dict[str, Any]:
    """Verify one exact active-but-not-routed recovery CloudFormation template."""
    if not _SHA256.fullmatch(activation_evidence_sha256):
        raise ActiveCellVerificationError("expected activation evidence SHA-256 is invalid")
    if not _MRK_ARN.fullmatch(signing_key_arn):
        raise ActiveCellVerificationError("expected recovery signing-key ARN is invalid")
    if (
        not _MRK_ARN.fullmatch(assurance_signing_key_arn)
        or assurance_signing_key_arn == signing_key_arn
    ):
        raise ActiveCellVerificationError("expected assurance signing-key ARN is invalid")
    if (
        len(historical_assurance_key_arns) > 8
        or len(set(historical_assurance_key_arns)) != len(historical_assurance_key_arns)
        or any(
            not _MRK_ARN.fullmatch(value) or value in {signing_key_arn, assurance_signing_key_arn}
            for value in historical_assurance_key_arns
        )
    ):
        raise ActiveCellVerificationError("historical assurance verification registry is invalid")
    resources = _object(template.get("Resources"), "template Resources")
    for resource in resources.values():
        item = _object(resource, "CloudFormation resource")
        resource_type = item.get("Type")
        if not isinstance(resource_type, str):
            raise ActiveCellVerificationError("CloudFormation resource type is malformed")
        if resource_type.startswith(_ROUTING_TYPES):
            raise ActiveCellVerificationError("active runtime template must not route traffic")

    if not re.fullmatch(r"https://[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])", stable_ui_origin):
        raise ActiveCellVerificationError("expected stable UI origin is invalid")
    apis = _resources(template, "AWS::ApiGatewayV2::Api")
    api_properties = _object(apis[0].get("Properties"), "API properties") if apis else {}
    if (
        len(apis) != 1
        or api_properties.get("DisableExecuteApiEndpoint") is not True
        or api_properties.get("CorsConfiguration", {}).get("AllowOrigins") != [stable_ui_origin]
    ):
        raise ActiveCellVerificationError(
            "active execute-api endpoint or stable UI origin contract is invalid"
        )

    functions = _resources(template, "AWS::Lambda::Function")
    if len(functions) != 4:
        raise ActiveCellVerificationError("active cell must contain exactly four functions")
    concurrency: list[int] = []
    assurance_workers = 0
    for function in functions:
        properties = _object(function.get("Properties"), "Lambda properties")
        assurance_worker = properties.get("Handler") == "assurance_report_worker.handler"
        assurance_workers += int(assurance_worker)
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
            or variables.get("REGIONAL_CELL_ROLE") != "recovery"
            or variables.get("REGIONAL_JOB_RECONCILIATION_ENABLED") != "true"
            or variables.get("ACTIVATION_EVIDENCE_SHA256") != activation_evidence_sha256
            or variables.get("POLICY_SIGNING_KEY_ARN")
            != ("" if assurance_worker else signing_key_arn)
            or variables.get("REGIONAL_POLICY_SIGNING_KEY_ARN")
            != ("" if assurance_worker else signing_key_arn)
            or variables.get("ASSURANCE_REPORT_SIGNING_KEY_ARN") != assurance_signing_key_arn
            or variables.get("ASSURANCE_REPORT_VERIFICATION_KEY_ARNS")
            != json.dumps(
                [assurance_signing_key_arn, *historical_assurance_key_arns],
                separators=(",", ":"),
            )
            or variables.get("ENTRA_PROVIDER_ENABLED") != "true"
            or variables.get("ENTRA_TENANT_ID") != entra_tenant_id
            or variables.get("ENTRA_AAI_TENANT_ID") != aai_tenant_id
            or variables.get("ENTRA_STRONG_AUTH_ENFORCED") != "true"
            or variables.get("SCIM_ENABLED") != "false"
            or not isinstance(variables.get("EVIDENCE_REPORT_BUCKET"), dict)
            or not isinstance(variables.get("ASSURANCE_REPORT_QUEUE_URL"), dict)
            or not _SHA256.fullmatch(str(variables.get("RUNTIME_ATTESTATION_MANIFESTS_SHA256", "")))
            or not _SHA256.fullmatch(str(variables.get("RUNTIME_ATTESTATION_APPROVALS_SHA256", "")))
        ):
            raise ActiveCellVerificationError("active Lambda authority binding is incomplete")
    if assurance_workers != 1:
        raise ActiveCellVerificationError("active cell assurance worker identity is ambiguous")
    if sorted(concurrency) != [5, 5, 20, 100]:
        raise ActiveCellVerificationError("active Lambda concurrency differs from reviewed bounds")

    mappings = _resources(template, "AWS::Lambda::EventSourceMapping")
    rules = _resources(template, "AWS::Events::Rule")
    if len(mappings) != 3 or any(
        _object(item.get("Properties"), "event mapping").get("Enabled") is not True
        for item in mappings
    ):
        raise ActiveCellVerificationError("active queue mappings are incomplete")
    if len(rules) != 21 or any(
        _object(item.get("Properties"), "schedule").get("State") != "ENABLED" for item in rules
    ):
        raise ActiveCellVerificationError("active schedules are incomplete")

    bucket_count = _verify_private_buckets(template)
    observed_actions = _verify_iam(
        template,
        signing_key_arn,
        assurance_signing_key_arn,
        historical_assurance_key_arns,
    )
    _verify_assurance_worker_authority(
        template, assurance_signing_key_arn, historical_assurance_key_arns
    )
    outputs = _object(template.get("Outputs"), "template Outputs")
    status = _object(outputs.get("PassiveCellStatus"), "PassiveCellStatus output")
    if status.get("Value") != "active-not-routed" or any(
        any(term in name.lower() for term in ("url", "endpoint", "domain")) for name in outputs
    ):
        raise ActiveCellVerificationError("active template advertises traffic or wrong status")
    fault_target_role = _fault_target_role(template, outputs)
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
        "faultTargetRoleLogicalId": fault_target_role,
    }


def main() -> int:
    """Read, bound and verify one synthesized active recovery template."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--activation-evidence-sha256", required=True)
    parser.add_argument("--signing-key-arn", required=True)
    parser.add_argument("--assurance-signing-key-arn", required=True)
    parser.add_argument("--historical-assurance-key-arns", default="[]")
    parser.add_argument("--entra-tenant-id", required=True)
    parser.add_argument("--aai-tenant-id", required=True)
    parser.add_argument("--stable-ui-origin", required=True)
    arguments = parser.parse_args()
    if arguments.template.stat().st_size > 5_000_000:
        raise ActiveCellVerificationError("CloudFormation template exceeds 5 MiB")
    try:
        value = json.loads(arguments.template.read_text(encoding="utf-8"))
        historical_assurance_key_arns = json.loads(arguments.historical_assurance_key_arns)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ActiveCellVerificationError("active template is unreadable") from error
    if not isinstance(historical_assurance_key_arns, list) or not all(
        isinstance(item, str) for item in historical_assurance_key_arns
    ):
        raise ActiveCellVerificationError("historical assurance key registry is malformed")
    print(
        json.dumps(
            verify(
                _object(value, "CloudFormation template"),
                activation_evidence_sha256=arguments.activation_evidence_sha256,
                signing_key_arn=arguments.signing_key_arn,
                assurance_signing_key_arn=arguments.assurance_signing_key_arn,
                historical_assurance_key_arns=historical_assurance_key_arns,
                entra_tenant_id=arguments.entra_tenant_id,
                aai_tenant_id=arguments.aai_tenant_id,
                stable_ui_origin=arguments.stable_ui_origin,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

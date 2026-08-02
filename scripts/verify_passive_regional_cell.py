"""Verify that a synthesized recovery cell has no executable authority.

The verifier consumes CloudFormation JSON only. It performs no AWS calls and
does not trust CDK construct intent: the synthesized resource properties and
IAM actions are the evidence reviewed before a passive-cell deployment.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class PassiveCellVerificationError(ValueError):
    """Raised when synthesized infrastructure could serve or mutate authority."""


_FORBIDDEN_RESOURCE_PREFIXES = (
    "AWS::Route53::",
    "AWS::GlobalAccelerator::",
    "AWS::ARCZonalShift::",
    "AWS::Route53RecoveryControl::",
    "AWS::CloudFront::",
)
_FORBIDDEN_ACTIONS = {
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:PutItem",
    "dynamodb:TransactWriteItems",
    "dynamodb:UpdateItem",
    "kms:Sign",
    "s3:DeleteObject",
    "s3:PutObject",
    "sns:Publish",
    "sqs:SendMessage",
}


def _object(value: object, label: str) -> dict[str, Any]:
    """Return one JSON object or reject an ambiguous template value."""
    if not isinstance(value, dict):
        raise PassiveCellVerificationError(f"{label} must be an object")
    return value


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    """Return exact resources of one CloudFormation type."""
    resources = _object(template.get("Resources"), "template Resources")
    return [
        _object(resource, "CloudFormation resource")
        for resource in resources.values()
        if isinstance(resource, dict) and resource.get("Type") == resource_type
    ]


def _resource_items(
    template: dict[str, Any], resource_type: str
) -> list[tuple[str, dict[str, Any]]]:
    """Return logical IDs and exact resources of one CloudFormation type."""
    resources = _object(template.get("Resources"), "template Resources")
    return [
        (identifier, _object(resource, "CloudFormation resource"))
        for identifier, resource in resources.items()
        if isinstance(resource, dict) and resource.get("Type") == resource_type
    ]


def _actions(value: object) -> set[str]:
    """Flatten one bounded IAM Action field without accepting wildcards."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    raise PassiveCellVerificationError("IAM Action must contain explicit strings")


def _policy_documents(template: dict[str, Any]) -> list[dict[str, Any]]:
    """Return managed and inline role policies from the synthesized template."""
    documents: list[dict[str, Any]] = []
    for policy in _resources(template, "AWS::IAM::Policy"):
        properties = _object(policy.get("Properties"), "IAM policy properties")
        documents.append(_object(properties.get("PolicyDocument"), "IAM policy document"))
    for role in _resources(template, "AWS::IAM::Role"):
        properties = _object(role.get("Properties"), "IAM role properties")
        inline = properties.get("Policies", [])
        if not isinstance(inline, list):
            raise PassiveCellVerificationError("IAM role Policies must be a list")
        for policy in inline:
            value = _object(policy, "inline IAM policy")
            documents.append(_object(value.get("PolicyDocument"), "inline IAM policy document"))
    return documents


def _has_tls_only_bucket_policy(template: dict[str, Any], bucket_id: str) -> bool:
    """Return whether a bucket policy explicitly denies insecure transport."""
    for policy in _resources(template, "AWS::S3::BucketPolicy"):
        properties = _object(policy.get("Properties"), "bucket policy properties")
        if properties.get("Bucket") != {"Ref": bucket_id}:
            continue
        document = _object(properties.get("PolicyDocument"), "bucket policy document")
        statements = document.get("Statement")
        if not isinstance(statements, list):
            continue
        for statement in statements:
            value = _object(statement, "bucket policy statement")
            condition = value.get("Condition")
            if not isinstance(condition, dict):
                continue
            boolean = condition.get("Bool")
            if (
                value.get("Effect") == "Deny"
                and isinstance(boolean, dict)
                and boolean.get("aws:SecureTransport") in ("false", False)
                and "s3:*" in _actions(value.get("Action"))
            ):
                return True
    return False


def _verify_role_managed_policies(template: dict[str, Any]) -> None:
    """Allow only Lambda's bounded logging policy on passive runtime roles."""
    expected = [
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
    for role in _resources(template, "AWS::IAM::Role"):
        properties = _object(role.get("Properties"), "IAM role properties")
        if properties.get("ManagedPolicyArns", []) not in ([], expected):
            raise PassiveCellVerificationError("passive role contains an unapproved managed policy")


def verify(template: dict[str, Any]) -> dict[str, int | str]:
    """Verify fail-closed standby invariants and return content-minimised evidence."""
    resources = _object(template.get("Resources"), "template Resources")
    if any(
        isinstance(resource, dict)
        and isinstance(resource.get("Type"), str)
        and resource["Type"].startswith(_FORBIDDEN_RESOURCE_PREFIXES)
        for resource in resources.values()
    ):
        raise PassiveCellVerificationError("passive cell contains a traffic-serving resource")

    functions = _resources(template, "AWS::Lambda::Function")
    if len(functions) != 3:
        raise PassiveCellVerificationError("passive cell must contain exactly three Lambdas")
    for function in functions:
        properties = _object(function.get("Properties"), "Lambda properties")
        variables = _object(
            _object(properties.get("Environment"), "Lambda Environment").get("Variables"),
            "Lambda environment variables",
        )
        if (
            properties.get("ReservedConcurrentExecutions") != 0
            or variables.get("PASSIVE_CELL_MODE") != "standby"
            or variables.get("RECOVERY_JOB_RECONCILIATION_ENABLED") != "false"
            or variables.get("REGIONAL_CELL_ROLE") != "recovery"
            or variables.get("REGIONAL_JOB_RECONCILIATION_ENABLED") != "false"
            or variables.get("POLICY_SIGNING_KEY_ARN") != ""
        ):
            raise PassiveCellVerificationError("Lambda executable authority is not disabled")

    apis = _resources(template, "AWS::ApiGatewayV2::Api")
    api_properties = _object(apis[0].get("Properties"), "API properties") if apis else {}
    if (
        len(apis) != 1
        or api_properties.get("DisableExecuteApiEndpoint") is not True
        or api_properties.get("CorsConfiguration", {}).get("AllowOrigins")
        != ["https://not-serving.invalid"]
    ):
        raise PassiveCellVerificationError(
            "execute-api and passive browser origins must be disabled"
        )
    if _resources(template, "AWS::ApiGatewayV2::DomainName"):
        raise PassiveCellVerificationError("passive cell must not attach a custom API domain")

    rules = _resources(template, "AWS::Events::Rule")
    if len(rules) != 4 or any(
        _object(rule.get("Properties"), "EventBridge properties").get("State") != "DISABLED"
        for rule in rules
    ):
        raise PassiveCellVerificationError("every passive schedule must be disabled")
    mappings = _resources(template, "AWS::Lambda::EventSourceMapping")
    if len(mappings) != 2 or any(
        _object(mapping.get("Properties"), "event mapping properties").get("Enabled") is not False
        for mapping in mappings
    ):
        raise PassiveCellVerificationError("every passive queue mapping must be disabled")

    buckets = _resource_items(template, "AWS::S3::Bucket")
    if len(buckets) != 1:
        raise PassiveCellVerificationError("passive cell must create one private UI origin")
    bucket_id, bucket_resource = buckets[0]
    bucket = _object(bucket_resource.get("Properties"), "UI bucket properties")
    public_block = _object(bucket.get("PublicAccessBlockConfiguration"), "public access block")
    encryption = _object(bucket.get("BucketEncryption"), "UI bucket encryption")
    encryption_rules = encryption.get("ServerSideEncryptionConfiguration")
    if (
        set(public_block.values()) != {True}
        or bucket.get("VersioningConfiguration") != {"Status": "Enabled"}
        or not isinstance(encryption_rules, list)
        or not encryption_rules
        or not all(
            isinstance(rule, dict)
            and isinstance(rule.get("ServerSideEncryptionByDefault"), dict)
            and rule["ServerSideEncryptionByDefault"].get("SSEAlgorithm") in {"AES256", "aws:kms"}
            for rule in encryption_rules
        )
        or not _has_tls_only_bucket_policy(template, bucket_id)
    ):
        raise PassiveCellVerificationError(
            "UI origin must be private, encrypted, versioned and TLS-only"
        )

    _verify_role_managed_policies(template)
    forbidden_actions = {action.lower() for action in _FORBIDDEN_ACTIONS}
    for document in _policy_documents(template):
        statements = document.get("Statement")
        if not isinstance(statements, list):
            raise PassiveCellVerificationError("IAM statements must be a list")
        for statement in statements:
            value = _object(statement, "IAM statement")
            if value.get("Effect") != "Allow":
                continue
            if "NotAction" in value:
                raise PassiveCellVerificationError("passive role contains NotAction authority")
            actions = _actions(value.get("Action"))
            if any("*" in action for action in actions):
                raise PassiveCellVerificationError("passive role contains wildcard authority")
            forbidden = {action for action in actions if action.lower() in forbidden_actions}
            if forbidden:
                raise PassiveCellVerificationError(
                    f"passive role contains forbidden authority: {sorted(forbidden)[0]}"
                )

    outputs = _object(template.get("Outputs"), "template Outputs")
    if any(any(term in name.lower() for term in ("url", "endpoint", "domain")) for name in outputs):
        raise PassiveCellVerificationError("passive stack must not advertise a serving origin")
    status = _object(outputs.get("PassiveCellStatus"), "PassiveCellStatus output")
    if status.get("Value") != "staged-not-serving":
        raise PassiveCellVerificationError("passive status output is missing or unsafe")
    return {
        "status": "verified-not-serving",
        "lambdaCount": len(functions),
        "disabledScheduleCount": len(rules),
        "disabledEventSourceCount": len(mappings),
    }


def main() -> int:
    """Read one bounded template, verify it and print non-sensitive evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    arguments = parser.parse_args()
    if arguments.template.stat().st_size > 5_000_000:
        raise PassiveCellVerificationError("CloudFormation template exceeds 5 MB")
    try:
        value = json.loads(arguments.template.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PassiveCellVerificationError("CloudFormation template is unreadable") from error
    evidence = verify(_object(value, "CloudFormation template"))
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

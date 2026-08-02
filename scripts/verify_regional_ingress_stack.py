#!/usr/bin/env python3
"""Verify one Regional API/private-UI custom-domain stack has no routing authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class RegionalIngressVerificationError(ValueError):
    """Raised when ingress infrastructure exceeds its bounded trust contract."""


_ALLOWED_COUNTS = {
    "AWS::ApiGatewayV2::Api": 1,
    "AWS::ApiGatewayV2::ApiMapping": 4,
    "AWS::ApiGatewayV2::DomainName": 4,
    "AWS::ApiGatewayV2::Integration": 1,
    "AWS::ApiGatewayV2::Route": 4,
    "AWS::ApiGatewayV2::Stage": 1,
    "AWS::CDK::Metadata": 1,
    "AWS::IAM::Policy": 1,
    "AWS::IAM::Role": 1,
    "AWS::Lambda::Function": 1,
    "AWS::Lambda::Permission": 4,
}


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegionalIngressVerificationError(f"{label} must be an object")
    return value


def _one(by_type: dict[str, list[dict[str, Any]]], kind: str) -> dict[str, Any]:
    values = by_type.get(kind, [])
    if len(values) != 1:
        raise RegionalIngressVerificationError(f"expected exactly one {kind}")
    return values[0]


def verify(
    template: dict[str, Any],
    *,
    cell_role: str,
    control_api_id: str,
    ui_bucket: str,
    certificate_arn: str,
    cognito_origin: str,
    stable_api_domain: str,
    stable_ui_domain: str,
    canary_api_domain: str,
    canary_ui_domain: str,
) -> dict[str, Any]:
    """Require exact regional domains, least privilege, and zero DNS authority."""
    if cell_role not in {"primary", "recovery"}:
        raise RegionalIngressVerificationError("cell role is invalid")
    domains = {stable_api_domain, stable_ui_domain, canary_api_domain, canary_ui_domain}
    if len(domains) != 4:
        raise RegionalIngressVerificationError("expected domains must be distinct")
    resources = _object(template.get("Resources"), "template Resources")
    by_type: dict[str, list[dict[str, Any]]] = {}
    for raw in resources.values():
        resource = _object(raw, "CloudFormation resource")
        kind = resource.get("Type")
        if not isinstance(kind, str) or kind not in _ALLOWED_COUNTS:
            raise RegionalIngressVerificationError(
                "stack contains DNS, global routing, storage mutation, or unexpected authority"
            )
        by_type.setdefault(kind, []).append(resource)
    counts = {kind: len(by_type.get(kind, [])) for kind in _ALLOWED_COUNTS}
    if counts != _ALLOWED_COUNTS:
        raise RegionalIngressVerificationError("regional ingress resource cardinality changed")

    domain_resources = by_type["AWS::ApiGatewayV2::DomainName"]
    observed_domains: set[str] = set()
    for resource in domain_resources:
        props = _object(resource.get("Properties"), "domain properties")
        name = props.get("DomainName")
        configurations = props.get("DomainNameConfigurations")
        if (
            not isinstance(name, str)
            or not isinstance(configurations, list)
            or configurations
            != [
                {
                    "CertificateArn": certificate_arn,
                    "EndpointType": "REGIONAL",
                    "IpAddressType": "ipv4",
                    "SecurityPolicy": "TLS_1_2",
                }
            ]
        ):
            raise RegionalIngressVerificationError("custom domain identity or TLS contract changed")
        observed_domains.add(name)
    if observed_domains != domains:
        raise RegionalIngressVerificationError("custom domain substitution detected")

    ui_api = _one(by_type, "AWS::ApiGatewayV2::Api")
    ui_api_props = _object(ui_api.get("Properties"), "UI API properties")
    if (
        ui_api_props.get("DisableExecuteApiEndpoint") is not True
        or ui_api_props.get("ProtocolType") != "HTTP"
        or ui_api_props.get("Name") != f"aai-sec-{cell_role}-regional-ui"
    ):
        raise RegionalIngressVerificationError("UI API exposes an unapproved endpoint")
    ui_api_ids = [
        logical_id
        for logical_id, raw in resources.items()
        if _object(raw, "resource").get("Type") == "AWS::ApiGatewayV2::Api"
    ]
    ui_ref = {"Ref": ui_api_ids[0]}
    mappings: dict[str, object] = {}
    for resource in by_type["AWS::ApiGatewayV2::ApiMapping"]:
        props = _object(resource.get("Properties"), "API mapping properties")
        if props.get("Stage") != "$default" or not isinstance(props.get("DomainName"), str):
            raise RegionalIngressVerificationError("API mapping stage or domain is unsafe")
        mappings[props["DomainName"]] = props.get("ApiId")
    expected_mappings = {
        stable_api_domain: control_api_id,
        canary_api_domain: control_api_id,
        stable_ui_domain: ui_ref,
        canary_ui_domain: ui_ref,
    }
    if mappings != expected_mappings:
        raise RegionalIngressVerificationError("API mapping target substitution detected")

    function = _one(by_type, "AWS::Lambda::Function")
    function_props = _object(function.get("Properties"), "UI function properties")
    expected_environment = {
        "REGIONAL_UI_API_ORIGIN": f"https://{stable_api_domain}",
        "REGIONAL_UI_BUCKET": ui_bucket,
        "REGIONAL_UI_COGNITO_ORIGIN": cognito_origin,
    }
    if (
        function_props.get("Architectures") != ["arm64"]
        or function_props.get("Runtime") != "python3.13"
        or function_props.get("Handler") != "regional_ui.handler"
        or function_props.get("MemorySize") != 256
        or function_props.get("Timeout") != 10
        or function_props.get("ReservedConcurrentExecutions") != 20
        or _object(function_props.get("Environment"), "UI environment").get("Variables")
        != expected_environment
    ):
        raise RegionalIngressVerificationError("UI runtime or browser trust contract changed")

    policy = _object(_one(by_type, "AWS::IAM::Policy").get("Properties"), "IAM policy")
    document = _object(policy.get("PolicyDocument"), "IAM policy document")
    statements = document.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        raise RegionalIngressVerificationError("UI IAM policy has unexpected authority")
    statement = _object(statements[0], "IAM statement")
    iam_resource = statement.get("Resource")
    joined = (
        _object(iam_resource, "S3 object ARN").get("Fn::Join")
        if isinstance(iam_resource, dict)
        else None
    )
    if (
        statement.get("Effect") != "Allow"
        or statement.get("Action") != "s3:GetObject"
        or not isinstance(joined, list)
        or len(joined) != 2
        or not isinstance(joined[1], list)
        or f":s3:::{ui_bucket}/*" not in joined[1]
    ):
        raise RegionalIngressVerificationError("UI IAM is not exact read-only bucket access")

    outputs = _object(template.get("Outputs"), "template Outputs")
    if (
        _object(outputs.get("RegionalIngressStatus"), "ingress status").get("Value")
        != "custom-domains-unrouted"
    ):
        raise RegionalIngressVerificationError("stack claims routed or ambiguous status")
    if (
        _object(outputs.get("RegionalIngressCellRole"), "cell role output").get("Value")
        != cell_role
    ):
        raise RegionalIngressVerificationError("cell role output differs from authority")
    return {
        "status": "verified-custom-domains-unrouted",
        "cellRole": cell_role,
        "customDomainCount": 4,
        "routingResourceCount": 0,
    }


def main() -> int:
    """Verify one bounded CDK template from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--cell-role", required=True)
    parser.add_argument("--control-api-id", required=True)
    parser.add_argument("--ui-bucket", required=True)
    parser.add_argument("--certificate-arn", required=True)
    parser.add_argument("--cognito-origin", required=True)
    parser.add_argument("--stable-api-domain", required=True)
    parser.add_argument("--stable-ui-domain", required=True)
    parser.add_argument("--canary-api-domain", required=True)
    parser.add_argument("--canary-ui-domain", required=True)
    args = parser.parse_args()
    if args.template.stat().st_size > 2_000_000:
        raise RegionalIngressVerificationError("template exceeds 2 MiB")
    value = json.loads(args.template.read_text(encoding="utf-8"))
    result = verify(
        _object(value, "template"),
        **{
            "cell_role": args.cell_role,
            "control_api_id": args.control_api_id,
            "ui_bucket": args.ui_bucket,
            "certificate_arn": args.certificate_arn,
            "cognito_origin": args.cognito_origin,
            "stable_api_domain": args.stable_api_domain,
            "stable_ui_domain": args.stable_ui_domain,
            "canary_api_domain": args.canary_api_domain,
            "canary_ui_domain": args.canary_ui_domain,
        },
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

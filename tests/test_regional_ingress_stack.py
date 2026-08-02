"""Adversarial contracts for non-routing Regional API/UI ingress."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_regional_ingress_stack.py"
    spec = importlib.util.spec_from_file_location("aai_verify_regional_ingress", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _arguments() -> dict[str, str]:
    return {
        "cell_role": "recovery",
        "control_api_id": "abcdefghij",
        "ui_bucket": "aai-recovery-ui-111111",
        "certificate_arn": (
            "arn:aws:acm:eu-west-1:111111111111:certificate/12345678-1234-4234-8234-123456789abc"
        ),
        "cognito_origin": "https://aai-recovery.auth.eu-west-1.amazoncognito.com",
        "stable_api_domain": "api.security.example.com",
        "stable_ui_domain": "security.example.com",
        "canary_api_domain": "api-recovery.security.example.com",
        "canary_ui_domain": "recovery.security.example.com",
    }


def _template() -> dict[str, Any]:
    args = _arguments()
    resources: dict[str, Any] = {
        "UiApi": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {
                "DisableExecuteApiEndpoint": True,
                "Name": "aai-sec-recovery-regional-ui",
                "ProtocolType": "HTTP",
            },
        },
        "Function": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "Architectures": ["arm64"],
                "Environment": {
                    "Variables": {
                        "REGIONAL_UI_API_ORIGIN": "https://api.security.example.com",
                        "REGIONAL_UI_BUCKET": args["ui_bucket"],
                        "REGIONAL_UI_COGNITO_ORIGIN": args["cognito_origin"],
                    }
                },
                "Handler": "regional_ui.handler",
                "MemorySize": 256,
                "ReservedConcurrentExecutions": 20,
                "Runtime": "python3.13",
                "Timeout": 10,
            },
        },
        "Role": {"Type": "AWS::IAM::Role", "Properties": {}},
        "Policy": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": "s3:GetObject",
                            "Effect": "Allow",
                            "Resource": {
                                "Fn::Join": [
                                    "",
                                    [
                                        "arn:",
                                        {"Ref": "AWS::Partition"},
                                        f":s3:::{args['ui_bucket']}/*",
                                    ],
                                ]
                            },
                        }
                    ]
                }
            },
        },
        "Stage": {"Type": "AWS::ApiGatewayV2::Stage", "Properties": {}},
        "Integration": {"Type": "AWS::ApiGatewayV2::Integration", "Properties": {}},
        "Metadata": {"Type": "AWS::CDK::Metadata", "Properties": {}},
    }
    for number in range(4):
        resources[f"Route{number}"] = {"Type": "AWS::ApiGatewayV2::Route", "Properties": {}}
        resources[f"Permission{number}"] = {"Type": "AWS::Lambda::Permission", "Properties": {}}
    mappings = {
        args["stable_api_domain"]: args["control_api_id"],
        args["canary_api_domain"]: args["control_api_id"],
        args["stable_ui_domain"]: {"Ref": "UiApi"},
        args["canary_ui_domain"]: {"Ref": "UiApi"},
    }
    for number, (domain, api_id) in enumerate(mappings.items()):
        resources[f"Domain{number}"] = {
            "Type": "AWS::ApiGatewayV2::DomainName",
            "Properties": {
                "DomainName": domain,
                "DomainNameConfigurations": [
                    {
                        "CertificateArn": args["certificate_arn"],
                        "EndpointType": "REGIONAL",
                        "IpAddressType": "ipv4",
                        "SecurityPolicy": "TLS_1_2",
                    }
                ],
            },
        }
        resources[f"Mapping{number}"] = {
            "Type": "AWS::ApiGatewayV2::ApiMapping",
            "Properties": {"ApiId": api_id, "DomainName": domain, "Stage": "$default"},
        }
    return {
        "Resources": resources,
        "Outputs": {
            "RegionalIngressStatus": {"Value": "custom-domains-unrouted"},
            "RegionalIngressCellRole": {"Value": "recovery"},
        },
    }


def test_exact_regional_ingress_is_verified_without_routing_authority() -> None:
    module = _load()
    assert module.verify(_template(), **_arguments()) == {
        "status": "verified-custom-domains-unrouted",
        "cellRole": "recovery",
        "customDomainCount": 4,
        "routingResourceCount": 0,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["Resources"].update(
                {"Dns": {"Type": "AWS::Route53::RecordSet", "Properties": {}}}
            ),
            "routing",
        ),
        (
            lambda value: value["Resources"]["Domain0"]["Properties"].update(
                {"DomainName": "evil.example.com"}
            ),
            "substitution",
        ),
        (
            lambda value: value["Resources"]["Domain0"]["Properties"]["DomainNameConfigurations"][
                0
            ].update({"CertificateArn": "substituted"}),
            "TLS",
        ),
        (
            lambda value: value["Resources"]["Mapping0"]["Properties"].update(
                {"ApiId": "attackerapi"}
            ),
            "mapping target",
        ),
        (
            lambda value: value["Resources"]["UiApi"]["Properties"].update(
                {"DisableExecuteApiEndpoint": False}
            ),
            "unapproved endpoint",
        ),
        (
            lambda value: value["Resources"]["Function"]["Properties"]["Environment"][
                "Variables"
            ].update({"REGIONAL_UI_BUCKET": "evil-bucket"}),
            "browser trust",
        ),
        (
            lambda value: value["Resources"]["Policy"]["Properties"]["PolicyDocument"]["Statement"][
                0
            ].update({"Action": "s3:*"}),
            "read-only",
        ),
        (
            lambda value: value["Outputs"]["RegionalIngressStatus"].update({"Value": "routed"}),
            "routed",
        ),
    ],
)
def test_verifier_rejects_domain_origin_route_and_authority_substitution(
    mutation: Any, message: str
) -> None:
    module = _load()
    value = copy.deepcopy(_template())
    mutation(value)
    with pytest.raises(module.RegionalIngressVerificationError, match=message):
        module.verify(value, **_arguments())

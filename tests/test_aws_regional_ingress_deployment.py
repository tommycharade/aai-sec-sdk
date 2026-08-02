"""Contracts for provider-bound, non-routing Regional ingress deployment."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts/deploy_aws_regional_ingress.py"
    spec = importlib.util.spec_from_file_location("aai_deploy_regional_ingress", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _payload(**changes: Any) -> str:
    value = {
        "schemaVersion": 1,
        "stackName": "AaiSecRecoveryRegionalIngress",
        "sourceStackName": "AaiSecPassiveRegionalCell",
        "cellRole": "recovery",
        "region": "eu-west-1",
        "certificateArn": (
            "arn:aws:acm:eu-west-1:111111111111:certificate/12345678-1234-4234-8234-123456789abc"
        ),
        "cognitoOrigin": "https://aai-recovery.auth.eu-west-1.amazoncognito.com",
        "stableApiDomain": "api.security.example.com",
        "stableUiDomain": "security.example.com",
        "canaryApiDomain": "api-recovery.security.example.com",
        "canaryUiDomain": "recovery.security.example.com",
        "approvalEvidenceRef": "change/INGRESS-123",
        "activationPermitted": False,
    }
    value.update(changes)
    return json.dumps(value)


def _certificate(manifest: Any) -> dict[str, Any]:
    return {
        "Certificate": {
            "CertificateArn": manifest.certificate_arn,
            "Status": "ISSUED",
            "SubjectAlternativeNames": [
                manifest.stable_api_domain,
                manifest.stable_ui_domain,
                manifest.canary_api_domain,
                manifest.canary_ui_domain,
            ],
            "DomainValidationOptions": [{"ValidationStatus": "SUCCESS"} for _ in range(4)],
            "KeyAlgorithm": "RSA_2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
        }
    }


def test_manifest_is_exact_non_routing_authority() -> None:
    module = _load()
    manifest = module.RegionalIngressManifest.parse(_payload())
    assert manifest.cell_role == "recovery"
    assert '"activationPermitted":false' in manifest.canonical_json()
    cases: list[tuple[dict[str, Any], str]] = [
        ({"activationPermitted": True}, "prohibit activation"),
        ({"stackName": "AaiSecPrimaryRegionalIngress"}, "cell role"),
        ({"region": "eu-west-2"}, "cross-Region"),
        ({"canaryUiDomain": "security.example.com"}, "distinct"),
        ({"cognitoOrigin": "https://login.example.com/path"}, "exact HTTPS"),
    ]
    for changes, message in cases:
        with pytest.raises(module.RegionalIngressDeploymentError, match=message):
            module.RegionalIngressManifest.parse(_payload(**changes))


def test_provider_identities_are_derived_and_certificate_is_exact(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.RegionalIngressManifest.parse(_payload())
    responses = iter(
        [
            {"Account": "111111111111"},
            {
                "Stacks": [
                    {
                        "StackStatus": "UPDATE_COMPLETE",
                        "Outputs": [
                            {"OutputKey": "PassiveControlPlaneApiId", "OutputValue": "abcdefghij"},
                            {
                                "OutputKey": "PassiveUiOriginBucketName",
                                "OutputValue": "private-ui-bucket",
                            },
                        ],
                    }
                ]
            },
            {
                "ApiId": "abcdefghij",
                "ProtocolType": "HTTP",
                "DisableExecuteApiEndpoint": True,
            },
            _certificate(manifest),
        ]
    )
    monkeypatch.setattr(module, "_aws", lambda *_args, **_kwargs: next(responses))
    assert module.provider_identities(manifest, profile="synthetic") == (
        "111111111111",
        "abcdefghij",
        "private-ui-bucket",
    )

    evidence = _certificate(manifest)
    evidence["Certificate"]["SubjectAlternativeNames"].append("wildcard.example.com")
    responses = iter(
        [
            {"Account": "111111111111"},
            {
                "Stacks": [
                    {
                        "StackStatus": "UPDATE_COMPLETE",
                        "Outputs": [
                            {"OutputKey": "PassiveControlPlaneApiId", "OutputValue": "abcdefghij"},
                            {
                                "OutputKey": "PassiveUiOriginBucketName",
                                "OutputValue": "private-ui-bucket",
                            },
                        ],
                    }
                ]
            },
            {
                "ApiId": "abcdefghij",
                "ProtocolType": "HTTP",
                "DisableExecuteApiEndpoint": True,
            },
            evidence,
        ]
    )
    monkeypatch.setattr(module, "_aws", lambda *_args, **_kwargs: next(responses))
    with pytest.raises(module.RegionalIngressDeploymentError, match="not exact"):
        module.provider_identities(manifest, profile="synthetic")


def test_environment_discards_ambient_ingress_authority(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.RegionalIngressManifest.parse(_payload())
    monkeypatch.setenv("REGIONAL_INGRESS_CONTROL_API_ID", "attacker")
    monkeypatch.setenv("REGIONAL_INGRESS_STABLE_UI_DOMAIN", "evil.example.com")
    environment = module.deployment_environment(
        manifest,
        profile="synthetic",
        account="111111111111",
        api_id="abcdefghij",
        bucket="private-ui-bucket",
    )
    assert environment["REGIONAL_INGRESS_CONTROL_API_ID"] == "abcdefghij"
    assert environment["REGIONAL_INGRESS_STABLE_UI_DOMAIN"] == "security.example.com"


def test_provider_gate_rejects_open_raw_control_api(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.RegionalIngressManifest.parse(_payload())
    responses = iter(
        [
            {"Account": "111111111111"},
            {
                "Stacks": [
                    {
                        "StackStatus": "UPDATE_COMPLETE",
                        "Outputs": [
                            {
                                "OutputKey": "PassiveControlPlaneApiId",
                                "OutputValue": "abcdefghij",
                            },
                            {
                                "OutputKey": "PassiveUiOriginBucketName",
                                "OutputValue": "private-ui-bucket",
                            },
                        ],
                    }
                ]
            },
            {
                "ApiId": "abcdefghij",
                "ProtocolType": "HTTP",
                "DisableExecuteApiEndpoint": False,
            },
        ]
    )
    monkeypatch.setattr(module, "_aws", lambda *_args, **_kwargs: next(responses))
    with pytest.raises(module.RegionalIngressDeploymentError, match="raw execute-api"):
        module.provider_identities(manifest, profile="synthetic")


def test_deploy_uses_exact_verified_assembly_and_has_no_route_command(
    monkeypatch: Any, tmp_path: Path
) -> None:
    module = _load()
    manifest = module.RegionalIngressManifest.parse(_payload())
    infrastructure = tmp_path / "infra/aws-control-plane"
    template = infrastructure / "cdk.out/AaiSecRecoveryRegionalIngress.template.json"
    template.parent.mkdir(parents=True)
    template.write_bytes(b'{"verified":true}')
    monkeypatch.setattr(module, "_ROOT", tmp_path)
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: Any) -> Any:
        calls.append(command)
        return type("Result", (), {"returncode": 0})()

    module.deploy(
        manifest,
        {},
        hashlib.sha256(template.read_bytes()).hexdigest(),
        runner=runner,
    )
    assert calls == [
        [
            "npx",
            "cdk",
            "--app",
            "cdk.out",
            "deploy",
            "AaiSecRecoveryRegionalIngress",
            "--require-approval",
            "never",
        ]
    ]
    assert not any(term in calls[0] for term in ("route53", "cloudfront", "globalaccelerator"))
    with pytest.raises(module.RegionalIngressDeploymentError, match="changed after verification"):
        module.deploy(manifest, {}, "0" * 64, runner=runner)

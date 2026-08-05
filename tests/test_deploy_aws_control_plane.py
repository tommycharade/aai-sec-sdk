"""Contracts for persistent, fail-closed AWS Entra deployment."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SYNTHETIC_RSA_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCn/CqjSUfACxgL
MC5UjgOHaIK36bFt/t4pqYN8bZSRNwcbXbw5BKjEN82xCh0P2JCe6IOcbbFxxFNA
Bjs4KHNWsCwIBx0rdGdYUQGHjtys79lDkfq2BZVPioxyKczPjdOrUmX928IwWlEU
XmR2QdYHlydPBgre7otZAafJbsEVBe4SOs/qJs6OwsdACh8GwYEWgq9ntP4sE8j6
N+3UPGJbIexvJl84wvOx1RaFFIhureNyd3id+P/Gn/DTqeR9lRMKdzEpMLIjlYD1
LqIfdHoAJzwvTPZR30XSUQME0kaj+aW/MImLSUrXrQFgJrDOaKa+UMsLydkaROuB
g3JWYhTVAgMBAAECggEAELlBk2z9uChClgaPbjqPLmFgtieNUvqPKo2mOfJ82nIk
gnxz+yc0GAjIMQplN0kjqLZUN/QRuNZHRXX5Wk9ooCY80/XFWSinCztRUCoQXSUp
t5jmYU2v/jG4ZrszmSww+PrkjX/d1st/C+yTytQmFy5cqvjahzQvakaIajzc+xcp
F5mtKuAHfDwIFpwfYydSwqUTszhPL/rnINiLXPY94CBYOhKekZRj6tL4k3yiNMiu
KvGPA/rZfVEd4cTNDK/xeEZgJAG2HWbVq0ZaRH1jgd2om8/0e8PTFTDKaTOdN1j0
S1E0RY5V5nYbMpRVSYrNS2v0oJ/tecjAxUrZSYgXcQKBgQDibjU2OnFUMfaPKeBm
sqp8expSyAKC9vpwJplJ5ZFnZ/y7OSB4mSIEvhT43lkzoBBvoWi0SGhtIuwp3vkZ
O1mqYVNGge3ybejMdFi4RKW7iJUP2vF8Im2TLOE5Wtnd5R5MJQNqbVP9hEJ81XeO
PS2Uoxjc/Bgluwwppsj+dbz3TQKBgQC97BHP4867dyoFfDqhlHgX0I9oj0u+WYba
ODdDVMwGIy6YXhwBVgCmyZNKslty4qFWt725nwBmD10Yb3SDjddtcGP0SmSqC+s+
4wtVJ1oxAjoggDOt/SFs7AdL3w6ArnL+j/mKmIePBB5QVHo1vUU9TBP3sNZS/424
4xTAujKfqQKBgQDUWfMBdnHOOkU3IljXN3v33iNjuzvPwvw/rZNY4DkrNzSoCP1Q
3Jwwwms8spoJdnWzmzZszPNSVswQwJHwfd6rkTbeCwAyuaz4Aa0qswaTB5Z0Fise
9dK5kf9vIKruFPADDTtU1k9MlHseQ7wp42oZ2ZN5u9qRmAfiEA6zxYuAiQKBgQCj
qfd/ivTwH7SanX95FpSXESdEF5hSJJxNGPymjUB0WYUh0JeZnx9Ym4TObfzYd+xI
6nYYq6iQStUS5ZkmdOkcain4rtMoprTGsKlnbE4QxbaJo3DlkqlnT87J1yKMScjX
DgMhKGhJGmd1GhdmkABG3nSmkkFfrNHYbffITayqYQKBgQCjOKgswf12bdBTIFJx
0BT19B2TcGbxmCrQcTeolmoPeUznPcqcpQ8YlM72Z/Y1B98AAbG8oJ9zjOmhXfIW
xdDYeIvjpzZdleHANkUGyl3JfIuh/H0SSAiHbpWoogDwkPeXC5nm07JX1at9x9lT
IFT5RXGbSTMKq3SgJ0w86JChMQ==
-----END PRIVATE KEY-----"""  # noqa: S105 - synthetic test-only key


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "deploy_aws_control_plane.py"
    spec = importlib.util.spec_from_file_location("aai_deploy_aws_control_plane", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "entraTenantId": "11111111-1111-4111-8111-111111111111",
        "entraClientId": "22222222-2222-4222-8222-222222222222",
        "entraClientSecretName": "aai-sec/entra/oidc-client-secret",
        "aaiTenantId": "tenant-enterprise-pilot",
        "entraScimTokenSecretName": "aai-sec/entra/scim-bearer",
        "strongAuthenticationEnforced": True,
        "conditionalAccessEvidenceRef": "CAB-1234",
    }
    value.update(updates)
    return value


def _recovery_manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "replicaBucketArn": "arn:aws:s3:::synthetic-audit-replica",
        "replicaRegion": "eu-west-1",
        "recoveryEvidenceRef": "DR-REVIEW-1234",
    }
    value.update(updates)
    return value


def _policy_github_manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "credentialSecretName": "aai-sec/policy/github-app-installation",
        "allowedRepositories": ["github.com/example/security-policy"],
        "reviewEvidenceRef": "SEC-REVIEW-1234",
    }
    value.update(updates)
    return value


def _policy_github_app_manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 2,
        "appPrivateKeySecretName": "aai-sec/policy/github-app-private-key",
        "appClientId": "Iv1.synthetic-client",
        "installationId": "12345678",
        "allowedRepositories": ["github.com/example/security-policy"],
        "reviewEvidenceRef": "SEC-REVIEW-1234",
    }
    value.update(updates)
    return value


def _data_boundary_manifest(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "homeRegion": "eu-west-2",
        "approvedDataRegions": ["eu-west-1", "eu-west-2"],
        "customerManagedDataKeyArn": (
            "arn:aws:kms:eu-west-2:111111111111:key/11111111-1111-4111-8111-111111111111"
        ),
        "operatorAccessMode": "ip-restricted",
        "operatorAllowedIpv4Cidrs": ["93.184.216.34/32"],
        "keyPolicyEvidenceRef": "SEC-KMS-1234",
        "residencyEvidenceRef": "LEGAL-RESIDENCY-1234",
        "deletionEvidenceRef": "PRIVACY-DELETION-1234",
        "conditionalAccessEvidenceRef": "ENTRA-CA-1234",
        "approvalEvidenceRef": "CHANGE-1234",
    }
    value.update(updates)
    return value


def test_data_boundary_manifest_is_exact_secret_free_and_network_safe() -> None:
    module = _load()
    manifest = module.DataBoundaryDeploymentManifest.parse(json.dumps(_data_boundary_manifest()))
    assert manifest.home_region == "eu-west-2"
    assert manifest.operator_allowed_ipv4_cidrs == ("93.184.216.34/32",)
    assert "operatorAllowedIpv4Cidrs" in manifest.canonical_json()
    assert manifest.deployment_environment()["DATA_BOUNDARY_OPERATOR_ACCESS_MODE"] == (
        "ip-restricted"
    )
    for unsafe in ("10.0.0.0/8", "127.0.0.1/32", "93.184.216.35/24"):
        with pytest.raises(module.DeploymentConfigurationError, match="IPv4 CIDRs"):
            module.DataBoundaryDeploymentManifest.parse(
                json.dumps(_data_boundary_manifest(operatorAllowedIpv4Cidrs=[unsafe]))
            )
    with pytest.raises(module.DeploymentConfigurationError, match="schema"):
        module.DataBoundaryDeploymentManifest.parse(
            json.dumps(_data_boundary_manifest(untrustedBrowserOverride=True))
        )
    duplicate = json.dumps(_data_boundary_manifest())[:-1] + ',"homeRegion":"eu-west-2"}'
    with pytest.raises(module.DeploymentConfigurationError, match="duplicate"):
        module.DataBoundaryDeploymentManifest.parse(duplicate)


def test_data_boundary_preflight_requires_exact_customer_key_and_rotation() -> None:
    module = _load()
    manifest = module.DataBoundaryDeploymentManifest.parse(json.dumps(_data_boundary_manifest()))

    def runner(command: list[str], **_: Any) -> Any:
        if "get-caller-identity" in command:
            return _completed(json.dumps({"Account": "111111111111"}))
        if "describe-key" in command:
            return _completed(
                json.dumps(
                    {
                        "KeyMetadata": {
                            "Arn": manifest.customer_managed_data_key_arn,
                            "AWSAccountId": "111111111111",
                            "KeyManager": "CUSTOMER",
                            "KeyState": "Enabled",
                            "Enabled": True,
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "KeySpec": "SYMMETRIC_DEFAULT",
                            "Origin": "AWS_KMS",
                        }
                    }
                )
            )
        if "get-key-rotation-status" in command:
            return _completed(json.dumps({"KeyRotationEnabled": True}))
        raise AssertionError(command)

    module.verify_data_boundary(
        manifest,
        profile="synthetic",
        region="eu-west-2",
        recovery=module.AuditRecoveryManifest.parse(json.dumps(_recovery_manifest())),
        runner=runner,
    )

    def no_rotation(command: list[str], **kwargs: Any) -> Any:
        response = runner(command, **kwargs)
        if "get-key-rotation-status" in command:
            return _completed(json.dumps({"KeyRotationEnabled": False}))
        return response

    with pytest.raises(module.DeploymentConfigurationError, match="rotation"):
        module.verify_data_boundary(
            manifest, profile="synthetic", region="eu-west-2", runner=no_rotation
        )
    with pytest.raises(module.DeploymentConfigurationError, match="homeRegion"):
        module.verify_data_boundary(
            manifest, profile="synthetic", region="eu-west-1", runner=runner
        )


def _completed(stdout: str = "{}", *, returncode: int = 0, stderr: str = "") -> Any:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class _Response:
    def __init__(
        self,
        value: dict[str, Any],
        resolved_url: str = (
            "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/"
            "v2.0/.well-known/openid-configuration"
        ),
    ) -> None:
        self.payload = json.dumps(value).encode()
        self.resolved_url = resolved_url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return self.payload

    def geturl(self) -> str:
        return self.resolved_url


def _metadata(tenant: str = "11111111-1111-4111-8111-111111111111") -> dict[str, str]:
    return {
        "issuer": f"https://login.microsoftonline.com/{tenant}/v2.0",
        "authorization_endpoint": (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        ),
        "token_endpoint": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "jwks_uri": f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
    }


def test_manifest_is_strict_canonical_and_never_contains_secret_values() -> None:
    module = _load()
    manifest = module.EntraDeploymentManifest.parse(json.dumps(_manifest()))
    assert manifest.entra_tenant_id == "11111111-1111-4111-8111-111111111111"
    assert json.loads(manifest.canonical_json()) == _manifest()
    assert manifest.deployment_environment() == {
        "ENTRA_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "ENTRA_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
        "ENTRA_CLIENT_SECRET_NAME": "aai-sec/entra/oidc-client-secret",
        "ENTRA_AAI_TENANT_ID": "tenant-enterprise-pilot",
        "ENTRA_SCIM_TOKEN_SECRET_NAME": "aai-sec/entra/scim-bearer",
        "ENTRA_STRONG_AUTH_ENFORCED": "true",
    }
    with pytest.raises(module.DeploymentConfigurationError, match="duplicate"):
        module.EntraDeploymentManifest.parse('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(module.DeploymentConfigurationError, match="strongAuthenticationEnforced"):
        module.EntraDeploymentManifest.parse(
            json.dumps(_manifest(strongAuthenticationEnforced=False))
        )
    with pytest.raises(module.DeploymentConfigurationError, match="separate secrets"):
        module.EntraDeploymentManifest.parse(
            json.dumps(_manifest(entraScimTokenSecretName="aai-sec/entra/oidc-client-secret"))
        )
    with pytest.raises(module.DeploymentConfigurationError, match="opaque non-secret"):
        module.EntraDeploymentManifest.parse(
            json.dumps(_manifest(conditionalAccessEvidenceRef="CAB 1234\nsecret"))
        )


def test_recovery_manifest_is_strict_canonical_and_bucket_scoped() -> None:
    module = _load()
    manifest = module.AuditRecoveryManifest.parse(json.dumps(_recovery_manifest()))
    assert manifest.replica_bucket_name == "synthetic-audit-replica"
    assert json.loads(manifest.canonical_json()) == _recovery_manifest()
    assert manifest.deployment_environment() == {
        "AUDIT_REPLICA_BUCKET_ARN": "arn:aws:s3:::synthetic-audit-replica",
        "AUDIT_REPLICA_REGION": "eu-west-1",
    }
    with pytest.raises(module.DeploymentConfigurationError, match="duplicate"):
        module.AuditRecoveryManifest.parse('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(module.DeploymentConfigurationError, match="exact S3 bucket ARN"):
        module.AuditRecoveryManifest.parse(
            json.dumps(_recovery_manifest(replicaBucketArn="arn:aws:s3:::bucket/prefix"))
        )
    with pytest.raises(module.DeploymentConfigurationError, match="replicaRegion"):
        module.AuditRecoveryManifest.parse(
            json.dumps(_recovery_manifest(replicaRegion="eu-west-1; unsafe"))
        )


def test_policy_github_manifest_is_strict_exact_and_secret_free() -> None:
    module = _load()
    manifest = module.PolicyGitHubDeploymentManifest.parse(json.dumps(_policy_github_manifest()))
    assert json.loads(manifest.canonical_json()) == _policy_github_manifest()
    assert manifest.deployment_environment() == {
        "POLICY_GITHUB_SECRET_NAME": "aai-sec/policy/github-app-installation",
        "POLICY_GITHUB_ALLOWED_REPOSITORIES": "github.com/example/security-policy",
    }
    with pytest.raises(module.DeploymentConfigurationError, match="unique exact"):
        module.PolicyGitHubDeploymentManifest.parse(
            json.dumps(
                _policy_github_manifest(
                    allowedRepositories=[
                        "github.com/example/security-policy",
                        "github.com/example/security-policy",
                    ]
                )
            )
        )
    with pytest.raises(module.DeploymentConfigurationError, match="unique exact"):
        module.PolicyGitHubDeploymentManifest.parse(
            json.dumps(_policy_github_manifest(allowedRepositories=["github.com/example/*"]))
        )
    with pytest.raises(module.DeploymentConfigurationError, match="opaque non-secret"):
        module.PolicyGitHubDeploymentManifest.parse(
            json.dumps(_policy_github_manifest(reviewEvidenceRef="secret review notes"))
        )


def test_policy_github_app_manifest_is_exact_and_single_installation() -> None:
    module = _load()
    value = _policy_github_app_manifest()
    manifest = module.PolicyGitHubDeploymentManifest.parse(json.dumps(value))
    assert json.loads(manifest.canonical_json()) == value
    assert manifest.deployment_environment() == {
        "POLICY_GITHUB_APP_SECRET_NAME": "aai-sec/policy/github-app-private-key",
        "POLICY_GITHUB_APP_CLIENT_ID": "Iv1.synthetic-client",
        "POLICY_GITHUB_INSTALLATION_ID": "12345678",
        "POLICY_GITHUB_ALLOWED_REPOSITORIES": "github.com/example/security-policy",
    }
    with pytest.raises(module.DeploymentConfigurationError, match="one installation owner"):
        module.PolicyGitHubDeploymentManifest.parse(
            json.dumps(
                _policy_github_app_manifest(
                    allowedRepositories=[
                        "github.com/example/security-policy",
                        "github.com/other/security-policy",
                    ]
                )
            )
        )


def test_oidc_discovery_requires_exact_tenant_bound_metadata() -> None:
    module = _load()
    tenant = "11111111-1111-4111-8111-111111111111"
    module.verify_oidc_metadata(tenant, opener=lambda *_args, **_kwargs: _Response(_metadata()))
    forged = _metadata()
    forged["issuer"] = "https://login.microsoftonline.com/common/v2.0"
    with pytest.raises(module.DeploymentConfigurationError, match="issuer"):
        module.verify_oidc_metadata(tenant, opener=lambda *_args, **_kwargs: _Response(forged))
    redirected = _metadata()
    redirected["token_endpoint"] = "https://attacker.invalid/token"  # noqa: S105
    with pytest.raises(module.DeploymentConfigurationError, match="not tenant-bound"):
        module.verify_oidc_metadata(tenant, opener=lambda *_args, **_kwargs: _Response(redirected))
    with pytest.raises(module.DeploymentConfigurationError, match="redirect is not allowed"):
        module.verify_oidc_metadata(
            tenant,
            opener=lambda *_args, **_kwargs: _Response(
                _metadata(), "https://attacker.invalid/discovery"
            ),
        )


def test_preflight_checks_secrets_existing_aai_tenant_and_never_prints_values() -> None:
    module = _load()
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        joined = " ".join(command)
        if "cloudformation describe-stacks" in joined:
            return _completed(
                json.dumps(
                    {
                        "Stacks": [
                            {
                                "Outputs": [
                                    {
                                        "OutputKey": "ControlTableName",
                                        "OutputValue": "synthetic-control-table",
                                    }
                                ]
                            }
                        ]
                    }
                )
            )
        if "aai-sec/entra/oidc-client-secret" in joined:
            return _completed(json.dumps({"SecretString": "synthetic-oidc-secret"}))
        if "aai-sec/entra/scim-bearer" in joined:
            return _completed(json.dumps({"SecretString": "s" * 40}))
        if "dynamodb get-item" in joined:
            return _completed(json.dumps({"Item": {"pk": {"S": "synthetic"}}}))
        raise AssertionError(command)

    manifest = module.EntraDeploymentManifest.parse(json.dumps(_manifest()))
    outputs = module.preflight(
        manifest,
        "AaiSecControlPlane",
        profile="synthetic",
        region="eu-west-2",
        runner=runner,
        opener=lambda *_args, **_kwargs: _Response(_metadata()),
    )
    assert outputs["ControlTableName"] == "synthetic-control-table"
    assert any("TENANT#tenant-enterprise-pilot" in item for call in calls for item in call)
    assert "synthetic-oidc-secret" not in repr(calls)
    assert "s" * 40 not in repr(calls)


def test_preflight_rejects_json_oidc_secret_and_control_character_bearer() -> None:
    module = _load()
    manifest = module.EntraDeploymentManifest.parse(json.dumps(_manifest()))

    def runner(command: list[str], **_: Any) -> Any:
        joined = " ".join(command)
        if "cloudformation describe-stacks" in joined:
            return _completed(
                json.dumps(
                    {
                        "Stacks": [
                            {
                                "Outputs": [
                                    {
                                        "OutputKey": "ControlTableName",
                                        "OutputValue": "synthetic-control-table",
                                    }
                                ]
                            }
                        ]
                    }
                )
            )
        if "aai-sec/entra/oidc-client-secret" in joined:
            return _completed(json.dumps({"SecretString": '{"clientSecret":"value"}'}))
        raise AssertionError(command)

    with pytest.raises(module.DeploymentConfigurationError, match="OIDC client secret"):
        module.preflight(
            manifest,
            "AaiSecControlPlane",
            profile="synthetic",
            region="eu-west-2",
            runner=runner,
            opener=lambda *_args, **_kwargs: _Response(_metadata()),
        )
    with pytest.raises(module.DeploymentConfigurationError, match="visible non-whitespace"):
        module._scim_token("a" * 32 + "\n" + "b" * 10)


def test_missing_or_malformed_persistent_configuration_fails_closed() -> None:
    module = _load()

    def missing(command: list[str], **_: Any) -> Any:
        assert "get-parameter" in command
        return _completed(returncode=254, stderr="ParameterNotFound")

    assert (
        module.load_persisted_manifest(
            "AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=missing
        )
        is None
    )

    def malformed(_command: list[str], **_: Any) -> Any:
        return _completed(json.dumps({"Parameter": {"Value": "{}"}}))

    with pytest.raises(module.DeploymentConfigurationError, match="fields"):
        module.load_persisted_manifest(
            "AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=malformed
        )

    assert (
        module.load_persisted_recovery_manifest(
            "AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=missing
        )
        is None
    )
    with pytest.raises(module.DeploymentConfigurationError, match="recovery manifest fields"):
        module.load_persisted_recovery_manifest(
            "AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=malformed
        )
    assert (
        module.load_persisted_policy_github_manifest(
            "AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=missing
        )
        is None
    )
    with pytest.raises(module.DeploymentConfigurationError, match="GitHub manifest fields"):
        module.load_persisted_policy_github_manifest(
            "AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=malformed
        )


def test_recovery_preflight_requires_distinct_versioned_compliance_destination() -> None:
    module = _load()
    manifest = module.AuditRecoveryManifest.parse(json.dumps(_recovery_manifest()))

    def runner(command: list[str], **_: Any) -> Any:
        if "get-bucket-versioning" in command:
            return _completed(json.dumps({"Status": "Enabled"}))
        if "get-object-lock-configuration" in command:
            return _completed(
                json.dumps(
                    {
                        "ObjectLockConfiguration": {
                            "ObjectLockEnabled": "Enabled",
                            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}},
                        }
                    }
                )
            )
        raise AssertionError(command)

    module.verify_recovery_destination(
        manifest, profile="synthetic", source_region="eu-west-2", runner=runner
    )
    with pytest.raises(module.DeploymentConfigurationError, match="must differ"):
        module.verify_recovery_destination(
            module.AuditRecoveryManifest.parse(
                json.dumps(_recovery_manifest(replicaRegion="eu-west-2"))
            ),
            profile="synthetic",
            source_region="eu-west-2",
            runner=runner,
        )

    def unlocked(command: list[str], **_: Any) -> Any:
        if "get-bucket-versioning" in command:
            return _completed(json.dumps({"Status": "Enabled"}))
        return _completed(
            json.dumps(
                {
                    "ObjectLockConfiguration": {
                        "ObjectLockEnabled": "Enabled",
                        "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 365}},
                    }
                }
            )
        )

    with pytest.raises(module.DeploymentConfigurationError, match="COMPLIANCE"):
        module.verify_recovery_destination(
            manifest, profile="synthetic", source_region="eu-west-2", runner=unlocked
        )


def test_first_deployment_may_start_without_an_entra_manifest() -> None:
    module = _load()

    def runner(command: list[str], **_: Any) -> Any:
        joined = " ".join(command)
        if "cloudformation describe-stacks" in joined:
            return _completed(
                returncode=255,
                stderr="ValidationError: Stack with id AaiSecControlPlane does not exist",
            )
        raise AssertionError(command)

    assert (
        module.stack_outputs(
            "AaiSecControlPlane",
            profile="synthetic",
            region="eu-west-2",
            runner=runner,
            allow_missing=True,
        )
        == {}
    )


def test_configured_stack_cannot_be_deployed_after_manifest_loss(monkeypatch: Any) -> None:
    module = _load()
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {"MicrosoftEntraIdStatus": "configured"},
    )
    with pytest.raises(module.DeploymentConfigurationError, match="manifest is missing"):
        module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2")


def test_configured_data_boundary_cannot_be_deployed_after_manifest_loss(
    monkeypatch: Any,
) -> None:
    module = _load()
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {"DataBoundaryStatus": "configured"},
    )
    calls: list[Any] = []
    with pytest.raises(module.DeploymentConfigurationError, match="data boundary.*missing"):
        module.deploy(
            "AaiSecControlPlane",
            profile="synthetic",
            region="eu-west-2",
            runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == []


def test_configured_replication_cannot_be_deployed_after_manifest_loss(monkeypatch: Any) -> None:
    module = _load()
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {
            "MicrosoftEntraIdStatus": "not-configured",
            "AuditReplicaBucketArn": "arn:aws:s3:::configured-replica",
        },
    )
    with pytest.raises(module.DeploymentConfigurationError, match="recovery manifest is missing"):
        module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2")


def test_rotated_signer_cannot_be_deployed_after_manifest_loss(monkeypatch: Any) -> None:
    module = _load()
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {"AssuranceReportSignerAuthorityStatus": "persisted-rotation"},
    )
    with pytest.raises(module.DeploymentConfigurationError, match="rotated assurance signer"):
        module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2")


def test_stale_signer_manifest_cannot_roll_back_outside_rotation(monkeypatch: Any) -> None:
    module = _load()
    deployed = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "1" * 32
    stale_current = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "2" * 32
    unrelated_history = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "3" * 32
    signer = module.AssuranceSignerDeploymentManifest(
        stale_current,
        (unrelated_history,),
        "eu-west-1",
        "change/STALE-1",
    )
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: signer
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {
            "AssuranceReportSignerAuthorityStatus": "persisted-rotation",
            "AssuranceReportSigningKeyArn": deployed,
            "AssuranceReportHistoricalVerificationKeyArns": "[]",
        },
    )
    with pytest.raises(module.DeploymentConfigurationError, match="outside rotation"):
        module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2")


@pytest.mark.parametrize(
    "deployed_history",
    (
        [],
        ["older-b", "older-a"],
        ["older-a", "substituted"],
        ["older-a"],
    ),
)
def test_stale_historical_signer_registry_fails_before_deploy(
    monkeypatch: Any, deployed_history: list[str]
) -> None:
    module = _load()
    current = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "1" * 32
    older_a = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "2" * 32
    older_b = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "3" * 32
    aliases = {"older-a": older_a, "older-b": older_b, "substituted": current}
    signer = module.AssuranceSignerDeploymentManifest(
        current,
        (older_a, older_b),
        "eu-west-1",
        "change/HISTORY-1",
    )
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: signer
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {
            "AssuranceReportSignerAuthorityStatus": "persisted-rotation",
            "AssuranceReportSigningKeyArn": current,
            "AssuranceReportHistoricalVerificationKeyArns": json.dumps(
                [aliases[value] for value in deployed_history]
            ),
        },
    )
    calls: list[Any] = []
    with pytest.raises(module.DeploymentConfigurationError, match="history differs"):
        module.deploy(
            "AaiSecControlPlane",
            profile="synthetic",
            region="eu-west-2",
            runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == []


def test_explicit_signer_cutover_accepts_exact_old_current_and_older_history(
    monkeypatch: Any,
) -> None:
    module = _load()
    old = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "1" * 32
    new = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "2" * 32
    older = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "3" * 32
    signer = module.AssuranceSignerDeploymentManifest(
        new,
        (old, older),
        "eu-west-1",
        "change/CUTOVER-1",
    )
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_policy_github_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_a, **_k: signer
    )
    monkeypatch.setattr(module, "load_persisted_data_boundary_manifest", lambda *_a, **_k: None)
    outputs = iter(
        [
            {
                "AssuranceReportSignerAuthorityStatus": "bootstrap",
                "AssuranceReportSigningKeyArn": old,
                "AssuranceReportHistoricalVerificationKeyArns": json.dumps([older]),
            },
            {
                "AssuranceReportSignerAuthorityStatus": "persisted-rotation",
                "AssuranceReportSigningKeyArn": new,
                "AssuranceReportHistoricalVerificationKeyArns": json.dumps(
                    [old, older], separators=(",", ":")
                ),
            },
        ]
    )
    monkeypatch.setattr(module, "stack_outputs", lambda *_a, **_k: next(outputs))
    commands: list[list[str]] = []

    def runner(command: list[str], **_kwargs: Any) -> Any:
        commands.append(command)
        return _completed()

    module.deploy(
        "AaiSecControlPlane",
        profile="synthetic",
        region="eu-west-2",
        allow_assurance_signer_transition=True,
        runner=runner,
    )
    assert len(commands) == 2


@pytest.mark.parametrize(
    "deployed_older_history",
    ([], ["older-b", "older-a"], ["older-a", "substituted"], ["older-a"]),
)
def test_explicit_cutover_rejects_changed_older_history_before_deploy(
    monkeypatch: Any, deployed_older_history: list[str]
) -> None:
    module = _load()
    old = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "1" * 32
    new = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "2" * 32
    older_a = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "3" * 32
    older_b = "arn:aws:kms:eu-west-2:111122223333:key/mrk-" + "4" * 32
    aliases = {"older-a": older_a, "older-b": older_b, "substituted": new}
    signer = module.AssuranceSignerDeploymentManifest(
        new,
        (old, older_a, older_b),
        "eu-west-1",
        "change/CUTOVER-2",
    )
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_policy_github_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_a, **_k: signer
    )
    monkeypatch.setattr(module, "load_persisted_data_boundary_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_a, **_k: {
            "AssuranceReportSignerAuthorityStatus": "persisted-rotation",
            "AssuranceReportSigningKeyArn": old,
            "AssuranceReportHistoricalVerificationKeyArns": json.dumps(
                [aliases[value] for value in deployed_older_history]
            ),
        },
    )
    calls: list[Any] = []
    with pytest.raises(module.DeploymentConfigurationError, match="history differs"):
        module.deploy(
            "AaiSecControlPlane",
            profile="synthetic",
            region="eu-west-2",
            allow_assurance_signer_transition=True,
            runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == []


def test_deploy_injects_only_manifest_references_and_verifies_posture(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.EntraDeploymentManifest.parse(json.dumps(_manifest()))
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: manifest)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    output_sequence = iter(
        [
            {"MicrosoftEntraIdStatus": "not-configured"},
            {
                "MicrosoftEntraIdStatus": "configured",
                "MicrosoftEntraScimStatus": "configured",
                "MicrosoftEntraScimEndpoint": "https://synthetic.example/scim/v2",
            },
        ]
    )
    monkeypatch.setattr(module, "stack_outputs", lambda *_args, **_kwargs: next(output_sequence))
    monkeypatch.setattr(module, "preflight", lambda *_args, **_kwargs: {})
    monkeypatch.setenv("ENTRA_TENANT_ID", "ambient-tenant-must-not-survive")
    monkeypatch.setenv("ENTRA_CLIENT_SECRET_NAME", "ambient-secret-must-not-survive")
    commands: list[tuple[list[str], dict[str, str]]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        commands.append((command, kwargs.get("env", {})))
        return _completed()

    assert (
        module.deploy(
            "AaiSecControlPlane",
            profile="synthetic",
            region="eu-west-2",
            runner=runner,
        )
        == manifest
    )
    assert [command for command, _ in commands] == [
        ["npm", "run", "build"],
        [
            "npx",
            "cdk",
            "deploy",
            "AaiSecControlPlane",
            "--require-approval",
            "never",
        ],
    ]
    deploy_environment = commands[-1][1]
    assert deploy_environment["ENTRA_CLIENT_SECRET_NAME"] == (
        "aai-sec/entra/oidc-client-secret"  # noqa: S105 - a reference, not a value
    )
    assert "synthetic-oidc-secret" not in repr(deploy_environment)
    assert "ambient-tenant-must-not-survive" not in repr(deploy_environment)
    assert "ambient-secret-must-not-survive" not in repr(deploy_environment)


def test_deploy_uses_only_persisted_recovery_authority(monkeypatch: Any) -> None:
    module = _load()
    recovery = module.AuditRecoveryManifest.parse(json.dumps(_recovery_manifest()))
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: recovery
    )
    monkeypatch.setattr(
        module, "load_persisted_policy_github_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    output_sequence = iter(
        [
            {"MicrosoftEntraIdStatus": "not-configured"},
            {
                "MicrosoftEntraIdStatus": "not-configured",
                "AuditReplicaBucketArn": recovery.replica_bucket_arn,
                "AuditReplicaRegion": recovery.replica_region,
                "AuditBatchReplicationRoleArn": "arn:aws:iam::111122223333:role/batch",
            },
        ]
    )
    monkeypatch.setattr(module, "stack_outputs", lambda *_args, **_kwargs: next(output_sequence))
    monkeypatch.setattr(module, "verify_recovery_destination", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("AUDIT_REPLICA_BUCKET_ARN", "arn:aws:s3:::ambient-unsafe")
    commands: list[tuple[list[str], dict[str, str]]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        commands.append((command, kwargs.get("env", {})))
        return _completed()

    module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=runner)
    environment = commands[-1][1]
    assert environment["AUDIT_REPLICA_BUCKET_ARN"] == recovery.replica_bucket_arn
    assert environment["AUDIT_REPLICA_REGION"] == recovery.replica_region
    assert "ambient-unsafe" not in repr(environment)


def test_persistence_requires_explicit_conditional_access_confirmation(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    module = _load()
    config = tmp_path / "entra.json"
    config.write_text(json.dumps(_manifest()), encoding="utf-8")
    monkeypatch.setattr(module, "preflight", lambda *_args, **_kwargs: {})
    persisted: list[Any] = []
    monkeypatch.setattr(
        module, "persist_manifest", lambda *args, **kwargs: persisted.append((args, kwargs))
    )
    assert module.main(["configure", "--config", str(config)]) == 1
    assert not persisted
    assert "--confirm-conditional-access is required" in capsys.readouterr().err
    assert (
        module.main(
            [
                "configure",
                "--config",
                str(config),
                "--confirm-conditional-access",
            ]
        )
        == 0
    )
    assert len(persisted) == 1


def test_data_boundary_persistence_requires_explicit_review_confirmation(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    module = _load()
    config = tmp_path / "data-boundary.json"
    config.write_text(json.dumps(_data_boundary_manifest()), encoding="utf-8")
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "verify_data_boundary", lambda *_args, **_kwargs: None)
    persisted: list[Any] = []
    monkeypatch.setattr(
        module,
        "persist_data_boundary_manifest",
        lambda *args, **kwargs: persisted.append((args, kwargs)),
    )

    assert module.main(["configure-data-boundary", "--config", str(config)]) == 1
    assert not persisted
    assert "--confirm-data-boundary-review is required" in capsys.readouterr().err

    assert (
        module.main(
            [
                "configure-data-boundary",
                "--config",
                str(config),
                "--confirm-data-boundary-review",
            ]
        )
        == 0
    )
    assert len(persisted) == 1


def test_recovery_persistence_requires_explicit_review_confirmation(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    module = _load()
    config = tmp_path / "recovery.json"
    config.write_text(json.dumps(_recovery_manifest()), encoding="utf-8")
    monkeypatch.setattr(module, "verify_recovery_destination", lambda *_args, **_kwargs: None)
    persisted: list[Any] = []
    monkeypatch.setattr(
        module,
        "persist_recovery_manifest",
        lambda *args, **kwargs: persisted.append((args, kwargs)),
    )
    assert module.main(["configure-recovery", "--config", str(config)]) == 1
    assert not persisted
    assert "--confirm-recovery-controls is required" in capsys.readouterr().err
    assert (
        module.main(
            [
                "configure-recovery",
                "--config",
                str(config),
                "--confirm-recovery-controls",
            ]
        )
        == 0
    )
    assert len(persisted) == 1


def test_scim_secret_json_is_exact_and_bounded() -> None:
    module = _load()
    token = "synthetic-scim-bearer-value-1234567890"  # noqa: S105
    assert module._scim_token(json.dumps({"token": token})) == token
    with pytest.raises(module.DeploymentConfigurationError, match="only token"):
        module._scim_token(json.dumps({"token": token, "extra": True}))
    with pytest.raises(module.DeploymentConfigurationError, match="32-512"):
        module._scim_token("short")


def test_policy_github_credential_is_exact_bounded_and_never_returned() -> None:
    module = _load()
    manifest = module.PolicyGitHubDeploymentManifest.parse(json.dumps(_policy_github_manifest()))
    token = "synthetic-github-installation-token"  # noqa: S105

    def valid(command: list[str], **_: Any) -> Any:
        assert "secretsmanager" in command
        return _completed(json.dumps({"SecretString": json.dumps({"token": token})}))

    assert (
        module.verify_policy_github_credential(
            manifest, profile="synthetic", region="eu-west-2", runner=valid
        )
        is None
    )

    def extra(_command: list[str], **_: Any) -> Any:
        return _completed(
            json.dumps({"SecretString": json.dumps({"token": token, "owner": "unsafe"})})
        )

    with pytest.raises(module.DeploymentConfigurationError, match="only token"):
        module.verify_policy_github_credential(
            manifest, profile="synthetic", region="eu-west-2", runner=extra
        )


def test_policy_github_app_private_key_is_rsa_and_secret_value_never_returned() -> None:
    module = _load()
    manifest = module.PolicyGitHubDeploymentManifest.parse(
        json.dumps(_policy_github_app_manifest())
    )

    def valid(_command: list[str], **_: Any) -> Any:
        return _completed(
            json.dumps({"SecretString": json.dumps({"privateKeyPem": SYNTHETIC_RSA_PRIVATE_KEY})})
        )

    assert (
        module.verify_policy_github_credential(
            manifest, profile="synthetic", region="eu-west-2", runner=valid
        )
        is None
    )

    def malformed(_command: list[str], **_: Any) -> Any:
        return _completed(
            json.dumps({"SecretString": json.dumps({"privateKeyPem": "must-not-escape"})})
        )

    with pytest.raises(module.DeploymentConfigurationError, match="malformed") as error:
        module.verify_policy_github_credential(
            manifest, profile="synthetic", region="eu-west-2", runner=malformed
        )
    assert "must-not-escape" not in str(error.value)


def test_deploy_uses_only_persisted_policy_github_authority(monkeypatch: Any) -> None:
    module = _load()
    policy_github = module.PolicyGitHubDeploymentManifest.parse(
        json.dumps(_policy_github_manifest())
    )
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module,
        "load_persisted_policy_github_manifest",
        lambda *_args, **_kwargs: policy_github,
    )
    monkeypatch.setattr(
        module, "load_persisted_assurance_signer_manifest", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        module, "load_persisted_data_boundary_manifest", lambda *_args, **_kwargs: None
    )
    output_sequence = iter(
        [
            {"PolicyGitHubSourceStatus": "not-configured"},
            {"PolicyGitHubSourceStatus": "configured"},
        ]
    )
    monkeypatch.setattr(module, "stack_outputs", lambda *_args, **_kwargs: next(output_sequence))
    monkeypatch.setattr(module, "verify_policy_github_credential", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("POLICY_GITHUB_SECRET_NAME", "ambient-unsafe-secret")
    monkeypatch.setenv("POLICY_GITHUB_ALLOWED_REPOSITORIES", "github.com/attacker/unsafe")
    commands: list[tuple[list[str], dict[str, str]]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        commands.append((command, kwargs.get("env", {})))
        return _completed()

    module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=runner)
    environment = commands[-1][1]
    assert environment["POLICY_GITHUB_SECRET_NAME"] == policy_github.credential_secret_name
    assert environment["POLICY_GITHUB_ALLOWED_REPOSITORIES"] == (
        "github.com/example/security-policy"
    )
    assert "ambient-unsafe" not in repr(environment)


def test_deploy_uses_only_persisted_data_boundary_authority(monkeypatch: Any) -> None:
    module = _load()
    boundary = module.DataBoundaryDeploymentManifest.parse(json.dumps(_data_boundary_manifest()))
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_recovery_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_policy_github_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_assurance_signer_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "load_persisted_data_boundary_manifest", lambda *_a, **_k: boundary)
    outputs = iter(
        [
            {"DataBoundaryStatus": "not-configured"},
            {
                "DataBoundaryStatus": "configured",
                "DataBoundaryHomeRegion": boundary.home_region,
                "DataBoundaryApprovedRegions": json.dumps(
                    boundary.approved_data_regions, separators=(",", ":")
                ),
                "DataBoundaryKeyArn": boundary.customer_managed_data_key_arn,
                "DataBoundaryOperatorAccessMode": "ip-restricted",
            },
        ]
    )
    monkeypatch.setattr(module, "stack_outputs", lambda *_a, **_k: next(outputs))
    monkeypatch.setattr(module, "verify_data_boundary", lambda *_a, **_k: None)
    monkeypatch.setenv("DATA_BOUNDARY_KMS_KEY_ARN", "arn:aws:kms:attacker")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_IPV4_CIDRS", "0.0.0.0/0")
    commands: list[tuple[list[str], dict[str, str]]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        commands.append((command, kwargs.get("env", {})))
        return _completed()

    module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2", runner=runner)
    environment = commands[-1][1]
    assert environment["DATA_BOUNDARY_KMS_KEY_ARN"] == (boundary.customer_managed_data_key_arn)
    assert environment["DATA_BOUNDARY_OPERATOR_IPV4_CIDRS"] == '["93.184.216.34/32"]'
    assert "attacker" not in repr(environment)
    assert "0.0.0.0/0" not in repr(environment)


def test_policy_github_persistence_requires_explicit_review_confirmation(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    module = _load()
    config = tmp_path / "policy-github.json"
    config.write_text(json.dumps(_policy_github_manifest()), encoding="utf-8")
    monkeypatch.setattr(module, "verify_policy_github_credential", lambda *_args, **_kwargs: None)
    persisted: list[Any] = []
    monkeypatch.setattr(
        module,
        "persist_policy_github_manifest",
        lambda *args, **kwargs: persisted.append((args, kwargs)),
    )
    assert module.main(["configure-policy-github", "--config", str(config)]) == 1
    assert not persisted
    assert "--confirm-policy-github-review is required" in capsys.readouterr().err
    assert (
        module.main(
            [
                "configure-policy-github",
                "--config",
                str(config),
                "--confirm-policy-github-review",
            ]
        )
        == 0
    )
    assert len(persisted) == 1

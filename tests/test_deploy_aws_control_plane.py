"""Contracts for persistent, fail-closed AWS Entra deployment."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


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
    monkeypatch.setattr(
        module,
        "stack_outputs",
        lambda *_args, **_kwargs: {"MicrosoftEntraIdStatus": "configured"},
    )
    with pytest.raises(module.DeploymentConfigurationError, match="manifest is missing"):
        module.deploy("AaiSecControlPlane", profile="synthetic", region="eu-west-2")


def test_deploy_injects_only_manifest_references_and_verifies_posture(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.EntraDeploymentManifest.parse(json.dumps(_manifest()))
    monkeypatch.setattr(module, "load_persisted_manifest", lambda *_args, **_kwargs: manifest)
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


def test_scim_secret_json_is_exact_and_bounded() -> None:
    module = _load()
    token = "synthetic-scim-bearer-value-1234567890"  # noqa: S105
    assert module._scim_token(json.dumps({"token": token})) == token
    with pytest.raises(module.DeploymentConfigurationError, match="only token"):
        module._scim_token(json.dumps({"token": token, "extra": True}))
    with pytest.raises(module.DeploymentConfigurationError, match="32-512"):
        module._scim_token("short")

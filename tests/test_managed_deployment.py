"""Adversarial contracts for digest-bound managed endpoint packages."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import replace
from typing import Any, cast

import pytest

import agentic_security.managed_deployment as managed_deployment
from agentic_security import (
    AgentHost,
    ManagedArtifact,
    ManagedConfigurationCompiler,
    ManagedConfigurationSource,
    ManagedDeploymentPackage,
    ManagedExecutableRequirement,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
    PolicyTrustStore,
    SecurityConfigurationError,
    TrustedPolicyKey,
)

_SYNTHETIC_P256_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9AednGdWX5tOVVBzU4graM3pMoB7
1zN9CeMI3CdIylAEaD5uETFZniRiQmvKmYClaOEdOrDhpXqNTe7q+cLtCw==
-----END PUBLIC KEY-----
"""


def _trust_store() -> PolicyTrustStore:
    """Return one synthetic deployment-pinned signing authority."""
    return PolicyTrustStore(
        (
            TrustedPolicyKey(
                "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc",
                _SYNTHETIC_P256_PUBLIC_PEM,
            ),
        )
    )


def _package(
    *,
    host: AgentHost = AgentHost.CLAUDE_CODE,
    platform: ManagedPlatform = ManagedPlatform.LINUX,
    policy_version: int = 1,
    with_trust: bool = False,
) -> ManagedDeploymentPackage:
    hook_path = (
        r"C:\Program Files\AAI Security\hooks\native-policy.exe"
        if platform is ManagedPlatform.WINDOWS
        else "/opt/aai-security/hooks/native-policy"
    )
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent(
            "policy-safe",
            policy_version,
            action_rules=(
                NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),
                NativeActionRule("Bash(rm *)", NativeActionDecision.DENY, "synthetic deny"),
            ),
        ),
        host=host,
        host_version="2.1.220" if host is AgentHost.CLAUDE_CODE else "0.146.0",
        platform=platform,
        hook_command=hook_path,
    )
    return ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(
            ManagedExecutableRequirement(hook_path, hashlib.sha256(b"synthetic hook").hexdigest()),
        ),
        policy_trust_store=_trust_store() if with_trust else None,
    )


def test_package_is_canonical_digest_bound_and_target_bound() -> None:
    package = _package()
    encoded = package.to_json()
    parsed = ManagedDeploymentPackage.from_json(
        encoded, expected_package_sha256=package.package_sha256
    )
    assert parsed == package
    parsed.require_target(
        host=AgentHost.CLAUDE_CODE,
        platform=ManagedPlatform.LINUX,
        bundle_hash=package.bundle_hash,
    )
    assert parsed.to_wire()["requiredExecutables"] == [
        {
            "path": "/opt/aai-security/hooks/native-policy",
            "sha256": hashlib.sha256(b"synthetic hook").hexdigest(),
        }
    ]


def test_schema_v2_binds_canonical_policy_trust_and_requires_out_of_band_digest() -> None:
    package = _package(with_trust=True)
    assert package.to_wire()["schemaVersion"] == 2
    assert package.policy_trust is not None
    assert package.policy_trust.path == "/opt/aai-security/trust/policy-signing.json"
    parsed = ManagedDeploymentPackage.from_json(
        package.to_json(), expected_package_sha256=package.package_sha256
    )
    parsed.require_target(
        host=AgentHost.CLAUDE_CODE,
        platform=ManagedPlatform.LINUX,
        bundle_hash=package.bundle_hash,
        policy_trust_bundle_sha256=package.policy_trust_bundle_sha256,
    )
    with pytest.raises(SecurityConfigurationError, match="trust is not desired"):
        parsed.require_target(
            host=AgentHost.CLAUDE_CODE,
            platform=ManagedPlatform.LINUX,
            bundle_hash=package.bundle_hash,
        )
    with pytest.raises(SecurityConfigurationError, match="trust is not desired"):
        parsed.require_target(
            host=AgentHost.CLAUDE_CODE,
            platform=ManagedPlatform.LINUX,
            bundle_hash=package.bundle_hash,
            policy_trust_bundle_sha256="f" * 64,
        )


@pytest.mark.parametrize("field", ["path", "content", "sha256"])
def test_schema_v2_rejects_policy_trust_tampering(field: str) -> None:
    package = _package(with_trust=True)
    value = cast(dict[str, Any], json.loads(package.to_json()))
    trust = cast(dict[str, Any], value["policyTrust"])
    trust[field] = {
        "path": "/untrusted/policy-signing.json",
        "content": "{}",
        "sha256": "f" * 64,
    }[field]
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(SecurityConfigurationError, match="policy trust"):
        ManagedDeploymentPackage.from_json(
            encoded, expected_package_sha256=hashlib.sha256(encoded).hexdigest()
        )


def test_schema_v2_measurement_reports_exact_trust_digest(monkeypatch: Any) -> None:
    package = _package(platform=ManagedPlatform.MACOS, with_trust=True)
    measured: list[str] = []
    monkeypatch.setattr(
        "agentic_security.managed_deployment.host_platform.system", lambda: "Darwin"
    )
    monkeypatch.setattr(
        managed_deployment,
        "_measure_artifact",
        lambda artifact, *, owner_uid: measured.append(f"{owner_uid}:{artifact.path}"),
    )
    evidence = managed_deployment.measure_managed_deployment_package(
        package,
        source=ManagedConfigurationSource.MDM,
        now=100.0,
    )
    assert len(measured) == len(package.artifacts) + 1
    assert all(item.startswith("0:") for item in measured)
    assert evidence.policy_trust_bundle_sha256 == package.policy_trust_bundle_sha256
    assert evidence.to_wire()["policyTrustBundleSha256"] == package.policy_trust_bundle_sha256
    with pytest.raises(SecurityConfigurationError, match="schema-v2"):
        managed_deployment.measure_managed_deployment_package(
            _package(platform=ManagedPlatform.MACOS),
            source=ManagedConfigurationSource.MDM,
            now=100.0,
        )


def test_artifact_measurement_rejects_unprotected_drifted_and_missing_files(
    tmp_path: Any,
) -> None:
    """Exercise the filesystem trust boundary used by endpoint heartbeats."""
    path = tmp_path / "policy-signing.json"
    content = '{"schemaVersion":1}'
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    artifact = ManagedArtifact(
        str(path),
        "application/json",
        content,
        hashlib.sha256(content.encode()).hexdigest(),
    )

    managed_deployment._measure_artifact(artifact, owner_uid=os.getuid())

    path.chmod(0o666)
    with pytest.raises(SecurityConfigurationError, match="not protected"):
        managed_deployment._measure_artifact(artifact, owner_uid=os.getuid())

    path.chmod(0o600)
    path.write_text("tampered", encoding="utf-8")
    with pytest.raises(SecurityConfigurationError, match="drifted"):
        managed_deployment._measure_artifact(artifact, owner_uid=os.getuid())

    path.unlink()
    with pytest.raises(SecurityConfigurationError, match="cannot be measured"):
        managed_deployment._measure_artifact(artifact, owner_uid=os.getuid())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"schemaVersion": 2}),
        lambda value: value["artifacts"].pop(),
        lambda value: value["artifacts"][0].update({"path": "/untrusted/managed-settings.json"}),
        lambda value: value["artifacts"][0].update({"content": "tampered"}),
        lambda value: value["requiredExecutables"][0].update({"path": "/untrusted/hook"}),
    ],
)
def test_package_rejects_schema_path_and_content_tampering(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    package = _package()
    value = json.loads(package.to_json())
    mutation(value)
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(SecurityConfigurationError):
        ManagedDeploymentPackage.from_json(
            encoded, expected_package_sha256=hashlib.sha256(encoded).hexdigest()
        )


def test_package_rejects_wrong_digest_duplicates_and_noncanonical_bytes() -> None:
    package = _package()
    with pytest.raises(SecurityConfigurationError, match="does not match"):
        ManagedDeploymentPackage.from_json(package.to_json(), expected_package_sha256="f" * 64)
    duplicate = package.to_json().replace(
        b'{"artifacts":', b'{"host":"claude-code","artifacts":', 1
    )
    with pytest.raises(SecurityConfigurationError, match="duplicate"):
        ManagedDeploymentPackage.from_json(
            duplicate, expected_package_sha256=hashlib.sha256(duplicate).hexdigest()
        )
    noncanonical = json.dumps(package.to_wire(), indent=2, sort_keys=True).encode()
    with pytest.raises(SecurityConfigurationError, match="not canonical"):
        ManagedDeploymentPackage.from_json(
            noncanonical, expected_package_sha256=hashlib.sha256(noncanonical).hexdigest()
        )


def test_package_rejects_cross_target_and_stale_bundle() -> None:
    package = _package()
    with pytest.raises(SecurityConfigurationError, match="another host"):
        package.require_target(
            host=AgentHost.CODEX_CLI,
            platform=ManagedPlatform.LINUX,
            bundle_hash=package.bundle_hash,
        )
    with pytest.raises(SecurityConfigurationError, match="not desired"):
        package.require_target(
            host=AgentHost.CLAUDE_CODE,
            platform=ManagedPlatform.LINUX,
            bundle_hash="f" * 64,
        )


def test_package_rejects_unsafe_executable_and_artifact_objects() -> None:
    with pytest.raises(SecurityConfigurationError, match="bounded non-empty"):
        ManagedExecutableRequirement("", "a" * 64)
    with pytest.raises(SecurityConfigurationError, match="must be SHA-256"):
        ManagedExecutableRequirement("/opt/aai-security/hook", "invalid")
    with pytest.raises(SecurityConfigurationError, match="administrator-owned"):
        ManagedExecutableRequirement("/opt/aai-security/../unsafe", "a" * 64)
    package = _package()
    artifact = package.artifacts[0]
    changed = ManagedArtifact(artifact.path, artifact.media_type, artifact.content, "f" * 64)
    with pytest.raises(SecurityConfigurationError, match="artifact digest"):
        replace(package, artifacts=(changed, *package.artifacts[1:]))
    with pytest.raises(SecurityConfigurationError, match="artifacts must be typed"):
        replace(package, artifacts=cast(Any, list(package.artifacts)))
    with pytest.raises(SecurityConfigurationError, match="host is unsupported"):
        replace(package, host=cast(AgentHost, "claude-code"))


def test_package_rejects_invalid_typed_fields_and_incomplete_requirements() -> None:
    package = _package()
    with pytest.raises(SecurityConfigurationError, match="platform must be typed"):
        replace(package, platform=cast(ManagedPlatform, "linux"))
    with pytest.raises(SecurityConfigurationError, match="host version is invalid"):
        replace(package, host_version="latest")
    with pytest.raises(SecurityConfigurationError, match="policy ID is invalid"):
        replace(package, policy_id="invalid policy")
    with pytest.raises(SecurityConfigurationError, match="policy version must be positive"):
        replace(package, policy_version=cast(int, True))
    with pytest.raises(SecurityConfigurationError, match="bundle hash must be SHA-256"):
        replace(package, bundle_hash="invalid")
    with pytest.raises(SecurityConfigurationError, match="artifacts must be typed"):
        replace(package, artifacts=())
    with pytest.raises(SecurityConfigurationError, match="one to eight typed executables"):
        replace(package, required_executables=())

    artifact = package.artifacts[0]
    wrong_media = ManagedArtifact(artifact.path, "text/plain", artifact.content, artifact.sha256)
    with pytest.raises(SecurityConfigurationError, match="media type is invalid"):
        replace(package, artifacts=(wrong_media, *package.artifacts[1:]))
    oversized_content = "x" * 1_100_000
    oversized = ManagedArtifact(
        artifact.path,
        artifact.media_type,
        oversized_content,
        hashlib.sha256(oversized_content.encode()).hexdigest(),
    )
    with pytest.raises(SecurityConfigurationError, match="exceeds safe size"):
        replace(package, artifacts=(oversized, *package.artifacts[1:]))

    requirement = package.required_executables[0]
    with pytest.raises(SecurityConfigurationError, match="paths must be unique"):
        replace(package, required_executables=(requirement, requirement))
    windows_requirement = ManagedExecutableRequirement(
        r"C:\Program Files\AAI Security\hooks\native-policy.exe", "a" * 64
    )
    with pytest.raises(SecurityConfigurationError, match="platform does not match"):
        replace(package, required_executables=(windows_requirement,))


def test_package_rejects_untyped_bundle_and_target() -> None:
    package = _package()
    with pytest.raises(SecurityConfigurationError, match="requires a compiled bundle"):
        ManagedDeploymentPackage.from_bundle(
            cast(Any, object()), required_executables=package.required_executables
        )
    with pytest.raises(SecurityConfigurationError, match="target must be typed"):
        package.require_target(
            host=cast(AgentHost, "claude-code"),
            platform=ManagedPlatform.LINUX,
            bundle_hash=package.bundle_hash,
        )


def test_package_rejects_empty_malformed_and_invalid_wire_values() -> None:
    package = _package()
    with pytest.raises(SecurityConfigurationError, match="exceeds safe size"):
        ManagedDeploymentPackage.from_json(b"", expected_package_sha256="a" * 64)
    malformed = b"{not-json"
    with pytest.raises(SecurityConfigurationError, match="is malformed"):
        ManagedDeploymentPackage.from_json(
            malformed, expected_package_sha256=hashlib.sha256(malformed).hexdigest()
        )

    def rejected(mutator: Callable[[dict[str, Any]], None], message: str) -> None:
        value = cast(dict[str, Any], json.loads(package.to_json()))
        mutator(value)
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        with pytest.raises(SecurityConfigurationError, match=message):
            ManagedDeploymentPackage.from_json(
                encoded, expected_package_sha256=hashlib.sha256(encoded).hexdigest()
            )

    rejected(lambda value: value.update(host="unknown"), "target is invalid")
    rejected(lambda value: value.update(policyVersion=True), "policy version must be positive")
    rejected(lambda value: value.update(artifacts={}), "package lists are invalid")
    rejected(lambda value: value["artifacts"][0].pop("sha256"), "artifact schema is invalid")
    rejected(
        lambda value: value["requiredExecutables"][0].pop("sha256"),
        "executable schema is invalid",
    )


def test_windows_and_codex_packages_use_exact_documented_targets() -> None:
    windows = _package(platform=ManagedPlatform.WINDOWS)
    assert tuple(item.path for item in windows.artifacts) == (
        r"C:\Program Files\ClaudeCode/managed-settings.json",
        r"C:\Program Files\ClaudeCode/managed-mcp.json",
    )
    codex = _package(host=AgentHost.CODEX_CLI)
    assert tuple(item.path for item in codex.artifacts) == ("/etc/codex/requirements.toml",)

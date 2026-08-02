"""Contracts for offline managed-package signing-trust migration."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from agentic_security import (
    AgentHost,
    ManagedConfigurationCompiler,
    ManagedDeploymentPackage,
    ManagedExecutableRequirement,
    ManagedPlatform,
    ManagedPolicyIntent,
    PolicyTrustStore,
    TrustedPolicyKey,
)

_SYNTHETIC_P256_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9AednGdWX5tOVVBzU4graM3pMoB7
1zN9CeMI3CdIylAEaD5uETFZniRiQmvKmYClaOEdOrDhpXqNTe7q+cLtCw==
-----END PUBLIC KEY-----
"""


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "upgrade_managed_package_trust.py"
    spec = importlib.util.spec_from_file_location("aai_upgrade_managed_package_trust", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _inputs(tmp_path: Path) -> tuple[Path, ManagedDeploymentPackage, Path, str]:
    hook_path = "/opt/aai-security/hooks/native-policy"
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent("policy-safe", 1),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=ManagedPlatform.LINUX,
        hook_command=hook_path,
    )
    package = ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(ManagedExecutableRequirement(hook_path, "a" * 64),),
    )
    package_path = tmp_path / "package-v1.json"
    package_path.write_bytes(package.to_json())
    package_path.chmod(0o600)
    trust = PolicyTrustStore(
        (
            TrustedPolicyKey(
                "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc",
                _SYNTHETIC_P256_PUBLIC_PEM,
            ),
        )
    ).to_json()
    trust_path = tmp_path / "policy-trust.json"
    trust_path.write_text(trust)
    trust_path.chmod(0o600)
    return package_path, package, trust_path, hashlib.sha256(trust.encode()).hexdigest()


def test_upgrade_creates_new_restrictive_digest_bound_v2_package(tmp_path: Path) -> None:
    module = _load()
    package_path, package, trust_path, trust_digest = _inputs(tmp_path)
    output = tmp_path / "package-v2.json"
    upgraded = module.upgrade_package(
        package_path=package_path,
        expected_package_sha256=package.package_sha256,
        trust_path=trust_path,
        expected_trust_sha256=trust_digest,
        output=output,
    )
    assert upgraded.to_wire()["schemaVersion"] == 2
    assert upgraded.policy_trust_bundle_sha256 == trust_digest
    assert output.stat().st_mode & 0o777 == 0o600
    assert package_path.read_bytes() == package.to_json()


def test_upgrade_rejects_wrong_digest_unsafe_input_and_overwrite(tmp_path: Path) -> None:
    module = _load()
    package_path, package, trust_path, trust_digest = _inputs(tmp_path)
    output = tmp_path / "package-v2.json"
    with pytest.raises(module.ManagedTrustUpgradeError, match="trust digest"):
        module.upgrade_package(
            package_path=package_path,
            expected_package_sha256=package.package_sha256,
            trust_path=trust_path,
            expected_trust_sha256="f" * 64,
            output=output,
        )
    link = tmp_path / "trust-link.json"
    link.symlink_to(trust_path)
    with pytest.raises(module.ManagedTrustUpgradeError, match="path is unsafe"):
        module.upgrade_package(
            package_path=package_path,
            expected_package_sha256=package.package_sha256,
            trust_path=link,
            expected_trust_sha256=trust_digest,
            output=output,
        )
    output.write_text("existing")
    os.chmod(output, 0o600)
    with pytest.raises(module.ManagedTrustUpgradeError, match="new absolute"):
        module.upgrade_package(
            package_path=package_path,
            expected_package_sha256=package.package_sha256,
            trust_path=trust_path,
            expected_trust_sha256=trust_digest,
            output=output,
        )

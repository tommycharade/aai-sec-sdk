"""Filesystem acceptance tests for the optional privileged endpoint installer."""

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
    NativeActionDecision,
    NativeActionRule,
)


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "install_managed_host_package.py"
    spec = importlib.util.spec_from_file_location("aai_managed_endpoint_installer", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _package(version: int, hook: bytes) -> ManagedDeploymentPackage:
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent(
            "policy-safe",
            version,
            action_rules=(NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),),
        ),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/native-policy",
    )
    return ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(
            ManagedExecutableRequirement(
                "/opt/aai-security/hooks/native-policy", hashlib.sha256(hook).hexdigest()
            ),
        ),
    )


def _endpoint(tmp_path: Path, hook: bytes) -> tuple[Path, Any, int]:
    root = tmp_path / "image"
    hook_path = root / "opt/aai-security/hooks/native-policy"
    hook_path.parent.mkdir(parents=True, mode=0o755)
    hook_path.write_bytes(hook)
    hook_path.chmod(0o755)
    (root / "etc").mkdir(mode=0o755)
    uid = os.getuid()
    return root, lambda path: root / path.lstrip("/"), uid


def test_preflight_and_install_write_exact_restrictive_files(tmp_path: Path) -> None:
    module = _load()
    hook = b"synthetic executable"
    package = _package(1, hook)
    root, mapper, uid = _endpoint(tmp_path, hook)
    ready = module.preflight_package(
        package,
        expected_host=AgentHost.CLAUDE_CODE,
        expected_platform=ManagedPlatform.LINUX,
        expected_bundle_hash=package.bundle_hash,
        path_mapper=mapper,
        owner_uid=uid,
    )
    assert ready.status == "ready"
    installed = module.install_package(
        package,
        expected_host=AgentHost.CLAUDE_CODE,
        expected_platform=ManagedPlatform.LINUX,
        expected_bundle_hash=package.bundle_hash,
        path_mapper=mapper,
        owner_uid=uid,
        effective_uid=uid,
    )
    assert installed.status == "installed"
    for artifact in package.artifacts:
        target = mapper(artifact.path)
        assert target.read_text() == artifact.content
        assert target.stat().st_mode & 0o777 == 0o644
        assert target.stat().st_uid == uid
    assert not list(root.rglob("*.aai-stage-*"))
    assert not list(root.rglob("*.aai-backup-*"))


def test_install_rejects_non_admin_tampered_hook_and_symlink_target(tmp_path: Path) -> None:
    module = _load()
    hook = b"synthetic executable"
    package = _package(1, hook)
    _root, mapper, uid = _endpoint(tmp_path, hook)
    with pytest.raises(module.ManagedEndpointInstallError, match="requires administrator"):
        module.install_package(
            package,
            expected_host=AgentHost.CLAUDE_CODE,
            expected_platform=ManagedPlatform.LINUX,
            expected_bundle_hash=package.bundle_hash,
            path_mapper=mapper,
            owner_uid=uid,
            effective_uid=uid + 1,
        )
    mapper("/opt/aai-security/hooks/native-policy").write_bytes(b"tampered")
    with pytest.raises(module.ManagedEndpointInstallError, match="does not match"):
        module.preflight_package(
            package,
            expected_host=AgentHost.CLAUDE_CODE,
            expected_platform=ManagedPlatform.LINUX,
            expected_bundle_hash=package.bundle_hash,
            path_mapper=mapper,
            owner_uid=uid,
        )
    mapper("/opt/aai-security/hooks/native-policy").write_bytes(hook)
    target = mapper(package.artifacts[0].path)
    target.parent.mkdir(mode=0o755)
    target.symlink_to(tmp_path / "outside")
    with pytest.raises(module.ManagedEndpointInstallError, match="target ownership or mode"):
        module.preflight_package(
            package,
            expected_host=AgentHost.CLAUDE_CODE,
            expected_platform=ManagedPlatform.LINUX,
            expected_bundle_hash=package.bundle_hash,
            path_mapper=mapper,
            owner_uid=uid,
        )


def test_preflight_rejects_intermediate_executable_directory_symlink(tmp_path: Path) -> None:
    module = _load()
    hook = b"synthetic executable"
    package = _package(1, hook)
    root = tmp_path / "image"
    outside = tmp_path / "outside"
    (outside / "aai-security/hooks").mkdir(parents=True)
    executable = outside / "aai-security/hooks/native-policy"
    executable.write_bytes(hook)
    executable.chmod(0o755)
    root.mkdir()
    (root / "etc").mkdir()
    (root / "opt").symlink_to(outside, target_is_directory=True)
    uid = os.getuid()

    def mapper(path: str) -> Path:
        return root / path.lstrip("/")

    with pytest.raises(module.ManagedEndpointInstallError, match="directory ownership or mode"):
        module.preflight_package(
            package,
            expected_host=AgentHost.CLAUDE_CODE,
            expected_platform=ManagedPlatform.LINUX,
            expected_bundle_hash=package.bundle_hash,
            path_mapper=mapper,
            owner_uid=uid,
        )


def test_partial_replacement_failure_restores_every_previous_file(tmp_path: Path) -> None:
    module = _load()
    hook = b"synthetic executable"
    original = _package(1, hook)
    _root, mapper, uid = _endpoint(tmp_path, hook)
    module.install_package(
        original,
        expected_host=AgentHost.CLAUDE_CODE,
        expected_platform=ManagedPlatform.LINUX,
        expected_bundle_hash=original.bundle_hash,
        path_mapper=mapper,
        owner_uid=uid,
        effective_uid=uid,
    )
    before = {artifact.path: mapper(artifact.path).read_bytes() for artifact in original.artifacts}
    replacement = _package(2, hook)
    calls = 0

    def fail_fourth(source: Any, destination: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("synthetic replacement failure")
        os.replace(source, destination)

    with pytest.raises(module.ManagedEndpointInstallError, match="rolled back"):
        module.install_package(
            replacement,
            expected_host=AgentHost.CLAUDE_CODE,
            expected_platform=ManagedPlatform.LINUX,
            expected_bundle_hash=replacement.bundle_hash,
            path_mapper=mapper,
            owner_uid=uid,
            effective_uid=uid,
            replace=fail_fourth,
        )
    assert {path: mapper(path).read_bytes() for path in before} == before

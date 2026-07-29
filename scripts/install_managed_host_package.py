#!/usr/bin/env python3
"""Preflight or install a digest-pinned Claude/Codex managed-host package.

The package is untrusted until its exact SHA-256, desired bundle hash, host and
platform match values delivered through endpoint management.  Installation is
offline, requires root, verifies administrator-owned executable prerequisites,
uses restrictive regular files, and rolls back every replaced target if a
later replacement fails. Windows is refused until an ACL-aware adapter exists.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform as host_platform
import stat
import sys
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# Bind direct-checkout execution to the reviewed source beside this installer.
_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from agentic_security import (  # noqa: E402
    AgentHost,
    ManagedDeploymentPackage,
    ManagedPlatform,
    SecurityConfigurationError,
)

_MAX_PACKAGE_BYTES = 3_000_000
_MAX_EXECUTABLE_BYTES = 64_000_000
PathMapper = Callable[[str], Path]
Replace = Callable[
    [
        str | bytes | os.PathLike[str] | os.PathLike[bytes],
        str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ],
    None,
]


class ManagedEndpointInstallError(RuntimeError):
    """Raised when endpoint package validation or installation fails closed."""


@dataclass(frozen=True, slots=True)
class EndpointInstallResult:
    """Content-minimised result for one check or completed installation."""

    status: str
    host: str
    platform: str
    policy_id: str
    policy_version: int
    bundle_hash: str
    package_sha256: str
    artifact_count: int
    executable_count: int


def _identity(path: str) -> Path:
    """Map one package path to the live endpoint path."""
    return Path(path)


def _read_regular(path: Path, maximum: int, label: str) -> tuple[bytes, os.stat_result]:
    """Read one bounded regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ManagedEndpointInstallError(f"{label} must be a regular file")
            if metadata.st_size > maximum:
                raise ManagedEndpointInstallError(f"{label} exceeds the safe size bound")
            encoded = stream.read(maximum + 1)
    except OSError as error:
        raise ManagedEndpointInstallError(f"{label} cannot be read safely") from error
    if len(encoded) > maximum:
        raise ManagedEndpointInstallError(f"{label} exceeds the safe size bound")
    return encoded, metadata


def load_package(path: Path, *, expected_package_sha256: str) -> ManagedDeploymentPackage:
    """Load one no-follow package and verify its out-of-band digest and schema."""
    encoded, _ = _read_regular(path, _MAX_PACKAGE_BYTES, "managed deployment package")
    try:
        return ManagedDeploymentPackage.from_json(
            encoded, expected_package_sha256=expected_package_sha256
        )
    except SecurityConfigurationError as error:
        raise ManagedEndpointInstallError("managed deployment package validation failed") from error


def _expected_platform() -> ManagedPlatform:
    """Return the implemented local platform or fail closed."""
    value = {
        "Darwin": ManagedPlatform.MACOS,
        "Linux": ManagedPlatform.LINUX,
    }.get(host_platform.system())
    if value is None:
        raise ManagedEndpointInstallError(
            "managed endpoint installation requires the future Windows ACL adapter"
        )
    return value


def _verify_directory(path: Path, *, owner_uid: int) -> None:
    """Require one administrator-owned directory without following its entry."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ManagedEndpointInstallError("managed target directory cannot be inspected") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ManagedEndpointInstallError("managed target directory ownership or mode is unsafe")


def _directory_chain(
    path: Path,
    *,
    endpoint_root: Path,
    owner_uid: int,
    create: bool,
) -> None:
    """Verify every lexical component below the endpoint root and optionally create it."""
    if not path.is_absolute() or not endpoint_root.is_absolute():
        raise ManagedEndpointInstallError("managed endpoint paths must be absolute")
    try:
        relative = path.relative_to(endpoint_root)
    except ValueError as error:
        raise ManagedEndpointInstallError("managed target escapes the endpoint root") from error
    _verify_directory(endpoint_root, owner_uid=owner_uid)
    current = endpoint_root
    for component in relative.parts:
        current = current / component
        if current.exists() or current.is_symlink():
            _verify_directory(current, owner_uid=owner_uid)
            continue
        if not create:
            # Missing managed directories are a valid no-write preflight state;
            # every existing ancestor has still been verified individually.
            continue
        try:
            current.mkdir(mode=0o755)
            os.chown(current, owner_uid, -1)
            # Managed configuration is not secret. Read/execute access is
            # required by host processes; only the administrator may modify.
            os.chmod(current, 0o755)  # noqa: S103
        except OSError as error:
            raise ManagedEndpointInstallError(
                "managed target directory cannot be created"
            ) from error
        _verify_directory(current, owner_uid=owner_uid)


def _verify_existing_target(path: Path, *, owner_uid: int) -> None:
    """Reject replacement of links, devices, or files writable by non-admin users."""
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ManagedEndpointInstallError("managed target cannot be inspected") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ManagedEndpointInstallError("managed target ownership or mode is unsafe")


def _verify_executable(path: Path, digest: str, *, owner_uid: int) -> None:
    """Require one exact administrator-owned executable prerequisite."""
    encoded, metadata = _read_regular(path, _MAX_EXECUTABLE_BYTES, "managed executable")
    if (
        metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_mode & 0o111 == 0
        or hashlib.sha256(encoded).hexdigest() != digest
    ):
        raise ManagedEndpointInstallError("managed executable identity or mode does not match")


def preflight_package(
    package: ManagedDeploymentPackage,
    *,
    expected_host: AgentHost,
    expected_platform: ManagedPlatform,
    expected_bundle_hash: str,
    path_mapper: PathMapper = _identity,
    owner_uid: int = 0,
) -> EndpointInstallResult:
    """Validate desired state, local platform, prerequisites and all targets."""
    try:
        package.require_target(
            host=expected_host,
            platform=expected_platform,
            bundle_hash=expected_bundle_hash,
        )
    except SecurityConfigurationError as error:
        raise ManagedEndpointInstallError(
            "managed deployment package is not desired state"
        ) from error
    if expected_platform is ManagedPlatform.WINDOWS:
        raise ManagedEndpointInstallError("Windows managed installation requires an ACL adapter")
    if path_mapper is _identity and _expected_platform() is not expected_platform:
        raise ManagedEndpointInstallError("managed deployment package targets another platform")
    endpoint_root = path_mapper("/")
    for requirement in package.required_executables:
        executable = path_mapper(requirement.path)
        _directory_chain(
            executable.parent,
            endpoint_root=endpoint_root,
            owner_uid=owner_uid,
            create=False,
        )
        _verify_executable(executable, requirement.sha256, owner_uid=owner_uid)
    for artifact in package.artifacts:
        target = path_mapper(artifact.path)
        _directory_chain(
            target.parent,
            endpoint_root=endpoint_root,
            owner_uid=owner_uid,
            create=False,
        )
        _verify_existing_target(target, owner_uid=owner_uid)
    return EndpointInstallResult(
        status="ready",
        host=package.host.value,
        platform=package.platform.value,
        policy_id=package.policy_id,
        policy_version=package.policy_version,
        bundle_hash=package.bundle_hash,
        package_sha256=package.package_sha256,
        artifact_count=len(package.artifacts),
        executable_count=len(package.required_executables),
    )


def _stage_artifact(path: Path, content: str, *, owner_uid: int) -> Path:
    """Create and fsync one restrictive regular file beside its final target."""
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.aai-stage-", dir=path.parent)
    staged = Path(name)
    try:
        os.fchmod(descriptor, 0o644)
        os.fchown(descriptor, owner_uid, -1)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        return staged
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        staged.unlink(missing_ok=True)
        raise


def _sync_directory(path: Path) -> None:
    """Persist directory entry changes where the platform supports directory fsync."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ManagedEndpointInstallError(
            "managed target directory cannot be synchronized"
        ) from error


def install_package(
    package: ManagedDeploymentPackage,
    *,
    expected_host: AgentHost,
    expected_platform: ManagedPlatform,
    expected_bundle_hash: str,
    path_mapper: PathMapper = _identity,
    owner_uid: int = 0,
    effective_uid: int | None = None,
    replace: Replace = os.replace,
) -> EndpointInstallResult:
    """Install all files with staged replacement and complete rollback on error."""
    current_uid = os.geteuid() if effective_uid is None else effective_uid
    if current_uid != owner_uid:
        raise ManagedEndpointInstallError("managed endpoint installation requires administrator")
    # Validate every source, prerequisite and existing target before the first
    # side effect. Parent creation is intentionally deferred until all existing
    # state has passed the security checks.
    try:
        package.require_target(
            host=expected_host,
            platform=expected_platform,
            bundle_hash=expected_bundle_hash,
        )
    except SecurityConfigurationError as error:
        raise ManagedEndpointInstallError(
            "managed deployment package is not desired state"
        ) from error
    if expected_platform is ManagedPlatform.WINDOWS:
        raise ManagedEndpointInstallError("Windows managed installation requires an ACL adapter")
    if path_mapper is _identity and _expected_platform() is not expected_platform:
        raise ManagedEndpointInstallError("managed deployment package targets another platform")
    endpoint_root = path_mapper("/")
    for requirement in package.required_executables:
        executable = path_mapper(requirement.path)
        _directory_chain(
            executable.parent,
            endpoint_root=endpoint_root,
            owner_uid=owner_uid,
            create=False,
        )
        _verify_executable(executable, requirement.sha256, owner_uid=owner_uid)
    for artifact in package.artifacts:
        target = path_mapper(artifact.path)
        _directory_chain(
            target.parent,
            endpoint_root=endpoint_root,
            owner_uid=owner_uid,
            create=False,
        )
        _verify_existing_target(target, owner_uid=owner_uid)

    staged: list[tuple[Path, Path]] = []
    completed: list[tuple[Path, Path | None]] = []
    try:
        for artifact in package.artifacts:
            target = path_mapper(artifact.path)
            _directory_chain(
                target.parent,
                endpoint_root=endpoint_root,
                owner_uid=owner_uid,
                create=True,
            )
            staged.append((target, _stage_artifact(target, artifact.content, owner_uid=owner_uid)))
        for target, temporary in staged:
            backup: Path | None = None
            if target.exists():
                backup = target.with_name(f".{target.name}.aai-backup-{uuid.uuid4().hex}")
                replace(target, backup)
            # Track the target as soon as the old file moves. A failure in the
            # following replacement is then covered by the same reverse-order
            # rollback as every already-installed artifact.
            completed.append((target, backup))
            replace(temporary, target)
            _sync_directory(target.parent)
    except Exception as error:
        rollback_error: Exception | None = None
        for target, backup in reversed(completed):
            try:
                target.unlink(missing_ok=True)
                if backup is not None:
                    replace(backup, target)
                _sync_directory(target.parent)
            except Exception as current:
                rollback_error = current
        if rollback_error is not None:
            raise ManagedEndpointInstallError(
                "managed endpoint installation failed and rollback was incomplete"
            ) from rollback_error
        raise ManagedEndpointInstallError(
            "managed endpoint installation failed and was rolled back"
        ) from error
    finally:
        for _target, temporary in staged:
            temporary.unlink(missing_ok=True)
    for target, backup in completed:
        if backup is not None:
            backup.unlink(missing_ok=True)
        _sync_directory(target.parent)
    result = preflight_package(
        package,
        expected_host=expected_host,
        expected_platform=expected_platform,
        expected_bundle_hash=expected_bundle_hash,
        path_mapper=path_mapper,
        owner_uid=owner_uid,
    )
    return EndpointInstallResult(
        status="installed",
        host=result.host,
        platform=result.platform,
        policy_id=result.policy_id,
        policy_version=result.policy_version,
        bundle_hash=result.bundle_hash,
        package_sha256=result.package_sha256,
        artifact_count=result.artifact_count,
        executable_count=result.executable_count,
    )


def main() -> int:
    """Parse a deployment-owned package and check or install it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--expected-bundle-hash", required=True)
    parser.add_argument(
        "--host",
        choices=(AgentHost.CLAUDE_CODE.value, AgentHost.CODEX_CLI.value),
        required=True,
    )
    parser.add_argument(
        "--platform", choices=tuple(item.value for item in ManagedPlatform), required=True
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--install", action="store_true")
    arguments = parser.parse_args()
    package = load_package(
        arguments.package,
        expected_package_sha256=arguments.expected_package_sha256,
    )
    host = AgentHost(arguments.host)
    platform = ManagedPlatform(arguments.platform)
    if arguments.install:
        result = install_package(
            package,
            expected_host=host,
            expected_platform=platform,
            expected_bundle_hash=arguments.expected_bundle_hash,
        )
    else:
        result = preflight_package(
            package,
            expected_host=host,
            expected_platform=platform,
            expected_bundle_hash=arguments.expected_bundle_hash,
        )
    print(
        f"Managed endpoint {result.status}: host={result.host} platform={result.platform} "
        f"policy={result.policy_id}@{result.policy_version} "
        f"artifacts={result.artifact_count} executables={result.executable_count} "
        f"bundle={result.bundle_hash} package={result.package_sha256}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ManagedEndpointInstallError as error:
        print(f"Managed endpoint installation FAILED: {error}", file=sys.stderr)
        sys.exit(1)

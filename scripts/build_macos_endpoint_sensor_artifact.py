#!/usr/bin/env python3
"""Build or independently verify a release-bound macOS endpoint sensor artifact.

The artifact is one architecture-specific PyInstaller executable plus a closed
manifest. Production builds require a Developer ID Application identity;
ad-hoc signing is available only through an explicit test posture. The script
never obtains signing credentials, invokes a shell or performs network access.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ARTIFACT_TYPE = "endpoint-evidence-sensor"
_EXECUTABLE_NAME = "aai-endpoint-evidence"
_MANIFEST_NAME = "artifact-manifest.json"
_PYINSTALLER_VERSION = "6.21.0"
_PSUTIL_VERSION = "7.2.2"
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_BUILD_TIMEOUT_SECONDS = 300
_INSPECTION_TIMEOUT_SECONDS = 60
_VERSION_PATTERN = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}")
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_ARCHITECTURES = frozenset({"arm64", "x86_64"})

Runner = Callable[..., subprocess.CompletedProcess[bytes]]
VersionReader = Callable[[str], str]


class MacOSEndpointSensorArtifactError(RuntimeError):
    """Report an unsafe artifact input, build, signature or verification failure."""


@dataclass(frozen=True, slots=True)
class MacOSEndpointSensorArtifactResult:
    """Return the content-minimised identity of one verified artifact generation."""

    directory: Path
    version: str
    source_commit: str
    source_sha256: str
    architecture: str
    executable_sha256: str
    manifest_sha256: str
    signing_mode: str
    signing_identity_sha256: str | None


def _sha256(value: bytes) -> str:
    """Return the lowercase SHA-256 identity of exact bytes."""
    return hashlib.sha256(value).hexdigest()


def _safe_regular_file(
    path: Path,
    *,
    owner_uid: int,
    minimum_bytes: int,
    maximum_bytes: int,
    executable: bool,
) -> os.stat_result:
    """Require one bounded owner-controlled regular inode without following a link."""
    if not path.is_absolute() or ".." in path.parts:
        raise MacOSEndpointSensorArtifactError("artifact file path is invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MacOSEndpointSensorArtifactError("artifact file could not be inspected") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not minimum_bytes <= metadata.st_size <= maximum_bytes
        or (executable and metadata.st_mode & 0o111 == 0)
    ):
        raise MacOSEndpointSensorArtifactError("artifact file is not protected")
    return metadata


def _read_exact_file(
    path: Path,
    *,
    owner_uid: int,
    minimum_bytes: int,
    maximum_bytes: int,
    executable: bool = False,
) -> bytes:
    """Read one already-validated inode and deny replacement during measurement."""
    lexical = _safe_regular_file(
        path,
        owner_uid=owner_uid,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        executable=executable,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                lexical.st_dev,
                lexical.st_ino,
            ):
                raise MacOSEndpointSensorArtifactError("artifact file changed during inspection")
            encoded = stream.read(maximum_bytes + 1)
            final = os.fstat(stream.fileno())
    except OSError as error:
        raise MacOSEndpointSensorArtifactError("artifact file could not be read safely") from error
    if not minimum_bytes <= len(encoded) <= maximum_bytes or (
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
        raise MacOSEndpointSensorArtifactError("artifact file changed during inspection")
    return encoded


def _protected_parent(path: Path, *, owner_uid: int) -> None:
    """Require an existing owner-controlled output parent and a new final directory."""
    if not path.is_absolute() or ".." in path.parts or path.exists() or path.is_symlink():
        raise MacOSEndpointSensorArtifactError("artifact output must be a new absolute directory")
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise MacOSEndpointSensorArtifactError("artifact output parent is unavailable") from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner_uid
        or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise MacOSEndpointSensorArtifactError("artifact output parent is not protected")


def _fixed_tool(path: Path, *, owner_uid: int, label: str) -> None:
    """Require one fixed administrator-owned executable at an absolute path."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MacOSEndpointSensorArtifactError(f"{label} is unavailable") from error
    if (
        not path.is_absolute()
        or ".." in path.parts
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_mode & 0o111 == 0
    ):
        raise MacOSEndpointSensorArtifactError(f"{label} is not protected")


def _run(
    runner: Runner,
    command: list[str],
    *,
    working_directory: Path,
    environment: Mapping[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run one fixed argument-array command with bounded output and no shell."""
    try:
        result = runner(
            command,
            check=False,
            cwd=working_directory,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise MacOSEndpointSensorArtifactError("artifact tool could not be executed") from error
    if result.returncode != 0:
        # Build/signing output can disclose checkout paths and certificate
        # details. Keep product errors fixed and inspect raw output only locally.
        raise MacOSEndpointSensorArtifactError("artifact tool failed")
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise MacOSEndpointSensorArtifactError("artifact tool output exceeded its bound")
    return result


def _tool_environment(temporary: Path) -> dict[str, str]:
    """Return a closed, secret-free PyInstaller and inspection environment."""
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "PYINSTALLER_CONFIG_DIR": str(temporary / "pyinstaller-config"),
        "TMPDIR": str(temporary / "tmp"),
    }


def _dependency_versions(version_reader: VersionReader) -> tuple[str, str]:
    """Require the exact reviewed PyInstaller and psutil build inputs."""
    try:
        pyinstaller = version_reader("pyinstaller")
        psutil = version_reader("psutil")
    except importlib.metadata.PackageNotFoundError as error:
        raise MacOSEndpointSensorArtifactError("sensor build dependencies are missing") from error
    if pyinstaller != _PYINSTALLER_VERSION or psutil != _PSUTIL_VERSION:
        raise MacOSEndpointSensorArtifactError("sensor build dependencies are not exact-pinned")
    return pyinstaller, psutil


def _architecture(
    executable: Path,
    *,
    runner: Runner,
    environment: Mapping[str, str],
    working_directory: Path,
    lipo_path: Path,
    tool_owner_uid: int,
) -> str:
    """Return the sole Mach-O architecture or deny a mixed/unknown artifact."""
    _fixed_tool(lipo_path, owner_uid=tool_owner_uid, label="lipo")
    result = _run(
        runner,
        [str(lipo_path), "-archs", str(executable)],
        working_directory=working_directory,
        environment=environment,
        timeout=_INSPECTION_TIMEOUT_SECONDS,
    )
    try:
        architectures = result.stdout.decode("ascii").strip().split()
    except UnicodeDecodeError as error:
        raise MacOSEndpointSensorArtifactError("artifact architecture output is invalid") from error
    if len(architectures) != 1 or architectures[0] not in _ARCHITECTURES:
        raise MacOSEndpointSensorArtifactError("artifact must contain exactly one architecture")
    return architectures[0]


def _signature(
    executable: Path,
    *,
    runner: Runner,
    environment: Mapping[str, str],
    working_directory: Path,
    codesign_path: Path,
    tool_owner_uid: int,
) -> tuple[str, str | None, bool]:
    """Verify code signing and return mode, leaf identity and test entitlement."""
    _fixed_tool(codesign_path, owner_uid=tool_owner_uid, label="codesign")
    _run(
        runner,
        [str(codesign_path), "--verify", "--deep", "--strict", "--verbose=2", str(executable)],
        working_directory=working_directory,
        environment=environment,
        timeout=_INSPECTION_TIMEOUT_SECONDS,
    )
    details = _run(
        runner,
        [str(codesign_path), "--display", "--verbose=4", str(executable)],
        working_directory=working_directory,
        environment=environment,
        timeout=_INSPECTION_TIMEOUT_SECONDS,
    )
    try:
        text = (details.stdout + b"\n" + details.stderr).decode("utf-8")
    except UnicodeDecodeError as error:
        raise MacOSEndpointSensorArtifactError("artifact signature output is invalid") from error
    entitlements_result = _run(
        runner,
        [
            str(codesign_path),
            "--display",
            "--entitlements",
            "-",
            "--xml",
            str(executable),
        ],
        working_directory=working_directory,
        environment=environment,
        timeout=_INSPECTION_TIMEOUT_SECONDS,
    )
    entitlement_output = entitlements_result.stdout + b"\n" + entitlements_result.stderr
    start = entitlement_output.find(b"<?xml")
    end = entitlement_output.find(b"</plist>")
    if start < 0 and end < 0:
        entitlements: dict[str, Any] = {}
    elif start < 0 or end < start:
        raise MacOSEndpointSensorArtifactError("artifact entitlements are malformed")
    else:
        try:
            loaded = plistlib.loads(entitlement_output[start : end + len(b"</plist>")])
        except plistlib.InvalidFileException as error:
            raise MacOSEndpointSensorArtifactError("artifact entitlements are malformed") from error
        if not isinstance(loaded, dict):
            raise MacOSEndpointSensorArtifactError("artifact entitlements are malformed")
        entitlements = loaded
    test_entitlements = {"com.apple.security.cs.disable-library-validation": True}
    if entitlements not in ({}, test_entitlements):
        raise MacOSEndpointSensorArtifactError("artifact contains unapproved entitlements")
    library_validation_disabled = entitlements == test_entitlements
    if "Signature=adhoc" in text:
        return "adhoc", None, library_validation_disabled
    authorities = [
        line.removeprefix("Authority=")
        for line in text.splitlines()
        if line.startswith("Authority=")
    ]
    if not authorities or not authorities[0].startswith("Developer ID Application:"):
        raise MacOSEndpointSensorArtifactError(
            "artifact lacks a Developer ID Application signature"
        )
    return "developer-id", _sha256(authorities[0].encode()), library_validation_disabled


def _smoke_help(
    executable: Path,
    *,
    runner: Runner,
    environment: Mapping[str, str],
    working_directory: Path,
) -> None:
    """Execute only the argument parser and prove the required secret-free interface."""
    result = _run(
        runner,
        [str(executable), "--help"],
        working_directory=working_directory,
        environment=environment,
        timeout=_INSPECTION_TIMEOUT_SECONDS,
    )
    required = (b"--manifest", b"--key-id-file", b"--secret-file", b"--output")
    if not all(item in result.stdout for item in required) or b"--secret " in result.stdout:
        raise MacOSEndpointSensorArtifactError("artifact command interface is incomplete or unsafe")


def _manifest(document: Mapping[str, Any]) -> bytes:
    """Encode one closed artifact manifest deterministically."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def build_artifact(
    *,
    source: Path,
    expected_source_sha256: str,
    expected_python_version: str,
    version: str,
    source_commit: str,
    architecture: str,
    output_directory: Path,
    codesign_identity: str | None = None,
    allow_adhoc: bool = False,
    owner_uid: int | None = None,
    system_name: str | None = None,
    python_executable: Path | None = None,
    lipo_path: Path = Path("/usr/bin/lipo"),
    codesign_path: Path = Path("/usr/bin/codesign"),
    tool_owner_uid: int = 0,
    runner: Runner = subprocess.run,
    version_reader: VersionReader = importlib.metadata.version,
) -> MacOSEndpointSensorArtifactResult:
    """Build one atomic macOS sensor generation from exact reviewed source."""
    uid = os.getuid() if owner_uid is None else owner_uid
    if (system_name or platform.system()) != "Darwin":
        raise MacOSEndpointSensorArtifactError("macOS sensor artifacts require a macOS host")
    if (
        not _VERSION_PATTERN.fullmatch(version)
        or not _COMMIT_PATTERN.fullmatch(source_commit)
        or not _DIGEST_PATTERN.fullmatch(expected_source_sha256)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_python_version)
        or architecture not in _ARCHITECTURES
    ):
        raise MacOSEndpointSensorArtifactError("artifact release identity is invalid")
    if bool(codesign_identity) == allow_adhoc:
        raise MacOSEndpointSensorArtifactError(
            "choose exactly one Developer ID identity or explicit ad-hoc test mode"
        )
    if codesign_identity is not None and (
        not 1 <= len(codesign_identity) <= 256
        or any(ord(character) < 32 or ord(character) == 127 for character in codesign_identity)
    ):
        raise MacOSEndpointSensorArtifactError("code-signing identity is invalid")
    _protected_parent(output_directory, owner_uid=uid)
    source_bytes = _read_exact_file(
        source,
        owner_uid=uid,
        minimum_bytes=1,
        maximum_bytes=_MAX_SOURCE_BYTES,
    )
    if not hmac.compare_digest(_sha256(source_bytes), expected_source_sha256):
        raise MacOSEndpointSensorArtifactError("sensor source digest does not match")
    pyinstaller_version, psutil_version = _dependency_versions(version_reader)
    if platform.python_version() != expected_python_version:
        raise MacOSEndpointSensorArtifactError("build Python version is not independently bound")
    interpreter = Path(sys.executable) if python_executable is None else python_executable
    if not interpreter.is_absolute():
        raise MacOSEndpointSensorArtifactError("build interpreter must be absolute")

    stage_name: str | None = None
    try:
        stage_name = tempfile.mkdtemp(
            prefix=f".{output_directory.name}.aai-stage-", dir=output_directory.parent
        )
        stage = Path(stage_name)
        stage.chmod(0o700)
        (stage / "tmp").mkdir(mode=0o700)
        environment = _tool_environment(stage)
        dist = stage / "dist"
        work = stage / "work"
        spec = stage / "spec"
        signing_selector = codesign_identity if codesign_identity is not None else "-"
        entitlements = stage / "adhoc-test-entitlements.plist"
        if allow_adhoc:
            entitlements.write_bytes(
                plistlib.dumps(
                    {"com.apple.security.cs.disable-library-validation": True},
                    fmt=plistlib.FMT_XML,
                    sort_keys=True,
                )
            )
            entitlements.chmod(0o600)
        pyinstaller_command = [
            str(interpreter),
            "-I",
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--onefile",
            "--console",
            "--noupx",
            "--name",
            _EXECUTABLE_NAME,
            "--distpath",
            str(dist),
            "--workpath",
            str(work),
            "--specpath",
            str(spec),
            "--target-arch",
            architecture,
            "--codesign-identity",
            signing_selector,
            "--hidden-import",
            "psutil",
        ]
        if allow_adhoc:
            pyinstaller_command.extend(["--osx-entitlements-file", str(entitlements)])
        pyinstaller_command.append(str(source))
        _run(
            runner,
            pyinstaller_command,
            working_directory=stage,
            environment=environment,
            timeout=_BUILD_TIMEOUT_SECONDS,
        )
        built = dist / _EXECUTABLE_NAME
        executable_bytes = _read_exact_file(
            built,
            owner_uid=uid,
            minimum_bytes=1,
            maximum_bytes=_MAX_EXECUTABLE_BYTES,
            executable=True,
        )
        actual_architecture = _architecture(
            built,
            runner=runner,
            environment=environment,
            working_directory=stage,
            lipo_path=lipo_path,
            tool_owner_uid=tool_owner_uid,
        )
        if actual_architecture != architecture:
            raise MacOSEndpointSensorArtifactError("artifact architecture does not match")
        signing_mode, signing_identity_sha256, library_validation_disabled = _signature(
            built,
            runner=runner,
            environment=environment,
            working_directory=stage,
            codesign_path=codesign_path,
            tool_owner_uid=tool_owner_uid,
        )
        if (signing_mode == "adhoc") != allow_adhoc:
            raise MacOSEndpointSensorArtifactError("artifact signature posture does not match")
        if library_validation_disabled != allow_adhoc:
            raise MacOSEndpointSensorArtifactError("artifact entitlement posture does not match")
        _smoke_help(
            built,
            runner=runner,
            environment=environment,
            working_directory=stage,
        )
        generation = stage / "generation"
        generation.mkdir(mode=0o700)
        executable = generation / _EXECUTABLE_NAME
        executable.write_bytes(executable_bytes)
        executable.chmod(0o700)
        executable_sha256 = _sha256(executable_bytes)
        document = {
            "schemaVersion": 1,
            "artifactType": _ARTIFACT_TYPE,
            "version": version,
            "sourceCommit": source_commit,
            "sourceSha256": expected_source_sha256,
            "architecture": architecture,
            "pythonVersion": expected_python_version,
            "pyinstallerVersion": pyinstaller_version,
            "psutilVersion": psutil_version,
            "signingMode": signing_mode,
            "signingIdentitySha256": signing_identity_sha256,
            "libraryValidationDisabled": library_validation_disabled,
            "executableName": _EXECUTABLE_NAME,
            "executableSha256": executable_sha256,
            "executableSizeBytes": len(executable_bytes),
        }
        manifest = generation / _MANIFEST_NAME
        manifest_bytes = _manifest(document)
        manifest.write_bytes(manifest_bytes)
        manifest.chmod(0o600)
        os.replace(generation, output_directory)
        result = MacOSEndpointSensorArtifactResult(
            directory=output_directory,
            version=version,
            source_commit=source_commit,
            source_sha256=expected_source_sha256,
            architecture=architecture,
            executable_sha256=executable_sha256,
            manifest_sha256=_sha256(manifest_bytes),
            signing_mode=signing_mode,
            signing_identity_sha256=signing_identity_sha256,
        )
        return result
    except OSError as error:
        raise MacOSEndpointSensorArtifactError(
            "artifact generation could not be committed"
        ) from error
    finally:
        if stage_name is not None:
            shutil.rmtree(stage_name, ignore_errors=True)


def _closed_manifest(value: Any) -> dict[str, Any]:
    """Return one schema-1 manifest or deny unknown/malformed authority fields."""
    fields = {
        "schemaVersion",
        "artifactType",
        "version",
        "sourceCommit",
        "sourceSha256",
        "architecture",
        "pythonVersion",
        "pyinstallerVersion",
        "psutilVersion",
        "signingMode",
        "signingIdentitySha256",
        "libraryValidationDisabled",
        "executableName",
        "executableSha256",
        "executableSizeBytes",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MacOSEndpointSensorArtifactError("artifact manifest schema is invalid")
    if (
        value["schemaVersion"] != 1
        or value["artifactType"] != _ARTIFACT_TYPE
        or value["executableName"] != _EXECUTABLE_NAME
        or not _VERSION_PATTERN.fullmatch(value.get("version", ""))
        or not _COMMIT_PATTERN.fullmatch(value.get("sourceCommit", ""))
        or not _DIGEST_PATTERN.fullmatch(value.get("sourceSha256", ""))
        or not _DIGEST_PATTERN.fullmatch(value.get("executableSha256", ""))
        or value.get("architecture") not in _ARCHITECTURES
        or value.get("pyinstallerVersion") != _PYINSTALLER_VERSION
        or value.get("psutilVersion") != _PSUTIL_VERSION
        or value.get("signingMode") not in {"adhoc", "developer-id"}
        or not isinstance(value.get("libraryValidationDisabled"), bool)
        or not isinstance(value.get("pythonVersion"), str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["pythonVersion"])
        or isinstance(value.get("executableSizeBytes"), bool)
        or not isinstance(value.get("executableSizeBytes"), int)
        or not 1 <= value["executableSizeBytes"] <= _MAX_EXECUTABLE_BYTES
    ):
        raise MacOSEndpointSensorArtifactError("artifact manifest values are invalid")
    identity = value.get("signingIdentitySha256")
    if (value["signingMode"] == "adhoc" and identity is not None) or (
        value["signingMode"] == "developer-id"
        and (not isinstance(identity, str) or not _DIGEST_PATTERN.fullmatch(identity))
    ):
        raise MacOSEndpointSensorArtifactError("artifact signing identity is invalid")
    if value["libraryValidationDisabled"] != (value["signingMode"] == "adhoc"):
        raise MacOSEndpointSensorArtifactError("artifact entitlement posture is invalid")
    return value


def verify_artifact(
    *,
    artifact_directory: Path,
    expected_manifest_sha256: str,
    expected_version: str,
    expected_source_commit: str,
    expected_source_sha256: str,
    expected_python_version: str,
    expected_architecture: str,
    expected_signing_identity_sha256: str | None = None,
    allow_adhoc: bool = False,
    owner_uid: int | None = None,
    system_name: str | None = None,
    lipo_path: Path = Path("/usr/bin/lipo"),
    codesign_path: Path = Path("/usr/bin/codesign"),
    tool_owner_uid: int = 0,
    runner: Runner = subprocess.run,
) -> MacOSEndpointSensorArtifactResult:
    """Independently verify exact artifact bytes, release identity and signature."""
    uid = os.getuid() if owner_uid is None else owner_uid
    if (system_name or platform.system()) != "Darwin":
        raise MacOSEndpointSensorArtifactError("macOS sensor verification requires macOS")
    if (
        not artifact_directory.is_absolute()
        or ".." in artifact_directory.parts
        or not _DIGEST_PATTERN.fullmatch(expected_manifest_sha256)
        or not _VERSION_PATTERN.fullmatch(expected_version)
        or not _COMMIT_PATTERN.fullmatch(expected_source_commit)
        or not _DIGEST_PATTERN.fullmatch(expected_source_sha256)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_python_version)
        or expected_architecture not in _ARCHITECTURES
        or (
            expected_signing_identity_sha256 is not None
            and not _DIGEST_PATTERN.fullmatch(expected_signing_identity_sha256)
        )
    ):
        raise MacOSEndpointSensorArtifactError("expected artifact authority is invalid")
    try:
        directory = artifact_directory.lstat()
        names = {item.name for item in artifact_directory.iterdir()}
    except OSError as error:
        raise MacOSEndpointSensorArtifactError(
            "artifact directory could not be inspected"
        ) from error
    if (
        stat.S_ISLNK(directory.st_mode)
        or not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != uid
        or directory.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or names != {_EXECUTABLE_NAME, _MANIFEST_NAME}
    ):
        raise MacOSEndpointSensorArtifactError("artifact directory is not closed and protected")
    manifest_path = artifact_directory / _MANIFEST_NAME
    manifest_bytes = _read_exact_file(
        manifest_path,
        owner_uid=uid,
        minimum_bytes=1,
        maximum_bytes=_MAX_MANIFEST_BYTES,
    )
    if not hmac.compare_digest(_sha256(manifest_bytes), expected_manifest_sha256):
        raise MacOSEndpointSensorArtifactError("artifact manifest digest does not match")
    try:
        document = _closed_manifest(json.loads(manifest_bytes))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MacOSEndpointSensorArtifactError("artifact manifest encoding is invalid") from error
    if (
        document["version"] != expected_version
        or document["sourceCommit"] != expected_source_commit
        or document["sourceSha256"] != expected_source_sha256
        or document["pythonVersion"] != expected_python_version
        or document["architecture"] != expected_architecture
    ):
        raise MacOSEndpointSensorArtifactError("artifact release identity does not match")
    executable = artifact_directory / _EXECUTABLE_NAME
    executable_bytes = _read_exact_file(
        executable,
        owner_uid=uid,
        minimum_bytes=1,
        maximum_bytes=_MAX_EXECUTABLE_BYTES,
        executable=True,
    )
    if len(executable_bytes) != document["executableSizeBytes"] or not hmac.compare_digest(
        _sha256(executable_bytes), document["executableSha256"]
    ):
        raise MacOSEndpointSensorArtifactError("artifact executable identity does not match")
    # A one-file PyInstaller executable extracts before Python starts. Give the
    # smoke run a newly created mode-0700 directory instead of a shared temp
    # root; the launchd package applies the same invariant in production.
    with tempfile.TemporaryDirectory(prefix="aai-sensor-verify-") as runtime_temporary:
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": runtime_temporary,
        }
        architecture = _architecture(
            executable,
            runner=runner,
            environment=environment,
            working_directory=artifact_directory,
            lipo_path=lipo_path,
            tool_owner_uid=tool_owner_uid,
        )
        signing_mode, signing_identity_sha256, library_validation_disabled = _signature(
            executable,
            runner=runner,
            environment=environment,
            working_directory=artifact_directory,
            codesign_path=codesign_path,
            tool_owner_uid=tool_owner_uid,
        )
        _smoke_help(
            executable,
            runner=runner,
            environment=environment,
            working_directory=artifact_directory,
        )
    if architecture != document["architecture"] or (
        signing_mode,
        signing_identity_sha256,
        library_validation_disabled,
    ) != (
        document["signingMode"],
        document["signingIdentitySha256"],
        document["libraryValidationDisabled"],
    ):
        raise MacOSEndpointSensorArtifactError("artifact measured posture does not match")
    if signing_mode == "adhoc":
        if not allow_adhoc or expected_signing_identity_sha256 is not None:
            raise MacOSEndpointSensorArtifactError("ad-hoc artifact is test-only")
    elif expected_signing_identity_sha256 is None or not hmac.compare_digest(
        signing_identity_sha256 or "", expected_signing_identity_sha256
    ):
        raise MacOSEndpointSensorArtifactError("Developer ID identity was not independently bound")
    return MacOSEndpointSensorArtifactResult(
        directory=artifact_directory,
        version=document["version"],
        source_commit=document["sourceCommit"],
        source_sha256=document["sourceSha256"],
        architecture=document["architecture"],
        executable_sha256=document["executableSha256"],
        manifest_sha256=expected_manifest_sha256,
        signing_mode=signing_mode,
        signing_identity_sha256=signing_identity_sha256,
    )


def _parser() -> argparse.ArgumentParser:
    """Build the explicit build and independent-verification operator commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source", required=True, type=Path)
    build.add_argument("--expected-source-sha256", required=True)
    build.add_argument("--expected-python-version", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--architecture", required=True, choices=sorted(_ARCHITECTURES))
    build.add_argument("--output-directory", required=True, type=Path)
    signing = build.add_mutually_exclusive_group(required=True)
    signing.add_argument("--codesign-identity")
    signing.add_argument("--allow-adhoc", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--artifact-directory", required=True, type=Path)
    verify.add_argument("--expected-manifest-sha256", required=True)
    verify.add_argument("--expected-version", required=True)
    verify.add_argument("--expected-source-commit", required=True)
    verify.add_argument("--expected-source-sha256", required=True)
    verify.add_argument("--expected-python-version", required=True)
    verify.add_argument("--expected-architecture", required=True, choices=sorted(_ARCHITECTURES))
    verify.add_argument("--expected-signing-identity-sha256")
    verify.add_argument("--allow-adhoc", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Build or verify one generation and print only content-minimised identities."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "build":
            result = build_artifact(
                source=arguments.source.expanduser(),
                expected_source_sha256=arguments.expected_source_sha256,
                expected_python_version=arguments.expected_python_version,
                version=arguments.version,
                source_commit=arguments.source_commit,
                architecture=arguments.architecture,
                output_directory=arguments.output_directory.expanduser(),
                codesign_identity=arguments.codesign_identity,
                allow_adhoc=arguments.allow_adhoc,
            )
        else:
            result = verify_artifact(
                artifact_directory=arguments.artifact_directory.expanduser(),
                expected_manifest_sha256=arguments.expected_manifest_sha256,
                expected_version=arguments.expected_version,
                expected_source_commit=arguments.expected_source_commit,
                expected_source_sha256=arguments.expected_source_sha256,
                expected_python_version=arguments.expected_python_version,
                expected_architecture=arguments.expected_architecture,
                expected_signing_identity_sha256=arguments.expected_signing_identity_sha256,
                allow_adhoc=arguments.allow_adhoc,
            )
    except MacOSEndpointSensorArtifactError as error:
        print(f"macOS sensor artifact failed: {error}", file=sys.stderr)
        return 2
    print(f"Version: {result.version}")
    print(f"Source commit: {result.source_commit}")
    print(f"Source SHA-256: {result.source_sha256}")
    print(f"Architecture: {result.architecture}")
    print(f"Executable SHA-256: {result.executable_sha256}")
    print(f"Manifest SHA-256: {result.manifest_sha256}")
    print(f"Signing mode: {result.signing_mode}")
    if result.signing_identity_sha256 is not None:
        print(f"Signing identity SHA-256: {result.signing_identity_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

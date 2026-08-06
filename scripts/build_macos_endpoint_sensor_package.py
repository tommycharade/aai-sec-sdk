#!/usr/bin/env python3
"""Build a digest-bound macOS MDM package for the endpoint evidence sensor.

The builder accepts one prebuilt sensor executable whose SHA-256 arrives through
an independent release channel. It creates a secret-free launchd payload and
invokes only fixed macOS packaging tools without a shell. Per-device manifest,
key ID and secret files are deliberately excluded and must be delivered through
the customer's MDM after package approval.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

_PACKAGE_IDENTIFIER = "com.aai-security.endpoint-evidence"
_LAUNCHD_LABEL = _PACKAGE_IDENTIFIER
_INSTALL_ROOT = Path("/Library/Application Support/AAI Security")
_EXECUTABLE_PATH = _INSTALL_ROOT / "bin/aai-endpoint-evidence"
_CONFIGURATION_ROOT = _INSTALL_ROOT / "config"
_MANIFEST_PATH = _CONFIGURATION_ROOT / "endpoint-evidence-manifest.json"
_KEY_ID_PATH = _CONFIGURATION_ROOT / "endpoint-evidence-key-id"
_SECRET_PATH = _CONFIGURATION_ROOT / "endpoint-evidence.key"
_REPORT_ROOT = Path("/var/db/aai-security/endpoint-evidence")
_REPORT_PATH = _REPORT_ROOT / "report.json"
_RUNTIME_TEMP_ROOT = _REPORT_ROOT / "runtime"
_LOG_ROOT = Path("/var/log/aai-security")
_LOG_PATH = _LOG_ROOT / "endpoint-evidence.log"
_PLIST_PATH = Path("/Library/LaunchDaemons") / f"{_LAUNCHD_LABEL}.plist"
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_PACKAGE_BYTES = 512 * 1024 * 1024
_BUILD_TIMEOUT_SECONDS = 120
_VERSION_PATTERN = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}")

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class MacOSEndpointPackageError(RuntimeError):
    """Report an unsafe input, unavailable tool or failed package build."""


@dataclass(frozen=True, slots=True)
class MacOSEndpointPackageResult:
    """Return content-minimised identities for one completed package build."""

    identifier: str
    version: str
    launchd_label: str
    collection_interval_seconds: int
    sensor_sha256: str
    package_sha256: str
    package_size_bytes: int
    signed: bool


def _sha256(value: bytes) -> str:
    """Return the lowercase SHA-256 identity of exact bytes."""
    return hashlib.sha256(value).hexdigest()


def _read_executable(path: Path, *, expected_sha256: str, owner_uid: int) -> bytes:
    """Read one protected executable inode and verify its out-of-band digest."""
    if (
        not path.is_absolute()
        or ".." in path.parts
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        raise MacOSEndpointPackageError("sensor executable authority is invalid")
    try:
        lexical = path.lstat()
    except OSError as error:
        raise MacOSEndpointPackageError("sensor executable could not be inspected") from error
    if (
        stat.S_ISLNK(lexical.st_mode)
        or not stat.S_ISREG(lexical.st_mode)
        or lexical.st_uid != owner_uid
        or lexical.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or lexical.st_mode & 0o111 == 0
        or not 1 <= lexical.st_size <= _MAX_EXECUTABLE_BYTES
    ):
        raise MacOSEndpointPackageError("sensor executable is not protected")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                lexical.st_dev,
                lexical.st_ino,
            ):
                raise MacOSEndpointPackageError("sensor executable changed during inspection")
            encoded = stream.read(_MAX_EXECUTABLE_BYTES + 1)
            final = os.fstat(stream.fileno())
    except OSError as error:
        raise MacOSEndpointPackageError("sensor executable could not be read safely") from error
    if (
        len(encoded) > _MAX_EXECUTABLE_BYTES
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
        or not hmac.compare_digest(_sha256(encoded), expected_sha256)
    ):
        raise MacOSEndpointPackageError("sensor executable digest does not match")
    return encoded


def _verify_output(path: Path, *, owner_uid: int, must_exist: bool) -> None:
    """Require one safe package output path or completed package file."""
    if not path.is_absolute() or ".." in path.parts or path.suffix != ".pkg":
        raise MacOSEndpointPackageError("package output must be an absolute .pkg path")
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise MacOSEndpointPackageError("package output directory is unavailable") from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner_uid
        or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise MacOSEndpointPackageError("package output directory is not protected")
    exists = path.exists() or path.is_symlink()
    if not must_exist and exists:
        raise MacOSEndpointPackageError("package output must not already exist")
    if must_exist:
        if not exists:
            raise MacOSEndpointPackageError("macOS packaging tool did not create the package")
        try:
            package = path.lstat()
        except OSError as error:
            raise MacOSEndpointPackageError("built package could not be inspected") from error
        if (
            stat.S_ISLNK(package.st_mode)
            or not stat.S_ISREG(package.st_mode)
            or package.st_uid != owner_uid
            or package.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= package.st_size <= _MAX_PACKAGE_BYTES
        ):
            raise MacOSEndpointPackageError("built package is not a protected regular file")


def _verify_tool(path: Path, *, owner_uid: int, label: str) -> None:
    """Require one fixed administrator-owned macOS packaging executable."""
    if not path.is_absolute() or ".." in path.parts:
        raise MacOSEndpointPackageError(f"{label} path is invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MacOSEndpointPackageError(f"{label} is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_mode & 0o111 == 0
    ):
        raise MacOSEndpointPackageError(f"{label} is not protected")


def _write_payload_file(path: Path, content: bytes, mode: int) -> None:
    """Write one builder-owned staging file with an exact mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def _launchd_plist(interval_seconds: int) -> bytes:
    """Return the closed shell-free launchd job definition."""
    value = {
        "Label": _LAUNCHD_LABEL,
        "ProgramArguments": [
            str(_EXECUTABLE_PATH),
            "--manifest",
            str(_MANIFEST_PATH),
            "--key-id-file",
            str(_KEY_ID_PATH),
            "--secret-file",
            str(_SECRET_PATH),
            "--output",
            str(_REPORT_PATH),
        ],
        "RunAtLoad": True,
        "StartInterval": interval_seconds,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "UserName": "root",
        "GroupName": "wheel",
        "Umask": 0o077,
        # PyInstaller one-file extraction happens before sensor code executes;
        # launchd must therefore provide a protected root-owned temp boundary.
        "EnvironmentVariables": {"TMPDIR": str(_RUNTIME_TEMP_ROOT)},
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": str(_LOG_PATH),
    }
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def _postinstall_script() -> bytes:
    """Return the fixed package lifecycle script with no caller interpolation."""
    script = """#!/bin/sh
set -eu
/usr/bin/install -d -o root -g wheel -m 0700 '/Library/Application Support/AAI Security/config'
/usr/bin/install -d -o root -g wheel -m 0700 '/var/db/aai-security/endpoint-evidence'
/usr/bin/install -d -o root -g wheel -m 0700 '/var/db/aai-security/endpoint-evidence/runtime'
/usr/bin/install -d -o root -g wheel -m 0755 '/var/log/aai-security'
/usr/sbin/chown root:wheel '/Library/Application Support/AAI Security'
/bin/chmod 0755 '/Library/Application Support/AAI Security'
/usr/sbin/chown root:wheel '/Library/Application Support/AAI Security/bin'
/bin/chmod 0755 '/Library/Application Support/AAI Security/bin'
/usr/sbin/chown root:wheel '/Library/Application Support/AAI Security/bin/aai-endpoint-evidence'
/bin/chmod 0755 '/Library/Application Support/AAI Security/bin/aai-endpoint-evidence'
/usr/sbin/chown root:wheel '/Library/Application Support/AAI Security/package-metadata.json'
/bin/chmod 0644 '/Library/Application Support/AAI Security/package-metadata.json'
/usr/sbin/chown root:wheel '/Library/LaunchDaemons/com.aai-security.endpoint-evidence.plist'
/bin/chmod 0644 '/Library/LaunchDaemons/com.aai-security.endpoint-evidence.plist'
/bin/launchctl bootout system/com.aai-security.endpoint-evidence >/dev/null 2>&1 || true
/bin/launchctl bootstrap system '/Library/LaunchDaemons/com.aai-security.endpoint-evidence.plist'
/bin/launchctl enable system/com.aai-security.endpoint-evidence
exit 0
"""
    return script.encode()


def _run_tool(
    runner: Runner,
    command: list[str],
    *,
    working_directory: Path,
) -> None:
    """Run one fixed packaging command with no shell or inherited secrets."""
    try:
        result = runner(
            command,
            check=False,
            cwd=working_directory,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise MacOSEndpointPackageError("macOS packaging tool could not be executed") from error
    if result.returncode != 0:
        # Tool output can contain developer paths or signing details. Keep the
        # product error content-minimised and let the operator inspect locally.
        raise MacOSEndpointPackageError("macOS packaging tool failed")


def build_package(
    *,
    sensor_executable: Path,
    expected_sensor_sha256: str,
    version: str,
    output: Path,
    interval_seconds: int = 300,
    signing_identity: str | None = None,
    allow_unsigned: bool = False,
    owner_uid: int | None = None,
    system_name: str | None = None,
    pkgbuild_path: Path = Path("/usr/bin/pkgbuild"),
    productsign_path: Path = Path("/usr/bin/productsign"),
    pkgutil_path: Path = Path("/usr/sbin/pkgutil"),
    tool_owner_uid: int = 0,
    runner: Runner = subprocess.run,
) -> MacOSEndpointPackageResult:
    """Build one MDM package without embedding device identity or credentials."""
    uid = os.getuid() if owner_uid is None else owner_uid
    if (system_name or platform.system()) != "Darwin":
        raise MacOSEndpointPackageError("macOS package builds require a macOS host")
    if not _VERSION_PATTERN.fullmatch(version):
        raise MacOSEndpointPackageError("package version must contain two to four numeric parts")
    if isinstance(interval_seconds, bool) or not 300 <= interval_seconds <= 3_600:
        raise MacOSEndpointPackageError("collection interval must be between 300 and 3600 seconds")
    if bool(signing_identity) == allow_unsigned:
        raise MacOSEndpointPackageError(
            "choose exactly one package signing identity or explicit unsigned test mode"
        )
    if signing_identity is not None and (
        not 1 <= len(signing_identity) <= 256
        or any(ord(character) < 32 or ord(character) == 127 for character in signing_identity)
    ):
        raise MacOSEndpointPackageError("package signing identity is invalid")
    _verify_output(output, owner_uid=uid, must_exist=False)
    sensor = _read_executable(
        sensor_executable,
        expected_sha256=expected_sensor_sha256,
        owner_uid=uid,
    )
    _verify_tool(pkgbuild_path, owner_uid=tool_owner_uid, label="pkgbuild")
    if signing_identity is not None:
        _verify_tool(productsign_path, owner_uid=tool_owner_uid, label="productsign")
        _verify_tool(pkgutil_path, owner_uid=tool_owner_uid, label="pkgutil")

    with tempfile.TemporaryDirectory(prefix="aai-macos-sensor-package-") as temporary_name:
        temporary = Path(temporary_name)
        payload = temporary / "payload"
        scripts = temporary / "scripts"
        _write_payload_file(payload / _EXECUTABLE_PATH.relative_to("/"), sensor, 0o755)
        _write_payload_file(
            payload / _PLIST_PATH.relative_to("/"),
            _launchd_plist(interval_seconds),
            0o644,
        )
        metadata = {
            "schemaVersion": 1,
            "identifier": _PACKAGE_IDENTIFIER,
            "version": version,
            "sensorSha256": expected_sensor_sha256,
            "launchdLabel": _LAUNCHD_LABEL,
            "collectionIntervalSeconds": interval_seconds,
            "credentialsIncluded": False,
        }
        _write_payload_file(
            payload / (_INSTALL_ROOT / "package-metadata.json").relative_to("/"),
            json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode() + b"\n",
            0o644,
        )
        _write_payload_file(scripts / "postinstall", _postinstall_script(), 0o755)
        unsigned = output if signing_identity is None else temporary / "unsigned.pkg"
        _run_tool(
            runner,
            [
                str(pkgbuild_path),
                "--root",
                str(payload),
                "--scripts",
                str(scripts),
                "--identifier",
                _PACKAGE_IDENTIFIER,
                "--version",
                version,
                "--install-location",
                "/",
                "--ownership",
                "recommended",
                str(unsigned),
            ],
            working_directory=temporary,
        )
        if signing_identity is not None:
            _run_tool(
                runner,
                [str(productsign_path), "--sign", signing_identity, str(unsigned), str(output)],
                working_directory=temporary,
            )
            _run_tool(
                runner,
                [str(pkgutil_path), "--check-signature", str(output)],
                working_directory=temporary,
            )

    _verify_output(output, owner_uid=uid, must_exist=True)
    package = output.read_bytes()
    return MacOSEndpointPackageResult(
        identifier=_PACKAGE_IDENTIFIER,
        version=version,
        launchd_label=_LAUNCHD_LABEL,
        collection_interval_seconds=interval_seconds,
        sensor_sha256=expected_sensor_sha256,
        package_sha256=_sha256(package),
        package_size_bytes=len(package),
        signed=signing_identity is not None,
    )


def _parser() -> argparse.ArgumentParser:
    """Build the explicit digest- and signing-bound operator command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor-executable", required=True, type=Path)
    parser.add_argument("--expected-sensor-sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interval-seconds", type=int, default=300)
    signing = parser.add_mutually_exclusive_group(required=True)
    signing.add_argument("--signing-identity")
    signing.add_argument("--allow-unsigned", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Build one package and print only its non-secret release identities."""
    arguments = _parser().parse_args(argv)
    try:
        result = build_package(
            # Preserve the lexical final component so the validator can reject
            # a symlink instead of accidentally authorizing its resolved target.
            sensor_executable=arguments.sensor_executable.expanduser(),
            expected_sensor_sha256=arguments.expected_sensor_sha256,
            version=arguments.version,
            output=arguments.output.expanduser(),
            interval_seconds=arguments.interval_seconds,
            signing_identity=arguments.signing_identity,
            allow_unsigned=arguments.allow_unsigned,
        )
    except MacOSEndpointPackageError as error:
        print(f"macOS endpoint package build failed: {error}", file=sys.stderr)
        return 2
    print(f"Identifier: {result.identifier}")
    print(f"Version: {result.version}")
    print(f"Sensor SHA-256: {result.sensor_sha256}")
    print(f"Package SHA-256: {result.package_sha256}")
    print(f"Signed: {'yes' if result.signed else 'no - test mode only'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

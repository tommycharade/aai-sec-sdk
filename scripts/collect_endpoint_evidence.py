#!/usr/bin/env python3
"""Measure and sign content-minimised Claude/Codex endpoint evidence.

The script is intended for root/administrator execution by endpoint management.
It never invokes a shell. Interactive runs may use a named environment variable;
scheduled runs may instead use protected root-owned key and secret files and an
atomic protected report output.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
import platform
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

_SUPPORTED_HOSTS = frozenset({"claude-code", "codex-cli"})
_IDENTIFIER_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)
_MAX_INSTALLATIONS = 100
_MAX_BINARY_BYTES = 1_073_741_824
_MAX_CREDENTIAL_BYTES = 4_096
_OPERATING_SYSTEMS = {"darwin": "darwin", "linux": "linux", "windows": "windows"}
_ARCHITECTURES = {
    "arm64": "arm64",
    "aarch64": "arm64",
    "x86_64": "x86_64",
    "amd64": "x86_64",
}


class EndpointEvidenceError(RuntimeError):
    """Report a bounded manifest, privilege, measurement or signing failure."""


def _identifier(value: Any, label: str) -> str:
    """Return one bounded opaque identifier."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(character not in _IDENTIFIER_CHARACTERS for character in value)
    ):
        raise EndpointEvidenceError(f"{label} is invalid")
    return value


def _absolute_path(value: Any, label: str) -> Path:
    """Return a lexical absolute path without resolving untrusted symlinks."""
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise EndpointEvidenceError(f"{label} is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise EndpointEvidenceError(f"{label} must be an absolute non-traversing path")
    return path


def _read_manifest(path: Path) -> dict[str, Any]:
    """Read one exact, bounded sensor manifest."""
    try:
        if path.stat().st_size > 1_000_000:
            raise EndpointEvidenceError("manifest exceeds the one-megabyte limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EndpointEvidenceError(f"could not read endpoint manifest: {error}") from error
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "device",
        "installations",
    }:
        raise EndpointEvidenceError("endpoint manifest has an invalid schema")
    if value["schemaVersion"] != 1:
        raise EndpointEvidenceError("endpoint manifest schema version is unsupported")
    return value


def _validate_manifest_security(path: Path) -> None:
    """Require a root-owned, non-writable regular POSIX manifest."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EndpointEvidenceError("endpoint manifest could not be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EndpointEvidenceError("endpoint manifest must be a regular non-symlink file")
    if os.name != "posix":
        raise EndpointEvidenceError("endpoint manifest ACL verification is unsupported")
    if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise EndpointEvidenceError("endpoint manifest must be root-owned and not broadly writable")


def _read_protected_text(
    path: Path,
    *,
    label: str,
    owner_uid: int = 0,
    minimum_bytes: int = 1,
    maximum_bytes: int = _MAX_CREDENTIAL_BYTES,
) -> str:
    """Read one exact administrator-owned value without following a link.

    The value must be UTF-8 without whitespace or NUL bytes. This deliberately
    rejects newline-terminated secret files so packaging cannot silently change
    credential bytes produced by the control plane.
    """
    if not path.is_absolute() or ".." in path.parts:
        raise EndpointEvidenceError(f"{label} path must be absolute and non-traversing")
    try:
        lexical = path.lstat()
    except OSError as error:
        raise EndpointEvidenceError(f"{label} could not be inspected") from error
    if (
        stat.S_ISLNK(lexical.st_mode)
        or not stat.S_ISREG(lexical.st_mode)
        or lexical.st_uid != owner_uid
        or lexical.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        or not minimum_bytes <= lexical.st_size <= maximum_bytes
    ):
        raise EndpointEvidenceError(f"{label} must be a protected administrator-owned file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                lexical.st_dev,
                lexical.st_ino,
            ):
                raise EndpointEvidenceError(f"{label} changed during inspection")
            encoded = stream.read(maximum_bytes + 1)
    except OSError as error:
        raise EndpointEvidenceError(f"{label} could not be read safely") from error
    if not minimum_bytes <= len(encoded) <= maximum_bytes:
        raise EndpointEvidenceError(f"{label} size is invalid")
    try:
        value = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EndpointEvidenceError(f"{label} must be UTF-8") from error
    if any(character.isspace() or character == "\x00" for character in value):
        raise EndpointEvidenceError(f"{label} must not contain whitespace or NUL bytes")
    return value


def _verify_protected_directory(path: Path, *, owner_uid: int) -> None:
    """Require one administrator-owned non-symlink output directory."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EndpointEvidenceError("endpoint report directory could not be inspected") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise EndpointEvidenceError("endpoint report directory is not protected")


def write_signed_report(
    path: Path,
    report: dict[str, Any],
    *,
    owner_uid: int = 0,
    effective_uid: int | None = None,
) -> None:
    """Atomically replace one mode-0600 report in a protected directory.

    The caller must already have generated a content-minimised report. Existing
    links, devices, non-administrator files and broadly writable files are
    rejected before replacement; a temporary file is fsynced before the atomic
    rename so an MDM collector never reads a partial report.
    """
    current_uid = os.geteuid() if effective_uid is None else effective_uid
    if current_uid != owner_uid:
        raise EndpointEvidenceError("endpoint report output requires administrator identity")
    output = _absolute_path(str(path), "output")
    _verify_protected_directory(output.parent, owner_uid=owner_uid)
    if output.exists() or output.is_symlink():
        try:
            existing = output.lstat()
        except OSError as error:
            raise EndpointEvidenceError("endpoint report output could not be inspected") from error
        if (
            stat.S_ISLNK(existing.st_mode)
            or not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != owner_uid
            or existing.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise EndpointEvidenceError("endpoint report output is not protected")
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{output.name}.aai-stage-", dir=output.parent)
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, owner_uid, -1)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        temporary = None
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(output.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise EndpointEvidenceError("endpoint report could not be written safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _is_administrator() -> bool:
    """Check the fixed operating-system administrator primitive."""
    if os.name == "posix":
        return os.geteuid() == 0
    if os.name == "nt":
        # A fixed system DLL and symbol are used; neither value is influenced by
        # manifest/model input. Failure is denied instead of guessed.
        try:
            import ctypes

            shell32 = ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
            return bool(shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return False


def _running_processes() -> set[tuple[Path, Path]]:
    """Return exact executable/project pairs or fail if visibility is incomplete."""
    try:
        import psutil
    except ImportError as error:
        raise EndpointEvidenceError(
            "process inspection requires the agentic-security-sdk[endpoint] extra"
        ) from error
    denied = object()
    processes: set[tuple[Path, Path]] = set()
    for process in psutil.process_iter(attrs=("exe", "cwd"), ad_value=denied):
        try:
            executable = process.info.get("exe")
            working_directory = process.info.get("cwd")
        except (psutil.AccessDenied, psutil.Error) as error:
            raise EndpointEvidenceError("process inspection was incomplete") from error
        if executable is denied or working_directory is denied:
            raise EndpointEvidenceError("process inspection was incomplete")
        if (
            isinstance(executable, str)
            and executable
            and isinstance(working_directory, str)
            and working_directory
        ):
            processes.add(
                (
                    Path(os.path.realpath(executable)),
                    Path(os.path.realpath(working_directory)),
                )
            )
    return processes


def _sha256_handle(handle: Any) -> str:
    """Hash one bounded already-open regular file."""
    digest = hashlib.sha256()
    size = 0
    try:
        while block := handle.read(1024 * 1024):
            size += len(block)
            if size > _MAX_BINARY_BYTES:
                raise EndpointEvidenceError("configured binary exceeds the one-gigabyte limit")
            digest.update(block)
    except OSError as error:
        raise EndpointEvidenceError("configured binary could not be hashed") from error
    return digest.hexdigest()


def _binary_present(path: Path, expected_digest: str | None) -> bool:
    """Measure one exact opened inode, rejecting symlinks and replacement races."""
    try:
        lexical_metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise EndpointEvidenceError("configured binary could not be inspected") from error
    if stat.S_ISLNK(lexical_metadata.st_mode) or not stat.S_ISREG(lexical_metadata.st_mode):
        return False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ELOOP}:
            return False
        raise EndpointEvidenceError("configured binary could not be opened safely") from error
    try:
        opened_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or (opened_metadata.st_dev, opened_metadata.st_ino)
            != (lexical_metadata.st_dev, lexical_metadata.st_ino)
            or not opened_metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            return False
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            measured_digest = _sha256_handle(handle)
        final_metadata = os.fstat(descriptor)
        if (
            opened_metadata.st_size,
            opened_metadata.st_mtime_ns,
            opened_metadata.st_ctime_ns,
        ) != (
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
            final_metadata.st_ctime_ns,
        ):
            return False
    finally:
        os.close(descriptor)
    return expected_digest is None or hmac.compare_digest(measured_digest, expected_digest)


def _canonical(value: dict[str, Any]) -> bytes:
    """Encode one report deterministically for signing and verification."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _endpoint_platform() -> tuple[str, str]:
    """Measure one supported OS/architecture pair without model or manifest input."""
    operating_system = _OPERATING_SYSTEMS.get(platform.system().lower())
    architecture = _ARCHITECTURES.get(platform.machine().lower())
    if operating_system is None or architecture is None:
        raise EndpointEvidenceError("endpoint platform is unsupported")
    return operating_system, architecture


def collect_signed_report(
    manifest_path: Path,
    *,
    key_id: str,
    secret: str,
    observed_at: int | None = None,
    administrator_check: Callable[[], bool] = _is_administrator,
    manifest_security_check: Callable[[Path], None] = _validate_manifest_security,
    process_reader: Callable[[], set[tuple[Path, Path]]] = _running_processes,
    platform_reader: Callable[[], tuple[str, str]] = _endpoint_platform,
) -> dict[str, Any]:
    """Measure one endpoint and return a canonical per-device signed report."""
    if not administrator_check():
        raise EndpointEvidenceError("endpoint evidence collection requires administrator identity")
    key_identifier = _identifier(key_id, "keyId")
    secret_bytes = secret.encode()
    if len(secret_bytes) < 32:
        raise EndpointEvidenceError("endpoint signing secret must contain at least 32 bytes")
    manifest_security_check(manifest_path)
    manifest = _read_manifest(manifest_path)
    device = manifest["device"]
    if (
        not isinstance(device, dict)
        or not {"id", "managed"}.issubset(device)
        or set(device)
        - {
            "id",
            "managed",
            "businessUnit",
            "userIds",
        }
    ):
        raise EndpointEvidenceError("endpoint device has an invalid schema")
    device_id = _identifier(device.get("id"), "device id")
    if not isinstance(device.get("managed"), bool):
        raise EndpointEvidenceError("endpoint managed state must be boolean")
    installations = manifest["installations"]
    if not isinstance(installations, list) or not 1 <= len(installations) <= _MAX_INSTALLATIONS:
        raise EndpointEvidenceError("endpoint manifest must contain 1 to 100 installations")
    running = process_reader()
    operating_system, architecture = platform_reader()
    if operating_system not in set(_OPERATING_SYSTEMS.values()) or architecture not in set(
        _ARCHITECTURES.values()
    ):
        raise EndpointEvidenceError("endpoint platform is unsupported")
    normalized_device: dict[str, Any] = {"id": device_id, "managed": device["managed"]}
    normalized_device.update({"operatingSystem": operating_system, "architecture": architecture})
    if "businessUnit" in device:
        normalized_device["businessUnit"] = _identifier(device["businessUnit"], "businessUnit")
    if "userIds" in device:
        users = device["userIds"]
        if not isinstance(users, list) or len(users) > 20:
            raise EndpointEvidenceError("endpoint userIds must be a bounded list")
        normalized_device["userIds"] = sorted(_identifier(item, "userId") for item in users)
        if len(normalized_device["userIds"]) != len(set(normalized_device["userIds"])):
            raise EndpointEvidenceError("endpoint userIds must not contain duplicates")
    normalized_installations: list[dict[str, Any]] = []
    seen: set[str] = set()
    required = {
        "id",
        "host",
        "projectRoot",
        "binaryPath",
        "processExecutablePaths",
    }
    allowed = required | {
        "expectedBinarySha256",
        "userId",
        "repositoryId",
        "businessUnit",
    }
    for installation in installations:
        if (
            not isinstance(installation, dict)
            or not required.issubset(installation)
            or set(installation) - allowed
        ):
            raise EndpointEvidenceError("endpoint installation has an invalid schema")
        installation_id = _identifier(installation.get("id"), "installation id")
        if installation_id in seen:
            raise EndpointEvidenceError("endpoint installation identifiers must be unique")
        seen.add(installation_id)
        host = installation.get("host")
        if host not in _SUPPORTED_HOSTS:
            raise EndpointEvidenceError("endpoint installation host is unsupported")
        project_root = _absolute_path(installation.get("projectRoot"), "projectRoot")
        try:
            project_metadata = project_root.lstat()
        except OSError as error:
            raise EndpointEvidenceError("projectRoot could not be inspected") from error
        if stat.S_ISLNK(project_metadata.st_mode) or not stat.S_ISDIR(project_metadata.st_mode):
            raise EndpointEvidenceError("projectRoot must be a non-symlink directory")
        resolved_project_root = Path(os.path.realpath(project_root))
        binary_path = _absolute_path(installation.get("binaryPath"), "binaryPath")
        process_paths = installation.get("processExecutablePaths")
        if not isinstance(process_paths, list) or not 1 <= len(process_paths) <= 10:
            raise EndpointEvidenceError("processExecutablePaths must contain 1 to 10 paths")
        normalized_process_paths = {
            Path(os.path.realpath(_absolute_path(item, "processExecutablePath")))
            for item in process_paths
        }
        if len(normalized_process_paths) != len(process_paths):
            raise EndpointEvidenceError("processExecutablePaths must not contain duplicates")
        expected_digest = installation.get("expectedBinarySha256")
        if expected_digest is not None and (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or any(character not in "0123456789abcdef" for character in expected_digest)
        ):
            raise EndpointEvidenceError("expectedBinarySha256 must be a lowercase SHA-256 digest")
        result: dict[str, Any] = {
            "id": installation_id,
            "deviceId": device_id,
            "host": host,
            "projectRootDigest": hashlib.sha256(str(project_root).encode()).hexdigest(),
            "binaryPresent": _binary_present(binary_path, expected_digest),
            "processActive": any(
                executable in normalized_process_paths
                and working_directory == resolved_project_root
                for executable, working_directory in running
            ),
        }
        for field in ("userId", "repositoryId", "businessUnit"):
            if field in installation:
                result[field] = _identifier(installation[field], field)
        normalized_installations.append(result)
    timestamp = int(time.time()) if observed_at is None else observed_at
    if isinstance(timestamp, bool) or timestamp < 0:
        raise EndpointEvidenceError("observedAt must be a non-negative integer")
    payload = {
        "schemaVersion": 2,
        "observedAt": timestamp,
        "device": normalized_device,
        "installations": sorted(normalized_installations, key=lambda item: item["id"]),
    }
    signature = hmac.new(secret_bytes, _canonical(payload), hashlib.sha256).hexdigest()
    return {"keyId": key_identifier, "payload": payload, "signature": signature}


def _parser() -> argparse.ArgumentParser:
    """Build a secret-free endpoint sensor command contract."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    key_source = parser.add_mutually_exclusive_group(required=True)
    key_source.add_argument("--key-id")
    key_source.add_argument("--key-id-file", type=Path)
    secret_source = parser.add_mutually_exclusive_group()
    secret_source.add_argument("--secret-env")
    secret_source.add_argument("--secret-file", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Measure and emit one signed report without exposing paths or secrets."""
    arguments = _parser().parse_args(argv)
    try:
        key_id = (
            arguments.key_id
            if arguments.key_id is not None
            else _read_protected_text(arguments.key_id_file, label="endpoint key ID")
        )
        secret = (
            _read_protected_text(arguments.secret_file, label="endpoint signing secret")
            if arguments.secret_file is not None
            else os.environ.get(arguments.secret_env or "AAI_ENDPOINT_EVIDENCE_KEY", "")
        )
        result = collect_signed_report(
            arguments.manifest,
            key_id=key_id,
            secret=secret,
        )
        if arguments.output is not None:
            write_signed_report(arguments.output, result)
        else:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except EndpointEvidenceError as error:
        print(f"Endpoint evidence collection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

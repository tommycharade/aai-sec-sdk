"""Adversarial contracts for the macOS endpoint sensor MDM package builder."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def _module() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "build_macos_endpoint_sensor_package.py"
    spec = importlib.util.spec_from_file_location("aai_macos_sensor_package", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _executable(path: Path, content: bytes = b"synthetic sensor executable") -> tuple[Path, str]:
    path.write_bytes(content)
    path.chmod(0o700)
    return path, hashlib.sha256(content).hexdigest()


class SyntheticMacOSTools:
    """Capture fixed packaging inputs and synthesize bounded package outputs."""

    def __init__(self, *, fail: str | None = None, omit_output: bool = False) -> None:
        self.fail = fail
        self.omit_output = omit_output
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.plist: dict[str, Any] | None = None
        self.metadata: dict[str, Any] | None = None
        self.postinstall: str | None = None

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((command, kwargs))
        name = Path(command[0]).name
        if self.fail == name:
            return subprocess.CompletedProcess(command, 1, b"sensitive developer path", b"failure")
        if name == "pkgbuild":
            payload = Path(command[command.index("--root") + 1])
            scripts = Path(command[command.index("--scripts") + 1])
            plist_path = payload / "Library/LaunchDaemons/com.aai-security.endpoint-evidence.plist"
            metadata_path = (
                payload / "Library/Application Support/AAI Security/package-metadata.json"
            )
            self.plist = plistlib.loads(plist_path.read_bytes())
            self.metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.postinstall = (scripts / "postinstall").read_text(encoding="utf-8")
            if not self.omit_output:
                Path(command[-1]).write_bytes(b"synthetic-unsigned-package")
        elif name == "productsign":
            Path(command[-1]).write_bytes(b"signed:" + Path(command[-2]).read_bytes())
        return subprocess.CompletedProcess(command, 0, b"", b"")


def _tools(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        _executable(tmp_path / "pkgbuild")[0],
        _executable(tmp_path / "productsign")[0],
        _executable(tmp_path / "pkgutil")[0],
    )


def test_builds_secret_free_shellless_launchd_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    sensor, digest = _executable(tmp_path / "sensor")
    pkgbuild, productsign, pkgutil = _tools(tmp_path)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o700)
    output = output_directory / "aai-endpoint-evidence.pkg"
    tools = SyntheticMacOSTools()
    monkeypatch.setenv("SYNTHETIC_SECRET_MUST_NOT_REACH_TOOL", "secret-value")

    result = module.build_package(
        sensor_executable=sensor,
        expected_sensor_sha256=digest,
        version="1.0.0",
        output=output,
        allow_unsigned=True,
        owner_uid=os.getuid(),
        system_name="Darwin",
        pkgbuild_path=pkgbuild,
        productsign_path=productsign,
        pkgutil_path=pkgutil,
        tool_owner_uid=os.getuid(),
        runner=tools,
    )

    assert result.signed is False
    assert result.sensor_sha256 == digest
    assert result.package_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert [Path(call[0][0]).name for call in tools.calls] == ["pkgbuild"]
    assert tools.plist is not None
    assert tools.plist["UserName"] == "root"
    assert tools.plist["StartInterval"] == 300
    assert tools.plist["EnvironmentVariables"] == {
        "TMPDIR": "/var/db/aai-security/endpoint-evidence/runtime"
    }
    assert tools.plist["ProgramArguments"] == [
        "/Library/Application Support/AAI Security/bin/aai-endpoint-evidence",
        "--manifest",
        "/Library/Application Support/AAI Security/config/endpoint-evidence-manifest.json",
        "--key-id-file",
        "/Library/Application Support/AAI Security/config/endpoint-evidence-key-id",
        "--secret-file",
        "/Library/Application Support/AAI Security/config/endpoint-evidence.key",
        "--output",
        "/var/db/aai-security/endpoint-evidence/report.json",
    ]
    assert all("secret-value" not in str(value) for value in tools.plist.values())
    assert tools.metadata == {
        "schemaVersion": 1,
        "identifier": "com.aai-security.endpoint-evidence",
        "version": "1.0.0",
        "sensorSha256": digest,
        "launchdLabel": "com.aai-security.endpoint-evidence",
        "collectionIntervalSeconds": 300,
        "credentialsIncluded": False,
    }
    assert tools.postinstall is not None
    assert "$" not in tools.postinstall and "`" not in tools.postinstall
    for _command, kwargs in tools.calls:
        assert kwargs["env"] == {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
        }
        assert kwargs["timeout"] == 120
        assert "shell" not in kwargs


def test_signed_build_uses_fixed_productsign_and_verifies_the_result(tmp_path: Path) -> None:
    module = _module()
    sensor, digest = _executable(tmp_path / "sensor")
    pkgbuild, productsign, pkgutil = _tools(tmp_path)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o700)
    output = output_directory / "aai-endpoint-evidence.pkg"
    tools = SyntheticMacOSTools()

    result = module.build_package(
        sensor_executable=sensor,
        expected_sensor_sha256=digest,
        version="1.0.1",
        output=output,
        signing_identity="Developer ID Installer: Synthetic Example (AAAAAAAAAA)",
        owner_uid=os.getuid(),
        system_name="Darwin",
        pkgbuild_path=pkgbuild,
        productsign_path=productsign,
        pkgutil_path=pkgutil,
        tool_owner_uid=os.getuid(),
        runner=tools,
    )

    assert result.signed is True
    assert output.read_bytes() == b"signed:synthetic-unsigned-package"
    assert [Path(call[0][0]).name for call in tools.calls] == [
        "pkgbuild",
        "productsign",
        "pkgutil",
    ]
    assert tools.calls[1][0][1:3] == [
        "--sign",
        "Developer ID Installer: Synthetic Example (AAAAAAAAAA)",
    ]
    assert tools.calls[2][0][1] == "--check-signature"


@pytest.mark.parametrize(
    ("version", "interval"),
    [("1", 300), ("1.0-beta", 300), ("1.0.0", 299), ("1.0.0", 3_601)],
)
def test_rejects_ambiguous_version_or_schedule(tmp_path: Path, version: str, interval: int) -> None:
    module = _module()
    sensor, digest = _executable(tmp_path / "sensor")
    pkgbuild, productsign, pkgutil = _tools(tmp_path)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o700)
    with pytest.raises(module.MacOSEndpointPackageError):
        module.build_package(
            sensor_executable=sensor,
            expected_sensor_sha256=digest,
            version=version,
            output=output_directory / "sensor.pkg",
            interval_seconds=interval,
            allow_unsigned=True,
            owner_uid=os.getuid(),
            system_name="Darwin",
            pkgbuild_path=pkgbuild,
            productsign_path=productsign,
            pkgutil_path=pkgutil,
            tool_owner_uid=os.getuid(),
        )


def test_rejects_tampered_sensor_existing_output_and_non_macos_host(tmp_path: Path) -> None:
    module = _module()
    sensor, digest = _executable(tmp_path / "sensor")
    pkgbuild, productsign, pkgutil = _tools(tmp_path)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o700)
    output = output_directory / "sensor.pkg"
    common = {
        "sensor_executable": sensor,
        "expected_sensor_sha256": digest,
        "version": "1.0.0",
        "output": output,
        "allow_unsigned": True,
        "owner_uid": os.getuid(),
        "system_name": "Darwin",
        "pkgbuild_path": pkgbuild,
        "productsign_path": productsign,
        "pkgutil_path": pkgutil,
        "tool_owner_uid": os.getuid(),
    }
    sensor.write_bytes(b"changed")
    with pytest.raises(module.MacOSEndpointPackageError, match="digest"):
        module.build_package(**common)
    sensor.write_bytes(b"synthetic sensor executable")
    output.write_bytes(b"existing")
    with pytest.raises(module.MacOSEndpointPackageError, match="must not already exist"):
        module.build_package(**common)
    output.unlink()
    with pytest.raises(module.MacOSEndpointPackageError, match="macOS host"):
        module.build_package(**{**common, "system_name": "Linux"})


def test_rejects_symlinked_sensor_insecure_output_and_implicit_unsigned_build(
    tmp_path: Path,
) -> None:
    module = _module()
    target, digest = _executable(tmp_path / "sensor-target")
    sensor = tmp_path / "sensor"
    sensor.symlink_to(target)
    pkgbuild, productsign, pkgutil = _tools(tmp_path)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o777)
    common = {
        "sensor_executable": sensor,
        "expected_sensor_sha256": digest,
        "version": "1.0.0",
        "output": output_directory / "sensor.pkg",
        "owner_uid": os.getuid(),
        "system_name": "Darwin",
        "pkgbuild_path": pkgbuild,
        "productsign_path": productsign,
        "pkgutil_path": pkgutil,
        "tool_owner_uid": os.getuid(),
    }
    with pytest.raises(module.MacOSEndpointPackageError, match="signing identity"):
        module.build_package(**common)
    with pytest.raises(module.MacOSEndpointPackageError, match="not protected"):
        module.build_package(**{**common, "allow_unsigned": True})
    output_directory.chmod(0o700)
    with pytest.raises(module.MacOSEndpointPackageError, match="executable is not protected"):
        module.build_package(**{**common, "allow_unsigned": True})


@pytest.mark.parametrize(
    ("failure", "message"), [("pkgbuild", "tool failed"), (None, "did not create")]
)
def test_packaging_failure_or_missing_output_fails_closed(
    tmp_path: Path, failure: str | None, message: str
) -> None:
    module = _module()
    sensor, digest = _executable(tmp_path / "sensor")
    pkgbuild, productsign, pkgutil = _tools(tmp_path)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o700)
    tools = SyntheticMacOSTools(fail=failure, omit_output=failure is None)
    with pytest.raises(module.MacOSEndpointPackageError, match=message):
        module.build_package(
            sensor_executable=sensor,
            expected_sensor_sha256=digest,
            version="1.0.0",
            output=output_directory / "sensor.pkg",
            allow_unsigned=True,
            owner_uid=os.getuid(),
            system_name="Darwin",
            pkgbuild_path=pkgbuild,
            productsign_path=productsign,
            pkgutil_path=pkgutil,
            tool_owner_uid=os.getuid(),
            runner=tools,
        )


def test_cli_requires_explicit_package_signing_posture() -> None:
    module = _module()
    parser = module._parser()
    options = {option for action in parser._actions for option in action.option_strings}
    assert {"--signing-identity", "--allow-unsigned"}.issubset(options)
    assert "--secret" not in options
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--sensor-executable",
                "/synthetic/sensor",
                "--expected-sensor-sha256",
                "a" * 64,
                "--version",
                "1.0.0",
                "--output",
                "/synthetic/sensor.pkg",
            ]
        )


def test_cli_preserves_and_rejects_a_symlinked_sensor(tmp_path: Path) -> None:
    module = _module()
    target, digest = _executable(tmp_path / "sensor-target")
    sensor = tmp_path / "sensor-link"
    sensor.symlink_to(target)
    output_directory = tmp_path / "output"
    output_directory.mkdir(mode=0o700)

    assert (
        module.main(
            [
                "--sensor-executable",
                str(sensor),
                "--expected-sensor-sha256",
                digest,
                "--version",
                "1.0.0",
                "--allow-unsigned",
                "--output",
                str(output_directory / "sensor.pkg"),
            ]
        )
        == 2
    )

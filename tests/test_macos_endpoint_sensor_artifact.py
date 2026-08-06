"""Adversarial contracts for standalone macOS endpoint sensor artifacts."""

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
    path = Path(__file__).parents[1] / "scripts" / "build_macos_endpoint_sensor_artifact.py"
    spec = importlib.util.spec_from_file_location("aai_macos_sensor_artifact", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _file(path: Path, content: bytes = b"synthetic content", mode: int = 0o700) -> Path:
    path.write_bytes(content)
    path.chmod(mode)
    return path


def _tools(tmp_path: Path) -> tuple[Path, Path]:
    return _file(tmp_path / "lipo"), _file(tmp_path / "codesign")


class SyntheticArtifactTools:
    """Create a synthetic frozen executable and return fixed inspection evidence."""

    def __init__(
        self,
        *,
        architecture: str = "arm64",
        authority: str | None = None,
        fail_command: str | None = None,
        complete_help: bool = True,
    ) -> None:
        self.architecture = architecture
        self.authority = authority
        self.fail_command = fail_command
        self.complete_help = complete_help
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((command, kwargs))
        if "PyInstaller" in command:
            label = "pyinstaller"
        elif Path(command[0]).name == "lipo":
            label = "lipo"
        elif Path(command[0]).name == "codesign" and "--entitlements" in command:
            label = "codesign-entitlements"
        elif Path(command[0]).name == "codesign" and "--display" in command:
            label = "codesign-display"
        elif Path(command[0]).name == "codesign":
            label = "codesign-verify"
        else:
            label = "help"
        if self.fail_command == label:
            return subprocess.CompletedProcess(command, 1, b"", b"synthetic failure")
        if label == "pyinstaller":
            dist = Path(command[command.index("--distpath") + 1])
            name = command[command.index("--name") + 1]
            dist.mkdir(parents=True)
            _file(dist / name, b"synthetic frozen endpoint sensor")
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if label == "lipo":
            return subprocess.CompletedProcess(command, 0, f"{self.architecture}\n".encode(), b"")
        if label == "codesign-display":
            details = (
                "Signature=adhoc\nTeamIdentifier=not set\n"
                if self.authority is None
                else f"Authority={self.authority}\nTeamIdentifier=AAAAAAAAAA\n"
            )
            return subprocess.CompletedProcess(command, 0, b"", details.encode())
        if label == "codesign-entitlements":
            entitlements = (
                {"com.apple.security.cs.disable-library-validation": True}
                if self.authority is None
                else {}
            )
            return subprocess.CompletedProcess(
                command,
                0,
                plistlib.dumps(entitlements, fmt=plistlib.FMT_XML, sort_keys=True),
                b"",
            )
        if label == "help":
            help_text = (
                b"--manifest --key-id-file --secret-file --output"
                if self.complete_help
                else b"--manifest"
            )
            return subprocess.CompletedProcess(command, 0, help_text, b"")
        return subprocess.CompletedProcess(command, 0, b"", b"")


def _versions(name: str) -> str:
    return {"pyinstaller": "6.21.0", "psutil": "7.2.2"}[name]


def _build(
    module: Any,
    tmp_path: Path,
    *,
    tools: SyntheticArtifactTools | None = None,
    developer_id: bool = False,
) -> tuple[Any, Path, SyntheticArtifactTools, Path, Path]:
    source = _file(tmp_path / "collect_endpoint_evidence.py", b"synthetic sensor source", 0o600)
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    output = output_parent / "sensor-arm64"
    lipo, codesign = _tools(tmp_path)
    runner = tools or SyntheticArtifactTools(
        authority="Developer ID Application: Synthetic Vendor (AAAAAAAAAA)"
        if developer_id
        else None
    )
    result = module.build_artifact(
        source=source,
        expected_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        expected_python_version=module.platform.python_version(),
        version="1.1.0",
        source_commit="a" * 40,
        architecture="arm64",
        output_directory=output,
        codesign_identity="Developer ID Application: Synthetic Vendor (AAAAAAAAAA)"
        if developer_id
        else None,
        allow_adhoc=not developer_id,
        owner_uid=os.getuid(),
        system_name="Darwin",
        python_executable=tmp_path / "python",
        lipo_path=lipo,
        codesign_path=codesign,
        tool_owner_uid=os.getuid(),
        runner=runner,
        version_reader=_versions,
    )
    return result, output, runner, lipo, codesign


def test_builds_and_independently_verifies_closed_adhoc_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setenv("SYNTHETIC_SECRET_MUST_NOT_REACH_BUILD", "secret-value")
    result, output, tools, lipo, codesign = _build(module, tmp_path)

    assert result.signing_mode == "adhoc"
    assert {item.name for item in output.iterdir()} == {
        "aai-endpoint-evidence",
        "artifact-manifest.json",
    }
    manifest = json.loads((output / "artifact-manifest.json").read_text(encoding="utf-8"))
    assert manifest == {
        "schemaVersion": 1,
        "artifactType": "endpoint-evidence-sensor",
        "version": "1.1.0",
        "sourceCommit": "a" * 40,
        "sourceSha256": hashlib.sha256(b"synthetic sensor source").hexdigest(),
        "architecture": "arm64",
        "pythonVersion": module.platform.python_version(),
        "pyinstallerVersion": "6.21.0",
        "psutilVersion": "7.2.2",
        "signingMode": "adhoc",
        "signingIdentitySha256": None,
        "libraryValidationDisabled": True,
        "executableName": "aai-endpoint-evidence",
        "executableSha256": hashlib.sha256(b"synthetic frozen endpoint sensor").hexdigest(),
        "executableSizeBytes": len(b"synthetic frozen endpoint sensor"),
    }
    assert output.stat().st_mode & 0o077 == 0
    assert (output / "artifact-manifest.json").stat().st_mode & 0o077 == 0
    assert (output / "aai-endpoint-evidence").stat().st_mode & 0o077 == 0
    pyinstaller = next(call for call in tools.calls if "PyInstaller" in call[0])
    assert pyinstaller[0][1:4] == ["-I", "-m", "PyInstaller"]
    assert "--onefile" in pyinstaller[0]
    assert pyinstaller[0][pyinstaller[0].index("--codesign-identity") + 1] == "-"
    assert "--osx-entitlements-file" in pyinstaller[0]
    for _command, kwargs in tools.calls:
        assert "SYNTHETIC_SECRET_MUST_NOT_REACH_BUILD" not in kwargs["env"]
        assert "shell" not in kwargs

    verified = module.verify_artifact(
        artifact_directory=output,
        expected_manifest_sha256=result.manifest_sha256,
        expected_version="1.1.0",
        expected_source_commit="a" * 40,
        expected_source_sha256=manifest["sourceSha256"],
        expected_python_version=module.platform.python_version(),
        expected_architecture="arm64",
        allow_adhoc=True,
        owner_uid=os.getuid(),
        system_name="Darwin",
        lipo_path=lipo,
        codesign_path=codesign,
        tool_owner_uid=os.getuid(),
        runner=tools,
    )
    assert verified == result
    smoke_environments = [
        kwargs["env"]
        for command, kwargs in tools.calls
        if Path(command[0]).name == "aai-endpoint-evidence"
    ]
    assert smoke_environments and all(
        environment["TMPDIR"] != "/private/tmp" for environment in smoke_environments
    )


def test_developer_id_identity_is_measured_and_must_be_independently_bound(tmp_path: Path) -> None:
    module = _module()
    result, output, tools, lipo, codesign = _build(module, tmp_path, developer_id=True)
    expected = hashlib.sha256(
        b"Developer ID Application: Synthetic Vendor (AAAAAAAAAA)"
    ).hexdigest()
    assert result.signing_mode == "developer-id"
    assert result.signing_identity_sha256 == expected
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="independently bound"):
        module.verify_artifact(
            artifact_directory=output,
            expected_manifest_sha256=result.manifest_sha256,
            expected_version="1.1.0",
            expected_source_commit="a" * 40,
            expected_source_sha256=hashlib.sha256(b"synthetic sensor source").hexdigest(),
            expected_python_version=module.platform.python_version(),
            expected_architecture="arm64",
            owner_uid=os.getuid(),
            system_name="Darwin",
            lipo_path=lipo,
            codesign_path=codesign,
            tool_owner_uid=os.getuid(),
            runner=tools,
        )
    verified = module.verify_artifact(
        artifact_directory=output,
        expected_manifest_sha256=result.manifest_sha256,
        expected_version="1.1.0",
        expected_source_commit="a" * 40,
        expected_source_sha256=hashlib.sha256(b"synthetic sensor source").hexdigest(),
        expected_python_version=module.platform.python_version(),
        expected_architecture="arm64",
        expected_signing_identity_sha256=expected,
        owner_uid=os.getuid(),
        system_name="Darwin",
        lipo_path=lipo,
        codesign_path=codesign,
        tool_owner_uid=os.getuid(),
        runner=tools,
    )
    assert verified.signing_identity_sha256 == expected


@pytest.mark.parametrize(
    ("source_sha256", "python_version"),
    [("0" * 64, None), (None, "0.0.0")],
)
def test_verifier_requires_independent_source_and_python_identity(
    tmp_path: Path, source_sha256: str | None, python_version: str | None
) -> None:
    module = _module()
    result, output, tools, lipo, codesign = _build(module, tmp_path)
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="release identity"):
        module.verify_artifact(
            artifact_directory=output,
            expected_manifest_sha256=result.manifest_sha256,
            expected_version="1.1.0",
            expected_source_commit="a" * 40,
            expected_source_sha256=source_sha256 or result.source_sha256,
            expected_python_version=python_version or module.platform.python_version(),
            expected_architecture="arm64",
            allow_adhoc=True,
            owner_uid=os.getuid(),
            system_name="Darwin",
            lipo_path=lipo,
            codesign_path=codesign,
            tool_owner_uid=os.getuid(),
            runner=tools,
        )


@pytest.mark.parametrize(
    ("version", "commit", "architecture"),
    [("1", "a" * 40, "arm64"), ("1.0.0", "A" * 40, "arm64"), ("1.0.0", "a" * 40, "universal2")],
)
def test_rejects_malformed_release_identity(
    tmp_path: Path, version: str, commit: str, architecture: str
) -> None:
    module = _module()
    source = _file(tmp_path / "source", mode=0o600)
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="release identity"):
        module.build_artifact(
            source=source,
            expected_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            expected_python_version=module.platform.python_version(),
            version=version,
            source_commit=commit,
            architecture=architecture,
            output_directory=output_parent / "artifact",
            allow_adhoc=True,
            system_name="Darwin",
        )


def test_rejects_source_symlink_digest_change_and_insecure_output(tmp_path: Path) -> None:
    module = _module()
    source = _file(tmp_path / "source", mode=0o600)
    link = tmp_path / "source-link"
    link.symlink_to(source)
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    common = {
        "expected_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "expected_python_version": module.platform.python_version(),
        "version": "1.1.0",
        "source_commit": "a" * 40,
        "architecture": "arm64",
        "output_directory": output_parent / "artifact",
        "allow_adhoc": True,
        "owner_uid": os.getuid(),
        "system_name": "Darwin",
        "version_reader": _versions,
    }
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="not protected"):
        module.build_artifact(source=link, **common)
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="digest"):
        module.build_artifact(source=source, **{**common, "expected_source_sha256": "0" * 64})
    output_parent.chmod(0o777)
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="parent"):
        module.build_artifact(source=source, **common)


def test_rejects_implicit_adhoc_wrong_dependencies_and_non_macos(tmp_path: Path) -> None:
    module = _module()
    source = _file(tmp_path / "source", mode=0o600)
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    common = {
        "source": source,
        "expected_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "expected_python_version": module.platform.python_version(),
        "version": "1.1.0",
        "source_commit": "a" * 40,
        "architecture": "arm64",
        "output_directory": output_parent / "artifact",
        "owner_uid": os.getuid(),
    }
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="choose exactly"):
        module.build_artifact(**common, system_name="Darwin", version_reader=_versions)
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="exact-pinned"):
        module.build_artifact(
            **common,
            allow_adhoc=True,
            system_name="Darwin",
            version_reader=lambda name: "0.0.0",
        )
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match="macOS host"):
        module.build_artifact(
            **common,
            allow_adhoc=True,
            system_name="Linux",
            version_reader=_versions,
        )


@pytest.mark.parametrize(
    ("tools", "message"),
    [
        (SyntheticArtifactTools(architecture="x86_64"), "architecture does not match"),
        (SyntheticArtifactTools(fail_command="pyinstaller"), "tool failed"),
        (SyntheticArtifactTools(complete_help=False), "interface"),
    ],
)
def test_build_tool_failure_wrong_architecture_or_incomplete_interface_fails_closed(
    tmp_path: Path, tools: SyntheticArtifactTools, message: str
) -> None:
    module = _module()
    with pytest.raises(module.MacOSEndpointSensorArtifactError, match=message):
        _build(module, tmp_path, tools=tools)


@pytest.mark.parametrize("tamper", ["executable", "manifest", "extra"])
def test_verifier_rejects_tampered_or_open_generation(tmp_path: Path, tamper: str) -> None:
    module = _module()
    result, output, tools, lipo, codesign = _build(module, tmp_path)
    if tamper == "executable":
        (output / "aai-endpoint-evidence").write_bytes(b"changed")
        (output / "aai-endpoint-evidence").chmod(0o700)
    elif tamper == "manifest":
        (output / "artifact-manifest.json").write_text("{}", encoding="utf-8")
    else:
        (output / "unexpected").write_text("unexpected", encoding="utf-8")
    with pytest.raises(module.MacOSEndpointSensorArtifactError):
        module.verify_artifact(
            artifact_directory=output,
            expected_manifest_sha256=result.manifest_sha256,
            expected_version="1.1.0",
            expected_source_commit="a" * 40,
            expected_source_sha256=hashlib.sha256(b"synthetic sensor source").hexdigest(),
            expected_python_version=module.platform.python_version(),
            expected_architecture="arm64",
            allow_adhoc=True,
            owner_uid=os.getuid(),
            system_name="Darwin",
            lipo_path=lipo,
            codesign_path=codesign,
            tool_owner_uid=os.getuid(),
            runner=tools,
        )


def test_cli_preserves_and_rejects_symlinked_source(tmp_path: Path) -> None:
    module = _module()
    source = _file(tmp_path / "source", mode=0o600)
    link = tmp_path / "source-link"
    link.symlink_to(source)
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    assert (
        module.main(
            [
                "build",
                "--source",
                str(link),
                "--expected-source-sha256",
                hashlib.sha256(source.read_bytes()).hexdigest(),
                "--expected-python-version",
                module.platform.python_version(),
                "--version",
                "1.1.0",
                "--source-commit",
                "a" * 40,
                "--architecture",
                "arm64",
                "--output-directory",
                str(output_parent / "artifact"),
                "--allow-adhoc",
            ]
        )
        == 2
    )


def test_ci_builds_both_architectures_but_never_publishes_adhoc_as_release() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github/workflows/macos-sensor-artifact.yml"
    ).read_text(encoding="utf-8")
    assert "runner: macos-15\n            architecture: arm64" in workflow
    assert "runner: macos-15-intel\n            architecture: x86_64" in workflow
    assert "--allow-adhoc" in workflow
    assert "adhoc-test.tar.gz" in workflow
    assert "retention-days: 7" in workflow
    assert "tags:" not in workflow
    assert "gh release create" not in workflow
    assert "attest-build-provenance" not in workflow

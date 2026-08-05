"""Adversarial contracts for signed endpoint evidence and fleet assembly."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest


def _module(name: str) -> Any:
    path = Path(__file__).parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest(tmp_path: Path) -> tuple[Path, Path, Path]:
    project = tmp_path / "sensitive-project-name"
    project.mkdir()
    binary = tmp_path / "claude"
    binary.write_bytes(b"synthetic-binary")
    binary.chmod(0o755)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "device": {
                    "id": "device-a",
                    "managed": True,
                    "businessUnit": "Platform",
                    "userIds": ["user-a"],
                },
                "installations": [
                    {
                        "id": "installation-a",
                        "host": "claude-code",
                        "projectRoot": str(project),
                        "binaryPath": str(binary),
                        "expectedBinarySha256": (
                            "8b2e664a762d291b5a221ca716297f78e26854ecb308b502f09ea47dc3045b02"
                        ),
                        "processExecutablePaths": [str(binary)],
                        "userId": "user-a",
                        "repositoryId": "repository-a",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest, project, binary


def _report(tmp_path: Path, *, observed_at: int = 1_000) -> dict[str, Any]:
    module = _module("collect_endpoint_evidence")
    manifest, project, binary = _manifest(tmp_path)
    return cast(
        dict[str, Any],
        module.collect_signed_report(
            manifest,
            key_id="key-a",
            secret="a" * 32,
            observed_at=observed_at,
            administrator_check=lambda: True,
            manifest_security_check=lambda _path: None,
            process_reader=lambda: {(binary, project)},
            platform_reader=lambda: ("darwin", "arm64"),
        ),
    )


def _assembly_inputs(tmp_path: Path, report: dict[str, Any]) -> tuple[Path, Path, Path]:
    devices = tmp_path / "devices.json"
    devices.write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "kind": "device",
                        "id": "device-a",
                        "managed": True,
                        "businessUnit": "Platform",
                        "userIds": ["user-a"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "device-a.json").write_text(json.dumps(report), encoding="utf-8")
    key_map = tmp_path / "keys.json"
    key_map.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "keys": [
                    {
                        "keyId": "key-a",
                        "deviceId": "device-a",
                        "secretEnv": "SYNTHETIC_ENDPOINT_KEY_A",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return devices, reports, key_map


def test_sensor_emits_signed_path_free_binary_and_process_evidence(tmp_path: Path) -> None:
    report = _report(tmp_path)
    encoded = json.dumps(report)
    assert report["payload"]["schemaVersion"] == 2
    assert report["payload"]["device"]["operatingSystem"] == "darwin"
    assert report["payload"]["device"]["architecture"] == "arm64"
    assert report["payload"]["installations"][0]["binaryPresent"] is True
    assert report["payload"]["installations"][0]["processActive"] is True
    assert "sensitive-project-name" not in encoded
    assert str(tmp_path) not in encoded
    assert "a" * 32 not in encoded


def test_sensor_fails_without_admin_or_complete_process_visibility(tmp_path: Path) -> None:
    module = _module("collect_endpoint_evidence")
    manifest, _, _ = _manifest(tmp_path)
    with pytest.raises(module.EndpointEvidenceError, match="administrator"):
        module.collect_signed_report(
            manifest,
            key_id="key-a",
            secret="a" * 32,
            administrator_check=lambda: False,
            manifest_security_check=lambda _path: None,
        )
    with pytest.raises(module.EndpointEvidenceError, match="incomplete"):
        module.collect_signed_report(
            manifest,
            key_id="key-a",
            secret="a" * 32,
            administrator_check=lambda: True,
            manifest_security_check=lambda _path: None,
            process_reader=lambda: (_ for _ in ()).throw(
                module.EndpointEvidenceError("process inspection was incomplete")
            ),
        )


def test_sensor_rejects_an_unprotected_manifest_before_measurement(tmp_path: Path) -> None:
    module = _module("collect_endpoint_evidence")
    manifest, _, _ = _manifest(tmp_path)
    with pytest.raises(module.EndpointEvidenceError, match="root-owned"):
        module.collect_signed_report(
            manifest,
            key_id="key-a",
            secret="a" * 32,
            administrator_check=lambda: True,
            process_reader=lambda: set(),
        )
    target = tmp_path / "manifest-target.json"
    manifest.rename(target)
    manifest.symlink_to(target)
    with pytest.raises(module.EndpointEvidenceError, match="non-symlink"):
        module.collect_signed_report(
            manifest,
            key_id="key-a",
            secret="a" * 32,
            administrator_check=lambda: True,
            process_reader=lambda: set(),
        )


def test_sensor_rejects_symlink_and_changed_binary_as_present(tmp_path: Path) -> None:
    module = _module("collect_endpoint_evidence")
    manifest, _, binary = _manifest(tmp_path)
    binary.write_bytes(b"changed")
    report = module.collect_signed_report(
        manifest,
        key_id="key-a",
        secret="a" * 32,
        observed_at=1_000,
        administrator_check=lambda: True,
        manifest_security_check=lambda _path: None,
        process_reader=lambda: set(),
    )
    assert report["payload"]["installations"][0]["binaryPresent"] is False
    target = tmp_path / "target"
    binary.rename(target)
    binary.symlink_to(target)
    report = module.collect_signed_report(
        manifest,
        key_id="key-a",
        secret="a" * 32,
        observed_at=1_000,
        administrator_check=lambda: True,
        manifest_security_check=lambda _path: None,
        process_reader=lambda: set(),
    )
    assert report["payload"]["installations"][0]["binaryPresent"] is False


def test_sensor_process_evidence_requires_exact_project_and_rejects_hidden_attributes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module("collect_endpoint_evidence")
    manifest, project, binary = _manifest(tmp_path)
    other_project = tmp_path / "other-project"
    other_project.mkdir()
    report = module.collect_signed_report(
        manifest,
        key_id="key-a",
        secret="a" * 32,
        observed_at=1_000,
        administrator_check=lambda: True,
        manifest_security_check=lambda _path: None,
        process_reader=lambda: {(binary, other_project)},
    )
    assert report["payload"]["installations"][0]["processActive"] is False

    class SyntheticProcessError(Exception):
        pass

    def hidden_processes(*, attrs: tuple[str, ...], ad_value: object) -> list[Any]:
        assert attrs == ("exe", "cwd")
        return [SimpleNamespace(info={"exe": ad_value, "cwd": str(project)})]

    monkeypatch.setitem(
        sys.modules,
        "psutil",
        SimpleNamespace(
            process_iter=hidden_processes,
            AccessDenied=SyntheticProcessError,
            Error=SyntheticProcessError,
        ),
    )
    with pytest.raises(module.EndpointEvidenceError, match="incomplete"):
        module._running_processes()


def test_fleet_assembly_verifies_signature_freshness_and_mdm_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module("assemble_endpoint_inventory")
    report = _report(tmp_path)
    devices, reports, key_map = _assembly_inputs(tmp_path, report)
    monkeypatch.setenv("SYNTHETIC_ENDPOINT_KEY_A", "a" * 32)
    result = module.assemble_inventory(
        device_inventory_path=devices,
        reports_directory=reports,
        key_map_path=key_map,
        now=1_100,
        max_age_seconds=300,
    )
    expected_device = {
        key: value
        for key, value in report["payload"]["device"].items()
        if key not in {"operatingSystem", "architecture"}
    }
    assert result["devices"] == [expected_device]
    assert result["installations"] == report["payload"]["installations"]


@pytest.mark.parametrize("mutation", ["payload", "signature", "binding"])
def test_fleet_assembly_rejects_tamper_and_cross_device_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    module = _module("assemble_endpoint_inventory")
    report = _report(tmp_path)
    devices, reports, key_map = _assembly_inputs(tmp_path, report)
    monkeypatch.setenv("SYNTHETIC_ENDPOINT_KEY_A", "a" * 32)
    if mutation == "payload":
        report["payload"]["installations"][0]["processActive"] = False
        (reports / "device-a.json").write_text(json.dumps(report), encoding="utf-8")
    elif mutation == "signature":
        report["signature"] = "0" * 64
        (reports / "device-a.json").write_text(json.dumps(report), encoding="utf-8")
    else:
        value = json.loads(key_map.read_text(encoding="utf-8"))
        value["keys"][0]["deviceId"] = "device-b"
        key_map.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(module.EndpointAssemblyError):
        module.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=key_map,
            now=1_100,
            max_age_seconds=300,
        )


def test_fleet_assembly_rejects_stale_revoked_and_duplicate_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module("assemble_endpoint_inventory")
    report = _report(tmp_path)
    devices, reports, key_map = _assembly_inputs(tmp_path, report)
    monkeypatch.setenv("SYNTHETIC_ENDPOINT_KEY_A", "a" * 32)
    with pytest.raises(module.EndpointAssemblyError, match="stale"):
        module.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=key_map,
            now=2_000,
            max_age_seconds=300,
        )
    value = json.loads(key_map.read_text(encoding="utf-8"))
    value["keys"][0]["revoked"] = True
    key_map.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(module.EndpointAssemblyError, match="revoked"):
        module.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=key_map,
            now=1_100,
            max_age_seconds=300,
        )
    value["keys"][0].pop("revoked")
    key_map.write_text(json.dumps(value), encoding="utf-8")
    (reports / "duplicate.json").write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(module.EndpointAssemblyError, match="at most one"):
        module.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=key_map,
            now=1_100,
            max_age_seconds=300,
        )


def test_fleet_assembly_rejects_signed_unknown_content_and_unexpected_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sensor = _module("collect_endpoint_evidence")
    assembly = _module("assemble_endpoint_inventory")
    report = _report(tmp_path)
    report["payload"]["installations"][0]["rawProjectPath"] = "/sensitive/project"
    report["signature"] = hmac.new(
        ("a" * 32).encode(),
        sensor._canonical(report["payload"]),
        hashlib.sha256,
    ).hexdigest()
    devices, reports, key_map = _assembly_inputs(tmp_path, report)
    monkeypatch.setenv("SYNTHETIC_ENDPOINT_KEY_A", "a" * 32)
    with pytest.raises(assembly.EndpointAssemblyError, match="installation"):
        assembly.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=key_map,
            now=1_100,
            max_age_seconds=300,
        )
    (reports / "ignored.txt").write_text("must not be ignored", encoding="utf-8")
    with pytest.raises(assembly.EndpointAssemblyError, match="unexpected entry"):
        assembly.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=key_map,
            now=1_100,
            max_age_seconds=300,
        )


def test_assembled_output_is_accepted_by_existing_endpoint_normalizer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assembly = _module("assemble_endpoint_inventory")
    collector = _module("collect_discovery_inventory")
    report = _report(tmp_path)
    devices, reports, key_map = _assembly_inputs(tmp_path, report)
    monkeypatch.setenv("SYNTHETIC_ENDPOINT_KEY_A", "a" * 32)
    output = assembly.assemble_inventory(
        device_inventory_path=devices,
        reports_directory=reports,
        key_map_path=key_map,
        now=1_100,
        max_age_seconds=300,
    )
    path = tmp_path / "endpoint-export.json"
    path.write_text(json.dumps(output), encoding="utf-8")
    observations = collector.collect_endpoint_export(path)
    assert {item["kind"] for item in observations} == {"device", "installation"}
    assert all(str(tmp_path) not in json.dumps(item) for item in observations)


def test_key_map_never_accepts_embedded_secret(tmp_path: Path) -> None:
    module = _module("assemble_endpoint_inventory")
    key_map = tmp_path / "keys.json"
    key_map.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "keys": [
                    {
                        "keyId": "key-a",
                        "deviceId": "device-a",
                        "secretEnv": "SYNTHETIC_ENDPOINT_KEY_A",
                        "secret": "must-not-be-here",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(module.EndpointAssemblyError, match="binding"):
        module._key_map(key_map)


def test_sensor_cli_does_not_accept_a_plaintext_secret_flag() -> None:
    module = _module("collect_endpoint_evidence")
    actions = {option for action in module._parser()._actions for option in action.option_strings}
    assert "--secret" not in actions
    assert "AAI_ENDPOINT_EVIDENCE_KEY" not in os.environ

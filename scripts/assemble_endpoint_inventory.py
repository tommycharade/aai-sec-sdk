#!/usr/bin/env python3
"""Assemble authenticated endpoint reports into one atomic fleet inventory input."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_MAX_REPORTS = 2_000
_MAX_REPORT_BYTES = 1_000_000
_IDENTIFIER_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)
_SUPPORTED_HOSTS = frozenset({"claude-code", "codex-cli"})
_SUPPORTED_OPERATING_SYSTEMS = frozenset({"darwin", "linux", "windows"})
_SUPPORTED_ARCHITECTURES = frozenset({"arm64", "x86_64"})


class EndpointAssemblyError(RuntimeError):
    """Report a bounded key, report, freshness or fleet-consistency failure."""


def _read_json(path: Path, label: str, *, maximum_bytes: int = _MAX_REPORT_BYTES) -> Any:
    """Read one bounded JSON document."""
    try:
        if path.stat().st_size > maximum_bytes:
            raise EndpointAssemblyError(f"{label} exceeds its size limit")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EndpointAssemblyError(f"could not read {label}: {error}") from error


def _canonical(value: dict[str, Any]) -> bytes:
    """Encode one report payload exactly as the endpoint sensor signs it."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _identifier(value: Any, label: str) -> str:
    """Return one bounded opaque identifier."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(character not in _IDENTIFIER_CHARACTERS for character in value)
    ):
        raise EndpointAssemblyError(f"{label} is invalid")
    return value


def _device(value: Any) -> dict[str, Any]:
    """Validate one authoritative content-minimised device object."""
    if (
        not isinstance(value, dict)
        or not {"id", "managed"}.issubset(value)
        or set(value)
        - {
            "id",
            "managed",
            "businessUnit",
            "userIds",
        }
    ):
        raise EndpointAssemblyError("authoritative device observation is invalid")
    result: dict[str, Any] = {
        "id": _identifier(value.get("id"), "device id"),
        "managed": value.get("managed"),
    }
    if not isinstance(result["managed"], bool):
        raise EndpointAssemblyError("authoritative device managed state is invalid")
    if "businessUnit" in value:
        result["businessUnit"] = _identifier(value["businessUnit"], "businessUnit")
    users = value.get("userIds", [])
    if not isinstance(users, list) or len(users) > 20:
        raise EndpointAssemblyError("authoritative device userIds are invalid")
    result["userIds"] = sorted(_identifier(item, "userId") for item in users)
    if len(result["userIds"]) != len(set(result["userIds"])):
        raise EndpointAssemblyError("authoritative device userIds must be unique")
    return result


def _installation(value: Any, device_id: str) -> dict[str, Any]:
    """Validate signed evidence without accepting path or process content."""
    required = {
        "id",
        "deviceId",
        "host",
        "projectRootDigest",
        "binaryPresent",
        "processActive",
    }
    allowed = required | {"userId", "repositoryId", "businessUnit"}
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - allowed:
        raise EndpointAssemblyError("endpoint report installation is invalid")
    if value.get("deviceId") != device_id or value.get("host") not in _SUPPORTED_HOSTS:
        raise EndpointAssemblyError("endpoint report installation is invalid")
    digest = value.get("projectRootDigest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not isinstance(value.get("binaryPresent"), bool)
        or not isinstance(value.get("processActive"), bool)
    ):
        raise EndpointAssemblyError("endpoint report installation evidence is invalid")
    result: dict[str, Any] = {
        "id": _identifier(value.get("id"), "installation id"),
        "deviceId": device_id,
        "host": value["host"],
        "projectRootDigest": digest,
        "binaryPresent": value["binaryPresent"],
        "processActive": value["processActive"],
    }
    for field in ("userId", "repositoryId", "businessUnit"):
        if field in value:
            result[field] = _identifier(value[field], field)
    return result


def _device_inventory(path: Path) -> dict[str, dict[str, Any]]:
    """Read an exact normalized authoritative MDM device inventory."""
    value = _read_json(path, "device inventory", maximum_bytes=5_000_000)
    if isinstance(value, dict) and set(value) == {"observations"}:
        value = value["observations"]
    if not isinstance(value, list) or not value:
        raise EndpointAssemblyError("device inventory must be a non-empty observation array")
    devices: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict) or item.get("kind") != "device":
            raise EndpointAssemblyError("authoritative device observation is invalid")
        normalized = _device({key: item[key] for key in item if key != "kind"})
        if normalized["id"] in devices:
            raise EndpointAssemblyError("authoritative device identities must be unique")
        devices[normalized["id"]] = normalized
    return devices


def _key_map(path: Path) -> dict[str, dict[str, Any]]:
    """Read key-to-device bindings without accepting secret material in the file."""
    value = _read_json(path, "endpoint key map")
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "keys"}:
        raise EndpointAssemblyError("endpoint key map has an invalid schema")
    if value["schemaVersion"] != 1 or not isinstance(value["keys"], list):
        raise EndpointAssemblyError("endpoint key map schema version or keys are invalid")
    result: dict[str, dict[str, Any]] = {}
    devices: set[str] = set()
    for item in value["keys"]:
        if (
            not isinstance(item, dict)
            or set(item)
            not in (
                {"keyId", "deviceId", "secretEnv"},
                {"keyId", "deviceId", "secretEnv", "revoked"},
            )
            or not all(
                isinstance(item.get(field), str) and item[field]
                for field in ("keyId", "deviceId", "secretEnv")
            )
            or ("revoked" in item and not isinstance(item["revoked"], bool))
        ):
            raise EndpointAssemblyError("endpoint key binding is invalid")
        key_id = _identifier(item["keyId"], "keyId")
        device_id = _identifier(item["deviceId"], "deviceId")
        secret_environment = item["secretEnv"]
        if (
            not secret_environment[0].isalpha()
            or not secret_environment.replace("_", "A").isalnum()
        ):
            raise EndpointAssemblyError("endpoint key secretEnv is invalid")
        if key_id in result or device_id in devices:
            raise EndpointAssemblyError("endpoint key and device bindings must be unique")
        result[key_id] = {**item, "keyId": key_id, "deviceId": device_id}
        devices.add(device_id)
    return result


def assemble_inventory(
    *,
    device_inventory_path: Path,
    reports_directory: Path,
    key_map_path: Path,
    now: int | None = None,
    max_age_seconds: int = 3_600,
) -> dict[str, list[dict[str, Any]]]:
    """Verify every report and return one complete endpoint export."""
    current_time = int(time.time()) if now is None else now
    if isinstance(current_time, bool) or current_time < 0:
        raise EndpointAssemblyError("current time must be a non-negative integer")
    if isinstance(max_age_seconds, bool) or not 60 <= max_age_seconds <= 86_400:
        raise EndpointAssemblyError("maximum report age must be between 60 and 86400 seconds")
    devices = _device_inventory(device_inventory_path)
    bindings = _key_map(key_map_path)
    try:
        entries = sorted(reports_directory.iterdir())
    except OSError as error:
        raise EndpointAssemblyError(f"could not read endpoint reports: {error}") from error
    if any(path.suffix != ".json" or path.is_symlink() or not path.is_file() for path in entries):
        raise EndpointAssemblyError("endpoint report directory contains an unexpected entry")
    report_paths = entries
    if not report_paths or len(report_paths) > _MAX_REPORTS:
        raise EndpointAssemblyError("endpoint report set must contain 1 to 2000 JSON reports")
    reports_seen: set[str] = set()
    installation_ids: set[str] = set()
    installations: list[dict[str, Any]] = []
    for report_path in report_paths:
        report = _read_json(report_path, "endpoint report")
        if not isinstance(report, dict) or set(report) != {"keyId", "payload", "signature"}:
            raise EndpointAssemblyError("endpoint report has an invalid envelope")
        key_id = report.get("keyId")
        signature = report.get("signature")
        payload = report.get("payload")
        binding = bindings.get(key_id) if isinstance(key_id, str) else None
        if not binding or binding.get("revoked") is True:
            raise EndpointAssemblyError("endpoint report key is unknown or revoked")
        if not isinstance(signature, str) or len(signature) != 64 or not isinstance(payload, dict):
            raise EndpointAssemblyError("endpoint report signature or payload is invalid")
        secret = os.environ.get(binding["secretEnv"], "")
        if len(secret.encode()) < 32:
            raise EndpointAssemblyError("endpoint report secret is unavailable")
        expected = hmac.new(secret.encode(), _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise EndpointAssemblyError("endpoint report signature is invalid")
        if set(payload) != {
            "schemaVersion",
            "observedAt",
            "device",
            "installations",
        } or payload.get("schemaVersion") not in {1, 2}:
            raise EndpointAssemblyError("endpoint report payload has an invalid schema")
        observed_at = payload.get("observedAt")
        if (
            isinstance(observed_at, bool)
            or not isinstance(observed_at, int)
            or not current_time - max_age_seconds <= observed_at <= current_time + 60
        ):
            raise EndpointAssemblyError("endpoint report is stale or from the future")
        device = payload.get("device")
        report_installations = payload.get("installations")
        if not isinstance(device, dict) or not isinstance(report_installations, list):
            raise EndpointAssemblyError("endpoint report device or installations are invalid")
        device_for_inventory = dict(device)
        if payload["schemaVersion"] == 2:
            operating_system = device_for_inventory.pop("operatingSystem", None)
            architecture = device_for_inventory.pop("architecture", None)
            if (
                operating_system not in _SUPPORTED_OPERATING_SYSTEMS
                or architecture not in _SUPPORTED_ARCHITECTURES
            ):
                raise EndpointAssemblyError("endpoint report platform is unsupported")
        normalized_device = _device(device_for_inventory)
        device_id = normalized_device["id"]
        if device_id != binding["deviceId"] or device_id not in devices:
            raise EndpointAssemblyError("endpoint report is not bound to an authoritative device")
        if device_id in reports_seen:
            raise EndpointAssemblyError("endpoint devices must have at most one current report")
        reports_seen.add(device_id)
        expected_device = devices[device_id]
        if normalized_device != expected_device:
            raise EndpointAssemblyError(
                "endpoint report device metadata differs from MDM authority"
            )
        if not 1 <= len(report_installations) <= 100:
            raise EndpointAssemblyError("endpoint report installation count is invalid")
        for installation_value in report_installations:
            installation = _installation(installation_value, device_id)
            installation_id = installation["id"]
            if installation_id in installation_ids:
                raise EndpointAssemblyError("endpoint installation identities must be unique")
            installation_ids.add(installation_id)
            installations.append(installation)
    return {
        "devices": [devices[identifier] for identifier in sorted(devices)],
        "installations": sorted(installations, key=lambda item: item["id"]),
    }


def _parser() -> argparse.ArgumentParser:
    """Build the fleet assembly command contract."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-inventory", required=True, type=Path)
    parser.add_argument("--reports-directory", required=True, type=Path)
    parser.add_argument("--key-map", required=True, type=Path)
    parser.add_argument("--max-age-seconds", type=int, default=3_600)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Assemble and print normalized fleet evidence without paths or secrets."""
    arguments = _parser().parse_args(argv)
    try:
        value = assemble_inventory(
            device_inventory_path=arguments.device_inventory,
            reports_directory=arguments.reports_directory,
            key_map_path=arguments.key_map,
            max_age_seconds=arguments.max_age_seconds,
        )
    except EndpointAssemblyError as error:
        print(f"Endpoint inventory assembly failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

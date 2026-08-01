#!/usr/bin/env python3
"""Run synthetic root/admin endpoint sensor and fleet assembly acceptance.

Run this command in an isolated root/admin environment with the SDK's
``endpoint`` extra installed. It creates only synthetic temporary state and
prints no filesystem path, device secret, process argument or report content.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from scripts import assemble_endpoint_inventory as assembly
from scripts import collect_discovery_inventory as normalization
from scripts import collect_endpoint_evidence as sensor


def _digest(path: Path) -> str:
    """Hash the bounded synthetic test executable."""
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def main() -> int:
    """Prove live measurement, minimisation, assembly and tamper denial."""
    secret = "synthetic-endpoint-key-material-0001"  # noqa: S105 - synthetic fixture only
    os.environ["AAI_SYNTHETIC_ENDPOINT_KEY"] = secret
    observed_at = 2_000_000_000
    with tempfile.TemporaryDirectory(prefix="aai-endpoint-acceptance-") as temporary:
        root = Path(temporary)
        project = root / "sensitive-project-path"
        project.mkdir()
        executable = Path(os.path.realpath(sys.executable))
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "device": {
                        "id": "synthetic-device-a",
                        "managed": True,
                        "businessUnit": "Platform",
                        "userIds": ["synthetic-user-a"],
                    },
                    "installations": [
                        {
                            "id": "synthetic-installation-a",
                            "host": "claude-code",
                            "projectRoot": str(project),
                            "binaryPath": str(executable),
                            "expectedBinarySha256": _digest(executable),
                            "processExecutablePaths": [str(executable)],
                            "userId": "synthetic-user-a",
                            "repositoryId": "synthetic-repository-a",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        original_working_directory = Path.cwd()
        os.chdir(project)
        try:
            report = sensor.collect_signed_report(
                manifest,
                key_id="synthetic-key-a",
                secret=secret,
                observed_at=observed_at,
            )
        finally:
            os.chdir(original_working_directory)
        encoded_report = json.dumps(report)
        installation = report["payload"]["installations"][0]
        if (
            installation["binaryPresent"] is not True
            or installation["processActive"] is not True
            or str(root) in encoded_report
            or secret in encoded_report
        ):
            raise RuntimeError("live endpoint measurement or minimisation failed")
        reports = root / "reports"
        reports.mkdir()
        (reports / "synthetic-device-a.json").write_text(encoded_report, encoding="utf-8")
        devices = root / "devices.json"
        devices.write_text(
            json.dumps(
                {
                    "observations": [
                        {
                            "kind": "device",
                            "id": "synthetic-device-a",
                            "managed": True,
                            "businessUnit": "Platform",
                            "userIds": ["synthetic-user-a"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        keys = root / "keys.json"
        keys.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "keys": [
                        {
                            "keyId": "synthetic-key-a",
                            "deviceId": "synthetic-device-a",
                            "secretEnv": "AAI_SYNTHETIC_ENDPOINT_KEY",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        fleet = assembly.assemble_inventory(
            device_inventory_path=devices,
            reports_directory=reports,
            key_map_path=keys,
            now=observed_at + 30,
            max_age_seconds=300,
        )
        export = root / "endpoint-export.json"
        export.write_text(json.dumps(fleet), encoding="utf-8")
        observations = normalization.collect_endpoint_export(export)
        if {item["kind"] for item in observations} != {"device", "installation"}:
            raise RuntimeError("assembled inventory did not satisfy endpoint normalization")
        changed = json.loads(encoded_report)
        changed["payload"]["installations"][0]["processActive"] = False
        (reports / "synthetic-device-a.json").write_text(json.dumps(changed), encoding="utf-8")
        try:
            assembly.assemble_inventory(
                device_inventory_path=devices,
                reports_directory=reports,
                key_map_path=keys,
                now=observed_at + 30,
                max_age_seconds=300,
            )
        except assembly.EndpointAssemblyError:
            pass
        else:
            raise RuntimeError("changed signed report was accepted")
    os.environ.pop("AAI_SYNTHETIC_ENDPOINT_KEY", None)
    print(
        "Endpoint evidence acceptance passed: administrator measurement, exact binary/process/"
        "project evidence, path/secret minimisation, authoritative fleet assembly, endpoint "
        "normalization, and changed-report denial."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

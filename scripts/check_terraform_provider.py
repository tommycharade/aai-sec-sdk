#!/usr/bin/env python3
"""Build and validate the Terraform provider through the real CLI protocol.

The smoke test uses a temporary development override and synthetic configuration.
It never calls the control plane or reads a service credential. Temporary binaries,
CLI configuration and schemas are removed when the process exits.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "terraform-provider-aai-sec"
EXAMPLE = PROVIDER / "examples" / "basic"
ADDRESS = "registry.terraform.io/tommycharade/aaisec"


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    """Run one bounded local build command and return its standard output."""
    # Commands are fixed by this repository's quality gate; no user or model
    # input reaches the executable or arguments.
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return completed.stdout


def main() -> int:
    """Verify provider schema discovery and example validation without network use."""
    with tempfile.TemporaryDirectory(prefix="aaisec-terraform-") as temporary:
        temporary_path = Path(temporary)
        binary = temporary_path / "terraform-provider-aaisec"
        _run(["go", "build", "-o", str(binary), "."], cwd=PROVIDER)
        cli_configuration = temporary_path / "terraform.rc"
        cli_configuration.write_text(
            "provider_installation {\n"
            "  dev_overrides {\n"
            f'    "{ADDRESS}" = "{temporary_path}"\n'
            "  }\n"
            "  direct {}\n"
            "}\n",
            encoding="utf-8",
        )
        environment = {**os.environ, "TF_CLI_CONFIG_FILE": str(cli_configuration)}
        schema_output = _run(
            ["terraform", "providers", "schema", "-json"],
            cwd=EXAMPLE,
            env=environment,
        )
        schema = json.loads(schema_output)["provider_schemas"][ADDRESS]
        expected_resources = {
            "aaisec_group",
            "aaisec_mcp_server",
            "aaisec_policy_draft",
            "aaisec_skill",
        }
        if set(schema["resource_schemas"]) != expected_resources:
            raise RuntimeError("Terraform protocol returned an unexpected resource inventory")
        if set(schema["data_source_schemas"]) != {"aaisec_tenant"}:
            raise RuntimeError("Terraform protocol returned an unexpected data-source inventory")
        _run(["terraform", "validate", "-no-color"], cwd=EXAMPLE, env=environment)
    print("Terraform provider protocol schema and example configuration are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

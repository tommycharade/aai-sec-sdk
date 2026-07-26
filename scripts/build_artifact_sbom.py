"""Create an SBOM from each actual release artifact in an isolated environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

CYCLONEDX_VERSION = "7.2.1"


def run(*args: str) -> None:
    """Run a subprocess and fail the release job on any error."""
    subprocess.run(args, check=True)  # noqa: S603 - fixed release-tool argv


def main() -> int:
    """Install each artifact subject into a clean venv and emit its SBOM."""
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    manifest: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="agentic-security-sbom-") as directory:
        root = Path(directory)
        for artifact in args.artifacts:
            wheel = artifact
            if artifact.suffixes[-2:] == [".tar", ".gz"]:
                wheel_dir = root / f"{artifact.stem}.wheel"
                wheel_dir.mkdir()
                run(
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    str(artifact),
                    "-w",
                    str(wheel_dir),
                )
                wheels = sorted(wheel_dir.glob("*.whl"))
                if len(wheels) != 1:
                    raise RuntimeError(f"expected one wheel from {artifact}, found {wheels}")
                wheel = wheels[0]
            venv = root / artifact.name.replace(".", "-")
            run(sys.executable, "-m", "venv", str(venv))
            python = venv / "bin" / "python"
            if sys.platform == "win32":
                python = venv / "Scripts" / "python.exe"
            run(str(python), "-m", "pip", "install", "--no-deps", str(wheel))
            run(str(python), "-m", "pip", "install", f"cyclonedx-bom=={CYCLONEDX_VERSION}")
            output = artifact.with_name(f"{artifact.name}.sbom.json")
            run(
                str(python),
                "-m",
                "cyclonedx_py",
                "environment",
                "--of",
                "JSON",
                "--output-file",
                str(output),
            )
            document = json.loads(output.read_text(encoding="utf-8"))
            properties = document.setdefault("metadata", {}).setdefault("properties", [])
            properties.extend(
                [
                    {"name": "release:artifact-filename", "value": artifact.name},
                    {
                        "name": "release:artifact-sha256",
                        "value": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    },
                ]
            )
            output.write_text(
                json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            manifest.append(
                {
                    "artifact": artifact.name,
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "sbom": output.name,
                    "sbom_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                }
            )
    (args.artifacts[0].parent / "SBOM-MANIFEST.json").write_text(
        json.dumps({"schema": 1, "subjects": manifest}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

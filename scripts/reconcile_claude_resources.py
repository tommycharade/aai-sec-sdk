"""Reconcile the authenticated effective resource manifest into a Claude project.

The control plane or deployment agent supplies the effective-policy JSON. This
script never trusts model output and never resolves secrets. It only installs
resource definitions already present in the signed/validated manifest and
preserves unrelated Claude configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def _write(path: Path, value: str) -> None:
    """Atomically write a managed file with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _load_policy(path: Path) -> dict[str, Any]:
    """Load the control-plane response and require a typed effective policy."""
    value = json.loads(path.read_text(encoding="utf-8"))
    policy = value.get("policy") if isinstance(value, dict) else None
    configuration = policy.get("configuration") if isinstance(policy, dict) else None
    claude = configuration.get("claudeCode") if isinstance(configuration, dict) else None
    if (
        not isinstance(claude, dict)
        or not isinstance(claude.get("managedSkills"), list)
        or not isinstance(claude.get("managedMcpServers"), list)
    ):
        raise ValueError("effective policy does not contain a managed Claude resource manifest")
    return claude


def reconcile(project_root: Path, policy_file: Path) -> dict[str, Any]:
    """Install the selected Skills and MCP servers and remove prior managed entries."""
    claude = _load_policy(policy_file)
    skills_root = project_root / ".claude" / "skills"
    manifest_path = project_root / ".claude" / "aai-sec-managed-resources.json"
    previous = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.exists()
        else {"skills": [], "mcpServers": []}
    )
    selected_skills: list[str] = []
    for skill in claude["managedSkills"]:
        if not isinstance(skill, dict) or not _SAFE_ID.fullmatch(str(skill.get("id", ""))):
            raise ValueError("invalid managed Skill identifier")
        content = skill.get("content")
        digest = skill.get("digest")
        if (
            not isinstance(content, str)
            or len(content) > 100_000
            or digest != f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
        ):
            raise ValueError("managed Skill digest validation failed")
        _write(skills_root / str(skill["id"]) / "SKILL.md", content.rstrip() + "\n")
        selected_skills.append(str(skill["id"]))
    for old_id in previous.get("skills", []):
        if isinstance(old_id, str) and old_id not in selected_skills and _SAFE_ID.fullmatch(old_id):
            managed_file = skills_root / old_id / "SKILL.md"
            if managed_file.exists():
                managed_file.unlink()

    mcp_path = project_root / ".mcp.json"
    mcp = json.loads(mcp_path.read_text(encoding="utf-8")) if mcp_path.exists() else {}
    if not isinstance(mcp, dict):
        raise ValueError(".mcp.json must contain an object")
    servers = mcp.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError(".mcp.json mcpServers must be an object")
    selected_mcp: list[str] = []
    for server in claude["managedMcpServers"]:
        if not isinstance(server, dict) or not _SAFE_ID.fullmatch(str(server.get("id", ""))):
            raise ValueError("invalid managed MCP identifier")
        server_id = str(server["id"])
        definition: dict[str, Any] = {"type": server.get("transport", "stdio")}
        if definition["type"] == "stdio":
            if not isinstance(server.get("command"), str) or not server["command"]:
                raise ValueError("managed stdio MCP server requires a command")
            definition["command"] = server["command"]
            definition["args"] = server.get("args", [])
        elif definition["type"] == "http":
            if not isinstance(server.get("url"), str) or not server["url"].startswith("https://"):
                raise ValueError("managed HTTP MCP server requires an HTTPS URL")
            definition["url"] = server["url"]
        else:
            raise ValueError("unsupported managed MCP transport")
        definition["env"] = {
            name: f"${{{name}}}"
            for name in server.get("environmentReferences", [])
            if isinstance(name, str) and name
        }
        servers[server_id] = definition
        selected_mcp.append(server_id)
    for old_id in previous.get("mcpServers", []):
        if isinstance(old_id, str) and old_id not in selected_mcp:
            servers.pop(old_id, None)
    _write(mcp_path, json.dumps(mcp, indent=2) + "\n")
    manifest = {"skills": selected_skills, "mcpServers": selected_mcp}
    _write(manifest_path, json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    """Run resource reconciliation for one project."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--effective-policy", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            reconcile(
                args.project_root.expanduser().resolve(),
                args.effective_policy.expanduser().resolve(),
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

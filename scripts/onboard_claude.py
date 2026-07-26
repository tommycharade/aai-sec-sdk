"""Prepare a project for the SDK's Claude Code integration.

This script writes project-scoped Claude configuration only. It never invokes
Claude, changes credentials, or overwrites an existing configuration without a
timestamped backup. Run it from any project directory with the SDK repository
available locally.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _timestamp() -> str:
    """Return a filesystem-safe UTC timestamp."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def _load_object(path: Path) -> dict[str, Any]:
    """Load an existing JSON object or return an empty configuration."""
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return value


def _backup(path: Path) -> Path | None:
    """Copy an existing configuration before modifying it."""
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak.{_timestamp()}")
    shutil.copy2(path, backup)
    return backup


def _write_json(path: Path, value: dict[str, Any], *, dry_run: bool) -> None:
    """Atomically write a project configuration with restrictive permissions."""
    if dry_run:
        print(f"Would write {path}")
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            json.dump(value, destination, indent=2)
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _copy_policy(source: Path, destination: Path, *, dry_run: bool) -> None:
    """Install the checked-in safe policy without replacing a project policy."""
    if destination.exists():
        print(f"Preserved existing Claude policy at {destination}")
        return
    if dry_run:
        print(f"Would copy safe policy to {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    os.chmod(destination, 0o600)


def onboard(
    project_root: Path,
    sdk_root: Path,
    *,
    python: str,
    dry_run: bool,
    control_plane_url: str | None = None,
    enterprise_control_plane_url: str | None = None,
    deployment_id: str | None = None,
    agent_id: str = "claude-code-local",
) -> None:
    """Create or update Claude hook and MCP configuration for one project."""
    project_root = project_root.expanduser().resolve()
    sdk_root = sdk_root.expanduser().resolve()
    hook = sdk_root / "examples" / "claude_code_hook.py"
    gateway = sdk_root / "examples" / "mcp_gateway.py"
    policy = sdk_root / "examples" / "claude_safe_config.json"
    if not hook.is_file() or not gateway.is_file() or not policy.is_file():
        raise SystemExit(f"SDK examples were not found under {sdk_root}")

    command = shlex.join([python, str(hook)])
    settings_path = project_root / ".claude" / "settings.json"
    policy_path = project_root / ".claude" / "aai-sec-config.json"
    mcp_path = project_root / ".mcp.json"
    settings = _load_object(settings_path)
    mcp = _load_object(mcp_path)
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SystemExit(f"{settings_path}: hooks must be a JSON object")
    pre_tool_use = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre_tool_use, list):
        raise SystemExit(f"{settings_path}: hooks.PreToolUse must be a JSON array")
    entry = {
        "matcher": "Bash|Read|Edit|Write|Glob|Grep",
        "hooks": [{"type": "command", "command": command, "timeout": 10}],
    }
    if not any(item == entry for item in pre_tool_use):
        pre_tool_use.append(entry)

    servers = mcp.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise SystemExit(f"{mcp_path}: mcpServers must be a JSON object")
    server: dict[str, Any] = {"command": python, "args": [str(gateway)]}
    if control_plane_url or enterprise_control_plane_url:
        server["env"] = {"AAI_SEC_AGENT_ID": agent_id}
        if enterprise_control_plane_url:
            server["env"]["AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL"] = (
                enterprise_control_plane_url.rstrip("/")
            )
        elif control_plane_url:
            server["env"]["AAI_SEC_CONTROL_PLANE_URL"] = control_plane_url.rstrip("/")
        if deployment_id:
            server["env"]["AAI_SEC_DEPLOYMENT_ID"] = deployment_id
    servers["agentic-security"] = server

    if not dry_run:
        settings_backup = _backup(settings_path)
        mcp_backup = _backup(mcp_path)
        _write_json(settings_path, settings, dry_run=False)
        _write_json(mcp_path, mcp, dry_run=False)
        if settings_backup:
            print(f"Backed up {settings_path} to {settings_backup}")
        if mcp_backup:
            print(f"Backed up {mcp_path} to {mcp_backup}")
    else:
        _write_json(settings_path, settings, dry_run=True)
        _write_json(mcp_path, mcp, dry_run=True)
    _copy_policy(policy, policy_path, dry_run=dry_run)

    print("Claude Code onboarding prepared.")
    print(f"Project root: {project_root}")
    print("Next steps:")
    print(f"  1. Review {settings_path}, {policy_path}, and {mcp_path}")
    print("  2. Run Claude Code from the project root: claude")
    print("  3. In Claude Code, run /mcp and confirm agentic-security is connected")
    print("  4. Test an allowed read, an approval-required command, and a denied command")
    if control_plane_url or enterprise_control_plane_url:
        print("  5. Export AAI_SEC_AGENT_TOKEN before starting Claude Code")
        print("  6. Confirm the live Claude agent appears in the management UI")
    else:
        print("  5. Add a control-plane URL and export AAI_SEC_AGENT_TOKEN for live UI presence")
    print("  7. Replace the synthetic example identity and policy before production use")


def main() -> int:
    """Parse arguments and prepare the requested project."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Claude project to configure (default: current directory)",
    )
    parser.add_argument(
        "--sdk-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Local SDK checkout containing examples/ (default: this checkout)",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable Claude should use for the hook and MCP server",
    )
    parser.add_argument(
        "--control-plane-url",
        help="Enable live registration, for example http://localhost:8000/api",
    )
    parser.add_argument(
        "--enterprise-control-plane-url",
        help="Enable deployment-scoped enterprise registration",
    )
    parser.add_argument(
        "--deployment-id",
        help="Enterprise deployment receiving this Claude agent",
    )
    parser.add_argument(
        "--agent-id",
        default="claude-code-local",
        help="Authenticated agent identity for live registration",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print changes without writing files"
    )
    args = parser.parse_args()
    onboard(
        args.project_root,
        args.sdk_root,
        python=args.python,
        dry_run=args.dry_run,
        control_plane_url=args.control_plane_url,
        enterprise_control_plane_url=args.enterprise_control_plane_url,
        deployment_id=args.deployment_id,
        agent_id=args.agent_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

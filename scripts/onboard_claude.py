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
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import certifi

# Support the documented direct-checkout command while keeping the imported
# package bound to this reviewed checkout, not an unrelated global install.
_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from agentic_security import (  # noqa: E402
    AgentSessionCredential,
    AgentSessionStore,
    AgentSessionStoreError,
)


@dataclass(frozen=True, slots=True)
class _Enrollment:
    """Bind a short-lived session to its server-derived tenant identity."""

    credential: AgentSessionCredential
    tenant_id: str


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


def _is_managed_hook(candidate: object) -> bool:
    """Return whether a Claude hook command invokes the SDK's hook entry point.

    Detection uses an exact command-token basename so onboarding can migrate a
    hook installed from an older checkout without deleting similarly named
    user commands or unrelated hooks that share the same matcher entry.
    """
    if not isinstance(candidate, dict) or candidate.get("type") != "command":
        return False
    command = candidate.get("command")
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        # A malformed user command is preserved; onboarding must not guess at
        # ownership when shell tokenization cannot establish the exact target.
        return False
    return any(Path(token).name == "claude_code_hook.py" for token in tokens)


def _remove_managed_hooks(entries: list[object]) -> list[object]:
    """Remove every legacy SDK hook while preserving all user-owned hooks."""
    retained: list[object] = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("hooks"), list):
            retained.append(item)
            continue
        candidates = item["hooks"]
        remaining = [candidate for candidate in candidates if not _is_managed_hook(candidate)]
        if len(remaining) == len(candidates):
            retained.append(item)
        elif remaining:
            retained.append({**item, "hooks": remaining})
    return retained


def _enroll_agent(
    base_url: str,
    bootstrap_token: str,
    project_root: Path,
) -> _Enrollment:
    """Consume one AWS bootstrap token and return the short-lived session."""
    parsed = urlsplit(base_url.rstrip("/"))
    local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not local_http:
        raise SystemExit("enterprise control-plane URL must use HTTPS outside localhost")
    request = urllib.request.Request(  # noqa: S310 - scheme is validated above
        f"{base_url.rstrip('/')}/agent/enroll",
        data=json.dumps(
            {"bootstrapToken": bootstrap_token, "projectRoot": str(project_root)}
        ).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - HTTPS and CA bundle are explicit
            request,
            timeout=15,
            context=ssl.create_default_context(cafile=certifi.where()),
        ) as response:
            value = json.loads(response.read(1_000_000))
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit("agent bootstrap enrollment failed") from exc
    token = value.get("accessToken") if isinstance(value, dict) else None
    expires_at = value.get("expiresAt") if isinstance(value, dict) else None
    tenant_id = value.get("tenantId") if isinstance(value, dict) else None
    if (
        not isinstance(token, str)
        or len(token) < 16
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or not isinstance(tenant_id, str)
        or not tenant_id
    ):
        raise SystemExit("agent enrollment returned no valid session or tenant identity")
    return _Enrollment(AgentSessionCredential(token, expires_at), tenant_id)


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
    bootstrap_token: str | None = None,
    tenant_id: str | None = None,
    policy_trust_bundle: Path | None = None,
) -> None:
    """Create or update Claude hook and MCP configuration for one project."""
    project_root = project_root.expanduser().resolve()
    sdk_root = sdk_root.expanduser().resolve()
    hook = sdk_root / "examples" / "claude_code_hook.py"
    gateway = sdk_root / "examples" / "mcp_gateway.py"
    policy = sdk_root / "examples" / "claude_safe_config.json"
    if not hook.is_file() or not gateway.is_file() or not policy.is_file():
        raise SystemExit(f"SDK examples were not found under {sdk_root}")

    session_store: AgentSessionStore | None = None
    if enterprise_control_plane_url:
        if not deployment_id:
            raise SystemExit("--enterprise-control-plane-url requires --deployment-id")
        try:
            # Constructing the store validates endpoint, identity, and host
            # storage semantics before any project configuration is changed.
            session_store = AgentSessionStore(
                enterprise_control_plane_url,
                deployment_id,
                agent_id,
                str(project_root),
            )
        except (ValueError, AgentSessionStoreError) as exc:
            raise SystemExit(f"enterprise session storage is unavailable: {exc}") from exc
        if policy_trust_bundle is None:
            raise SystemExit(
                "enterprise onboarding requires --policy-trust-bundle from an administrator"
            )
        policy_trust_bundle = policy_trust_bundle.expanduser().resolve()
        if not policy_trust_bundle.is_absolute():  # pragma: no cover - resolve guarantees this.
            raise SystemExit("policy trust bundle path must be absolute")

    agent_session: AgentSessionCredential | None = None
    if bootstrap_token:
        if not enterprise_control_plane_url or not deployment_id:
            raise SystemExit(
                "--bootstrap-token requires --enterprise-control-plane-url and --deployment-id"
            )
        if not dry_run:
            enrollment = _enroll_agent(enterprise_control_plane_url, bootstrap_token, project_root)
            agent_session = enrollment.credential
            tenant_id = enrollment.tenant_id

    tenant_id = tenant_id or os.environ.get("AAI_SEC_TENANT_ID")
    if enterprise_control_plane_url and not tenant_id:
        raise SystemExit(
            "enterprise onboarding requires --tenant-id unless bootstrap enrollment supplies it"
        )

    inherited_token = os.environ.get("AAI_SEC_AGENT_TOKEN")
    if agent_session is None and inherited_token:
        # Direct UI enrollment supplies a 15-minute session. The server remains
        # authoritative for its real expiry; this conservative local bound is
        # replaced by the first authenticated heartbeat.
        agent_session = AgentSessionCredential(inherited_token, int(time.time()) + 900)
    session_cached = False
    if not dry_run and agent_session is not None and session_store is not None:
        session_store.save(agent_session)
        session_cached = True
    elif not dry_run and session_store is not None:
        try:
            session_cached = session_store.load() is not None
        except AgentSessionStoreError as exc:
            raise SystemExit(f"enterprise session storage is unavailable: {exc}") from exc

    source_root = sdk_root / "src"
    hook_environment = {"PYTHONPATH": str(source_root)}
    if enterprise_control_plane_url:
        # Selecting an enterprise endpoint always selects fail-closed AWS
        # session mode. Deriving authority mode from a transient shell token
        # made repeat onboarding silently downgrade to local policy after the
        # token was correctly cleared.
        hook_environment.update(
            {
                "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL": enterprise_control_plane_url.rstrip("/"),
                "AAI_SEC_DEPLOYMENT_ID": deployment_id or "",
                "AAI_SEC_AGENT_ID": agent_id,
                "AAI_SEC_AGENT_SESSION_MODE": "aws",
                "AAI_SEC_TENANT_ID": tenant_id or "",
                "AAI_SEC_POLICY_TRUST_BUNDLE": str(policy_trust_bundle),
            }
        )
    command_parts = [
        "env",
        *[f"{key}={value}" for key, value in hook_environment.items()],
        python,
        str(hook),
    ]
    command = shlex.join(command_parts)
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
    # Own the SDK hook entry point across checkout upgrades. Matching only the
    # current absolute path leaves contradictory legacy hooks active; removing
    # exact entry-point tokens preserves unrelated user automation.
    pre_tool_use[:] = _remove_managed_hooks(pre_tool_use)
    pre_tool_use.append(entry)

    servers = mcp.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise SystemExit(f"{mcp_path}: mcpServers must be a JSON object")
    server: dict[str, Any] = {
        "command": python,
        "args": [str(gateway)],
        "env": {"PYTHONPATH": str(source_root)},
    }
    if control_plane_url or enterprise_control_plane_url:
        server["env"]["AAI_SEC_AGENT_ID"] = agent_id
        if enterprise_control_plane_url:
            server["env"]["AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL"] = (
                enterprise_control_plane_url.rstrip("/")
            )
            server["env"]["AAI_SEC_AGENT_SESSION_MODE"] = "aws"
            server["env"]["AAI_SEC_TENANT_ID"] = tenant_id
            server["env"]["AAI_SEC_POLICY_TRUST_BUNDLE"] = str(policy_trust_bundle)
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
        if session_cached:
            print("  5. The short-lived session is secured in the user-private host cache")
            print("     Unset AAI_SEC_AGENT_TOKEN before starting Claude Code.")
        else:
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
        "--bootstrap-token",
        help="One-time AWS agent bootstrap token; exchange it for a short-lived session",
    )
    parser.add_argument(
        "--tenant-id",
        help="Server-assigned tenant identity (derived automatically during bootstrap enrollment)",
    )
    parser.add_argument(
        "--policy-trust-bundle",
        type=Path,
        help="Absolute administrator-installed public policy trust bundle",
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
        bootstrap_token=args.bootstrap_token,
        tenant_id=args.tenant_id,
        policy_trust_bundle=args.policy_trust_bundle,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

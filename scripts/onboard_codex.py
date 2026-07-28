"""Prepare one trusted project for the SDK's Codex CLI integration.

The script writes a project-scoped ``.codex/config.toml`` entry that starts the
SDK MCP gateway. A short-lived bearer supplied during onboarding is placed in
the user-private SDK host cache, never in project TOML. Existing configuration
outside the marked AAI Security block is preserved.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

# Support direct execution from a source checkout. The script deliberately
# imports the package beside itself so a different global SDK cannot alter the
# configuration or credential-storage semantics being installed.
_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from agentic_security import AgentSessionCredential, AgentSessionStore  # noqa: E402

_BEGIN = "# BEGIN AAI SECURITY MANAGED MCP"
_END = "# END AAI SECURITY MANAGED MCP"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _toml_string(value: str) -> str:
    """Return a TOML-compatible quoted string without interpreting input."""
    return json.dumps(value, ensure_ascii=False)


def _validate_identifier(value: str, label: str) -> str:
    """Reject routing identifiers that are unsafe or ambiguous in host config."""
    if not _IDENTIFIER.fullmatch(value):
        raise SystemExit(f"{label} must use 1-128 letters, numbers, '.', '_', ':', or '-'")
    return value


def _validate_control_plane_url(value: str) -> str:
    """Require HTTPS except for an explicitly local development endpoint."""
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    local_http = parsed.scheme == "http" and parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }
    if parsed.scheme != "https" and not local_http:
        raise SystemExit("enterprise control-plane URL must use HTTPS outside localhost")
    if not parsed.netloc:
        raise SystemExit("enterprise control-plane URL must include a host")
    return normalized


def _managed_block(
    *,
    gateway: Path,
    project_root: Path,
    python: str,
    control_plane_url: str,
    deployment_id: str,
    agent_id: str,
) -> str:
    """Build the non-secret project-scoped MCP configuration block."""
    values = {
        "AAI_SEC_AGENT_HOST": "codex-cli",
        "AAI_SEC_AGENT_SESSION_MODE": "aws",
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL": control_plane_url,
        "AAI_SEC_DEPLOYMENT_ID": deployment_id,
        "AAI_SEC_AGENT_ID": agent_id,
    }
    lines = [
        _BEGIN,
        '[mcp_servers."agentic-security"]',
        f"command = {_toml_string(python)}",
        f"args = [{_toml_string(str(gateway))}]",
        f"cwd = {_toml_string(str(project_root))}",
        "",
        '[mcp_servers."agentic-security".env]',
        *[f"{key} = {_toml_string(value)}" for key, value in values.items()],
        _END,
    ]
    return "\n".join(lines)


def _merge_configuration(existing: str, block: str) -> str:
    """Replace only the managed block and refuse ownership ambiguity."""
    has_begin = _BEGIN in existing
    has_end = _END in existing
    if has_begin != has_end:
        raise SystemExit("existing Codex configuration has an incomplete AAI Security block")
    if has_begin:
        start = existing.index(_BEGIN)
        end = existing.index(_END, start) + len(_END)
        merged = f"{existing[:start].rstrip()}\n\n{block}{existing[end:]}"
    else:
        if '[mcp_servers."agentic-security"]' in existing:
            raise SystemExit(
                "agentic-security MCP configuration exists outside the managed block; "
                "review it manually"
            )
        merged = f"{existing.rstrip()}\n\n{block}" if existing.strip() else block
    return f"{merged.strip()}\n"


def _atomic_write(path: Path, content: str) -> None:
    """Write validated TOML atomically without following configuration symlinks."""
    if path.is_symlink() or path.parent.is_symlink():
        raise SystemExit("refusing to write Codex configuration through a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(content)
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


def onboard(
    project_root: Path,
    sdk_root: Path,
    *,
    python: str,
    control_plane_url: str,
    deployment_id: str,
    agent_id: str,
    dry_run: bool,
) -> Path:
    """Create or update a non-secret, project-scoped Codex MCP configuration.

    If the caller supplies ``AAI_SEC_AGENT_TOKEN``, the installer transfers it
    into the user-private rotating cache and never serializes it into this
    project. Codex does not need to retain the variable after onboarding.
    """
    project_root = project_root.expanduser().resolve()
    sdk_root = sdk_root.expanduser().resolve()
    if not project_root.is_dir():
        raise SystemExit(f"project root does not exist: {project_root}")
    gateway = sdk_root / "examples" / "mcp_gateway.py"
    if not gateway.is_file():
        raise SystemExit(f"SDK MCP gateway was not found under {sdk_root}")
    deployment_id = _validate_identifier(deployment_id, "deployment ID")
    agent_id = _validate_identifier(agent_id, "agent ID")
    control_plane_url = _validate_control_plane_url(control_plane_url)
    # Validate host credential protection before touching project state, even
    # on repeat onboarding where the rotating session already exists.
    session_store = AgentSessionStore(control_plane_url, deployment_id, agent_id)
    config_path = project_root / ".codex" / "config.toml"
    if config_path.is_symlink() or config_path.parent.is_symlink():
        raise SystemExit("refusing to read Codex configuration through a symbolic link")
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if existing:
        try:
            tomllib.loads(existing)
        except tomllib.TOMLDecodeError as exc:
            raise SystemExit(f"cannot update invalid TOML at {config_path}: {exc}") from exc
    block = _managed_block(
        gateway=gateway,
        project_root=project_root,
        python=python,
        control_plane_url=control_plane_url,
        deployment_id=deployment_id,
        agent_id=agent_id,
    )
    merged = _merge_configuration(existing, block)
    try:
        tomllib.loads(merged)
    except tomllib.TOMLDecodeError as exc:  # pragma: no cover - invariant guard
        raise SystemExit(f"generated Codex configuration is invalid: {exc}") from exc
    inherited_token = os.environ.get("AAI_SEC_AGENT_TOKEN")
    if dry_run:
        print(f"Would write {config_path}")
        print(merged, end="")
    else:
        if inherited_token:
            # Secure the session before replacing project configuration. If
            # cache validation or persistence fails, the original TOML remains
            # untouched and the host cannot be left half-enrolled.
            session_store.save(AgentSessionCredential(inherited_token, int(time.time()) + 900))
        _atomic_write(config_path, merged)
    print("Codex CLI onboarding prepared.")
    print(f"Project root: {project_root}")
    print(f"Configuration: {config_path}")
    if os.environ.get("AAI_SEC_AGENT_TOKEN") and not dry_run:
        print("The short-lived session is secured in the user-private host cache.")
        print("You can unset AAI_SEC_AGENT_TOKEN before starting Codex.")
    else:
        print("No agent token was written to project configuration.")
    print("Verify with: codex mcp get agentic-security --json")
    return config_path


def main() -> int:
    """Parse arguments and prepare the selected Codex project."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--sdk-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--enterprise-control-plane-url", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    onboard(
        args.project_root,
        args.sdk_root,
        python=args.python,
        control_plane_url=args.enterprise_control_plane_url,
        deployment_id=args.deployment_id,
        agent_id=args.agent_id,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

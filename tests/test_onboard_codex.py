"""Tests for secure project-scoped Codex CLI onboarding."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest
from scripts.onboard_codex import onboard


def _onboard(project: Path) -> Path:
    """Run onboarding with synthetic routing metadata."""
    return onboard(
        project,
        Path.cwd(),
        python="python3",
        control_plane_url="https://fleet.example.test/api",
        deployment_id="deployment-test",
        agent_id="codex-test",
        dry_run=False,
    )


def test_onboard_codex_forwards_bearer_by_name_without_persisting_it(
    tmp_path: Path,
) -> None:
    """The project config contains routing metadata but never a bearer value."""
    config_path = _onboard(tmp_path)
    content = config_path.read_text(encoding="utf-8")
    parsed = tomllib.loads(content)
    server = parsed["mcp_servers"]["agentic-security"]

    assert server["command"] == "python3"
    assert server["args"][0].endswith("examples/mcp_gateway.py")
    assert server["cwd"] == str(tmp_path)
    assert server["env_vars"] == ["AAI_SEC_AGENT_TOKEN"]
    assert server["env"]["AAI_SEC_AGENT_HOST"] == "codex-cli"
    assert server["env"]["AAI_SEC_DEPLOYMENT_ID"] == "deployment-test"
    assert "synthetic-token" not in content
    assert config_path.stat().st_mode & 0o777 == 0o600


def test_onboard_codex_preserves_unrelated_configuration_and_is_idempotent(
    tmp_path: Path,
) -> None:
    """Repeated setup updates one owned block without duplicating user config."""
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir()
    config_path = codex_dir / "config.toml"
    config_path.write_text('model = "synthetic-model"\n', encoding="utf-8")

    _onboard(tmp_path)
    _onboard(tmp_path)
    content = config_path.read_text(encoding="utf-8")

    assert tomllib.loads(content)["model"] == "synthetic-model"
    assert content.count("# BEGIN AAI SECURITY MANAGED MCP") == 1
    assert content.count('[mcp_servers."agentic-security"]') == 1


def test_onboard_codex_rejects_unowned_or_symlinked_configuration(
    tmp_path: Path,
) -> None:
    """The installer never overwrites ambiguous config or follows a write link."""
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir()
    config_path = codex_dir / "config.toml"
    config_path.write_text(
        '[mcp_servers."agentic-security"]\ncommand = "other"\n',
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="outside the managed block"):
        _onboard(tmp_path)

    config_path.unlink()
    external = tmp_path / "external.toml"
    external.write_text("", encoding="utf-8")
    os.symlink(external, config_path)
    with pytest.raises(SystemExit, match="symbolic link"):
        _onboard(tmp_path)

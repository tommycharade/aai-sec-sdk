"""Tests for the safe Claude Code onboarding command."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.onboard_claude import onboard


def test_onboard_creates_separate_hook_and_mcp_configuration(tmp_path: Path) -> None:
    onboard(
        tmp_path,
        Path.cwd(),
        python="python3",
        dry_run=False,
        control_plane_url="http://localhost:8000/api",
    )

    settings = json.loads((tmp_path / ".claude/settings.json").read_text())
    policy = json.loads((tmp_path / ".claude/aai-sec-config.json").read_text())
    mcp = json.loads((tmp_path / ".mcp.json").read_text())

    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"].endswith(
        "examples/claude_code_hook.py"
    )
    assert mcp["mcpServers"]["agentic-security"]["args"][0].endswith("examples/mcp_gateway.py")
    assert mcp["mcpServers"]["agentic-security"]["env"] == {
        "AAI_SEC_CONTROL_PLANE_URL": "http://localhost:8000/api",
        "AAI_SEC_AGENT_ID": "claude-code-local",
    }
    assert policy["allowedTools"] == ["Read", "Glob", "Grep"]
    assert "rm\\s+-rf" in policy["deniedCommandPatterns"][0]


def test_onboard_preserves_existing_configuration_and_is_idempotent(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Read"]}}), encoding="utf-8"
    )
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"existing": {"command": "tool"}}}), encoding="utf-8"
    )

    onboard(tmp_path, Path.cwd(), python="python3", dry_run=False)
    onboard(tmp_path, Path.cwd(), python="python3", dry_run=False)

    settings = json.loads((claude_dir / "settings.json").read_text())
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    assert settings["permissions"] == {"allow": ["Read"]}
    assert len(settings["hooks"]["PreToolUse"]) == 1
    assert "existing" in mcp["mcpServers"]
    assert (claude_dir / "aai-sec-config.json").exists()
    assert len(list(claude_dir.glob("settings.json.bak.*"))) == 2
    assert len(list(tmp_path.glob(".mcp.json.bak.*"))) == 2

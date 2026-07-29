"""Tests for the safe Claude Code onboarding command."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.onboard_claude import onboard

from agentic_security import AgentSessionCredential, AgentSessionStore


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
        "PYTHONPATH": str(Path.cwd() / "src"),
        "AAI_SEC_CONTROL_PLANE_URL": "http://localhost:8000/api",
        "AAI_SEC_AGENT_ID": "claude-code-local",
    }
    assert policy["allowedTools"] == ["Read", "Glob", "Grep"]
    assert "rm\\s+-rf" in policy["deniedCommandPatterns"][0]


def test_generated_claude_hook_runs_from_checkout_without_installed_sdk(tmp_path: Path) -> None:
    """Generated configuration imports its adjacent SDK and emits a real decision."""
    onboard(tmp_path, Path.cwd(), python=sys.executable, dry_run=False)
    settings = json.loads((tmp_path / ".claude/settings.json").read_text(encoding="utf-8"))
    handler = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["CLAUDE_PROJECT_DIR"] = str(tmp_path)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "README.md")},
        "tool_use_id": "tool:onboarded",
        "session_id": "session:synthetic",
        "cwd": str(tmp_path),
    }

    result = subprocess.run(  # noqa: S603 - generated fixed checkout command
        shlex.split(handler["command"]),
        # Keep the SDK checkout as cwd so mutmut's instrumented subprocess can
        # read its test configuration. With a src layout and PYTHONPATH removed
        # above, cwd alone still cannot make agentic_security importable.
        cwd=Path.cwd(),
        input=json.dumps(payload) + "\n",
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    decision = json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]
    assert decision == "allow"
    assert "ModuleNotFoundError" not in result.stderr


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


def test_onboard_replaces_legacy_checkout_hook_without_removing_user_hooks(tmp_path: Path) -> None:
    """An SDK checkout upgrade leaves one authoritative hook and keeps user automation."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    legacy = {
        "type": "command",
        "command": "python3 /previous/sdk/examples/claude_code_hook.py",
        "timeout": 10,
    }
    user_hook = {"type": "command", "command": "python3 ./tools/custom_hook.py", "timeout": 5}
    malformed_user_hook = {
        "type": "command",
        "command": "python3 'unterminated",
        "timeout": 5,
    }
    (claude_dir / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash|Read|Edit|Write|Glob|Grep",
                            "hooks": [legacy, user_hook],
                        },
                        {"matcher": "Read", "hooks": [malformed_user_hook]},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    onboard(tmp_path, Path.cwd(), python="python3", dry_run=False)

    settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
    entries = settings["hooks"]["PreToolUse"]
    commands = [hook["command"] for entry in entries for hook in entry["hooks"]]
    managed = [command for command in commands if "claude_code_hook.py" in command]
    assert len(managed) == 1
    assert str(Path.cwd() / "examples/claude_code_hook.py") in managed[0]
    assert user_hook["command"] in commands
    assert malformed_user_hook["command"] in commands


def test_onboard_writes_deployment_scoped_enterprise_environment(tmp_path: Path) -> None:
    """Enterprise onboarding writes routing metadata but never an agent secret."""
    onboard(
        tmp_path,
        Path.cwd(),
        python="python3",
        dry_run=False,
        enterprise_control_plane_url="https://fleet.example.test/api",
        deployment_id="deployment-prod-eu",
        agent_id="claude-platform-prod",
    )

    settings = json.loads((tmp_path / ".claude/settings.json").read_text())
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    environment = mcp["mcpServers"]["agentic-security"]["env"]
    assert environment == {
        "PYTHONPATH": str(Path.cwd() / "src"),
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL": "https://fleet.example.test/api",
        "AAI_SEC_DEPLOYMENT_ID": "deployment-prod-eu",
        "AAI_SEC_AGENT_ID": "claude-platform-prod",
        "AAI_SEC_AGENT_SESSION_MODE": "aws",
    }
    assert "AAI_SEC_AGENT_TOKEN" not in environment
    hook_command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "AAI_SEC_AGENT_TOKEN" not in hook_command
    assert "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL" in hook_command
    assert "deployment-prod-eu" in hook_command
    command_tokens = shlex.split(hook_command)
    assert command_tokens[:6] == [
        "env",
        f"PYTHONPATH={Path.cwd() / 'src'}",
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL=https://fleet.example.test/api",
        "AAI_SEC_DEPLOYMENT_ID=deployment-prod-eu",
        "AAI_SEC_AGENT_ID=claude-platform-prod",
        "AAI_SEC_AGENT_SESSION_MODE=aws",
    ]


def test_onboard_secures_ui_session_outside_project_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A UI-issued bearer enters only the user-private rotating cache."""
    user_home = tmp_path / "home"
    user_home.mkdir(mode=0o700)
    project = tmp_path / "project"
    project.mkdir()
    token = "synthetic-ui-session-token-1234"  # noqa: S105 - synthetic fixture
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", token)
    monkeypatch.setattr("scripts.onboard_claude.time.time", lambda: 1_000)
    monkeypatch.setattr("agentic_security.agent_sessions.time.time", lambda: 1_000)

    onboard(
        project,
        Path.cwd(),
        python="python3",
        dry_run=False,
        enterprise_control_plane_url="https://fleet.example.test/api",
        deployment_id="deployment-prod-eu",
        agent_id="claude-platform-prod",
    )

    cache = AgentSessionStore(
        "https://fleet.example.test/api",
        "deployment-prod-eu",
        "claude-platform-prod",
        str(project.resolve()),
        now=lambda: 1_000,
    )
    assert cache.load() == AgentSessionCredential(token, 1_900)
    assert token not in (project / ".mcp.json").read_text(encoding="utf-8")
    assert token not in (project / ".claude/settings.json").read_text(encoding="utf-8")
    assert token not in capsys.readouterr().out


def test_repeat_enterprise_onboarding_stays_aws_and_replaces_managed_hook(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Clearing the one-time token cannot downgrade or duplicate enforcement."""
    user_home = tmp_path / "home"
    user_home.mkdir(mode=0o700)
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", "synthetic-repeat-session-1234")

    def run_onboarding() -> None:
        onboard(
            project,
            Path.cwd(),
            python="python3",
            dry_run=False,
            enterprise_control_plane_url="https://fleet.example.test/api",
            deployment_id="deployment-prod-eu",
            agent_id="claude-platform-prod",
        )

    run_onboarding()
    capsys.readouterr()
    monkeypatch.delenv("AAI_SEC_AGENT_TOKEN")
    run_onboarding()
    output = capsys.readouterr().out

    settings = json.loads((project / ".claude/settings.json").read_text(encoding="utf-8"))
    managed = settings["hooks"]["PreToolUse"]
    assert len(managed) == 1
    assert "AAI_SEC_AGENT_SESSION_MODE=aws" in managed[0]["hooks"][0]["command"]
    mcp = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp["mcpServers"]["agentic-security"]["env"]["AAI_SEC_AGENT_SESSION_MODE"] == "aws"
    assert "short-lived session is secured" in output
    assert "Export AAI_SEC_AGENT_TOKEN" not in output


def test_enterprise_onboarding_validates_scope_before_writing_project(
    tmp_path: Path,
) -> None:
    """Missing deployment identity cannot produce an unusable host config."""
    with pytest.raises(SystemExit, match="requires --deployment-id"):
        onboard(
            tmp_path,
            Path.cwd(),
            python="python3",
            dry_run=False,
            enterprise_control_plane_url="https://fleet.example.test/api",
        )

    assert not (tmp_path / ".claude").exists()
    assert not (tmp_path / ".mcp.json").exists()

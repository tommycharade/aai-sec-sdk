"""Tests for secure project-scoped Codex CLI onboarding."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from scripts.onboard_codex import onboard

from agentic_security import AgentSessionCredential, AgentSessionStore, AgentSessionStoreError


def _onboard(project: Path) -> Path:
    """Run onboarding with synthetic routing metadata."""
    return onboard(
        project,
        Path.cwd(),
        python="python3",
        control_plane_url="https://fleet.example.test/api",
        deployment_id="deployment-test",
        agent_id="codex-test",
        tenant_id="tenant-test",
        policy_trust_bundle=Path("/etc/aai-security/policy-trust.json"),
        dry_run=False,
    )


def test_onboard_codex_uses_host_cache_without_project_bearer_configuration(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The project config contains routing metadata but never a bearer value."""
    config_path = _onboard(tmp_path)
    content = config_path.read_text(encoding="utf-8")
    parsed = tomllib.loads(content)
    server = parsed["mcp_servers"]["agentic-security"]

    assert server["command"] == "python3"
    assert server["args"][0].endswith("examples/mcp_gateway.py")
    assert server["cwd"] == str(tmp_path)
    assert server["required"] is True
    assert "env_vars" not in server
    assert server["env"]["AAI_SEC_AGENT_HOST"] == "codex-cli"
    assert server["env"]["AAI_SEC_DEPLOYMENT_ID"] == "deployment-test"
    assert server["env"]["AAI_SEC_TENANT_ID"] == "tenant-test"
    assert server["env"]["AAI_SEC_POLICY_TRUST_BUNDLE"] == (
        str(Path("/etc/aai-security/policy-trust.json").resolve())
    )
    assert server["env"]["PYTHONPATH"] == str(Path.cwd() / "src")
    assert "synthetic-token" not in content
    assert config_path.stat().st_mode & 0o777 == 0o600
    hook = parsed["hooks"]["PreToolUse"][0]
    assert hook["matcher"] == "*"
    handler = hook["hooks"][0]
    assert handler["type"] == "command"
    assert handler["timeout"] == 10
    assert "examples/codex_cli_hook.py" in handler["command"]
    assert "AAI_SEC_AGENT_SESSION_MODE=aws" in handler["command"]
    assert f"AAI_SEC_PROJECT_ROOT={tmp_path}" in handler["command"]
    assert f"PYTHONPATH={Path.cwd() / 'src'}" in handler["command"]
    assert "AAI_SEC_AGENT_TOKEN" not in handler["command"]
    output = capsys.readouterr().out
    assert "Codex ignores project MCP and hook" in output
    assert "codex mcp get agentic-security --json" in output
    assert f'[projects."{tmp_path}"]' in output
    assert 'trust_level = "trusted"' in output
    assert output.index("Approve the project trust prompt") < output.index("codex mcp get")


def test_generated_codex_hook_runs_from_checkout_without_installed_sdk(tmp_path: Path) -> None:
    """Generated configuration imports its adjacent SDK and emits a real decision."""
    config_path = _onboard(tmp_path)
    handler = tomllib.loads(config_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0][
        "hooks"
    ][0]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
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
    assert decision == "deny"
    assert "ModuleNotFoundError" not in result.stderr


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
    assert content.count("[[hooks.PreToolUse]]") == 1
    assert content.count("[[hooks.PreToolUse.hooks]]") == 1


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


def test_onboard_codex_secures_session_without_project_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Codex and its gateway share rotation through a user-private cache."""
    user_home = tmp_path / "home"
    user_home.mkdir(mode=0o700)
    project = tmp_path / "project"
    project.mkdir()
    token = "synthetic-codex-session-token-1234"  # noqa: S105 - synthetic fixture
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", token)
    monkeypatch.setattr("scripts.onboard_codex.time.time", lambda: 1_000)
    monkeypatch.setattr("agentic_security.agent_sessions.time.time", lambda: 1_000)

    config_path = _onboard(project)

    cache = AgentSessionStore(
        "https://fleet.example.test/api",
        "deployment-test",
        "codex-test",
        str(project.resolve()),
        now=lambda: 1_000,
    )
    assert cache.load() == AgentSessionCredential(token, 1_900)
    assert token not in config_path.read_text(encoding="utf-8")
    assert token not in capsys.readouterr().out


def test_onboard_codex_leaves_configuration_untouched_when_cache_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed credential transfer cannot leave a half-enrolled project."""
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir()
    config_path = codex_dir / "config.toml"
    original = 'model = "synthetic-model"\n'
    config_path.write_text(original, encoding="utf-8")
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", "synthetic-cache-failure-1234")

    def fail_save(_store: object, _credential: object) -> None:
        raise AgentSessionStoreError("synthetic cache failure")

    monkeypatch.setattr(AgentSessionStore, "save", fail_save)
    with pytest.raises(AgentSessionStoreError, match="synthetic cache failure"):
        _onboard(tmp_path)

    assert config_path.read_text(encoding="utf-8") == original


def test_onboard_codex_checks_session_store_before_project_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Unsupported host credential security fails before creating TOML."""

    def fail_store(*_args: object, **_kwargs: object) -> AgentSessionStore:
        raise AgentSessionStoreError("synthetic unsupported host")

    monkeypatch.setattr("scripts.onboard_codex.AgentSessionStore", fail_store)
    with pytest.raises(AgentSessionStoreError, match="unsupported host"):
        _onboard(tmp_path)

    assert not (tmp_path / ".codex").exists()


@pytest.mark.parametrize("script", ["onboard_claude.py", "onboard_codex.py"])
def test_onboarding_script_imports_adjacent_checkout_without_install(
    script: str,
) -> None:
    """Documented direct-checkout entry points load the adjacent src package."""
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, str(Path.cwd() / "scripts" / script), "--help"],
        cwd="/",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout

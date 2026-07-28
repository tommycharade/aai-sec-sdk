from __future__ import annotations

import io
import json
import time
from pathlib import Path

import examples.claude_code_hook as claude_hook_example
import pytest

from agentic_security import (
    AgentSessionCredential,
    AgentSessionStore,
    ClaudeCodeHook,
    ClaudeHookDecision,
    ClaudeHookResult,
    JsonlAuditSink,
    command_rule,
    exact_tool_rule,
    path_within_rule,
)


def event(
    tool_name: str, tool_input: dict[str, object], *, tool_use_id: str = "tool:1"
) -> dict[str, object]:
    """Build synthetic Claude hook input."""
    return {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
        "session_id": "session:synthetic",
        "cwd": "/workspace/project",
    }


def test_claude_hook_denies_by_default_and_returns_native_decision_shape() -> None:
    hook = ClaudeCodeHook([])
    result = hook.handle(event("Bash", {"command": "unknown-command"}))
    assert result == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "tool is not explicitly allowed",
        }
    }


def test_claude_hook_orders_deny_ask_and_allow_command_rules() -> None:
    hook = ClaudeCodeHook(
        [
            command_rule((r"rm\s+-rf",), decision=ClaudeHookDecision.DENY, reason="destructive"),
            command_rule((r"git\s+push",), decision=ClaudeHookDecision.ASK, reason="review"),
            command_rule((r"git\s+status",), decision=ClaudeHookDecision.ALLOW, reason="safe"),
        ]
    )
    assert (
        hook.handle(event("Bash", {"command": "rm -rf /tmp/x"}))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "deny"
    )
    assert (
        hook.handle(event("Bash", {"command": "git push origin main"}))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "ask"
    )
    assert (
        hook.handle(event("Bash", {"command": "git status"}))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "allow"
    )


def test_claude_hook_restricts_file_tools_to_project_and_audits(tmp_path: Path) -> None:
    audit = JsonlAuditSink(tmp_path / "audit.jsonl")
    hook = ClaudeCodeHook([path_within_rule({"Read", "Edit", "Write"}, tmp_path)], audit=audit)
    allowed = hook.handle(event("Read", {"file_path": str(tmp_path / "file.py")}))
    denied = hook.handle(event("Write", {"file_path": "/etc/hosts"}, tool_use_id="tool:2"))
    assert allowed["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert audit.verify()


def test_path_rule_uses_project_cwd_for_search_tools_without_explicit_path(tmp_path: Path) -> None:
    hook = ClaudeCodeHook([path_within_rule({"Glob", "Grep"}, tmp_path)])
    allowed = hook.handle(
        {
            "tool_name": "Glob",
            "tool_input": {"pattern": "*.py"},
            "tool_use_id": "tool:cwd",
            "cwd": str(tmp_path),
        }
    )
    denied = hook.handle(
        {
            "tool_name": "Glob",
            "tool_input": {"pattern": "*.py"},
            "tool_use_id": "tool:outside",
            "cwd": str(tmp_path.parent.parent),
        }
    )
    assert allowed["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_hook_rule_failures_and_malformed_input_fail_closed() -> None:
    def broken(_event: object) -> ClaudeHookResult:
        raise RuntimeError("synthetic failure")

    hook = ClaudeCodeHook([broken])
    result = hook.handle(event("Bash", {"command": "echo safe"}))
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    with pytest.raises(ValueError):
        hook.handle({"tool_name": "Bash", "tool_input": {}})

    source = io.StringIO(json.dumps({"tool_name": "Bash"}) + "\n")
    destination = io.StringIO()
    hook.serve_stdio(source, destination)
    assert json.loads(destination.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_exact_tool_rule_matches_only_registered_names() -> None:
    hook = ClaudeCodeHook([exact_tool_rule({"Read"})])
    assert hook.handle(event("Read", {}))["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert hook.handle(event("Edit", {}))["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_hook_denies_when_audit_persistence_fails() -> None:
    class BrokenAudit:
        def append(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic audit outage")

    hook = ClaudeCodeHook(
        [exact_tool_rule({"Read"})],
        audit=BrokenAudit(),  # type: ignore[arg-type]
    )
    result = hook.handle(event("Read", {}))
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_native_hook_resolves_central_policy_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Native tools use the same authenticated group policy as the MCP gateway."""

    class Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def effective_policy(self) -> dict[str, object]:
            return {
                "policy": {
                    "configuration": {
                        "policy": {"denyByDefault": True},
                        "tools": {"allowed": ["lookup_record"]},
                        "claudeCode": {
                            "allowedBuiltInTools": ["Read"],
                            "fileTools": ["Read"],
                            "deniedCommandPatterns": [r"rm\s+-rf"],
                            "approvalCommandPatterns": [r"git\s+push"],
                        },
                        "audit": {"redactSensitiveData": True},
                    }
                }
            }

    monkeypatch.setenv("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL", "https://fleet.example.test/api")
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", "synthetic-agent-token-1234")
    monkeypatch.setenv("AAI_SEC_DEPLOYMENT_ID", "deployment-a")
    monkeypatch.setattr(claude_hook_example, "ControlPlaneAgentClient", Client)
    config = claude_hook_example._load_central_config(tmp_path)
    assert config is not None
    assert config["allowedTools"] == ["Read"]
    assert config["allowedCommandPatterns"] == []

    monkeypatch.delenv("AAI_SEC_AGENT_TOKEN")
    assert claude_hook_example._load_central_config(tmp_path) is None


def test_claude_native_hook_prefers_rotated_host_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each hook process adopts the gateway's latest cached bearer."""
    user_home = tmp_path / "home"
    user_home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL", "https://fleet.example.test/api")
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", "synthetic-original-token-1234")
    monkeypatch.setenv("AAI_SEC_DEPLOYMENT_ID", "deployment-a")
    monkeypatch.setenv("AAI_SEC_AGENT_ID", "claude-a")
    monkeypatch.setenv("AAI_SEC_AGENT_SESSION_MODE", "aws")
    rotated = "synthetic-rotated-token-5678"
    store = AgentSessionStore(
        "https://fleet.example.test/api",
        "deployment-a",
        "claude-a",
    )
    store.save(AgentSessionCredential(rotated, int(time.time()) + 900))

    class Client:
        def __init__(self, _url: str, token: str, **kwargs: object) -> None:
            self.token = token
            self.session_store = kwargs.get("session_store")

    monkeypatch.setattr(claude_hook_example, "ControlPlaneAgentClient", Client)

    client = claude_hook_example._control_plane_client(tmp_path)

    assert client is not None
    assert client.token == rotated
    assert isinstance(client.session_store, AgentSessionStore)

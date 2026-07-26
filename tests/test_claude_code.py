from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agentic_security import (
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

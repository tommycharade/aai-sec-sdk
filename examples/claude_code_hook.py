"""Fail-closed Claude Code PreToolUse hook example.

Install the SDK, copy ``examples/.claude/settings.json`` to your project as
``.claude/settings.json``, and run Claude Code from the project directory. The
hook protects Claude's native Bash/Edit/Write tools; application actions that
need SDK-owned credentials and idempotency should be exposed through the MCP
gateway instead.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from agentic_security import (
    ClaudeCodeHook,
    ClaudeHookDecision,
    ClaudeHookResult,
    JsonlAuditSink,
    command_rule,
    path_within_rule,
)


def _load_safe_config(project_dir: Path) -> dict[str, Any] | None:
    """Load the project policy or fail closed if it is malformed."""
    config_path = project_dir / ".claude" / "aai-sec-config.json"
    if not config_path.exists():
        config_path = Path(__file__).with_name("claude_safe_config.json")
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("version") != 1:
        return None
    list_fields = (
        "allowedTools",
        "deniedCommandPatterns",
        "approvalCommandPatterns",
        "allowedCommandPatterns",
        "fileTools",
    )
    if any(
        not isinstance(value.get(field), list)
        or any(not isinstance(item, str) or not item.strip() for item in value[field])
        for field in list_fields
    ):
        return None
    try:
        for field in list_fields[1:4]:
            for pattern in value[field]:
                re.compile(pattern)
    except re.error:
        return None
    audit_file = value.get("auditFile")
    if not isinstance(audit_file, str) or not audit_file:
        return None
    return value


def main() -> None:
    """Read one Claude event and emit one decision."""
    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve()
    config = _load_safe_config(project_dir)
    audit_path = project_dir / ".claude" / "security-audit.jsonl"
    if config is not None:
        configured_audit = Path(config["auditFile"])
        audit_path = (
            configured_audit if configured_audit.is_absolute() else project_dir / configured_audit
        )
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    if config is None:
        hook = ClaudeCodeHook(
            rules=[],
            default=ClaudeHookResult(
                ClaudeHookDecision.DENY, "Claude security configuration is invalid"
            ),
            audit=JsonlAuditSink(audit_path),
        )
        hook.serve_stdio()
        return
    hook = ClaudeCodeHook(
        rules=[
            command_rule(
                tuple(config["deniedCommandPatterns"]),
                decision=ClaudeHookDecision.DENY,
                reason="dangerous shell command is blocked by the project policy",
            ),
            command_rule(
                tuple(config["approvalCommandPatterns"]),
                decision=ClaudeHookDecision.ASK,
                reason="consequential command requires interactive approval",
            ),
            command_rule(
                tuple(config["allowedCommandPatterns"]),
                decision=ClaudeHookDecision.ALLOW,
                reason="read-only or test command is approved",
            ),
            path_within_rule(set(config["fileTools"]), project_dir),
        ],
        audit=JsonlAuditSink(audit_path),
    )
    hook.serve_stdio()


if __name__ == "__main__":
    main()

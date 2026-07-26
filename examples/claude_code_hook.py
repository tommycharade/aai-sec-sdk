"""Fail-closed Claude Code PreToolUse hook example.

Install the SDK, copy ``examples/.claude/settings.json`` to your project as
``.claude/settings.json``, and run Claude Code from the project directory. The
hook protects Claude's native Bash/Edit/Write tools; application actions that
need SDK-owned credentials and idempotency should be exposed through the MCP
gateway instead.
"""

from __future__ import annotations

import os
from pathlib import Path

from agentic_security import (
    ClaudeCodeHook,
    ClaudeHookDecision,
    JsonlAuditSink,
    command_rule,
    path_within_rule,
)


def main() -> None:
    """Read one Claude event and emit one decision."""
    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve()
    audit_path = project_dir / ".claude" / "security-audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    hook = ClaudeCodeHook(
        rules=[
            command_rule(
                (
                    r"(^|\s)(rm\s+-rf|git\s+reset\s+--hard|sudo|chmod\s+777)(\s|$)",
                    r"curl\s+[^|]+\|\s*(sh|bash)",
                ),
                decision=ClaudeHookDecision.DENY,
                reason="dangerous shell command is blocked by the project policy",
            ),
            command_rule(
                (
                    r"\bgit\s+(push|commit)\b",
                    r"\b(npm|pnpm|yarn)\s+publish\b",
                    r"\b(deploy|terraform\s+apply)\b",
                ),
                decision=ClaudeHookDecision.ASK,
                reason="consequential command requires interactive approval",
            ),
            command_rule(
                (r"^(pwd|ls|git\s+(status|diff|log)|pytest|python\s+-m\s+pytest)(\s|$)",),
                decision=ClaudeHookDecision.ALLOW,
                reason="read-only or test command is approved",
            ),
            path_within_rule({"Read", "Edit", "Write", "Glob", "Grep"}, project_dir),
        ],
        audit=JsonlAuditSink(audit_path),
    )
    hook.serve_stdio()


if __name__ == "__main__":
    main()

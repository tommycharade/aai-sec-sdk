"""Claude Code ``PreToolUse`` hook integration.

Claude Code hooks are a native host enforcement point for built-in tools such
as Bash, Edit, Write, Read, and MCP tools. This adapter makes that boundary
usable without pretending that a hook executes the action itself: it returns a
typed Claude decision, and Claude remains responsible for the eventual host
operation. Consequential application operations should still use
``GuardedRuntime`` and an MCP tool handler when the SDK must own execution,
credentials, idempotency, or reconciliation.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, TextIO

from .audit import AuditSink

JsonObject = dict[str, Any]
_HOOK_EVENT: Final[str] = "PreToolUse"


class ClaudeHookDecision(StrEnum):
    """Decisions understood by Claude Code's ``PreToolUse`` hook."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class ClaudeToolEvent:
    """Validated, untrusted details of one Claude Code tool proposal."""

    tool_name: str
    tool_input: Mapping[str, Any]
    tool_use_id: str
    session_id: str | None = None
    cwd: str | None = None


@dataclass(frozen=True, slots=True)
class ClaudeHookResult:
    """Safe decision and explanation returned by a hook policy."""

    decision: ClaudeHookDecision
    reason: str

    def __post_init__(self) -> None:
        """Reject ambiguous hook outcomes and explanations."""
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("hook decision reason must be non-empty")


HookRule = Callable[[ClaudeToolEvent], ClaudeHookResult | None]


class ClaudeCodeHook:
    """Run deterministic, fail-closed Claude Code pre-tool rules.

    Rules are evaluated in order. The first rule returning a result wins; if
    no rule matches, ``default`` is returned. The hook never trusts a
    principal, approval, credential, or policy version from Claude's JSON.
    ``audit`` receives the redaction-aware event through the SDK audit
    boundary, while stdout contains only Claude's hook response.
    """

    def __init__(
        self,
        rules: Sequence[HookRule],
        *,
        default: ClaudeHookResult | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        """Create an ordered hook policy with a deny-by-default fallback."""
        self.rules = tuple(rules)
        self.default = default or ClaudeHookResult(
            ClaudeHookDecision.DENY, "tool is not explicitly allowed"
        )
        self.audit = audit

    def handle(self, payload: Mapping[str, Any]) -> JsonObject:
        """Translate one Claude hook JSON object into Claude's JSON response."""
        event = self._parse_event(payload)
        result = self._decide(event)
        if self.audit is not None:
            try:
                self.audit.append(
                    "claude_pre_tool_decision",
                    event.tool_use_id,
                    {
                        "tool_name": event.tool_name,
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "session_id": event.session_id,
                        "cwd": event.cwd,
                        "tool_input": dict(event.tool_input),
                    },
                )
            except Exception:
                result = ClaudeHookResult(ClaudeHookDecision.DENY, "hook audit persistence failed")
        return {
            "hookSpecificOutput": {
                "hookEventName": _HOOK_EVENT,
                "permissionDecision": result.decision.value,
                "permissionDecisionReason": result.reason,
            }
        }

    def serve_stdio(
        self, input_stream: TextIO | None = None, output_stream: TextIO | None = None
    ) -> None:
        """Read Claude hook events from stdin and write decisions to stdout."""
        source = input_stream or sys.stdin
        destination = output_stream or sys.stdout
        for line in source:
            try:
                payload = json.loads(line)
                if not isinstance(payload, Mapping):
                    raise ValueError("Claude hook payload must be an object")
                response = self.handle(payload)
            except (json.JSONDecodeError, TypeError, ValueError):
                response = {
                    "hookSpecificOutput": {
                        "hookEventName": _HOOK_EVENT,
                        "permissionDecision": ClaudeHookDecision.DENY.value,
                        "permissionDecisionReason": "malformed Claude hook input",
                    }
                }
            destination.write(json.dumps(response, separators=(",", ":")) + "\n")
            destination.flush()

    def _decide(self, event: ClaudeToolEvent) -> ClaudeHookResult:
        """Evaluate rules without allowing a rule exception to authorize."""
        for rule in self.rules:
            try:
                result = rule(event)
            except Exception:
                return ClaudeHookResult(ClaudeHookDecision.DENY, "hook policy evaluation failed")
            if result is not None:
                return result
        return self.default

    @staticmethod
    def _parse_event(payload: Mapping[str, Any]) -> ClaudeToolEvent:
        """Validate only Claude-owned event fields needed by the policy."""
        tool_name = payload.get("tool_name")
        tool_input = payload.get("tool_input", {})
        tool_use_id = payload.get("tool_use_id")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("Claude tool_name is required")
        if not isinstance(tool_input, Mapping):
            raise ValueError("Claude tool_input must be an object")
        if not isinstance(tool_use_id, str) or not tool_use_id.strip():
            raise ValueError("Claude tool_use_id is required")
        session_id = payload.get("session_id")
        cwd = payload.get("cwd")
        if session_id is not None and not isinstance(session_id, str):
            raise ValueError("Claude session_id must be text")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("Claude cwd must be text")
        return ClaudeToolEvent(tool_name, dict(tool_input), tool_use_id, session_id, cwd)


def exact_tool_rule(
    tool_names: set[str] | frozenset[str],
    *,
    decision: ClaudeHookDecision = ClaudeHookDecision.ALLOW,
    reason: str = "tool is explicitly allowed",
) -> HookRule:
    """Create a rule matching an explicit set of Claude tool names."""
    names = frozenset(tool_names)
    result = ClaudeHookResult(decision, reason)

    def rule(event: ClaudeToolEvent) -> ClaudeHookResult | None:
        return result if event.tool_name in names else None

    return rule


def command_rule(
    patterns: Sequence[str],
    *,
    decision: ClaudeHookDecision,
    reason: str,
) -> HookRule:
    """Create a rule matching Bash ``command`` values with regex patterns."""
    compiled = tuple(re.compile(pattern) for pattern in patterns)
    result = ClaudeHookResult(decision, reason)

    def rule(event: ClaudeToolEvent) -> ClaudeHookResult | None:
        command = event.tool_input.get("command")
        if event.tool_name != "Bash" or not isinstance(command, str):
            return None
        return result if any(pattern.search(command) for pattern in compiled) else None

    return rule


def path_within_rule(
    tool_names: set[str] | frozenset[str],
    root: str | Path,
    *,
    reason: str = "path is outside the approved project directory",
) -> HookRule:
    """Allow file tools only when their path is lexically under ``root``."""
    names = frozenset(tool_names)
    allowed_root = Path(root).expanduser().resolve()
    denied = ClaudeHookResult(ClaudeHookDecision.DENY, reason)
    allowed = ClaudeHookResult(
        ClaudeHookDecision.ALLOW, "path is inside the approved project directory"
    )

    def rule(event: ClaudeToolEvent) -> ClaudeHookResult | None:
        if event.tool_name not in names:
            return None
        value = event.tool_input.get("file_path", event.tool_input.get("path"))
        if value is None and event.tool_name in {"Glob", "Grep"}:
            value = event.cwd
        if not isinstance(value, str) or not value.strip():
            return denied
        try:
            candidate = Path(value).expanduser().resolve()
            candidate.relative_to(allowed_root)
        except (OSError, RuntimeError, ValueError):
            return denied
        return allowed

    return rule


__all__ = [
    "ClaudeCodeHook",
    "ClaudeHookDecision",
    "ClaudeHookResult",
    "ClaudeToolEvent",
    "HookRule",
    "command_rule",
    "exact_tool_rule",
    "path_within_rule",
]

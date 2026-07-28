"""Fail-closed Codex CLI ``PreToolUse`` policy integration.

Codex owns the host sandbox and the eventual tool execution. This module
evaluates untrusted native-tool proposals before that boundary and emits only
documented Codex hook decisions. A policy outcome that requires approval is
audited as such but denied at ``PreToolUse`` because Codex cannot currently
turn that hook result into an approval prompt; applications should expose that
action through the SDK's governed MCP workflow instead.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, TextIO

from ._command_patterns import (
    MAX_COMMAND_TEXT_LENGTH,
    command_is_single_invocation,
    compile_command_patterns,
)
from .audit import AuditReplicationError, AuditSink, ReplicatedAuditSink

JsonObject = dict[str, Any]
_HOOK_EVENT: Final[str] = "PreToolUse"
_PROTECTED_PROJECT_STATE: Final = (
    Path(".codex"),
    Path(".claude"),
    Path(".git"),
    Path(".mcp.json"),
)
_PROTECTED_PROJECT_ROOT_NAMES: Final = frozenset(
    path.name.casefold() for path in _PROTECTED_PROJECT_STATE
)
_MAX_PATCH_TEXT_LENGTH: Final = 262_144
_MAX_PATCH_TARGETS: Final = 256
_ARGUMENT_SENSITIVE_TOOLS: Final = frozenset({"Bash", "apply_patch", "exec_command", "write_stdin"})


def _is_protected_project_state(relative: Path) -> bool:
    """Conservatively detect authority roots across host case semantics."""
    # A case-insensitive host may map .CoDeX to .codex while Path.resolve()
    # retains caller spelling. Enforce one invariant on every platform.
    return bool(relative.parts) and relative.parts[0].casefold() in _PROTECTED_PROJECT_ROOT_NAMES


def _content_digest(value: object) -> str:
    """Return a stable digest without persisting untrusted command content."""
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


class CodexHookDecision(StrEnum):
    """Policy outcomes understood by the SDK's Codex hook adapter."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class CodexPatchOperation(StrEnum):
    """Patch operations that central policy may grant independently."""

    ADD = "add"
    UPDATE = "update"
    DELETE = "delete"
    MOVE = "move"


@dataclass(frozen=True, slots=True)
class CodexToolEvent:
    """Validated, untrusted details of one Codex native-tool proposal."""

    tool_name: str
    tool_input: Mapping[str, Any]
    tool_use_id: str
    session_id: str | None = None
    cwd: str | None = None


@dataclass(frozen=True, slots=True)
class CodexHookResult:
    """One deterministic native-tool policy outcome and explanation."""

    decision: CodexHookDecision
    reason: str

    def __post_init__(self) -> None:
        """Reject ambiguous explanations before they reach the host boundary."""
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("hook decision reason must be non-empty")


CodexHookRule = Callable[[CodexToolEvent], CodexHookResult | None]


class CodexCliHook:
    """Evaluate Codex native tools with ordered, deny-by-default rules.

    The first matching rule wins. Unknown tools, malformed input, rule errors,
    and required-audit failures deny. ``ASK`` remains visible in audit evidence
    but is emitted to Codex as ``deny`` because current ``PreToolUse`` hooks do
    not support an ask decision and otherwise continue the tool call.
    """

    def __init__(
        self,
        rules: Sequence[CodexHookRule],
        *,
        default: CodexHookResult | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        """Create a hook from explicit rules and an optional required audit sink."""
        self.rules = tuple(rules)
        self.default = default or CodexHookResult(
            CodexHookDecision.DENY, "tool is not explicitly allowed"
        )
        self.audit = audit

    def handle(self, payload: Mapping[str, Any]) -> JsonObject:
        """Translate one Codex hook object into a documented hook response.

        An allowed call returns an empty object so ``serve_stdio`` can emit no
        output, which is Codex's documented successful-continue contract.
        Only denials use ``permissionDecision``; an allow decision without
        ``updatedInput`` is a host error and would continue fail-open.
        """
        try:
            if not isinstance(payload, Mapping):
                raise ValueError("Codex hook payload must be an object")
            event = self._parse_event(payload)
        except (TypeError, ValueError):
            # Direct API consumers need the same fail-closed contract as the
            # stdio adapter. Codex treats hook crashes as non-authoritative, so
            # malformed host input must become an explicit host denial here.
            return {
                "hookSpecificOutput": {
                    "hookEventName": _HOOK_EVENT,
                    "permissionDecision": CodexHookDecision.DENY.value,
                    "permissionDecisionReason": "malformed Codex hook input",
                }
            }
        result = self._decide(event)
        if self.audit is not None:
            try:
                self.audit.append(
                    "codex_pre_tool_decision",
                    event.tool_use_id,
                    {
                        "tool_name": event.tool_name,
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "session_id": event.session_id,
                        "cwd_hash": _content_digest(event.cwd) if event.cwd else None,
                        "tool_input_hash": _content_digest(dict(event.tool_input)),
                    },
                )
            except AuditReplicationError as exc:
                result = CodexHookResult(CodexHookDecision.DENY, "hook audit persistence failed")
                if isinstance(self.audit, ReplicatedAuditSink):
                    try:
                        self.audit.record_local_replication_failure(
                            "codex_pre_tool_effective_decision",
                            event.tool_use_id,
                            {
                                "tool_name": event.tool_name,
                                "decision": result.decision.value,
                                "reason": result.reason,
                                "session_id": event.session_id,
                                "cwd_hash": _content_digest(event.cwd) if event.cwd else None,
                                "tool_input_hash": _content_digest(dict(event.tool_input)),
                            },
                            exc.local_event,
                        )
                    except Exception:
                        # The host denial remains authoritative even if local
                        # compensation cannot be persisted either.
                        result = CodexHookResult(
                            CodexHookDecision.DENY,
                            "hook audit persistence failed; local failure evidence unavailable",
                        )
            except Exception:
                result = CodexHookResult(CodexHookDecision.DENY, "hook audit persistence failed")
        host_decision = (
            CodexHookDecision.DENY if result.decision is CodexHookDecision.ASK else result.decision
        )
        reason = result.reason
        if result.decision is CodexHookDecision.ASK:
            reason = (
                f"{reason}; Codex native hooks cannot request approval, "
                "use the governed MCP workflow"
            )
        if host_decision is CodexHookDecision.ALLOW:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": _HOOK_EVENT,
                "permissionDecision": host_decision.value,
                "permissionDecisionReason": reason,
            }
        }

    def serve_stdio(
        self, input_stream: TextIO | None = None, output_stream: TextIO | None = None
    ) -> None:
        """Read newline-delimited Codex events and emit one response per event."""
        source = input_stream or sys.stdin
        destination = output_stream or sys.stdout
        for line in source:
            try:
                payload = json.loads(line)
                if not isinstance(payload, Mapping):
                    raise ValueError("Codex hook payload must be an object")
                response = self.handle(payload)
            except (json.JSONDecodeError, TypeError, ValueError):
                response = {
                    "hookSpecificOutput": {
                        "hookEventName": _HOOK_EVENT,
                        "permissionDecision": CodexHookDecision.DENY.value,
                        "permissionDecisionReason": "malformed Codex hook input",
                    }
                }
            if response:
                destination.write(json.dumps(response, separators=(",", ":")) + "\n")
                destination.flush()

    def _decide(self, event: CodexToolEvent) -> CodexHookResult:
        """Evaluate rules without allowing a rule exception to authorize."""
        for rule in self.rules:
            try:
                result = rule(event)
            except Exception:
                return CodexHookResult(CodexHookDecision.DENY, "hook policy evaluation failed")
            if result is not None:
                return result
        return self.default

    @staticmethod
    def _parse_event(payload: Mapping[str, Any]) -> CodexToolEvent:
        """Validate only Codex-owned fields required for the policy decision."""
        if payload.get("hook_event_name") != _HOOK_EVENT:
            raise ValueError("Codex hook event must be PreToolUse")
        tool_name = payload.get("tool_name")
        tool_input = payload.get("tool_input", {})
        tool_use_id = payload.get("tool_use_id")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("Codex tool_name is required")
        if not isinstance(tool_input, Mapping):
            raise ValueError("Codex tool_input must be an object")
        if not isinstance(tool_use_id, str) or not tool_use_id.strip():
            raise ValueError("Codex tool_use_id is required")
        session_id = payload.get("session_id")
        cwd = payload.get("cwd")
        if session_id is not None and not isinstance(session_id, str):
            raise ValueError("Codex session_id must be text")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("Codex cwd must be text")
        return CodexToolEvent(tool_name, dict(tool_input), tool_use_id, session_id, cwd)


def codex_exact_tool_rule(
    tool_names: set[str] | frozenset[str],
    *,
    reason: str = "tool is explicitly allowed",
) -> CodexHookRule:
    """Allow exact tool names that do not require argument-aware policy.

    Native command, patch and process tools are rejected at construction.
    They must use the dedicated rules below so live arguments, paths and
    working-directory scope participate in every authorization decision.
    """
    names = frozenset(tool_names)
    unsafe = names & _ARGUMENT_SENSITIVE_TOOLS
    if unsafe:
        raise ValueError(
            "Codex argument-sensitive tools require a dedicated policy rule: "
            + ", ".join(sorted(unsafe))
        )
    result = CodexHookResult(CodexHookDecision.ALLOW, reason)

    def rule(event: CodexToolEvent) -> CodexHookResult | None:
        return result if event.tool_name in names else None

    return rule


def codex_tool_prefix_rule(
    prefixes: set[str] | frozenset[str],
    *,
    reason: str = "tool belongs to an explicitly trusted integration",
) -> CodexHookRule:
    """Allow canonical Codex tool names under an exact integration prefix."""
    allowed_prefixes = frozenset(prefixes)
    if any(not prefix or not prefix.endswith("__") for prefix in allowed_prefixes):
        raise ValueError("Codex tool prefixes must be non-empty and end with '__'")
    result = CodexHookResult(CodexHookDecision.ALLOW, reason)

    def rule(event: CodexToolEvent) -> CodexHookResult | None:
        matches = any(event.tool_name.startswith(prefix) for prefix in allowed_prefixes)
        return result if matches else None

    return rule


def codex_command_rule(
    patterns: Sequence[str],
    *,
    decision: CodexHookDecision,
    reason: str,
    allowed_root: str | Path | None = None,
) -> CodexHookRule:
    """Match Codex ``Bash`` text, confining allow results to ``allowed_root``."""
    compiled = compile_command_patterns(patterns)
    if decision is CodexHookDecision.ALLOW and allowed_root is None:
        raise ValueError("Codex command allow rules require an approved project root")
    approved_root = Path(allowed_root).expanduser().resolve() if allowed_root is not None else None
    result = CodexHookResult(decision, reason)

    def working_directories_are_approved(event: CodexToolEvent) -> bool:
        """Bind host and tool-level working directories to one approved root."""
        if approved_root is None or not isinstance(event.cwd, str) or not event.cwd.strip():
            return False
        try:
            event_root = Path(event.cwd).expanduser().resolve()
            candidates = [event_root]
            for key in ("cwd", "workdir", "working_directory"):
                if key not in event.tool_input:
                    continue
                value = event.tool_input[key]
                if not isinstance(value, str) or not value.strip():
                    return False
                candidate = Path(value).expanduser()
                candidates.append(
                    candidate.resolve()
                    if candidate.is_absolute()
                    else (event_root / candidate).resolve()
                )
            for candidate in candidates:
                candidate.relative_to(approved_root)
        except (OSError, RuntimeError, ValueError):
            return False
        return True

    def rule(event: CodexToolEvent) -> CodexHookResult | None:
        command = event.tool_input.get("command")
        if event.tool_name != "Bash" or not isinstance(command, str):
            return None
        if len(command) > MAX_COMMAND_TEXT_LENGTH:
            return CodexHookResult(
                CodexHookDecision.DENY, "command exceeds the policy evaluation limit"
            )
        if decision is CodexHookDecision.ALLOW and not command_is_single_invocation(command):
            return CodexHookResult(
                CodexHookDecision.DENY, "shell control syntax requires governed execution"
            )
        # An allow rule must authorize the entire shell string. Deny and ask
        # rules deliberately search anywhere so a dangerous component cannot
        # hide behind an otherwise harmless prefix.
        matches = (
            any(pattern.fullmatch(command) for pattern in compiled)
            if decision is CodexHookDecision.ALLOW
            else any(pattern.search(command) for pattern in compiled)
        )
        if (
            matches
            and decision is CodexHookDecision.ALLOW
            and not working_directories_are_approved(event)
        ):
            return CodexHookResult(
                CodexHookDecision.DENY,
                "command working directory is outside the approved project",
            )
        return result if matches else None

    return rule


def codex_patch_within_rule(
    root: str | Path,
    allowed_operations: Collection[CodexPatchOperation],
) -> CodexHookRule:
    """Allow only granted patch operations inside ``root`` and outside authority state."""
    allowed_root = Path(root).expanduser().resolve()
    granted = frozenset(allowed_operations)
    denied = CodexHookResult(
        CodexHookDecision.DENY, "patch target is missing or outside the approved project"
    )
    allowed = CodexHookResult(
        CodexHookDecision.ALLOW, "all patch targets are inside the approved project"
    )
    source_header = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$", re.MULTILINE)
    move_header = re.compile(r"^\*\*\* Move to: (.+)$", re.MULTILINE)

    def rule(event: CodexToolEvent) -> CodexHookResult | None:
        if event.tool_name != "apply_patch":
            return None
        command = event.tool_input.get("command")
        if not isinstance(command, str) or not event.cwd:
            return denied
        # Bound scans and filesystem work before materializing attacker-
        # controlled headers. Hook timeouts are not authoritative to the host.
        if len(command) > _MAX_PATCH_TEXT_LENGTH:
            return denied
        source_matches = list(source_header.finditer(command))
        if not source_matches:
            return denied
        operations = [CodexPatchOperation(match.group(1).lower()) for match in source_matches]
        if any(operation not in granted for operation in operations):
            return denied
        sources = [match.group(2) for match in source_matches]
        moves = [match.group(1) for match in move_header.finditer(command)]
        if moves and CodexPatchOperation.MOVE not in granted:
            return denied
        targets = [*sources, *moves]
        if len(targets) > _MAX_PATCH_TARGETS:
            return denied
        try:
            # Codex applies relative patch headers from the live hook working
            # directory. Bind validation to that same host-owned value so a
            # caller cannot authorize ``root / target`` while Codex writes
            # ``cwd / target`` somewhere else.
            event_root = Path(event.cwd).expanduser().resolve()
            event_root.relative_to(allowed_root)
        except (OSError, RuntimeError, ValueError):
            return denied
        for target in targets:
            # Codex's patch parser trims header suffix whitespace. Reject any
            # representation that would resolve differently after host parsing.
            if target != target.strip():
                return denied
            try:
                candidate = Path(target).expanduser()
                if not candidate.is_absolute():
                    candidate = event_root / candidate
                relative = candidate.resolve().relative_to(allowed_root)
                if _is_protected_project_state(relative):
                    return denied
            except (OSError, RuntimeError, ValueError):
                return denied
        return allowed

    return rule


__all__ = [
    "CodexCliHook",
    "CodexHookDecision",
    "CodexHookResult",
    "CodexPatchOperation",
    "CodexHookRule",
    "CodexToolEvent",
    "codex_command_rule",
    "codex_exact_tool_rule",
    "codex_patch_within_rule",
    "codex_tool_prefix_rule",
]

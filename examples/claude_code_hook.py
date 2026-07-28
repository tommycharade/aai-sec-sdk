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
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agentic_security import (
    AgentSessionStore,
    AgentSessionStoreError,
    ClaudeCodeHook,
    ClaudeHookDecision,
    ClaudeHookResult,
    ControlPlaneAgentClient,
    ControlPlaneDecisionExporter,
    ControlPlaneDependencyError,
    JsonlAuditSink,
    ReplicatedAuditSink,
    command_rule,
    exact_tool_rule,
    path_within_rule,
)
from agentic_security._command_patterns import compile_command_patterns


def _patterns_are_safe(patterns: list[str]) -> bool:
    """Reject invalid or availability-hostile policy regex before hook startup."""
    try:
        compile_command_patterns(patterns)
    except ValueError:
        return False
    return True


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
    if any(not _patterns_are_safe(value[field]) for field in list_fields[1:4]):
        return None
    audit_file = value.get("auditFile")
    if not isinstance(audit_file, str) or not audit_file:
        return None
    return value


def _string_list(value: object) -> list[str] | None:
    """Validate a central policy list before using it as hook authority."""
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        return None
    return value


def _control_plane_client(project_dir: Path) -> ControlPlaneAgentClient | None:
    """Build the enrolled client without accepting identity from Claude input."""
    control_plane_url = os.environ.get("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL")
    if not control_plane_url:
        return None
    deployment_id = os.environ.get("AAI_SEC_DEPLOYMENT_ID")
    agent_id = os.environ.get("AAI_SEC_AGENT_ID", "claude-code-local")
    if not deployment_id:
        return None
    session_store = None
    token = os.environ.get("AAI_SEC_AGENT_TOKEN")
    if os.environ.get("AAI_SEC_AGENT_SESSION_MODE") == "aws":
        try:
            session_store = AgentSessionStore(
                control_plane_url, deployment_id, agent_id, str(project_dir)
            )
            cached = session_store.load()
        except (AgentSessionStoreError, ValueError):
            return None
        if cached is not None:
            token = cached.token
    if not token:
        return None
    try:
        return ControlPlaneAgentClient(
            control_plane_url,
            token,
            agent_id=agent_id,
            project_root=str(project_dir),
            deployment_id=deployment_id,
            aws_agent_session=os.environ.get("AAI_SEC_AGENT_SESSION_MODE") == "aws",
            session_store=session_store,
            timeout_seconds=3,
        )
    except ValueError:
        return None


def _load_central_config(
    project_dir: Path,
    client: ControlPlaneAgentClient | None = None,
) -> dict[str, Any] | None:
    """Resolve the authenticated group policy for Claude native tools.

    The hook receives only routing metadata from onboarding. It reads the
    current short-lived bearer from the user-private host cache, falling back
    to the inherited first-session value before the gateway has persisted it.
    A central lookup failure is returned as ``None`` so the caller's existing
    invalid-policy path denies the event. The translation deliberately
    includes only Claude-native controls and keeps the SDK's immutable
    deny-by-default and redaction requirements.
    """
    control_plane_url = os.environ.get("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL")
    if not control_plane_url:
        return _load_safe_config(project_dir)
    client = client or _control_plane_client(project_dir)
    if client is None:
        return None
    try:
        effective = client.effective_policy()
    except (ControlPlaneDependencyError, ValueError):
        return None
    # The server-owned kill switch is mandatory. Absence, malformed values,
    # and an active stop all fail closed; only explicit JSON false activates
    # native rules from the returned policy.
    if effective.get("emergencyStop") is not False:
        return None
    policy = effective.get("policy")
    configuration = policy.get("configuration") if isinstance(policy, Mapping) else None
    if not isinstance(configuration, Mapping):
        return None
    policy_section = configuration.get("policy")
    audit_section = configuration.get("audit")
    if (
        not isinstance(policy_section, Mapping)
        or policy_section.get("denyByDefault") is not True
        or not isinstance(audit_section, Mapping)
        or audit_section.get("redactSensitiveData") is not True
    ):
        return None
    claude = configuration.get("claudeCode")
    tools = configuration.get("tools")
    if not isinstance(claude, Mapping):
        return None
    allowed_tools = _string_list(claude.get("allowedBuiltInTools"))
    file_tools = _string_list(claude.get("fileTools"))
    denied_patterns = _string_list(claude.get("deniedCommandPatterns"))
    approval_patterns = _string_list(claude.get("approvalCommandPatterns"))
    allowed_patterns = _string_list(claude.get("allowedCommandPatterns", []))
    if any(
        value is None
        for value in (
            allowed_tools,
            file_tools,
            denied_patterns,
            approval_patterns,
            allowed_patterns,
        )
    ):
        return None
    if not all(
        _patterns_are_safe(patterns or [])
        for patterns in (denied_patterns, approval_patterns, allowed_patterns)
    ):
        return None
    # Native-tool policy is intentionally separate from SDK-owned MCP tools.
    # An absent allow-list is an empty list, never an implicit allow-all.
    if not isinstance(tools, Mapping):
        return None
    return {
        "version": 1,
        "allowedTools": allowed_tools,
        "deniedCommandPatterns": denied_patterns,
        "approvalCommandPatterns": approval_patterns,
        "allowedCommandPatterns": allowed_patterns,
        "fileTools": file_tools,
        "auditFile": ".claude/security-audit.jsonl",
    }


def _build_hook() -> ClaudeCodeHook:
    """Construct the configured hook without consuming the event from stdin."""
    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve()
    central_client = _control_plane_client(project_dir)
    config = _load_central_config(project_dir, central_client)
    audit_path = project_dir / ".claude" / "security-audit.jsonl"
    if config is not None:
        configured_audit = Path(config["auditFile"])
        audit_path = (
            configured_audit if configured_audit.is_absolute() else project_dir / configured_audit
        )
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        local_audit = JsonlAuditSink(audit_path)
    except Exception:
        # Claude may continue after a hook process failure. Always produce an
        # explicit deny when the required local audit chain is unavailable.
        return ClaudeCodeHook(
            rules=[],
            default=ClaudeHookResult(
                ClaudeHookDecision.DENY, "Claude security audit is unavailable"
            ),
        )
    audit = (
        ReplicatedAuditSink(
            local_audit,
            ControlPlaneDecisionExporter(central_client, source="claude_native"),
        )
        if central_client is not None and central_client.aws_agent_session
        else local_audit
    )
    if config is None:
        hook = ClaudeCodeHook(
            rules=[],
            default=ClaudeHookResult(
                ClaudeHookDecision.DENY, "Claude security configuration is invalid"
            ),
            audit=audit,
        )
        return hook
    return ClaudeCodeHook(
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
                allowed_root=project_dir,
            ),
            # The allow-list is an authority boundary. Restrict path checks to
            # file tools that are also explicitly allowed; otherwise a
            # fileTools entry could accidentally bypass allowedTools.
            path_within_rule(set(config["fileTools"]) & set(config["allowedTools"]), project_dir),
            # Non-file tools need an explicit registration too. Bash is
            # intentionally handled only by the command rules above so a
            # broad Bash allow-list cannot bypass command restrictions.
            exact_tool_rule(
                set(config["allowedTools"]) - set(config["fileTools"]) - {"Bash"},
                reason="tool is explicitly allowed by the project policy",
            ),
        ],
        audit=audit,
    )


def main() -> None:
    """Read a Claude event and deny explicitly after any unexpected setup failure."""
    try:
        hook = _build_hook()
    except Exception:
        # Provider and filesystem adapters can fail outside their documented
        # exception sets. Never let a startup crash become a missing host
        # decision that Claude could treat as non-authoritative.
        hook = ClaudeCodeHook(
            rules=[],
            default=ClaudeHookResult(
                ClaudeHookDecision.DENY, "Claude security hook initialization failed"
            ),
        )
    hook.serve_stdio()


if __name__ == "__main__":
    main()

"""Fail-closed Codex CLI ``PreToolUse`` hook example.

The hook applies the centrally assigned native-tool policy to Codex ``Bash``
and ``apply_patch`` calls. Calls to the SDK's own MCP server are admitted to
the gateway because that gateway performs live SDK authorization itself. All
other native and MCP tools deny by default.
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
    CodexCliHook,
    CodexHookDecision,
    CodexHookResult,
    CodexPatchOperation,
    ControlPlaneAgentClient,
    ControlPlaneDecisionExporter,
    ControlPlaneDependencyError,
    JsonlAuditSink,
    ReplicatedAuditSink,
    codex_command_rule,
    codex_patch_within_rule,
    codex_tool_prefix_rule,
)
from agentic_security._command_patterns import compile_command_patterns

_MAX_LOCAL_AUDIT_BYTES = 1_000_000


def _string_list(value: object) -> list[str] | None:
    """Validate one policy list before it can become hook authority."""
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        return None
    return value


def _patterns_are_safe(patterns: list[str]) -> bool:
    """Reject invalid or availability-hostile policy regex before hook startup."""
    try:
        compile_command_patterns(patterns)
    except ValueError:
        return False
    return True


def _control_plane_client(project_dir: Path) -> ControlPlaneAgentClient | None:
    """Build an enrolled client without accepting identity from Codex input."""
    control_plane_url = os.environ.get("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL")
    deployment_id = os.environ.get("AAI_SEC_DEPLOYMENT_ID")
    agent_id = os.environ.get("AAI_SEC_AGENT_ID", "codex-cli-local")
    if not control_plane_url or not deployment_id:
        return None
    token = os.environ.get("AAI_SEC_AGENT_TOKEN")
    session_store = None
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


def _load_local_config(project_dir: Path) -> dict[str, Any] | None:
    """Translate the checked-in safe policy for an offline demonstration."""
    project_policy = project_dir / ".codex" / "aai-sec-config.json"
    fallback = Path(__file__).with_name("claude_safe_config.json")
    config_path = project_policy if project_policy.exists() else fallback
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("version") != 1:
        return None
    fields = (
        "allowedTools",
        "deniedCommandPatterns",
        "approvalCommandPatterns",
        "allowedCommandPatterns",
        "fileTools",
    )
    if any(_string_list(value.get(field)) is None for field in fields):
        return None
    if any(not _patterns_are_safe(value[field]) for field in fields[1:4]):
        return None
    return value


def _load_central_config(
    project_dir: Path,
    client: ControlPlaneAgentClient | None = None,
) -> dict[str, Any] | None:
    """Translate one authenticated enterprise policy into Codex-native controls."""
    if not os.environ.get("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL"):
        return _load_local_config(project_dir)
    client = client or _control_plane_client(project_dir)
    if client is None:
        return None
    try:
        effective = client.effective_policy()
    except (ControlPlaneDependencyError, ValueError):
        return None
    # The server-owned kill-switch state is mandatory. Missing, malformed, or
    # active state all fail closed; only an explicit JSON false admits policy.
    if effective.get("emergencyStop") is not False:
        return None
    policy = effective.get("policy")
    configuration = policy.get("configuration") if isinstance(policy, Mapping) else None
    if not isinstance(configuration, Mapping):
        return None
    policy_section = configuration.get("policy")
    audit_section = configuration.get("audit")
    native = configuration.get("claudeCode")
    if (
        not isinstance(policy_section, Mapping)
        or policy_section.get("denyByDefault") is not True
        or not isinstance(audit_section, Mapping)
        or audit_section.get("redactSensitiveData") is not True
        or not isinstance(native, Mapping)
    ):
        return None
    allowed_tools = _string_list(native.get("allowedBuiltInTools"))
    denied_patterns = _string_list(native.get("deniedCommandPatterns"))
    approval_patterns = _string_list(native.get("approvalCommandPatterns"))
    allowed_patterns = _string_list(native.get("allowedCommandPatterns", []))
    if any(
        value is None
        for value in (allowed_tools, denied_patterns, approval_patterns, allowed_patterns)
    ):
        return None
    if not all(
        _patterns_are_safe(patterns or [])
        for patterns in (denied_patterns, approval_patterns, allowed_patterns)
    ):
        return None
    return {
        "allowedTools": allowed_tools,
        "deniedCommandPatterns": denied_patterns,
        "approvalCommandPatterns": approval_patterns,
        "allowedCommandPatterns": allowed_patterns,
    }


def _build_hook() -> CodexCliHook:
    """Construct the configured hook without consuming events from stdin."""
    project_dir = Path(os.environ.get("AAI_SEC_PROJECT_ROOT", os.getcwd())).resolve()
    client = _control_plane_client(project_dir)
    config = _load_central_config(project_dir, client)
    audit_path = project_dir / ".codex" / "security-audit.jsonl"
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        # This short-lived process verifies the local chain at construction and
        # append. Cap both scans well below the generic sink's 100 MB maximum so
        # history cannot approach Codex's hook timeout. Full files fail closed
        # until an operator exports and rotates them; evidence is not discarded.
        if audit_path.exists() and audit_path.stat().st_size > _MAX_LOCAL_AUDIT_BYTES:
            raise RuntimeError("Codex local audit requires operator rotation")
        local_audit = JsonlAuditSink(audit_path, max_bytes=_MAX_LOCAL_AUDIT_BYTES)
    except Exception:
        # Codex treats a crashed hook as non-authoritative. A deny-only hook
        # response is therefore the only safe outcome when required evidence
        # storage cannot be initialized.
        return CodexCliHook(
            [],
            default=CodexHookResult(CodexHookDecision.DENY, "Codex security audit is unavailable"),
        )
    audit = (
        ReplicatedAuditSink(
            local_audit,
            ControlPlaneDecisionExporter(client, source="codex_native"),
        )
        if client is not None and client.aws_agent_session
        else local_audit
    )
    if config is None:
        return CodexCliHook(
            [],
            default=CodexHookResult(
                CodexHookDecision.DENY, "Codex security configuration is invalid"
            ),
            audit=audit,
        )
    allowed_tools = set(config["allowedTools"])
    rules = [
        codex_command_rule(
            tuple(config["deniedCommandPatterns"]),
            decision=CodexHookDecision.DENY,
            reason="dangerous shell command is blocked by the project policy",
        ),
        codex_command_rule(
            tuple(config["approvalCommandPatterns"]),
            decision=CodexHookDecision.ASK,
            reason="consequential command requires governed approval",
        ),
        codex_command_rule(
            tuple(config["allowedCommandPatterns"]),
            decision=CodexHookDecision.ALLOW,
            reason="command is explicitly allowed by the project policy",
            allowed_root=project_dir,
        ),
        codex_tool_prefix_rule(
            {"mcp__agentic-security__"},
            reason="the governed SDK gateway performs live authorization",
        ),
    ]
    patch_operations: set[CodexPatchOperation] = set()
    if "Edit" in allowed_tools:
        patch_operations.update({CodexPatchOperation.UPDATE, CodexPatchOperation.DELETE})
    if "Write" in allowed_tools:
        patch_operations.add(CodexPatchOperation.ADD)
    if {"Edit", "Write"} <= allowed_tools:
        patch_operations.add(CodexPatchOperation.MOVE)
    if patch_operations:
        rules.append(codex_patch_within_rule(project_dir, patch_operations))
    return CodexCliHook(rules, audit=audit)


def main() -> None:
    """Read Codex events and deny explicitly after any unexpected setup failure."""
    try:
        hook = _build_hook()
    except Exception:
        # A provider or filesystem adapter can fail outside its documented
        # exception set. Codex treats a crashed hook as non-authoritative, so
        # no setup exception may escape without a structured denial.
        hook = CodexCliHook(
            [],
            default=CodexHookResult(
                CodexHookDecision.DENY, "Codex security hook initialization failed"
            ),
        )
    hook.serve_stdio()


if __name__ == "__main__":
    main()

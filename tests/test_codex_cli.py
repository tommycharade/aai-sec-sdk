"""Adversarial tests for Codex CLI native-tool enforcement."""

from __future__ import annotations

import io
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import examples.codex_cli_hook as codex_hook_example
import pytest

from agentic_security.audit import InMemoryAuditSink, ReplicatedAuditSink
from agentic_security.codex_cli import (
    CodexCliHook,
    CodexHookDecision,
    CodexHookResult,
    CodexPatchOperation,
    codex_command_rule,
    codex_exact_tool_rule,
    codex_patch_within_rule,
    codex_tool_prefix_rule,
)
from agentic_security.codex_cli import _content_digest as codex_content_digest

ALL_PATCH_OPERATIONS = frozenset(CodexPatchOperation)
ADD_PATCH = "*** Begin Patch\n*** Add File: new.py\n+new\n*** End Patch"
UPDATE_PATCH = "*** Begin Patch\n*** Update File: old.py\n@@\n-old\n+new\n*** End Patch"
DELETE_PATCH = "*** Begin Patch\n*** Delete File: old.py\n*** End Patch"
MOVE_PATCH = (
    "*** Begin Patch\n*** Update File: old.py\n*** Move to: new.py\n@@\n-old\n+new\n*** End Patch"
)


def event(
    tool_name: str,
    tool_input: dict[str, object],
    *,
    tool_use_id: str = "tool:1",
    cwd: str | None = "/workspace/project",
) -> dict[str, object]:
    """Build one synthetic Codex ``PreToolUse`` event."""
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
        "session_id": "session:synthetic",
        "cwd": cwd,
    }


def test_codex_content_digest_is_canonical_and_content_bound() -> None:
    """Audit digests preserve exact canonical evidence without storing raw content."""
    value = {"z": 1, "a": "é"}
    expected = sha256('{"a":"é","z":1}'.encode()).hexdigest()

    assert codex_content_digest(value) == expected
    assert codex_content_digest({"z": 2, "a": "é"}) != expected


def test_codex_hook_allows_only_explicit_tools_and_denies_unknown_tools() -> None:
    """The default cannot authorize an unregistered native capability."""
    hook = CodexCliHook([codex_exact_tool_rule({"mcp__agentic-security__propose"})])

    allowed = hook.handle(event("mcp__agentic-security__propose", {"tool": "lookup"}))
    denied = hook.handle(event("mcp__unknown__execute", {}))

    assert allowed == {}
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("tool_name", ["Bash", "apply_patch", "exec_command", "write_stdin"])
def test_codex_exact_tool_rule_rejects_argument_sensitive_tools(tool_name: str) -> None:
    """Name-only authority cannot bypass command, patch, path, or process checks."""
    with pytest.raises(ValueError, match="dedicated policy rule"):
        codex_exact_tool_rule({tool_name})


def test_codex_tool_prefix_rule_is_scoped_to_one_registered_server() -> None:
    """Trusting the governed gateway cannot authorize another MCP server."""
    hook = CodexCliHook([codex_tool_prefix_rule({"mcp__agentic-security__"})])

    allowed = hook.handle(event("mcp__agentic-security__lookup_record", {}))
    assert allowed == {}
    assert (
        hook.handle(event("mcp__github__create_issue", {}))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "deny"
    )
    with pytest.raises(ValueError, match="end with"):
        codex_tool_prefix_rule({"mcp__unsafe"})


def test_codex_hook_orders_command_rules_and_converts_ask_to_deny() -> None:
    """An approval rule cannot use Codex's unsupported, fail-open ask value."""
    hook = CodexCliHook(
        [
            codex_command_rule(
                (r"rm\s+-rf",),
                decision=CodexHookDecision.DENY,
                reason="dangerous command is blocked",
            ),
            codex_command_rule(
                (r"git\s+push",),
                decision=CodexHookDecision.ASK,
                reason="command requires approval",
            ),
            codex_command_rule(
                (r"git\s+status",),
                decision=CodexHookDecision.ALLOW,
                reason="command is allowed",
                allowed_root="/workspace/project",
            ),
        ]
    )

    assert (
        hook.handle(event("Bash", {"command": "rm -rf /tmp/x"}))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "deny"
    )
    approval = hook.handle(event("Bash", {"command": "git push origin main"}))["hookSpecificOutput"]
    assert approval["permissionDecision"] == "deny"
    assert "governed MCP" in approval["permissionDecisionReason"]
    assert hook.handle(event("Bash", {"command": "git status"})) == {}
    appended = hook.handle(event("Bash", {"command": "git status && touch outside"}))
    assert appended["hookSpecificOutput"]["permissionDecision"] == "deny"
    multiline = hook.handle(event("Bash", {"command": "git status\npython evil.py"}))
    assert multiline["hookSpecificOutput"]["permissionDecision"] == "deny"
    nested = CodexCliHook(
        [
            codex_command_rule(
                (r"bash -c 'echo safe; touch /tmp/escaped'",),
                decision=CodexHookDecision.ALLOW,
                reason="broad nested shell",
                allowed_root="/workspace/project",
            )
        ]
    ).handle(event("Bash", {"command": "bash -c 'echo safe; touch /tmp/escaped'"}))
    assert nested["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert nested["hookSpecificOutput"]["permissionDecisionReason"] == (
        "shell control syntax requires governed execution"
    )


def test_codex_command_rules_reject_unsafe_patterns_and_oversized_input() -> None:
    """Regex denial-of-service cannot turn the native hook into a fail-open timeout."""
    with pytest.raises(ValueError, match="backtracking"):
        codex_command_rule(
            (r"(a+)+",),
            decision=CodexHookDecision.ALLOW,
            reason="unsafe",
            allowed_root="/workspace/project",
        )
    hook = CodexCliHook(
        [
            codex_command_rule(
                (r"pwd",),
                decision=CodexHookDecision.ALLOW,
                reason="safe",
                allowed_root="/workspace/project",
            )
        ]
    )
    oversized = hook.handle(event("Bash", {"command": "a" * 8_193}))
    assert oversized["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert oversized["hookSpecificOutput"]["permissionDecisionReason"] == (
        "command exceeds the policy evaluation limit"
    )
    boundary = CodexCliHook(
        [
            codex_command_rule(
                (r"a{8192}",),
                decision=CodexHookDecision.ALLOW,
                reason="boundary command is allowed",
                allowed_root="/workspace/project",
            )
        ]
    ).handle(event("Bash", {"command": "a" * 8_192}))
    assert boundary == {}
    broad = CodexCliHook(
        [
            codex_command_rule(
                (r"git status[ ;A-Za-z]*",),
                decision=CodexHookDecision.ALLOW,
                reason="broad",
                allowed_root="/workspace/project",
            )
        ]
    )
    controlled = broad.handle(event("Bash", {"command": "git status;python evil"}))
    assert controlled["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "shell control" in controlled["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_command_allow_rule_requires_and_confines_live_working_directory(
    tmp_path: Path,
) -> None:
    """Command text cannot authorize reads from a different repository or symlink."""
    with pytest.raises(ValueError, match="approved project root"):
        codex_command_rule(
            (r"git status",),
            decision=CodexHookDecision.ALLOW,
            reason="missing scope",
        )
    project = tmp_path / "project"
    subdirectory = project / "src"
    outside = tmp_path / "outside"
    subdirectory.mkdir(parents=True)
    outside.mkdir()
    (project / "external-link").symlink_to(outside, target_is_directory=True)
    hook = CodexCliHook(
        [
            codex_command_rule(
                (r"git status",),
                decision=CodexHookDecision.ALLOW,
                reason="scoped read",
                allowed_root=project,
            )
        ]
    )

    inside_event = event("Bash", {"command": "git status"})
    inside_event["cwd"] = str(subdirectory)
    assert hook.handle(inside_event) == {}

    escaping_cases: tuple[tuple[str | None, dict[str, object]], ...] = (
        (None, {"command": "git status"}),
        (str(outside), {"command": "git status"}),
        (str(project), {"command": "git status", "workdir": "../outside"}),
        (str(project), {"command": "git status", "cwd": "external-link"}),
        (str(project), {"command": "git status", "working_directory": 7}),
    )
    for cwd, tool_input in escaping_cases:
        proposed = event("Bash", tool_input)
        if cwd is None:
            proposed.pop("cwd")
        else:
            proposed["cwd"] = cwd
        result = hook.handle(proposed)["hookSpecificOutput"]
        assert result["permissionDecision"] == "deny"
        assert result["permissionDecisionReason"] == (
            "command working directory is outside the approved project"
        )


def test_codex_approval_requirement_remains_visible_in_audit() -> None:
    """Operations can distinguish approval routing from an ordinary denial."""

    class RecordingAudit:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, object]]] = []

        def append(
            self,
            event_type: str,
            _request_id: str,
            payload: dict[str, object],
        ) -> None:
            self.events.append((event_type, payload))

    audit = RecordingAudit()
    hook = CodexCliHook(
        [
            codex_command_rule(
                (r"git\s+push",),
                decision=CodexHookDecision.ASK,
                reason="command requires approval",
            )
        ],
        audit=audit,  # type: ignore[arg-type]
    )

    hook.handle(event("Bash", {"command": "git push origin main"}))

    assert audit.events[0][0] == "codex_pre_tool_decision"
    assert audit.events[0][1]["decision"] == "ask"
    assert audit.events[0][1]["tool_input_hash"]
    assert "tool_input" not in audit.events[0][1]
    assert "git push" not in json.dumps(audit.events)


def test_codex_patch_rule_requires_every_target_inside_project(tmp_path: Path) -> None:
    """A multi-file patch is denied when any declared path escapes the root."""
    hook = CodexCliHook([codex_patch_within_rule(tmp_path, ALL_PATCH_OPERATIONS)])
    inside = "*** Begin Patch\n*** Add File: src/new.py\n+pass\n*** End Patch"
    mixed = (
        "*** Begin Patch\n"
        "*** Update File: src/new.py\n"
        "@@\n-pass\n+value = 1\n"
        "*** Add File: ../outside.py\n+bad = True\n"
        "*** End Patch"
    )

    allowed = hook.handle(event("apply_patch", {"command": inside}, cwd=str(tmp_path)))
    denied = hook.handle(event("apply_patch", {"command": mixed}, cwd=str(tmp_path)))[
        "hookSpecificOutput"
    ]
    assert allowed == {}
    assert denied == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "patch target is missing or outside the approved project",
    }
    escaping_move = (
        "*** Begin Patch\n"
        "*** Update File: src/new.py\n"
        "*** Move to: ../outside.py\n"
        "@@\n-pass\n+value = 1\n"
        "*** End Patch"
    )
    assert (
        hook.handle(event("apply_patch", {"command": escaping_move}, cwd=str(tmp_path)))[
            "hookSpecificOutput"
        ]["permissionDecision"]
        == "deny"
    )


@pytest.mark.parametrize(
    ("operations", "patch", "expected"),
    [
        ({CodexPatchOperation.ADD}, ADD_PATCH, "allow"),
        ({CodexPatchOperation.UPDATE}, UPDATE_PATCH, "allow"),
        ({CodexPatchOperation.DELETE}, DELETE_PATCH, "allow"),
        ({CodexPatchOperation.UPDATE}, ADD_PATCH, "deny"),
        ({CodexPatchOperation.ADD}, UPDATE_PATCH, "deny"),
        ({CodexPatchOperation.ADD}, DELETE_PATCH, "deny"),
        ({CodexPatchOperation.UPDATE}, MOVE_PATCH, "deny"),
        ({CodexPatchOperation.UPDATE, CodexPatchOperation.MOVE}, MOVE_PATCH, "allow"),
    ],
)
def test_codex_patch_rule_requires_each_operation_grant(
    tmp_path: Path,
    operations: set[CodexPatchOperation],
    patch: str,
    expected: str,
) -> None:
    """Path confinement cannot turn one granted patch operation into another."""
    result = CodexCliHook([codex_patch_within_rule(tmp_path, operations)]).handle(
        event("apply_patch", {"command": patch}, cwd=str(tmp_path))
    )
    actual = result.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
    assert actual == expected


@pytest.mark.parametrize(
    "suffix",
    [" ", "\t", "\r"],
)
def test_codex_patch_rule_rejects_host_trimmed_header_suffix(tmp_path: Path, suffix: str) -> None:
    """The SDK and host cannot authorize different textual path representations."""
    patch = (
        f"*** Begin Patch\n*** Update File: .codex/config.toml{suffix}\n"
        "@@\n-old\n+new\n*** End Patch"
    )
    result = CodexCliHook([codex_patch_within_rule(tmp_path, ALL_PATCH_OPERATIONS)]).handle(
        event("apply_patch", {"command": patch}, cwd=str(tmp_path))
    )
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    ("allowed_tools", "patch", "expected"),
    [
        (["Write"], ADD_PATCH, "allow"),
        (["Write"], DELETE_PATCH, "deny"),
        (["Edit"], UPDATE_PATCH, "allow"),
        (["Edit"], ADD_PATCH, "deny"),
        (["Edit"], MOVE_PATCH, "deny"),
        (["Edit", "Write"], MOVE_PATCH, "allow"),
    ],
)
def test_codex_example_maps_tool_permissions_to_patch_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    allowed_tools: list[str],
    patch: str,
    expected: str,
) -> None:
    """The installed hook preserves Edit/Write semantics for every patch."""
    config = {
        "allowedTools": allowed_tools,
        "deniedCommandPatterns": [],
        "approvalCommandPatterns": [],
        "allowedCommandPatterns": [],
    }
    monkeypatch.setenv("AAI_SEC_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr(codex_hook_example, "_control_plane_client", lambda _root: None)
    monkeypatch.setattr(
        codex_hook_example,
        "_load_central_config",
        lambda _root, _client: config,
    )

    result = codex_hook_example._build_hook().handle(
        event("apply_patch", {"command": patch}, cwd=str(tmp_path))
    )
    actual = result.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
    assert actual == expected


@pytest.mark.parametrize(
    "protected_path",
    [
        ".codex/config.toml",
        ".codex/aai-sec-config.json",
        ".codex/security-audit.jsonl",
        ".claude/settings.json",
        ".git/config",
        ".git/hooks/pre-commit",
        ".mcp.json",
        ".ClAuDe/settings.json",
        ".CoDeX/config.toml",
        ".GIT/hooks/pre-commit",
        ".MCP.JSON",
    ],
)
def test_codex_patch_rule_protects_project_security_state(
    tmp_path: Path, protected_path: str
) -> None:
    """A patch cannot rewrite policy, hook, MCP, or native evidence state."""
    patch = f"*** Begin Patch\n*** Add File: {protected_path}\n+tampered\n*** End Patch"

    result = CodexCliHook([codex_patch_within_rule(tmp_path, ALL_PATCH_OPERATIONS)]).handle(
        event("apply_patch", {"command": patch}, cwd=str(tmp_path))
    )

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("tool_input", [{}, {"command": 7}, {"command": "not a patch"}])
def test_codex_patch_rule_denies_missing_or_malformed_targets(
    tmp_path: Path, tool_input: dict[str, object]
) -> None:
    """Malformed patch input cannot bypass target validation."""
    result = CodexCliHook([codex_patch_within_rule(tmp_path, ALL_PATCH_OPERATIONS)]).handle(
        event("apply_patch", tool_input, cwd=str(tmp_path))
    )
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_patch_rule_bounds_text_and_target_count(tmp_path: Path) -> None:
    """Oversized patch work denies before it can exhaust the native hook."""
    hook = CodexCliHook([codex_patch_within_rule(tmp_path, ALL_PATCH_OPERATIONS)])
    oversized = "*** Begin Patch\n*** Add File: safe.py\n+" + ("x" * 262_145)
    excessive = "*** Begin Patch\n" + "".join(
        f"*** Add File: generated-{index}.py\n+value\n" for index in range(257)
    )

    assert (
        hook.handle(event("apply_patch", {"command": oversized}, cwd=str(tmp_path)))[
            "hookSpecificOutput"
        ]["permissionDecision"]
        == "deny"
    )
    assert (
        hook.handle(event("apply_patch", {"command": excessive}, cwd=str(tmp_path)))[
            "hookSpecificOutput"
        ]["permissionDecision"]
        == "deny"
    )


def test_codex_patch_rule_binds_relative_targets_to_live_cwd(tmp_path: Path) -> None:
    """Relative targets cannot escape or rewrite protected state through hook cwd."""
    hook = CodexCliHook([codex_patch_within_rule(tmp_path, ALL_PATCH_OPERATIONS)])
    patch = "*** Begin Patch\n*** Add File: marker.txt\n+safe\n*** End Patch"
    subdirectory = tmp_path / "src"
    protected = tmp_path / ".codex"
    outside = tmp_path.parent / "outside"
    subdirectory.mkdir()
    protected.mkdir()
    outside.mkdir(exist_ok=True)

    assert hook.handle(event("apply_patch", {"command": patch}, cwd=str(subdirectory))) == {}
    for cwd in (str(outside), str(protected), None):
        result = hook.handle(event("apply_patch", {"command": patch}, cwd=cwd))
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_hook_rule_and_audit_failures_deny() -> None:
    """Policy and required-evidence failures never authorize execution."""

    def broken_rule(_event: object) -> CodexHookResult:
        raise RuntimeError("synthetic policy failure")

    class BrokenAudit:
        def append(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic audit failure")

    policy_failure = CodexCliHook([broken_rule]).handle(event("Bash", {"command": "pwd"}))
    audit_failure = CodexCliHook(
        [
            codex_command_rule(
                [r"^pwd$"],
                decision=CodexHookDecision.ALLOW,
                reason="synthetic allowed command",
                allowed_root="/workspace/project",
            )
        ],
        audit=BrokenAudit(),  # type: ignore[arg-type]
    ).handle(event("Bash", {"command": "pwd"}))

    assert policy_failure["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert audit_failure["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "audit" in audit_failure["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_replication_failure_records_effective_denial_locally() -> None:
    """Local evidence supersedes a provisional allow when export fails."""

    class BrokenExporter:
        def export(self, _event: object) -> None:
            raise OSError("synthetic remote outage")

    primary = InMemoryAuditSink()
    hook = CodexCliHook(
        [
            codex_command_rule(
                [r"^pwd$"],
                decision=CodexHookDecision.ALLOW,
                reason="synthetic allowed command",
                allowed_root="/workspace/project",
            )
        ],
        audit=ReplicatedAuditSink(primary, BrokenExporter()),
    )

    result = hook.handle(event("Bash", {"command": "pwd"}))
    events = primary.events()

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert [item.payload["decision"] for item in events] == ["allow", "deny"]
    assert events[1].event_type == "codex_pre_tool_effective_decision"
    assert events[1].payload["replication_status"] == "failed"
    assert events[1].payload["supersedes_event_hash"] == events[0].event_hash


def test_codex_stdio_rejects_wrong_event_and_malformed_json() -> None:
    """The process contract emits one fail-closed response per bad line."""
    source = io.StringIO(
        json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
                "tool_use_id": "tool:1",
            }
        )
        + "\n{bad json\n"
    )
    destination = io.StringIO()

    CodexCliHook([]).serve_stdio(source, destination)

    responses = [json.loads(line) for line in destination.getvalue().splitlines()]
    assert len(responses) == 2
    assert all(
        response["hookSpecificOutput"]["permissionDecision"] == "deny" for response in responses
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"hook_event_name": "PostToolUse"},
        {"hook_event_name": "PreToolUse", "tool_name": 7, "tool_use_id": "tool:1"},
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": [],
            "tool_use_id": "tool:1",
        },
    ],
)
def test_codex_direct_handle_returns_explicit_denial_for_malformed_payload(
    payload: dict[str, object],
) -> None:
    """Malformed direct API input cannot escape as a fail-open hook error."""
    result = CodexCliHook([]).handle(payload)

    assert result == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "malformed Codex hook input",
        }
    }


def test_codex_direct_handle_denies_a_non_mapping_payload() -> None:
    """Runtime type violations still return an authoritative denial."""
    result = CodexCliHook([]).handle(cast(Any, ["not", "an", "object"]))

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_native_hook_resolves_central_policy_and_emergency_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex consumes authenticated policy and fails closed on a fleet stop."""

    class Client:
        def __init__(self, stopped: bool = False) -> None:
            self.stopped = stopped

        def effective_policy(self) -> dict[str, object]:
            return {
                "emergencyStop": self.stopped,
                "policy": {
                    "configuration": {
                        "policy": {"denyByDefault": True},
                        "claudeCode": {
                            "allowedBuiltInTools": ["Edit"],
                            "deniedCommandPatterns": [r"rm\s+-rf"],
                            "approvalCommandPatterns": [r"git\s+push"],
                            "allowedCommandPatterns": [r"git\s+status"],
                        },
                        "audit": {"redactSensitiveData": True},
                    }
                },
            }

    monkeypatch.setenv("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL", "https://fleet.example.test/api")
    config = codex_hook_example._load_central_config(tmp_path, Client())  # type: ignore[arg-type]

    assert config is not None
    assert config["allowedTools"] == ["Edit"]
    assert config["allowedCommandPatterns"] == [r"git\s+status"]
    assert (
        codex_hook_example._load_central_config(tmp_path, Client(stopped=True))  # type: ignore[arg-type]
        is None
    )

    class InvalidStopClient(Client):
        def __init__(self, value: object) -> None:
            super().__init__()
            self.value = value

        def effective_policy(self) -> dict[str, object]:
            value = super().effective_policy()
            value["emergencyStop"] = self.value
            return value

    for invalid_stop in (None, "false", 0):
        assert (
            codex_hook_example._load_central_config(
                tmp_path, cast(Any, InvalidStopClient(invalid_stop))
            )
            is None
        )

    class InvalidClient(Client):
        def effective_policy(self) -> dict[str, object]:
            value = super().effective_policy()
            policy = value["policy"]
            assert isinstance(policy, dict)
            configuration = policy["configuration"]
            assert isinstance(configuration, dict)
            native = configuration["claudeCode"]
            assert isinstance(native, dict)
            native["allowedCommandPatterns"] = ["(a+)+"]
            return value

    assert codex_hook_example._load_central_config(tmp_path, cast(Any, InvalidClient())) is None


def test_codex_local_policy_rejects_unsafe_legacy_pattern(tmp_path: Path) -> None:
    """A policy saved before API validation cannot bypass hook-local screening."""
    policy = json.loads(
        (Path.cwd() / "examples" / "claude_safe_config.json").read_text(encoding="utf-8")
    )
    policy["allowedCommandPatterns"] = ["(a+)+"]
    config_dir = tmp_path / ".codex"
    config_dir.mkdir()
    (config_dir / "aai-sec-config.json").write_text(json.dumps(policy), encoding="utf-8")

    assert codex_hook_example._load_local_config(tmp_path) is None


@pytest.mark.parametrize(
    "command",
    [
        "git diff --no-index --output=.codex/security-audit.jsonl /dev/null /dev/null",
        "git log --output=.codex/aai-sec-config.json",
        "pytest tests/test_owned.py",
        "python -m pytest tests/test_owned.py",
    ],
)
def test_codex_offline_fallback_denies_write_capable_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    """The shipped fallback cannot write authority state or execute project tests."""
    monkeypatch.setenv("AAI_SEC_PROJECT_ROOT", str(tmp_path))
    for name in (
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL",
        "AAI_SEC_AGENT_TOKEN",
        "AAI_SEC_DEPLOYMENT_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    result = codex_hook_example._build_hook().handle(event("Bash", {"command": command}))

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_hook_main_denies_when_audit_initialization_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit corruption or permissions return a denial instead of crashing the hook."""

    class BrokenAudit:
        def __init__(self, _path: Path) -> None:
            raise ValueError("synthetic corrupt chain")

    destination = io.StringIO()
    monkeypatch.setenv("AAI_SEC_PROJECT_ROOT", str(tmp_path))
    for name in (
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL",
        "AAI_SEC_AGENT_TOKEN",
        "AAI_SEC_DEPLOYMENT_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(codex_hook_example, "JsonlAuditSink", BrokenAudit)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps(event("Bash", {"command": "pwd"})) + "\n")
    )
    monkeypatch.setattr("sys.stdout", destination)

    codex_hook_example.main()

    result = json.loads(destination.getvalue())
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "audit is unavailable" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_hook_caps_local_audit_verification_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A large history denies before the per-invocation hook rescans its chain."""
    audit_path = tmp_path / ".codex" / "security-audit.jsonl"
    audit_path.parent.mkdir()
    audit_path.write_bytes(b"x" * 1_000_001)

    class UnexpectedAudit:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("oversized audit must be rejected before construction")

    monkeypatch.setenv("AAI_SEC_PROJECT_ROOT", str(tmp_path))
    for name in (
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL",
        "AAI_SEC_AGENT_TOKEN",
        "AAI_SEC_DEPLOYMENT_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(codex_hook_example, "JsonlAuditSink", UnexpectedAudit)

    result = codex_hook_example._build_hook().handle(event("Bash", {"command": "pwd"}))

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "audit is unavailable" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_hook_constructs_audit_with_bounded_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Normal hook startup pins the local chain to the reviewed scan bound."""
    captured: list[int] = []

    class RecordingAudit(InMemoryAuditSink):
        def __init__(self, _path: Path, *, max_bytes: int) -> None:
            captured.append(max_bytes)
            super().__init__()

    monkeypatch.setenv("AAI_SEC_PROJECT_ROOT", str(tmp_path))
    for name in (
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL",
        "AAI_SEC_AGENT_TOKEN",
        "AAI_SEC_DEPLOYMENT_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(codex_hook_example, "JsonlAuditSink", RecordingAudit)

    codex_hook_example._build_hook()

    assert captured == [1_000_000]


def test_codex_hook_main_denies_after_unexpected_setup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An adapter exception outside its declared contract cannot crash fail open."""

    def fail_setup(_project: Path, _client: object) -> None:
        raise RuntimeError("synthetic unexpected provider failure")

    destination = io.StringIO()
    monkeypatch.setenv("AAI_SEC_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr(codex_hook_example, "_load_central_config", fail_setup)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps(event("Bash", {"command": "pwd"})) + "\n")
    )
    monkeypatch.setattr("sys.stdout", destination)

    codex_hook_example.main()

    result = json.loads(destination.getvalue())
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "initialization failed" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_local_hook_subprocess_contract_allows_safe_status_and_denies_push(
    tmp_path: Path,
) -> None:
    """The runnable adapter emits valid host decisions without a global install."""
    import os
    import subprocess
    import sys

    hook_path = Path.cwd() / "examples" / "codex_cli_hook.py"
    proposals = [
        event("Bash", {"command": "git status"}, tool_use_id="tool:status"),
        event("Bash", {"command": "git push origin main"}, tool_use_id="tool:push"),
        event(
            "Bash",
            {"command": "git status\npython evil.py"},
            tool_use_id="tool:newline",
        ),
    ]
    for proposal in proposals:
        proposal["cwd"] = str(tmp_path)
    payloads = "\n".join(json.dumps(proposal) for proposal in proposals)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path.cwd() / "src")
    environment["AAI_SEC_PROJECT_ROOT"] = str(tmp_path)
    for name in (
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL",
        "AAI_SEC_AGENT_TOKEN",
        "AAI_SEC_DEPLOYMENT_ID",
    ):
        environment.pop(name, None)

    result = subprocess.run(  # noqa: S603 - fixed interpreter and checked-in hook
        [sys.executable, str(hook_path)],
        cwd=Path.cwd(),
        input=payloads + "\n",
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    decisions = [
        json.loads(line)["hookSpecificOutput"]["permissionDecision"]
        for line in result.stdout.splitlines()
    ]
    assert decisions == ["deny", "deny"]
    audit_path = tmp_path / ".codex" / "security-audit.jsonl"
    audit_events = [
        json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [item["payload"]["decision"] for item in audit_events] == ["allow", "ask", "deny"]

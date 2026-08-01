from __future__ import annotations

import io
import json
import time
from hashlib import sha256
from pathlib import Path
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parser  # type: ignore[attr-defined]
from typing import Any, cast

import examples.claude_code_hook as claude_hook_example
import pytest

from agentic_security import (
    AgentSessionCredential,
    AgentSessionStore,
    ClaudeCodeHook,
    ClaudeHookDecision,
    ClaudeHookResult,
    InMemoryAuditSink,
    JsonlAuditSink,
    PolicyTrustStore,
    ReplicatedAuditSink,
    command_rule,
    exact_tool_rule,
    path_within_rule,
)
from agentic_security._command_patterns import (
    _atom_matches_literal,
    _category_matches_literal,
    _leading_atoms,
    command_is_single_invocation,
    compile_command_patterns,
)
from agentic_security.claude_code import _content_digest as claude_content_digest


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


def test_claude_content_digest_is_canonical_and_content_bound() -> None:
    """Audit digests preserve exact canonical evidence without storing raw content."""
    value = {"z": 1, "a": "é"}
    expected = sha256('{"a":"é","z":1}'.encode()).hexdigest()

    assert claude_content_digest(value) == expected
    assert claude_content_digest({"z": 2, "a": "é"}) != expected


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
            command_rule(
                (r"git\s+status",),
                decision=ClaudeHookDecision.ALLOW,
                reason="safe",
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
    appended = hook.handle(event("Bash", {"command": "git status && touch outside"}))
    assert appended["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert appended["hookSpecificOutput"]["permissionDecisionReason"] == (
        "shell control syntax requires governed execution"
    )
    multiline = hook.handle(event("Bash", {"command": "git status\npython evil.py"}))
    assert multiline["hookSpecificOutput"]["permissionDecision"] == "deny"

    missing_cwd = event("Bash", {"command": "git status"})
    missing_cwd.pop("cwd")
    assert hook.handle(missing_cwd)["hookSpecificOutput"]["permissionDecision"] == "deny"
    outside_cwd = event("Bash", {"command": "git status"})
    outside_cwd["cwd"] = "/workspace/other-project"
    outside = hook.handle(outside_cwd)["hookSpecificOutput"]
    assert outside["permissionDecision"] == "deny"
    assert outside["permissionDecisionReason"] == (
        "command working directory is outside the approved project"
    )


def test_claude_command_rules_reject_unsafe_patterns_and_oversized_input() -> None:
    """Regex denial-of-service cannot turn the native hook into a fail-open timeout."""
    with pytest.raises(ValueError, match="backtracking"):
        command_rule((r"(a+)+",), decision=ClaudeHookDecision.ALLOW, reason="unsafe")
    with pytest.raises(ValueError, match="ambiguous repetition"):
        command_rule((r"a*a*b",), decision=ClaudeHookDecision.ALLOW, reason="unsafe")
    with pytest.raises(ValueError, match="ambiguous repetition"):
        command_rule(
            (r"[ab]*a[ab]*a[ab]*a[ab]*b",),
            decision=ClaudeHookDecision.ALLOW,
            reason="unsafe",
        )
    with pytest.raises(ValueError, match="unsupported expression"):
        command_rule((r".*",), decision=ClaudeHookDecision.ALLOW, reason="unsafe")
    with pytest.raises(ValueError, match="supported limit"):
        command_rule((r"safe",) * 101, decision=ClaudeHookDecision.ALLOW, reason="unsafe")
    with pytest.raises(ValueError, match="invalid"):
        command_rule((r"a{4294967295}",), decision=ClaudeHookDecision.ALLOW, reason="unsafe")
    with pytest.raises(ValueError, match="approved project root"):
        command_rule((r"pwd",), decision=ClaudeHookDecision.ALLOW, reason="unsafe")
    hook = ClaudeCodeHook(
        [
            command_rule(
                (r"pwd",),
                decision=ClaudeHookDecision.ALLOW,
                reason="safe",
                allowed_root="/workspace/project",
            )
        ]
    )
    oversized = hook.handle(event("Bash", {"command": "a" * 8_193}))
    assert oversized["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "limit" in oversized["hookSpecificOutput"]["permissionDecisionReason"]
    broad = ClaudeCodeHook(
        [
            command_rule(
                (r"git status[ ;A-Za-z]*",),
                decision=ClaudeHookDecision.ALLOW,
                reason="broad",
                allowed_root="/workspace/project",
            )
        ]
    )
    controlled = broad.handle(event("Bash", {"command": "git status;python evil"}))
    assert controlled["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "shell control" in controlled["hookSpecificOutput"]["permissionDecisionReason"]

    safe = ClaudeCodeHook(
        [
            command_rule(
                (r"^(git[ \t]+status|git[ \t]+status[ \t]+--short)$",),
                decision=ClaudeHookDecision.ALLOW,
                reason="safe",
                allowed_root="/workspace/project",
            )
        ]
    )
    assert (
        safe.handle(event("Bash", {"command": "git status --short"}))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "allow"
    )


@pytest.mark.parametrize(
    "pattern",
    [
        r"[ab]+c[ab]+",
        r"[^a]+a[^a]+",
        r"[a-c]+z[a-c]+",
        r"\d+a\d+",
        r"\s+a\s+",
        r"\w+ \w+",
        r"\D+1\D+",
        r"\S+ \S+",
        r"\W+a\W+",
        r"^(git[ \t]+(status|diff|log)[ \tA-Za-z0-9_./:=,@-]*)$",
    ],
)
def test_command_pattern_validator_accepts_provably_disjoint_separators(pattern: str) -> None:
    """Useful repeated fields remain valid when a fixed separator removes ambiguity."""
    assert compile_command_patterns([pattern])


@pytest.mark.parametrize(
    "pattern",
    [
        r"[ab]+a[ab]+",
        r"[^a]+b[^a]+",
        r"[a-c]+b[a-c]+",
        r"\d+1\d+",
        r"\s+ \s+",
        r"\w+a\w+",
        r"\D+a\D+",
        r"\S+a\S+",
        r"\W+!\W+",
        r"[ab]+(a|z)[ab]+",
    ],
)
def test_command_pattern_validator_rejects_overlapping_separators(pattern: str) -> None:
    """No character consumable by a prior repeat can reset the ambiguity guard."""
    with pytest.raises(ValueError, match="ambiguous repetition"):
        compile_command_patterns([pattern])


def test_command_pattern_validator_rejects_named_unicode_escapes() -> None:
    """Python-only named escapes cannot hide shell syntax from browser validation."""
    with pytest.raises(ValueError, match="unsupported"):
        compile_command_patterns([r"^git status\N{SEMICOLON}rm$"])


@pytest.mark.parametrize(
    ("category", "literal", "expected"),
    [
        (sre_constants.CATEGORY_DIGIT, ord("1"), True),
        (sre_constants.CATEGORY_SPACE, ord(" "), True),
        (sre_constants.CATEGORY_WORD, ord("_"), True),
        (sre_constants.CATEGORY_LINEBREAK, ord("\n"), True),
        (sre_constants.CATEGORY_NOT_DIGIT, ord("a"), True),
        (sre_constants.CATEGORY_NOT_SPACE, ord("a"), True),
        (sre_constants.CATEGORY_NOT_WORD, ord("!"), True),
        (sre_constants.CATEGORY_NOT_LINEBREAK, ord("a"), True),
        (object(), ord("a"), True),
    ],
)
def test_command_pattern_category_overlap_is_conservative(
    category: object, literal: int, expected: bool
) -> None:
    """Every parser category used by the safety proof has an explicit contract."""
    assert _category_matches_literal(category, literal) is expected


def test_command_pattern_atom_overlap_covers_supported_parser_atoms() -> None:
    """Literal, category, range, negation, and unknown atoms fail safely."""
    assert _atom_matches_literal(sre_constants.LITERAL, ord("a"), ord("a"))
    assert _atom_matches_literal(sre_constants.NOT_LITERAL, ord("a"), ord("b"))
    assert _atom_matches_literal(sre_constants.CATEGORY, sre_constants.CATEGORY_DIGIT, ord("1"))
    assert _atom_matches_literal(
        sre_constants.IN, [(sre_constants.RANGE, (ord("a"), ord("c")))], ord("b")
    )
    assert _atom_matches_literal(
        sre_constants.IN,
        [(sre_constants.NEGATE, None), (sre_constants.LITERAL, ord("a"))],
        ord("b"),
    )
    assert _atom_matches_literal(object(), object(), ord("a"))


def test_command_pattern_leading_atom_analysis_handles_nullable_groups() -> None:
    """The AST proof distinguishes fixed and nullable starts before clearing a repeat."""
    fixed_atoms, fixed_nullable = _leading_atoms(sre_parser.parse(r"^(a|b)", flags=0))
    nullable_atoms, nullable = _leading_atoms(sre_parser.parse(r"^(|a)", flags=0))

    assert fixed_atoms
    assert fixed_nullable is False
    assert nullable_atoms
    assert nullable is True


@pytest.mark.parametrize(
    "command",
    [
        "git status\npython evil.py",
        "git status; python evil.py",
        "git status | python evil.py",
        "git status > output.txt",
        "git status && python evil.py",
        "git status $(python evil.py)",
        "git status `python evil.py`",
        "$SHELL -c id",
        "${SHELL} -c id",
        "$0 -c id",
        "env -- $SHELL -c id",
        "bash -c 'echo safe; python evil.py'",
        "sh -c id",
        "/bin/bash -c id",
        "/bin/BASH -c id",
        "bash.exe -c id",
        "C:\\tools\\SH.EXE -c id",
        "eval 'echo safe && python evil.py'",
        'eval "$PAYLOAD"',
        "env zsh -c id",
        "source /tmp/payload",
        ". /tmp/payload",
        "env -S 'sh -c id'",
        "echo 'quoted | pipeline'",
        "git status 'unterminated",
        "",
    ],
)
def test_single_invocation_screen_rejects_shell_control_syntax(command: str) -> None:
    """No regex can opt a compound or malformed shell program into native allow."""
    assert command_is_single_invocation(command) is False


def test_single_invocation_screen_accepts_one_plain_command() -> None:
    """Ordinary argv-like commands remain eligible for full-regex authorization."""
    assert command_is_single_invocation("git status --short") is True


def test_claude_hook_restricts_file_tools_to_project_and_audits(tmp_path: Path) -> None:
    audit = JsonlAuditSink(tmp_path / "audit.jsonl")
    hook = ClaudeCodeHook([path_within_rule({"Read", "Edit", "Write"}, tmp_path)], audit=audit)
    allowed = hook.handle(event("Read", {"file_path": str(tmp_path / "file.py")}))
    denied = hook.handle(event("Write", {"file_path": "/etc/hosts"}, tool_use_id="tool:2"))
    assert allowed["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert audit.verify()
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "/etc/hosts" not in audit_text
    assert str(tmp_path) not in audit_text
    assert "tool_input_hash" in audit_text


def test_claude_audit_correlates_the_exact_semantic_action(tmp_path: Path) -> None:
    """Presentation-only arguments cannot spoof or prevent proof correlation."""
    audit = InMemoryAuditSink()
    hook = ClaudeCodeHook([exact_tool_rule({"Read", "Bash"})], audit=audit)
    read_path = tmp_path / "README.md"

    first = event("Read", {"file_path": "README.md", "offset": 1}, tool_use_id="read-a")
    first["cwd"] = str(tmp_path)
    second = event("Read", {"file_path": str(read_path), "limit": 20}, tool_use_id="read-b")
    second["cwd"] = str(tmp_path)
    other = event("Read", {"file_path": "SECURITY.md"}, tool_use_id="read-c")
    other["cwd"] = str(tmp_path)
    bash_a = event(
        "Bash",
        {"command": "git push origin main", "description": "Push branch"},
        tool_use_id="bash-a",
    )
    bash_a["cwd"] = str(tmp_path)
    bash_b = event("Bash", {"command": "git push origin main"}, tool_use_id="bash-b")
    bash_b["cwd"] = str(tmp_path)

    for payload in (first, second, other, bash_a, bash_b):
        hook.handle(payload)
    digests = [item.payload["action_digest"] for item in audit.events()]

    assert digests[0] == digests[1]
    assert digests[0] != digests[2]
    assert digests[3] == digests[4]
    assert all(isinstance(value, str) and len(value) == 64 for value in digests)

    fixed_audit = InMemoryAuditSink()
    fixed_hook = ClaudeCodeHook([exact_tool_rule({"Read"})], audit=fixed_audit)
    fixed_hook.handle(event("Read", {"file_path": "/workspace/project/README.md"}))
    assert (
        fixed_audit.events()[0].payload["action_digest"]
        == "b6df7756eb072fe23bf8352642abd4b00a90fd7ac61264c24e7a9700ca75208e"
    )


@pytest.mark.parametrize(
    "protected_path",
    [
        ".claude/settings.json",
        ".claude/aai-sec-config.json",
        ".codex/config.toml",
        ".git/config",
        ".git/hooks/pre-commit",
        ".mcp.json",
        ".ClAuDe/settings.json",
        ".CoDeX/config.toml",
        ".GIT/hooks/pre-commit",
        ".MCP.JSON",
    ],
)
def test_claude_path_rule_protects_security_state_from_native_writes(
    tmp_path: Path, protected_path: str
) -> None:
    """Native file tools cannot rewrite the authority that governs later calls."""
    hook = ClaudeCodeHook([path_within_rule({"Read", "Edit", "Write"}, tmp_path)])
    target = tmp_path / protected_path

    read = hook.handle(event("Read", {"file_path": str(target)}))
    edit = hook.handle(event("Edit", {"file_path": str(target)}))
    write = hook.handle(event("Write", {"file_path": str(target)}))

    assert read["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert edit["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert write["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert read["hookSpecificOutput"]["permissionDecisionReason"] == (
        "path is inside the approved project directory"
    )
    assert write["hookSpecificOutput"]["permissionDecisionReason"] == (
        "path is outside the approved project directory"
    )


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


def test_claude_replication_failure_records_effective_denial_locally() -> None:
    """Local evidence supersedes a provisional allow when export fails."""

    class BrokenExporter:
        def export(self, _event: object) -> None:
            raise OSError("synthetic remote outage")

    primary = InMemoryAuditSink()
    hook = ClaudeCodeHook(
        [exact_tool_rule({"Read"})],
        audit=ReplicatedAuditSink(primary, BrokenExporter()),
    )

    result = hook.handle(event("Read", {}))
    events = primary.events()

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert [item.payload["decision"] for item in events] == ["allow", "deny"]
    assert events[1].event_type == "claude_pre_tool_effective_decision"
    assert events[1].payload["replication_status"] == "failed"
    assert events[1].payload["supersedes_event_hash"] == events[0].event_hash


def test_claude_native_hook_resolves_central_policy_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Native tools use the same authenticated group policy as the MCP gateway."""

    class Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def effective_policy(self) -> dict[str, object]:
            return {
                "emergencyStop": False,
                "policy": {
                    "configuration": {
                        "policy": {"denyByDefault": True},
                        "tools": {"allowed": ["lookup_record"]},
                        "claudeCode": {
                            "allowedBuiltInTools": ["Read"],
                            "fileTools": ["Read"],
                            "deniedCommandPatterns": [r"rm\s+-rf"],
                            "approvalCommandPatterns": [r"git\s+push"],
                            "allowedCommandPatterns": [r"git\s+status"],
                        },
                        "audit": {"redactSensitiveData": True},
                    }
                },
            }

    monkeypatch.setenv("AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL", "https://fleet.example.test/api")
    monkeypatch.setenv("AAI_SEC_AGENT_TOKEN", "synthetic-agent-token-1234")
    monkeypatch.setenv("AAI_SEC_DEPLOYMENT_ID", "deployment-a")
    monkeypatch.setattr(claude_hook_example, "ControlPlaneAgentClient", Client)
    config = claude_hook_example._load_central_config(tmp_path)
    assert config is not None
    assert config["allowedTools"] == ["Read"]
    assert config["allowedCommandPatterns"] == [r"git\s+status"]

    class StoppedClient(Client):
        def __init__(self, stop_value: object) -> None:
            self.stop_value = stop_value

        def effective_policy(self) -> dict[str, object]:
            value = super().effective_policy()
            value["emergencyStop"] = self.stop_value
            return value

    for stop_value in (True, None, "false", 0):
        assert (
            claude_hook_example._load_central_config(tmp_path, cast(Any, StoppedClient(stop_value)))
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

    assert claude_hook_example._load_central_config(tmp_path, cast(Any, InvalidClient())) is None

    monkeypatch.delenv("AAI_SEC_AGENT_TOKEN")
    assert claude_hook_example._load_central_config(tmp_path) is None


def test_claude_local_policy_rejects_unsafe_legacy_pattern(tmp_path: Path) -> None:
    """A policy saved before API validation cannot bypass hook-local screening."""
    policy = json.loads(
        (Path.cwd() / "examples" / "claude_safe_config.json").read_text(encoding="utf-8")
    )
    policy["allowedCommandPatterns"] = ["(a+)+"]
    config_dir = tmp_path / ".claude"
    config_dir.mkdir()
    (config_dir / "aai-sec-config.json").write_text(json.dumps(policy), encoding="utf-8")

    assert claude_hook_example._load_safe_config(tmp_path) is None


def test_claude_hook_main_denies_when_audit_initialization_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit corruption or permissions return a denial instead of crashing the hook."""

    class BrokenAudit:
        def __init__(self, _path: Path) -> None:
            raise ValueError("synthetic corrupt chain")

    destination = io.StringIO()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    for name in (
        "AAI_SEC_ENTERPRISE_CONTROL_PLANE_URL",
        "AAI_SEC_AGENT_TOKEN",
        "AAI_SEC_DEPLOYMENT_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(claude_hook_example, "JsonlAuditSink", BrokenAudit)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps(event("Bash", {"command": "pwd"})) + "\n")
    )
    monkeypatch.setattr("sys.stdout", destination)

    claude_hook_example.main()

    result = json.loads(destination.getvalue())
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "audit is unavailable" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_claude_hook_main_denies_after_unexpected_setup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An adapter exception outside its declared contract cannot crash fail open."""

    def fail_setup(_project: Path, _client: object) -> None:
        raise RuntimeError("synthetic unexpected provider failure")

    destination = io.StringIO()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(claude_hook_example, "_load_central_config", fail_setup)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps(event("Bash", {"command": "pwd"})) + "\n")
    )
    monkeypatch.setattr("sys.stdout", destination)

    claude_hook_example.main()

    result = json.loads(destination.getvalue())
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "initialization failed" in result["hookSpecificOutput"]["permissionDecisionReason"]


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
    monkeypatch.setenv("AAI_SEC_TENANT_ID", "tenant-a")
    monkeypatch.setenv("AAI_SEC_POLICY_TRUST_BUNDLE", "/etc/aai-security/policy-trust.json")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path.resolve()))
    rotated = "synthetic-rotated-token-5678"
    store = AgentSessionStore(
        "https://fleet.example.test/api",
        "deployment-a",
        "claude-a",
        str(tmp_path.resolve()),
    )
    store.save(AgentSessionCredential(rotated, int(time.time()) + 900))

    class Client:
        def __init__(self, _url: str, token: str, **kwargs: object) -> None:
            self.token = token
            self.session_store = kwargs.get("session_store")

    monkeypatch.setattr(claude_hook_example, "ControlPlaneAgentClient", Client)
    monkeypatch.setattr(
        PolicyTrustStore,
        "from_file",
        lambda _path: object(),
    )

    client = claude_hook_example._control_plane_client(tmp_path)

    assert client is not None
    assert client.token == rotated
    assert isinstance(client.session_store, AgentSessionStore)

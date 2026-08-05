"""Adversarial and contract tests for live Codex effective-control evidence."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from agentic_security.codex_effective_controls import (
    CodexAppServerEffectiveControlProbe,
    codex_effective_control_evidence_from_wire,
)
from agentic_security.errors import SecurityConfigurationError
from agentic_security.integrations import AgentHost
from agentic_security.managed_configuration import (
    EnforcementState,
    ManagedCommandRule,
    ManagedConfigurationCompiler,
    ManagedMcpServer,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
)


def _platform() -> ManagedPlatform:
    """Return the current test platform as the managed compiler enum."""
    if sys.platform == "darwin":
        return ManagedPlatform.MACOS
    if sys.platform.startswith("linux"):
        return ManagedPlatform.LINUX
    return ManagedPlatform.WINDOWS


def _bundle(*, extended: bool = False):  # type: ignore[no-untyped-def]
    """Compile a synthetic Codex policy for the current platform."""
    intent = ManagedPolicyIntent(
        "policy-live",
        3,
        action_rules=(
            NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),
            NativeActionRule("Bash(rm *)", NativeActionDecision.DENY, "synthetic deny"),
        ),
        command_rules=(ManagedCommandRule(("rm",), NativeActionDecision.DENY, "synthetic deny"),)
        if extended
        else (),
        mcp_servers=(ManagedMcpServer("github", url="https://example.test/mcp"),)
        if extended
        else (),
        deny_read=("/synthetic/private",) if extended else (),
        allow_web_search=True,
    )
    return ManagedConfigurationCompiler().compile(
        intent,
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=_platform(),
        hook_command=(
            r"C:\Program Files\AAI Security\hooks\codex-policy.exe"
            if os.name == "nt"
            else "/opt/aai-security/hooks/codex-policy"
        ),
    )


def _fake_server(tmp_path: Path) -> tuple[Path, str]:
    """Create a synthetic JSONL app-server with selectable hostile behavior."""
    script = tmp_path / "synthetic-codex"
    posix_hook = json.dumps("/opt/aai-security/hooks/codex-policy")
    windows_hook = json.dumps(r"C:\Program Files\AAI Security\hooks\codex-policy.exe")
    family = json.dumps(
        "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux"
    )
    script.write_text(
        f"""#!{sys.executable}
import json
import os
import sys
import time

mode = os.environ.get("AAI_SYNTHETIC_CODEX_MODE", "match")
for _ in range(4):
    sys.stdin.buffer.readline()
if mode == "timeout":
    time.sleep(10)
    raise SystemExit(0)
if mode == "oversized":
    sys.stdout.write("x" * 4_000_001 + "\\n")
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)
if mode == "malformed":
    print("{{not-json")
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)
if mode == "closed":
    raise SystemExit(0)
if mode == "nonobject":
    print("[]", flush=True)
    time.sleep(10)
    raise SystemExit(0)

hook = {posix_hook}
if os.name == "nt":
    hook = {windows_hook}
requirements = {{
    "allowedApprovalPolicies": ["on-request"],
    "defaultPermissions": ":workspace",
    "allowedPermissionProfiles": {{":read-only": True, ":workspace": True}},
    "allowedSandboxModes": [],
    "allowedWebSearchModes": ["cached"],
    "allowManagedHooksOnly": True,
    "featureRequirements": {{
        "browser_use": False,
        "computer_use": False,
        "hooks": True,
        "plugins": False,
    }},
}}
if mode == "missing":
    requirements = None
elif mode == "drift":
    requirements["allowedApprovalPolicies"] = ["never"]

messages = [
    {{"id": "aai-initialize", "result": {{
        "userAgent": "codex/0.146.0",
        "platformFamily": {family},
        "platformOs": "synthetic",
        "codexHome": "/synthetic/secret/path",
    }}}},
    {{"id": "aai-config", "result": {{
        "config": {{
            "approval_policy": "on-request",
            "sandbox_mode": "workspace-write",
            "default_permissions": ":workspace",
            "web_search": "cached",
            "hooks": {{"PreToolUse": [{{"hooks": [{{"type": "command", "command": hook}}]}}]}},
            "mcp_servers": {{
                "github": {{"url": "https://example.test/mcp"}},
                "synthetic-secret-server": {{
                    "http_headers": {{"Authorization": "Bearer synthetic-secret-value"}}
                }},
            }},
            "developer_instructions": "synthetic-secret-prompt",
        }},
        "origins": {{
            "approval_policy": {{
                "name": {{"type": "system", "file": "/secret/path"}}, "version": "1"
            }},
            "mcp_servers.synthetic-secret-server.http_headers.Authorization": {{
                "name": {{"type": "user", "file": "/secret/user"}}, "version": "1"
            }},
        }},
    }}}},
    {{"id": "aai-requirements", "result": {{"requirements": requirements}}}},
]
if mode == "error-secret":
    messages[2] = {{"id": "aai-requirements", "error": {{"message": "synthetic-secret-value"}}}}
if mode == "duplicate":
    messages.insert(1, messages[0])
if mode == "notification":
    messages.insert(0, {{"method": "synthetic/notice", "params": {{}}}})
if mode == "no-mcp":
    messages[1]["result"]["config"]["mcp_servers"] = None
if mode == "no-hooks":
    messages[1]["result"]["config"]["hooks"] = None
if mode == "non-command-hook":
    messages[1]["result"]["config"]["hooks"]["PreToolUse"][0]["hooks"][0] = {{"type": "prompt"}}
if mode == "bad-hook-groups":
    messages[1]["result"]["config"]["hooks"]["PreToolUse"] = "bad"
if mode == "bad-hook-handlers":
    messages[1]["result"]["config"]["hooks"]["PreToolUse"][0]["hooks"] = "bad"
if mode == "bad-hook-command":
    messages[1]["result"]["config"]["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = 7
if mode == "no-origins":
    messages[1]["result"]["origins"] = None
if mode == "bad-origin":
    messages[1]["result"]["origins"]["approval_policy"]["name"]["type"] = "secret"
if mode == "bad-version":
    messages[0]["result"]["userAgent"] = "codex-without-version"
if mode == "bad-platform":
    messages[0]["result"]["platformFamily"] = "windows"
for message in messages:
    print(json.dumps(message, separators=(",", ":")), flush=True)
""",
        encoding="utf-8",
    )
    script.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return script, hashlib.sha256(script.read_bytes()).hexdigest()


def _probe(tmp_path: Path, *, timeout_seconds: float = 1) -> CodexAppServerEffectiveControlProbe:
    """Return a probe pinned to the synthetic executable."""
    executable, digest = _fake_server(tmp_path)
    return CodexAppServerEffectiveControlProbe(
        executable=str(executable),
        executable_sha256=digest,
        timeout_seconds=timeout_seconds,
    )


def _valid_enforced_wire() -> dict[str, object]:
    """Return a complete synthetic wire object for parser boundary tests."""
    return {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": _platform().value,
        "bundleHash": "d" * 64,
        "state": "enforced",
        "reason": "effective-controls-match",
        "expectedDigest": "a" * 64,
        "observedDigest": "b" * 64,
        "approvalPolicy": "on-request",
        "sandboxMode": "workspace-write",
        "defaultPermissions": ":workspace",
        "webSearchMode": "cached",
        "managedMcpServerNames": [],
        "unexpectedMcpServerCount": 0,
        "preToolHookSha256": ["c" * 64],
        "requirements": {
            "allowedApprovalPolicies": ["on-request"],
            "defaultPermissions": ":workspace",
            "allowedPermissionProfiles": {":workspace": True},
            "allowedSandboxModes": [],
            "allowedWebSearchModes": ["cached"],
            "allowManagedHooksOnly": True,
            "featureRequirements": {"hooks": True},
            "network": {
                "enabled": None,
                "managedAllowedDomainsOnly": None,
                "domains": {},
            },
        },
        "securityOrigins": {"approval_policy": "system"},
        "mismatches": [],
        "unverifiedControls": [],
        "allowedActions": ["Read"],
        "deniedActions": ["Bash(rm *)"],
        "approvalRequiredActions": [],
        "verifiedAt": 100,
        "expiresAt": 160,
    }


def _set_path(value: dict[str, object], path: tuple[str, ...], replacement: object) -> None:
    """Set one nested synthetic field for parameterized bypass tests."""
    current = value
    for key in path[:-1]:
        child = current[key]
        assert isinstance(child, dict)
        current = child
    current[path[-1]] = replacement


def test_matching_observable_controls_create_short_lived_enforced_evidence(
    tmp_path: Path,
) -> None:
    """A minimal policy becomes effective only after every exposed field matches."""
    evidence = _probe(tmp_path).inspect(
        _bundle(), project_root=str(tmp_path), now=100, ttl_seconds=60
    )

    assert evidence.state is EnforcementState.ENFORCED
    assert evidence.reason == "effective-controls-match"
    assert evidence.allowed_actions == ("Read",)
    assert evidence.denied_actions == ("Bash(rm *)",)
    assert evidence.expires_at == 160
    assert evidence.unexpected_mcp_server_count == 2
    assert evidence.managed_mcp_server_names == ()
    wire = json.dumps(evidence.to_wire(), sort_keys=True)
    assert "synthetic-secret" not in wire
    assert "/secret/" not in wire
    assert "example.test" not in wire


def test_unobservable_requested_controls_fail_closed_as_deployment_required(
    tmp_path: Path,
) -> None:
    """MCP, rule, and deny-read observability gaps cannot inherit intended allows."""
    evidence = _probe(tmp_path).inspect(_bundle(extended=True), project_root=str(tmp_path), now=100)

    assert evidence.state is EnforcementState.DEPLOYMENT_REQUIRED
    assert evidence.allowed_actions == ()
    assert evidence.mismatches == ()
    assert set(evidence.unverified_controls) == {
        "command-rule-runtime-match",
        "deny-read-runtime-match",
        "mcp-runtime-status",
    }
    assert evidence.managed_mcp_server_names == ("github",)


@pytest.mark.parametrize(
    ("mode", "state", "reason"),
    [
        ("missing", EnforcementState.MISSING, "administrator-requirements-missing"),
        ("drift", EnforcementState.CONFLICT, "effective-controls-differ"),
    ],
)
def test_missing_or_drifted_requirements_withhold_allows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: EnforcementState,
    reason: str,
) -> None:
    """No requirements and weaker requirements are explicit closed states."""
    monkeypatch.setenv("AAI_SYNTHETIC_CODEX_MODE", mode)
    evidence = _probe(tmp_path).inspect(_bundle(), project_root=str(tmp_path), now=100)

    assert evidence.state is state
    assert evidence.reason == reason
    assert evidence.allowed_actions == ()
    assert evidence.denied_actions == ("Bash(rm *)", "Read")


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("timeout", "timed out"),
        ("oversized", "safe bounds"),
        ("malformed", "malformed JSON"),
        ("duplicate", "duplicate response"),
        ("error-secret", "rejected a configuration request"),
        ("closed", "closed before responding"),
        ("nonobject", "invalid message"),
        ("bad-hook-groups", "hooks are malformed"),
        ("bad-hook-handlers", "handlers are malformed"),
        ("bad-hook-command", "command hook is malformed"),
        ("bad-origin", "origin is malformed"),
        ("bad-version", "version is unavailable"),
        ("bad-platform", "platform differs"),
    ],
)
def test_hostile_protocol_responses_are_bounded_and_secret_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    message: str,
) -> None:
    """Malformed app-server behavior fails closed without reflecting raw text."""
    monkeypatch.setenv("AAI_SYNTHETIC_CODEX_MODE", mode)
    with pytest.raises(SecurityConfigurationError, match=message) as caught:
        _probe(tmp_path, timeout_seconds=3 if mode == "oversized" else 1).inspect(
            _bundle(), project_root=str(tmp_path)
        )

    assert "synthetic-secret-value" not in str(caught.value)


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        ("notification", EnforcementState.ENFORCED),
        ("no-mcp", EnforcementState.ENFORCED),
        ("no-origins", EnforcementState.ENFORCED),
        ("no-hooks", EnforcementState.CONFLICT),
        ("non-command-hook", EnforcementState.CONFLICT),
    ],
)
def test_optional_or_irrelevant_app_server_fields_are_handled_deterministically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: EnforcementState,
) -> None:
    """Notifications and absent optional inventory never widen authority."""
    monkeypatch.setenv("AAI_SYNTHETIC_CODEX_MODE", mode)

    evidence = _probe(tmp_path).inspect(_bundle(), project_root=str(tmp_path), now=100)

    assert evidence.state is state
    assert evidence.allowed_actions == (("Read",) if state is EnforcementState.ENFORCED else ())


def test_executable_and_call_inputs_are_verified_before_launch(tmp_path: Path) -> None:
    """Wrong release bytes, relative roots, and invalid TTLs fail before evidence."""
    executable, digest = _fake_server(tmp_path)
    with pytest.raises(SecurityConfigurationError, match="digest does not match"):
        CodexAppServerEffectiveControlProbe(executable=str(executable), executable_sha256="0" * 64)
    probe = CodexAppServerEffectiveControlProbe(
        executable=str(executable), executable_sha256=digest
    )
    with pytest.raises(SecurityConfigurationError, match="absolute directory"):
        probe.inspect(_bundle(), project_root="relative")
    with pytest.raises(SecurityConfigurationError, match="TTL"):
        probe.inspect(_bundle(), project_root=str(tmp_path), ttl_seconds=1)
    with pytest.raises(SecurityConfigurationError, match="time is invalid"):
        probe.inspect(_bundle(), project_root=str(tmp_path), now=-1)
    with pytest.raises(SecurityConfigurationError, match="timeout"):
        CodexAppServerEffectiveControlProbe(
            executable=str(executable), executable_sha256=digest, timeout_seconds=float("inf")
        )
    with pytest.raises(SecurityConfigurationError, match="path or digest is invalid"):
        CodexAppServerEffectiveControlProbe(executable=str(executable), executable_sha256="z" * 64)
    with pytest.raises(SecurityConfigurationError, match="cannot be verified"):
        CodexAppServerEffectiveControlProbe(
            executable=str(tmp_path / "missing"), executable_sha256="a" * 64
        )


def test_wrong_host_platform_and_malformed_bundle_fail_before_process_launch(
    tmp_path: Path,
) -> None:
    """Only a current-platform Codex bundle with one valid TOML artifact is accepted."""
    probe = _probe(tmp_path)
    wrong_host = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent("policy-live", 1),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=_platform(),
        hook_command=(
            r"C:\Program Files\AAI Security\hooks\claude-policy.exe"
            if os.name == "nt"
            else "/opt/aai-security/hooks/claude-policy"
        ),
    )
    with pytest.raises(SecurityConfigurationError, match="requires a Codex bundle"):
        probe.inspect(wrong_host, project_root=str(tmp_path))
    codex = _bundle()
    malformed = replace(codex, artifacts=(replace(codex.artifacts[0], content="not = [toml"),))
    with pytest.raises(SecurityConfigurationError, match="requirements are malformed"):
        probe.inspect(malformed, project_root=str(tmp_path))


def test_group_writable_executable_is_rejected(tmp_path: Path) -> None:
    """A mutable helper cannot be trusted even when its digest currently matches."""
    executable, digest = _fake_server(tmp_path)
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IWGRP)

    with pytest.raises(SecurityConfigurationError, match="permissions are unsafe"):
        CodexAppServerEffectiveControlProbe(executable=str(executable), executable_sha256=digest)


def test_executable_is_remeasured_immediately_before_each_launch(tmp_path: Path) -> None:
    """A binary replaced after probe construction cannot reuse a stale measurement."""
    executable, digest = _fake_server(tmp_path)
    probe = CodexAppServerEffectiveControlProbe(
        executable=str(executable), executable_sha256=digest
    )
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    with pytest.raises(SecurityConfigurationError, match="digest does not match"):
        probe.inspect(_bundle(), project_root=str(tmp_path), now=100)


def test_wire_parser_round_trips_safe_evidence_and_rejects_unknown_content(
    tmp_path: Path,
) -> None:
    """Control-plane ingestion accepts only the exact content-minimised schema."""
    evidence = _probe(tmp_path).inspect(
        _bundle(), project_root=str(tmp_path), now=100, ttl_seconds=60
    )
    wire = evidence.to_wire()

    assert codex_effective_control_evidence_from_wire(wire).to_wire() == wire
    wire["rawConfig"] = {"Authorization": "Bearer synthetic-secret-value"}
    with pytest.raises(SecurityConfigurationError, match="invalid schema") as caught:
        codex_effective_control_evidence_from_wire(wire)
    assert "synthetic-secret-value" not in str(caught.value)


def test_wire_parser_rejects_allows_in_a_closed_state(tmp_path: Path) -> None:
    """A forged missing report cannot smuggle effective action authority."""
    monkeypatch_wire = (
        _probe(tmp_path)
        .inspect(_bundle(), project_root=str(tmp_path), now=100, ttl_seconds=60)
        .to_wire()
    )
    monkeypatch_wire["state"] = "missing"
    monkeypatch_wire["reason"] = "administrator-requirements-missing"
    monkeypatch_wire["requirements"] = None

    with pytest.raises(SecurityConfigurationError, match="cannot contain effective allows"):
        codex_effective_control_evidence_from_wire(monkeypatch_wire)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("platform",), None, "invalid enums"),
        (("state",), "bogus", "invalid enums"),
        (("reason",), "synthetic-secret-reason", "reason does not match"),
        (("expectedDigest",), "short", "digest is invalid"),
        (("expectedDigest",), "g" * 64, "digest is invalid"),
        (("expectedDigest",), "A" * 64, "digest is invalid"),
        (("bundleHash",), "short", "bundle hash is invalid"),
        (("securityOrigins",), {"secret.path": "system"}, "origin is unsupported"),
        (("securityOrigins",), {"approval_policy": "secret-source"}, "origin is malformed"),
        (("expiresAt",), 401, "expiry is invalid"),
        (("unexpectedMcpServerCount",), True, "MCP count is invalid"),
        (("mismatches",), ["synthetic-secret-code"], "mismatches are unsupported"),
        (("verifiedAt",), 100.5, "verifiedAt is invalid"),
        (("hostVersion",), "bad\nversion", "host version is malformed"),
        (
            ("requirements", "allowedApprovalPolicies"),
            "on-request",
            "policies are malformed",
        ),
        (("requirements", "allowManagedHooksOnly"), "true", "requirement is malformed"),
        (
            ("requirements", "allowedPermissionProfiles"),
            {":workspace": "true"},
            "profiles are malformed",
        ),
        (
            ("requirements", "network", "domains"),
            {"example.test": "prompt"},
            "domains are malformed",
        ),
        (("requirements", "network", "enabled"), "true", "requirement is malformed"),
        (("preToolHookSha256",), ["short"], "hook digest is invalid"),
        (("allowedActions",), "Read", "actions are malformed"),
    ],
)
def test_wire_parser_rejects_each_nested_bypass_class(
    path: tuple[str, ...], replacement: object, message: str
) -> None:
    """Every nested evidence type and enum is independently fail-closed."""
    wire = deepcopy(_valid_enforced_wire())
    _set_path(wire, path, replacement)

    with pytest.raises(SecurityConfigurationError, match=message) as caught:
        codex_effective_control_evidence_from_wire(wire)
    assert "synthetic-secret" not in str(caught.value)


def test_wire_parser_rejects_missing_state_with_forged_requirements() -> None:
    """A missing state cannot carry a requirements object that implies control."""
    wire = _valid_enforced_wire()
    wire.update(
        {
            "state": "missing",
            "reason": "administrator-requirements-missing",
            "allowedActions": [],
        }
    )

    with pytest.raises(SecurityConfigurationError, match="cannot contain requirements"):
        codex_effective_control_evidence_from_wire(wire)


def test_wire_parser_rejects_enforced_state_with_unresolved_controls() -> None:
    """An enforced report cannot retain mismatch or observability-gap codes."""
    for field, code in (
        ("mismatches", "host-version"),
        ("unverifiedControls", "mcp-runtime-status"),
    ):
        wire = _valid_enforced_wire()
        wire[field] = [code]
        with pytest.raises(SecurityConfigurationError, match="unresolved controls"):
            codex_effective_control_evidence_from_wire(wire)

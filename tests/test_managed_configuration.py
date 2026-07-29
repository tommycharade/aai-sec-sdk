"""Security and contract tests for host-managed policy compilation."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from agentic_security.errors import SecurityConfigurationError
from agentic_security.integrations import AgentHost
from agentic_security.managed_configuration import (
    EnforcementState,
    ManagedCommandRule,
    ManagedConfigurationBundle,
    ManagedConfigurationCompiler,
    ManagedConfigurationEvidence,
    ManagedConfigurationSource,
    ManagedMcpServer,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
    ObservedManagedConfiguration,
    measure_managed_configuration,
    reconcile_effective_authority,
)


def policy(*, conflicting: bool = False) -> ManagedPolicyIntent:
    """Return a synthetic restrictive policy used by both host contracts."""
    action_rules = [
        NativeActionRule("Read", NativeActionDecision.ALLOW, "repository reads are allowed"),
        NativeActionRule("Bash(git push *)", NativeActionDecision.APPROVAL_REQUIRED, "review push"),
        NativeActionRule("Bash(rm *)", NativeActionDecision.DENY, "destructive command"),
    ]
    if conflicting:
        action_rules.append(
            NativeActionRule("Read", NativeActionDecision.DENY, "sensitive repository")
        )
    return ManagedPolicyIntent(
        policy_id="policy-safe",
        policy_version=7,
        action_rules=tuple(action_rules),
        command_rules=(
            ManagedCommandRule(
                ("rm",), NativeActionDecision.DENY, "use an approved cleanup workflow"
            ),
            ManagedCommandRule(
                ("git", "push"), NativeActionDecision.APPROVAL_REQUIRED, "review publishing"
            ),
        ),
        mcp_servers=(
            ManagedMcpServer("github", url="https://api.githubcopilot.com/mcp/"),
            ManagedMcpServer(
                "aai-security",
                command="/opt/aai-security/bin/mcp-gateway",
                args=("serve",),
            ),
        ),
        deny_read=("~/.ssh", "/**/*.env"),
        allowed_network_domains=("api.github.com", "*.corp.example.com"),
        allow_web_search=True,
    )


def test_claude_compiler_emits_fail_closed_managed_files() -> None:
    """Claude output locks permissions, bypass mode, hook, and MCP inventory."""
    bundle = ManagedConfigurationCompiler().compile(
        policy(),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.211",
        platform=ManagedPlatform.MACOS,
        hook_command="/opt/aai-security/hooks/claude-policy",
    )

    assert [item.path for item in bundle.artifacts] == [
        "/Library/Application Support/ClaudeCode/managed-settings.json",
        "/Library/Application Support/ClaudeCode/managed-mcp.json",
    ]
    settings = json.loads(bundle.artifacts[0].content)
    assert settings["allowManagedPermissionRulesOnly"] is True
    assert settings["forceRemoteSettingsRefresh"] is True
    assert settings["permissions"]["disableBypassPermissionsMode"] == "disable"
    assert settings["permissions"]["allow"] == ["Read"]
    assert settings["permissions"]["ask"] == ["Bash(git push *)"]
    assert settings["permissions"]["deny"] == ["Bash(rm *)"]
    assert settings["sandbox"]["network"]["allowedDomains"] == [
        "api.github.com",
        "*.corp.example.com",
    ]
    mcp = json.loads(bundle.artifacts[1].content)["mcpServers"]
    assert set(mcp) == {"github", "aai-security"}
    assert "env" not in mcp["aai-security"]
    assert all(len(item.sha256) == 64 for item in bundle.artifacts)
    assert any(
        item.control == "mcp_inventory" and item.state is EnforcementState.ENFORCED
        for item in bundle.coverage
    )


def test_codex_compiler_emits_parseable_immutable_requirements() -> None:
    """Codex output parses and pins profiles, hooks, command rules, and MCP identity."""
    bundle = ManagedConfigurationCompiler().compile(
        policy(),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/codex-policy",
    )

    assert bundle.artifacts[0].path == "/etc/codex/requirements.toml"
    value = tomllib.loads(bundle.artifacts[0].content)
    assert value["allowed_approval_policies"] == ["on-request"]
    assert value["default_permissions"] == ":workspace"
    assert value["allow_managed_hooks_only"] is True
    assert value["features"]["hooks"] is True
    assert value["features"]["plugins"] is False
    assert value["hooks"]["PreToolUse"][0]["hooks"][0]["command"].startswith("/opt/")
    assert value["permissions"]["filesystem"]["deny_read"] == ["~/.ssh", "/**/*.env"]
    assert value["rules"]["prefix_rules"][0]["decision"] == "forbidden"
    assert value["rules"]["prefix_rules"][1]["decision"] == "prompt"
    assert value["mcp_servers"]["github"]["identity"]["url"].startswith("https://")
    assert value["mcp_servers"]["aai-security"]["identity"]["command"]["args"] == [
        {"match": "exact", "value": "serve"}
    ]
    assert value["experimental_network"]["managed_allowed_domains_only"] is True


def test_windows_compilation_uses_machine_managed_paths() -> None:
    """Windows artifacts and hooks stay in administrator-owned locations."""
    compiler = ManagedConfigurationCompiler()
    claude = compiler.compile(
        policy(),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.211",
        platform=ManagedPlatform.WINDOWS,
        hook_command=r"C:\Program Files\AAI Security\hooks\claude-policy.exe",
    )
    codex = compiler.compile(
        policy(),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.WINDOWS,
        hook_command=r"C:\Program Files\AAI Security\hooks\codex-policy.exe",
    )

    assert claude.artifacts[0].path.startswith(r"C:\Program Files\ClaudeCode")
    assert codex.artifacts[0].path == r"C:\ProgramData\OpenAI\Codex\requirements.toml"
    requirements = tomllib.loads(codex.artifacts[0].content)
    assert requirements["hooks"]["windows_managed_dir"] == (r"C:\Program Files\AAI Security\hooks")


def test_managed_file_measurement_binds_exact_root_owned_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A heartbeat proof is created only from exact protected artifact bytes."""
    compiled = ManagedConfigurationCompiler().compile(
        policy(),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=ManagedPlatform.MACOS,
        hook_command="/opt/aai-security/hooks/claude-policy",
    )
    managed_file = tmp_path / "managed-settings.json"
    managed_file.write_text(compiled.artifacts[0].content, encoding="utf-8")
    measured = replace(
        compiled,
        artifacts=(replace(compiled.artifacts[0], path=str(managed_file)),),
    )
    real_fstat = os.fstat

    def root_owned(descriptor: int) -> SimpleNamespace:
        metadata = real_fstat(descriptor)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0, st_size=metadata.st_size)

    monkeypatch.setattr("agentic_security.managed_configuration.os.fstat", root_owned)
    monkeypatch.setattr(
        "agentic_security.managed_configuration.host_platform.system", lambda: "Darwin"
    )

    evidence = measure_managed_configuration(
        measured,
        source=ManagedConfigurationSource.MDM,
        now=100,
        ttl_seconds=60,
    )

    assert isinstance(evidence, ManagedConfigurationEvidence)
    assert evidence.to_wire() == {
        "host": "claude-code",
        "hostVersion": "2.1.220",
        "platform": "macos",
        "bundleHash": compiled.bundle_hash,
        "policyId": "policy-safe",
        "policyVersion": 7,
        "source": "mdm",
        "verifiedAt": 100,
        "expiresAt": 160,
    }

    managed_file.write_text("{}\n", encoding="utf-8")
    with pytest.raises(SecurityConfigurationError, match="does not match"):
        measure_managed_configuration(
            measured,
            source=ManagedConfigurationSource.MDM,
            now=101,
        )


def test_managed_file_measurement_rejects_unsafe_owner_and_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """User-writable or wrong-platform policy can never become enforced evidence."""
    compiled = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent("policy-safe", 1),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.MACOS,
        hook_command="/opt/aai-security/hooks/codex-policy",
    )
    managed_file = tmp_path / "requirements.toml"
    managed_file.write_text(compiled.artifacts[0].content, encoding="utf-8")
    measured = replace(
        compiled,
        artifacts=(replace(compiled.artifacts[0], path=str(managed_file)),),
    )
    metadata = managed_file.stat()
    monkeypatch.setattr(
        "agentic_security.managed_configuration.host_platform.system", lambda: "Darwin"
    )
    monkeypatch.setattr(
        "agentic_security.managed_configuration.os.fstat",
        lambda _descriptor: SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=501,
            st_size=metadata.st_size,
        ),
    )
    with pytest.raises(SecurityConfigurationError, match="ownership or mode"):
        measure_managed_configuration(
            measured,
            source=ManagedConfigurationSource.CODEX_MDM,
            now=100,
        )

    monkeypatch.setattr(
        "agentic_security.managed_configuration.host_platform.system", lambda: "Linux"
    )
    with pytest.raises(SecurityConfigurationError, match="current platform"):
        measure_managed_configuration(
            measured,
            source=ManagedConfigurationSource.CODEX_MDM,
            now=100,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "claude-code"},
        {"platform": "macos"},
        {"source": "mdm"},
        {"source": ManagedConfigurationSource.CODEX_SYSTEM},
        {"host_version": "latest"},
        {"bundle_hash": "A" * 64},
        {"policy_id": " "},
        {"policy_version": 0},
        {"policy_version": True},
        {"verified_at": float("inf")},
        {"verified_at": -1},
        {"expires_at": 99},
    ],
)
def test_managed_evidence_rejects_ambiguous_identity_and_expiry(
    changes: dict[str, object],
) -> None:
    """Malformed, cross-host, and non-expiring evidence fails at construction."""
    values: dict[str, object] = {
        "host": AgentHost.CLAUDE_CODE,
        "host_version": "2.1.220",
        "platform": ManagedPlatform.MACOS,
        "bundle_hash": "a" * 64,
        "policy_id": "policy-safe",
        "policy_version": 1,
        "source": ManagedConfigurationSource.MDM,
        "verified_at": 100,
        "expires_at": 200,
    }
    with pytest.raises(SecurityConfigurationError):
        ManagedConfigurationEvidence(**(values | changes))  # type: ignore[arg-type]


def test_managed_measurement_rejects_untrusted_inputs_and_missing_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verifier rejects untyped input, unsafe bounds, and absent artifacts."""
    compiled = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent("policy-safe", 1),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=ManagedPlatform.MACOS,
        hook_command="/opt/aai-security/hooks/claude-policy",
    )
    monkeypatch.setattr(
        "agentic_security.managed_configuration.host_platform.system", lambda: "Darwin"
    )
    invalid_calls: tuple[Callable[[], ManagedConfigurationEvidence], ...] = (
        lambda: measure_managed_configuration(
            cast(ManagedConfigurationBundle, {}),
            source=ManagedConfigurationSource.MDM,
            now=100,
        ),
        lambda: measure_managed_configuration(
            compiled,
            source=cast(ManagedConfigurationSource, "mdm"),
            now=100,
        ),
        lambda: measure_managed_configuration(
            compiled,
            source=ManagedConfigurationSource.CLAUDE_SERVER_MANAGED,
            now=100,
        ),
        lambda: measure_managed_configuration(
            compiled, source=ManagedConfigurationSource.MDM, now=float("inf")
        ),
        lambda: measure_managed_configuration(
            compiled, source=ManagedConfigurationSource.MDM, now=100, ttl_seconds=29
        ),
        lambda: measure_managed_configuration(
            replace(compiled, bundle_hash="bad"),
            source=ManagedConfigurationSource.MDM,
            now=100,
        ),
        lambda: measure_managed_configuration(
            replace(compiled, artifacts=()),
            source=ManagedConfigurationSource.MDM,
            now=100,
        ),
        lambda: measure_managed_configuration(
            replace(
                compiled,
                artifacts=(replace(compiled.artifacts[0], path="relative.json"),),
            ),
            source=ManagedConfigurationSource.MDM,
            now=100,
        ),
        lambda: measure_managed_configuration(
            replace(
                compiled,
                artifacts=(replace(compiled.artifacts[0], path="/missing/managed.json"),),
            ),
            source=ManagedConfigurationSource.MDM,
            now=100,
        ),
    )
    for invalid_call in invalid_calls:
        with pytest.raises(SecurityConfigurationError):
            invalid_call()


def test_managed_measurement_rejects_windows_without_acl_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider-neutral evidence never guesses whether Windows ACLs are safe."""
    compiled = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent("policy-safe", 1),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.WINDOWS,
        hook_command=r"C:\Program Files\AAI Security\hooks\codex-policy.exe",
    )
    monkeypatch.setattr(
        "agentic_security.managed_configuration.host_platform.system", lambda: "Windows"
    )
    with pytest.raises(SecurityConfigurationError, match="ACL verification"):
        measure_managed_configuration(
            compiled,
            source=ManagedConfigurationSource.CODEX_MDM,
            now=100,
        )


@pytest.mark.parametrize(
    ("host", "version", "message"),
    [
        (AgentHost.CLAUDE_CODE, "2.1.190", "2.1.191"),
        (AgentHost.CODEX_CLI, "0.137.0", "0.138.0"),
    ],
)
def test_compiler_rejects_versions_without_required_native_guarantees(
    host: AgentHost, version: str, message: str
) -> None:
    """An old client never receives an artifact falsely labelled enforceable."""
    with pytest.raises(SecurityConfigurationError, match=message):
        ManagedConfigurationCompiler().compile(
            policy(),
            host=host,
            host_version=version,
            platform=ManagedPlatform.LINUX,
            hook_command="/opt/aai-security/hooks/policy",
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "bad", "url": "http://example.com/mcp"},
        {"name": "bad", "url": "https://user:secret@example.com/mcp"},
        {"name": "bad", "url": "https://example.com/mcp#override"},
        {"name": "bad", "command": "python", "args": ()},
        {"name": "bad", "command": "/opt/../bin/mcp", "args": ()},
        {"name": "bad", "url": "https://example.com", "command": "/bin/mcp"},
    ],
)
def test_mcp_configuration_rejects_insecure_or_ambiguous_identity(
    kwargs: dict[str, object],
) -> None:
    """Remote plaintext, relative executables, and dual transports fail closed."""
    with pytest.raises(SecurityConfigurationError):
        ManagedMcpServer(**kwargs)  # type: ignore[arg-type]


def test_managed_command_rules_cannot_grant_allow() -> None:
    """Codex requirement rules are restrictive and never become an allow bypass."""
    with pytest.raises(SecurityConfigurationError, match="cannot grant allow"):
        ManagedCommandRule(("git",), NativeActionDecision.ALLOW, "unsafe widening")


@pytest.mark.parametrize(
    "command",
    [
        "python hook.py",
        "/bin/hook && true",
        "/bin/hook|true",
        "/bin/hook$(true)",
        "/opt/../bin/hook",
        "/bin/hook\ntrue",
    ],
)
def test_hook_command_rejects_relative_and_shell_composed_values(command: str) -> None:
    """Generated managed configuration cannot carry a shell-injection payload."""
    with pytest.raises(SecurityConfigurationError):
        ManagedConfigurationCompiler().compile(
            policy(),
            host=AgentHost.CLAUDE_CODE,
            host_version="2.1.211",
            platform=ManagedPlatform.LINUX,
            hook_command=command,
        )


def test_bundle_hash_changes_for_policy_content_even_when_version_is_reused() -> None:
    """Improper policy-version reuse cannot conceal a changed authority payload."""
    compiler = ManagedConfigurationCompiler()
    first = compiler.compile(
        policy(),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.211",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/policy",
    )
    changed = ManagedPolicyIntent(
        policy_id="policy-safe",
        policy_version=7,
        action_rules=(NativeActionRule("Read", NativeActionDecision.DENY, "changed"),),
    )
    second = compiler.compile(
        changed,
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.211",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/policy",
    )
    assert first.bundle_hash != second.bundle_hash


def test_reconciliation_requires_exact_fresh_same_host_evidence() -> None:
    """Desired state alone never yields effective permission."""
    bundle = ManagedConfigurationCompiler().compile(
        policy(),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/policy",
    )
    missing = reconcile_effective_authority(bundle, None, now=100)
    stale = reconcile_effective_authority(
        bundle,
        ObservedManagedConfiguration(
            AgentHost.CODEX_CLI,
            bundle.bundle_hash,
            ManagedConfigurationSource.CODEX_SYSTEM,
            1,
            50,
        ),
        now=100,
    )
    wrong_hash = reconcile_effective_authority(
        bundle,
        ObservedManagedConfiguration(
            AgentHost.CODEX_CLI,
            "0" * 64,
            ManagedConfigurationSource.CODEX_SYSTEM,
            1,
            200,
        ),
        now=100,
    )
    wrong_host = reconcile_effective_authority(
        bundle,
        ObservedManagedConfiguration(
            AgentHost.CLAUDE_CODE,
            bundle.bundle_hash,
            ManagedConfigurationSource.ENDPOINT_MANAGED_FILE,
            1,
            200,
        ),
        now=100,
    )

    assert missing.state is EnforcementState.MISSING
    assert stale.state is EnforcementState.STALE
    assert wrong_hash.state is EnforcementState.CONFLICT
    assert wrong_host.state is EnforcementState.CONFLICT
    for result in (missing, stale, wrong_hash, wrong_host):
        assert result.allowed_actions == ()
        assert result.approval_required_actions == ()
        assert "Read" in result.denied_actions


def test_observed_evidence_requires_a_typed_managed_source() -> None:
    """Free-form agent source labels cannot become trusted provenance."""
    with pytest.raises(SecurityConfigurationError, match="source must be typed"):
        ObservedManagedConfiguration(
            AgentHost.CLAUDE_CODE,
            "a" * 64,
            "project-file",  # type: ignore[arg-type]
            1,
            2,
        )


def test_reconciliation_reports_exact_evidence_and_deny_first_conflicts() -> None:
    """Fresh evidence permits only non-conflicting intent and exposes conflicts."""
    compiler = ManagedConfigurationCompiler()
    clean_bundle = compiler.compile(
        policy(),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.211",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/policy",
    )
    clean = reconcile_effective_authority(
        clean_bundle,
        ObservedManagedConfiguration(
            AgentHost.CLAUDE_CODE,
            clean_bundle.bundle_hash,
            ManagedConfigurationSource.ENDPOINT_MANAGED_FILE,
            90,
            200,
        ),
        now=100,
    )
    assert clean.state is EnforcementState.ENFORCED
    assert clean.allowed_actions == ("Read",)
    assert clean.source == "endpoint-managed-file"

    conflict_bundle = compiler.compile(
        policy(conflicting=True),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.211",
        platform=ManagedPlatform.LINUX,
        hook_command="/opt/aai-security/hooks/policy",
    )
    conflict = reconcile_effective_authority(
        conflict_bundle,
        ObservedManagedConfiguration(
            AgentHost.CLAUDE_CODE,
            conflict_bundle.bundle_hash,
            ManagedConfigurationSource.ENDPOINT_MANAGED_FILE,
            90,
            200,
        ),
        now=100,
    )
    assert conflict.state is EnforcementState.CONFLICT
    assert conflict.conflicts == ("Read",)
    assert "Read" not in conflict.allowed_actions
    assert "Read" in conflict.denied_actions


def test_compilation_is_deterministic() -> None:
    """The same reviewed intent always produces byte-identical artifacts and hashes."""
    compiler = ManagedConfigurationCompiler()
    first = compiler.compile(
        policy(),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.MACOS,
        hook_command="/opt/aai-security/hooks/policy",
    )
    second = compiler.compile(
        policy(),
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.MACOS,
        hook_command="/opt/aai-security/hooks/policy",
    )
    assert first == second

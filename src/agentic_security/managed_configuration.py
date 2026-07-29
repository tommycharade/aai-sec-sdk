"""Compile central policy intent into verifiable host-managed configuration.

This module separates three facts that an enterprise control plane must never
conflate: what an operator requested, what a supported host can enforce, and
what a particular endpoint has actually attested.  Compilation is pure and
deterministic.  It does not write privileged paths or claim that endpoint
management has deployed the returned artifacts.

The generated files intentionally contain no credentials.  MCP authentication
must use per-user OAuth, environment expansion, or a deployment-owned helper.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

from .errors import SecurityConfigurationError
from .integrations import AgentHost

_MAX_RULES: Final[int] = 200
_MAX_TEXT: Final[int] = 1_024
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)


class ManagedPlatform(StrEnum):
    """Operating-system family used to choose immutable managed paths."""

    MACOS = "macos"
    LINUX = "linux"
    WINDOWS = "windows"


class NativeActionDecision(StrEnum):
    """Host-independent decision requested for one native action expression."""

    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class EnforcementState(StrEnum):
    """Truthful state of one requested control at a host boundary."""

    ENFORCED = "enforced"
    SDK_ENFORCED = "sdk_enforced"
    DEPLOYMENT_REQUIRED = "deployment_required"
    UNSUPPORTED = "unsupported"
    MISSING = "missing"
    STALE = "stale"
    CONFLICT = "conflict"
    VERSION_INCOMPATIBLE = "version_incompatible"


class ManagedConfigurationSource(StrEnum):
    """Administrator-owned source from which a running host loaded policy."""

    CLAUDE_SERVER_MANAGED = "claude-server-managed"
    ENDPOINT_MANAGED_FILE = "endpoint-managed-file"
    MDM = "mdm"
    CODEX_SYSTEM = "codex-system"
    CODEX_CLOUD = "codex-cloud"
    CODEX_MDM = "codex-mdm"


@dataclass(frozen=True, slots=True)
class NativeActionRule:
    """One bounded host-native action expression and its desired decision.

    ``expression`` uses the destination host's native permission syntax.  The
    compiler does not reinterpret regular expressions as shell commands or
    vice versa; callers must supply a reviewed expression for the target host.
    """

    expression: str
    decision: NativeActionDecision
    reason: str

    def __post_init__(self) -> None:
        """Reject empty or unbounded policy expressions before serialization."""
        _bounded_text(self.expression, "action expression")
        _bounded_text(self.reason, "action reason")
        if not isinstance(self.decision, NativeActionDecision):
            raise SecurityConfigurationError("action decision must be typed")


@dataclass(frozen=True, slots=True)
class ManagedCommandRule:
    """Restrictive exact-token command rule supported by Codex requirements.

    Codex managed requirements can only add ``prompt`` or ``forbidden`` rules;
    an allow decision is deliberately not representable by this type.
    """

    tokens: tuple[str, ...]
    decision: NativeActionDecision
    reason: str

    def __post_init__(self) -> None:
        """Require a bounded token sequence and a restrictive decision."""
        if not self.tokens or len(self.tokens) > 20:
            raise SecurityConfigurationError("command rule must contain 1 to 20 tokens")
        for token in self.tokens:
            _bounded_text(token, "command token")
        if not isinstance(self.decision, NativeActionDecision) or self.decision not in {
            NativeActionDecision.DENY,
            NativeActionDecision.APPROVAL_REQUIRED,
        }:
            raise SecurityConfigurationError("managed command rules cannot grant allow")
        _bounded_text(self.reason, "command rule reason")


@dataclass(frozen=True, slots=True)
class ManagedMcpServer:
    """Credential-free identity and launch configuration for one MCP server."""

    name: str
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require exactly one secure transport identity and bounded arguments."""
        _bounded_text(self.name, "MCP server name")
        if (self.url is None) == (self.command is None):
            raise SecurityConfigurationError("MCP server requires exactly one of url or command")
        if self.url is not None:
            _bounded_text(self.url, "MCP server URL")
            parsed = urlsplit(self.url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise SecurityConfigurationError("remote MCP servers must use HTTPS")
            if self.args:
                raise SecurityConfigurationError("remote MCP servers cannot define command args")
        if self.command is not None:
            _bounded_text(self.command, "MCP server command")
            if not self.command.startswith(("/", "C:\\")):
                raise SecurityConfigurationError("managed MCP commands must use an absolute path")
            if len(self.args) > 30:
                raise SecurityConfigurationError("MCP server args exceed the configured limit")
            for argument in self.args:
                _bounded_text(argument, "MCP server argument")
            if any(part == ".." for part in re.split(r"[/\\]", self.command)):
                raise SecurityConfigurationError("managed MCP command cannot traverse directories")


@dataclass(frozen=True, slots=True)
class ManagedPolicyIntent:
    """Typed central intent compiled for one supported agent host.

    This object contains policy and deployment references only.  It cannot
    carry environment-variable values, API keys, or other credential material.
    """

    policy_id: str
    policy_version: int
    action_rules: tuple[NativeActionRule, ...] = ()
    command_rules: tuple[ManagedCommandRule, ...] = ()
    mcp_servers: tuple[ManagedMcpServer, ...] = ()
    deny_read: tuple[str, ...] = ()
    allowed_network_domains: tuple[str, ...] = ()
    allow_web_search: bool = False

    def __post_init__(self) -> None:
        """Reject oversized, duplicate, or ambiguous deployment policy input."""
        _bounded_text(self.policy_id, "policy id")
        if self.policy_version <= 0:
            raise SecurityConfigurationError("policy version must be positive")
        if len(self.action_rules) > _MAX_RULES or len(self.command_rules) > _MAX_RULES:
            raise SecurityConfigurationError("managed policy contains too many rules")
        if not all(isinstance(rule, NativeActionRule) for rule in self.action_rules):
            raise SecurityConfigurationError("action rules must use NativeActionRule")
        if not all(isinstance(rule, ManagedCommandRule) for rule in self.command_rules):
            raise SecurityConfigurationError("command rules must use ManagedCommandRule")
        if not all(isinstance(server, ManagedMcpServer) for server in self.mcp_servers):
            raise SecurityConfigurationError("MCP servers must use ManagedMcpServer")
        names = [server.name for server in self.mcp_servers]
        if len(names) != len(set(names)):
            raise SecurityConfigurationError("managed MCP server names must be unique")
        for path in self.deny_read:
            _bounded_text(path, "deny-read path")
            if path.startswith("./"):
                raise SecurityConfigurationError("deny-read paths cannot start with ./")
        for domain in self.allowed_network_domains:
            _bounded_text(domain, "network domain")
            if _DOMAIN_PATTERN.fullmatch(domain) is None:
                raise SecurityConfigurationError("network allow entries must be domain names")


@dataclass(frozen=True, slots=True)
class ManagedArtifact:
    """One deterministic file that endpoint management must deploy atomically."""

    path: str
    media_type: str
    content: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ControlCoverage:
    """Capability-level statement about how a requested control is delivered."""

    control: str
    state: EnforcementState
    source: str
    reason: str


@dataclass(frozen=True, slots=True)
class ManagedConfigurationBundle:
    """Compiled artifacts and coverage evidence for one host policy version."""

    host: AgentHost
    host_version: str
    platform: ManagedPlatform
    policy_id: str
    policy_version: int
    artifacts: tuple[ManagedArtifact, ...]
    coverage: tuple[ControlCoverage, ...]
    bundle_hash: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    approval_required_actions: tuple[str, ...]
    conflicts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ObservedManagedConfiguration:
    """Endpoint-owned evidence for the managed bundle loaded by a host process."""

    host: AgentHost
    bundle_hash: str
    source: ManagedConfigurationSource
    verified_at: float
    expires_at: float

    def __post_init__(self) -> None:
        """Reject malformed or non-expiring attestation evidence."""
        if not _SHA256_PATTERN.fullmatch(self.bundle_hash):
            raise SecurityConfigurationError("observed bundle hash must be lowercase SHA-256")
        if not isinstance(self.host, AgentHost):
            raise SecurityConfigurationError("observed host must be typed")
        if not isinstance(self.source, ManagedConfigurationSource):
            raise SecurityConfigurationError("managed configuration source must be typed")
        if self.verified_at < 0 or self.expires_at <= self.verified_at:
            raise SecurityConfigurationError("managed configuration evidence expiry is invalid")


@dataclass(frozen=True, slots=True)
class EffectiveAuthority:
    """Deny-first authority derived from desired policy and observed host evidence."""

    state: EnforcementState
    reason: str
    bundle_hash: str
    source: str | None
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    approval_required_actions: tuple[str, ...]
    conflicts: tuple[str, ...]


class ManagedConfigurationCompiler:
    """Compile typed policy into Claude Code or Codex managed artifacts.

    Compilation never mutates the machine.  The caller must distribute every
    artifact through an administrator-owned channel and later reconcile it
    against endpoint evidence with :func:`reconcile_effective_authority`.
    """

    def compile(
        self,
        intent: ManagedPolicyIntent,
        *,
        host: AgentHost,
        host_version: str,
        platform: ManagedPlatform,
        hook_command: str,
    ) -> ManagedConfigurationBundle:
        """Return deterministic artifacts or fail for an unsupported host/version."""
        if not isinstance(host, AgentHost) or not isinstance(platform, ManagedPlatform):
            raise SecurityConfigurationError("host and platform must be typed")
        version = _parse_version(host_version)
        _absolute_command(hook_command, platform)
        allowed, denied, approval, conflicts = _resolve_action_rules(intent.action_rules)
        if host is AgentHost.CLAUDE_CODE:
            if version < (2, 1, 191):
                raise SecurityConfigurationError(
                    "Claude Code 2.1.191 or later is required for fail-closed managed refresh"
                )
            artifacts, coverage = self._compile_claude(intent, platform, hook_command, conflicts)
        elif host is AgentHost.CODEX_CLI:
            if version < (0, 138, 0):
                raise SecurityConfigurationError(
                    "Codex 0.138.0 or later is required for managed permission profiles"
                )
            artifacts, coverage = self._compile_codex(intent, platform, hook_command, conflicts)
        else:
            raise SecurityConfigurationError("managed compilation supports Claude Code and Codex")
        bundle_hash = _bundle_hash(host, host_version, platform, intent, artifacts)
        return ManagedConfigurationBundle(
            host=host,
            host_version=host_version,
            platform=platform,
            policy_id=intent.policy_id,
            policy_version=intent.policy_version,
            artifacts=artifacts,
            coverage=coverage,
            bundle_hash=bundle_hash,
            allowed_actions=allowed,
            denied_actions=denied,
            approval_required_actions=approval,
            conflicts=conflicts,
        )

    @staticmethod
    def _compile_claude(
        intent: ManagedPolicyIntent,
        platform: ManagedPlatform,
        hook_command: str,
        conflicts: tuple[str, ...],
    ) -> tuple[tuple[ManagedArtifact, ...], tuple[ControlCoverage, ...]]:
        """Compile endpoint-managed Claude settings and exclusive MCP inventory."""
        allow, deny, approval, _ = _resolve_action_rules(intent.action_rules)
        settings = {
            "allowManagedPermissionRulesOnly": True,
            "forceRemoteSettingsRefresh": True,
            "permissions": {
                "allow": list(allow),
                "ask": list(approval),
                "deny": list(deny),
                "disableBypassPermissionsMode": "disable",
            },
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": hook_command, "timeout": 30}],
                    }
                ]
            },
        }
        if intent.allowed_network_domains:
            settings["sandbox"] = {
                "enabled": True,
                "network": {"allowedDomains": list(intent.allowed_network_domains)},
            }
        mcp = {"mcpServers": {server.name: _claude_mcp(server) for server in intent.mcp_servers}}
        settings_path, mcp_path = _claude_paths(platform)
        artifacts = (
            _artifact(settings_path, "application/json", _json_document(settings)),
            _artifact(mcp_path, "application/json", _json_document(mcp)),
        )
        coverage = (
            ControlCoverage(
                "native_actions",
                EnforcementState.CONFLICT if conflicts else EnforcementState.ENFORCED,
                "claude_managed_settings",
                (
                    "deny-first conflicts require operator review"
                    if conflicts
                    else "managed permissions"
                ),
            ),
            ControlCoverage(
                "managed_hook", EnforcementState.ENFORCED, "claude_managed_settings", "PreToolUse"
            ),
            ControlCoverage(
                "mcp_inventory", EnforcementState.ENFORCED, "claude_managed_mcp", "exclusive set"
            ),
            ControlCoverage(
                "command_rules",
                EnforcementState.SDK_ENFORCED,
                "aai_pre_tool_hook",
                "Claude managed settings cannot consume Codex token rules",
            ),
            ControlCoverage(
                "deny_read",
                EnforcementState.SDK_ENFORCED,
                "aai_pre_tool_hook",
                "path policy is enforced by the SDK hook",
            ),
        )
        return artifacts, coverage

    @staticmethod
    def _compile_codex(
        intent: ManagedPolicyIntent,
        platform: ManagedPlatform,
        hook_command: str,
        conflicts: tuple[str, ...],
    ) -> tuple[tuple[ManagedArtifact, ...], tuple[ControlCoverage, ...]]:
        """Compile immutable Codex requirements with managed hooks and MCP identities."""
        lines = [
            'allowed_approval_policies = ["on-request"]',
            'default_permissions = ":workspace"',
            "allow_managed_hooks_only = true",
            'allowed_web_search_modes = ["cached"]'
            if intent.allow_web_search
            else "allowed_web_search_modes = []",
            "",
            "[allowed_permission_profiles]",
            '":read-only" = true',
            '":workspace" = true',
            "",
            "[features]",
            "hooks = true",
            "plugins = false",
            "browser_use = false",
            "computer_use = false",
            "",
            "[hooks]",
            f"managed_dir = {_toml_string(_hook_directory(platform))}",
        ]
        if platform is ManagedPlatform.WINDOWS:
            lines.append(f"windows_managed_dir = {_toml_string(_hook_directory(platform))}")
        lines.extend(
            [
                "",
                "[[hooks.PreToolUse]]",
                'matcher = ".*"',
                "",
                "[[hooks.PreToolUse.hooks]]",
                'type = "command"',
                f"command = {_toml_string(hook_command)}",
                f"command_windows = {_toml_string(hook_command)}",
                "timeout = 30",
                'statusMessage = "Checking enterprise security policy"',
            ]
        )
        if intent.deny_read:
            lines.extend(["", "[permissions.filesystem]"])
            lines.append("deny_read = " + _toml_array(intent.deny_read))
        if intent.allowed_network_domains:
            lines.extend(
                [
                    "",
                    "[experimental_network]",
                    "enabled = true",
                    "managed_allowed_domains_only = true",
                    "allowed_domains = " + _toml_array(intent.allowed_network_domains),
                ]
            )
        if intent.command_rules:
            lines.extend(["", "[rules]", "prefix_rules = ["])
            for rule in intent.command_rules:
                decision = "forbidden" if rule.decision is NativeActionDecision.DENY else "prompt"
                pattern = ", ".join(f"{{ token = {_toml_string(token)} }}" for token in rule.tokens)
                lines.append(
                    "  { pattern = ["
                    + pattern
                    + f"], decision = {_toml_string(decision)}, "
                    + f"justification = {_toml_string(rule.reason)} }},"
                )
            lines.append("]")
        for server in intent.mcp_servers:
            lines.extend(["", f"[mcp_servers.{_toml_key(server.name)}]"])
            if server.url is not None:
                lines.append(f"identity = {{ url = {_toml_string(server.url)} }}")
            else:
                args = ", ".join(
                    f'{{ match = "exact", value = {_toml_string(argument)} }}'
                    for argument in server.args
                )
                command = (
                    "{ executable = " + _toml_string(server.command or "") + f", args = [{args}] }}"
                )
                lines.append(f"identity = {{ command = {command} }}")
        content = "\n".join(lines) + "\n"
        artifact = _artifact(_codex_path(platform), "application/toml", content)
        coverage = (
            ControlCoverage(
                "native_actions",
                EnforcementState.CONFLICT if conflicts else EnforcementState.SDK_ENFORCED,
                "aai_managed_pre_tool_hook",
                "deny-first conflicts require operator review" if conflicts else "managed hook",
            ),
            ControlCoverage(
                "managed_hook",
                EnforcementState.ENFORCED,
                "codex_requirements",
                "managed-only hooks",
            ),
            ControlCoverage(
                "mcp_inventory",
                EnforcementState.ENFORCED,
                "codex_requirements",
                "identity allowlist",
            ),
            ControlCoverage(
                "command_rules",
                EnforcementState.ENFORCED,
                "codex_requirements",
                "restrictive rules",
            ),
            ControlCoverage(
                "deny_read", EnforcementState.ENFORCED, "codex_requirements", "filesystem deny_read"
            ),
            ControlCoverage(
                "network",
                EnforcementState.ENFORCED,
                "codex_requirements",
                "experimental managed domain allowlist; canary validation required",
            ),
        )
        return (artifact,), coverage


def reconcile_effective_authority(
    bundle: ManagedConfigurationBundle,
    observed: ObservedManagedConfiguration | None,
    *,
    now: float,
) -> EffectiveAuthority:
    """Derive effective authority from endpoint evidence and fail closed on uncertainty.

    A desired bundle is not evidence of enforcement.  Until an endpoint reports
    an exact, fresh hash from the same host, every intended allow is withheld.
    """
    conflicts = bundle.conflicts
    if observed is None:
        return _closed_authority(bundle, EnforcementState.MISSING, "no endpoint evidence", None)
    if observed.host is not bundle.host:
        return _closed_authority(
            bundle,
            EnforcementState.CONFLICT,
            "endpoint evidence is for another host",
            observed.source.value,
        )
    if observed.expires_at <= now or observed.verified_at > now:
        return _closed_authority(
            bundle,
            EnforcementState.STALE,
            "endpoint evidence is stale or future-dated",
            observed.source.value,
        )
    if observed.bundle_hash != bundle.bundle_hash:
        return _closed_authority(
            bundle,
            EnforcementState.CONFLICT,
            "observed bundle hash differs from desired",
            observed.source.value,
        )
    if conflicts:
        return EffectiveAuthority(
            EnforcementState.CONFLICT,
            "conflicting rules resolved deny-first",
            bundle.bundle_hash,
            observed.source.value,
            tuple(action for action in bundle.allowed_actions if action not in conflicts),
            bundle.denied_actions,
            tuple(action for action in bundle.approval_required_actions if action not in conflicts),
            conflicts,
        )
    return EffectiveAuthority(
        EnforcementState.ENFORCED,
        "exact managed bundle observed",
        bundle.bundle_hash,
        observed.source.value,
        bundle.allowed_actions,
        bundle.denied_actions,
        bundle.approval_required_actions,
        (),
    )


def _closed_authority(
    bundle: ManagedConfigurationBundle,
    state: EnforcementState,
    reason: str,
    source: str | None,
) -> EffectiveAuthority:
    """Return no effective allows when host enforcement is not proven."""
    denied = tuple(
        sorted(
            set(bundle.allowed_actions)
            | set(bundle.denied_actions)
            | set(bundle.approval_required_actions)
        )
    )
    return EffectiveAuthority(state, reason, bundle.bundle_hash, source, (), denied, (), ())


def _resolve_action_rules(
    rules: tuple[NativeActionRule, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve duplicate expressions by deny, approval, allow precedence."""
    decisions: dict[str, set[NativeActionDecision]] = {}
    for rule in rules:
        decisions.setdefault(rule.expression, set()).add(rule.decision)
    conflicts = tuple(sorted(key for key, values in decisions.items() if len(values) > 1))
    denied = tuple(
        sorted(key for key, values in decisions.items() if NativeActionDecision.DENY in values)
    )
    approval = tuple(
        sorted(
            key
            for key, values in decisions.items()
            if NativeActionDecision.DENY not in values
            and NativeActionDecision.APPROVAL_REQUIRED in values
        )
    )
    allowed = tuple(
        sorted(key for key, values in decisions.items() if values == {NativeActionDecision.ALLOW})
    )
    return allowed, denied, approval, conflicts


def _claude_mcp(server: ManagedMcpServer) -> dict[str, object]:
    """Serialize one credential-free Claude managed MCP entry."""
    if server.url is not None:
        return {"type": "http", "url": server.url}
    return {"type": "stdio", "command": server.command, "args": list(server.args)}


def _claude_paths(platform: ManagedPlatform) -> tuple[str, str]:
    """Return documented endpoint-managed Claude policy paths."""
    if platform is ManagedPlatform.MACOS:
        root = "/Library/Application Support/ClaudeCode"
    elif platform is ManagedPlatform.LINUX:
        root = "/etc/claude-code"
    else:
        root = r"C:\Program Files\ClaudeCode"
    return f"{root}/managed-settings.json", f"{root}/managed-mcp.json"


def _codex_path(platform: ManagedPlatform) -> str:
    """Return the documented system requirements path for Codex."""
    if platform is ManagedPlatform.WINDOWS:
        return r"C:\ProgramData\OpenAI\Codex\requirements.toml"
    return "/etc/codex/requirements.toml"


def _hook_directory(platform: ManagedPlatform) -> str:
    """Return the administrator-owned hook installation directory."""
    if platform is ManagedPlatform.WINDOWS:
        return r"C:\Program Files\AAI Security\hooks"
    return "/opt/aai-security/hooks"


def _absolute_command(command: str, platform: ManagedPlatform) -> None:
    """Reject relative or shell-composed hook commands at the trust boundary."""
    _bounded_text(command, "hook command")
    if any(part == ".." for part in re.split(r"[/\\]", command)):
        raise SecurityConfigurationError("hook command cannot traverse directories")
    if platform is ManagedPlatform.WINDOWS:
        if re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9 ._\\-]+", command) is None:
            raise SecurityConfigurationError("Windows hook command must use an absolute path")
    elif re.fullmatch(r"/[A-Za-z0-9._/-]+", command) is None:
        raise SecurityConfigurationError("hook command must be one absolute executable path")


def _artifact(path: str, media_type: str, content: str) -> ManagedArtifact:
    """Create immutable file evidence from deterministic UTF-8 content."""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return ManagedArtifact(path, media_type, content, digest)


def _bundle_hash(
    host: AgentHost,
    host_version: str,
    platform: ManagedPlatform,
    intent: ManagedPolicyIntent,
    artifacts: tuple[ManagedArtifact, ...],
) -> str:
    """Bind host, target version, policy version, paths, and bytes."""
    payload = {
        "host": host.value,
        "hostVersion": host_version,
        "platform": platform.value,
        "policyId": intent.policy_id,
        "policyVersion": intent.policy_version,
        "intent": {
            "actions": [
                {
                    "expression": rule.expression,
                    "decision": rule.decision.value,
                    "reason": rule.reason,
                }
                for rule in intent.action_rules
            ],
            "commands": [
                {
                    "tokens": list(rule.tokens),
                    "decision": rule.decision.value,
                    "reason": rule.reason,
                }
                for rule in intent.command_rules
            ],
            "mcp": [
                {
                    "name": server.name,
                    "url": server.url,
                    "command": server.command,
                    "args": list(server.args),
                }
                for server in intent.mcp_servers
            ],
            "denyRead": list(intent.deny_read),
            "networkDomains": list(intent.allowed_network_domains),
            "allowWebSearch": intent.allow_web_search,
        },
        "artifacts": [
            {"path": item.path, "mediaType": item.media_type, "sha256": item.sha256}
            for item in artifacts
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_document(value: object) -> str:
    """Return stable, human-reviewable JSON with a final newline."""
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _toml_string(value: str) -> str:
    """Encode a string using JSON escaping, which is valid TOML basic-string syntax."""
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: tuple[str, ...]) -> str:
    """Encode a deterministic TOML string array."""
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _toml_key(value: str) -> str:
    """Always quote dynamic TOML keys to prevent table-path injection."""
    return _toml_string(value)


def _parse_version(value: str) -> tuple[int, int, int]:
    """Parse a three-component host version without accepting ambiguous input."""
    match = _VERSION_PATTERN.fullmatch(value)
    if match is None:
        raise SecurityConfigurationError("host version must use major.minor.patch")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _bounded_text(value: str, field: str) -> str:
    """Return trimmed text after applying common public-input bounds."""
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > _MAX_TEXT
        or any(ord(character) < 32 for character in value)
    ):
        raise SecurityConfigurationError(f"{field} must be non-empty bounded text")
    return value.strip()


__all__ = [
    "ControlCoverage",
    "EffectiveAuthority",
    "EnforcementState",
    "ManagedArtifact",
    "ManagedCommandRule",
    "ManagedConfigurationSource",
    "ManagedConfigurationBundle",
    "ManagedConfigurationCompiler",
    "ManagedMcpServer",
    "ManagedPlatform",
    "ManagedPolicyIntent",
    "NativeActionDecision",
    "NativeActionRule",
    "ObservedManagedConfiguration",
    "reconcile_effective_authority",
]

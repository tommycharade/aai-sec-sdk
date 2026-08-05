"""Read and reconcile content-minimised Codex effective-control evidence.

Codex app-server configuration responses are untrusted and can contain bearer
tokens, commands, paths, URLs, prompts, and environment variables. This module
keeps those response objects in process memory only, projects a fixed safe
schema, and never copies raw host errors into exceptions or evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform as host_platform
import queue
import re
import stat
import subprocess
import threading
import time
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .errors import SecurityConfigurationError
from .integrations import AgentHost
from .managed_configuration import (
    EnforcementState,
    ManagedConfigurationBundle,
    ManagedPlatform,
)

_SHA256_LENGTH: Final[int] = 64
_MAX_LINE_BYTES: Final[int] = 4_000_000
_MAX_TOTAL_BYTES: Final[int] = 8_000_000
_MAX_MESSAGES: Final[int] = 128
_MAX_ITEMS: Final[int] = 256
_REQUEST_IDS: Final[frozenset[str]] = frozenset(
    {"aai-initialize", "aai-config", "aai-requirements"}
)
_SOURCE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "mdm",
        "system",
        "enterpriseManaged",
        "user",
        "project",
        "sessionFlags",
        "legacyManagedConfigTomlFromFile",
        "legacyManagedConfigTomlFromMdm",
    }
)
_SECURITY_ORIGINS: Final[tuple[str, ...]] = (
    "approval_policy",
    "sandbox_mode",
    "default_permissions",
    "web_search",
)
_EVIDENCE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "host",
        "hostVersion",
        "platform",
        "state",
        "reason",
        "expectedDigest",
        "observedDigest",
        "approvalPolicy",
        "sandboxMode",
        "defaultPermissions",
        "webSearchMode",
        "managedMcpServerNames",
        "unexpectedMcpServerCount",
        "preToolHookSha256",
        "requirements",
        "securityOrigins",
        "mismatches",
        "unverifiedControls",
        "allowedActions",
        "deniedActions",
        "approvalRequiredActions",
        "verifiedAt",
        "expiresAt",
    }
)
_REASONS_BY_STATE: Final[dict[EnforcementState, str]] = {
    EnforcementState.ENFORCED: "effective-controls-match",
    EnforcementState.MISSING: "administrator-requirements-missing",
    EnforcementState.CONFLICT: "effective-controls-differ",
    EnforcementState.DEPLOYMENT_REQUIRED: "effective-controls-partially-observable",
}
_MISMATCH_CODES: Final[set[str]] = {
    "allowed-approval-policies",
    "default-permissions",
    "allowed-permission-profiles",
    "allowed-sandbox-modes",
    "allowed-web-search-modes",
    "managed-hooks-only",
    "feature-requirements",
    "network-enabled",
    "managed-network-domains-only",
    "network-domains",
    "effective-approval-policy",
    "effective-sandbox-mode",
    "effective-default-permissions",
    "managed-pre-tool-hook",
    "host-version",
}
_GAP_CODES: Final[set[str]] = {
    "mcp-runtime-status",
    "command-rule-runtime-match",
    "deny-read-runtime-match",
}


@dataclass(frozen=True, slots=True)
class CodexRequirementProjection:
    """Safe allowlisted projection of Codex administrator requirements."""

    allowed_approval_policies: tuple[str, ...]
    default_permissions: str | None
    allowed_permission_profiles: tuple[tuple[str, bool], ...]
    allowed_sandbox_modes: tuple[str, ...]
    allowed_web_search_modes: tuple[str, ...]
    allow_managed_hooks_only: bool | None
    feature_requirements: tuple[tuple[str, bool], ...]
    network_enabled: bool | None
    network_managed_domains_only: bool | None
    network_domains: tuple[tuple[str, str], ...]

    def to_wire(self) -> dict[str, object]:
        """Return the fixed credential-free wire representation."""
        return {
            "allowedApprovalPolicies": list(self.allowed_approval_policies),
            "defaultPermissions": self.default_permissions,
            "allowedPermissionProfiles": dict(self.allowed_permission_profiles),
            "allowedSandboxModes": list(self.allowed_sandbox_modes),
            "allowedWebSearchModes": list(self.allowed_web_search_modes),
            "allowManagedHooksOnly": self.allow_managed_hooks_only,
            "featureRequirements": dict(self.feature_requirements),
            "network": {
                "enabled": self.network_enabled,
                "managedAllowedDomainsOnly": self.network_managed_domains_only,
                "domains": dict(self.network_domains),
            },
        }


@dataclass(frozen=True, slots=True)
class CodexEffectiveControlEvidence:
    """Short-lived, content-minimised result of live Codex reconciliation.

    The evidence deliberately excludes raw configuration, commands, paths,
    URLs, headers, environment variables, and app-server error text. It proves
    only what the queried app-server exposed at ``verified_at``.
    """

    host_version: str
    platform: str
    state: EnforcementState
    reason: str
    expected_digest: str
    observed_digest: str | None
    approval_policy: str | None
    sandbox_mode: str | None
    default_permissions: str | None
    web_search_mode: str | None
    managed_mcp_server_names: tuple[str, ...]
    unexpected_mcp_server_count: int
    pre_tool_hook_sha256: tuple[str, ...]
    requirement_projection: CodexRequirementProjection | None
    security_origins: tuple[tuple[str, str], ...]
    mismatches: tuple[str, ...]
    unverified_controls: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    approval_required_actions: tuple[str, ...]
    verified_at: int
    expires_at: int

    def to_wire(self) -> dict[str, object]:
        """Return the fixed heartbeat payload without sensitive host content."""
        return {
            "host": AgentHost.CODEX_CLI.value,
            "hostVersion": self.host_version,
            "platform": self.platform,
            "state": self.state.value,
            "reason": self.reason,
            "expectedDigest": self.expected_digest,
            "observedDigest": self.observed_digest,
            "approvalPolicy": self.approval_policy,
            "sandboxMode": self.sandbox_mode,
            "defaultPermissions": self.default_permissions,
            "webSearchMode": self.web_search_mode,
            "managedMcpServerNames": list(self.managed_mcp_server_names),
            "unexpectedMcpServerCount": self.unexpected_mcp_server_count,
            "preToolHookSha256": list(self.pre_tool_hook_sha256),
            "requirements": (
                None
                if self.requirement_projection is None
                else self.requirement_projection.to_wire()
            ),
            "securityOrigins": dict(self.security_origins),
            "mismatches": list(self.mismatches),
            "unverifiedControls": list(self.unverified_controls),
            "allowedActions": list(self.allowed_actions),
            "deniedActions": list(self.denied_actions),
            "approvalRequiredActions": list(self.approval_required_actions),
            "verifiedAt": self.verified_at,
            "expiresAt": self.expires_at,
        }


def codex_effective_control_evidence_from_wire(
    value: object,
) -> CodexEffectiveControlEvidence:
    """Parse an untrusted heartbeat projection into validated typed evidence.

    Unknown fields, free-form reason codes, secret-bearing nested content, and
    inconsistent state/action combinations fail closed. The returned object can
    be safely re-serialized with :meth:`CodexEffectiveControlEvidence.to_wire`.
    """
    item = _object(value, "effective-control evidence")
    if frozenset(item) != _EVIDENCE_FIELDS or item.get("host") != AgentHost.CODEX_CLI.value:
        raise SecurityConfigurationError("Codex effective-control evidence has invalid schema")
    platform_value = item.get("platform")
    state_value = item.get("state")
    try:
        if not isinstance(platform_value, str) or not isinstance(state_value, str):
            raise ValueError
        platform = ManagedPlatform(platform_value)
        state = EnforcementState(state_value)
    except (TypeError, ValueError):
        raise SecurityConfigurationError(
            "Codex effective-control evidence has invalid enums"
        ) from None
    if state not in _REASONS_BY_STATE or item.get("reason") != _REASONS_BY_STATE[state]:
        raise SecurityConfigurationError("Codex effective-control reason does not match state")
    expected_digest = _sha256(item.get("expectedDigest"), "expected evidence digest")
    observed_value = item.get("observedDigest")
    observed_digest = (
        None if observed_value is None else _sha256(observed_value, "observed evidence digest")
    )
    requirements_value = item.get("requirements")
    requirements = (
        None
        if requirements_value is None
        else _project_requirements(_object(requirements_value, "evidence requirements"))
    )
    origins_value = _object(item.get("securityOrigins"), "evidence security origins")
    if any(key not in _SECURITY_ORIGINS for key in origins_value):
        raise SecurityConfigurationError("Codex evidence security origin is unsupported")
    origins: list[tuple[str, str]] = []
    for key, source in origins_value.items():
        if not isinstance(source, str) or source not in _SOURCE_TYPES:
            raise SecurityConfigurationError("Codex evidence security origin is malformed")
        origins.append((key, source))
    mismatches = _coded_tuple(item.get("mismatches"), "mismatches", _MISMATCH_CODES)
    gaps = _coded_tuple(item.get("unverifiedControls"), "control gaps", _GAP_CODES)
    allowed = _string_tuple(item.get("allowedActions"), "allowed actions")
    denied = _string_tuple(item.get("deniedActions"), "denied actions")
    approval = _string_tuple(item.get("approvalRequiredActions"), "approval-required actions")
    verified_at = _timestamp(item.get("verifiedAt"), "verifiedAt")
    expires_at = _timestamp(item.get("expiresAt"), "expiresAt")
    if expires_at <= verified_at or expires_at - verified_at > 300:
        raise SecurityConfigurationError("Codex effective-control evidence expiry is invalid")
    count = item.get("unexpectedMcpServerCount")
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= _MAX_ITEMS:
        raise SecurityConfigurationError("Codex unexpected MCP count is invalid")
    if state is not EnforcementState.ENFORCED and (allowed or approval):
        raise SecurityConfigurationError("closed Codex evidence cannot contain effective allows")
    if state is EnforcementState.ENFORCED and (mismatches or gaps or requirements is None):
        raise SecurityConfigurationError("enforced Codex evidence contains unresolved controls")
    if state is EnforcementState.MISSING and requirements is not None:
        raise SecurityConfigurationError("missing Codex evidence cannot contain requirements")
    return CodexEffectiveControlEvidence(
        host_version=_enum_text(item.get("hostVersion"), "evidence host version", 128),
        platform=platform.value,
        state=state,
        reason=_REASONS_BY_STATE[state],
        expected_digest=expected_digest,
        observed_digest=observed_digest,
        approval_policy=_optional_mode(item.get("approvalPolicy"), "evidence approval policy"),
        sandbox_mode=_optional_mode(item.get("sandboxMode"), "evidence sandbox mode"),
        default_permissions=_optional_enum(
            item.get("defaultPermissions"), "evidence default permissions"
        ),
        web_search_mode=_optional_enum(item.get("webSearchMode"), "evidence web-search mode"),
        managed_mcp_server_names=_string_tuple(
            item.get("managedMcpServerNames"), "managed MCP server names"
        ),
        unexpected_mcp_server_count=count,
        pre_tool_hook_sha256=tuple(
            _sha256(digest, "hook digest")
            for digest in _string_tuple(item.get("preToolHookSha256"), "hook digests")
        ),
        requirement_projection=requirements,
        security_origins=tuple(sorted(origins)),
        mismatches=mismatches,
        unverified_controls=gaps,
        allowed_actions=allowed,
        denied_actions=denied,
        approval_required_actions=approval,
        verified_at=verified_at,
        expires_at=expires_at,
    )


@dataclass(frozen=True, slots=True)
class _ObservedProjection:
    """Internal safe projection retained after raw app-server data is discarded."""

    host_version: str
    platform: str
    approval_policy: str | None
    sandbox_mode: str | None
    default_permissions: str | None
    web_search_mode: str | None
    managed_mcp_server_names: tuple[str, ...]
    unexpected_mcp_server_count: int
    pre_tool_hook_sha256: tuple[str, ...]
    requirements: CodexRequirementProjection | None
    security_origins: tuple[tuple[str, str], ...]

    def canonical(self) -> dict[str, object]:
        """Return deterministic allowlisted data used only for hashing."""
        return {
            "hostVersion": self.host_version,
            "platform": self.platform,
            "approvalPolicy": self.approval_policy,
            "sandboxMode": self.sandbox_mode,
            "defaultPermissions": self.default_permissions,
            "webSearchMode": self.web_search_mode,
            "managedMcpServerNames": list(self.managed_mcp_server_names),
            "unexpectedMcpServerCount": self.unexpected_mcp_server_count,
            "preToolHookSha256": list(self.pre_tool_hook_sha256),
            "requirements": None if self.requirements is None else self.requirements.to_wire(),
            "securityOrigins": dict(self.security_origins),
        }


class CodexAppServerEffectiveControlProbe:
    """Launch a pinned Codex app-server and reconcile its effective controls.

    Args:
        executable: Absolute Codex executable path selected by deployment code.
        executable_sha256: Approved release digest for the complete executable.
        timeout_seconds: Total read deadline from 1 through 30 seconds.

    Side effects:
        Starts one local Codex app-server process without a shell, reads its
        effective configuration, and terminates it. No MCP status request is
        sent because that could initialize external servers.

    Raises:
        SecurityConfigurationError: If inputs, binary integrity, protocol, or
            response bounds are invalid. Errors never contain host response
            content.
    """

    def __init__(
        self,
        *,
        executable: str,
        executable_sha256: str,
        timeout_seconds: float = 8.0,
    ) -> None:
        """Validate immutable probe inputs without starting a process."""
        self._executable = _validate_executable(executable, executable_sha256)
        self._executable_sha256 = executable_sha256
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 1 <= timeout_seconds <= 30
        ):
            raise SecurityConfigurationError("Codex probe timeout must be 1 to 30 seconds")
        self._timeout_seconds = float(timeout_seconds)

    def inspect(
        self,
        bundle: ManagedConfigurationBundle,
        *,
        project_root: str,
        now: int | None = None,
        ttl_seconds: int = 120,
    ) -> CodexEffectiveControlEvidence:
        """Return live deny-first evidence for one compiled Codex bundle.

        The project root selects the same layered configuration that the target
        Codex session would read. It must be an existing absolute directory.
        Evidence expires after 30 through 300 seconds and must be re-read before
        later security decisions.
        """
        _validate_bundle(bundle)
        root = Path(project_root)
        if not root.is_absolute() or not root.is_dir():
            raise SecurityConfigurationError("Codex project root must be an absolute directory")
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 30 <= ttl_seconds <= 300
        ):
            raise SecurityConfigurationError("Codex evidence TTL must be 30 to 300 seconds")
        observed_at = int(time.time()) if now is None else now
        if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
            raise SecurityConfigurationError("Codex evidence time is invalid")

        responses = self._read_app_server(str(root))
        observed = _project_responses(
            responses, _expected_mcp_names(bundle), expected_platform=bundle.platform
        )
        return _reconcile(bundle, observed, observed_at, ttl_seconds)

    def _read_app_server(self, project_root: str) -> Mapping[str, object]:
        """Perform the bounded JSONL handshake and return correlated results."""
        # Re-measure at the last practical point before launch. The OS and local
        # administrator remain trust anchors, but a binary changed after probe
        # construction must not inherit the earlier approval measurement.
        executable = _validate_executable(str(self._executable), self._executable_sha256)
        try:
            process = subprocess.Popen(  # noqa: S603 - exact pinned executable, no shell.
                [str(executable), "app-server"],
                cwd=project_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            raise SecurityConfigurationError("Codex app-server could not be started") from None
        try:
            if process.stdin is None or process.stdout is None:
                raise SecurityConfigurationError("Codex app-server pipes are unavailable")
            requests = (
                {
                    "method": "initialize",
                    "id": "aai-initialize",
                    "params": {
                        "clientInfo": {"name": "aai-sec-effective-controls", "version": "1"},
                        "capabilities": {},
                    },
                },
                {"method": "initialized", "params": {}},
                {
                    "method": "config/read",
                    "id": "aai-config",
                    "params": {"cwd": project_root, "includeLayers": True},
                },
                {
                    "method": "configRequirements/read",
                    "id": "aai-requirements",
                    "params": {},
                },
            )
            for request in requests:
                process.stdin.write(_canonical_json(request) + b"\n")
            process.stdin.flush()
            return _receive_responses(process, self._timeout_seconds)
        except (BrokenPipeError, OSError):
            raise SecurityConfigurationError("Codex app-server protocol failed") from None
        finally:
            _stop_process(process)


def _receive_responses(
    process: subprocess.Popen[bytes], timeout_seconds: float
) -> Mapping[str, object]:
    """Read bounded lines on a worker so pipe behavior is portable."""
    output = process.stdout
    if output is None:
        raise SecurityConfigurationError("Codex app-server output pipe is unavailable")
    messages: queue.Queue[bytes | None] = queue.Queue(maxsize=_MAX_MESSAGES + 1)

    def read_lines() -> None:
        """Read at most one bounded protocol line per queue entry."""
        try:
            while True:
                line = output.readline(_MAX_LINE_BYTES + 1)
                messages.put(line if line else None)
                if not line:
                    return
        except (OSError, ValueError):
            try:
                messages.put_nowait(None)
            except queue.Full:
                return

    threading.Thread(target=read_lines, daemon=True).start()
    deadline = time.monotonic() + timeout_seconds
    results: dict[str, object] = {}
    total_bytes = 0
    message_count = 0
    while set(results) != _REQUEST_IDS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecurityConfigurationError("Codex app-server response timed out")
        try:
            line = messages.get(timeout=remaining)
        except queue.Empty:
            raise SecurityConfigurationError("Codex app-server response timed out") from None
        if line is None:
            raise SecurityConfigurationError("Codex app-server closed before responding")
        message_count += 1
        total_bytes += len(line)
        if (
            len(line) > _MAX_LINE_BYTES
            or total_bytes > _MAX_TOTAL_BYTES
            or message_count > _MAX_MESSAGES
        ):
            raise SecurityConfigurationError("Codex app-server response exceeded safe bounds")
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SecurityConfigurationError("Codex app-server returned malformed JSON") from None
        if not isinstance(message, dict):
            raise SecurityConfigurationError("Codex app-server returned an invalid message")
        request_id = message.get("id")
        if request_id not in _REQUEST_IDS:
            continue
        if request_id in results:
            raise SecurityConfigurationError("Codex app-server returned a duplicate response")
        if "error" in message or not isinstance(message.get("result"), dict):
            # Never surface a raw server error: it is an untrusted secret-bearing field.
            raise SecurityConfigurationError("Codex app-server rejected a configuration request")
        results[request_id] = message["result"]
    return results


def _project_responses(
    responses: Mapping[str, object],
    expected_mcp_names: tuple[str, ...],
    *,
    expected_platform: ManagedPlatform,
) -> _ObservedProjection:
    """Discard raw responses after constructing an allowlisted projection."""
    initialize = _object(responses.get("aai-initialize"), "initialization result")
    config_result = _object(responses.get("aai-config"), "configuration result")
    requirements_result = _object(responses.get("aai-requirements"), "requirements result")
    config = _object(config_result.get("config"), "effective configuration")
    host_version = _host_version(initialize.get("userAgent"))
    platform = _platform_name(initialize.get("platformFamily"), expected_platform)
    approval = _optional_mode(config.get("approval_policy"), "approval policy")
    sandbox = _optional_mode(config.get("sandbox_mode"), "sandbox mode")
    default_permissions = _optional_enum(config.get("default_permissions"), "default permissions")
    web_search = _optional_enum(config.get("web_search"), "web search mode")

    mcp = config.get("mcp_servers")
    if mcp is None:
        mcp_object: Mapping[str, object] = {}
    else:
        mcp_object = _object(mcp, "MCP inventory")
    if len(mcp_object) > _MAX_ITEMS:
        raise SecurityConfigurationError("Codex MCP inventory exceeded safe bounds")
    configured_expected = tuple(sorted(name for name in expected_mcp_names if name in mcp_object))
    unexpected_count = len(set(mcp_object) - set(expected_mcp_names))

    hook_digests = _hook_digests(config.get("hooks"))
    origins = _security_origins(config_result.get("origins"))
    raw_requirements = requirements_result.get("requirements")
    requirements = (
        None
        if raw_requirements is None
        else _project_requirements(_object(raw_requirements, "administrator requirements"))
    )
    return _ObservedProjection(
        host_version=host_version,
        platform=platform,
        approval_policy=approval,
        sandbox_mode=sandbox,
        default_permissions=default_permissions,
        web_search_mode=web_search,
        managed_mcp_server_names=configured_expected,
        unexpected_mcp_server_count=unexpected_count,
        pre_tool_hook_sha256=hook_digests,
        requirements=requirements,
        security_origins=origins,
    )


def _project_requirements(value: Mapping[str, object]) -> CodexRequirementProjection:
    """Project only supported primitive requirement decisions."""
    network_raw = value.get("network")
    network = {} if network_raw is None else _object(network_raw, "network requirements")
    domain_raw = network.get("domains")
    if domain_raw is None and network.get("allowedDomains") is not None:
        allowed = _string_tuple(network.get("allowedDomains"), "allowed network domains")
        domains = tuple((domain, "allow") for domain in allowed)
    else:
        domains = _enum_map(domain_raw, "network domains", {"allow", "deny"})
    return CodexRequirementProjection(
        allowed_approval_policies=_mode_tuple(
            value.get("allowedApprovalPolicies"), "allowed approval policies"
        ),
        default_permissions=_optional_enum(
            value.get("defaultPermissions"), "required default permissions"
        ),
        allowed_permission_profiles=_bool_map(
            value.get("allowedPermissionProfiles"), "allowed permission profiles"
        ),
        allowed_sandbox_modes=_mode_tuple(
            value.get("allowedSandboxModes"), "allowed sandbox modes"
        ),
        allowed_web_search_modes=_string_tuple(
            value.get("allowedWebSearchModes"), "allowed web-search modes"
        ),
        allow_managed_hooks_only=_optional_bool(
            value.get("allowManagedHooksOnly"), "managed-hooks-only requirement"
        ),
        feature_requirements=_bool_map(value.get("featureRequirements"), "feature requirements"),
        network_enabled=_optional_bool(network.get("enabled"), "network enabled requirement"),
        network_managed_domains_only=_optional_bool(
            network.get("managedAllowedDomainsOnly"), "managed network domains requirement"
        ),
        network_domains=domains,
    )


def _reconcile(
    bundle: ManagedConfigurationBundle,
    observed: _ObservedProjection,
    now: int,
    ttl_seconds: int,
) -> CodexEffectiveControlEvidence:
    """Compare observed process state with the deterministic expected projection."""
    expected = _expected_requirements(bundle)
    expected_digest = _digest(expected.to_wire())
    observed_digest = _digest(observed.canonical())
    mismatches: list[str] = []
    gaps: list[str] = []
    if observed.requirements is None:
        state = EnforcementState.MISSING
        reason = "administrator-requirements-missing"
    else:
        if observed.host_version != bundle.host_version:
            mismatches.append("host-version")
        _compare_requirements(expected, observed.requirements, mismatches)
        if observed.approval_policy not in expected.allowed_approval_policies:
            mismatches.append("effective-approval-policy")
        if (
            expected.allowed_sandbox_modes
            and observed.sandbox_mode not in expected.allowed_sandbox_modes
        ):
            mismatches.append("effective-sandbox-mode")
        if observed.default_permissions != expected.default_permissions:
            mismatches.append("effective-default-permissions")
        expected_hook = _expected_hook_digest(bundle)
        if expected_hook not in observed.pre_tool_hook_sha256:
            mismatches.append("managed-pre-tool-hook")
        intent = _requirements_toml(bundle)
        if intent.get("mcp_servers"):
            gaps.append("mcp-runtime-status")
        if intent.get("rules"):
            gaps.append("command-rule-runtime-match")
        permissions = intent.get("permissions")
        if isinstance(permissions, dict) and permissions.get("filesystem"):
            gaps.append("deny-read-runtime-match")
        if mismatches:
            state = EnforcementState.CONFLICT
            reason = "effective-controls-differ"
        elif gaps:
            state = EnforcementState.DEPLOYMENT_REQUIRED
            reason = "effective-controls-partially-observable"
        else:
            state = EnforcementState.ENFORCED
            reason = "effective-controls-match"
    if state is EnforcementState.ENFORCED:
        allowed = bundle.allowed_actions
        denied = bundle.denied_actions
        approval = bundle.approval_required_actions
    else:
        allowed = ()
        denied = tuple(
            sorted(
                set(bundle.allowed_actions)
                | set(bundle.denied_actions)
                | set(bundle.approval_required_actions)
            )
        )
        approval = ()
    return CodexEffectiveControlEvidence(
        host_version=observed.host_version,
        platform=observed.platform,
        state=state,
        reason=reason,
        expected_digest=expected_digest,
        observed_digest=observed_digest,
        approval_policy=observed.approval_policy,
        sandbox_mode=observed.sandbox_mode,
        default_permissions=observed.default_permissions,
        web_search_mode=observed.web_search_mode,
        managed_mcp_server_names=observed.managed_mcp_server_names,
        unexpected_mcp_server_count=observed.unexpected_mcp_server_count,
        pre_tool_hook_sha256=observed.pre_tool_hook_sha256,
        requirement_projection=observed.requirements,
        security_origins=observed.security_origins,
        mismatches=tuple(sorted(set(mismatches))),
        unverified_controls=tuple(sorted(set(gaps))),
        allowed_actions=allowed,
        denied_actions=denied,
        approval_required_actions=approval,
        verified_at=now,
        expires_at=now + ttl_seconds,
    )


def _expected_requirements(bundle: ManagedConfigurationBundle) -> CodexRequirementProjection:
    """Derive comparable app-server requirements from the compiled TOML."""
    value = _requirements_toml(bundle)
    network_value = value.get("experimental_network")
    network = network_value if isinstance(network_value, dict) else {}
    domains = network.get("domains")
    if isinstance(domains, dict):
        network_domains = tuple(
            sorted((str(key), str(decision)) for key, decision in domains.items())
        )
    else:
        allowed = _string_tuple(network.get("allowed_domains"), "expected network domains")
        network_domains = tuple((domain, "allow") for domain in allowed)
    return CodexRequirementProjection(
        allowed_approval_policies=_mode_tuple(
            value.get("allowed_approval_policies"), "expected approval policies"
        ),
        default_permissions=_optional_enum(
            value.get("default_permissions"), "expected default permissions"
        ),
        allowed_permission_profiles=_bool_map(
            value.get("allowed_permission_profiles"), "expected permission profiles"
        ),
        allowed_sandbox_modes=_mode_tuple(
            value.get("allowed_sandbox_modes"), "expected sandbox modes"
        ),
        allowed_web_search_modes=_string_tuple(
            value.get("allowed_web_search_modes"), "expected web-search modes"
        ),
        allow_managed_hooks_only=_optional_bool(
            value.get("allow_managed_hooks_only"), "expected managed-hooks-only"
        ),
        feature_requirements=_bool_map(value.get("features"), "expected features"),
        network_enabled=_optional_bool(network.get("enabled"), "expected network enabled"),
        network_managed_domains_only=_optional_bool(
            network.get("managed_allowed_domains_only"), "expected managed network domains"
        ),
        network_domains=network_domains,
    )


def _compare_requirements(
    expected: CodexRequirementProjection,
    observed: CodexRequirementProjection,
    mismatches: list[str],
) -> None:
    """Append fixed field identifiers for every observable mismatch."""
    checks = (
        (
            "allowed-approval-policies",
            expected.allowed_approval_policies,
            observed.allowed_approval_policies,
        ),
        ("default-permissions", expected.default_permissions, observed.default_permissions),
        (
            "allowed-permission-profiles",
            expected.allowed_permission_profiles,
            observed.allowed_permission_profiles,
        ),
        ("allowed-sandbox-modes", expected.allowed_sandbox_modes, observed.allowed_sandbox_modes),
        (
            "allowed-web-search-modes",
            expected.allowed_web_search_modes,
            observed.allowed_web_search_modes,
        ),
        (
            "managed-hooks-only",
            expected.allow_managed_hooks_only,
            observed.allow_managed_hooks_only,
        ),
        ("feature-requirements", expected.feature_requirements, observed.feature_requirements),
        ("network-enabled", expected.network_enabled, observed.network_enabled),
        (
            "managed-network-domains-only",
            expected.network_managed_domains_only,
            observed.network_managed_domains_only,
        ),
        ("network-domains", expected.network_domains, observed.network_domains),
    )
    mismatches.extend(name for name, wanted, actual in checks if wanted != actual)


def _requirements_toml(bundle: ManagedConfigurationBundle) -> dict[str, object]:
    """Parse the sole expected Codex requirements artifact."""
    if len(bundle.artifacts) != 1 or bundle.artifacts[0].media_type != "application/toml":
        raise SecurityConfigurationError("Codex bundle must contain one TOML requirement artifact")
    try:
        value = tomllib.loads(bundle.artifacts[0].content)
    except tomllib.TOMLDecodeError:
        raise SecurityConfigurationError("Codex bundle requirements are malformed") from None
    return value


def _expected_mcp_names(bundle: ManagedConfigurationBundle) -> tuple[str, ...]:
    """Return policy-owned MCP names without endpoint definitions."""
    value = _requirements_toml(bundle).get("mcp_servers", {})
    if not isinstance(value, dict):
        raise SecurityConfigurationError("Codex MCP requirements are malformed")
    return tuple(sorted(value))


def _expected_hook_digest(bundle: ManagedConfigurationBundle) -> str:
    """Hash the expected managed command without exporting its content."""
    value = _requirements_toml(bundle)
    try:
        command = value["hooks"]["PreToolUse"][0]["hooks"][0]["command"]  # type: ignore[index]
    except (KeyError, IndexError, TypeError):
        raise SecurityConfigurationError("Codex managed hook requirement is missing") from None
    if not isinstance(command, str):
        raise SecurityConfigurationError("Codex managed hook command is malformed")
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _hook_digests(value: object) -> tuple[str, ...]:
    """Project command hook bodies to SHA-256 without retaining command text."""
    if value is None:
        return ()
    hooks = _object(value, "effective hooks")
    groups = hooks.get("PreToolUse", [])
    if not isinstance(groups, list) or len(groups) > _MAX_ITEMS:
        raise SecurityConfigurationError("Codex PreToolUse hooks are malformed")
    digests: set[str] = set()
    for group in groups:
        group_value = _object(group, "PreToolUse hook group")
        handlers = group_value.get("hooks", [])
        if not isinstance(handlers, list) or len(handlers) > _MAX_ITEMS:
            raise SecurityConfigurationError("Codex PreToolUse hook handlers are malformed")
        for handler in handlers:
            handler_value = _object(handler, "PreToolUse hook handler")
            if handler_value.get("type") == "command":
                command = handler_value.get("command")
                if not isinstance(command, str):
                    raise SecurityConfigurationError("Codex command hook is malformed")
                digests.add(hashlib.sha256(command.encode("utf-8")).hexdigest())
    return tuple(sorted(digests))


def _security_origins(value: object) -> tuple[tuple[str, str], ...]:
    """Return source categories for fixed security keys, never source paths."""
    if value is None:
        return ()
    origins = _object(value, "configuration origins")
    result: list[tuple[str, str]] = []
    for key in _SECURITY_ORIGINS:
        metadata = origins.get(key)
        if metadata is None:
            continue
        name = _object(_object(metadata, "origin metadata").get("name"), "origin source")
        source_type = name.get("type")
        if not isinstance(source_type, str) or source_type not in _SOURCE_TYPES:
            raise SecurityConfigurationError("Codex security origin is malformed")
        result.append((key, source_type))
    return tuple(result)


def _validate_executable(executable: str, expected_sha256: str) -> Path:
    """Verify a regular non-writable executable against approved release bytes."""
    path = Path(executable)
    if not path.is_absolute() or len(expected_sha256) != _SHA256_LENGTH:
        raise SecurityConfigurationError("Codex executable path or digest is invalid")
    try:
        int(expected_sha256, 16)
    except ValueError:
        raise SecurityConfigurationError("Codex executable path or digest is invalid") from None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as binary:
            metadata = os.fstat(binary.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                raise SecurityConfigurationError("Codex executable permissions are unsafe")
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
    except OSError:
        raise SecurityConfigurationError("Codex executable cannot be verified") from None
    if digest != expected_sha256:
        raise SecurityConfigurationError("Codex executable digest does not match release metadata")
    if not os.access(path, os.X_OK):
        raise SecurityConfigurationError("Codex executable is not executable")
    return path


def _validate_bundle(bundle: ManagedConfigurationBundle) -> None:
    """Require a typed Codex bundle for the endpoint's current platform."""
    if not isinstance(bundle, ManagedConfigurationBundle) or bundle.host is not AgentHost.CODEX_CLI:
        raise SecurityConfigurationError("effective-control inspection requires a Codex bundle")
    platform = {"posix": {"darwin": ManagedPlatform.MACOS, "linux": ManagedPlatform.LINUX}}
    expected: ManagedPlatform | None
    if os.name == "nt":
        expected = ManagedPlatform.WINDOWS
    else:
        expected = platform["posix"].get(host_platform.system().lower())
    if expected is None or bundle.platform is not expected:
        raise SecurityConfigurationError("Codex bundle does not match the current platform")


def _host_version(value: object) -> str:
    """Extract a bounded semantic version from the app-server user agent."""
    text = _enum_text(value, "Codex user agent", 256)
    match = re.search(r"(?<![0-9])(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)", text)
    if match is not None:
        return match.group(1)
    raise SecurityConfigurationError("Codex app-server version is unavailable")


def _platform_name(value: object, expected: ManagedPlatform) -> str:
    """Bind the app-server platform family to the compiled host platform."""
    family = _enum_text(value, "platform family", 64).lower()
    compatible = {
        ManagedPlatform.MACOS: {"macos", "darwin", "unix"},
        ManagedPlatform.LINUX: {"linux", "unix"},
        ManagedPlatform.WINDOWS: {"windows"},
    }
    if family not in compatible[expected]:
        raise SecurityConfigurationError("Codex app-server platform differs from the bundle")
    return expected.value


def _object(value: object, label: str) -> Mapping[str, object]:
    """Require one bounded JSON object without echoing its content."""
    if not isinstance(value, dict) or len(value) > _MAX_ITEMS:
        raise SecurityConfigurationError(f"Codex {label} is malformed")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    """Project a bounded list of enum-like strings."""
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise SecurityConfigurationError(f"Codex {label} are malformed")
    return tuple(sorted(_enum_text(item, label, 128) for item in value))


def _optional_enum(value: object, label: str) -> str | None:
    """Project a nullable enum-like string."""
    return None if value is None else _enum_text(value, label, 128)


def _optional_mode(value: object, label: str) -> str | None:
    """Normalize documented app-server camelCase and config-file mode names."""
    return None if value is None else _normalize_mode(_enum_text(value, label, 128))


def _mode_tuple(value: object, label: str) -> tuple[str, ...]:
    """Project and normalize a bounded list of security modes."""
    return tuple(sorted(_normalize_mode(item) for item in _string_tuple(value, label)))


def _normalize_mode(value: str) -> str:
    """Map documented app-server spellings to canonical config spellings."""
    return {
        "onRequest": "on-request",
        "unlessTrusted": "untrusted",
        "readOnly": "read-only",
        "workspaceWrite": "workspace-write",
        "dangerFullAccess": "danger-full-access",
    }.get(value, value)


def _enum_text(value: object, label: str, maximum: int) -> str:
    """Reject empty, oversized, or control-character enum text."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise SecurityConfigurationError(f"Codex {label} is malformed")
    return value


def _optional_bool(value: object, label: str) -> bool | None:
    """Project a nullable strict boolean."""
    if value is None:
        return None
    if not isinstance(value, bool):
        raise SecurityConfigurationError(f"Codex {label} is malformed")
    return value


def _bool_map(value: object, label: str) -> tuple[tuple[str, bool], ...]:
    """Project a bounded named boolean map."""
    if value is None:
        return ()
    values = _object(value, label)
    result: list[tuple[str, bool]] = []
    for key, decision in values.items():
        name = _enum_text(key, label, 128)
        if not isinstance(decision, bool):
            raise SecurityConfigurationError(f"Codex {label} are malformed")
        result.append((name, decision))
    return tuple(sorted(result))


def _enum_map(value: object, label: str, choices: set[str]) -> tuple[tuple[str, str], ...]:
    """Project a bounded map whose decisions come from a fixed enum."""
    if value is None:
        return ()
    values = _object(value, label)
    result: list[tuple[str, str]] = []
    for key, decision in values.items():
        name = _enum_text(key, label, 253)
        if not isinstance(decision, str) or decision not in choices:
            raise SecurityConfigurationError(f"Codex {label} are malformed")
        result.append((name, decision))
    return tuple(sorted(result))


def _coded_tuple(value: object, label: str, choices: set[str]) -> tuple[str, ...]:
    """Project a bounded list whose values come from a fixed code set."""
    result = _string_tuple(value, label)
    if any(item not in choices for item in result):
        raise SecurityConfigurationError(f"Codex evidence {label} are unsupported")
    return result


def _sha256(value: object, label: str) -> str:
    """Require one lowercase SHA-256 string."""
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH:
        raise SecurityConfigurationError(f"Codex {label} is invalid")
    try:
        int(value, 16)
    except ValueError:
        raise SecurityConfigurationError(f"Codex {label} is invalid") from None
    if value != value.lower():
        raise SecurityConfigurationError(f"Codex {label} is invalid")
    return value


def _timestamp(value: object, label: str) -> int:
    """Require one non-negative whole-second evidence timestamp."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SecurityConfigurationError(f"Codex evidence {label} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    """Encode deterministic protocol and digest input."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> str:
    """Return SHA-256 of one content-minimised canonical projection."""
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate the bounded helper without surfacing process output."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return


__all__ = [
    "CodexAppServerEffectiveControlProbe",
    "CodexEffectiveControlEvidence",
    "CodexRequirementProjection",
    "codex_effective_control_evidence_from_wire",
]

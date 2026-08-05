"""Explain static conflicts between SDK policy and native agent controls.

This module performs no endpoint discovery and grants no authority.  It compares
the exact, already composed policy that the control plane intends to activate.
The resulting report is safe to show to operators, but staging and activation
must recompute it from authoritative policy content instead of trusting a
browser-supplied result.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

NativeControlSeverity = Literal["blocking", "warning"]
NativeControlStatus = Literal["clear", "warning", "blocked"]

_HOSTS = ("claude-code", "codex-cli")
_COMMAND_FIELDS = (
    "allowedCommandPatterns",
    "approvalCommandPatterns",
    "deniedCommandPatterns",
)


class NativeControlAnalysisError(ValueError):
    """Report malformed policy input at the static-analysis trust boundary."""


@dataclass(frozen=True, slots=True)
class NativeControlConflict:
    """One content-minimised conflict with fixed operator remediation guidance."""

    code: str
    severity: NativeControlSeverity
    host: str
    field: str
    related_fields: tuple[str, ...]
    summary: str
    resolution: str

    def to_dict(self) -> dict[str, Any]:
        """Return the stable camel-case control-plane representation."""
        return {
            "code": self.code,
            "severity": self.severity,
            "host": self.host,
            "field": self.field,
            "relatedFields": list(self.related_fields),
            "summary": self.summary,
            "resolution": self.resolution,
        }


@dataclass(frozen=True, slots=True)
class NativeControlAnalysis:
    """Static compatibility result bound to one exact policy configuration."""

    configuration_sha256: str
    status: NativeControlStatus
    blocking_count: int
    warning_count: int
    evaluated_hosts: tuple[str, ...]
    conflicts: tuple[NativeControlConflict, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a secret-free result suitable for policy review APIs."""
        return {
            "schemaVersion": 1,
            "configurationSha256": self.configuration_sha256,
            "status": self.status,
            "blockingCount": self.blocking_count,
            "warningCount": self.warning_count,
            "evaluatedHosts": list(self.evaluated_hosts),
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "endpointVerification": "required-after-activation",
        }


def analyze_native_control_conflicts(
    configuration: Mapping[str, Any],
) -> NativeControlAnalysis:
    """Compare SDK and native controls without treating analysis as authority.

    The analysis intentionally reports configuration structure, never command
    expressions, paths, credentials, or resource values.  A managed-host target
    narrows the report; otherwise both currently supported hosts are evaluated.
    Live endpoint state is outside this static boundary and must be proven by
    post-activation convergence evidence.
    """
    if not isinstance(configuration, Mapping):
        raise NativeControlAnalysisError("configuration must be an object")
    try:
        canonical = json.dumps(
            dict(configuration), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise NativeControlAnalysisError("configuration must contain JSON values") from error
    if len(canonical) > 1_000_000:
        raise NativeControlAnalysisError("configuration exceeds the analysis limit")

    native = _object(configuration.get("claudeCode"), "claudeCode")
    sdk_tools = _object(configuration.get("tools"), "tools")
    managed_host = _object(configuration.get("managedHost"), "managedHost")
    target = managed_host.get("host")
    if target is not None and target not in _HOSTS:
        raise NativeControlAnalysisError("managedHost.host is unsupported")
    hosts = (target,) if isinstance(target, str) else _HOSTS
    conflicts: list[NativeControlConflict] = []

    pattern_fields: dict[str, tuple[str, ...]] = {
        field: _text_list(native.get(field), f"claudeCode.{field}") for field in _COMMAND_FIELDS
    }
    # Compare exact expressions without returning their content. Regex overlap is
    # undecidable in general; exact duplication is deterministic and bypass-safe.
    for left_index, left in enumerate(_COMMAND_FIELDS):
        for right in _COMMAND_FIELDS[left_index + 1 :]:
            duplicate_count = len(set(pattern_fields[left]) & set(pattern_fields[right]))
            for _ in range(duplicate_count):
                conflicts.extend(
                    _conflict(
                        "command-decision-conflict",
                        "blocking",
                        hosts,
                        f"claudeCode.{left}",
                        (f"claudeCode.{right}",),
                        "A command rule has more than one policy decision.",
                        "Keep the command expression in exactly one allow, approval, or deny list.",
                    )
                )

    native_tools = _optional_set(native, "allowedBuiltInTools", "claudeCode")
    sdk_built_ins = _optional_set(sdk_tools, "builtIn", "tools")
    if native_tools is not None and sdk_built_ins is not None:
        for _ in sorted(native_tools - sdk_built_ins):
            conflicts.extend(
                _conflict(
                    "native-authority-exceeds-sdk",
                    "blocking",
                    hosts,
                    "claudeCode.allowedBuiltInTools",
                    ("tools.builtIn",),
                    "A native tool is permitted outside the SDK built-in tool boundary.",
                    "Remove the native permission or add the tool to the reviewed SDK boundary.",
                )
            )
        for _ in sorted(sdk_built_ins - native_tools):
            conflicts.extend(
                _conflict(
                    "sdk-tool-unavailable-natively",
                    "warning",
                    hosts,
                    "tools.builtIn",
                    ("claudeCode.allowedBuiltInTools",),
                    "An SDK-permitted built-in tool is unavailable in native controls.",
                    "Align the native allow-list or remove the unused SDK permission.",
                )
            )

    native_files = _optional_set(native, "fileTools", "claudeCode")
    sdk_files = _optional_set(sdk_tools, "fileTools", "tools")
    if native_files is not None and sdk_files is not None:
        for _ in sorted(native_files - sdk_files):
            conflicts.extend(
                _conflict(
                    "native-file-authority-exceeds-sdk",
                    "blocking",
                    hosts,
                    "claudeCode.fileTools",
                    ("tools.fileTools",),
                    "A native file tool is outside the SDK file-tool boundary.",
                    "Remove the native file tool or add it to the reviewed SDK file-tool boundary.",
                )
            )
        for _ in sorted(sdk_files - native_files):
            conflicts.extend(
                _conflict(
                    "sdk-file-tool-unavailable-natively",
                    "warning",
                    hosts,
                    "tools.fileTools",
                    ("claudeCode.fileTools",),
                    "An SDK file tool is unavailable in native controls.",
                    "Align the native file-tool list or remove the unused SDK permission.",
                )
            )

    if native_tools is not None and native_files is not None:
        for _ in sorted(native_files - native_tools):
            conflicts.extend(
                _conflict(
                    "inactive-native-file-rule",
                    "warning",
                    hosts,
                    "claudeCode.fileTools",
                    ("claudeCode.allowedBuiltInTools",),
                    "A file-tool rule targets a native tool that is not allowed.",
                    "Allow the built-in tool or remove its inactive file-tool rule.",
                )
            )

    configured_native_controls = any(
        value not in (None, [], {}) for key, value in native.items() if key != "enabled"
    )
    if native.get("enabled") is False and configured_native_controls:
        conflicts.extend(
            _conflict(
                "native-controls-disabled",
                "blocking",
                hosts,
                "claudeCode.enabled",
                tuple(f"claudeCode.{field}" for field in sorted(native) if field != "enabled"),
                "Native controls are disabled while native permissions or rules are configured.",
                "Enable native controls or remove the native configuration before activation.",
            )
        )

    flattened = tuple(
        sorted(
            conflicts,
            key=lambda item: (item.severity != "blocking", item.code, item.host, item.field),
        )
    )
    blocking = sum(item.severity == "blocking" for item in flattened)
    warnings = len(flattened) - blocking
    status: NativeControlStatus = "blocked" if blocking else "warning" if warnings else "clear"
    return NativeControlAnalysis(
        configuration_sha256=hashlib.sha256(canonical).hexdigest(),
        status=status,
        blocking_count=blocking,
        warning_count=warnings,
        evaluated_hosts=tuple(hosts),
        conflicts=flattened,
    )


def _object(value: object, name: str) -> Mapping[str, Any]:
    """Return an optional object or reject an ambiguous shape."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise NativeControlAnalysisError(f"{name} must be an object")
    return value


def _text_list(value: object, name: str) -> tuple[str, ...]:
    """Read a bounded text list while retaining duplicates for schema parity."""
    if value is None:
        return ()
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or len(value) > 100
        or any(not isinstance(item, str) or not item or len(item) > 1_000 for item in value)
    ):
        raise NativeControlAnalysisError(f"{name} must be a bounded text list")
    return tuple(value)


def _optional_set(section: Mapping[str, Any], field: str, prefix: str) -> set[str] | None:
    """Distinguish an omitted control from an explicitly empty boundary."""
    if field not in section:
        return None
    return set(_text_list(section[field], f"{prefix}.{field}"))


def _conflict(
    code: str,
    severity: NativeControlSeverity,
    hosts: tuple[str, ...],
    field: str,
    related_fields: tuple[str, ...],
    summary: str,
    resolution: str,
) -> tuple[NativeControlConflict, ...]:
    """Create one fixed-content finding without duplicating shared controls."""
    finding_hosts = ("shared",) if hosts == _HOSTS else hosts
    return tuple(
        NativeControlConflict(
            code=code,
            severity=severity,
            host=host,
            field=field,
            related_fields=related_fields,
            summary=summary,
            resolution=resolution,
        )
        for host in finding_hosts
    )

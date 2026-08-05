"""Deterministically compose reusable policy fragments without widening authority.

The module is provider-neutral and side-effect free. It accepts already
authenticated, schema-validated policy fragments and applies code-owned merge
rules. Unknown fields never receive implicit last-writer-wins behavior.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

# Generated deployment support; edit the SDK source and rerun the generator.
class SecurityConfigurationError(ValueError):
    """Standalone Lambda configuration failure base class."""


class _FrozenMapping(Mapping[Any, Any]):
    """Minimal read-only mapping used by generated Lambda evidence."""

    def __init__(self, values: Mapping[Any, Any]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: Any) -> Any:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return NotImplemented


class _FrozenList(tuple[Any, ...]):
    """Tuple-backed immutable representation of a JSON list."""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (list, tuple)):
            return tuple(self) == tuple(other)
        return NotImplemented


def freeze_value(value: Any) -> Any:
    """Recursively freeze JSON data without importing the complete SDK."""
    if isinstance(value, Mapping):
        return _FrozenMapping({key: freeze_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return _FrozenList(freeze_value(item) for item in value)
    return value

PolicyMergeRule = Literal[
    "allow_intersection",
    "deny_union",
    "approval_union",
    "minimum",
    "safeguard_or",
    "optional_and",
    "exact",
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOW_INTERSECTION = frozenset(
    {
        "policy.allowedPrincipals",
        "tools.allowed",
        "tools.builtIn",
        "tools.fileTools",
        "credentials.scopes",
        "runtime.allowedTools",
        "runtime.allowedPrincipals",
        "claudeCode.allowedBuiltInTools",
        "claudeCode.allowedCommandPatterns",
        "claudeCode.fileTools",
        "claudeCode.allowedSkills",
        "claudeCode.allowedMcpServers",
        "isolation.acceptedProfiles",
    }
)
_DENY_UNION = frozenset({"tools.denied", "claudeCode.deniedCommandPatterns"})
_APPROVAL_UNION = frozenset({"approvals.requiredFor", "claudeCode.approvalCommandPatterns"})
_MINIMUM = frozenset(
    {
        "approvals.ttlSeconds",
        "budgets.maxActions",
        "budgets.maxConcurrent",
        "budgets.maxFanOut",
        "budgets.maxCostUnits",
        "budgets.maxDelegationDepth",
        "budgets.maxActionsPerSecond",
        "budgets.executionTimeoutSeconds",
        "budgets.maxTimedOutWorkers",
        "runtime.maxActions",
        "runtime.maxConcurrent",
        "runtime.maxFanOut",
        "runtime.maxCostUnits",
        "runtime.maxDelegationDepth",
        "runtime.maxActionsPerSecond",
        "runtime.executionTimeoutSeconds",
        "runtime.maxTimedOutWorkers",
        "runtime.idempotencyTtlSeconds",
        "runtime.approvalTtlSeconds",
    }
)
_SAFEGUARD_OR = frozenset(
    {
        "policy.denyByDefault",
        "credentials.enabled",
        "isolation.requiredForHighRisk",
        "audit.redactSensitiveData",
        "telemetry.redactSensitiveData",
        "runtime.credentialsEnabled",
        "runtime.isolationRequiredForHighRisk",
        "runtime.redactSensitiveData",
    }
)
_OPTIONAL_AND = frozenset(
    {
        "audit.captureToolContent",
        "telemetry.enabled",
        "telemetry.captureToolContent",
        "runtime.telemetryEnabled",
        "runtime.captureToolContent",
        "claudeCode.enabled",
    }
)
_MANDATORY_TRUE = frozenset(
    {
        "policy.denyByDefault",
        "audit.redactSensitiveData",
        "telemetry.redactSensitiveData",
        "runtime.redactSensitiveData",
    }
)
_TYPED_SECTIONS = frozenset(
    {
        "policy",
        "approvals",
        "tools",
        "budgets",
        "credentials",
        "isolation",
        "audit",
        "telemetry",
        "runtime",
        "claudeCode",
        "managedHost",
    }
)


class PolicyCompositionError(SecurityConfigurationError):
    """Report policy fragments that cannot be composed without ambiguity."""


@dataclass(frozen=True, slots=True)
class PolicyComponent:
    """One exact immutable governed policy version used as a component."""

    policy_id: str
    version: int
    content_hash: str
    configuration: Mapping[str, Any]
    graph_digest: str | None = None

    def __post_init__(self) -> None:
        """Reject ambiguous component identities before composition."""
        if (
            not isinstance(self.policy_id, str)
            or not self.policy_id.strip()
            or len(self.policy_id) > 256
        ):
            raise PolicyCompositionError("component policy ID is invalid")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version <= 0:
            raise PolicyCompositionError("component version must be a positive integer")
        if not isinstance(self.content_hash, str) or not _SHA256.fullmatch(self.content_hash):
            raise PolicyCompositionError("component content hash is invalid")
        if self.graph_digest is not None and (
            not isinstance(self.graph_digest, str) or not _SHA256.fullmatch(self.graph_digest)
        ):
            raise PolicyCompositionError("component graph digest is invalid")
        if not isinstance(self.configuration, Mapping):
            raise PolicyCompositionError("component configuration must be an object")
        object.__setattr__(self, "configuration", _freeze_json(self.configuration))

    @property
    def identity(self) -> str:
        """Return the stable human-readable component source identity."""
        return f"{self.policy_id}@{self.version}#{self.content_hash}"


@dataclass(frozen=True, slots=True)
class PolicyCompositionStep:
    """Explain how one effective field was constrained by its sources."""

    field: str
    rule: PolicyMergeRule
    sources: tuple[str, ...]
    effective: Any
    removed: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Freeze nested effective evidence retained by the explanation."""
        object.__setattr__(self, "effective", _freeze_json(self.effective))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe explanation projection for API and UI use."""
        return {
            "field": self.field,
            "rule": self.rule,
            "sources": list(self.sources),
            "effective": _copy_json(self.effective),
            "removed": list(self.removed),
        }


@dataclass(frozen=True, slots=True)
class PolicyCompositionResult:
    """The effective policy plus deterministic, content-bound explanation."""

    configuration: Mapping[str, Any]
    graph_digest: str
    explanation: tuple[PolicyCompositionStep, ...]

    def __post_init__(self) -> None:
        """Freeze the effective policy so review evidence cannot be mutated."""
        object.__setattr__(self, "configuration", _freeze_json(self.configuration))

    def to_dict(self) -> dict[str, Any]:
        """Return a defensive JSON-safe result for persistence or transport."""
        return {
            "configuration": _copy_json(self.configuration),
            "graphDigest": self.graph_digest,
            "explanation": [step.to_dict() for step in self.explanation],
        }


def _copy_json(value: Any, *, depth: int = 0) -> Any:
    """Normalize bounded JSON data while rejecting duplicate and opaque values."""
    if depth > 8:
        raise PolicyCompositionError("policy composition nesting exceeds eight levels")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 256 or key in result:
                raise PolicyCompositionError("policy composition object key is invalid")
            result[key] = _copy_json(child, depth=depth + 1)
        return result
    if isinstance(value, list | tuple):
        if len(value) > 10_000:
            raise PolicyCompositionError("policy composition list exceeds its bound")
        return [_copy_json(child, depth=depth + 1) for child in value]
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise PolicyCompositionError("policy composition contains unsupported data")


def _freeze_json(value: Any) -> Any:
    """Return a recursively immutable defensive JSON representation."""
    return freeze_value(_copy_json(value))


def _rule(path: str) -> PolicyMergeRule:
    """Return the code-owned merge rule for one exact field path."""
    if path in _ALLOW_INTERSECTION:
        return "allow_intersection"
    if path in _DENY_UNION:
        return "deny_union"
    if path in _APPROVAL_UNION:
        return "approval_union"
    if path in _MINIMUM:
        return "minimum"
    if path in _SAFEGUARD_OR:
        return "safeguard_or"
    if path in _OPTIONAL_AND:
        return "optional_and"
    return "exact"


def _string_set(value: Any, path: str) -> set[str]:
    """Return one duplicate-free bounded list as a semantic string set."""
    if (
        not isinstance(value, list)
        or len(value) > 1_000
        or not all(isinstance(item, str) and item and len(item) <= 1_024 for item in value)
        or len(set(value)) != len(value)
    ):
        raise PolicyCompositionError(f"{path} must be a duplicate-free bounded string list")
    return set(value)


def _merge_scalar(
    current: Any, incoming: Any, path: str, rule: PolicyMergeRule
) -> tuple[Any, set[str]]:
    """Merge one field according to its restrictive semantic rule."""
    removed: set[str] = set()
    if rule in {"allow_intersection", "deny_union", "approval_union"}:
        left, right = _string_set(current, path), _string_set(incoming, path)
        if rule == "allow_intersection":
            effective = left & right
            removed = (left | right) - effective
        else:
            effective = left | right
        return sorted(effective), removed
    if rule == "minimum":
        if (
            isinstance(current, bool)
            or isinstance(incoming, bool)
            or not isinstance(current, int | float)
            or not isinstance(incoming, int | float)
            or not math.isfinite(float(current))
            or not math.isfinite(float(incoming))
            or current < 0
            or incoming < 0
        ):
            raise PolicyCompositionError(f"{path} must contain non-negative finite limits")
        return min(current, incoming), removed
    if rule in {"safeguard_or", "optional_and"}:
        if not isinstance(current, bool) or not isinstance(incoming, bool):
            raise PolicyCompositionError(f"{path} must contain booleans")
        return (current or incoming) if rule == "safeguard_or" else (current and incoming), removed
    if current != incoming:
        raise PolicyCompositionError(f"{path} has conflicting exact values")
    return current, removed


def _flatten(value: Mapping[str, Any], *, prefix: str = "") -> dict[str, Any]:
    """Flatten typed leaves while keeping legacy extension sections exact."""
    result: dict[str, Any] = {}
    for key in sorted(value):
        child = value[key]
        path = f"{prefix}.{key}" if prefix else key
        if not prefix and key not in _TYPED_SECTIONS:
            result[path] = child
        elif isinstance(child, Mapping) and child:
            result.update(_flatten(child, prefix=path))
        elif not isinstance(child, Mapping):
            result[path] = child
    return result


def _inflate(values: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild a nested object from validated non-overlapping field paths."""
    result: dict[str, Any] = {}
    for path in sorted(values):
        target = result
        parts = path.split(".")
        for part in parts[:-1]:
            child = target.setdefault(part, {})
            if not isinstance(child, dict):
                raise PolicyCompositionError("policy composition path is ambiguous")
            target = child
        target[parts[-1]] = _copy_json(values[path])
    return result


def compose_policy(
    components: Sequence[PolicyComponent],
    local_configuration: Mapping[str, Any],
) -> PolicyCompositionResult:
    """Compose exact components and local intent into one restrictive policy.

    Components are processed in the supplied display order, but no rule uses
    last-writer-wins semantics. Missing fields mean “no opinion”. The local
    policy is the final source and is constrained by the same rules.
    """
    if len(components) > 8:
        raise PolicyCompositionError("a policy may reference at most eight components")
    identities = [component.identity for component in components]
    if len(set(identities)) != len(identities):
        raise PolicyCompositionError("component references must be unique")
    sources: list[tuple[str, Mapping[str, Any]]] = [
        (component.identity, component.configuration) for component in components
    ]
    sources.append(("local", local_configuration))
    effective: dict[str, Any] = {}
    field_sources: dict[str, list[str]] = {}
    field_rules: dict[str, PolicyMergeRule] = {}
    removed: dict[str, set[str]] = {}
    for source, raw in sources:
        normalized = _copy_json(raw)
        if not isinstance(normalized, dict):
            raise PolicyCompositionError("policy source must be an object")
        for path, incoming in _flatten(normalized).items():
            rule = _rule(path)
            if path in _MANDATORY_TRUE and incoming is not True:
                raise PolicyCompositionError(f"{path} cannot disable an immutable safeguard")
            if path not in effective:
                # Validate first opinions too; otherwise a malformed single
                # component could avoid type checks performed during merge.
                if rule in {"allow_intersection", "deny_union", "approval_union"}:
                    incoming = sorted(_string_set(incoming, path))
                elif rule == "minimum":
                    incoming, _ = _merge_scalar(incoming, incoming, path, rule)
                elif rule in {"safeguard_or", "optional_and"} and not isinstance(incoming, bool):
                    raise PolicyCompositionError(f"{path} must contain booleans")
                effective[path] = incoming
                field_sources[path] = [source]
                field_rules[path] = rule
                removed[path] = set()
                continue
            if field_rules[path] != rule:
                raise PolicyCompositionError(f"{path} merge rule changed unexpectedly")
            effective[path], newly_removed = _merge_scalar(effective[path], incoming, path, rule)
            field_sources[path].append(source)
            removed[path].update(newly_removed)
    configuration = _inflate(effective)
    explanation = tuple(
        PolicyCompositionStep(
            field=path,
            rule=field_rules[path],
            sources=tuple(field_sources[path]),
            effective=_copy_json(effective[path]),
            removed=tuple(sorted(removed[path])),
        )
        for path in sorted(effective)
    )
    graph = {
        "schemaVersion": 1,
        "components": [
            {
                "policyId": component.policy_id,
                "version": component.version,
                "contentHash": component.content_hash,
                "graphDigest": component.graph_digest,
            }
            for component in components
        ],
        "localConfiguration": _copy_json(local_configuration),
        "configuration": configuration,
    }
    encoded = json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > 1_048_576:
        raise PolicyCompositionError("composed policy exceeds 1 MiB")
    return PolicyCompositionResult(
        configuration=configuration,
        graph_digest=hashlib.sha256(encoded).hexdigest(),
        explanation=explanation,
    )

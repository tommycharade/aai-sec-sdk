"""Explicit tool definitions and registry management."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from .errors import DuplicateToolError, SecurityConfigurationError
from .types import ExecutionContext, Resource, RiskLevel

ArgumentValidator: TypeAlias = Callable[[Mapping[str, Any]], Any]
"""Callable that validates and normalizes untrusted tool arguments."""

ToolHandler: TypeAlias = Callable[[ExecutionContext, Any], Any]
"""Callable that executes a validated action using application-owned context."""


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Security contract for one callable tool.

    ``resources`` extracts target resources from validated arguments. Keeping
    this declaration beside the handler lets policy evaluate live targets,
    rather than authorizing a vague tool name.
    """

    name: str
    handler: ToolHandler
    validator: ArgumentValidator
    risk: RiskLevel = RiskLevel.LOW
    resources: Callable[[Any], tuple[Resource, ...]] = field(default=lambda _: ())
    requires_approval: bool = False
    idempotency_required: bool = False
    external_egress: bool = False
    requires_credential: bool = False
    credential_ttl_seconds: int = 120
    description: str = ""

    def __post_init__(self) -> None:
        """Reject tool contracts that make safe mediation ambiguous."""
        if not self.name or self.name.strip() != self.name:
            raise SecurityConfigurationError("tool names must be non-empty and trimmed")
        if not self.description:
            raise SecurityConfigurationError(f"tool {self.name!r} requires a description")
        if self.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL} and not self.requires_approval:
            raise SecurityConfigurationError(
                f"high-impact tool {self.name!r} must require approval"
            )
        if self.requires_credential and self.credential_ttl_seconds <= 0:
            raise SecurityConfigurationError(
                f"credential TTL for tool {self.name!r} must be positive"
            )


class ToolRegistry:
    """Explicit allow-list of tools available to a guarded runtime."""

    def __init__(self) -> None:
        """Create an empty registry; dynamic lookup is intentionally unsupported."""
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register ``tool`` or raise if its name is already present."""
        if tool.name in self._tools:
            raise DuplicateToolError(f"tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition | None:
        """Return a registered tool, or ``None`` for an unknown proposal."""
        return self._tools.get(name)

    def names(self) -> frozenset[str]:
        """Return the immutable set of registered tool names."""
        return frozenset(self._tools)

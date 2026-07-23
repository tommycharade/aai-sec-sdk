"""Deterministic policy interfaces and a useful local allow-list policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .tools import ToolDefinition
from .types import ExecutionContext, Resource


class PolicyDecision(StrEnum):
    """Possible outcomes from the policy enforcement point."""

    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Policy outcome with a safe, model-visible reason."""

    decision: PolicyDecision
    reason: str


class PolicyEngine(Protocol):
    """Protocol for local or external policy decision points."""

    def decide(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        arguments: object,
        resources: tuple[Resource, ...],
    ) -> PolicyResult:
        """Decide whether this exact action may proceed."""


class AllowListPolicy:
    """Deny-by-default policy for a declared set of tools and principals."""

    def __init__(
        self,
        allowed_tools: set[str] | frozenset[str],
        allowed_principals: set[str] | frozenset[str] | None = None,
    ) -> None:
        """Create a policy with explicit tool and optional principal allow-lists."""
        self._allowed_tools = frozenset(allowed_tools)
        self._allowed_principals = (
            frozenset(allowed_principals) if allowed_principals is not None else None
        )

    def decide(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        arguments: object,
        resources: tuple[Resource, ...],
    ) -> PolicyResult:
        """Allow only explicitly declared tools and authenticated principals."""
        del arguments
        if tool.name not in self._allowed_tools:
            return PolicyResult(PolicyDecision.DENY, "tool is not allowed for this task")
        if (
            self._allowed_principals is not None
            and context.principal.id not in self._allowed_principals
        ):
            return PolicyResult(PolicyDecision.DENY, "principal is not allowed for this task")
        if context.tenant is not None and context.principal.tenant not in {None, context.tenant}:
            return PolicyResult(PolicyDecision.DENY, "principal tenant does not match task tenant")
        if context.tenant is not None and any(
            resource.tenant not in {None, context.tenant} for resource in resources
        ):
            return PolicyResult(PolicyDecision.DENY, "resource is outside the task tenant")
        if tool.requires_approval:
            return PolicyResult(PolicyDecision.APPROVAL_REQUIRED, "explicit approval is required")
        return PolicyResult(PolicyDecision.ALLOW, "tool and principal are allow-listed")

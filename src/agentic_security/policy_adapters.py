"""Provider-neutral adapters for external policy decision points.

The adapters translate the SDK's canonical action context into a serializable
request. They intentionally accept an injected evaluator instead of owning an
HTTP client, authentication, retries, or endpoint discovery. Those concerns
belong to the deployment-specific adapter around this module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .policies import PolicyDecision, PolicyResult
from .tools import ToolDefinition
from .types import ExecutionContext, Resource


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Canonical, serializable input for an external policy decision."""

    agent_id: str
    principal_id: str
    principal_kind: str
    principal_tenant: str | None
    task_id: str
    purpose: str
    tenant: str | None
    environment: str
    tool_name: str
    arguments: Mapping[str, Any]
    resources: tuple[Resource, ...]

    @classmethod
    def from_action(
        cls,
        context: ExecutionContext,
        tool: ToolDefinition,
        arguments: object,
        resources: tuple[Resource, ...],
    ) -> PolicyRequest:
        """Build a request from the same live values used by the runtime."""
        if not isinstance(arguments, Mapping):
            raise TypeError("external policy requests require mapping arguments")
        return cls(
            context.agent_id,
            context.principal.id,
            context.principal.kind,
            context.principal.tenant,
            context.task_id,
            context.purpose,
            context.tenant,
            context.environment,
            tool.name,
            dict(arguments),
            resources,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-shaped request with explicit resource fields."""
        value = asdict(self)
        value["resources"] = [asdict(resource) for resource in self.resources]
        return value


Evaluator = Callable[[Mapping[str, Any]], Mapping[str, Any]]
"""Injected external policy evaluator contract."""


def _decision(value: Any) -> PolicyDecision | None:
    """Map supported decision spellings without treating unknown values as allow."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace("-", "_")
    return {
        "allow": PolicyDecision.ALLOW,
        "allowed": PolicyDecision.ALLOW,
        "permit": PolicyDecision.ALLOW,
        "permitted": PolicyDecision.ALLOW,
        "deny": PolicyDecision.DENY,
        "denied": PolicyDecision.DENY,
        "forbid": PolicyDecision.DENY,
        "approval_required": PolicyDecision.APPROVAL_REQUIRED,
        "approval": PolicyDecision.APPROVAL_REQUIRED,
    }.get(normalized)


def _map_decision(result: Mapping[str, Any], default_reason: str) -> PolicyResult:
    """Convert an explicit external response to a fail-closed SDK result."""
    decision = _decision(result.get("decision"))
    if decision is None and result.get("allow") is True:
        decision = PolicyDecision.ALLOW
    if decision is None and result.get("allow") is False:
        decision = PolicyDecision.DENY
    if decision is None:
        return PolicyResult(PolicyDecision.DENY, "external policy returned an invalid decision")
    reason = result.get("reason")
    return PolicyResult(decision, reason if isinstance(reason, str) and reason else default_reason)


class OpaPolicyEngine:
    """Policy engine for an evaluator shaped like an OPA JSON query client.

    The evaluator receives ``{"input": <canonical policy request>}`` and must
    return a mapping containing an OPA-like ``result`` object. Both the common
    ``{"allow": true}`` shape and the explicit SDK decision shape are accepted.
    """

    def __init__(self, evaluator: Evaluator) -> None:
        """Create an OPA adapter around an injected, authenticated evaluator."""
        self.evaluator = evaluator

    def decide(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        arguments: object,
        resources: tuple[Resource, ...],
    ) -> PolicyResult:
        """Evaluate the live action and deny on transport or response failure."""
        try:
            request = PolicyRequest.from_action(context, tool, arguments, resources)
            response = self.evaluator({"input": request.to_dict()})
            result = response.get("result")
            if not isinstance(result, Mapping):
                return PolicyResult(PolicyDecision.DENY, "OPA returned no valid result")
            return _map_decision(result, "OPA policy allowed this action")
        except Exception:
            return PolicyResult(PolicyDecision.DENY, "OPA policy evaluation failed")


class CedarPolicyEngine:
    """Policy engine for a Cedar-style authorization evaluator.

    The evaluator receives the canonical policy request directly and must
    return an explicit ``decision`` value such as ``Allow`` or ``Deny``.
    Ambiguous or missing decisions are denied.
    """

    def __init__(self, evaluator: Evaluator) -> None:
        """Create a Cedar adapter around an injected, authenticated evaluator."""
        self.evaluator = evaluator

    def decide(
        self,
        context: ExecutionContext,
        tool: ToolDefinition,
        arguments: object,
        resources: tuple[Resource, ...],
    ) -> PolicyResult:
        """Evaluate the live action and deny on transport or response failure."""
        try:
            request = PolicyRequest.from_action(context, tool, arguments, resources)
            response = self.evaluator(request.to_dict())
            return _map_decision(response, "Cedar policy allowed this action")
        except Exception:
            return PolicyResult(PolicyDecision.DENY, "Cedar policy evaluation failed")

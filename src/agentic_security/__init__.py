"""Agent execution-security primitives.

The package deliberately mediates actions rather than attempting to make model
output trustworthy. The public entry point is :class:`GuardedRuntime`.
"""

from .approvals import ApprovalGrant, ApprovalProvider, InMemoryApprovalProvider
from .audit import AuditEvent, InMemoryAuditSink
from .budgets import Budget
from .credentials import CredentialBroker, InMemoryCredentialBroker, ScopedCredential
from .errors import DuplicateToolError, RuntimeStateError, SecurityConfigurationError
from .policies import AllowListPolicy, PolicyDecision, PolicyEngine, PolicyResult
from .policy_adapters import CedarPolicyEngine, OpaPolicyEngine, PolicyRequest
from .runtime import GuardedRuntime, RuntimeConfig
from .telemetry import CompositeAuditSink, OpenTelemetryAuditSink
from .tools import ToolDefinition, ToolRegistry
from .types import (
    ActionProposal,
    ExecutionContext,
    ExecutionResult,
    Principal,
    Resource,
    RiskLevel,
)

__all__ = [
    "ActionProposal",
    "ApprovalGrant",
    "ApprovalProvider",
    "AllowListPolicy",
    "AuditEvent",
    "CompositeAuditSink",
    "CredentialBroker",
    "Budget",
    "CedarPolicyEngine",
    "DuplicateToolError",
    "ExecutionContext",
    "ExecutionResult",
    "GuardedRuntime",
    "InMemoryApprovalProvider",
    "InMemoryAuditSink",
    "InMemoryCredentialBroker",
    "OpenTelemetryAuditSink",
    "OpaPolicyEngine",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyResult",
    "PolicyRequest",
    "Principal",
    "Resource",
    "RiskLevel",
    "RuntimeConfig",
    "RuntimeStateError",
    "ScopedCredential",
    "SecurityConfigurationError",
    "ToolDefinition",
    "ToolRegistry",
]

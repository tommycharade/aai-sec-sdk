"""Agent execution-security primitives.

The package deliberately mediates actions rather than attempting to make model
output trustworthy. The public entry point is :class:`GuardedRuntime`.
"""

from .adapters import (
    HttpApprovalProvider,
    HttpCedarPolicyEngine,
    HttpOpaPolicyEngine,
    JsonlAuditSink,
    SubprocessToolHandler,
)
from .approvals import ApprovalGrant, ApprovalProvider, InMemoryApprovalProvider, action_hash
from .audit import AuditEvent, InMemoryAuditSink
from .budgets import Budget
from .credentials import (
    CredentialBroker,
    CredentialMetadata,
    InMemoryCredentialBroker,
    ScopedCredential,
    TokenCredentialBroker,
)
from .errors import (
    DuplicateToolError,
    RuntimeCancelledError,
    RuntimeOperationTimeoutError,
    RuntimeStateError,
    SecurityConfigurationError,
)
from .policies import AllowListPolicy, PolicyDecision, PolicyEngine, PolicyResult
from .policy_adapters import CedarPolicyEngine, OpaPolicyEngine, PolicyRequest
from .runtime import GuardedRuntime, RuntimeConfig
from .telemetry import CompositeAuditSink, OpenTelemetryAuditSink
from .tools import OutputValidator, ReconciliationHandler, ToolDefinition, ToolRegistry
from .types import (
    ActionProposal,
    CancellationToken,
    ExecutionContext,
    ExecutionResult,
    ExecutionStatus,
    Principal,
    Resource,
    RiskLevel,
)

__all__ = [
    "ActionProposal",
    "CancellationToken",
    "ApprovalGrant",
    "ApprovalProvider",
    "action_hash",
    "AllowListPolicy",
    "AuditEvent",
    "CompositeAuditSink",
    "CredentialBroker",
    "CredentialMetadata",
    "Budget",
    "CedarPolicyEngine",
    "DuplicateToolError",
    "ExecutionContext",
    "ExecutionResult",
    "ExecutionStatus",
    "GuardedRuntime",
    "HttpApprovalProvider",
    "HttpCedarPolicyEngine",
    "HttpOpaPolicyEngine",
    "InMemoryApprovalProvider",
    "InMemoryAuditSink",
    "InMemoryCredentialBroker",
    "JsonlAuditSink",
    "OpenTelemetryAuditSink",
    "OutputValidator",
    "ReconciliationHandler",
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
    "RuntimeCancelledError",
    "RuntimeOperationTimeoutError",
    "ScopedCredential",
    "SubprocessToolHandler",
    "TokenCredentialBroker",
    "SecurityConfigurationError",
    "ToolDefinition",
    "ToolRegistry",
]

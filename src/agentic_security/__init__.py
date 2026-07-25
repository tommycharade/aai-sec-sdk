"""Agent execution-security primitives.

The package deliberately mediates actions rather than attempting to make model
output trustworthy. The public entry point is :class:`GuardedRuntime`.
"""

from .adapters import (
    HttpApprovalProvider,
    HttpAuditExporter,
    HttpCedarPolicyEngine,
    HttpOpaPolicyEngine,
    JsonlAuditSink,
    SubprocessToolHandler,
)
from .approvals import ApprovalGrant, ApprovalProvider, InMemoryApprovalProvider, action_hash
from .audit import (
    AuditEvent,
    AuditExporter,
    AuditReplicationError,
    InMemoryAuditExporter,
    InMemoryAuditSink,
    ReplicatedAuditSink,
)
from .budgets import Budget
from .credentials import (
    CredentialBroker,
    CredentialMetadata,
    InMemoryCredentialBroker,
    ProviderToken,
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
from .idempotency import (
    IdempotencyClaim,
    IdempotencyClaimStatus,
    IdempotencyGCReport,
    IdempotencyRecord,
    IdempotencyState,
    IdempotencyStore,
    InMemoryIdempotencyStore,
)
from .isolation import (
    CallbackIsolationVerifier,
    IsolationAttestation,
    IsolationVerifier,
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
    ReconciliationResult,
    ReconciliationState,
    Resource,
    RiskLevel,
    SideEffectState,
    TimeoutPhase,
)

__all__ = [
    "ActionProposal",
    "CancellationToken",
    "ApprovalGrant",
    "ApprovalProvider",
    "action_hash",
    "AllowListPolicy",
    "AuditEvent",
    "AuditExporter",
    "AuditReplicationError",
    "InMemoryAuditExporter",
    "ReplicatedAuditSink",
    "CompositeAuditSink",
    "CredentialBroker",
    "CredentialMetadata",
    "Budget",
    "IdempotencyClaim",
    "IdempotencyClaimStatus",
    "IdempotencyGCReport",
    "IdempotencyRecord",
    "IdempotencyState",
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "IsolationAttestation",
    "IsolationVerifier",
    "CallbackIsolationVerifier",
    "CedarPolicyEngine",
    "DuplicateToolError",
    "ExecutionContext",
    "ExecutionResult",
    "ExecutionStatus",
    "SideEffectState",
    "TimeoutPhase",
    "GuardedRuntime",
    "HttpApprovalProvider",
    "HttpAuditExporter",
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
    "ReconciliationResult",
    "ReconciliationState",
    "RuntimeConfig",
    "RuntimeStateError",
    "RuntimeCancelledError",
    "RuntimeOperationTimeoutError",
    "ScopedCredential",
    "SubprocessToolHandler",
    "TokenCredentialBroker",
    "ProviderToken",
    "SecurityConfigurationError",
    "ToolDefinition",
    "ToolRegistry",
]

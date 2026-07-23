"""The fail-closed action mediation runtime."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from threading import RLock
from typing import Any

from .approvals import ApprovalProvider, action_hash
from .audit import AuditSink
from .budgets import Budget, BudgetState
from .credentials import CredentialBroker
from .policies import PolicyDecision, PolicyEngine
from .tools import ToolRegistry
from .types import ActionProposal, ExecutionContext, ExecutionResult, ExecutionStatus, Resource


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Runtime-wide safety settings."""

    budget: Budget = Budget()


class GuardedRuntime:
    """Execute only actions that pass every configured security control.

    The runtime accepts a proposal, but the application-owned context supplies
    identity and purpose. A handler is called only after explicit registry,
    validation, policy, approval, budget, idempotency, and kill-switch checks.
    """

    def __init__(
        self,
        context: ExecutionContext,
        registry: ToolRegistry,
        policy: PolicyEngine,
        audit: AuditSink,
        approvals: ApprovalProvider | None = None,
        config: RuntimeConfig | None = None,
        credentials: CredentialBroker | None = None,
    ) -> None:
        """Create a runtime with all required security dependencies explicit."""
        self.context = context
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.config = config or RuntimeConfig()
        self.credentials = credentials
        self._budget = BudgetState(self.config.budget)
        self._stopped = False
        self._stop_lock = RLock()
        self._completed: dict[str, ExecutionResult] = {}
        # A re-entrant lock makes the check-and-execute sequence atomic for
        # idempotent tools. This is intentionally conservative: a later
        # adapter can provide per-key locks without weakening the invariant.
        self._idempotency_lock = RLock()

    def stop(self) -> None:
        """Activate the emergency stop; future actions fail closed."""
        with self._stop_lock:
            self._stopped = True

    def is_stopped(self) -> bool:
        """Return whether the emergency stop is active."""
        with self._stop_lock:
            return self._stopped

    def execute(self, proposal: ActionProposal) -> ExecutionResult:
        """Mediate and, if allowed, execute one untrusted action proposal."""
        tool = self.registry.get(proposal.tool_name)
        guard = (
            self._idempotency_lock
            if tool is not None and tool.idempotency_required
            else nullcontext()
        )
        with guard:
            return self._execute_unlocked(proposal)

    def _execute_unlocked(self, proposal: ActionProposal) -> ExecutionResult:
        """Run one proposal while the caller owns any required idempotency lock."""
        request_id = str(uuid.uuid4())
        tool = self.registry.get(proposal.tool_name)
        if tool is None:
            reason = "unknown tool" if isinstance(proposal.tool_name, str) else "malformed tool"
            return self._deny(request_id, proposal, reason)
        if self.is_stopped():
            return self._deny(request_id, proposal, "runtime emergency stop is active")
        if not self._budget.acquire():
            return self._deny(
                request_id, proposal, "task budget exhausted or concurrency limit reached"
            )
        try:
            try:
                arguments = tool.validator(proposal.arguments)
            except Exception:
                return self._deny(request_id, proposal, "invalid tool arguments")
            try:
                resources = tool.resources(arguments)
                if not isinstance(resources, tuple) or not all(
                    isinstance(resource, Resource) for resource in resources
                ):
                    raise TypeError("resources must be a tuple of Resource objects")
            except Exception:
                return self._deny(request_id, proposal, "invalid action resource")
            try:
                policy_result = self.policy.decide(self.context, tool, arguments, resources)
            except Exception:
                return self._deny(request_id, proposal, "policy evaluation failed")
            try:
                fingerprint = action_hash(self.context, tool.name, arguments, resources)
            except Exception:
                return self._deny(request_id, proposal, "action could not be fingerprinted")
            idempotency_key = f"{tool.name}:{proposal.proposal_id}:{fingerprint}"
            if tool.idempotency_required:
                with self._idempotency_lock:
                    prior = self._completed.get(idempotency_key)
                    if prior is not None:
                        return prior
            if policy_result.decision is PolicyDecision.DENY:
                return self._deny(
                    request_id,
                    proposal,
                    policy_result.reason,
                    {
                        "resources": [asdict(resource) for resource in resources],
                        "policy_decision": policy_result.decision.value,
                    },
                )
            if policy_result.decision is PolicyDecision.APPROVAL_REQUIRED:
                if self.approvals is None or proposal.approval_id is None:
                    return self._approval_required(request_id, proposal, policy_result.reason)
                try:
                    approved = self.approvals.consume(
                        proposal.approval_id,
                        self.context,
                        tool.name,
                        proposal.proposal_id,
                        fingerprint,
                    )
                except Exception:
                    approved = False
                if not approved:
                    return self._deny(
                        request_id, proposal, "approval missing, expired, or out of scope"
                    )
            handler_context = self.context
            if tool.requires_credential:
                if self.credentials is None:
                    return self._deny(request_id, proposal, "credential broker is not configured")
                try:
                    credential = self.credentials.mint(
                        self.context,
                        tool,
                        resources,
                        tool.credential_ttl_seconds,
                    )
                    if not credential.valid_for(tool.name, resources):
                        return self._deny(request_id, proposal, "credential scope is invalid")
                except Exception:
                    return self._deny(request_id, proposal, "credential broker failed")
                handler_context = replace(self.context, credential=credential)
            output = tool.handler(handler_context, arguments)
            result = ExecutionResult(ExecutionStatus.EXECUTED, tool.name, request_id, output=output)
            self._record(
                "action_executed",
                request_id,
                proposal,
                {
                    "status": result.status,
                    "resources": [asdict(resource) for resource in resources],
                    "policy_decision": policy_result.decision.value,
                },
            )
            if tool.idempotency_required:
                with self._idempotency_lock:
                    self._completed[idempotency_key] = result
            return result
        except Exception as exc:  # pragma: no cover - exercised by integration tests
            self._record("action_failed", request_id, proposal, {"error_type": type(exc).__name__})
            return ExecutionResult(
                ExecutionStatus.FAILED, tool.name, request_id, reason="tool execution failed"
            )
        finally:
            self._budget.release()

    def _deny(
        self,
        request_id: str,
        proposal: ActionProposal,
        reason: str,
        details: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        """Record and return a safe denial without executing a handler."""
        self._record("action_denied", request_id, proposal, {"reason": reason, **(details or {})})
        tool_name = proposal.tool_name if isinstance(proposal.tool_name, str) else "<invalid>"
        return ExecutionResult(ExecutionStatus.DENIED, tool_name, request_id, reason=reason)

    def _approval_required(
        self, request_id: str, proposal: ActionProposal, reason: str
    ) -> ExecutionResult:
        """Record a non-executing approval request."""
        self._record("approval_required", request_id, proposal, {"reason": reason})
        tool_name = proposal.tool_name if isinstance(proposal.tool_name, str) else "<invalid>"
        return ExecutionResult(
            ExecutionStatus.APPROVAL_REQUIRED,
            tool_name,
            request_id,
            reason=reason,
            approval_id=proposal.approval_id,
        )

    def _record(
        self, event_type: str, request_id: str, proposal: ActionProposal, payload: Mapping[str, Any]
    ) -> None:
        """Write a redaction-aware audit event with no raw model transcript."""
        if isinstance(proposal.arguments, Mapping):
            try:
                safe_arguments: object = dict(proposal.arguments)
            except Exception:
                safe_arguments = {"[invalid_arguments]": type(proposal.arguments).__name__}
        else:
            safe_arguments = {"[invalid_arguments_type]": type(proposal.arguments).__name__}
        self.audit.append(
            event_type,
            request_id,
            {
                "agent_id": self.context.agent_id,
                "principal_id": self.context.principal.id,
                "task_id": self.context.task_id,
                "purpose": self.context.purpose,
                "tool_name": proposal.tool_name,
                "proposal_id": proposal.proposal_id,
                "arguments": safe_arguments,
                **dict(payload),
            },
        )

"""The fail-closed action mediation runtime."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any

from .approvals import ApprovalProvider
from .audit import AuditSink
from .budgets import Budget, BudgetState
from .credentials import CredentialBroker
from .policies import PolicyDecision, PolicyEngine
from .tools import ToolRegistry
from .types import ActionProposal, ExecutionContext, ExecutionResult


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
            return self._deny(request_id, proposal, "unknown tool")
        if self.is_stopped():
            return self._deny(request_id, proposal, "runtime emergency stop is active")
        if tool.idempotency_required:
            with self._idempotency_lock:
                prior = self._completed.get(proposal.proposal_id)
                if prior is not None:
                    return prior
        if not self._budget.acquire():
            return self._deny(
                request_id, proposal, "task budget exhausted or concurrency limit reached"
            )
        try:
            try:
                arguments = tool.validator(proposal.arguments)
            except (TypeError, ValueError, KeyError) as exc:
                return self._deny(request_id, proposal, f"invalid tool arguments: {exc}")
            try:
                resources = tool.resources(arguments)
            except (TypeError, ValueError, KeyError) as exc:
                return self._deny(request_id, proposal, f"invalid action resource: {exc}")
            policy_result = self.policy.decide(self.context, tool, arguments, resources)
            if policy_result.decision is PolicyDecision.DENY:
                return self._deny(request_id, proposal, policy_result.reason)
            if policy_result.decision is PolicyDecision.APPROVAL_REQUIRED:
                if self.approvals is None or proposal.approval_id is None:
                    return self._approval_required(request_id, proposal, policy_result.reason)
                if not self.approvals.consume(
                    proposal.approval_id, self.context, tool.name, proposal.proposal_id
                ):
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
            result = ExecutionResult("executed", tool.name, request_id, output=output)
            self._record("action_executed", request_id, proposal, {"status": result.status})
            if tool.idempotency_required:
                with self._idempotency_lock:
                    self._completed[proposal.proposal_id] = result
            return result
        except Exception as exc:  # pragma: no cover - exercised by integration tests
            self._record("action_failed", request_id, proposal, {"error_type": type(exc).__name__})
            return ExecutionResult("failed", tool.name, request_id, reason="tool execution failed")
        finally:
            self._budget.release()

    def _deny(self, request_id: str, proposal: ActionProposal, reason: str) -> ExecutionResult:
        """Record and return a safe denial without executing a handler."""
        self._record("action_denied", request_id, proposal, {"reason": reason})
        return ExecutionResult("denied", proposal.tool_name, request_id, reason=reason)

    def _approval_required(
        self, request_id: str, proposal: ActionProposal, reason: str
    ) -> ExecutionResult:
        """Record a non-executing approval request."""
        self._record("approval_required", request_id, proposal, {"reason": reason})
        return ExecutionResult(
            "approval_required",
            proposal.tool_name,
            request_id,
            reason=reason,
            approval_id=proposal.approval_id,
        )

    def _record(
        self, event_type: str, request_id: str, proposal: ActionProposal, payload: Mapping[str, Any]
    ) -> None:
        """Write a redaction-aware audit event with no raw model transcript."""
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
                "arguments": dict(proposal.arguments),
                **dict(payload),
            },
        )

"""The fail-closed action mediation runtime."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as HandlerTimeoutError
from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from threading import RLock
from typing import Any

from .approvals import ApprovalProvider, action_hash
from .audit import AuditSink, redact
from .budgets import Budget, BudgetState
from .credentials import CredentialBroker
from .errors import RuntimeCancelledError, SecurityConfigurationError
from .policies import PolicyDecision, PolicyEngine, PolicyResult
from .tools import ToolRegistry
from .types import (
    ActionProposal,
    CancellationToken,
    ExecutionContext,
    ExecutionResult,
    ExecutionStatus,
    Resource,
)


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Runtime-wide safety settings."""

    budget: Budget = Budget()
    execution_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject an unbounded or non-positive handler wait configuration."""
        if self.execution_timeout_seconds <= 0:
            raise SecurityConfigurationError("execution timeout must be positive")


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
        self._active_tokens: dict[str, CancellationToken] = {}
        # A re-entrant lock makes the check-and-execute sequence atomic for
        # idempotent tools. This is intentionally conservative: a later
        # adapter can provide per-key locks without weakening the invariant.
        self._idempotency_lock = RLock()

    def stop(self) -> None:
        """Activate the emergency stop and request cooperative cancellation."""
        with self._stop_lock:
            self._stopped = True
            for token in self._active_tokens.values():
                token.cancel()

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
        idempotency_key: str | None = None
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
        cancellation = CancellationToken()
        budget_release_deferred = False
        with self._stop_lock:
            if self._stopped:
                self._budget.release()
                return self._deny(request_id, proposal, "runtime emergency stop is active")
            self._active_tokens[request_id] = cancellation
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
            if not isinstance(policy_result, PolicyResult) or not isinstance(
                policy_result.decision, PolicyDecision
            ):
                return self._deny(request_id, proposal, "policy returned an invalid decision")
            try:
                fingerprint = action_hash(self.context, tool.name, arguments, resources)
            except Exception:
                return self._deny(request_id, proposal, "action could not be fingerprinted")
            idempotency_key = f"{tool.name}:{proposal.proposal_id}:{fingerprint}"
            if tool.idempotency_required and idempotency_key is not None:
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
                        "policy_version": policy_result.policy_version,
                        "policy_provenance": policy_result.provenance,
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
            handler_context = replace(self.context, cancellation=cancellation)
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
                handler_context = replace(handler_context, credential=credential)
            output = self._run_handler(
                tool.handler,
                handler_context,
                arguments,
                cancellation,
                self._budget.release,
            )
            try:
                normalized_output = (
                    tool.output_validator(output) if tool.output_validator is not None else output
                )
                safe_output = redact(normalized_output)
                encoded_output = json.dumps(
                    safe_output, sort_keys=True, separators=(",", ":")
                ).encode()
                if len(encoded_output) > tool.max_output_bytes:
                    raise ValueError("tool output exceeds configured size limit")
            except Exception as exc:
                result = ExecutionResult(
                    ExecutionStatus.EXECUTED_RESULT_REJECTED,
                    tool.name,
                    request_id,
                    reason=f"side effect executed but result was rejected: {type(exc).__name__}",
                )
                recorded = self._record(
                    "action_result_rejected",
                    request_id,
                    proposal,
                    {"error_type": type(exc).__name__},
                )
                if not recorded:
                    result = replace(result, audit_recorded=False)
                if tool.idempotency_required:
                    with self._idempotency_lock:
                        self._completed[idempotency_key] = result
                return result
            result = ExecutionResult(
                ExecutionStatus.EXECUTED, tool.name, request_id, output=safe_output
            )
            recorded = self._record(
                "action_executed",
                request_id,
                proposal,
                {
                    "status": result.status.value,
                    "resources": [asdict(resource) for resource in resources],
                    "policy_decision": policy_result.decision.value,
                    "policy_version": policy_result.policy_version,
                    "policy_provenance": policy_result.provenance,
                },
            )
            if not recorded:
                result = replace(
                    result,
                    status=ExecutionStatus.EXECUTED_UNRECORDED,
                    reason="action executed but audit recording failed",
                    audit_recorded=False,
                )
            if tool.idempotency_required and idempotency_key is not None:
                with self._idempotency_lock:
                    self._completed[idempotency_key] = result
            return result
        except HandlerTimeoutError:
            cancellation.cancel()
            # A non-cooperative handler may still be performing a side effect
            # after the caller receives TIMED_OUT. Keep its concurrency slot
            # reserved until the worker exits so a timeout cannot create
            # overlapping side effects.
            budget_release_deferred = True
            result = ExecutionResult(
                ExecutionStatus.TIMED_OUT,
                tool.name,
                request_id,
                reason="handler exceeded execution timeout; side-effect status is uncertain",
            )
            recorded = self._record(
                "action_timed_out", request_id, proposal, {"reason": result.reason}
            )
            if not recorded:
                result = replace(result, audit_recorded=False)
            if tool.idempotency_required and idempotency_key is not None:
                with self._idempotency_lock:
                    self._completed[idempotency_key] = result
            return result
        except RuntimeCancelledError:
            result = ExecutionResult(
                ExecutionStatus.CANCELLED,
                tool.name,
                request_id,
                reason="handler observed runtime cancellation",
            )
            recorded = self._record(
                "action_cancelled", request_id, proposal, {"reason": result.reason}
            )
            if not recorded:
                result = replace(result, audit_recorded=False)
            return result
        except Exception as exc:  # pragma: no cover - exercised by integration tests
            recorded = self._record(
                "action_failed", request_id, proposal, {"error_type": type(exc).__name__}
            )
            result = ExecutionResult(
                ExecutionStatus.FAILED,
                tool.name,
                request_id,
                reason="tool execution failed",
                audit_recorded=recorded,
            )
            if tool.idempotency_required and idempotency_key is not None:
                with self._idempotency_lock:
                    self._completed[idempotency_key] = result
            return result
        finally:
            with self._stop_lock:
                self._active_tokens.pop(request_id, None)
            if not budget_release_deferred:
                self._budget.release()

    def _run_handler(
        self,
        handler: Any,
        context: ExecutionContext,
        arguments: Any,
        cancellation: CancellationToken,
        on_timeout: Callable[[], None],
    ) -> Any:
        """Run a handler with a bounded wait and cooperative timeout signal."""
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="agentic-tool")
        future = executor.submit(handler, context, arguments)
        timed_out = False
        try:
            return future.result(timeout=self.config.execution_timeout_seconds)
        except HandlerTimeoutError:
            timed_out = True
            cancellation.cancel()
            future.add_done_callback(lambda _future: on_timeout())
            future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            if not timed_out:
                executor.shutdown(wait=True, cancel_futures=True)

    def _deny(
        self,
        request_id: str,
        proposal: ActionProposal,
        reason: str,
        details: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        """Record and return a safe denial without executing a handler."""
        recorded = self._record(
            "action_denied", request_id, proposal, {"reason": reason, **(details or {})}
        )
        tool_name = proposal.tool_name if isinstance(proposal.tool_name, str) else "<invalid>"
        return ExecutionResult(
            ExecutionStatus.DENIED,
            tool_name,
            request_id,
            reason=reason,
            audit_recorded=recorded,
        )

    def _approval_required(
        self, request_id: str, proposal: ActionProposal, reason: str
    ) -> ExecutionResult:
        """Record a non-executing approval request."""
        recorded = self._record("approval_required", request_id, proposal, {"reason": reason})
        tool_name = proposal.tool_name if isinstance(proposal.tool_name, str) else "<invalid>"
        return ExecutionResult(
            ExecutionStatus.APPROVAL_REQUIRED,
            tool_name,
            request_id,
            reason=reason,
            approval_id=proposal.approval_id,
            audit_recorded=recorded,
        )

    def _record(
        self, event_type: str, request_id: str, proposal: ActionProposal, payload: Mapping[str, Any]
    ) -> bool:
        """Write a redaction-aware audit event and report whether it was stored."""
        if isinstance(proposal.arguments, Mapping):
            try:
                safe_arguments: object = dict(proposal.arguments)
            except Exception:
                safe_arguments = {"[invalid_arguments]": type(proposal.arguments).__name__}
        else:
            safe_arguments = {"[invalid_arguments_type]": type(proposal.arguments).__name__}
        try:
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
        except Exception:
            return False
        return True

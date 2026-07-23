"""Complete synthetic support-operations application.

Run this example from the repository root with ``python examples/support_agent.py``.
It has no network access, real credentials, model dependency, or production
data. The proposal objects stand in for untrusted model output so the example
can demonstrate the security boundary deterministically.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentic_security import (
    ActionProposal,
    ExecutionContext,
    GuardedRuntime,
    InMemoryApprovalProvider,
    InMemoryAuditSink,
    InMemoryCredentialBroker,
    Principal,
    Resource,
    RiskLevel,
    ToolDefinition,
    ToolRegistry,
    action_hash,
)
from agentic_security.policies import AllowListPolicy


@dataclass(frozen=True, slots=True)
class Ticket:
    """Synthetic support ticket used as the example's application data."""

    ticket_id: str
    tenant: str
    status: str
    customer_email: str


class SupportStore:
    """Small in-memory store whose methods represent application side effects."""

    def __init__(self) -> None:
        """Create two synthetic tickets belonging to separate tenants."""
        self._tickets: dict[str, Ticket] = {
            "ticket_001": Ticket("ticket_001", "tenant:acme", "open", "alice@customer.test"),
            "ticket_002": Ticket("ticket_002", "tenant:other", "open", "bob@customer.test"),
        }
        self.sent_messages: list[dict[str, str]] = []

    def resource_for(self, ticket_id: str) -> Resource:
        """Return the policy resource for a ticket, including its tenant."""
        ticket = self._tickets.get(ticket_id)
        tenant = ticket.tenant if ticket is not None else "tenant:unknown"
        return Resource(ticket_id, "support_ticket", tenant)

    def read(self, ticket_id: str) -> dict[str, str]:
        """Read one synthetic ticket after the runtime authorizes the action."""
        ticket = self._tickets[ticket_id]
        return {"ticket_id": ticket.ticket_id, "status": ticket.status}

    def update(self, ticket_id: str, status: str) -> dict[str, str]:
        """Update one ticket; authorization is performed before this method."""
        ticket = self._tickets[ticket_id]
        self._tickets[ticket_id] = Ticket(
            ticket.ticket_id, ticket.tenant, status, ticket.customer_email
        )
        return {"ticket_id": ticket_id, "status": status}

    def send_email(
        self, ticket_id: str, destination: str, body: str, credential_id: str
    ) -> dict[str, str]:
        """Record a synthetic email using only the broker-issued credential ID."""
        self.sent_messages.append(
            {
                "ticket_id": ticket_id,
                "destination": destination,
                "body": body,
                "credential_id": credential_id,
            }
        )
        return {"ticket_id": ticket_id, "delivery": "synthetic-queued"}


def _ticket_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a ticket identifier supplied by an untrusted proposal."""
    ticket_id = arguments.get("ticket_id")
    if not isinstance(ticket_id, str) or not ticket_id.startswith("ticket_"):
        raise ValueError("ticket_id must be a synthetic ticket identifier")
    return {"ticket_id": ticket_id}


def _update_arguments(arguments: Mapping[str, Any]) -> dict[str, str]:
    """Validate a ticket update without accepting arbitrary status values."""
    result = _ticket_arguments(arguments)
    status = arguments.get("status")
    if status not in {"open", "pending", "resolved"}:
        raise ValueError("status must be open, pending, or resolved")
    return {"ticket_id": result["ticket_id"], "status": status}


def _email_arguments(arguments: Mapping[str, Any]) -> dict[str, str]:
    """Validate a synthetic email and constrain its destination to test data."""
    result = _ticket_arguments(arguments)
    destination = arguments.get("destination")
    body = arguments.get("body")
    if not isinstance(destination, str) or not destination.endswith("@customer.test"):
        raise ValueError("destination must be a synthetic customer.test address")
    if not isinstance(body, str) or not body.strip() or len(body) > 500:
        raise ValueError("body must be non-empty and at most 500 characters")
    return {"ticket_id": result["ticket_id"], "destination": destination, "body": body}


def build_demo_application() -> tuple[
    GuardedRuntime,
    InMemoryApprovalProvider,
    InMemoryAuditSink,
    SupportStore,
]:
    """Build the complete local application with explicit security controls."""
    store = SupportStore()
    context = ExecutionContext(
        agent_id="agent:support-demo",
        principal=Principal("user:alice", tenant="tenant:acme"),
        task_id="task:support-demo",
        purpose="resolve synthetic customer support tickets",
        tenant="tenant:acme",
        environment="development",
    )

    def ticket_resource(arguments: Mapping[str, Any]) -> tuple[Resource, ...]:
        """Extract the live ticket resource used by policy authorization."""
        return (store.resource_for(arguments["ticket_id"]),)

    def read_ticket(_: ExecutionContext, arguments: Mapping[str, Any]) -> dict[str, str]:
        """Execute an authorized synthetic ticket read."""
        return store.read(arguments["ticket_id"])

    def update_ticket(_: ExecutionContext, arguments: Mapping[str, Any]) -> dict[str, str]:
        """Execute an authorized synthetic ticket update."""
        return store.update(arguments["ticket_id"], arguments["status"])

    def send_customer_email(
        handler_context: ExecutionContext, arguments: Mapping[str, Any]
    ) -> dict[str, str]:
        """Execute an approved email using the runtime-attached credential."""
        credential = handler_context.credential
        if credential is None:  # Defensive invariant for direct misuse of the handler.
            raise RuntimeError("runtime did not attach a credential")
        return store.send_email(
            arguments["ticket_id"],
            arguments["destination"],
            arguments["body"],
            credential.credential_id,
        )

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="read_ticket",
            handler=read_ticket,
            validator=_ticket_arguments,
            resources=ticket_resource,
            description="Read one synthetic support ticket.",
        )
    )
    registry.register(
        ToolDefinition(
            name="update_ticket",
            handler=update_ticket,
            validator=_update_arguments,
            resources=ticket_resource,
            idempotency_required=True,
            description="Update the status of one synthetic support ticket.",
        )
    )
    registry.register(
        ToolDefinition(
            name="send_customer_email",
            handler=send_customer_email,
            validator=_email_arguments,
            resources=ticket_resource,
            risk=RiskLevel.HIGH,
            requires_approval=True,
            external_egress=True,
            idempotency_required=True,
            requires_credential=True,
            description="Queue a synthetic customer email after explicit approval.",
        )
    )
    approvals = InMemoryApprovalProvider()
    audit = InMemoryAuditSink()
    runtime = GuardedRuntime(
        context,
        registry,
        AllowListPolicy({"read_ticket", "update_ticket", "send_customer_email"}),
        audit,
        approvals=approvals,
        credentials=InMemoryCredentialBroker(),
    )
    return runtime, approvals, audit, store


def main() -> None:
    """Run successful, denied, approval, replay, and stop demonstrations."""
    runtime, approvals, audit, store = build_demo_application()

    read = runtime.execute(
        ActionProposal("read_ticket", {"ticket_id": "ticket_001"}, "proposal:read")
    )
    cross_tenant = runtime.execute(
        ActionProposal("read_ticket", {"ticket_id": "ticket_002"}, "proposal:cross-tenant")
    )
    email_proposal = ActionProposal(
        "send_customer_email",
        {
            "ticket_id": "ticket_001",
            "destination": "alice@customer.test",
            "body": "Your synthetic ticket has been resolved.",
        },
        "proposal:email",
    )
    approval_needed = runtime.execute(email_proposal)
    grant = approvals.issue(
        "approval:email",
        runtime.context,
        "send_customer_email",
        email_proposal.proposal_id,
        "approver:manager",
        action_hash(
            runtime.context,
            email_proposal.tool_name,
            email_proposal.arguments,
            (store.resource_for("ticket_001"),),
        ),
    )
    email = runtime.execute(
        ActionProposal(
            email_proposal.tool_name,
            email_proposal.arguments,
            email_proposal.proposal_id,
            grant.approval_id,
        )
    )
    idempotent_replay = runtime.execute(email_proposal)
    approval_replay = runtime.execute(
        ActionProposal(
            "send_customer_email",
            dict(email_proposal.arguments),
            "proposal:approval-replay",
            grant.approval_id,
        )
    )
    runtime.stop()
    stopped = runtime.execute(
        ActionProposal(
            "update_ticket",
            {"ticket_id": "ticket_001", "status": "resolved"},
            "proposal:stopped",
        )
    )

    print(f"read_ticket: {read.status} {read.output}")
    print(f"cross_tenant_read: {cross_tenant.status} ({cross_tenant.reason})")
    print(f"email_without_approval: {approval_needed.status} ({approval_needed.reason})")
    print(f"approved_email: {email.status} {email.output}")
    print(f"idempotent_replay: {idempotent_replay.status}")
    print(f"approval_replay: {approval_replay.status} ({approval_replay.reason})")
    print(f"emergency_stop: {stopped.status} ({stopped.reason})")
    print(f"synthetic_messages: {len(store.sent_messages)}")
    print(f"audit_chain_valid: {audit.verify()}")


if __name__ == "__main__":
    main()

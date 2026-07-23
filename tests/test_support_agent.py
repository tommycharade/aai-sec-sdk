from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from examples.support_agent import build_demo_application

from agentic_security import ActionProposal, action_hash

ROOT = Path(__file__).resolve().parents[1]


def _email_proposal(proposal_id: str = "proposal:test-email") -> ActionProposal:
    return ActionProposal(
        "send_customer_email",
        {
            "ticket_id": "ticket_001",
            "destination": "alice@customer.test",
            "body": "Synthetic update.",
        },
        proposal_id,
    )


def test_support_agent_example_runs_without_external_services() -> None:
    completed = subprocess.run(
        [sys.executable, "examples/support_agent.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "read_ticket: executed" in completed.stdout
    assert "cross_tenant_read: denied" in completed.stdout
    assert "email_without_approval: approval_required" in completed.stdout
    assert "approved_email: executed" in completed.stdout
    assert "idempotent_replay: executed" in completed.stdout
    assert "approval_replay: denied" in completed.stdout
    assert "emergency_stop: denied" in completed.stdout
    assert "synthetic_messages: 1" in completed.stdout
    assert "audit_chain_valid: True" in completed.stdout


def test_support_agent_requires_approval_before_credential_backed_side_effect() -> None:
    runtime, approvals, audit, store = build_demo_application()
    proposal = _email_proposal()

    awaiting_approval = runtime.execute(proposal)
    assert awaiting_approval.status == "approval_required"
    assert store.sent_messages == []

    grant = approvals.issue(
        "approval:test-email",
        runtime.context,
        proposal.tool_name,
        proposal.proposal_id,
        "approver:test",
        action_hash(
            runtime.context,
            proposal.tool_name,
            {
                "ticket_id": "ticket_001",
                "destination": "alice@customer.test",
                "body": "Synthetic update.",
            },
            (store.resource_for("ticket_001"),),
        ),
    )
    executed = runtime.execute(
        ActionProposal(
            proposal.tool_name,
            proposal.arguments,
            proposal.proposal_id,
            grant.approval_id,
        )
    )

    assert executed.status == "executed"
    assert store.sent_messages[0]["credential_id"].startswith("cred:")
    assert "Synthetic update." in str(store.sent_messages)
    # Audit records identify the action but do not persist the broker token or
    # the handler-only credential ID.
    assert "cred:" not in str(audit.events())


def test_support_agent_rejects_untrusted_destination_before_side_effect() -> None:
    runtime, _, _, store = build_demo_application()
    proposal = ActionProposal(
        "send_customer_email",
        {
            "ticket_id": "ticket_001",
            "destination": "attacker.invalid",
            "body": "Synthetic update.",
        },
        "proposal:bad-destination",
    )

    result = runtime.execute(proposal)

    assert result.status == "denied"
    assert "invalid tool arguments" in (result.reason or "")
    assert store.sent_messages == []

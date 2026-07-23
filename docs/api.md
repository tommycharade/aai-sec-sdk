# API reference and design

The public API uses typed objects and structured outcomes. A minimal integration looks like this:

The package ships a `py.typed` marker so downstream type checkers can use its
public annotations.

```python
@agent.tool(
    name="send_email",
    risk=Risk.HIGH,
    requires_scope="mail.send",
    approval=Approval.required(ttl_seconds=120),
)
def send_email(ctx: ExecutionContext, args: SendEmail) -> SendResult:
    """Send one approved message using the caller-scoped credential."""
    return mail_client.send(to=args.to, body=args.body,
                            credential=ctx.credential)
```

Expected policy outcomes are structured decisions rather than ambiguous boolean returns. The generated reference below is built from the public docstrings and is checked in CI.

## Public runtime API

::: agentic_security.GuardedRuntime

::: agentic_security.types.ExecutionContext

::: agentic_security.types.ActionProposal

::: agentic_security.types.ExecutionResult

::: agentic_security.RuntimeConfig

## Tools

::: agentic_security.tools.ToolDefinition

::: agentic_security.tools.ToolRegistry

## Policies

::: agentic_security.policies.PolicyEngine

::: agentic_security.policies.AllowListPolicy

::: agentic_security.policies.PolicyDecision

::: agentic_security.policies.PolicyResult

::: agentic_security.policy_adapters.PolicyRequest

::: agentic_security.policy_adapters.OpaPolicyEngine

::: agentic_security.policy_adapters.CedarPolicyEngine

## Approvals and audit

::: agentic_security.approvals.ApprovalProvider

::: agentic_security.approvals.InMemoryApprovalProvider

::: agentic_security.audit.InMemoryAuditSink

## Credential brokering

::: agentic_security.credentials.CredentialBroker

::: agentic_security.credentials.ScopedCredential

::: agentic_security.credentials.InMemoryCredentialBroker

## Telemetry

::: agentic_security.telemetry.CompositeAuditSink

::: agentic_security.telemetry.OpenTelemetryAuditSink

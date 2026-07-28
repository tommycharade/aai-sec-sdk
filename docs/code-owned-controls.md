# Code-owned and deployment-owned controls

Some SDK features should not be configurable by an administrator in either the
Policy editor or the ordinary enterprise UI. They are security invariants,
typed API contracts or development/deployment responsibilities. They may be
visible as immutable capability information, health status or evidence.

## SDK invariants and developer-owned APIs

| Feature | Ownership and UI treatment |
| --- | --- |
| Typed action proposals | Application integration; expose as a typed API, not a UI setting. |
| Structured execution results | Runtime contract consumed by application code. |
| Fail-closed authorization | Immutable runtime behaviour; never offer a disable switch. |
| Tool registry | Explicit code-owned registration of executable tools. |
| Tool validators | Code-owned argument validation for each tool. |
| JSON Schema tool contracts | Code-owned contracts published to MCP hosts and UI clients. |
| Output validation | Code-owned validation and constraining of tool output. |
| Reconciliation handlers | Application-owned handling of uncertain or interrupted side effects. |
| Cancellation tokens | Runtime/application control for cooperative cancellation. |
| Phase-specific timeout outcomes | Immutable result semantics that identify the timeout phase. |
| Approval replay protection | Mandatory runtime protection; no separate toggle. |
| Credential scope enforcement | Runtime invariant checked against live action facts. |
| Credential TTL and revocation implementation | Broker/IAM responsibility; UI may show status and configure references. |
| Callback isolation verifier | Application-provided code adapter. |
| Composite audit sink | Code/deployment composition of multiple sinks. |
| Audit replication failure handling | Runtime/adapter behaviour; failures must be visible and safe. |
| Terminal recording | Bounded application/runtime diagnostic behaviour. |
| Authenticated identity binding | Mandatory binding between authenticated identity and registered agent. |

These controls should be displayed in an “SDK guarantees” or “security
invariants” panel, with their implementation version and test/evidence status.

## Integration and deployment responsibilities

| Feature | Ownership and UI treatment |
| --- | --- |
| MCP HTTP application | Application deployment, hosting and network configuration. |
| MCP session store | Application infrastructure and session persistence. |
| Custom host integration | Developer implementation translating host calls into `ActionProposal`. |
| In-memory credential broker | Synthetic/local development adapter; not an enterprise policy setting. |
| In-memory audit sink | Test/local-development adapter; show as non-production status. |
| Configuration backups | Onboarding/deployment script behaviour and storage operations. |
| Generated README | Documentation build workflow. |
| MkDocs documentation site | Documentation publishing workflow. |
| Guardrail and quality checks | CI/development workflow, including tests, coverage, docs and dependency checks. |

## Why these controls are protected

Making these behaviours configurable would allow a well-meaning administrator
or a compromised control-plane credential to weaken the execution boundary.
The correct approach is to make them:

- explicit in the public API;
- documented with trust-boundary and failure-mode explanations;
- covered by positive and adversarial tests;
- visible as immutable capabilities or health evidence;
- changeable only through reviewed code, deployment configuration or governed
  infrastructure changes.

The policy and enterprise UIs may configure requirements and references around
these mechanisms, but they must not be able to bypass the mechanisms
themselves.

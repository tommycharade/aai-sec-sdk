# Enterprise operations readiness

This page is the acceptance matrix for the P1/P2 adopter findings. A source
fix is not treated as deployment evidence: rows marked deployment-owned still
require an enterprise adapter, infrastructure test, or published release
verification before consequential workloads are approved.

| Finding | Source-level resolution | Evidence | Deployment acceptance still required |
| --- | --- | --- | --- |
| Production UI mock data or missing auth | Mock mode is explicit; production HTTP client fails closed without bearer auth and supports explicit HttpOnly cookie sessions through a BFF. | UI typecheck, 14 UI tests, production build. | OIDC/SSO session through a BFF or equivalent, CSRF controls, RBAC and TLS. |
| Stale long-running policy | Runtime policy replacement is atomic; MCP heartbeat refreshes effective policy and stops on refresh failure or emergency stop. | Runtime and MCP gateway tests; `make check`. | Validate refresh latency and outage behavior in the target deployment. |
| Fleet incident response | Deployment, group, and agent emergency stops are audited and exposed in the UI. | Enterprise API tests cover activation and clearing at each scope. | Bind the authority adapter to the real process supervisor and credential revocation path. |
| Unverified enrollment | Agent verification reports registration, heartbeat, project root, policy assignment, and stop state. | API and store verification tests. | Validate host identity, binary provenance, and attestation in the enterprise environment. |
| Weak investigation evidence | Bounded redaction-safe audit evidence index is available to the UI and API. | Audit API tests and redaction assertions. | Export immutable/WORM records to the enterprise audit or SIEM system. |
| Policy lifecycle ambiguity | Policies are immutable; group reassignment is an explicit audited operation and live runtimes refresh. | Group policy reassignment API/UI tests. | Add four-eyes approval and change-management integration if required by policy. |
| Fleet scale and drift | Inventory reads are cursor-paginated, bounded, tenant-scoped, and UI collection has a safety cap. | Pagination and fleet contract tests. | Load-test the selected database, queue, cache, and browser workload at target fleet size. |
| Alert response | Alerts are derived from authoritative state, acknowledged without deleting evidence, and dispatched through an injected sink. | Alert adapter and API tests. | Connect PagerDuty/SIEM/SOC routing and test delivery retries and ownership. |
| Release integrity | Tag-only release workflow builds, checksums the exact bundle, verifies the downloaded release, and verifies tag-bound provenance. | `.github/workflows/release-artifacts.yml`, `scripts/verify_release_evidence.py`; public `v1.0.1` checksum and attestation verification passed on 2026-07-27. | Repeat the same verification for every future release; historical `v1.0.0` assets remain superseded. |
| Idempotency uncertainty | Timeout, cancellation, and handler-failure paths surface failed terminal persistence as an uncertain unrecorded result. | Runtime tests and 90%+ repository coverage gate. | Test a shared durable store under process crash, failover, and concurrent retry conditions. |
| Immutable authorization facts | Validated JSON-like arguments are recursively frozen and thawed only at the handler boundary. | Component adversarial tests and mutation gate. | Validate behavior with application-specific validators and hostile handler tests. |
| Host integration | Claude Code, Codex CLI, and GitHub Copilot use the provider-neutral MCP gateway; all supported profiles share contract tests. | `tests/test_integrations.py` and onboarding documentation. | Run acceptance tests with the actual host binaries, organization settings, and upgrade policy. |

## AWS pilot evidence — 2026-07-27

The first AWS control-plane deployment provides retained evidence for part of
the deployment-owned matrix:

- Cognito Managed Login is used for operator authentication.
- API Gateway rejects unauthenticated requests with HTTP 401.
- Requests without a verified `custom:tenant_id` claim, or with a tenant that
  has not been independently provisioned, fail closed with HTTP 403; the
  Lambda never falls back to a default tenant.
- Mutations require the Cognito `platform-admin` or `security-operator` group.
- DynamoDB control and presence tables use on-demand capacity; the control
  table has point-in-time recovery and the presence table uses TTL.
- The audit bucket is versioned, retained, SSL-only, private, and configured
  with S3 Object Lock compliance retention.
- A retained DynamoDB idempotency table is deployed with TTL and point-in-time
  recovery. `DynamoDbIdempotencyStore` was exercised against that live table
  across independent processes and a new adapter instance for atomic claim,
  replay detection, and terminal persistence.
- Agent enrollment now consumes a one-time hashed bootstrap secret and issues
  a deployment/agent-bound short-lived session. The live API contract test
  covered enrollment, replay refusal, heartbeat, effective-policy retrieval,
  and URL identity mismatch refusal.
- Remote approvals are stored tenant-scoped and consumed with a conditional
  exact-action update. The live API contract accepted one matching action and
  rejected its replay.
- The live smoke activates an enrolled agent emergency stop, verifies that the
  agent API refuses effective-policy retrieval with `409`, then clears the stop
  and verifies recovery before executing any synthetic action.
- The live audit check verifies S3 Object Lock compliance retention and
  versioning, and a delete attempt against a retained audit version is rejected
  by AWS.
- A separate `eu-west-1` Object-Lock-protected audit replica is deployed and
  configured through S3 cross-region replication. The live recovery test
  received a synthetic object with `ReplicationStatus=REPLICA`, preserved
  metadata, and `COMPLIANCE` retention on 2026-07-27.
- CloudWatch alarms are deployed for Lambda errors, Lambda throttles, and
  idempotency-table `PutItem` throttles.
- The security-alert SNS topic has a durable encrypted SQS subscriber and
  dead-letter queue. A live synthetic publish was received and acknowledged by
  the queue on 2026-07-27, and an unacknowledged synthetic alert was verified
  to reach the DLQ. PagerDuty/SIEM subscription and on-call ownership remain
  enterprise deployment responsibilities.
- A dedicated scoped tool role is deployed. AWS IAM policy simulation returned
  `allowed` for `s3:GetObject` under the synthetic
  `tenant=tenant-demo/agent-claude-local/` prefix and `implicitDeny` for the
  sibling `other-agent` prefix. This is a reference provider-scope proof, not
  permission to reuse the role for unrelated production tools.
- CloudWatch error/throttle alarms publish to a retained SNS security-alert
  topic. A production deployment must add and test its PagerDuty, SIEM, or SOC
  subscription; the topic ARN is an output and no personal subscription is
  created by this stack.
- Browser preflight requests are handled without the API JWT authorizer, and
  the authenticated hosted UI has been exercised through Cognito, policy and
  group management, effective-policy lookup, and agent emergency-stop flows.

This closes the AWS pilot's credential-exchange, remote-approval, durable
idempotency reference path, and synthetic provider-IAM proof. It does not
close the remaining high-impact deployment requirements: the actual
production runtime must be connected to the table, each real provider/tool
role must be simulated, hostile-code escape or microVM/WASM isolation evidence
must be retained, and enterprise alert ownership and recovery artifacts must
be demonstrated before consequential workloads are approved. The pilot now
also includes a real Docker boundary probe; this does not certify the Docker
daemon/host or substitute for a stronger isolation boundary.

## Approval rule

The SDK is suitable for a low-risk pilot when the source-level evidence and
authenticated policy/audit adapters pass. It is not approved for payments,
deletion, messaging, credentialed state changes, hostile code, or regulated
workloads until every deployment-owned row has a retained acceptance artifact.

The management UI is an operator surface, never the authority boundary. The
runtime, control plane, IAM, approval service, credential broker, isolation
verifier, and durable audit service must each fail closed independently.

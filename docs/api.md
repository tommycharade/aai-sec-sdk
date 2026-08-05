# API reference and design

The public API uses typed objects and structured outcomes. A minimal integration
with the current SDK looks like this:

The package ships a `py.typed` marker so downstream type checkers can use its
public annotations.

```python
from agentic_security import (
    ActionProposal,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    Principal,
    RiskLevel,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.policies import AllowListPolicy

context = ExecutionContext(
    agent_id="agent:example",
    principal=Principal("user:alice", tenant="tenant:example"),
    task_id="task:example",
    purpose="read one synthetic record",
    tenant="tenant:example",
)
registry = ToolRegistry()
registry.register(ToolDefinition(
    name="read_record",
    handler=lambda ctx, args: {"record_id": args["record_id"]},
    validator=lambda args: {"record_id": args["record_id"]},
    risk=RiskLevel.LOW,
    description="Read one synthetic record.",
))
runtime = GuardedRuntime(
    context, registry, AllowListPolicy({"read_record"}), InMemoryAuditSink()
)
result = runtime.execute(
    ActionProposal("read_record", {"record_id": "record_001"}, "proposal:1")
)
assert result.status == "executed"
```

Expected outcomes use `ExecutionStatus.EXECUTED`, `DENIED`,
`APPROVAL_REQUIRED`, `FAILED`, `EXECUTED_UNRECORDED`,
`EXECUTED_RESULT_REJECTED`, `TIMED_OUT`, or `CANCELLED`; the legacy
`RECONCILED` enum value is retained for compatibility but is not emitted by the
current runtime. Callers must not blindly retry `TIMED_OUT` or
`EXECUTED_UNRECORDED` because side-effect or audit state may be uncertain.
`ExecutionResult.idempotency_recorded` independently reports whether a
terminal idempotency result was durably persisted. For uncertain timeout,
cancellation, or handler-failure outcomes, `False` is a release-blocking
operational signal and the side effect must be reconciled before retrying.
`ExecutionResult.reconciliation_state` independently
reports `STILL_RUNNING`, `CONFIRMED_COMPLETE`, `CONFIRMED_ABSENT`, `UNKNOWN`, or
`FAILED`. A live timed-out worker always keeps the primary status `TIMED_OUT`.
`ExecutionResult.timeout_phase` identifies `POLICY`, `APPROVAL`, `CREDENTIAL`,
`AUDIT`, `HANDLER`, or `RECONCILIATION`. `handler_started` and
`side_effect_state` distinguish pre-handler denials from actions whose effect
is uncertain; policy, approval, and credential timeouts never invoke the
handler.
Policy decisions use `PolicyDecision`. The
generated reference below is built from public docstrings and is checked in CI.
The example is synthetic and does not connect to a model or external service.

## Public runtime API

::: agentic_security.GuardedRuntime

::: agentic_security.types.ExecutionContext

::: agentic_security.types.Principal

::: agentic_security.types.Resource

::: agentic_security.types.ActionProposal

::: agentic_security.types.ExecutionResult

::: agentic_security.types.ExecutionStatus

::: agentic_security.types.CancellationToken

::: agentic_security.types.ReconciliationResult

::: agentic_security.types.ReconciliationState

::: agentic_security.RuntimeConfig

## Typed security components

## Enterprise fleet control plane

::: agentic_security.enterprise_control_plane.FleetIdentity

::: agentic_security.enterprise_control_plane.EnterpriseFleetStore

::: agentic_security.enterprise_control_plane.EnterpriseFleetApplication

## Policy composition and reviewed Git sources

Git is a reviewed transport, never runtime authority. The source verifier
accepts one exact repository, full commit object ID and path. A successful
import creates only a normal draft; it cannot submit, approve, activate or
assign a policy. Export signatures are produced by a deployment-owned KMS/HSM
adapter over canonical provenance bytes.

::: agentic_security.policy_sources.PolicySourceDocument

::: agentic_security.policy_sources.PolicySourceRequest

::: agentic_security.policy_sources.VerifiedPolicySource

::: agentic_security.policy_sources.PolicySourceVerifier

::: agentic_security.policy_sources.PolicyExportSignature

::: agentic_security.policy_sources.PolicyExportSigner

::: agentic_security.policy_sources.CallbackPolicyExportSigner

::: agentic_security.github_policy_source.GitHubPolicySourceVerifier

::: agentic_security.github_policy_source.GitHubHttpTransport

::: agentic_security.github_policy_source.GitHubHttpResponse

## Native agent host hooks

::: agentic_security.claude_code

::: agentic_security.codex_cli

## Managed host policy compilation

The compiler produces deployment artifacts but does not write privileged host
paths. Effective authority remains fail-closed until independently observed
endpoint evidence matches the complete desired bundle.

::: agentic_security.managed_configuration.ManagedConfigurationCompiler

::: agentic_security.managed_configuration.ManagedPolicyIntent

::: agentic_security.managed_configuration.NativeActionRule

::: agentic_security.managed_configuration.ManagedCommandRule

::: agentic_security.managed_configuration.ManagedMcpServer

::: agentic_security.managed_configuration.ManagedConfigurationBundle

::: agentic_security.managed_configuration.ManagedConfigurationEvidence

::: agentic_security.managed_configuration.measure_managed_configuration

::: agentic_security.managed_configuration.ObservedManagedConfiguration

::: agentic_security.managed_configuration.EffectiveAuthority

::: agentic_security.managed_configuration.reconcile_effective_authority

### Codex process-loaded effective controls

`CodexAppServerEffectiveControlProbe` invokes an exact release-pinned Codex
binary directly and reads the supported app-server configuration endpoints. It
returns only a content-minimised projection. Raw configuration can contain
credentials and is never returned, logged, or included in errors. A successful
probe can still return `deployment_required` when Codex does not expose enough
runtime detail to prove every requested control.

`CodexEffectiveControlEvidence.bundle_hash` binds the observation to the exact
managed bundle passed to the probe. The control plane does not trust the
submitted state in isolation: it compares bundle, host version and platform
with current desired state and derives freshness with the server clock.

For an enrolled Codex agent, heartbeat `controlState` contains:

```json
{
  "executionAllowed": false,
  "evidenceAllowed": true,
  "activeStopScopes": [],
  "authorityBlockers": ["native_effective_controls"],
  "nativeEffectiveControls": {
    "required": true,
    "status": "missing",
    "desired": {
      "bundleHash": "<lowercase SHA-256>",
      "hostVersion": "0.146.0",
      "platform": "macos"
    }
  },
  "quarantine": null
}
```

`authorityBlockers` uses only `missing_agent`, `emergency_stop`, `quarantine`,
and `native_effective_controls`. Clients must treat absent or false
`executionAllowed` as closed. The managed-package GET route is the only repair
exception to the native evidence blocker; response controls and runtime
attestation still apply.

::: agentic_security.codex_effective_controls.CodexAppServerEffectiveControlProbe

::: agentic_security.codex_effective_controls.CodexEffectiveControlEvidence

::: agentic_security.codex_effective_controls.CodexRequirementProjection

::: agentic_security.codex_effective_controls.codex_effective_control_evidence_from_wire

## Managed endpoint deployment packages

Packages are canonical, credential-free and digest-bound, but they are not
self-authorizing. Endpoint management must supply the expected package digest,
bundle digest, host and platform through an authenticated channel. The optional
privileged installer is documented in
[Managed endpoint deployment](managed-endpoint-deployment-design.md).
The enterprise control plane can publish a package with optimistic concurrency
and deliver it only over the exact enrolled agent's authenticated route. Use
`ControlPlaneAgentClient.managed_deployment_package` to retrieve, bound-check
and reparse that response. Operator reads expose metadata, not package content.

::: agentic_security.managed_deployment.ManagedDeploymentPackage

::: agentic_security.managed_deployment.ManagedExecutableRequirement

Applications normally continue to use `GuardedRuntime`; these contracts are
provided for integrations and contract tests. Do not construct a permit from
model output or bypass the runtime lifecycle.

::: agentic_security.ActionFacts

::: agentic_security.AuthorizationEvidence

::: agentic_security.ExecutionPermit

Permits are issued only by `PreExecutionAuthorizer`. The lifecycle authenticates
the permit's object identity against an internal issuer registry; constructing a
same-shaped object or copying fields cannot authorize a handler call.
Validated argument mappings and sequences inside `ActionFacts` and
`ExecutionPermit` are recursively frozen. The lifecycle passes handlers a
defensive ordinary-container copy, so a handler can transform its local input
without mutating the authorization snapshot.

::: agentic_security.PreExecutionAuthorizer

::: agentic_security.ExecutionLifecycle

::: agentic_security.TerminalRecorder

::: agentic_security.BoundedOperationTracker

::: agentic_security.BoundedOperationExecutor

::: agentic_security.ActionBudgetLease

`TerminalRecorder` owns the idempotency state transition around a consequential
action. Callers must claim before invoking `record`; the configured store
enforces atomic claim/replay/conflict/expiry semantics. `lookup` rejects a
different action under the same operation key, `claim` returns existing or
expired evidence without permitting unsafe replay, `record` returns `False`
when terminal persistence fails, and `gc` returns the store's observable
garbage-collection report.
`replay_completed` is the single completed-result replay API; malformed
terminal records and identity collisions fail closed, while in-progress and
uncertain records remain non-replayable.

`RuntimeConfig.execution_timeout_seconds` is a caller-wait deadline for policy,
approval, credential, audit, handler, and reconciliation operations. Python
cannot forcibly terminate an arbitrary running thread, so non-cooperative
workers remain tracked and count against `max_timed_out_workers` until they
return. Use `GuardedRuntime.health()` for operational alerts. Configure a
custom `redactor` for domain-specific secret or PII rules.

`GuardedRuntime.telemetry()` returns the bounded, content-free aggregate
execution counters used by the agent heartbeat. It reports action outcomes,
admission and cost units, and aggregate latency; it never includes tool names,
arguments, resources, principals, credentials, or handler output. Deployments
may send this snapshot to the enterprise control plane for fleet performance
views. It is an operational metric snapshot, not a replacement for the
redacted audit stream.

## Tools

::: agentic_security.tools.ToolDefinition

`ToolDefinition` applies result redaction and a serialized size limit before a
handler result crosses the runtime boundary. Use `output_validator` for an
application-specific result schema or normalization step.
High-impact and external-egress tools must be idempotent or provide a typed
reconciliation callback. A handler timeout remains uncertain while the worker
can still commit. `requires_isolation=True` requires a handler-provided
attestation and configured verifier; a boolean `isolated` marker is not
security evidence. The included subprocess adapter is only a process boundary.

For tools with `idempotency_required=True`, every proposal must include a
caller-supplied stable `operation_key` representing the business side effect,
not a generated proposal ID. Configure `RuntimeConfig.idempotency_store`;
`InMemoryIdempotencyStore` is process-local development/test storage, not
durable production storage. If terminal persistence fails after a handler has
run, the runtime returns `EXECUTED_UNRECORDED` and leaves the operation unsafe
to retry until the store is repaired or the side effect is reconciled.
`RuntimeConfig.idempotency_ttl_seconds` defaults to one day. Expired completed
records may be reclaimed; expired in-progress or uncertain records remain
retained and return `EXPIRED` until explicitly reconciled. Call `store.gc()`
and retain its `IdempotencyGCReport`; GC never silently deletes active or
uncertain records.

::: agentic_security.tools.ToolRegistry

::: agentic_security.tools.OutputValidator

::: agentic_security.tools.ReconciliationHandler

::: agentic_security.idempotency.IdempotencyStore

::: agentic_security.idempotency.InMemoryIdempotencyStore

::: agentic_security.idempotency.IdempotencyGCReport

::: agentic_security.isolation.IsolationAttestation

::: agentic_security.isolation.IsolationVerifier

::: agentic_security.isolation.CallbackIsolationVerifier

::: agentic_security.isolation.IsolationBoundary

::: agentic_security.isolation.IsolationNetworkMode

::: agentic_security.isolation.IsolationCredentialMode

::: agentic_security.isolation.IsolationConstraints

::: agentic_security.isolation.IsolationProfile

::: agentic_security.isolation.IsolationRequirement

::: agentic_security.isolation.IsolationVerification

::: agentic_security.isolation.ProductionIsolationVerifier

::: agentic_security.isolation.isolation_action_binding

::: agentic_security.isolation.isolation_attestation_payload

## Policies

::: agentic_security.policies.PolicyEngine

::: agentic_security.policies.AllowListPolicy

::: agentic_security.policies.PolicyDecision

::: agentic_security.policies.PolicyResult

::: agentic_security.policy_adapters.PolicyRequest

::: agentic_security.policy_adapters.OpaPolicyEngine

::: agentic_security.policy_adapters.CedarPolicyEngine

::: agentic_security.policy_composition.PolicyComponent

::: agentic_security.policy_composition.PolicyCompositionResult

::: agentic_security.policy_composition.PolicyCompositionStep

::: agentic_security.policy_composition.PolicyCompositionError

::: agentic_security.policy_composition.compose_policy

`PolicyResult` may carry an external policy version and provenance label. The
runtime preserves both in execution audit evidence so operators can identify
which policy decision point authorized an action.

## Approvals and audit

Approvals must be bound to the hash of the validated arguments and extracted
resources. An approval for one proposal or argument set cannot authorize a
modified action.

::: agentic_security.approvals.ApprovalProvider

::: agentic_security.approvals.ApprovalConsumption

::: agentic_security.approvals.ApprovalOutcome

::: agentic_security.approvals.ApprovalGrant

::: agentic_security.approvals.action_hash

::: agentic_security.approvals.InMemoryApprovalProvider

::: agentic_security.audit.InMemoryAuditSink

::: agentic_security.audit.AuditExporter

::: agentic_security.audit.ReplicatedAuditSink

::: agentic_security.audit.InMemoryAuditExporter

::: agentic_security.audit.Redactor

## Credential brokering

::: agentic_security.credentials.CredentialBroker

::: agentic_security.credentials.CredentialMetadata

::: agentic_security.credentials.ScopedCredential

::: agentic_security.cloud_credentials.CloudCredentialProvider

::: agentic_security.cloud_credentials.CloudScopePolicy

::: agentic_security.cloud_credentials.CloudProviderGrant

::: agentic_security.cloud_credentials.CloudTokenExchangeClient

::: agentic_security.cloud_credentials.CloudScopeBuilder

::: agentic_security.cloud_credentials.GrantRevocationChecker

::: agentic_security.cloud_credentials.CloudWorkloadCredentialBroker

::: agentic_security.cloud_credentials.AzureWorkloadIdentityCredentialBroker

::: agentic_security.cloud_credentials.GcpWorkloadIdentityCredentialBroker

`AwsStsCredentialBroker` and the cloud workload brokers can receive a live
revocation callback. A false result or callback failure denies mint and blocks
callback-checked use. See [Cloud credential
authority](cloud-credential-authority-design.md) for the hosted evidence and
revocation lifecycle. AWS STS requests must be 900–3,600 seconds because STS
cannot issue a shorter role session; Azure and GCP support the SDK's 1–3,600
second mint range.

## UI control plane adapter

The optional management UI talks to an authenticated control-plane adapter.
The reference implementation below validates complete configuration
replacements, applies persisted controls to a live authority before serving,
persists them atomically, records requested/activated changes, and exposes a
persisted emergency stop. Bind it to an application-owned authority and an
authoritative audit sink before enabling mutation. It does not create
application identity or replace the deployment's policy, approval, credential,
audit, or isolation services.

::: agentic_security.ControlPlaneStore

::: agentic_security.ControlPlaneApplication

::: agentic_security.ControlPlaneAuthority

::: agentic_security.CallbackControlPlaneAuthority

::: agentic_security.OperatorAuthenticator

::: agentic_security.OperatorIdentity

::: agentic_security.StaticBearerAuthenticator

::: agentic_security.ControlPlaneDependencyError

::: agentic_security.InMemoryControlPlaneAuthority

::: agentic_security.AgentPresence

::: agentic_security.AgentPresenceStore

::: agentic_security.AgentSessionCredential

::: agentic_security.AgentSessionStore

::: agentic_security.AgentSessionStoreError

`AgentSessionStore` is the reference same-user credential cache for native hook
and MCP processes. It derives an opaque filename from the control-plane URL,
deployment and agent identity, writes atomically outside the project with
directory mode `0700` and file mode `0600`, and rejects symlinks, foreign
ownership, broad permissions, malformed content and expired credentials. The
cache transfers a bearer; it does not validate or authorize it. The control
plane remains authoritative on every request. The reference implementation is
POSIX-only and refuses construction when numeric ownership and private file
modes cannot be verified; Windows deployments require an ACL-aware credential
store adapter. Reads use a no-follow descriptor, revalidate its metadata, and
are bounded to 4096 bytes before decoding.

::: agentic_security.ControlPlaneAgentClient

## Runtime remediation coordination

`RuntimeRemediationClient` is for an administrator-owned external endpoint
workflow, never a model process or normal agent session. Give its service
identity only `inventory_read` and `runtime_remediation`. The client reads
exact rollout-selected release digests, leases work and reports a fixed channel
outcome. It has no download, command, install or elevation method, and an
`installed` result remains unverified until fresh runtime attestation exists.
See [Runtime remediation coordination](runtime-remediation-coordination-design.md).

::: agentic_security.RuntimeRemediationClient

::: agentic_security.RuntimeRemediationInstruction

::: agentic_security.RuntimeRemediationPage

Pass a deployment-owned `managed_configuration_provider` when an enrolled AWS
agent has an assigned managed-host bundle. The callback must re-measure the
administrator-owned files and return `ManagedConfigurationEvidence`; the
client invokes it for every heartbeat and rejects mappings or evidence for a
different host. Never construct this evidence from model output, project
configuration, or the desired policy returned by the server.

`ControlPlaneAgentClient.report_decision` is available only for an enrolled AWS
agent session. It submits a SHA-256 event digest plus fixed, content-minimised
decision metadata; it never submits tool arguments, prompts, commands, paths,
outputs, credentials, principals, or caller-selected policy identity. The
server derives ownership and current policy metadata from the authenticated
session. A report is operational evidence and grants no authority.

::: agentic_security.ControlPlaneDecisionExporter

`ControlPlaneDecisionExporter` is an `AuditExporter` for host and SDK decision
events. It maps structured local outcomes into the closed control-plane
vocabulary, discards free-form action content, and ignores lifecycle events
that are not decisions. Use it as the required replica in
`ReplicatedAuditSink` when the management plane must acknowledge evidence
before a consequential action proceeds:

```python
from agentic_security import (
    ControlPlaneAgentClient,
    ControlPlaneDecisionExporter,
    JsonlAuditSink,
    ReplicatedAuditSink,
)

client = ControlPlaneAgentClient(
    "https://control-plane.example",
    "synthetic-short-lived-agent-session",
    agent_id="claude-example",
    deployment_id="deployment-example",
    aws_agent_session=True,
)
audit = ReplicatedAuditSink(
    JsonlAuditSink(".claude/security-audit.jsonl"),
    ControlPlaneDecisionExporter(client, source="claude_native"),
)
```

The example token and identities are synthetic. Supply the real short-lived
session through a deployment secret boundary rather than source code.

::: agentic_security.ControlPlaneConfigurationError

::: agentic_security.validate_configuration

::: agentic_security.credentials.InMemoryCredentialBroker

::: agentic_security.credentials.TokenCredentialBroker

::: agentic_security.credentials.ProviderToken

Credential callbacks must return `ProviderToken`, not a bare string. The
provider attests the effective tool/resource scope and expiry; the SDK checks
that attestation against the live action. `ScopedCredential.with_secret()`
accepts a non-returning operation, preventing accidental secret return through
the handler result. In-process handlers remain trusted code; use process or
container isolation for hostile code.

## Deployment adapters

The package includes explicit adapters for common deployment infrastructure.
`JsonHttpClient` requires HTTPS (except explicitly enabled localhost tests),
uses a bounded timeout, and never invents authentication or retry behavior.
`HttpOpaPolicyEngine`, `HttpCedarPolicyEngine`, and `HttpApprovalProvider` use
that transport. `JsonlAuditSink` provides fsync-backed append-only audit
storage, a multi-process lock, a size fail-closed limit, verification, and a
bounded tail reserved for fail-closed replication compensation. Individual
ordinary records are capped at half that reserve. It
is local evidence, not a forensic/WORM service: production deployments should
replicate to access-controlled encrypted remote storage. On restart, the local
sink verifies the complete existing chain before appending; corruption is a
fail-closed error that must be preserved and investigated. `SubprocessToolHandler`
provides a no-shell JSON process boundary with timeout and streaming output
limits enforced while the child process is being read; input writes are also
deadline-bounded. A
subprocess is not a complete OS sandbox; production deployments should add
container or platform isolation.

::: agentic_security.http.JsonHttpClient

::: agentic_security.adapters.HttpOpaPolicyEngine

::: agentic_security.adapters.HttpCedarPolicyEngine

::: agentic_security.adapters.HttpApprovalProvider

::: agentic_security.adapters.HttpAuditExporter

::: agentic_security.adapters.JsonlAuditSink

::: agentic_security.adapters.SubprocessToolHandler

## Telemetry

::: agentic_security.telemetry.CompositeAuditSink

::: agentic_security.telemetry.OpenTelemetryAuditSink

## Enterprise population discovery

The AWS control plane exposes a content-minimised discovery contract for
reconciling the expected Claude Code and Codex population with enrolled agents:

- `POST /api/enterprise/discovery/sources/{sourceId}/snapshots` publishes one
  complete, expiring, revision-bound identity, endpoint, or source-control
  snapshot. It requires `discovery_write`, currently limited to platform
  administrators.
- `POST` and `DELETE`
  `/api/enterprise/discovery/sources/{sourceId}/connector-credential` rotate or
  revoke a one-time-returned, digest-at-rest service credential scoped to that
  tenant and source.
- `GET /api/enterprise/discovery/sources` returns the operator-safe source
  directory: stable ID/class, credential status/revision/timestamps, and the
  latest committed snapshot's generation, revision, freshness, count and hash.
  It deliberately excludes token material, token digests, observations and
  provider payloads. Any authenticated tenant operator may read it; mutations
  remain limited to `discovery_write`.
- `/discovery-ingest/{tenantId}/{sourceId}/generations/...` lets that
  connector declare a bounded generation, upload up to 20 immutable
  exact-version S3 pages of 1,000 observations and atomically commit the
  complete generation. Partial uploads never affect the report. The service,
  not the connector, derives tenant-isolated object keys.
- `GET /api/enterprise/discovery` returns current source confidence, the
  expected-instance denominator, findings, and business-unit/repository/device
  breakdowns.
- `GET /api/enterprise/discovery/export` adds a canonical content hash for
  evidence handling.

Percentages are `null` unless every required source class is complete and
current. See [Agent population discovery](agent-discovery-design.md) and
[object-backed discovery ingestion](object-backed-discovery-ingestion-design.md) for exact
schemas, limits, credential handling, commit semantics, and trust boundaries.
The repository's `collect_discovery_inventory.py` reference adapters normalize
Entra Graph, deployment-owned endpoint exports, and GitHub repository inventory.
For endpoint fleets, `collect_endpoint_evidence.py` produces a path-free,
per-device signed installation/process report and
`assemble_endpoint_inventory.py` validates every current report against the
authoritative MDM device inventory before producing one complete endpoint
export. The `intune` mode of `collect_discovery_inventory.py` obtains that
device file from the fixed Microsoft Graph v1.0 managed-devices query with only
opaque managed-device/user IDs, the canonical Entra device registration ID
needed for later online target resolution, and optional reviewed business-unit
mappings. Endpoint reports cannot submit that registration identity.
`publish_discovery_generation.py` performs the bounded three-phase upload. See
[Endpoint evidence publisher](endpoint-evidence-publisher-design.md) for the
manifest, key, privilege and freshness boundaries, and
[hosted endpoint evidence](hosted-endpoint-evidence.md) for credential,
ingestion and health APIs. The service derives health; endpoint reports never
carry authority or a submitted health label.

## Managed endpoint delivery preflight

`GET /api/enterprise/endpoint-delivery?deploymentId=...` requires
`inventory_read` and returns a complete deployment-scoped readiness projection.
The same read is available to an exact `inventory_read` service identity at
`/machine/v1/enterprise/endpoint-delivery`. Each active agent is `ready` only
when the server derives one current managed device, one signed installation,
one active enrolled agent, signed schema-v2 operating-system/architecture
evidence, one approved runtime release and one matching approved delivery
package.

The response contains only stable IDs, status/reason codes, evidence times and
SHA-256 identities. It never contains an S3 bucket/key/version, URL, executable
bytes, installation command, signing material or provider credential. The
route is read-only and is not Intune dispatch authority. See
[Managed endpoint delivery authority](managed-endpoint-delivery-authority-design.md)
and [managed endpoint delivery user journeys](managed-endpoint-delivery-user-journeys.md).
The provider-specific group-assignment and online identity-resolution boundary
is documented in
[Microsoft Intune managed delivery](intune-managed-delivery-design.md). Hosted
Graph mutation is deployment-disabled by default, while the following governed
control-plane APIs are available:

- `GET /api/enterprise/endpoint-delivery/providers` and `/providers/intune`
  return secret-free provider lifecycle posture to `inventory_read` roles.
- `POST /api/enterprise/endpoint-delivery/providers/intune/drafts` accepts only
  canonical tenant identity, a tenant-tagged secret ARN, explicit deployment
  IDs, permission-evidence SHA-256 and rationale. It validates secret metadata
  with `DescribeSecret` and never reads its value.
- `POST /api/enterprise/endpoint-delivery/providers/intune/versions/{version}/submit`
  freezes the exact content hash under `integration_admin` authority.
- `POST .../{version}/decision` requires `provider_approval`, an independent
  subject and an approval/rejection rationale.
- `POST .../{version}/activate` requires `provider_approval`, the expected
  active version and a still-valid tenant/KMS/tag-bound secret.
- `GET /api/enterprise/endpoint-delivery/commands?deploymentId=...` returns a
  locator-free outbox view. Each command includes its bounded attempt count,
  fixed failure code and, after provider convergence, only hashed group, app
  and assignment references plus the reproduced target count. Raw Graph IDs,
  provider payloads and credentials are excluded. `dispatchEnabled` reflects
  immutable deployment state; it is not browser-controlled.

The five-minute reconciler creates an outbox command automatically from exact
live provider, rollout, deployment, agent, endpoint-evidence and package
authority. There is no browser install endpoint. The isolated FIFO worker and
repair schedule remain inert unless deployment owners supply both the exact
enablement flag and a reviewed evidence SHA-256. A worker invocation admits at
most 40 targets and reauthorizes live state before each Graph mutation.

`GET /enterprise/alerts` reconciles and returns content-minimised endpoint,
explainable behavior and independently derived repository/configuration
detections to authorized security operators. `POST
/enterprise/alerts/{alertId}/acknowledge` requires `incident_response`, an exact
live revision and a redaction-safe investigation rationale. Acknowledgement is
ownership evidence, not remediation. Behavior alerts expose only fixed signal,
count, threshold, baseline and digest metadata; raw commands, arguments,
prompts and results are excluded. Integrity alerts expose exact signal, fixed
reason codes, retained generation identities and expected/observed digests;
repository paths, remote URLs, configuration bytes and credentials are
excluded. See [Endpoint detection and response](endpoint-detection-response.md),
[Explainable agent behavior detection](behavior-detection-design.md) and
[Repository and configuration anomaly detection](repository-configuration-anomaly-design.md).

`GET /enterprise/alert-suppressions` returns retained active, expired and
revoked exact-scope records. `POST /enterprise/alert-suppressions` requires
`incident_response`, a stable ID, a 20–500-character rationale, a server-future
expiry no more than seven days away, explicit source/severity lists and at
least one exact reason, rule, deployment, agent or device selector. Wildcards
and unknown fields fail closed. `POST
/enterprise/alert-suppressions/{suppressionId}/revoke` requires the current
revision and a rationale. Suppression retains the alert but withholds outbound
delivery and automatic endpoint containment; see [Governed alert suppression
and deduplication](alert-suppression-design.md).

## Policy change assurance

`GET /enterprise/policies/{policyId}/versions/{version}` returns a typed
`changeSummary` comparing the candidate with its immutable base version. The
summary identifies individual authority expansions/restrictions, approval and
limit changes, credential/isolation requirements and data-capture changes.

`POST /enterprise/policies/{policyId}/versions/{version}/simulate` accepts only
`{"lookbackDays": N}`, where `N` is 1–90. A policy author, policy approver or
platform administrator can evaluate a pending version against at most 250
recent redacted decisions for that policy and tenant. The result is read-only,
content-hash bound and contains explicit indeterminate outcomes where command
text or MCP server identity was not retained. It never executes actions or
changes policy authority. See
[Policy change assurance](policy-change-assurance-design.md).

## Enterprise assurance reports

`GET /enterprise/reports/executive` returns an aggregate-only leadership view.
Any canonical tenant operator may read it. `GET
/enterprise/reports/auditor` requires `evidence_read` and adds bounded policy,
group and business-scope references plus least-privilege routes to detailed
evidence. These live views are derived responses and are not retained evidence.

`GET|PUT /enterprise/reports/schedule` reads or revision-guards a daily or
weekly UTC signed-snapshot schedule. Reads require `evidence_read`; writes
require `evidence_admin`, a 20–500 character rationale and the exact current
`expectedRevision`. The request is a closed object containing `enabled`,
`profile`, `cadence`, `hourUtc`, `dayOfWeek`, `expectedRevision` and
`rationale`. A fresh claimed occurrence prevents schedule changes until the
worker completes or the bounded claim expires. The response exposes
`generationStatus` as `idle`, `queued` or `quarantined`, together with
`quarantinedAt` and the content-minimised `quarantineReason`. Saving a reviewed
new revision is the only API repair path; it replaces the quarantined record
and restores a validated due-index entry. If stored revision authority itself
is malformed, reads expose opaque revision `0` and quarantine rather than
coercing the value. A save with `expectedRevision: 0` conditionally binds the
exact malformed value or its absence before replacing it with revision `1`.

`GET|POST /enterprise/reports/snapshots` lists retained snapshot metadata or
creates an operator-requested snapshot. Creation requires `evidence_admin` and
a closed `{requestId, profile, rationale}` object. Reusing a request ID with a
different actor, profile or rationale returns `409`, including concurrent
first use because the bound request claim is committed before signing. History
returns at most 100 newest records and an explicit `truncated` marker; it never
turns additional retained history into an error or performs an unbounded read.

`GET /enterprise/reports/snapshots/{snapshotId}` returns the signed document;
`POST /enterprise/reports/snapshots/{snapshotId}/verify` re-reads its exact S3
version, recomputes the report and identity-envelope hashes and verifies the
KMS signature. Executive downloads require a canonical tenant role. Auditor
downloads, all history, and auditor verification require `evidence_read`.
Roleless tenant identities are denied. A retained exact version that is
missing, corrupt or not yet available in the active Region returns `503` and
never falls back to the latest object version.

Both profiles are generated only from bounded server-owned reads. They expose
population, runtime trust, managed configuration, policy governance,
exceptions, operational work and immutable-evidence monitoring. Coverage
percentages remain unavailable when discovery sources are incomplete. Raw
paths, user names, command content, credentials and free-form decision text are
excluded. Each section and complete live report has a canonical SHA-256 digest.
A retained snapshot additionally carries a domain-separated KMS ECDSA P-256
signature binding tenant, snapshot identity, profile, source, schedule revision,
time and report digest. It proves control-plane origin and alteration detection,
not a trusted timestamp, compliance certification or independent attestation. See
[Enterprise assurance reports](enterprise-assurance-reports-design.md).

The signer is a dedicated retained multi-Region assurance key. Verification
resolves the snapshot's stable MRK identity through a deployment-owned list of
current and historical local-Region replica ARNs. Unknown, duplicate,
cross-Region or policy-signing authority fails closed.

## Service identities and machine access

Human lifecycle management uses the Cognito/Entra-protected API:

- `GET|POST /api/enterprise/identity/service-identities` lists secret-free
  posture or creates an identity;
- `POST /api/enterprise/identity/service-identities/{id}/rotate` atomically
  replaces the credential using `expectedRevision` and `expiresInDays`;
- `POST /api/enterprise/identity/service-identities/{id}/revoke` atomically
  removes authority using `expectedRevision` and a bounded rationale; and
- `GET /api/enterprise/identity/service-identities/{id}/usage` returns the
  latest 100 content-minimised admitted-request records.

Only a current platform administrator can change this authority. Create and
rotate responses contain a one-time `credential`; later reads never do.

Workloads replace `/api` with `/machine/v1` on explicitly supported enterprise
routes and send the one-time bearer. The server derives tenant and capability
from live stored state; unsupported methods/routes are denied. See
[Scoped service identities and machine API](service-identities-design.md) for
the exact capability matrix, schemas, lifecycle and non-guarantees.

Declarative clients may additionally use revision-guarded management routes:

- `PUT|DELETE /machine/v1/enterprise/skills/{id}` updates or retires a Skill
  using `expectedRevision`;
- `PUT|DELETE /machine/v1/enterprise/mcp-servers/{id}` updates or retires an
  MCP registration using `expectedRevision`;
- `PUT /machine/v1/enterprise/groups/{id}` changes name or active-policy
  binding using `expectedConfigurationRevision` without overwriting the
  independently revised membership; and
- `DELETE /machine/v1/enterprise/groups/{id}` deletes only an empty group when
  configuration and membership revisions still match.

`GET /machine/v1/enterprise/tenant` returns only the tenant bound to the live
service credential. Tenant creation and deletion are not machine API
operations. See [Terraform provider and declarative
management](terraform-provider-design.md).

## Incident cases and response authority

The hosted AWS adapter exposes a revisioned case API for endpoint, explainable
behavior and independently derived integrity detections:

- `POST /enterprise/cases` opens one deterministic case from an exact live
  alert revision. For endpoint alerts, the server—not the browser—correlates
  current managed-device inventory, fresh signed evidence, exact host identity
  and the SHA-256 of the registered project root. For behavior alerts, it
  reloads the authenticated enrolled-agent lifecycle, deployment, sole group,
  active policy and project-root digest. Integrity cases additionally bind the
  exact retained evidence digest. Neither reported behavior nor an integrity
  finding grants containment authority.
- `GET /enterprise/cases` and `GET /enterprise/cases/{caseId}` return case
  metadata, authoritative binding state, a content-minimised timeline and
  correlated decision/approval references. Detailed reads additionally return
  a typed unified investigation timeline covering identity, policy, tool, MCP,
  approval, credential, isolation, evidence and operator facts. The server
  supplies provenance, category counts, correlation-window metadata and an
  explicit completeness result; the browser does not join these sources. Raw
  endpoint payloads, free-form narrative, project roots and credentials are
  excluded. See [Unified investigation timeline](unified-investigation-timeline-design.md).
- `GET /enterprise/cases/{caseId}/export` returns schema-version `1` audit-ready
  JSON to a canonical `platform-admin`, `security-operator`,
  `incident-responder` or `auditor`. The control plane strongly reads the case,
  source alert and bounded correlated evidence; refuses truncation or concurrent
  revision changes; SHA-256 hashes canonical `content`; and persists that digest
  to the immutable audit sink before returning it. Free-form approval reasons,
  project paths, prompts, arguments, results and credentials are excluded.
- `POST /enterprise/cases/{caseId}/contain` requires the current case revision
  and binding digest. It creates a server-owned quarantine for the exactly
  bound agent. Policy delivery, approvals and managed-package retrieval fail
  closed while heartbeat and attestation evidence remain available.
- `POST /enterprise/cases/{caseId}/sessions/revoke` increments server-owned
  session authority. Existing sessions and unused bootstrap material then fail
  on their next live-authority check.
- `POST /enterprise/cases/{caseId}/credentials/revoke` requires the current
  case revision and binding digest. It creates an exact-agent control that
  blocks all current and future registered credential brokers for that agent.
- `POST /enterprise/cases/{caseId}/credentials/restore` requires exact case and
  credential-control revisions. It restores brokered authority only after the
  current binding, agent verification, source-alert recovery and absence of
  quarantine or independent stop scopes are re-established.
- `POST /machine/v1/enterprise/credential-brokers/{brokerId}/authority/check`
  is restricted to `credential_broker_runtime`. Human sessions cannot call it,
  and machine identities cannot create or restore incident controls. Runtime
  adapters call it before mint, after mint and before credential use.
- `POST /enterprise/cases/{caseId}/release` requires exact case and
  containment revisions. Release is denied unless binding remains current,
  non-response verification checks pass, no independent stop scope is active
  and the source alert is ready. Endpoint cases additionally require healthy
  endpoint evidence; behavior and integrity cases require the alert to be
  acknowledged or resolved.
- `resolve` and `close` preserve the case timeline and cannot bypass active
  containment or credential control.

All mutations require `incident_response`, a 20–500 character redaction-safe
rationale and optimistic concurrency. There is intentionally no `agentId` in a
containment request. See
[Incident case and containment design](incident-case-containment-design.md).
Credential response and recovery are specified in [Incident-driven credential
revocation](incident-credential-revocation-design.md).
Artifact schema, refusal bounds and offline verification are specified in
[Audit-ready incident case export](incident-case-export-design.md).

### Durable evidence governance

The AWS control plane exposes a tenant-bound records-management contract:

- `GET /api/enterprise/evidence` verifies the live bounded S3 version inventory
  and returns retention, legal-hold, delete-marker and content-integrity posture;
- `PUT /api/enterprise/evidence/retention` accepts exactly
  `expectedRevision`, `retentionDays` and `rationale`, permits 365–3,650 days,
  never permits a reduction and is the complete-inventory fast path;
- `POST /api/enterprise/evidence/retention-jobs` accepts exactly `requestId`,
  `expectedRevision`, `retentionDays` and `rationale`, atomically activates the
  longer future-write policy and starts a revision-bound existing-version
  backfill;
- `GET /api/enterprise/evidence/retention-jobs` and
  `GET /api/enterprise/evidence/retention-jobs/{jobId}` expose server-owned
  counts, progress, terminal failure and durable-alert delivery posture;
- `POST /api/enterprise/evidence/legal-hold` sets or clears hold for one exact
  tenant key/version after rejecting cross-tenant identity; and
- `GET /api/enterprise/evidence/export` returns a canonical content-hashed
  complete manifest only when every record fits the 250-version synchronous
  boundary and no content mismatch exists;
- `POST /api/enterprise/evidence/jobs` accepts exactly `requestId` and
  `rationale` and idempotently starts a tenant-wide point-in-time job;
- `GET /api/enterprise/evidence/jobs` and
  `GET /api/enterprise/evidence/jobs/{jobId}` expose server-owned progress and
  the completed chain-bound export index; and
- `GET /api/enterprise/evidence/jobs/{jobId}/pages/{page}` returns one completed
  page only after tenant binding, closed-schema and canonical-digest checks.

Security operators and platform administrators manage retention and legal hold.
Auditors may read assurance and export evidence but cannot mutate it. Rationale
text is content-hashed before audit persistence. See
[Durable evidence governance](durable-evidence-governance-design.md) and
[Asynchronous tenant retention](asynchronous-retention-design.md) for queue
authority, cutover, snapshot, hash-chain, schedule, alert and failure behavior.

## Detection and response rules

The hosted adapter exposes one independently governed rule API with three
closed trust boundaries:

- `GET /enterprise/response-rules` lists active authority separately from a
  pending version; `GET /enterprise/response-rules/{ruleId}` includes immutable
  versions and content-minimised execution outcomes.
- `POST /enterprise/response-rules/preview` evaluates one typed configuration
  against current retained alerts, complete bounded activity history or exact
  retained integrity authority without creating an alert, case or changing
  agent authority.
- `POST /enterprise/response-rules` creates a rule shell and version-1 draft;
  `POST /enterprise/response-rules/{ruleId}/versions` appends a draft based on
  the current active version.
- version `submit`, `decision` and `activate` routes enforce exact lifecycle
  state, independent approval, immutable content hash and optimistic active-
  version comparison.
- `POST /enterprise/response-rules/{ruleId}/disable` immediately removes new
  automatic authority; `rollback` atomically restores only an independently
  approved superseded version.
- `GET /enterprise/response-executions` returns idempotent `alerted`,
  `contained` and safely skipped outcomes without prompts, arguments, results,
  credentials or raw endpoint payloads.
- `GET /enterprise/behavior-baselines?limit=50&nextToken=...` returns a
  tenant-scoped, paginated readiness view for active agents. Each row contains
  exact-agent event bounds, migration/completeness state and rule-by-rule
  sample progress. The response declares
  `readConsistency=eventually_consistent_index`; raw prompts, tool arguments,
  results, credentials, project paths and tool identities are excluded.

The endpoint schema permits server-derived reason codes,
medium/high/critical severity, `claude-code`/`codex` host scope, fixed
`quarantine_agent` action, 1–25 actions per hour, a 300–86,400 second
per-agent cooldown and priority 1–1,000. The agent-activity schema permits only
`new_tool`, `new_mcp_server`, `denied_action_spike`,
`approval_request_spike`, `decision_volume_spike`, `outside_project_spike` and
`configuration_error_spike`; a 1–30 day lookback,
5–60 minute current window, bounded minimum sample sizes, a 1.5–10 sensitivity
multiplier and fixed `create_alert` action. Unknown fields, non-finite values,
empty selections and attempts to assign automatic containment to agent
activity are rejected. The integrity schema permits only
`repository_mapping_changed`, `managed_configuration_drift` and
`runtime_attestation_drift`, exact Claude Code/Codex host scope, fixed severity,
fixed `create_alert` action and priority 1–1,000. It accepts no statistical
sensitivity controls. Missing, stale, incomplete or malformed authority yields
`baseline_insufficient`, creates no alert or containment and marks active
detector health degraded. See [Approved automatic response
rules](automatic-response-rules-design.md), [Explainable agent behavior
detection](behavior-detection-design.md) and [Repository and configuration
anomaly detection](repository-configuration-anomaly-design.md).

## Secure webhooks

Authenticated tenant roles may read secret-free webhook posture. Only a
platform administrator may mutate destinations:

- `GET /api/enterprise/webhooks` lists destinations and the exact supported
  event-type allow-list.
- `POST /api/enterprise/webhooks` accepts exactly `name`, `description`,
  `endpoint` and `eventTypes`; it returns the HMAC secret exactly once.
- `GET /api/enterprise/webhooks/{destinationId}` returns one redacted
  destination and worker-derived last-delivery posture.
- `GET /api/enterprise/webhooks/{destinationId}/deliveries` returns up to 100
  content-free delivery records.
- `POST /api/enterprise/webhooks/{destinationId}/test` accepts only
  `expectedRevision` and queues a server-owned synthetic event.
- `POST /api/enterprise/webhooks/{destinationId}/rotate` accepts
  `expectedRevision` and `overlapSeconds` from 3,600 through 604,800, then
  returns the new secret once while retaining the previous signature authority
  for that interval.
- `pause`, `resume` and `retire` accept `expectedRevision` plus a 20–500
  character operational reason. Retirement is irreversible through this API.

Secrets Manager names, versions, ARNs and key bytes are never returned by a
read. Event payloads cannot be supplied by an operator. See
[Secure webhooks](secure-webhooks-design.md) for signature headers, replay,
retry and receiver requirements.

## Governed incident workflows

Authenticated tenant roles may read secret-free connection and delivery
posture. Only `integration_admin` authority may create, verify, activate,
pause, resume, retire or retry. Provider credential values are not accepted by
any API route; administrators create an AWS Secrets Manager value separately
and submit only its exact tenant-namespaced ARN.

- `GET /api/enterprise/workflow-integrations` lists connections plus the exact
  supported providers and lifecycle events.
- `POST /api/enterprise/workflow-integrations` accepts exactly `name`,
  `description`, `provider`, `configuration`, `credentialSecretArn` and
  `eventTypes`. New connections are `pending_verification`.
- `GET /api/enterprise/workflow-integrations/{connectionId}` returns one
  secret-free connection and worker-derived verification/delivery posture.
- `GET /api/enterprise/workflow-integrations/{connectionId}/deliveries`
  returns at most 100 content-minimised delivery records.
- `POST /api/enterprise/workflow-integrations/{connectionId}/verify` accepts
  only `expectedRevision` and queues a server-owned synthetic incident.
- `POST /api/enterprise/workflow-integrations/{connectionId}/{action}` accepts
  `expectedRevision` and a 20–500-character `reason`; action is `activate`,
  `pause`, `resume` or `retire`. Activation/resume require successful proof of
  the exact pre-transition revision.
- `POST /api/enterprise/workflow-integrations/{connectionId}/deliveries/{deliveryId}/retry`
  accepts `expectedAttemptCount` and a 20–500-character `reason`. It requires a
  terminal failed delivery and unchanged active connection revision, then
  creates a new linked queue identity.

ServiceNow accepts exactly `baseUrl` and `assignmentGroup`; Jira accepts
`baseUrl`, `projectKey` and `issueType`; PagerDuty accepts only `serviceLabel`.
Supported events are `case.opened`, `case.contained`, `case.resolved` and
`case.closed`. See [Governed incident workflow
integrations](incident-workflow-integrations-design.md) for queue semantics,
credential schemas, provider mappings and residual risks.

## Enterprise data-boundary posture

`GET /api/enterprise/data-boundary` is a read-only authenticated operator
route. It returns deployment-owned encryption, residency, network-access,
deletion and acceptance posture. The response exposes only the final eight
characters of the KMS key identity and the count of approved networks; it does
not return key ARNs, CIDRs or evidence-reference values.

In `ip-restricted` mode, every human tenant route checks API Gateway's
`requestContext.http.sourceIp` against the persisted IPv4 allow-list. In
`private-link` mode, the private REST API first enforces an exact
`aws:SourceVpce` resource-policy condition and Cognito authorization; Lambda
then requires the exact private API ID and `requestContext.identity.vpceId`.
Missing, malformed or mismatched context returns HTTP 403 before tenant
resolution. Forwarding headers cannot override either decision.
Machine, SCIM, enrollment, discovery, endpoint and agent routes keep their
separate authentication boundaries.

The route reports `allowedNetworkCount`, `allowedVpcEndpointCount` and
`privateLinkConfigured` without exposing addresses or endpoint IDs.
`approvedDataRegions` covers retained application data; it
does not claim that CloudFront, Cognito, Entra or other global providers process
only in those Regions. See [Enterprise data boundary](enterprise-data-boundary-design.md).

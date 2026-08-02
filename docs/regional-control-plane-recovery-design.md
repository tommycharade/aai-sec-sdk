# Regional control-plane recovery design

## Decision

P0-11 uses a fail-closed, active-passive AWS design. The first-customer target
is a fleet of 1,000 enrolled Claude Code or Codex agents, a 30-minute recovery
time objective (RTO), and a 60-second recovery point objective (RPO) for
authoritative DynamoDB state. These are engineering targets until a customer
security owner approves the manifest's evidence reference and a live exercise
meets them. They are not a contractual SLA.

The recovery cell is `eu-west-1`; the current primary is `eu-west-2`. No second
cell may receive production traffic merely because its resources exist. A
regional activation must prove identity, signing-key trust, global-table
replication, immutable audit posture, queue reconciliation, endpoint routing
and operator authority before it changes traffic.

## Risk and trust boundary

A partial recovery can be worse than an outage. A second API with stale policy,
identity, approval or idempotency state can widen authority, replay an action,
or create two conflicting control planes. The design therefore treats every
regional dependency as part of one security boundary:

```text
operator/agent endpoint
  -> one advertised active cell
  -> replicated identity and policy signing trust
  -> replicated policy, approval, session and idempotency state
  -> Region-local workers and queues reconciled from authoritative records
  -> bidirectional immutable audit persistence
```

During an unproven outage, enrolled runtimes retain no implicit bypass. The MCP
gateway stops execution when heartbeats or policy refresh fail. A signed policy
cached on disk can prove policy integrity, but it does not prove current
emergency-stop, revocation, approval or session state and therefore does not
authorize disconnected operation.

## Architecture

### Authoritative data

The control, presence, idempotency and SCIM lifecycle tables become DynamoDB
Global Tables with `NEW_AND_OLD_IMAGES` streams, deletion protection and
point-in-time recovery in both Regions. The first phase uses multi-Region
eventual consistency because the existing TTL-backed tables cannot be converted
to multi-Region strong consistency without a new-table data migration: MRSC
does not support TTL.

MREC is not a distributed lock. The system therefore remains active-passive.
Only one control-plane endpoint may be advertised, the recovery API starts in a
non-serving posture, and activation is a controlled operation rather than an
automatic health-check reaction. The exercise measures actual create and
delete replication for all four tables. A result above 60 seconds prevents
activation.

Region-local SQS messages are delivery mechanisms, not authority. Jobs,
revisions, approvals and idempotency records remain in DynamoDB. Recovery
workers reload those records before doing work; missing or conflicting state
fails closed. The activation runbook reconciles pending and stale jobs instead
of copying queue messages.

### Identity

Amazon Cognito native multi-Region replication is the target identity design.
The primary pool must use the Essentials or Plus plan, a multi-Region KMS key
and a multi-Region issuer before an `ACTIVE` replica is created. Microsoft Entra
remains the first federation provider. Entra OIDC and SCIM configuration stays
tenant-bound and secret values stay in Secrets Manager.

The secondary Cognito pool can authenticate existing users during failover but
has documented limitations, including no user creation/profile mutation and no
TOTP MFA in the secondary. Enterprise activation therefore requires Entra
federation with Conditional Access evidence; native TOTP-only users are not an
accepted recovery population. Until real Entra and Cognito replication are
configured and exercised, identity recovery remains incomplete.

### Policy signing

The deployed signing key is single-Region and cannot be converted in place.
The primary stack therefore stages a retained P-256 multi-Region signing key
without making it active. The safe migration is:

1. Create its KMS replica in the recovery Region.
2. Publish an endpoint trust bundle containing both old and new public keys.
3. Prove every governed endpoint has the overlapping bundle.
4. Switch new policy signatures to the multi-Region key.
5. Exercise verification and signing in both Regions.
6. Keep the old key trusted for all still-valid historical bundles.

Creating the staged key is not signer cutover evidence. The stack continues to
set `POLICY_SIGNING_KEY_ARN` to the existing key until the measured rollout is
complete.

### Audit and evidence

The existing S3 replica already proves exact immutable recovery for retained
evidence. Before the recovery cell can write audit events, two-way replication
and replica-modification sync must be enabled and independently verified. This
ensures direct writes during failover return to the former primary without
shortening Object Lock retention. Delete markers remain excluded because they
are not retained evidence.

The phase-5 implementation and its fail-closed job planner are specified in
[Evidence continuity and recovery-job reconciliation](evidence-continuity-and-job-reconciliation-design.md).
The guarded deployment and retained two-direction canary passed on 2026-08-02;
see the [phase-5 acceptance](evidence-continuity-acceptance-2026-08-02.md).
This does not activate or accept the passive control plane.

### API, UI and routing

The passive cell will contain Region-local Lambda, API Gateway, SQS/SNS,
EventBridge schedules, CloudWatch alarms and a UI origin. A production customer
supplies a custom API/authentication domain and certificates. A controlled
Route 53 or AWS ARC Region Switch operation then advertises one cell.

The public `execute-api` origins must not become an alternate bypass route once
custom routing is enabled. Recovery activation must also update the UI's API
and Cognito issuer configuration atomically from a reviewed deployment
manifest. Agents use the stable managed endpoint; they are not asked to edit
every project during an incident.

The first passive-cell implementation intentionally has no executable
authority: Lambda reserved concurrency is zero, schedules and queue mappings
are disabled, the `execute-api` origin is disabled, the UI bucket is private,
and runtime roles have no table-write, audit-write, queue-send or signing
permission. See the [passive regional cell design](passive-regional-cell-design.md).
Activation requires a separately reviewed CloudFormation change; DNS alone is
not treated as the active/passive lock.

## Delivery phases and acceptance gates

| Phase | Deliverable | Activation permitted? |
| --- | --- | --- |
| 1. Storage foundation | Streams, PITR, deletion protection, four active Global Table replicas, measured canaries, staged signing key | No |
| 2. Trust foundation | Multi-Region signing-key replica and measured endpoint trust overlap | No |
| 3. Identity foundation | Cognito MRR, Entra OIDC/SCIM, Conditional Access and joiner/mover/leaver exercise | No |
| 4. Passive cell | Full API/workers/alerts/UI with schedules disabled and direct-origin bypass closed | No |
| 5. Evidence continuity | Two-way Object Lock replication and worker/job reconciliation | No |
| 6. Recovery exercise | Load, dependency failure, regional failover, emergency access, key recovery and failback within targets | Yes, after approval |

Acceptance requires retained evidence that:

- all four table replicas are active and match schema, PITR and deletion posture;
- canary create/delete replication is within RPO;
- policy, identity, approvals, sessions and idempotency do not widen or replay;
- every still-valid policy verifies before and after signer/cell transition;
- audit writes made in either Region have exact immutable counterparts;
- 1,000 simulated agents meet heartbeat, policy-read and decision-ingest load;
- dependency failures stop execution and do not activate a bypass;
- backup restore, KMS recovery, emergency access and return-to-service are
  rehearsed within RTO.

## Cost position

The implementation deliberately avoids an ARC routing-control cluster for the
first-customer tier: AWS currently prices one at $2.50/hour, approximately
$1,825/month. ARC Region Switch is a more appropriate optional enterprise
upgrade at $70/month per plan.

The passive serverless cell has low fixed cost. At pilot volume, the working
planning range is **$10–$30/month plus usage**, before optional Region Switch:

- Global Tables duplicate storage and bill replicated writes in each Region;
- the staged primary and eventual replica KMS keys are each billed as a key;
- passive Lambda, API Gateway, SQS/SNS and CloudWatch are usage-based;
- Cognito MRR Essentials is $0.0045 per monthly active user in the replica
  Region, plus a 30% M2M add-on;
- Route 53, logs, backup storage and cross-Region restore add small variable
  charges.

This range must be recalculated from observed requests, storage, retention and
operator MAU before a customer quote. See the authoritative AWS pricing pages
for [DynamoDB](https://aws.amazon.com/dynamodb/pricing/),
[Cognito](https://aws.amazon.com/cognito/pricing/) and
[Application Recovery Controller](https://aws.amazon.com/application-recovery-controller/pricing/).

## Non-guarantees

The storage foundation alone is not regional failover. It does not replicate
Cognito, create a recovery API, activate a multi-Region signer, provide
bidirectional audit writes, route agents, prove load, or approve an SLA. The UI
must continue to show P0-11 as partial until every phase and live exercise is
complete.

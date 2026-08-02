# Evidence continuity and recovery-job reconciliation

## Decision

P0-11 phase 5 uses two independent recovery mechanisms:

1. S3 replicates immutable audit versions in both directions, including replica
   retention, legal-hold and tag modifications.
2. Recovery queues are reconstructed from authoritative DynamoDB job records.

Neither mechanism activates the passive control plane. Live acceptance remains
blocked until both synthesized directions, provider configuration and a
two-direction canary have passed under an approved recovery change.

## Immutable evidence contract

The primary and recovery buckets are versioned, private, TLS-only and use a
365-day COMPLIANCE Object Lock default. Each direction has one enabled V2
replication rule over the complete namespace with:

- the exact opposite bucket ARN as destination;
- `ReplicaModifications` enabled;
- delete-marker replication disabled;
- replication metrics enabled; and
- an S3 service role limited to version, retention and legal-hold reads plus
  `ReplicateObject`, `ReplicateDelete` and `ReplicateTags` on the exact
  destination object namespace.

`ReplicateDelete` is an S3 replication service action; it is not
`DeleteObject`, `DeleteObjectVersion` or authority to create an evidence delete
marker. The template verifier rejects destructive actions, wildcards,
`NotAction`, a substituted destination, missing Object Lock, shortened default
retention, enabled delete markers or disabled replica-modification sync.

The recovery bucket can still be deployed in `destination-only` posture before
the primary ARN is known. That posture is not evidence-continuity readiness.
Supplying only one of the primary ARN or Region fails synthesis, and the two
Regions must be distinct.

## Queue and job recovery contract

SQS contains delivery hints, not authorization. It is Region-local and is
never copied, inspected to choose a winner or treated as completion evidence.
The durable control Global Table remains authoritative for:

- tenant and job identity;
- job class and lifecycle state;
- exact optimistic revision;
- evidence inventory cursor and committed page count;
- retention-policy revision and application-job binding; and
- terminal completion or failure.

The internal `aai.regional-recovery-jobs` event has an exact schema and two
modes. `check` is read-only and can run while the cell is in standby. `apply`
requires both `PASSIVE_CELL_MODE=active` and
`RECOVERY_JOB_RECONCILIATION_ENABLED=true`; the passive and primary templates
set the latter to `false`. Standby IAM also lacks table-write, audit-write and
queue-send authority.

For each bounded tenant shard, reconciliation:

- dispatches a queued assurance job at its exact current revision;
- terminally fails a stale running assurance job so a later scheduled scan can
  create a fresh point-in-time snapshot;
- dispatches a due/queued or stale-running retention job only when its exact
  policy revision and application-job binding still match; and
- defers fresh running work rather than racing a worker.

More than one active job of either class, malformed identity/revision, an
unbound retention job, an oversized shard or pagination beyond the safe bound
fails the whole reconciliation. FIFO deduplication IDs are deterministic from
job ID and revision. Workers reload the server-owned record and condition every
commit on that revision, so replayed or stale messages cannot repeat committed
authority.

The activation evidence reference is validated but not retained in clear text;
the result exposes only its SHA-256. It is correlation evidence, not activation
authority.

## Required deployment and acceptance order

1. Derive both bucket ARNs, Regions and account from the persisted recovery
   authority and live CloudFormation/S3 state.
2. Synthesize the recovery replica with the exact primary bucket ARN and run
   `verify_aws_evidence_continuity.py` against the resulting template.
3. Update the recovery stack, then synthesize and verify the primary rule with
   the exact recovery ARN before updating the primary stack.
4. Read both live S3 replication configurations and confirm rule, role and
   Object Lock posture match the verified templates.
5. Write one synthetic COMPLIANCE-locked version in each Region. For each,
   prove the counterpart has the same key, version, bytes, digest metadata,
   retention and replication provenance.
6. Extend retention and change a synthetic tag on each replicated version;
   prove replica-modification sync returns the change without shortening either
   side.
7. Invoke job reconciliation in `check` mode and retain the redacted plan.
8. During an approved recovery exercise only, activate/fence the cell, grant
   the reviewed runtime authority and invoke `apply`. Prove every dispatched
   revision reaches a terminal or deliberately deferred state.

The synthetic retained objects are evidence and are not deleted. A successful
template check is not a live recovery acceptance result.

The supported operator entry point is
`scripts/deploy_aws_evidence_continuity.py`. It requires both strict manifests
and uses four explicit commands: `check` synthesizes and verifies without AWS
mutation; `prepare --confirm-authority` persists the reviewed non-activation
authority; `deploy --confirm-replication-deployment` updates the exact verified
assemblies and re-reads provider state; and `canary --confirm-retained-canary`
writes and verifies the two retained synthetic versions. The checked-in
manifests are
`infra/aws-control-plane/evidence-continuity.example.json` and
`infra/aws-control-plane/regional-recovery.example.json`.

## Threats and controls

| Threat | Control | Failure posture |
| --- | --- | --- |
| Split evidence after failover writes | Two-way replication plus replica-modification sync | Recovery activation is refused |
| Retention is shorter in one Region | COMPLIANCE defaults and exact-version retention comparison | Verification fails; no acceptance |
| Queue replay repeats a page or retention mutation | Revision-bound FIFO messages and conditional DynamoDB commits | Stale message is ignored or repairs only the recorded next revision |
| A stale queue is copied across Regions | Queue contents are never read by reconciliation | Jobs are rebuilt only from DynamoDB |
| Ambiguous jobs cause last-writer-wins recovery | More than one active job is a hard conflict | Entire reconciliation fails closed |
| Reconciliation is invoked in standby | Two environment gates plus read-only standby IAM | Apply raises before dispatch |
| Template intent hides broad IAM | Independent CloudFormation verifier checks exact actions | Deployment evidence is rejected |

## Current status

The infrastructure, provider-state deployment guard, independent verifier,
adversarial tests and standby reconciliation planner are implemented. Both
directions were deployed from exact verified assemblies and passed the retained
two-direction canary on 2026-08-02. The acceptance evidence is recorded in
[Evidence continuity acceptance](evidence-continuity-acceptance-2026-08-02.md).
P0-11 remains partial because identity, passive-cell activation, routing, load
and full failover/failback acceptance are separate phases.

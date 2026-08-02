# Regional transition witness and journal

## Decision

Regional transition authority uses one DynamoDB witness in a third AWS Region.
It is deliberately **not** a Global Table. DynamoDB Global Tables reconcile
concurrent writes with cross-Region last-writer-wins behavior and therefore
cannot provide the strongly consistent compare-and-swap needed to prove that
only one failover or failback owns authority.

The first-customer topology is:

```text
primary runtime (eu-west-2) ─┐
                             ├─ strongly consistent CAS ─ witness (eu-central-1)
recovery runtime (eu-west-1) ┘
```

Loss of the witness fails closed: an in-progress step can be inspected, but no
new transition or phase advancement is permitted. This adds a third-Region
dependency in exchange for removing the split-brain ambiguity of replicated
coordination state.

## Infrastructure boundary

`AaiSecRegionalTransitionJournal` contains exactly:

- one DynamoDB on-demand table with string `pk`/`sk` keys, point-in-time
  recovery, deletion protection and retained replacement/deletion policy;
- one retained customer-managed KMS key with annual rotation and a 30-day
  deletion window; and
- one KMS alias.

It contains no Lambda, IAM role/policy, API, queue, scheduler, DNS, CloudFront,
Global Accelerator or Route 53 Recovery Control resource. The synthesized
template must have no DynamoDB `Replicas` property and reports
`uninitialized-single-writer-witness`.

The deployment guard is `scripts/deploy_aws_transition_journal.py`. Its strict
manifest sets `activationPermitted: false`, fixes all three Regions and the
table/stack names, and is persisted as an encrypted SSM parameter. The guard
strips ambient CDK authority, derives the AWS account through STS, verifies the
template, binds its SHA-256 and deploys only the exact `cdk.out` assembly. It
cannot initialize the journal.

## Schema-v2 and schema-v3 transition authority

Mutating transition commands reject legacy schema-v1 manifests. Schema v2 adds:

| Field | Purpose |
| --- | --- |
| `coordinationRegion` | Exact third Region containing the witness |
| `journalTableName` | Exact single-writer table identity |
| `expectedRoutingGeneration` | CAS generation observed before approval |
| `approvals` | Exactly two independently authenticated human approvals |

Each approval contains a canonical Microsoft Entra principal UUID, opaque
evidence reference, approval time and strong-authentication time. The two
principal IDs and evidence references must differ. Approval must be no more
than one hour old and its strong-authentication event no more than five minutes
before approval. The complete sorted approval set, witness identity and expected
generation are included in `authoritySha256`; the retained activation bundle
must contain that digest.

The journal stores only principal-independent SHA-256 approval evidence in its
events. It does not store tokens, claims, secrets or approval content.

Routing requires schema v3. It additionally binds the exact primary and
recovery ingress stack names, four Region-specific canary names, stable-route
generation marker, dedicated routing-role ARN and retained routing-authority
evidence reference. Schema v2 remains valid for non-routing runtime steps but
is rejected before ingress journaling or Route 53 access.

## State model

The strongly consistent singleton record is `pk=AUTHORITY, sk=CURRENT`.
Generation changes only in the future routing CAS step; revision changes on
every journal phase.

```text
STABLE
  -> FENCING_SOURCE
  -> SOURCE_FENCED
  -> ACTIVATING_TARGET
  -> TARGET_ACTIVE_NOT_ROUTED
  -> RECONCILING_TARGET_JOBS
  -> TARGET_JOBS_RECONCILED_NOT_ROUTED
  -> VERIFYING_TARGET_INGRESS
  -> TARGET_INGRESS_VERIFIED_NOT_ROUTED
  -> ROUTING_TARGET
  -> VERIFYING_STABLE_ROUTE
  -> STABLE (generation + 1, activeRegion = target)
```

Every phase change is one DynamoDB transaction containing:

1. a conditional update of the singleton with exact phase, revision,
   generation, source Region, transition UUID, authority digest, evidence
   digest, approval digest and expiry; and
2. an append-only transition event whose key includes revision and phase.

The source-fence claim moves `STABLE` to `FENCING_SOURCE` before any EventBridge,
event-source-mapping or Lambda mutation. Target activation moves
`SOURCE_FENCED` to `ACTIVATING_TARGET` before CDK deployment. Completion is
recorded only after independent provider verification or successful exact
assembly deployment.

If a process stops mid-step, the in-progress phase remains. The same transition
with byte-equivalent authority may resume that step. A different transition,
changed approver, changed evidence, changed generation, expired authority or
out-of-order command is denied. A completed phase is idempotent and does not
append a duplicate event.

Target reconciliation claims its in-progress phase before the first job
dispatch. Completion appends a SHA-256 over the independently verified source
fence, live target resource set, check/apply results and final zero-action
check. An idempotent completed retry must present that exact digest.

Ingress and route phases follow the same revision CAS. Stable completion is a
single DynamoDB transaction that increments generation, changes active Region,
removes active-transition fields and appends the final immutable evidence
event. An exact retry verifies the existing event digest; a changed stable
probe or substituted authority is denied.

## Initialization

The stack starts with no authority record. After deployment, the guarded
executor exposes a separate `initialize-journal` command requiring
`--confirm-journal-initialization`. It still repeats full provider preflight and
requires schema-v2, two-person, generation-zero failover authority. It can
create only:

- `activeRegion = primaryRegion`;
- `generation = 0`;
- `phase = STABLE`; and
- `revision = 0`.

The conditional transaction fails if either singleton or initialization event
already exists. Initialization cannot select recovery as active, activate a
runtime or route traffic.

## Deployment sequence

Copy the synthetic deployment example outside the repository and replace its
approval reference:

```bash
python3 scripts/deploy_aws_transition_journal.py check \
  --config /absolute/path/to/transition-journal.json --profile p1

python3 scripts/deploy_aws_transition_journal.py prepare \
  --config /absolute/path/to/transition-journal.json --profile p1 \
  --confirm-persist-authority

python3 scripts/deploy_aws_transition_journal.py deploy \
  --config /absolute/path/to/transition-journal.json --profile p1 \
  --confirm-uninitialized-deployment
```

Then create a short-lived schema-v2 activation manifest and retained evidence
bundle. Initialization is a different confirmed command:

```bash
python3 scripts/deploy_aws_active_cell.py initialize-journal \
  --manifest /absolute/path/to/activation-manifest-v2.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --evidence-continuity-config /absolute/path/to/evidence-continuity.json \
  --passive-cell-config /absolute/path/to/passive-cell.json \
  --profile p1 \
  --confirm-journal-initialization
```

## Threats and evidence

| Threat | Control | Evidence |
| --- | --- | --- |
| Two Regions claim transition ownership | Third-Region single writer, consistent read and transactional CAS | No `Replicas`; exact conditional expressions |
| Stale plan follows another route change | `expectedRoutingGeneration` in retained authority | Generation mismatch denied before mutation |
| One operator self-approves | Exactly two distinct Entra UUIDs and evidence refs | Approval digest in every journal event |
| Approval substitution | Sorted approvals included in `authoritySha256` | Retained bundle identity check fails |
| Process dies after partial AWS mutation | In-progress phase is committed first | Same exact authority can resume; competitors denied |
| Event replay or overwrite | Revision/phase event key plus `attribute_not_exists` | Transaction fails atomically |
| Witness becomes replicated | Independent template and live table posture verifiers | Deployment/execution denied |
| Table/key is removed | Deletion protection, PITR and retain policies | Template/live posture denied if weakened |

Tests cover weak/duplicate approvals, stale strong authentication, Region
substitution, generation replay, wrong active source, competing transitions,
provider CAS races, out-of-order phases, retry idempotency, malformed journal
records, weakened table posture, replicated infrastructure, unknown runtime
resources, ambient deployment substitution and post-verification template
replacement.

## Current non-guarantees

Stable ingress, public authenticated smoke, journal-governed transactional
Route 53 movement and transition sealing are implemented but have not been run
against live customer domains. Primary reactivation, safe rollback and
failback remain deliberately unavailable. The live witness is not deployed or
initialized. Those gates and a retained exercise remain required before P0-11
is complete.

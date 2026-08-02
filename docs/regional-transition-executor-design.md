# Guarded regional transition executor

## Outcome and boundary

`scripts/deploy_aws_active_cell.py` implements the first three mutable recovery
steps without implementing traffic movement. It can independently check an
active-but-not-routed target, fence source execution, deploy the exact verified
target assembly, or reconcile the live target runtime and Region-local jobs. It
cannot update DNS, CloudFront, Route 53, Global Accelerator, custom domains or
API routing.

A successful target deployment means **active-not-routed**, not “failover
complete.” The recovery cell has no SCIM endpoint. Existing recovery identities
can use the runtime during an outage, but joiner/mover/leaver changes remain
unavailable until primary identity lifecycle or a later reviewed regional SCIM
design recovers.

## One command, one transition step

Every command first repeats the complete live provider preflight described in
the [regional activation design](regional-activation-and-exercise-design.md).

| Command | Mutation | Additional proof |
| --- | --- | --- |
| `check` | None | Derives persisted identity/signing authority, verifies the journal, and verifies the active-but-not-routed template |
| `initialize-journal` | Creates only generation-zero primary `STABLE` authority | Requires schema-v2 two-person authority and `--confirm-journal-initialization` |
| `fence-source` | Claims `FENCING_SOURCE`, disables source rules/mappings and all source-stack Lambda concurrency, then records `SOURCE_FENCED` | Requires `--confirm-source-fence` and independently reads every resulting state |
| `activate-target` | Claims `ACTIVATING_TARGET`, deploys the exact verified CDK assembly, then records `TARGET_ACTIVE_NOT_ROUTED` | Requires `--confirm-target-activation` and a newly verified complete source fence |
| `reconcile-target` | Claims `RECONCILING_TARGET_JOBS`, verifies exact live target authority and rebuilds Region-local work from DynamoDB, then records `TARGET_JOBS_RECONCILED_NOT_ROUTED` | Requires `--confirm-target-reconciliation`, active-not-routed provider state and a bounded zero-action final check |

The commands cannot be combined. A later command repeats preflight rather than
trusting prior terminal output. Source ingress is disabled before Lambda
concurrency, the complete bounded mutation set is attempted, and any partial
failure is reported as failure. Target activation never routes traffic.
Mutating commands require the [single-writer transition journal](regional-transition-journal-design.md),
schema-v2 authority, an exact expected routing generation and two independently
strong-authenticated Entra principals.

## Authority binding

The retained bundle includes `authoritySha256`, a digest over the manifest’s
transition, direction, Regions, stable domains, hosted zone, fleet/RTO/RPO
targets, approval reference, expiry and manual-activation flags. This prevents
valid evidence being replayed with a substituted domain, zone or approval.

The verifier returns the exact Entra tenant UUID and recovery signing-key ARN.
Active synthesis accepts them only when they match the encrypted persisted
Entra manifest, live recovery-key output and retained evidence. Account, table,
bucket, pool and client identities are provider-derived. Ambient authority
values are discarded before active values are added from verified sources.

## Source fence

The executor requires a stable primary CloudFormation stack, paginates its
resources, and accepts at most 50 Lambda functions, 20 event-source mappings
and 50 EventBridge rules. Duplicate, missing or malformed identities fail
closed. The sorted exact resource set is SHA-256-bound into operator evidence.

Fencing proceeds in this order:

1. disable every discovered EventBridge rule;
2. disable every discovered Lambda event-source mapping;
3. set reserved concurrency to zero on every discovered source Lambda; and
4. independently re-read every rule, mapping and concurrency value.

The source is fenced only when every rule is `DISABLED`, every mapping is
`Disabled`, and every function reports exactly zero reserved concurrency. This
hard fence may make the primary UI/API unavailable and belongs only in an
approved recovery window.

## Active template verification

The independent CloudFormation verifier requires:

- exactly three bounded Lambdas with concurrency `100`, `5`, and `5`;
- exact activation digest, Entra tenant, AAI tenant and recovery signing key on
  every Lambda;
- enabled queue mappings and schedules;
- disabled raw execute-api access and no routing resources or domain outputs;
- exactly two private, encrypted, versioned buckets, each covered by its own
  TLS-only policy; and
- an exact reviewed 40-action IAM allow-list, scoped signing key, no role
  assumption, no administrative services and no unexpected wildcard resource.

The template SHA-256 is checked again immediately before CDK deployment.
Deployment uses `--app cdk.out`, so source re-synthesis cannot change the
reviewed assembly.

## Operator sequence

Keep all reviewed authority files outside source control. First run `check`:

```bash
python3 scripts/deploy_aws_active_cell.py check \
  --manifest /absolute/path/to/activation-manifest.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --evidence-continuity-config /absolute/path/to/evidence-continuity.json \
  --passive-cell-config /absolute/path/to/passive-cell.json \
  --profile p1
```

Only inside the approved outage window, run one confirmed source step:

```bash
python3 scripts/deploy_aws_active_cell.py fence-source \
  --manifest /absolute/path/to/activation-manifest.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --evidence-continuity-config /absolute/path/to/evidence-continuity.json \
  --passive-cell-config /absolute/path/to/passive-cell.json \
  --profile p1 \
  --confirm-source-fence
```

After independent review, activate but do not route the target:

```bash
python3 scripts/deploy_aws_active_cell.py activate-target \
  --manifest /absolute/path/to/activation-manifest.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --evidence-continuity-config /absolute/path/to/evidence-continuity.json \
  --passive-cell-config /absolute/path/to/passive-cell.json \
  --profile p1 \
  --confirm-target-activation
```

After the stack reports `active-not-routed`, reconcile the exact live target:

```bash
python3 scripts/deploy_aws_active_cell.py reconcile-target \
  --manifest /absolute/path/to/activation-manifest.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --evidence-continuity-config /absolute/path/to/evidence-continuity.json \
  --passive-cell-config /absolute/path/to/passive-cell.json \
  --profile p1 \
  --confirm-target-reconciliation
```

Exit code `2` is fail-closed. Never treat terminal output as permission to move
traffic. Public-ingress smoke, routing CAS, transition sealing, primary
reactivation, failback and retained live RTO/RPO evidence remain separate
incomplete gates. See [Regional target readiness and stable ingress](regional-target-readiness-and-stable-ingress-design.md).

## Test evidence and non-guarantees

Focused tests cover unstable/duplicate discovery, bounded pagination, resource
digest binding, ordered fencing, partial mutation failure, independent state
reads, identity/signing substitution, exact assembly deployment, unknown IAM
actions, mismatched bucket policies and absence of routing commands. CI
synthesizes standby and synthetic active variants with separate verifiers.

No live AWS mutation was performed by this tranche. P0-11 remains **Partial**
until real identity, trust, stable-origin, passive/witness deployment,
routing CAS and rehearsed exercise gates all pass.

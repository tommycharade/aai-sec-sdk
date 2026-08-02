# Guarded regional transition executor

## Outcome and boundary

`scripts/deploy_aws_active_cell.py` implements the first three mutable regional
steps without implementing traffic movement. It can independently check an
active-but-not-routed target, fence source execution, deploy the exact verified
recovery assembly, restore an exact template-bound primary target, or reconcile
the live target runtime and Region-local jobs in either direction. It
cannot update DNS, CloudFront, Route 53, Global Accelerator, custom domains or
API routing. Routing is isolated in `scripts/execute_aws_regional_routing.py`,
which requires schema-v3 or schema-v4 authority and cannot activate target
compute. Schema v4 is mandatory for source restoration and rollback.

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
| `activate-target` | Claims `ACTIVATING_TARGET`, deploys the exact recovery assembly for failover or restores the exact processed-template primary runtime for failback, then records `TARGET_ACTIVE_NOT_ROUTED` | Requires `--confirm-target-activation`, schema-v4 authority and a newly verified complete source fence |
| `reconcile-target` | Claims `RECONCILING_TARGET_JOBS`, verifies exact live target authority and rebuilds Region-local work from DynamoDB, then records `TARGET_JOBS_RECONCILED_NOT_ROUTED` | Requires `--confirm-target-reconciliation`, direction-bound target state and a bounded zero-action final check |

The routing component exposes three forward steps: `verify-ingress`
proves invalid-token rejection, authenticated policy read and HSTS UI delivery
on target canaries; `route-target` repeats source-fence, target-runtime and
zero-action reconciliation proofs before one transactional Route 53 batch;
and `verify-stable` repeats stable API/UI probes before committing the next
journal generation. Each has a distinct confirmation flag.

If stable verification fails after Route 53 accepted the forward batch, five
separately confirmed rollback steps are available under schema-v4 authority:

| Command | Mutation or proof | Required confirmation |
| --- | --- | --- |
| `fence-failed-target` | Fences every target rule, mapping and Lambda and independently verifies it | `--confirm-failed-target-fence` |
| `reactivate-source` | Restores the exact approved source-template runtime while the target remains fenced | `--confirm-source-reactivation` |
| `verify-source-ingress` | Proves invalid-token denial, authenticated policy read and HSTS on source canaries | `--confirm-source-ingress` |
| `route-source-rollback` | Atomically replaces target aliases/marker with source aliases and generation + 2 | `--confirm-rollback-route53` |
| `verify-source-rollback` | Probes stable API/UI and seals `ROLLED_BACK` in the witness | `--confirm-rollback-completion` |

Generation advances by two because generation + 1 identifies the failed
target route and generation + 2 identifies the restored source. This avoids an
ABA state where DNS appears to return to its original generation.

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

The verifier returns the exact Entra tenant UUID and target signing-key ARN.
Failover synthesis accepts them only when they match the encrypted persisted
Entra manifest, live recovery-key output and retained evidence. Failback binds
the same Entra authority to the live primary regional signer and normal primary
policy signer. Account, table, bucket, pool and client identities are
provider-derived. Ambient authority values are discarded before active values
are added from verified sources.

## Source fence

The executor requires the exact stable source CloudFormation stack, paginates its
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

## Source reactivation boundary

Schema v4 adds the primary and recovery runtime stack names and exact SHA-256
digests of their processed CloudFormation templates. Before the original
source is fenced, the executor downloads the provider-processed template,
maps its bounded logical resources to exact physical resources, and records a
typed restoration plan. Lambda reserved concurrency may be absent or a literal
bounded integer; event-source mappings default enabled; EventBridge rules
default enabled. Dynamic or ambiguous values fail closed.

Rollback re-derives the plan and requires the processed-template digest to
match retained authority. It first proves the failed target is completely
fenced, proves the exact current source physical-resource set is also still
fenced, restores all source Lambda concurrency, mappings and rules, and then
independently re-reads every resource. Partial mutation is failure, never
success. If a process stops after the reactivation claim, an exact retry first
re-proves the target fence and then reapplies the bounded approved source plan;
it does not require partially restored source resources to be fenced again.
The source canary must pass before stable DNS can move.

This follows AWS's [processed-template contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_GetTemplate.html),
uses [delete-function-concurrency](https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunctionConcurrency.html)
to restore functions that had no reservation, and restores exact
[EventBridge rule state](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-rule.html).

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

## Primary failback target

Planned failback does not deploy the recovery template under a different name.
After recovery is fenced, the adapter re-derives the primary restoration plan
from the exact schema-v4 processed-template digest and proves the primary was
still fenced before the first restoration mutation. It then restores the
complete bounded function/mapping/rule set and independently verifies:

- the exact primary handler and two asynchronous workers;
- concurrency `100`, `5`, and `5`, Python 3.13, ARM64, handler, memory,
  timeout, code digest and configuration revision;
- persisted Entra tenant/AAI tenant, enabled strong authentication and SCIM;
- primary and regional signing-key identities;
- explicit `primary` cell role and transition-reconciliation gate; and
- two enabled queue mappings and four enabled schedules.

The primary handler, trial onboarding, SCIM and discovery application Lambdas
have explicit concurrency bounds. CDK support Lambdas remain part of the exact
fence/restoration plan but are not accepted as application-runtime evidence.

The internal reconciliation event is schema v2 and includes direction, target
Region, transition UUID and `authoritySha256`. A failover event is accepted
only by a recovery cell; a failback event only by primary. The dedicated
transition role must have `lambda:InvokeFunction` only on the exact target
handler. That role also needs only the enumerated read APIs used by preflight
and verification. The separate DNS mutation grant must be limited to
`route53:ChangeResourceRecordSets` on the exact hosted zone and removed from
ordinary operator roles. The Lambda result is still untrusted and must echo the
authority digest and reach a bounded zero-action check before routing.

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

Create an owner-only file containing a short-lived operator JWT (`chmod 600`),
then execute one routing step at a time with
`scripts/execute_aws_regional_routing.py`. The commands require the same four
authority files as this executor plus `--operator-token-file`. Confirmation
flags are `--confirm-journal-ingress`, `--confirm-route53-cutover`, and
`--confirm-stable-completion` respectively.

Exit code `2` is fail-closed. Failover and planned failback use the same command
sequence with source and target derived from signed direction authority.
Failed-cutover rollback is available in either direction. Retained live
RTO/RPO evidence remains an incomplete gate. See
[Regional target readiness and stable ingress](regional-target-readiness-and-stable-ingress-design.md).

## Test evidence and non-guarantees

Focused tests cover unstable/duplicate discovery, bounded pagination, resource
digest binding, ordered fencing, partial mutation failure, independent state
reads, identity/signing substitution, exact assembly deployment, unknown IAM
actions, mismatched bucket policies, direction/Region/transition/authority
binding, exact primary restoration, symmetric failback routing, retry safety
and routing refusal before complete target state. CI synthesizes standby,
recovery-active and failback-capable primary variants with separate verifiers.

No live AWS mutation was performed by this tranche. P0-11 remains **Partial**
until real identity, trust, stable-origin, passive/witness/ingress deployment,
exclusive provider authority and rehearsed failover/failback gates all pass.

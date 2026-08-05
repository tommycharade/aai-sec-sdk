# Measured runtime-release rollouts

## Purpose

An enterprise cannot replace every Claude Code or Codex runtime at once and
still claim a controlled release process. The control plane therefore treats a
runtime upgrade as a revision-bound transition between exactly two
deployment-approved releases: the retained current release and one target
release.

This design adds selection and admission authority to the approved-release
catalog. It does not distribute executable files. Intune, another MDM tool, or
an administrator-owned software channel must deliver the already approved
bytes to each endpoint.

The [runtime remediation coordination](runtime-remediation-coordination-design.md)
contract exposes exact server-selected, executable-free work to a scoped
external endpoint-management worker and records bounded channel outcomes.
Those outcomes remain operational observations; only fresh exact attestation
can complete this rollout.

## Security invariants

- A deployment has one current release and at most one target release.
- Both releases must exist in the immutable deployment-owned approval catalog
  and must match the deployment's single active host population. Starting a
  transition copies each release's exact closed attestation manifest, source
  revision, artifact digests and manifest/approval bundle digests into the
  rollout authority. A later catalog replacement cannot change an open
  transition, even if it reuses the same host and semantic version or becomes
  empty. Catalog removal never disables persisted attestation enforcement.
- Every new transition begins with a deterministic canary of 1–25 percent.
- The server selects members by tenant, deployment and agent identity. A
  browser cannot submit or inspect a privileged member list.
- Broad exposure is more than 25 percent and is rejected until the selected
  population meets the configured minimum sample and every selected canary has
  fresh attestation for the exact target version, source revision and complete
  artifact manifest.
- Exposure can only increase. A target cannot change while a transition is
  open. Reducing exposure or changing target requires rollback.
- Pause snapshots the already selected active identities as sorted, content-free
  SHA-256 membership digests. New or reactivated agents cannot enter that
  cohort until an operator explicitly resumes. Rollback retains the same frozen
  cohort and directs only those endpoints to the retained current release.
- Missing, expired, quarantined, unavailable or mismatched evidence never
  contributes to convergence.
- Authority changes use optimistic revisions. Runtime authority and
  content-minimised primary audit evidence commit in one DynamoDB transaction.
  That evidence binds the complete resulting authority-document hash, previous
  and next state, release identities, percentage and exact health criteria;
  Object Lock export is a best-effort replica of that durable evidence.

## States

| State | Meaning | Endpoint authority |
| --- | --- | --- |
| `canary` | Bounded target cohort is being measured | Selected agents: target; others: current |
| `active` | Converged canary has expanded above 25 percent | Selected agents: target; others: current |
| `paused` | Operator or threshold removed expansion authority | Frozen selected agents remain target-authorised; newcomers remain current |
| `rolling_back` | Frozen selected agents must return to current | Current only |
| `converged` | Every active agent proved the target | Target becomes retained current |
| `rolled_back` | Measured selected population returned to current | Current only |

The five-minute control-plane reconciliation cycle derives convergence and can
automatically pause when the configured unavailable or mismatch threshold is
exceeded after the grace period and minimum sample size. It never declares
endpoint state from a browser request.

## API contract

Human reads require `inventory_read`; mutations require fleet runtime-write
authority and remain constrained by delegated deployment scope.

- `GET /api/enterprise/runtime-rollouts` returns tenant-scoped rollout records
  with live, server-derived convergence.
- `POST /api/enterprise/runtime-rollouts` starts, resumes or expands a rollout.
  The closed request schema includes deployment ID, expected revision, exact
  target release ID, target state, percentage, health criteria and rationale.
- `POST /api/enterprise/runtime-rollouts/{deploymentId}/pause` requires the
  exact current revision and rationale.
- `POST /api/enterprise/runtime-rollouts/{deploymentId}/rollback` requires the
  exact current revision and rationale.

The version-compliance projection includes current release, target release,
rollout state and percentage for each deployment. During a transition, each
agent is evaluated against the release selected for that exact identity rather
than against one browser-authored deployment version.

## Operator journey

1. Publish and independently approve the target release manifest through the
   deployment workflow.
2. Open **Deployments → Runtime releases** and choose **Change release** for one
   deployment.
3. Confirm the retained current release and choose one compatible approved
   target.
4. Set a 1–25 percent canary, unavailable and mismatch thresholds, minimum
   sample, grace period and change rationale.
5. Start the canary, then deliver the approved bytes with the managed endpoint
   channel.
6. Wait for exact target attestation. The **Broad** control remains disabled
   until the server reports canary convergence and minimum-sample satisfaction.
7. Expand, pause or roll back using the current revision. Full exact evidence
   promotes the target to retained current.

After a pause, **Resume runtime canary** or **Resume broad rollout** is an
explicit authority change. It discards the frozen incident cohort and allows
the live deterministic population to be selected again. Do not resume merely
to clear an alert.

The dialog explicitly distinguishes release-selection authority from binary
delivery. This prevents an operator from mistaking a control-plane intent for
a completed endpoint upgrade.

## Threats and controls

| Threat | Control |
| --- | --- |
| Browser submits arbitrary canary members | Server-only deterministic identity selection |
| Unapproved or cross-host target | Exact approved catalog and homogeneous host checks |
| Target switched mid-rollout | Immutable open-transition target |
| Catalog entry replaced under an open rollout | Complete current/target release bindings are copied into rollout authority |
| Catalog removed to bypass attestation | Persisted authority is resolved before the development-only empty-catalog compatibility path |
| State fields removed to force current-release fallback | One closed state-specific validator gates admission, convergence, mutation, reconciliation and projection |
| Canary bypassed with a small “active” ring | Active percentage must exceed 25 and requires converged canary evidence |
| Minimum sample configured but ignored | Server includes sample sufficiency in the promotion predicate |
| New agent enters while paused | Pause and rollback use a frozen digest-only identity cohort |
| Stale operator overwrites authority | Strong read plus optimistic revision transaction |
| Authority exists without complete audit binding | Authority and complete resulting-document hash commit atomically |
| Heartbeat is mistaken for upgrade proof | Exact fresh version, revision and manifest attestation |
| Browser claims convergence | Counts and states are derived from tenant-scoped agent records |
| Old UI cannot load rollout endpoint | Release posture fails independently; fleet operations remain available and release mutation is disabled |

## Verification and remaining deployment gate

Automated contracts cover deterministic dual-version selection, exact
attestation admission, minimum-sample enforcement, canary convergence, broad
expansion, completion, premature expansion, undersized broad rings, target
switching, live-catalog replacement, paused population churn, malformed
persisted authority, empty-catalog bypass, state-specific field removal, stale
revisions, target-attested measured rollback,
tenant/delegated-scope and role denial, complete authority-hash audit, S3
replica failure, machine route/capability allow-listing, closed UI response
validation and rendered UI canary, pause, resume, rollback and refresh-failure
journeys. UI adversarial coverage also rejects contradictory convergence and
malformed catalog authority, prevents pending-operation dismissal, resets
terminal transitions to canary and proves refresh-lock recovery.

The persisted-authority contracts use DynamoDB's production `Decimal`
representation recursively, including the nested attestation manifest, so the
in-memory test adapter cannot mask resource-layer numeric conversion defects.

Production acceptance still requires publishing a real next release and using
the chosen MDM/software-distribution system to install it on a representative
Claude Code and Codex pilot population. This control plane does not claim that
physical delivery gate is complete.

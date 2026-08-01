# Measured managed-configuration rollouts

## Purpose

This design replaces the legacy deployment rollout flag with an evidence-led
authority boundary for managed Claude Code and Codex configuration. An operator
may choose a rollout target and ring, but cannot declare that endpoints applied
it. Only current, exact endpoint evidence can establish convergence.

The first slice targets P1-POL-05 and P1-POL-06 and provides the control-plane
foundation needed by P1-FLT-06 and P1-FLT-08. It does not claim that an MDM has
installed the SDK or that an unapproved SDK release is safe. Release-manifest
and physical-device rollout evidence remain separate gates.

## Trust boundaries

- The authenticated operator chooses deployments, a bounded percentage,
  channel, ring, schedule, health criteria and reason.
- The server resolves each deployment, desired configuration, exact package,
  active agents and current evidence. Browser-provided counts and health are
  never accepted.
- A rollout binds one immutable configuration version and one immutable managed
  package revision. Publishing a later package cannot alter an active rollout.
- Agent selection is deterministic from the tenant-scoped deployment/agent
  identity and percentage. The browser cannot choose a favourable canary.
- `appliedHash` is written only after every selected endpoint in a 100-percent
  rollout reports fresh exact managed configuration. An operator transition
  can never write it.
- Threshold breaches and deadlines only remove rollout authority by pausing.
  They never expand a ring or grant execution authority.
- Rollback creates a new immutable configuration version from the last
  server-recorded known-good version and its retained package revision.

## Lifecycle

```text
staged -> scheduled -> canary -> active -> converged
                    \         \         -> paused
                     \         -> paused
                      -> paused

paused -> canary | active
any non-staged version with known-good history -> rolling_back -> converged
```

`canary` remains visible after its selected endpoints converge; expansion is a
separate authenticated mutation. `active` becomes `converged` only at 100
percent with exact evidence from every active enrolled endpoint. A scheduled
five-minute reconciler applies due schedules, calculates convergence and
automatically pauses unhealthy or overdue rollouts.

## Rollout request

The batch mutation accepts no presentation state or endpoint counts:

```json
{
  "deploymentIds": ["deployment-a"],
  "expectedRevisions": {"deployment-a": 3},
  "targetState": "canary",
  "percentage": 10,
  "channel": "stable",
  "ring": "canary",
  "reason": "Deploy the reviewed configuration to the engineering canary ring.",
  "healthCriteria": {
    "maxUnavailablePercent": 5,
    "maxDriftPercent": 5,
    "minSampleSize": 1,
    "gracePeriodSeconds": 600
  },
  "schedule": {
    "notBefore": 1800000000,
    "deadline": 1800003600,
    "timeZone": "Europe/London"
  }
}
```

The batch is bounded and all-or-none. Each deployment must have an active
population, one current exact package matching desired managed-host state, no
incompatible agent host, and the expected rollout revision. Canary rings are
limited to 1–25 percent. Percentage may only increase unless a governed
rollback is requested.

## Measured convergence

For the deterministic selected population the control plane reports:

- total and selected active agents;
- healthy, converged, pending, unavailable and drifted counts;
- measured percentages, not requested percentages;
- whether the grace period is active;
- threshold and deadline posture;
- exact desired hash, configuration version and package revision; and
- blockers such as missing package, no agents or incompatible host.

An endpoint is converged only when it is active and connected and its fresh
managed report exactly matches host, host version, platform, bundle hash,
policy ID and policy version. Project-owned files, browser claims and rollout
state do not count as evidence.

## Deterministic rollback

Every desired configuration version stores an integrity hash and the package
revision bound when rollout began. Full convergence marks that version as the
last known good. Rollback accepts only that exact version, expected rollout
revision and a durable reason. It creates a new version with the known-good
desired document and package revision, selects 100 percent, and remains
`rolling_back` until endpoint evidence converges.

## UI journey

Deployments & rollout opens with measured state, not action buttons. Selecting
a deployment opens a focused rollout workspace showing readiness, exact target,
current versus desired authority, measured convergence and blockers. Starting
or expanding a rollout requires typed ring, channel, percentage, maintenance
window, thresholds and reason. Pause and rollback are visually consequential
and require confirmation. Help text explains every field.

## Required evidence

- no operator request can set `appliedHash`, convergence counts or known-good
  state;
- stale revision, malformed schedule, decreasing percentage, oversized batch,
  incompatible host and package mismatch fail closed;
- stable canary selection and exact package revision are deterministic;
- fresh exact reports converge, while missing/stale/conflicting reports do not;
- health or deadline breach automatically pauses and emits audit evidence;
- rollback restores immutable desired content and package revision;
- concurrent reconciliation cannot overwrite a newer operator transition;
- scheduled reconciliation has bounded tenant/configuration work, retries, DLQ
  and alarm evidence; and
- UI contract, responsive browser and live AWS synthetic acceptance evidence.

# Repository and configuration anomaly detection

This design completes the next production-shaped slice of P1-SOC-06 and
P1-SOC-07. It detects unexpected repository scope and security-configuration
behavior for enrolled Claude Code and Codex agents without treating an agent's
own report as proof of host integrity.

## Customer outcome

Security operations can create independently reviewed, immutable detection
rules for two distinct evidence tiers:

1. **Agent activity** reports repeated attempts outside the registered project
   or repeated fail-closed configuration errors. These observations are useful
   but remain alert-only.
2. **Control-plane integrity** compares complete source-control generations,
   server-owned desired managed configuration, fresh endpoint measurements and
   runtime-attestation state. It reports an exact repository mapping or
   configuration-integrity finding and identifies the evidence that changed.

The Incidents workspace explains which tier produced every result, what was
expected, what was observed, whether the baseline was complete, and why the
system alerted or refused to evaluate. No rule widens agent authority.

## Trust boundaries

Agent decision reports are authenticated, bounded observations. The server
derives tenant, deployment, agent, host, project-root digest, policy version and
receipt time from the live session. The model and endpoint cannot select those
fields. Decision reports can still be omitted by a bypassed or offline host, so
they cannot authorize automatic containment.

Integrity findings use only server-owned or independently authenticated inputs:

- the current and immediately preceding atomically committed, complete
  source-control discovery generations;
- the SHA-256 digest of the registered project root, computed by the control
  plane;
- desired managed-host package identity and server-derived endpoint posture;
- current runtime-attestation status and bounded reason codes; and
- immutable active rule version and content hash.

Source-control and endpoint connectors remain observations. They may lower
posture or raise an alert, but they cannot register an agent, assign policy,
change desired configuration or grant response authority.

## Closed rule language

The existing `agent_activity` language gains two fixed signals:

- `outside_project_spike`; and
- `configuration_error_spike`.

They use the existing lookback, current-window, minimum-sample and sensitivity
controls. `outside_project_spike` counts only decisions whose fixed reason code
is `outside_project`. `configuration_error_spike` counts only
`invalid_configuration` and `policy_error`. Both keep action fixed to
`create_alert`.

A new `integrity_evidence` source uses this closed configuration:

- one or more signals from `repository_mapping_changed`,
  `managed_configuration_drift` and `runtime_attestation_drift`;
- Claude Code and/or Codex host scope;
- severity `medium`, `high` or `critical`;
- fixed action `create_alert`; and
- priority 1–1,000.

Unknown fields, unsupported signals, duplicate values, empty selections and
source changes within an existing rule ID fail closed. Integrity rules do not
accept a statistical sensitivity control because their expected value is an
exact retained authority or inventory baseline, not a learned norm.

## Repository baseline

Repository evaluation requires a current, complete source-control generation
and its immediately preceding committed generation for the same immutable
source ID. Both generations must have every declared page present and matching
its retained hash. Missing, stale, incomplete, oversized, non-consecutive or
malformed generations produce `baseline_insufficient` and no alert.

The evaluator normalizes each repository to its bounded repository ID,
project-root digest and expected host set. A finding exists only when an active
enrolled agent's server-derived project-root digest and host were in the prior
mapping and the current mapping removes or changes that exact scope. New
repositories that do not affect an enrolled agent are inventory changes, not
agent-security alerts.

Alerts retain repository ID, prior/current generation IDs, prior/current
mapping digests and the source content hashes. They never retain a filesystem
path, remote URL, source-control credential or repository content.

## Configuration integrity

`managed_configuration_drift` evaluates only agents with server-owned desired
managed-host configuration. A finding requires the server-derived posture to
be `conflict`; missing or stale evidence is already represented by endpoint
availability detections and must not be mislabeled as a proven change. The
evidence binds desired hash, observed package/bundle digest, report time and
deployment ID without copying protected configuration bytes.

`runtime_attestation_drift` evaluates a current agent state of `quarantined`
with one of the fixed configuration or launch-context mismatch reason codes.
The existing attestation boundary has already revoked the session before this
alert is materialized. The detection records that response; it does not claim
to have caused process, device or network isolation.

Malformed retained posture or attestation state yields
`baseline_insufficient` and evaluator health `degraded`. Corrupt state must
never be interpreted as healthy and must never create broader response
authority.

## Alert identity, suppression and response

One immutable alert ID binds tenant, rule ID/version, agent, signal and exact
evidence digest. A stable deduplication key omits the evidence digest so later
occurrences group together while each changed generation or posture remains a
separate retained record.

Integrity alerts use source `integrity_evidence`; activity alerts continue to
use `behavior_analytics`. Exact, expiring suppressions may select either source
but cannot suppress on source or severity alone. Every suppressed occurrence
is retained and cannot trigger outbound delivery or automatic response.

This tranche keeps all new signals alert-only. An incident responder may open a
case and use the existing server-revalidated case quarantine. Any future
automatic integrity response requires a separate independently approved rule
language, exact binding, rate/cooldown controls and dedicated adversarial
acceptance.

## Operator journey

1. Open **Incidents → Detection rules** and choose **Repository & configuration
   integrity** or **Agent behavior**.
2. Select only signals valid for that evidence tier and the Claude/Codex host
   scope.
3. Preview current findings. The preview never writes alerts or changes agent
   authority.
4. Inspect expected versus observed evidence, baseline completeness and blind
   spots.
5. Save a draft, submit it, obtain approval from a different subject and
   activate the exact immutable version.
6. Investigate a resulting alert in a case. Apply manual SDK quarantine only
   after the current server-owned binding is revalidated.

Every form control includes contextual help. The UI must not collapse both
tiers into a generic “configuration anomaly” badge.

## Failure modes and non-guarantees

- An offline or bypassed agent can omit activity; managed configuration,
  runtime attestation, discovery completeness and endpoint evidence remain
  separate P0 controls.
- A connector can publish incorrect observations within its credential scope.
  The finding proves a retained comparison, not malicious intent.
- Repository history is not inferred when complete consecutive generations do
  not exist.
- SDK quarantine does not terminate a process, isolate a device, block a
  network or revoke third-party credentials.
- Splunk remains a labelled non-delivering stub.

## Required evidence

Contracts must prove closed schemas, source immutability, two-person approval,
complete consecutive repository baselines, changed and unchanged mappings,
host/agent scope, desired-versus-observed configuration comparison, attestation
reason filtering, malformed-state degradation, deterministic alert IDs,
cross-occurrence deduplication, exact suppression, case binding, tenant
isolation, redaction and disabled/rolled-back rules. UI tests must prove typed
authoring, evidence-tier explanation, preview-before-activation and no implied
automatic containment. `make check` and the private UI quality gate must pass
before deployment.

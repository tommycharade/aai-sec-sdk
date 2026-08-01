# Measured managed-rollout acceptance — 2026-08-01

## Result

The managed-configuration rollout authority, scheduled reconciler and focused
operator UI passed local and deployed synthetic acceptance on 1 August 2026.
The result proves that an operator can propose and control a bounded rollout,
but cannot claim endpoint enforcement. Fresh exact authenticated endpoint
evidence is the only path to `converged` state and a known-good anchor.

This closes the implementation slice for the control-plane portions of
P1-FLT-08, P1-POL-05 and P1-POL-06. It does **not** close enterprise-wide host
acceptance or P1-FLT-06 managed upgrades. Runtime release attestation, approved
SDK/gateway/hook release manifests and real MDM distribution remain required.

## Authority and adversarial evidence

The AWS Lambda contract suite contains 118 passing tests. The rollout tests
prove:

- a legacy browser request containing only state and percentage is rejected;
- a browser cannot submit `appliedHash`, convergence or endpoint membership;
- stale optimistic rollout revisions fail with conflict;
- canaries use deterministic tenant/agent hashing and cannot exceed 25%;
- percentage can expand but cannot decrease outside rollback;
- invalid IANA zones and malformed or inverted windows fail closed;
- an active 100% rollout remains drifted with no applied hash until all active
  endpoints provide fresh exact managed-host evidence;
- the rollout binds the exact immutable package revision current at start;
- unavailable or drift thresholds automatically pause after grace;
- an elapsed deadline pauses incomplete rollout authority;
- only full exact evidence records the current configuration/package pair as
  last known good; and
- rollback creates a new immutable configuration version, selects that exact
  retained package revision and measures endpoint convergence again.

The complete SDK quality gate passed with 873 tests, one intentional optional
PostgreSQL skip, 90.26% coverage, formatting, lint, typing, repository
guardrails, generated README and strict documentation build.

## UI evidence

The private management UI passed 133 tests, TypeScript checking and a
production Vite build. Contract tests verify the exact start, pause and
rollback request bodies and prove that no applied hash or endpoint convergence
field is transmitted by the browser.

The Deployments page now opens a dedicated **Manage rollout** workspace. It
shows desired configuration, package and endpoint-evidence state before action
and provides typed controls for:

- deterministic canary or broad ring;
- monotonically increasing percentage;
- stable, preview or emergency channel;
- maximum unavailable and drift percentages;
- minimum measured sample and grace period;
- optional not-before/deadline window with IANA time zone;
- retained operator rationale;
- explicit pause; and
- rollback only when the server exposes an exact known-good pair.

Browser QA at 1280×720 found no horizontal overflow or console warnings. The
workspace used a persistent assurance summary and action footer while detailed
controls scrolled. The production CloudFront assets were then verified to
contain the measured-rollout workspace and pause route.

## Deployed AWS evidence

The `AaiSecControlPlane` stack in `eu-west-2` was updated through the approved
`p1` profile. CloudFormation completed successfully and now contains:

- a five-minute EventBridge rollout-reconciliation schedule;
- exact Lambda target permission;
- two target retries with a maximum event age of one hour;
- a dedicated SQS dead-letter queue;
- a CloudWatch dead-letter alarm routed through the existing security-alert
  channel; and
- the `RolloutReconciliationDlqArn` stack output.

Target inspection confirmed the deployed control-plane Lambda, dedicated DLQ,
retry count `2` and maximum event age `3600`. The DLQ had zero messages after
deployment and acceptance.

The expanded deployed smoke test created a synthetic deployment, desired
managed-host configuration, immutable package and active enrolled Claude Code
agent. It then demonstrated:

1. start a 100% broad rollout against the exact rollout revision;
2. receive `active` with package revision `1` and `appliedHash: null`;
3. enroll and authenticate the exact endpoint;
4. submit fresh exact managed-configuration evidence through the agent
   heartbeat; and
5. read server-reconciled `converged`, equal desired/applied hashes, full
   convergence and last-known-good configuration/package revision `1`.

The same live harness also retained its authentication, enrollment, ownership,
bulk assignment, policy, approval, emergency stop, idempotency, WORM audit,
durable alert, lifecycle and temporary policy-exception acceptance.

## Honest remaining gates

- Microsoft Entra OIDC and SCIM are still `not-configured` in this AWS stack.
- Runtime attestation is still `not-configured`; the deployed smoke explicitly
  allowed only that named failure and did not claim release provenance or full
  agent verification.
- Synthetic endpoint evidence proves the authority protocol, not privileged
  installation or host loading on a genuinely managed physical device.
- Managed SDK, gateway and hook upgrades require independently approved release
  manifests, compatibility evidence and an MDM/Jamf/Intune delivery adapter.
- Enterprise rollout acceptance still requires the measured rollout and
  rollback SLO on the agreed real pilot population.

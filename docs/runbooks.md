# Operational runbooks

These runbooks are for operators deploying the SDK with real policy, identity,
approval, audit, idempotency, and isolation services. The SDK exposes signals
and fail-closed outcomes; it does not operate customer infrastructure. Use
synthetic identifiers in tickets and examples, and preserve restricted
evidence according to the organisation's incident policy.

## Common rules

1. Freeze consequential retries while the outcome is `TIMED_OUT`, `UNKNOWN`,
   `FAILED`, or `EXECUTED_UNRECORDED`.
2. Do not bypass the runtime, disable audit, broaden credentials, or replay a
   proposal to “see what happened”.
3. Record the request ID, operation key, tool, tenant, runtime health snapshot,
   and relevant audit hashes—never credentials or raw arguments containing
   secrets.
4. Escalate to the security owner when integrity, identity, or isolation is
   uncertain.

## Emergency stop

**Detect:** the kill switch is active, an incident commander declares an
emergency, or `health()` shows unsafe worker saturation.

**Safe actions:** activate the application-owned stop control; prevent new
admissions; preserve the last audit hash and health snapshot; reconcile
already-started side effects through the domain system; notify the incident
commander.

**Unsafe actions:** deleting the audit file, restarting repeatedly to clear
worker state, rotating away evidence, or re-enabling execution without a
recorded approval.

**Recover:** verify policy, credentials, audit replication, idempotency, and
isolation health; run a synthetic read-only probe; obtain two-person approval;
then clear the stop control and monitor gradually.

**Escalate:** security owner and service owner for any side effect that started
before the stop.

## Audit failure, full, or corruption

**Detect:** `AuditReplicationError`, an `EXECUTED_UNRECORDED` result, a full
`JsonlAuditSink`, `verify() is False`, or exporter health failure.

**Safe actions:** stop consequential actions; retain the local file and lock
file; copy it to restricted evidence storage; verify the last known hash;
restore the remote exporter or rotate only after preserving the chain.

**Unsafe actions:** truncating a corrupt file, ignoring a negative remote
acknowledgement, or treating local JSONL as immutable forensic evidence.

**Recover:** repair the collector or storage quota, replay only from a
verified, deduplicating export process, and confirm remote acknowledgement.

**Escalate:** security and compliance owners when an event cannot be proven
replicated or the chain has been altered. Local JSONL is not WORM storage.

## Timed-out worker saturation

**Detect:** `health()` reports timed-out workers at capacity, increasing
per-operation timeout counters, or an old lingering worker.

**Safe actions:** stop new consequential work; wait for cooperative workers;
move non-cooperative work to an isolated process; inspect policy/provider
latency and resource limits.

**Unsafe actions:** raising `max_timed_out_workers` during an incident,
force-retrying an uncertain side effect, or assuming a Python thread stopped.

**Recover:** drain workers, repair the dependency, run bounded probes, and
resume only below the documented alert threshold.

**Escalate:** service owner for repeated saturation or any non-cooperative
handler that can commit external state.

Action-budget leases are released by an atomic, single-use guard. Timeout,
reconciliation, audit, and worker-exit callbacks may race, but only the first
callback can release the lease; duplicate callbacks cannot decrement active or
fan-out counters below zero. Do not repair counters manually or restart merely
to clear a suspected duplicate release. Capture the request ID and runtime
health snapshot, and escalate if counters do not return to zero after all
workers exit.

## Reconciliation and uncertain side effects

**Detect:** `TIMED_OUT` with `STILL_RUNNING`, `UNKNOWN`, `FAILED`, or an
`EXECUTED_UNRECORDED` result.

**Safe actions:** query the domain idempotency/reconciliation system using the
stable operation key; compare the exact action fingerprint; record the
outcome; retry only after `CONFIRMED_ABSENT` or an explicit domain override.

**Unsafe actions:** retrying with a new proposal ID, changing arguments under
the same operation key, or interpreting a live worker as cancelled.

**Recover:** persist `COMPLETED` or `UNCERTAIN` in the idempotency store and
follow the domain compensating-action procedure.

**Escalate:** domain owner for payments, messages, deletion, or other
irreversible effects.

## Credential provider outage or scope mismatch

**Detect:** credential timeout, provider error, expired `ProviderToken`, or
tool/resource scope mismatch.

**Safe actions:** deny the action; verify provider health and attestation
configuration; rotate affected credentials through the normal IAM process.

**Unsafe actions:** accepting a raw token, broadening the requested scope, or
using a cached credential outside its expiry.

**Recover:** restore the provider, validate a synthetic least-privilege token,
and resume with normal policy and approval checks.

**Escalate:** IAM and security owners for any scope mismatch or suspected
credential exposure.

## Policy or approval outage

**Detect:** timeout, transport failure, malformed decision, stale policy
version, or approval rejection.

**Safe actions:** fail closed; preserve the request ID and policy provenance;
check service health and deployment configuration.

**Unsafe actions:** replacing the service with an allow-all callback, reusing
an expired approval, or approving modified arguments.

**Recover:** restore the service, verify the current policy version, and issue
a new action-bound approval if required.

**Escalate:** policy owner for unexpected allow/deny behavior or provenance
drift.

Approval consumption has three states: `CONSUMED`, `NOT_CONSUMED`, and
`UNKNOWN`. A timeout or transport failure after an approval request may be
`UNKNOWN`; do not retry the side effect or assume the approval remains unused.
Inspect the action-bound audit event (`approval_id`, `approval_action_hash`,
`approval_outcome`) and reconcile with the approval service before deciding
whether a new approval is required. If emergency stop occurs after a provider
reports `CONSUMED`, the runtime records `approval_stop_after_consume=true` and
does not start the handler; treat that approval as consumed until the provider
proves otherwise.

For the hosted central queue, confirm the request is still `pending` and has
not expired before reviewing it. Verify the enrolled agent, principal, tool,
task, resource identifiers, risk class, and action fingerprint; request
out-of-band business-owner confirmation when those bounded fields are not
sufficient. Record a concise rationale without secrets. Never approve from the
audit event alone, copy an old approval ID to a new action, or grant a broader
TTL to work around operator delay. If two operators race, the second decision
must receive a conflict and must not be retried as a new request. A denied or
expired action requires the agent to submit a fresh exact binding.

## Idempotency-store outage or corruption

**Detect:** claim failure, collision, unavailable store, or
`EXECUTED_UNRECORDED` after terminal persistence failure.

**Safe actions:** deny new required-idempotency actions; preserve operation
keys and fingerprints; inspect the store without mutating records.

**Unsafe actions:** deleting `IN_PROGRESS` records, generating replacement
keys, or replaying a side effect without reconciliation.

**Recover:** restore a transactional store, verify claims and fingerprints,
reconcile uncertain operations, then run a concurrent claim test.

**Escalate:** data and domain owners when state cannot be reconstructed.

## Isolation-attestation failure

**Detect:** missing, expired, replayed, wrong-profile, wrong-tenant, or
unverifiable attestation.

**Safe actions:** deny execution; quarantine the workload; inspect verifier and
platform evidence; preserve the nonce and request ID.

**Unsafe actions:** setting `isolated=True`, accepting a stale attestation, or
falling back to an in-process handler for hostile code.

**Recover:** repair the platform verifier/sandbox, issue fresh bound evidence,
and run a synthetic restricted workload.

**Escalate:** platform security owner for any forged or downgraded evidence.

## Rotation and evidence preservation

Rotate signing keys, IAM credentials, policy versions, and audit destinations
through an approved change. Keep old verification material available for the
retention period. Before rotation, capture the last verified event hash and
remote export receipt; after rotation, run a synthetic append, verification,
and export test. Preserve original files read-only, access logs, deployment
manifests, health snapshots, and relevant provider responses. Do not include
secrets in incident artifacts.

## Tabletop exercise

At least once per release line, simulate a remote audit outage during a timed
handler and an idempotency-store failure. The expected result is no blind
retry, a fail-closed runtime outcome, preserved local evidence, an operator
alert, and a documented reconciliation decision.

## Enterprise fleet rollout, drift, and rollback

**Before rollout:** verify the target organization, project, deployment IDs,
environment, region, SDK version, current health, and operator authorization.
Review the desired configuration hash and ensure the deployment authority is
connected. Never put bearer tokens, credentials, or raw tool arguments into a
template or ticket.

**Stage safely:** assign the reviewed template, use a staged or canary rollout,
and start with a small percentage. Confirm agent heartbeats, health, alerts,
policy decisions, audit replication, and representative synthetic actions
before increasing the percentage. The UI's Enterprise fleet page is an
operator view; the API remains the authoritative control boundary.

**Detect drift:** treat a desired/applied hash mismatch as an operational
condition, not as permission to continue. Inspect the deployment's version,
authority response, and audit trail. Reconcile through the deployment
authority or reapply the reviewed template. Do not edit the database directly
to hide drift.

**Rollback:** select a known-good configuration history version and invoke the
fleet rollback endpoint. The authority is called before the control plane
claims the rollback. If the authority rejects it, the desired state remains
unchanged and the action must be escalated. Validate health and drift after
rollback, then record the decision and evidence.

**Emergency stop:** use the deployment-scoped stop control for a localized
incident or the tenant-wide stop for a wider incident. The hosted fleet stop is
durable server-owned state and causes every enrolled agent's effective-policy
request to fail closed, including agents enrolled after activation. Fleet,
deployment, group, and agent stops are independent; clearing the fleet scope
must not clear a narrower stop. Preserve the incident ID, last heartbeat,
configuration hashes, operator identity, and audit references. Clear the stop
only after incident-command approval, then verify the dashboard posture and a
synthetic read-only action. A still-active narrower stop should continue to
deny that agent after fleet recovery.

**Operational limitation:** the bundled SQLite store, static bearer
authenticator, and reference server are demonstration/development adapters.
Replace them with enterprise IAM, secret storage, HA persistence, durable
alert delivery, and a real deployment authority before production use.

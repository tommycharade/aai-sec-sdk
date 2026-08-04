# Governed alert suppression and deduplication

Alert suppression reduces known operational noise without deleting evidence or
changing agent authority. It is a tenant control-plane capability for incident
responders and security operators. It is not a browser filter, policy override,
approval, quarantine release, or way to make a detection appear healthy.

## Trust boundary

The browser proposes a closed typed match. The authenticated control plane
derives the tenant, operator and current server time, validates the exact scope,
and persists the suppression. Models, agents and endpoint reports cannot create,
extend or revoke suppressions.

Every suppression:

- has an immutable stable ID, display name, accountable operator and rationale;
- selects one or both supported sources and explicit severities;
- must also select at least one exact reason code, response-rule ID, deployment,
  agent or managed-device ID;
- rejects wildcards, partial matching, duplicate values and unknown fields;
- starts immediately and expires between five minutes and seven days after the
  server's current time;
- cannot be edited or extended; a changed scope requires a new record;
- is retained for 90 days after expiry for operational traceability; and
- may be revoked with optimistic concurrency and a second rationale.

The control plane caps each selector list at 20 values and each tenant at 100
simultaneously active suppressions. Credential-shaped rationale is rejected.

## Detection behavior

A matching detection is still materialized as an immutable alert. Its status
and delivery state are `suppressed`, and it records the suppression ID and
expiry. The control plane writes a content-minimised audit event. It does not
publish the alert to SNS or signed webhooks, and an endpoint automatic-response
rule cannot consume it.

Revocation or expiry does not rewrite earlier alert evidence. A later behavior
window creates a normally routed alert. A continuing endpoint condition reopens
its stable alert on the next reconciliation. Suppression therefore reduces
delivery noise without creating a historical blind spot.

Endpoint detections retain their existing stable alert ID as the deduplication
key. Behavior detections retain one evidence record per deterministic evaluation
window and expose a separate stable deduplication key derived from tenant,
active rule version, exact agent, signal and content-minimised dimension hash.
The UI can group those records without collapsing or mutating their evidence.

## UI journey

Open **Incidents → Suppressions** to see active, expired and revoked records,
including owner, exact scope and expiry. **Create suppression** uses a typed form
for source, severity, exact selector, duration and rationale. Contextual help
explains every field. The review copy states that evidence remains retained and
agent authority is unchanged. Revocation is a separate confirmation with an
optimistic revision and rationale.

The expert API supports intersections of several exact selector lists. The UI
starts with one explicit identity to keep the common workflow understandable.
Neither surface supports regexes or wildcard scope.

## Guarantees and non-guarantees

The implementation guarantees bounded exact matching, server-time expiry,
retained alert and audit evidence, no outbound delivery for a currently matched
suppressed alert, and exclusion from automatic endpoint containment.

It does not prove that an external receiver discarded an alert already delivered
before suppression, remove the underlying security condition, silence local
agent/endpoint logs, or replace maintenance/change approval. A compromised host
may still omit telemetry; behavior detection remains limited by authenticated,
retained observations and complete-history bounds.

## Verification

AWS Lambda contracts cover exact target matching, unrelated-target delivery,
expiry/revocation reopening, stable cross-window behavior grouping, retained
records, audit events, suppressed response executions, and rejection of broad,
overlong, wildcard and unauthorized requests. UI tests cover the dedicated
workspace, trust copy, contextual help, disabled invalid submission and exact
HTTP contracts. The full repository gate remains `make check`; the private UI
gate remains `npm run check`.

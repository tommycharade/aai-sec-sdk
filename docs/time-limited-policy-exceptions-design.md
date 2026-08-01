# Time-limited policy exceptions

## Decision

Temporary policy exceptions are independently reviewed, KMS-signed derived
policy bundles. An exception is bound to one tenant, one enrolled agent, one
group and one exact active base-policy version. The server clock determines
expiry. An expired, revoked, stale-base, reassigned or otherwise inconsistent
exception is never returned as runtime authority; resolution falls back to the
normal signed active policy.

This design implements the authority foundation for P1-FLT-09 and P1-POL-10.
It does not make project configuration an enforcement boundary and does not
permit immutable SDK safeguards to be disabled.

## Threat and trust boundary

Exception identifiers, requested configuration, owner, purpose, expiry and UI
state are untrusted input. The model and browser cannot choose tenant identity,
review identity, signing key, server time, active base policy, group membership
or enrolled-agent identity.

The control plane therefore:

- derives tenant and actor from authenticated context;
- resolves the target agent, sole group and active policy from strongly
  consistent server-owned state;
- validates the complete proposed effective configuration through the normal
  policy schema and immutable safeguards;
- binds the request to the exact base policy ID, version and content hash;
- permits only one open exception per agent through a conditional slot record;
- requires `draft -> review -> approved -> active` and prevents the author from
  approving their own request;
- signs the exact derived authority with the deployment-owned KMS key only at
  activation;
- returns the derived bundle only while every binding remains live and its
  server-clock expiry is in the future; and
- atomically releases the agent's exception slot on expiry, revocation or
  invalidation so the ordinary secure policy is restored without a browser,
  agent or model action.

The exception envelope uses its own stable signed policy identity. It never
reuses a base policy ID/version with different content, because doing so would
break the immutability guarantee of signed policy bundles.

## Lifecycle and API

```text
draft -> review -> approved -> active -> expired
                   |           |       -> revoked
                   |           -> invalidated (base/group/agent changed)
                   -> rejected
```

```text
GET  /api/enterprise/policy-exceptions
POST /api/enterprise/policy-exceptions
POST /api/enterprise/policy-exceptions/{id}/submit
POST /api/enterprise/policy-exceptions/{id}/decision
POST /api/enterprise/policy-exceptions/{id}/activate
POST /api/enterprise/policy-exceptions/{id}/revoke
```

Creation accepts an exact deployment and agent, accountable owner, bounded
purpose, expiry and full candidate effective configuration. The response shows
the semantic authority diff, base binding, lifecycle attribution and effective
status without returning signing internals or secrets. Decision and revocation
require a rationale. Activation accepts no policy content.

Policy authors create and submit. Policy approvers decide, activate and revoke.
Platform administrators retain wildcard capability but remain subject to
self-approval denial.

The first hosted workflow intentionally permits temporary changes only to SDK
tool allow/deny lists, Claude built-in tools, registered Skills and MCP servers,
command allow/deny/approval patterns, and the maximum-action budget. Identity
scope, approval provider, credentials, isolation, audit capture, telemetry and
redaction are inherited exactly from the base policy. The API independently
enforces this closed field set so an advanced client cannot bypass the typed
UI. Broader changes use the normal versioned policy lifecycle.

## Runtime resolution

Effective-policy retrieval first establishes the normal active signed bundle.
It then resolves the target agent's conditional exception slot. The exception
is usable only when all of these facts match:

1. state is `active`;
2. expiry is strictly later than server time;
3. agent lifecycle is active;
4. deployment, agent and sole group match the request;
5. group still points at the bound policy;
6. active policy version and content hash match the bound base; and
7. the persisted derived bundle is internally consistent.

Any mismatch fails back to the normal secure bundle and records an expiry or
invalidation event. A KMS or stored-signature failure fails closed; it is not
treated as permission to return unsigned exception content.

## UI journey

The Policy page presents temporary exceptions separately from ordinary policy
versions:

1. review active, expiring, pending and historical exceptions in one table;
2. select one exact enrolled agent and its current policy;
3. edit a typed copy of the effective settings and set owner, purpose and
   expiry;
4. review the semantic authority change and affected agent before submission;
5. have a second operator approve or reject with rationale;
6. activate the signed exception; and
7. see the countdown, restoration target and immutable lifecycle evidence.

The UI never labels a draft or approval as applied. `Active` means the
control-plane resolver can currently return the exception; endpoint convergence
and runtime attestation remain separate evidence.

## Guarantees and non-guarantees

The control plane guarantees bounded lifetime, independent approval, exact
scope, signed content, automatic secure fallback and auditable lifecycle for
the implemented AWS runtime channel. It does not guarantee endpoint receipt,
MDM enforcement, execution of an already cached policy after its refresh SLO,
or customer approval of the business justification. Those remain visible
operational acceptance requirements.

## Required evidence

- positive lifecycle and signed-runtime contract tests;
- self-approval, cross-tenant, malformed content and stale-base denial;
- concurrent/open-slot, replay and out-of-order transition denial;
- server-clock boundary, expiry, revocation and reassignment fallback tests;
- altered persisted bundle and signing failure tests;
- UI tests for typed authoring, semantic review, state labels and countdown;
- live AWS synthetic create/review/activate/fetch/expire-or-revoke/fallback
  evidence with exact cleanup; and
- documentation, threat-model, changelog and P0/P1 ledger updates.

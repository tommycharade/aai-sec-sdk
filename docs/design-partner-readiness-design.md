# Design-partner readiness authority

This design turns the console's pilot checklist into a tenant-scoped,
server-owned go/no-go projection. It helps a platform or security team decide
whether a controlled Claude Code design-partner pilot has enough current
evidence to begin. It also keeps the stricter enterprise-wide rollout result
separate, so a successful pilot cannot be presented as P0 completion.

## Security boundary

The browser, agent and model cannot submit readiness, waive a check or choose
the tenant. `GET /api/enterprise/pilot-readiness` derives the tenant from the
authenticated human or service identity and reads bounded, strongly
consistent control-plane records. It accepts no request body or query-shaped
facts and performs no mutation.

The projection uses one server clock and fails closed when evidence is absent,
stale, malformed, ambiguous or beyond a bounded read. Each item contains only
aggregate counts, fixed reason codes, an evidence timestamp and a code-owned
console route. It excludes paths, user names, raw alerts, prompts, tool
arguments, credentials and provider payloads.

`inventory_read` is sufficient because the response is aggregate operational
posture. Detailed identity, incident and immutable evidence remain behind
their existing least-privilege routes.

## Two deliberately different decisions

- **Controlled pilot** requires current Entra/SCIM/MFA posture, at least 95%
  complete population coverage, exactly one active policy per enrolled agent,
  exact managed-host evidence, release-bound runtime evidence, clear response
  controls and fresh healthy durable-evidence monitoring.
- **Enterprise rollout** requires every pilot item plus released buyer
  assurance and production SIEM delivery. The parked Splunk integration is
  returned as `deferred`, with `deliveryVerified: false`, and therefore cannot
  satisfy enterprise readiness.

Buyer assurance may be `external_required` while the source candidate awaits
an immutable release, legal approval or independent evidence. That status is
never upgraded from repository intent or browser configuration.

## Response contract

The response has a closed schema:

```json
{
  "schemaVersion": 1,
  "generatedAt": 1800000000,
  "expiresAt": 1800000060,
  "scope": "tenant",
  "pilot": {"status": "action_required", "ready": 4, "required": 7},
  "enterprise": {"status": "blocked", "ready": 4, "required": 9},
  "items": [],
  "nonGuarantees": [],
  "contentHash": "..."
}
```

Each item has an immutable ID, label, `ready`, `action_required`,
`external_required` or `deferred` status, pilot and enterprise requirement
flags, a fixed explanation, a fixed next-action route and content-minimised
evidence. `contentHash` covers every field except itself. `expiresAt` prevents
a cached summary from being presented as current after sixty seconds.

The initial item set is:

1. enterprise identity;
2. population coverage;
3. policy assignment;
4. managed host policy;
5. runtime trust;
6. incident response readiness;
7. durable evidence;
8. buyer assurance; and
9. Splunk delivery.

## Failure modes and non-guarantees

- A healthy response is an operational gate, not a compliance certification,
  penetration test, legal approval or proof of every endpoint.
- Discovery and endpoint reports remain observations; they can lower posture
  but cannot grant execution authority.
- A read failure returns an error. The UI shows readiness as unavailable and
  never reconstructs a healthier result from its fleet cache.
- The initial projection is synchronous and inherits the control plane's
  2,000-record tenant-list ceiling. Larger customer fleets require a
  server-owned materialized aggregate and load acceptance before this endpoint
  can be used as their rollout gate; partial data is never scored as ready.
- Pilot readiness does not waive any enterprise P0 requirement, customer
  change control, deployment approval or independent acceptance evidence.
- Splunk remains a visible stub. No event delivery, replay or delivery-health
  claim is made.

## Verification

Contract and adversarial tests cover a fully ready synthetic pilot, every
individual failed foundation, zero-agent denial, stale runtime and evidence,
ambiguous policy assignment, active containment, open security work,
cross-tenant isolation, role denial, machine-scope allowlisting, ignored
caller input and deterministic content hashing. UI tests cover unavailable,
pilot-ready and enterprise-blocked states, action routing, keyboard-accessible
help and accessibility scanning.

# Dynamic policy groups

Dynamic groups automate which enrolled agents receive a policy without making
the browser, agent, or model an authority source. They are a materialized,
reviewed assignment mechanism: the control plane evaluates a bounded rule over
its own inventory, shows the exact effect, and applies that result only after an
operator confirms it.

## Operator journey

1. Open a group and select **Automate membership**.
2. Add one or more typed conditions. All conditions must match.
3. Enter an auditable business reason and select **Preview rule**.
4. Review matched, added, removed, unchanged and conflicting agents.
5. Resolve any overlap with another policy group.
6. Apply the exact preview. The group becomes rule-managed and manual add or
   remove operations are disabled.
7. After the first reviewed apply, the control plane reevaluates the approved
   rule every five minutes. Select **Review rule** at any time to preview the
   current effect or replace the rule.

No JSON or expression language is required. The supported server-owned fields
are agent host, project ID, deployment ID, deployment team, environment,
region, reviewed agent criticality, endpoint posture and open-alert risk.
Conditions support exact inclusion or exclusion of up to 20 values. Wildcards,
regular expressions, volatile heartbeat state and browser-supplied posture or
risk values are not accepted.

Endpoint posture is a fixed enumeration: `healthy`, `attention` or `stale`.
The control plane derives it from the authenticated endpoint-evidence ledger,
authoritative device inventory, credential state, report freshness, SDK binary
measurement and process observation. An agent is joined to an endpoint only by
the digest of its registered project root plus its registered host. Missing evidence or
more than one device for the same target produces no posture attribute. Because
missing attributes match neither `equals_any` nor `not_equals_any`, an
ambiguous endpoint cannot enter a group through a negative condition.

Open-alert risk is `none`, `low`, `medium`, `high` or `critical`. It is the
highest severity among unresolved retained alerts correlated to the exact
agent or its endpoint target. Acknowledgement and suppression do not lower the
risk tier; only resolution removes it. Unknown status or severity values fail
the entire evaluation instead of becoming `none`.

## API contract

`POST /api/enterprise/groups/{group}/dynamic-membership` accepts a closed
schema with `mode`, `requestId`, `expectedMembershipRevision`, `reason` and a
rule. A rule has `match: all` and one to seven unique conditions.

Preview performs strongly consistent inventory reads and writes nothing. Its
typed response includes the canonical rule and hash, current/resulting
revision, additions, removals, unchanged agents, overlaps and summary counts.
`canApply` is true only when a real change exists and no overlap is present.
The response also includes evaluation time, fixed source labels and a SHA-256
digest of the content-minimised posture/risk projection. It never returns
project paths, device membership, alert content or the projected per-agent
values.

Apply repeats the evaluation. A stale revision or overlapping group returns
HTTP 409 with no partial authority change. A successful change atomically
stores the materialized membership, canonical rule, next membership revision,
request-bound idempotency result and immutable primary audit record. Reusing a
request ID with different semantics fails closed. The S3 audit export is a
best-effort secondary copy after the DynamoDB transaction.

## Scheduled reconciliation

Only a rule that an operator has already previewed and applied is eligible for
automatic reconciliation. A fixed five-minute EventBridge rule invokes an
internal schema-versioned service contract that cannot be reached through API
Gateway. The service strongly reloads the group, its canonical rule, every
candidate agent and deployment, then deterministically derives membership.

When membership changes, one DynamoDB transaction compares the exact current
revision, replaces the materialized membership, advances the revision, records
the latest reconciliation state and commits immutable primary audit evidence.
A no-change evaluation updates only the bounded status record. An overlap,
malformed rule, incomplete lineage or concurrent revision change preserves the
last-known policy authority and records a failed reconciliation state. The
Lambda invocation then fails so EventBridge performs bounded retries and sends
exhausted work to a monitored dead-letter queue.

The service is bounded to 2,000 registered tenants, 5,000 dynamic groups per
cycle and 500 candidate agents per group. It never accepts candidate members,
rules, actors or tenant identifiers from a browser or agent event. The fleet
response exposes only operational status: last attempt, last success, outcome,
counts, fixed source labels, evaluation time, context digest and a fixed error
code. It does not expose scheduler coordinates, alert content or membership
lists through the status record. Groups requesting the same operational fields
share one derived context per tenant and reconciliation cycle, preventing the
5,000-group bound from multiplying endpoint and alert-ledger reads.

## Security invariants

- An agent can belong to at most one policy group.
- Only active agents in the group's server-resolved organization are eligible.
- Deployment lineage and reviewed criticality come from control-plane records,
  never request JSON or model output.
- Endpoint posture comes only from authenticated endpoint evidence and exact,
  unambiguous installation lineage.
- Risk comes only from unresolved retained alerts; acknowledgement and
  suppression never reduce the derived severity.
- Missing attributes do not match.
- Candidate size is bounded to 500 agents.
- Dynamic groups reject manual single and bulk membership mutations.
- Inventory, groups and the target revision are re-read before every preview
  and apply; optimistic concurrency rejects races.
- Audit payloads contain counts, identifiers and hashes, not prompts, tool
  arguments, credentials or full membership lists.
- Scheduled reconciliation can materialize only the last operator-approved
  canonical rule; it cannot author or broaden that rule.
- A failed automatic evaluation never clears or partially rewrites the current
  membership. The last-known policy authority remains in force while operators
  receive a durable visible failure and monitored dead-letter alert.

## Threat model and limits

An attacker controlling a browser request can choose only a code-owned field,
operator and allowed value. The API rejects custom posture strings, custom risk
scores, duplicate fields and unsupported enumerations. An endpoint sensor can
submit signed measurements only for its credential-bound device; it cannot
select the AAI tenant, agent, group or policy. Alert-producing agents cannot
directly set risk: the control plane retains and correlates alert records before
the dynamic-group reader derives a tier.

Compromising the endpoint credential or the control-plane alert writer remains
inside the trusted deployment boundary and requires separate detection,
credential rotation and incident response. Posture grouping does not prove an
endpoint is malware-free, and alert risk is not a probabilistic threat score.
A rule can remove the last group from an agent; runtime verification then has
no policy and fails closed. Operators must use preview and a restrictive policy
for posture/risk cohorts rather than assuming automatic grouping remediates the
underlying device or incident condition.

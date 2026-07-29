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
7. Select **Review rule** after trusted inventory changes to preview and apply
   deterministic reevaluation.

No JSON or expression language is required. The supported server-owned fields
are agent host, project ID, deployment ID, deployment team, environment,
region and reviewed agent criticality. Conditions support exact inclusion or
exclusion of up to 20 values. Wildcards, regular expressions, volatile
heartbeat state and browser-supplied risk values are not accepted.

## API contract

`POST /api/enterprise/groups/{group}/dynamic-membership` accepts a closed
schema with `mode`, `requestId`, `expectedMembershipRevision`, `reason` and a
rule. A rule has `match: all` and one to seven unique conditions.

Preview performs strongly consistent inventory reads and writes nothing. Its
typed response includes the canonical rule and hash, current/resulting
revision, additions, removals, unchanged agents, overlaps and summary counts.
`canApply` is true only when a real change exists and no overlap is present.

Apply repeats the evaluation. A stale revision or overlapping group returns
HTTP 409 with no partial authority change. A successful change atomically
stores the materialized membership, canonical rule, next membership revision,
request-bound idempotency result and immutable primary audit record. Reusing a
request ID with different semantics fails closed. The S3 audit export is a
best-effort secondary copy after the DynamoDB transaction.

## Security invariants

- An agent can belong to at most one policy group.
- Only active agents in the group's server-resolved organization are eligible.
- Deployment lineage and reviewed criticality come from control-plane records,
  never request JSON or model output.
- Missing attributes do not match.
- Candidate size is bounded to 500 agents.
- Dynamic groups reject manual single and bulk membership mutations.
- Inventory, groups and the target revision are re-read before every preview
  and apply; optimistic concurrency rejects races.
- Audit payloads contain counts, identifiers and hashes, not prompts, tool
  arguments, credentials or full membership lists.

This first contract intentionally requires an operator to apply reevaluation.
Scheduled automatic reevaluation will require a separate service identity,
failure policy, change notification and rollout design before it can safely
change policy authority without a human confirmation.

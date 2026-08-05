# Unified investigation timeline

This design implements the software foundation of P1-SOC-05 from the
[enterprise rollout requirements](enterprise-rollout-p0-p1-requirements.md).
It gives a responder one ordered view of the identity, policy, tool, MCP,
approval, credential, isolation, evidence and operator facts related to an
incident case.

## Customer outcome

The **Incidents** workspace presents a single chronological investigation
instead of separate case-event, decision and approval lists. Every event says
what happened, when it happened, which evidence source supplied it and whether
that source is server-derived, server-owned, an authenticated agent report or
an operator action. Operators can filter the view by security facet without
changing the underlying correlation.

The timeline also says whether its evidence is complete. A bounded source or
record limit that could omit relevant events produces an explicit incomplete
state and reason. The UI must never turn that state into a complete-looking
investigation.

## Trust boundary

The browser does not join records or choose an agent. The AWS control plane:

1. loads the tenant-scoped case and source alert;
2. uses the agent binding captured by the case;
3. strongly reads the append-only case events and approvals;
4. reads the bounded decision-timeline index;
5. correlates only the captured deployment and agent within the declared time
   window; and
6. projects every source through a fixed content-minimising schema before
   ordering it.

Agent decisions remain labelled `authenticated_agent_report`. They are useful
observations, not proof that the reported action executed or that policy
allowed it. Case bindings, policy snapshots and alert facts are
`server_derived`; approval state is `server_owned`; and response actions are
`operator_action`.

```text
source alert -----------+
captured case binding --+--> tenant-scoped correlation --> typed events
case lifecycle ---------+                                  |
agent decisions --------+                                  +--> ordered view
approval lifecycle -----+                                  +--> completeness
```

## Typed event contract

Each event includes:

- a stable source-qualified ID and occurrence time;
- a fixed event type, title, bounded summary and outcome;
- one or more facets from `identity`, `policy`, `tool`, `mcp`, `approval`,
  `credential`, `isolation`, `evidence` and `operator`;
- an actor when one is known;
- source kind, source ID and provenance; and
- content-minimised references such as agent key, policy version, tool name,
  MCP registration ID, action digest, evidence digest or case-event payload
  hash.

There is deliberately no field for prompts, tool arguments, tool results,
credential values, project paths, approval narrative or case rationale.
Human-facing summaries come from fixed mappings rather than untrusted event
text.

## Correlation window and completeness

Decision and approval evidence starts 24 hours before the earlier of case
creation and the alert's first observation, and ends at the server time used to
build the response. Case lifecycle events are retained for the entire case.
The ordered response contains at most 500 events.

The response sets `complete: false` and lists stable reason codes when:

- the tenant decision index reports that its bounded window omitted older
  records; or
- more than 500 normalized events match the case.

When the record limit is exceeded, the newest 500 events remain visible and
`omittedEvents` reports the exact number omitted from the assembled set. This
is an operational view, not the complete portable evidence package. The
[audit-ready case export](incident-case-export-design.md) still refuses rather
than truncates when its evidence bounds are exceeded.

## UI behavior

The timeline defaults to **All activity** and offers facet filters with live
counts. Each row displays time, outcome, title, summary, actor and provenance;
the details affordance exposes only typed references. Credential and isolation
events have distinct visual treatment because they change authority. The UI
shows a prominent incomplete-evidence warning with the server reason and
omitted count.

Responsive layouts preserve chronology, filtering and provenance. Empty
facets explain that no matching evidence exists; they do not imply that the
control was never configured.

## Non-guarantees

The timeline does not prove endpoint isolation, cloud-provider credential
revocation, agent-reported execution or SIEM delivery. It does not replace the
integrity-verified case export or immutable audit records. Customer deployment
acceptance must still validate source retention, clock behavior, provider
evidence and incident-response operating procedures.

## Verification

Contract and adversarial tests cover chronological ordering, exact-agent
correlation, provenance, MCP and approval facets, fixed redaction, record-limit
and decision-window incompleteness, tenant isolation and rejection of raw
narrative. UI tests cover facet filtering, incomplete states, typed reference
details and responsive rendering. The repository quality gate remains
`make check`.

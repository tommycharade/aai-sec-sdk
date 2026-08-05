# Incident cases and containment

This design turns a server-derived endpoint alert into a governed investigation
without allowing endpoint evidence, browser input or model output to choose the
agent that loses authority. It covers the hosted AWS control plane and the
enrolled Claude Code and Codex runtime client.

## Security boundary

Endpoint evidence is an authenticated observation. It is not execution
authority. A case may be created for any retained endpoint alert, but a response
action is enabled only when the control plane independently resolves exactly one
active enrolled agent from current trusted facts:

1. the device is present and managed in current endpoint inventory;
2. its newest HMAC-verified report is fresh;
3. one reported installation supplies a host and project-root digest;
4. one active enrolled agent has that exact host and a server-hashed registered
   project root; and
5. the resulting binding is unique across the tenant.

Zero matches are `unbound`. Multiple matches are `ambiguous`. Both fail closed.
The UI cannot submit an agent identifier to override either result. Every
response mutation compares the live binding digest and case revision again.

```text
signed endpoint report       enrolled-agent registry
          |                           |
          +-- host + project digest --+
                         |
             unique server-side binding
                         |
alert -> case -> operator confirmation -> independent control record
                                            |
                       heartbeat evidence remains available
                       execution authority is withheld
```

## Case model

A case is tenant-scoped, revisioned and content-minimised. It retains:

- the source alert ID, type, severity, reason code and device ID;
- the authenticated owner and lifecycle status;
- the endpoint-to-agent binding snapshot and its digest;
- the affected deployment, group and active policy version when uniquely known;
- response actions and their resulting authority state; and
- an ordered, append-only timeline of fixed event types and bounded operator
  rationale.

Case statuses are `open`, `investigating`, `contained`, `resolved` and `closed`.
Creation is deterministic per alert, so concurrent requests cannot create two
active cases for one detection. Every mutation uses optimistic concurrency.

## Independent controls

Emergency stops and investigative quarantine are separate server-owned records:

- **fleet stop** blocks every enrolled agent in the tenant;
- **deployment stop** blocks one deployment;
- **group stop** blocks current and future members of one group;
- **agent stop** blocks one enrolled identity; and
- **quarantine** is owned by one case and one uniquely bound agent.

Clearing one scope never clears another. Legacy agent stop flags remain a
fail-closed compatibility input, but new deployment and group operations never
rewrite agent flags.

Quarantine permits only the authenticated heartbeat and attestation evidence
path. Effective policy, approvals, decision reporting and managed-package
retrieval are withheld. The heartbeat returns the exact server-owned authority
state and the SDK client fails closed before continuing normal service.

## Session revocation

A responder may separately revoke sessions from a bound case. Each agent has a
server-owned session revision copied into bootstrap and session records. The
control plane compares it on every request. Incrementing the revision
invalidates all old sessions and unused bootstrap material without scanning for
bearer-token hashes. New enrollment material is unavailable while quarantine
is active.

Session revocation is deliberately not implicit in investigative quarantine:
the evidence channel stays available unless the responder explicitly chooses
the stronger action.

## Brokered credential revocation

A responder may also revoke brokered cloud authority for the exact case-bound
agent. The browser supplies neither an agent ID nor broker list. The server
creates a revisioned case-owned control, and the machine-only credential
authority route denies new mints and callback-checked use across every current
and future registered broker for that agent. Sibling agents are unaffected.

Restoration requires the same current binding, all normal verification checks,
no active quarantine or independent stop and a recovered source alert. An
active credential control blocks case resolution and closure. See
[Incident-driven credential revocation](incident-credential-revocation-design.md).

## Release safeguards

Quarantine release requires all of the following live server evidence:

- the case and containment revisions match;
- the endpoint-to-agent binding is still unique and unchanged;
- endpoint inventory and the signed report are current;
- the enrolled agent passes identity, attestation, managed-configuration,
  ownership and policy checks when the quarantine itself is excluded; and
- the source posture alert is resolved, or an event alert has been
  acknowledged by incident response.

Release does not close the case. Resolution and closure are explicit, audited
transitions, and both are denied while any case-owned containment or credential
control remains active.

## API contract

The hosted API provides:

```text
GET  /api/enterprise/cases
POST /api/enterprise/cases
GET  /api/enterprise/cases/{caseId}
POST /api/enterprise/cases/{caseId}/contain
POST /api/enterprise/cases/{caseId}/release
POST /api/enterprise/cases/{caseId}/sessions/revoke
POST /api/enterprise/cases/{caseId}/credentials/revoke
POST /api/enterprise/cases/{caseId}/credentials/restore
POST /api/enterprise/cases/{caseId}/resolve
POST /api/enterprise/cases/{caseId}/close
```

Mutations require `incident_response`. Security operators, incident responders
and auditors may read cases; auditors cannot mutate them. Exact request schemas,
bounded rationale and secret-shaped-text rejection are enforced server-side.

## Non-guarantees

This control plane cannot isolate a laptop at the operating-system or network
layer. It withholds AAI-governed Claude Code and Codex authority when those
runtimes refresh policy or heartbeat. Customer MDM/EDR isolation, hardware-
backed device identity and independently verified response latency remain
deployment acceptance work. Splunk remains a non-delivering stub.

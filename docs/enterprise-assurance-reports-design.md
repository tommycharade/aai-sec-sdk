# Enterprise assurance reports

This design defines the first production-shaped implementation of P1-ADM-05.
It gives executives and auditors purpose-specific views of the same bounded,
tenant-owned evidence without presenting an operational dashboard as a
compliance certificate.

## Security boundary

Agent reports, discovery snapshots, policy metadata, alerts and browser input
are untrusted observations. They cannot grant authority or prove compliance.
The report API derives tenant and role from authenticated context, strongly
reads server-owned records and never accepts report facts from the caller.

The control plane therefore:

- exposes only two fixed report profiles: `executive` and `auditor`;
- requires a canonical tenant role and requires `evidence_read` for the auditor
  profile;
- derives every count from bounded tenant reads and fails instead of silently
  truncating a population;
- returns unavailable percentages when discovery evidence is incomplete;
- excludes project paths, user names, command content, credentials and raw tool
  arguments;
- labels observation gaps and non-guarantees next to the affected metric;
- includes section hashes and existing evidence endpoints so an auditor can
  trace a summary to detailed, independently retained evidence;
- hashes the complete canonical report so a downloaded snapshot can be checked
  for alteration; and
- performs no mutation, policy decision, approval, containment or agent action.

The content hash proves only that a downloaded report has not changed since it
was generated. It is not a signature, timestamp authority or compliance
attestation. Immutable audit evidence remains in the Object Lock evidence
store and is verified through the existing evidence-assurance workflow.

## Report profiles

### Executive posture

The executive view is aggregate-only. It shows known-population coverage,
healthy and compliant installation posture, policy governance, active
exceptions, open security work, evidence readiness and the most important
blind spots. It does not expose agent, device, policy, group or operator
identifiers.

### Auditor readiness

The auditor view contains the same aggregate posture plus bounded breakdowns,
policy and group references, exception/approval lifecycle counts and evidence
trace references. It still excludes raw sensitive content. Detailed immutable
records remain behind their existing least-privilege APIs rather than being
copied into the report.

## API contract

```text
GET /api/enterprise/reports/executive
GET /api/enterprise/reports/auditor
```

Both responses contain:

- schema version, fixed profile, generation time and canonical content hash;
- an overall `ready`, `attention` or `evidence_incomplete` posture;
- population, runtime, policy, exception, incident and evidence summaries;
- explicit blind spots and non-guarantees; and
- content-addressed trace entries for the report sections.

The auditor response additionally contains bounded business-unit and
repository breakdowns, policy/group references and routes to the current
discovery, endpoint, access-certification and immutable-evidence views.

## Operator journey

1. Open **Assurance** and choose Executive or Auditor view.
2. Read the posture statement and unresolved blind spots before interpreting a
   percentage.
3. Review coverage, runtime trust, policy governance, exceptions, incidents and
   evidence readiness.
4. In Auditor view, follow a trace entry to the least-privilege detailed source.
5. Download the current JSON snapshot and retain its SHA-256 value with the
   review record.
6. Use the evidence-assurance export—not this summary—as the immutable evidence
   package for an audit.

## Acceptance evidence

Contract tests must prove role separation, tenant isolation, fail-closed
coverage, bounded reads, deterministic hashes for a fixed clock, no sensitive
fields, no mutation, honest empty-state behavior and hash changes when source
evidence changes. UI tests must prove the two profiles have visibly different
information density, blind spots cannot be hidden, JSON download uses the
server-produced snapshot and mobile layouts do not overflow.

This slice does not implement a compliance framework mapping, signed report,
scheduled distribution or independent attestation. Those claims require a
reviewed controls catalogue and customer assurance process.

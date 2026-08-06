# Customer assurance pack

This is the buyer-facing index for the Agentic AI Security SDK and enterprise
control plane. It separates evidence that exists today from work that still
requires legal review, a customer environment or an independent assessor.

| Pack owner | Technical approval | Legal status | Approved | Next review |
| --- | --- | --- | --- | --- |
| Tom Mooney, project owner and security owner | Approved | Review required | 2026-08-05 | 2026-11-03 |

The schema-v2 machine-readable source is
`assurance/customer-assurance-pack.json`. CI validates its closed schema,
ownership, document existence, shared review clock, canonical vulnerability
policy and explicitly synthetic rehearsal, and independent-assurance claims.
An overdue or internally inconsistent pack fails `make check`.

Every tagged release attaches `customer-assurance-pack.zip`. The archive
contains this index, the machine-readable pack and every listed evidence
document. Its internal manifest hashes each file, and the release-level
`SHA256SUMS` hashes the archive, binding the reviewed claims to that release.

## Current assurance status

| Area | Current evidence | Honest status |
| --- | --- | --- |
| Security architecture | Published architecture, security model, threat boundaries and deployment responsibilities | Technically reviewed |
| Secure development | Guardrails, adversarial tests, ≥90% coverage gate, bounded mutation testing and dependency audits | Automated evidence; not independent certification |
| Supply chain | Per-artifact SBOMs, checksums, clean-install tests and GitHub provenance attestations in the release workflow | Implemented release control |
| Vulnerability management | Private intake, machine-enforced severity method, calendar-time targets and synthetic critical-response rehearsal | Public engineering commitment and tested record shape; not proof of staffed response or delivered notification |
| Data processing | Data categories, default AWS service boundary, optional providers and deletion/retention responsibilities | Technical disclosure; DPA and final subprocessor notice require legal review |
| Penetration test | Provider and scope not yet approved | Not completed |
| SOC 2 Type II | Roadmap only | Not certified |
| ISO 27001 | Roadmap only | Not certified |

## Approved technical guarantees

- The host, never model output, decides whether a governed action executes.
- Unknown tools and missing or malformed identity, policy, approval or other
  required security context fail closed at the SDK boundary.
- The release workflow produces checksums, per-artifact SBOMs and GitHub
  provenance attestations. The deterministic assurance archive is separately
  checksum-bound and provenance-attested.
- Paid functionality is not required for core fail-closed behavior, public
  contracts, security fixes or documentation.

These statements are bounded by the [security model](security-model.md),
[production-readiness matrix](production-readiness.md) and exact deployed
configuration. They are not promises about an integration that has not passed
its documented acceptance gate.

## Approved non-guarantees

- The product does not prove that an agent, model output or generated code is
  safe.
- Repository tests and signed assurance reports are not SOC 2, ISO 27001 or
  regulatory certification.
- Production identity, managed-host enforcement, isolation, credential and
  network controls require deployment-owned configuration and acceptance.
- No independent penetration-test completion is claimed by this pack.

## Pack contents

- `SECURITY.md` — security policy, private reporting route and support policy
- [Vulnerability management](vulnerability-management.md)
- [Detailed enterprise trust statement](enterprise-trust-pack.md)
- `security/vulnerability-management-policy.json` — canonical response authority
- `security/vulnerability-rehearsal.example.json` — explicitly synthetic rehearsal evidence
- [Security model](security-model.md)
- [Production readiness](production-readiness.md)
- [Testing and assurance](testing.md)
- [Release evidence and provenance](releasing.md)
- [Data processing and subprocessors](data-processing-and-subprocessors.md)
- [SOC 2 and ISO 27001 roadmap](compliance-roadmap.md)
- [Enterprise P0/P1 status](p0-p1-implementation-status.md)

## Buyer use

1. Confirm the review date is current and read the independent-assurance row
   before relying on any claim.
2. Match required controls to the responsibility matrix; do not treat a
   configurable UI field as deployed evidence.
3. Request customer-specific architecture, data-flow and acceptance artifacts
   for the intended Region, identity provider, managed hosts and integrations.
4. Require legal approval and an executed DPA before customer personal data is
   processed by a hosted pilot.
5. Record exceptions for every unmet rollout gate with owner, scope,
   compensating control and expiry.

This pack is technical due-diligence material, not legal advice, a contract or
an independent attestation.

The hosted control plane presents the same distinction through the
[customer assurance Trust Center](customer-assurance-trust-center-design.md).
The Trust Center does not enable its download action until a deployment-owned
manifest binds this pack to one independently verified immutable release.

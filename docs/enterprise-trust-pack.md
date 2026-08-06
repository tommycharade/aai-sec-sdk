# Enterprise trust pack

This page is the buyer-facing index for technical due diligence. It states what
the project can prove today, what remains deployment-owned and what must not be
represented as certification.

## Document control

| Field | Value |
| --- | --- |
| Technical owner | Tom Mooney, project owner |
| Security owner | Tom Mooney, project security owner |
| Technical statements reviewed | 5 August 2026 |
| Next review | 3 November 2026 (CI-enforced; an expired pack fails the repository gate) |
| Applies to | Draft SDK `1.1.0` source candidate; release claims become valid only when the release workflow binds this pack to the exact tag, commit, artifact digests, SBOMs and provenance |
| Legal status | Technical assurance statement; not a contract, DPA or certification |
| Approval status | Technical owner review only; legal/privacy approval and immutable release binding are outstanding |

## Executive position

This is a **draft pre-release assurance pack**, not evidence for an immutable
published artifact. The SDK is an Apache-2.0 execution-security boundary for agent actions. The
host, never the model, decides whether a tool executes. Unknown tools,
malformed input, missing identity/policy, stale authority and unverified
approval fail closed. The hosted control plane adds fleet policy, identity,
evidence, incident and reporting workflows.

The product does **not** guarantee that an AI agent is correct, that every host
is uncompromised, that customer IAM is least-privilege, or that using the SDK
creates regulatory compliance. Production claims require deployment-specific
identity, endpoint, credential, isolation, evidence and recovery acceptance.

## Evidence available now

| Buyer question | Evidence | Current conclusion |
| --- | --- | --- |
| Can the model bypass execution approval? | [Security model](security-model.md), adversarial runtime tests | Host-owned boundary; model output supplies no principal, credential or approval authority |
| Is the release supply chain verifiable? | [Releasing](releasing.md), [v1.0.1 release evidence](release-evidence-v1.0.1.md) | Checksums, per-artifact SBOMs and GitHub provenance are required and independently verified |
| Is evidence durable and recoverable? | [Durable evidence governance](durable-evidence-governance-design.md), [recovery acceptance](cross-region-audit-recovery-acceptance-2026-08-01.md) | Object Lock and exact-version cross-region verification are implemented in the reference AWS stack |
| Are policies and reports signed? | [Signed bundles](signed-policy-bundles-design.md), [assurance reports](enterprise-assurance-reports-design.md) | Domain-separated KMS signatures and historical verification trust are implemented |
| How are vulnerabilities handled? | [Vulnerability management](vulnerability-management.md), machine policy and rehearsal | Calendar-time targets are explicit and CI-verifiable; checked rehearsal is synthetic |
| What data is processed? | [Data processing and subprocessors](data-processing-and-subprocessors.md) | Categories, minimisation, locations, retention constraints and providers are documented |
| Is enterprise identity complete? | [P0/P1 status](p0-p1-implementation-status.md) | Entra/SCIM/RBAC implementation exists; real customer-tenant acceptance remains outstanding |
| Is regional recovery proven? | [Regional recovery design](regional-control-plane-recovery-design.md) | Storage continuity is live; serving-cell failover at target scale remains outstanding |

## Guarantees

When the documented runtime is correctly integrated and its required adapters
are healthy:

- every consequential action is evaluated with live identity, arguments,
  resource, purpose and policy;
- deny, approval-required and allow are structured decisions;
- credentials, principals and approval state are never accepted from model
  output;
- redaction happens before configured persistence/export boundaries;
- signed artifacts are verified against configured trust and exact bytes; and
- audit or authority uncertainty cannot be converted into apparent success.

These guarantees do not cover code paths that bypass the SDK, unmanaged agent
launchers, customer-created permissive IAM, disabled host controls or adapters
that falsely attest external state.

## Known gaps that block an enterprise-wide claim

- No independent penetration test has yet produced a clean critical/high
  closure report.
- No executed DPA, legal/privacy approval or production support roster exists;
  the four-hour critical acknowledgement is a project target, not 24x7 proof.
- This pack is not yet bound to a published `1.1.0` tag, commit, checksums,
  SBOMs and provenance. Until that release evidence exists, it supports review
  of this source candidate only.
- The reference deployment has not completed live Microsoft Entra OIDC/SCIM
  joiner, mover, leaver and two-person MFA acceptance.
- Managed Claude Code and Codex enforcement has not been deployed through a
  real customer MDM across the approved pilot denominator.
- Regional serving-cell failover, dependency fault injection and 1,000-agent
  RTO/RPO acceptance remain unexecuted.
- Production cloud credential inventories, hardened sandbox selection,
  customer-specific data residency/private access and customer legal terms
  remain deployment-owned.
- Splunk is an explicitly non-delivering stub in this iteration.

The [inputs needed from the product owner](needed-from-from.md) lists the exact
external evidence and authority required to close these items.

## Certification roadmap

The project is not currently SOC 2 or ISO 27001 certified.

| Target | Planned evidence | Earliest planning window | Dependency |
| --- | --- | --- | --- |
| Control baseline | Asset/vendor registers, risk method, access review, vulnerability and incident procedures | Q3 2026 | Named control owners and retained operation evidence |
| Independent security assessment | External penetration test and verified critical/high remediation | Q4 2026 | Approved testing provider and production-like scope |
| SOC 2 readiness / ISO 27001 gap analysis | Independent scope and control-design review | Q4 2026 | Legal entity, service boundary and auditor selected |
| SOC 2 Type I / ISO ISMS implementation | Design evidence, policies, internal audit and management review | Q1–Q2 2027 | Staffed control operation and risk treatment |
| SOC 2 Type II / ISO certification audit | Observation-period evidence and independent audit opinion | Q3–Q4 2027 at earliest | Auditor schedule and sustained operating effectiveness |

Dates are planning targets, not certification promises. Only an independent
auditor can issue an opinion or certificate.

## Buyer acceptance gate

Before a paid pilot, agree the managed-agent denominator, supported agent/tool
versions, identity tenant, endpoint-management path, approved policy baseline,
data/retention terms, incident contacts, recovery objectives and success/exit
criteria. Retain the exact deployment and test evidence. A green repository
build alone is not customer production acceptance.

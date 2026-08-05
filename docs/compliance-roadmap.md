# SOC 2 and ISO 27001 roadmap

The project is not SOC 2 Type II certified and is not ISO/IEC 27001 certified.
This roadmap describes the evidence and operating system needed to pursue those
assessments; it is not a target-date promise or a framework-mapping claim.

## Phase 1 — accountable scope and gap assessment

- establish the legal/service boundary, asset inventory and control owners;
- approve risk methodology, information-security policies and exception flow;
- map product and deployment responsibilities to candidate Trust Services
  Criteria and ISO 27001:2022 controls with qualified reviewer input;
- approve DPA, subprocessors, vulnerability SLA and incident contacts; and
- commission an independent penetration test with authenticated control-plane,
  tenant-isolation, host-boundary and cloud-infrastructure scope.

Exit evidence: approved scope, owner matrix, risk register, reviewed mappings,
legal pack and no unresolved critical/high penetration-test finding.

## Phase 2 — operating evidence

- operate access reviews, joiner/mover/leaver, change approval, vulnerability,
  incident, backup/recovery, supplier and secure-development controls;
- retain immutable evidence for the selected observation period;
- exercise Entra SSO/SCIM, break glass, regional recovery, notification,
  deletion, key recovery and customer offboarding; and
- remediate control-design and operating-effectiveness gaps.

Exit evidence: management-approved readiness review with sampled operating
records and all exceptions owned, bounded and unexpired.

## Phase 3 — independent assessment

- engage an accredited/qualified assessor for the approved scope;
- provide source evidence through least-privilege, integrity-verifiable
  channels;
- track findings without rewriting historical evidence; and
- publish only the exact report/certificate, scope, period and exceptions
  issued by the assessor.

The assurance manifest may change `soc2_type_ii` or `iso_27001` to `certified`
only when a reviewed evidence document is included in the pack. CI rejects a
certification label without that evidence.

## Current blockers

- legal entity, DPA and final subprocessor terms;
- approved framework scope and qualified mapping review;
- independent penetration-test provider and remediation evidence;
- first-customer operating period and control owners; and
- external assessor selection and commercial approval.

Tenant assurance snapshots and repository CI are useful source evidence. They
are not a substitute for an assessor's opinion or certificate.

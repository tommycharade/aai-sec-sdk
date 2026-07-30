# Inputs needed from the product owner

This is the live owner-input checklist for completing the enterprise P0 and P1
requirements. It separates engineering that can continue autonomously from
decisions, credentials, physical-device actions and independent evidence that
only the product owner or an enterprise stakeholder can provide.

Never place passwords, client secrets, SCIM bearers, signing keys or production
credentials in source control, issues, documentation or chat. Store secrets in
the approved secrets manager and provide only the secret resource name.

## Immediate critical-path inputs

### Microsoft Entra ID pilot

- Microsoft Entra tenant UUID.
- Entra application/client ID.
- AWS Secrets Manager name containing the OIDC client secret.
- The AAI tenant to bind to the Entra directory, or approval to create a new
  pilot tenant.
- AWS Secrets Manager name containing a separate SCIM bearer of at least 32
  characters.
- Confirmation that Conditional Access requires MFA for pilot administrators.
- At least two administrator identities, one operator and one test leaver.
- Entra group UUIDs for platform administrators, identity administrators,
  policy authors, policy approvers, fleet operators, incident responders and
  auditors.
- An Entra administrator able to configure the Cognito redirect URI and SCIM
  enterprise application when the runbook requests it.

These inputs are required to replace the deployed `not-configured` Entra OIDC
and SCIM posture with real joiner, mover, leaver, role-transition, four-eyes
and access-certification evidence.

### Managed Claude Code and Codex hosts

- Confirmation that `/Users/tommooney/dev/kratos` remains the first local
  Claude Code and Codex pilot project.
- A product-owner-run `sudo` step when macOS requests a password; automation
  must never collect or persist the password.
- The endpoint-management path: Microsoft Intune, Jamf, Kandji or an explicitly
  time-bounded local root-owned pilot.
- Whether policy applies per project, per user or system-wide.
- The approved skills, MCP servers, command patterns, network destinations and
  project paths.
- Whether local weakening is always denied or may use an expiring, audited
  exception.
- Working Claude Code and Codex installations on the pilot host.
- At least one genuinely managed test device before claiming enterprise
  endpoint enforcement.

The recommended sequence is a root-owned local Kratos pilot followed by
Microsoft Intune, because Microsoft Entra ID is the first identity provider.

### Runtime attestation and release trust

- Approval of the next public release version.
- Authorization to create the GitHub release and publish signed artifacts.
- Approval to use GitHub OIDC and Sigstore for release signing.
- Supported Claude Code and Codex version ranges.
- Permission to generate and deploy pinned runtime manifests.
- A managed host for modified package, hook, configuration, process identity,
  replay and quarantine tests.
- A later decision on hardware-backed device identity, such as an MDM-issued
  certificate or platform attestation.

These inputs are required to replace the deployed `not-configured` runtime
attestation posture with release-bound enforcement evidence.

### GitHub organization discovery pilot

- GitHub organization slug and an agreed complete repository denominator.
- An organization-approved read-only credential stored in the deployed AWS
  Secrets Manager namespace; provide only its secret ARN to the control plane.
- Independent evidence that the credential can enumerate every repository in
  scope, including private repositories.
- A reviewed repository-to-project-root mapping and expected Claude Code or
  Codex host selection for each active repository.
- Approval to migrate from the initial token adapter to a centrally installed
  GitHub App when that integration is implemented.

These inputs are required to replace the synthetic failure-path acceptance
with successful collection and measured source-control coverage. The current
hosted connector and UI workflow are deployed and synthetically validated.

## Enterprise operating decisions

The following decisions can be supplied progressively:

- organization, project, team and deployment hierarchy;
- delegated administrators for each business unit;
- operations requiring independent two-person approval;
- break-glass duration and accountable owners;
- policy-exception duration and approval requirements;
- heartbeat, stale and unhealthy thresholds;
- automatic quarantine and recovery rules;
- retention period per tenant and legal-hold requirements;
- required AWS regions and data-residency constraints;
- recovery-time and recovery-point objectives;
- customer-managed KMS key requirements; and
- private networking requirements such as VPN-only access or AWS PrivateLink.

## Production security integrations

These inputs are not required for the next autonomous engineering slice, but
are required before an enterprise production claim:

- AWS, Azure and GCP production role inventories for the credential broker;
- approved test accounts and roles for issuance and revocation evidence;
- production isolation choice: container, microVM, endpoint sandbox or
  customer-owned runner;
- endpoint credential-revocation mechanism;
- case-management or SOAR destination;
- vulnerability owner and remediation SLA; and
- independent penetration-testing provider.

Splunk remains an explicitly labelled non-delivering stub for the current
iteration. No Splunk credential is required yet.

## Customer-readiness inputs

- Target customer size, regulated sector and expected managed-agent count.
- Pilot size, such as 25, 100 or 1,000 installations.
- Commercial packaging decision. The recommended model is the Apache-2.0 SDK
  plus a paid hosted enterprise control plane and support offering.
- Product name, domain, support address and approved branding.
- A pilot customer or design partner for observed workflow testing.
- Required assurance targets, such as SOC 2, ISO 27001, Cyber Essentials or
  GDPR.
- Pricing assumptions or authority for the product team to propose pricing.

## Work that can continue without owner input

Engineering can continue autonomously on:

- bulk enrollment import and dynamic groups;
- production identity, endpoint and source-control connector packaging for the
  implemented orphan/leaver reconciler;
- managed upgrades and expiring exceptions;
- policy simulation, semantic diff, inheritance, scheduling and signed
  bundles;
- security cases, quarantine, automatic containment and credential-revocation
  workflows;
- executive and auditor reporting;
- Terraform deployment support;
- customer-managed key, residency and private-access implementation;
- UI simplification, accessibility and responsive browser testing; and
- documentation, threat models, automated tests, pull requests, AWS deployment
  and synthetic acceptance evidence.

Progress and evidence remain tracked in the
[enterprise P0 and P1 implementation status](p0-p1-implementation-status.md).

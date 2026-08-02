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

Engineering no longer needs six values to be re-entered for every deployment.
Once supplied, the deployment guard validates the secret references, tenant
binding and Microsoft OIDC metadata and stores the secret-free configuration in
encrypted Parameter Store. See the
[persistent Entra deployment guard](entra-deployment-guard-design.md).

### Recovery-region identity foundation

The passive regional cell is implemented but must not be deployed with a
synthetic or primary-region identity. The `p1` AWS account currently has no
Cognito user pool in `eu-west-1`, and the primary stack still reports Microsoft
Entra ID as `not-configured`. To cross this gate, provide:

- approval to configure Cognito managed login multi-Region resiliency for the
  pilot identity pool, with `eu-west-1` as the recovery Region;
- the resulting real `eu-west-1` user-pool ID and app-client ID after AWS has
  created and verified them;
- the Microsoft Entra pilot inputs listed above, including the administrator
  who can register both primary and recovery redirect URIs; and
- retained acceptance references for recovery-region login, strong
  authentication and joiner/mover/leaver behavior.

When those values exist, copy `infra/aws-control-plane/passive-cell.example.json`
outside the repository, replace its synthetic identities/evidence references,
and use the three-stage deployment guard documented in the
[passive regional cell design](passive-regional-cell-design.md). No table,
bucket, account or key ARN needs to be supplied manually.

Do not create placeholder identity resources or reuse the `eu-west-2` pool to
unblock deployment. The stack rejects wrong-Region identity and remains
non-serving until a separate reviewed activation change.

### Regional routing and activation exercise

The read-only activation preflight and bounded exercise contract are
implemented. Live activation still requires owner/platform inputs that cannot
be invented by engineering:

- the Route 53 hosted-zone ID and approved stable API/UI domain names;
- approval to deploy the single-writer transition witness in a third Region
  (`eu-central-1` is the proposed first-customer Region), plus the retained
  change reference for its deployment;
- ACM certificates and authority to close both raw execute-api origins;
- approved Region-specific API/UI canary names and ACM certificate ARNs for
  both the primary and recovery Regions;
- approval for a dedicated Route 53 transition role plus an organization SCP
  or equivalent boundary that removes ordinary DNS-write authority;
- two independent named approvers for each failover and failback rehearsal;
- an approved change window in which source fencing, synthetic dependency
  failures and stable-route movement may be exercised;
- confirmation that 1,000 synthetic agents is the approved first-customer
  target, or a reviewed replacement regional-recovery manifest;
- backup/key-recovery and break-glass exercise participants; and
- approval to retain the exact activation bundle in the primary COMPLIANCE
  Object Lock bucket.

The activation manifest must be created only for the scheduled exercise and
expires within one hour. Do not commit it or its provider evidence. The
[regional activation and exercise design](regional-activation-and-exercise-design.md)
documents the exact fields, checks and non-mutating preflight command.
The [guarded transition executor](regional-transition-executor-design.md) is
implemented, but its mutating commands must not be used until every item above
is real, retained and approved. The separate routing executor can move traffic
under schema-v3 authority and can perform template-bound failed-cutover
rollback only under schema-v4 authority and the dedicated role; neither path
has been run live.
The [transition journal design](regional-transition-journal-design.md) explains
why the witness must not be converted to a Global Table and how the two Entra
approver identities and expected routing generation are supplied.
The [target-readiness and stable-ingress design](regional-target-readiness-and-stable-ingress-design.md)
defines the implemented serverless custom-domain topology, guarded deployment
commands and remaining routing inputs. Each Regional certificate must be
issued and fully validated in that Region and contain exactly four SANs: the
stable API/UI names plus that Region's API/UI canary names. Copy the checked-in
example manifest outside the repository; do not commit real domain,
certificate or approval authority.

The primary target adapter, exact source reactivation, failed-cutover rollback
and symmetric planned failback are implemented and synthetically tested.
Engineering can continue without owner input on exercise automation and
target-cell fault controls. Exact evidence packaging, immutable retention and
the real target load adapter are implemented and synthetically tested. Live
routing cannot continue until the listed domains,
certificates, Entra token path, two approvers, retained schema-v4 template
digests, exact-handler invocation authority and exclusive Route 53 authority
are supplied and approved.

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
- managed upgrades and live acceptance of implemented expiring exceptions;
- policy inheritance, scheduling and signed bundles;
- credential-revocation workflows and broader tool/MCP anomaly response;
- executive and auditor reporting;
- Terraform deployment support;
- customer-managed key, residency and private-access implementation;
- UI simplification, accessibility and responsive browser testing; and
- documentation, threat models, automated tests, pull requests, AWS deployment
  and synthetic acceptance evidence.

Progress and evidence remain tracked in the
[enterprise P0 and P1 implementation status](p0-p1-implementation-status.md).

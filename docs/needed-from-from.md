# Inputs needed from the product owner

This is the live owner-input checklist for completing the enterprise P0 and P1
requirements. It separates engineering that can continue autonomously from
decisions, credentials, physical-device actions and independent evidence that
only the product owner or an enterprise stakeholder can provide.

Never place passwords, client secrets, SCIM bearers, signing keys or production
credentials in source control, issues, documentation or chat. Store secrets in
the approved secrets manager and provide only the secret resource name.

## Immediate critical-path inputs

### Incident workflow live acceptance

The ServiceNow, Jira Cloud and PagerDuty software foundation is implemented and
synthetically tested. Live acceptance needs one customer-owned non-production
provider selected for the first pilot and inputs engineering must not invent:

- provider instance, site or service and its accountable owner;
- a least-privilege service identity or routing key stored under
  `aai-sec/workflows/<tenant>/<connection>` using the deployed
  `WorkflowCredentialKeyArn`;
- ServiceNow assignment group, Jira project/issue type, or PagerDuty service
  label and escalation owner;
- approved egress/proxy rules and DNS-rebinding control evidence;
- a change window to verify create, update, resolve, response-loss
  reconciliation, provider outage, controlled retry, credential rotation and
  credential revocation; and
- retained provider record IDs and change/evidence references for the test.

Provide only the secret ARN to the UI. Never paste credential JSON into this
document, source control, chat or a ticket. Until this acceptance is complete,
P1-SOC-09 is an implemented production-shaped foundation, not a claim of live
compatibility with customer provider customization.

### AWS CDK development-tooling advisory decision (2026-08-04)

The latest published `aws-cdk-lib@2.263.0` bundle contains
`brace-expansion@5.0.8`. `npm audit` now reports
`GHSA-rgw5-rvv9-x895` as high severity and requires `5.0.9`. The package is a
build/deployment-only dependency and is absent from the SDK, UI and Lambda
runtime, but the previous dated exception covers a different advisory and must
not be silently widened.

Choose one of these paths:

- wait for AWS CDK to publish a bundle containing `brace-expansion>=5.0.9`,
  then upgrade the exact pin; or
- explicitly approve a new dated, owner-assigned development-tooling risk
  record with compensating controls and an expiry no later than 2026-08-28.

No credential or production input is required. Until one path is chosen, a
clean full Node development-dependency audit remains blocked; production-only
dependency audit remains clear.

### Machine API live acceptance

The scoped service-identity implementation and synthetic adversarial contracts
are complete. First-customer acceptance still needs owner/platform inputs that
engineering must not invent:

- one approved non-production CI or evidence-export workload;
- the enterprise secret-manager destination and operator who can write it;
- the minimum required capability set and a 7–30-day pilot lifetime;
- approval to deploy the machine route to the pilot AWS stack;
- a maintenance window to prove old-bearer denial after rotation and immediate
  denial after revocation; and
- the retained change/evidence reference for the exercise.

Do not paste the issued bearer into this document, source control, chat or a
ticket. The UI reveals it once; the target secret manager is the only approved
destination.

### Current `p1` Regional deployment preflight (2026-08-05)

A read-only AWS inspection found the following state. Resource identifiers are
intentionally omitted from this public document; the provider remains the
source of truth.

| Boundary | Observed state | Deployment consequence |
| --- | --- | --- |
| Primary control plane | Stable stack is `UPDATE_COMPLETE`; termination protection is off; Entra, SCIM and runtime attestation report `not-configured`; Regional fault-target outputs and bootstrap assurance-signing authority are deployed | Do not represent bootstrap identity/release authority as enterprise acceptance; enable termination protection and independently verify any Regional activation template |
| Recovery storage/signing | Audit replica and staged multi-Region signing replica exist | Foundation only; this does not create a serving recovery cell |
| Recovery identity | No recovery-Region Cognito pool exists | Passive/active recovery runtime deployment is denied |
| Regional certificates | No ACM certificate exists in either application Region | Regional ingress deployment is denied |
| Hosted DNS | One public hosted zone exists, with no stable API/UI or generation-marker records | Owner must approve exact names and exclusive transition authority before ingress/routing |
| Recovery runtime and ingress | Passive runtime, active target and both Regional ingress stacks are absent | No target can be activated or routed |
| Third-Region coordination | CDK bootstrap, transition witness, security-alert topic, fault controller and persisted `/aai-sec/` authority are absent | Bootstrap and separately approve the retained witness/alert/controller deployment before any exercise |

This is a blocker report, not permission to create the missing authority.
Synthetic CI values must not be reused. Repeat the read-only inspection after
the owner inputs below are supplied and before preparing any mutating command.

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
Exact evidence packaging, immutable retention and the real target load adapter
are implemented and synthetically tested. The private 18-state Step Functions
workflow, fault authority, exact target identities, single-writer lock,
independent watchdog, code-owned IAM boundaries, expiry-safe cleanup, live
journal/template/runtime/routing preconditions and target-role audit,
DynamoDB, KMS and queue probes are implemented and synthetically tested.
Cognito dependency injection remains unsupported because authentication is
outside the target handler role. Live routing and fault acceptance cannot
continue until the listed domains,
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

### Hosted endpoint-remediation provider

Executable-free remediation coordination and its read-only operator view are
implemented and synthetically tested. The software validates an immutable
package registry, derives a `1:1:1` endpoint readiness binding, governs an
Intune credential reference through independent approval and can create exact
dormant outbox commands transactionally. The checked-in package authority is
intentionally empty, dispatch is explicitly disabled and no customer device is
claimed as ready. A hosted Intune dispatcher remains deliberately gated on
provider-owned inputs that engineering must not invent:

- the approved endpoint-management provider and a non-production managed-device
  cohort;
- customer-approved immutable package records for each pilot OS/architecture,
  including exact versioned S3 objects, signatures and independent approval
  evidence bound to an approved runtime release;
- fresh schema-v2 signed endpoint evidence and current MDM inventory that make
  the software-derived managed-device, SDK installation and enrolled-agent
  mapping bijective for every pilot endpoint;
- a tenant-tagged Secrets Manager resource and dedicated IAM execution role for
  the provider adapter, with no provider credentials exposed to the browser,
  model or enrolled agent;
- separate read-only discovery and delivery application identities; the
  discovery credential must not be widened silently;
- customer-approved AAI-owned assigned-membership Entra device-group authority
  and the Intune mobile-app IDs whose digests match the package manifests;
- Graph permission and scope evidence proving the adapter can manage only the
  intended device identities, AAI-owned groups and approved app assignments;
- approved privilege, restart, retry and maintenance-window behavior; and
- retained provider job evidence and a live acceptance window proving that a
  channel success remains `awaiting_attestation` until the governed host emits
  fresh exact runtime evidence.

The isolated hosted worker now exists but remains deployment-disabled. Before
the first pilot, provide the inputs above, retain an adapter-specific review,
create the exact secret resource registry, and approve a lowercase SHA-256
enablement evidence identity. Set that digest together with
`ENDPOINT_DELIVERY_DISPATCH_ENABLED=true`; CDK rejects either input alone.
Commands are bounded at 500 targets and use 40-target revisioned
continuations. The product still does not claim live Intune compatibility,
remote installation success or causal proof until a real provider run is
followed by fresh exact runtime attestation.

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
- the approved execute-api VPC endpoint IDs, VPN or Direct Connect path, DNS,
  endpoint policy and security-group design for live PrivateLink acceptance.

## Production security integrations

These inputs are not required for the next autonomous engineering slice, but
are required before an enterprise production claim:

- AWS, Azure and GCP production role inventories for the credential broker;
- approved test accounts and roles for issuance and revocation evidence;
- exact AWS role ARNs, Entra tenant/client UUID pairs and GCP service-account
  identities, with approved audiences, tools, resources, scopes and maximum
  session lifetimes;
- a deployment-owned token-exchange endpoint/client and live revocation source
  for each provider, plus a secret-manager location for any provider material;
- an independent cloud-IAM reviewer and an operator authorized to run the
  allowed, widened-scope, expiry, outage and revocation acceptance exercises;
- production isolation choice: container, microVM, endpoint sandbox or
  customer-owned runner;
- immutable worker/runtime identities, exact filesystem/network/process/
  resource/credential constraints, platform evidence issuer and revocation
  source for that isolation choice;
- independent hostile-code assessor and an authorized operator who can retain
  escape, forbidden-access, exhaustion, outage and revocation evidence;
- endpoint credential-revocation mechanism;
- case-management or SOAR destination;
- vulnerability owner and remediation SLA; and
- independent penetration-testing provider.

Splunk remains an explicitly labelled non-delivering stub for the current
iteration. No Splunk credential is required yet.

Secure-webhook implementation can be developed and synthesized without a
customer endpoint. Live acceptance requires a customer-controlled public HTTPS
receiver, an approved secret-manager location, a durable atomic replay store,
the permitted egress/DNS policy and an operator who can retain evidence from a
verification, key-overlap rotation, interruption, bounded retry and DLQ replay
exercise. These inputs are not permission to send production events; event
types and test tenant must be approved explicitly.

## Customer-readiness inputs

- Legal contracting entity, registered address, privacy/security contact and
  authority to approve the DPA and final subprocessor terms.
- Independent penetration-test provider, approved scope and remediation budget.
- Named security-assurance owner for annual critical/high vulnerability
  tabletop evidence and framework-readiness review.
- Target customer size, regulated sector and expected managed-agent count.
- Pilot size, such as 25, 100 or 1,000 installations.
- Commercial packaging decision. The recommended model is the Apache-2.0 SDK
  plus a paid hosted enterprise control plane and support offering.
- Product name, domain, support address and approved branding.
- A pilot customer or design partner for observed workflow testing.
- Required assurance targets, such as SOC 2, ISO 27001, Cyber Essentials or
  GDPR.
- Pricing assumptions or authority for the product team to propose pricing.

### macOS endpoint sensor rollout

The repository includes a digest-bound macOS installer-package builder and a
fixed root launch-daemon contract. Live acceptance still needs:

- an independently built and signed production sensor executable;
- an Apple installer signing identity;
- customer MDM package and protected per-device configuration delivery;
- a non-production managed macOS cohort; and
- a retained pilot window for package, process and report-freshness evidence.

Per-device key IDs and secrets must be delivered as protected files by the MDM
and must never be embedded in the common installer package.

### Buyer assurance and incident readiness

The technical enterprise trust pack, vulnerability SLA, synthetic critical-
incident rehearsal, data-processing inventory, subprocessor register and
SOC 2/ISO 27001 roadmap are now maintained in the repository. They do not
replace owner selection of an independent penetration-testing provider, legal
approval of a customer-specific DPA or an auditor's certification opinion.
Production support also requires a second authenticated vulnerability-intake
route, a named escalation roster with calendar-time coverage, legal/privacy
approval of the trust statements and a release workflow that binds the final
pack to the `1.1.0` tag, commit, artifact digests, SBOMs and provenance.

## Work that can continue without owner input

Engineering can continue autonomously on:

- production identity, endpoint and source-control connector packaging for the
  implemented orphan/leaver reconciler;
- managed SDK, gateway and hook upgrades with approved drift remediation;
- live customer acceptance of implemented expiring exceptions, policy
  composition, scheduled rollout and signed bundles;
- live-provider credential-revocation acceptance and customer-specific load
  proof for the implemented exact-agent behavior baseline storage;
- external assurance-report delivery and reviewed framework mappings; signed,
  scheduled in-product retention and verification are implemented without
  customer delivery authority;
- Terraform Registry namespace/repository authority, release-signing identity
  and an approved non-production tenant for live provider acceptance;
- live acceptance inputs for the implemented customer-managed key, residency,
  deletion and private operator ingress, including approved VPC endpoint IDs,
  VPN/Direct Connect routing, private DNS, endpoint policy and security groups;
- UI simplification, accessibility and responsive browser testing; and
- documentation, threat models, automated tests, pull requests and synthetic
  acceptance evidence.

The maximum 500-target Intune continuation path now has reproducible
[synthetic acceptance evidence](synthetic-intune-continuation-acceptance-2026-08-05.md).
Customer-specific capacity proof and live Microsoft provider acceptance remain
owner-dependent and are not implied by that result.

AWS deployment may continue only for stacks whose real owner-approved inputs
already exist. Synthetic values may be used for synthesis and CI verification,
never to create production or pilot authority.

Progress and evidence remain tracked in the
[enterprise P0 and P1 implementation status](p0-p1-implementation-status.md).

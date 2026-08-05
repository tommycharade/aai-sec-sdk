<!-- THIS FILE IS GENERATED. Edit docs/README.md and run `make docs`. -->

# Agentic AI Security SDK

The Agentic AI Security SDK is an open-source execution-security runtime for agentic systems. It is designed around a simple boundary:

> The model proposes; the host validates, authorizes, approves, executes, records, and can stop.

## Start here

- [Getting started](docs/getting-started.md)
- [Security model](docs/security-model.md)
- [Persistent audit-recovery deployment guard](docs/audit-recovery-deployment-guard-design.md)
- [Cross-region audit recovery acceptance — 2026-08-01](docs/cross-region-audit-recovery-acceptance-2026-08-01.md)
- [Regional control-plane recovery design](docs/regional-control-plane-recovery-design.md)
- [Regional recovery storage runbook](docs/regional-recovery-storage-runbook.md)
- [Regional recovery storage acceptance — 2026-08-02](docs/regional-recovery-storage-acceptance-2026-08-02.md)
- [Passive regional control-plane cell](docs/passive-regional-cell-design.md)
- [Regional activation and recovery exercise](docs/regional-activation-and-exercise-design.md)
- [Guarded regional transition executor](docs/regional-transition-executor-design.md)
- [Regional transition witness and journal](docs/regional-transition-journal-design.md)
- [Regional target readiness and stable ingress](docs/regional-target-readiness-and-stable-ingress-design.md)
- [Managed policy-signing trust convergence](docs/policy-trust-convergence-design.md)
- [Managed policy-trust convergence acceptance — 2026-08-02](docs/policy-trust-convergence-acceptance-2026-08-02.md)
- [Operational runbooks](docs/runbooks.md)
- [Testing and assurance](docs/testing.md)
- [Customer assurance pack](docs/customer-assurance-pack.md)
- [Vulnerability management](docs/vulnerability-management.md)
- [Data processing and subprocessors](docs/data-processing-and-subprocessors.md)
- [SOC 2 and ISO 27001 roadmap](docs/compliance-roadmap.md)
- [Production readiness](docs/production-readiness.md)
- [Architecture](docs/architecture.md)
- [Cloud credential authority](docs/cloud-credential-authority-design.md)
- [Production isolation authority](docs/production-isolation-authority-design.md)
- [Agent integrations](docs/integrations.md)
- [Claude Code example](docs/claude-code.md)
- [Real Claude Code acceptance harness](docs/real-claude-code-acceptance-harness.md)
- [Real Claude Code acceptance evidence — 2026-08-05](docs/real-claude-code-acceptance-evidence-2026-08-05.md)
- [Real Codex CLI acceptance harness](docs/real-codex-cli-acceptance-harness.md)
- [Real Codex CLI acceptance evidence — 2026-08-05](docs/real-codex-cli-acceptance-evidence-2026-08-05.md)
- [Synthetic Intune continuation acceptance — 2026-08-05](docs/synthetic-intune-continuation-acceptance-2026-08-05.md)
- [Management UI](docs/ui.md)
- [Enterprise fleet control plane](docs/enterprise-fleet.md)
- [AWS-managed discovery connectors](docs/scheduled-discovery-connectors-design.md)
- [Endpoint evidence publisher](docs/endpoint-evidence-publisher-design.md)
- [macOS endpoint sensor MDM package](docs/macos-endpoint-sensor-package.md)
- [Hosted endpoint evidence and fleet health](docs/hosted-endpoint-evidence.md)
- [Endpoint detection and response](docs/endpoint-detection-response.md)
- [Incident cases and containment](docs/incident-case-containment-design.md)
- [Incident-driven credential revocation](docs/incident-credential-revocation-design.md)
- [Unified investigation timeline](docs/unified-investigation-timeline-design.md)
- [Audit-ready incident case export](docs/incident-case-export-design.md)
- [Durable evidence governance](docs/durable-evidence-governance-design.md)
- [Asynchronous tenant retention](docs/asynchronous-retention-design.md)
- [Asynchronous mass-retention acceptance — 2026-08-01](docs/async-retention-acceptance-2026-08-01.md)
- [Asynchronous evidence assurance acceptance — 2026-08-01](docs/async-evidence-acceptance-2026-08-01.md)
- [Approved automatic response rules](docs/automatic-response-rules-design.md)
- [Explainable agent behavior detection](docs/behavior-detection-design.md)
- [Repository and configuration anomaly detection](docs/repository-configuration-anomaly-design.md)
- [Fleet integrity baseline storage](docs/fleet-integrity-baseline-storage-design.md)
- [Object-backed discovery ingestion](docs/object-backed-discovery-ingestion-design.md)
- [Governed alert suppression and deduplication](docs/alert-suppression-design.md)
- [Endpoint evidence publisher acceptance — 2026-08-01](docs/endpoint-evidence-acceptance-2026-08-01.md)
- [macOS endpoint sensor package acceptance — 2026-08-06](docs/macos-endpoint-sensor-package-acceptance-2026-08-06.md)
- [Dynamic policy groups](docs/dynamic-groups-design.md)
- [Policy editor](docs/policy-editor.md)
- [Enterprise console navigation](docs/console-navigation-design.md)
- [Policy governance design](docs/policy-governance-design.md)
- [Policy composition and GitOps](docs/policy-composition-and-gitops-design.md)
- [GitHub App policy-source authentication](docs/github-app-policy-source-auth-design.md)
- [Policy change assurance](docs/policy-change-assurance-design.md)
- [Enterprise assurance reports](docs/enterprise-assurance-reports-design.md)
- [Scoped service identities and machine API](docs/service-identities-design.md)
- [Terraform provider and declarative management](docs/terraform-provider-design.md)
- [Secure webhooks](docs/secure-webhooks-design.md)
- [Governed incident workflow integrations](docs/incident-workflow-integrations-design.md)
- [Enterprise data boundary](docs/enterprise-data-boundary-design.md)
- [Policy change assurance live acceptance — 2026-08-01](docs/policy-change-assurance-acceptance-2026-08-01.md)
- [Signed policy bundles](docs/signed-policy-bundles-design.md)
- [Signed policy bundle acceptance — 2026-08-01](docs/signed-policy-acceptance-2026-08-01.md)
- [Time-limited policy exceptions](docs/time-limited-policy-exceptions-design.md)
- [Time-limited policy exception acceptance — 2026-08-01](docs/time-limited-policy-exception-acceptance-2026-08-01.md)
- [Wider enterprise UI](docs/enterprise-ui.md)
- [Enterprise integration design](docs/enterprise-integration-design.md)
- [Runtime attestation design](docs/runtime-attestation-design.md)
- [Runtime remediation coordination](docs/runtime-remediation-coordination-design.md)
- [Managed endpoint deployment design](docs/managed-endpoint-deployment-design.md)
- [Managed package distribution design](docs/managed-package-distribution-design.md)
- [Measured managed-configuration rollout design](docs/measured-managed-rollout-design.md)
- [Measured managed-rollout acceptance — 2026-08-01](docs/measured-managed-rollout-acceptance-2026-08-01.md)
- [Enterprise user journeys](docs/enterprise-user-journeys.md)
- [Enterprise rollout P0 and P1 requirements](docs/enterprise-rollout-p0-p1-requirements.md)
- [Enterprise P0 and P1 implementation status](docs/p0-p1-implementation-status.md)
- [AWS pilot acceptance evidence — 2026-07-29](docs/aws-pilot-acceptance-2026-07-29.md)
- [Discovery source management acceptance — 2026-07-30](docs/discovery-source-management-acceptance-2026-07-30.md)
- [AWS-managed Entra discovery acceptance — 2026-07-30](docs/managed-discovery-acceptance-2026-07-30.md)
- [AWS-managed GitHub discovery acceptance — 2026-07-30](docs/managed-github-discovery-acceptance-2026-07-30.md)
- [Microsoft Entra SCIM lifecycle runbook](docs/entra-scim-runbook.md)
- [Persistent Microsoft Entra deployment guard](docs/entra-deployment-guard-design.md)
- [Emergency access and access certification runbook](docs/access-governance-runbook.md)
- [Delegated administration](docs/delegated-administration.md)
- [Product Owner enterprise Claude Code rollout review](docs/product-owner-enterprise-claude-rollout-review-2026-07-27.md)
- [Enterprise Claude Code rollout plan](docs/enterprise-claude-rollout-plan.md)
- [Real Claude Code acceptance evidence](docs/real-claude-code-acceptance-evidence-2026-07-27.md)
- [Code-owned and deployment-owned controls](docs/code-owned-controls.md)
- [End-to-end example](docs/end-to-end-example.md)
- [MCP gateway example](https://github.com/tommycharade/aai-sec-sdk/blob/main/examples/mcp_gateway.py)
- [API design](docs/api.md)
- [Runnable example](docs/end-to-end-example.md)
- [Engineering guardrails](docs/guardrails.md)
- [Licensing](docs/license.md)
- [Contributing](docs/contributing.md)
- [Governance](GOVERNANCE.md)
- [Releasing](docs/releasing.md)
- [Deployment evidence](docs/deployment-evidence.md)
- [P1/P2 closure evidence](docs/p1-p2-closure-evidence-2026-07-27.md)
- [Release evidence v1.0.1](docs/release-evidence-v1.0.1.md)
- [SDK assessment](SDK-assessment.md)
- [Online documentation](https://tommycharade.github.io/aai-sec-sdk/)

## Project status

The core runtime, synthetic reference application, typed idempotency and
isolation contracts, phase-specific timeout outcomes, bounded HTTP
policy/approval adapters, token broker, audit exporters, and process-boundary
integration surfaces are available. The execution boundary now exposes typed
action facts, permits, centralized pre-execution authorization, and lifecycle
gates while preserving the `GuardedRuntime` entry point. See [production readiness](docs/production-readiness.md)
for the exact boundary between SDK guarantees and deployment responsibilities.
The MCP integration layer provides one extensible gateway and host profiles
for OpenCode, OpenHands self-hosted, Claude Code, Cline, Gemini CLI, GitHub
Copilot CLI/cloud agent, and Codex CLI; see [Agent integrations](docs/integrations.md).
The enterprise fleet layer adds tenant-scoped organization, project,
deployment, agent, rollout, drift, health, alert, and emergency-stop controls;
see [Enterprise fleet control plane](docs/enterprise-fleet.md).
Managed rollouts bind immutable desired configuration and package revisions,
select deterministic canary rings, enforce maintenance windows and health
thresholds, and accept convergence only from fresh exact endpoint evidence;
see [Measured managed-configuration rollouts](docs/measured-managed-rollout-design.md).
Approved runtime-release inventory separately projects deployment-owned SDK,
gateway and hook evidence, while server-derived version compliance identifies
unapproved, missing, expired, mismatched and quarantined agents; see [Approved
runtime releases and version compliance](docs/runtime-release-compliance-design.md).
Runtime upgrades add a separate revision-bound current/target authority,
deterministic canaries and exact-evidence expansion, pause and rollback; see
[Measured runtime-release rollouts](docs/runtime-release-rollout-design.md).
AWS policy activation freezes registry-resolved Skills and MCP servers and
signs the exact tenant, policy version and effective configuration with a
non-exportable asymmetric KMS key. Claude Code and Codex verify that bundle
locally against administrator-installed public trust before loading it; see
[Signed policy bundles](docs/signed-policy-bundles-design.md).
The Terraform provider adds repeatable tenant inspection, governed policy
drafts, groups, Skills and MCP registrations through the separately scoped
machine API. Optimistic revisions detect drift, while approval and activation
remain human-owned; see [Terraform provider and declarative
management](docs/terraform-provider-design.md).
Azure, GCP and AWS cloud credential adapters bind short-lived grants to exact
tools, resources, scopes and live revocation state. The hosted control plane
keeps human registration separate from machine evidence and exposes no cloud
secret; see [Cloud credential authority](docs/cloud-credential-authority-design.md).
Incident responders can revoke all current and future brokered authority for
one exact server-bound agent without editing policy; the runtime checks before
mint, after mint and before each use. Recovery remains server-gated; see
[Incident-driven credential revocation](docs/incident-credential-revocation-design.md).
Hostile or generated code additionally needs an exact reviewed boundary; see
[Production isolation authority](docs/production-isolation-authority-design.md).

## Development

```bash
make docs       # regenerate README and build the site
make check      # run all quality and documentation gates
```

For release adoption, use the standalone checksum, SBOM, commit/tag, and
provenance verification procedure in [Releasing](docs/releasing.md); build success
alone is not release evidence.

The root `README.md` is generated from this page. Do not edit the generated file directly.

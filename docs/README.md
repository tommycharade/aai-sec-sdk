# Agentic AI Security SDK

The Agentic AI Security SDK is an open-source execution-security runtime for agentic systems. It is designed around a simple boundary:

> The model proposes; the host validates, authorizes, approves, executes, records, and can stop.

## Start here

- [Getting started](getting-started.md)
- [Security model](security-model.md)
- [Persistent audit-recovery deployment guard](audit-recovery-deployment-guard-design.md)
- [Cross-region audit recovery acceptance — 2026-08-01](cross-region-audit-recovery-acceptance-2026-08-01.md)
- [Regional control-plane recovery design](regional-control-plane-recovery-design.md)
- [Regional recovery storage runbook](regional-recovery-storage-runbook.md)
- [Regional recovery storage acceptance — 2026-08-02](regional-recovery-storage-acceptance-2026-08-02.md)
- [Passive regional control-plane cell](passive-regional-cell-design.md)
- [Regional activation and recovery exercise](regional-activation-and-exercise-design.md)
- [Guarded regional transition executor](regional-transition-executor-design.md)
- [Regional transition witness and journal](regional-transition-journal-design.md)
- [Regional target readiness and stable ingress](regional-target-readiness-and-stable-ingress-design.md)
- [Managed policy-signing trust convergence](policy-trust-convergence-design.md)
- [Managed policy-trust convergence acceptance — 2026-08-02](policy-trust-convergence-acceptance-2026-08-02.md)
- [Operational runbooks](runbooks.md)
- [Testing and assurance](testing.md)
- [Production readiness](production-readiness.md)
- [Architecture](architecture.md)
- [Cloud credential authority](cloud-credential-authority-design.md)
- [Production isolation authority](production-isolation-authority-design.md)
- [Agent integrations](integrations.md)
- [Claude Code example](claude-code.md)
- [Real Claude Code acceptance harness](real-claude-code-acceptance-harness.md)
- [Real Claude Code acceptance evidence — 2026-08-05](real-claude-code-acceptance-evidence-2026-08-05.md)
- [Real Codex CLI acceptance harness](real-codex-cli-acceptance-harness.md)
- [Real Codex CLI acceptance evidence — 2026-08-05](real-codex-cli-acceptance-evidence-2026-08-05.md)
- [Synthetic Intune continuation acceptance — 2026-08-05](synthetic-intune-continuation-acceptance-2026-08-05.md)
- [Management UI](ui.md)
- [Enterprise fleet control plane](enterprise-fleet.md)
- [AWS-managed discovery connectors](scheduled-discovery-connectors-design.md)
- [Endpoint evidence publisher](endpoint-evidence-publisher-design.md)
- [macOS endpoint sensor artifact](macos-endpoint-sensor-artifact.md)
- [macOS endpoint sensor MDM package](macos-endpoint-sensor-package.md)
- [Hosted endpoint evidence and fleet health](hosted-endpoint-evidence.md)
- [Endpoint detection and response](endpoint-detection-response.md)
- [Incident cases and containment](incident-case-containment-design.md)
- [Incident-driven credential revocation](incident-credential-revocation-design.md)
- [Unified investigation timeline](unified-investigation-timeline-design.md)
- [Audit-ready incident case export](incident-case-export-design.md)
- [Durable evidence governance](durable-evidence-governance-design.md)
- [Asynchronous tenant retention](asynchronous-retention-design.md)
- [Asynchronous mass-retention acceptance — 2026-08-01](async-retention-acceptance-2026-08-01.md)
- [Asynchronous evidence assurance acceptance — 2026-08-01](async-evidence-acceptance-2026-08-01.md)
- [Approved automatic response rules](automatic-response-rules-design.md)
- [Explainable agent behavior detection](behavior-detection-design.md)
- [Repository and configuration anomaly detection](repository-configuration-anomaly-design.md)
- [Fleet integrity baseline storage](fleet-integrity-baseline-storage-design.md)
- [Object-backed discovery ingestion](object-backed-discovery-ingestion-design.md)
- [Governed alert suppression and deduplication](alert-suppression-design.md)
- [Endpoint evidence publisher acceptance — 2026-08-01](endpoint-evidence-acceptance-2026-08-01.md)
- [macOS endpoint sensor package acceptance — 2026-08-06](macos-endpoint-sensor-package-acceptance-2026-08-06.md)
- [macOS endpoint sensor artifact acceptance — 2026-08-06](macos-endpoint-sensor-artifact-acceptance-2026-08-06.md)
- [Policy editor](policy-editor.md)
- [Enterprise console navigation](console-navigation-design.md)
- [Policy governance design](policy-governance-design.md)
- [Policy composition and GitOps](policy-composition-and-gitops-design.md)
- [GitHub App policy-source authentication](github-app-policy-source-auth-design.md)
- [Policy change assurance](policy-change-assurance-design.md)
- [Enterprise assurance reports](enterprise-assurance-reports-design.md)
- [Scoped service identities and machine API](service-identities-design.md)
- [Terraform provider and declarative management](terraform-provider-design.md)
- [Secure webhooks](secure-webhooks-design.md)
- [Governed incident workflow integrations](incident-workflow-integrations-design.md)
- [Enterprise data boundary](enterprise-data-boundary-design.md)
- [Policy change assurance live acceptance — 2026-08-01](policy-change-assurance-acceptance-2026-08-01.md)
- [Signed policy bundles](signed-policy-bundles-design.md)
- [Signed policy bundle acceptance — 2026-08-01](signed-policy-acceptance-2026-08-01.md)
- [Time-limited policy exceptions](time-limited-policy-exceptions-design.md)
- [Time-limited policy exception acceptance — 2026-08-01](time-limited-policy-exception-acceptance-2026-08-01.md)
- [Wider enterprise UI](enterprise-ui.md)
- [Enterprise integration design](enterprise-integration-design.md)
- [Runtime attestation design](runtime-attestation-design.md)
- [Runtime remediation coordination](runtime-remediation-coordination-design.md)
- [Managed endpoint deployment design](managed-endpoint-deployment-design.md)
- [Managed package distribution design](managed-package-distribution-design.md)
- [Measured managed-configuration rollout design](measured-managed-rollout-design.md)
- [Measured managed-rollout acceptance — 2026-08-01](measured-managed-rollout-acceptance-2026-08-01.md)
- [Enterprise user journeys](enterprise-user-journeys.md)
- [Enterprise rollout P0 and P1 requirements](enterprise-rollout-p0-p1-requirements.md)
- [Enterprise P0 and P1 implementation status](p0-p1-implementation-status.md)
- [AWS pilot acceptance evidence — 2026-07-29](aws-pilot-acceptance-2026-07-29.md)
- [Discovery source management acceptance — 2026-07-30](discovery-source-management-acceptance-2026-07-30.md)
- [AWS-managed Entra discovery acceptance — 2026-07-30](managed-discovery-acceptance-2026-07-30.md)
- [AWS-managed GitHub discovery acceptance — 2026-07-30](managed-github-discovery-acceptance-2026-07-30.md)
- [Microsoft Entra SCIM lifecycle runbook](entra-scim-runbook.md)
- [Persistent Microsoft Entra deployment guard](entra-deployment-guard-design.md)
- [Emergency access and access certification runbook](access-governance-runbook.md)
- [Delegated administration](delegated-administration.md)
- [Product Owner enterprise Claude Code rollout review](product-owner-enterprise-claude-rollout-review-2026-07-27.md)
- [Enterprise Claude Code rollout plan](enterprise-claude-rollout-plan.md)
- [Real Claude Code acceptance evidence](real-claude-code-acceptance-evidence-2026-07-27.md)
- [Code-owned and deployment-owned controls](code-owned-controls.md)
- [End-to-end example](end-to-end-example.md)
- [MCP gateway example](https://github.com/tommycharade/aai-sec-sdk/blob/main/examples/mcp_gateway.py)
- [API design](api.md)
- [Runnable example](end-to-end-example.md)
- [Engineering guardrails](guardrails.md)
- [Licensing](license.md)
- [Contributing](contributing.md)
- [Governance](../GOVERNANCE.md)
- [Releasing](releasing.md)
- [Deployment evidence](deployment-evidence.md)
- [P1/P2 closure evidence](p1-p2-closure-evidence-2026-07-27.md)
- [Release evidence v1.0.1](release-evidence-v1.0.1.md)
- [SDK assessment](../SDK-assessment.md)
- [Online documentation](https://tommycharade.github.io/aai-sec-sdk/)

## Project status

The core runtime, synthetic reference application, typed idempotency and
isolation contracts, phase-specific timeout outcomes, bounded HTTP
policy/approval adapters, token broker, audit exporters, and process-boundary
integration surfaces are available. The execution boundary now exposes typed
action facts, permits, centralized pre-execution authorization, and lifecycle
gates while preserving the `GuardedRuntime` entry point. See [production readiness](production-readiness.md)
for the exact boundary between SDK guarantees and deployment responsibilities.
The MCP integration layer provides one extensible gateway and host profiles
for OpenCode, OpenHands self-hosted, Claude Code, Cline, Gemini CLI, GitHub
Copilot CLI/cloud agent, and Codex CLI; see [Agent integrations](integrations.md).
The enterprise fleet layer adds tenant-scoped organization, project,
deployment, agent, rollout, drift, health, alert, and emergency-stop controls;
see [Enterprise fleet control plane](enterprise-fleet.md).
Managed rollouts bind immutable desired configuration and package revisions,
select deterministic canary rings, enforce maintenance windows and health
thresholds, and accept convergence only from fresh exact endpoint evidence;
see [Measured managed-configuration rollouts](measured-managed-rollout-design.md).
Approved runtime-release inventory separately projects deployment-owned SDK,
gateway and hook evidence, while server-derived version compliance identifies
unapproved, missing, expired, mismatched and quarantined agents; see [Approved
runtime releases and version compliance](runtime-release-compliance-design.md).
Runtime upgrades add a separate revision-bound current/target authority,
deterministic canaries and exact-evidence expansion, pause and rollback; see
[Measured runtime-release rollouts](runtime-release-rollout-design.md).
AWS policy activation freezes registry-resolved Skills and MCP servers and
signs the exact tenant, policy version and effective configuration with a
non-exportable asymmetric KMS key. Claude Code and Codex verify that bundle
locally against administrator-installed public trust before loading it; see
[Signed policy bundles](signed-policy-bundles-design.md).
The Terraform provider adds repeatable tenant inspection, governed policy
drafts, groups, Skills and MCP registrations through the separately scoped
machine API. Optimistic revisions detect drift, while approval and activation
remain human-owned; see [Terraform provider and declarative
management](terraform-provider-design.md).
Azure, GCP and AWS cloud credential adapters bind short-lived grants to exact
tools, resources, scopes and live revocation state. The hosted control plane
keeps human registration separate from machine evidence and exposes no cloud
secret; see [Cloud credential authority](cloud-credential-authority-design.md).
Incident responders can revoke all current and future brokered authority for
one exact server-bound agent without editing policy; the runtime checks before
mint, after mint and before each use. Recovery remains server-gated; see
[Incident-driven credential revocation](incident-credential-revocation-design.md).
Hostile or generated code additionally needs an exact reviewed boundary; see
[Production isolation authority](production-isolation-authority-design.md).

## Development

```bash
make docs       # regenerate README and build the site
make check      # run all quality and documentation gates
```

For release adoption, use the standalone checksum, SBOM, commit/tag, and
provenance verification procedure in [Releasing](releasing.md); build success
alone is not release evidence.

The root `README.md` is generated from this page. Do not edit the generated file directly.

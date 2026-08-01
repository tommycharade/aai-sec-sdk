<!-- THIS FILE IS GENERATED. Edit docs/README.md and run `make docs`. -->

# Agentic AI Security SDK

The Agentic AI Security SDK is an open-source execution-security runtime for agentic systems. It is designed around a simple boundary:

> The model proposes; the host validates, authorizes, approves, executes, records, and can stop.

## Start here

- [Getting started](docs/getting-started.md)
- [Security model](docs/security-model.md)
- [Operational runbooks](docs/runbooks.md)
- [Testing and assurance](docs/testing.md)
- [Production readiness](docs/production-readiness.md)
- [Architecture](docs/architecture.md)
- [Agent integrations](docs/integrations.md)
- [Claude Code example](docs/claude-code.md)
- [Management UI](docs/ui.md)
- [Enterprise fleet control plane](docs/enterprise-fleet.md)
- [AWS-managed discovery connectors](docs/scheduled-discovery-connectors-design.md)
- [Endpoint evidence publisher](docs/endpoint-evidence-publisher-design.md)
- [Hosted endpoint evidence and fleet health](docs/hosted-endpoint-evidence.md)
- [Endpoint evidence publisher acceptance — 2026-08-01](docs/endpoint-evidence-acceptance-2026-08-01.md)
- [Policy editor](docs/policy-editor.md)
- [Policy governance design](docs/policy-governance-design.md)
- [Wider enterprise UI](docs/enterprise-ui.md)
- [Enterprise integration design](docs/enterprise-integration-design.md)
- [Runtime attestation design](docs/runtime-attestation-design.md)
- [Managed endpoint deployment design](docs/managed-endpoint-deployment-design.md)
- [Managed package distribution design](docs/managed-package-distribution-design.md)
- [Enterprise user journeys](docs/enterprise-user-journeys.md)
- [Enterprise rollout P0 and P1 requirements](docs/enterprise-rollout-p0-p1-requirements.md)
- [Enterprise P0 and P1 implementation status](docs/p0-p1-implementation-status.md)
- [AWS pilot acceptance evidence — 2026-07-29](docs/aws-pilot-acceptance-2026-07-29.md)
- [Discovery source management acceptance — 2026-07-30](docs/discovery-source-management-acceptance-2026-07-30.md)
- [AWS-managed Entra discovery acceptance — 2026-07-30](docs/managed-discovery-acceptance-2026-07-30.md)
- [AWS-managed GitHub discovery acceptance — 2026-07-30](docs/managed-github-discovery-acceptance-2026-07-30.md)
- [Microsoft Entra SCIM lifecycle runbook](docs/entra-scim-runbook.md)
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

## Development

```bash
make docs       # regenerate README and build the site
make check      # run all quality and documentation gates
```

For release adoption, use the standalone checksum, SBOM, commit/tag, and
provenance verification procedure in [Releasing](docs/releasing.md); build success
alone is not release evidence.

The root `README.md` is generated from this page. Do not edit the generated file directly.

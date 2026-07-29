# Enterprise P0 and P1 implementation status

This page is the live delivery ledger for the
[enterprise rollout requirements](enterprise-rollout-p0-p1-requirements.md).
It records implementation and evidence separately so a configuration field,
mock, heartbeat or local test cannot be mistaken for enterprise acceptance.

## Status meanings

- **Implemented:** production-shaped implementation and required local contract
  evidence exist. Deployment acceptance may still be outstanding.
- **Partial:** a meaningful control exists, but the requirement's acceptance
  evidence is incomplete.
- **Not started:** no implementation satisfies the requirement.
- **Stub:** interface and honest product workflow exist, but no production
  integration or delivery claim exists.

## P0 ledger

| ID | Requirement | Status | Current evidence | Next acceptance work |
| --- | --- | --- | --- | --- |
| P0-01 | Enterprise-enforced Claude configuration | Partial | Project hook/MCP onboarding and live policy refresh | Managed Claude distribution, tamper test and effective-source evidence |
| P0-02 | Codex managed requirements | Partial | Project hook/MCP onboarding, project trust and bypass documentation | Managed `requirements.toml`, launch-profile enforcement and live bypass denial |
| P0-03 | Native-control reconciliation | Partial | Shared typed policy and host decision evidence | Combined Claude/Codex effective-authority engine and conflict UI |
| P0-04 | Complete agent discovery | Partial | Enrolled inventory and health | Device/user/repository discovery and unmanaged-instance denominator |
| P0-05 | Runtime attestation | Partial | Typed Claude/Codex measurement, release-bound clean-checkout manifest generator, exact manifest/provenance validation, nonce-bound heartbeat, baseline drift detection, quarantine/session revocation, fleet/group posture UI and adversarial contracts | Publish and pin the next independently verified release manifests, then complete live modified-package/hook/config/process and hardware-backed identity acceptance |
| P0-06 | Entra SSO, SCIM and granular RBAC | Partial | Tenant-specific Entra OIDC, tenant-bound SCIM users/groups/memberships, admin-controlled canonical-role mapping, five-minute token reconciliation, adversarial contracts and Identity & Trust UI | Live Entra joiner/mover/leaver acceptance, break glass, access certification and delegated scopes |
| P0-07 | SIEM/SOAR | Stub | Splunk status contract and honest UI state with `deliveryVerified: false` | HEC delivery, authentication, schema, retry, dead letter, monitoring and replay |
| P0-08 | Durable evidence | Partial | S3 Object Lock, retention and cross-region pilot evidence | Tenant retention, legal hold, complete export and evidence-loss recovery SLO |
| P0-09 | Production credential broker | Partial | Typed broker contracts and AWS scoped STS reference | Real AWS/Azure/GCP production role inventory and revocation evidence |
| P0-10 | Production isolation | Partial | Typed attestation contract and Docker probe | Supported production sandbox adapter and independent hostile-code assessment |
| P0-11 | HA/DR | Partial | Durable AWS stores, audit replication and recovery checks | Approved RTO/RPO, regional control-plane recovery and rehearsed runbooks |
| P0-12 | Assurance package | Partial | Apache-2.0 project, SBOM/release provenance and security policy | Independent penetration test, vulnerability SLA and customer legal/compliance pack |

No P0 row is complete for enterprise-wide rollout yet.

## P1 ledger

| Workstream | Status | Implemented foundation | Major remaining work |
| --- | --- | --- | --- |
| Fleet lifecycle | Partial | Enrollment, groups, assignment, health, rollouts, rollback, drift and emergency stop | Bulk operations, dynamic groups, revoke/delete/replace, owner metadata, managed upgrades, exception expiry and offboarding |
| Policy governance | Partial | Typed editor, immutable version number, readable effective policy, assignment impact and rollback | Draft/review/approve lifecycle, four-eyes, simulation, semantic diff, signed bundles, inheritance and expiring exceptions |
| Security operations | Partial | Alerts, approvals, audit timeline and emergency stops | Cases, quarantine, automatic containment, credential revocation, detections, anomaly controls and workflow integrations |
| Reporting and administration | Partial | Fleet posture, health, SLO and compliance evidence summaries | Coverage denominator, executive/auditor reports, delegated scopes, service identities, Terraform, CMK/residency and private access |

## Current delivery slice — Entra identity and trust

The active implementation establishes the provider-neutral identity boundary
with Microsoft Entra ID as the first adapter:

1. CDK rejects partial Entra configuration and non-tenant-specific issuer IDs.
2. The OIDC client secret resolves from Secrets Manager and is never returned
   to the UI or Lambda environment.
3. A Cognito V2 pre-token trigger adds provider provenance only for the exact
   configured OIDC identity.
4. The API independently binds that directory to one provisioned AAI tenant.
5. Mutating routes require an explicit capability from one of seven canonical
   roles; malformed and lookalike roles fail closed.
6. A separate bearer-protected SCIM endpoint provisions tenant-bound users,
   groups and memberships using immutable Entra object UUIDs.
7. Only a platform administrator maps exact active groups to canonical roles;
   token issuance reconciles live lifecycle state and fails closed.
8. Access and ID tokens expire after five minutes, bounding mover/leaver
   convergence when refresh repeats the lifecycle lookup.
9. The UI reports lifecycle counts, sync posture and role mappings while
   preserving honest degraded and not-configured states. Splunk remains a
   non-delivering stub.

This advances but does not close P0-06. The next identity acceptance slice is
a live Entra joiner/mover/leaver exercise, followed by break glass, quarterly
access certification and delegated administrative scopes.

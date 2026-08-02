# Managed policy-trust convergence acceptance — 2026-08-02

## Result

The central policy-trust distribution and convergence boundary passed its live
AWS deployment acceptance on 2026-08-02. The deployed control plane can publish
a digest-bound schema-v2 managed package, require the exact overlap trust
artifact in desired state and endpoint evidence, and derive fleet-wide signer
cutover readiness without allowing the browser or an endpoint to assert that
status.

This result does **not** authorize signing-key cutover. No real endpoint has yet
installed the overlap trust in its administrator-owned system path, so the
active single-Region signer remains authoritative and P0-11 remains Partial.

## Quality evidence

The complete repository gate passed before deployment:

- 927 tests passed and one optional external integration was skipped;
- statement/branch coverage passed at 90.12%;
- Ruff formatting and linting and strict mypy checks passed;
- strict documentation generation and the source/wheel package checks passed;
- documentation, CI and build dependency audits found no known vulnerabilities;
- the mutation baseline and repository guardrails passed.

Adversarial contracts cover schema-v1 compatibility, schema-v2 trust binding,
wrong or missing out-of-band digests, malformed and non-canonical trust,
unexpected key identities, unsafe ownership/modes, symlink-safe measurement,
content drift, installer rollback, stale or conflicting heartbeat evidence,
incomplete rollouts, role denial and forged readiness.

## Reviewed AWS change

The CDK diff contained no resource replacement, deletion, IAM change,
authoritative-store change, Cognito change or active-signer change. It updated
the shared Lambda code asset and added only these variables to the control-plane
handler:

- `REGIONAL_POLICY_SIGNING_KEY_ARN` for the staged primary multi-Region key;
- `RECOVERY_REGION=eu-west-1` for deriving its recovery replica identity.

Stack `AaiSecControlPlane` ended `UPDATE_COMPLETE`. Independent post-deployment
inspection found:

- active signer: `arn:aws:kms:eu-west-2:396510133537:key/98161959-8216-49b9-85ce-c1c7dd27c317`;
- staged signer: `arn:aws:kms:eu-west-2:396510133537:key/mrk-be901b9e4d604c039103a052869d3227`;
- recovery Region: `eu-west-1`;
- unauthenticated trust-posture request: HTTP 401.

The active and staged signer identities are different, proving that deployment
did not perform a cutover.

## Live posture exercise

A short-lived synthetic tenant root was conditionally created, the deployed
Lambda was invoked through the read-only operator route, and that exact record
was deleted and verified absent in a `finally` cleanup. The response returned:

| Field | Observed value |
| --- | --- |
| Lambda invocation | HTTP 200 |
| Route response | HTTP 200 |
| Schema | 1 |
| Deployment authority configured | `true` |
| Required trust key count | 3 |
| Active agents | 0 |
| Managed deployments | 0 |
| Ready for signer cutover | `false` |
| Synthetic tenant cleaned | `true` |

This is the required safe state before endpoint rollout: the control plane
recognises the active signer, staged primary and recovery replica, but an empty
or incomplete fleet cannot satisfy cutover readiness.

## Endpoint rollout still required

The local Kratos Claude Code project is project-scoped and currently has no
administrator-owned trust file at
`/opt/aai-security/trust/policy-signing.json`. Installing the schema-v2 package
on macOS must write root-owned native Claude configuration and trust files and
therefore requires an interactive administrator-approved operation. The SDK
does not weaken that boundary or silently install into a user-owned substitute.

Before signer cutover, the remaining acceptance sequence is:

1. review and publish the exact schema-v2 package carrying the three-key overlap;
2. install it through the privileged endpoint-management path;
3. start Claude Code from an approved managed launch path;
4. publish a fresh measured heartbeat containing the exact trust digest;
5. prove every active Claude Code and Codex deployment is at 100% converged;
6. inspect the central posture and require `readyForSignerCutover: true`;
7. approve signer activation as a separate, independently reviewed change.

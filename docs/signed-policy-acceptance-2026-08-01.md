# Signed policy bundle acceptance — 2026-08-01

## Outcome

The signed-policy bundle boundary passed local, CI, deployed AWS and hosted UI
acceptance. The deployed control plane signs exact effective policy authority
with a non-exportable AWS KMS P-256 key. The SDK rejected transport-only trust
and verified the returned tenant, policy ID, version, configuration hash and
ECDSA signature locally against an independently exported public key.

This evidence does **not** claim complete production readiness. Runtime release
attestation and Microsoft Entra ID remain explicitly unconfigured in this
deployment.

## Reviewed changes

| Repository change | Evidence |
| --- | --- |
| SDK signed-policy implementation | PR [#83](https://github.com/tommycharade/aai-sec-sdk/pull/83), merged as `c67919538cabad912514e602a03a5fbdd242b90f` |
| UI signing provenance | PR [#40](https://github.com/tommycharade/aai-sec-ui/pull/40), merged as `5369581` |
| DynamoDB numeric normalization hotfix | PR [#84](https://github.com/tommycharade/aai-sec-sdk/pull/84), merged as `f7d4f60b1abaad8d271362893f0a2728861ee0f7` |

PR #83 passed documentation, dependency/mutation audit, Python 3.11, 3.12 and
3.13, Docker isolation and PostgreSQL integration checks. PR #84 repeated the
same independent gates after the deployment-only defect was fixed. The UI PR
passed its type, test and production-build gate.

## Local assurance

- `make check`: 859 tests passed and one deployment-dependent PostgreSQL test
  skipped; coverage, type checking, linting, strict documentation, package
  validation and all three dependency audits passed.
- Signed-policy adversarial suite: 26 tests covering altered payloads,
  cross-tenant bundles, unknown and rotated keys, malformed signatures,
  duplicate JSON keys, unsafe trust files, bounds and fail-closed behavior.
- Mutation gate: 3,275 of 4,010 mutants killed (81.7%) against the required
  80% threshold.
- AWS CDK TypeScript build and synthesis passed.
- UI gate: 129 tests, type checking and production build passed.

## AWS deployment evidence

The `AaiSecControlPlane` stack in `eu-west-2` completed successfully using the
`p1` profile. CloudFormation created retained KMS key alias
`alias/aai-sec-policy-signing` and updated the control-plane and trial-onboarding
Lambdas without replacing the existing data stores or UI distribution.

The deployed signing key is
`arn:aws:kms:eu-west-2:396510133537:key/98161959-8216-49b9-85ce-c1c7dd27c317`.
`GetPublicKey` produced SHA-256 public-key fingerprint
`72a5ca43a8afb9cf9d1a324101478cb907c43dd6c15cbe991d5a2be04dbfacb2`.
Only public material was exported for acceptance; the private key remained in
KMS. The SDK trust file was supplied independently to the host-side verifier,
not learned from the effective-policy response.

## Live test result

The deployed smoke test passed these boundaries:

- authentication, enrollment and project-root binding;
- accountable ownership and compare-and-swap updates;
- managed-host missing and conflicting evidence denial;
- signed effective-policy retrieval and local SDK verification;
- policy-group assignment and agent verification;
- approval decision binding and replay denial;
- emergency-stop enforcement and recovery;
- durable cross-process idempotency;
- WORM audit retention and SNS/SQS alert delivery; and
- irreversible replacement and offboarding behavior.

The first deployed run correctly exposed a database-boundary defect: DynamoDB
returned persisted JSON integers as `Decimal`, and bundle reconstruction
validated that storage representation before normalization. The API returned
HTTP 400 with `policy configuration contains a non-JSON value`; it did not
return unsigned authority. PR #84 moved normalization to the DynamoDB boundary,
added a regression test, passed all CI gates, was deployed, and the complete
live smoke then passed.

## Hosted UI evidence

CloudFront invalidation `I7BC7S2OTATF1YZDMPKIIBZQBV` completed. The hosted
index referenced the exact merged production assets:

- `/assets/index-XkjuCc6h.js`
- `/assets/index-C7m3zW8W.css`

Browser QA found no console warnings or errors. The policy view distinguishes
signed from unsigned runtime authority, shows bounded signer provenance and
never presents browser-returned key material as automatically trusted. Claude
and Codex onboarding commands include the exact tenant and an
administrator-installed trust-bundle path.

## Explicit residual gaps

- Runtime release attestation reports `not-configured`; the live test used the
  explicit acceptance flag and made no release-provenance claim.
- Microsoft Entra ID and SCIM report `not-configured` in this stack.
- The public trust bundle still requires an administrator-owned distribution
  and rotation process on enrolled endpoints. Browser delivery is not a trust
  bootstrap mechanism.


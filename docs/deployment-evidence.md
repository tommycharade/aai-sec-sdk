# Deployment evidence

The open-source SDK can prove its local contracts and release integrity. It
cannot prove properties of infrastructure that the adopter has not supplied.
Consequential production use therefore requires an adopter-owned evidence
pack for every deployment.

## Required evidence

- A multi-process idempotency adapter test demonstrating atomic claim,
  conflict detection, terminal persistence, restart recovery, and reconciliation
  after a timeout or store outage.
- Immutable or WORM audit retention, access controls, replication, and a test
  showing that an operator or application process cannot rewrite accepted
  events.
- Provider-side IAM evidence showing that issued credentials cannot exceed the
  exact tool, principal, tenant, resource, and operation scope.
- A genuine container, microVM, or WASM isolation implementation, including
  denial tests for network, filesystem, identity, and sandbox-escape attempts.
- Remote policy and approval adapter contract tests, including provider outage,
  timeout, stale approval, and fail-closed behavior.
- Operational evidence for worker saturation, audit/export failure,
  reconciliation backlog, emergency stop, and key rotation.

The repository's in-memory stores, callback isolation verifier, local audit
sinks, and Python handlers are reference implementations for tests and pilots;
they are not deployment evidence for high-impact actions. Keep the evidence
with the deployed commit, adapter versions, configuration, and release
verification record.

## AWS pilot evidence — 2026-07-29

The merged commit `066cb8725d112c58867cfb776d4d69bf37688f0c` was deployed to
the `AaiSecControlPlane` stack in `eu-west-2` with AWS profile `p1`.
TypeScript compilation and CDK synthesis passed. CloudFormation updated both
Lambda functions and reached `UPDATE_COMPLETE` at 11:15 Europe/London.

The deployed control-plane acceptance then established the following exact
state:

- the earlier production-only DynamoDB `Decimal` policy-version rejection no
  longer occurred;
- an exact, fresh synthetic Claude managed bundle produced
  `managedConfiguration.passed: true` and status `enforced`;
- the overall agent remained `verified: false` because
  `runtimeAttestation.passed` was false with
  `approved_manifest_missing`;
- a post-run DynamoDB scan found zero records containing the unique
  `aws-smoke` prefix, proving synthetic lifecycle cleanup;
- the Entra SCIM acceptance preflight returned exit status `2` and
  `Microsoft Entra ID is not configured in this stack` before any secret
  lookup or lifecycle write.

This is positive production evidence for the managed-host protocol fix and
negative evidence for two outstanding P0 prerequisites. It is not a full AWS,
runtime-attestation or Entra acceptance pass. The checked-in runtime manifest
bundle remains deliberately empty, and the stack outputs report Microsoft
Entra ID, SCIM and runtime attestation as `not-configured`.

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

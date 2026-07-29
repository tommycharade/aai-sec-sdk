# Managed package distribution design

This design connects the canonical managed endpoint package to the enterprise
control plane. It lets a central platform administrator publish one exact
Claude Code or Codex package for a deployment and lets the enrolled endpoint
retrieve it over its authenticated agent channel. The privileged installer
remains the only component that writes administrator-owned host files.

## Security boundary and threat model

Package bytes, browser fields, deployment identifiers, revisions and endpoint
requests are untrusted. An attacker may try to publish a package for another
tenant, replace a hook prerequisite, race two publications, replay an old
package, download a package with another agent bearer, or keep using a package
after desired state changes.

The control plane therefore:

- derives tenant and operator identity from authenticated context;
- permits publication only through the managed-deployment administration
  capability (initially platform administrator only in the AWS adapter);
- accepts canonical package bytes plus their SHA-256 and reparses them through
  the SDK package validator;
- requires the package host, host version, platform, policy identity, policy
  version and bundle digest to exactly match current server-owned desired
  state;
- uses an expected revision for optimistic concurrency so publication is never
  silent last-writer-wins;
- stores at most 280 KiB of canonical, credential-free package data so the
  base64 representation remains below DynamoDB's item-size boundary;
- returns package content only to a live, project-bound agent session for the
  exact deployment and agent identity;
- rechecks current desired state on every download, making a package
  unavailable immediately when configuration changes; and
- audits only package digest, revision and target metadata, never embedded
  configuration content.

Package retrieval deliberately remains available when managed configuration is
missing or conflicting. Requiring the endpoint to prove the package was already
installed before it could download that package would create a repair
deadlock. Retrieval still requires current runtime attestation and is denied by
an emergency stop. Download is not enforcement evidence: only a subsequent
administrator-owned measurement can move posture to `enforced`.

## API contract

An authenticated platform administrator publishes to:

```text
PUT /api/enterprise/deployments/{deploymentId}/managed-package
```

The bounded JSON body contains:

```json
{
  "expectedRevision": 0,
  "packageBase64": "<canonical package bytes>",
  "packageSha256": "<lowercase SHA-256>"
}
```

Revision `0` means no package has been published. A successful publication
returns metadata only: revision, package and bundle digests, target, policy and
publication time. The UI can read that metadata with an operator `GET` on the
same route without exposing the package content to the browser.

An enrolled endpoint retrieves its package from:

```text
GET /agent/{deploymentId}/{agentId}/managed-package
```

The response includes the canonical bytes as bounded base64 plus the same
metadata. `ControlPlaneAgentClient.managed_deployment_package` decodes the
response, verifies its SHA-256, reparses the canonical schema and checks the
expected host, platform and bundle digest before returning a typed
`ManagedDeploymentPackage`.

## Endpoint and MDM journey

1. Compile a managed bundle and package from an approved immutable policy.
2. Publish it with the currently displayed revision and review the returned
   target metadata.
3. Endpoint management installs the separately reviewed SDK, gateway and hook.
4. The enrolled endpoint retrieves the package over its project-bound session,
   or MDM obtains the same reviewed artifact through its administrator channel.
5. Run installer `--check`, then the privileged `--install` transaction.
6. Restart the host and heartbeat with a fresh managed-configuration
   measurement.
7. The UI reports download availability separately from observed enforcement.

The control plane never executes package content, installs prerequisites,
elevates the agent process or claims that publication/download proves the host
loaded the configuration.

## Acceptance evidence and remaining work

Contract evidence must cover cross-tenant publication, stale revision,
non-canonical or altered bytes, package/desired-state mismatch, cross-agent
download, stale desired state, emergency stop, missing managed configuration
repair, response tampering and exact typed client verification.

This closes authenticated control-plane package distribution. It does not by
itself complete P0-01 or P0-02. Real MDM delivery of the SDK, gateway and hook;
approved-launch enforcement; a root-owned installation on supported endpoint
images; and live Claude/Codex execution probes remain required.

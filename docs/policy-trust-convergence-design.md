# Managed policy-signing trust convergence

## Decision

Signer rotation and regional recovery use a schema-v2 managed endpoint package.
It atomically combines the host-native Claude Code or Codex configuration with
one canonical public policy-trust artifact. The package digest binds all files,
but package bytes do not choose trust authority: the control plane separately
owns `policyTrustBundleSha256`, and the privileged installer requires that exact
digest before writing anything.

Schema-v1 packages remain readable during migration. They cannot report policy
trust and therefore cannot satisfy signer-cutover readiness.

## Trust boundary

```text
deployment-owned active/staged/recovery KMS identities
          -> reviewed canonical overlap bundle
          -> separately approved trust SHA-256
          -> schema-v2 managed package publication
          -> root-owned atomic endpoint installation
          -> no-follow exact file measurement on every heartbeat
          -> server-derived fleet convergence
          -> signer cutover eligibility (never automatic cutover)
```

The browser, model, project repository and package transport cannot introduce a
fourth signer. The AWS adapter accepts schema-v2 trust only when its key IDs are
exactly the deployed active key, staged multi-Region primary and derived
recovery replica. Altering public bytes for one of those identities can cause a
safe denial but cannot create signing authority because KMS still holds the
corresponding private key.

## Package and installation contract

`ManagedDeploymentPackage` version 2 adds `policyTrust`, containing the exact
administrator path, canonical trust JSON and SHA-256. Supported paths are:

| Platform | Trust path |
| --- | --- |
| macOS/Linux | `/opt/aai-security/trust/policy-signing.json` |
| Windows | `C:\Program Files\AAI Security\trust\policy-signing.json` |

Windows package parsing is supported, but privileged installation and ACL
measurement remain unavailable until a Windows adapter is implemented.

The installer preflights the independent package, native bundle and trust
digests before its first write. It stages every file with restrictive mode,
replaces the complete set, reopens and hashes final bytes while backups still
exist, and rolls all files back if any final verification fails. It refuses
symlinks, devices, unsafe ownership, writable parent chains, missing executable
prerequisites and cross-host/platform packages.

`measure_managed_deployment_package` reopens all native and trust files without
following symlinks on every heartbeat. Its evidence contains only host/policy
identity, native bundle hash, trust hash and short-lived timestamps. Missing,
stale or different trust produces `conflict` or `stale`, never enforcement.

## Server-derived cutover readiness

`GET /enterprise/resilience/policy-trust` returns tenant-wide posture. It is
read-only and requires an operator role. `readyForSignerCutover` is true only
when:

- deployment trust authority is configured from stack-owned key identities;
- at least one active Claude Code or Codex endpoint is in scope;
- every scoped deployment has one common desired trust digest;
- every current package carries that digest;
- every rollout is 100% and server-derived `converged`; and
- every active endpoint has fresh exact native and trust evidence.

This flag is evidence, not authority. It never calls KMS, edits Lambda
configuration, signs a policy or routes recovery traffic. Signer cutover still
requires the reviewed recovery runbook and independent approval.

## Operator flow

Generate the reviewed overlap bundle with all three deployed identities, then
upgrade an existing digest-pinned package without modifying either input:

```bash
python3 scripts/upgrade_managed_package_trust.py \
  --package /secure/package-v1.json \
  --expected-package-sha256 "$PACKAGE_SHA256" \
  --trust-bundle /secure/policy-trust-overlap.json \
  --expected-trust-sha256 "$INPUT_TRUST_FILE_SHA256" \
  --output /secure/package-v2.json
```

Use the printed canonical policy-trust digest in the deployment's managed-host
desired state. Publish the printed package digest, start a canary rollout and
install only with both independent expected values:

```bash
sudo python3 scripts/install_managed_host_package.py \
  --package /secure/package-v2.json \
  --expected-package-sha256 "$PACKAGE_V2_SHA256" \
  --expected-bundle-hash "$NATIVE_BUNDLE_SHA256" \
  --expected-policy-trust-sha256 "$CANONICAL_TRUST_SHA256" \
  --host claude-code --platform macos --install
```

Restart the host, run allowed/denied/approval/MCP probes, and wait for fresh
heartbeat measurement. Do not infer convergence from successful file copying.

## Guarantees and non-guarantees

The implementation guarantees exact package parsing, deployment-owned signer
identities, all-or-rollback installation, short-lived measured evidence and
server-derived readiness. Tests cover forged keys, altered trust, omitted
out-of-band digests, symlinks, unsafe files, partial replacement and stale or
conflicting heartbeat evidence.

It does not prove that a host process loaded native settings; live action probes
remain required. It does not replace MDM, hardware-backed device identity,
Cognito/Entra recovery, audit continuity, passive API deployment or a rehearsed
regional failover. A process with root authority can replace trust and remains
inside the endpoint-administrator trust boundary.

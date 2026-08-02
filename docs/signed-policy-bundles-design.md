# Signed policy bundles

## Decision

Every newly activated AWS policy is frozen into one canonical effective
configuration and signed by a deployment-owned asymmetric AWS KMS key. An
enrolled runtime must verify the signature, tenant, policy identity, version and
content hash against an administrator-pinned trust bundle before it constructs
or replaces runtime policy authority.

This closes P1-POL-08 for the implemented AWS and Python runtime boundary. A
configuration hash remains useful evidence, but it is not an authenticity
control and is never accepted as a substitute for a valid trusted signature.

## Trust boundary

The model, project repository and browser are outside the trust boundary. They
cannot choose the signing key, signature, tenant identity or accepted trust
anchor.

```text
reviewed policy + enabled registry resources
                    |
                    v
          canonical effective bundle
                    |
             AWS KMS Sign
                    |
                    v
       immutable active version record
                    |
           authenticated retrieval
                    |
                    v
 administrator-pinned public trust bundle
                    |
        local signature verification
                    |
                    v
          runtime policy replacement
```

The private signing key remains inside KMS. The Lambda receives only
`kms:Sign` for the exact key. Runtime hosts receive public verification keys
through an endpoint-management or other administrator-owned channel; they do
not trust a key merely because the policy response contains it.

## Canonical signed payload

The signed payload is UTF-8 JSON with sorted keys and compact separators:

```json
{
  "configuration": {},
  "contentHash": "<sha256>",
  "policyId": "policy-safe-default",
  "schemaVersion": 1,
  "tenantId": "tenant-example",
  "version": 2
}
```

`contentHash` is SHA-256 over the separately canonicalized configuration. KMS
signs the SHA-256 digest of the complete payload using `ECDSA_SHA_256` and a
P-256 key. The wire envelope adds the KMS key ARN, algorithm, base64 signature
and signing time; none of those fields can alter the payload meaning.

The effective configuration is resolved and frozen at activation. Referenced
Skills and MCP servers therefore cannot silently change an active policy.
Changing a registry resource requires a new governed policy version and a new
signature.

## Runtime verification

The Python SDK accepts a bounded trust bundle containing one or more explicit
KMS key ARNs and P-256 public keys. Multiple keys permit planned rotation. The
runtime rejects:

- missing signing metadata;
- unknown keys or algorithms;
- malformed or duplicate trust-bundle entries;
- invalid public keys or signatures;
- modified configuration, content hash, tenant, policy ID or version;
- booleans or non-positive values where an integer version is required;
- oversized, deeply nested or non-JSON policy content; and
- a response for a tenant other than the constructor-owned expected tenant.

Verification happens before returning effective policy to the host integration.
A failed refresh cannot preserve an unverified replacement as authority. The
existing runtime outage behavior remains fail closed.

Export the public trust bundle with
`scripts/export_policy_trust_bundle.py`, then install it through MDM, endpoint
management or another administrator-owned channel. The exporter validates KMS
key usage, P-256 key spec and the sole `ECDSA_SHA_256` algorithm before writing
a new file; it refuses to overwrite an existing trust bundle. Production
runtimes require root ownership and reject group/world-writable files and
symlinks. The operator API may display a key ARN and SHA-256 fingerprint for
provenance, but the SDK never automatically trusts those network-returned
bytes.

## Existing active policies and trials

Activation writes signed metadata atomically with the active version. Trial
provisioning signs the safe default before any policy record is stored. Existing
active versions are migrated once by signing their exact stored configuration;
the migration changes no policy authority and records an audit event. If KMS is
unavailable or the stored content hash is inconsistent, migration and effective
policy retrieval fail closed.

## Rotation and compromise response

Rotation is explicit because runtimes must receive the new public key before
the control plane uses it:

1. Create the replacement KMS signing key.
2. Distribute a trust bundle containing old and new public keys.
3. Verify endpoint adoption and trust-bundle digest.
4. Configure the control plane to sign new activations with the new key.
5. Re-sign or replace active policies through governed activation.
6. Remove the old key only after no active bundle references it.

For centrally managed fleets, steps 2 and 3 use the schema-v2 package,
short-lived heartbeat measurement and server-derived cutover posture described
in [managed policy-signing trust convergence](policy-trust-convergence-design.md).
Package delivery alone is never convergence evidence.

Emergency response may disable the KMS key and activate server-owned stops.
Disabling a key prevents new signatures; already signed bundles remain
cryptographically valid until the old public trust anchor is removed. Incident
runbooks must therefore combine key disablement with session revocation,
emergency stop and trust-bundle rollout.

## Guarantees

- An altered or unsigned bundle cannot be loaded by a correctly configured SDK
  runtime.
- Signature verification is local and does not depend on the model or browser.
- Tenant, policy ID, version, configuration and content hash are inseparable
  under the signature.
- Registry-resolved execution configuration is immutable for the active
  version.
- The private signing key is non-exportable and is not stored in DynamoDB,
  project files, Lambda environment values or telemetry.

## Non-guarantees

- A signature does not prove that policy content is safe, correctly reviewed or
  deployed to every endpoint.
- A user-writable trust bundle is not an enterprise trust anchor. Production
  deployments must install it through an administrator-owned channel.
- This control does not replace runtime attestation, managed-host enforcement,
  endpoint convergence monitoring, emergency stop or independent approval.
- ECDSA authenticity does not make ordinary DynamoDB records WORM evidence.
- A compromised process with authority to replace the pinned trust bundle can
  choose a different signer; file ownership and endpoint management remain
  required controls.

## Required evidence

- SDK unit and adversarial tests with a real P-256 key pair.
- AWS contract tests proving exact KMS key/algorithm/digest use, atomic signed
  activation, signed trial defaults and no unsigned effective-policy response.
- Tests for modified payloads, untrusted keys, malformed signatures, tenant
  replay, resource mutation after activation and KMS outage.
- UI evidence that operators can distinguish signed, unsigned and migration
  failure states and identify the active key without exposing private material.
- Live AWS acceptance proving signing, local verification and cleanup with
  synthetic data.

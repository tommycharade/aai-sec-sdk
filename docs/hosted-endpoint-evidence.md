# Hosted endpoint evidence and fleet health

## Purpose

The hosted channel lets a central security team see whether each
Intune-managed device currently observes the approved Claude Code or Codex
binary and an exact project-bound process. Health is calculated by the control
plane. A device cannot submit `healthy`, create inventory, enroll an agent,
receive policy authority, or approve an action.

This is software evidence, not hardware attestation. The reference sensor is
macOS/Linux only until a Windows adapter can prove the manifest owner SID and
DACL. Hardware-backed device identity remains part of P0-05 acceptance.

## Trust model

1. A complete, current Intune source establishes the managed-device
   population.
2. A platform administrator issues a credential only for an exact managed
   device. The service stores only its SHA-256 digest; plaintext is returned
   once for protected MDM delivery.
3. The credential is both the HTTPS bearer and HMAC key for the canonical
   sensor payload. Tenant, device, key ID, signature and clock bounds must all
   match.
4. Reports older than 15 minutes, more than five minutes in the future,
   reordered, replayed with different content, cross-device, cross-tenant,
   altered or signed by a revoked/rotated credential fail closed.
5. DynamoDB retains the newest accepted path-free report. S3 Object Lock
   receives content-minimised acceptance, rejection and credential-lifecycle
   audit evidence.

Sensor report schema v2 additionally signs a normalized operating system
(`darwin`, `linux` or `windows`) and architecture (`arm64` or `x86_64`)
measured from the local administrator process. The manifest, browser and model
cannot supply these values. Schema-v1 reports remain valid health evidence for
backward compatibility, but they are explicitly insufficient for selecting a
platform-specific delivery package.

The server derives `healthy`, `attention` or `stale` from independent MDM
inventory, credential state, report freshness, binary measurement and process
measurement. Stale Intune inventory remains visible as stale rather than
silently removing a known device.

## Operator journey

In **Coverage → Endpoint sensors**, select an MDM-discovered device and choose
**Enroll sensor**. Save the one-time key ID and secret in the protected MDM
profile. Collect and publish on a schedule shorter than 15 minutes:

```bash
sudo AAI_ENDPOINT_EVIDENCE_KEY='<from-mdm-secret>' \
  python scripts/collect_endpoint_evidence.py \
  --manifest /var/lib/aai-security/endpoint-manifest.json \
  --key-id endpoint-example \
  > /var/lib/aai-security/endpoint-report.json

sudo AAI_ENDPOINT_EVIDENCE_KEY='<from-mdm-secret>' \
  python scripts/publish_endpoint_evidence.py \
  --api-url "$AAI_CONTROL_PLANE_URL" \
  --tenant-id tenant-example \
  --device-id device-example \
  --report /var/lib/aai-security/endpoint-report.json
```

The publisher requires HTTPS, uses a ten-second timeout and at most three
idempotent attempts, and never accepts the secret on the command line. Rotation
makes the prior report non-current until the device reports with the new key.
Revocation denies new reports immediately.

## API contracts

- `GET /enterprise/endpoint-evidence` returns bounded, secret-free device
  health to authenticated tenant operators.
- `POST /enterprise/endpoint-evidence/devices/{deviceId}/credential` requires
  `fleet_write`, a current managed device and `expectedRevision`.
- `DELETE /enterprise/endpoint-evidence/devices/{deviceId}/credential` requires
  `fleet_write` and `expectedRevision`.
- `POST /endpoint-evidence/{tenantId}/{deviceId}` uses only the per-device
  bearer/HMAC credential; Cognito operator tokens are not accepted.

## Non-guarantees and remaining acceptance

The channel does not prove hardware custody, measured boot, MDM deployment
success, Windows ACL safety, or 95% pilot coverage. Enterprise acceptance still
requires real Intune packaging, independent credential-scope review,
physical-device rollout, at least 95% current reports, and documented blind
spots.

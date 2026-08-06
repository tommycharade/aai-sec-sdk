# Customer assurance Trust Center

## Purpose

The hosted **Evidence → Assurance** workspace includes a buyer-facing Trust
Center. It presents the reviewed customer assurance pack, its limitations and
its release binding without turning repository tests into a certification
claim. The current source candidate deliberately reports **Release pending**:
no download is enabled until an immutable release archive has passed the
documented release verification workflow.

## Authority and threat boundary

The browser, tenant records and enrolled agents are not assurance authorities.
The deployment contains one closed `customer-assurance-release.json` manifest.
CDK validates those bytes, passes their SHA-256 digest to Lambda, and Lambda
revalidates both the digest and the complete schema at startup. A stale,
malformed, contradictory or unbound manifest prevents the control plane from
starting.

An available archive must bind all of the following:

- one semantic release tag and exact 40-character source commit;
- the fixed `customer-assurance-pack.zip` filename and SHA-256 digest;
- the exact official GitHub release-asset URL derived from that tag;
- verified provenance status and verification date; and
- an empty blocker list.

An unavailable manifest must have no archive and at least one explicit blocker.
Technical approval, legal review and independent-assurance statuses remain
separate fields. The UI never infers one from another.

## API contract

| Route | Authority | Result |
| --- | --- | --- |
| `GET /api/enterprise/trust-center` | `evidence_read` | Reviewed claims, open blockers, independent-assurance status and release metadata without an external URL |
| `GET /api/enterprise/trust-center/download` | `evidence_read` | Exact official release locator, filename, tag and expected SHA-256 only when the manifest is available |

The metadata response exposes an authenticated API download path rather than
the external locator. The download exchange is unavailable before release and
does not accept request content. The UI rechecks the returned tag, URL and
digest against the metadata it displayed before opening the asset. Adopters
must still verify the downloaded bytes against the displayed SHA-256 and the
release provenance instructions.

## Operator journey

1. Open **Evidence → Assurance** and locate **Trust Center**.
2. Read technical and legal status separately.
3. Review penetration-test and certification rows plus every blocker.
4. If a verified release exists, download the exact archive and verify its
   SHA-256 and provenance using [Releasing](releasing.md).
5. Treat the pack as technical due-diligence material, not legal advice,
   contractual assurance or certification.

## Failure behavior and non-guarantees

- Missing `evidence_read` authority returns `403`.
- An unpublished pack returns useful metadata but no archive or locator.
- A changed deployment digest fails at startup.
- A changed locator, digest or tag blocks the UI download.
- The Trust Center does not certify SOC 2, ISO 27001, regulatory compliance,
  agent safety or deployment correctness.
- Public GitHub release distribution is not tenant-private. The authenticated
  API protects control-plane access and release selection; the release asset is
  intentionally public open-source evidence.

## Verification

Contract tests cover evidence-role authorization, unavailable-pack behavior,
caller-shaped locator rejection and deployment-digest tampering. CDK synthesis
validates the deployment manifest. UI tests cover explicit blockers, disabled
downloads, contextual help and changed-locator fail-closed behavior. Responsive
browser verification covers desktop and narrow layouts.

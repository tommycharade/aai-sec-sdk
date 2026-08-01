# AWS-managed Intune discovery acceptance — 2026-08-01

## Scope

This report records a live, bounded acceptance of the AWS-managed Microsoft
Intune device-discovery connector. It proves provisioning, scheduling, secret
isolation, fixed-destination provider access, controlled provider failure,
redacted operator visibility, fail-closed coverage semantics, disablement,
credential revocation and recoverable cleanup in the deployed AWS control
plane. Every identity, device and credential used by the acceptance was
synthetic.

This is not evidence of successful collection from a real Intune tenant or of
95% endpoint coverage. Microsoft Graph managed-device records establish device
enrollment only. A production endpoint publisher must separately report
installed binaries, active processes and project-root digests.

## Tested revisions

| Component | Revision | Evidence |
| --- | --- | --- |
| SDK and AWS control plane | `48953665bd9ac61535bd3cbc3dcd6e1ada97584f` | Merged pull request [#69](https://github.com/tommycharade/aai-sec-sdk/pull/69) |
| Management UI | `3aead6302d4acf5e11812d2d815b0d138296afde` | Merged private UI pull request #32 |
| AWS stack | `AaiSecControlPlane` | `UPDATE_COMPLETE` in account `396510133537`, region `eu-west-2` |
| Hosted UI | `https://d2ir54klde64bd.cloudfront.net` | CloudFront invalidation `I7SBN1NTCBCHBDZKEIC9KLLDAX` completed |

The SDK pull request passed Python 3.11, 3.12 and 3.13 quality gates,
PostgreSQL integration, Docker isolation, strict documentation, dependency
audit and the bounded mutation gate. The local gate passed 781 tests, one
intentionally skipped external integration, 90.20% coverage, package
validation and dependency audits. The UI passed type checking, 117 tests,
production build, and desktop plus 390-pixel browser acceptance without
horizontal overflow.

The workstation had an editable SDK installation pointing at an older checkout.
The reproducible local SDK gate therefore explicitly used
`PYTHONPATH="$PWD/src" make check`; plain `pytest` would otherwise import the
unrelated checkout rather than the tested worktree.

## Live acceptance path

The test registered `intune-acceptance-20260801` for `tenant-demo`. Its
deployment-owned provider secret contained synthetic UUIDs and a synthetic
invalid client secret. The typed provider configuration contained one opaque
synthetic user ID to business-unit mapping.

| Assertion | Result |
| --- | --- |
| Configure managed source | HTTP 201; Intune/endpoint job revision 1; status `scheduled` |
| Scheduler target | Enabled, service-derived `rate(60 minutes)` schedule targeting the fixed collector Lambda |
| Schedule binding | Event contained live job, configuration and provider-configuration digests; the user mapping was not copied into the event |
| Browser/API exposure | Source directory returned only mapping count and `installationEvidenceRequired`; no user ID, provider configuration, secret ARN or bearer was returned |
| Controlled collection | Fixed error `provider_authentication_failed`; provider response content was not persisted or displayed |
| Durable job state | Status `degraded`; `lastAttemptAt` set; failure count 1; no `lastSuccessAt` |
| Atomic evidence on failure | Failed authentication created no source snapshot |
| Device-only semantic test | A current complete synthetic device snapshot still returned `coverageAvailable=false`, `sourceComplete=false`, null percentages and blind spot `missing_endpoint_installations` |
| False orphan prevention | Device-only evidence returned zero orphan findings rather than inferring conclusions from incomplete endpoint semantics |
| Disable result | Job status `disabled`, revision 2; connector status `revoked`, revision 2; `cleanupRequired=false` |
| External cleanup | Schedule absent; connector and provider secrets under seven-day recoverable deletion |
| Audit evidence | Hash-retained `managed_discovery_created` and `managed_discovery_disabled` records present |
| Failure containment | Collector dead-letter queue had zero visible, in-flight and delayed messages |
| Hosted delivery | CloudFront returned HTTP 200 and the deployed asset contained the Intune permission, evidence warning and coverage-unavailable copy |
| API boundary | Unauthenticated managed-collector capability request returned HTTP 401 |

The device-only snapshot used to prove the semantic coverage gate was removed by
an exact tenant/source/revision-conditioned deletion after the assertion. It was
synthetic transient test data; the disabled job, revoked connector and hashed
audit records remain as redacted operational evidence.

## Security properties demonstrated

- The browser contract supplies only a tenant-scoped KMS secret ARN and bounded
  non-secret attribution; it never receives the provider or connector secret.
- Intune access is fixed to the service-owned Graph token and managed-devices
  endpoints and requests only `id` and `userId`.
- The collector revalidates the current job and configuration digest before
  reading a provider secret or opening a network connection.
- Device enrollment cannot be upgraded into binary, process or project-root
  evidence. Missing installation observations suppress every percentage and
  orphan conclusion.
- Operator views retain only provider, source kind, schedule health, timestamps,
  fixed error code, mapping count and the explicit installation requirement.
- Disablement revokes ingestion before external cleanup, and secret deletion is
  recoverable rather than forced.

## Cleanup evidence

After acceptance:

- the managed schedule was absent;
- the generated connector secret was under recoverable deletion;
- the synthetic provider secret was scheduled for deletion on 2026-08-08;
- the transient device-only snapshot was conditionally deleted;
- the collector dead-letter queue remained empty; and
- CloudFormation remained `UPDATE_COMPLETE`.

## Remaining production acceptance

Before relying on Intune discovery for an enterprise denominator:

1. provision a separate Entra application with only
   `DeviceManagementManagedDevices.Read.All` application permission and retain
   administrator-consent evidence;
2. complete a successful scheduled collection against a non-production pilot
   tenant and compare the opaque device IDs with the agreed managed-device
   denominator;
3. deploy a production endpoint installation/process publisher and prove that
   known missing, duplicate and inactive Claude/Codex instances appear within
   the discovery SLO;
4. test application-secret rotation, expiry, permission removal and tenant
   revocation;
5. reach at least 95% of the agreed pilot population and document every blind
   spot; and
6. replace the client secret with workload identity when the deployment
   platform supports that credential model.

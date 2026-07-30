# AWS-managed Entra discovery acceptance — 2026-07-30

## Scope

This report records a live, bounded acceptance of the AWS-managed Microsoft
Entra ID discovery connector. It proves provisioning, scheduling, secret
isolation, controlled provider failure, operator visibility, disablement,
credential revocation, and recoverable cleanup in the deployed AWS control
plane. All identities and credentials used for this acceptance were synthetic.

This is not evidence of successful Microsoft Graph collection or 95% enterprise
population coverage. Those outcomes require a real pilot-tenant application
credential, Microsoft Entra administrator consent, and an agreed population
denominator.

## Tested revisions

| Component | Revision | Evidence |
| --- | --- | --- |
| SDK and AWS control plane | `a09ed0420b9a9d13891c831cb2cbe8e922c0cfd6` | Merged pull request [#65](https://github.com/tommycharade/aai-sec-sdk/pull/65) |
| Management UI | `b4ed479` | Merged UI pull request #30 and deployed CloudFront invalidation `IBSIYNYRN1WFGQOOMYFSXUAVN3` |
| AWS stack | `AaiSecControlPlane` | Successful deployment in account `396510133537`, region `eu-west-2` |

The final SDK pull request passed all required GitHub checks: Python 3.11,
3.12, and 3.13 quality gates; Docker isolation; PostgreSQL integration; strict
documentation; dependency audit; and the bounded mutation gate. The local
pre-merge quality gate also completed with 759 passing tests, one intentionally
skipped external test, at least 90% configured coverage, strict documentation
and package builds, and dependency audits.

## Live acceptance path

The test registered source `entra-acceptance-20260730b` for tenant
`tenant-demo`. Its deployment-owned provider secret contained only synthetic
UUIDs and a synthetic client secret. The source used a 60-minute interval and
the stack-owned KMS key.

| Assertion | Result |
| --- | --- |
| Configure managed source | HTTP 201; job revision 1; status `scheduled` |
| Scheduler target | Exact collector Lambda ARN with an enabled, service-derived schedule |
| Browser exposure | No provider credential, connector bearer, schedule input, or raw provider response shown |
| Controlled collection attempt | Fixed error `provider_authentication_failed`; no `internal_error` |
| Durable job state | Status `degraded`; `lastAttemptAt` set; failure count 1; no `lastSuccessAt` |
| Atomic evidence | No `DISCOVERY_SOURCE` snapshot was created after failed authentication |
| Hosted UI | Source displayed as `DEGRADED`, awaiting first run, with the fixed error code and one failure |
| Consequential change | UI required a separate **Disable collector** confirmation |
| Disable result | UI confirmed schedule removal and ingestion-authority revocation |
| Durable disable state | Job status `disabled`, job revision 2, connector status `revoked`, credential revision 2 |
| External cleanup | Scheduler absent; connector secret scheduled for recoverable deletion |
| Audit evidence | `managed_discovery_created` and `managed_discovery_disabled` events retained |
| Failure containment | Collector dead-letter queue had zero visible, in-flight, or delayed messages |

## Defects found and closed during acceptance

The live path exposed four differences between mocked tests and AWS service
contracts. Each was fixed with a regression test and passed the complete quality
gate before deployment.

1. Secrets Manager rejected connector-secret creation because the control-plane
   role lacked `TagResource`. The permission is now constrained to the connector
   namespace and exact required tenant/purpose tag keys and values.
2. Customer-managed KMS secret creation required `kms:Decrypt` during the
   Secrets Manager operation. The control-plane permission is now restricted by
   `kms:ViaService` to Secrets Manager; the handler still has no
   `GetSecretValue` authority.
3. EventBridge Scheduler rejected a slash-form Lambda ARN. The target now uses
   the exact colon resource-name ARN returned by Lambda.
4. Real DynamoDB rejected unused expression placeholders during collector state
   updates. State-specific expressions now receive only their referenced values,
   and the test double rejects unused or missing placeholders.

The changes were merged through SDK pull requests
[#62](https://github.com/tommycharade/aai-sec-sdk/pull/62),
[#63](https://github.com/tommycharade/aai-sec-sdk/pull/63),
[#64](https://github.com/tommycharade/aai-sec-sdk/pull/64), and
[#65](https://github.com/tommycharade/aai-sec-sdk/pull/65).

## Security properties demonstrated

- The browser supplied a provider-secret ARN, not secret content.
- The control-plane Lambda could provision and describe tagged secrets but
  could not retrieve their values.
- The collector converted provider details into a fixed, content-free error
  code before durable storage and UI presentation.
- A failed provider request did not create or replace committed inventory.
- Disablement revoked ingestion authority before external cleanup and removed
  the schedule.
- Secret deletion remained recoverable; no force deletion was used.
- Tenant and platform-administrator claims controlled the operator mutation.

## Cleanup evidence

After acceptance:

- the EventBridge Scheduler prefix contained no active schedules;
- the managed connector secret was scheduled for recoverable deletion;
- the synthetic provider secret was scheduled for deletion on 2026-08-06;
- the temporary Cognito platform-administrator user was deleted; and
- the collector dead-letter queue remained empty.

The tenant-scoped job, connector, and audit records were retained as redacted
operational evidence. They contain ARNs, state, revisions, timestamps, fixed
error codes, and hashes, but no provider secret, connector bearer, Graph token,
or collected identity content.

## Remaining acceptance

Before calling this connector production-ready for an enterprise pilot:

1. provision a dedicated Entra application with only `User.Read.All`
   application permission and retain administrator-consent evidence;
2. complete one successful scheduled collection against a non-production pilot
   tenant and prove atomic publication and healthy-state transition;
3. compare the committed identities with an agreed authoritative denominator
   and document exclusions until measured coverage reaches the rollout target;
4. test rotation and expiry of the real Entra credential; and
5. exercise alarms and operator response against repeated authentication,
   transport, inventory-bound, ingestion, and dead-letter failures.


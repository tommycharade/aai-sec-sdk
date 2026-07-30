# AWS-managed GitHub discovery acceptance — 2026-07-30

## Scope

This report records a live, bounded acceptance of the AWS-managed GitHub
organization discovery connector. It proves provisioning, scheduling, secret
isolation, fixed-destination provider access, controlled provider failure,
redacted operator visibility, disablement, credential revocation and
recoverable cleanup in the deployed AWS control plane. Every identity,
repository mapping and credential used in this test was synthetic.

This is not evidence of successful collection from a real GitHub organization
or complete enterprise repository coverage. GitHub can return only repositories
visible to the selected credential, so production acceptance must independently
prove that the credential covers the agreed organization denominator.

## Tested revisions

| Component | Revision | Evidence |
| --- | --- | --- |
| SDK and AWS control plane | `60288a2ef04393d3c384c70da681872aff3ce3d4` | Merged pull request [#67](https://github.com/tommycharade/aai-sec-sdk/pull/67) |
| Management UI | `5df6a54723b0fa43b98aa67337ef9a0186c2290d` | Merged pull request [#31](https://github.com/tommycharade/aai-sec-ui/pull/31) |
| AWS stack | `AaiSecControlPlane` | `UPDATE_COMPLETE` in account `396510133537`, region `eu-west-2` |
| Hosted UI | `https://d2ir54klde64bd.cloudfront.net` | CloudFront invalidation `I5QV1H9J0I8ITTL0KA36JKHCEZ` completed |

The SDK pull request passed Python 3.11, 3.12 and 3.13 quality gates,
PostgreSQL integration, Docker isolation, strict documentation, dependency
audit and the bounded mutation gate. The local quality gate passed 772 tests,
one intentionally skipped external test, 90.18% coverage, package validation
and dependency audits. The UI passed type checking, 114 tests, production build
and desktop plus 390-pixel browser acceptance.

## Live acceptance path

The test registered `github-acceptance-20260730` for `tenant-demo`. Its
deployment-owned provider secret contained one synthetic invalid token. The
typed mapping contained one synthetic repository, one SHA-256 project-root
digest, both supported hosts and one synthetic business unit.

| Assertion | Result |
| --- | --- |
| Configure managed source | HTTP 201; GitHub/source-control job revision 1; status `scheduled` |
| Scheduler target | Enabled, service-derived `rate(60 minutes)` schedule targeting the fixed collector Lambda |
| Schedule binding | Event contained the live job revision plus configuration and provider-configuration digests; no repository map was copied into the event |
| Browser exposure | No provider token, connector bearer, secret ARN, schedule input, repository name or project-root digest was returned |
| Controlled collection | Fixed error `provider_authentication_failed`; provider response text was not persisted or displayed |
| Durable job state | Status `degraded`; `lastAttemptAt` set; no `lastSuccessAt` |
| Atomic evidence | No `DISCOVERY_SOURCE` snapshot was created after failed authentication |
| Hosted UI | Authenticated Coverage view showed `DEGRADED`, the redacted organization, one mapped repository, fixed error and no committed generation |
| Consequential change | A separate **Disable collector** confirmation was required |
| Disable result | UI confirmed schedule removal and ingestion-authority revocation |
| Durable disable state | Job status `disabled`, job revision 2; connector status `revoked`, credential revision 2 |
| External cleanup | Schedule absent; connector and provider secrets scheduled for recoverable deletion |
| Audit evidence | Hash-retained `managed_discovery_created` and `managed_discovery_disabled` records present |
| Failure containment | Collector dead-letter queue had zero visible, in-flight and delayed messages |

Three controlled authentication failures were recorded because both the live
schedule and explicit acceptance invocations ran before disablement. Every run
produced the same fixed code and none advanced evidence.

## Security properties demonstrated

- The browser supplied only a tenant-scoped, KMS-encrypted provider-secret ARN
  and bounded non-secret mapping; it never received or submitted token bytes.
- GitHub access used the service-owned `api.github.com` organization repository
  endpoint and fixed pagination/query contract.
- The collector revalidated the current job, schedule digest and mapping digest
  before secret retrieval or provider network access.
- A failed provider request could lower assurance but could not enroll agents,
  publish partial evidence or create an optimistic coverage percentage.
- Operator views retained only organization, repository count, operational
  status, timestamps and fixed error codes.
- Disablement revoked ingestion authority before external cleanup. Secret
  deletion used recovery windows; no force deletion was used.

## Cleanup evidence

After acceptance:

- the managed schedule was absent;
- the generated connector secret was under recoverable deletion;
- the synthetic provider secret was scheduled for deletion on 2026-08-06;
- the temporary Cognito platform-administrator user was deleted; and
- the collector dead-letter queue remained empty.

The disabled job, revoked connector record and two audit records remain as
redacted operational evidence. They contain no token, repository name or
project-root digest in any operator-facing response.

## Remaining production acceptance

Before relying on GitHub discovery for an enterprise denominator:

1. use an organization-approved, read-only credential with no code-content,
   administration, Actions or write access;
2. independently prove that it can enumerate every repository in the agreed
   organization scope, including private repositories;
3. complete one successful scheduled collection and verify numeric repository
   IDs plus deployment-owned correlation are the only committed observations;
4. reconcile the resulting expected Claude Code and Codex instances against a
   separately agreed source-control denominator and reach the rollout target;
5. test rotation, expiry, permission reduction and organization-access removal;
   and
6. replace the token with a centrally installed GitHub App when that credential
   adapter is available.

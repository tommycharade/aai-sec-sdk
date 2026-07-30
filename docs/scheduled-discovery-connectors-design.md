# AWS-managed discovery connectors

## Decision

The managed discovery providers are Microsoft Entra ID and GitHub. The AWS
control plane creates a tenant-scoped EventBridge Scheduler job that invokes a
dedicated collector Lambda. Entra produces the expected identity population;
GitHub produces the expected Claude Code and Codex repository population. Both
publish through the existing source-scoped atomic ingestion contract.

This is intentionally separate from Entra operator SSO and SCIM. Those
integrations authenticate and provision console operators. Discovery observes
the population that should be governed. Reusing an SSO or SCIM credential for
collection would combine unrelated authority and make revocation unsafe.

## Trust boundaries

### Browser to control plane

The browser submits only:

- the stable source ID;
- the provider enum `entra` or `github`;
- an interval from the closed set supported by the service;
- the ARN of a deployment-owned provider secret; and
- for GitHub only, a bounded typed repository-to-project mapping; and
- optimistic-concurrency revisions.

It never submits a client secret, Graph token, connector token, tenant override,
target Lambda ARN, scheduler role ARN, network URL, or arbitrary schedule
expression. The authenticated tenant comes from the operator context and the
control plane derives every AWS target.

### Provider secret

An Entra provider secret contains exactly:

```json
{
  "tenantId": "11111111-1111-4111-8111-111111111111",
  "clientId": "22222222-2222-4222-8222-222222222222",
  "clientSecret": "<deployment-owned-secret>"
}
```

It must be in the deployed AWS account and region, use the stack's discovery
KMS key, have a name under
`aai-sec/discovery/providers/{aaiTenantId}/`, and carry exact tags
`aai-sec:tenant-id={aaiTenantId}` and
`aai-sec:purpose=discovery-provider`. The control-plane Lambda may describe but
cannot read provider values. Only the collector Lambda can call
`GetSecretValue` for this bounded namespace.

Secrets Manager requires a KMS decrypt check while creating a connector secret
with the customer-managed key. The control-plane role's KMS decrypt permission
is therefore constrained to requests routed through Secrets Manager. The role
still has no `GetSecretValue` permission, so it cannot retrieve provider or
connector secret bytes.

The Entra application receives only Microsoft Graph application permission
`User.Read.All`, with tenant-admin consent and no directory write permission.
A GitHub provider secret contains exactly `{"token":"<secret>"}`. Use an
organization-approved fine-grained token covering every organization
repository, with repository metadata read-only and no content, administration,
Actions, or write permission. Production onboarding must retain evidence of
the selected organization's permission and repository-access review.

### Connector credential

For a managed source, the control plane generates the ingestion bearer and
stores its SHA-256 digest in DynamoDB. The plaintext is written directly to a
KMS-encrypted service secret whose name is derived from hashes of the tenant and
source IDs. It is never returned to the browser, logs, audit payloads, or job
read model. The collector reads it only when publishing.

Manual connectors keep the existing one-time-returned credential flow. A source
cannot be both manual and managed at the same credential revision.

### Scheduler to collector

The schedule name and invocation payload are derived by the control plane. A
dedicated IAM role can invoke only the collector Lambda and send failed events
only to the collector dead-letter queue. Schedule targets use a fixed retry
budget and no flexible delivery window. The collector accepts an exact event
schema and rejects unknown fields, providers, identifiers, secret namespaces,
and unbounded values before any network request.

### Collector to provider and ingestion

The Entra collector may contact only:

- `login.microsoftonline.com` for the exact tenant OAuth token endpoint;
- `graph.microsoft.com` for the exact `/v1.0/users` collection and validated
  continuation links; and
- the deployment-owned HTTPS API Gateway origin for discovery ingestion.

The GitHub collector may contact only `api.github.com` at the fixed
`/orgs/{organization}/repos` endpoint and the same deployment-owned ingestion
origin. The service supplies the API version, sort order, pagination and page
size; browser input cannot change a hostname, path or query.

Collection is bounded to 20 pages and 2,000 users, applies independent request
timeouts, rejects duplicate or malformed identities, and retains only opaque
object ID, active state, and optional department. GitHub collection has the
same 20-page and 2,000-observation limits. It rejects duplicate or malformed
repository IDs and requires every visible active repository to have exactly one
deployment-owned mapping and every configured repository to be visible.
Archived, unmapped repositories are ignored. Only the numeric repository ID,
project-root digest, expected hosts and optional business unit are published.
Names remain transient mapping keys. Email, display name, repository name,
provider token responses, and arbitrary provider properties are not persisted.

The collector strongly reads the current source revision before publication.
Partial upload pages remain invisible until the existing hash-bound atomic
commit succeeds.

## State model

One `DISCOVERY_JOB` record exists per managed source:

| Field | Purpose |
| --- | --- |
| `provider` | Closed provider enum: `entra` or `github` |
| `providerConfiguration` | Canonical non-secret GitHub organization and repository map; absent for Entra |
| `providerConfigurationDigest` | SHA-256 binding used by the schedule and collector |
| `status` | `provisioning`, `scheduled`, `running`, `healthy`, `degraded`, or `disabled` |
| `revision` | Optimistic-concurrency revision for operator changes |
| `intervalMinutes` | Bounded service-defined cadence |
| `providerSecretArn` | Reviewed AWS reference, never secret content |
| `scheduleName` | Server-derived EventBridge Scheduler identity |
| `lastAttemptAt` | Start of the latest collector invocation |
| `lastSuccessAt` | Latest committed generation |
| `lastErrorCode` | Fixed content-free operational reason |
| `consecutiveFailures` | Bounded failure counter for UI/alerting |

Credential state, job state, and snapshot state remain separate. A configured
schedule does not imply that credentials work, that Graph collection succeeded,
or that evidence is current.

## API

All mutations require `discovery_write` and exact platform-administrator
authority.

### Configure

`POST /api/enterprise/discovery/sources/{sourceId}/managed-collector`

```json
{
  "provider": "entra",
  "intervalMinutes": 15,
  "providerSecretArn": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:aai-sec/discovery/providers/tenant-a/entra-production-AbCdEf",
  "expectedJobRevision": 0,
  "expectedCredentialRevision": 0
}
```

The response is redacted job metadata. Initial provisioning creates the
connector secret and schedule before conditionally committing authority. Any
failed precondition removes the newly created external resources. A schedule
cannot run before its delayed start time, so no job observes uncommitted state.

GitHub uses the same route with a typed configuration:

```json
{
  "provider": "github",
  "intervalMinutes": 15,
  "providerSecretArn": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:aai-sec/discovery/providers/tenant-a/github-production-AbCdEf",
  "providerConfiguration": {
    "organization": "example-enterprise",
    "repositories": [
      {
        "fullName": "example-enterprise/platform-api",
        "projectRootDigest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "expectedHosts": ["claude-code", "codex-cli"],
        "businessUnit": "Platform"
      }
    ]
  },
  "expectedJobRevision": 0,
  "expectedCredentialRevision": 0
}
```

The configuration permits at most 500 mappings. Unknown fields, unsafe slugs,
raw project paths, duplicate repositories or digests, unsupported hosts and
empty host sets fail closed. The response exposes only organization and mapping
count, never repository names, project digests or secret references.

### Disable

`DELETE /api/enterprise/discovery/sources/{sourceId}/managed-collector`
requires the job and credential revisions in its JSON body. The control plane
atomically marks the job disabled and revokes the connector before deleting the
schedule and scheduling secret deletion. If external cleanup fails, ingestion
still remains denied by live connector state and the job reports cleanup
required.

### Read

`GET /api/enterprise/discovery/sources` includes redacted `managedCollector`
metadata alongside credential and snapshot state. It never includes connector
secret names/ARNs, provider secret values, Graph tokens, schedule input, or raw
errors.

## Failure and monitoring behavior

The collector records only fixed reason codes:

- `configuration_invalid`
- `provider_secret_unavailable`
- `connector_secret_unavailable`
- `provider_authentication_failed`
- `provider_transport_failed`
- `provider_response_invalid`
- `provider_inventory_too_large`
- `provider_mapping_incomplete`
- `source_revision_conflict`
- `ingestion_rejected`
- `internal_error`

Every failed invocation increments a bounded counter and leaves the previous
snapshot untouched. Lambda failure metrics and the dedicated dead-letter queue
feed the existing security alerting foundation. The UI shows the last attempt,
last success, failure count, and fixed reason without exposing provider data.

## Low-friction operator journey

1. In **Coverage → Inventory sources**, choose **Microsoft Entra ID** or
   **GitHub organization**, then **AWS-managed schedule**.
2. Copy the generated AWS CLI template for the required KMS key, secret prefix,
   and tags; fill the three values locally or through the enterprise secret
   provisioning workflow.
3. For GitHub, enter the organization and edit or import the typed repository
   map. Paste only the resulting secret ARN, select a cadence, and review the
   exact permission and data-minimisation boundary.
4. Choose **Create managed collector**. The UI reports schedule state separately
   from credential and evidence state.
5. Wait for the first run or choose a bounded **Run now** action when supported.
6. Confirm **Healthy** collector state and **Current** evidence before relying on
   coverage.

## Non-guarantees and remaining work

- Managed Entra and GitHub collection does not prove endpoint coverage.
- GitHub REST responses can prove only repositories visible to the token. A
  token that hides both an unmapped repository and its mapping cannot reveal
  that blind spot. Production acceptance must independently prove that the
  token covers all organization repositories; a future organization-installed
  GitHub App is preferred for centrally governed access and revocation.
- A client secret is not workload identity; future deployments may replace it
  with Entra workload identity federation without changing normalized output.
- The first live acceptance can prove AWS scheduling, secret isolation, bounded
  failure, and synthetic provider contracts. Successful real Graph collection
  requires pilot-tenant credentials and admin consent.
- Population acceptance still requires a measured 95% pilot denominator and
  documented blind spots.

# AWS-managed discovery connectors

## Decision

The first managed discovery provider is Microsoft Entra ID. The AWS control
plane creates a tenant-scoped EventBridge Scheduler job that invokes a dedicated
collector Lambda. The collector renews a Microsoft Graph application token from
an AWS Secrets Manager client-credential secret, collects a bounded user
inventory, and publishes it through the existing source-scoped atomic ingestion
contract.

This is intentionally separate from Entra operator SSO and SCIM. Those
integrations authenticate and provision console operators. Discovery observes
the population that should be governed. Reusing an SSO or SCIM credential for
collection would combine unrelated authority and make revocation unsafe.

## Trust boundaries

### Browser to control plane

The browser submits only:

- the stable source ID;
- the provider enum `entra`;
- an interval from the closed set supported by the service;
- the ARN of a deployment-owned provider secret; and
- optimistic-concurrency revisions.

It never submits a client secret, Graph token, connector token, tenant override,
target Lambda ARN, scheduler role ARN, network URL, or arbitrary schedule
expression. The authenticated tenant comes from the operator context and the
control plane derives every AWS target.

### Provider secret

The provider secret contains exactly:

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

The Entra application receives only Microsoft Graph application permission
`User.Read.All`, with tenant-admin consent and no directory write permission.
Production onboarding must retain evidence of that permission review.

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

Collection is bounded to 20 pages and 2,000 users, applies independent request
timeouts, rejects duplicate or malformed identities, and retains only opaque
object ID, active state, and optional department. Email, display name, token
responses, and arbitrary Graph properties are not persisted.

The collector strongly reads the current source revision before publication.
Partial upload pages remain invisible until the existing hash-bound atomic
commit succeeds.

## State model

One `DISCOVERY_JOB` record exists per managed source:

| Field | Purpose |
| --- | --- |
| `provider` | Closed provider enum; initially `entra` |
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
- `source_revision_conflict`
- `ingestion_rejected`
- `internal_error`

Every failed invocation increments a bounded counter and leaves the previous
snapshot untouched. Lambda failure metrics and the dedicated dead-letter queue
feed the existing security alerting foundation. The UI shows the last attempt,
last success, failure count, and fixed reason without exposing provider data.

## Low-friction operator journey

1. In **Coverage → Inventory sources**, choose **Microsoft Entra ID** and
   **AWS-managed schedule**.
2. Copy the generated AWS CLI template for the required KMS key, secret prefix,
   and tags; fill the three values locally or through the enterprise secret
   provisioning workflow.
3. Paste only the resulting secret ARN, select a cadence, and review the exact
   permission and data-minimisation boundary.
4. Choose **Create managed collector**. The UI reports schedule state separately
   from credential and evidence state.
5. Wait for the first run or choose a bounded **Run now** action when supported.
6. Confirm **Healthy** collector state and **Current** evidence before relying on
   coverage.

## Non-guarantees and remaining work

- AWS-managed Entra collection does not prove endpoint or GitHub coverage.
- A client secret is not workload identity; future deployments may replace it
  with Entra workload identity federation without changing normalized output.
- The first live acceptance can prove AWS scheduling, secret isolation, bounded
  failure, and synthetic provider contracts. Successful real Graph collection
  requires pilot-tenant credentials and admin consent.
- Population acceptance still requires a measured 95% pilot denominator and
  documented blind spots.

# Regional target readiness and stable ingress

## Outcome

The guarded transition now has an implemented pre-routing target-readiness
step and an independently verified Regional ingress stack. The stack can
create stable and canary custom-domain attachments in either Region, but it
cannot create or change DNS. Live deployment remains pending customer-owned
domains and certificates. These boundaries are separate on purpose: live
compute, reconstructed jobs and custom domains do not imply that traffic may
move.

## Implemented target-readiness step

`reconcile-target` is available only after the journal reaches
`TARGET_ACTIVE_NOT_ROUTED`. It repeats the complete provider preflight but now
requires the deployed recovery stack to report exactly `active-not-routed`.
It then:

1. transactionally claims `RECONCILING_TARGET_JOBS` in the third-Region
   witness;
2. independently re-verifies the complete source fence;
3. discovers exactly one handler, two workers, two queue mappings and four
   schedules from stable CloudFormation state;
4. reads each live Lambda configuration and requires the reviewed concurrency,
   handler, memory, timeout, architecture, code digest, revision, Python
   runtime, activation-evidence digest, recovery signer and Entra authority;
5. requires both mappings and all schedules to be enabled;
6. invokes the exact target handler in read-only `check` mode;
7. invokes `apply`, which rebuilds Region-local queue work only from strongly
   read DynamoDB job and policy revisions;
8. polls with a bounded ten-minute window until no dispatch/fail action
   remains; fresh running jobs may remain explicitly deferred; and
9. re-reads the target and rejects any code/config revision change during the
   step; and
10. records `TARGET_JOBS_RECONCILED_NOT_ROUTED` with a SHA-256 over the source
   fence, live target posture, initial check, apply result and final check.

The Lambda response is untrusted. Duplicate JSON keys, unknown fields,
booleans-as-counts, oversized counts, a changed evidence digest, a different
queue source, inconsistent dispatch totals, Lambda errors and oversized output
all fail closed. If the process or provider fails after dispatch, the journal
remains in progress. The same authority may retry; FIFO deduplication and
revision-conditioned workers prevent repeated committed effects. A completed
retry must match the exact evidence digest already appended to the journal.

This is a runtime and job-reconciliation smoke, not a public-ingress smoke. The
raw `execute-api` endpoints remain disabled and traffic remains on the source.
A future route command must repeat a zero-action reconciliation check
immediately before claiming routing; it cannot rely indefinitely on this
earlier result.

## Stable ingress decision

The target design uses Regional API Gateway custom domains in both Regions.
AWS documents that Regional APIs deployed in multiple Regions may use the same
custom domain name. Each Region requires its own same-Region ACM certificate.
Route 53 aliases can then select the active Regional endpoint.

The two stable names are implemented consistently:

- `stableApiDomain` maps to the Region's existing authenticated control-plane
  API stage;
- `stableUiDomain` maps to a small Regional HTTP API and bounded Lambda that
  reads only the exact private UI bucket;
- the UI proxy disables its default `execute-api` endpoint and deployment is
  rejected unless the mapped control API has also disabled its raw endpoint;
- TLS 1.2 is mandatory and certificates, API mappings, S3 role scope and
  hosted-zone identity are independently verified; and
- separate Region-specific canary names reach each regional API/UI endpoint
  before stable traffic moves.

## Implemented non-routing ingress

`RegionalIngressStack` creates exactly four TLS 1.2 Regional custom domains:
stable API, stable UI, Region-specific canary API and Region-specific canary
UI. The API names map to the provider-derived existing control API. The UI
names map to a new HTTP API whose default `execute-api` endpoint is disabled.
It serves GET and HEAD only through one 256 MiB, ten-second, concurrency-20
Lambda with `s3:GetObject` on one exact private bucket and no list/write,
control-plane or routing authority.

The UI handler bounds assets to 5 MB, rejects encoded and unencoded traversal,
uses SPA fallback only for missing objects, gives the entry document
`no-store`, and applies HSTS, frame denial, MIME protection and an exact CSP.
The CSP permits browser connections only to the stable API and reviewed
Cognito origin. The active recovery API now accepts browser CORS only from the
exact stable UI origin; the standby template retains the deliberately invalid
origin. Both states are independently verified.

`verify_regional_ingress_stack.py` uses a resource allow-list and exact
cardinality. It rejects Route 53, CloudFront, Global Accelerator and every
unexpected resource; certificate/domain/origin substitutions; altered API
mappings; raw API fallback; changed Lambda limits; additional IAM statements;
and any status other than `custom-domains-unrouted`.

`deploy_aws_regional_ingress.py` is the only supported deployment path. Its
schema-v1 manifest explicitly sets `activationPermitted` to false. The guard:

1. derives the AWS account from STS;
2. derives the existing API ID and private UI bucket from a stable source
   CloudFormation stack and requires the live HTTP API's raw execute-api
   endpoint to be disabled;
3. reads ACM and requires one issued, fully validated, same-account,
   same-Region certificate with exactly the four manifest names;
4. discards ambient ingress environment variables;
5. synthesizes and independently verifies the template;
6. persists the secret-free authority in encrypted Parameter Store; and
7. deploys only the byte-identical, SHA-256-verified CDK assembly.

Prepare a private copy of
`infra/aws-control-plane/regional-ingress.example.json`, then run:

```bash
python3 scripts/deploy_aws_regional_ingress.py check \
  --config /private/path/recovery-ingress.json --profile p1
python3 scripts/deploy_aws_regional_ingress.py prepare \
  --config /private/path/recovery-ingress.json --profile p1 \
  --confirm-persist-authority
python3 scripts/deploy_aws_regional_ingress.py deploy \
  --config /private/path/recovery-ingress.json --profile p1 \
  --confirm-unrouted-deployment
```

Repeat with the primary role/stack and its provider identities. These commands
do not create Route 53 records and do not make either Region active.

The UI proxy is deliberately serverless. It trades some CDN performance for a
single routing primitive that can move the UI and API together. A later CDN may
sit in front only if it preserves atomic regional authority and does not
reintroduce a globally unique alternate-domain conflict.

AWS references:

- [API Gateway Regional endpoint types](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-endpoint-types.html)
- [Regional custom-domain setup](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-regional-api-custom-domain-create.html)
- [API Gateway S3 proxy integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services-s3.html)
- [Route 53 transactional change batches](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)

## Implemented routing compare-and-swap

Route 53 change batches are transactional—all records in a valid batch change
or none do—but Route 53 does not expose a conditional generation token. The
single-writer witness therefore remains the CAS authority. The implemented route
step is:

```text
TARGET_JOBS_RECONCILED_NOT_ROUTED
  -> VERIFYING_TARGET_INGRESS
  -> TARGET_INGRESS_VERIFIED_NOT_ROUTED
  -> ROUTING_TARGET
  -> VERIFYING_STABLE_ROUTE
  -> STABLE (generation + 1, activeRegion = target)
```

Before `ROUTING_TARGET`, the executor repeats source fencing, target live
posture, zero-action job reconciliation, canary authentication and policy read.
It strongly reads
the witness generation and exact current Route 53 API, UI and generation-marker
records. One Route 53 change batch will delete the byte-equivalent source
aliases and marker and create the exact target aliases and next marker. It will
wait for the returned change ID to become `INSYNC`, then independently read
Route 53 and probe both stable names before committing the new journal
generation. It validates the public hosted zone, reads a bounded paginated
record inventory, rejects parallel AAAA/CNAME/routing records, and accepts only
the exact source state or exact next-generation target state. A retry after
provider acceptance but before journal advancement recognizes only that exact
target state.

An out-of-band DNS administrator could still race the provider between the
exact read and Route 53 mutation. Production acceptance therefore also
requires a dedicated transition role, removal of ordinary Route 53 write
authority, an organization SCP or equivalent permission boundary, CloudTrail
alerting and AWS Config drift detection. Without that control, the adapter can
detect divergence but cannot truthfully claim provider-level CAS.

## Failed cutover and failback

If Route 53 rejects the change batch, no DNS record changes and the journal
remains `ROUTING_TARGET`. If Route 53 accepts the batch but stable probes fail,
the executor does not mark the target stable. It also never performs DNS-only
rollback: the source was intentionally fenced, so routing users back before
independent source reactivation would create an outage.

Schema-v4 rollback instead performs five ordered, independently confirmed
steps. It fences and verifies the failed target, restores the original source
from an exact processed-template-bound plan, proves source canary
authentication, transactionally moves API/UI/marker back at generation + 2,
then proves stable service before recording `ROLLED_BACK`. The target remains
fenced throughout source restoration. Mixed DNS, changed templates, partial
restoration, stale journal authority and changed retry evidence all fail
closed. A retry after Route 53 convergence recognizes the exact source records
and does not submit a duplicate mutation.

Failback is not implemented by swapping labels in the failover code. The
primary runtime needs the same active-template verifier, target job
reconciliation, regional ingress and canary contracts first. Only then may the
same state machine run with source and target reversed.

## Current blockers and non-guarantees

Live deployment and routing still require:

- approved stable and regional-canary names in one Route 53 hosted zone;
- primary and recovery ACM certificate ARNs, each covering exactly its stable
  API/UI names and that Region's API/UI canary names;
- deployment of the recovery Cognito/Entra configuration and regional cell;
- migration of the primary control API away from its currently open raw
  execute-api endpoint before primary ingress can pass the deployment guard;
- customer approval for the dedicated routing role and organization-level DNS
  write restriction;
- schema-v4 retained digests for both exact provider-processed runtime
  templates; and
- a scheduled two-person recovery exercise.

No Route 53 record, certificate, custom domain, UI proxy or live AWS transition
was created by this implementation tranche. Forward routing and failed-cutover
rollback are implemented and synthetically tested; planned failback and the
live exercise remain incomplete, so P0-11 remains **Partial**.

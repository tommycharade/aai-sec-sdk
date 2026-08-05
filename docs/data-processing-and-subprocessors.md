# Data processing and subprocessors

This is the technical data-processing schedule for security review of the
open-source SDK and reference AWS control plane. It is not a signed Data
Processing Agreement (DPA). A customer-specific DPA must identify the legal
entities, governing law, approved regions, retention choices and commercial
service before production data is processed.

## Roles and scope

The Apache-2.0 SDK runs in the adopter's application or developer host. The
project does not receive data merely because the SDK is installed. In that
deployment the adopter selects providers and normally acts as both controller
and operator of processing.

For the hosted control plane, the customer determines purposes, authorized
agents, users, policies, evidence settings and integrations. The hosted service
processes those instructions as a processor. Model providers remain the
customer's direct providers: the reference control plane does not proxy prompts
or model responses to Anthropic, OpenAI or GitHub Copilot.

## Data categories and minimisation

| Category | Examples | Default handling |
| --- | --- | --- |
| Identity and ownership | Tenant, user subject, role, team, business owner | Required for authorization; no model-supplied principal is trusted |
| Agent and device posture | Agent ID, project root, version, heartbeat, configuration digest | Collected for fleet governance and drift; no raw credential is accepted |
| Policy and approval | Policy versions, semantic changes, rationale, approval binding | Versioned and auditable; activated policy is immutable |
| Decision evidence | Tool identity, redacted arguments, outcome, policy version, timestamps | Redacted before persistence; content capture is opt-in |
| Integration metadata | Repository, MCP, skill, provider and delivery status | Scoped to configured integrations; secrets are referenced, not returned |
| Incident and assurance | Alert/case metadata, evidence object identities, signed report summaries | Content-minimised and integrity-bound |

The system is not designed to store prompts, source files, tool output or
credentials by default. A customer who enables content capture must define a
lawful purpose, minimisation rule, retention period and authorized reader
scope. Secret values belong in the customer's approved secret manager.

## Reference AWS locations and retention

The current reference deployment uses `eu-west-2` as its primary application
region and `eu-west-1` for immutable audit recovery. CloudFront serves public
static UI assets through its global edge network; this does not move control-
plane records into the UI bundle. No broader residency guarantee is made until
a customer-specific architecture and contract identify it.

Immutable audit evidence uses S3 Object Lock COMPLIANCE retention. Tenant
retention is increase-only from 365 to 3,650 days. Legal hold can extend
retention. DynamoDB control records and retained KMS keys use infrastructure
retention protections; deletion therefore requires a reviewed tenant
offboarding plan and cannot override active Object Lock or legal hold.
CloudWatch retention is resource-specific, not a single service-wide promise.
The regional fault-controller workflow explicitly retains its log group for
one year. Some Lambda-created log groups currently rely on AWS defaults rather
than an explicit CDK retention declaration. A production deployment must
inventory every log group, set the customer-approved period and retain that
generated inventory as DPA evidence; this draft schedule must not be used to
infer an undocumented 1-, 4- or 14-day guarantee.

The deletion procedure must inventory active records, retained evidence,
replicas, backups, legal holds, pending jobs and secret references. A request
cannot promise immediate erasure of compliance-locked evidence. The response
must state what was deleted, what remains, the controlling retention basis and
the final eligible deletion date.

## Subprocessor and provider register

| Provider | Purpose | Data involved | Location/control | Optional |
| --- | --- | --- | --- | --- |
| Amazon Web Services | Hosted API, identity, compute, storage, queues, keys, monitoring and static UI delivery | Categories enabled in the hosted tenant | Primary `eu-west-2`, audit recovery `eu-west-1`, CloudFront global edge | No for reference hosted service |
| GitHub | Source repository, private vulnerability intake, release artifacts/provenance and optional repository discovery/policy source | Project source; private-report identity/contact details, embargoed evidence and affected-version metadata; and, only when configured, scoped customer repository metadata | Project security repository plus customer-approved GitHub organization and repository scope | Repository connector is optional; project vulnerability intake is not |
| PyPI | Public Python package distribution | Public artifacts and package metadata; no customer control-plane data | PyPI service | Optional; GitHub artifacts may be used instead |
| Microsoft Entra ID | Customer-selected workforce identity and SCIM lifecycle | User/group identifiers and role mapping | Customer tenant; configured directly by customer administrator | Optional until enterprise federation is enabled |

Anthropic, OpenAI and other model providers are not subprocessors of the
reference control plane merely because an enrolled developer uses their agent.
If a future hosted feature transmits data to a model provider, it requires a
new data-flow review, register update and customer opt-in before release.

## Security measures

Technical measures include tenant-bound authorization, deny-by-default runtime
policy, per-action approval binding, scoped credentials, redaction before
persistence, private S3 origins, encryption in transit and at rest, KMS-signed
policy/evidence artifacts, Object Lock, cross-region audit replication,
bounded queues with dead-letter alarms and authenticated operator/agent
surfaces. The [security model](security-model.md) defines the exact guarantees
and non-guarantees.

## Customer decisions required for a DPA

Before production use, record:

- controller and processor legal entities and contacts;
- data subjects, purposes and lawful basis;
- approved regions and cross-border transfer mechanism;
- tenant retention, legal hold and deletion contacts;
- enabled integrations and their credential/data scopes;
- incident notification terms and audit rights;
- approved subprocessor notice/change mechanism; and
- return/deletion evidence required at termination.

The absence of those decisions is a deployment blocker, not permission to use
synthetic defaults for customer data.

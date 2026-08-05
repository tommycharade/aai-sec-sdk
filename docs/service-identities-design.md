# Scoped service identities and the machine API

## Purpose

Enterprise automation must not borrow a person's Cognito or Microsoft Entra
session. The control plane therefore provides expiring, tenant-bound service
identities for CI, inventory, evidence collection and bounded fleet workflows.
The browser remains the only supported place to create, rotate or revoke these
identities. Workloads use a separate versioned API surface:

```text
human:   /api/enterprise/...       Cognito/Entra JWT
machine: /machine/v1/enterprise/... scoped service bearer
```

This is control-plane automation authority. It is not an enrolled Claude Code
or Codex runtime identity, an AWS IAM role, or a replacement for workload
identity federation and an enterprise secret manager.

## Trust boundary

The machine route is deliberately declared without the API Gateway JWT
authorizer because its bearer is not a Cognito JWT. The Lambda handler is the
mandatory authenticator for that route. It hashes the presented bearer, loads
the digest-keyed credential pointer and strongly reads the tenant-owned service
identity before admitting every request. It checks status, expiry, credential
revision, current credential binding and the exact capability required by the
versioned route.

The bearer never carries trusted tenant, role or scope claims. Server records
derive all three. A private in-process marker distinguishes this derived
context from caller-shaped JWT claims. Machine authority cannot inherit a
human role, delegated grant or break-glass grant.

The unversioned `/machine/...` path, unknown routes, malformed records, missing
bearers, stale revisions, expired credentials and failed authority reads all
fail closed.

## Lifecycle

Only a current `platform-admin` can manage service identities. Delegated and
emergency authority cannot satisfy this check.

1. **Create.** Supply a stable ID, display name, purpose, optional description,
   one or more capabilities and a lifetime of 1–90 days.
2. **Reveal once.** The plaintext bearer appears only in the create response.
   Store it directly in an approved secret manager. Later list and detail reads
   expose only a short SHA-256 fingerprint.
3. **Use.** Send the bearer to an explicitly allowed `/machine/v1` route. Every
   admitted request records method, canonical route, capability, credential
   revision and server time; arguments and response bodies are not copied into
   usage evidence.
4. **Rotate.** Submit the expected identity revision and a new lifetime. One
   transaction replaces the credential pointer and revokes the old bearer. The
   replacement bearer is again shown once.
5. **Revoke.** Submit the expected revision and rationale. Identity and pointer
   become inactive atomically. Later requests fail before downstream routing.

Creation, rotation and revocation also retain content-minimised authority-change
records and export immutable Object Lock audit evidence. Usage records expire
after 90 days; lifecycle records remain available under the control plane's
normal retention model.

## Capability contract

Capabilities map to an explicit route allowlist. Adding a human endpoint does
not expose it to existing machine credentials.

| Capability | Permitted workload | Important exclusions |
| --- | --- | --- |
| `inventory_read` | Read agents, groups, policies and versions, deployments, health, drift, projects, organizations, templates, Skills and MCP registrations | No identity, approval or incident administration |
| `evidence_read` | Read audit, discovery, evidence and executive/auditor assurance exports | No retention changes, legal hold or case response |
| `policy_draft_write` | Create policies, draft versions, Skills and MCP registrations | No submission, approval, staging, activation, exception or package publication |
| `policy_simulation` | Run the bounded historical simulation route for an exact draft version | No action execution or policy activation |
| `fleet_write` | Create projects, groups and deployments; bootstrap/register agents; manage bounded group membership | No emergency stop, identity lifecycle or incident containment |
| `runtime_write` | Create templates and start, pause or roll back measured deployment-configuration and runtime-release rollouts | No endpoint remediation report, managed-package publication, signing-key governance or emergency authority |
| `runtime_remediation` | Read an exact server-selected instruction when paired with `inventory_read`, then claim it and report one bounded channel outcome | No rollout authoring, member selection, executable delivery, provider credential, installation authority or verification claim |

The control plane advertises exactly these seven values. Unsupported, duplicated,
empty or oversized capability lists are rejected. A service identity with
multiple capabilities receives their union only on the routes listed above.

## Operator journey

Open **Administration → API access** in the enterprise UI. The table shows
identity status, scope summary, last admitted use, expiry and fingerprint. The
detail panel shows the complete capability set and recent retained usage. The
posture summary calls out near-expiry and never-used authority.

Use one identity per workload and environment. Start with a read capability,
use the shortest practical lifetime, rotate through the target secret manager,
and revoke identities whose usage evidence does not match their stated purpose.
The UI requires explicit acknowledgement before dismissing a newly issued
secret and explains every selectable capability in place.

## Machine API example

Use a synthetic environment variable name in local testing; do not place the
bearer in a command line, source file or shell history.

```bash
export AAI_SERVICE_TOKEN="$(security find-generic-password \
  -a aai-ci-reader -s aai-security -w)"

curl --fail-with-body \
  --header "Authorization: Bearer ${AAI_SERVICE_TOKEN}" \
  "https://CONTROL_PLANE.example.invalid/machine/v1/enterprise/policies"
```

Create, rotate and revoke operations intentionally have no machine route. An
authenticated platform administrator performs them through the UI or the human
API. The create request schema is:

```json
{
  "serviceIdentityId": "github-policy-check",
  "name": "GitHub policy check",
  "description": "Owned by the policy validation workflow.",
  "purpose": "Read inventory and simulate reviewed policy drafts.",
  "capabilities": ["inventory_read", "policy_simulation"],
  "expiresInDays": 30
}
```

The official Terraform provider uses this same boundary for repeatable policy
draft, group, Skill and MCP configuration. Its revision-guarded update routes
are included only in `policy_draft_write` or `fleet_write`; human policy
transitions remain absent. See [Terraform provider and declarative
management](terraform-provider-design.md).

## Guarantees and non-guarantees

The implementation guarantees, within the hosted control-plane boundary, that
an admitted machine request has a live tenant-owned identity, current unexpired
credential and an exact route capability at admission time. Rotation and
revocation use optimistic revision checks and transactional authority changes.
Plaintext bearers are not persisted by this feature or returned by list/detail
APIs.

It does not prove the identity of the external workload holding a bearer,
prevent that workload or its logs from leaking the secret, provide mTLS,
automatically rotate a downstream secret manager, or replace network controls.
For production, restrict API ingress, alert on unusual route/use patterns,
store the bearer in a managed secret service and prefer a future short-lived
federated credential adapter when available.

## Test evidence

The AWS Lambda contracts exercise one-time issue, secret-free reads, successful
machine admission, usage evidence, rotation, immediate revocation, expiry,
forged credentials, tenant isolation, unsupported capability escalation and
human-governance route denial. A CDK contract verifies the separate machine
route is not assigned the human JWT authorizer. UI tests exercise management
authority, typed capability help, one-time secret handling and usage display.

Run the relevant suites with:

```bash
python3 -m pytest tests/test_aws_lambda_contract.py -q
cd aai-sec-ui
npm run check
```

Synthetic tests establish implementation behavior, not live workload or secret
manager acceptance. Production evidence still requires a real CI workload,
approved secret store, deployed AWS route and observed rotate/revoke exercise.

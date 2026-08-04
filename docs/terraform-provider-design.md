# Terraform provider and declarative management

The Agentic Security Terraform provider gives platform teams a repeatable,
reviewable way to configure one existing tenant. It uses only the versioned
`/machine/v1` API and a tenant-bound service identity. It does not use a human
Cognito or Entra session and cannot approve, stage or activate policy.

## Security boundary

Terraform is an automation principal, not a policy approver. Its authority is
deliberately split:

| Object | Declarative behavior | Destruction behavior |
| --- | --- | --- |
| Tenant | Read the exact tenant bound to the bearer | Tenant provisioning and deletion remain deployment-owned |
| Policy | Create an inactive version-one draft; a later change appends a draft after the previous version completes governance | Remove Terraform tracking while retaining the immutable policy ledger |
| Group | Create or update metadata and bind an already-active policy | Delete only when membership is empty and exact revisions still match |
| Skill | Create and revision-check updates | Retire and retain evidence |
| MCP server | Create and revision-check updates | Retire and retain evidence |

The provider cannot call policy submission, approval, staging, activation,
identity administration, human approvals, emergency controls, incident
response or managed-package publication. Adding a human API route does not
make it available to machine clients because the machine allow-list is
independent.

## Provider configuration

Use a service identity with only the capabilities required by the plan:

- `inventory_read` for refresh, import and drift detection;
- `policy_draft_write` for policy drafts, Skills and MCP servers; and
- `fleet_write` for groups.

Supply the endpoint and short-lived bearer through `AAI_SEC_ENDPOINT` and
`AAI_SEC_SERVICE_TOKEN`. Environment variables keep the bearer out of HCL and
normal Terraform state, but the CI secret store and process environment remain
deployment-owned security boundaries. Rotate the credential at most every 90
days and immediately after suspected disclosure.

```hcl
terraform {
  required_providers {
    aaisec = {
      source = "tommycharade/aaisec"
    }
  }
}

provider "aaisec" {
  timeout_seconds = 30
}

data "aaisec_tenant" "current" {}
```

The endpoint must be HTTPS. Plain HTTP is accepted only for `localhost` and
`127.0.0.1` development. Requests have an explicit 1–120 second timeout and
responses are bounded to 8 MiB. The provider never logs or stores the bearer
as resource state.

Every accepted create, update, retirement or group deletion commits a
content-minimised configuration-audit record in the same DynamoDB transaction
as the desired-state mutation. S3 Object Lock export is a best-effort replica
of that already durable primary evidence, so an export outage cannot create an
unaudited configuration change.

## Resources

### Policy draft

`aaisec_policy_draft` accepts the SDK policy object as
`configuration_json`. The server schema-validates it, composes exact component
versions and creates only an inactive draft. An update appends another draft;
it fails while an earlier version is still pending. An independent human must
review, approve, stage and activate the version in the UI or human API.

Destroying the Terraform resource deliberately retains the server ledger and
emits a warning. This is evidence retention, not an unreported no-op. Import
uses the policy ID and refresh selects the pending version, then the active or
latest version.

### Group

`aaisec_group` binds a group to an already-active policy. Name and policy
changes use `configuration_revision`; membership has a separate
`membership_revision`, so an update cannot overwrite concurrent fleet work.
Destroy fails if the group contains any agent. Empty the group through the
approved fleet workflow first.

### Skill and MCP server

`aaisec_skill` stores bounded Skill content and returns its server-computed
SHA-256 digest. `aaisec_mcp_server` permits `stdio` or HTTPS `http`
definitions. MCP credentials are environment-variable names only; secret
values are never accepted. HTTP definitions also reject URL credentials,
queries and fragments. Both resources use optimistic revisions. Destroy
changes status to `retired`, disables deployment and retains evidence and
historical policy references.

## Import and drift

Every resource imports by its tenant-scoped ID, for example:

```bash
terraform import aaisec_group.platform group-platform
terraform import aaisec_skill.review secure-review
```

Refresh reads the live tenant collection and matches only the exact ID. A
missing resource is removed from state. Out-of-band content changes appear in
the next plan. Apply sends the revision last observed by Terraform; if another
operator changes the object between refresh and apply, HTTP 409 stops the run
instead of applying last-writer-wins authority.

## Guarantees and non-guarantees

The implementation guarantees versioned routing, tenant derivation from live
credential state, bounded network behavior, secret-free Terraform resource
state, optimistic concurrency and exclusion of human governance transitions.
It does not provision tenants, store CI credentials, approve policy, manage
group membership, distribute host packages, or prove endpoint convergence.
Those remain explicit control-plane, human-governance and deployment concerns.

The provider source currently lives in `terraform-provider-aai-sec/` so its API
and acceptance tests can evolve with the control plane. Publishing it to the
Terraform Registry requires a separately versioned release and signing
workflow; local development instructions are in that directory's README.
The repository quality gate runs formatting, `go vet`, unit tests, the Go
vulnerability database scanner, real Terraform protocol-schema discovery and
example validation.

# Approved runtime releases and version compliance

## Purpose

Enterprise operators need to answer two different questions before expanding a
Claude Code or Codex rollout:

1. which SDK, MCP gateway and native-hook artifacts have been independently
   approved; and
2. which active enrolled runtimes currently prove that exact approved version.

The control plane now exposes those answers separately. `GET
/api/enterprise/runtime-releases` projects the immutable deployment-owned
release authority. `GET /api/enterprise/version-compliance` compares each
active tenant agent with its deployment target and fresh runtime attestation.
The Deployments **Runtime releases** workspace presents both views without
allowing the browser to create release authority.

This is the release and compliance foundation for P1-FLT-06 and P1-ADM-02.
The control plane now also provides revision-bound dual-version canary
selection, exact per-agent admission, measured expansion, pause and rollback as
documented in [Measured runtime-release rollouts](runtime-release-rollout-design.md).
MDM or another administrator-owned delivery channel remains required before a
managed upgrade can be marked physically complete.

## Trust boundary

- Release manifests and their provenance are deployment inputs produced from a
  clean tagged checkout by the documented generator.
- CDK validates the exact files and passes their SHA-256 identities to Lambda.
- Lambda revalidates bundle integrity, closed schemas, unique host/version
  identities and exact approval coverage before serving any release metadata.
- The browser and enrolled endpoint cannot submit a release, approval, digest,
  compliance count or status.
- Tenant identity comes from authenticated context. Tenant-wide release and
  compliance reads require the explicit human `inventory_read` capability
  (`platform-admin`, `security-operator`, `fleet-operator`, or `auditor`) or
  the exact `inventory_read` machine capability. Policy-only and
  approval-only roles are denied.
- Compliance is derived from current tenant-scoped deployment and active-agent
  records. Revoked and offboarded identities remain evidence but do not count
  as a live release population.

An open transition is insulated from later catalog replacement: the control
plane persists closed current and target release bindings containing the exact
attestation manifest, revision, artifact identities and both approval-bundle
identities. Malformed or missing persisted bindings fail closed rather than
falling back to a deployment version. The persisted authority is evaluated
before the empty-catalog development compatibility path, so removing the live
catalog cannot turn off attestation during an open or retained rollout.

The release catalog intentionally returns no executable bytes, source origin,
project path, credential, prompt, command, tool arguments or result content.
Artifact and evidence digests are identifiers, not downloadable artifacts or
digital-signature claims.

## Release catalog contract

The response contains:

- `status`: `configured` only when at least one exactly approved host manifest
  is deployed; otherwise `not_configured`;
- SHA-256 identities for the exact manifest and approval bundles;
- one stable `host:sdkVersion` release identity per approved Claude Code or
  Codex target;
- release tag and source commit identity; and
- separate SDK package, MCP gateway and native-hook digests.

An empty, malformed, stale, partially approved or ambiguously duplicated bundle
fails closed. The checked-in bundle is intentionally empty, so an undeployed
development checkout reports `not_configured` rather than healthy.

## Version-compliance contract

The endpoint returns at most 250 stored-agent records per request. A bounded,
tenant-bound opaque `nextToken` continues the query without the former 2,000
record all-or-nothing ceiling. `hasMore` states whether another cursor exists.
`scope` is `fleet` only for an initial request whose complete population fits
on one page; every continuation response remains `page`, including the final
fragment. Counts and deployment summaries describe the returned active-agent
page. Page-scoped deployment outcomes are named `page_compliant` or
`page_attention`; neither API nor UI may present them as fleet conclusions.

For every active enrolled agent on the page, the server resolves the
deployment's desired SDK version and current runtime-attestation evidence.
Exactly one status is returned:

| Status | Meaning |
| --- | --- |
| `compliant` | Fresh compliant evidence reports the exact desired SDK version and that host/version is approved. |
| `release_not_configured` | No deployment-owned approved release catalog exists. |
| `desired_release_unapproved` | The deployment target has no exact approved host/version manifest. |
| `quarantined` | Runtime attestation or agent state is quarantined. |
| `evidence_missing` | No current compliant version evidence exists. |
| `evidence_expired` | Previously supplied attestation is outside its server-clock validity window. |
| `version_mismatch` | The observed SDK version differs from the deployment target. |
| `artifact_mismatch` | The reported SDK revision or complete package/gateway/hook manifest binding differs from the approved release. |

Page and deployment totals are calculated from those rows; callers cannot
supply counts. Quarantine has highest precedence so missing release authority
cannot hide active containment. An empty page is unmeasured, not compliant. A
heartbeat without exact runtime evidence never contributes to the compliant
count.

## Operator journey

1. Open **Deployments** and select **Runtime releases**.
2. Confirm that the release-authority banner is configured and inspect the
   approved Claude Code and Codex targets.
3. Expand integrity evidence when validating the manifest and independently
   verified release-evidence digests.
4. Review deployment-level compliance, then work the agent remediation queue
   for missing, expired, mismatched, quarantined or unapproved targets.
5. Return to **Deployments** and use the existing measured configuration
   rollout only after runtime-release and managed-configuration evidence are
   both ready.

The UI explicitly states that it cannot approve a release. Approval remains a
reviewed deployment workflow so a compromised browser cannot manufacture
trusted SDK, gateway or hook bytes.

## Guarantees and non-guarantees

This control guarantees that the displayed approved catalog is derived from
the exact deployment bundle and that displayed compliance is derived from one
bounded page of tenant-scoped server state at one recorded server time. The UI
labels every page-scoped response and does not elevate even a final continuation
page to fleet-wide health. A fleet-scoped compliant result
also matches the current approved SDK revision and canonical complete-manifest
digest, which binds the package, gateway and hook identities. It makes missing
release authority and stale evidence visible instead of treating them as
healthy.

It does not distribute files, update an endpoint, prove hardware identity,
prove MDM enforcement or approve a release. The separate measured rollout
authority chooses a deterministic canary, freezes membership on pause or
rollback, and safely admits the exact bound old and new releases; it still
depends on an endpoint channel to deliver bytes.
Software attestation retains the
root-administrator limitation documented in the
[runtime attestation design](runtime-attestation-design.md).

## Verification

Automated contracts prove:

- exact catalog projection for both supported hosts;
- omission of source origin, executable bytes and credential-shaped fields;
- rejection of unbound, partial and mismatched approval evidence;
- tenant isolation, tenant-bound cursor rejection and exclusion of inactive lifecycle records;
- each compliance status, including empty-catalog and quarantine precedence;
- policy-only human denial and exact machine `inventory_read` allow-listing;
- bounded continuation across multiple compliance pages;
- honest empty-catalog and attention UI states;
- question-mark help for release metrics and bundle identities; and
- responsive production build and the complete UI test suite.

Live acceptance still requires publishing the next release evidence, deploying
the non-empty bundle, enrolling real Claude Code and Codex pilots and retaining
their fresh attestation results.

# Discovery source management acceptance — 2026-07-30

## Scope

This evidence covers the operator-safe discovery source directory, source-
scoped connector credential lifecycle, atomic connector publication, and the
management UI added for P0-04. It is bounded synthetic evidence, not proof of
95% coverage of a real enterprise population.

## Quality gates

The SDK quality gate completed with:

- 741 passing Python tests and one intentionally skipped external PostgreSQL
  integration test;
- 90.17% statement/branch-aware coverage against the configured 90% gate;
- strict Ruff formatting/lint and mypy checks;
- strict MkDocs build and generated README verification;
- wheel/sdist build and metadata validation;
- dependency audits with no known vulnerabilities; and
- bounded mutation-baseline verification.

The separate management UI completed `npm run check` with 109 passing tests,
TypeScript compilation, and a production Vite build. Browser acceptance covered
the source table, registration modal, one-time credential panel, and a 390 ×
844 responsive viewport. The responsive page had no body-level horizontal
overflow; source records became labelled cards so credential and evidence
state remained visible.

## Deployed evidence

The `AaiSecControlPlane` stack was updated successfully in AWS account
`396510133537`, region `eu-west-2`, using profile `p1`. The built UI was synced
to the private UI bucket and CloudFront invalidation
`I2QA4B57BSFNO5UMZIGCQCEXU2` completed. CloudFront returned HTTP 200 and the
deployed index referenced these exact build assets:

- `assets/index--BPBOdV9.js`
- `assets/index-BOhalXpq.css`

## Live connector lifecycle

The acceptance tenant was `tenant-live-discovery-e867740860`. Operator routes
were invoked against the deployed Lambda with bounded synthetic platform-admin
claims. The connector routes were called through the public API Gateway origin,
including TLS verification with an explicit CA bundle.

| Assertion | Result |
| --- | --- |
| Create source-scoped credential | HTTP 201; revision 1; plaintext returned once |
| Read source directory before first run | HTTP 200; credential `active`; snapshot `null` |
| Directory content minimisation | Plaintext token, token digest, observations, and provider payload excluded |
| Read without an operator role | HTTP 403 |
| Declare generation through API Gateway | HTTP 201 |
| Upload immutable page through API Gateway | HTTP 201 |
| Atomically commit generation | HTTP 200; source revision 1 |
| Read directory after commit | Snapshot `current`; observation count 1; observation content excluded |
| Revoke connector credential | Directory state `revoked`; credential revision 2 |
| Reuse revoked credential | HTTP 403 |

Five tenant-scoped DynamoDB records created by the acceptance were deleted by
exact partition key. Three synthetic audit objects were intentionally retained
because the audit bucket uses immutable retention. Earlier connectivity
preflights also produced content-minimised `tenant-live-discovery-*` credential
audit objects; immutable evidence was not bypassed or deleted for test cleanup.

## Trust boundaries proved

- Registration does not create a current snapshot or coverage assurance.
- Connector credentials cannot use operator identity and policy routes.
- Tenant operators can inspect redacted source health, while mutation remains
  platform-administrator-only.
- A partial generation remains invisible until a hash-bound atomic commit.
- Revocation is checked live on the next connector request.
- The UI keeps the plaintext credential only in transient component state and
  removes it from the rendered page after acknowledgement.

## Remaining P0-04 work

This tranche does not close P0-04. Production acceptance still requires
secret-manager delivery and scheduling for real Entra, endpoint, and GitHub
collectors; dedicated object storage for estates beyond the bounded page model;
and measured proof that discovery represents at least 95% of the agreed pilot
population.

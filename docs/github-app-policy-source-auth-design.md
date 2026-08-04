# GitHub App authentication for reviewed policy sources

## Decision

Production policy imports use an installation-scoped GitHub App credential.
A dedicated token-broker Lambda owns the App private key, creates a short-lived
RS256 App JWT and exchanges it for a one-hour installation token on demand. The
policy-source verifier may invoke only that broker. The control-plane handler
may invoke only the verifier and receives neither credential.

Schema-v2 deployment authority contains the App client ID, installation ID,
private-key secret reference, exact repository allow-list and retained security
review reference. It contains no secret bytes. Schema v1 remains accepted only
as a migration path for controlled pilots using an externally rotated token.

## Trust boundaries

The browser supplies only an exact repository, full commit SHA and relative
path. It cannot select an App, installation, secret, token, permission or
repository outside the deployment allow-list.

The token broker:

- reads one exact Secrets Manager secret containing only `privateKeyPem`;
- accepts only the fixed internal request `{ "schemaVersion": 1 }`;
- signs a JWT with `RS256`, a 60-second clock-skew allowance and a lifetime
  below GitHub's ten-minute maximum;
- posts only to the fixed `api.github.com` installation-token path, without
  redirects, and requests only read-only Contents, Metadata and Pull requests;
- validates a bounded response and returns only the installation token and
  provider expiry to the verifier; and
- has no DynamoDB, KMS signing or control-plane mutation permission.

The verifier validates that the broker response is exact and unexpired before
using the token in memory. It does not persist or return the token. GitHub
provider evidence, policy content and the inactive draft follow the existing
reviewed GitOps transaction.

## Failure posture

Missing or malformed deployment authority, non-RSA or weak private keys,
broker invocation errors, GitHub redirects, non-201 responses, excessive
response sizes, broadened permissions, malformed tokens and expired or
implausibly long expiry all fail closed before policy content is retrieved or
any draft is written. Error responses contain no private key, JWT or token.

## Deployment and migration

New production manifests use schema version 2. Existing schema-v1 manifests
continue to synthesize the pilot token path so migration is explicit and
reversible. The deployment preflight reads the private key only into memory,
validates its exact JSON shape and RSA strength, and never prints it. Routine
deployments continue to discard ambient policy-source variables and load only
the encrypted persisted manifest.

## Required evidence

Unit and adversarial tests cover JWT claims and signatures, key shape and
strength, exact installation path and permissions, timeout/redirect/size/error
handling, broker response expiry, schema migration and IAM privilege
separation. Live acceptance still requires an organization-owned GitHub App,
selected-repository installation, successful reviewed import and retained
denial evidence for wrong installation, repository, permission and key.

The protocol follows GitHub's current primary contracts for
[generating an App JWT](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
and
[creating an installation access token](https://docs.github.com/en/enterprise-cloud@latest/rest/apps/apps#create-an-installation-access-token-for-an-app).

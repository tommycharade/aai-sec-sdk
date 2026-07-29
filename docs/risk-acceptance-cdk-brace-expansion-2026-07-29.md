# Temporary risk acceptance: AWS CDK bundled brace-expansion

| Field | Decision |
| --- | --- |
| Status | Accepted temporarily; upstream remediation pending |
| Owner | Tom Mooney, project owner |
| Accepted | 2026-07-29 |
| Expires | 2026-08-28 |
| Advisory | `GHSA-mh99-v99m-4gvg` / `CVE-2026-14257` |
| Affected component | `aws-cdk-lib@2.262.2` development dependency |
| Vulnerable bundled package | `brace-expansion@5.0.7` |
| Patched package | `brace-expansion@5.0.8` |
| Upstream fix | `aws/aws-cdk#38410`, merged but not yet published in an `aws-cdk-lib` bundle |

## Decision

The project temporarily accepts this development-tooling availability risk
until 2026-08-28. It does not accept the dependency as a production runtime
component and does not suppress other high-severity findings. The exception
must be removed sooner if AWS publishes a bundle containing
`brace-expansion>=5.0.8`.

`npm audit fix` and package-manager overrides cannot repair this finding
because AWS CDK embeds the affected package as a bundled dependency. Editing
`node_modules`, relabelling version metadata, or maintaining an unreviewed fork
would create a less trustworthy supply-chain state and is prohibited.

## Exposure assessment

- AWS CDK is used only to compile, synthesize, diff and deploy infrastructure.
- `aws-cdk-lib`, `aws-cdk` and `constructs` are exact-pinned development
  dependencies in the private infrastructure package.
- The packages are not included in the Python SDK wheel, source distribution,
  browser UI, or deployed Python Lambda source bundle.
- CDK synthesis consumes reviewed repository configuration. The hosted UI,
  control-plane API, agents and models cannot submit brace or glob patterns to
  the CDK process.
- The advisory is an availability failure caused by attacker-influenced brace
  expansion. No such untrusted input path exists in the deployment workflow.
- `npm audit --omit=dev` reports zero production dependency vulnerabilities.
  A full audit continues to report the accepted development finding, preserving
  visibility.

This lowers exploitability for this deployment but does not make the affected
package safe in a different context. CDK commands must not be exposed as a
service or run against untrusted repositories or user-supplied patterns.

## Compensating controls

1. CDK dependencies are exact-pinned and lockfile-resolved.
2. Synthesis and deployment run from reviewed source with bounded CI job time
   and memory supplied by the runner.
3. CloudFormation diff is reviewed before deployment.
4. Production artifacts are built and audited independently of the CDK
   development package.
5. GitHub automatically marks Dependabot alert 1 as `auto_dismissed` because
   the affected transitive package is development-scoped. The API does not
   attach a manual dismissal rationale to that state, so this record and
   tracking issue 34 provide the accountable decision trail. Other findings
   remain blocking unless separately accepted.
6. `.github/workflows/cdk-upstream-watch.yml` inspects the latest published CDK
   bundle every day. It deliberately fails when the patched bundle becomes
   available, making removal of the exception an operator action.
7. Dependabot monitors the infrastructure npm package daily for direct updates.
8. Repository tests fail after the expiry date unless this record and the
   dependency state are reviewed.

## Closure criteria

Close the exception only after all of the following are true:

1. a published `aws-cdk-lib` contains `brace-expansion>=5.0.8`;
2. the exact CDK pin and lockfile are upgraded;
3. full `npm audit` reports no finding for this advisory;
4. TypeScript build, CDK synthesis and CloudFormation diff succeed;
5. SDK `make check` succeeds; and
6. Dependabot alert 1 is marked fixed by dependency-graph evidence, tracking
   issue 34 is closed with the upgrade commit, and this exception is retired.

If no fixed AWS package is available by 2026-08-28, the owner must explicitly
renew the exception with new evidence or replace the CDK packaging strategy.
CI is intended to fail rather than silently extending the acceptance.

## References

- [GitHub security advisory](https://github.com/advisories/GHSA-mh99-v99m-4gvg)
- [Repository tracking issue 34](https://github.com/tommycharade/aai-sec-sdk/issues/34)
- [AWS CDK upstream issue 38409](https://github.com/aws/aws-cdk/issues/38409)
- [Merged AWS CDK fix 38410](https://github.com/aws/aws-cdk/pull/38410)

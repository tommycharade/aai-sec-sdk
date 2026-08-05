# Releasing

## Stable-release checklist

The `1.x` compatibility policy follows Semantic Versioning: public API
breaking changes require a major version, and every breaking change must be
called out in `CHANGELOG.md` with a migration note. Python 3.11, 3.12, and
3.13 are the supported CI versions. Security fixes are backported only to the
latest supported release line.

- [ ] `make check` passes on the release commit.
- [ ] `make mutation` passes within its declared bound and its raw evidence
      proves >=80% overall, >=75% per component, 100% critical mutants, and
      zero timeout/suspicious/skipped/not-checked results; retain the artifact.
- [ ] `make package-check` builds and validates wheel and source distributions.
- [ ] `make security-check` reports no unaccepted dependency vulnerabilities;
      any build-only exception has a named owner, compensating controls,
      automated upstream monitoring and an unexpired review date.
- [ ] `python scripts/verify_vulnerability_management.py` proves the public
      support/SLA policy is in review and the checked synthetic rehearsal meets
      every deadline; retain separate live exercise evidence before claiming
      operational performance.
- [ ] `requirements-ci.txt` and `requirements-docs.txt` are reviewed when
      direct toolchain versions change; direct inputs are exact-pinned.
- [ ] `requirements-build.txt` matches the exact PEP 517 build requirements.
- [ ] `LICENSE` and `NOTICE` are present in both distributions.
- [ ] `CHANGELOG.md` describes user-visible and security-relevant changes.
- [ ] Public API and migration notes are up to date.
- [ ] Security regressions and known limitations are documented.
- [ ] `make assurance-check` confirms the buyer assurance pack has current
      technical approval, a non-expired review date, bounded vulnerability
      targets and evidence-backed independent-assurance labels.
- [ ] `customer-assurance-pack.zip` is built deterministically, internally
      hash-verified, covered by `SHA256SUMS` and attached to the GitHub release.
- [ ] Every critical/high vulnerability since the prior release has retained
      acknowledgement, assessment, notification and remediation/exception
      evidence against the published targets.
- [ ] The release is tagged from a clean, reviewed commit.
- [ ] The package is published through trusted CI credentials, not a developer workstation token.
- [ ] Release artifacts and checksums are retained.
- [ ] An independently verified SBOM is generated and hash-bound for each
      artifact; dependency provenance is attached by trusted CI.
- [ ] GitHub Actions provenance attestation is present for release artifacts.
- [ ] Wheel installation is tested in clean Python 3.11, 3.12, and 3.13
      environments.
- [ ] The compatibility policy and migration notes are published.
- [ ] At least two maintainers/code owners review security-sensitive changes.

Do not describe a release as a security certification. The SDK provides implementation controls; adopters remain responsible for configuring policy, identity, infrastructure, and domain authorization.

## Supply-chain boundaries

The repository exact-pins direct development, documentation, and PEP 517 build
inputs and audits all three input files with `pip-audit`. Release CI builds the
wheel and source archive, then installs each actual artifact into a fresh
virtual environment before generating one CycloneDX SBOM per artifact. It also
writes SHA-256 checksums and requests GitHub provenance attestations for the
same artifact subjects. Exact hashes for every platform wheel are not
committed because the supported Python matrix selects different transitive
wheels; artifact SBOMs, checksums, and provenance are the release evidence.
PyPI publication, if enabled, must use repository trusted publishing and never
a developer workstation token.

Infrastructure tooling is a separate build-time boundary. AWS CDK, its
construct library and `constructs` are exact-pinned development dependencies
and are excluded from deployed SDK, UI and Lambda artifacts. A scanner finding
in bundled CDK tooling may be accepted only through a dated, owner-approved
risk record that documents exploitability, preserves full-audit visibility,
monitors upstream daily and causes CI to fail when the exception expires. The
[historical AWS CDK record](risk-acceptance-cdk-brace-expansion-2026-07-29.md)
covers only `GHSA-mh99-v99m-4gvg`; it does not authorize later findings
against the same bundled package. The current owner decision is tracked in
[Inputs needed from the product owner](needed-from-from.md).

The build job adds the raw mutation evidence to `dist/` before creating
checksums with `scripts/write_checksums.py`, excluding only the checksum file
itself. A separate publish job creates the GitHub Release from that exact
bundle, and a clean verification job downloads the published assets rather
than trusting the pre-publication workspace.

`verify_release_evidence.py` is run in a separate clean-verification job. It
independently checks that every wheel and source
archive has a matching SHA-256 entry, a matching SBOM manifest entry, and an
SBOM containing the artifact filename and digest. It also checks the mutation
evidence files, clean checkout commit, and exact tag against
`RELEASE-METADATA.json`. The workflow then runs `gh attestation verify` for
every subject in that same clean job, constraining the signer workflow and full
`refs/tags/...` source ref. Release CI runs only for pushed version tags; it
does not permit an independently selected source ref and release tag. These checks verify artifact
identity and provenance bindings; they do not certify the package's runtime
behavior or external provider deployments.

### Standalone adopter verification

Adopters can verify downloaded release evidence without trusting the build
workspace:

```bash
git clone https://github.com/tommycharade/aai-sec-sdk.git
cd aai-sec-sdk
git checkout --detach vX.Y.Z
# Copy the published release-evidence bundle into ./dist first.
python scripts/verify_release_evidence.py dist \
  --commit "$(git rev-parse HEAD)" --tag "vX.Y.Z"
gh attestation verify dist/*.whl --repo tommycharade/aai-sec-sdk \
  --signer-workflow tommycharade/aai-sec-sdk/.github/workflows/release-artifacts.yml \
  --source-ref refs/tags/vX.Y.Z
```

Do not use `--allow-untagged` for a published release; that option is only for
local pre-tag verification.

`make check` validates the mutation contract; `make mutation` executes the
mutmut run through `scripts/run_mutation_check.py`, enforces the declared 80%
killed-mutant threshold, and fails on stale/missing/truncated/timeout,
unparseable, or other-commit evidence. The run is bounded to two workers and
600 seconds (10 minutes). No mutation score is claimed unless that command has completed
successfully for the commit.

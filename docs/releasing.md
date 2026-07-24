# Releasing

## Pre-release checklist

The compatibility policy for the current `0.x` series is intentionally
conservative: minor releases may change public APIs, but every breaking change
must be called out in `CHANGELOG.md` with a migration note. Python 3.11, 3.12,
and 3.13 are the supported CI versions. Security fixes are backported only to
the latest supported release line until a stable support policy is published.

- [ ] `make check` passes on the release commit.
- [ ] `make package-check` builds and validates wheel and source distributions.
- [ ] `make security-check` reports no known dependency vulnerabilities.
- [ ] `requirements-ci.txt` and `requirements-docs.txt` are reviewed when
      direct toolchain versions change; direct inputs are exact-pinned.
- [ ] `LICENSE` and `NOTICE` are present in both distributions.
- [ ] `CHANGELOG.md` describes user-visible and security-relevant changes.
- [ ] Public API and migration notes are up to date.
- [ ] Security regressions and known limitations are documented.
- [ ] The release is tagged from a clean, reviewed commit.
- [ ] The package is published through trusted CI credentials, not a developer workstation token.
- [ ] Release artifacts and checksums are retained.
- [ ] An SBOM is generated for each artifact and dependency provenance is
      attached by trusted CI.
- [ ] GitHub Actions provenance attestation is present for release artifacts.
- [ ] Wheel installation is tested in clean Python 3.11, 3.12, and 3.13
      environments.
- [ ] The compatibility policy and migration notes are published.
- [ ] At least two maintainers/code owners review security-sensitive changes.

Do not describe a release as a security certification. The SDK provides implementation controls; adopters remain responsible for configuring policy, identity, infrastructure, and domain authorization.

## Supply-chain boundaries

The repository pins direct development and documentation inputs, audits both
constraint files with `pip-audit`, builds from a clean tag, generates a
CycloneDX SBOM, writes SHA-256 checksums, and requests GitHub artifact
provenance through the release workflow. Exact hashes for every platform wheel
are intentionally not committed because the supported Python matrix selects
different transitive wheels; releases retain the generated SBOM and
provenance instead. PyPI publication, if enabled, must use repository trusted
publishing and never a developer workstation token.

The local `make mutation` command is separate from `make check`: it is bounded
by the checked-in baseline, but mutation tooling is not a runtime dependency.

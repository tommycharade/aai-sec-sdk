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
- [ ] `requirements-build.txt` matches the exact PEP 517 build requirements.
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

`make check` validates the mutation contract; `make mutation` executes the
mutmut run through `scripts/run_mutation_check.py`, enforces the declared 80%
killed-mutant threshold, and fails on timeout or an unparseable result. The
run is bounded to two workers and 120 seconds. No mutation score is claimed
unless that command has completed successfully for the commit.

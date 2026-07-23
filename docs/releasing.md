# Releasing

## Pre-release checklist

- [ ] `make check` passes on the release commit.
- [ ] `make package-check` builds and validates wheel and source distributions.
- [ ] `make security-check` reports no known dependency vulnerabilities.
- [ ] `LICENSE` and `NOTICE` are present in both distributions.
- [ ] `CHANGELOG.md` describes user-visible and security-relevant changes.
- [ ] Public API and migration notes are up to date.
- [ ] Security regressions and known limitations are documented.
- [ ] The release is tagged from a clean, reviewed commit.
- [ ] The package is published through trusted CI credentials, not a developer workstation token.
- [ ] Release artifacts and checksums are retained.

Do not describe a release as a security certification. The SDK provides implementation controls; adopters remain responsible for configuring policy, identity, infrastructure, and domain authorization.

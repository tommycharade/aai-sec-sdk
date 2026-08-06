# macOS endpoint sensor package acceptance — 2026-08-06

## Result

The digest-bound macOS endpoint sensor package passed its deterministic unit
and adversarial contracts and a disposable real-tool assembly check on macOS
26.5.2 (build 25F84).

This evidence proves package construction and payload confinement. It does not
prove Apple Developer ID signing, notarization, MDM deployment, installation on
a managed pilot device, sensor execution, network delivery, fleet coverage or
hardware-backed identity.

## Commands and evidence

The focused static and adversarial gate was:

```bash
python3 -m ruff check \
  scripts/collect_endpoint_evidence.py \
  scripts/build_macos_endpoint_sensor_package.py \
  scripts/test_macos_endpoint_sensor_package.py \
  tests/test_endpoint_evidence_publisher.py \
  tests/test_macos_endpoint_sensor_package.py
python3 -m mypy \
  scripts/collect_endpoint_evidence.py \
  scripts/build_macos_endpoint_sensor_package.py \
  scripts/test_macos_endpoint_sensor_package.py
python3 -m pytest -q \
  tests/test_endpoint_evidence_publisher.py \
  tests/test_macos_endpoint_sensor_package.py
```

Result: Ruff and mypy passed; all 30 focused tests passed.

The real macOS package check was:

```bash
python3 scripts/test_macos_endpoint_sensor_package.py
```

Result: the fixed `/usr/bin/pkgbuild` assembled a disposable unsigned test
package; `/usr/sbin/pkgutil --payload-files` confirmed the fixed executable,
metadata and launch-daemon payload and found no key-ID or secret path. The
output was a protected regular file, and its temporary directory and package
were deleted before the command returned.

## Adversarial coverage

The retained tests deny:

- altered executable bytes or a wrong out-of-band SHA-256;
- a symlinked executable through both the typed API and operator CLI;
- non-macOS builds, malformed versions and out-of-range intervals;
- implicit unsigned builds, malformed signing identities and failed signature
  verification;
- existing, symlinked or broadly writable package output;
- missing or failing fixed packaging tools;
- inherited secrets or shell execution at the packaging-tool boundary;
- group/world-accessible, linked, wrong-owner or malformed credential files;
  and
- non-administrator, linked or unsafe report output.

## Remaining live acceptance

P0-04 remains **Partial**. Completion needs an independently built production
sensor executable, reviewed Apple installer signing identity, customer MDM
delivery of the signed package and protected per-device files, a bounded
managed macOS cohort, fresh signed hosted reports from at least 95% of the
agreed pilot and explicit review of every missing endpoint.

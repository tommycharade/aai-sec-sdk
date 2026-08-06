# macOS endpoint sensor artifact

## Purpose and status

The endpoint evidence collector is Python source. Enterprise MDM deployment
needs a fixed executable that does not depend on a repository checkout, ambient
Python installation or mutable site packages. The macOS artifact builder freezes
that source with exact PyInstaller and psutil inputs, measures the resulting
Mach-O executable and emits a closed manifest for independent verification.

This closes the software build boundary, not the production release boundary.
The repository can produce and test ad-hoc Apple Silicon and Intel artifacts.
A production artifact still requires a customer- or publisher-controlled
Developer ID Application identity. P0-04 remains **Partial** until that signed
artifact is independently verified, packaged with a Developer ID Installer
identity, deployed through a real MDM and produces current pilot evidence.

## Artifact generation

One generation is a new mode-`0700` directory containing exactly:

| File | Mode | Purpose |
| --- | --- | --- |
| `aai-endpoint-evidence` | `0700` | One architecture-specific frozen sensor |
| `artifact-manifest.json` | `0600` | Closed release, toolchain, executable and signing identities |

The manifest contains no path, credential, tenant, device, project, signing
certificate text or customer data. It binds:

- semantic sensor version;
- exact 40-character source commit;
- independently supplied collector-source SHA-256;
- `arm64` or `x86_64` Mach-O architecture;
- Python, PyInstaller and psutil versions;
- executable size and SHA-256;
- signing mode;
- SHA-256 of the measured Developer ID leaf authority, when present; and
- whether the test-only library-validation entitlement is present.

The directory is committed by one atomic rename. A consumer sees either no
generation or both complete files. Existing output, links, unknown files,
wrong-owner files, broad write permissions, changed inodes and malformed
manifests fail closed.

## Build trust boundary

`scripts/build_macos_endpoint_sensor_artifact.py build` requires:

- an absolute owner-controlled collector source file;
- its exact SHA-256 delivered through an independent review channel;
- the reviewed source commit and product version;
- an explicit reviewed Python patch version matching the build interpreter;
- one explicit architecture;
- the exact dependencies in `requirements-sensor-build.txt`; and
- either a Developer ID Application selector or explicit ad-hoc test mode.

The builder runs the current absolute Python interpreter with `-I` and a fixed
PyInstaller argument array. It uses a closed environment, fixed build paths,
bounded output and timeouts, no shell and no network client. PyInstaller is
configured as one-file, console-only, no UPX, one architecture and an explicit
code-signing posture. The resulting binary must pass fixed `lipo`, `codesign`
and frozen-command smoke checks before the atomic generation is committed.

PyInstaller documents that macOS artifacts must be built on macOS, supports
`arm64` and `x86_64` targets, and signs generated binaries. See the official
[PyInstaller macOS options](https://pyinstaller.org/en/stable/usage.html#macos-specific-options).

## Production Developer ID build

Import the reviewed Developer ID Application certificate into a dedicated
ephemeral build keychain. Obtain the expected source digest and leaf authority
digest through a separate release-approval channel. Then run:

```bash
python scripts/build_macos_endpoint_sensor_artifact.py build \
  --source /protected/source/collect_endpoint_evidence.py \
  --expected-source-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --expected-python-version 3.13.14 \
  --version 1.1.0 \
  --source-commit 0123456789abcdef0123456789abcdef01234567 \
  --architecture arm64 \
  --codesign-identity 'Developer ID Application: Example Enterprise (AAAAAAAAAA)' \
  --output-directory /protected/release/aai-endpoint-evidence-arm64
```

The builder prints only hashes, version, commit, architecture and signing mode.
It does not read a certificate file, password, Apple account credential or
notarization token. Keychain setup, certificate lifecycle and notarization are
deployment-owned release operations.

Independently transfer the manifest SHA-256 and measured leaf-authority SHA-256
to the verifier, then run from a separate operator context:

```bash
python scripts/build_macos_endpoint_sensor_artifact.py verify \
  --artifact-directory /protected/release/aai-endpoint-evidence-arm64 \
  --expected-manifest-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --expected-version 1.1.0 \
  --expected-source-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-source-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --expected-python-version 3.13.14 \
  --expected-architecture arm64 \
  --expected-signing-identity-sha256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

Production verification denies an ad-hoc signature, an absent independent leaf
identity, extra entitlements, architecture drift, altered bytes and an
incomplete command interface.

## Ad-hoc acceptance boundary

Python.org's framework and an ad-hoc PyInstaller outer executable have
different signing teams. On current macOS, hardened library validation correctly
prevents the outer process from loading that embedded framework. Disposable
ad-hoc acceptance therefore uses the fixed entitlement:

```text
com.apple.security.cs.disable-library-validation = true
```

That weakening is explicit, measured in the manifest and accepted only with
`--allow-adhoc`. A Developer ID build must not contain it. The independent
verifier rejects any other entitlement and rejects the ad-hoc posture by
default. An ad-hoc artifact must never be enrolled, uploaded to MDM, described
as production-signed or used as release provenance.

Run local disposable acceptance after installing the exact build inputs:

```bash
python -m pip install -r requirements-sensor-build.txt
python scripts/test_macos_endpoint_sensor_artifact.py \
  --source-commit "$(git rev-parse HEAD)" \
  --version 1.1.0
```

The acceptance command deletes its frozen artifact before returning. The
dedicated GitHub workflow pins the reviewed Python 3.13.14 patch release and
repeats the check on the official `macos-15` arm64
and `macos-15-intel` runners. It uploads clearly named `adhoc-test` archives for
seven days only. It has no tag trigger, provenance attestation or GitHub Release
authority. GitHub's current official runner labels and architectures are listed
in the [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## One-file extraction boundary

The PyInstaller bootloader extracts bundled libraries before collector Python
code starts. The collector cannot make that directory safe after the fact.
Every execution authority must therefore supply a pre-created, root-owned,
mode-`0700` `TMPDIR`.

The MDM package's launch daemon sets:

```text
TMPDIR=/var/db/aai-security/endpoint-evidence/runtime
```

The fixed post-install script creates that directory as root before launchd is
loaded. The verifier and disposable acceptance each use a fresh mode-`0700`
temporary directory. Running the one-file sensor as root from an unmanaged
shell without a protected `TMPDIR` is unsupported.

## Package handoff

After independent production verification, pass the exact executable path and
its printed executable SHA-256 to the
[macOS endpoint sensor package builder](macos-endpoint-sensor-package.md). Keep
the artifact manifest, manifest digest, source approval, leaf-authority digest,
package digest and installer-signing evidence in the release record. The common
package remains secret-free; per-device manifest and HMAC credentials are still
delivered separately through MDM.

The current package API accepts the executable and digest because some
enterprises use an external artifact-verification service. Verification and
packaging must occur in one protected release workspace without changing the
executable between those commands. Directly hashing unreviewed source output is
not equivalent to the independent artifact workflow.

## Guarantees and non-guarantees

When its preconditions hold, the implementation guarantees:

- exact source bytes and release identity are bound before freezing;
- exact direct build inputs and architecture are recorded;
- generated bytes, signature posture and command interface are measured;
- the verifier defaults to Developer ID and independent leaf-authority binding;
- unknown files, fields, entitlements and unsafe filesystem state are denied;
- no build-time secret or inherited environment is written to the manifest;
  and
- test-only weakening is explicit and cannot satisfy production verification.

It does not guarantee:

- bit-for-bit reproducibility across macOS/Python toolchain images;
- Apple certificate ownership, revocation status, notarization or Gatekeeper
  acceptance merely from a leaf authority string;
- MDM installation, launchd execution, report delivery or 95% fleet coverage;
- protection from a compromised build runner, Apple identity or endpoint root;
- hardware-backed device identity; or
- Windows support.

Production provenance should bind the final Developer ID artifact and package
as release subjects after signing credentials and a tagged release workflow are
approved. The repository deliberately does not attest or publish disposable
ad-hoc CI artifacts.

## Verification coverage

`tests/test_macos_endpoint_sensor_artifact.py` covers closed generations,
source and executable tampering, symlinks, weak permissions, malformed release
identities, exact dependency versions, wrong architectures, tool failures,
unknown files, incomplete CLI behavior, test entitlements, Developer ID leaf
identity binding and non-release CI semantics.

`scripts/test_macos_endpoint_sensor_artifact.py` uses the real pinned
PyInstaller, `lipo`, `codesign` and frozen executable on macOS. The separate
arm64/Intel workflow is needed before claiming cross-architecture build
compatibility. Developer ID and MDM evidence remain separate live acceptance.

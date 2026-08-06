# macOS endpoint sensor artifact acceptance — 2026-08-06

## Result

The standalone endpoint evidence sensor passed its focused adversarial suite
and a disposable real PyInstaller build on Apple Silicon macOS 26.5.2 (build
25F84).

This proves the checked-in build and verifier on one arm64 host. It does not
prove Intel compatibility, Developer ID signing, notarization, release
provenance, MDM installation, sensor collection as root, report delivery or
fleet coverage. The pull-request workflow must supply separate Intel evidence.

## Focused software evidence

The focused command was:

```bash
python -m ruff check \
  scripts/build_macos_endpoint_sensor_artifact.py \
  scripts/test_macos_endpoint_sensor_artifact.py \
  tests/test_macos_endpoint_sensor_artifact.py
python -m mypy \
  scripts/build_macos_endpoint_sensor_artifact.py \
  scripts/test_macos_endpoint_sensor_artifact.py
python -m pytest -q \
  tests/test_macos_endpoint_sensor_artifact.py \
  tests/test_macos_endpoint_sensor_package.py
```

Result: Ruff and mypy passed; all 29 focused artifact/package tests passed.

The tests include source, manifest and executable alteration; symlinked CLI
input; wrong architecture; weak output; unknown files; malformed identities;
dependency drift; tool failure; incomplete frozen CLI; explicit ad-hoc
entitlement posture; and independently bound Developer ID leaf identity.

## Real arm64 evidence

The exact build dependencies were installed into a temporary virtual
environment from `requirements-sensor-build.txt`, then this command ran:

```bash
python scripts/test_macos_endpoint_sensor_artifact.py \
  --source-commit 7ef1be0ad9140100cf48015982dd2c69ce7323c1 \
  --version 1.1.0
```

Result: the local Python 3.13.0 interpreter, real PyInstaller 6.21.0 build and
psutil 7.2.2 emitted one
arm64 Mach-O executable, passed strict ad-hoc code-signature verification, ran
the frozen parser from a protected extraction directory and matched the
independent closed-manifest verifier. The temporary environment and artifact
were moved to Trash after acceptance.

During acceptance, macOS correctly denied an initial ad-hoc artifact that tried
to load the differently signed Python.org framework under hardened library
validation. The implementation was corrected to add
`disable-library-validation` only to explicit ad-hoc test artifacts, record it
in the manifest and reject it for Developer ID posture. The corrected real
artifact executed and verified successfully.

Python 3.13.0 is superseded and is not the proposed production build runtime.
The cross-architecture workflow pins Python 3.13.14; its separate CI result is
required before promotion.

## Remaining production evidence

Before using the artifact in MDM:

1. obtain and protect a Developer ID Application identity;
2. build each required architecture from the reviewed release commit;
3. independently verify source, manifest and leaf-authority digests;
4. complete notarization and Gatekeeper acceptance under the approved release
   process;
5. feed the exact verified executable digest into the signed package builder;
6. deploy to a bounded customer pilot; and
7. retain fresh signed report and coverage evidence.

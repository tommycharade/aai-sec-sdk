# macOS endpoint sensor MDM package

## Purpose and status

The macOS package turns the endpoint evidence sensor into a repeatable,
administrator-owned launchd deployment artifact. It removes the need for an
interactive shell, environment-held device secret, stdout redirection or a
repository-owned scheduler on each managed Mac.

This is a production-shaped packaging boundary, not evidence that a customer
MDM installed it. P0-04 remains **Partial** until a real Intune, Jamf or
equivalent deployment produces fresh reports for at least 95% of the agreed
pilot population and every blind spot is reviewed. The package provides
software evidence, not hardware-backed device identity or proof against a
compromised root administrator.

## Package boundary

`scripts/build_macos_endpoint_sensor_package.py` accepts a prebuilt endpoint
sensor executable and its independently delivered SHA-256. It builds a macOS
installer with the fixed identifier
`com.aai-security.endpoint-evidence`. A normal operator build requires a
Developer ID Installer signing identity; unsigned output requires the explicit
`--allow-unsigned` test-only flag.

The builder invokes the fixed macOS `/usr/bin/pkgbuild`,
`/usr/bin/productsign` and `/usr/sbin/pkgutil` executables as argument arrays.
It never invokes a shell, passes a closed non-secret environment and bounds each
tool call to 120 seconds. Tool output is not copied into product errors because
it can contain developer paths or signing details.

The package contains only:

| Installed artifact | Mode after installation | Purpose |
| --- | --- | --- |
| `/Library/Application Support/AAI Security/bin/aai-endpoint-evidence` | `0755`, root-owned | Exact digest-bound standalone sensor executable |
| `/Library/Application Support/AAI Security/package-metadata.json` | `0644`, root-owned | Package version, sensor SHA-256, launchd label and interval |
| `/Library/LaunchDaemons/com.aai-security.endpoint-evidence.plist` | `0644`, root-owned | Fixed, shell-free five-minute collection job |

The package never contains a manifest, key ID, signing secret, control-plane
bearer, tenant, device identity, project path, repository mapping or customer
endpoint. `package-metadata.json` explicitly records
`"credentialsIncluded": false`.

## Per-device authority

The MDM must deliver these three files separately after issuing one endpoint
sensor credential for the exact device:

| File | Required protection | Content |
| --- | --- | --- |
| `/Library/Application Support/AAI Security/config/endpoint-evidence-manifest.json` | Root-owned regular file; no group/world write | Closed schema-1 expected device/installations manifest |
| `/Library/Application Support/AAI Security/config/endpoint-evidence-key-id` | Root-owned `0600`; no newline | One opaque key ID returned for that device |
| `/Library/Application Support/AAI Security/config/endpoint-evidence.key` | Root-owned `0600`; no newline | The corresponding one-time secret, at least 32 UTF-8 bytes |

The key ID and secret readers use `lstat`, `O_NOFOLLOW`, inode equality, owner
and mode checks, bounded reads and strict UTF-8. Whitespace is rejected rather
than silently trimming or changing credential bytes. A key or secret from
model output, a repository, command arguments or package metadata is outside
the supported boundary.

The manifest may contain local paths because they are endpoint-owned
measurement input. The signed report replaces project paths with SHA-256 and
excludes every path, process argument, environment value, prompt, command and
tool result.

## Scheduled collection and report output

launchd runs the fixed executable directly as `root` every 300 seconds. The
interval can be increased up to 3,600 seconds at package build time, but cannot
be reduced below the five-minute enterprise detection target. The job passes
only the fixed manifest, key-ID, secret and output file paths.

The sensor writes:

```text
/var/db/aai-security/endpoint-evidence/report.json
```

The report directory must be root-owned and not group/world writable. Existing
links, devices, non-root files or broadly writable files fail closed. The
sensor writes a mode-`0600` temporary file, flushes and fsyncs it, atomically
replaces the prior report, then fsyncs the directory. An MDM collection job
therefore observes either the previous complete report or the next complete
report, never partial JSON.

Collection errors go to the protected
`/var/log/aai-security/endpoint-evidence.log`. Failures contain fixed reason
text and never print credential bytes or the manifest's project paths.

## Build journey

The sensor executable is a release artifact, not a source checkout. Build or
retrieve the reviewed standalone executable first, verify its release
provenance, and obtain its SHA-256 through an independent channel. Then run on
macOS:

```bash
python3 scripts/build_macos_endpoint_sensor_package.py \
  --sensor-executable /protected/release/aai-endpoint-evidence \
  --expected-sensor-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --version 1.0.0 \
  --signing-identity 'Developer ID Installer: Example Enterprise (AAAAAAAAAA)' \
  --output /protected/release/aai-endpoint-evidence-1.0.0.pkg
```

The command prints only the identifier, version, sensor SHA-256, final package
SHA-256 and whether signing was used. Retain those identities with the release
approval and configure the MDM to require the exact signed package.

Unsigned mode exists only for local packaging tests:

```bash
python3 scripts/build_macos_endpoint_sensor_package.py \
  --sensor-executable /protected/test/aai-endpoint-evidence \
  --expected-sensor-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --version 1.0.0 \
  --allow-unsigned \
  --output /protected/test/aai-endpoint-evidence-test.pkg
```

Do not upload an unsigned test package to an enterprise MDM.

## MDM rollout journey

1. In **Coverage → Endpoint sensors**, select one MDM-discovered pilot device
   and issue its sensor credential. Move the one-time secret directly into the
   MDM's per-device protected secret workflow.
2. Generate the closed endpoint manifest from reviewed device, Claude Code and
   Codex inventory. Keep raw project paths only on the endpoint-management side
   of the boundary.
3. Deploy the signed package to a bounded non-production device group.
4. Deliver the manifest, key ID and secret as separate root-owned files. Never
   use one fleet-wide secret or a script argument.
5. Confirm the launchd service is loaded and that `report.json` is current,
   mode `0600` and signature-valid. MDM channel success alone is not evidence;
   inspect the resulting report and hosted sensor health.
6. Collect the report through the protected MDM channel and use the existing
   fleet assembler plus atomic discovery publisher, or send it through the
   separately authenticated hosted endpoint evidence transport.
7. Verify **Coverage → Endpoint sensors** shows a current report for the exact
   MDM device, then verify complete identity, endpoint and source-control
   generations before relying on any coverage percentage.
8. Expand only after the canary cohort remains current for the approved
   observation window. Rotate the device credential on reassignment and revoke
   it immediately on loss or offboarding.

The checked-in package deliberately does not contain a background network
publisher. This keeps provider egress, tenant origin and bearer delivery out of
the generic sensor package. A deployment may collect the mode-`0600` report
through MDM or package the existing HTTPS-only publisher as a separately
reviewed adapter.

## Update, rollback and removal

Package updates use the same identifier and a higher numeric version. The
post-install script applies fixed root ownership and modes, unloads the prior
launchd label, installs the new job and reloads it. Per-device configuration is
stored outside the package payload and survives an ordinary package update.

Rollback requires a previously approved signed package and its retained
sensor/package digests. After rollback, require a newly generated signed report
and verify the reported binary digest before restoring coverage confidence.
Removing only the package receipt is insufficient: offboarding must unload the
launchd label, remove the executable and root-owned per-device secret, revoke
the hosted credential, remove or retain reports under the records policy, and
verify that the device becomes explicitly stale or unenrolled.

## Guarantees and non-guarantees

The package guarantees, when its preconditions hold:

- exact sensor bytes are bound to an out-of-band SHA-256 and signed package;
- launchd invokes a fixed program and arguments without a shell;
- per-device credentials are absent from the package and command line;
- scheduled credential reads and report writes enforce root ownership, modes,
  regular-file identity and no-follow behavior; and
- report replacement is atomic and content-minimised.

It does not guarantee:

- that an MDM installed, retained or launched the package;
- that the prebuilt executable has approved provenance merely because its
  supplied digest matches;
- hardware-backed device identity, measured boot or protection from root;
- Windows support;
- direct network delivery, complete fleet coverage or a 95% denominator; or
- that Claude Code or Codex loaded a managed policy. Runtime attestation and
  live host acceptance remain separate controls.

## Verification

`tests/test_macos_endpoint_sensor_package.py` proves digest and owner binding,
fixed launchd arguments, credential exclusion, closed tool environment,
explicit signed/unsigned posture, signing verification, malformed version and
interval denial, symlink and tamper denial, output protection and packaging
failure behavior. `tests/test_endpoint_evidence_publisher.py` additionally
proves protected key/secret reads and atomic report replacement, including
unsafe directory, symlink and non-administrator denial.

`scripts/test_macos_endpoint_sensor_package.py` performs a local macOS package
assembly acceptance with the real `pkgbuild` executable. Its unsigned package
is disposable synthetic evidence only and is never an MDM deployment claim.

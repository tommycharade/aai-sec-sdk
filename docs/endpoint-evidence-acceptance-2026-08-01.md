# Endpoint evidence publisher acceptance — 2026-08-01

## Scope and verdict

This acceptance covers the new administrator-run endpoint sensor, per-device
signed report, authoritative MDM fleet assembly and compatibility with the
existing atomic endpoint discovery publisher. The synthetic live path passed.

It is not evidence of a customer Intune/Jamf deployment, hardware-backed device
identity, real Claude/Codex installation coverage, or the required 95% pilot
population. Those remain explicit P0-04 deployment acceptance items.

## Environment

- Source branch: `codex/endpoint-installation-publisher`
- Date: 2026-08-01
- Isolated runtime: Docker `python:3.13-slim`
- Image digest:
  `sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91`
- Sensor identity: container root; no host privilege or process table mounted
- Process adapter: `psutil>=7,<8`
- Data: generated synthetic device, user, repository, project and secret only

## Live command and result

The repository was mounted read-only. Only `certifi` and the optional endpoint
process adapter were installed into the disposable container:

```bash
docker run --rm \
  --volume "$PWD:/workspace:ro" \
  --workdir /workspace \
  python:3.13-slim \
  sh -c "python -m pip install --disable-pip-version-check \
    --root-user-action=ignore --quiet 'certifi>=2024.8.30' 'psutil>=7,<8' \
    && PYTHONPATH=/workspace:/workspace/src \
    python scripts/test_endpoint_evidence.py"
```

Observed output:

```text
Endpoint evidence acceptance passed: administrator measurement, exact binary/process/project evidence, path/secret minimisation, authoritative fleet assembly, endpoint normalization, and changed-report denial.
```

The command measured the live container Python executable and process through
the same production sensor functions. It then verified the signed report,
joined it to an independently supplied synthetic device inventory, passed the
existing endpoint normalizer, changed `processActive` without re-signing, and
proved that fleet assembly rejected the altered report.

## Automated contract evidence

Focused contracts prove:

- administrator denial and incomplete process-visibility failure;
- exact process executable and project working-directory matching;
- protected-manifest enforcement and symlink denial;
- regular executable file and configured binary digest measurement;
- symlink and changed-binary denial;
- absence of raw project paths and device secrets from signed output;
- exact report/key-map schemas and environment-only secrets;
- per-device HMAC verification and authoritative MDM metadata equality;
- stale, future, revoked, unknown, duplicate and cross-device report denial;
- rejection of signed unknown/path fields and unexpected report-directory
  entries; and
- compatibility with `collect_endpoint_export` and the atomic generation input.

The complete SDK gate passed with 797 tests, one external PostgreSQL skip,
90.20% branch coverage, strict formatting/lint/type/docs/package checks, three
dependency audits and the mutation baseline. The private UI passed 119 tests,
TypeScript checking and its production build.

## UI evidence

The endpoint setup journey is available both while registering an external
endpoint source and from the **Setup** action on an existing endpoint source.
It shows the complete Intune device export → signed per-device sensors → fleet
assembly → atomic publication sequence, exact commands, least-privilege Graph
permission, unique-key requirement, source-health dependency and software-
versus-hardware attestation limitation.

Browser verification used simulation fixtures and found:

- desktop viewport: 1280 CSS pixels; document scroll width 1280;
- narrow viewport: 390 CSS pixels; document/body scroll width 390;
- narrow dialog: left 10, right 380, width 370, and no internal horizontal
  overflow; and
- no application console error (the development server returned only the
  pre-existing missing `favicon.ico` 404).

## Remaining deployment acceptance

Before closing P0-04, an enterprise pilot must still:

1. package and deploy the SDK endpoint extra, protected manifest and unique
   device keys through its real MDM;
2. prove root/administrator ownership and secret rotation/revocation;
3. obtain successful current reports from at least 95% of the agreed device
   population and explicitly review every missing device;
4. compare observed Claude/Codex installations to source-control expectations
   and active enrollments within the discovery SLO;
5. expose per-device report freshness and collection failures in the hosted UI;
   and
6. evaluate hardware-backed endpoint identity for higher-assurance estates;
   and
7. implement and independently test the Windows owner-SID/DACL adapter before
   including Windows devices in affirmative sensor coverage.

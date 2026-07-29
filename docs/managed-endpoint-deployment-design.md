# Managed endpoint deployment design

This design connects a centrally compiled Claude Code or Codex policy to
administrator-owned endpoint files without treating desired state as proof of
enforcement. It introduces a deterministic deployment package and an optional
offline privileged installer. It does not turn the SDK process, model, browser,
or package file into an endpoint administrator.

## Threat and trust boundary

The package file, its path, its JSON fields and every embedded artifact are
untrusted input. An attacker may alter bytes, add duplicate JSON keys, replace
paths, target another host, substitute a hook, race a symlink or interrupt a
multi-file update. The installer grants no authority from those values alone.

Endpoint management must deliver these four expected values through an
authenticated, administrator-controlled channel:

- package SHA-256;
- compiled bundle SHA-256;
- exact host (`claude-code` or `codex-cli`); and
- exact platform (`macos` or `linux`).

Delivering a package and its expected digest together over an unauthenticated
channel provides no integrity. A production adapter should pin the digest in
MDM, signed device-management metadata or a future control-plane signature.
The current AWS desired-state contract does not yet distribute package bytes;
that remains the next control-plane integration slice.

## Package contract

`ManagedDeploymentPackage` serializes canonical schema-1 JSON containing:

- host, host version and operating-system family;
- policy ID and immutable policy version;
- the compiler's complete bundle digest;
- the complete ordered set of documented managed files, including exact UTF-8
  content and individual digests; and
- one to eight administrator-owned executable prerequisites with absolute path
  and digest.

The package contains no credentials, bearer tokens or environment values. It
rejects unknown or duplicate fields, non-canonical JSON, unknown hosts,
incomplete artifact sets, unsafe paths, duplicate executables, oversized data,
digest mismatches and cross-platform executable locations.

The package deliberately does not embed executable code. Endpoint management
installs the reviewed native hook and MCP gateway first under
`/opt/aai-security/`. The installer verifies regular-file type, administrator
ownership, restrictive write permissions, executable mode and exact bytes
before touching host configuration. This prevents a valid configuration from
activating an unreviewed local enforcement process.

## Installation transaction

`scripts/install_managed_host_package.py` has two explicit modes:

- `--check` performs target, prerequisite and filesystem preflight without
  changing endpoint state; and
- `--install` additionally requires administrator identity and performs the
  update.

Before the first write it validates every package field, prerequisite,
existing target and parent directory. It rejects symlinks, devices, foreign
ownership and group/world-writable state. New files are staged beside their
targets with administrator ownership and mode `0644`, flushed to disk and then
replaced with same-filesystem renames. Existing files are moved to unique
same-directory backups. Any later replacement or directory-sync failure rolls
back every changed target in reverse order. Backups are removed only after all
artifacts are installed.

Windows installation remains fail-closed until an ACL-aware adapter can prove
owner SID, inherited ACLs and protected path semantics. The package format can
represent Windows targets, but the POSIX installer cannot apply them.

## Creating a package

This abbreviated example assumes the native hook has already been built and
reviewed. The package digest must be copied into authenticated MDM metadata,
not derived from the downloaded package on the endpoint:

```python
import hashlib
from pathlib import Path

from agentic_security import (
    ManagedDeploymentPackage,
    ManagedExecutableRequirement,
)

# `bundle` is the result of ManagedConfigurationCompiler.compile(...).
hook_bytes = Path("/staging/native-policy").read_bytes()
package = ManagedDeploymentPackage.from_bundle(
    bundle,
    required_executables=(
        ManagedExecutableRequirement(
            "/opt/aai-security/hooks/native-policy",
            hashlib.sha256(hook_bytes).hexdigest(),
        ),
    ),
)
Path("managed-endpoint-package.json").write_bytes(package.to_json())
print(package.package_sha256)
```

On the endpoint, first run no-write preflight and compare the reported policy,
bundle and package identifiers with the rollout record:

```bash
PYTHONPATH=src python scripts/install_managed_host_package.py \
  --package /var/lib/aai-security/managed-endpoint-package.json \
  --expected-package-sha256 <digest-from-authenticated-mdm> \
  --expected-bundle-hash <desired-bundle-digest> \
  --host claude-code \
  --platform macos \
  --check
```

After approval, repeat with `sudo` and `--install`. Restart the host, use
`measure_managed_configuration` to prove exact protected bytes, then run live
allowed, denied, approval-required and unapproved-MCP probes. File installation
alone is never recorded as proof that Claude Code or Codex loaded the policy.

## Evidence and remaining work

Automated contracts cover canonical parsing, package and artifact tampering,
duplicate keys, traversal, cross-target substitution, missing or changed
executables, symlink targets, non-administrator calls, restrictive installed
modes and complete rollback after a synthetic second-file failure.

This closes the repository's package/install transaction gap but does not
complete P0-01 through P0-03. Authenticated package publication and enrolled
agent retrieval are now provided by the
[managed package distribution](managed-package-distribution-design.md)
contract. Remaining acceptance requires:

- MDM deployment of the SDK wheel, gateway, native hook and package;
- approved-launch enforcement, including Codex flag restrictions;
- real root-owned macOS/Linux installation and host restart evidence;
- live Claude/Codex effective-source and action probes; and
- Windows ACL installation plus hardware-backed endpoint identity.

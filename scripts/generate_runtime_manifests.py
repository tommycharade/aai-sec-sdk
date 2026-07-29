"""Generate deployment manifests only from independently verified release inputs.

This command executes fixed ``git`` and ``gh`` argument vectors. It never runs
through a shell and never accepts a command from model or project content. Run
it only from a trusted release workstation: repository-local Git configuration
and the authenticated GitHub CLI remain deployment-owned trust boundaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Final

from agentic_security import RuntimeAttestationError, RuntimeAttestor

_REVISION: Final = re.compile(r"[0-9a-f]{40}")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_TAG: Final = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_REPOSITORY: Final = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_HOSTS: Final = ("claude-code", "codex-cli")


class RuntimeManifestGenerationError(RuntimeError):
    """Raised when release provenance or measured artifacts are not trustworthy."""


def _run_silent(command: list[str], *, cwd: Path, timeout: int = 120) -> None:
    """Execute one fixed argv without retaining child output or invoking a shell."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed, validated deployment-tool argv
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeManifestGenerationError("release verification command failed") from exc
    if completed.returncode != 0:
        raise RuntimeManifestGenerationError("release verification command failed")


def _git_status(sdk_root: Path) -> bytes:
    """Return bounded porcelain status from the selected checkout."""
    with tempfile.TemporaryFile() as output:
        try:
            completed = subprocess.run(  # noqa: S603, S607 - fixed local Git argv
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],  # noqa: S607
                cwd=sdk_root,
                env={
                    **os.environ,
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                },
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeManifestGenerationError("clean checkout cannot be verified") from exc
        if completed.returncode != 0:
            raise RuntimeManifestGenerationError("clean checkout cannot be verified")
        size = output.tell()
        if size > 1_000_000:
            raise RuntimeManifestGenerationError("Git status exceeds the safe bound")
        output.seek(0)
        return output.read(1_000_001)


def assert_clean_checkout(sdk_root: Path) -> None:
    """Reject tracked, staged, or untracked changes before measuring approval state."""
    if _git_status(sdk_root):
        raise RuntimeManifestGenerationError("runtime manifests require a clean checkout")


def verify_release_inputs(
    *,
    sdk_root: Path,
    release_evidence: Path,
    revision: str,
    tag: str,
    repository: str,
) -> str:
    """Verify release evidence and GitHub provenance, returning its bundle digest."""
    if not release_evidence.is_dir() or release_evidence.is_symlink():
        raise RuntimeManifestGenerationError("release evidence directory is unavailable or unsafe")
    verifier = sdk_root / "scripts" / "verify_release_evidence.py"
    if not verifier.is_file() or verifier.is_symlink():
        raise RuntimeManifestGenerationError("release evidence verifier is unavailable or unsafe")
    _run_silent(
        [
            sys.executable,
            str(verifier),
            str(release_evidence),
            "--commit",
            revision,
            "--tag",
            tag,
        ],
        cwd=sdk_root,
    )

    wheel = sorted(release_evidence.glob("*.whl"))
    source = sorted(release_evidence.glob("*.tar.gz"))
    if len(wheel) != 1 or len(source) != 1:
        raise RuntimeManifestGenerationError(
            "release evidence requires one wheel and source archive"
        )
    if any(
        artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > 256_000_000
        for artifact in (*wheel, *source)
    ):
        raise RuntimeManifestGenerationError("release artifacts are unavailable or unsafe")
    gh = shutil.which("gh")
    if gh is None:
        raise RuntimeManifestGenerationError("GitHub CLI is required for provenance verification")
    workflow = f"{repository}/.github/workflows/release-artifacts.yml"
    for artifact in (*wheel, *source):
        _run_silent(
            [
                gh,
                "attestation",
                "verify",
                str(artifact),
                "--repo",
                repository,
                "--signer-workflow",
                workflow,
                "--source-ref",
                f"refs/tags/{tag}",
            ],
            cwd=sdk_root,
        )

    checksums = _read_regular_bounded(
        release_evidence / "SHA256SUMS", 1_000_000, "release checksum evidence"
    )
    return hashlib.sha256(checksums).hexdigest()


def build_runtime_manifest_bundle(
    *,
    sdk_root: Path,
    package_root: Path,
    sdk_version: str,
    expected_revision: str,
    expected_origin_digest: str,
    hosts: tuple[str, ...] = _HOSTS,
) -> list[dict[str, object]]:
    """Measure deterministic host manifests and bind them to reviewed source identity."""
    if not _REVISION.fullmatch(expected_revision):
        raise RuntimeManifestGenerationError("expected revision must be a full Git SHA")
    if not _SHA256.fullmatch(expected_origin_digest):
        raise RuntimeManifestGenerationError("expected origin digest must be SHA-256")
    if not hosts or len(hosts) != len(set(hosts)) or any(host not in _HOSTS for host in hosts):
        raise RuntimeManifestGenerationError("manifest hosts must be unique supported integrations")
    try:
        project = tomllib.loads((sdk_root / "pyproject.toml").read_text(encoding="utf-8"))
        declared_version = project["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeManifestGenerationError("SDK version metadata is unavailable") from exc
    if declared_version != sdk_version:
        raise RuntimeManifestGenerationError("SDK version does not match pyproject.toml")

    manifests: list[dict[str, object]] = []
    try:
        for host in hosts:
            attestor = RuntimeAttestor(
                sdk_root=sdk_root,
                project_root=sdk_root,
                package_root=package_root,
                host=host,
                sdk_version=sdk_version,
            )
            manifest = attestor.artifact_manifest()
            if manifest.sdk_revision != expected_revision:
                raise RuntimeManifestGenerationError(
                    "measured SDK revision does not match verified release"
                )
            if manifest.source_origin_digest != expected_origin_digest:
                raise RuntimeManifestGenerationError(
                    "measured source origin does not match approved repository"
                )
            manifests.append(manifest.to_wire())
    except RuntimeAttestationError as exc:
        raise RuntimeManifestGenerationError("runtime artifacts cannot be measured safely") from exc
    return manifests


def _encoded(value: object) -> bytes:
    """Return stable reviewable JSON bytes."""
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_runtime_manifest_approval(
    *,
    manifest_bundle: bytes,
    hosts: tuple[str, ...],
    release_evidence_digest: str,
    release_tag: str,
    sdk_revision: str,
    sdk_version: str,
    source_origin_digest: str,
) -> dict[str, object]:
    """Bind exact manifest bytes to the independently verified release identity."""
    if not manifest_bundle or len(manifest_bundle) > 65_536:
        raise RuntimeManifestGenerationError("runtime manifest bundle is outside the safe bound")
    if not _SHA256.fullmatch(release_evidence_digest):
        raise RuntimeManifestGenerationError("release evidence digest must be SHA-256")
    if not _TAG.fullmatch(release_tag) or not _REVISION.fullmatch(sdk_revision):
        raise RuntimeManifestGenerationError("release approval identity is invalid")
    if not _SHA256.fullmatch(source_origin_digest):
        raise RuntimeManifestGenerationError("release approval origin must be SHA-256")
    if not sdk_version or len(sdk_version) > 64:
        raise RuntimeManifestGenerationError("release approval SDK version is invalid")
    if not hosts or len(hosts) != len(set(hosts)) or any(host not in _HOSTS for host in hosts):
        raise RuntimeManifestGenerationError("release approval hosts are invalid")
    return {
        "approvals": [
            {
                "hosts": list(hosts),
                "releaseEvidenceSha256": release_evidence_digest,
                "releaseTag": release_tag,
                "sdkRevision": sdk_revision,
                "sdkVersion": sdk_version,
                "sourceOriginDigest": source_origin_digest,
            }
        ],
        "manifestBundleSha256": hashlib.sha256(manifest_bundle).hexdigest(),
        "schemaVersion": 1,
    }


def _write_atomic(path: Path, value: bytes) -> None:
    """Replace a non-secret manifest without following a target symlink."""
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or path.parent.resolve() != path.parent.absolute()
    ):
        raise RuntimeManifestGenerationError("refusing to write through a symlinked directory")
    if path.is_symlink():
        raise RuntimeManifestGenerationError("refusing to replace a symlinked manifest")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeManifestGenerationError("runtime manifest cannot be written safely") from exc


def _read_regular_bounded(path: Path, maximum_bytes: int, label: str) -> bytes:
    """Read one stable regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeManifestGenerationError(f"{label} is unavailable or unsafe") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise RuntimeManifestGenerationError(f"{label} is unavailable or unsafe")
        while chunk := os.read(descriptor, min(65_536, maximum_bytes + 1 - total)):
            total += len(chunk)
            if total > maximum_bytes:
                raise RuntimeManifestGenerationError(f"{label} exceeds the safe bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise RuntimeManifestGenerationError(f"{label} changed during verification")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _matches(path: Path, expected: bytes) -> bool:
    """Compare an existing bounded regular file to deterministic output."""
    try:
        value = _read_regular_bounded(path, 1_000_000, "checked-in runtime manifest")
    except RuntimeManifestGenerationError:
        return False
    return value == expected


def main() -> int:
    """Verify one release and generate its deployable runtime trust bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--sdk-version", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-origin-digest", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--release-evidence", type=Path, required=True)
    parser.add_argument("--repository", default="tommycharade/aai-sec-sdk")
    parser.add_argument("--host", action="append", choices=_HOSTS)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("infra/aws-control-plane/lambda/runtime-manifests.json"),
    )
    parser.add_argument(
        "--approval-output",
        type=Path,
        default=Path("infra/aws-control-plane/lambda/runtime-manifests.provenance.json"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    sdk_input = args.sdk_root.expanduser().absolute()
    evidence_input = args.release_evidence.expanduser().absolute()
    package_input = (args.package_root or sdk_input / "src" / "agentic_security").expanduser()
    if sdk_input.is_symlink() or evidence_input.is_symlink() or package_input.is_symlink():
        raise RuntimeManifestGenerationError("release input directories cannot be symbolic links")
    sdk_root = sdk_input.resolve()
    package_root = package_input.resolve()
    release_evidence = evidence_input.resolve()
    if not _TAG.fullmatch(args.release_tag):
        raise RuntimeManifestGenerationError("release tag is invalid")
    if not _REPOSITORY.fullmatch(args.repository):
        raise RuntimeManifestGenerationError("GitHub repository identity is invalid")
    assert_clean_checkout(sdk_root)
    release_evidence_digest = verify_release_inputs(
        sdk_root=sdk_root,
        release_evidence=release_evidence,
        revision=args.expected_revision,
        tag=args.release_tag,
        repository=args.repository,
    )
    hosts = tuple(args.host or _HOSTS)
    manifests = build_runtime_manifest_bundle(
        sdk_root=sdk_root,
        package_root=package_root,
        sdk_version=args.sdk_version,
        expected_revision=args.expected_revision,
        expected_origin_digest=args.expected_origin_digest,
        hosts=hosts,
    )
    bundle = _encoded(manifests)
    approval = _encoded(
        build_runtime_manifest_approval(
            manifest_bundle=bundle,
            hosts=hosts,
            release_evidence_digest=release_evidence_digest,
            release_tag=args.release_tag,
            sdk_revision=args.expected_revision,
            sdk_version=args.sdk_version,
            source_origin_digest=args.expected_origin_digest,
        )
    )
    output = args.output.expanduser()
    approval_output = args.approval_output.expanduser()
    output = (output if output.is_absolute() else sdk_root / output).absolute()
    approval_output = (
        approval_output if approval_output.is_absolute() else sdk_root / approval_output
    ).absolute()
    if args.check:
        if not _matches(output, bundle) or not _matches(approval_output, approval):
            raise RuntimeManifestGenerationError("checked-in runtime manifests are stale")
        print(f"Verified {len(manifests)} runtime manifests against {args.release_tag}.")
        return 0
    _write_atomic(output, bundle)
    _write_atomic(approval_output, approval)
    print(f"Generated {len(manifests)} runtime manifests from verified {args.release_tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

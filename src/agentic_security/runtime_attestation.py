"""Content-minimised runtime integrity evidence for enrolled agent hosts.

The attestor measures local artifacts; it does not decide that they are
approved. A trusted control plane must compare the artifact fields to a
deployment-owned approved manifest, bind the project-specific fields at
enrollment, and require a fresh server nonce on every heartbeat. Digests are
evidence identifiers and never substitute for OS or hardware-backed device
identity.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

_HOST_HOOKS: Final = {
    "claude-code": "claude_code_hook.py",
    "codex-cli": "codex_cli_hook.py",
}
_HOST_CONFIGS: Final = {
    "claude-code": (
        ".claude/settings.json",
        ".claude/aai-sec-config.json",
        ".mcp.json",
    ),
    "codex-cli": (".codex/config.toml",),
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_REF = re.compile(r"refs/[A-Za-z0-9._/-]{1,240}")


class RuntimeAttestationError(RuntimeError):
    """Raised when local integrity evidence cannot be measured safely."""


@dataclass(frozen=True, slots=True)
class RuntimeArtifactManifest:
    """Invariant SDK artifacts that a deployment can approve out of band."""

    schema_version: int
    sdk_version: str
    sdk_revision: str
    source_origin_digest: str
    package_digest: str
    gateway_digest: str
    hook_digest: str
    host: str

    def to_wire(self) -> dict[str, object]:
        """Return the stable camel-case manifest consumed by control planes."""
        return _camel_case(asdict(self))


@dataclass(frozen=True, slots=True)
class RuntimeAttestationEvidence:
    """Fresh nonce-bound host evidence sent with an authenticated heartbeat."""

    schema_version: int
    sdk_version: str
    sdk_revision: str
    source_origin_digest: str
    package_digest: str
    gateway_digest: str
    hook_digest: str
    configuration_digest: str
    executable_digest: str
    launch_context_digest: str
    project_root_digest: str
    host: str
    observed_at: int
    nonce: str

    def __post_init__(self) -> None:
        """Reject malformed evidence before it can leave the trusted host code."""
        if self.schema_version != 1:
            raise ValueError("runtime attestation schema version must be 1")
        if self.host not in _HOST_HOOKS:
            raise ValueError("runtime attestation host is unsupported")
        if not _REVISION.fullmatch(self.sdk_revision):
            raise ValueError("runtime attestation SDK revision must be a Git SHA")
        for value in (
            self.source_origin_digest,
            self.package_digest,
            self.gateway_digest,
            self.hook_digest,
            self.configuration_digest,
            self.executable_digest,
            self.launch_context_digest,
            self.project_root_digest,
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError("runtime attestation artifact digests must be SHA-256")
        if isinstance(self.observed_at, bool) or self.observed_at <= 0:
            raise ValueError("runtime attestation observation time must be positive")
        if not isinstance(self.nonce, str) or not 32 <= len(self.nonce) <= 256:
            raise ValueError("runtime attestation nonce must contain 32 to 256 characters")

    def to_wire(self) -> dict[str, object]:
        """Return the bounded wire shape without local paths or file content."""
        return _camel_case(asdict(self))


class RuntimeAttestor:
    """Measure one Claude Code or Codex CLI runtime from trusted local paths.

    The constructor performs no network calls and stores no credentials. Every
    call re-reads the measured artifacts so post-enrollment changes are visible
    on the next heartbeat. Files are opened without following symbolic links;
    unsafe, missing, oversized or racing inputs fail closed.
    """

    def __init__(
        self,
        *,
        sdk_root: str | Path,
        project_root: str | Path,
        host: str,
        sdk_version: str,
        package_root: str | Path | None = None,
        executable: str | Path | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        """Bind measurement to canonical SDK, project, package and executable roots."""
        if host not in _HOST_HOOKS:
            raise ValueError("runtime attestation supports claude-code and codex-cli")
        if not isinstance(sdk_version, str) or not 1 <= len(sdk_version) <= 64:
            raise ValueError("SDK version is required for runtime attestation")
        self.sdk_root = _canonical_directory(sdk_root, "SDK root")
        self.project_root = _canonical_directory(project_root, "project root")
        self.package_root = _canonical_directory(
            package_root or Path(__file__).parent,
            "installed package root",
        )
        candidate = Path(executable or sys.executable).expanduser()
        try:
            self.executable = candidate.resolve(strict=True)
        except OSError as exc:
            raise RuntimeAttestationError("Python executable cannot be resolved") from exc
        if not self.executable.is_file():
            raise RuntimeAttestationError("Python executable is not a regular file")
        self.host = host
        self.sdk_version = sdk_version
        self._now = now or (lambda: int(time.time()))

    def artifact_manifest(self) -> RuntimeArtifactManifest:
        """Measure deployment-invariant SDK artifacts for manifest approval."""
        gateway = self.sdk_root / "examples" / "mcp_gateway.py"
        hook = self.sdk_root / "examples" / _HOST_HOOKS[self.host]
        return RuntimeArtifactManifest(
            schema_version=1,
            sdk_version=self.sdk_version,
            sdk_revision=_git_revision(self.sdk_root),
            source_origin_digest=_source_origin_digest(self.sdk_root),
            package_digest=_digest_tree(self.package_root),
            gateway_digest=_digest_file(gateway, 2_000_000),
            hook_digest=_digest_file(hook, 2_000_000),
            host=self.host,
        )

    def attest(self, nonce: str) -> RuntimeAttestationEvidence:
        """Measure fresh project/runtime state and bind it to a server nonce."""
        if not isinstance(nonce, str) or not 32 <= len(nonce) <= 256:
            raise RuntimeAttestationError("server attestation nonce is invalid")
        manifest = self.artifact_manifest()
        configuration_digest = _digest_set(
            (self.project_root / relative for relative in _HOST_CONFIGS[self.host]),
            self.project_root,
        )
        launch_context = json.dumps(
            {
                "executable": str(self.executable),
                "gateway": str((self.sdk_root / "examples" / "mcp_gateway.py").resolve()),
                "host": self.host,
                "packageRoot": str(self.package_root),
                "projectRoot": str(self.project_root),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return RuntimeAttestationEvidence(
            **asdict(manifest),
            configuration_digest=configuration_digest,
            executable_digest=_digest_file(self.executable, 256_000_000),
            launch_context_digest=hashlib.sha256(launch_context).hexdigest(),
            project_root_digest=hashlib.sha256(str(self.project_root).encode("utf-8")).hexdigest(),
            observed_at=int(self._now()),
            nonce=nonce,
        )


def _canonical_directory(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeAttestationError(f"{label} cannot be resolved") from exc
    if not resolved.is_dir():
        raise RuntimeAttestationError(f"{label} is not a directory")
    return resolved


def _digest_file(path: Path, maximum_bytes: int) -> str:
    """Hash one regular file without following a final-component symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeAttestationError("required runtime artifact cannot be opened safely") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise RuntimeAttestationError("runtime artifact is not a regular file")
        while chunk := os.read(descriptor, 131_072):
            total += len(chunk)
            if total > maximum_bytes:
                raise RuntimeAttestationError("runtime artifact exceeds its measurement bound")
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise RuntimeAttestationError("runtime artifact changed during measurement")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _digest_tree(root: Path) -> str:
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and (path.suffix == ".py" or path.name == "py.typed")
    )
    if not files or len(files) > 512:
        raise RuntimeAttestationError("installed package file count is outside the safe bound")
    return _digest_set(files, root)


def _digest_set(paths: Iterable[Path], root: Path) -> str:
    digest = hashlib.sha256()
    count = 0
    for path in sorted(paths):
        count += 1
        if count > 512:
            raise RuntimeAttestationError("runtime artifact set exceeds the safe bound")
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise RuntimeAttestationError("runtime artifact escaped its trusted root") from exc
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeAttestationError("runtime artifact cannot be resolved") from exc
        # Reject symlinks in any path component. O_NOFOLLOW in _digest_file protects
        # the final component; this check also preserves the trusted-root boundary
        # when an attacker replaces a parent directory with a symlink.
        if resolved != path.absolute():
            raise RuntimeAttestationError("runtime artifact path contains a symbolic link")
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise RuntimeAttestationError("runtime artifact escaped its trusted root") from exc
        file_digest = _digest_file(path, 2_000_000)
        digest.update(str(relative).encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    if count == 0:
        raise RuntimeAttestationError("runtime artifact set is empty")
    return digest.hexdigest()


def _read_bounded(path: Path, maximum_bytes: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeAttestationError("Git provenance metadata is unavailable") from exc
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise RuntimeAttestationError("Git provenance metadata is not a regular file")
        if initial.st_size > maximum_bytes:
            raise RuntimeAttestationError("Git provenance metadata exceeds the safe bound")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(65_536, maximum_bytes + 1 - total)):
            total += len(chunk)
            if total > maximum_bytes:
                raise RuntimeAttestationError("Git provenance metadata exceeds the safe bound")
            chunks.append(chunk)
        final = os.fstat(descriptor)
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise RuntimeAttestationError("Git provenance metadata changed during measurement")
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeError as exc:
            raise RuntimeAttestationError("Git provenance metadata is not UTF-8") from exc
    finally:
        os.close(descriptor)


def _git_revision(sdk_root: Path) -> str:
    git = sdk_root / ".git"
    if git.is_symlink() or not git.is_dir():
        raise RuntimeAttestationError("SDK checkout has no measurable Git directory")
    head = _read_bounded(git / "HEAD", 512).strip()
    if _REVISION.fullmatch(head):
        return head
    if not head.startswith("ref: ") or not _REF.fullmatch(head[5:]):
        raise RuntimeAttestationError("SDK Git revision is malformed")
    reference = (git / head[5:]).resolve()
    try:
        reference.relative_to(git.resolve())
    except ValueError as exc:
        raise RuntimeAttestationError("SDK Git revision escaped the metadata root") from exc
    revision = _read_bounded(reference, 512).strip()
    if not _REVISION.fullmatch(revision):
        raise RuntimeAttestationError("SDK Git revision is not a full commit SHA")
    return revision


def _source_origin_digest(sdk_root: Path) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(_read_bounded(sdk_root / ".git" / "config", 64_000))
        origin = parser.get('remote "origin"', "url")
    except (configparser.Error, KeyError, ValueError) as exc:
        raise RuntimeAttestationError("SDK origin cannot be resolved") from exc
    if not origin or len(origin) > 512 or any(character.isspace() for character in origin):
        raise RuntimeAttestationError("SDK origin is malformed")
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()


def _camel_case(value: dict[str, object]) -> dict[str, object]:
    return {
        key.split("_")[0] + "".join(part.title() for part in key.split("_")[1:]): item
        for key, item in value.items()
    }


__all__ = [
    "RuntimeArtifactManifest",
    "RuntimeAttestationError",
    "RuntimeAttestationEvidence",
    "RuntimeAttestor",
]

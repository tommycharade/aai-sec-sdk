"""Adversarial tests for content-minimised host runtime attestation."""

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agentic_security import (
    RuntimeAttestationError,
    RuntimeAttestor,
)

REVISION = "a" * 40
NONCE = "synthetic-server-challenge-value-123456"


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _attestor(tmp_path: Path, host: str = "claude-code") -> RuntimeAttestor:
    sdk = tmp_path / "sdk"
    project = tmp_path / "project"
    package = tmp_path / "package" / "agentic_security"
    executable = tmp_path / "python"
    _write(sdk / ".git" / "HEAD", f"{REVISION}\n")
    _write(
        sdk / ".git" / "config",
        '[remote "origin"]\n\turl = https://example.invalid/aai-sec-sdk.git\n',
    )
    _write(sdk / "examples" / "mcp_gateway.py", "# synthetic gateway\n")
    _write(sdk / "examples" / "claude_code_hook.py", "# synthetic Claude hook\n")
    _write(sdk / "examples" / "codex_cli_hook.py", "# synthetic Codex hook\n")
    _write(package / "__init__.py", "# synthetic package\n")
    _write(executable, "synthetic executable\n")
    executable.chmod(0o700)
    if host == "claude-code":
        _write(project / ".claude" / "settings.json", "{}\n")
        _write(project / ".claude" / "aai-sec-config.json", "{}\n")
        _write(project / ".mcp.json", "{}\n")
    else:
        _write(project / ".codex" / "config.toml", "# synthetic config\n")
    return RuntimeAttestor(
        sdk_root=sdk,
        project_root=project,
        package_root=package,
        executable=executable,
        host=host,
        sdk_version="1.1.0",
        now=lambda: 1_900_000_000,
    )


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_runtime_attestation_is_fresh_typed_and_content_minimised(
    tmp_path: Path, host: str
) -> None:
    """Both supported hosts emit stable digests without paths or file content."""
    attestor = _attestor(tmp_path, host)
    evidence = attestor.attest(NONCE).to_wire()
    manifest = attestor.artifact_manifest().to_wire()

    assert evidence["host"] == host
    assert evidence["sdkRevision"] == REVISION
    assert evidence["nonce"] == NONCE
    assert evidence["observedAt"] == 1_900_000_000
    assert (
        evidence["projectRootDigest"]
        == hashlib.sha256(str((tmp_path / "project").resolve()).encode()).hexdigest()
    )
    assert manifest["packageDigest"] == evidence["packageDigest"]
    serialized = str(evidence)
    assert str(tmp_path) not in serialized
    assert "synthetic gateway" not in serialized


def test_runtime_attestation_detects_configuration_and_package_changes(tmp_path: Path) -> None:
    """Post-enrollment changes alter the exact fields compared by the control plane."""
    attestor = _attestor(tmp_path)
    before = attestor.attest(NONCE)
    _write(tmp_path / "project" / ".mcp.json", '{"changed": true}\n')
    after_configuration = attestor.attest(NONCE)
    assert after_configuration.configuration_digest != before.configuration_digest
    assert after_configuration.package_digest == before.package_digest

    _write(tmp_path / "package" / "agentic_security" / "runtime.py", "# modified runtime\n")
    after_package = attestor.attest(NONCE)
    assert after_package.package_digest != before.package_digest


def test_runtime_attestation_fails_closed_for_missing_symlinked_or_oversized_artifacts(
    tmp_path: Path,
) -> None:
    """Unsafe local files cannot be omitted or followed to manufacture evidence."""
    attestor = _attestor(tmp_path)
    (tmp_path / "project" / ".mcp.json").unlink()
    with pytest.raises(RuntimeAttestationError, match="cannot be resolved"):
        attestor.attest(NONCE)

    _write(tmp_path / "outside.json", "{}")
    (tmp_path / "project" / ".mcp.json").symlink_to(tmp_path / "outside.json")
    with pytest.raises(RuntimeAttestationError, match="path contains a symbolic link"):
        attestor.attest(NONCE)

    (tmp_path / "project" / ".mcp.json").unlink()
    (tmp_path / "project" / ".mcp.json").write_bytes(b"x" * 2_000_001)
    with pytest.raises(RuntimeAttestationError, match="exceeds its measurement bound"):
        attestor.attest(NONCE)


def test_runtime_attestation_rejects_symlinked_parent_directories(tmp_path: Path) -> None:
    """A swapped parent directory cannot redirect measurement outside the project."""
    attestor = _attestor(tmp_path)
    claude_directory = tmp_path / "project" / ".claude"
    outside_directory = tmp_path / "outside-claude"
    claude_directory.rename(outside_directory)
    claude_directory.symlink_to(outside_directory, target_is_directory=True)

    with pytest.raises(RuntimeAttestationError, match="path contains a symbolic link"):
        attestor.attest(NONCE)


def test_runtime_attestation_rejects_symlinked_git_metadata(tmp_path: Path) -> None:
    """Git provenance reads do not follow a substituted metadata file."""
    attestor = _attestor(tmp_path)
    head = tmp_path / "sdk" / ".git" / "HEAD"
    head.unlink()
    _write(tmp_path / "outside-head", f"{REVISION}\n")
    head.symlink_to(tmp_path / "outside-head")

    with pytest.raises(RuntimeAttestationError, match="metadata is unavailable"):
        attestor.attest(NONCE)


def test_runtime_attestation_rejects_bad_provenance_and_replay_inputs(tmp_path: Path) -> None:
    """Malformed Git metadata and weak nonces never produce an attestation."""
    attestor = _attestor(tmp_path)
    with pytest.raises(RuntimeAttestationError, match="nonce is invalid"):
        attestor.attest("short")

    _write(tmp_path / "sdk" / ".git" / "HEAD", "main\n")
    with pytest.raises(RuntimeAttestationError, match="revision is malformed"):
        attestor.attest(NONCE)


def test_runtime_attestation_rejects_unsupported_hosts(tmp_path: Path) -> None:
    """Unknown host integrations cannot silently inherit another hook profile."""
    with pytest.raises(ValueError, match="supports claude-code and codex-cli"):
        _attestor(tmp_path, "unknown-host")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"schema_version": 2}, "schema version"),
        ({"host": "unknown"}, "host is unsupported"),
        ({"sdk_revision": "short"}, "revision must be a Git SHA"),
        ({"package_digest": "short"}, "digests must be SHA-256"),
        ({"observed_at": 0}, "observation time must be positive"),
        ({"observed_at": True}, "observation time must be positive"),
        ({"nonce": "short"}, "nonce must contain"),
    ],
)
def test_runtime_evidence_rejects_invalid_typed_fields(
    tmp_path: Path, changes: dict[str, Any], message: str
) -> None:
    """Every security-relevant evidence field is validated before transport."""
    evidence = _attestor(tmp_path).attest(NONCE)

    with pytest.raises(ValueError, match=message):
        replace(evidence, **changes)


def test_runtime_evidence_rejects_non_text_nonce(tmp_path: Path) -> None:
    """A non-text nonce cannot bypass the bounded nonce contract."""
    evidence = _attestor(tmp_path).attest(NONCE)

    with pytest.raises(ValueError, match="nonce must contain"):
        replace(evidence, nonce=123)  # type: ignore[arg-type]


def test_runtime_attestor_rejects_invalid_roots_versions_and_executables(
    tmp_path: Path,
) -> None:
    """Construction fails closed before any unsafe path becomes trusted state."""
    attestor = _attestor(tmp_path)
    values: Any = {
        "sdk_root": attestor.sdk_root,
        "project_root": attestor.project_root,
        "package_root": attestor.package_root,
        "host": "claude-code",
        "sdk_version": "1.1.0",
    }
    with pytest.raises(ValueError, match="SDK version is required"):
        RuntimeAttestor(**{**values, "sdk_version": ""})
    with pytest.raises(RuntimeAttestationError, match="SDK root cannot be resolved"):
        RuntimeAttestor(**{**values, "sdk_root": tmp_path / "missing"})

    regular_file = tmp_path / "not-a-directory"
    _write(regular_file, "file")
    with pytest.raises(RuntimeAttestationError, match="project root is not a directory"):
        RuntimeAttestor(**{**values, "project_root": regular_file})
    with pytest.raises(RuntimeAttestationError, match="executable cannot be resolved"):
        RuntimeAttestor(**values, executable=tmp_path / "missing-python")
    with pytest.raises(RuntimeAttestationError, match="executable is not a regular file"):
        RuntimeAttestor(**values, executable=tmp_path)


def test_runtime_attestation_supports_git_refs_and_rejects_bad_origin(tmp_path: Path) -> None:
    """Symbolic Git refs are bounded while absent or malformed origins fail closed."""
    attestor = _attestor(tmp_path)
    _write(tmp_path / "sdk" / ".git" / "HEAD", "ref: refs/heads/main\n")
    _write(tmp_path / "sdk" / ".git" / "refs" / "heads" / "main", f"{REVISION}\n")
    assert attestor.artifact_manifest().sdk_revision == REVISION

    _write(tmp_path / "sdk" / ".git" / "refs" / "heads" / "main", "short\n")
    with pytest.raises(RuntimeAttestationError, match="not a full commit SHA"):
        attestor.artifact_manifest()

    _write(tmp_path / "sdk" / ".git" / "HEAD", f"{REVISION}\n")
    _write(tmp_path / "sdk" / ".git" / "config", "[core]\n")
    with pytest.raises(RuntimeAttestationError, match="origin cannot be resolved"):
        attestor.artifact_manifest()

    _write(
        tmp_path / "sdk" / ".git" / "config",
        '[remote "origin"]\n\turl = invalid origin\n',
    )
    with pytest.raises(RuntimeAttestationError, match="origin is malformed"):
        attestor.artifact_manifest()


def test_runtime_attestation_supports_linked_worktrees_and_packed_refs(tmp_path: Path) -> None:
    """Normal linked-worktree metadata produces the same bounded provenance identity."""
    attestor = _attestor(tmp_path)
    sdk = tmp_path / "sdk"
    common = tmp_path / "common-git"
    worktree = common / "worktrees" / "sdk"
    original = sdk / ".git"
    original.rename(common)
    worktree.mkdir(parents=True)
    _write(worktree / "HEAD", "ref: refs/heads/release\n")
    _write(worktree / "commondir", "../..\n")
    _write(
        common / "packed-refs",
        f"# pack-refs with: peeled fully-peeled sorted\n{REVISION} refs/heads/release\n",
    )
    _write(sdk / ".git", f"gitdir: {worktree}\n")

    manifest = attestor.artifact_manifest()

    assert manifest.sdk_revision == REVISION
    assert (
        manifest.source_origin_digest
        == hashlib.sha256(b"https://example.invalid/aai-sec-sdk.git").hexdigest()
    )


def test_runtime_attestation_rejects_unsafe_worktree_metadata(tmp_path: Path) -> None:
    """Malformed, unavailable or symlinked worktree pointers fail closed."""
    attestor = _attestor(tmp_path)
    marker = tmp_path / "sdk" / ".git"
    original = tmp_path / "git-original"
    marker.rename(original)
    _write(marker, "not-a-git-pointer\n")
    with pytest.raises(RuntimeAttestationError, match="pointer is malformed"):
        attestor.artifact_manifest()

    _write(marker, "gitdir: unsafe\x00directory\n")
    with pytest.raises(RuntimeAttestationError, match="pointer is malformed"):
        attestor.artifact_manifest()

    marker.unlink()
    marker.symlink_to(original, target_is_directory=True)
    with pytest.raises(RuntimeAttestationError, match="metadata is unsafe"):
        attestor.artifact_manifest()


def test_runtime_attestation_rejects_malformed_or_ambiguous_packed_refs(
    tmp_path: Path,
) -> None:
    """Packed refs cannot smuggle malformed or duplicate source revisions."""
    attestor = _attestor(tmp_path)
    git = tmp_path / "sdk" / ".git"
    _write(git / "HEAD", "ref: refs/heads/release\n")
    _write(git / "packed-refs", "malformed packed ref\n")
    with pytest.raises(RuntimeAttestationError, match="packed Git references are malformed"):
        attestor.artifact_manifest()

    _write(git / "packed-refs", f"{REVISION} refs/heads/other\n^short\n")
    with pytest.raises(RuntimeAttestationError, match="packed Git references are malformed"):
        attestor.artifact_manifest()

    _write(
        git / "packed-refs",
        f"{REVISION} refs/heads/release\n{'b' * 40} refs/heads/release\n",
    )
    with pytest.raises(RuntimeAttestationError, match="revision is ambiguous"):
        attestor.artifact_manifest()


def test_runtime_attestation_rejects_empty_package_and_missing_git_directory(
    tmp_path: Path,
) -> None:
    """An unverifiable checkout or empty enforcement package cannot be approved."""
    attestor = _attestor(tmp_path)
    (tmp_path / "package" / "agentic_security" / "__init__.py").unlink()
    with pytest.raises(RuntimeAttestationError, match="file count"):
        attestor.artifact_manifest()

    _write(tmp_path / "package" / "agentic_security" / "__init__.py", "# restored\n")
    (tmp_path / "sdk" / ".git").rename(tmp_path / "sdk" / "git-hidden")
    with pytest.raises(RuntimeAttestationError, match="no measurable Git directory"):
        attestor.artifact_manifest()

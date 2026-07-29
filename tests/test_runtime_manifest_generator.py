"""Security and determinism tests for deployment runtime-manifest generation."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from scripts import generate_runtime_manifests as generator

REVISION = "a" * 40
ORIGIN = "https://github.com/tommycharade/aai-sec-sdk.git"
ORIGIN_DIGEST = hashlib.sha256(ORIGIN.encode()).hexdigest()


def _write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8")


def _sdk(tmp_path: Path) -> tuple[Path, Path]:
    sdk = tmp_path / "sdk"
    package = sdk / "src" / "agentic_security"
    _write(sdk / ".git" / "HEAD", f"{REVISION}\n")
    _write(sdk / ".git" / "config", f'[remote "origin"]\n\turl = {ORIGIN}\n')
    _write(sdk / "pyproject.toml", '[project]\nversion = "1.1.0"\n')
    _write(sdk / "examples" / "mcp_gateway.py", "# gateway\n")
    _write(sdk / "examples" / "claude_code_hook.py", "# claude\n")
    _write(sdk / "examples" / "codex_cli_hook.py", "# codex\n")
    _write(package / "__init__.py", "# package\n")
    return sdk, package


def test_build_runtime_manifest_bundle_is_release_bound_and_deterministic(
    tmp_path: Path,
) -> None:
    """One verified source identity produces exact manifests for both host hooks."""
    sdk, package = _sdk(tmp_path)

    first = generator.build_runtime_manifest_bundle(
        sdk_root=sdk,
        package_root=package,
        sdk_version="1.1.0",
        expected_revision=REVISION,
        expected_origin_digest=ORIGIN_DIGEST,
    )
    second = generator.build_runtime_manifest_bundle(
        sdk_root=sdk,
        package_root=package,
        sdk_version="1.1.0",
        expected_revision=REVISION,
        expected_origin_digest=ORIGIN_DIGEST,
    )

    assert first == second
    assert [item["host"] for item in first] == ["claude-code", "codex-cli"]
    assert first[0]["sdkRevision"] == REVISION
    assert first[0]["packageDigest"] == first[1]["packageDigest"]
    assert first[0]["hookDigest"] != first[1]["hookDigest"]


@pytest.mark.parametrize(
    ("version", "revision", "origin", "message"),
    [
        ("wrong", REVISION, ORIGIN_DIGEST, "does not match pyproject"),
        ("1.1.0", "short", ORIGIN_DIGEST, "full Git SHA"),
        ("1.1.0", "b" * 40, ORIGIN_DIGEST, "does not match verified release"),
        ("1.1.0", REVISION, "c" * 64, "does not match approved repository"),
    ],
)
def test_build_runtime_manifest_bundle_rejects_unapproved_identity(
    tmp_path: Path,
    version: str,
    revision: str,
    origin: str,
    message: str,
) -> None:
    """Version, revision and repository identity must all match independent inputs."""
    sdk, package = _sdk(tmp_path)

    with pytest.raises(generator.RuntimeManifestGenerationError, match=message):
        generator.build_runtime_manifest_bundle(
            sdk_root=sdk,
            package_root=package,
            sdk_version=version,
            expected_revision=revision,
            expected_origin_digest=origin,
        )


def test_manifest_generation_rejects_duplicate_or_unknown_hosts(tmp_path: Path) -> None:
    """An ambiguous host/version identity cannot reach the deployment bundle."""
    sdk, package = _sdk(tmp_path)
    for hosts in (("claude-code", "claude-code"), ("unknown",)):
        with pytest.raises(generator.RuntimeManifestGenerationError, match="unique supported"):
            generator.build_runtime_manifest_bundle(
                sdk_root=sdk,
                package_root=package,
                sdk_version="1.1.0",
                expected_revision=REVISION,
                expected_origin_digest=ORIGIN_DIGEST,
                hosts=hosts,
            )


def test_runtime_manifest_approval_binds_exact_bundle_and_release() -> None:
    """Changing any manifest byte invalidates the separately reviewable approval digest."""
    bundle = b'[{"host":"claude-code"}]\n'
    approval = generator.build_runtime_manifest_approval(
        manifest_bundle=bundle,
        hosts=("claude-code", "codex-cli"),
        release_evidence_digest="9" * 64,
        release_tag="v1.1.0",
        sdk_revision=REVISION,
        sdk_version="1.1.0",
        source_origin_digest=ORIGIN_DIGEST,
    )

    assert approval["manifestBundleSha256"] == hashlib.sha256(bundle).hexdigest()
    assert approval["approvals"] == [
        {
            "hosts": ["claude-code", "codex-cli"],
            "releaseEvidenceSha256": "9" * 64,
            "releaseTag": "v1.1.0",
            "sdkRevision": REVISION,
            "sdkVersion": "1.1.0",
            "sourceOriginDigest": ORIGIN_DIGEST,
        }
    ]
    assert hashlib.sha256(bundle + b" ").hexdigest() != approval["manifestBundleSha256"]


def test_clean_checkout_enforcement_includes_untracked_files(tmp_path: Path) -> None:
    """Tracked, staged and untracked content all block approval measurement."""
    sdk = tmp_path / "checkout"
    sdk.mkdir()
    subprocess.run(["git", "init", "-q", str(sdk)], check=True)  # noqa: S603, S607
    subprocess.run(  # noqa: S603, S607
        [  # noqa: S607 - fixed local Git argv
            "git",
            "-C",
            str(sdk),
            "config",
            "user.email",
            "synthetic@example.invalid",
        ],
        check=True,
    )
    subprocess.run(  # noqa: S603, S607
        [  # noqa: S607 - fixed local Git argv
            "git",
            "-C",
            str(sdk),
            "config",
            "user.name",
            "Synthetic Test",
        ],
        check=True,
    )
    _write(sdk / "tracked.txt", "approved\n")
    subprocess.run(["git", "-C", str(sdk), "add", "tracked.txt"], check=True)  # noqa: S603, S607
    subprocess.run(  # noqa: S603, S607
        [  # noqa: S607 - fixed local Git argv
            "git",
            "-C",
            str(sdk),
            "commit",
            "-q",
            "-m",
            "synthetic",
        ],
        check=True,
    )
    generator.assert_clean_checkout(sdk)

    _write(sdk / "untracked.txt", "not approved\n")
    with pytest.raises(generator.RuntimeManifestGenerationError, match="clean checkout"):
        generator.assert_clean_checkout(sdk)


def test_release_verification_requires_both_attested_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The generator verifies its evidence bundle plus wheel and source provenance."""
    sdk, _ = _sdk(tmp_path)
    _write(sdk / "scripts" / "verify_release_evidence.py", "# verifier\n")
    evidence = tmp_path / "release"
    _write(evidence / "package.whl", b"wheel")
    _write(evidence / "package.tar.gz", b"source")
    _write(evidence / "SHA256SUMS", b"synthetic checksums\n")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        generator, "_run_silent", lambda command, **_kwargs: commands.append(command)
    )
    monkeypatch.setattr(
        "scripts.generate_runtime_manifests.shutil.which", lambda _name: "/synthetic/gh"
    )

    digest = generator.verify_release_inputs(
        sdk_root=sdk,
        release_evidence=evidence,
        revision=REVISION,
        tag="v1.1.0",
        repository="tommycharade/aai-sec-sdk",
    )

    assert digest == hashlib.sha256(b"synthetic checksums\n").hexdigest()
    assert len(commands) == 3
    assert commands[0][1].endswith("verify_release_evidence.py")
    assert [command[3] for command in commands[1:]] == [
        str(evidence / "package.whl"),
        str(evidence / "package.tar.gz"),
    ]
    assert all("refs/tags/v1.1.0" in command for command in commands[1:])


def test_release_verification_and_output_paths_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing subjects, GitHub CLI and symlinked outputs never degrade verification."""
    sdk, _ = _sdk(tmp_path)
    _write(sdk / "scripts" / "verify_release_evidence.py", "# verifier\n")
    evidence = tmp_path / "release"
    _write(evidence / "package.whl", b"wheel")
    _write(evidence / "SHA256SUMS", b"checksums\n")
    monkeypatch.setattr(generator, "_run_silent", lambda *_args, **_kwargs: None)
    with pytest.raises(generator.RuntimeManifestGenerationError, match="wheel and source"):
        generator.verify_release_inputs(
            sdk_root=sdk,
            release_evidence=evidence,
            revision=REVISION,
            tag="v1.1.0",
            repository="tommycharade/aai-sec-sdk",
        )

    _write(evidence / "package.tar.gz", b"source")
    monkeypatch.setattr("scripts.generate_runtime_manifests.shutil.which", lambda _name: None)
    with pytest.raises(generator.RuntimeManifestGenerationError, match="GitHub CLI"):
        generator.verify_release_inputs(
            sdk_root=sdk,
            release_evidence=evidence,
            revision=REVISION,
            tag="v1.1.0",
            repository="tommycharade/aai-sec-sdk",
        )

    target = tmp_path / "manifest.json"
    destination = tmp_path / "elsewhere.json"
    _write(destination, "do not replace\n")
    target.symlink_to(destination)
    with pytest.raises(generator.RuntimeManifestGenerationError, match="symlinked manifest"):
        generator._write_atomic(target, b"[]\n")
    assert destination.read_text(encoding="utf-8") == "do not replace\n"

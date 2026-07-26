from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_required_guardrail_files_exist() -> None:
    for path in (
        "AGENTS.md",
        "CONTRIBUTING.md",
        "README.md",
        "docs/guardrails.md",
        "pyproject.toml",
        "Makefile",
        "LICENSE",
        "NOTICE",
        "TRADEMARKS.md",
        "docs/license.md",
    ):
        assert (ROOT / path).is_file(), path


def test_guardrails_define_security_invariants() -> None:
    text = (ROOT / "docs/guardrails.md").read_text(encoding="utf-8").lower()
    for phrase in ("fail-closed", "per action", "redact", "adversarial"):
        assert phrase in text


def test_license_policy_is_explicit() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    docs_text = (ROOT / "docs/license.md").read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Creative Commons Attribution 4.0" in docs_text
    assert "commercial" in docs_text.lower()
    assert "no separate" in docs_text.lower()
    assert "commercial permission" in docs_text.lower()
    assert "branding" in docs_text.lower()


def test_generated_readme_links_resolve_from_repository_root() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "](docs/getting-started.md)" in readme
    assert "](docs/end-to-end-example.md)" in readme
    assert "](SDK-assessment.md)" in readme
    assert "](../SDK-assessment.md)" not in readme


def test_release_workflow_is_tag_bound_and_publishes_the_verified_bundle() -> None:
    """Release provenance cannot be detached from the tag or evidence bundle."""
    # mutmut runs copied tests below ``mutants/`` and may also change the
    # working directory. Discover the checkout from either stable path rather
    # than assuming the process cwd is the repository root.
    candidates = (*Path(__file__).resolve().parents, *Path.cwd().resolve().parents)
    workflow_path = next(
        parent / ".github/workflows/release-artifacts.yml"
        for parent in candidates
        if (parent / ".github/workflows/release-artifacts.yml").is_file()
    )
    workflow = workflow_path.read_text(encoding="utf-8")
    assert 'tags: ["v*.*.*"]' in workflow
    assert "workflow_dispatch" not in workflow
    assert "cp .mutmut-cache/evidence.json dist/evidence.json" in workflow
    assert "cp .mutmut-cache/results.txt dist/results.txt" in workflow
    assert "gh release create" in workflow
    assert "gh release download" in workflow
    assert '--source-ref "$GITHUB_REF"' in workflow

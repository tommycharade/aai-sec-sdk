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

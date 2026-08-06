import json
import re
from datetime import date
from pathlib import Path


def _repository_root() -> Path:
    """Locate the checkout when tests run normally or below Mutmut's copy."""
    for candidate in Path(__file__).resolve().parents:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("repository root containing .git was not found")


ROOT = _repository_root()


def test_required_guardrail_files_exist() -> None:
    for path in (
        "AGENTS.md",
        "CONTRIBUTING.md",
        "README.md",
        "docs/guardrails.md",
        "docs/enterprise-trust-pack.md",
        "docs/vulnerability-management.md",
        "docs/data-processing-and-subprocessors.md",
        "security/vulnerability-management-policy.json",
        "security/vulnerability-rehearsal.example.json",
        "pyproject.toml",
        "Makefile",
        "LICENSE",
        "NOTICE",
        "TRADEMARKS.md",
        "docs/license.md",
        "assurance/customer-assurance-pack.json",
        "docs/customer-assurance-pack.md",
        "docs/vulnerability-management.md",
        "docs/data-processing-and-subprocessors.md",
        "docs/compliance-roadmap.md",
    ):
        assert (ROOT / path).is_file(), path


def test_guardrails_define_security_invariants() -> None:
    text = (ROOT / "docs/guardrails.md").read_text(encoding="utf-8").lower()
    for phrase in ("fail-closed", "per action", "redact", "adversarial"):
        assert phrase in text


def test_quality_gate_propagates_coverage_failure() -> None:
    """A failed coverage command must make ``make check`` fail in CI."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "coverage:\n\t@set -e;" in makefile
    assert "fail_under = 90\nprecision = 2" in project


def test_mutation_workspace_copies_assurance_evidence_inputs() -> None:
    """Mutation's isolated checkout must retain assurance guardrail inputs."""
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"assurance/",' in project
    assert '"security/",' in project
    assert '"SECURITY.md",' in project
    for test_module in (
        "tests/test_customer_assurance_bundle.py",
        "tests/test_customer_assurance_pack.py",
        "tests/test_vulnerability_management.py",
    ):
        assert f'"--ignore={test_module}",' in project


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
    assert "dist/customer-assurance-pack.zip" in workflow
    assert "dist/*.tar.gz dist/customer-assurance-pack.zip" in workflow
    assert '--source-ref "$GITHUB_REF"' in workflow


def test_cdk_exception_is_exact_pinned_monitored_and_unexpired() -> None:
    """A temporary toolchain exception cannot drift or silently become permanent."""
    package = json.loads(
        (ROOT / "infra/aws-control-plane/package.json").read_text(encoding="utf-8")
    )
    development = package["devDependencies"]
    for dependency in ("aws-cdk", "aws-cdk-lib", "constructs"):
        assert re.fullmatch(r"\d+\.\d+\.\d+", development[dependency])
    assert "aws-cdk-lib" not in package.get("dependencies", {})
    assert "constructs" not in package.get("dependencies", {})

    workflow = (ROOT / ".github/workflows/cdk-upstream-watch.yml").read_text(encoding="utf-8")
    assert 'cron: "23 7 * * *"' in workflow
    assert "npm view aws-cdk-lib version" in workflow
    assert "brace-expansion/package.json" in workflow
    assert "5.0.8" in workflow

    acceptance = (ROOT / "docs/risk-acceptance-cdk-brace-expansion-2026-07-29.md").read_text(
        encoding="utf-8"
    )
    expiry_match = re.search(r"\| Expires \| (\d{4}-\d{2}-\d{2}) \|", acceptance)
    assert expiry_match is not None
    assert date.today() <= date.fromisoformat(expiry_match.group(1))
    assert "aws/aws-cdk#38410" in acceptance


def test_aws_deploy_routes_through_the_persistent_identity_guard() -> None:
    """A routine deployment cannot regress to ephemeral Entra shell variables."""
    package = json.loads(
        (ROOT / "infra/aws-control-plane/package.json").read_text(encoding="utf-8")
    )
    assert package["scripts"]["deploy"] == (
        "python3 ../../scripts/deploy_aws_control_plane.py deploy"
    )
    guard = (ROOT / "scripts/deploy_aws_control_plane.py").read_text(encoding="utf-8")
    assert "stack has Entra configured but its persistent deployment manifest is missing" in guard
    assert '"--with-decryption"' in guard

"""Contract and adversarial tests for real Claude Code host acceptance."""

from __future__ import annotations

import hashlib
import json
import platform
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from examples.ui_control_plane import _ensure_safe_default_policy
from scripts.test_real_claude_code import (
    AcceptanceExecutionError,
    _decode_stream,
    attest_binary,
    invoke_claude,
    run_acceptance,
)

from agentic_security import EnterpriseFleetStore, FleetIdentity


def _normalized_architecture() -> str:
    """Return the architecture spelling used by the acceptance matrix."""
    value = platform.machine().lower()
    if value == "aarch64":
        return "arm64"
    if value in {"x86_64", "amd64"}:
        return "x86_64"
    return value


def _write_fake_claude(path: Path, *, authenticated: bool = True) -> None:
    """Create a deterministic host-protocol fake that never executes tools."""
    auth_literal = "True" if authenticated else "False"
    source = f"""#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if "--version" in sys.argv:
    print("9.9.9 (Claude Code)")
    raise SystemExit(0)

authenticated = {auth_literal}
prompt = sys.argv[sys.argv.index("--print") + 1]
if not authenticated:
    print(json.dumps({{"type": "result", "is_error": True,
                      "terminal_reason": "api_error",
                      "result": "OAuth session expired; authenticate"}}))
    raise SystemExit(0)

decision = None
tool = None
result = ""
if "AAI_ACCEPTANCE_READY" in prompt:
    result = "AAI_ACCEPTANCE_READY"
elif "README.md" in prompt:
    decision, tool = "allow", "Read"
    result = Path("README.md").read_text(encoding="utf-8").split("=", 1)[1].strip()
elif "rm -rf" in prompt:
    decision, tool = "deny", "Bash"
    result = "denied"
elif "git push" in prompt:
    decision, tool = "ask", "Bash"
    result = "approval required"
elif "/etc/hosts" in prompt:
    decision, tool = "deny", "Read"
    result = "denied"
else:
    tool = "mcp__agentic-security__lookup_record"
    result = "record_acceptance_001"

if decision:
    output = json.dumps({{"hookSpecificOutput": {{
        "hookEventName": "PreToolUse", "permissionDecision": decision
    }}}})
    print(json.dumps({{"type": "system", "subtype": "hook_response",
                      "hook_event": "PreToolUse", "output": output}}))
if tool:
    print(json.dumps({{"type": "assistant", "message": {{"content": [{{
        "type": "tool_use", "name": tool, "input": {{"synthetic": True}}
    }}]}}}}))
print(json.dumps({{"type": "result", "is_error": False, "result": result}}))
"""
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _write_matrix(path: Path, binary: Path, *, digest: str | None = None) -> None:
    """Write an exact local support matrix for the synthetic executable."""
    measured = hashlib.sha256(binary.read_bytes()).hexdigest()
    value = {
        "schemaVersion": 1,
        "host": "claude-code",
        "defaultStatus": "unsupported",
        "versions": [
            {
                "version": "9.9.9",
                "operatingSystem": platform.system().lower(),
                "architecture": _normalized_architecture(),
                "installMethod": "synthetic-test",
                "status": "accepted",
                "binarySha256": [digest or measured],
            }
        ],
    }
    path.write_text(json.dumps(value), encoding="utf-8")


def test_exact_binary_attestation_accepts_reviewed_digest(tmp_path: Path) -> None:
    """An exact version, platform, architecture, and digest is accepted."""
    binary = tmp_path / "claude"
    matrix = tmp_path / "matrix.json"
    _write_fake_claude(binary)
    _write_matrix(matrix, binary)

    attestation = attest_binary(binary, matrix)

    assert attestation.version == "9.9.9"
    assert attestation.matrix_status == "accepted"


def test_changed_binary_is_unsupported_and_never_invoked(tmp_path: Path) -> None:
    """A digest mismatch fails before any model/tool acceptance turn."""
    binary = tmp_path / "claude"
    matrix = tmp_path / "matrix.json"
    report = tmp_path / "report.json"
    _write_fake_claude(binary)
    _write_matrix(matrix, binary, digest="0" * 64)

    exit_code = run_acceptance(
        binary,
        matrix,
        report,
        timeout_seconds=5,
        max_budget_usd=0.01,
        include_mcp=False,
    )

    evidence = json.loads(report.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert evidence["verdict"] == "unsupported_version"
    assert [item["name"] for item in evidence["checks"]] == ["binary_attestation"]


def test_native_acceptance_is_complete_and_content_free(tmp_path: Path) -> None:
    """The native host journey proves all boundaries without retaining content."""
    binary = tmp_path / "claude"
    matrix = tmp_path / "matrix.json"
    report = tmp_path / "report.json"
    _write_fake_claude(binary)
    _write_matrix(matrix, binary)

    exit_code = run_acceptance(
        binary,
        matrix,
        report,
        timeout_seconds=5,
        max_budget_usd=0.01,
        include_mcp=False,
    )

    raw = report.read_text(encoding="utf-8")
    evidence = json.loads(raw)
    assert exit_code == 0
    assert evidence["verdict"] == "passed"
    assert evidence["summary"] == {"passed": 7, "failed": 0, "blocked": 0}
    assert all(item["status"] == "passed" for item in evidence["checks"])
    assert str(tmp_path) not in raw
    assert "AAI_ACCEPTANCE_READY" not in raw
    assert "ACCEPTANCE_NONCE" not in raw
    assert "synthetic-agent" not in raw
    assert evidence["contentCaptured"] is False
    assert evidence["pathsCaptured"] is False
    assert stat.S_IMODE(report.stat().st_mode) == 0o600


def test_mcp_acceptance_starts_reference_control_plane(tmp_path: Path) -> None:
    """The default journey includes the short-lived guarded MCP boundary."""
    binary = tmp_path / "claude"
    matrix = tmp_path / "matrix.json"
    report = tmp_path / "report.json"
    _write_fake_claude(binary)
    _write_matrix(matrix, binary)

    exit_code = run_acceptance(
        binary,
        matrix,
        report,
        timeout_seconds=5,
        max_budget_usd=0.01,
        include_mcp=True,
    )

    evidence = json.loads(report.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert evidence["summary"] == {"passed": 8, "failed": 0, "blocked": 0}
    assert evidence["checks"][-1]["name"] == "guarded_mcp_lookup"
    assert evidence["checks"][-1]["status"] == "passed"


def test_reference_seed_activates_policy_idempotently(tmp_path: Path) -> None:
    """Fresh and repeated local startup retains one governed active policy."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    store.create_organization("org-example", "Example enterprise")
    operator = FleetIdentity("local-operator", "org-example", frozenset({"admin"}))

    _ensure_safe_default_policy(store, operator)
    _ensure_safe_default_policy(store, operator)

    policy = store.list_policies(operator).items[0]
    versions = store.list_policy_versions(operator, "policy-safe-default").items
    assert policy["version"] == 1
    assert policy["latestVersion"] == 1
    assert [version["state"] for version in versions] == ["active"]


def test_authentication_failure_is_reported_as_blocked(tmp_path: Path) -> None:
    """An expired Claude session cannot be mistaken for a passing host test."""
    binary = tmp_path / "claude"
    matrix = tmp_path / "matrix.json"
    report = tmp_path / "report.json"
    _write_fake_claude(binary, authenticated=False)
    _write_matrix(matrix, binary)

    exit_code = run_acceptance(
        binary,
        matrix,
        report,
        timeout_seconds=5,
        max_budget_usd=0.01,
        include_mcp=True,
    )

    raw = report.read_text(encoding="utf-8")
    evidence = json.loads(raw)
    assert exit_code == 3
    assert evidence["verdict"] == "blocked"
    assert evidence["summary"] == {"passed": 2, "failed": 0, "blocked": 6}
    assert "OAuth" not in raw
    assert "authenticate" not in raw
    assert {item["actual"] for item in evidence["checks"] if item["status"] == "blocked"} == {
        "claude_authentication_unavailable"
    }


@pytest.mark.parametrize(
    "payload",
    [b"not-json\n", b"[]\n", b"\xff\n", b"\n"],
)
def test_malformed_stream_fails_closed(payload: bytes) -> None:
    """Malformed, ambiguous, non-UTF-8, and empty host output is rejected."""
    with pytest.raises(AcceptanceExecutionError):
        _decode_stream(payload)


def test_live_process_is_stopped_at_output_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The output ceiling is enforced while the host process is active."""
    binary = tmp_path / "claude"
    project = tmp_path / "project"
    project.mkdir()
    binary.write_text(
        "#!/usr/bin/env python3\nimport sys, time\n"
        "sys.stdout.write('x' * 10000)\nsys.stdout.flush()\ntime.sleep(10)\n",
        encoding="utf-8",
    )
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr("scripts.test_real_claude_code._MAX_STREAM_BYTES", 128)

    with pytest.raises(AcceptanceExecutionError, match="bounded output limit"):
        invoke_claude(
            binary,
            project,
            "synthetic",
            tools="",
            timeout_seconds=2,
            max_budget_usd=0.01,
            environment={},
        )


def test_repository_matrix_is_default_deny_and_digest_bounded() -> None:
    """The published matrix cannot silently accept an unmeasured release."""
    matrix_path = Path(__file__).parents[1] / "docs" / "claude-code-supported-versions.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))

    assert matrix["defaultStatus"] == "unsupported"
    assert matrix["versions"]
    for release in matrix["versions"]:
        assert release["status"] == "accepted"
        assert release["binarySha256"]
        assert all(
            len(digest) == 64 and set(digest) <= set("0123456789abcdef")
            for digest in release["binarySha256"]
        )


def test_script_is_directly_executable_from_repository_root() -> None:
    """The documented script invocation resolves its sibling dependencies."""
    repository = Path(__file__).parents[1]

    result = subprocess.run(  # noqa: S603 - fixed interpreter and checked-in script
        [sys.executable, "scripts/test_real_claude_code.py", "--help"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "--version-matrix" in result.stdout
    assert result.stderr == ""

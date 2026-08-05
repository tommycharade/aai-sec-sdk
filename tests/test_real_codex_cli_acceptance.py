"""Contract and adversarial tests for real Codex CLI host acceptance."""

from __future__ import annotations

import hashlib
import json
import platform
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from scripts import test_real_codex_cli as acceptance


def _normalized_architecture() -> str:
    """Return the architecture spelling used by the acceptance matrix."""
    value = platform.machine().lower()
    if value == "aarch64":
        return "arm64"
    if value in {"x86_64", "amd64"}:
        return "x86_64"
    return value


def _write_fake_codex(path: Path) -> None:
    """Create a deterministic executable used only for binary attestation."""
    path.write_text(
        "#!/usr/bin/env python3\nimport sys\n"
        "if '--version' in sys.argv:\n print('codex-cli 9.9.9')\n raise SystemExit(0)\n"
        "raise SystemExit(91)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _write_matrix(path: Path, binary: Path, *, digest: str | None = None) -> None:
    """Write an exact local support matrix for the synthetic executable."""
    measured = hashlib.sha256(binary.read_bytes()).hexdigest()
    value = {
        "schemaVersion": 1,
        "host": "codex-cli",
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


def _invocation(
    *,
    returncode: int = 0,
    item_type: str = "agent_message",
    text: str = "",
    status: str | None = None,
) -> acceptance.CodexInvocation:
    """Build one fixed successful terminal stream without raw tool arguments."""
    item: dict[str, object] = {"type": item_type}
    if item_type == "agent_message":
        item["text"] = text
    if status is not None:
        item["status"] = status
    if item_type == "command_execution":
        item["exit_code"] = 0
    return acceptance.CodexInvocation(
        returncode,
        (
            {"type": "item.completed", "item": item},
            {"type": "turn.completed"},
        ),
        b"",
    )


def test_exact_binary_attestation_accepts_reviewed_digest(tmp_path: Path) -> None:
    """An exact version, platform, architecture, and digest is accepted."""
    binary = tmp_path / "codex"
    matrix = tmp_path / "matrix.json"
    _write_fake_codex(binary)
    _write_matrix(matrix, binary)

    result = acceptance.attest_binary(binary, matrix)

    assert result.version == "9.9.9"
    assert result.matrix_status == "accepted"


def test_changed_binary_is_unsupported_before_host_turn(tmp_path: Path) -> None:
    """A changed executable writes default-deny evidence without running a turn."""
    binary = tmp_path / "codex"
    matrix = tmp_path / "matrix.json"
    report = tmp_path / "report.json"
    _write_fake_codex(binary)
    _write_matrix(matrix, binary, digest="0" * 64)

    result = acceptance.run_acceptance(binary, matrix, report, timeout_seconds=5, include_mcp=True)

    evidence = json.loads(report.read_text(encoding="utf-8"))
    assert result == 2
    assert evidence["verdict"] == "unsupported_version"
    assert [item["name"] for item in evidence["checks"]] == ["binary_attestation"]


def test_full_journey_distinguishes_host_passes_from_managed_blocker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Passing project controls cannot conceal missing machine-level authority."""
    binary = tmp_path / "codex"
    matrix = tmp_path / "matrix.json"
    report = tmp_path / "report.json"
    _write_fake_codex(binary)
    _write_matrix(matrix, binary)
    decisions: list[str] = []

    monkeypatch.setattr(
        acceptance,
        "_inspect_effective_controls",
        lambda *_args: {
            "state": "missing",
            "reason": "administrator-requirements-missing",
            "requirementsPresent": False,
        },
    )
    monkeypatch.setattr(acceptance, "_audit_decisions", lambda _project: tuple(decisions))

    def invoke(
        _binary: Path,
        project: Path,
        prompt: str,
        **kwargs: object,
    ) -> acceptance.CodexInvocation:
        if "ACCEPTANCE_READY" in prompt:
            return _invocation(text="AAI_CODEX_ACCEPTANCE_READY")
        if "git status" in prompt:
            decisions.append("allow")
            return acceptance.CodexInvocation(
                0,
                (
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "command_execution",
                            "status": "completed",
                            "exit_code": 0,
                        },
                    },
                    {
                        "type": "item.completed",
                        "item": {"type": "agent_message", "text": "AAI_CODEX_ALLOWED_DONE"},
                    },
                    {"type": "turn.completed"},
                ),
                b"",
            )
        if "rm -rf" in prompt:
            decisions.append("deny")
            return _invocation(text="denied")
        if "git push" in prompt:
            decisions.append("ask")
            return _invocation(text="approval required")
        if "synthetic-accepted.txt" in prompt:
            marker = prompt.split("containing exactly ", 1)[1].split(" followed", 1)[0]
            (project / "synthetic-accepted.txt").write_text(f"{marker}\n", encoding="utf-8")
            decisions.append("allow")
            return _invocation(item_type="file_change", status="completed")
        if "linked-outside" in prompt:
            decisions.append("deny")
            return _invocation(text="denied")
        assert kwargs.get("mcp_override") is not None
        decisions.append("allow")
        return acceptance.CodexInvocation(
            0,
            (
                {
                    "type": "item.completed",
                    "item": {"type": "mcp_tool_call", "status": "completed"},
                },
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": "record_acceptance_001"},
                },
                {"type": "turn.completed"},
            ),
            b"",
        )

    monkeypatch.setattr(acceptance, "invoke_codex", invoke)

    result = acceptance.run_acceptance(binary, matrix, report, timeout_seconds=5, include_mcp=True)

    raw = report.read_text(encoding="utf-8")
    evidence = json.loads(raw)
    assert result == 4
    assert evidence["verdict"] == "deployment_blocked"
    assert evidence["summary"] == {"passed": 10, "failed": 0, "blocked": 1}
    assert evidence["checks"][2]["name"] == "administrator_managed_requirements"
    assert evidence["checks"][2]["status"] == "blocked"
    assert str(tmp_path) not in raw
    assert "record_acceptance_001" not in raw
    assert "AAI_CODEX_ACCEPTANCE_READY" not in raw
    assert evidence["contentCaptured"] is False
    assert evidence["credentialsCaptured"] is False
    assert stat.S_IMODE(report.stat().st_mode) == 0o600


def test_mcp_override_approves_and_exposes_only_guarded_lookup(tmp_path: Path) -> None:
    """Headless host approval cannot broaden the server's explicit tool allow-list."""
    value = acceptance._mcp_override(tmp_path)

    assert 'default_tools_approval_mode = "approve"' in value
    assert 'enabled_tools = ["lookup_record"]' in value
    assert "disabled_tools" not in value
    assert "dangerously-bypass-approvals-and-sandbox" not in value


@pytest.mark.parametrize("payload", [b"not-json\n", b"[]\n", b"\xff\n", b"\n"])
def test_malformed_stream_fails_closed(payload: bytes) -> None:
    """Malformed, ambiguous, non-UTF-8, and empty host output is rejected."""
    with pytest.raises(acceptance.AcceptanceExecutionError):
        acceptance._decode_stream(payload)


def test_failed_mcp_item_is_not_counted_as_success() -> None:
    """A completed event with failed host status cannot satisfy acceptance."""
    failed = _invocation(item_type="mcp_tool_call", status="failed")
    passed = _invocation(item_type="mcp_tool_call", status="completed")

    assert acceptance._successful_mcp_count(failed) == 0
    assert acceptance._successful_mcp_count(passed) == 1


def test_repository_matrix_is_default_deny_and_digest_bounded() -> None:
    """The published matrix cannot silently accept an unmeasured release."""
    path = Path(__file__).parents[1] / "docs" / "codex-cli-supported-versions.json"
    matrix = json.loads(path.read_text(encoding="utf-8"))

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
        [sys.executable, "scripts/test_real_codex_cli.py", "--help"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "--version-matrix" in result.stdout
    assert result.stderr == ""

"""Tests for the bounded Claude resource reconciliation helper."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parents[1] / "scripts" / "reconcile_claude_resources.py"
_SPEC = importlib.util.spec_from_file_location("reconcile_claude_resources", _MODULE_PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
reconcile = _MODULE.reconcile


def _policy(
    path: Path, *, skills: list[dict[str, object]], servers: list[dict[str, object]]
) -> None:
    path.write_text(
        json.dumps(
            {
                "policy": {
                    "configuration": {
                        "claudeCode": {"managedSkills": skills, "managedMcpServers": servers}
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def test_reconcile_installs_selected_resources_and_preserves_unmanaged_mcp(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"unmanaged": {"command": "local-tool"}}}), encoding="utf-8"
    )
    content = "# Review\nRead only.\n"
    skill: dict[str, object] = {
        "id": "review",
        "content": content,
        "digest": f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
    }
    server: dict[str, object] = {
        "id": "gateway",
        "transport": "stdio",
        "command": "python",
        "args": ["gateway.py"],
        "environmentReferences": ["TOKEN"],
    }
    policy = tmp_path / "policy.json"
    _policy(policy, skills=[skill], servers=[server])

    assert reconcile(project, policy) == {"skills": ["review"], "mcpServers": ["gateway"]}
    assert (project / ".claude/skills/review/SKILL.md").read_text(encoding="utf-8") == content
    config = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    assert set(config["mcpServers"]) == {"unmanaged", "gateway"}
    assert config["mcpServers"]["gateway"]["env"] == {"TOKEN": "${TOKEN}"}


def test_reconcile_rejects_tampered_skill(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    _policy(
        policy,
        skills=[{"id": "review", "content": "tampered", "digest": "sha256:wrong"}],
        servers=[],
    )

    with pytest.raises(ValueError, match="digest"):
        reconcile(tmp_path / "project", policy)

"""End-to-end proof that a policy-managed MCP server can serve guarded calls."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_MODULE_PATH = Path(__file__).parents[1] / "scripts" / "reconcile_claude_resources.py"
_SPEC = importlib.util.spec_from_file_location("reconcile_claude_resources_e2e", _MODULE_PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
reconcile = _MODULE.reconcile


def test_policy_managed_mcp_server_reconciles_and_executes_guarded_call(tmp_path: Path) -> None:
    """A selected MCP server is installed and its JSON-RPC calls remain policy-guarded."""
    repository_root = Path(__file__).parents[1]
    project = tmp_path / "claude-project"
    project.mkdir()
    gateway = repository_root / "examples" / "mcp_gateway.py"
    effective_policy = tmp_path / "effective-policy.json"
    effective_policy.write_text(
        json.dumps(
            {
                "policy": {
                    "id": "policy-safe",
                    "version": 1,
                    "configuration": {
                        "claudeCode": {
                            "managedSkills": [],
                            "managedMcpServers": [
                                {
                                    "id": "agentic-security",
                                    "transport": "stdio",
                                    "command": sys.executable,
                                    "args": [str(gateway)],
                                    "environmentReferences": [],
                                }
                            ],
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = reconcile(project, effective_policy)
    assert manifest == {"skills": [], "mcpServers": ["agentic-security"]}
    installed = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    assert installed["mcpServers"]["agentic-security"] == {
        "type": "stdio",
        "command": sys.executable,
        "args": [str(gateway)],
        "env": {},
    }
    assert (project / ".claude/aai-sec-managed-resources.json").exists()

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "lookup_record", "arguments": {"record_id": "record_42"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "delete_everything", "arguments": {}},
        },
    ]
    # The executable and gateway are trusted repository test fixtures.
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(gateway)],
        cwd=repository_root,
        input="\n".join(json.dumps(request) for request in requests) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    assert responses[0]["result"]["serverInfo"]["name"] == "agentic-security-gateway"
    assert responses[1]["result"]["tools"][0]["name"] == "lookup_record"
    assert responses[2]["result"]["isError"] is False
    assert responses[2]["result"]["structuredContent"]["status"] == "executed"
    assert responses[3]["result"]["isError"] is True
    assert responses[3]["result"]["structuredContent"]["status"] == "denied"

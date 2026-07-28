"""Validate a locally deployed Claude Code policy without executing actions.

The harness temporarily installs a synthetic project policy, sends synthetic
``PreToolUse`` events to the configured SDK hook, optionally creates the
corresponding enterprise policy/group records, and writes a coverage report.
It never invokes Claude, Bash, a tool handler, a credential broker, or a
network destination other than the explicitly supplied control-plane URL.

Exit codes:

* ``0``: every in-scope check passed;
* ``1``: one or more checks failed;
* ``2``: checks passed but one or more policy settings are not covered by the
  selected local surface. Use ``--allow-untested`` for hook-only smoke runs.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One deterministic policy test result."""

    name: str
    status: str
    expected: str | None
    actual: str | None
    detail: str


def _result(
    name: str, status: str, detail: str, *, expected: str | None = None, actual: str | None = None
) -> CheckResult:
    """Create a compact result with an optional expected/actual decision."""
    return CheckResult(name, status, expected, actual, detail)


def _load_object(path: Path) -> dict[str, Any]:
    """Load a JSON object or fail with an operator-facing message."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    """Write a local test policy with restrictive file permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.policy-test-{uuid.uuid4().hex}")
    try:
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _api_json(
    url: str, token: str, *, method: str = "GET", body: dict[str, Any] | None = None
) -> Any:
    """Call an explicitly configured local control-plane JSON endpoint."""
    if not url.startswith(("http://", "https://")):
        raise RuntimeError("control-plane URL must use HTTP(S)")
    request = Request(  # noqa: S310 - scheme is checked immediately above
        url, method=method, headers={"Authorization": f"Bearer {token}"}
    )
    if body is not None:
        request.add_header("Content-Type", "application/json")
        request.data = json.dumps(body).encode("utf-8")
    try:
        with urlopen(request, timeout=5) as response:  # noqa: S310 - explicit operator URL
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        detail = getattr(exc, "read", lambda: b"")()
        suffix = f": {detail.decode('utf-8', errors='replace')[:300]}" if detail else ""
        raise RuntimeError(f"control-plane request failed{suffix}") from exc


def _policy_configuration(audit_file: str) -> dict[str, Any]:
    """Build a closed, synthetic policy containing every supported section."""
    return {
        "policy": {
            "provider": "local_allow_list",
            "allowedPrincipals": ["policy-test-agent"],
            "denyByDefault": True,
        },
        "tools": {
            "allowed": ["read_repository"],
            "denied": ["delete_repository"],
            "builtIn": ["Read", "Glob", "Grep"],
            "fileTools": ["Read", "Glob", "Grep", "Edit", "Write"],
        },
        "approvals": {
            "provider": "in_memory",
            "ttlSeconds": 60,
            "requiredFor": ["write", "destructive", "external_egress"],
        },
        "budgets": {
            "maxActions": 5,
            "maxConcurrent": 1,
            "maxFanOut": 1,
            "maxCostUnits": 10,
            "maxDelegationDepth": 1,
            "maxActionsPerSecond": 1,
            "executionTimeoutSeconds": 30,
            "maxTimedOutWorkers": 1,
        },
        "credentials": {
            "enabled": False,
            "mode": "disabled",
            "scopes": [],
            "brokerEndpoint": "https://credentials.example.test/broker",
        },
        "isolation": {"verifier": "disabled", "requiredForHighRisk": True, "mode": "required"},
        "audit": {
            "provider": "jsonl",
            "path": audit_file,
            "redactSensitiveData": True,
            "captureToolContent": False,
        },
        "telemetry": {
            "enabled": True,
            "exporter": "opentelemetry",
            "redactSensitiveData": True,
            "captureToolContent": False,
        },
        "claudeCode": {
            "enabled": True,
            "allowedBuiltInTools": ["Read", "Glob", "Grep"],
            "deniedCommandPatterns": [r"rm\s+-rf", r"sudo"],
            "approvalCommandPatterns": [r"git\s+push", r"npm\s+publish"],
            "fileTools": ["Read", "Glob", "Grep", "Edit", "Write"],
        },
    }


def _hook_configuration(audit_file: str) -> dict[str, Any]:
    """Build the project-scoped configuration consumed by the Claude hook."""
    return {
        "version": 1,
        "allowedTools": ["Read", "Glob", "Grep"],
        "deniedCommandPatterns": [r"(^|\s)rm\s+-rf(\s|$)", r"(^|\s)sudo(\s|$)"],
        "approvalCommandPatterns": [r"\bgit\s+push\b", r"\bnpm\s+publish\b"],
        "allowedCommandPatterns": [r"^git[ \t]+status([ \t]|$)", r"^pwd([ \t]|$)"],
        "fileTools": ["Read", "Glob", "Grep", "Edit", "Write"],
        "auditFile": audit_file,
    }


def _event(
    tool_name: str, tool_input: dict[str, Any], tool_use_id: str, project_root: Path
) -> dict[str, Any]:
    """Build a synthetic Claude event with no model-controlled authority."""
    return {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
        "session_id": "policy-test-session",
        "cwd": str(project_root),
    }


def _run_hook(hook_path: Path, project_root: Path, events: list[str]) -> list[dict[str, Any]]:
    """Run the hook in a bounded subprocess and parse only JSON stdout."""
    environment = os.environ.copy()
    environment["CLAUDE_PROJECT_DIR"] = str(project_root)
    # Bind the child to the selected checkout exactly as onboarding does. An
    # ambient editable install must not replace the hook implementation under
    # test or make release evidence depend on another local repository.
    environment["PYTHONPATH"] = str(hook_path.parent.parent / "src")
    # Mutmut's instrumented package reads its checked-in configuration when a
    # child trampoline starts. Keep that child at the selected mutation
    # checkout while CLAUDE_PROJECT_DIR and each event continue to supply the
    # synthetic project boundary under test.
    selected_checkout = hook_path.parent.parent
    mutation_metadata = selected_checkout / "src" / "agentic_security" / "claude_code.py.meta"
    child_directory = selected_checkout if mutation_metadata.is_file() else project_root
    completed = subprocess.run(  # noqa: S603 - hook path is derived from the selected SDK checkout
        [sys.executable, str(hook_path)],
        input="\n".join(events) + "\n",
        capture_output=True,
        text=True,
        cwd=child_directory,
        env=environment,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Claude hook exited {completed.returncode}: {completed.stderr[-500:]}")
    responses: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Claude hook returned a non-object response")
        responses.append(value)
    if len(responses) != len(events):
        raise RuntimeError(
            f"Claude hook returned {len(responses)} responses for {len(events)} events"
        )
    return responses


def _decision(response: dict[str, Any]) -> str:
    """Extract Claude's native permission decision from a hook response."""
    return str(response.get("hookSpecificOutput", {}).get("permissionDecision", "missing"))


def _check_hook(hook_path: Path, project_root: Path, audit_file: Path) -> list[CheckResult]:
    """Exercise every setting that the native Claude hook can enforce."""
    cases = [
        (
            "claude.allowedTools.Read",
            _event(
                "Read", {"file_path": str(project_root / "README.md")}, "allowed-read", project_root
            ),
            "allow",
        ),
        (
            "claude.allowedTools.Edit",
            _event(
                "Edit", {"file_path": str(project_root / "README.md")}, "denied-edit", project_root
            ),
            "deny",
        ),
        (
            "claude.allowedCommandPatterns",
            _event("Bash", {"command": "git status"}, "allowed-status", project_root),
            "allow",
        ),
        (
            "claude.approvalCommandPatterns",
            _event("Bash", {"command": "git push origin main"}, "approval-push", project_root),
            "ask",
        ),
        (
            "claude.deniedCommandPatterns",
            _event("Bash", {"command": "rm -rf /tmp/policy-test"}, "denied-rm", project_root),
            "deny",
        ),
        (
            "claude.fileTools.pathBoundary",
            _event("Read", {"file_path": "/etc/hosts"}, "denied-outside", project_root),
            "deny",
        ),
        (
            "claude.unknownTool.failClosed",
            _event("UnknownTool", {}, "denied-unknown", project_root),
            "deny",
        ),
    ]
    events = [json.dumps(item[1]) for item in cases] + ["{malformed"]
    try:
        responses = _run_hook(hook_path, project_root, events)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        return [_result("claude.hook.process", "failed", str(exc))]
    results: list[CheckResult] = []
    for (name, _payload, expected), response in zip(cases, responses[: len(cases)], strict=True):
        actual = _decision(response)
        results.append(
            _result(
                name,
                "passed" if actual == expected else "failed",
                "decision matches expected policy",
                expected=expected,
                actual=actual,
            )
        )
    malformed = _decision(responses[-1])
    results.append(
        _result(
            "claude.malformedInput.failClosed",
            "passed" if malformed == "deny" else "failed",
            "malformed hook input must deny",
            expected="deny",
            actual=malformed,
        )
    )
    if not audit_file.exists():
        results.append(
            _result("claude.auditFile", "failed", f"audit file was not created at {audit_file}")
        )
    else:
        try:
            audit_lines = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            valid = all(
                isinstance(item, dict) and item.get("event_type") == "claude_pre_tool_decision"
                for item in audit_lines
            )
            results.append(
                _result(
                    "claude.auditFile",
                    "passed" if valid and len(audit_lines) >= len(cases) else "failed",
                    f"{len(audit_lines)} redacted decision event(s) recorded",
                )
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            results.append(_result("claude.auditFile", "failed", f"audit file is invalid: {exc}"))
    return results


def _check_settings(settings_path: Path) -> CheckResult:
    """Verify the project has a Claude PreToolUse hook pointing at this SDK."""
    try:
        settings = _load_object(settings_path)
        entries = settings.get("hooks", {}).get("PreToolUse", [])
        commands = [
            hook.get("command", "")
            for entry in entries
            if isinstance(entry, dict)
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict)
        ]
        configured = any("claude_code_hook.py" in command for command in commands)
        return _result(
            "claude.projectHookConfigured",
            "passed" if configured else "failed",
            "SDK Claude PreToolUse hook is configured"
            if configured
            else "no claude_code_hook.py command found",
        )
    except RuntimeError as exc:
        return _result("claude.projectHookConfigured", "failed", str(exc))


def _check_control_plane(
    base_url: str,
    token: str,
    policy_id: str,
    group_id: str,
    deployment_id: str | None,
    agent_id: str | None,
    configuration: dict[str, Any],
) -> list[CheckResult]:
    """Create and verify the enterprise policy and optional group assignment."""
    results: list[CheckResult] = []
    try:
        policy = _api_json(
            f"{base_url.rstrip('/')}/enterprise/policies",
            token,
            method="POST",
            body={
                "policyId": policy_id,
                "name": "Claude local policy test",
                "configuration": configuration,
            },
        )
        same = policy.get("id") == policy_id and policy.get("configuration") == configuration
        results.append(
            _result(
                "controlPlane.policy.createAndRoundTrip",
                "passed" if same else "failed",
                "enterprise policy created and configuration round-tripped",
            )
        )
    except RuntimeError as exc:
        results.append(_result("controlPlane.policy.createAndRoundTrip", "failed", str(exc)))
        return results
    try:
        group = _api_json(
            f"{base_url.rstrip('/')}/enterprise/groups",
            token,
            method="POST",
            body={
                "groupId": group_id,
                "name": "Claude local policy test group",
                "policyId": policy_id,
            },
        )
        results.append(
            _result(
                "controlPlane.group.policyBinding",
                "passed" if group.get("policyId") == policy_id else "failed",
                "group is bound to the test policy",
            )
        )
    except RuntimeError as exc:
        results.append(_result("controlPlane.group.policyBinding", "failed", str(exc)))
        return results
    if deployment_id and agent_id:
        try:
            member = _api_json(
                f"{base_url.rstrip('/')}/enterprise/groups/{group_id}/agents",
                token,
                method="POST",
                body={"deploymentId": deployment_id, "agentId": agent_id},
            )
            enrolled = any(
                item.get("id") == agent_id and item.get("deployment_id") == deployment_id
                for item in member.get("agents", [])
            )
            results.append(
                _result(
                    "controlPlane.group.agentMembership",
                    "passed" if enrolled else "failed",
                    "test agent enrolled in the policy group",
                )
            )
        except RuntimeError as exc:
            results.append(_result("controlPlane.group.agentMembership", "failed", str(exc)))
    else:
        results.append(
            _result(
                "controlPlane.group.agentMembership",
                "not_tested",
                "pass --deployment-id and --agent-id to verify live group membership",
            )
        )
    return results


def _untested_runtime_checks() -> list[CheckResult]:
    """Report controls that require GuardedRuntime/MCP, not a native hook."""
    return [
        _result(name, "not_tested", detail)
        for name, detail in [
            (
                "runtime.budgets",
                "requires a GuardedRuntime/MCP execution test; Claude hooks do not own "
                "action budgets",
            ),
            ("runtime.credentials", "requires an application-owned credential broker test"),
            (
                "runtime.isolation",
                "requires deployment isolation evidence and verifier integration",
            ),
            ("runtime.auditSinks", "requires the selected durable/replicated sink adapter"),
            ("runtime.telemetry", "requires an OpenTelemetry exporter integration test"),
            ("runtime.idempotency", "requires a repeated MCP action execution test"),
        ]
    ]


def run(args: argparse.Namespace | SimpleNamespace) -> int:
    """Run the local policy test and print or save the coverage report."""
    project_root = args.project_root.expanduser().resolve()
    sdk_root = args.sdk_root.expanduser().resolve()
    hook_path = sdk_root / "examples" / "claude_code_hook.py"
    policy_path = project_root / ".claude" / "aai-sec-config.json"
    audit_path = project_root / ".claude" / "policy-test-audit.jsonl"
    settings_path = project_root / ".claude" / "settings.json"
    if not hook_path.is_file():
        raise RuntimeError(f"SDK hook not found: {hook_path}")
    policy_id = args.policy_id or f"policy-claude-test-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    group_id = f"group-{policy_id}"
    hook_config = _hook_configuration(".claude/policy-test-audit.jsonl")
    enterprise_config = _policy_configuration(".claude/policy-test-audit.jsonl")
    previous_policy = policy_path.read_bytes() if policy_path.exists() else None
    previous_audit = audit_path.read_bytes() if audit_path.exists() else None
    results: list[CheckResult] = []
    try:
        _write_json(policy_path, hook_config)
        audit_path.unlink(missing_ok=True)
        results.append(_check_settings(settings_path))
        results.extend(_check_hook(hook_path, project_root, audit_path))
        if args.control_plane_url:
            if not args.operator_token:
                raise RuntimeError(
                    "--operator-token or AAI_SEC_UI_TOKEN is required with --control-plane-url"
                )
            results.extend(
                _check_control_plane(
                    args.control_plane_url,
                    args.operator_token,
                    policy_id,
                    group_id,
                    args.deployment_id,
                    args.agent_id,
                    enterprise_config,
                )
            )
        else:
            results.append(
                _result(
                    "controlPlane.policy.createAndRoundTrip",
                    "not_tested",
                    "pass --control-plane-url to create and verify the enterprise policy record",
                )
            )
        results.extend(_untested_runtime_checks())
    finally:
        if args.keep_config:
            print(f"Kept test policy at {policy_path}", file=sys.stderr)
        elif previous_policy is None:
            policy_path.unlink(missing_ok=True)
        else:
            policy_path.write_bytes(previous_policy)
        if previous_audit is None:
            audit_path.unlink(missing_ok=True)
        else:
            audit_path.write_bytes(previous_audit)
    failed_count = sum(item.status == "failed" for item in results)
    not_tested_count = sum(item.status == "not_tested" for item in results)
    report = {
        "projectRoot": str(project_root),
        "policyId": policy_id,
        "groupId": group_id,
        "results": [asdict(item) for item in results],
        "summary": {
            "passed": sum(item.status == "passed" for item in results),
            "failed": failed_count,
            "notTested": not_tested_count,
        },
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    if failed_count:
        return 1
    if not_tested_count and not args.allow_untested:
        return 2
    return 0


def main() -> int:
    """Parse CLI arguments and run the bounded local test."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd(), help="Claude project root")
    parser.add_argument(
        "--sdk-root", type=Path, default=Path(__file__).resolve().parents[1], help="SDK checkout"
    )
    parser.add_argument(
        "--control-plane-url", help="Enterprise API base, for example http://localhost:8001/api"
    )
    parser.add_argument(
        "--operator-token",
        default=os.environ.get("AAI_SEC_UI_TOKEN"),
        help="Control-plane operator token",
    )
    parser.add_argument("--deployment-id", help="Live enterprise deployment to enroll")
    parser.add_argument(
        "--agent-id", default="claude-code-local", help="Live Claude agent identity"
    )
    parser.add_argument(
        "--policy-id", help="Stable policy ID; a unique test ID is generated by default"
    )
    parser.add_argument("--report", type=Path, help="Write the JSON report to this path")
    parser.add_argument(
        "--keep-config",
        action="store_true",
        help="Leave the synthetic project policy installed after testing",
    )
    parser.add_argument(
        "--allow-untested",
        action="store_true",
        help="Return success for hook-only runs with runtime controls not tested",
    )
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Policy test could not run: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

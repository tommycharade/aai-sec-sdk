# Real Claude Code acceptance evidence

**Test date:** 2026-07-27
**Claude Code:** 2.1.220
**Host:** operator device, macOS arm64
**AWS region:** `eu-west-2`
**Control plane:** deployed AWS API Gateway/Lambda control plane
**Scope:** disposable synthetic projects only

No production repository, credential, destructive command or unredacted
personal data was used. SIEM/PagerDuty/SOC integration was intentionally
deferred for the rollout goal.

## Results

| Capability | Result | Evidence |
| --- | --- | --- |
| Project-scoped onboarding | Pass | Generated `.claude/settings.json`, `.claude/aai-sec-config.json` and `.mcp.json`; existing config preservation and no token in files verified |
| Real native allowed action | Pass | Actual Claude `PreToolUse:Read` hook returned `allow`; Claude read `README.md` |
| Real native denied action | Pass | Actual Claude `PreToolUse:Bash` hook returned `deny` for `rm -rf`; marker was not created |
| Real native approval boundary | Pass | Actual Claude `PreToolUse:Bash` hook returned `ask` for `git push origin main`; non-interactive session did not run it |
| AWS enrollment | Pass | One-time bootstrap exchange returned a short-lived deployment/agent-bound session |
| Central policy lookup | Pass | Real AWS agent session resolved a centrally assigned policy and Claude native hook used it |
| AWS MCP connection | Pass | Claude stream reported `agentic-security` MCP server status `connected` |
| Real MCP tool execution | Pass | Claude invoked `mcp__agentic-security__lookup_record` and received the synthetic record response |
| MCP heartbeat | Pass | DynamoDB `last_heartbeat` advanced from `1785159021` to `1785159179` during the Claude session |
| Central rollout and drift | Pass | Live AWS API staged a deployment, reported drift, moved it to 10% canary, then 100% active with matching desired/applied hashes |
| Emergency stop | Pass | AWS agent stop returned HTTP 200; a real Claude `Read` received a fail-closed denial while stopped |
| Emergency recovery | Pass | Stop clear returned HTTP 200; the same real Claude `Read` returned `allow` and executed after recovery |
| Local audit evidence | Pass | Three native decisions were written to `.claude/security-audit.jsonl` with chained hashes |
| AWS control-plane security boundary | Pass | Deployed smoke passed auth, enrollment, heartbeat, policy, approval replay, emergency stop/recovery, durable idempotency and WORM audit checks |

## Defects found and fixed

### Invalid generated `env` command

The onboarding script generated `env NAME VALUE`, which is not valid POSIX
environment assignment syntax. The real Claude hook therefore failed before
reaching central policy lookup. It now generates `env NAME=VALUE ...`, and a
regression test verifies the tokenized command.

### Integer policy version serialized as a float

The AWS Lambda JSON boundary converted DynamoDB `Decimal("1")` to `1.0`.
The MCP gateway correctly rejected that as an invalid typed policy version.
The Lambda now preserves integral decimals as JSON integers, with a contract
test covering integral and fractional values. The fix was deployed to the AWS
control plane before the successful MCP run.

### Initial AWS MCP presence heartbeat

AWS enrollment marks an agent connected, but the running MCP process must also
prove presence. AWS-mode `ControlPlaneAgentClient.register()` now sends an
immediate authenticated heartbeat before the gateway serves tools. The
heartbeat advanced during the successful real Claude MCP session.

### Incomplete AWS rollout read path

The first live rollout exercise showed that the AWS adapter stored staged
configuration but returned an empty drift collection. The derived drift route
was querying an unused entity type. The route now returns tenant-scoped
configuration records whose desired and applied hashes differ. The deployed
live exercise then observed `staged`/drifted, `canary` at 10%, and `active` at
100% with matching hashes.

## Remaining limitations

This is strong real-host acceptance evidence, not a blanket enterprise
production certification. The following remain deployment-owned launch gates:

- production SSO/federation, mandatory MFA and final enterprise RBAC review;
- real credential-broker and per-tool IAM evidence for consequential tools;
- process-supervisor credential revocation and termination proof for production
  emergency stop;
- target-fleet load, convergence SLO and control-plane DR exercises;
- stronger isolation evidence for hostile-code workloads;
- SIEM/PagerDuty/SOC routing, intentionally deferred to a later goal.

The tested device path is suitable for a controlled Claude Code design-partner
rollout using synthetic/read-only actions while those deployment-owned gates
are completed.

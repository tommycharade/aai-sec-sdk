# Real Claude Code acceptance harness

The real-host acceptance harness closes the gap between deterministic hook
unit tests and evidence from an installed Claude Code process. It invokes only
an exact, reviewed Claude Code binary against a disposable synthetic project
and produces a content-free JSON report.

This is host compatibility evidence. It is not an Anthropic certification, a
penetration test, MDM evidence, or proof that a production repository is safe.

## What it proves

One successful default run proves all of these observations through the real
Claude Code JSON-stream boundary:

| Check | Required observation |
| --- | --- |
| Binary attestation | Version, OS, architecture and SHA-256 match the reviewed matrix |
| Project onboarding | Hook, policy and MCP files are separate and contain no agent token |
| Claude authentication | A bounded no-tool turn reaches the Claude service |
| Allowed native read | `Read` is allowed, invoked and returns the random synthetic marker |
| Denied command | `rm -rf` is denied and the disposable target remains present |
| Approval boundary | `git push origin main` returns `ask`; a PATH shim proves Git was not invoked |
| Project scope | Reading `/etc/hosts` is denied before execution |
| Guarded MCP lookup | Claude connects to the localhost reference gateway and invokes the guarded synthetic tool |

The denied and approval scenarios operate only inside a newly created
temporary directory. The Git shim records invocation but cannot push. The MCP
scenario uses a short-lived loopback control plane, random synthetic bearer
values and the repository's synthetic `lookup_record` handler.

## Supported host matrix

The machine-readable [Claude Code supported-version
matrix](claude-code-supported-versions.json) is default deny. A release is
accepted only when all four values match an entry:

- Claude Code version;
- operating system;
- architecture; and
- SHA-256 of the resolved native executable.

The initial accepted host is native Claude Code `2.1.220` on macOS arm64 with
the exact digest recorded in the matrix. A same-version binary with different
bytes is unsupported until its provenance and behavior are reviewed and a
separate digest is added. Other operating systems, architectures, installers
and Claude versions are unsupported by this harness until measured evidence is
added. This narrow matrix does not prevent an operator from using another
Claude release; it prevents untested releases from producing a passing AAI
acceptance artifact.

## Run it

Authenticate Claude Code first, then run from the SDK checkout:

```bash
claude auth login
python3 scripts/test_real_claude_code.py \
  --report /tmp/aai-real-claude-acceptance.json
```

The default run may make up to six low-effort model invocations. Each
invocation has a 90-second timeout and a maximum model budget of USD 0.25. Use
`--max-budget-usd` to reduce that per-invocation ceiling and
`--timeout-seconds` to reduce the timeout. Both options have hard upper bounds.
Use `--skip-mcp` only when intentionally testing the native-tool boundary; the
MCP check is then absent, never reported as passed.

Exit codes are stable:

| Code | Meaning |
| --- | --- |
| `0` | Every requested observation passed |
| `1` | Configuration, protocol, safety or acceptance failure |
| `2` | Exact binary is unsupported by the reviewed matrix |
| `3` | External prerequisite is unavailable, such as expired Claude authentication |

Treat codes `1`, `2` and `3` as non-passing. A blocked report is useful
diagnostic evidence but cannot satisfy a rollout gate.

## Evidence and data handling

The report contains only fixed check names and outcomes, observation digests,
host version/platform, executable digest and size, SDK version, counts and the
overall verdict. It records explicit `contentCaptured`, `pathsCaptured` and
`credentialsCaptured` flags as `false`.

Prompts, tool arguments, model responses, hook payloads, credentials and file
paths are inspected only in bounded process memory. They are not written to
the report. The report is atomically created with mode `0600`. Claude stdout
and stderr are held in temporary files, size checked before parsing and
discarded when each invocation ends. The runner never uses a shell and kills
the complete subprocess group on timeout.

Do not point the harness at a production project. It deliberately ignores an
operator-supplied project root and always creates its own synthetic project.

## Trust boundary and failure behavior

The local operator and installed executable remain trusted. Exact binary
measurement detects an unreviewed binary before model invocation, but it is
not hardware-backed attestation and cannot defeat an administrator modifying
the host during execution. Project-only setting sources, strict MCP
configuration, disabled slash commands and an explicit tool list reduce
ambient Claude configuration; they do not sandbox the Claude process.

Malformed JSON streams, duplicate or missing terminal results, oversized
output, unsupported binaries, invalid onboarding, timeouts and absent
authentication fail closed. Provider text is inspected in memory only to map
authentication/service failure to a fixed reason code. It is never retained
as evidence.

The localhost MCP test proves the checked-in integration boundary. It does not
prove AWS availability, central policy rollout, production credentials,
durable audit, isolation, emergency response or fleet convergence. Those
remain separate acceptance exercises in the [enterprise Claude Code rollout
plan](enterprise-claude-rollout-plan.md).

## Adding a supported release

Do not widen the matrix from a version string alone. For each new tuple:

1. obtain the native executable through the approved release channel;
2. record installer/provenance evidence and independently measure SHA-256;
3. run this harness successfully on the exact OS and architecture;
4. run `make check`;
5. add a dated evidence page and link it from the matrix; and
6. obtain normal code review for the matrix change.

Removal or deprecation is a reviewed matrix change. Existing historical
reports remain evidence of what was tested at that time; they do not make a
removed release currently supported.

# Real Claude Code acceptance evidence — 2026-08-05

**Result:** blocked by expired Claude authentication; no acceptance pass

**Installed host:** Claude Code `2.1.220`, native macOS arm64

**Scope:** disposable synthetic project and content-free evidence only

## Observed result

The new repeatable host harness was run against the installed Claude Code
binary. Exact binary attestation and generated project onboarding passed. The
bounded no-tool preflight reached Claude's JSON-stream protocol, which reported
that the local OAuth session was unavailable. The runner exited with code `3`
and marked every model/tool-dependent check `blocked`; it did not report any of
them as passed.

| Check | Result | Fixed observation |
| --- | --- | --- |
| Exact binary attestation | Pass | `accepted` |
| Project onboarding | Pass | `verified` |
| Claude authentication | Blocked | `claude_authentication_unavailable` |
| Allowed native read | Blocked | `claude_authentication_unavailable` |
| Denied command | Blocked | `claude_authentication_unavailable` |
| Approval boundary | Blocked | `claude_authentication_unavailable` |
| Project-scope denial | Blocked | `claude_authentication_unavailable` |
| Guarded MCP lookup | Blocked | `claude_authentication_unavailable` |

Summary: 2 passed, 0 failed, 6 blocked. The report was written atomically with
mode `0600`. Inspection confirmed that it contained no home-directory path,
prompt marker or synthetic agent token. Its content/path/credential capture
flags were all `false`.

The exact accepted executable measurement was:

- size: `256908272` bytes;
- SHA-256: `8addc857f3fe64d5a0368af9ee50321b50afb4a6918ba3ef018ab84f5dbbe081`.

## Reproduce after authentication

```bash
claude auth login
python3 scripts/test_real_claude_code.py \
  --report /tmp/aai-real-claude-acceptance-2026-08-05.json
```

A successful rerun must exit `0` and show no failed or blocked checks. This
evidence page must then be updated with the new observation; the historical
manual evidence from 2026-07-27 does not substitute for that rerun.

## Deterministic supporting evidence

Thirteen focused tests passed for exact attestation, changed-binary rejection,
native allow/deny/approval/scope observations without executing tools,
authentication blocking, malformed-stream denial, restrictive matrix shape,
live output bounds, content minimisation, report permissions, direct CLI
invocation and governed reference-control-plane startup.

This blocked run is honest diagnostic evidence, not enterprise rollout
approval. Production SSO, MDM, credentials, isolation, fleet convergence,
resilience and other deployment-owned gates remain separate. Splunk delivery
remains deferred and stubbed.

# Runtime attestation design

Runtime attestation closes the gap between **a bearer sent a heartbeat** and
**the approved Claude Code or Codex security runtime is still running in its
approved state**. It is the implementation design for P0-05 in the
[enterprise rollout requirements](enterprise-rollout-p0-p1-requirements.md).

## Trust boundary

The host measures the installed SDK package, MCP gateway, native security hook,
project configuration, Python executable, project scope, source origin/revision
and launch context. Only SHA-256 identifiers and bounded metadata leave the
host. No source, configuration content, local path, prompt, command, credential
or result is captured.

Measurement is not approval. The control plane must compare invariant artifact
digests to a deployment-owned manifest that was independently verified against
the signed release provenance. Project-specific executable, configuration and
launch-context digests are bound on the first compliant enrollment and must
remain exact thereafter.

Every heartbeat follows this sequence:

```text
authenticated session -> one-time server challenge -> local measurement
                      -> exact manifest/baseline comparison -> posture update
                      -> heartbeat accepted or session quarantined/revoked
```

The nonce and short observation window prevent replaying an old compliant
measurement. A missing, expired, malformed or mismatched attestation fails
closed. Quarantined agents cannot retrieve effective policy, request approval
or report a consequential governed action until they are remediated and
re-enrolled.

The repository intentionally ships with an empty
`infra/aws-control-plane/lambda/runtime-manifests.json`. In that state the
control plane records `not_configured`, operator verification fails its runtime
attestation check, and no production trust claim is made. Governed agent routes
retain their pre-attestation compatibility until an approved manifest exists.
Production rollout must replace the empty bundle with independently verified
manifests before enrolling agents. Once a matching host/version manifest is
configured, attestation becomes mandatory and fail-closed for that runtime.

## Evidence fields

| Evidence | Purpose |
| --- | --- |
| SDK version and Git revision | Identifies the intended release/source state. |
| Source-origin digest | Detects a checkout from an unapproved repository without exposing its URL. |
| Installed package digest | Detects changed Python enforcement code. |
| Gateway and native-hook digests | Detects changes at the MCP and native-tool enforcement points. |
| Configuration digest | Detects project policy/configuration tampering. |
| Executable and launch-context digests | Detects a changed interpreter or unexpected launch path/context. |
| Project-root digest | Binds evidence to the immutable enrolled checkout. |
| Observation time and nonce | Proves freshness and prevents replay. |

## Guarantees and limitations

This control detects accidental or adversarial file/configuration changes when
the attestor remains inside the trusted execution path. It binds runtime
posture to enrollment and makes reason codes, freshness and quarantine events
centrally auditable.

Software-only attestation cannot prove host integrity against an attacker with
root/administrator control who can alter the attestor itself or forge process
memory. Enterprise production should pair this control with endpoint
management and a hardware-backed device/workload identity (TPM, Secure Enclave,
managed workload certificate or equivalent). That limitation must remain
visible in acceptance evidence; a compliant software measurement is not device
attestation.

## Acceptance plan

1. Verify a release wheel/source archive and its GitHub provenance, then pin
   the resulting manifest at deployment.
2. Enroll one synthetic Claude Code and one Codex pilot with immediate
   nonce-bound attestation.
3. Modify the package, gateway, native hook, project configuration and launch
   executable independently. Each change must quarantine the agent within five
   minutes and emit a content-minimised reason code.
4. Prove stale/replayed evidence is denied and its session cannot fetch an
   effective policy or submit a governed approval/action.
5. Restore approved artifacts, re-enroll and prove posture recovery without
   deleting the audit history.

The current automated contracts prove comparison, replay, freshness, baseline,
quarantine and session-revocation behavior. Live release-manifest, five-minute
detection and host-identity acceptance remain required before P0-05 can be
marked complete.

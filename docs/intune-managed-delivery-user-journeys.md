# Microsoft Intune managed delivery user journeys

## Journey 1 — prepare the customer tenant

**Actor:** Microsoft 365 platform administrator

1. Create separate read-only discovery and delivery application identities.
2. Grant only the reviewed Microsoft Graph application permissions.
3. Upload each signed Claude Code or Codex package to Intune and retain its
   mobile-app ID outside source control.
4. Store the delivery credential and package-ID mapping in the approved
   tenant-tagged AWS Secrets Manager namespace.
5. Create or authorize only the dedicated AAI rollout-group namespace; do not
   nominate a general-purpose customer group.
6. Retain the change and approval evidence.

No secret value, package byte or Graph request body is pasted into the UI.

## Journey 2 — register and independently approve Intune delivery

**Actor:** platform administrator and independent approver

1. Open **Integrations → Microsoft Intune → Hosted delivery**.
2. Enter only the secret ARN, canonical Microsoft tenant ID, explicit pilot
   deployments, permission-evidence digest and rationale.
3. Create the draft. The server validates the exact tenant namespace, tags,
   dedicated KMS key and referenced deployments without reading the secret.
4. Review the exact affected deployments, permission evidence and
   immutable configuration digest.
5. Submit for approval.
6. A different authorized person approves the exact revision.
7. Activate one non-production deployment and leave all others outside the
   explicit configuration scope.

The API lifecycle is implemented; this Integrations workspace is the next UI
slice. Activation currently enables dormant outbox creation only, not Graph
dispatch.

Editing the configuration invalidates approval and returns it to draft.

## Journey 3 — resolve delivery blockers

**Actor:** fleet engineer

1. Open **Rollouts → Runtime releases → Delivery readiness**.
2. Select the pilot deployment.
3. Confirm separate green states for release, package, endpoint binding,
   directory target and provider configuration.
4. If directory target is missing, open **Fleet → Coverage** and refresh the
   Intune source; never type or force-map a device ID.
5. If package identity is missing, return to the release pipeline and Intune
   app registration; never substitute an app in the rollout dialog.
6. Continue only when the complete canary cohort is ready.

## Journey 4 — start a canary

**Actor:** fleet engineer

1. Start the normal revision-bound runtime canary.
2. The control plane derives the cohort and commits exact dormant outbox jobs
   automatically.
3. Until the worker phase is enabled, confirm the command says **Dispatch
   disabled**. After worker acceptance, watch the provider progression: queued,
   resolving targets, converging members, converging assignment and assigned
   reported.
4. Treat assigned reported as **Awaiting runtime attestation**.
5. Expand only after the exact target release is freshly attested and rollout
   health remains inside the approved bounds.

There is no per-agent **Install** button.

## Journey 5 — investigate provider uncertainty

**Actor:** security operations engineer

1. Open the affected rollout and select the provider event.
2. Review the fixed reason, attempt count, desired-state digest and last
   independently reproduced Graph state.
3. For a timeout or throttle, allow bounded reconciliation; do not create a
   second manual assignment.
4. For changed authority, correct the source and start a new rollout revision.
5. For credential revocation, keep dispatch disabled until a new exact
   configuration revision is independently approved.

Raw Graph payloads, tokens and device names are never shown.

## Journey 6 — roll back

**Actor:** fleet engineer and required approver

1. Pause the rollout and select rollback to the retained known-good release.
2. The previous target instruction becomes stale immediately.
3. The server derives a new cohort/package/assignment desired state.
4. The worker reconciles only AAI-owned group membership and assignments,
   preserving unrelated customer state.
5. Provider convergence remains **Awaiting runtime attestation**.
6. Close rollback only after every frozen endpoint freshly attests the retained
   release.

## Journey 7 — complete first-customer acceptance

**Actor:** product owner, platform engineer and security assessor

1. Exercise Claude Code and Codex on genuinely managed pilot devices.
2. Test install, canary expansion, pause, rollback, provider outage, timeout,
   throttling, duplicate delivery, credential rotation and revocation.
3. Inject target and assignment drift and prove the reconciler fails closed or
   restores only AAI-owned state.
4. Verify that provider success alone never completes a rollout.
5. Retain content-minimised audit, provider and runtime-attestation evidence.
6. Approve hosted delivery only when the acceptance harness exits zero.

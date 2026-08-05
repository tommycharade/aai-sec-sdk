# Managed endpoint delivery user journeys

These journeys describe the lowest-friction path from approved runtime release
to verified managed endpoint. They preserve the separation between approval,
delivery-channel observation and runtime proof.

## Journey 1 — prepare an approved delivery package

**Actor:** release engineer

1. Build the SDK, MCP gateway and native hook from a clean tagged checkout.
2. Verify checksums, SBOM, provenance and the approved runtime manifest.
3. Produce the operating-system package and verify its signature.
4. Upload it to the approved versioned S3 release bucket.
5. Generate the secret-free delivery manifest and separate approval bundle.
6. Run the guarded deployment preflight; malformed, partial or mismatched
   authority stops before CDK synthesis.
7. Deploy the reviewed bundle.
8. Open **Rollouts → Runtime releases** and confirm **Package ready** for the
   intended host/platform.

The engineer never uploads executable bytes through the web UI.
Until signed endpoint evidence identifies a distribution/package manager, the
bundle must contain only one package format for each exact
release/operating-system/architecture tuple.

## Journey 2 — resolve endpoint identity before rollout

**Actor:** fleet engineer

1. Open **Rollouts → Runtime releases → Delivery readiness**.
2. Select a deployment.
3. Review endpoint rows grouped by safe next action.
4. For missing endpoint or platform evidence, open **Fleet → Coverage** and
   restore the Intune/device source or deploy sensor schema v2.
5. For **Installation identity is not unique** or **Agent matches more than one
   managed device**, correct the duplicate authority in endpoint management and
   enrollment inventory.
6. Return to Delivery readiness and refresh.
7. Continue only when each canary endpoint shows one package and a unique
   current device/install/agent binding.

No manual “force bind” control exists. Ambiguity is corrected at its source.

## Journey 3 — start and observe a canary

**Actor:** fleet engineer

1. From a ready deployment, choose **Change release**.
2. Review the exact current and target releases, package coverage, eligible
   endpoints, canary percentage, health criteria and reason.
3. Start the bounded canary.
4. Observe four independent states per endpoint:
   **release approved**, **package ready**, **target bound**, and
   **runtime verified**.
5. The server creates exact dormant outbox commands automatically. Until the
   separately reviewed worker exists, confirm they remain **Dispatch disabled**;
   do not export or manually execute their internal instruction.
6. Treat channel success as **Awaiting attestation**.
7. Expand only after every selected endpoint has fresh exact target
   attestation and the server reports canary convergence.

## Journey 4 — investigate a blocked endpoint

**Actor:** security operations engineer

1. Open the blocked row from Delivery readiness or the Overview attention
   queue.
2. Read the fixed reason, evidence freshness and affected authority.
3. Follow the stated next action: Coverage for source/binding issues, the
   deployment pipeline for release-package authority, Fleet for
   lifecycle/quarantine, or Incidents for active response.
4. Do not clear quarantine, retry delivery or weaken policy merely to make the
   row green.
5. After correcting the source condition, refresh and require a new binding
   digest plus fresh runtime attestation.

## Journey 5 — roll back safely

**Actor:** fleet engineer with required approval

1. Pause the rollout from the deployment detail.
2. Review the frozen affected cohort and current binding/package readiness.
3. Select rollback; the server chooses the retained known-good release and its
   exact delivery package.
4. A stale target instruction becomes invalid immediately.
5. Observe delivery-channel reports without treating them as proof.
6. Close the rollback only when the frozen cohort attests the retained release.

## Journey 6 — complete Microsoft Intune delivery

**Actor:** platform administrator

1. Register the approved Entra/Intune application outside the browser and put
   its credential in the tenant-tagged AWS Secrets Manager namespace.
2. Create, independently approve and activate the immutable provider
   configuration for one non-production deployment.
3. Confirm deterministic commands are created with **Dispatch disabled**.
4. Deploy the dedicated least-privilege Intune worker role and run synthetic
   provider verification without exposing the credential value.
5. Exercise install, response loss, duplicate submission, provider outage,
   retry, rotation, revocation and rollback.
6. Retain provider job evidence and independently verify endpoint attestation.

Until this journey passes in a customer-owned tenant, the product says
**Customer-operated delivery** rather than **Hosted Intune delivery**.

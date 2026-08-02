# Regional recovery storage runbook

This runbook prepares phases 1 and 2 of the
[regional control-plane recovery design](regional-control-plane-recovery-design.md).
It creates no recovery API and changes no traffic, Cognito configuration,
active policy signer or audit retention.

## Prerequisites

- Use a clean, reviewed revision of the SDK repository.
- Confirm the primary stack is `UPDATE_COMPLETE`.
- Confirm the immutable audit recovery verifier passes.
- Review `infra/aws-control-plane/regional-recovery.example.json` and replace
  `approvalEvidenceRef` with the approved change/evidence identifier.
- Record the expected incremental cost and maintenance window.
- Run with an AWS profile authorized for CloudFormation, DynamoDB, KMS, SSM and
  read-only S3 posture checks. Never put credentials or secret values in the
  manifest.

## 1. Validate locally

```bash
PYTHONPATH="$PWD/src" python3 -m pytest -q tests/test_aws_regional_recovery.py
cd infra/aws-control-plane
npm run build
npx cdk synth AaiSecControlPlane
```

Review `cdk diff`. The foundation diff must contain only:

- streams, deletion protection and missing PITR on the four tables;
- one retained, staged multi-Region P-256 signing key;
- table/key outputs.

It must not replace a table or key, change `POLICY_SIGNING_KEY_ARN`, remove
audit replication, alter Cognito, or route traffic.

## 2. Deploy the primary prerequisites

Use the guarded deployer so persisted Entra and audit-recovery configuration is
reloaded instead of trusting ambient shell variables:

```bash
python3 scripts/deploy_aws_control_plane.py deploy \
  --profile p1 \
  --region eu-west-2 \
  --stack-name AaiSecControlPlane
```

Abort if CloudFormation proposes replacement or deletion of an authoritative
store, identity provider, KMS key or Object Lock bucket.

## 3. Add and prove storage replicas

Copy the example outside the repository if it contains a customer change
identifier. Then run:

```bash
python3 scripts/manage_aws_regional_recovery.py prepare-storage \
  --config /absolute/path/to/regional-recovery.json \
  --profile p1 \
  --confirm-storage-replication \
  --evidence-out /absolute/path/to/regional-recovery-storage-evidence.json
```

The command:

1. derives table identities from exact CloudFormation outputs;
2. refuses missing streams, deletion protection or primary PITR;
3. creates only absent `eu-west-1` replicas and waits within RTO;
4. enables recovery deletion protection and PITR;
5. writes a synthetic, non-authoritative canary to every table;
6. requires exact content in the recovery Region within RPO;
7. conditionally deletes the canary and proves delete replication;
8. verifies the staged signing key remains multi-Region but inactive; and
9. persists the secret-free recovery manifest only after success.

The evidence file contains resource names and synthetic digests, not tokens,
customer records or secret values. Retain it with the change record.

## 4. Independent check

```bash
python3 scripts/manage_aws_regional_recovery.py check \
  --config /absolute/path/to/regional-recovery.json \
  --profile p1
```

Also inspect each table from both Regions and verify `ACTIVE`, PITR enabled,
deletion protection enabled and a current Global Tables version. Do not infer
exact replication from `ItemCount`; it is approximate. Use the canary evidence.

## 5. Create and prove the staged signing replica

This step creates the recovery-Region replica of the staged multi-Region key.
It does not switch the active policy signer or activate recovery traffic:

```bash
python3 scripts/manage_aws_regional_recovery.py prepare-trust \
  --config /absolute/path/to/regional-recovery.json \
  --profile p1 \
  --confirm-trust-replication \
  --evidence-out /absolute/path/to/regional-recovery-trust-evidence.json
```

The command requires the exact manifest previously persisted by the successful
storage exercise. It deploys only the retained KMS replica, then proves the
primary and replica share one `mrk-` key ID, use P-256 `SIGN_VERIFY`, are
enabled in the intended Regions and remain staged rather than active authority.
An independent read-only check is:

```bash
python3 scripts/manage_aws_regional_recovery.py check-trust \
  --config /absolute/path/to/regional-recovery.json \
  --profile p1
```

Generate an overlapping endpoint trust bundle before signer cutover. Repeat
`--key-arn` once for the existing signer, staged primary and staged replica:

```bash
python3 scripts/export_policy_trust_bundle.py \
  --profile p1 \
  --key-arn arn:aws:kms:eu-west-2:ACCOUNT:key/EXISTING_KEY \
  --key-arn arn:aws:kms:eu-west-2:ACCOUNT:key/mrk-STAGED_KEY \
  --key-arn arn:aws:kms:eu-west-1:ACCOUNT:key/mrk-STAGED_KEY \
  --output /administrator-owned/path/policy-trust-overlap.json
```

The exporter creates a new mode-`0600` file, refuses overwrite, rejects
duplicate key identities and permits at most eight exact P-256 signing keys.
Publishing the file is not convergence evidence. Do not switch the signer
until every governed endpoint reports the expected trust-bundle digest.

## Failure handling

- **Primary prerequisite failure:** do not add replicas. Restore the reviewed
  stack revision; never remove table data.
- **Replica creation timeout/failure:** leave the existing primary table and
  any provider-created replica intact, retain provider events, and investigate.
  Do not delete a partially created replica during the incident.
- **Canary exceeds RPO or differs:** do not persist or declare the storage
  foundation ready. Preserve the exact digest and table status.
- **PITR/deletion protection cannot be proven:** recovery remains incomplete.
- **Staged signing key check fails:** do not rotate the active signer.
- **Replica relationship differs or the persisted manifest changes:** do not
  publish trust or rotate the signer; retain both keys and investigate.

No phase-1 failure authorizes traffic failover. Enrolled runtimes continue to
fail closed when the primary control plane is unavailable.

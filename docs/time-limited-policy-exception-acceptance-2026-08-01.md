# Time-limited policy exception acceptance — 2026-08-01

## Outcome

The deployed AWS control plane passed the synthetic policy-exception lifecycle
against `AaiSecControlPlane` in `eu-west-2`. The tested implementation is the
SDK `main` merge commit `225d9d67032454056783419fc61c0c6e7eb7a667` from pull
request 87.

The acceptance created an isolated Claude Code deployment and enrolled agent,
assigned its sole group and active policy, then proved:

1. an authenticated policy author could create and submit an exact-agent draft;
2. the same subject could not approve that draft, even with an approver role;
3. a distinct authenticated approver could approve and activate it;
4. activation produced a distinct `exception:` policy identity signed by the
   deployed P-256 KMS key;
5. only the bound agent received the temporary configuration through the live
   HTTPS effective-policy route;
6. advancing the persisted server-owned expiry boundary caused the next policy
   refresh to return the ordinary signed base policy; and
7. the exception was durably reconciled to `expired` before exact synthetic
   cleanup.

The wider smoke continued to pass authentication, enrollment, ownership CAS,
bulk group assignment, managed-host evidence, approval replay denial,
emergency-stop recovery, durable idempotency, WORM audit retention, SNS/SQS
alert delivery and irreversible replacement/offboarding.

## Reproducible command

The acceptance is part of `scripts/test_aws_control_plane.py`. Follow the
parameterized command in [AWS deployment](aws-deployment.md#verification) with
a freshly exported administrator-pinned policy trust bundle. The script uses
only synthetic identifiers and removes their exact records in `finally`.

## Evidence boundaries

- The policy signing public key digest used for this run was
  `72a5ca43a8afb9cf9d1a324101478cb907c43dd6c15cbe991d5a2be04dbfacb2`.
- Local `make check` passed with 872 tests passing and one explicitly optional
  Postgres test skipped; UI `npm run check` passed 132 tests.
- Pull-request CI passed Python 3.11, 3.12 and 3.13, Postgres, Docker isolation,
  documentation and the bounded mutation/security audit.
- Runtime attestation and Microsoft Entra ID remain explicitly `not-configured`
  in this AWS tenant. This run therefore proves control-plane policy authority,
  not release provenance, MDM delivery or full endpoint convergence.

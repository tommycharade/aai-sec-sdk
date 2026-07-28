#!/usr/bin/env python3
"""Prove an AWS provider role allows one scope and denies a sibling scope."""

from __future__ import annotations

import argparse

import boto3  # type: ignore[import-untyped]


def _decision(iam: object, role_arn: str, action: str, resource_arn: str) -> str:
    """Return AWS's decision for one action/resource pair."""
    result = iam.simulate_principal_policy(  # type: ignore[attr-defined]
        PolicySourceArn=role_arn,
        ActionNames=[action],
        ResourceArns=[resource_arn],
    )
    evaluations = result.get("EvaluationResults", [])
    if len(evaluations) != 1:
        raise RuntimeError(f"expected one IAM evaluation, received {evaluations!r}")
    return str(evaluations[0]["EvalDecision"])


def main() -> int:
    """Fail unless the configured provider role has the expected narrow scope."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--allowed-resource", required=True)
    parser.add_argument("--denied-resource", required=True)
    parser.add_argument("--region", default=None)
    parser.add_argument("--profile", default=None)
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    iam = session.client("iam")
    allowed = _decision(iam, args.role_arn, args.action, args.allowed_resource)
    denied = _decision(iam, args.role_arn, args.action, args.denied_resource)
    if allowed != "allowed" or denied not in {"implicitDeny", "explicitDeny"}:
        raise RuntimeError(f"provider scope failed: allowed={allowed!r}, denied={denied!r}")
    print(
        "AWS IAM scope passed: "
        f"{args.action} allowed for the configured resource and denied for the sibling resource"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

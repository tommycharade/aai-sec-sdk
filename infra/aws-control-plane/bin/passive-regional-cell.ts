#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { PassiveRegionalCellStack } from "../lib/passive-regional-cell-stack";

/** Return a required deployment identifier without accepting whitespace aliases. */
function required(name: string): string {
  const value = process.env[name];
  if (!value || value !== value.trim()) {
    throw new Error(`${name} is required and must be trimmed`);
  }
  return value;
}

const app = new cdk.App();
new PassiveRegionalCellStack(app, "AaiSecPassiveRegionalCell", {
  env: {
    account: required("RECOVERY_AWS_ACCOUNT_ID"),
    region: process.env.RECOVERY_REGION ?? "eu-west-1",
  },
  description: "Non-serving AAI Security regional recovery compute and delivery cell",
  primaryRegion: process.env.PRIMARY_REGION ?? "eu-west-2",
  controlTableName: required("RECOVERY_CONTROL_TABLE"),
  presenceTableName: required("RECOVERY_PRESENCE_TABLE"),
  idempotencyTableName: required("RECOVERY_IDEMPOTENCY_TABLE"),
  scimTableName: required("RECOVERY_SCIM_TABLE"),
  auditReplicaBucketName: required("RECOVERY_AUDIT_BUCKET"),
  policySigningReplicaKeyArn: required("RECOVERY_POLICY_SIGNING_KEY_ARN"),
  recoveryUserPoolId: required("RECOVERY_USER_POOL_ID"),
  recoveryUserPoolClientId: required("RECOVERY_USER_POOL_CLIENT_ID"),
});

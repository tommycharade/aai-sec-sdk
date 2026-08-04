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
const cellMode = process.env.RECOVERY_CELL_MODE ?? "standby";
if (cellMode !== "standby" && cellMode !== "active") {
  throw new Error("RECOVERY_CELL_MODE must be standby or active");
}
let historicalAssuranceVerificationKeyArns: string[];
try {
  const value = JSON.parse(
    process.env.RECOVERY_ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS ?? "[]",
  ) as unknown;
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error("invalid historical assurance keys");
  }
  historicalAssuranceVerificationKeyArns = value;
} catch {
  throw new Error(
    "RECOVERY_ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS must be a JSON string array",
  );
}
new PassiveRegionalCellStack(app, "AaiSecPassiveRegionalCell", {
  env: {
    account: required("RECOVERY_AWS_ACCOUNT_ID"),
    region: process.env.RECOVERY_REGION ?? "eu-west-1",
  },
  description: "Non-serving AAI Security regional recovery compute and delivery cell",
  cellMode,
  activationEvidenceSha256: process.env.RECOVERY_ACTIVATION_EVIDENCE_SHA256,
  stableUiOrigin: process.env.RECOVERY_STABLE_UI_ORIGIN,
  primaryRegion: process.env.PRIMARY_REGION ?? "eu-west-2",
  controlTableName: required("RECOVERY_CONTROL_TABLE"),
  presenceTableName: required("RECOVERY_PRESENCE_TABLE"),
  idempotencyTableName: required("RECOVERY_IDEMPOTENCY_TABLE"),
  scimTableName: required("RECOVERY_SCIM_TABLE"),
  auditReplicaBucketName: required("RECOVERY_AUDIT_BUCKET"),
  policySigningReplicaKeyArn: required("RECOVERY_POLICY_SIGNING_KEY_ARN"),
  assuranceReportSigningReplicaKeyArn: required(
    "RECOVERY_ASSURANCE_REPORT_SIGNING_KEY_ARN",
  ),
  assuranceReportHistoricalVerificationKeyArns: historicalAssuranceVerificationKeyArns,
  recoveryUserPoolId: required("RECOVERY_USER_POOL_ID"),
  recoveryUserPoolClientId: required("RECOVERY_USER_POOL_CLIENT_ID"),
  entraTenantId: process.env.ENTRA_TENANT_ID,
  entraAaiTenantId: process.env.ENTRA_AAI_TENANT_ID,
  entraStrongAuthEnforced: process.env.ENTRA_STRONG_AUTH_ENFORCED === "true",
});

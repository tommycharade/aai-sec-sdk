#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { RegionalRecoveryStack } from "../lib/regional-recovery-stack";

const primarySigningKeyArn = process.env.REGIONAL_POLICY_SIGNING_KEY_ARN?.trim();
if (!primarySigningKeyArn) {
  throw new Error("REGIONAL_POLICY_SIGNING_KEY_ARN is required");
}
const primaryAssuranceSigningKeyArn = process.env.ASSURANCE_REPORT_SIGNING_KEY_ARN?.trim();
if (!primaryAssuranceSigningKeyArn) {
  throw new Error("ASSURANCE_REPORT_SIGNING_KEY_ARN is required");
}
let historicalAssuranceSigningKeyArns: string[];
let configuredHistoricalAssuranceReplicaKeyArns: string[];
try {
  const value = JSON.parse(
    process.env.ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS ?? "[]",
  ) as unknown;
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error("invalid historical assurance keys");
  }
  historicalAssuranceSigningKeyArns = value;
  const replicaValue = JSON.parse(
    process.env.ASSURANCE_REPORT_HISTORICAL_VERIFICATION_REPLICA_KEY_ARNS ?? "[]",
  ) as unknown;
  if (!Array.isArray(replicaValue) || !replicaValue.every((item) => typeof item === "string")) {
    throw new Error("invalid historical assurance replicas");
  }
  configuredHistoricalAssuranceReplicaKeyArns = replicaValue;
} catch {
  throw new Error(
    "ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS must be a JSON string array",
  );
}

const app = new cdk.App();
new RegionalRecoveryStack(
  app,
  "AaiSecRegionalRecovery",
  primarySigningKeyArn,
  primaryAssuranceSigningKeyArn,
  historicalAssuranceSigningKeyArns,
  process.env.ASSURANCE_REPORT_SIGNING_REPLICA_KEY_ARN?.trim() ?? "",
  configuredHistoricalAssuranceReplicaKeyArns,
  {
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.RECOVERY_REGION ?? "eu-west-1",
    },
    description: "Passive regional trust and control-plane recovery resources",
    tags: {
      ActiveAuthority: "false",
      PrimaryRegion: process.env.PRIMARY_REGION ?? "not-configured",
    },
  },
);

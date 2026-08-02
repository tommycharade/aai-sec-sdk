#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { RegionalRecoveryStack } from "../lib/regional-recovery-stack";

const primarySigningKeyArn = process.env.REGIONAL_POLICY_SIGNING_KEY_ARN?.trim();
if (!primarySigningKeyArn) {
  throw new Error("REGIONAL_POLICY_SIGNING_KEY_ARN is required");
}

const app = new cdk.App();
new RegionalRecoveryStack(
  app,
  "AaiSecRegionalRecovery",
  primarySigningKeyArn,
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

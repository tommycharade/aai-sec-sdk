#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import {
  RegionalFaultCellBoundary,
  RegionalFaultControllerStack,
} from "../lib/regional-fault-controller-stack";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function arns(name: string): string[] {
  const value: unknown = JSON.parse(required(name));
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`${name} must be a JSON array of ARNs`);
  }
  return value;
}

function cell(prefix: string): RegionalFaultCellBoundary {
  return {
    region: required(`${prefix}_FAULT_REGION`),
    targetRoleArn: required(`${prefix}_FAULT_TARGET_ROLE_ARN`),
    auditBucketArn: required(`${prefix}_FAULT_AUDIT_BUCKET_ARN`),
    dynamodbTableArns: arns(`${prefix}_FAULT_DYNAMODB_TABLE_ARNS`),
    signingKeyArn: required(`${prefix}_FAULT_SIGNING_KEY_ARN`),
    queueArns: arns(`${prefix}_FAULT_QUEUE_ARNS`),
  };
}

const app = new cdk.App();
new RegionalFaultControllerStack(app, "AaiSecRegionalFaultController", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: required("TRANSITION_COORDINATION_REGION"),
  },
  primary: cell("PRIMARY"),
  recovery: cell("RECOVERY"),
  journalTableName: required("TRANSITION_JOURNAL_TABLE_NAME"),
  journalTableArn: required("TRANSITION_JOURNAL_TABLE_ARN"),
  securityAlertTopicArn: required("FAULT_SECURITY_ALERT_TOPIC_ARN"),
  description: "Private compensated Regional dependency-fault exercise controller",
  terminationProtection: true,
  tags: {
    ActiveAuthority: "false-until-real-probes",
    CoordinationModel: "single-region-strong-cas",
  },
});

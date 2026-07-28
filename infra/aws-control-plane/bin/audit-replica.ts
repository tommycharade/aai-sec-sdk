#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { AuditReplicaStack } from "../lib/audit-replica-stack";

const app = new cdk.App();
new AuditReplicaStack(app, "AaiSecAuditReplica", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.AUDIT_REPLICA_REGION ?? "eu-west-1",
  },
  description: "Immutable secondary-region audit destination for AAI Security",
});

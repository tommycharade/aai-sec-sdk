#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { AwsControlPlaneStack } from "../lib/aws-control-plane-stack";

const app = new cdk.App();
new AwsControlPlaneStack(app, "AaiSecControlPlane", {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION ?? "eu-west-2" },
  description: "Serverless multi-tenant AAI Security SDK control plane",
  tags: { AuditReplicaRegion: process.env.AUDIT_REPLICA_REGION ?? "not-configured" },
});

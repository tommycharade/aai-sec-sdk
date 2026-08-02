#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { RegionalIngressStack } from "../lib/regional-ingress-stack";

/** Return one required, trimmed deployment input. */
function required(name: string): string {
  const value = process.env[name];
  if (!value || value !== value.trim()) {
    throw new Error(`${name} is required and must be trimmed`);
  }
  return value;
}

const role = required("REGIONAL_INGRESS_CELL_ROLE");
if (role !== "primary" && role !== "recovery") {
  throw new Error("REGIONAL_INGRESS_CELL_ROLE must be primary or recovery");
}
const app = new cdk.App();
new RegionalIngressStack(app, required("REGIONAL_INGRESS_STACK_NAME"), {
  env: {
    account: required("REGIONAL_INGRESS_AWS_ACCOUNT_ID"),
    region: required("REGIONAL_INGRESS_REGION"),
  },
  description: "Unrouted AAI Security regional API and private UI custom-domain ingress",
  cellRole: role,
  controlPlaneApiId: required("REGIONAL_INGRESS_CONTROL_API_ID"),
  uiBucketName: required("REGIONAL_INGRESS_UI_BUCKET"),
  certificateArn: required("REGIONAL_INGRESS_CERTIFICATE_ARN"),
  cognitoOrigin: required("REGIONAL_INGRESS_COGNITO_ORIGIN"),
  stableApiDomain: required("REGIONAL_INGRESS_STABLE_API_DOMAIN"),
  stableUiDomain: required("REGIONAL_INGRESS_STABLE_UI_DOMAIN"),
  canaryApiDomain: required("REGIONAL_INGRESS_CANARY_API_DOMAIN"),
  canaryUiDomain: required("REGIONAL_INGRESS_CANARY_UI_DOMAIN"),
});

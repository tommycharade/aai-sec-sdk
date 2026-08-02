import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as kms from "aws-cdk-lib/aws-kms";

/**
 * Passive recovery-region trust resources.
 *
 * The stack initially contains only the policy-signing replica. It cannot
 * serve API traffic, authenticate an operator, sign a policy or alter the
 * active primary signer. Later recovery-cell resources can depend on this key
 * after endpoint trust-bundle convergence has been independently measured.
 */
export class RegionalRecoveryStack extends cdk.Stack {
  constructor(scope: Construct, id: string, primarySigningKeyArn: string, props?: cdk.StackProps) {
    super(scope, id, props);

    if (
      !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:key\/mrk-[0-9a-f]{32}$/.test(
        primarySigningKeyArn,
      )
    ) {
      throw new Error("REGIONAL_POLICY_SIGNING_KEY_ARN must be one exact multi-Region KMS key ARN");
    }
    const primaryRegion = cdk.Stack.of(this).splitArn(
      primarySigningKeyArn,
      cdk.ArnFormat.SLASH_RESOURCE_NAME,
    ).region;
    if (primaryRegion === this.region) {
      throw new Error("regional signing-key replica must be deployed outside the primary Region");
    }

    const replica = new kms.CfnReplicaKey(this, "RegionalPolicySigningReplica", {
      primaryKeyArn: primarySigningKeyArn,
      description: "Passive AAI Security policy-signing replica; not active authority",
      enabled: true,
      keyPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "EnableAccountAdministration",
            Effect: "Allow",
            Principal: {
              AWS: `arn:${cdk.Aws.PARTITION}:iam::${cdk.Aws.ACCOUNT_ID}:root`,
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      pendingWindowInDays: 30,
      tags: [
        { key: "aai-sec:purpose", value: "regional-policy-signing-replica" },
        { key: "aai-sec:active-authority", value: "false" },
      ],
    });
    replica.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);

    new cdk.CfnOutput(this, "RegionalPolicySigningReplicaKeyArn", {
      value: replica.attrArn,
    });
    new cdk.CfnOutput(this, "RegionalPolicySigningReplicaStatus", {
      value: "staged-not-active",
    });
  }
}

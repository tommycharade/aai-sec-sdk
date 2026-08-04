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
  constructor(
    scope: Construct,
    id: string,
    primarySigningKeyArn: string,
    primaryAssuranceSigningKeyArn: string,
    historicalAssuranceSigningKeyArns: string[],
    configuredAssuranceReplicaKeyArn = "",
    configuredHistoricalAssuranceReplicaKeyArns: string[] = [],
    props?: cdk.StackProps,
  ) {
    super(scope, id, props);

    if (
      !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:key\/mrk-[0-9a-f]{32}$/.test(
        primarySigningKeyArn,
      )
    ) {
      throw new Error("REGIONAL_POLICY_SIGNING_KEY_ARN must be one exact multi-Region KMS key ARN");
    }
    if (
      !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:key\/mrk-[0-9a-f]{32}$/.test(
        primaryAssuranceSigningKeyArn,
      )
      || primaryAssuranceSigningKeyArn === primarySigningKeyArn
    ) {
      throw new Error(
        "ASSURANCE_REPORT_SIGNING_KEY_ARN must be one distinct multi-Region KMS key ARN",
      );
    }
    const primaryRegion = cdk.Stack.of(this).splitArn(
      primarySigningKeyArn,
      cdk.ArnFormat.SLASH_RESOURCE_NAME,
    ).region;
    if (primaryRegion === this.region) {
      throw new Error("regional signing-key replica must be deployed outside the primary Region");
    }
    const assurancePrimaryRegion = cdk.Stack.of(this).splitArn(
      primaryAssuranceSigningKeyArn,
      cdk.ArnFormat.SLASH_RESOURCE_NAME,
    ).region;
    if (assurancePrimaryRegion !== primaryRegion) {
      throw new Error("regional signing keys must share one primary Region");
    }
    if (
      historicalAssuranceSigningKeyArns.length > 8
      || new Set(historicalAssuranceSigningKeyArns).size
        !== historicalAssuranceSigningKeyArns.length
      || historicalAssuranceSigningKeyArns.some(
        (value) =>
          !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:key\/mrk-[0-9a-f]{32}$/.test(
            value,
          )
          || cdk.Stack.of(this).splitArn(value, cdk.ArnFormat.SLASH_RESOURCE_NAME).region
            !== primaryRegion
          || value === primaryAssuranceSigningKeyArn,
      )
    ) {
      throw new Error("historical assurance keys must be unique primary-Region MRK ARNs");
    }
    const recoveryArn = /^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):key\/(mrk-[0-9a-f]{32})$/;
    const primaryAssuranceMatch = recoveryArn.exec(primaryAssuranceSigningKeyArn);
    const configuredReplicaMatch = configuredAssuranceReplicaKeyArn
      ? recoveryArn.exec(configuredAssuranceReplicaKeyArn)
      : null;
    if (
      configuredAssuranceReplicaKeyArn
      && (
        !configuredReplicaMatch
        || !primaryAssuranceMatch
        || configuredReplicaMatch[2] !== this.region
        || configuredReplicaMatch[3] !== primaryAssuranceMatch[3]
        || configuredReplicaMatch[4] !== primaryAssuranceMatch[4]
      )
    ) {
      throw new Error("configured assurance replica must be the exact recovery-Region MRK");
    }
    if (
      configuredHistoricalAssuranceReplicaKeyArns.length !== 0
      && configuredHistoricalAssuranceReplicaKeyArns.length
        !== historicalAssuranceSigningKeyArns.length
    ) {
      throw new Error("configured historical assurance replicas must exactly cover history");
    }
    configuredHistoricalAssuranceReplicaKeyArns.forEach((replicaArn, index) => {
      const replicaMatch = recoveryArn.exec(replicaArn);
      const primaryMatch = recoveryArn.exec(historicalAssuranceSigningKeyArns[index]);
      if (
        !replicaMatch
        || !primaryMatch
        || replicaMatch[2] !== this.region
        || replicaMatch[3] !== primaryMatch[3]
        || replicaMatch[4] !== primaryMatch[4]
      ) {
        throw new Error("configured historical assurance replica identity is invalid");
      }
    });

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

    const assuranceReplica = configuredAssuranceReplicaKeyArn ? null : new kms.CfnReplicaKey(this, "AssuranceReportSigningReplica", {
      primaryKeyArn: primaryAssuranceSigningKeyArn,
      description: "Passive AAI Security assurance-report signing replica; not active authority",
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
        { key: "aai-sec:purpose", value: "assurance-report-signing-replica" },
        { key: "aai-sec:active-authority", value: "false" },
      ],
    });
    assuranceReplica?.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
    const historicalAssuranceReplicas = historicalAssuranceSigningKeyArns.map(
      (primaryKeyArn, index) => {
        if (configuredHistoricalAssuranceReplicaKeyArns.length) {
          return configuredHistoricalAssuranceReplicaKeyArns[index];
        }
        const historicalReplica = new kms.CfnReplicaKey(
          this,
          `HistoricalAssuranceReportSigningReplica${index}`,
          {
            primaryKeyArn,
            description: "Retained historical assurance-report verification replica",
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
              { key: "aai-sec:purpose", value: "historical-assurance-verification-replica" },
              { key: "aai-sec:active-authority", value: "false" },
            ],
          },
        );
        historicalReplica.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
        return historicalReplica.attrArn;
      },
    );

    new cdk.CfnOutput(this, "RegionalPolicySigningReplicaKeyArn", {
      value: replica.attrArn,
    });
    new cdk.CfnOutput(this, "RegionalPolicySigningReplicaStatus", {
      value: "staged-not-active",
    });
    new cdk.CfnOutput(this, "AssuranceReportSigningReplicaKeyArn", {
      value: configuredAssuranceReplicaKeyArn || assuranceReplica!.attrArn,
    });
    new cdk.CfnOutput(this, "AssuranceReportHistoricalVerificationReplicaKeyArns", {
      value: historicalAssuranceReplicas.length
        ? cdk.Fn.join("", [
          '["',
          cdk.Fn.join('\",\"', historicalAssuranceReplicas),
          '"]',
        ])
        : "[]",
    });
  }
}

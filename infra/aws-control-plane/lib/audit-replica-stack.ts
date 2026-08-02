import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";

export interface AuditReplicaStackProps extends cdk.StackProps {
  /** Exact retained primary audit bucket ARN; omit only while staging the destination. */
  readonly primaryAuditBucketArn?: string;
  /** Region containing the primary audit bucket. */
  readonly primaryRegion?: string;
}

/**
 * Immutable secondary-region destination for the control-plane audit stream.
 *
 * This stack is intentionally separate from the primary control plane because
 * an S3 bucket's region is fixed at creation. Deploy it in the recovery region
 * before enabling replication on the primary stack.
 */
export class AuditReplicaStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: AuditReplicaStackProps) {
    super(scope, id, props);

    if (Boolean(props?.primaryAuditBucketArn) !== Boolean(props?.primaryRegion)) {
      throw new Error("primaryAuditBucketArn and primaryRegion must be configured together");
    }
    if (
      props?.primaryAuditBucketArn
      && !/^arn:[^:]+:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(props.primaryAuditBucketArn)
    ) {
      throw new Error("primaryAuditBucketArn must be an exact S3 bucket ARN");
    }
    if (props?.primaryRegion && props.env?.region === props.primaryRegion) {
      throw new Error("primary and recovery audit Regions must be distinct");
    }

    const bucket = new s3.Bucket(this, "AuditReplicaBucket", {
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(cdk.Duration.days(365)),
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
    });

    if (props?.primaryAuditBucketArn && props.primaryRegion) {
      // This role is assumed only by S3. It can read immutable source versions
      // and replicate them back to the exact primary bucket; it cannot create
      // delete markers or mutate unrelated storage.
      const reverseReplicationRole = new iam.Role(this, "ReverseAuditReplicationRole", {
        assumedBy: new iam.ServicePrincipal("s3.amazonaws.com"),
        description: "Replicate recovery-region audit evidence back to the primary region",
      });
      reverseReplicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetReplicationConfiguration", "s3:ListBucket"],
          resources: [bucket.bucketArn],
        }),
      );
      reverseReplicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: [
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectRetention",
            "s3:GetObjectLegalHold",
          ],
          resources: [bucket.arnForObjects("*")],
        }),
      );
      reverseReplicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
          resources: [`${props.primaryAuditBucketArn}/*`],
        }),
      );
      const bucketResource = bucket.node.defaultChild as s3.CfnBucket;
      bucketResource.replicationConfiguration = {
        role: reverseReplicationRole.roleArn,
        rules: [
          {
            id: "replicate-recovery-audit-to-primary-region",
            priority: 1,
            filter: { prefix: "" },
            deleteMarkerReplication: { status: "Disabled" },
            sourceSelectionCriteria: {
              // Replica modification sync carries retention, legal-hold and
              // tag changes made in either Region back to its counterpart.
              replicaModifications: { status: "Enabled" },
            },
            status: "Enabled",
            destination: {
              bucket: props.primaryAuditBucketArn,
              storageClass: "STANDARD",
              metrics: { status: "Enabled" },
            },
          },
        ],
      };
      new cdk.CfnOutput(this, "PrimaryAuditBucketArn", {
        value: props.primaryAuditBucketArn,
      });
      new cdk.CfnOutput(this, "PrimaryAuditRegion", { value: props.primaryRegion });
      new cdk.CfnOutput(this, "ReverseAuditReplicationRoleArn", {
        value: reverseReplicationRole.roleArn,
      });
      new cdk.CfnOutput(this, "EvidenceContinuityStatus", {
        value: "reverse-replication-configured",
      });
    } else {
      new cdk.CfnOutput(this, "EvidenceContinuityStatus", {
        value: "destination-only",
      });
    }

    new cdk.CfnOutput(this, "AuditReplicaBucketArn", { value: bucket.bucketArn });
    new cdk.CfnOutput(this, "AuditReplicaBucketName", { value: bucket.bucketName });
  }
}

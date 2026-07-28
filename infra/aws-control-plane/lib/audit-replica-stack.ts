import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as s3 from "aws-cdk-lib/aws-s3";

/**
 * Immutable secondary-region destination for the control-plane audit stream.
 *
 * This stack is intentionally separate from the primary control plane because
 * an S3 bucket's region is fixed at creation. Deploy it in the recovery region
 * before enabling replication on the primary stack.
 */
export class AuditReplicaStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

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

    new cdk.CfnOutput(this, "AuditReplicaBucketArn", { value: bucket.bucketArn });
    new cdk.CfnOutput(this, "AuditReplicaBucketName", { value: bucket.bucketName });
  }
}

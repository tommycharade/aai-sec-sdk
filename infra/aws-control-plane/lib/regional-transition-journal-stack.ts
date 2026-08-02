import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as kms from "aws-cdk-lib/aws-kms";

/** Secret-free deployment inputs for the independent transition witness. */
export interface RegionalTransitionJournalProps extends cdk.StackProps {
  readonly primaryRegion: string;
  readonly recoveryRegion: string;
  readonly tableName: string;
}

/**
 * Deploy the single-Region, single-writer CAS authority for regional changes.
 *
 * This table must not become a Global Table: cross-Region last-writer-wins
 * reconciliation cannot safely arbitrate two concurrent recovery operators.
 * The witness Region is therefore a third failure domain and fails closed.
 */
export class RegionalTransitionJournalStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: RegionalTransitionJournalProps) {
    super(scope, id, props);

    const witnessRegion = props.env?.region;
    const regionPattern = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
    if (
      !witnessRegion
      || !regionPattern.test(witnessRegion)
      || !regionPattern.test(props.primaryRegion)
      || !regionPattern.test(props.recoveryRegion)
      || new Set([witnessRegion, props.primaryRegion, props.recoveryRegion]).size !== 3
    ) {
      throw new Error("transition witness, primary and recovery Regions must be distinct");
    }
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(props.tableName)) {
      throw new Error("transition journal table name is invalid");
    }

    const key = new kms.Key(this, "TransitionJournalKey", {
      alias: "alias/aai-sec-regional-transition-journal",
      description: "Encrypts the independent AAI Security regional transition witness",
      enableKeyRotation: true,
      pendingWindow: cdk.Duration.days(30),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const table = new dynamodb.Table(this, "TransitionJournal", {
      tableName: props.tableName,
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: key,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    cdk.Tags.of(table).add("aai-sec:purpose", "regional-transition-single-writer-witness");
    cdk.Tags.of(table).add("aai-sec:replicated", "false");
    cdk.Tags.of(table).add("aai-sec:primary-region", props.primaryRegion);
    cdk.Tags.of(table).add("aai-sec:recovery-region", props.recoveryRegion);

    new cdk.CfnOutput(this, "TransitionJournalTableName", { value: table.tableName });
    new cdk.CfnOutput(this, "TransitionJournalTableArn", { value: table.tableArn });
    new cdk.CfnOutput(this, "TransitionJournalKeyArn", { value: key.keyArn });
    new cdk.CfnOutput(this, "TransitionJournalStatus", {
      value: "uninitialized-single-writer-witness",
    });
  }
}

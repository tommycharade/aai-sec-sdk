import * as path from "node:path";
import * as fs from "node:fs";
import { createHash } from "node:crypto";
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as authorizers from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as sqs from "aws-cdk-lib/aws-sqs";

/** Deployment-owned, secret-free identities required by the passive cell. */
export interface PassiveRegionalCellProps extends cdk.StackProps {
  readonly cellMode: "standby" | "active";
  readonly activationEvidenceSha256?: string;
  readonly stableUiOrigin?: string;
  readonly primaryRegion: string;
  readonly controlTableName: string;
  readonly presenceTableName: string;
  readonly idempotencyTableName: string;
  readonly scimTableName: string;
  readonly auditReplicaBucketName: string;
  readonly policySigningReplicaKeyArn: string;
  readonly recoveryUserPoolId: string;
  readonly recoveryUserPoolClientId: string;
  readonly entraTenantId?: string;
  readonly entraAaiTenantId?: string;
  readonly entraStrongAuthEnforced?: boolean;
}

/** Return one bounded AWS resource name or reject ambiguous deployment input. */
function resourceName(value: string, label: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,254}$/.test(value)) {
    throw new Error(`${label} must be one bounded AWS resource name`);
  }
  return value;
}

/** Return one exact S3 bucket identity; bucket aliases are not accepted. */
function bucketName(value: string): string {
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value) || value.includes("..")) {
    throw new Error("audit replica bucket must be one exact S3 bucket name");
  }
  return value;
}

/**
 * Production-shaped recovery compute with no executable or routing authority.
 *
 * The stack deliberately requires a later CloudFormation change for
 * activation. DNS isolation by itself is not considered a security boundary.
 */
export class PassiveRegionalCellStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: PassiveRegionalCellProps) {
    super(scope, id, props);

    const recoveryRegion = props.env?.region;
    const active = props.cellMode === "active";
    if (!active && props.cellMode !== "standby") {
      throw new Error("cellMode must be standby or active");
    }
    if (!recoveryRegion || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(recoveryRegion)) {
      throw new Error("passive cell requires one explicit recovery AWS Region");
    }
    if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(props.primaryRegion)) {
      throw new Error("primaryRegion must be one exact AWS Region");
    }
    if (props.primaryRegion === recoveryRegion) {
      throw new Error("passive cell must be outside the primary Region");
    }
    if (!props.recoveryUserPoolId.startsWith(`${recoveryRegion}_`)) {
      throw new Error("recovery user pool must belong to the passive Region");
    }
    if (!/^[a-z0-9]{10,128}$/.test(props.recoveryUserPoolClientId)) {
      throw new Error("recovery user-pool client ID is invalid");
    }
    if (active) {
      if (!/^[0-9a-f]{64}$/.test(props.activationEvidenceSha256 ?? "")) {
        throw new Error("active cell requires one exact activation evidence SHA-256");
      }
      if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          props.entraTenantId ?? "",
        )
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(props.entraAaiTenantId ?? "")
        || props.entraStrongAuthEnforced !== true
      ) {
        throw new Error("active cell requires tenant-bound Entra strong authentication");
      }
      if (!/^https:\/\/[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])$/.test(props.stableUiOrigin ?? "")) {
        throw new Error("active cell requires one exact stable UI HTTPS origin");
      }
    } else if (
      props.activationEvidenceSha256
      || props.stableUiOrigin
      || props.entraTenantId
      || props.entraAaiTenantId
      || props.entraStrongAuthEnforced
    ) {
      throw new Error("standby cell must not receive active identity or evidence authority");
    }
    const deploymentAccount = props.env?.account;
    if (!deploymentAccount || !/^\d{12}$/.test(deploymentAccount)) {
      throw new Error("passive cell requires one explicit 12-digit AWS account");
    }
    const expectedReplicaArn = new RegExp(
      `^arn:(aws|aws-us-gov|aws-cn):kms:${recoveryRegion}:${deploymentAccount}:key/mrk-[0-9a-f]{32}$`,
    );
    if (!expectedReplicaArn.test(props.policySigningReplicaKeyArn)) {
      throw new Error("policy signing replica must be an exact recovery-Region MRK ARN");
    }

    const control = dynamodb.Table.fromTableName(
      this,
      "ControlTableReplica",
      resourceName(props.controlTableName, "control table"),
    );
    const presence = dynamodb.Table.fromTableName(
      this,
      "PresenceTableReplica",
      resourceName(props.presenceTableName, "presence table"),
    );
    const idempotency = dynamodb.Table.fromTableName(
      this,
      "IdempotencyTableReplica",
      resourceName(props.idempotencyTableName, "idempotency table"),
    );
    const scim = dynamodb.Table.fromTableName(
      this,
      "ScimTableReplica",
      resourceName(props.scimTableName, "SCIM table"),
    );
    const auditReplica = s3.Bucket.fromBucketName(
      this,
      "AuditReplica",
      bucketName(props.auditReplicaBucketName),
    );
    const policySigningReplica = kms.Key.fromKeyArn(
      this,
      "PolicySigningReplica",
      props.policySigningReplicaKeyArn,
    );

    const alertsDlq = new sqs.Queue(this, "SecurityAlertsDlq", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    const alertsQueue = new sqs.Queue(this, "SecurityAlertsQueue", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
      deadLetterQueue: { queue: alertsDlq, maxReceiveCount: 5 },
    });
    const alerts = new sns.Topic(this, "SecurityAlerts", {
      displayName: "AAI Security passive-cell alerts",
      enforceSSL: true,
    });
    alerts.addSubscription(
      new subscriptions.SqsSubscription(alertsQueue, { rawMessageDelivery: true }),
    );

    const evidenceDlq = new sqs.Queue(this, "EvidenceWorkerDlq", {
      fifo: true,
      contentBasedDeduplication: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    const evidenceQueue = new sqs.Queue(this, "EvidenceWorkerQueue", {
      fifo: true,
      contentBasedDeduplication: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      visibilityTimeout: cdk.Duration.minutes(6),
      deadLetterQueue: { queue: evidenceDlq, maxReceiveCount: 5 },
    });
    const retentionDlq = new sqs.Queue(this, "RetentionWorkerDlq", {
      fifo: true,
      contentBasedDeduplication: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    const retentionQueue = new sqs.Queue(this, "RetentionWorkerQueue", {
      fifo: true,
      contentBasedDeduplication: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      visibilityTimeout: cdk.Duration.minutes(6),
      deadLetterQueue: { queue: retentionDlq, maxReceiveCount: 5 },
    });
    const regionalFaultCanaryQueue = new sqs.Queue(this, "RegionalFaultCanaryQueue", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(1),
    });
    const scheduleDlqs = {
      endpoint: new sqs.Queue(this, "EndpointDetectionDlq", {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: cdk.Duration.days(14),
      }),
      rollout: new sqs.Queue(this, "RolloutReconciliationDlq", {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: cdk.Duration.days(14),
      }),
      assurance: new sqs.Queue(this, "EvidenceAssuranceDlq", {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: cdk.Duration.days(14),
      }),
      retention: new sqs.Queue(this, "EvidenceRetentionDlq", {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: cdk.Duration.days(14),
      }),
    };

    const evidenceReports = active
      ? new s3.Bucket(this, "ActiveEvidenceReports", {
          blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
          encryption: s3.BucketEncryption.S3_MANAGED,
          enforceSSL: true,
          versioned: true,
          removalPolicy: cdk.RemovalPolicy.RETAIN,
        })
      : undefined;
    const runtimeManifestBundle = fs.readFileSync(
      path.join(__dirname, "../lambda/runtime-manifests.json"),
      "utf8",
    );
    const runtimeApprovalBundle = fs.readFileSync(
      path.join(__dirname, "../lambda/runtime-manifests.provenance.json"),
      "utf8",
    );
    const environment = {
      CONTROL_TABLE: control.tableName,
      PRESENCE_TABLE: presence.tableName,
      IDEMPOTENCY_TABLE: idempotency.tableName,
      SCIM_TABLE: scim.tableName,
      AUDIT_BUCKET: auditReplica.bucketName,
      EVIDENCE_QUEUE_URL: evidenceQueue.queueUrl,
      EVIDENCE_RETENTION_QUEUE_URL: retentionQueue.queueUrl,
      REGIONAL_FAULT_CANARY_QUEUE_URL: regionalFaultCanaryQueue.queueUrl,
      SECURITY_ALERTS_TOPIC_ARN: alerts.topicArn,
      EVIDENCE_REPORT_BUCKET: evidenceReports?.bucketName ?? "",
      PASSIVE_CELL_MODE: active ? "active" : "standby",
      RECOVERY_JOB_RECONCILIATION_ENABLED: active ? "true" : "false",
      REGIONAL_CELL_ROLE: "recovery",
      REGIONAL_JOB_RECONCILIATION_ENABLED: active ? "true" : "false",
      PRIMARY_REGION: props.primaryRegion,
      RECOVERY_REGION: recoveryRegion,
      // An ARN in this field would claim live signing authority. The replica
      // identity is staged separately and the role receives no KMS grant.
      POLICY_SIGNING_KEY_ARN: active ? props.policySigningReplicaKeyArn : "",
      REGIONAL_POLICY_SIGNING_KEY_ARN: props.policySigningReplicaKeyArn,
      ACTIVATION_EVIDENCE_SHA256: props.activationEvidenceSha256 ?? "",
      ENTRA_PROVIDER_ENABLED: active ? "true" : "false",
      ENTRA_TENANT_ID: active ? (props.entraTenantId ?? "") : "",
      ENTRA_AAI_TENANT_ID: active ? (props.entraAaiTenantId ?? "") : "",
      ENTRA_STRONG_AUTH_ENFORCED: active ? "true" : "false",
      SCIM_ENABLED: "false",
      SPLUNK_STUB_ENABLED: "true",
      RUNTIME_ATTESTATION_MANIFESTS_SHA256: createHash("sha256")
        .update(runtimeManifestBundle)
        .digest("hex"),
      RUNTIME_ATTESTATION_APPROVALS_SHA256: createHash("sha256")
        .update(runtimeApprovalBundle)
        .digest("hex"),
    };
    const code = lambda.Code.fromAsset(path.join(__dirname, "../lambda"));
    const handler = new lambda.Function(this, "PassiveControlPlaneHandler", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "handler.handler",
      code,
      timeout: cdk.Duration.seconds(15),
      memorySize: 512,
      reservedConcurrentExecutions: active ? 100 : 0,
      environment,
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    const evidenceWorker = new lambda.Function(this, "PassiveEvidenceWorker", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "evidence_worker.handler",
      code,
      timeout: cdk.Duration.seconds(60),
      memorySize: 1024,
      recursiveLoop: active ? lambda.RecursiveLoop.ALLOW : lambda.RecursiveLoop.TERMINATE,
      reservedConcurrentExecutions: active ? 5 : 0,
      environment,
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    const retentionWorker = new lambda.Function(this, "PassiveRetentionWorker", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "retention_worker.handler",
      code,
      timeout: cdk.Duration.seconds(60),
      memorySize: 1024,
      recursiveLoop: active ? lambda.RecursiveLoop.ALLOW : lambda.RecursiveLoop.TERMINATE,
      reservedConcurrentExecutions: active ? 5 : 0,
      environment,
      tracing: lambda.Tracing.PASS_THROUGH,
    });

    // Standby roles can inspect replicated posture but cannot mutate tables,
    // write audit, send jobs/alerts or sign policy before activation approval.
    for (const target of [handler, evidenceWorker, retentionWorker]) {
      control.grantReadData(target);
      presence.grantReadData(target);
      idempotency.grantReadData(target);
      scim.grantReadData(target);
      target.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetBucketLocation", "s3:ListBucket"],
          resources: [auditReplica.bucketArn],
        }),
      );
      target.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetObject", "s3:GetObjectVersion"],
          resources: [auditReplica.arnForObjects("*")],
        }),
      );
    }
    if (active && evidenceReports) {
      control.grantReadWriteData(handler);
      presence.grantReadWriteData(handler);
      idempotency.grantReadWriteData(handler);
      scim.grantReadWriteData(handler);
      control.grant(handler, "dynamodb:TransactWriteItems");
      auditReplica.grantRead(handler);
      auditReplica.grantPut(handler);
      handler.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "s3:GetObjectLegalHold",
            "s3:GetObjectRetention",
            "s3:PutObjectLegalHold",
            "s3:PutObjectRetention",
          ],
          resources: [auditReplica.arnForObjects("tenant=*")],
        }),
      );
      evidenceReports.grantRead(handler);
      evidenceQueue.grantSendMessages(handler);
      retentionQueue.grantSendMessages(handler);
      regionalFaultCanaryQueue.grantSendMessages(handler);
      alerts.grantPublish(handler);
      policySigningReplica.grant(handler, "kms:Sign", "kms:Verify", "kms:GetPublicKey");

      control.grantReadWriteData(evidenceWorker);
      auditReplica.grantRead(evidenceWorker);
      auditReplica.grantPut(evidenceWorker);
      evidenceWorker.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetObjectLegalHold", "s3:GetObjectRetention"],
          resources: [auditReplica.arnForObjects("tenant=*")],
        }),
      );
      evidenceReports.grantReadWrite(evidenceWorker);
      evidenceQueue.grantSendMessages(evidenceWorker);
      alerts.grantPublish(evidenceWorker);

      control.grantReadWriteData(retentionWorker);
      control.grant(retentionWorker, "dynamodb:TransactWriteItems");
      auditReplica.grantRead(retentionWorker);
      auditReplica.grantPut(retentionWorker);
      retentionWorker.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetObjectRetention", "s3:PutObjectRetention"],
          resources: [auditReplica.arnForObjects("tenant=*")],
        }),
      );
      retentionQueue.grantSendMessages(retentionWorker);
      alerts.grantPublish(retentionWorker);
    }
    evidenceWorker.addEventSource(
      new lambdaEventSources.SqsEventSource(evidenceQueue, {
        batchSize: 1,
        enabled: active,
        reportBatchItemFailures: false,
      }),
    );
    retentionWorker.addEventSource(
      new lambdaEventSources.SqsEventSource(retentionQueue, {
        batchSize: 1,
        enabled: active,
        reportBatchItemFailures: false,
      }),
    );

    const api = new apigwv2.HttpApi(this, "PassiveControlPlaneApi", {
      apiName: "aai-sec-passive-control-plane",
      disableExecuteApiEndpoint: true,
      corsPreflight: {
        allowHeaders: ["authorization", "content-type"],
        allowMethods: [apigwv2.CorsHttpMethod.ANY],
        allowOrigins: [active ? props.stableUiOrigin! : "https://not-serving.invalid"],
      },
    });
    const issuer = `https://cognito-idp.${recoveryRegion}.amazonaws.com/${props.recoveryUserPoolId}`;
    const jwt = new authorizers.HttpJwtAuthorizer("RecoveryCognitoAuthorizer", issuer, {
      jwtAudience: [props.recoveryUserPoolClientId],
    });
    const integration = new integrations.HttpLambdaIntegration("PassiveApiIntegration", handler);
    api.addRoutes({
      path: "/agent/{proxy+}",
      methods: [apigwv2.HttpMethod.ANY],
      integration,
    });
    api.addRoutes({
      path: "/endpoint-evidence/{proxy+}",
      methods: [apigwv2.HttpMethod.ANY],
      integration,
    });
    api.addRoutes({
      path: "/discovery-ingest/{proxy+}",
      methods: [apigwv2.HttpMethod.ANY],
      integration,
    });
    api.addRoutes({
      path: "/{proxy+}",
      methods: [apigwv2.HttpMethod.ANY],
      integration,
      authorizer: jwt,
    });

    const schedules: Array<[string, events.Schedule, sqs.IQueue, Record<string, unknown>]> = [
      [
        "EndpointDetectionSchedule",
        events.Schedule.rate(cdk.Duration.minutes(5)),
        scheduleDlqs.endpoint,
        { source: "aai.endpoint-detection", schemaVersion: 1 },
      ],
      [
        "RolloutReconciliationSchedule",
        events.Schedule.rate(cdk.Duration.minutes(5)),
        scheduleDlqs.rollout,
        { source: "aai.rollout-reconciliation", schemaVersion: 1 },
      ],
      [
        "EvidenceAssuranceSchedule",
        events.Schedule.rate(cdk.Duration.minutes(15)),
        scheduleDlqs.assurance,
        { source: "aai.evidence-assurance", schemaVersion: 1 },
      ],
      [
        "EvidenceRetentionSchedule",
        events.Schedule.rate(cdk.Duration.minutes(1)),
        scheduleDlqs.retention,
        { source: "aai.evidence-retention", schemaVersion: 1 },
      ],
    ];
    for (const [identifier, schedule, deadLetterQueue, event] of schedules) {
      const rule = new events.Rule(this, identifier, {
        schedule,
        enabled: active,
        description: `Passive recovery ${identifier}; activation is separately governed`,
      });
      rule.addTarget(
        new eventTargets.LambdaFunction(handler, {
          event: events.RuleTargetInput.fromObject(event),
          deadLetterQueue,
          maxEventAge: cdk.Duration.hours(1),
          retryAttempts: 2,
        }),
      );
    }

    const uiOrigin = new s3.Bucket(this, "PassiveUiOrigin", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const alarmTopicAction = new cloudwatchActions.SnsAction(alerts);
    for (const [identifier, metric] of [
      ["HandlerErrors", handler.metricErrors()],
      ["EvidenceWorkerErrors", evidenceWorker.metricErrors()],
      ["RetentionWorkerErrors", retentionWorker.metricErrors()],
      ["AlertDlqMessages", alertsDlq.metricApproximateNumberOfMessagesVisible()],
      ["EvidenceDlqMessages", evidenceDlq.metricApproximateNumberOfMessagesVisible()],
      ["RetentionDlqMessages", retentionDlq.metricApproximateNumberOfMessagesVisible()],
    ] as Array<[string, cloudwatch.IMetric]>) {
      const alarm = new cloudwatch.Alarm(this, identifier, {
        metric,
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarm.addAlarmAction(alarmTopicAction);
    }

    cdk.Tags.of(this).add("aai-sec:cell-role", active ? "recovery-active" : "passive");
    cdk.Tags.of(this).add("aai-sec:active-authority", active ? "true" : "false");
    cdk.Tags.of(this).add("aai-sec:primary-region", props.primaryRegion);
    new cdk.CfnOutput(this, "PassiveCellStatus", {
      value: active ? "active-not-routed" : "staged-not-serving",
    });
    new cdk.CfnOutput(this, "PassiveControlPlaneApiId", { value: api.apiId });
    new cdk.CfnOutput(this, "PassiveUiOriginBucketName", { value: uiOrigin.bucketName });
    new cdk.CfnOutput(this, "PassiveSecurityAlertsTopicArn", { value: alerts.topicArn });
    // This exact role is deployment authority for the future fault controller;
    // it is never selected by an operator, UI request or model output.
    new cdk.CfnOutput(this, "RegionalFaultTargetExecutionRoleArn", {
      value: handler.role!.roleArn,
    });
    new cdk.CfnOutput(this, "RegionalFaultTargetFunctionArn", {
      value: handler.functionArn,
    });
    new cdk.CfnOutput(this, "RegionalFaultCanaryQueueArn", {
      value: regionalFaultCanaryQueue.queueArn,
    });
  }
}

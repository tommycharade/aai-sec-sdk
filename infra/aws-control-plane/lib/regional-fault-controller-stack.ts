import * as path from "node:path";
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as scheduler from "aws-cdk-lib/aws-scheduler";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as stepfunctions from "aws-cdk-lib/aws-stepfunctions";

/** Exact deployment-owned fault boundary for one Regional runtime cell. */
export interface RegionalFaultCellBoundary {
  readonly region: string;
  readonly targetRoleArn: string;
  readonly auditBucketArn: string;
  readonly dynamodbTableArns: readonly string[];
  readonly signingKeyArn: string;
  readonly queueArns: readonly string[];
}

/** Secret-free deployment inputs for the independent Regional fault controller. */
export interface RegionalFaultControllerProps extends cdk.StackProps {
  readonly primary: RegionalFaultCellBoundary;
  readonly recovery: RegionalFaultCellBoundary;
  readonly journalTableName: string;
  readonly journalTableArn: string;
  readonly securityAlertTopicArn: string;
}

const regionPattern = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const rolePattern = /^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role\/(?:[A-Za-z0-9+=,.@_-]+\/)*[A-Za-z0-9+=,.@_-]+$/;
const bucketPattern = /^arn:(aws|aws-us-gov|aws-cn):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

function requireCell(cell: RegionalFaultCellBoundary, label: string): void {
  if (!regionPattern.test(cell.region) || !rolePattern.test(cell.targetRoleArn)) {
    throw new Error(`${label} fault cell Region or target role is invalid`);
  }
  if (!bucketPattern.test(cell.auditBucketArn)) {
    throw new Error(`${label} fault audit bucket ARN is invalid`);
  }
  if (
    cell.dynamodbTableArns.length !== 4
    || new Set(cell.dynamodbTableArns).size !== 4
    || cell.dynamodbTableArns.some((arn) => !new RegExp(
      `^arn:(aws|aws-us-gov|aws-cn):dynamodb:${cell.region}:\\d{12}:table\\/[A-Za-z0-9_.-]{3,255}$`,
    ).test(arn))
  ) {
    throw new Error(`${label} fault boundary requires four exact DynamoDB tables`);
  }
  if (!new RegExp(
    `^arn:(aws|aws-us-gov|aws-cn):kms:${cell.region}:\\d{12}:key\\/[A-Za-z0-9-]{32,128}$`,
  ).test(cell.signingKeyArn)) {
    throw new Error(`${label} fault signing key ARN is invalid`);
  }
  if (
    cell.queueArns.length < 1
    || cell.queueArns.length > 4
    || new Set(cell.queueArns).size !== cell.queueArns.length
    || cell.queueArns.some((arn) => !new RegExp(
      `^arn:(aws|aws-us-gov|aws-cn):sqs:${cell.region}:\\d{12}:[A-Za-z0-9_-]{1,80}$`,
    ).test(arn))
  ) {
    throw new Error(`${label} fault queue ARNs are invalid`);
  }
}

/**
 * Deploy the private, compensated fault-exercise workflow in the witness Region.
 *
 * The workflow has no API, UI route or broad StartExecution grant. Its first
 * task is a code-owned probe gate that currently always fails, so this stack
 * cannot mutate IAM until real target-only provider probes are implemented.
 */
export class RegionalFaultControllerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: RegionalFaultControllerProps) {
    super(scope, id, props);

    const coordinationRegion = props.env?.region;
    requireCell(props.primary, "primary");
    requireCell(props.recovery, "recovery");
    if (
      !coordinationRegion
      || !regionPattern.test(coordinationRegion)
      || new Set([coordinationRegion, props.primary.region, props.recovery.region]).size !== 3
      || props.primary.targetRoleArn === props.recovery.targetRoleArn
    ) {
      throw new Error("coordination, primary and recovery fault Regions and roles must be distinct");
    }
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(props.journalTableName)) {
      throw new Error("fault journal table name is invalid");
    }
    const tableArnPattern = new RegExp(
      `^arn:(aws|aws-us-gov|aws-cn):dynamodb:${coordinationRegion}:(\\d{12}):table\\/${props.journalTableName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
    );
    const journalIdentity = tableArnPattern.exec(props.journalTableArn);
    if (!journalIdentity) {
      throw new Error("fault journal ARN differs from the coordination Region or table name");
    }
    const [, partition, deploymentAccount] = journalIdentity;
    if (!new RegExp(
      `^arn:${partition}:sns:${coordinationRegion}:${deploymentAccount}:[A-Za-z0-9_-]{1,256}$`,
    ).test(props.securityAlertTopicArn)) {
      throw new Error("security alert topic ARN is invalid or outside the coordination Region");
    }
    const deploymentPrefix = `arn:${partition}:`;
    for (const cell of [props.primary, props.recovery]) {
      if (
        !cell.targetRoleArn.startsWith(`${deploymentPrefix}iam::${deploymentAccount}:role/`)
        || !cell.auditBucketArn.startsWith(`${deploymentPrefix}s3:::`)
        || !cell.signingKeyArn.startsWith(`${deploymentPrefix}kms:${cell.region}:${deploymentAccount}:key/`)
        || cell.dynamodbTableArns.some((arn) => !arn.startsWith(`${deploymentPrefix}dynamodb:${cell.region}:${deploymentAccount}:table/`))
        || cell.queueArns.some((arn) => !arn.startsWith(`${deploymentPrefix}sqs:${cell.region}:${deploymentAccount}:`))
      ) {
        throw new Error("fault cell resources must share the journal partition and account");
      }
    }

    const alerts = sns.Topic.fromTopicArn(this, "SecurityAlerts", props.securityAlertTopicArn);
    const watchdogDlq = new sqs.Queue(this, "FaultWatchdogDeadLetters", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const scheduleGroup = new scheduler.CfnScheduleGroup(this, "FaultWatchdogScheduleGroup", {
      name: "aai-sec-regional-fault-watchdogs",
    });

    const lambdaCode = lambda.Code.fromAsset(path.join(__dirname, "../../.."), {
      ignoreMode: cdk.IgnoreMode.GIT,
      exclude: [
        "*",
        "!scripts/",
        "scripts/*",
        "!scripts/__init__.py",
        "!scripts/verify_aws_regional_activation.py",
        "!scripts/plan_aws_regional_fault_exercise.py",
        "!scripts/regional_fault_controller_lambda.py",
        "!scripts/regional_fault_cleanup_lambda.py",
        "!scripts/regional_fault_probe_lambda.py",
      ],
    });
    const commonFunction = {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      code: lambdaCode,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      reservedConcurrentExecutions: 1,
    } as const;
    const probeFunction = new lambda.Function(this, "FaultProbe", {
      ...commonFunction,
      handler: "scripts.regional_fault_probe_lambda.handler",
      description: "Fail-closed Regional fault probe gate; no provider authority",
    });
    const cleanupFunction = new lambda.Function(this, "FaultCleanup", {
      ...commonFunction,
      handler: "scripts.regional_fault_cleanup_lambda.handler",
      description: "Expiry-safe exact Regional IAM fault cleanup",
    });
    const watchdogRole = new iam.Role(this, "FaultWatchdogInvocationRole", {
      assumedBy: new iam.ServicePrincipal("scheduler.amazonaws.com"),
      description: "Invokes only the Regional fault cleanup Lambda",
    });
    watchdogRole.addToPolicy(new iam.PolicyStatement({
      actions: ["lambda:InvokeFunction"],
      resources: [cleanupFunction.functionArn],
    }));
    watchdogRole.addToPolicy(new iam.PolicyStatement({
      actions: ["sqs:SendMessage"],
      resources: [watchdogDlq.queueArn],
    }));

    const cellEnvironment = (prefix: string, cell: RegionalFaultCellBoundary): Record<string, string> => ({
      [`${prefix}_FAULT_TARGET_ROLE_ARN`]: cell.targetRoleArn,
      [`${prefix}_FAULT_AUDIT_BUCKET_ARN`]: cell.auditBucketArn,
      [`${prefix}_FAULT_DYNAMODB_TABLE_ARNS`]: JSON.stringify(cell.dynamodbTableArns),
      [`${prefix}_FAULT_SIGNING_KEY_ARN`]: cell.signingKeyArn,
      [`${prefix}_FAULT_QUEUE_ARNS`]: JSON.stringify(cell.queueArns),
    });
    const runtimeEnvironment = {
      ...cellEnvironment("PRIMARY", props.primary),
      ...cellEnvironment("RECOVERY", props.recovery),
      TRANSITION_JOURNAL_TABLE_NAME: props.journalTableName,
      FAULT_WATCHDOG_SCHEDULE_GROUP: scheduleGroup.name!,
      FAULT_WATCHDOG_ROLE_ARN: watchdogRole.roleArn,
      FAULT_CLEANUP_FUNCTION_ARN: cleanupFunction.functionArn,
      FAULT_WATCHDOG_DLQ_ARN: watchdogDlq.queueArn,
    };
    for (const [key, value] of Object.entries(runtimeEnvironment)) {
      cleanupFunction.addEnvironment(key, value);
    }
    const controllerFunction = new lambda.Function(this, "FaultController", {
      ...commonFunction,
      handler: "scripts.regional_fault_controller_lambda.handler",
      description: "Exact, journal-conditioned Regional fault mutations",
      environment: runtimeEnvironment,
    });

    const journalActions = [
      "dynamodb:DeleteItem", "dynamodb:GetItem", "dynamodb:PutItem",
      "dynamodb:TransactWriteItems", "dynamodb:UpdateItem",
    ];
    controllerFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: journalActions,
      resources: [props.journalTableArn],
    }));
    controllerFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ["iam:DeleteRolePolicy", "iam:ListRolePolicies", "iam:PutRolePolicy"],
      resources: [props.primary.targetRoleArn, props.recovery.targetRoleArn],
    }));
    controllerFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ["scheduler:CreateSchedule", "scheduler:DeleteSchedule"],
      resources: [
        `arn:${partition}:scheduler:${coordinationRegion}:${deploymentAccount}:schedule/${scheduleGroup.name}/aai-sec-fault-*`,
      ],
    }));
    controllerFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ["iam:PassRole"],
      resources: [watchdogRole.roleArn],
      conditions: { StringEquals: { "iam:PassedToService": "scheduler.amazonaws.com" } },
    }));
    cleanupFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem", "dynamodb:TransactWriteItems"],
      resources: [props.journalTableArn],
    }));
    cleanupFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ["iam:DeleteRolePolicy"],
      resources: [props.primary.targetRoleArn, props.recovery.targetRoleArn],
    }));

    const workflowRole = new iam.Role(this, "FaultWorkflowRole", {
      assumedBy: new iam.ServicePrincipal("states.amazonaws.com"),
      description: "Invokes only Regional fault workflow Lambdas",
    });
    workflowRole.addToPolicy(new iam.PolicyStatement({
      actions: ["lambda:InvokeFunction"],
      resources: [probeFunction.functionArn, controllerFunction.functionArn, cleanupFunction.functionArn],
    }));

    const invoke = (functionName: string, payload: Record<string, unknown>, next: string): Record<string, unknown> => ({
      Type: "Task",
      Resource: "arn:aws:states:::lambda:invoke",
      Parameters: { FunctionName: functionName, Payload: payload },
      Retry: [{
        ErrorEquals: [
          "Lambda.ServiceException", "Lambda.AWSLambdaException",
          "Lambda.SdkClientException", "Lambda.TooManyRequestsException",
        ],
        IntervalSeconds: 2,
        BackoffRate: 2,
        MaxAttempts: 3,
      }],
      ResultPath: null,
      Next: next,
    });
    const controllerPayload = (operation: string): Record<string, unknown> => ({
      schemaVersion: 1,
      operation,
      "manifest.$": "$.manifest",
      "faultAuthority.$": "$.faultAuthority",
    });
    const probePayload = (phase: string): Record<string, unknown> => ({
      schemaVersion: 1,
      phase,
      "manifest.$": "$.manifest",
      "faultAuthority.$": "$.faultAuthority",
    });
    const compensationPayload = {
      schemaVersion: 1,
      "faultId.$": "$.faultAuthority.faultId",
      "authoritySha256.$": "$.controller.authoritySha256",
      "targetCellRole.$": "$.faultAuthority.targetCellRole",
    };
    const failCatch = [{ ErrorEquals: ["States.ALL"], ResultPath: "$.failure", Next: "Compensate" }];
    const definition: Record<string, unknown> = {
      Comment: "Private Regional dependency-fault workflow with independent cleanup",
      StartAt: "VerifyPreconditions",
      TimeoutSeconds: 1200,
      States: {
        VerifyPreconditions: {
          ...invoke("${ProbeArn}", probePayload("preconditions"), "AcquireFaultLock"),
          Catch: [{ ErrorEquals: ["States.ALL"], ResultPath: "$.failure", Next: "PreconditionFailed" }],
        },
        AcquireFaultLock: {
          ...invoke("${ControllerArn}", controllerPayload("acquire"), "ArmWatchdog"),
          ResultSelector: { "authoritySha256.$": "$.Payload.authoritySha256" },
          ResultPath: "$.controller",
          Catch: [{ ErrorEquals: ["States.ALL"], ResultPath: "$.failure", Next: "ReleaseUnarmedLock" }],
        },
        ReleaseUnarmedLock: {
          ...invoke("${ControllerArn}", controllerPayload("release-unarmed-lock"), "AcquireFailed"),
          Catch: [{ ErrorEquals: ["States.ALL"], ResultPath: "$.cleanupFailure", Next: "CompensationFailed" }],
        },
        ArmWatchdog: { ...invoke("${ControllerArn}", controllerPayload("arm-watchdog"), "ApplyDeny"), Catch: failCatch },
        ApplyDeny: { ...invoke("${ControllerArn}", controllerPayload("apply-deny"), "VerifyDependencyUnavailable"), Catch: failCatch },
        VerifyDependencyUnavailable: { ...invoke("${ProbeArn}", probePayload("dependency-unavailable"), "VerifyExecutionDenied"), Catch: failCatch },
        VerifyExecutionDenied: { ...invoke("${ProbeArn}", probePayload("execution-denied-no-bypass"), "RemoveDeny"), Catch: failCatch },
        RemoveDeny: { ...invoke("${ControllerArn}", controllerPayload("remove-deny"), "VerifyRecovery"), Catch: failCatch },
        VerifyRecovery: { ...invoke("${ProbeArn}", probePayload("dependency-and-target-recovered"), "DisarmWatchdog"), Catch: failCatch },
        DisarmWatchdog: { ...invoke("${ControllerArn}", controllerPayload("disarm-watchdog"), "SealEvidence"), Catch: failCatch },
        SealEvidence: {
          ...invoke("${ControllerArn}", controllerPayload("seal-evidence"), "ExerciseComplete"),
          Catch: [{ ErrorEquals: ["States.ALL"], ResultPath: "$.failure", Next: "CompletionFailed" }],
        },
        Compensate: {
          ...invoke("${CleanupArn}", compensationPayload, "ExerciseFailed"),
          Catch: [{ ErrorEquals: ["States.ALL"], ResultPath: "$.cleanupFailure", Next: "CompensationFailed" }],
        },
        ExerciseComplete: { Type: "Succeed" },
        PreconditionFailed: { Type: "Fail", Error: "RegionalFaultPreconditionFailed" },
        AcquireFailed: { Type: "Fail", Error: "RegionalFaultAcquireFailed" },
        ExerciseFailed: { Type: "Fail", Error: "RegionalFaultExerciseFailed" },
        CompensationFailed: { Type: "Fail", Error: "RegionalFaultCompensationFailed" },
        CompletionFailed: { Type: "Fail", Error: "RegionalFaultEvidenceSealFailed" },
      },
    };

    const workflowLogs = new logs.LogGroup(this, "FaultWorkflowLogs", {
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const stateMachine = new stepfunctions.CfnStateMachine(this, "FaultStateMachine", {
      roleArn: workflowRole.roleArn,
      stateMachineName: "aai-sec-regional-fault-controller",
      stateMachineType: "STANDARD",
      definitionString: JSON.stringify(definition),
      definitionSubstitutions: {
        ProbeArn: probeFunction.functionArn,
        ControllerArn: controllerFunction.functionArn,
        CleanupArn: cleanupFunction.functionArn,
      },
      loggingConfiguration: {
        destinations: [{ cloudWatchLogsLogGroup: { logGroupArn: workflowLogs.logGroupArn } }],
        includeExecutionData: false,
        level: "ERROR",
      },
    });
    stateMachine.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
    // CloudWatch Logs delivery control-plane APIs do not support resource-level
    // permissions. Keep this exceptional wildcard on the workflow role only,
    // with the exact AWS-documented delivery actions and no log-content reads.
    workflowRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        "logs:CreateLogDelivery", "logs:DeleteLogDelivery", "logs:DescribeLogGroups",
        "logs:DescribeResourcePolicies", "logs:GetLogDelivery", "logs:ListLogDeliveries",
        "logs:PutResourcePolicy", "logs:UpdateLogDelivery",
      ],
      resources: ["*"],
    }));

    for (const [id, alarm] of [
      ["FaultControllerErrors", controllerFunction.metricErrors({ statistic: "Sum" })],
      ["FaultCleanupErrors", cleanupFunction.metricErrors({ statistic: "Sum" })],
      ["FaultProbeErrors", probeFunction.metricErrors({ statistic: "Sum" })],
      ["FaultWatchdogDeadLetterAlarm", watchdogDlq.metricApproximateNumberOfMessagesVisible({ statistic: "Maximum" })],
    ] as const) {
      const resourceAlarm = new cloudwatch.Alarm(this, id, {
        metric: alarm,
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      resourceAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alerts));
    }
    const workflowFailures = new cloudwatch.Alarm(this, "FaultWorkflowFailures", {
      metric: new cloudwatch.Metric({
        namespace: "AWS/States",
        metricName: "ExecutionsFailed",
        statistic: "Sum",
        dimensionsMap: { StateMachineArn: stateMachine.attrArn },
      }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    workflowFailures.addAlarmAction(new cloudwatchActions.SnsAction(alerts));

    new cdk.CfnOutput(this, "RegionalFaultControllerStateMachineArn", { value: stateMachine.attrArn });
    new cdk.CfnOutput(this, "RegionalFaultControllerStatus", {
      value: "probes-disabled-no-fault-authority",
    });
    new cdk.CfnOutput(this, "RegionalFaultWatchdogDlqArn", { value: watchdogDlq.queueArn });
  }
}

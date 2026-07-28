import * as path from "node:path";
import * as fs from "node:fs";
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as authorizers from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as sqs from "aws-cdk-lib/aws-sqs";

/** Initial production-shaped AWS boundary for the fleet management UI. */
export class AwsControlPlaneStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const table = new dynamodb.Table(this, "ControlPlaneTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    table.addGlobalSecondaryIndex({
      indexName: "DecisionTimeline",
      partitionKey: { name: "timeline_pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "timeline_sk", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const presence = new dynamodb.Table(this, "PresenceTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const idempotency = new dynamodb.Table(this, "IdempotencyTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const audit = new s3.Bucket(this, "AuditBucket", {
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(cdk.Duration.days(365)),
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
    });
    const auditReplicaArn = process.env.AUDIT_REPLICA_BUCKET_ARN;
    if (auditReplicaArn) {
      const replicationRole = new iam.Role(this, "AuditReplicationRole", {
        assumedBy: new iam.ServicePrincipal("s3.amazonaws.com"),
        description: "Replicate immutable control-plane audit versions to the recovery region",
      });
      replicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetReplicationConfiguration", "s3:ListBucket"],
          resources: [audit.bucketArn],
        }),
      );
      replicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: [
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectRetention",
            "s3:GetObjectLegalHold",
          ],
          resources: [audit.arnForObjects("*")],
        }),
      );
      replicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
          resources: [`${auditReplicaArn}/*`],
        }),
      );
      const auditResource = audit.node.defaultChild as s3.CfnBucket;
      auditResource.replicationConfiguration = {
        role: replicationRole.roleArn,
        rules: [
          {
            id: "replicate-audit-to-recovery-region",
            status: "Enabled",
            destination: { bucket: auditReplicaArn, storageClass: "STANDARD" },
          },
        ],
      };
    }

    const scopedToolRole = new iam.Role(this, "ScopedToolRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "Synthetic least-privilege provider role for the AWS scope-policy example",
      inlinePolicies: {
        ReadSyntheticAudit: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ["s3:GetObject"],
              resources: [audit.arnForObjects("tenant=tenant-demo/agent-claude-local/*")],
            }),
          ],
        }),
      },
    });
    const securityAlerts = new sns.Topic(this, "SecurityAlerts", {
      displayName: "AAI Security control-plane alerts",
      enforceSSL: true,
    });
    const securityAlertsDlq = new sqs.Queue(this, "SecurityAlertsDlq", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
    });
    const securityAlertsQueue = new sqs.Queue(this, "SecurityAlertsQueue", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      visibilityTimeout: cdk.Duration.seconds(60),
      retentionPeriod: cdk.Duration.days(14),
      deadLetterQueue: { queue: securityAlertsDlq, maxReceiveCount: 5 },
      enforceSSL: true,
    });
    securityAlerts.addSubscription(
      new subscriptions.SqsSubscription(securityAlertsQueue, {
        deadLetterQueue: securityAlertsDlq,
        rawMessageDelivery: false,
      }),
    );

    const userPool = new cognito.UserPool(this, "OperatorUserPool", {
      userPoolName: "aai-sec-operators",
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      mfa: cognito.Mfa.OPTIONAL,
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      customAttributes: { tenant_id: new cognito.StringAttribute({ mutable: false }) },
      passwordPolicy: { minLength: 14, requireLowercase: true, requireUppercase: true, requireDigits: true, requireSymbols: true },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const domainPrefix = `aai-sec-${this.account?.slice(-8) ?? "control"}`.toLowerCase();
    const userPoolDomain = userPool.addDomain("ManagedLogin", {
      cognitoDomain: { domainPrefix },
      // Use the current branding-editor experience so the hosted signup page
      // can carry the same visual identity as the control-plane landing page.
      managedLoginVersion: cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
    });
    new cognito.CfnUserPoolGroup(this, "PlatformAdmins", { userPoolId: userPool.userPoolId, groupName: "platform-admin", description: "Operators allowed to change tenant control-plane state" });
    const trialOnboarding = new lambda.Function(this, "TrialOnboarding", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "trial_onboarding.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      environment: { CONTROL_TABLE: table.tableName, TRIAL_DAYS: "14" },
    });
    table.grantReadWriteData(trialOnboarding);
    // Do not reference userPool.userPoolArn here: Cognito embeds the trigger
    // Lambda in the pool resource, so that reference creates a CloudFormation
    // cycle. The trigger receives and validates the originating pool ID from
    // Cognito; the role is limited to this one administrative action and does
    // not receive user lookup, attribute-write, or pool-management rights.
    trialOnboarding.addToRolePolicy(new iam.PolicyStatement({ actions: ["cognito-idp:AdminAddUserToGroup"], resources: [`arn:aws:cognito-idp:${this.region}:${this.account}:userpool/*`] }));
    userPool.addTrigger(cognito.UserPoolOperation.POST_CONFIRMATION, trialOnboarding);
    const client = userPool.addClient("WebClient", {
      generateSecret: false,
      authFlows: { userSrp: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls: ["http://localhost:5174/auth/callback", "https://d2ir54klde64bd.cloudfront.net/auth/callback"],
        logoutUrls: ["http://localhost:5174/", "https://d2ir54klde64bd.cloudfront.net/"],
      },
    });

    // Keep the authentication handoff reproducible with the rest of the
    // control plane. The landing page uses a dark navy/teal system; applying
    // the same style to Cognito prevents a trust-breaking visual discontinuity
    // between “Start free trial” and account creation.
    new cognito.CfnManagedLoginBranding(this, "ManagedLoginBranding", {
      userPoolId: userPool.userPoolId,
      clientId: client.userPoolClientId,
      settings: JSON.parse(fs.readFileSync(path.join(__dirname, "../branding-settings.json"), "utf8")),
      assets: [{
        bytes: fs.readFileSync(path.join(__dirname, "../aai-security-logo.svg")).toString("base64"),
        category: "FORM_LOGO",
        colorMode: "DARK",
        extension: "SVG",
      }],
    });

    const handler = new lambda.Function(this, "ControlPlaneHandler", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "handler.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(15),
      memorySize: 512,
      environment: {
        CONTROL_TABLE: table.tableName,
        PRESENCE_TABLE: presence.tableName,
        IDEMPOTENCY_TABLE: idempotency.tableName,
        AUDIT_BUCKET: audit.bucketName,
      },
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    table.grantReadWriteData(handler);
    presence.grantReadWriteData(handler);
    idempotency.grantReadWriteData(handler);
    audit.grantPut(handler);
    handler.addToRolePolicy(new iam.PolicyStatement({ actions: ["sts:AssumeRole"], resources: [scopedToolRole.roleArn] }));

    const api = new apigwv2.HttpApi(this, "ControlPlaneApi", {
      apiName: "aai-sec-control-plane",
      corsPreflight: { allowHeaders: ["authorization", "content-type"], allowMethods: [apigwv2.CorsHttpMethod.ANY], allowOrigins: ["*"] },
    });
    const issuer = `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`;
    const jwt = new authorizers.HttpJwtAuthorizer("CognitoAuthorizer", issuer, { jwtAudience: [client.userPoolClientId] });
    // Agent enrollment and short-lived session calls are authenticated by the
    // handler with one-time/expiring credentials, not by an operator JWT.
    api.addRoutes({ path: "/agent/{proxy+}", methods: [apigwv2.HttpMethod.ANY], integration: new integrations.HttpLambdaIntegration("AgentIntegration", handler) });
    api.addRoutes({ path: "/{proxy+}", methods: [apigwv2.HttpMethod.OPTIONS], integration: new integrations.HttpLambdaIntegration("OptionsIntegration", handler) });
    api.addRoutes({ path: "/{proxy+}", methods: [apigwv2.HttpMethod.ANY], integration: new integrations.HttpLambdaIntegration("ApiIntegration", handler), authorizer: jwt });

    const controlPlaneErrors = new cloudwatch.Alarm(this, "ControlPlaneErrors", {
      metric: handler.metricErrors({ period: cdk.Duration.minutes(5), statistic: "Sum" }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: "Control-plane errors require security-operator investigation.",
    });
    controlPlaneErrors.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const controlPlaneThrottles = new cloudwatch.Alarm(this, "ControlPlaneThrottles", {
      metric: handler.metricThrottles({ period: cdk.Duration.minutes(5), statistic: "Sum" }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: "Control-plane throttling may prevent policy or stop-state propagation.",
    });
    controlPlaneThrottles.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const idempotencyThrottles = new cloudwatch.Alarm(this, "IdempotencyThrottles", {
      metric: idempotency.metricThrottledRequestsForOperation("PutItem", { period: cdk.Duration.minutes(5), statistic: "Sum" }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: "Idempotency persistence throttling must be investigated before retrying side effects.",
    });
    idempotencyThrottles.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));

    const uiBucket = new s3.Bucket(this, "UiBucket", { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, encryption: s3.BucketEncryption.S3_MANAGED, enforceSSL: true, removalPolicy: cdk.RemovalPolicy.RETAIN });
    const distribution = new cloudfront.Distribution(this, "UiDistribution", { defaultBehavior: { origin: origins.S3BucketOrigin.withOriginAccessControl(uiBucket), viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS }, defaultRootObject: "index.html", errorResponses: [{ httpStatus: 403, responseHttpStatus: 200, responsePagePath: "/index.html" }, { httpStatus: 404, responseHttpStatus: 200, responsePagePath: "/index.html" }] });
    new s3deploy.BucketDeployment(this, "UiPlaceholder", { destinationBucket: uiBucket, sources: [s3deploy.Source.data("index.html", "<!doctype html><html><body><h1>AAI Security Control Plane</h1><p>UI deployment pending.</p></body></html>")] });

    new cdk.CfnOutput(this, "ApiUrl", { value: api.apiEndpoint });
    new cdk.CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
    new cdk.CfnOutput(this, "UserPoolClientId", { value: client.userPoolClientId });
    new cdk.CfnOutput(this, "CognitoDomain", { value: userPoolDomain.baseUrl() });
    new cdk.CfnOutput(this, "UiUrl", { value: `https://${distribution.domainName}` });
    new cdk.CfnOutput(this, "UiBucketName", { value: uiBucket.bucketName });
    new cdk.CfnOutput(this, "ControlTableName", { value: table.tableName });
    new cdk.CfnOutput(this, "IdempotencyTableName", { value: idempotency.tableName });
    new cdk.CfnOutput(this, "ScopedToolRoleArn", { value: scopedToolRole.roleArn });
    new cdk.CfnOutput(this, "SecurityAlertsTopicArn", { value: securityAlerts.topicArn });
    new cdk.CfnOutput(this, "SecurityAlertsQueueArn", { value: securityAlertsQueue.queueArn });
    new cdk.CfnOutput(this, "SecurityAlertsDlqArn", { value: securityAlertsDlq.queueArn });
    if (auditReplicaArn) {
      new cdk.CfnOutput(this, "AuditReplicaBucketArn", { value: auditReplicaArn });
      new cdk.CfnOutput(this, "AuditReplicaRegion", { value: process.env.AUDIT_REPLICA_REGION ?? "eu-west-1" });
    }
  }
}

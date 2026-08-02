import * as path from "node:path";
import * as fs from "node:fs";
import { createHash } from "node:crypto";
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as authorizers from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as kms from "aws-cdk-lib/aws-kms";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3Notifications from "aws-cdk-lib/aws-s3-notifications";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";

const runtimeManifestFields = new Set([
  "schemaVersion",
  "sdkVersion",
  "sdkRevision",
  "sourceOriginDigest",
  "packageDigest",
  "gatewayDigest",
  "hookDigest",
  "host",
]);

/** Fail synthesis before an invalid deployment-owned trust bundle can reach Lambda. */
function validateRuntimeManifests(raw: string): void {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("runtime-manifests.json must contain valid JSON");
  }
  if (!Array.isArray(value) || value.length > 32) {
    throw new Error("runtime-manifests.json must contain at most 32 manifests");
  }
  const identities = new Set<string>();
  for (const candidate of value) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      throw new Error("each runtime manifest must be an object");
    }
    const manifest = candidate as Record<string, unknown>;
    const keys = Object.keys(manifest);
    if (keys.length !== runtimeManifestFields.size || keys.some((key) => !runtimeManifestFields.has(key))) {
      throw new Error("runtime manifest schema is invalid");
    }
    if (
      manifest.schemaVersion !== 1
      || (manifest.host !== "claude-code" && manifest.host !== "codex-cli")
      || typeof manifest.sdkVersion !== "string"
      || manifest.sdkVersion.length < 1
      || manifest.sdkVersion.length > 64
      || typeof manifest.sdkRevision !== "string"
      || !/^[0-9a-f]{40}$/.test(manifest.sdkRevision)
    ) {
      throw new Error("runtime manifest identity is invalid");
    }
    for (const field of ["sourceOriginDigest", "packageDigest", "gatewayDigest", "hookDigest"]) {
      if (typeof manifest[field] !== "string" || !/^[0-9a-f]{64}$/.test(manifest[field] as string)) {
        throw new Error(`runtime manifest ${field} must be SHA-256`);
      }
    }
    const identity = `${manifest.host}:${manifest.sdkVersion}`;
    if (identities.has(identity)) {
      throw new Error("runtime manifest host and SDK version must be unique");
    }
    identities.add(identity);
  }
}

/** Bind the deployable manifest bytes to a separately reviewed release approval record. */
function validateRuntimeManifestApprovals(raw: string, manifestBundle: string): void {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("runtime-manifests.provenance.json must contain valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("runtime manifest approval bundle must be an object");
  }
  const approval = value as Record<string, unknown>;
  if (
    Object.keys(approval).sort().join(",") !== "approvals,manifestBundleSha256,schemaVersion"
    || approval.schemaVersion !== 1
    || !Array.isArray(approval.approvals)
    || approval.approvals.length > 32
    || approval.manifestBundleSha256 !== createHash("sha256").update(manifestBundle).digest("hex")
  ) {
    throw new Error("runtime manifest approval bundle is invalid or stale");
  }
  const manifests = JSON.parse(manifestBundle) as Array<Record<string, unknown>>;
  const approvalFields = new Set([
    "hosts",
    "releaseEvidenceSha256",
    "releaseTag",
    "sdkRevision",
    "sdkVersion",
    "sourceOriginDigest",
  ]);
  const approved = new Map<string, Record<string, unknown>>();
  for (const candidate of approval.approvals) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      throw new Error("runtime manifest approval entry must be an object");
    }
    const entry = candidate as Record<string, unknown>;
    const keys = Object.keys(entry);
    if (keys.length !== approvalFields.size || keys.some((key) => !approvalFields.has(key))) {
      throw new Error("runtime manifest approval entry schema is invalid");
    }
    const hosts = entry.hosts;
    if (
      !Array.isArray(hosts)
      || hosts.length < 1
      || hosts.length !== new Set(hosts).size
      || hosts.some((host) => host !== "claude-code" && host !== "codex-cli")
      || typeof entry.sdkVersion !== "string"
      || entry.sdkVersion.length < 1
      || entry.sdkVersion.length > 64
      || typeof entry.releaseTag !== "string"
      || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(entry.releaseTag)
      || typeof entry.sdkRevision !== "string"
      || !/^[0-9a-f]{40}$/.test(entry.sdkRevision)
      || typeof entry.sourceOriginDigest !== "string"
      || !/^[0-9a-f]{64}$/.test(entry.sourceOriginDigest)
      || typeof entry.releaseEvidenceSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(entry.releaseEvidenceSha256)
    ) {
      throw new Error("runtime manifest approval identity is invalid");
    }
    for (const host of hosts) {
      const identity = `${host}:${entry.sdkVersion}`;
      if (approved.has(identity)) {
        throw new Error("runtime manifest approval identity is ambiguous");
      }
      approved.set(identity, entry);
    }
  }
  if (approved.size !== manifests.length) {
    throw new Error("runtime manifest approvals must exactly cover configured manifests");
  }
  for (const manifest of manifests) {
    const entry = approved.get(`${manifest.host}:${manifest.sdkVersion}`);
    if (
      !entry
      || entry.sdkRevision !== manifest.sdkRevision
      || entry.sourceOriginDigest !== manifest.sourceOriginDigest
    ) {
      throw new Error("runtime manifest approval identity does not match its manifest");
    }
  }
}

/** Initial production-shaped AWS boundary for the fleet management UI. */
export class AwsControlPlaneStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const entraTenantId = process.env.ENTRA_TENANT_ID?.trim();
    const entraClientId = process.env.ENTRA_CLIENT_ID?.trim();
    const entraClientSecretName = process.env.ENTRA_CLIENT_SECRET_NAME?.trim();
    const entraAaiTenantId = process.env.ENTRA_AAI_TENANT_ID?.trim();
    const entraScimTokenSecretName = process.env.ENTRA_SCIM_TOKEN_SECRET_NAME?.trim();
    const entraStrongAuthValue = process.env.ENTRA_STRONG_AUTH_ENFORCED?.trim();
    if (entraStrongAuthValue && !["true", "false"].includes(entraStrongAuthValue)) {
      throw new Error("ENTRA_STRONG_AUTH_ENFORCED must be true or false");
    }
    const entraStrongAuthEnforced = entraStrongAuthValue === "true";
    const runtimeManifestPath = path.join(__dirname, "../lambda/runtime-manifests.json");
    const runtimeManifestBundle = fs.readFileSync(runtimeManifestPath, "utf8");
    validateRuntimeManifests(runtimeManifestBundle);
    const runtimeApprovalPath = path.join(
      __dirname,
      "../lambda/runtime-manifests.provenance.json",
    );
    const runtimeApprovalBundle = fs.readFileSync(runtimeApprovalPath, "utf8");
    validateRuntimeManifestApprovals(runtimeApprovalBundle, runtimeManifestBundle);
    const runtimeManifestCount = (JSON.parse(runtimeManifestBundle) as unknown[]).length;
    const runtimeManifestDigest = createHash("sha256").update(runtimeManifestBundle).digest("hex");
    const runtimeApprovalDigest = createHash("sha256").update(runtimeApprovalBundle).digest("hex");
    const entraInputs = [entraTenantId, entraClientId, entraClientSecretName, entraAaiTenantId];
    if (entraInputs.some(Boolean) && !entraInputs.every(Boolean)) {
      throw new Error(
        "ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET_NAME and ENTRA_AAI_TENANT_ID must be configured together",
      );
    }
    if (
      entraTenantId
      && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(entraTenantId)
    ) {
      throw new Error("ENTRA_TENANT_ID must be a tenant-specific UUID");
    }
    if (entraScimTokenSecretName && !entraInputs.every(Boolean)) {
      throw new Error("ENTRA_SCIM_TOKEN_SECRET_NAME requires the complete Entra OIDC configuration");
    }
    if (entraStrongAuthEnforced && !entraInputs.every(Boolean)) {
      throw new Error("ENTRA_STRONG_AUTH_ENFORCED requires the complete Entra OIDC configuration");
    }

    const table = new dynamodb.Table(this, "ControlPlaneTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    table.addGlobalSecondaryIndex({
      indexName: "DecisionTimeline",
      partitionKey: { name: "timeline_pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "timeline_sk", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: "EndpointDetectionTenants",
      partitionKey: { name: "endpoint_detection_pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "endpoint_detection_sk", type: dynamodb.AttributeType.STRING },
      // Only tenant registration fields are needed to schedule reconciliation.
      // Endpoint reports and credentials remain outside this cross-tenant index.
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });
    table.addGlobalSecondaryIndex({
      indexName: "EvidenceAssuranceTenants",
      partitionKey: { name: "evidence_assurance_pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "evidence_assurance_sk", type: dynamodb.AttributeType.STRING },
      // Scheduling needs only the tenant root key; evidence/job content never
      // crosses tenants through this index.
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    const presence = new dynamodb.Table(this, "PresenceTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const idempotency = new dynamodb.Table(this, "IdempotencyTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // SCIM lifecycle state is isolated from runtime policy and session state.
    // Its tenant is deployment-owned, while alternate partitions support
    // bounded membership lookup in both the user and group directions.
    const scim = new dynamodb.Table(this, "ScimLifecycleTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      deletionProtection: true,
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
    // Derived assurance pages are private, short-lived and content-bound back
    // to an immutable audit event. They live outside the Object Lock bucket so
    // inventory jobs never recursively inventory their own output.
    const evidenceReports = new s3.Bucket(this, "EvidenceReportBucket", {
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(30), noncurrentVersionExpiration: cdk.Duration.days(7) }],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
    });
    const auditReplicaArn = process.env.AUDIT_REPLICA_BUCKET_ARN;
    let auditBatchReplicationRole: iam.Role | undefined;
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
            // Metrics require the V2 replication schema. Keep the empty
            // prefix explicit so every immutable audit version is eligible;
            // delete markers are not evidence and remain excluded.
            priority: 1,
            filter: { prefix: "" },
            deleteMarkerReplication: { status: "Disabled" },
            status: "Enabled",
            destination: {
              bucket: auditReplicaArn,
              storageClass: "STANDARD",
              metrics: { status: "Enabled" },
            },
          },
        ],
      };

      // S3 Batch Operations starts replication for historical versions, while
      // the replication role above remains the only principal that can copy
      // immutable bytes to the recovery bucket. The manifest/report bucket is
      // deliberately separate from the WORM audit namespace.
      auditBatchReplicationRole = new iam.Role(this, "AuditBatchReplicationRole", {
        assumedBy: new iam.ServicePrincipal("batchoperations.s3.amazonaws.com"),
        description: "Initiate bounded historical audit replication jobs",
      });
      auditBatchReplicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetReplicationConfiguration", "s3:PutInventoryConfiguration"],
          resources: [audit.bucketArn],
        }),
      );
      auditBatchReplicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:PutObject"],
          resources: [evidenceReports.arnForObjects("replication-reports/*")],
        }),
      );
      auditBatchReplicationRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["s3:InitiateReplication"],
          resources: [audit.arnForObjects("*")],
        }),
      );
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
    if (auditReplicaArn) {
      // Replication metrics make these object-level failure events available.
      // Route them through the same durable SNS/SQS channel as other security
      // failures so a provider-side copy failure cannot remain console-only.
      const destination = new s3Notifications.SnsDestination(securityAlerts);
      audit.addEventNotification(
        s3.EventType.REPLICATION_OPERATION_FAILED_REPLICATION,
        destination,
      );
      audit.addEventNotification(
        s3.EventType.REPLICATION_OPERATION_NOT_TRACKED,
        destination,
      );
    }
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
    const endpointDetectionDlq = new sqs.Queue(this, "EndpointDetectionDlq", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
    });
    const rolloutReconciliationDlq = new sqs.Queue(this, "RolloutReconciliationDlq", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
    });
    const evidenceWorkerDlq = new sqs.Queue(this, "EvidenceWorkerDlq", {
      fifo: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
    });
    const evidenceWorkerQueue = new sqs.Queue(this, "EvidenceWorkerQueue", {
      fifo: true,
      contentBasedDeduplication: false,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      // Six times the worker timeout leaves room for Lambda throttling and
      // event-source backoff without exposing the same page concurrently.
      visibilityTimeout: cdk.Duration.minutes(6),
      retentionPeriod: cdk.Duration.days(4),
      deadLetterQueue: { queue: evidenceWorkerDlq, maxReceiveCount: 3 },
      enforceSSL: true,
    });
    const evidenceRetentionWorkerDlq = new sqs.Queue(this, "EvidenceRetentionWorkerDlq", {
      fifo: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
    });
    const evidenceRetentionWorkerQueue = new sqs.Queue(this, "EvidenceRetentionWorkerQueue", {
      fifo: true,
      contentBasedDeduplication: false,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      visibilityTimeout: cdk.Duration.minutes(6),
      retentionPeriod: cdk.Duration.days(4),
      deadLetterQueue: { queue: evidenceRetentionWorkerDlq, maxReceiveCount: 3 },
      enforceSSL: true,
    });
    const evidenceScheduleDlq = new sqs.Queue(this, "EvidenceScheduleDlq", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
    });
    const evidenceRetentionScheduleDlq = new sqs.Queue(this, "EvidenceRetentionScheduleDlq", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
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
      customAttributes: {
        tenant_id: new cognito.StringAttribute({ mutable: false }),
        // This OIDC-signed object ID is only a lookup key. The SCIM lifecycle
        // table independently decides whether the identity is active and what
        // canonical roles its provisioned groups receive.
        entra_object_id: new cognito.StringAttribute({ mutable: true, minLen: 36, maxLen: 36 }),
      },
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
    const nativeOperatorGroups = [
      ["PlatformAdmins", "platform-admin", "Tenant administration and break-glass recovery"],
      ["SecurityOperators", "security-operator", "Security monitoring, response and approval operations"],
      ["PolicyAuthors", "policy-author", "Draft and update policy resources"],
      ["PolicyApprovers", "policy-approver", "Approve policy and exact-action changes"],
      ["FleetOperators", "fleet-operator", "Manage deployments, groups and enrolled agents"],
      ["IncidentResponders", "incident-responder", "Contain agents and acknowledge incidents"],
      ["Auditors", "auditor", "Read-only evidence and compliance access"],
    ] as const;
    for (const [constructId, groupName, description] of nativeOperatorGroups) {
      new cognito.CfnUserPoolGroup(this, constructId, {
        userPoolId: userPool.userPoolId,
        groupName,
        description,
      });
    }
    // Runtime policy trust is asymmetric: only these two service roles may
    // sign, while enrolled hosts receive a separately pinned public key.
    const policySigningKey = new kms.Key(this, "PolicySigningKey", {
      alias: "alias/aai-sec-policy-signing",
      description: "Signs immutable tenant-bound AAI Security policy bundles",
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // This key is staged before signer cutover so endpoint trust bundles can
    // carry both the current single-Region key and the future multi-Region key.
    // Deploying it does not change active policy authority. A reviewed DR
    // exercise must prove trust convergence before POLICY_SIGNING_KEY_ARN is
    // switched, avoiding a failover that silently invalidates active policy.
    const regionalPolicySigningKey = new kms.Key(this, "RegionalPolicySigningKey", {
      description: "Staged multi-Region policy signing authority for controlled recovery",
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      multiRegion: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const trialOnboarding = new lambda.Function(this, "TrialOnboarding", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "trial_onboarding.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      environment: {
        CONTROL_TABLE: table.tableName,
        TRIAL_DAYS: "14",
        POLICY_SIGNING_KEY_ARN: policySigningKey.keyArn,
      },
    });
    table.grantReadWriteData(trialOnboarding);
    policySigningKey.grant(trialOnboarding, "kms:Sign");
    // Do not reference userPool.userPoolArn here: Cognito embeds the trigger
    // Lambda in the pool resource, so that reference creates a CloudFormation
    // cycle. The trigger receives and validates the originating pool ID from
    // Cognito; the role is limited to this one administrative action and does
    // not receive user lookup, attribute-write, or pool-management rights.
    trialOnboarding.addToRolePolicy(new iam.PolicyStatement({ actions: ["cognito-idp:AdminAddUserToGroup"], resources: [`arn:aws:cognito-idp:${this.region}:${this.account}:userpool/*`] }));
    userPool.addTrigger(cognito.UserPoolOperation.POST_CONFIRMATION, trialOnboarding);
    let entraProvider: cognito.UserPoolIdentityProviderOidc | undefined;
    if (entraTenantId && entraClientId && entraClientSecretName && entraAaiTenantId) {
      entraProvider = new cognito.UserPoolIdentityProviderOidc(this, "MicrosoftEntraId", {
        userPool,
        name: "MicrosoftEntraID",
        issuerUrl: `https://login.microsoftonline.com/${entraTenantId}/v2.0`,
        clientId: entraClientId,
        // Resolve the secret at deployment time. It is never written to the
        // repository, Lambda environment or CloudFormation plaintext output.
        clientSecret: cdk.SecretValue.secretsManager(entraClientSecretName).toString(),
        scopes: ["openid", "email", "profile"],
        attributeRequestMethod: cognito.OidcAttributeRequestMethod.GET,
        attributeMapping: {
          email: cognito.ProviderAttribute.other("email"),
          givenName: cognito.ProviderAttribute.other("given_name"),
          familyName: cognito.ProviderAttribute.other("family_name"),
          custom: {
            entra_object_id: cognito.ProviderAttribute.other("oid"),
          },
        },
      });
      const entraClaims = new lambda.Function(this, "MicrosoftEntraClaims", {
        runtime: lambda.Runtime.PYTHON_3_13,
        architecture: lambda.Architecture.ARM_64,
        handler: "pre_token.handler",
        code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
        timeout: cdk.Duration.seconds(5),
        memorySize: 128,
        environment: {
          ENTRA_PROVIDER_NAME: entraProvider.providerName,
          ENTRA_TENANT_ID: entraTenantId,
          SCIM_ENABLED: entraScimTokenSecretName ? "true" : "false",
          SCIM_TABLE: scim.tableName,
          CONTROL_TABLE: table.tableName,
          SCIM_AAI_TENANT_ID: entraAaiTenantId,
          ENTRA_STRONG_AUTH_ENFORCED: entraStrongAuthEnforced ? "true" : "false",
        },
      });
      scim.grantReadData(entraClaims);
      table.grantReadData(entraClaims);
      // V2 can add independently verified provider provenance to both ID and
      // access tokens. The API still resolves application tenant and roles
      // from server-owned configuration; these claims are not authorization.
      userPool.addTrigger(
        cognito.UserPoolOperation.PRE_TOKEN_GENERATION_CONFIG,
        entraClaims,
        cognito.LambdaVersion.V2_0,
      );
    }
    const client = userPool.addClient("WebClient", {
      generateSecret: false,
      authFlows: { userSrp: true },
      // SCIM deactivation is enforced at every refresh and any already-issued
      // operator token expires within the five-minute lifecycle SLO.
      accessTokenValidity: cdk.Duration.minutes(5),
      idTokenValidity: cdk.Duration.minutes(5),
      refreshTokenValidity: cdk.Duration.days(1),
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO,
        ...(entraProvider
          ? [cognito.UserPoolClientIdentityProvider.custom(entraProvider.providerName)]
          : []),
      ],
      readAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ email: true, givenName: true, familyName: true })
        .withCustomAttributes("tenant_id", "entra_object_id"),
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

    const controlPlaneEnvironment = {
      CONTROL_TABLE: table.tableName,
      PRESENCE_TABLE: presence.tableName,
      IDEMPOTENCY_TABLE: idempotency.tableName,
      AUDIT_BUCKET: audit.bucketName,
      EVIDENCE_REPORT_BUCKET: evidenceReports.bucketName,
      EVIDENCE_QUEUE_URL: evidenceWorkerQueue.queueUrl,
      EVIDENCE_RETENTION_QUEUE_URL: evidenceRetentionWorkerQueue.queueUrl,
      ENTRA_PROVIDER_ENABLED: entraProvider ? "true" : "false",
      ENTRA_TENANT_ID: entraTenantId ?? "",
      ENTRA_AAI_TENANT_ID: entraAaiTenantId ?? "",
      ENTRA_STRONG_AUTH_ENFORCED: entraStrongAuthEnforced ? "true" : "false",
      SCIM_ENABLED: entraScimTokenSecretName ? "true" : "false",
      SCIM_TABLE: scim.tableName,
      SPLUNK_STUB_ENABLED: "true",
      SECURITY_ALERTS_TOPIC_ARN: securityAlerts.topicArn,
      RUNTIME_ATTESTATION_MANIFESTS_SHA256: runtimeManifestDigest,
      RUNTIME_ATTESTATION_APPROVALS_SHA256: runtimeApprovalDigest,
      POLICY_SIGNING_KEY_ARN: policySigningKey.keyArn,
    };
    const handler = new lambda.Function(this, "ControlPlaneHandler", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "handler.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(15),
      memorySize: 512,
      environment: controlPlaneEnvironment,
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    table.grantReadWriteData(handler);
    policySigningKey.grant(handler, "kms:Sign", "kms:GetPublicKey");
    // CDK's read/write convenience grant excludes TransactWriteItems. Policy
    // activation uses one same-table transaction so active authority, the
    // immutable candidate, and the retired predecessor cannot diverge.
    table.grant(handler, "dynamodb:TransactWriteItems");
    presence.grantReadWriteData(handler);
    idempotency.grantReadWriteData(handler);
    scim.grantReadWriteData(handler);
    audit.grantPut(handler);
    // Evidence governance is tenant-prefix constrained in Lambda and requires
    // exact-version reads before retention or legal-hold mutation. S3 Object
    // Lock COMPLIANCE mode remains the non-bypassable enforcement boundary.
    audit.grantRead(handler);
    handler.addToRolePolicy(new iam.PolicyStatement({
      actions: ["s3:GetObjectRetention", "s3:GetObjectLegalHold", "s3:PutObjectRetention", "s3:PutObjectLegalHold"],
      resources: [audit.arnForObjects("tenant=*")],
    }));
    securityAlerts.grantPublish(handler);
    evidenceReports.grantRead(handler);
    evidenceWorkerQueue.grantSendMessages(handler);
    evidenceRetentionWorkerQueue.grantSendMessages(handler);
    handler.addToRolePolicy(new iam.PolicyStatement({ actions: ["sts:AssumeRole"], resources: [scopedToolRole.roleArn] }));

    const evidenceWorker = new lambda.Function(this, "EvidenceWorker", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "evidence_worker.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(60),
      memorySize: 1024,
      // This worker intentionally advances one revision-bound page by sending
      // the next exact revision to its dedicated FIFO queue. Lambda otherwise
      // terminates that valid chain after roughly 16 invocations. Application
      // page limits, optimistic revisions, FIFO deduplication, reserved
      // concurrency, retries, the DLQ and alarms remain the runaway controls.
      recursiveLoop: lambda.RecursiveLoop.ALLOW,
      reservedConcurrentExecutions: 5,
      environment: controlPlaneEnvironment,
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    table.grantReadWriteData(evidenceWorker);
    audit.grantRead(evidenceWorker);
    audit.grantPut(evidenceWorker);
    evidenceWorker.addToRolePolicy(new iam.PolicyStatement({
      actions: ["s3:GetObjectRetention", "s3:GetObjectLegalHold"],
      resources: [audit.arnForObjects("tenant=*")],
    }));
    evidenceReports.grantReadWrite(evidenceWorker);
    securityAlerts.grantPublish(evidenceWorker);
    evidenceWorkerQueue.grantSendMessages(evidenceWorker);
    evidenceWorker.addEventSource(new lambdaEventSources.SqsEventSource(evidenceWorkerQueue, {
      batchSize: 1,
      reportBatchItemFailures: false,
    }));

    const evidenceRetentionWorker = new lambda.Function(this, "EvidenceRetentionWorker", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "retention_worker.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(60),
      memorySize: 1024,
      // The dedicated FIFO continuation is intentional and bounded by exact
      // revisions, 100,000 pages, reserved concurrency, retries and its DLQ.
      recursiveLoop: lambda.RecursiveLoop.ALLOW,
      reservedConcurrentExecutions: 5,
      environment: controlPlaneEnvironment,
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    table.grantReadWriteData(evidenceRetentionWorker);
    table.grant(evidenceRetentionWorker, "dynamodb:TransactWriteItems");
    audit.grantRead(evidenceRetentionWorker);
    audit.grantPut(evidenceRetentionWorker);
    evidenceRetentionWorker.addToRolePolicy(new iam.PolicyStatement({
      actions: ["s3:GetObjectRetention", "s3:PutObjectRetention"],
      resources: [audit.arnForObjects("tenant=*")],
    }));
    securityAlerts.grantPublish(evidenceRetentionWorker);
    evidenceRetentionWorkerQueue.grantSendMessages(evidenceRetentionWorker);
    evidenceRetentionWorker.addEventSource(
      new lambdaEventSources.SqsEventSource(evidenceRetentionWorkerQueue, {
        batchSize: 1,
        reportBatchItemFailures: false,
      }),
    );

    const endpointDetectionRule = new events.Rule(this, "EndpointDetectionSchedule", {
      description: "Reconcile tenant endpoint evidence and persist actionable detections",
      schedule: events.Schedule.rate(cdk.Duration.minutes(5)),
      enabled: true,
    });
    endpointDetectionRule.addTarget(
      new eventTargets.LambdaFunction(handler, {
        event: events.RuleTargetInput.fromObject({
          source: "aai.endpoint-detection",
          schemaVersion: 1,
        }),
        deadLetterQueue: endpointDetectionDlq,
        maxEventAge: cdk.Duration.hours(1),
        retryAttempts: 2,
      }),
    );
    const rolloutReconciliationRule = new events.Rule(this, "RolloutReconciliationSchedule", {
      description: "Measure managed rollout convergence and pause unhealthy deployment rings",
      schedule: events.Schedule.rate(cdk.Duration.minutes(5)),
      enabled: true,
    });
    rolloutReconciliationRule.addTarget(
      new eventTargets.LambdaFunction(handler, {
        event: events.RuleTargetInput.fromObject({
          source: "aai.rollout-reconciliation",
          schemaVersion: 1,
        }),
        deadLetterQueue: rolloutReconciliationDlq,
        maxEventAge: cdk.Duration.hours(1),
        retryAttempts: 2,
      }),
    );
    const evidenceAssuranceRule = new events.Rule(this, "EvidenceAssuranceSchedule", {
      description: "Run tenant-wide asynchronous evidence assurance and gap detection",
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      enabled: true,
    });
    evidenceAssuranceRule.addTarget(
      new eventTargets.LambdaFunction(handler, {
        event: events.RuleTargetInput.fromObject({
          source: "aai.evidence-assurance",
          schemaVersion: 1,
        }),
        deadLetterQueue: evidenceScheduleDlq,
        maxEventAge: cdk.Duration.hours(1),
        retryAttempts: 2,
      }),
    );
    const evidenceRetentionRule = new events.Rule(this, "EvidenceRetentionSchedule", {
      description: "Dispatch due asynchronous evidence-retention backfills",
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
      enabled: true,
    });
    evidenceRetentionRule.addTarget(
      new eventTargets.LambdaFunction(handler, {
        event: events.RuleTargetInput.fromObject({
          source: "aai.evidence-retention",
          schemaVersion: 1,
        }),
        deadLetterQueue: evidenceRetentionScheduleDlq,
        maxEventAge: cdk.Duration.hours(1),
        retryAttempts: 2,
      }),
    );

    const api = new apigwv2.HttpApi(this, "ControlPlaneApi", {
      apiName: "aai-sec-control-plane",
      corsPreflight: { allowHeaders: ["authorization", "content-type"], allowMethods: [apigwv2.CorsHttpMethod.ANY], allowOrigins: ["*"] },
    });
    const issuer = `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`;
    const jwt = new authorizers.HttpJwtAuthorizer("CognitoAuthorizer", issuer, { jwtAudience: [client.userPoolClientId] });
    let scimEndpointStatus = "not-configured";
    if (entraScimTokenSecretName && entraAaiTenantId) {
      const scimToken = secretsmanager.Secret.fromSecretNameV2(
        this,
        "MicrosoftEntraScimToken",
        entraScimTokenSecretName,
      );
      const scimHandler = new lambda.Function(this, "MicrosoftEntraScim", {
        runtime: lambda.Runtime.PYTHON_3_13,
        architecture: lambda.Architecture.ARM_64,
        handler: "scim.handler",
        code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
        timeout: cdk.Duration.seconds(15),
        memorySize: 256,
        environment: {
          SCIM_TABLE: scim.tableName,
          SCIM_AAI_TENANT_ID: entraAaiTenantId,
          SCIM_TOKEN_SECRET_NAME: entraScimTokenSecretName,
        },
      });
      scim.grantReadWriteData(scimHandler);
      scimToken.grantRead(scimHandler);
      api.addRoutes({
        path: "/scim/v2/{proxy+}",
        methods: [apigwv2.HttpMethod.ANY],
        integration: new integrations.HttpLambdaIntegration("MicrosoftEntraScimIntegration", scimHandler),
      });
      scimEndpointStatus = "configured";
    }
    // Agent enrollment and short-lived session calls are authenticated by the
    // handler with one-time/expiring credentials, not by an operator JWT.
    api.addRoutes({ path: "/agent/{proxy+}", methods: [apigwv2.HttpMethod.ANY], integration: new integrations.HttpLambdaIntegration("AgentIntegration", handler) });
    // Endpoint sensors authenticate with a per-device bearer that also signs
    // the exact path-free payload. Cognito operator tokens are never accepted
    // on this machine ingestion boundary.
    api.addRoutes({ path: "/endpoint-evidence/{proxy+}", methods: [apigwv2.HttpMethod.ANY], integration: new integrations.HttpLambdaIntegration("EndpointEvidenceIntegration", handler) });
    // Discovery connectors authenticate with a revocable source-scoped bearer
    // in the handler. They are deliberately isolated from operator JWT routes.
    api.addRoutes({ path: "/discovery-ingest/{proxy+}", methods: [apigwv2.HttpMethod.ANY], integration: new integrations.HttpLambdaIntegration("DiscoveryIngestIntegration", handler) });
    api.addRoutes({ path: "/{proxy+}", methods: [apigwv2.HttpMethod.OPTIONS], integration: new integrations.HttpLambdaIntegration("OptionsIntegration", handler) });
    api.addRoutes({ path: "/{proxy+}", methods: [apigwv2.HttpMethod.ANY], integration: new integrations.HttpLambdaIntegration("ApiIntegration", handler), authorizer: jwt });

    // Managed discovery separates provider credentials, source ingestion
    // authority and schedule invocation. The browser receives only setup
    // metadata; neither secret value is returned by the control plane.
    const discoverySecretKey = new kms.Key(this, "DiscoverySecretKey", {
      enableKeyRotation: true,
      description: "Tenant-scoped managed discovery provider and connector secrets",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const discoveryCollectorDlq = new sqs.Queue(this, "DiscoveryCollectorDlq", {
      encryption: sqs.QueueEncryption.KMS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    const discoveryCollectorFunctionName = "aai-sec-managed-discovery-collector";
    const discoveryCollectorArn = cdk.Stack.of(this).formatArn({
      service: "lambda",
      resource: "function",
      resourceName: discoveryCollectorFunctionName,
      arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
    });
    const discoveryCollector = new lambda.Function(this, "DiscoveryCollector", {
      functionName: discoveryCollectorFunctionName,
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "discovery_collector.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        CONTROL_TABLE: table.tableName,
        CONTROL_PLANE_API_URL: api.apiEndpoint,
      },
      tracing: lambda.Tracing.PASS_THROUGH,
    });
    discoveryCollector.addToRolePolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem", "dynamodb:UpdateItem"],
      resources: [table.tableArn],
    }));
    const providerSecretPrefix = "aai-sec/discovery/providers/";
    const connectorSecretPrefix = "aai-sec/discovery/connectors/";
    const providerSecretResources = [
      `arn:${cdk.Aws.PARTITION}:secretsmanager:${this.region}:${this.account}:secret:${providerSecretPrefix}*`,
    ];
    const connectorSecretResources = [
      `arn:${cdk.Aws.PARTITION}:secretsmanager:${this.region}:${this.account}:secret:${connectorSecretPrefix}*`,
    ];
    discoveryCollector.addToRolePolicy(new iam.PolicyStatement({
      actions: ["secretsmanager:GetSecretValue"],
      resources: providerSecretResources,
      conditions: {
        StringEquals: { "secretsmanager:ResourceTag/aai-sec:purpose": "discovery-provider" },
      },
    }));
    discoveryCollector.addToRolePolicy(new iam.PolicyStatement({
      actions: ["secretsmanager:GetSecretValue"],
      resources: connectorSecretResources,
      conditions: {
        StringEquals: { "secretsmanager:ResourceTag/aai-sec:purpose": "discovery-connector" },
      },
    }));
    discoverySecretKey.grantDecrypt(discoveryCollector);

    const discoverySchedulerRole = new iam.Role(this, "DiscoverySchedulerRole", {
      assumedBy: new iam.ServicePrincipal("scheduler.amazonaws.com"),
      description: "Invokes only the AAI Security managed discovery collector",
    });
    discoveryCollector.grantInvoke(discoverySchedulerRole);
    discoveryCollectorDlq.grantSendMessages(discoverySchedulerRole);

    // Use the deterministic ARN rather than a Lambda Ref here. The collector
    // needs the API endpoint, while the API integrates this handler; avoiding
    // a handler-to-collector Ref prevents a CloudFormation dependency cycle.
    handler.addEnvironment("DISCOVERY_COLLECTOR_ARN", discoveryCollectorArn);
    handler.addEnvironment("DISCOVERY_SCHEDULER_ROLE_ARN", discoverySchedulerRole.roleArn);
    handler.addEnvironment("DISCOVERY_COLLECTOR_DLQ_ARN", discoveryCollectorDlq.queueArn);
    handler.addEnvironment("DISCOVERY_SECRET_KMS_KEY_ARN", discoverySecretKey.keyArn);
    handler.addEnvironment("DISCOVERY_PROVIDER_SECRET_PREFIX", providerSecretPrefix);
    handler.addEnvironment("DISCOVERY_CONNECTOR_SECRET_PREFIX", connectorSecretPrefix);
    handler.addEnvironment("AWS_ACCOUNT_ID", this.account);
    handler.addEnvironment("AWS_PARTITION", cdk.Aws.PARTITION);
    handler.addToRolePolicy(new iam.PolicyStatement({
      actions: ["secretsmanager:DescribeSecret"],
      resources: providerSecretResources,
      conditions: {
        StringEquals: { "secretsmanager:ResourceTag/aai-sec:purpose": "discovery-provider" },
      },
    }));
    handler.addToRolePolicy(new iam.PolicyStatement({
      actions: ["secretsmanager:CreateSecret", "secretsmanager:TagResource"],
      resources: connectorSecretResources,
      conditions: {
        StringEquals: { "aws:RequestTag/aai-sec:purpose": "discovery-connector" },
        Null: { "aws:RequestTag/aai-sec:tenant-id": "false" },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": ["aai-sec:tenant-id", "aai-sec:purpose"],
        },
      },
    }));
    handler.addToRolePolicy(new iam.PolicyStatement({
      actions: ["secretsmanager:DeleteSecret"],
      resources: connectorSecretResources,
    }));
    // Secrets Manager performs both data-key generation and a decrypt check
    // when it creates a customer-key-encrypted secret. Bind decrypt to calls
    // routed through Secrets Manager; the handler deliberately has no
    // GetSecretValue permission and therefore cannot retrieve secret bytes.
    discoverySecretKey.grantEncrypt(handler);
    discoverySecretKey.grantDecrypt(new kms.ViaServicePrincipal(
      `secretsmanager.${this.region}.amazonaws.com`,
      handler.grantPrincipal,
    ));
    handler.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        "scheduler:CreateSchedule",
        "scheduler:GetSchedule",
        "scheduler:UpdateSchedule",
        "scheduler:DeleteSchedule",
      ],
      resources: [
        `arn:${cdk.Aws.PARTITION}:scheduler:${this.region}:${this.account}:schedule/default/aai-sec-discovery-*`,
      ],
    }));
    handler.addToRolePolicy(new iam.PolicyStatement({
      actions: ["iam:PassRole"],
      resources: [discoverySchedulerRole.roleArn],
      conditions: { StringEquals: { "iam:PassedToService": "scheduler.amazonaws.com" } },
    }));

    const controlPlaneErrors = new cloudwatch.Alarm(this, "ControlPlaneErrors", {
      metric: handler.metricErrors({ period: cdk.Duration.minutes(5), statistic: "Sum" }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: "Control-plane errors require security-operator investigation.",
    });
    controlPlaneErrors.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const discoveryCollectorErrors = new cloudwatch.Alarm(this, "DiscoveryCollectorErrors", {
      metric: discoveryCollector.metricErrors({
        period: cdk.Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: "Managed discovery collection failed and may reduce inventory freshness.",
    });
    discoveryCollectorErrors.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const discoveryCollectorDeadLetters = new cloudwatch.Alarm(
      this,
      "DiscoveryCollectorDeadLetters",
      {
        metric: discoveryCollectorDlq.metricApproximateNumberOfMessagesVisible({
          period: cdk.Duration.minutes(5),
          statistic: "Maximum",
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: "A managed discovery schedule exhausted bounded retries.",
      },
    );
    discoveryCollectorDeadLetters.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const endpointDetectionDeadLetters = new cloudwatch.Alarm(
      this,
      "EndpointDetectionDeadLetters",
      {
        metric: endpointDetectionDlq.metricApproximateNumberOfMessagesVisible({
          period: cdk.Duration.minutes(5),
          statistic: "Maximum",
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: "Endpoint detection reconciliation exhausted bounded retries.",
      },
    );
    endpointDetectionDeadLetters.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const rolloutReconciliationDeadLetters = new cloudwatch.Alarm(
      this,
      "RolloutReconciliationDeadLetters",
      {
        metric: rolloutReconciliationDlq.metricApproximateNumberOfMessagesVisible({
          period: cdk.Duration.minutes(5),
          statistic: "Maximum",
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: "Managed rollout reconciliation exhausted bounded retries.",
      },
    );
    rolloutReconciliationDeadLetters.addAlarmAction(
      new cloudwatchActions.SnsAction(securityAlerts),
    );
    const evidenceWorkerErrors = new cloudwatch.Alarm(this, "EvidenceWorkerErrors", {
      metric: evidenceWorker.metricErrors({ period: cdk.Duration.minutes(5), statistic: "Sum" }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: "Asynchronous evidence verification failed and may delay assurance.",
    });
    evidenceWorkerErrors.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    const evidenceRetentionWorkerErrors = new cloudwatch.Alarm(
      this,
      "EvidenceRetentionWorkerErrors",
      {
        metric: evidenceRetentionWorker.metricErrors({
          period: cdk.Duration.minutes(5),
          statistic: "Sum",
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: "Asynchronous evidence retention failed and requires attention.",
      },
    );
    evidenceRetentionWorkerErrors.addAlarmAction(
      new cloudwatchActions.SnsAction(securityAlerts),
    );
    for (const [id, queue, description] of [
      ["EvidenceWorkerDeadLetters", evidenceWorkerDlq, "Evidence verification exhausted bounded retries."],
      ["EvidenceScheduleDeadLetters", evidenceScheduleDlq, "Scheduled evidence assurance exhausted bounded retries."],
      ["EvidenceRetentionWorkerDeadLetters", evidenceRetentionWorkerDlq, "Evidence retention exhausted bounded retries."],
      ["EvidenceRetentionScheduleDeadLetters", evidenceRetentionScheduleDlq, "Scheduled evidence-retention dispatch exhausted bounded retries."],
    ] as const) {
      const alarm = new cloudwatch.Alarm(this, id, {
        metric: queue.metricApproximateNumberOfMessagesVisible({
          period: cdk.Duration.minutes(5),
          statistic: "Maximum",
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: description,
      });
      alarm.addAlarmAction(new cloudwatchActions.SnsAction(securityAlerts));
    }
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
    new cdk.CfnOutput(this, "AuditBucketName", { value: audit.bucketName });
    new cdk.CfnOutput(this, "ControlTableName", { value: table.tableName });
    new cdk.CfnOutput(this, "PresenceTableName", { value: presence.tableName });
    new cdk.CfnOutput(this, "IdempotencyTableName", { value: idempotency.tableName });
    new cdk.CfnOutput(this, "ScimLifecycleTableName", { value: scim.tableName });
    new cdk.CfnOutput(this, "ScopedToolRoleArn", { value: scopedToolRole.roleArn });
    new cdk.CfnOutput(this, "SecurityAlertsTopicArn", { value: securityAlerts.topicArn });
    new cdk.CfnOutput(this, "SecurityAlertsQueueArn", { value: securityAlertsQueue.queueArn });
    new cdk.CfnOutput(this, "SecurityAlertsDlqArn", { value: securityAlertsDlq.queueArn });
    new cdk.CfnOutput(this, "EndpointDetectionDlqArn", { value: endpointDetectionDlq.queueArn });
    new cdk.CfnOutput(this, "RolloutReconciliationDlqArn", {
      value: rolloutReconciliationDlq.queueArn,
    });
    new cdk.CfnOutput(this, "EvidenceReportBucketName", { value: evidenceReports.bucketName });
    new cdk.CfnOutput(this, "EvidenceWorkerDlqArn", { value: evidenceWorkerDlq.queueArn });
    new cdk.CfnOutput(this, "EvidenceScheduleDlqArn", { value: evidenceScheduleDlq.queueArn });
    new cdk.CfnOutput(this, "EvidenceRetentionWorkerDlqArn", {
      value: evidenceRetentionWorkerDlq.queueArn,
    });
    new cdk.CfnOutput(this, "EvidenceRetentionScheduleDlqArn", {
      value: evidenceRetentionScheduleDlq.queueArn,
    });
    new cdk.CfnOutput(this, "DiscoverySecretKmsKeyArn", { value: discoverySecretKey.keyArn });
    new cdk.CfnOutput(this, "PolicySigningKeyArn", { value: policySigningKey.keyArn });
    new cdk.CfnOutput(this, "RegionalPolicySigningKeyArn", {
      value: regionalPolicySigningKey.keyArn,
    });
    new cdk.CfnOutput(this, "DiscoveryProviderSecretNamePrefix", {
      value: providerSecretPrefix,
    });
    new cdk.CfnOutput(this, "DiscoveryCollectorDlqArn", {
      value: discoveryCollectorDlq.queueArn,
    });
    new cdk.CfnOutput(this, "MicrosoftEntraIdStatus", {
      value: entraProvider ? "configured" : "not-configured",
    });
    new cdk.CfnOutput(this, "MicrosoftEntraScimStatus", { value: scimEndpointStatus });
    new cdk.CfnOutput(this, "RuntimeAttestationStatus", {
      value: runtimeManifestCount > 0 ? `configured:${runtimeManifestCount}` : "not-configured",
    });
    if (scimEndpointStatus === "configured") {
      new cdk.CfnOutput(this, "MicrosoftEntraScimEndpoint", {
        value: `${api.apiEndpoint}/scim/v2`,
      });
    }
    if (auditReplicaArn) {
      new cdk.CfnOutput(this, "AuditReplicaBucketArn", { value: auditReplicaArn });
      new cdk.CfnOutput(this, "AuditReplicaRegion", { value: process.env.AUDIT_REPLICA_REGION ?? "eu-west-1" });
      new cdk.CfnOutput(this, "AuditBatchReplicationRoleArn", {
        value: auditBatchReplicationRole!.roleArn,
      });
    }
  }
}

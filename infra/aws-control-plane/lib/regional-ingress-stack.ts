import * as path from "node:path";
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from "aws-cdk-lib/aws-s3";

/** Exact, non-routing identities for one Region's API and UI ingress. */
export interface RegionalIngressProps extends cdk.StackProps {
  readonly cellRole: "primary" | "recovery";
  readonly controlPlaneApiId: string;
  readonly uiBucketName: string;
  readonly certificateArn: string;
  readonly cognitoOrigin: string;
  readonly stableApiDomain: string;
  readonly stableUiDomain: string;
  readonly canaryApiDomain: string;
  readonly canaryUiDomain: string;
}

/** Require one lowercase DNS name without wildcard or trailing-dot aliases. */
function domainName(value: string, label: string): string {
  if (
    value.length > 253
    || !/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)
  ) {
    throw new Error(`${label} must be one exact lowercase DNS name`);
  }
  return value;
}

/** Require one exact HTTPS origin without paths, queries, fragments, or credentials. */
function httpsOrigin(value: string): string {
  if (!/^https:\/\/[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])(?::\d{2,5})?$/.test(value)) {
    throw new Error("Cognito origin must be one exact lowercase HTTPS origin");
  }
  return value;
}

/** Deployment-only Regional API/UI ingress with no DNS or activation authority. */
export class RegionalIngressStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: RegionalIngressProps) {
    super(scope, id, props);
    const account = props.env?.account;
    const region = props.env?.region;
    if (!account || !/^\d{12}$/.test(account) || !region || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) {
      throw new Error("regional ingress requires an explicit account and Region");
    }
    if (!/^[a-z0-9]{8,64}$/.test(props.controlPlaneApiId)) {
      throw new Error("control-plane API ID is invalid");
    }
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(props.uiBucketName)) {
      throw new Error("regional UI bucket name is invalid");
    }
    const certificatePattern = new RegExp(
      `^arn:(aws|aws-us-gov|aws-cn):acm:${region}:${account}:certificate/[0-9a-f-]{36}$`,
      "i",
    );
    if (!certificatePattern.test(props.certificateArn)) {
      throw new Error("certificate must be an exact same-account, same-Region ACM ARN");
    }
    const domains = [
      domainName(props.stableApiDomain, "stable API domain"),
      domainName(props.stableUiDomain, "stable UI domain"),
      domainName(props.canaryApiDomain, "canary API domain"),
      domainName(props.canaryUiDomain, "canary UI domain"),
    ];
    if (new Set(domains).size !== domains.length) {
      throw new Error("regional ingress domains must be distinct");
    }
    const [stableApi, stableUi, canaryApi, canaryUi] = domains;
    const cognitoOrigin = httpsOrigin(props.cognitoOrigin);

    const uiBucket = s3.Bucket.fromBucketName(this, "RegionalUiBucket", props.uiBucketName);
    const uiHandler = new lambda.Function(this, "RegionalUiHandler", {
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: "regional_ui.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      memorySize: 256,
      timeout: cdk.Duration.seconds(10),
      reservedConcurrentExecutions: 20,
      environment: {
        REGIONAL_UI_API_ORIGIN: `https://${stableApi}`,
        REGIONAL_UI_BUCKET: props.uiBucketName,
        REGIONAL_UI_COGNITO_ORIGIN: cognitoOrigin,
      },
    });
    uiHandler.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject"],
        resources: [uiBucket.arnForObjects("*")],
      }),
    );
    const uiApi = new apigwv2.HttpApi(this, "RegionalUiApi", {
      apiName: `aai-sec-${props.cellRole}-regional-ui`,
      disableExecuteApiEndpoint: true,
    });
    const uiIntegration = new integrations.HttpLambdaIntegration(
      "RegionalUiIntegration",
      uiHandler,
    );
    uiApi.addRoutes({ path: "/", methods: [apigwv2.HttpMethod.GET, apigwv2.HttpMethod.HEAD], integration: uiIntegration });
    uiApi.addRoutes({ path: "/{proxy+}", methods: [apigwv2.HttpMethod.GET, apigwv2.HttpMethod.HEAD], integration: uiIntegration });

    const domainResources = new Map<string, apigwv2.CfnDomainName>();
    for (const domain of domains) {
      domainResources.set(
        domain,
        new apigwv2.CfnDomainName(this, `Domain${domain.replace(/[^A-Za-z0-9]/g, "")}`, {
          domainName: domain,
          domainNameConfigurations: [{
            certificateArn: props.certificateArn,
            endpointType: "REGIONAL",
            ipAddressType: "ipv4",
            securityPolicy: "TLS_1_2",
          }],
        }),
      );
    }
    for (const [domain, apiId] of [
      [stableApi, props.controlPlaneApiId],
      [canaryApi, props.controlPlaneApiId],
      [stableUi, uiApi.apiId],
      [canaryUi, uiApi.apiId],
    ]) {
      const domainResource = domainResources.get(domain)!;
      const mapping = new apigwv2.CfnApiMapping(
        this,
        `Mapping${domain.replace(/[^A-Za-z0-9]/g, "")}`,
        { apiId, domainName: domain, stage: "$default" },
      );
      mapping.addResourceDependency(domainResource);
    }

    cdk.Tags.of(this).add("aai-sec:ingress-role", props.cellRole);
    cdk.Tags.of(this).add("aai-sec:routing-authority", "false");
    new cdk.CfnOutput(this, "RegionalIngressStatus", { value: "custom-domains-unrouted" });
    new cdk.CfnOutput(this, "RegionalIngressCellRole", { value: props.cellRole });
    for (const [label, domain] of [
      ["StableApi", stableApi],
      ["StableUi", stableUi],
      ["CanaryApi", canaryApi],
      ["CanaryUi", canaryUi],
    ]) {
      const configuration = domainResources.get(domain)!.attrRegionalDomainName;
      const zone = domainResources.get(domain)!.attrRegionalHostedZoneId;
      new cdk.CfnOutput(this, `${label}RegionalDomainName`, { value: configuration });
      new cdk.CfnOutput(this, `${label}RegionalHostedZoneId`, { value: zone });
    }
  }
}

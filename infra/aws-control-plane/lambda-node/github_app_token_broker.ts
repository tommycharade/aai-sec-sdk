/** Least-privilege GitHub App installation-token broker for policy imports. */
import { createPrivateKey, createSign, KeyObject } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";

const API_VERSION = "2026-03-10";
const MAX_SECRET_BYTES = 32_768;
const MAX_RESPONSE_BYTES = 65_536;
const TOKEN_PATH = /^\/app\/installations\/[1-9][0-9]{0,19}\/access_tokens$/;
const TOKEN_PATTERN = /^[\x21-\x7e]{20,512}$/;

export interface HttpResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

export interface BrokerDependencies {
  readSecret: (secretArn: string) => Promise<string>;
  post: (path: string, headers: Record<string, string>, body: Buffer) => Promise<HttpResult>;
  now: () => number;
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

/** Create the exact short-lived RS256 JWT accepted by GitHub App endpoints. */
export function createAppJwt(clientId: string, privateKeyPem: string, nowSeconds: number): string {
  if (!/^[A-Za-z0-9._-]{6,128}$/.test(clientId)) {
    throw new Error("GitHub App authority is unavailable");
  }
  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw new Error("GitHub App credential is unavailable");
  }
  if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new Error("GitHub App credential is unavailable");
  }
  const issuedAt = Math.floor(nowSeconds) - 60;
  const signingInput = `${base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${base64Url(
    JSON.stringify({ iat: issuedAt, exp: issuedAt + 540, iss: clientId }),
  )}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(key).toString("base64url")}`;
}

function parsePrivateKeySecret(payload: string): string {
  const privateKeyFieldCount = payload.match(/"privateKeyPem"\s*:/g)?.length ?? 0;
  if (Buffer.byteLength(payload, "utf8") > MAX_SECRET_BYTES || privateKeyFieldCount !== 1) {
    throw new Error("GitHub App credential is unavailable");
  }
  let value: unknown;
  try {
    value = JSON.parse(payload);
  } catch {
    throw new Error("GitHub App credential is unavailable");
  }
  if (
    typeof value !== "object"
    || value === null
    || Array.isArray(value)
    || Object.keys(value).length !== 1
    || !("privateKeyPem" in value)
    || typeof value.privateKeyPem !== "string"
  ) {
    throw new Error("GitHub App credential is unavailable");
  }
  return value.privateKeyPem;
}

function parseRepositories(value: string): string[] {
  const repositories = value.split(",");
  if (
    repositories.length < 1
    || repositories.length > 100
    || new Set(repositories).size !== repositories.length
    || repositories.some((repository) => !/^[A-Za-z0-9_.-]{1,100}$/.test(repository))
  ) {
    throw new Error("GitHub App authority is unavailable");
  }
  return repositories;
}

/** Mint one repository- and permission-scoped installation token in memory. */
export async function mintInstallationToken(
  event: unknown,
  environment: NodeJS.ProcessEnv,
  dependencies: BrokerDependencies,
): Promise<{ schemaVersion: 1; token: string; expiresAt: number }> {
  if (
    typeof event !== "object"
    || event === null
    || Array.isArray(event)
    || Object.keys(event).length !== 1
    || !("schemaVersion" in event)
    || event.schemaVersion !== 1
  ) {
    throw new Error("GitHub App token request is invalid");
  }
  const secretArn = environment.POLICY_GITHUB_APP_SECRET_ARN ?? "";
  const clientId = environment.POLICY_GITHUB_APP_CLIENT_ID ?? "";
  const installationId = environment.POLICY_GITHUB_INSTALLATION_ID ?? "";
  if (!secretArn.startsWith("arn:") || !/^[1-9][0-9]{0,19}$/.test(installationId)) {
    throw new Error("GitHub App authority is unavailable");
  }
  const repositories = parseRepositories(environment.POLICY_GITHUB_REPOSITORY_NAMES ?? "");
  const privateKeyPem = parsePrivateKeySecret(await dependencies.readSecret(secretArn));
  const now = dependencies.now();
  const jwt = createAppJwt(clientId, privateKeyPem, now);
  const path = `/app/installations/${installationId}/access_tokens`;
  const requestBody = Buffer.from(JSON.stringify({
    repositories,
    permissions: { contents: "read", metadata: "read", pull_requests: "read" },
  }));
  const response = await dependencies.post(
    path,
    {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${jwt}`,
      "Content-Type": "application/json",
      "User-Agent": "aai-sec-sdk-policy-source",
      "X-GitHub-Api-Version": API_VERSION,
    },
    requestBody,
  );
  if (response.status !== 201 || response.body.length > MAX_RESPONSE_BYTES) {
    throw new Error("GitHub App token exchange failed");
  }
  let result: unknown;
  try {
    result = JSON.parse(response.body.toString("utf8"));
  } catch {
    throw new Error("GitHub App token exchange failed");
  }
  if (typeof result !== "object" || result === null || Array.isArray(result)) {
    throw new Error("GitHub App token exchange failed");
  }
  const token = "token" in result ? result.token : undefined;
  const expiresAtText = "expires_at" in result ? result.expires_at : undefined;
  const permissions = "permissions" in result ? result.permissions : undefined;
  const expiresAt = typeof expiresAtText === "string" ? Date.parse(expiresAtText) / 1000 : NaN;
  if (
    typeof token !== "string"
    || !TOKEN_PATTERN.test(token)
    || typeof expiresAtText !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(expiresAtText)
    || !Number.isInteger(expiresAt)
    || expiresAt < now + 3000
    || expiresAt > now + 3900
    || typeof permissions !== "object"
    || permissions === null
    || Array.isArray(permissions)
    || Object.entries(permissions).some(
      ([name, level]) => !["contents", "metadata", "pull_requests"].includes(name) || level !== "read",
    )
    || !["contents", "metadata", "pull_requests"].every(
      (name) => (permissions as Record<string, unknown>)[name] === "read",
    )
  ) {
    throw new Error("GitHub App token exchange failed");
  }
  return { schemaVersion: 1, token, expiresAt };
}

async function postGitHub(path: string, headers: Record<string, string>, body: Buffer): Promise<HttpResult> {
  if (!TOKEN_PATH.test(path) || body.length > 16_384) {
    throw new Error("GitHub App token request is invalid");
  }
  return await new Promise<HttpResult>((resolve, reject) => {
    const request = httpsRequest(
      { hostname: "api.github.com", port: 443, protocol: "https:", method: "POST", path, headers, timeout: 5000 },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            request.destroy(new Error("GitHub App token exchange failed"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => resolve({
          status: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.concat(chunks),
        }));
      },
    );
    request.on("timeout", () => request.destroy(new Error("GitHub App token exchange failed")));
    request.on("error", () => reject(new Error("GitHub App token exchange failed")));
    request.end(body);
  });
}

const secrets = new SecretsManagerClient({});

/** AWS Lambda entry point; errors are deliberately detail-safe. */
export async function handler(event: unknown): Promise<{ schemaVersion: 1; token: string; expiresAt: number }> {
  return await mintInstallationToken(event, process.env, {
    now: () => Date.now() / 1000,
    post: postGitHub,
    readSecret: async (secretArn) => {
      const response = await secrets.send(new GetSecretValueCommand({ SecretId: secretArn, VersionStage: "AWSCURRENT" }));
      if (typeof response.SecretString !== "string") {
        throw new Error("GitHub App credential is unavailable");
      }
      return response.SecretString;
    },
  });
}

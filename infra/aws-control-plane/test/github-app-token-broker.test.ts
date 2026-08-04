import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import test from "node:test";
import { createAppJwt, mintInstallationToken, type BrokerDependencies } from "../lambda-node/github_app_token_broker";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
const NOW = 1_800_000_000;

function environment(): NodeJS.ProcessEnv {
  return {
    POLICY_GITHUB_APP_SECRET_ARN: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:policy-app",
    POLICY_GITHUB_APP_CLIENT_ID: "Iv1.synthetic-client",
    POLICY_GITHUB_INSTALLATION_ID: "12345678",
    POLICY_GITHUB_REPOSITORY_NAMES: "security-policy,engineering-policy",
  };
}

test("creates a bounded RS256 GitHub App JWT", () => {
  const jwt = createAppJwt("Iv1.synthetic-client", privateKeyPem, NOW);
  const [header, payload, signature] = jwt.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url").toString()), { alg: "RS256", typ: "JWT" });
  assert.deepEqual(JSON.parse(Buffer.from(payload, "base64url").toString()), {
    iat: NOW - 60,
    exp: NOW + 480,
    iss: "Iv1.synthetic-client",
  });
  assert.equal(
    verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, "base64url")),
    true,
  );
});

test("mints an exact repository- and permission-scoped installation token", async () => {
  let observedPath = "";
  let observedBody: unknown;
  const dependencies: BrokerDependencies = {
    now: () => NOW,
    readSecret: async (secretArn) => {
      assert.match(secretArn, /policy-app$/);
      return JSON.stringify({ privateKeyPem });
    },
    post: async (path, headers, body) => {
      observedPath = path;
      observedBody = JSON.parse(body.toString());
      assert.match(headers.Authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
      return {
        status: 201,
        headers: {},
        body: Buffer.from(JSON.stringify({
          token: "ghs_synthetic_installation_token_1234567890",
          expires_at: new Date((NOW + 3600) * 1000).toISOString(),
          permissions: { contents: "read", metadata: "read", pull_requests: "read" },
        })),
      };
    },
  };
  const result = await mintInstallationToken({ schemaVersion: 1 }, environment(), dependencies);
  assert.equal(observedPath, "/app/installations/12345678/access_tokens");
  assert.deepEqual(observedBody, {
    repositories: ["security-policy", "engineering-policy"],
    permissions: { contents: "read", metadata: "read", pull_requests: "read" },
  });
  assert.equal(result.expiresAt, NOW + 3600);
  assert.match(result.token, /^ghs_/);
});

test("fails closed for malformed authority, secrets, broad permissions and expiry", async () => {
  const validResponse = {
    status: 201,
    headers: {},
    body: Buffer.from(JSON.stringify({
      token: "ghs_synthetic_installation_token_1234567890",
      expires_at: new Date((NOW + 3600) * 1000).toISOString(),
      permissions: { contents: "read", metadata: "read", pull_requests: "write" },
    })),
  };
  const dependencies: BrokerDependencies = {
    now: () => NOW,
    readSecret: async () => JSON.stringify({ privateKeyPem }),
    post: async () => validResponse,
  };
  await assert.rejects(
    mintInstallationToken({ schemaVersion: 1 }, environment(), dependencies),
    /token exchange failed/,
  );
  await assert.rejects(
    mintInstallationToken({}, environment(), dependencies),
    /request is invalid/,
  );
  await assert.rejects(
    mintInstallationToken(
      { schemaVersion: 1 },
      environment(),
      { ...dependencies, readSecret: async () => JSON.stringify({ privateKeyPem, token: "leak" }) },
    ),
    /credential is unavailable/,
  );
  await assert.rejects(
    mintInstallationToken(
      { schemaVersion: 1 },
      environment(),
      {
        ...dependencies,
        readSecret: async () => `{"privateKeyPem":${JSON.stringify(privateKeyPem)},"privateKeyPem":"duplicate"}`,
      },
    ),
    /credential is unavailable/,
  );
  assert.throws(() => createAppJwt("Iv1.synthetic-client", "not-a-key", NOW), /credential is unavailable/);
});

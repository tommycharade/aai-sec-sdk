import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { validateDeliveryPackageBundles } from "../lib/delivery-package-authority";

const digest = (value: string): string => createHash("sha256").update(value).digest("hex");
const canonical = (value: Record<string, unknown>): string => JSON.stringify(
  Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])),
);

const runtimeManifests = JSON.stringify([
  {
    schemaVersion: 1,
    sdkVersion: "1.1.0",
    sdkRevision: "a".repeat(40),
    sourceOriginDigest: "b".repeat(64),
    packageDigest: "c".repeat(64),
    gatewayDigest: "d".repeat(64),
    hookDigest: "e".repeat(64),
    host: "claude-code",
  },
]);
const runtimeApprovals = JSON.stringify({
  schemaVersion: 1,
  manifestBundleSha256: digest(runtimeManifests),
  approvals: [
    {
      hosts: ["claude-code"],
      releaseTag: "v1.1.0",
      sdkVersion: "1.1.0",
      sdkRevision: "a".repeat(40),
      sourceOriginDigest: "b".repeat(64),
      releaseEvidenceSha256: "f".repeat(64),
    },
  ],
});

const deliveryPackage = (): Record<string, unknown> => ({
  schemaVersion: 1,
  releaseId: "claude-code:1.1.0",
  host: "claude-code",
  operatingSystem: "darwin",
  architecture: "arm64",
  packageFormat: "pkg",
  bucketArn: "arn:aws:s3:::synthetic-aai-release-bucket",
  objectKey: "releases/v1.1.0/aai-sec.pkg",
  objectVersionId: "synthetic-object-version-1",
  objectSha256: "0".repeat(64),
  providerPackageIdentitySha256: "1".repeat(64),
  packageSignatureEvidenceSha256: "2".repeat(64),
  releaseEvidenceSha256: "f".repeat(64),
});

function authority(value: Record<string, unknown>): [string, string] {
  const packages = `${JSON.stringify([value], null, 2)}\n`;
  const manifestSha256 = digest(canonical(value));
  const approvals = `${JSON.stringify({
    schemaVersion: 1,
    packageBundleSha256: digest(packages),
    approvals: [
      {
        packageId: `delivery:${manifestSha256}`,
        manifestSha256,
        approvedAt: "2026-08-05",
        approverEvidenceSha256: "3".repeat(64),
      },
    ],
  }, null, 2)}\n`;
  return [packages, approvals];
}

test("validates an exact release-bound immutable package", () => {
  const [packages, approvals] = authority(deliveryPackage());
  assert.doesNotThrow(() => validateDeliveryPackageBundles(
    packages,
    approvals,
    runtimeManifests,
    runtimeApprovals,
  ));
});

test("rejects object traversal before synthesis", () => {
  const value = deliveryPackage();
  value.objectKey = "releases/../../unreviewed.pkg";
  const [packages, approvals] = authority(value);
  assert.throws(
    () => validateDeliveryPackageBundles(packages, approvals, runtimeManifests, runtimeApprovals),
    /object key is unsafe/,
  );
});

test("rejects a package that drifts from runtime release evidence", () => {
  const value = deliveryPackage();
  value.releaseEvidenceSha256 = "9".repeat(64);
  const [packages, approvals] = authority(value);
  assert.throws(
    () => validateDeliveryPackageBundles(packages, approvals, runtimeManifests, runtimeApprovals),
    /release evidence does not match/,
  );
});

test("rejects multiple package formats for one signed endpoint platform", () => {
  const deb = deliveryPackage();
  deb.operatingSystem = "linux";
  deb.packageFormat = "deb";
  deb.objectKey = "releases/v1.1.0/aai-sec.deb";
  const rpm = { ...deb };
  rpm.packageFormat = "rpm";
  rpm.objectKey = "releases/v1.1.0/aai-sec.rpm";
  rpm.objectVersionId = "synthetic-object-version-2";
  rpm.objectSha256 = "5".repeat(64);
  const packages = `${JSON.stringify([deb, rpm], null, 2)}\n`;
  const approvals = JSON.stringify({
    schemaVersion: 1,
    packageBundleSha256: digest(packages),
    approvals: [],
  });
  assert.throws(
    () => validateDeliveryPackageBundles(packages, approvals, runtimeManifests, runtimeApprovals),
    /platform authority is ambiguous/,
  );
});

test("rejects approval coverage drift", () => {
  const [packages] = authority(deliveryPackage());
  const approvals = JSON.stringify({
    schemaVersion: 1,
    packageBundleSha256: digest(packages),
    approvals: [],
  });
  assert.throws(
    () => validateDeliveryPackageBundles(packages, approvals, runtimeManifests, runtimeApprovals),
    /do not exactly cover/,
  );
});

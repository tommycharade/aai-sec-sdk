import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

const packageFields = new Set([
  "schemaVersion",
  "releaseId",
  "host",
  "operatingSystem",
  "architecture",
  "packageFormat",
  "bucketArn",
  "objectKey",
  "objectVersionId",
  "objectSha256",
  "providerPackageIdentitySha256",
  "packageSignatureEvidenceSha256",
  "releaseEvidenceSha256",
]);
const approvalFields = new Set([
  "packageId",
  "manifestSha256",
  "approvedAt",
  "approverEvidenceSha256",
]);
const platformFormats = new Map<string, Set<string>>([
  ["darwin", new Set(["pkg"])],
  ["linux", new Set(["deb", "rpm"])],
  ["windows", new Set(["msi", "msix"])],
]);
const sha256Pattern = /^[0-9a-f]{64}$/;

export type DeliveryPackageBundles = {
  packageBundle: string;
  approvalBundle: string;
  packageBundleSha256: string;
  approvalBundleSha256: string;
};

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function exactObject(value: unknown, fields: Set<string>, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== fields.size || keys.some((key) => !fields.has(key))) {
    throw new Error(`${label} schema is invalid`);
  }
  return record;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !sha256Pattern.test(value)) {
    throw new Error(`${label} must be SHA-256`);
  }
  return value;
}

function text(value: unknown, label: string, maximum: number): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function canonical(value: Record<string, unknown>): string {
  const sorted = Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]));
  return JSON.stringify(sorted);
}

/**
 * Validate endpoint-delivery bundles before any Lambda asset can be synthesized.
 * The runtime repeats these checks because deployment validation is not request
 * authority by itself.
 */
export function validateDeliveryPackageBundles(
  packageBundle: string,
  approvalBundle: string,
  runtimeManifestBundle: string,
  runtimeApprovalBundle: string,
): void {
  let packages: unknown;
  let approvals: unknown;
  let runtimeManifests: unknown;
  let runtimeApprovals: unknown;
  try {
    packages = JSON.parse(packageBundle);
    approvals = JSON.parse(approvalBundle);
    runtimeManifests = JSON.parse(runtimeManifestBundle);
    runtimeApprovals = JSON.parse(runtimeApprovalBundle);
  } catch {
    throw new Error("delivery package authority must contain valid JSON");
  }
  if (!Array.isArray(packages) || packages.length > 64) {
    throw new Error("delivery package bundle must contain at most 64 entries");
  }
  if (!Array.isArray(runtimeManifests) || !runtimeApprovals || typeof runtimeApprovals !== "object") {
    throw new Error("runtime release authority is malformed");
  }
  const runtimeApprovalEntries = (runtimeApprovals as Record<string, unknown>).approvals;
  if (!Array.isArray(runtimeApprovalEntries)) {
    throw new Error("runtime release approval authority is malformed");
  }
  const releaseEvidence = new Map<string, string>();
  for (const value of runtimeApprovalEntries) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("runtime release approval authority is malformed");
    }
    const record = value as Record<string, unknown>;
    if (!Array.isArray(record.hosts) || typeof record.sdkVersion !== "string") {
      throw new Error("runtime release approval authority is malformed");
    }
    for (const host of record.hosts) {
      if (typeof host !== "string") throw new Error("runtime release host is malformed");
      releaseEvidence.set(`${host}:${record.sdkVersion}`, digest(record.releaseEvidenceSha256, "releaseEvidenceSha256"));
    }
  }

  const packageIds = new Map<string, string>();
  const platformKeys = new Set<string>();
  for (const value of packages) {
    const record = exactObject(value, packageFields, "delivery package");
    if (record.schemaVersion !== 1) throw new Error("delivery package version is unsupported");
    const releaseId = text(record.releaseId, "releaseId", 128);
    const host = text(record.host, "host", 32);
    if (!releaseEvidence.has(releaseId) || !releaseId.startsWith(`${host}:`)) {
      throw new Error("delivery package release is not approved for its host");
    }
    const operatingSystem = text(record.operatingSystem, "operatingSystem", 16);
    const packageFormat = text(record.packageFormat, "packageFormat", 8);
    if (!platformFormats.get(operatingSystem)?.has(packageFormat)) {
      throw new Error("delivery package format is unsupported for its platform");
    }
    const architecture = text(record.architecture, "architecture", 16);
    if (!new Set(["arm64", "x86_64"]).has(architecture)) {
      throw new Error("delivery package architecture is unsupported");
    }
    const bucketArn = text(record.bucketArn, "bucketArn", 256);
    if (!/^arn:(?:aws|aws-us-gov):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucketArn)) {
      throw new Error("delivery package bucket ARN is invalid");
    }
    const objectKey = text(record.objectKey, "objectKey", 512);
    if (objectKey.startsWith("/") || objectKey.includes("\\") || objectKey.split("/").includes("..") || objectKey.endsWith("/")) {
      throw new Error("delivery package object key is unsafe");
    }
    const objectVersionId = text(record.objectVersionId, "objectVersionId", 256);
    if (objectVersionId === "null") throw new Error("delivery package object version is mutable");
    for (const field of [
      "objectSha256",
      "providerPackageIdentitySha256",
      "packageSignatureEvidenceSha256",
      "releaseEvidenceSha256",
    ]) digest(record[field], field);
    if (record.releaseEvidenceSha256 !== releaseEvidence.get(releaseId)) {
      throw new Error("delivery package release evidence does not match its release");
    }
    const manifestSha256 = sha256(canonical(record));
    const packageId = `delivery:${manifestSha256}`;
    // Signed endpoint evidence currently identifies OS and architecture, not a
    // distro-specific package manager. Keep selection deterministic by allowing
    // only one format for an exact release/OS/architecture tuple.
    const platformKey = `${releaseId}:${operatingSystem}:${architecture}`;
    if (packageIds.has(packageId) || platformKeys.has(platformKey)) {
      throw new Error("delivery package platform authority is ambiguous");
    }
    packageIds.set(packageId, manifestSha256);
    platformKeys.add(platformKey);
  }

  const approval = exactObject(
    approvals,
    new Set(["schemaVersion", "packageBundleSha256", "approvals"]),
    "delivery package approval bundle",
  );
  if (
    approval.schemaVersion !== 1
    || approval.packageBundleSha256 !== sha256(packageBundle)
    || !Array.isArray(approval.approvals)
    || approval.approvals.length > 64
  ) {
    throw new Error("delivery package approval bundle is invalid or stale");
  }
  const approved = new Set<string>();
  for (const value of approval.approvals) {
    const record = exactObject(value, approvalFields, "delivery package approval");
    const packageId = text(record.packageId, "packageId", 80);
    if (
      approved.has(packageId)
      || record.manifestSha256 !== packageIds.get(packageId)
      || typeof record.approvedAt !== "string"
      || !/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/.test(record.approvedAt)
    ) {
      throw new Error("delivery package approval does not match its manifest");
    }
    digest(record.approverEvidenceSha256, "approverEvidenceSha256");
    approved.add(packageId);
  }
  if (approved.size !== packageIds.size || [...packageIds.keys()].some((id) => !approved.has(id))) {
    throw new Error("delivery package approvals do not exactly cover the bundle");
  }
}

/** Load and validate the exact delivery authority copied into a Lambda asset. */
export function loadDeliveryPackageBundles(
  directory: string,
  runtimeManifestBundle: string,
  runtimeApprovalBundle: string,
): DeliveryPackageBundles {
  const packageBundle = fs.readFileSync(path.join(directory, "delivery-packages.json"), "utf8");
  const approvalBundle = fs.readFileSync(
    path.join(directory, "delivery-packages.approvals.json"),
    "utf8",
  );
  validateDeliveryPackageBundles(
    packageBundle,
    approvalBundle,
    runtimeManifestBundle,
    runtimeApprovalBundle,
  );
  return {
    packageBundle,
    approvalBundle,
    packageBundleSha256: sha256(packageBundle),
    approvalBundleSha256: sha256(approvalBundle),
  };
}

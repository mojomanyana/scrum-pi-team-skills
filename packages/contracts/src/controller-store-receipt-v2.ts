import { createHash } from "node:crypto";

import {
  canonicalizeControllerStoreValueV2,
  digestControllerStoreValueV2,
  type ControllerRunIdentityV2,
} from "./controller-store-v2.js";
import type { DigestSha256V2, GitSha1V2 } from "./controller-command-v2.js";

export const CONTROLLER_STORE_RECEIPT_CONTRACT_ID_V2 =
  "spts.controller-store-receipt.v2" as const;
export const CONTROLLER_STORE_RECEIPT_SCHEMA_VERSION_V2 = 2 as const;

export const CONTROLLER_STORE_RECORD_TYPES_V2 = Object.freeze([
  "store-manifest",
  "snapshot-record",
  "transition-record",
  "operation-record",
  "commit-record",
  "head-pointer",
  "transaction-journal",
  "lock-owner",
  "bootstrap-owner",
  "committed-transition-receipt",
] as const);

export type ControllerStoreRecordTypeV2 =
  (typeof CONTROLLER_STORE_RECORD_TYPES_V2)[number];

export interface ControllerStoreAuthenticationInputV2 {
  readonly domain: "spts/controller-store-auth/v1";
  readonly algorithm: "hmac-sha256";
  readonly algorithmVersion: 1;
  readonly keyId: string;
  readonly recordType: ControllerStoreRecordTypeV2;
  readonly bodyDigest: DigestSha256V2;
}

export interface CommittedControllerTransitionReceiptV2 {
  readonly contractId: typeof CONTROLLER_STORE_RECEIPT_CONTRACT_ID_V2;
  readonly schemaVersion: typeof CONTROLLER_STORE_RECEIPT_SCHEMA_VERSION_V2;
  readonly algorithm: "hmac-sha256";
  readonly algorithmVersion: 1;
  readonly namespaceDigest: DigestSha256V2;
  readonly keyId: string;
  readonly taskId: string;
  readonly projectId: string;
  readonly repositoryId: string;
  readonly runId: string;
  readonly branch: string;
  readonly candidateCommit: GitSha1V2;
  readonly candidateTree: GitSha1V2;
  readonly previousRevision: number;
  readonly committedRevision: number;
  readonly previousSnapshotDigest: DigestSha256V2;
  readonly transitionDigest: DigestSha256V2;
  readonly proposalDigest: DigestSha256V2;
  readonly orderedChangesDigest: DigestSha256V2;
  readonly orderedIntentsDigest: DigestSha256V2;
  readonly transitionChainDigest: DigestSha256V2;
  readonly committedSnapshotDigest: DigestSha256V2;
  readonly operationIdentity: string;
  readonly idempotencyIdentity: string;
  readonly canonicalRequestDigest: DigestSha256V2;
  readonly committedAt: string;
  readonly previousReceiptDigest: DigestSha256V2 | null;
  readonly recordDigest: DigestSha256V2;
  readonly receiptDigest: DigestSha256V2;
  readonly authenticationTag: DigestSha256V2;
}

export type CommittedControllerTransitionReceiptPayloadV2 = Omit<
  CommittedControllerTransitionReceiptV2,
  "receiptDigest" | "authenticationTag"
>;

const receiptKeys = Object.freeze([
  "contractId",
  "schemaVersion",
  "algorithm",
  "algorithmVersion",
  "namespaceDigest",
  "keyId",
  "taskId",
  "projectId",
  "repositoryId",
  "runId",
  "branch",
  "candidateCommit",
  "candidateTree",
  "previousRevision",
  "committedRevision",
  "previousSnapshotDigest",
  "transitionDigest",
  "proposalDigest",
  "orderedChangesDigest",
  "orderedIntentsDigest",
  "transitionChainDigest",
  "committedSnapshotDigest",
  "operationIdentity",
  "idempotencyIdentity",
  "canonicalRequestDigest",
  "committedAt",
  "previousReceiptDigest",
  "recordDigest",
  "receiptDigest",
  "authenticationTag",
] as const);
const payloadKeys = receiptKeys.filter(
  (key) => key !== "receiptDigest" && key !== "authenticationTag",
);
const digestPattern = /^[0-9a-f]{64}$/;
const gitPattern = /^[0-9a-f]{40}$/;
const keyIdPattern = /^[\x21-\x7e]{1,64}$/;
const timestampPattern =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;

function cloneCanonical(value: unknown): unknown {
  return JSON.parse(canonicalizeControllerStoreValueV2(value)) as unknown;
}

function exactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function isDigest(value: unknown): value is DigestSha256V2 {
  return typeof value === "string" && digestPattern.test(value);
}

function isIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    Buffer.byteLength(value, "utf8") <= 128
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !timestampPattern.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

export function controllerStoreAuthenticationInputV2(
  keyId: string,
  recordType: ControllerStoreRecordTypeV2,
  bodyDigest: DigestSha256V2,
): Readonly<ControllerStoreAuthenticationInputV2> {
  if (
    typeof keyId !== "string" ||
    !keyIdPattern.test(keyId) ||
    !CONTROLLER_STORE_RECORD_TYPES_V2.includes(recordType) ||
    !isDigest(bodyDigest)
  ) {
    throw new TypeError("Controller store authentication input is invalid.");
  }
  return Object.freeze({
    domain: "spts/controller-store-auth/v1" as const,
    algorithm: "hmac-sha256" as const,
    algorithmVersion: 1 as const,
    keyId,
    recordType,
    bodyDigest,
  });
}

export function canonicalControllerStoreAuthenticationInputV2(
  value: ControllerStoreAuthenticationInputV2,
): string {
  let copy: unknown;
  try {
    copy = cloneCanonical(value);
  } catch {
    throw new TypeError("Controller store authentication input is invalid.");
  }
  if (
    !exactKeys(copy, [
      "domain",
      "algorithm",
      "algorithmVersion",
      "keyId",
      "recordType",
      "bodyDigest",
    ]) ||
    copy.domain !== "spts/controller-store-auth/v1" ||
    copy.algorithm !== "hmac-sha256" ||
    copy.algorithmVersion !== 1 ||
    typeof copy.keyId !== "string" ||
    !keyIdPattern.test(copy.keyId) ||
    !CONTROLLER_STORE_RECORD_TYPES_V2.includes(
      copy.recordType as ControllerStoreRecordTypeV2,
    ) ||
    !isDigest(copy.bodyDigest)
  ) {
    throw new TypeError("Controller store authentication input is invalid.");
  }
  return canonicalizeControllerStoreValueV2(copy);
}

export function committedControllerTransitionReceiptPayloadV2(
  value: unknown,
): Readonly<CommittedControllerTransitionReceiptPayloadV2> {
  let copy: unknown;
  try {
    copy = cloneCanonical(value);
  } catch {
    throw new TypeError("Committed controller transition receipt is invalid.");
  }
  if (!exactKeys(copy, receiptKeys) && !exactKeys(copy, payloadKeys)) {
    throw new TypeError("Committed controller transition receipt is invalid.");
  }
  const payload: Record<string, unknown> = {};
  for (const key of payloadKeys) payload[key] = copy[key];
  return deepFreeze(
    payload as unknown as CommittedControllerTransitionReceiptPayloadV2,
  );
}

export function computeCommittedControllerTransitionReceiptDigestV2(
  value: unknown,
): DigestSha256V2 {
  const payload = committedControllerTransitionReceiptPayloadV2(value);
  return createHash("sha256")
    .update("spts/controller-store-receipt/v2")
    .update("\0")
    .update(canonicalizeControllerStoreValueV2(payload))
    .digest("hex");
}

function validReceipt(
  value: unknown,
): value is CommittedControllerTransitionReceiptV2 {
  if (!exactKeys(value, receiptKeys)) return false;
  if (
    value.contractId !== CONTROLLER_STORE_RECEIPT_CONTRACT_ID_V2 ||
    value.schemaVersion !== CONTROLLER_STORE_RECEIPT_SCHEMA_VERSION_V2 ||
    value.algorithm !== "hmac-sha256" ||
    value.algorithmVersion !== 1 ||
    !isDigest(value.namespaceDigest) ||
    typeof value.keyId !== "string" ||
    !keyIdPattern.test(value.keyId) ||
    !isIdentifier(value.taskId) ||
    !isIdentifier(value.projectId) ||
    !isIdentifier(value.repositoryId) ||
    !isIdentifier(value.runId) ||
    !isIdentifier(value.branch) ||
    !isIdentifier(value.operationIdentity) ||
    typeof value.candidateCommit !== "string" ||
    !gitPattern.test(value.candidateCommit) ||
    typeof value.candidateTree !== "string" ||
    !gitPattern.test(value.candidateTree) ||
    !Number.isSafeInteger(value.previousRevision) ||
    (value.previousRevision as number) < 0 ||
    !Number.isSafeInteger(value.committedRevision) ||
    value.committedRevision !== (value.previousRevision as number) + 1 ||
    ![
      value.previousSnapshotDigest,
      value.transitionDigest,
      value.proposalDigest,
      value.orderedChangesDigest,
      value.orderedIntentsDigest,
      value.transitionChainDigest,
      value.committedSnapshotDigest,
      value.canonicalRequestDigest,
      value.recordDigest,
      value.receiptDigest,
      value.authenticationTag,
    ].every(isDigest) ||
    value.transitionChainDigest !== value.transitionDigest ||
    (value.previousReceiptDigest !== null &&
      !isDigest(value.previousReceiptDigest)) ||
    !isCanonicalTimestamp(value.committedAt) ||
    typeof value.idempotencyIdentity !== "string" ||
    !/^op-[0-9a-f]{64}$/.test(value.idempotencyIdentity)
  ) {
    return false;
  }

  const runIdentity: ControllerRunIdentityV2 = {
    namespaceDigest: value.namespaceDigest,
    projectId: value.projectId,
    taskId: value.taskId,
    repositoryId: value.repositoryId,
    snapshotId: value.runId,
    headBranch: value.branch,
    runIdentityDigest: digestControllerStoreValueV2(
      "spts/controller-store-run/v2",
      {
        namespaceDigest: value.namespaceDigest,
        projectId: value.projectId,
        taskId: value.taskId,
        repository: value.repositoryId,
        runId: value.runId,
        branch: value.branch,
      },
    ),
  };
  const operationIdentityDigest = digestControllerStoreValueV2(
    "spts/controller-store-operation-identity/v2",
    {
      namespaceDigest: value.namespaceDigest,
      runIdentityDigest: runIdentity.runIdentityDigest,
      operationId: value.operationIdentity,
    },
  );
  return (
    value.idempotencyIdentity === `op-${operationIdentityDigest}` &&
    computeCommittedControllerTransitionReceiptDigestV2(value) ===
      value.receiptDigest
  );
}

export function validateCommittedControllerTransitionReceiptV2(
  value: unknown,
): value is CommittedControllerTransitionReceiptV2 {
  try {
    return validReceipt(cloneCanonical(value));
  } catch {
    return false;
  }
}

export function parseCommittedControllerTransitionReceiptV2(
  value: unknown,
): Readonly<CommittedControllerTransitionReceiptV2> {
  let copy: unknown;
  try {
    copy = cloneCanonical(value);
  } catch {
    throw new TypeError("Committed controller transition receipt is invalid.");
  }
  if (!validReceipt(copy)) {
    throw new TypeError("Committed controller transition receipt is invalid.");
  }
  return deepFreeze(copy);
}

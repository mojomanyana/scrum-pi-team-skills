import { createHash } from "node:crypto";

import type { DigestSha256V2 } from "./controller-command-v2.js";

export const CONTROLLER_STORE_CONTRACT_ID_V2 =
  "spts.controller-store.v2" as const;
export const CONTROLLER_STORE_SCHEMA_VERSION_V2 = 2 as const;
export const CONTROLLER_STORE_DURABILITY_MODE_V2 =
  "linux-local-fsync-rename-v1" as const;
export const CONTROLLER_STORE_INTEGRITY_ALGORITHM_V2 = "hmac-sha256" as const;

export const CONTROLLER_STORE_LIMITS_V2 = Object.freeze({
  maximumDepth: 16,
  maximumNodes: 2_048,
  maximumOwnKeys: 64,
  maximumArrayLength: 256,
  maximumIdentifierBytes: 128,
  maximumCanonicalValueBytes: 1024 * 1024,
  maximumRecordBytes: 4 * 1024 * 1024,
  maximumReceiptBytes: 64 * 1024,
  maximumMetadataBytes: 256 * 1024,
  maximumHistoryRevisions: 100_000,
  maximumRecoveryTransactions: 1_024,
  maximumRecoveryRecords: 10_000,
  maximumRecoveryBytes: 256 * 1024 * 1024,
  maximumPathComponentBytes: 80,
  maximumStoreRelativePathBytes: 512,
} as const);

export const CONTROLLER_STORE_DIAGNOSTIC_CODES_V2 = Object.freeze([
  "store-closed",
  "invalid-bootstrap",
  "unsupported-platform",
  "durability-unavailable",
  "permission-denied",
  "invalid-input",
  "invalid-identity",
  "invalid-snapshot",
  "invalid-proposal",
  "noncanonical-proposal",
  "integrity-failure",
  "key-unavailable",
  "run-absent",
  "run-exists",
  "busy",
  "stale-revision",
  "future-revision",
  "revision-overflow",
  "replay-conflict",
  "abort-before-commit",
  "recovery-required",
  "recovery-failed",
  "resource-limit",
  "storage-unavailable",
] as const);

export type ControllerStoreDiagnosticCodeV2 =
  (typeof CONTROLLER_STORE_DIAGNOSTIC_CODES_V2)[number];

export interface ControllerStoreDiagnosticV2 {
  readonly code: ControllerStoreDiagnosticCodeV2;
  readonly message: "Controller store request denied.";
}

export const CONTROLLER_STORE_DIAGNOSTICS_V2: Readonly<
  Record<ControllerStoreDiagnosticCodeV2, Readonly<ControllerStoreDiagnosticV2>>
> = Object.freeze(
  Object.fromEntries(
    CONTROLLER_STORE_DIAGNOSTIC_CODES_V2.map((code) => [
      code,
      Object.freeze({
        code,
        message: "Controller store request denied." as const,
      }),
    ]),
  ) as Record<
    ControllerStoreDiagnosticCodeV2,
    Readonly<ControllerStoreDiagnosticV2>
  >,
);

export interface ControllerStoreIdentityV2 {
  readonly contractId: typeof CONTROLLER_STORE_CONTRACT_ID_V2;
  readonly schemaVersion: typeof CONTROLLER_STORE_SCHEMA_VERSION_V2;
  readonly namespaceDigest: DigestSha256V2;
  readonly keyId: string;
  readonly integrityAlgorithm: typeof CONTROLLER_STORE_INTEGRITY_ALGORITHM_V2;
  readonly formatVersion: 1;
  readonly durabilityMode: typeof CONTROLLER_STORE_DURABILITY_MODE_V2;
}

export interface PersistedRunIdentityProjectionV2 {
  readonly namespaceDigest: DigestSha256V2;
  readonly projectId: string;
  readonly taskId: string;
  readonly repository: string;
  readonly runId: string;
  readonly branch: string;
}

export interface ControllerRunIdentityV2 {
  readonly namespaceDigest: DigestSha256V2;
  readonly projectId: string;
  readonly taskId: string;
  readonly repositoryId: string;
  readonly snapshotId: string;
  readonly headBranch: string;
  readonly runIdentityDigest: DigestSha256V2;
}

interface ControllerStoreRunStatusBaseV2 {
  readonly identity: ControllerStoreIdentityV2;
  readonly runIdentity: ControllerRunIdentityV2;
}

export interface ReadyControllerStoreStatusV2 extends ControllerStoreRunStatusBaseV2 {
  readonly kind: "ready";
  readonly committedRevision: number;
  readonly headRecordDigest: DigestSha256V2;
  readonly snapshotDigest: DigestSha256V2;
  readonly lastReceiptDigest: DigestSha256V2 | null;
  readonly operationCount: number;
  readonly quarantineCount: number;
  readonly cleanupRequired: boolean;
}

export interface RepairRequiredControllerStoreStatusV2 extends ControllerStoreRunStatusBaseV2 {
  readonly kind: "repair-required";
  readonly code:
    | "integrity-failure"
    | "recovery-required"
    | "resource-limit"
    | "durability-unavailable"
    | "storage-unavailable";
}

export interface AbsentControllerStoreStatusV2 extends ControllerStoreRunStatusBaseV2 {
  readonly kind: "absent";
}

export interface ClosedControllerStoreStatusV2 extends ControllerStoreRunStatusBaseV2 {
  readonly kind: "closed";
}

export interface BusyControllerStoreStatusV2 extends ControllerStoreRunStatusBaseV2 {
  readonly kind: "busy";
}

export interface UnsupportedControllerStoreStatusV2 extends ControllerStoreRunStatusBaseV2 {
  readonly kind: "unsupported";
  readonly code: "unsupported-platform" | "durability-unavailable";
}

export type ControllerStoreStatusV2 =
  | ReadyControllerStoreStatusV2
  | RepairRequiredControllerStoreStatusV2
  | AbsentControllerStoreStatusV2
  | ClosedControllerStoreStatusV2
  | BusyControllerStoreStatusV2
  | UnsupportedControllerStoreStatusV2;

const encoder = new TextEncoder();
const digestPattern = /^[0-9a-f]{64}$/;
const keyIdPattern = /^[\x21-\x7e]{1,64}$/;
const credentialPattern =
  /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:^|\s)(?:authorization\s*:\s*)?(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]+|(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:$|[^A-Z0-9])|(?:^|[^A-Za-z0-9])(?:ghp|github_pat)_[A-Za-z0-9_]{20,})/i;

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function safeString(value: string): boolean {
  return (
    value.normalize("NFC") === value &&
    !hasLoneSurrogate(value) &&
    !hasControlCharacter(value)
  );
}

function snapshotPublicValue(value: unknown): unknown {
  let nodes = 0;
  const ancestors = new Set<object>();

  const visit = (item: unknown, depth: number): unknown => {
    nodes += 1;
    if (
      depth > CONTROLLER_STORE_LIMITS_V2.maximumDepth ||
      nodes > CONTROLLER_STORE_LIMITS_V2.maximumNodes
    ) {
      throw new TypeError("Controller store value is invalid.");
    }
    if (typeof item === "string") {
      if (!safeString(item)) {
        throw new TypeError("Controller store value is invalid.");
      }
      return item;
    }
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) {
        throw new TypeError("Controller store value is invalid.");
      }
      return item;
    }
    if (typeof item !== "object" || ancestors.has(item)) {
      throw new TypeError("Controller store value is invalid.");
    }

    ancestors.add(item);
    try {
      const keys = Reflect.ownKeys(item);
      if (keys.some((key) => typeof key !== "string")) {
        throw new TypeError("Controller store value is invalid.");
      }
      if (Array.isArray(item)) {
        const lengthDescriptor = Object.getOwnPropertyDescriptor(
          item,
          "length",
        );
        if (
          !lengthDescriptor ||
          !("value" in lengthDescriptor) ||
          lengthDescriptor.value !== item.length ||
          !Number.isSafeInteger(item.length) ||
          item.length < 0 ||
          item.length > CONTROLLER_STORE_LIMITS_V2.maximumArrayLength ||
          keys.length !== item.length + 1
        ) {
          throw new TypeError("Controller store value is invalid.");
        }
        const result: unknown[] = [];
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(
            item,
            String(index),
          );
          if (!descriptor?.enumerable || !("value" in descriptor)) {
            throw new TypeError("Controller store value is invalid.");
          }
          result.push(visit(descriptor.value, depth + 1));
        }
        return result;
      }

      if (
        Object.getPrototypeOf(item) !== Object.prototype ||
        keys.length > CONTROLLER_STORE_LIMITS_V2.maximumOwnKeys
      ) {
        throw new TypeError("Controller store value is invalid.");
      }
      const result: Record<string, unknown> = {};
      for (const key of keys as string[]) {
        if (!safeString(key)) {
          throw new TypeError("Controller store value is invalid.");
        }
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor?.enumerable || !("value" in descriptor)) {
          throw new TypeError("Controller store value is invalid.");
        }
        result[key] = visit(descriptor.value, depth + 1);
      }
      return result;
    } finally {
      ancestors.delete(item);
    }
  };

  return visit(value, 0);
}

function renderCanonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(renderCanonical).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${renderCanonical(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Canonical UTF-8 JSON for the closed controller-store public JSON subset. */
export function canonicalizeControllerStoreValueV2(value: unknown): string {
  const canonical = renderCanonical(snapshotPublicValue(value));
  if (
    encoder.encode(canonical).length >
    CONTROLLER_STORE_LIMITS_V2.maximumCanonicalValueBytes
  ) {
    throw new TypeError("Controller store value is invalid.");
  }
  return canonical;
}

export function digestControllerStoreValueV2(
  domain: string,
  value: unknown,
): DigestSha256V2 {
  if (
    typeof domain !== "string" ||
    !safeString(domain) ||
    domain.length === 0
  ) {
    throw new TypeError("Controller store digest input is invalid.");
  }
  return createHash("sha256")
    .update(domain)
    .update("\0")
    .update(canonicalizeControllerStoreValueV2(value))
    .digest("hex");
}

export function controllerStoreValueContainsCredentialV2(
  value: unknown,
): boolean {
  let copy: unknown;
  try {
    copy = snapshotPublicValue(value);
  } catch {
    return true;
  }
  const visit = (item: unknown): boolean =>
    typeof item === "string"
      ? credentialPattern.test(item)
      : Array.isArray(item)
        ? item.some(visit)
        : typeof item === "object" && item !== null
          ? Object.values(item).some(visit)
          : false;
  return visit(copy);
}

function exactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const own = Object.keys(value);
  return (
    own.length === keys.length && keys.every((key) => Object.hasOwn(value, key))
  );
}

function isDigest(value: unknown): value is DigestSha256V2 {
  return typeof value === "string" && digestPattern.test(value);
}

function isIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    safeString(value) &&
    value.length > 0 &&
    encoder.encode(value).length <=
      CONTROLLER_STORE_LIMITS_V2.maximumIdentifierBytes
  );
}

function validStoreIdentity(
  value: unknown,
): value is ControllerStoreIdentityV2 {
  return (
    exactKeys(value, [
      "contractId",
      "schemaVersion",
      "namespaceDigest",
      "keyId",
      "integrityAlgorithm",
      "formatVersion",
      "durabilityMode",
    ]) &&
    value.contractId === CONTROLLER_STORE_CONTRACT_ID_V2 &&
    value.schemaVersion === CONTROLLER_STORE_SCHEMA_VERSION_V2 &&
    isDigest(value.namespaceDigest) &&
    typeof value.keyId === "string" &&
    safeString(value.keyId) &&
    keyIdPattern.test(value.keyId) &&
    value.integrityAlgorithm === CONTROLLER_STORE_INTEGRITY_ALGORITHM_V2 &&
    value.formatVersion === 1 &&
    value.durabilityMode === CONTROLLER_STORE_DURABILITY_MODE_V2
  );
}

function validRunIdentityShape(
  value: unknown,
): value is ControllerRunIdentityV2 {
  return (
    exactKeys(value, [
      "namespaceDigest",
      "projectId",
      "taskId",
      "repositoryId",
      "snapshotId",
      "headBranch",
      "runIdentityDigest",
    ]) &&
    isDigest(value.namespaceDigest) &&
    isIdentifier(value.projectId) &&
    isIdentifier(value.taskId) &&
    isIdentifier(value.repositoryId) &&
    isIdentifier(value.snapshotId) &&
    isIdentifier(value.headBranch) &&
    isDigest(value.runIdentityDigest)
  );
}

export function deriveControllerStoreNamespaceDigestV2(
  namespaceSeed: Uint8Array,
): DigestSha256V2 {
  if (
    !(namespaceSeed instanceof Uint8Array) ||
    namespaceSeed.byteLength < 32 ||
    namespaceSeed.byteLength > 64
  ) {
    throw new TypeError("Controller store namespace seed is invalid.");
  }
  const namespaceSeedDigest = createHash("sha256")
    .update(namespaceSeed)
    .digest("hex");
  return digestControllerStoreValueV2("spts/controller-store-namespace/v2", {
    namespaceSeedDigest,
    formatVersion: 1,
  });
}

export function projectPersistedRunIdentityV2(
  identity: ControllerRunIdentityV2,
): PersistedRunIdentityProjectionV2 {
  let copy: unknown;
  try {
    copy = snapshotPublicValue(identity);
  } catch {
    throw new TypeError("Controller run identity is invalid.");
  }
  if (!validRunIdentityShape(copy)) {
    throw new TypeError("Controller run identity is invalid.");
  }
  return Object.freeze({
    namespaceDigest: copy.namespaceDigest,
    projectId: copy.projectId,
    taskId: copy.taskId,
    repository: copy.repositoryId,
    runId: copy.snapshotId,
    branch: copy.headBranch,
  });
}

export function deriveControllerRunIdentityDigestV2(
  identity: ControllerRunIdentityV2,
): DigestSha256V2 {
  return digestControllerStoreValueV2(
    "spts/controller-store-run/v2",
    projectPersistedRunIdentityV2(identity),
  );
}

export function validateControllerRunIdentityV2(
  value: unknown,
): value is ControllerRunIdentityV2 {
  try {
    const copy = snapshotPublicValue(value);
    return (
      validRunIdentityShape(copy) &&
      deriveControllerRunIdentityDigestV2(copy) === copy.runIdentityDigest
    );
  } catch {
    return false;
  }
}

export function validateControllerStoreIdentityV2(
  value: unknown,
): value is ControllerStoreIdentityV2 {
  try {
    return validStoreIdentity(snapshotPublicValue(value));
  } catch {
    return false;
  }
}

function validStatus(value: unknown): value is ControllerStoreStatusV2 {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    !("kind" in value)
  ) {
    return false;
  }
  const status = value as Record<string, unknown>;
  const baseValid =
    validStoreIdentity(status.identity) &&
    validRunIdentityShape(status.runIdentity);
  if (!baseValid) return false;

  if (status.kind === "ready") {
    return (
      exactKeys(status, [
        "kind",
        "identity",
        "runIdentity",
        "committedRevision",
        "headRecordDigest",
        "snapshotDigest",
        "lastReceiptDigest",
        "operationCount",
        "quarantineCount",
        "cleanupRequired",
      ]) &&
      Number.isSafeInteger(status.committedRevision) &&
      (status.committedRevision as number) >= 0 &&
      isDigest(status.headRecordDigest) &&
      isDigest(status.snapshotDigest) &&
      (status.lastReceiptDigest === null ||
        isDigest(status.lastReceiptDigest)) &&
      Number.isSafeInteger(status.operationCount) &&
      (status.operationCount as number) >= 1 &&
      (status.operationCount as number) <=
        CONTROLLER_STORE_LIMITS_V2.maximumHistoryRevisions + 1 &&
      Number.isSafeInteger(status.quarantineCount) &&
      (status.quarantineCount as number) >= 0 &&
      (status.quarantineCount as number) <=
        CONTROLLER_STORE_LIMITS_V2.maximumRecoveryRecords &&
      typeof status.cleanupRequired === "boolean" &&
      ((status.committedRevision === 0 && status.lastReceiptDigest === null) ||
        (status.committedRevision !== 0 && isDigest(status.lastReceiptDigest)))
    );
  }
  if (status.kind === "repair-required") {
    return (
      exactKeys(status, ["kind", "identity", "runIdentity", "code"]) &&
      [
        "integrity-failure",
        "recovery-required",
        "resource-limit",
        "durability-unavailable",
        "storage-unavailable",
      ].includes(status.code as string)
    );
  }
  if (["absent", "closed", "busy"].includes(status.kind as string)) {
    return exactKeys(status, ["kind", "identity", "runIdentity"]);
  }
  return (
    status.kind === "unsupported" &&
    exactKeys(status, ["kind", "identity", "runIdentity", "code"]) &&
    ["unsupported-platform", "durability-unavailable"].includes(
      status.code as string,
    )
  );
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

export function parseControllerStoreStatusV2(
  value: unknown,
): Readonly<ControllerStoreStatusV2> {
  let copy: unknown;
  try {
    copy = snapshotPublicValue(value);
  } catch {
    throw new TypeError("Controller store status is invalid.");
  }
  if (!validStatus(copy)) {
    throw new TypeError("Controller store status is invalid.");
  }
  return deepFreeze(copy);
}

export function validateControllerStoreStatusV2(
  value: unknown,
): value is ControllerStoreStatusV2 {
  try {
    parseControllerStoreStatusV2(value);
    return true;
  } catch {
    return false;
  }
}

import { createHash, createHmac } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join, normalize, parse, sep } from "node:path";

import {
  deriveControllerStoreCommitRequestV2,
  deriveControllerStoreCreationRequestV2,
  type ClosedControllerStoreV2,
  type CommittedControllerTransitionV2,
  type ControllerStoreResultV2,
  type ControllerStoreV2,
  type CreatedControllerRunV2,
  type LoadedControllerRunV2,
  type RecoveredControllerRunV2,
} from "./controller-store-v2.js";
import {
  canonicalControllerStoreAuthenticationInputV2,
  canonicalizeControllerStoreValueV2,
  computeCommittedControllerTransitionReceiptDigestV2,
  controllerStoreAuthenticationInputV2,
  controllerStoreValueContainsCredentialV2,
  deriveControllerStoreNamespaceDigestV2,
  digestControllerSnapshotV2,
  digestControllerStoreValueV2,
  parseCommittedControllerTransitionReceiptV2,
  parseControllerStoreStatusV2,
  validateCommittedControllerTransitionReceiptV2,
  validateControllerRunIdentityV2,
  validateControllerSnapshotV2,
  type CommittedControllerTransitionReceiptV2,
  type ControllerRunIdentityV2,
  type ControllerSnapshotV2,
  type ControllerStoreDiagnosticCodeV2,
  type ControllerStoreIdentityV2,
  type ControllerStoreRecordTypeV2,
  type ControllerStoreStatusV2,
  type DigestSha256V2,
  type ReadyControllerStoreStatusV2,
  type EffectIntentV2,
} from "@scrum-pi-team-skills/contracts";

const STORE_ROOT_DIRECTORY = "controller-store-v2";
const MANIFEST_FILE = "manifest.json";
const RUNS_DIRECTORY = "runs";
const OPERATIONS_DIRECTORY = "operations";
const TRANSACTION_DIRECTORY = "transaction";
const HEAD_FILE = "head.json";
const JOURNAL_FILE = "journal.json";
const RECORDS_FILE = "records.json";
const RECEIPT_FILE = "receipt.json";
const OPERATION_FILE = "operation.json";
const TEMP_HEAD_FILE = "head.json.tmp";
const LOCK_DIRECTORY = "lock";
const LOCK_CANDIDATES_DIRECTORY = "lock-candidates";
const LOCK_OWNER_FILE = "owner.json";
const QUARANTINE_DIRECTORY = "quarantine";
const DEAD_LOCK_QUARANTINE = "dead-lock";
const RELEASED_LOCK_QUARANTINE = "released-lock";
const LOCK_CANDIDATE_QUARANTINE = "lock-candidate";
const RECORD_CONTRACT_ID = "spts.controller-store-file.v2" as const;
const RECORD_SCHEMA_VERSION = 2 as const;
const RECORD_BODY_DOMAIN = "spts/controller-store-file-body/v2";
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_HEAD_BYTES = 4 * 1024 * 1024;
const MAX_OPERATION_BYTES = 4 * 1024 * 1024;
const MAX_TRANSACTION_BYTES = 4 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_LOCK_OWNER_BYTES = 64 * 1024;
const LOCK_LEASE_MILLISECONDS = 30_000;
const digestPattern = /^[0-9a-f]{64}$/;
const bootIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const processStartTicksPattern = /^(?:0|[1-9][0-9]{0,31})$/;
const digestByteLength = 32;
const safePathPattern = /^[\x20-\x7e]+$/;

export const CONTROLLER_STORE_FAULT_POINTS_V2 = Object.freeze([
  "transaction-announced",
  "journal-prepared",
  "records-durable",
  "receipt-durable",
  "operation-durable",
  "head-prepared",
  "head-published",
  "head-durable",
  "journal-committed",
] as const);

export interface ControllerStoreTestingOptionsV2 {
  readonly fault?: (
    point: (typeof CONTROLLER_STORE_FAULT_POINTS_V2)[number],
  ) => void;
  readonly lockOwnerProbe?: () => "live" | "dead" | "ambiguous";
}

interface ControllerStoreBootstrapKeyProviderV2 {
  readonly keyId: string;
  readonly algorithm: "hmac-sha256";
  acquire(): Uint8Array;
  release(): void;
}

interface ControllerStoreBootstrapClockV2 {
  now(): string;
}

interface ControllerStoreBootstrapRandomV2 {
  fill(target: Uint8Array): void;
}

interface ControllerStoreBootstrapDeploymentAttestationV2 {
  readonly kind: "trusted-local-filesystem-v1";
  readonly platform: "linux";
  readonly nodeMajor: number;
  readonly semantics: readonly string[];
  readonly expectedUid: number;
  readonly rootDevice: number;
  readonly attestedBy: string;
}

interface ControllerStoreBootstrapV2 {
  readonly rootPath: string;
  readonly namespaceSeed: Uint8Array;
  readonly keyProvider: ControllerStoreBootstrapKeyProviderV2;
  readonly durabilityPolicy: "linux-local-fsync-rename-v1";
  readonly clock: ControllerStoreBootstrapClockV2;
  readonly random: ControllerStoreBootstrapRandomV2;
  readonly deploymentAttestation: ControllerStoreBootstrapDeploymentAttestationV2;
}

type StoreRecordBodyV2 = object;

interface AuthenticatedStoreRecordEnvelopeV2<T extends StoreRecordBodyV2> {
  readonly contractId: typeof RECORD_CONTRACT_ID;
  readonly schemaVersion: typeof RECORD_SCHEMA_VERSION;
  readonly recordType: ControllerStoreRecordTypeV2;
  readonly keyId: string;
  readonly body: T;
  readonly recordDigest: DigestSha256V2;
  readonly authenticationTag: DigestSha256V2;
}

type StoredReadyControllerStoreStatusV2 = Omit<
  ReadyControllerStoreStatusV2,
  "headRecordDigest"
>;

interface StoredManifestBodyV2 {
  readonly identity: Readonly<ControllerStoreIdentityV2>;
}

interface StoredHeadBodyV2 {
  readonly status: Readonly<StoredReadyControllerStoreStatusV2>;
  readonly snapshot: Readonly<ControllerSnapshotV2>;
}

interface StoredOperationRecordBodyV2 {
  readonly kind: "create" | "commit";
  readonly operationId: string;
  readonly requestDigest: DigestSha256V2;
  readonly result:
    | Readonly<CreatedControllerRunV2>
    | Readonly<CommittedControllerTransitionV2>;
}

interface StoredJournalBodyV2 {
  readonly operationId: string;
  readonly requestDigest: DigestSha256V2;
  readonly fromRevision: number;
  readonly toRevision: number;
  readonly committedSnapshotDigest: DigestSha256V2;
  readonly operationIdentity: string;
  readonly operationIdentityDigest: DigestSha256V2;
  readonly idempotencyIdentity: `op-${string}`;
  readonly headPublished: boolean;
}

interface StoredRecordsBodyV2 {
  readonly previousSnapshotDigest: DigestSha256V2;
  readonly sourceCommandDigest: DigestSha256V2;
  readonly transitionDigest: DigestSha256V2;
  readonly proposalDigest: DigestSha256V2;
  readonly committedSnapshotDigest: DigestSha256V2;
}

interface StoredFilesystemIdentityV2 {
  readonly device: number;
  readonly inode: number;
  readonly uid: number;
  readonly mode: number;
}

interface StoredLockCurrentTransactionV2 {
  readonly transactionIdDigest: DigestSha256V2;
  readonly kind: "create" | "commit" | "recover";
  readonly operationId: string;
  readonly requestDigest: DigestSha256V2 | null;
  readonly runIdentityDigest: DigestSha256V2;
  readonly fromRevision: number | null;
  readonly toRevision: number | null;
  readonly relativePath: string;
}

interface StoredLockOwnerBodyV2 {
  readonly namespaceDigest: DigestSha256V2;
  readonly runIdentityDigest: DigestSha256V2;
  readonly ownerToken: DigestSha256V2;
  readonly ownerTokenDigest: DigestSha256V2;
  readonly bootId: string;
  readonly pid: number;
  readonly processStartTicks: string;
  readonly acquiredAt: string;
  readonly leaseExpiresAt: string;
  readonly renewalCounter: number;
  readonly currentTransaction: StoredLockCurrentTransactionV2 | null;
  readonly rootIdentity: StoredFilesystemIdentityV2;
  readonly lockIdentity: StoredFilesystemIdentityV2;
}

interface HeldNamespaceLockV2 {
  readonly namespacePath: string;
  readonly namespaceIdentity: StoredFilesystemIdentityV2;
  readonly lockPath: string;
  readonly lockDevice: number;
  readonly lockInode: number;
  owner: Readonly<StoredLockOwnerBodyV2>;
}

type LockQuarantineKindV2 =
  | typeof DEAD_LOCK_QUARANTINE
  | typeof RELEASED_LOCK_QUARANTINE
  | typeof LOCK_CANDIDATE_QUARANTINE;

let lockOwnerSerial = 0;

class StoreDeniedError extends Error {
  constructor(readonly code: ControllerStoreDiagnosticCodeV2) {
    super(code);
    this.name = "StoreDeniedError";
  }
}

class StoreBootstrapValidationError extends Error {
  constructor() {
    super("store bootstrap is invalid");
    this.name = "StoreBootstrapValidationError";
  }
}

class StoreIntegrityError extends Error {
  constructor() {
    super("store record integrity failed");
    this.name = "StoreIntegrityError";
  }
}

class StoreUnexpectedError extends Error {
  constructor() {
    super("store operation failed");
    this.name = "StoreUnexpectedError";
  }
}

interface StoreFileReadResult<T> {
  readonly body: T;
  readonly recordDigest: DigestSha256V2;
  readonly authenticationTag: DigestSha256V2;
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function cloneJsonValue<T>(value: unknown): T {
  return JSON.parse(canonicalizeControllerStoreValueV2(value)) as T;
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

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
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

function isSafeString(value: string): boolean {
  return (
    value.length > 0 &&
    value.normalize("NFC") === value &&
    !hasLoneSurrogate(value) &&
    !hasControlCharacter(value)
  );
}

function validateAbsoluteNormalizedPath(value: unknown): string {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    value === parse(value).root ||
    value.endsWith(sep) ||
    value.includes("\0") ||
    value.split(sep).some((segment) => segment === "." || segment === "..") ||
    normalize(value) !== value ||
    !safePathPattern.test(value) ||
    controllerStoreValueContainsCredentialV2(value)
  ) {
    throw new StoreBootstrapValidationError();
  }
  return value;
}

function validateNullPrototypeRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== null
  ) {
    throw new StoreBootstrapValidationError();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !keys.every((key) => Object.hasOwn(value, key))
  ) {
    throw new StoreBootstrapValidationError();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new StoreBootstrapValidationError();
    }
  }
  return value as Record<string, unknown>;
}

function expectedUid(): number {
  if (typeof process.getuid !== "function")
    throw new StoreBootstrapValidationError();
  return process.getuid();
}

function walkWithoutSymlinks(path: string): void {
  const root = parse(path).root;
  let current = root;
  for (const segment of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw new StoreBootstrapValidationError();
  }
}

function requirePrivateDirectory(path: string): void {
  walkWithoutSymlinks(path);
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== expectedUid() ||
    (stat.mode & 0o777) !== 0o700 ||
    realpathSync(path) !== path
  ) {
    throw new StoreBootstrapValidationError();
  }
}

function ensurePrivateDirectory(path: string): void {
  let created = false;
  try {
    mkdirSync(path, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as { code?: unknown }).code !== "EEXIST"
    ) {
      throw error;
    }
  }
  if (!created) {
    requirePrivateDirectory(path);
    return;
  }

  const before = lstatSync(path);
  if (
    !before.isDirectory() ||
    before.isSymbolicLink() ||
    before.uid !== expectedUid()
  ) {
    throw new StoreBootstrapValidationError();
  }
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | noFollowFlag(),
  );
  try {
    const opened = fstatSync(descriptor);
    if (
      !opened.isDirectory() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) {
      throw new StoreBootstrapValidationError();
    }
    fchmodSync(descriptor, 0o700);
    const after = lstatSync(path);
    if (
      !after.isDirectory() ||
      after.isSymbolicLink() ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino
    ) {
      throw new StoreBootstrapValidationError();
    }
  } finally {
    closeSync(descriptor);
  }
  requirePrivateDirectory(path);
}

function noFollowFlag(): number {
  return typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
}

function sameIdentity(descriptor: number, path: string): boolean {
  const descriptorStat = fstatSync(descriptor);
  const pathStat = lstatSync(path);
  return (
    descriptorStat.isFile() &&
    pathStat.isFile() &&
    !pathStat.isSymbolicLink() &&
    descriptorStat.dev === pathStat.dev &&
    descriptorStat.ino === pathStat.ino &&
    descriptorStat.nlink === 1 &&
    pathStat.nlink === 1
  );
}

function openExclusivePrivateFile(path: string): number {
  const descriptor = openSync(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_APPEND |
      noFollowFlag(),
    0o600,
  );
  try {
    fchmodSync(descriptor, 0o600);
    if (!sameIdentity(descriptor, path)) throw new StoreUnexpectedError();
    return descriptor;
  } catch (error) {
    try {
      closeSync(descriptor);
    } catch {
      // The original file-system failure remains authoritative.
    }
    throw error;
  }
}

function openPrivateFileForInspection(
  path: string,
  maximumBytes: number,
): number {
  const stat = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== expectedUid() ||
    (stat.mode & 0o777) !== 0o600 ||
    stat.size > maximumBytes
  ) {
    throw new StoreIntegrityError();
  }
  const descriptor = openSync(path, constants.O_RDONLY | noFollowFlag());
  if (!sameIdentity(descriptor, path)) {
    closeSync(descriptor);
    throw new StoreIntegrityError();
  }
  return descriptor;
}

function writeAllBytes(descriptor: number, buffer: Uint8Array): void {
  let offset = 0;
  while (offset < buffer.byteLength) {
    let written: number;
    try {
      written = writeSync(
        descriptor,
        buffer,
        offset,
        buffer.byteLength - offset,
        null,
      );
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        (error as { code?: unknown }).code === "EINTR"
      ) {
        continue;
      }
      throw error;
    }
    if (
      !Number.isSafeInteger(written) ||
      written <= 0 ||
      written > buffer.byteLength - offset
    ) {
      throw new StoreUnexpectedError();
    }
    offset += written;
  }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function atomicWriteCanonicalJson(path: string, value: unknown): void {
  const tempPath = `${path}.tmp`;
  const serialized = canonicalizeControllerStoreValueV2(value);
  const bytes = Buffer.from(serialized, "utf8");
  const descriptor = openExclusivePrivateFile(tempPath);
  try {
    writeAllBytes(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(tempPath, path);
  syncDirectory(parse(path).dir);
}

function recordDigest(body: unknown): DigestSha256V2 {
  return digestControllerStoreValueV2(RECORD_BODY_DOMAIN, body);
}

function authenticateRecord(
  keyId: string,
  recordType: ControllerStoreRecordTypeV2,
  bodyDigest: DigestSha256V2,
  keyBytes: Uint8Array,
): DigestSha256V2 {
  const input = controllerStoreAuthenticationInputV2(
    keyId,
    recordType,
    bodyDigest,
  );
  return createHmac("sha256", Buffer.from(keyBytes))
    .update(canonicalControllerStoreAuthenticationInputV2(input))
    .digest("hex") as DigestSha256V2;
}

function writeAuthenticatedRecord<T extends StoreRecordBodyV2>(options: {
  readonly path: string;
  readonly recordType: ControllerStoreRecordTypeV2;
  readonly keyId: string;
  readonly keyBytes: Uint8Array;
  readonly body: T;
}): AuthenticatedStoreRecordEnvelopeV2<T> {
  const body = cloneJsonValue<T>(options.body);
  const digest = recordDigest(body);
  const envelope: AuthenticatedStoreRecordEnvelopeV2<T> = {
    contractId: RECORD_CONTRACT_ID,
    schemaVersion: RECORD_SCHEMA_VERSION,
    recordType: options.recordType,
    keyId: options.keyId,
    body,
    recordDigest: digest,
    authenticationTag: authenticateRecord(
      options.keyId,
      options.recordType,
      digest,
      options.keyBytes,
    ),
  };
  atomicWriteCanonicalJson(options.path, envelope);
  return envelope;
}

function readAuthenticatedRecord<T extends StoreRecordBodyV2>(options: {
  readonly path: string;
  readonly recordType: ControllerStoreRecordTypeV2;
  readonly keyId: string;
  readonly keyBytes: Uint8Array;
  readonly maximumBytes: number;
}): StoreFileReadResult<T> {
  const descriptor = openPrivateFileForInspection(
    options.path,
    options.maximumBytes,
  );
  let text: string;
  try {
    text = readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
    if (canonicalizeControllerStoreValueV2(parsed) !== text) {
      throw new StoreIntegrityError();
    }
  } catch {
    throw new StoreIntegrityError();
  }
  if (
    !exactKeys(parsed, [
      "contractId",
      "schemaVersion",
      "recordType",
      "keyId",
      "body",
      "recordDigest",
      "authenticationTag",
    ])
  ) {
    throw new StoreIntegrityError();
  }
  if (
    parsed.contractId !== RECORD_CONTRACT_ID ||
    parsed.schemaVersion !== RECORD_SCHEMA_VERSION ||
    parsed.recordType !== options.recordType ||
    parsed.keyId !== options.keyId ||
    typeof parsed.body !== "object" ||
    parsed.body === null ||
    Array.isArray(parsed.body)
  ) {
    throw new StoreIntegrityError();
  }
  const body = cloneJsonValue<T>(parsed.body);
  const digest = recordDigest(body);
  if (digest !== parsed.recordDigest) throw new StoreIntegrityError();
  const authenticationTag = authenticateRecord(
    options.keyId,
    options.recordType,
    digest,
    options.keyBytes,
  );
  if (authenticationTag !== parsed.authenticationTag) {
    throw new StoreIntegrityError();
  }
  return {
    body: deepFreeze(body),
    recordDigest: digest,
    authenticationTag,
  };
}

function isStoreRootValid(path: string): boolean {
  try {
    validateAbsoluteNormalizedPath(path);
    requirePrivateDirectory(path);
    return true;
  } catch {
    return false;
  }
}

function validateBootstrap(value: unknown): ControllerStoreBootstrapV2 {
  const bootstrap = validateNullPrototypeRecord(value, [
    "rootPath",
    "namespaceSeed",
    "keyProvider",
    "durabilityPolicy",
    "clock",
    "random",
    "deploymentAttestation",
  ]) as Record<string, unknown>;
  const rootPath = validateAbsoluteNormalizedPath(bootstrap.rootPath);
  if (!isStoreRootValid(rootPath)) {
    throw new StoreDeniedError("permission-denied");
  }
  const namespaceSeed =
    bootstrap.namespaceSeed instanceof Uint8Array
      ? bootstrap.namespaceSeed
      : null;
  if (
    !namespaceSeed ||
    namespaceSeed.byteLength < 32 ||
    namespaceSeed.byteLength > 64
  ) {
    throw new StoreBootstrapValidationError();
  }
  const keyProviderRecord = validateNullPrototypeRecord(bootstrap.keyProvider, [
    "keyId",
    "algorithm",
    "acquire",
    "release",
  ]) as Record<string, unknown>;
  if (
    typeof keyProviderRecord.keyId !== "string" ||
    !isSafeString(keyProviderRecord.keyId) ||
    keyProviderRecord.algorithm !== "hmac-sha256" ||
    typeof keyProviderRecord.acquire !== "function" ||
    typeof keyProviderRecord.release !== "function"
  ) {
    throw new StoreBootstrapValidationError();
  }
  const clockRecord = validateNullPrototypeRecord(bootstrap.clock, [
    "now",
  ]) as Record<string, unknown>;
  if (typeof clockRecord.now !== "function")
    throw new StoreBootstrapValidationError();
  const randomRecord = validateNullPrototypeRecord(bootstrap.random, [
    "fill",
  ]) as Record<string, unknown>;
  if (typeof randomRecord.fill !== "function")
    throw new StoreBootstrapValidationError();
  const attestationRecord = validateNullPrototypeRecord(
    bootstrap.deploymentAttestation,
    [
      "kind",
      "platform",
      "nodeMajor",
      "semantics",
      "expectedUid",
      "rootDevice",
      "attestedBy",
    ],
  ) as Record<string, unknown>;
  const expectedSemantics = Object.freeze([
    "exclusive-create",
    "same-filesystem-atomic-rename",
    "file-fsync",
    "directory-fsync",
    "atomic-mkdir",
    "stable-owner-mode",
  ] as const);
  const attestedSemantics = attestationRecord.semantics;
  const semanticsKeys = expectedSemantics.map((_, index) => String(index));
  if (
    !Object.isFrozen(attestationRecord) ||
    attestationRecord.kind !== "trusted-local-filesystem-v1" ||
    attestationRecord.platform !== "linux" ||
    attestationRecord.nodeMajor !== 24 ||
    !Array.isArray(attestedSemantics) ||
    !Object.isFrozen(attestedSemantics) ||
    Object.getPrototypeOf(attestedSemantics) !== Array.prototype ||
    Reflect.ownKeys(attestedSemantics).length !==
      expectedSemantics.length + 1 ||
    !semanticsKeys.every((key) => Object.hasOwn(attestedSemantics, key)) ||
    !Object.hasOwn(attestedSemantics, "length") ||
    attestedSemantics.length !== expectedSemantics.length ||
    !expectedSemantics.every((item, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(
        attestedSemantics,
        String(index),
      );
      return (
        descriptor?.enumerable === true &&
        "value" in descriptor &&
        descriptor.value === item
      );
    }) ||
    attestationRecord.expectedUid !== expectedUid() ||
    attestationRecord.rootDevice !== statSync(rootPath).dev ||
    typeof attestationRecord.attestedBy !== "string" ||
    !isSafeString(attestationRecord.attestedBy)
  ) {
    throw new StoreDeniedError("durability-unavailable");
  }
  if (bootstrap.durabilityPolicy !== "linux-local-fsync-rename-v1") {
    throw new StoreDeniedError("durability-unavailable");
  }
  return {
    rootPath,
    namespaceSeed,
    keyProvider: {
      keyId: keyProviderRecord.keyId,
      algorithm: "hmac-sha256",
      acquire: keyProviderRecord.acquire as () => Uint8Array,
      release: keyProviderRecord.release as () => void,
    },
    durabilityPolicy: "linux-local-fsync-rename-v1",
    clock: { now: clockRecord.now as () => string },
    random: { fill: randomRecord.fill as (target: Uint8Array) => void },
    deploymentAttestation: {
      kind: "trusted-local-filesystem-v1",
      platform: "linux",
      nodeMajor: 24,
      semantics: expectedSemantics,
      expectedUid: expectedUid(),
      rootDevice: statSync(rootPath).dev,
      attestedBy: attestationRecord.attestedBy as string,
    },
  } as ControllerStoreBootstrapV2;
}

function storeRootPath(bootstrap: ControllerStoreBootstrapV2): string {
  return join(bootstrap.rootPath, STORE_ROOT_DIRECTORY);
}

function namespaceDigest(
  bootstrap: ControllerStoreBootstrapV2,
): DigestSha256V2 {
  return deriveControllerStoreNamespaceDigestV2(bootstrap.namespaceSeed);
}

function namespacePath(bootstrap: ControllerStoreBootstrapV2): string {
  return join(storeRootPath(bootstrap), namespaceDigest(bootstrap));
}

function manifestPath(bootstrap: ControllerStoreBootstrapV2): string {
  return join(namespacePath(bootstrap), MANIFEST_FILE);
}

function runsPath(bootstrap: ControllerStoreBootstrapV2): string {
  return join(namespacePath(bootstrap), RUNS_DIRECTORY);
}

function storeIdentity(
  bootstrap: ControllerStoreBootstrapV2,
): ControllerStoreIdentityV2 {
  return {
    contractId: "spts.controller-store.v2",
    schemaVersion: 2,
    namespaceDigest: namespaceDigest(bootstrap),
    keyId: bootstrap.keyProvider.keyId,
    integrityAlgorithm: "hmac-sha256",
    formatVersion: 1,
    durabilityMode: "linux-local-fsync-rename-v1",
  };
}

function runPathFromIdentity(
  bootstrap: ControllerStoreBootstrapV2,
  identity: ControllerRunIdentityV2,
): string {
  return join(runsPath(bootstrap), identity.runIdentityDigest);
}

function operationsPath(runPath: string): string {
  return join(runPath, OPERATIONS_DIRECTORY);
}

function transactionPath(runPath: string): string {
  return join(runPath, TRANSACTION_DIRECTORY);
}

function headPath(runPath: string): string {
  return join(runPath, HEAD_FILE);
}

function operationRecordPath(runPath: string, operationId: string): string {
  const operationPathDigest = digestControllerStoreValueV2(
    "spts/controller-store-operation-path/v2",
    { operationId },
  );
  return join(operationsPath(runPath), `${operationPathDigest}.json`);
}

function journalPath(runPath: string): string {
  return join(transactionPath(runPath), JOURNAL_FILE);
}

function recordsPath(runPath: string): string {
  return join(transactionPath(runPath), RECORDS_FILE);
}

function receiptPath(runPath: string): string {
  return join(transactionPath(runPath), RECEIPT_FILE);
}

function pendingOperationPath(runPath: string): string {
  return join(transactionPath(runPath), OPERATION_FILE);
}

function tempHeadPath(runPath: string): string {
  return join(transactionPath(runPath), TEMP_HEAD_FILE);
}

function namespaceLockPath(bootstrap: ControllerStoreBootstrapV2): string {
  return join(namespacePath(bootstrap), LOCK_DIRECTORY);
}

function lockCandidatesPath(bootstrap: ControllerStoreBootstrapV2): string {
  return join(namespacePath(bootstrap), LOCK_CANDIDATES_DIRECTORY);
}

function lockCandidatePath(
  bootstrap: ControllerStoreBootstrapV2,
  ownerTokenDigest: DigestSha256V2,
): string {
  return join(lockCandidatesPath(bootstrap), ownerTokenDigest);
}

function lockOwnerPath(lockPath: string): string {
  return join(lockPath, LOCK_OWNER_FILE);
}

function lockQuarantineKindPath(
  bootstrap: ControllerStoreBootstrapV2,
  kind: LockQuarantineKindV2,
): string {
  return join(namespacePath(bootstrap), QUARANTINE_DIRECTORY, kind);
}

function directResult<T>(value: T): ControllerStoreResultV2<T> {
  return {
    disposition: "ok",
    value: deepFreeze(value),
  };
}

function denied<T>(
  code: ControllerStoreDiagnosticCodeV2,
): ControllerStoreResultV2<T> {
  return {
    disposition: "denied",
    diagnostic: Object.freeze({
      code,
      message: "Controller store request denied." as const,
    }),
  };
}

interface ValidatedOperationOptionsV2 {
  readonly operationId: string;
  readonly requestDigest: DigestSha256V2;
  readonly abortSignal?: AbortSignal;
}

interface ValidatedRecoveryOptionsV2 {
  readonly operationId: string;
  readonly abortSignal?: AbortSignal;
}

function readOptionsDataRecord(
  value: unknown,
  requiredKeys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new StoreDeniedError("invalid-input");
  }
  const allowedKeys = [...requiredKeys, "abortSignal"];
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string") ||
    requiredKeys.some((key) => !Object.hasOwn(value, key)) ||
    keys.some((key) => !allowedKeys.includes(key as string))
  ) {
    throw new StoreDeniedError("invalid-input");
  }
  const result: Record<string, unknown> = {};
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !("value" in descriptor)) {
      throw new StoreDeniedError("invalid-input");
    }
    result[key] = descriptor.value;
  }
  return result;
}

function validateAbortSignal(value: unknown): AbortSignal | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof AbortSignal)) {
    throw new StoreDeniedError("invalid-input");
  }
  return value;
}

function validateOperationOptions(value: unknown): ValidatedOperationOptionsV2 {
  const record = readOptionsDataRecord(value, ["operationId", "requestDigest"]);
  if (
    typeof record.operationId !== "string" ||
    !isSafeString(record.operationId) ||
    typeof record.requestDigest !== "string" ||
    !digestPattern.test(record.requestDigest)
  ) {
    throw new StoreDeniedError("invalid-input");
  }
  return {
    operationId: record.operationId,
    requestDigest: record.requestDigest as DigestSha256V2,
    abortSignal: validateAbortSignal(record.abortSignal),
  };
}

function validateRecoveryOptions(value: unknown): ValidatedRecoveryOptionsV2 {
  const record = readOptionsDataRecord(value, ["operationId"]);
  if (
    typeof record.operationId !== "string" ||
    !isSafeString(record.operationId)
  ) {
    throw new StoreDeniedError("invalid-input");
  }
  return {
    operationId: record.operationId,
    abortSignal: validateAbortSignal(record.abortSignal),
  };
}

function keyBytesFromProvider(bootstrap: ControllerStoreBootstrapV2): Buffer {
  const raw = bootstrap.keyProvider.acquire();
  if (!(raw instanceof Uint8Array) || raw.byteLength < digestByteLength) {
    throw new StoreDeniedError("key-unavailable");
  }
  const key = Buffer.from(raw);
  if (raw.byteLength > 0) raw.fill(0);
  return key;
}

function writeManifest(
  bootstrap: ControllerStoreBootstrapV2,
  keyBytes: Uint8Array,
): void {
  writeAuthenticatedRecord<StoredManifestBodyV2>({
    path: manifestPath(bootstrap),
    recordType: "store-manifest",
    keyId: bootstrap.keyProvider.keyId,
    keyBytes,
    body: { identity: storeIdentity(bootstrap) },
  });
}

function readManifest(
  bootstrap: ControllerStoreBootstrapV2,
  keyBytes: Uint8Array,
): void {
  const manifest = readAuthenticatedRecord<StoredManifestBodyV2>({
    path: manifestPath(bootstrap),
    recordType: "store-manifest",
    keyId: bootstrap.keyProvider.keyId,
    keyBytes,
    maximumBytes: MAX_MANIFEST_BYTES,
  });
  if (
    !exactKeys(manifest.body, ["identity"]) ||
    !sameCanonicalValue(manifest.body.identity, storeIdentity(bootstrap))
  ) {
    throw new StoreIntegrityError();
  }
}

function readHeadEnvelope(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
): StoreFileReadResult<StoredHeadBodyV2> | null {
  const path = headPath(runPath);
  if (!existsSync(path)) return null;
  return readAuthenticatedRecord<StoredHeadBodyV2>({
    path,
    recordType: "head-pointer",
    keyId,
    keyBytes,
    maximumBytes: MAX_HEAD_BYTES,
  });
}

function readOperationEnvelope(
  runPath: string,
  operationId: string,
  keyId: string,
  keyBytes: Uint8Array,
): StoreFileReadResult<StoredOperationRecordBodyV2> | null {
  const path = operationRecordPath(runPath, operationId);
  if (!existsSync(path)) return null;
  return readAuthenticatedRecord<StoredOperationRecordBodyV2>({
    path,
    recordType: "operation-record",
    keyId,
    keyBytes,
    maximumBytes: MAX_OPERATION_BYTES,
  });
}

function readJournalEnvelope(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
): StoreFileReadResult<StoredJournalBodyV2> | null {
  const path = journalPath(runPath);
  if (!existsSync(path)) return null;
  return readAuthenticatedRecord<StoredJournalBodyV2>({
    path,
    recordType: "transaction-journal",
    keyId,
    keyBytes,
    maximumBytes: MAX_TRANSACTION_BYTES,
  });
}

function readPendingOperationEnvelope(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
): StoreFileReadResult<StoredOperationRecordBodyV2> | null {
  const path = pendingOperationPath(runPath);
  if (!existsSync(path)) return null;
  return readAuthenticatedRecord<StoredOperationRecordBodyV2>({
    path,
    recordType: "operation-record",
    keyId,
    keyBytes,
    maximumBytes: MAX_OPERATION_BYTES,
  });
}

function readReceiptEnvelope(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
): StoreFileReadResult<CommittedControllerTransitionReceiptV2> | null {
  const path = receiptPath(runPath);
  if (!existsSync(path)) return null;
  const descriptor = openPrivateFileForInspection(path, MAX_RECEIPT_BYTES);
  let text: string;
  try {
    text = readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
    if (canonicalizeControllerStoreValueV2(parsed) !== text) {
      throw new StoreIntegrityError();
    }
  } catch {
    throw new StoreIntegrityError();
  }
  if (!validateCommittedTransitionReceiptEnvelope(parsed, keyId, keyBytes)) {
    throw new StoreIntegrityError();
  }
  const body = parseCommittedTransitionReceiptEnvelope(parsed, keyId, keyBytes);
  return {
    body,
    recordDigest: body.receiptDigest,
    authenticationTag: body.authenticationTag,
  };
}

function validateCommittedTransitionReceiptEnvelope(
  value: unknown,
  keyId: string,
  keyBytes: Uint8Array,
): boolean {
  try {
    return validateCommittedTransitionReceiptEnvelopeStrict(
      value,
      keyId,
      keyBytes,
    );
  } catch {
    return false;
  }
}

function validateCommittedTransitionReceiptEnvelopeStrict(
  value: unknown,
  keyId: string,
  keyBytes: Uint8Array,
): boolean {
  if (!validateCommittedControllerTransitionReceiptV2(value)) return false;
  const parsed = value as CommittedControllerTransitionReceiptV2;
  if (parsed.keyId !== keyId) return false;
  const body = parseCommittedControllerTransitionReceiptV2(parsed);
  const digest = computeCommittedControllerTransitionReceiptDigestV2(body);
  if (digest !== body.receiptDigest) return false;
  const auth = authenticateRecord(
    keyId,
    "committed-transition-receipt",
    digest,
    keyBytes,
  );
  return auth === body.authenticationTag;
}

function parseCommittedTransitionReceiptEnvelope(
  value: unknown,
  keyId: string,
  keyBytes: Uint8Array,
): Readonly<CommittedControllerTransitionReceiptV2> {
  if (
    !validateCommittedTransitionReceiptEnvelopeStrict(value, keyId, keyBytes)
  ) {
    throw new StoreIntegrityError();
  }
  return parseCommittedControllerTransitionReceiptV2(value);
}

function snapshotMatchesRunIdentity(
  snapshot: Readonly<ControllerSnapshotV2>,
  identity: Readonly<ControllerRunIdentityV2>,
): boolean {
  return (
    snapshot.snapshotId === identity.snapshotId &&
    snapshot.identity.projectId === identity.projectId &&
    snapshot.identity.taskId === identity.taskId &&
    snapshot.identity.repositoryId === identity.repositoryId &&
    snapshot.identity.headBranch === identity.headBranch
  );
}

function readCurrentHeadState(
  runPath: string,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
): {
  readonly status: Readonly<ReadyControllerStoreStatusV2>;
  readonly snapshot: Readonly<ControllerSnapshotV2>;
  readonly cleanupRequired: boolean;
  readonly recordDigest: DigestSha256V2;
} | null {
  const envelope = readHeadEnvelope(runPath, keyId, keyBytes);
  if (!envelope) return null;
  const body = envelope.body;
  if (!exactKeys(body, ["status", "snapshot"])) throw new StoreIntegrityError();
  if (
    !exactKeys(body.status, [
      "kind",
      "identity",
      "runIdentity",
      "committedRevision",
      "snapshotDigest",
      "lastReceiptDigest",
      "operationCount",
      "quarantineCount",
      "cleanupRequired",
    ])
  ) {
    throw new StoreIntegrityError();
  }
  if (body.status.kind !== "ready") throw new StoreIntegrityError();
  const snapshot = cloneJsonValue<ControllerSnapshotV2>(body.snapshot);
  if (
    !validateControllerSnapshotV2(snapshot) ||
    !sameCanonicalValue(body.status.identity, expectedStoreIdentity) ||
    !sameCanonicalValue(body.status.runIdentity, expectedRunIdentity) ||
    !snapshotMatchesRunIdentity(snapshot, expectedRunIdentity) ||
    body.status.committedRevision !== snapshot.revision ||
    body.status.snapshotDigest !== digestControllerSnapshotV2(snapshot) ||
    body.status.operationCount !== snapshot.revision + 1 ||
    body.status.quarantineCount !== 0 ||
    body.status.cleanupRequired !== false
  ) {
    throw new StoreIntegrityError();
  }
  const cleanupRequired = hasPendingTransaction(runPath, keyId, keyBytes);
  const status = parseControllerStoreStatusV2({
    ...body.status,
    cleanupRequired,
    headRecordDigest: envelope.recordDigest,
  });
  if (status.kind !== "ready") throw new StoreIntegrityError();
  assertHeadOperationReachability(
    runPath,
    expectedStoreIdentity,
    expectedRunIdentity,
    keyId,
    keyBytes,
    status,
    snapshot,
  );
  return {
    status,
    snapshot: deepFreeze(snapshot),
    cleanupRequired,
    recordDigest: envelope.recordDigest,
  };
}

function hasPendingTransaction(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
): boolean {
  const txnDir = transactionPath(runPath);
  if (!existsSync(txnDir)) return false;
  const journal = readJournalEnvelope(runPath, keyId, keyBytes);
  return journal !== null;
}

function currentRunStatusOrAbsent(
  runPath: string,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
):
  | { readonly kind: "absent" }
  | {
      readonly status: Readonly<ReadyControllerStoreStatusV2>;
      readonly snapshot: Readonly<ControllerSnapshotV2>;
      readonly cleanupRequired: boolean;
      readonly recordDigest: DigestSha256V2;
    }
  | {
      readonly repairRequired: true;
      readonly code: "integrity-failure" | "recovery-required";
    } {
  try {
    const head = readCurrentHeadState(
      runPath,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    );
    if (head) return head;
    const txnDir = transactionPath(runPath);
    if (existsSync(txnDir)) {
      return { repairRequired: true, code: "recovery-required" };
    }
    return { kind: "absent" };
  } catch (error) {
    if (error instanceof StoreIntegrityError) {
      return { repairRequired: true, code: "integrity-failure" };
    }
    throw error;
  }
}

function writeHeadState(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
  status: Readonly<ReadyControllerStoreStatusV2>,
  snapshot: Readonly<ControllerSnapshotV2>,
): void {
  ensurePrivateDirectory(runPath);
  const body: StoredHeadBodyV2 = {
    status: {
      kind: status.kind,
      identity: status.identity,
      runIdentity: status.runIdentity,
      committedRevision: status.committedRevision,
      snapshotDigest: status.snapshotDigest,
      lastReceiptDigest: status.lastReceiptDigest,
      operationCount: status.operationCount,
      quarantineCount: status.quarantineCount,
      cleanupRequired: false,
    },
    snapshot,
  };
  writeAuthenticatedRecord({
    path: headPath(runPath),
    recordType: "head-pointer",
    keyId,
    keyBytes,
    body,
  });
}

function writeOperationRecordFinal(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
  operationId: string,
  requestDigest: DigestSha256V2,
  result:
    | Readonly<CreatedControllerRunV2>
    | Readonly<CommittedControllerTransitionV2>,
): void {
  ensurePrivateDirectory(operationsPath(runPath));
  writeAuthenticatedRecord({
    path: operationRecordPath(runPath, operationId),
    recordType: "operation-record",
    keyId,
    keyBytes,
    body: {
      kind: result.kind,
      operationId,
      requestDigest,
      result,
    },
  });
}

function writeOperationRecordPending(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
  operationId: string,
  requestDigest: DigestSha256V2,
  result: Readonly<CommittedControllerTransitionV2>,
): void {
  writeAuthenticatedRecord({
    path: pendingOperationPath(runPath),
    recordType: "operation-record",
    keyId,
    keyBytes,
    body: {
      kind: result.kind,
      operationId,
      requestDigest,
      result,
    },
  });
}

function writeTransactionJournal(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
  body: StoredJournalBodyV2,
): void {
  writeAuthenticatedRecord({
    path: journalPath(runPath),
    recordType: "transaction-journal",
    keyId,
    keyBytes,
    body,
  });
}

function writeTransactionRecords(
  runPath: string,
  keyId: string,
  keyBytes: Uint8Array,
  body: StoredRecordsBodyV2,
): void {
  writeAuthenticatedRecord({
    path: recordsPath(runPath),
    recordType: "transition-record",
    keyId,
    keyBytes,
    body,
  });
}

function writeTransactionReceipt(
  runPath: string,
  receipt: Readonly<CommittedControllerTransitionReceiptV2>,
): void {
  atomicWriteCanonicalJson(receiptPath(runPath), receipt);
  syncDirectory(transactionPath(runPath));
}

function removeTransactionDirectory(runPath: string): void {
  rmSync(transactionPath(runPath), { recursive: true, force: true });
}

function removeOperationRecordPending(runPath: string): void {
  rmSync(pendingOperationPath(runPath), { force: true });
}

function validateOperationRecordBody(
  value: unknown,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
): value is StoredOperationRecordBodyV2 {
  if (!exactKeys(value, ["kind", "operationId", "requestDigest", "result"])) {
    return false;
  }
  if (
    (value.kind !== "create" && value.kind !== "commit") ||
    typeof value.operationId !== "string" ||
    !isSafeString(value.operationId) ||
    !digestPattern.test(String(value.requestDigest)) ||
    typeof value.result !== "object" ||
    value.result === null ||
    Array.isArray(value.result)
  ) {
    return false;
  }
  const result = value.result as Record<string, unknown>;
  const expectedResultKeys =
    value.kind === "create"
      ? ["kind", "replayed", "revision", "snapshot", "status"]
      : [
          "kind",
          "replayed",
          "revision",
          "snapshot",
          "intents",
          "receipt",
          "status",
        ];
  if (
    !exactKeys(result, expectedResultKeys) ||
    result.kind !== value.kind ||
    result.replayed !== false ||
    !Number.isSafeInteger(result.revision) ||
    Number(result.revision) < 0
  ) {
    return false;
  }
  const snapshot = cloneJsonValue<ControllerSnapshotV2>(result.snapshot);
  if (
    !validateControllerSnapshotV2(snapshot) ||
    snapshot.revision !== result.revision ||
    !snapshotMatchesRunIdentity(snapshot, expectedRunIdentity) ||
    !validateControllerStoreStatusV2(result.status)
  ) {
    return false;
  }
  const status = result.status as ReadyControllerStoreStatusV2;
  if (
    status.kind !== "ready" ||
    !sameCanonicalValue(status.identity, expectedStoreIdentity) ||
    !sameCanonicalValue(status.runIdentity, expectedRunIdentity) ||
    !sameCanonicalValue(
      status,
      createStoredStatus(
        expectedStoreIdentity,
        expectedRunIdentity,
        snapshot,
        snapshot.revision,
        status.lastReceiptDigest,
        snapshot.revision + 1,
        false,
      ),
    )
  ) {
    return false;
  }
  if (value.kind === "create") {
    return (
      result.revision === 0 &&
      snapshot.previousTransitionDigest === null &&
      status.lastReceiptDigest === null
    );
  }
  if (
    result.revision === 0 ||
    !Array.isArray(result.intents) ||
    !validateCommittedTransitionReceiptEnvelope(result.receipt, keyId, keyBytes)
  ) {
    return false;
  }
  const receipt = result.receipt as CommittedControllerTransitionReceiptV2;
  const operationIdentityDigest = digestControllerStoreValueV2(
    "spts/controller-store-operation-identity/v2",
    {
      namespaceDigest: expectedRunIdentity.namespaceDigest,
      runIdentityDigest: expectedRunIdentity.runIdentityDigest,
      operationId: value.operationId,
    },
  );
  return (
    receipt.namespaceDigest === expectedRunIdentity.namespaceDigest &&
    receipt.keyId === expectedStoreIdentity.keyId &&
    receipt.taskId === expectedRunIdentity.taskId &&
    receipt.projectId === expectedRunIdentity.projectId &&
    receipt.repositoryId === expectedRunIdentity.repositoryId &&
    receipt.runId === expectedRunIdentity.snapshotId &&
    receipt.branch === expectedRunIdentity.headBranch &&
    receipt.previousRevision === Number(result.revision) - 1 &&
    receipt.committedRevision === result.revision &&
    receipt.committedSnapshotDigest === digestControllerSnapshotV2(snapshot) &&
    receipt.operationIdentity === value.operationId &&
    receipt.idempotencyIdentity === `op-${operationIdentityDigest}` &&
    receipt.canonicalRequestDigest === value.requestDigest &&
    receipt.transitionDigest === snapshot.previousTransitionDigest &&
    receipt.transitionChainDigest === receipt.transitionDigest &&
    receipt.recordDigest === receipt.transitionDigest &&
    receipt.orderedIntentsDigest ===
      digestControllerStoreValueV2(
        "spts/controller-store-ordered-intents/v2",
        result.intents,
      ) &&
    status.lastReceiptDigest === receipt.receiptDigest
  );
}

function validateControllerStoreStatusV2(
  value: unknown,
): value is ControllerStoreStatusV2 {
  try {
    return parseControllerStoreStatusV2(value) !== undefined;
  } catch {
    return false;
  }
}

interface StoredOperationEvidenceV2 {
  readonly body: Readonly<StoredOperationRecordBodyV2>;
  readonly source: "final" | "pending";
}

interface StoredTransactionOperationEvidenceV2 {
  readonly final: Readonly<StoredOperationRecordBodyV2> | null;
  readonly pending: Readonly<StoredOperationRecordBodyV2> | null;
}

function requireValidOperationRecordBody(
  value: unknown,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
): asserts value is StoredOperationRecordBodyV2 {
  try {
    if (
      validateOperationRecordBody(
        value,
        expectedStoreIdentity,
        expectedRunIdentity,
        keyId,
        keyBytes,
      )
    ) {
      return;
    }
  } catch {
    // Authenticated but malformed operation data is an integrity failure.
  }
  throw new StoreIntegrityError();
}

function validateJournalBody(
  value: unknown,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
): value is StoredJournalBodyV2 {
  if (
    !exactKeys(value, [
      "operationId",
      "requestDigest",
      "fromRevision",
      "toRevision",
      "committedSnapshotDigest",
      "operationIdentity",
      "operationIdentityDigest",
      "idempotencyIdentity",
      "headPublished",
    ]) ||
    typeof value.operationId !== "string" ||
    !isSafeString(value.operationId) ||
    typeof value.requestDigest !== "string" ||
    !digestPattern.test(value.requestDigest) ||
    typeof value.fromRevision !== "number" ||
    !Number.isSafeInteger(value.fromRevision) ||
    value.fromRevision < 0 ||
    value.fromRevision === Number.MAX_SAFE_INTEGER ||
    typeof value.toRevision !== "number" ||
    !Number.isSafeInteger(value.toRevision) ||
    value.toRevision !== value.fromRevision + 1 ||
    typeof value.committedSnapshotDigest !== "string" ||
    !digestPattern.test(value.committedSnapshotDigest) ||
    value.operationIdentity !== value.operationId ||
    typeof value.operationIdentityDigest !== "string" ||
    !digestPattern.test(value.operationIdentityDigest) ||
    typeof value.idempotencyIdentity !== "string" ||
    typeof value.headPublished !== "boolean"
  ) {
    return false;
  }
  const operationIdentityDigest = digestControllerStoreValueV2(
    "spts/controller-store-operation-identity/v2",
    {
      namespaceDigest: expectedRunIdentity.namespaceDigest,
      runIdentityDigest: expectedRunIdentity.runIdentityDigest,
      operationId: value.operationId,
    },
  );
  return (
    value.operationIdentityDigest === operationIdentityDigest &&
    value.idempotencyIdentity === `op-${operationIdentityDigest}`
  );
}

function operationRecordMatchesJournal(
  body: Readonly<StoredOperationRecordBodyV2>,
  journal: Readonly<StoredJournalBodyV2>,
): boolean {
  if (body.kind !== "commit") return false;
  const result = body.result as Readonly<CommittedControllerTransitionV2>;
  return (
    body.operationId === journal.operationId &&
    body.requestDigest === journal.requestDigest &&
    result.revision === journal.toRevision &&
    digestControllerSnapshotV2(
      cloneJsonValue<ControllerSnapshotV2>(result.snapshot),
    ) === journal.committedSnapshotDigest &&
    result.receipt.previousRevision === journal.fromRevision &&
    result.receipt.committedRevision === journal.toRevision &&
    result.receipt.committedSnapshotDigest ===
      journal.committedSnapshotDigest &&
    result.receipt.operationIdentity === journal.operationIdentity &&
    result.receipt.idempotencyIdentity === journal.idempotencyIdentity &&
    result.receipt.canonicalRequestDigest === journal.requestDigest
  );
}

function readFinalOperationEvidence(
  runPath: string,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
): readonly StoredOperationEvidenceV2[] {
  const directory = operationsPath(runPath);
  if (!existsSync(directory)) return [];
  requirePrivateDirectory(directory);
  const evidence: StoredOperationEvidenceV2[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/.test(entry.name)) {
      throw new StoreIntegrityError();
    }
    const path = join(directory, entry.name);
    const envelope = readAuthenticatedRecord<StoredOperationRecordBodyV2>({
      path,
      recordType: "operation-record",
      keyId,
      keyBytes,
      maximumBytes: MAX_OPERATION_BYTES,
    });
    requireValidOperationRecordBody(
      envelope.body,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    );
    if (operationRecordPath(runPath, envelope.body.operationId) !== path) {
      throw new StoreIntegrityError();
    }
    evidence.push({ body: envelope.body, source: "final" });
  }
  return evidence;
}

function readTransactionOperationEvidence(
  runPath: string,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
  journal: Readonly<StoredJournalBodyV2>,
): StoredTransactionOperationEvidenceV2 {
  const pendingEnvelope = readPendingOperationEnvelope(
    runPath,
    keyId,
    keyBytes,
  );
  const finalEnvelope = readOperationEnvelope(
    runPath,
    journal.operationId,
    keyId,
    keyBytes,
  );
  if (pendingEnvelope) {
    requireValidOperationRecordBody(
      pendingEnvelope.body,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    );
    if (!operationRecordMatchesJournal(pendingEnvelope.body, journal)) {
      throw new StoreIntegrityError();
    }
  }
  if (finalEnvelope) {
    requireValidOperationRecordBody(
      finalEnvelope.body,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    );
    if (!operationRecordMatchesJournal(finalEnvelope.body, journal)) {
      throw new StoreIntegrityError();
    }
  }
  if (
    pendingEnvelope &&
    finalEnvelope &&
    !sameCanonicalValue(pendingEnvelope.body, finalEnvelope.body)
  ) {
    throw new StoreIntegrityError();
  }
  return {
    final: finalEnvelope?.body ?? null,
    pending: pendingEnvelope?.body ?? null,
  };
}

function selectCanonicalOperationEvidence(
  matches: readonly StoredOperationEvidenceV2[],
): StoredOperationEvidenceV2 {
  const selected = matches[0];
  if (
    !selected ||
    matches.some(
      (candidate) => !sameCanonicalValue(candidate.body, selected.body),
    )
  ) {
    throw new StoreIntegrityError();
  }
  return selected;
}

function assertHeadOperationReachability(
  runPath: string,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  keyId: string,
  keyBytes: Uint8Array,
  status: Readonly<ReadyControllerStoreStatusV2>,
  snapshot: Readonly<ControllerSnapshotV2>,
): void {
  const finalEvidence = readFinalOperationEvidence(
    runPath,
    expectedStoreIdentity,
    expectedRunIdentity,
    keyId,
    keyBytes,
  );
  const journalEnvelope = readJournalEnvelope(runPath, keyId, keyBytes);
  let transactionEvidence: StoredTransactionOperationEvidenceV2 = {
    final: null,
    pending: null,
  };
  if (journalEnvelope) {
    if (!validateJournalBody(journalEnvelope.body, expectedRunIdentity)) {
      throw new StoreIntegrityError();
    }
    transactionEvidence = readTransactionOperationEvidence(
      runPath,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
      journalEnvelope.body,
    );
    if (
      journalEnvelope.body.toRevision === status.committedRevision &&
      !transactionEvidence.final &&
      !transactionEvidence.pending
    ) {
      throw new StoreIntegrityError();
    }
  } else if (readPendingOperationEnvelope(runPath, keyId, keyBytes)) {
    throw new StoreIntegrityError();
  }

  const candidates: StoredOperationEvidenceV2[] = [...finalEvidence];
  if (
    journalEnvelope &&
    transactionEvidence.pending &&
    journalEnvelope.body.toRevision === status.committedRevision
  ) {
    candidates.push({
      body: transactionEvidence.pending,
      source: "pending",
    });
  }

  const reachableFinalOperations = new Set<string>();
  let expectedSnapshotDigest = status.snapshotDigest;
  let expectedReceiptDigest = status.lastReceiptDigest;
  for (let revision = status.committedRevision; revision > 0; revision -= 1) {
    if (expectedReceiptDigest === null) throw new StoreIntegrityError();
    const matches = candidates.filter((candidate) => {
      if (candidate.body.kind !== "commit") return false;
      const result = candidate.body
        .result as Readonly<CommittedControllerTransitionV2>;
      return (
        result.revision === revision &&
        result.receipt.receiptDigest === expectedReceiptDigest &&
        digestControllerSnapshotV2(
          cloneJsonValue<ControllerSnapshotV2>(result.snapshot),
        ) === expectedSnapshotDigest
      );
    });
    const selected = selectCanonicalOperationEvidence(matches);
    const result = selected.body
      .result as Readonly<CommittedControllerTransitionV2>;
    if (
      revision === status.committedRevision &&
      !sameCanonicalValue(result.snapshot, snapshot)
    ) {
      throw new StoreIntegrityError();
    }
    for (const match of matches) {
      if (match.source === "final") {
        reachableFinalOperations.add(match.body.operationId);
      }
    }
    expectedSnapshotDigest = result.receipt.previousSnapshotDigest;
    expectedReceiptDigest = result.receipt.previousReceiptDigest;
  }

  const genesisMatches = candidates.filter((candidate) => {
    if (candidate.body.kind !== "create") return false;
    const result = candidate.body.result as Readonly<CreatedControllerRunV2>;
    return (
      result.revision === 0 &&
      result.status.lastReceiptDigest === null &&
      digestControllerSnapshotV2(
        cloneJsonValue<ControllerSnapshotV2>(result.snapshot),
      ) === expectedSnapshotDigest
    );
  });
  const genesis = selectCanonicalOperationEvidence(genesisMatches);
  if (
    status.committedRevision === 0 &&
    !sameCanonicalValue(genesis.body.result.snapshot, snapshot)
  ) {
    throw new StoreIntegrityError();
  }
  for (const match of genesisMatches) {
    if (match.source === "final") {
      reachableFinalOperations.add(match.body.operationId);
    }
  }
  if (
    expectedReceiptDigest !== null ||
    reachableFinalOperations.size !== finalEvidence.length
  ) {
    throw new StoreIntegrityError();
  }
}

function replayOperationResult<
  T extends CreatedControllerRunV2 | CommittedControllerTransitionV2,
>(body: StoredOperationRecordBodyV2): T {
  const result = cloneJsonValue<T>(body.result);
  (result as { replayed: boolean }).replayed = true;
  return deepFreeze(result);
}

function createHeadStatusBody(
  storeIdentity: Readonly<ControllerStoreIdentityV2>,
  runIdentity: Readonly<ControllerRunIdentityV2>,
  snapshot: Readonly<ControllerSnapshotV2>,
  committedRevision: number,
  lastReceiptDigest: DigestSha256V2 | null,
  operationCount: number,
  cleanupRequired = false,
): StoredReadyControllerStoreStatusV2 {
  return {
    kind: "ready",
    identity: storeIdentity,
    runIdentity,
    committedRevision,
    snapshotDigest: digestControllerSnapshotV2(
      cloneJsonValue<ControllerSnapshotV2>(snapshot),
    ),
    lastReceiptDigest,
    operationCount,
    quarantineCount: 0,
    cleanupRequired,
  };
}

function createStoredStatus(
  storeIdentity: Readonly<ControllerStoreIdentityV2>,
  runIdentity: Readonly<ControllerRunIdentityV2>,
  snapshot: Readonly<ControllerSnapshotV2>,
  committedRevision: number,
  lastReceiptDigest: DigestSha256V2 | null,
  operationCount: number,
  cleanupRequired: boolean,
): Readonly<ReadyControllerStoreStatusV2> {
  const body = createHeadStatusBody(
    storeIdentity,
    runIdentity,
    snapshot,
    committedRevision,
    lastReceiptDigest,
    operationCount,
    cleanupRequired,
  );
  const status = parseControllerStoreStatusV2({
    ...body,
    headRecordDigest: digestControllerStoreValueV2(
      "spts.controller-store-head-status/v2",
      {
        status: body,
        snapshot,
      },
    ),
  });
  if (status.kind !== "ready") throw new StoreUnexpectedError();
  return status;
}

function loadExistingOperationResult(
  runPath: string,
  expectedStoreIdentity: Readonly<ControllerStoreIdentityV2>,
  expectedRunIdentity: Readonly<ControllerRunIdentityV2>,
  operationId: string,
  requestDigest: DigestSha256V2,
  keyId: string,
  keyBytes: Uint8Array,
):
  | {
      readonly kind: "replay";
      readonly result:
        | Readonly<CreatedControllerRunV2>
        | Readonly<CommittedControllerTransitionV2>;
    }
  | { readonly kind: "conflict" }
  | { readonly kind: "none" } {
  const finalRecord = readOperationEnvelope(
    runPath,
    operationId,
    keyId,
    keyBytes,
  );
  if (finalRecord) {
    requireValidOperationRecordBody(
      finalRecord.body,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    );
    if (finalRecord.body.operationId !== operationId) {
      throw new StoreIntegrityError();
    }
    const head = readCurrentHeadState(
      runPath,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    );
    if (!head) throw new StoreIntegrityError();
    if (finalRecord.body.requestDigest !== requestDigest) {
      return { kind: "conflict" };
    }
    return { kind: "replay", result: replayOperationResult(finalRecord.body) };
  }
  const pendingRecord = readPendingOperationEnvelope(runPath, keyId, keyBytes);
  if (!pendingRecord) return { kind: "none" };
  if (
    !validateOperationRecordBody(
      pendingRecord.body,
      expectedStoreIdentity,
      expectedRunIdentity,
      keyId,
      keyBytes,
    )
  ) {
    throw new StoreIntegrityError();
  }
  if (pendingRecord.body.requestDigest !== requestDigest)
    return { kind: "conflict" };
  const journal = readJournalEnvelope(runPath, keyId, keyBytes);
  if (!journal) return { kind: "none" };
  if (journal.body.operationId !== operationId) return { kind: "none" };
  const head = readCurrentHeadState(
    runPath,
    expectedStoreIdentity,
    expectedRunIdentity,
    keyId,
    keyBytes,
  );
  if (!head) return { kind: "none" };
  if (head.status.committedRevision === journal.body.toRevision) {
    ensurePrivateDirectory(operationsPath(runPath));
    writeOperationRecordFinal(
      runPath,
      keyId,
      keyBytes,
      operationId,
      requestDigest,
      pendingRecord.body.result,
    );
    removeOperationRecordPending(runPath);
    return {
      kind: "replay",
      result: replayOperationResult(pendingRecord.body),
    };
  }
  return { kind: "none" };
}

function cleanupPendingTransaction(runPath: string): void {
  removeTransactionDirectory(runPath);
}

function hasFsCode(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}

function readBoundedSystemText(path: string, maximumBytes: number): string {
  const descriptor = openSync(path, constants.O_RDONLY | noFollowFlag());
  const bytes = Buffer.alloc(maximumBytes + 1);
  let offset = 0;
  try {
    while (offset < bytes.byteLength) {
      let count: number;
      try {
        count = readSync(
          descriptor,
          bytes,
          offset,
          bytes.byteLength - offset,
          null,
        );
      } catch (error) {
        if (hasFsCode(error, "EINTR")) continue;
        throw error;
      }
      if (count === 0) break;
      if (!Number.isSafeInteger(count) || count < 0) {
        throw new StoreUnexpectedError();
      }
      offset += count;
    }
  } finally {
    closeSync(descriptor);
  }
  if (offset > maximumBytes) throw new StoreUnexpectedError();
  return bytes.subarray(0, offset).toString("utf8");
}

function currentBootId(): string {
  const value = readBoundedSystemText(
    "/proc/sys/kernel/random/boot_id",
    128,
  ).trim();
  if (!bootIdPattern.test(value)) throw new StoreUnexpectedError();
  return value;
}

function processStartTicks(pid: number): string {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    throw new StoreUnexpectedError();
  }
  const text = readBoundedSystemText(`/proc/${pid}/stat`, 16 * 1024).trim();
  const opening = text.indexOf("(");
  const closing = text.lastIndexOf(")");
  if (
    opening <= 0 ||
    closing <= opening ||
    Number(text.slice(0, opening).trim()) !== pid
  ) {
    throw new StoreUnexpectedError();
  }
  const fields = text
    .slice(closing + 1)
    .trim()
    .split(/\s+/);
  const ticks = fields[19];
  if (!ticks || !processStartTicksPattern.test(ticks)) {
    throw new StoreUnexpectedError();
  }
  return ticks;
}

function canonicalLockTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function lockTimestamp(bootstrap: ControllerStoreBootstrapV2): {
  readonly now: string;
  readonly expires: string;
} {
  const now = bootstrap.clock.now();
  if (!canonicalLockTimestamp(now)) throw new StoreUnexpectedError();
  const expires = new Date(
    new Date(now).getTime() + LOCK_LEASE_MILLISECONDS,
  ).toISOString();
  return { now, expires };
}

function filesystemIdentity(path: string): StoredFilesystemIdentityV2 {
  const stat = lstatSync(path);
  return {
    device: stat.dev,
    inode: stat.ino,
    uid: stat.uid,
    mode: stat.mode & 0o777,
  };
}

function trustedDirectoryIdentity(path: string): StoredFilesystemIdentityV2 {
  requirePrivateDirectory(path);
  const identity = filesystemIdentity(path);
  if (
    !Number.isSafeInteger(identity.device) ||
    !Number.isSafeInteger(identity.inode) ||
    identity.device < 0 ||
    identity.inode <= 0
  ) {
    throw new StoreUnexpectedError();
  }
  return identity;
}

function sameFilesystemIdentity(
  left: StoredFilesystemIdentityV2,
  right: StoredFilesystemIdentityV2,
): boolean {
  return (
    left.device === right.device &&
    left.inode === right.inode &&
    left.uid === right.uid &&
    left.mode === right.mode
  );
}

function validStoredFilesystemIdentity(
  value: unknown,
): value is StoredFilesystemIdentityV2 {
  return (
    exactKeys(value, ["device", "inode", "uid", "mode"]) &&
    Number.isSafeInteger(value.device) &&
    Number(value.device) >= 0 &&
    Number.isSafeInteger(value.inode) &&
    Number(value.inode) > 0 &&
    Number.isSafeInteger(value.uid) &&
    Number(value.uid) >= 0 &&
    Number.isSafeInteger(value.mode) &&
    Number(value.mode) >= 0 &&
    Number(value.mode) <= 0o777
  );
}

function validLockCurrentTransaction(
  value: unknown,
): value is StoredLockCurrentTransactionV2 {
  if (
    !exactKeys(value, [
      "transactionIdDigest",
      "kind",
      "operationId",
      "requestDigest",
      "runIdentityDigest",
      "fromRevision",
      "toRevision",
      "relativePath",
    ])
  ) {
    return false;
  }
  if (
    !digestPattern.test(String(value.transactionIdDigest)) ||
    (value.kind !== "create" &&
      value.kind !== "commit" &&
      value.kind !== "recover") ||
    typeof value.operationId !== "string" ||
    !isSafeString(value.operationId) ||
    (value.requestDigest !== null &&
      !digestPattern.test(String(value.requestDigest))) ||
    !digestPattern.test(String(value.runIdentityDigest)) ||
    (value.fromRevision !== null &&
      (!Number.isSafeInteger(value.fromRevision) ||
        Number(value.fromRevision) < 0)) ||
    (value.toRevision !== null &&
      (!Number.isSafeInteger(value.toRevision) ||
        Number(value.toRevision) < 0)) ||
    typeof value.relativePath !== "string" ||
    value.relativePath !==
      `${RUNS_DIRECTORY}/${String(value.runIdentityDigest)}/${TRANSACTION_DIRECTORY}`
  ) {
    return false;
  }
  return true;
}

function validStoredLockOwnerBody(
  value: unknown,
): value is StoredLockOwnerBodyV2 {
  if (
    !exactKeys(value, [
      "namespaceDigest",
      "runIdentityDigest",
      "ownerToken",
      "ownerTokenDigest",
      "bootId",
      "pid",
      "processStartTicks",
      "acquiredAt",
      "leaseExpiresAt",
      "renewalCounter",
      "currentTransaction",
      "rootIdentity",
      "lockIdentity",
    ])
  ) {
    return false;
  }
  if (
    !digestPattern.test(String(value.namespaceDigest)) ||
    !digestPattern.test(String(value.runIdentityDigest)) ||
    !digestPattern.test(String(value.ownerToken)) ||
    !digestPattern.test(String(value.ownerTokenDigest)) ||
    !bootIdPattern.test(String(value.bootId)) ||
    !Number.isSafeInteger(value.pid) ||
    Number(value.pid) <= 0 ||
    !processStartTicksPattern.test(String(value.processStartTicks)) ||
    !canonicalLockTimestamp(value.acquiredAt) ||
    !canonicalLockTimestamp(value.leaseExpiresAt) ||
    !Number.isSafeInteger(value.renewalCounter) ||
    Number(value.renewalCounter) < 0 ||
    (value.currentTransaction !== null &&
      !validLockCurrentTransaction(value.currentTransaction)) ||
    !validStoredFilesystemIdentity(value.rootIdentity) ||
    !validStoredFilesystemIdentity(value.lockIdentity)
  ) {
    return false;
  }
  return (
    createHash("sha256")
      .update(Buffer.from(String(value.ownerToken), "hex"))
      .digest("hex") === value.ownerTokenDigest
  );
}

function readStoredLockOwner(
  path: string,
  namespace: DigestSha256V2,
  keyId: string,
  keyBytes: Uint8Array,
): Readonly<StoredLockOwnerBodyV2> {
  const envelope = readAuthenticatedRecord<StoredLockOwnerBodyV2>({
    path: lockOwnerPath(path),
    recordType: "lock-owner",
    keyId,
    keyBytes,
    maximumBytes: MAX_LOCK_OWNER_BYTES,
  });
  if (
    !validStoredLockOwnerBody(envelope.body) ||
    envelope.body.namespaceDigest !== namespace
  ) {
    throw new StoreIntegrityError();
  }
  return envelope.body;
}

function ensureNamespaceLockLayout(
  bootstrap: ControllerStoreBootstrapV2,
): void {
  const namespace = namespacePath(bootstrap);
  requirePrivateDirectory(namespace);
  ensurePrivateDirectory(lockCandidatesPath(bootstrap));
  const quarantine = join(namespace, QUARANTINE_DIRECTORY);
  ensurePrivateDirectory(quarantine);
  ensurePrivateDirectory(
    lockQuarantineKindPath(bootstrap, DEAD_LOCK_QUARANTINE),
  );
  ensurePrivateDirectory(
    lockQuarantineKindPath(bootstrap, RELEASED_LOCK_QUARANTINE),
  );
  ensurePrivateDirectory(
    lockQuarantineKindPath(bootstrap, LOCK_CANDIDATE_QUARANTINE),
  );
  syncDirectory(lockCandidatesPath(bootstrap));
  syncDirectory(quarantine);
  syncDirectory(namespace);
}

function createOwnerToken(
  bootstrap: ControllerStoreBootstrapV2,
  bootId: string,
  startTicks: string,
): {
  readonly token: DigestSha256V2;
  readonly tokenDigest: DigestSha256V2;
} {
  const random = Buffer.alloc(32);
  bootstrap.random.fill(random);
  const serial = lockOwnerSerial;
  lockOwnerSerial += 1;
  const token = createHash("sha256")
    .update("spts/controller-store-lock-owner/v2\0")
    .update(random)
    .update("\0")
    .update(bootId)
    .update("\0")
    .update(String(process.pid))
    .update("\0")
    .update(startTicks)
    .update("\0")
    .update(String(serial))
    .digest("hex") as DigestSha256V2;
  random.fill(0);
  return {
    token,
    tokenDigest: createHash("sha256")
      .update(Buffer.from(token, "hex"))
      .digest("hex") as DigestSha256V2,
  };
}

function quarantineDigest(
  bootstrap: ControllerStoreBootstrapV2,
  kind: LockQuarantineKindV2,
  runIdentityDigest: DigestSha256V2,
  ownerTokenDigest: DigestSha256V2,
): DigestSha256V2 {
  return digestControllerStoreValueV2("spts/controller-store-quarantine/v2", {
    kind,
    namespaceDigest: namespaceDigest(bootstrap),
    runIdentityDigestOrNull: runIdentityDigest,
    sourceTokenDigests: [ownerTokenDigest],
  });
}

function quarantineLockPath(
  bootstrap: ControllerStoreBootstrapV2,
  kind: LockQuarantineKindV2,
  owner: Readonly<StoredLockOwnerBodyV2>,
): string {
  return join(
    lockQuarantineKindPath(bootstrap, kind),
    quarantineDigest(
      bootstrap,
      kind,
      owner.runIdentityDigest,
      owner.ownerTokenDigest,
    ),
  );
}

function moveLockDirectory(source: string, destination: string): void {
  if (existsSync(destination)) throw new StoreIntegrityError();
  renameSync(source, destination);
  syncDirectory(parse(source).dir);
  syncDirectory(parse(destination).dir);
}

function sameCanonicalValue(left: unknown, right: unknown): boolean {
  return (
    canonicalizeControllerStoreValueV2(left) ===
    canonicalizeControllerStoreValueV2(right)
  );
}

function retainOwnedLockCandidate(
  bootstrap: ControllerStoreBootstrapV2,
  candidatePath: string,
  expectedOwner: Readonly<StoredLockOwnerBodyV2>,
  keyBytes: Uint8Array,
): void {
  if (!existsSync(candidatePath)) return;
  requirePrivateDirectory(candidatePath);
  const owner = readStoredLockOwner(
    candidatePath,
    namespaceDigest(bootstrap),
    bootstrap.keyProvider.keyId,
    keyBytes,
  );
  const identity = filesystemIdentity(candidatePath);
  if (
    !sameCanonicalValue(owner, expectedOwner) ||
    !sameFilesystemIdentity(identity, expectedOwner.lockIdentity)
  ) {
    throw new StoreIntegrityError();
  }
  const destination = quarantineLockPath(
    bootstrap,
    LOCK_CANDIDATE_QUARANTINE,
    owner,
  );
  moveLockDirectory(candidatePath, destination);
  const retainedOwner = readStoredLockOwner(
    destination,
    namespaceDigest(bootstrap),
    bootstrap.keyProvider.keyId,
    keyBytes,
  );
  if (!sameCanonicalValue(retainedOwner, expectedOwner)) {
    throw new StoreIntegrityError();
  }
}

function probeStoredLockOwner(
  owner: Readonly<StoredLockOwnerBodyV2>,
  options: ControllerStoreTestingOptionsV2 | undefined,
): "live" | "dead" | "ambiguous" {
  if (options?.lockOwnerProbe) {
    try {
      const result = options.lockOwnerProbe();
      return result === "live" || result === "dead" ? result : "ambiguous";
    } catch {
      return "ambiguous";
    }
  }
  let bootId: string;
  try {
    bootId = currentBootId();
  } catch {
    return "ambiguous";
  }
  if (bootId !== owner.bootId) return "dead";
  try {
    return processStartTicks(owner.pid) === owner.processStartTicks
      ? "live"
      : "dead";
  } catch (error) {
    return hasFsCode(error, "ENOENT") || hasFsCode(error, "ESRCH")
      ? "dead"
      : "ambiguous";
  }
}

function classifyDeadOwnerTransaction(
  bootstrap: ControllerStoreBootstrapV2,
  owner: Readonly<StoredLockOwnerBodyV2>,
  keyBytes: Uint8Array,
): void {
  if (!owner.currentTransaction) return;
  const runPath = join(runsPath(bootstrap), owner.runIdentityDigest);
  if (!existsSync(runPath)) {
    if (owner.currentTransaction.kind === "create") return;
    throw new StoreDeniedError("recovery-required");
  }
  try {
    requirePrivateDirectory(runPath);
    if (existsSync(headPath(runPath))) {
      readHeadEnvelope(runPath, bootstrap.keyProvider.keyId, keyBytes);
    }
    if (existsSync(transactionPath(runPath))) {
      requirePrivateDirectory(transactionPath(runPath));
      if (existsSync(journalPath(runPath))) {
        readJournalEnvelope(runPath, bootstrap.keyProvider.keyId, keyBytes);
      }
    }
  } catch {
    throw new StoreDeniedError("recovery-required");
  }
}

function verifyTrustedLockParents(
  bootstrap: ControllerStoreBootstrapV2,
  rootIdentity: StoredFilesystemIdentityV2,
  namespaceIdentity: StoredFilesystemIdentityV2,
): void {
  const currentRoot = trustedDirectoryIdentity(bootstrap.rootPath);
  const currentNamespace = trustedDirectoryIdentity(namespacePath(bootstrap));
  if (
    !sameFilesystemIdentity(currentRoot, rootIdentity) ||
    !sameFilesystemIdentity(currentNamespace, namespaceIdentity) ||
    currentNamespace.device !== currentRoot.device
  ) {
    throw new StoreDeniedError("storage-unavailable");
  }
}

function finishNamespaceLockAcquisition(
  bootstrap: ControllerStoreBootstrapV2,
  expectedOwner: Readonly<StoredLockOwnerBodyV2>,
  namespaceIdentity: StoredFilesystemIdentityV2,
  keyBytes: Uint8Array,
): HeldNamespaceLockV2 {
  const path = namespaceLockPath(bootstrap);
  requirePrivateDirectory(path);
  const identity = filesystemIdentity(path);
  const owner = readStoredLockOwner(
    path,
    namespaceDigest(bootstrap),
    bootstrap.keyProvider.keyId,
    keyBytes,
  );
  if (
    !sameFilesystemIdentity(identity, expectedOwner.lockIdentity) ||
    !sameCanonicalValue(owner, expectedOwner)
  ) {
    throw new StoreDeniedError("recovery-required");
  }
  const held: HeldNamespaceLockV2 = {
    namespacePath: namespacePath(bootstrap),
    namespaceIdentity,
    lockPath: path,
    lockDevice: identity.device,
    lockInode: identity.inode,
    owner,
  };
  return held;
}

function acquireNamespaceLock(
  bootstrap: ControllerStoreBootstrapV2,
  runIdentityDigest: DigestSha256V2,
  keyBytes: Uint8Array,
  options: ControllerStoreTestingOptionsV2 | undefined,
): HeldNamespaceLockV2 {
  ensureNamespaceLockLayout(bootstrap);
  const rootIdentity = trustedDirectoryIdentity(bootstrap.rootPath);
  const namespaceIdentity = trustedDirectoryIdentity(namespacePath(bootstrap));
  if (rootIdentity.device !== namespaceIdentity.device) {
    throw new StoreDeniedError("storage-unavailable");
  }
  const bootId = currentBootId();
  const startTicks = processStartTicks(process.pid);
  const { token, tokenDigest } = createOwnerToken(
    bootstrap,
    bootId,
    startTicks,
  );
  const candidatePath = lockCandidatePath(bootstrap, tokenDigest);
  mkdirSync(candidatePath, { mode: 0o700 });
  requirePrivateDirectory(candidatePath);
  const candidateIdentity = filesystemIdentity(candidatePath);
  const timestamp = lockTimestamp(bootstrap);
  const owner: StoredLockOwnerBodyV2 = {
    namespaceDigest: namespaceDigest(bootstrap),
    runIdentityDigest,
    ownerToken: token,
    ownerTokenDigest: tokenDigest,
    bootId,
    pid: process.pid,
    processStartTicks: startTicks,
    acquiredAt: timestamp.now,
    leaseExpiresAt: timestamp.expires,
    renewalCounter: 0,
    currentTransaction: null,
    rootIdentity,
    lockIdentity: candidateIdentity,
  };
  writeAuthenticatedRecord({
    path: lockOwnerPath(candidatePath),
    recordType: "lock-owner",
    keyId: bootstrap.keyProvider.keyId,
    keyBytes,
    body: owner,
  });
  syncDirectory(candidatePath);
  syncDirectory(lockCandidatesPath(bootstrap));

  const fixedPath = namespaceLockPath(bootstrap);
  for (let attempt = 0; attempt < 8; attempt += 1) {
    verifyTrustedLockParents(bootstrap, rootIdentity, namespaceIdentity);
    if (existsSync(fixedPath)) {
      let fixedOwner: Readonly<StoredLockOwnerBodyV2>;
      let fixedIdentity: StoredFilesystemIdentityV2;
      try {
        requirePrivateDirectory(fixedPath);
        fixedIdentity = filesystemIdentity(fixedPath);
        fixedOwner = readStoredLockOwner(
          fixedPath,
          namespaceDigest(bootstrap),
          bootstrap.keyProvider.keyId,
          keyBytes,
        );
        if (
          !sameFilesystemIdentity(fixedIdentity, fixedOwner.lockIdentity) ||
          !sameFilesystemIdentity(fixedOwner.rootIdentity, rootIdentity)
        ) {
          throw new StoreIntegrityError();
        }
      } catch {
        retainOwnedLockCandidate(bootstrap, candidatePath, owner, keyBytes);
        throw new StoreDeniedError("recovery-required");
      }
      if (sameCanonicalValue(fixedOwner, owner)) {
        syncDirectory(lockCandidatesPath(bootstrap));
        syncDirectory(namespacePath(bootstrap));
        return finishNamespaceLockAcquisition(
          bootstrap,
          owner,
          namespaceIdentity,
          keyBytes,
        );
      }
      const liveness = probeStoredLockOwner(fixedOwner, options);
      if (liveness !== "dead") {
        retainOwnedLockCandidate(bootstrap, candidatePath, owner, keyBytes);
        throw new StoreDeniedError(
          liveness === "live" ? "busy" : "recovery-required",
        );
      }
      try {
        classifyDeadOwnerTransaction(bootstrap, fixedOwner, keyBytes);
        const currentIdentity = filesystemIdentity(fixedPath);
        if (!sameFilesystemIdentity(currentIdentity, fixedIdentity)) {
          throw new StoreDeniedError("recovery-required");
        }
        const deadPath = quarantineLockPath(
          bootstrap,
          DEAD_LOCK_QUARANTINE,
          fixedOwner,
        );
        moveLockDirectory(fixedPath, deadPath);
        const retainedOwner = readStoredLockOwner(
          deadPath,
          namespaceDigest(bootstrap),
          bootstrap.keyProvider.keyId,
          keyBytes,
        );
        if (!sameCanonicalValue(retainedOwner, fixedOwner)) {
          throw new StoreDeniedError("recovery-required");
        }
      } catch (error) {
        if (!existsSync(fixedPath) && hasFsCode(error, "ENOENT")) continue;
        retainOwnedLockCandidate(bootstrap, candidatePath, owner, keyBytes);
        if (error instanceof StoreDeniedError) throw error;
        throw new StoreDeniedError("recovery-required");
      }
      continue;
    }

    requirePrivateDirectory(candidatePath);
    const currentCandidateIdentity = filesystemIdentity(candidatePath);
    const currentCandidateOwner = readStoredLockOwner(
      candidatePath,
      namespaceDigest(bootstrap),
      bootstrap.keyProvider.keyId,
      keyBytes,
    );
    if (
      !sameFilesystemIdentity(currentCandidateIdentity, candidateIdentity) ||
      !sameCanonicalValue(currentCandidateOwner, owner)
    ) {
      throw new StoreDeniedError("recovery-required");
    }
    try {
      renameSync(candidatePath, fixedPath);
    } catch (error) {
      if (existsSync(fixedPath)) continue;
      if (!existsSync(candidatePath) && existsSync(fixedPath)) continue;
      throw error;
    }
    syncDirectory(lockCandidatesPath(bootstrap));
    syncDirectory(namespacePath(bootstrap));
    return finishNamespaceLockAcquisition(
      bootstrap,
      owner,
      namespaceIdentity,
      keyBytes,
    );
  }
  retainOwnedLockCandidate(bootstrap, candidatePath, owner, keyBytes);
  throw new StoreDeniedError("busy");
}

function verifyNamespaceLock(
  bootstrap: ControllerStoreBootstrapV2,
  held: HeldNamespaceLockV2,
  keyBytes: Uint8Array,
): void {
  verifyTrustedLockParents(
    bootstrap,
    held.owner.rootIdentity,
    held.namespaceIdentity,
  );
  requirePrivateDirectory(held.lockPath);
  const identity = filesystemIdentity(held.lockPath);
  if (
    identity.device !== held.lockDevice ||
    identity.inode !== held.lockInode ||
    !sameFilesystemIdentity(identity, held.owner.lockIdentity)
  ) {
    throw new StoreDeniedError("storage-unavailable");
  }
  const owner = readStoredLockOwner(
    held.lockPath,
    namespaceDigest(bootstrap),
    bootstrap.keyProvider.keyId,
    keyBytes,
  );
  if (
    !sameCanonicalValue(owner, held.owner) ||
    owner.bootId !== currentBootId() ||
    owner.pid !== process.pid ||
    owner.processStartTicks !== processStartTicks(process.pid)
  ) {
    throw new StoreDeniedError("storage-unavailable");
  }
}

function renewNamespaceLock(
  bootstrap: ControllerStoreBootstrapV2,
  held: HeldNamespaceLockV2,
  keyBytes: Uint8Array,
  currentTransaction: StoredLockCurrentTransactionV2 | null,
): void {
  verifyNamespaceLock(bootstrap, held, keyBytes);
  if (held.owner.renewalCounter === Number.MAX_SAFE_INTEGER) {
    throw new StoreDeniedError("resource-limit");
  }
  const timestamp = lockTimestamp(bootstrap);
  const next: StoredLockOwnerBodyV2 = {
    ...held.owner,
    leaseExpiresAt: timestamp.expires,
    renewalCounter: held.owner.renewalCounter + 1,
    currentTransaction,
  };
  const envelope = writeAuthenticatedRecord({
    path: lockOwnerPath(held.lockPath),
    recordType: "lock-owner",
    keyId: bootstrap.keyProvider.keyId,
    keyBytes,
    body: next,
  });
  syncDirectory(held.namespacePath);
  held.owner = deepFreeze(envelope.body);
  verifyNamespaceLock(bootstrap, held, keyBytes);
}

function releaseNamespaceLock(
  bootstrap: ControllerStoreBootstrapV2,
  held: HeldNamespaceLockV2,
  keyBytes: Uint8Array,
): boolean {
  verifyNamespaceLock(bootstrap, held, keyBytes);
  const releasedPath = quarantineLockPath(
    bootstrap,
    RELEASED_LOCK_QUARANTINE,
    held.owner,
  );
  moveLockDirectory(held.lockPath, releasedPath);
  const releasedIdentity = filesystemIdentity(releasedPath);
  const releasedOwner = readStoredLockOwner(
    releasedPath,
    namespaceDigest(bootstrap),
    bootstrap.keyProvider.keyId,
    keyBytes,
  );
  if (
    releasedIdentity.device !== held.lockDevice ||
    releasedIdentity.inode !== held.lockInode ||
    !sameCanonicalValue(releasedOwner, held.owner)
  ) {
    throw new StoreDeniedError("storage-unavailable");
  }
  try {
    rmSync(releasedPath, { recursive: true, force: false });
    syncDirectory(parse(releasedPath).dir);
    return true;
  } catch {
    // A conclusively owned released lock is retained as detectable cleanup evidence.
    return false;
  }
}

function lockCurrentTransaction(options: {
  readonly kind: StoredLockCurrentTransactionV2["kind"];
  readonly operationId: string;
  readonly requestDigest: DigestSha256V2 | null;
  readonly runIdentityDigest: DigestSha256V2;
  readonly fromRevision: number | null;
  readonly toRevision: number | null;
}): StoredLockCurrentTransactionV2 {
  const relativePath = `${RUNS_DIRECTORY}/${options.runIdentityDigest}/${TRANSACTION_DIRECTORY}`;
  const transactionIdDigest = digestControllerStoreValueV2(
    "spts/controller-store-lock-transaction/v2",
    { ...options, relativePath },
  );
  return {
    transactionIdDigest,
    kind: options.kind,
    operationId: options.operationId,
    requestDigest: options.requestDigest,
    runIdentityDigest: options.runIdentityDigest,
    fromRevision: options.fromRevision,
    toRevision: options.toRevision,
    relativePath,
  };
}

async function openStoreInternal(
  bootstrapInput: unknown,
  options: ControllerStoreTestingOptionsV2 | undefined,
  productionRefusal: boolean,
): Promise<ControllerStoreResultV2<ControllerStoreV2>> {
  let bootstrap: ControllerStoreBootstrapV2;
  let keyBytes: Buffer | null = null;
  try {
    bootstrap = validateBootstrap(bootstrapInput);
  } catch (error) {
    if (error instanceof StoreDeniedError) {
      return denied(error.code);
    }
    return denied("invalid-bootstrap");
  }
  if (productionRefusal) {
    return denied("permission-denied");
  }
  try {
    keyBytes = keyBytesFromProvider(bootstrap);
  } catch (error) {
    if (error instanceof StoreDeniedError) {
      return denied(error.code);
    }
    return denied("key-unavailable");
  }
  try {
    const storeRoot = storeRootPath(bootstrap);
    const namespaceDir = namespacePath(bootstrap);
    const runsDir = runsPath(bootstrap);
    const namespaceAlreadyExists = existsSync(namespaceDir);
    ensurePrivateDirectory(storeRoot);
    if (namespaceAlreadyExists) {
      requirePrivateDirectory(namespaceDir);
      if (!existsSync(manifestPath(bootstrap))) {
        throw new StoreIntegrityError();
      }
      readManifest(bootstrap, keyBytes);
    } else {
      ensurePrivateDirectory(namespaceDir);
      writeManifest(bootstrap, keyBytes);
      readManifest(bootstrap, keyBytes);
    }
    ensurePrivateDirectory(runsDir);
    for (const entry of readdirSync(runsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) throw new StoreIntegrityError();
      const runDir = join(runsDir, entry.name);
      requirePrivateDirectory(runDir);
      if (existsSync(headPath(runDir))) {
        readHeadEnvelope(runDir, bootstrap.keyProvider.keyId, keyBytes);
      }
      if (existsSync(operationsPath(runDir))) {
        requirePrivateDirectory(operationsPath(runDir));
        for (const opEntry of readdirSync(operationsPath(runDir), {
          withFileTypes: true,
        })) {
          if (!opEntry.isFile() || !opEntry.name.endsWith(".json")) {
            throw new StoreIntegrityError();
          }
          readAuthenticatedRecord<StoredOperationRecordBodyV2>({
            path: join(operationsPath(runDir), opEntry.name),
            recordType: "operation-record",
            keyId: bootstrap.keyProvider.keyId,
            keyBytes,
            maximumBytes: MAX_OPERATION_BYTES,
          });
        }
      }
      if (existsSync(transactionPath(runDir))) {
        requirePrivateDirectory(transactionPath(runDir));
        if (existsSync(journalPath(runDir)))
          readJournalEnvelope(runDir, bootstrap.keyProvider.keyId, keyBytes);
        if (existsSync(recordsPath(runDir)))
          readAuthenticatedRecord({
            path: recordsPath(runDir),
            recordType: "transition-record",
            keyId: bootstrap.keyProvider.keyId,
            keyBytes,
            maximumBytes: MAX_TRANSACTION_BYTES,
          });
        if (existsSync(pendingOperationPath(runDir)))
          readPendingOperationEnvelope(
            runDir,
            bootstrap.keyProvider.keyId,
            keyBytes,
          );
        if (existsSync(receiptPath(runDir)))
          readReceiptEnvelope(runDir, bootstrap.keyProvider.keyId, keyBytes);
        if (existsSync(tempHeadPath(runDir)))
          readAuthenticatedRecord({
            path: tempHeadPath(runDir),
            recordType: "head-pointer",
            keyId: bootstrap.keyProvider.keyId,
            keyBytes,
            maximumBytes: MAX_HEAD_BYTES,
          });
      }
    }
  } catch (error) {
    if (error instanceof StoreDeniedError) {
      return denied(error.code);
    }
    if (error instanceof StoreIntegrityError) {
      return denied("integrity-failure");
    }
    return denied("storage-unavailable");
  }

  let closed = false;
  let released = false;
  const releaseKey = (): void => {
    if (released) return;
    released = true;
    try {
      keyBytes?.fill(0);
    } catch {
      // Key zeroization is best-effort cleanup.
    }
    try {
      bootstrap.keyProvider.release();
    } catch {
      // Cleanup failures do not expose secret material.
    }
  };

  const inspectRunIdentity = (value: unknown): ControllerRunIdentityV2 => {
    if (!validateControllerRunIdentityV2(value)) {
      throw new StoreDeniedError("invalid-input");
    }
    const identity = value as ControllerRunIdentityV2;
    if (identity.namespaceDigest !== namespaceDigest(bootstrap)) {
      throw new StoreDeniedError("invalid-input");
    }
    return identity;
  };

  const currentRunDir = (identity: ControllerRunIdentityV2): string =>
    runPathFromIdentity(bootstrap, identity);

  const loadStatus = async (
    identityInput: unknown,
  ): Promise<ControllerStoreResultV2<LoadedControllerRunV2>> => {
    if (closed) return denied("store-closed");
    try {
      const identity = inspectRunIdentity(identityInput);
      const runPath = currentRunDir(identity);
      const state = currentRunStatusOrAbsent(
        runPath,
        storeIdentity(bootstrap),
        identity,
        bootstrap.keyProvider.keyId,
        keyBytes!,
      );
      if ("repairRequired" in state) return denied(state.code);
      if ("kind" in state) return denied("run-absent");
      return directResult({
        kind: "load",
        snapshot: state.snapshot,
        status: state.status,
      });
    } catch (error) {
      if (error instanceof StoreDeniedError) return denied(error.code);
      if (error instanceof StoreIntegrityError)
        return denied("integrity-failure");
      return denied("storage-unavailable");
    }
  };

  const inspectStatus = async (
    identityInput: unknown,
  ): Promise<ControllerStoreResultV2<ControllerStoreStatusV2>> => {
    if (closed) return denied("store-closed");
    try {
      const identity = inspectRunIdentity(identityInput);
      const runPath = currentRunDir(identity);
      const state = currentRunStatusOrAbsent(
        runPath,
        storeIdentity(bootstrap),
        identity,
        bootstrap.keyProvider.keyId,
        keyBytes!,
      );
      if ("repairRequired" in state) {
        return directResult(
          parseControllerStoreStatusV2({
            kind: "repair-required",
            identity: storeIdentity(bootstrap),
            runIdentity: identity,
            code: state.code,
          }),
        );
      }
      if ("kind" in state) {
        return directResult(
          parseControllerStoreStatusV2({
            kind: "absent",
            identity: storeIdentity(bootstrap),
            runIdentity: identity,
          }),
        );
      }
      return directResult(state.status);
    } catch (error) {
      if (error instanceof StoreDeniedError) return denied(error.code);
      if (error instanceof StoreIntegrityError)
        return denied("integrity-failure");
      return denied("storage-unavailable");
    }
  };

  const createControllerRunV2 = async (
    initialSnapshotInput: unknown,
    optionsInput: {
      readonly operationId: string;
      readonly requestDigest: DigestSha256V2;
      readonly abortSignal?: AbortSignal;
    },
  ): Promise<ControllerStoreResultV2<CreatedControllerRunV2>> => {
    if (closed) return denied("store-closed");
    try {
      optionsInput = validateOperationOptions(optionsInput);
      if (optionsInput.abortSignal?.aborted)
        return denied("abort-before-commit");
      const request = deriveControllerStoreCreationRequestV2(
        deriveControllerStoreNamespaceDigestV2(bootstrap.namespaceSeed),
        initialSnapshotInput,
        optionsInput.operationId,
      );
      if (request.canonicalRequestDigest !== optionsInput.requestDigest) {
        return denied("invalid-input");
      }
      const runPath = currentRunDir(request.identity);
      const held = acquireNamespaceLock(
        bootstrap,
        request.identity.runIdentityDigest,
        keyBytes!,
        options,
      );
      try {
        const existing = loadExistingOperationResult(
          runPath,
          storeIdentity(bootstrap),
          request.identity,
          optionsInput.operationId,
          optionsInput.requestDigest,
          bootstrap.keyProvider.keyId,
          keyBytes!,
        );
        if (existing.kind === "replay") {
          return directResult({
            ...(existing.result as CreatedControllerRunV2),
            replayed: true,
          });
        }
        if (existing.kind === "conflict") return denied("replay-conflict");
        const state = currentRunStatusOrAbsent(
          runPath,
          storeIdentity(bootstrap),
          request.identity,
          bootstrap.keyProvider.keyId,
          keyBytes!,
        );
        if ("repairRequired" in state) return denied(state.code);
        if (!("kind" in state)) return denied("run-exists");
        if (existsSync(transactionPath(runPath)))
          return denied("recovery-required");
        const currentTransaction = lockCurrentTransaction({
          kind: "create",
          operationId: optionsInput.operationId,
          requestDigest: optionsInput.requestDigest,
          runIdentityDigest: request.identity.runIdentityDigest,
          fromRevision: null,
          toRevision: 0,
        });
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        ensurePrivateDirectory(runsPath(bootstrap));
        ensurePrivateDirectory(runPath);
        const snapshot = deepFreeze(
          cloneJsonValue<ControllerSnapshotV2>(initialSnapshotInput),
        );
        const status = createStoredStatus(
          storeIdentity(bootstrap),
          request.identity,
          snapshot,
          0,
          null,
          1,
          false,
        );
        writeHeadState(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          status,
          snapshot,
        );
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        const result: CreatedControllerRunV2 = deepFreeze({
          kind: "create",
          replayed: false,
          revision: 0,
          snapshot,
          status,
        });
        writeOperationRecordFinal(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          optionsInput.operationId,
          optionsInput.requestDigest,
          result,
        );
        renewNamespaceLock(bootstrap, held, keyBytes!, null);
        return directResult(result);
      } finally {
        releaseNamespaceLock(bootstrap, held, keyBytes!);
      }
    } catch (error) {
      if (error instanceof StoreDeniedError) return denied(error.code);
      if (error instanceof StoreIntegrityError)
        return denied("integrity-failure");
      if (error instanceof StoreBootstrapValidationError)
        return denied("invalid-bootstrap");
      return denied("storage-unavailable");
    }
  };

  const commitControllerTransitionV2 = async (
    previousSnapshotInput: unknown,
    sourceCommandInput: unknown,
    proposalInput: unknown,
    optionsInput: {
      readonly operationId: string;
      readonly requestDigest: DigestSha256V2;
      readonly abortSignal?: AbortSignal;
    },
  ): Promise<ControllerStoreResultV2<CommittedControllerTransitionV2>> => {
    if (closed) return denied("store-closed");
    let linearizedResult: Readonly<CommittedControllerTransitionV2> | null =
      null;
    try {
      optionsInput = validateOperationOptions(optionsInput);
      if (optionsInput.abortSignal?.aborted)
        return denied("abort-before-commit");
      const request = deriveControllerStoreCommitRequestV2(
        deriveControllerStoreNamespaceDigestV2(bootstrap.namespaceSeed),
        previousSnapshotInput,
        sourceCommandInput,
        proposalInput,
        optionsInput.operationId,
      );
      if (request.canonicalRequestDigest !== optionsInput.requestDigest) {
        return denied("invalid-proposal");
      }
      const runPath = currentRunDir(request.identity);
      const held = acquireNamespaceLock(
        bootstrap,
        request.identity.runIdentityDigest,
        keyBytes!,
        options,
      );
      try {
        const existing = loadExistingOperationResult(
          runPath,
          storeIdentity(bootstrap),
          request.identity,
          optionsInput.operationId,
          optionsInput.requestDigest,
          bootstrap.keyProvider.keyId,
          keyBytes!,
        );
        if (existing.kind === "replay") {
          return directResult({
            ...(existing.result as CommittedControllerTransitionV2),
            replayed: true,
          });
        }
        if (existing.kind === "conflict") return denied("replay-conflict");
        const state = currentRunStatusOrAbsent(
          runPath,
          storeIdentity(bootstrap),
          request.identity,
          bootstrap.keyProvider.keyId,
          keyBytes!,
        );
        if ("repairRequired" in state) return denied(state.code);
        if ("kind" in state) return denied("run-absent");
        const current = state;
        if (
          current.status.committedRevision !== request.previousSnapshot.revision
        ) {
          return denied(
            current.status.committedRevision > request.previousSnapshot.revision
              ? "stale-revision"
              : "future-revision",
          );
        }
        if (existsSync(transactionPath(runPath))) {
          const journal = readJournalEnvelope(
            runPath,
            bootstrap.keyProvider.keyId,
            keyBytes!,
          );
          if (
            journal &&
            journal.body.operationId !== optionsInput.operationId
          ) {
            return denied("recovery-required");
          }
          if (
            journal &&
            journal.body.operationId === optionsInput.operationId
          ) {
            const pending = readPendingOperationEnvelope(
              runPath,
              bootstrap.keyProvider.keyId,
              keyBytes!,
            );
            if (
              pending &&
              pending.body.requestDigest === optionsInput.requestDigest &&
              current.status.committedRevision === journal.body.toRevision
            ) {
              ensurePrivateDirectory(operationsPath(runPath));
              writeOperationRecordFinal(
                runPath,
                bootstrap.keyProvider.keyId,
                keyBytes!,
                optionsInput.operationId,
                optionsInput.requestDigest,
                pending.body.result,
              );
              removeOperationRecordPending(runPath);
              return directResult({
                ...(pending.body.result as CommittedControllerTransitionV2),
                replayed: true,
              });
            }
            return denied("recovery-required");
          }
        }
        const operation = request;
        const currentTransaction = lockCurrentTransaction({
          kind: "commit",
          operationId: optionsInput.operationId,
          requestDigest: optionsInput.requestDigest,
          runIdentityDigest: request.identity.runIdentityDigest,
          fromRevision: request.previousSnapshot.revision,
          toRevision: request.previousSnapshot.revision + 1,
        });
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        const pendingRunPath = transactionPath(runPath);
        ensurePrivateDirectory(runsPath(bootstrap));
        ensurePrivateDirectory(runPath);
        ensurePrivateDirectory(pendingRunPath);
        const committedAt = bootstrap.clock.now();
        const receiptBase: Omit<
          CommittedControllerTransitionReceiptV2,
          "receiptDigest" | "authenticationTag"
        > = {
          contractId: "spts.controller-store-receipt.v2",
          schemaVersion: 2,
          algorithm: "hmac-sha256",
          algorithmVersion: 1,
          namespaceDigest: operation.identity.namespaceDigest,
          keyId: bootstrap.keyProvider.keyId,
          taskId: operation.identity.taskId,
          projectId: operation.identity.projectId,
          repositoryId: operation.identity.repositoryId,
          runId: operation.identity.snapshotId,
          branch: operation.identity.headBranch,
          candidateCommit: request.previousSnapshot.candidate.commit,
          candidateTree: request.previousSnapshot.candidate.tree,
          previousRevision: request.previousSnapshot.revision,
          committedRevision: request.previousSnapshot.revision + 1,
          previousSnapshotDigest: request.previousSnapshotDigest,
          transitionDigest: request.transitionDigest,
          proposalDigest: request.proposalDigest,
          orderedChangesDigest: request.orderedChangesDigest,
          orderedIntentsDigest: request.orderedIntentsDigest,
          transitionChainDigest: request.transitionChainDigest,
          committedSnapshotDigest: request.committedSnapshotDigest,
          operationIdentity: optionsInput.operationId,
          idempotencyIdentity: request.idempotencyIdentity,
          canonicalRequestDigest: optionsInput.requestDigest,
          committedAt,
          previousReceiptDigest: current.status.lastReceiptDigest,
          recordDigest: request.transitionDigest,
        };
        const receiptSeed: CommittedControllerTransitionReceiptV2 = {
          ...receiptBase,
          receiptDigest: "0".repeat(64),
          authenticationTag: "0".repeat(64),
        };
        const receiptDigest =
          computeCommittedControllerTransitionReceiptDigestV2(receiptSeed);
        const receipt: CommittedControllerTransitionReceiptV2 =
          parseCommittedControllerTransitionReceiptV2({
            ...receiptBase,
            receiptDigest,
            authenticationTag: authenticateRecord(
              bootstrap.keyProvider.keyId,
              "committed-transition-receipt",
              receiptDigest,
              keyBytes!,
            ),
          });
        const committedSnapshot = deepFreeze(
          cloneJsonValue<ControllerSnapshotV2>(request.committedSnapshot),
        );
        const status = createStoredStatus(
          storeIdentity(bootstrap),
          operation.identity,
          committedSnapshot,
          request.previousSnapshot.revision + 1,
          receipt.receiptDigest,
          current.status.operationCount + 1,
          false,
        );
        const result: CommittedControllerTransitionV2 = deepFreeze({
          kind: "commit",
          replayed: false,
          revision: request.previousSnapshot.revision + 1,
          snapshot: committedSnapshot,
          intents: deepFreeze(
            cloneJsonValue<EffectIntentV2[]>(request.intents),
          ),
          receipt,
          status,
        });
        writeTransactionJournal(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          {
            operationId: optionsInput.operationId,
            requestDigest: optionsInput.requestDigest,
            fromRevision: request.previousSnapshot.revision,
            toRevision: request.previousSnapshot.revision + 1,
            committedSnapshotDigest: request.committedSnapshotDigest,
            operationIdentity: optionsInput.operationId,
            operationIdentityDigest: request.operationIdentityDigest,
            idempotencyIdentity: request.idempotencyIdentity,
            headPublished: false,
          },
        );
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("transaction-announced");
        writeTransactionRecords(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          {
            previousSnapshotDigest: request.previousSnapshotDigest,
            sourceCommandDigest: request.sourceCommandDigest,
            transitionDigest: request.transitionDigest,
            proposalDigest: request.proposalDigest,
            committedSnapshotDigest: request.committedSnapshotDigest,
          },
        );
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("journal-prepared");
        writeTransactionReceipt(runPath, receipt);
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("records-durable");
        writeOperationRecordPending(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          optionsInput.operationId,
          optionsInput.requestDigest,
          result,
        );
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("receipt-durable");
        atomicWriteCanonicalJson(tempHeadPath(runPath), {
          contractId: RECORD_CONTRACT_ID,
          schemaVersion: RECORD_SCHEMA_VERSION,
          recordType: "head-pointer",
          keyId: bootstrap.keyProvider.keyId,
          body: {
            status: {
              kind: status.kind,
              identity: status.identity,
              runIdentity: status.runIdentity,
              committedRevision: status.committedRevision,
              snapshotDigest: status.snapshotDigest,
              lastReceiptDigest: status.lastReceiptDigest,
              operationCount: status.operationCount,
              quarantineCount: status.quarantineCount,
              cleanupRequired: false,
            },
            snapshot: committedSnapshot,
          },
          recordDigest: digestControllerStoreValueV2(RECORD_BODY_DOMAIN, {
            status: {
              kind: status.kind,
              identity: status.identity,
              runIdentity: status.runIdentity,
              committedRevision: status.committedRevision,
              snapshotDigest: status.snapshotDigest,
              lastReceiptDigest: status.lastReceiptDigest,
              operationCount: status.operationCount,
              quarantineCount: status.quarantineCount,
              cleanupRequired: false,
            },
            snapshot: committedSnapshot,
          }),
          authenticationTag: authenticateRecord(
            bootstrap.keyProvider.keyId,
            "head-pointer",
            digestControllerStoreValueV2(RECORD_BODY_DOMAIN, {
              status: {
                kind: status.kind,
                identity: status.identity,
                runIdentity: status.runIdentity,
                committedRevision: status.committedRevision,
                snapshotDigest: status.snapshotDigest,
                lastReceiptDigest: status.lastReceiptDigest,
                operationCount: status.operationCount,
                quarantineCount: status.quarantineCount,
                cleanupRequired: false,
              },
              snapshot: committedSnapshot,
            }),
            keyBytes!,
          ),
        });
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("operation-durable");
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("head-prepared");
        renameSync(tempHeadPath(runPath), headPath(runPath));
        syncDirectory(runPath);
        linearizedResult = result;
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("head-published");
        writeOperationRecordFinal(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          optionsInput.operationId,
          optionsInput.requestDigest,
          result,
        );
        renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
        options?.fault?.("head-durable");
        cleanupPendingTransaction(runPath);
        renewNamespaceLock(bootstrap, held, keyBytes!, null);
        options?.fault?.("journal-committed");
        return directResult(result);
      } finally {
        releaseNamespaceLock(bootstrap, held, keyBytes!);
      }
    } catch (error) {
      if (linearizedResult) return directResult(linearizedResult);
      if (error instanceof StoreDeniedError) return denied(error.code);
      if (error instanceof StoreIntegrityError)
        return denied("integrity-failure");
      if (error instanceof StoreBootstrapValidationError)
        return denied("invalid-bootstrap");
      return denied("storage-unavailable");
    }
  };

  const recoverControllerRunV2 = async (
    identityInput: unknown,
    optionsInput: {
      readonly operationId: string;
      readonly abortSignal?: AbortSignal;
    },
  ): Promise<ControllerStoreResultV2<RecoveredControllerRunV2>> => {
    if (closed) return denied("store-closed");
    try {
      optionsInput = validateRecoveryOptions(optionsInput);
      if (optionsInput.abortSignal?.aborted)
        return denied("abort-before-commit");
      const identity = inspectRunIdentity(identityInput);
      const runPath = currentRunDir(identity);
      const held = acquireNamespaceLock(
        bootstrap,
        identity.runIdentityDigest,
        keyBytes!,
        options,
      );
      try {
        if (!existsSync(runPath)) return denied("run-absent");
        requirePrivateDirectory(runPath);
        const state = currentRunStatusOrAbsent(
          runPath,
          storeIdentity(bootstrap),
          identity,
          bootstrap.keyProvider.keyId,
          keyBytes!,
        );
        if ("repairRequired" in state) return denied(state.code);
        if ("kind" in state) return denied("run-absent");
        if (!existsSync(transactionPath(runPath))) {
          return directResult({
            kind: "recovery",
            outcome: "ready",
            status: state.status,
          });
        }
        const journal = readJournalEnvelope(
          runPath,
          bootstrap.keyProvider.keyId,
          keyBytes!,
        );
        if (!journal) return denied("recovery-required");
        if (!validateJournalBody(journal.body, identity)) {
          throw new StoreIntegrityError();
        }
        const operationEvidence = readTransactionOperationEvidence(
          runPath,
          storeIdentity(bootstrap),
          identity,
          bootstrap.keyProvider.keyId,
          keyBytes!,
          journal.body,
        );
        const currentTransaction = lockCurrentTransaction({
          kind: "recover",
          operationId: optionsInput.operationId,
          requestDigest: null,
          runIdentityDigest: identity.runIdentityDigest,
          fromRevision: journal.body.fromRevision,
          toRevision: journal.body.toRevision,
        });
        if (state.status.committedRevision === journal.body.toRevision) {
          if (!operationEvidence.pending && !operationEvidence.final) {
            throw new StoreIntegrityError();
          }
          renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
          if (operationEvidence.pending && !operationEvidence.final) {
            writeOperationRecordFinal(
              runPath,
              bootstrap.keyProvider.keyId,
              keyBytes!,
              journal.body.operationId,
              journal.body.requestDigest,
              operationEvidence.pending.result,
            );
          }
          renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
          cleanupPendingTransaction(runPath);
          renewNamespaceLock(bootstrap, held, keyBytes!, null);
          return directResult({
            kind: "recovery",
            outcome: "new-head-preserved",
            status: state.status,
          });
        }
        if (state.status.committedRevision === journal.body.fromRevision) {
          if (operationEvidence.final) throw new StoreIntegrityError();
          renewNamespaceLock(bootstrap, held, keyBytes!, currentTransaction);
          cleanupPendingTransaction(runPath);
          renewNamespaceLock(bootstrap, held, keyBytes!, null);
          return directResult({
            kind: "recovery",
            outcome: "old-head-restored",
            status: state.status,
          });
        }
        return denied("recovery-required");
      } finally {
        releaseNamespaceLock(bootstrap, held, keyBytes!);
      }
    } catch (error) {
      if (error instanceof StoreDeniedError) return denied(error.code);
      if (error instanceof StoreIntegrityError)
        return denied("integrity-failure");
      return denied("storage-unavailable");
    }
  };

  const closeControllerStoreV2 = async (): Promise<
    ControllerStoreResultV2<ClosedControllerStoreV2>
  > => {
    if (closed) return directResult({ kind: "closed" });
    closed = true;
    releaseKey();
    return directResult({ kind: "closed" });
  };

  const store: ControllerStoreV2 = Object.freeze({
    createControllerRunV2,
    loadControllerRunV2: loadStatus as ControllerStoreV2["loadControllerRunV2"],
    inspectControllerRunV2:
      inspectStatus as ControllerStoreV2["inspectControllerRunV2"],
    commitControllerTransitionV2,
    recoverControllerRunV2,
    closeControllerStoreV2,
  });
  return directResult(store);
}

export async function openControllerStoreV2(
  bootstrapInput: unknown,
): Promise<ControllerStoreResultV2<ControllerStoreV2>> {
  try {
    validateBootstrap(bootstrapInput);
  } catch (error) {
    if (error instanceof StoreDeniedError) return denied(error.code);
    return denied("invalid-bootstrap");
  }
  return denied("permission-denied");
}

export async function openControllerStoreV2ForTesting(
  bootstrapInput: unknown,
  options?: ControllerStoreTestingOptionsV2,
): Promise<ControllerStoreResultV2<ControllerStoreV2>> {
  return openStoreInternal(bootstrapInput, options, false);
}

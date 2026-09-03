import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  dirname,
  isAbsolute,
  join,
  normalize,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";

import {
  CLEAN_REPOSITORY_DIGESTS_V1,
  FIXTURE_DIAGNOSTIC_MESSAGES_V1,
  canonicalizeGitCheckFixtureValueV1,
  computeFixtureRepositoryObservationDigestV1,
  computeFixtureRepositoryRequestDigestV1,
  computeGitCheckFixtureDigestV1,
  computeNamedCheckRequestDigestV1,
  containsCredentialShapedContent,
  createFixtureDiagnosticV1,
  type FixtureDiagnosticCodeV1,
  type FixtureRepositoryObservationV1,
  type NamedCheckResultV1,
  type RepositoryStateV1,
  type ValidationResult,
} from "@scrum-pi-team-skills/contracts";
import {
  cancelNamedCheckPermitV1,
  createNamedCheckAuthorityV1,
  issueNamedCheckPermitV1 as issueRuntimeNamedCheckPermitV1,
  runExactNamedCheckV1,
  type IssueNamedCheckPermitV1Options,
  type NamedCheckAuthorityV1,
  type NamedCheckPermitV1,
  type NamedCheckRepositoryObservationV1,
} from "@scrum-pi-team-skills/runtime";

import {
  createRegistrationRecordV1,
  digestRelativePathV1,
  registrationDigestV1,
  snapshotFixtureFilesV1,
  type CreateBareRemoteRequestV1,
  type CreateRepositoryRequestV1,
  type FixtureFileV1,
  type FixtureRootIdentityProofV1,
  type FixtureWorktreeRoleV1,
  type RegisterWorktreeRequestV1,
} from "./worktrees.js";

export interface TrustedNamedCheckPolicyEntryV1 {
  readonly checkId: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly maxDurationMs: number;
  readonly maxOutputBytes: number;
}

export interface FixtureLimitsV1 {
  readonly maxRootPathBytes: number;
  readonly maxComponentBytes: number;
  readonly maxContainmentDepth: number;
  readonly maxArgvCount: number;
  readonly maxArgvEntryBytes: number;
  readonly maxArgvBytes: number;
  readonly maxEnvironmentEntries: number;
  readonly maxEnvironmentEntryBytes: number;
  readonly maxEnvironmentBytes: number;
  readonly maxFixtureFiles: number;
  readonly maxFixtureFileBytes: number;
  readonly maxFixtureBytes: number;
  readonly maxGitObjects: number;
  readonly maxGitObjectBytes: number;
  readonly maxActiveWorktrees: number;
  readonly maxObservedWorktrees: number;
  readonly maxOperations: number;
  readonly maxNamedChecks: number;
  readonly maxAttempts: number;
  readonly maxOutputBytesPerStream: number;
  readonly maxCombinedOutputBytes: number;
  readonly maxDurationMs: number;
  readonly terminationGraceMs: number;
  readonly killConfirmationMs: number;
  readonly processPollMs: number;
  readonly maxCleanupEntries: number;
  readonly maxCleanupBytes: number;
  readonly maxRecoveryRecords: number;
  readonly maxRecoveryBytes: number;
  readonly maxInputDepth: number;
  readonly maxInputNodes: number;
  readonly maxInputObjectKeys: number;
  readonly maxInputArrayEntries: number;
  readonly maxInputStringBytes: number;
}

export interface TrustedFixtureGitPolicyV1Definition {
  readonly policyId: string;
  readonly trustedParent: string;
  readonly gitExecutable: string;
  readonly gitExecPath: string;
  readonly namedChecks: readonly TrustedNamedCheckPolicyEntryV1[];
  readonly limits: FixtureLimitsV1;
}

export interface TrustedFixtureGitPolicyV1 {
  readonly policyId: string;
  readonly limits: Readonly<FixtureLimitsV1>;
  readonly namedChecks: readonly Readonly<
    Pick<
      TrustedNamedCheckPolicyEntryV1,
      "checkId" | "maxDurationMs" | "maxOutputBytes"
    >
  >[];
  revoke(): Promise<void>;
}

export interface CreateFixtureRepositoryHarnessV1Options {
  readonly runId: string;
  readonly taskId: string;
  readonly expectedBaseCommit: string;
  readonly expectedBaseTree: string;
}

export interface IssueHarnessNamedCheckPermitV1Input {
  readonly operationId: string;
  readonly registrationId: string;
  readonly checkId: string;
  readonly attempt: number;
}

export interface RunNamedCheckRequestV1 extends IssueHarnessNamedCheckPermitV1Input {
  readonly signal?: AbortSignal;
}

export interface FixtureRepositoryHarnessV1 {
  readonly runId: string;
  readonly taskId: string;
  readonly expectedBaseCommit: string;
  readonly expectedBaseTree: string;
  readonly policyId: string;
  createRepository(
    request: CreateRepositoryRequestV1,
  ): Promise<FixtureRepositoryObservationV1>;
  createBareRemote(
    request: CreateBareRemoteRequestV1,
  ): Promise<FixtureRepositoryObservationV1>;
  createWorktree(
    request: RegisterWorktreeRequestV1,
  ): Promise<FixtureRepositoryObservationV1>;
  inspectWorktrees(
    operationId: string,
  ): Promise<FixtureRepositoryObservationV1>;
  removeWorktree(
    operationId: string,
    registrationId: string,
  ): Promise<FixtureRepositoryObservationV1>;
  issueNamedCheckPermitV1(
    request: IssueHarnessNamedCheckPermitV1Input,
  ): Promise<NamedCheckPermitV1>;
  runNamedCheckV1(
    request: RunNamedCheckRequestV1,
  ): Promise<ValidationResult<NamedCheckResultV1>>;
  cancel(): Promise<void>;
  close(): Promise<void>;
  cleanup(): Promise<void>;
}

type OperationKindV1 =
  | "create-repository"
  | "create-bare-remote"
  | "create-worktree"
  | "inspect-worktrees"
  | "remove-worktree"
  | "named-check";

type OperationStageV1 =
  "prepared" | "effect-started" | "effect-observed" | "completed";

type OperationTerminalStateV1 =
  | "pending"
  | "applied"
  | "already-applied"
  | "not-applied"
  | "blocked"
  | "outcome-unknown";

interface FileIdentityV1 {
  readonly path: string;
  readonly realpath: string;
  readonly device: number;
  readonly inode: number;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
  readonly sha256: string;
}

interface DirectoryIdentityV1 {
  readonly path: string;
  readonly realpath: string;
  readonly device: number;
  readonly inode: number;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
  readonly nlink: number;
  readonly mountDigest: string;
}

interface GitProcessResultV1 {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

interface RegistrationStateV1 {
  readonly registrationId: string;
  readonly registrationDigest: string;
  readonly role: FixtureWorktreeRoleV1 | "fixture-remote";
  readonly checkId: string | null;
  readonly sourceRegistrationId: string | null;
  readonly path: string;
  readonly commonDirectory: string;
  readonly adminDirectory: string;
  readonly commonDirectoryDigest: string;
  readonly rootIdentity: FixtureRootIdentityProofV1;
  readonly sourceCommonDirectoryDigest: string | null;
  readonly commonConfigDigest: string;
  candidateCommit: string | null;
  candidateTree: string | null;
  state: "active" | "cleanup-pending" | "retained" | "removed";
  generation: number;
  cleanupBlockedReason: "workspace-mutated" | "outcome-unknown" | null;
}

interface RootManifestV1 {
  readonly contract: "spts.fixture-root-manifest";
  readonly version: "1.0.0";
  readonly policyId: string;
  readonly runId: string;
  readonly taskId: string;
  readonly expectedBaseCommit: string;
  readonly expectedBaseTree: string;
  readonly runDigest: string;
  readonly parentDigest: string;
  readonly rootDigest: string;
  readonly limitsDigest: string;
  readonly manifestDigest: string;
}

interface OperationStageRecordV1 {
  readonly contract: "spts.fixture-operation-record";
  readonly version: "1.0.0";
  readonly runDigest: string;
  readonly manifestDigest: string;
  readonly operationId: string;
  readonly operationDigest: string;
  readonly sequence: number;
  readonly stage: OperationStageV1;
  readonly kind: OperationKindV1;
  readonly registrationId: string;
  readonly registrationDigest: string;
  readonly requestDigest: string;
  readonly request: unknown;
  readonly priorRecordDigest: string | null;
  readonly terminalState: OperationTerminalStateV1;
  readonly resultDigest: string | null;
  readonly result: unknown | null;
  readonly recordDigest: string;
}

interface RepositoryFixtureProjectionFileV1 {
  readonly pathComponents: readonly string[];
  readonly pathDigest: string;
  readonly mode: FixtureFileV1["mode"];
  readonly contentDigest: string;
}

interface CreateRepositoryOperationRequestV1 {
  readonly registrationId: string;
  readonly files: readonly RepositoryFixtureProjectionFileV1[];
  readonly expectedConfigDigest: string;
  readonly expectedObjectFormat: "sha256";
  readonly expectedBranch: "fixture-main";
}

interface BareRemoteRefEntryV1 {
  readonly refname: string;
  readonly objectId: string;
}

interface WorktreePorcelainEntryV1 {
  readonly pathDigest: string;
  readonly head: string;
  readonly branch?: string;
  readonly detached?: true;
}

interface WorktreeAdminRegistrationEntryV1 {
  readonly registrationDigest: string;
  readonly pathDigest: string;
}

interface CreateBareRemoteOperationRequestV1 {
  readonly registrationId: string;
  readonly sourceRegistrationId: string;
  readonly expectedConfigDigest: string;
  readonly expectedObjectFormat: "sha256";
  readonly expectedBranch: "fixture-main";
  readonly expectedHeadRef: "refs/heads/fixture-main";
  readonly expectedRefs: readonly BareRemoteRefEntryV1[];
  readonly expectedRefSetDigest: string;
  readonly expectedCommit: string;
  readonly expectedTree: string;
  readonly expectedSourceCommonDirectoryDigest: string;
}

interface CreateWorktreeOperationRequestV1 {
  readonly registrationId: string;
  readonly sourceRegistrationId: string;
  readonly role: FixtureWorktreeRoleV1;
  readonly checkId: string | null;
  readonly candidateCommit: string;
  readonly candidateTree: string;
  readonly expectedConfigDigest: string;
  readonly expectedObjectFormat: "sha256";
  readonly expectedDetached: true;
  readonly expectedCommonDirectoryDigest: string;
  readonly expectedWorktreeSet: readonly WorktreePorcelainEntryV1[];
  readonly expectedWorktreeSetDigest: string;
  readonly expectedAdminRegistrationSet: readonly WorktreeAdminRegistrationEntryV1[];
  readonly expectedAdminRegistrationSetDigest: string;
}

interface RemoveWorktreeOperationRequestV1 {
  readonly registrationId: string;
  readonly sourceRegistrationId: string;
  readonly role: Exclude<FixtureWorktreeRoleV1, "principal-candidate">;
  readonly checkId: string | null;
  readonly candidateCommit: string;
  readonly candidateTree: string;
  readonly expectedConfigDigest: string;
  readonly expectedObjectFormat: "sha256";
  readonly expectedDetached: true;
  readonly expectedCommonDirectoryDigest: string;
}

interface OperationStateV1 {
  readonly operationId: string;
  readonly kind: OperationKindV1;
  readonly requestDigest: string;
  readonly latestStage: OperationStageV1;
  readonly latestSequence: number;
  readonly latestRecordDigest: string;
  readonly request: unknown;
  readonly registrationId: string;
  readonly registrationDigest: string;
  readonly completed: boolean;
  readonly result: unknown | null;
}

interface PolicyStateV1 {
  readonly publicPolicy: TrustedFixtureGitPolicyV1;
  readonly parentIdentity: DirectoryIdentityV1;
  readonly gitExecutableIdentity: FileIdentityV1;
  readonly gitExecPathIdentity: DirectoryIdentityV1;
  readonly namedChecks: readonly TrustedNamedCheckPolicyEntryV1[];
  readonly limits: Readonly<FixtureLimitsV1>;
  readonly authority: NamedCheckAuthorityV1;
  revoked: boolean;
  readonly harnesses: Set<FixtureRepositoryHarnessV1>;
}

interface ActiveNamedCheckExecutionV1 {
  readonly operationId: string;
  readonly registrationId: string;
  readonly controller: AbortController;
  readonly promise: Promise<ValidationResult<NamedCheckResultV1>>;
}

interface HarnessStateV1 {
  readonly policyState: PolicyStateV1;
  readonly runId: string;
  readonly taskId: string;
  readonly expectedBaseCommit: string;
  readonly expectedBaseTree: string;
  readonly runDigest: string;
  readonly rootPath: string;
  readonly rootIdentity: DirectoryIdentityV1;
  manifest: RootManifestV1;
  readonly directories: {
    readonly home: string;
    readonly hooksDisabled: string;
    readonly repositories: string;
    readonly remotes: string;
    readonly worktrees: string;
    readonly metadata: string;
    readonly transactions: string;
    readonly quarantine: string;
    readonly operations: string;
    readonly registrations: string;
  };
  readonly operations: Map<string, OperationStateV1>;
  readonly operationsByRegistration: Map<string, Set<string>>;
  readonly registrations: Map<string, RegistrationStateV1>;
  readonly issuedPermits: Set<NamedCheckPermitV1>;
  readonly activeNamedChecks: Map<string, ActiveNamedCheckExecutionV1>;
  faultPoint: string | null;
  status:
    | "active"
    | "cancelling"
    | "cancelled"
    | "closing"
    | "closed"
    | "recovery-required"
    | "removed";
}

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const VERSION_PATTERN = /^git version (\d+)\.(\d+)\.(\d+)/;
const ROOT_DIR_NAMES = Object.freeze([
  "home",
  "hooks-disabled",
  "repositories",
  "remotes",
  "worktrees",
  "metadata",
  "transactions",
  "quarantine",
] as const);
const ROOT_MANIFEST_FILE = "root-manifest.json";
const HARD_LIMITS_V1: Readonly<FixtureLimitsV1> = Object.freeze({
  maxRootPathBytes: 4096,
  maxComponentBytes: 255,
  maxContainmentDepth: 16,
  maxArgvCount: 32,
  maxArgvEntryBytes: 1024,
  maxArgvBytes: 8192,
  maxEnvironmentEntries: 16,
  maxEnvironmentEntryBytes: 1024,
  maxEnvironmentBytes: 4096,
  maxFixtureFiles: 256,
  maxFixtureFileBytes: 1024 * 1024,
  maxFixtureBytes: 8 * 1024 * 1024,
  maxGitObjects: 4096,
  maxGitObjectBytes: 32 * 1024 * 1024,
  maxActiveWorktrees: 32,
  maxObservedWorktrees: 128,
  maxOperations: 10_000,
  maxNamedChecks: 256,
  maxAttempts: 32,
  maxOutputBytesPerStream: 1024 * 1024,
  maxCombinedOutputBytes: 2 * 1024 * 1024,
  maxDurationMs: 15 * 60 * 1000,
  terminationGraceMs: 5_000,
  killConfirmationMs: 5_000,
  processPollMs: 50,
  maxCleanupEntries: 4096,
  maxCleanupBytes: 64 * 1024 * 1024,
  maxRecoveryRecords: 10_000,
  maxRecoveryBytes: 16 * 1024 * 1024,
  maxInputDepth: 16,
  maxInputNodes: 2048,
  maxInputObjectKeys: 256,
  maxInputArrayEntries: 256,
  maxInputStringBytes: 1024 * 1024,
});

const POLICY_STATE = new WeakMap<object, PolicyStateV1>();
const HARNESS_STATE = new WeakMap<object, HarnessStateV1>();

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function validateSafeId(label: string, value: unknown): string {
  if (
    typeof value !== "string" ||
    !SAFE_ID_PATTERN.test(value) ||
    utf8Bytes(value) > 128 ||
    containsCredentialShapedContent(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateObjectId(label: string, value: unknown): string {
  if (typeof value !== "string" || !OBJECT_ID_PATTERN.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateAbsoluteDirectory(label: string, value: unknown): string {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    containsCredentialShapedContent(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function containsPath(left: string, right: string): boolean {
  const relation = relative(left, right);
  return (
    relation === "" || (!relation.startsWith(`..${sep}`) && relation !== "..")
  );
}

function noFollowFlag(): number {
  return typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
}

function openPrivateDirectory(path: string): number {
  return openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | noFollowFlag(),
  );
}

function syncDirectory(path: string): void {
  const descriptor = openPrivateDirectory(path);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function writeAllBytes(descriptor: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const written = writeSync(
      descriptor,
      bytes,
      offset,
      bytes.byteLength - offset,
      null,
    );
    if (!Number.isSafeInteger(written) || written <= 0) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["storage-unavailable"],
      );
    }
    offset += written;
  }
}

function writeCanonicalFileImmutable(path: string, value: unknown): void {
  const serialized = canonicalizeGitCheckFixtureValueV1(value);
  const bytes = Buffer.from(serialized, "utf8");
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(),
    0o600,
  );
  try {
    writeAllBytes(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  syncDirectory(parent);
}

function writeCanonicalFileMutable(path: string, value: unknown): void {
  const serialized = canonicalizeGitCheckFixtureValueV1(value);
  const bytes = Buffer.from(serialized, "utf8");
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const tempPath = `${path}.tmp-${randomBytes(8).toString("hex")}`;
  const descriptor = openSync(
    tempPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(),
    0o600,
  );
  try {
    writeAllBytes(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(tempPath, path);
  syncDirectory(parent);
}

function readCanonicalJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function walkWithoutSymlinks(path: string): void {
  const normalized = normalize(path);
  const root = parse(normalized).root;
  let current = root;
  for (const segment of normalized
    .slice(root.length)
    .split(sep)
    .filter(Boolean)) {
    current = join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw new TypeError("trusted root is invalid");
  }
}

function decodeMountInfoField(value: string): string {
  return value.replace(/\\([0-7]{3})/gu, (_match, octal) =>
    String.fromCharCode(Number.parseInt(octal, 8)),
  );
}

function mountPointContainsPath(mountPoint: string, path: string): boolean {
  return mountPoint === "/"
    ? path.startsWith("/")
    : path === mountPoint || path.startsWith(`${mountPoint}/`);
}

function mountDigestForPath(path: string): string {
  const realpath = realpathSync(path);
  const mountinfo = readFileSync("/proc/self/mountinfo", "utf8");
  let bestMatch: {
    readonly mountPoint: string;
    readonly digest: string;
  } | null = null;
  for (const line of mountinfo.split("\n")) {
    if (line.length === 0) continue;
    const separator = line.indexOf(" - ");
    if (separator === -1) continue;
    const leftFields = line.slice(0, separator).split(" ");
    const rightFields = line.slice(separator + 3).split(" ");
    if (leftFields.length < 5 || rightFields.length < 2) continue;
    const mountPoint = decodeMountInfoField(leftFields[4]!);
    if (!mountPointContainsPath(mountPoint, realpath)) continue;
    const digest = computeGitCheckFixtureDigestV1(
      "spts.fixture-common-directory/1.0.0",
      {
        mountId: leftFields[0],
        parentMountId: leftFields[1],
        mountDevice: leftFields[2],
        root: decodeMountInfoField(leftFields[3]!),
        mountPoint,
        filesystemType: rightFields[0],
        source: decodeMountInfoField(rightFields[1]!),
      },
    );
    if (bestMatch === null || mountPoint.length > bestMatch.mountPoint.length) {
      bestMatch = { mountPoint, digest };
    }
  }
  if (bestMatch === null) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
  return bestMatch.digest;
}

function snapshotDirectoryIdentity(path: string): DirectoryIdentityV1 {
  walkWithoutSymlinks(path);
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    !isAbsolute(path) ||
    (stat.mode & 0o022) !== 0
  ) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
  return Object.freeze({
    path,
    realpath: realpathSync(path),
    device: stat.dev,
    inode: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode,
    nlink: stat.nlink,
    mountDigest: mountDigestForPath(path),
  });
}

function snapshotFileIdentity(path: string): FileIdentityV1 {
  walkWithoutSymlinks(dirname(path));
  const stat = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    !isAbsolute(path) ||
    (stat.mode & 0o022) !== 0
  ) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
  return Object.freeze({
    path,
    realpath: realpathSync(path),
    device: stat.dev,
    inode: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
    sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
  });
}

function sameDirectoryIdentity(
  left: DirectoryIdentityV1,
  right: DirectoryIdentityV1,
): boolean {
  return (
    left.realpath === right.realpath &&
    left.device === right.device &&
    left.inode === right.inode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.mode === right.mode &&
    left.mountDigest === right.mountDigest
  );
}

function sameFileIdentity(
  left: FileIdentityV1,
  right: FileIdentityV1,
): boolean {
  return (
    left.realpath === right.realpath &&
    left.device === right.device &&
    left.inode === right.inode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.sha256 === right.sha256
  );
}

function validateLimits(limits: FixtureLimitsV1): Readonly<FixtureLimitsV1> {
  const keys = Object.keys(HARD_LIMITS_V1) as (keyof FixtureLimitsV1)[];
  if (
    Object.keys(limits).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(limits, key))
  ) {
    throw new TypeError("fixture limits are invalid");
  }
  const snapshot = Object.create(null) as Record<keyof FixtureLimitsV1, number>;
  for (const key of keys) {
    const value = limits[key];
    if (
      !Number.isSafeInteger(value) ||
      value <= 0 ||
      value > HARD_LIMITS_V1[key]
    ) {
      throw new TypeError("fixture limits are invalid");
    }
    snapshot[key] = value;
  }
  return Object.freeze(snapshot as FixtureLimitsV1);
}

function validateNamedCheckEntry(
  entry: TrustedNamedCheckPolicyEntryV1,
  limits: FixtureLimitsV1,
): TrustedNamedCheckPolicyEntryV1 {
  validateSafeId("checkId", entry.checkId);
  if (typeof entry.executable !== "string" || !isAbsolute(entry.executable)) {
    throw new TypeError("named check executable is invalid");
  }
  if (!Array.isArray(entry.argv) || entry.argv.length > limits.maxArgvCount) {
    throw new TypeError("named check argv is invalid");
  }
  let argvBytes = utf8Bytes(entry.executable);
  for (const arg of entry.argv) {
    if (
      typeof arg !== "string" ||
      utf8Bytes(arg) > limits.maxArgvEntryBytes ||
      hasControlCharacter(arg) ||
      arg.startsWith("@") ||
      /[`$;&|<>]/.test(arg) ||
      arg.includes("$(")
    ) {
      throw new TypeError("named check argv is invalid");
    }
    argvBytes += utf8Bytes(arg);
  }
  if (argvBytes > limits.maxArgvBytes) {
    throw new TypeError("named check argv is invalid");
  }
  if (
    !Number.isSafeInteger(entry.maxDurationMs) ||
    entry.maxDurationMs <= 0 ||
    entry.maxDurationMs > limits.maxDurationMs ||
    !Number.isSafeInteger(entry.maxOutputBytes) ||
    entry.maxOutputBytes <= 0 ||
    entry.maxOutputBytes > limits.maxOutputBytesPerStream
  ) {
    throw new TypeError("named check limits are invalid");
  }
  snapshotFileIdentity(entry.executable);
  return Object.freeze({
    checkId: entry.checkId,
    executable: entry.executable,
    argv: Object.freeze([...entry.argv]),
    maxDurationMs: entry.maxDurationMs,
    maxOutputBytes: entry.maxOutputBytes,
  });
}

function requirePolicyState(policy: unknown): PolicyStateV1 {
  if (typeof policy !== "object" || policy === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  const state = POLICY_STATE.get(policy);
  if (!state) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  return state;
}

function requireHarnessState(harness: unknown): HarnessStateV1 {
  if (typeof harness !== "object" || harness === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  const state = HARNESS_STATE.get(harness);
  if (!state) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  return state;
}

function revalidateTrustedPolicyState(state: PolicyStateV1): void {
  if (state.revoked) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  const parent = snapshotDirectoryIdentity(state.parentIdentity.path);
  const gitExecutable = snapshotFileIdentity(state.gitExecutableIdentity.path);
  const gitExecPath = snapshotDirectoryIdentity(state.gitExecPathIdentity.path);
  if (
    !sameDirectoryIdentity(state.parentIdentity, parent) ||
    !sameFileIdentity(state.gitExecutableIdentity, gitExecutable) ||
    !sameDirectoryIdentity(state.gitExecPathIdentity, gitExecPath)
  ) {
    state.revoked = true;
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
}

function ensureHarnessState(state: HarnessStateV1, allowClosed = false): void {
  revalidateTrustedPolicyState(state.policyState);
  const root = snapshotDirectoryIdentity(state.rootPath);
  if (!sameDirectoryIdentity(state.rootIdentity, root)) {
    state.status = "recovery-required";
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
  if (!allowClosed && state.status !== "active") {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
}

function operationDigest(runDigest: string, operationId: string): string {
  return computeGitCheckFixtureDigestV1("spts.fixture-operation-record/1.0.0", {
    runDigest,
    operationId,
  });
}

function registrationPathDigest(registrationDigest: string): string {
  return digestRelativePathV1([registrationDigest]);
}

function relativePathComponentsFromRoot(
  state: HarnessStateV1,
  path: string,
): readonly string[] {
  if (!containsPath(state.rootPath, path)) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  const relativePath = relative(state.rootPath, path);
  const components = relativePath.split(sep).filter(Boolean);
  if (components.length === 0) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return Object.freeze(components);
}

function snapshotTargetRootIdentity(
  state: HarnessStateV1,
  path: string,
): FixtureRootIdentityProofV1 {
  const identity = snapshotDirectoryIdentity(path);
  return Object.freeze({
    pathDigest: digestRelativePathV1(
      relativePathComponentsFromRoot(state, path),
    ),
    device: identity.device,
    inode: identity.inode,
    uid: identity.uid,
    gid: identity.gid,
    mode: identity.mode,
    nlink: identity.nlink,
    mountDigest: identity.mountDigest,
  });
}

function sameTargetRootIdentity(
  left: FixtureRootIdentityProofV1,
  right: FixtureRootIdentityProofV1,
): boolean {
  return (
    left.pathDigest === right.pathDigest &&
    left.device === right.device &&
    left.inode === right.inode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.mountDigest === right.mountDigest
  );
}

function registrationRootIdentityMatches(
  state: HarnessStateV1,
  registration: RegistrationStateV1,
): boolean {
  try {
    return sameTargetRootIdentity(
      registration.rootIdentity,
      snapshotTargetRootIdentity(state, registration.path),
    );
  } catch {
    return false;
  }
}

function readStoredTargetRootIdentity(
  value: unknown,
): FixtureRootIdentityProofV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw recoveryIntegrityError();
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.pathDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(record.pathDigest) ||
    !Number.isSafeInteger(record.device) ||
    !Number.isSafeInteger(record.inode) ||
    !Number.isSafeInteger(record.uid) ||
    !Number.isSafeInteger(record.gid) ||
    !Number.isSafeInteger(record.mode) ||
    !Number.isSafeInteger(record.nlink) ||
    typeof record.mountDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(record.mountDigest)
  ) {
    throw recoveryIntegrityError();
  }
  return Object.freeze({
    pathDigest: record.pathDigest,
    device: record.device as number,
    inode: record.inode as number,
    uid: record.uid as number,
    gid: record.gid as number,
    mode: record.mode as number,
    nlink: record.nlink as number,
    mountDigest: record.mountDigest,
  });
}

function directoryDigest(identity: DirectoryIdentityV1): string {
  return computeGitCheckFixtureDigestV1("spts.fixture-common-directory/1.0.0", {
    realpath: identity.realpath,
    device: identity.device,
    inode: identity.inode,
    uid: identity.uid,
    gid: identity.gid,
    mode: identity.mode,
    mountDigest: identity.mountDigest,
  });
}

function rootDigest(identity: DirectoryIdentityV1, runDigest: string): string {
  return computeGitCheckFixtureDigestV1("spts.fixture-common-directory/1.0.0", {
    realpath: identity.realpath,
    device: identity.device,
    inode: identity.inode,
    uid: identity.uid,
    gid: identity.gid,
    mode: identity.mode,
    nlink: identity.nlink,
    mountDigest: identity.mountDigest,
    runDigest,
  });
}

function createRootManifest(state: HarnessStateV1): RootManifestV1 {
  const unsigned = {
    contract: "spts.fixture-root-manifest" as const,
    version: "1.0.0" as const,
    policyId: state.policyState.publicPolicy.policyId,
    runId: state.runId,
    taskId: state.taskId,
    expectedBaseCommit: state.expectedBaseCommit,
    expectedBaseTree: state.expectedBaseTree,
    runDigest: state.runDigest,
    parentDigest: directoryDigest(state.policyState.parentIdentity),
    rootDigest: rootDigest(state.rootIdentity, state.runDigest),
    limitsDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-operation-record/1.0.0",
      state.policyState.limits,
    ),
  };
  return Object.freeze({
    ...unsigned,
    manifestDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-operation-record/1.0.0",
      unsigned,
    ),
  });
}

function buildRunDirectories(rootPath: string): HarnessStateV1["directories"] {
  return {
    home: join(rootPath, "home"),
    hooksDisabled: join(rootPath, "hooks-disabled"),
    repositories: join(rootPath, "repositories"),
    remotes: join(rootPath, "remotes"),
    worktrees: join(rootPath, "worktrees"),
    metadata: join(rootPath, "metadata"),
    transactions: join(rootPath, "transactions"),
    quarantine: join(rootPath, "quarantine"),
    operations: join(rootPath, "metadata", "operations"),
    registrations: join(rootPath, "metadata", "registrations"),
  };
}

function createRunDirectories(rootPath: string): HarnessStateV1["directories"] {
  const directories = buildRunDirectories(rootPath);
  for (const directory of ROOT_DIR_NAMES) {
    mkdirSync(join(rootPath, directory), { recursive: true, mode: 0o700 });
  }
  mkdirSync(directories.operations, { recursive: true, mode: 0o700 });
  mkdirSync(directories.registrations, { recursive: true, mode: 0o700 });
  return directories;
}

function deriveRunDigest(
  policyId: string,
  options: CreateFixtureRepositoryHarnessV1Options,
): string {
  return computeGitCheckFixtureDigestV1("spts.fixture-run/1.0.0", {
    policyId,
    runId: options.runId,
    taskId: options.taskId,
    expectedBaseCommit: options.expectedBaseCommit,
    expectedBaseTree: options.expectedBaseTree,
  });
}

function recoveryIntegrityError(): TypeError {
  return new TypeError(
    "fixture recovery requires intact immutable ledger evidence",
  );
}

function assertExactEntrySet(
  directoryPath: string,
  expected: Readonly<Record<string, "file" | "directory">>,
): void {
  const entries = readdirSync(directoryPath, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  const expectedNames = Object.keys(expected).sort((left, right) =>
    left.localeCompare(right),
  );
  if (entries.length !== expectedNames.length) throw recoveryIntegrityError();
  for (const entry of entries) {
    const expectedType = expected[entry.name];
    if (!expectedType) throw recoveryIntegrityError();
    const stat = lstatSync(join(directoryPath, entry.name));
    if (stat.isSymbolicLink()) throw recoveryIntegrityError();
    if (
      (expectedType === "directory" && !stat.isDirectory()) ||
      (expectedType === "file" && !stat.isFile())
    ) {
      throw recoveryIntegrityError();
    }
  }
}

function validateRecoveryRootTopology(
  rootPath: string,
  directories: HarnessStateV1["directories"],
): void {
  assertExactEntrySet(
    rootPath,
    Object.freeze(
      Object.fromEntries(
        ROOT_DIR_NAMES.map((name) => [name, "directory"] as const),
      ),
    ),
  );
  assertExactEntrySet(
    directories.metadata,
    Object.freeze({
      [ROOT_MANIFEST_FILE]: "file",
      operations: "directory",
      registrations: "directory",
    }),
  );
  snapshotDirectoryIdentity(directories.transactions);
  snapshotDirectoryIdentity(directories.operations);
  snapshotDirectoryIdentity(directories.registrations);
}

function findMatchingHarnessRoots(
  parentPath: string,
  runDigest: string,
): readonly string[] {
  return readdirSync(parentPath)
    .map((entry) => join(parentPath, entry))
    .filter((entry) => existsSync(join(entry, "metadata", ROOT_MANIFEST_FILE)))
    .filter((entry) => {
      try {
        return (
          readCanonicalJson<RootManifestV1>(
            join(entry, "metadata", ROOT_MANIFEST_FILE),
          ).runDigest === runDigest
        );
      } catch {
        return false;
      }
    })
    .sort();
}

function maybeInjectFault(state: HarnessStateV1, point: string): void {
  if (state.faultPoint !== point) return;
  state.faultPoint = null;
  throw new Error("fixture injected fault");
}

function fixedGitEnvironment(
  state: HarnessStateV1,
  extra?: Readonly<Record<string, string>>,
): Record<string, string> {
  const environment = Object.create(null) as Record<string, string>;
  environment.HOME = state.directories.home;
  environment.XDG_CONFIG_HOME = state.directories.home;
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GCM_INTERACTIVE = "never";
  environment.GIT_ASKPASS = "/bin/false";
  environment.SSH_ASKPASS = "/bin/false";
  environment.GIT_PAGER = "cat";
  environment.PAGER = "cat";
  environment.GIT_EDITOR = "/bin/false";
  environment.GIT_SEQUENCE_EDITOR = "/bin/false";
  environment.GIT_MERGE_AUTOEDIT = "no";
  environment.GIT_EXEC_PATH = state.policyState.gitExecPathIdentity.path;
  environment.LANG = "C";
  environment.LC_ALL = "C";
  environment.TZ = "UTC";
  if (extra) {
    for (const [key, value] of Object.entries(extra)) environment[key] = value;
  }
  return environment;
}

function fixedGitConfigArguments(
  state: HarnessStateV1,
  cwd: string,
  allowFileProtocol = false,
): string[] {
  const argv = [
    "--no-pager",
    "-c",
    `core.hooksPath=${state.directories.hooksDisabled}`,
    "-c",
    "core.pager=false",
    "-c",
    "pager.branch=false",
    "-c",
    "pager.log=false",
    "-c",
    "credential.helper=",
    "-c",
    "credential.useHttpPath=false",
    "-c",
    "commit.gpgSign=false",
    "-c",
    "tag.gpgSign=false",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "diff.external=",
    "-c",
    "core.externalDiff=",
    "-c",
    "protocol.allow=never",
    "-c",
    "uploadpack.allowFilter=false",
    "-c",
    "uploadpack.allowAnySHA1InWant=false",
    "-c",
    "fetch.writeCommitGraph=false",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
    "-c",
    `safe.directory=${cwd}`,
  ];
  if (allowFileProtocol) argv.push("-c", "protocol.file.allow=always");
  return argv;
}

interface ResolvedGitPathsV1 {
  readonly bare: boolean;
  readonly adminDirectory: string;
  readonly commonDirectory: string;
}

function resolveGitPaths(cwd: string): ResolvedGitPathsV1 | null {
  if (existsSync(join(cwd, "config")) && existsSync(join(cwd, "objects"))) {
    return {
      bare: true,
      adminDirectory: cwd,
      commonDirectory: cwd,
    };
  }
  const dotGitPath = join(cwd, ".git");
  if (!existsSync(dotGitPath)) return null;
  const stat = lstatSync(dotGitPath);
  if (stat.isDirectory()) {
    return {
      bare: false,
      adminDirectory: dotGitPath,
      commonDirectory: dotGitPath,
    };
  }
  if (!stat.isFile()) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  const gitdirLine = readFileSync(dotGitPath, "utf8").trim();
  if (!gitdirLine.startsWith("gitdir: ")) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  const adminDirectory = resolve(cwd, gitdirLine.slice(8));
  const commondirPath = join(adminDirectory, "commondir");
  const commonDirectory = existsSync(commondirPath)
    ? resolve(adminDirectory, readFileSync(commondirPath, "utf8").trim())
    : adminDirectory;
  return {
    bare: false,
    adminDirectory,
    commonDirectory,
  };
}

function parseGitConfig(path: string): Map<string, Map<string, string>> {
  const sections = new Map<string, Map<string, string>>();
  const lines = readFileSync(path, "utf8").split(/\r?\n/u);
  let currentSection: string | null = null;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#") || line.startsWith(";"))
      continue;
    if (line.startsWith("[")) {
      const match = /^\[([A-Za-z0-9.-]+)\]$/u.exec(line);
      if (!match) {
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
      }
      currentSection = match[1]!.toLowerCase();
      if (sections.has(currentSection)) {
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
      }
      sections.set(currentSection, new Map());
      continue;
    }
    if (currentSection === null) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    const match = /^([A-Za-z0-9.-]+)\s*=\s*(.+)$/u.exec(line);
    if (!match) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    const key = match[1]!.toLowerCase();
    const value = match[2]!.trim();
    const section = sections.get(currentSection)!;
    if (section.has(key)) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    section.set(key, value);
  }
  return sections;
}

function normalizedConfigProjection(
  config: Map<string, Map<string, string>>,
): unknown {
  return [...config.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([section, entries]) => ({
      section,
      entries: [...entries.entries()].sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    }));
}

function expectedGitConfigShape(bare: boolean): {
  readonly extensions: { readonly objectformat: "sha256" };
  readonly core: {
    readonly repositoryformatversion: "1";
    readonly filemode: "true";
    readonly bare: "true" | "false";
    readonly logallrefupdates?: "true";
  };
} {
  return bare
    ? {
        extensions: { objectformat: "sha256" },
        core: {
          repositoryformatversion: "1",
          filemode: "true",
          bare: "true",
        },
      }
    : {
        extensions: { objectformat: "sha256" },
        core: {
          repositoryformatversion: "1",
          filemode: "true",
          bare: "false",
          logallrefupdates: "true",
        },
      };
}

function expectedGitConfigDigest(bare: boolean): string {
  const shape = expectedGitConfigShape(bare);
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-common-directory/1.0.0",
    Object.entries(shape)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([section, entries]) => ({
        section,
        entries: Object.entries(entries).sort(([left], [right]) =>
          left.localeCompare(right),
        ),
      })),
  );
}

function validateExactGitConfig(
  cwd: string,
): { readonly digest: string; readonly bare: boolean } | null {
  const resolved = resolveGitPaths(cwd);
  if (!resolved) return null;
  const commonConfigPath = join(resolved.commonDirectory, "config");
  if (!existsSync(commonConfigPath)) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  if (existsSync(join(resolved.adminDirectory, "config.worktree"))) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  const config = parseGitConfig(commonConfigPath);
  const expected = expectedGitConfigShape(resolved.bare);
  const expectedSections = Object.keys(expected).sort();
  const actualSections = [...config.keys()].sort();
  if (expectedSections.length !== actualSections.length) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  for (const sectionName of actualSections) {
    const expectedEntries = expected[sectionName as keyof typeof expected];
    if (!expectedEntries) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    const actualEntries = config.get(sectionName)!;
    const expectedKeys = Object.keys(expectedEntries).sort();
    const actualKeys = [...actualEntries.keys()].sort();
    if (expectedKeys.length !== actualKeys.length) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    for (const key of actualKeys) {
      if (
        !Object.hasOwn(expectedEntries, key) ||
        actualEntries.get(key) !==
          expectedEntries[key as keyof typeof expectedEntries]
      ) {
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
      }
    }
  }
  return {
    bare: resolved.bare,
    digest: computeGitCheckFixtureDigestV1(
      "spts.fixture-common-directory/1.0.0",
      normalizedConfigProjection(config),
    ),
  };
}

function runGit(
  state: HarnessStateV1,
  cwd: string,
  arguments_: readonly string[],
  options?: {
    readonly allowFailure?: boolean;
    readonly allowFileProtocol?: boolean;
    readonly environment?: Readonly<Record<string, string>>;
    readonly allowClosed?: boolean;
    readonly failureCode?: FixtureDiagnosticCodeV1;
  },
): GitProcessResultV1 {
  ensureHarnessState(state, options?.allowClosed ?? false);
  const configState = validateExactGitConfig(cwd);
  if (configState && containsPath(state.directories.worktrees, cwd)) {
    const registration = [...state.registrations.values()].find(
      (entry) => entry.path === cwd,
    );
    if (
      registration &&
      registration.commonConfigDigest !== configState.digest
    ) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
  }
  const gitExecutable = snapshotFileIdentity(
    state.policyState.gitExecutableIdentity.path,
  );
  const gitExecPath = snapshotDirectoryIdentity(
    state.policyState.gitExecPathIdentity.path,
  );
  if (
    !sameFileIdentity(state.policyState.gitExecutableIdentity, gitExecutable) ||
    !sameDirectoryIdentity(state.policyState.gitExecPathIdentity, gitExecPath)
  ) {
    state.policyState.revoked = true;
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
  const argv = [
    ...fixedGitConfigArguments(state, cwd, options?.allowFileProtocol === true),
    ...arguments_,
  ];
  const result = spawnSync(state.policyState.gitExecutableIdentity.path, argv, {
    cwd,
    env: fixedGitEnvironment(state, options?.environment),
    shell: false,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const failureCode = options?.failureCode ?? "repository-identity-drift";
  if (result.error) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1[failureCode]);
  }
  const status = result.status ?? 1;
  if (!options?.allowFailure && status !== 0) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1[failureCode]);
  }
  return {
    status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function validateGitVersion(state: HarnessStateV1): void {
  const result = spawnSync(
    state.policyState.gitExecutableIdentity.path,
    ["--version"],
    {
      encoding: "utf8",
    },
  );
  const match = VERSION_PATTERN.exec((result.stdout ?? "").trim());
  if (!match) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["platform-unsupported"]);
  }
  const major = Number.parseInt(match[1] ?? "0", 10);
  const minor = Number.parseInt(match[2] ?? "0", 10);
  if (major !== 2 || minor < 43 || minor > 60) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["platform-unsupported"]);
  }
}

function readGitAbsoluteDir(state: HarnessStateV1, cwd: string): string {
  const resolved = resolveGitPaths(cwd);
  if (!resolved) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return resolved.adminDirectory;
}

function readGitCommonDir(state: HarnessStateV1, cwd: string): string {
  const resolved = resolveGitPaths(cwd);
  if (!resolved) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return resolved.commonDirectory;
}

function readObjectFormat(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): "sha1" | "sha256" {
  const value = runGit(state, cwd, ["rev-parse", "--show-object-format"], {
    allowClosed,
  }).stdout.trim();
  if (value !== "sha1" && value !== "sha256") {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return value;
}

function readBranch(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): string | null {
  const result = runGit(
    state,
    cwd,
    ["symbolic-ref", "--quiet", "--short", "HEAD"],
    { allowFailure: true, allowClosed },
  );
  return result.status === 0 ? result.stdout.trim() : null;
}

function assertHostileStateAbsent(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): void {
  const gitDir = readGitAbsoluteDir(state, cwd);
  const commonDir = readGitCommonDir(state, cwd);
  const hostilePaths = [
    join(commonDir, "objects", "info", "alternates"),
    join(commonDir, "info", "grafts"),
    join(commonDir, "shallow"),
    join(commonDir, "MERGE_HEAD"),
    join(commonDir, "CHERRY_PICK_HEAD"),
    join(commonDir, "BISECT_LOG"),
    join(commonDir, "index.lock"),
    join(commonDir, "packed-refs.lock"),
    join(commonDir, "refs", "replace"),
    join(commonDir, "rebase-apply"),
    join(commonDir, "rebase-merge"),
    join(commonDir, "sequencer"),
    join(commonDir, "info", "sparse-checkout"),
    join(commonDir, "config.worktree"),
  ];
  if (hostilePaths.some((path) => existsSync(path))) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  const fsck = runGit(state, cwd, ["fsck", "--strict", "--no-progress"], {
    allowFailure: true,
    allowClosed,
  });
  if (fsck.status !== 0) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  if (gitDir !== commonDir) {
    if (!containsPath(commonDir, gitDir)) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
  }
}

function pathDigestForRelative(relativePath: string): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-path/1.0.0",
    relativePath,
  );
}

function digestFileContent(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function snapshotTreeEntry(
  path: string,
  relativePath: string,
): {
  readonly stat: ReturnType<typeof lstatSync>;
  readonly observation: {
    readonly pathDigest: string;
    readonly type: "directory" | "file";
    readonly mode: number;
    readonly uid: number;
    readonly gid: number;
    readonly device: number;
    readonly inode: number;
    readonly nlink: number;
    readonly size: number;
    readonly ctimeMicros: number;
    readonly mtimeMicros: number;
    readonly contentDigest: string | null;
  };
} {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !(stat.isDirectory() || stat.isFile())) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return {
    stat,
    observation: {
      pathDigest: pathDigestForRelative(relativePath),
      type: stat.isDirectory() ? "directory" : "file",
      mode: stat.mode,
      uid: stat.uid,
      gid: stat.gid,
      device: stat.dev,
      inode: stat.ino,
      nlink: stat.nlink,
      size: stat.size,
      ctimeMicros: Math.trunc(stat.ctimeMs * 1_000),
      mtimeMicros: Math.trunc(stat.mtimeMs * 1_000),
      contentDigest: stat.isFile() ? digestFileContent(path) : null,
    },
  };
}

function walkTree(rootPath: string, prefix = ""): unknown[] {
  const rootEntry = snapshotTreeEntry(rootPath, prefix);
  const rootStat = rootEntry.stat!;
  if (!rootStat.isDirectory()) {
    return [rootEntry.observation];
  }
  const entries = readdirSync(rootPath, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  const observations: unknown[] = [rootEntry.observation];
  for (const entry of entries) {
    const absolute = join(rootPath, entry.name);
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    observations.push(...walkTree(absolute, relativePath));
  }
  return observations;
}

function walkStableTree(rootPath: string, prefix = ""): unknown[] {
  const rootEntry = snapshotTreeEntry(rootPath, prefix);
  const rootStat = rootEntry.stat!;
  if (!rootStat.isDirectory()) {
    return [
      {
        pathDigest: rootEntry.observation.pathDigest,
        type: rootEntry.observation.type,
        mode: rootEntry.observation.mode,
        size: rootEntry.observation.size,
        contentDigest: rootEntry.observation.contentDigest,
      },
    ];
  }
  const entries = readdirSync(rootPath, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  const observations: unknown[] = [
    {
      pathDigest: rootEntry.observation.pathDigest,
      type: rootEntry.observation.type,
      mode: rootEntry.observation.mode,
      size: rootEntry.observation.size,
      contentDigest: rootEntry.observation.contentDigest,
    },
  ];
  for (const entry of entries) {
    const absolute = join(rootPath, entry.name);
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    observations.push(...walkStableTree(absolute, relativePath));
  }
  return observations;
}

function workspaceOnlySentinelDigest(path: string): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-filesystem-sentinel/1.0.0",
    walkTree(path),
  );
}

function adminOnlySentinelDigest(path: string): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-filesystem-sentinel/1.0.0",
    walkStableTree(path, "__admin__"),
  );
}

function toNamedCheckRepositoryObservation(
  observation: {
    readonly repositoryIdentity: FixtureRepositoryObservationV1["repositoryIdentity"];
    readonly state: RepositoryStateV1;
  },
  workspacePath: string,
  adminPath: string,
): NamedCheckRepositoryObservationV1 {
  return Object.freeze({
    repositoryIdentity: Object.freeze({
      commonDirectoryDigest:
        observation.repositoryIdentity.commonDirectoryDigest,
      objectFormat: observation.repositoryIdentity.objectFormat,
    }),
    state: observation.state,
    workspaceSentinelDigest: workspaceOnlySentinelDigest(workspacePath),
    adminSentinelDigest: adminOnlySentinelDigest(adminPath),
  });
}

function worktreePorcelainEntry(input: {
  readonly path: string;
  readonly head: string;
  readonly branch?: string;
  readonly detached?: true;
}): WorktreePorcelainEntryV1 {
  const pathDigest = pathDigestForRelative(input.path);
  if (!OBJECT_ID_PATTERN.test(input.head)) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  if (input.branch !== undefined) {
    if (
      input.detached === true ||
      !input.branch.startsWith("refs/") ||
      hasControlCharacter(input.branch)
    ) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    return Object.freeze({
      pathDigest,
      head: input.head,
      branch: input.branch,
    });
  }
  if (input.detached !== true) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return Object.freeze({
    pathDigest,
    head: input.head,
    detached: true,
  });
}

function finalizeWorktreePorcelainEntry(current: {
  readonly path: string | null;
  readonly head: string | null;
  readonly branch: string | null;
  readonly detached: boolean;
}): WorktreePorcelainEntryV1 {
  if (current.path === null || current.head === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  if (current.branch !== null) {
    return worktreePorcelainEntry({
      path: current.path,
      head: current.head,
      branch: current.branch,
    });
  }
  if (!current.detached) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return worktreePorcelainEntry({
    path: current.path,
    head: current.head,
    detached: true,
  });
}

function parseWorktreeList(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): readonly WorktreePorcelainEntryV1[] {
  const output = runGit(state, cwd, ["worktree", "list", "--porcelain", "-z"], {
    allowClosed,
  }).stdout;
  if (utf8Bytes(output) > state.policyState.limits.maxRecoveryBytes) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
  const records = output.split("\0").filter(Boolean);
  const worktrees: WorktreePorcelainEntryV1[] = [];
  let current: {
    path: string | null;
    head: string | null;
    branch: string | null;
    detached: boolean;
  } | null = null;
  for (const record of records) {
    if (record.startsWith("worktree ")) {
      if (current !== null) {
        worktrees.push(finalizeWorktreePorcelainEntry(current));
      }
      if (worktrees.length > state.policyState.limits.maxObservedWorktrees) {
        throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
      }
      current = {
        path: record.slice(9),
        head: null,
        branch: null,
        detached: false,
      };
      continue;
    }
    if (current === null) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    if (record.startsWith("HEAD ")) current.head = record.slice(5);
    else if (record.startsWith("branch ")) current.branch = record.slice(7);
    else if (record === "detached") current.detached = true;
    else {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
  }
  if (current !== null) {
    worktrees.push(finalizeWorktreePorcelainEntry(current));
  }
  if (worktrees.length > state.policyState.limits.maxObservedWorktrees) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
  worktrees.sort((left, right) =>
    left.pathDigest.localeCompare(right.pathDigest),
  );
  return Object.freeze(worktrees);
}

function readHeadReference(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): string | null {
  const result = runGit(state, cwd, ["symbolic-ref", "--quiet", "HEAD"], {
    allowFailure: true,
    allowClosed,
  });
  return result.status === 0 ? result.stdout.trim() : null;
}

function readBareRemoteRefs(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): readonly BareRemoteRefEntryV1[] {
  const output = runGit(
    state,
    cwd,
    [
      "for-each-ref",
      "--sort=refname",
      "--format=%(refname)%00%(objectname)",
      "refs",
    ],
    { allowClosed },
  ).stdout;
  if (utf8Bytes(output) > state.policyState.limits.maxRecoveryBytes) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
  const refs = output
    .split(/\n/u)
    .map((line) => line.replace(/\r$/u, ""))
    .filter((line) => line.length > 0)
    .map((line) => {
      const fields = line.split("\0");
      if (fields.length !== 2) {
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
      }
      const [refname, objectId] = fields;
      if (
        refname === undefined ||
        objectId === undefined ||
        !refname.startsWith("refs/") ||
        hasControlCharacter(refname) ||
        !OBJECT_ID_PATTERN.test(objectId)
      ) {
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
      }
      return Object.freeze({ refname, objectId });
    });
  if (refs.length > state.policyState.limits.maxRecoveryRecords) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
  return Object.freeze(refs);
}

function observeAdminWorktreeRegistrationSet(
  state: HarnessStateV1,
  commonDirectory: string,
): readonly WorktreeAdminRegistrationEntryV1[] {
  const worktreesDirectory = join(commonDirectory, "worktrees");
  if (!existsSync(worktreesDirectory)) {
    return Object.freeze([]);
  }
  const entries = readdirSync(worktreesDirectory, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  if (entries.length > state.policyState.limits.maxObservedWorktrees) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
  const registrations = entries.map((entry) => {
    const adminPath = join(worktreesDirectory, entry.name);
    const stat = lstatSync(adminPath);
    if (
      !SHA256_HEX_PATTERN.test(entry.name) ||
      stat.isSymbolicLink() ||
      !stat.isDirectory()
    ) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    const gitdir = readFileSync(join(adminPath, "gitdir"), "utf8").trim();
    if (
      gitdir.length === 0 ||
      utf8Bytes(gitdir) > state.policyState.limits.maxRootPathBytes ||
      hasControlCharacter(gitdir)
    ) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    const worktreeDotGit = resolve(adminPath, gitdir);
    if (parse(worktreeDotGit).base !== ".git") {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    return Object.freeze({
      registrationDigest: entry.name,
      pathDigest: pathDigestForRelative(dirname(worktreeDotGit)),
    });
  });
  return Object.freeze(registrations);
}

function bareRemoteRefSetDigest(refs: readonly BareRemoteRefEntryV1[]): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-operation-record/1.0.0",
    refs,
  );
}

function worktreeAdminRegistrationSetDigest(
  registrations: readonly WorktreeAdminRegistrationEntryV1[],
): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-operation-record/1.0.0",
    registrations,
  );
}

function worktreeSetContainsPath(
  state: HarnessStateV1,
  sourcePath: string,
  worktreePath: string,
  allowClosed = false,
): boolean {
  const pathDigest = pathDigestForRelative(worktreePath);
  return parseWorktreeList(state, sourcePath, allowClosed).some(
    (entry) => entry.pathDigest === pathDigest,
  );
}

function countGitObjects(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): void {
  const count = Number.parseInt(
    runGit(state, cwd, ["count-objects", "-v"], { allowClosed })
      .stdout.split(/\r?\n/u)
      .find((line) => line.startsWith("count: "))
      ?.slice(7) ?? "0",
    10,
  );
  if (
    !Number.isSafeInteger(count) ||
    count > state.policyState.limits.maxGitObjects
  ) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
}

function observeRepositoryState(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): {
  readonly repositoryIdentity: FixtureRepositoryObservationV1["repositoryIdentity"];
  readonly state: RepositoryStateV1;
} {
  assertHostileStateAbsent(state, cwd, allowClosed);
  const objectFormat = readObjectFormat(state, cwd, allowClosed);
  const headCommit = runGit(
    state,
    cwd,
    ["rev-parse", "--verify", "HEAD^{commit}"],
    { allowClosed },
  ).stdout.trim();
  const headTree = runGit(state, cwd, ["rev-parse", "HEAD^{tree}"], {
    allowClosed,
  }).stdout.trim();
  const branch = readBranch(state, cwd, allowClosed);
  const status = runGit(
    state,
    cwd,
    [
      "status",
      "--porcelain=v2",
      "-z",
      "--branch",
      "--untracked-files=all",
      "--ignored=matching",
    ],
    { allowClosed },
  ).stdout;
  const indexEntries = runGit(state, cwd, ["ls-files", "--stage", "-z"], {
    allowClosed,
  })
    .stdout.split("\0")
    .filter(Boolean)
    .map((entry) => {
      const match = /^(\d{6}) ([a-f0-9]{40,64}) (\d)\t(.+)$/u.exec(entry);
      if (!match) {
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
      }
      return {
        mode: match[1],
        objectId: match[2],
        stage: Number.parseInt(match[3] ?? "0", 10),
        pathDigest: pathDigestForRelative(match[4] ?? ""),
      };
    });
  const indexDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-index/1.0.0",
    indexEntries,
  );
  const trackedWorktreeDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-tracked-worktree/1.0.0",
    indexEntries,
  );
  const statusRecords = status.split("\0").filter(Boolean);
  const untracked = statusRecords
    .filter((entry) => entry.startsWith("? "))
    .map((entry) => entry.slice(2))
    .sort();
  const ignored = statusRecords
    .filter((entry) => entry.startsWith("! "))
    .map((entry) => entry.slice(2))
    .sort();
  const conflicts = statusRecords
    .filter((entry) => entry.startsWith("u "))
    .map((entry) => entry.slice(2))
    .sort();
  const dirtyTracked = statusRecords.filter(
    (entry) => entry.startsWith("1 ") || entry.startsWith("2 "),
  );
  const worktreeSetDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-worktree-set/1.0.0",
    parseWorktreeList(state, cwd, allowClosed),
  );
  const filesystemObservations = walkTree(cwd);
  const gitDir = readGitAbsoluteDir(state, cwd);
  if (!containsPath(cwd, gitDir)) {
    filesystemObservations.push(...walkTree(gitDir, "__admin__"));
  }
  countGitObjects(state, cwd, allowClosed);
  return {
    repositoryIdentity: {
      commonDirectoryDigest: directoryDigest(
        snapshotDirectoryIdentity(readGitCommonDir(state, cwd)),
      ),
      objectFormat,
    },
    state: Object.freeze({
      headCommit,
      headTree,
      branch,
      detached: branch === null,
      clean:
        dirtyTracked.length === 0 &&
        untracked.length === 0 &&
        ignored.length === 0 &&
        conflicts.length === 0,
      indexDigest,
      trackedWorktreeDigest,
      untrackedSetDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-untracked-set/1.0.0",
        untracked.map((entry) => pathDigestForRelative(entry)),
      ),
      ignoredSetDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-ignored-set/1.0.0",
        ignored.map((entry) => pathDigestForRelative(entry)),
      ),
      conflictSetDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-conflict-set/1.0.0",
        conflicts.map((entry) => pathDigestForRelative(entry)),
      ),
      submoduleSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.submoduleSetDigest,
      filesystemSentinelDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-filesystem-sentinel/1.0.0",
        filesystemObservations,
      ),
      worktreeSetDigest,
    }),
  };
}

function observeBareRepositoryState(
  state: HarnessStateV1,
  cwd: string,
  allowClosed = false,
): {
  readonly repositoryIdentity: FixtureRepositoryObservationV1["repositoryIdentity"];
  readonly headCommit: string;
  readonly headTree: string;
  readonly branch: string | null;
} {
  assertHostileStateAbsent(state, cwd, allowClosed);
  countGitObjects(state, cwd, allowClosed);
  return {
    repositoryIdentity: {
      commonDirectoryDigest: directoryDigest(snapshotDirectoryIdentity(cwd)),
      objectFormat: readObjectFormat(state, cwd, allowClosed),
    },
    headCommit: runGit(state, cwd, ["rev-parse", "--verify", "HEAD^{commit}"], {
      allowClosed,
    }).stdout.trim(),
    headTree: runGit(state, cwd, ["rev-parse", "HEAD^{tree}"], {
      allowClosed,
    }).stdout.trim(),
    branch: readBranch(state, cwd, allowClosed),
  };
}

function currentSequence(state: HarnessStateV1): number {
  return state.operations.size + 1;
}

function operationDirectory(
  state: HarnessStateV1,
  operationId: string,
): string {
  return join(
    state.directories.operations,
    operationDigest(state.runDigest, operationId),
  );
}

function operationHintPath(state: HarnessStateV1, operationId: string): string {
  return join(
    state.directories.transactions,
    `${operationDigest(state.runDigest, operationId)}.head`,
  );
}

function stageFilename(sequence: number, stage: OperationStageV1): string {
  return `${sequence.toString().padStart(6, "0")}-${stage}.json`;
}

function recordDigestForStage(
  record: Omit<OperationStageRecordV1, "recordDigest">,
): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-operation-record/1.0.0",
    record,
  );
}

function stageResultDigest(result: unknown): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-operation-record/1.0.0",
    result,
  );
}

function storageUnavailableError(): TypeError {
  return new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["storage-unavailable"]);
}

function writeOperationStage(
  state: HarnessStateV1,
  input: {
    readonly operationId: string;
    readonly kind: OperationKindV1;
    readonly registrationId: string;
    readonly registrationDigest: string;
    readonly requestDigest: string;
    readonly request: unknown;
    readonly sequence: number;
    readonly stage: OperationStageV1;
    readonly priorRecordDigest: string | null;
    readonly terminalState: OperationTerminalStateV1;
    readonly result: unknown | null;
  },
): OperationStageRecordV1 {
  try {
    const operationDir = operationDirectory(state, input.operationId);
    mkdirSync(operationDir, { recursive: true, mode: 0o700 });
    const resultDigest =
      input.result === null ? null : stageResultDigest(input.result);
    const unsigned: Omit<OperationStageRecordV1, "recordDigest"> = {
      contract: "spts.fixture-operation-record",
      version: "1.0.0",
      runDigest: state.runDigest,
      manifestDigest: state.manifest.manifestDigest,
      operationId: input.operationId,
      operationDigest: operationDigest(state.runDigest, input.operationId),
      sequence: input.sequence,
      stage: input.stage,
      kind: input.kind,
      registrationId: input.registrationId,
      registrationDigest: input.registrationDigest,
      requestDigest: input.requestDigest,
      request: input.request,
      priorRecordDigest: input.priorRecordDigest,
      terminalState: input.terminalState,
      resultDigest,
      result: input.result,
    };
    const record: OperationStageRecordV1 = Object.freeze({
      ...unsigned,
      recordDigest: recordDigestForStage(unsigned),
    });
    writeCanonicalFileImmutable(
      join(operationDir, stageFilename(input.sequence, input.stage)),
      record,
    );
    writeCanonicalFileMutable(operationHintPath(state, input.operationId), {
      sequence: input.sequence,
      recordDigest: record.recordDigest,
    });
    return record;
  } catch {
    throw storageUnavailableError();
  }
}

function loadStageRecord(path: string): OperationStageRecordV1 {
  return readCanonicalJson<OperationStageRecordV1>(path);
}

function writeRegistrationRecord(
  state: HarnessStateV1,
  registration: RegistrationStateV1,
): void {
  try {
    const directory = join(
      state.directories.registrations,
      registration.registrationDigest,
    );
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const previousDigest =
      registration.generation > 1
        ? readCanonicalJson<{ readonly recordDigest: string }>(
            join(directory, `${registration.generation - 1}.json`),
          ).recordDigest
        : null;
    const record = createRegistrationRecordV1({
      registrationId: registration.registrationId,
      sourceRegistrationId: registration.sourceRegistrationId,
      role: registration.role,
      checkId: registration.checkId,
      candidateCommit: registration.candidateCommit,
      candidateTree: registration.candidateTree,
      commonDirectoryDigest: registration.commonDirectoryDigest,
      workspacePathDigest: registrationPathDigest(
        registration.registrationDigest,
      ),
      adminDirectoryDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-common-directory/1.0.0",
        registration.adminDirectory,
      ),
      rootIdentity: registration.rootIdentity,
      state: registration.state,
      generation: registration.generation,
      previousDigest,
    });
    writeCanonicalFileImmutable(
      join(directory, `${registration.generation}.json`),
      record,
    );
  } catch {
    throw storageUnavailableError();
  }
}

function updateRegistrationCleanupState(
  registration: RegistrationStateV1,
  result: ValidationResult<NamedCheckResultV1>,
): void {
  if (!result.valid) return;
  if (
    result.value.outcome === "mutation-detected" ||
    result.value.outcome === "outcome-unknown"
  ) {
    registration.cleanupBlockedReason =
      result.value.outcome === "mutation-detected"
        ? "workspace-mutated"
        : "outcome-unknown";
    return;
  }
  registration.cleanupBlockedReason = null;
}

function createObservation(
  state: HarnessStateV1,
  input: {
    readonly operationId: string;
    readonly registrationId: string;
    readonly operationKind: FixtureRepositoryObservationV1["operationKind"];
    readonly purpose: FixtureRepositoryObservationV1["purpose"];
    readonly sequence: number;
    readonly repositoryIdentity: FixtureRepositoryObservationV1["repositoryIdentity"];
    readonly pre: RepositoryStateV1 | null;
    readonly post: RepositoryStateV1 | null;
    readonly outcome: FixtureRepositoryObservationV1["outcome"];
    readonly diagnostic: FixtureRepositoryObservationV1["diagnostic"];
    readonly requestDigest: string;
  },
): FixtureRepositoryObservationV1 {
  const unsigned: FixtureRepositoryObservationV1 = {
    contract: "spts.fixture-repository-observation",
    version: "1.0.0",
    runId: state.runId,
    operationId: input.operationId,
    registrationId: input.registrationId,
    operationKind: input.operationKind,
    purpose: input.purpose,
    sequence: input.sequence,
    observedAt: new Date().toISOString(),
    repositoryIdentity: input.repositoryIdentity,
    pre: input.pre,
    post: input.post,
    outcome: input.outcome,
    diagnostic: input.diagnostic,
    requestDigest: input.requestDigest,
    observationDigest: "",
  };
  return Object.freeze({
    ...unsigned,
    observationDigest: computeFixtureRepositoryObservationDigestV1(unsigned),
  });
}

function completeRecoveredOperation(
  state: HarnessStateV1,
  operation: OperationStateV1,
  result: unknown,
): void {
  const completed = writeOperationStage(state, {
    operationId: operation.operationId,
    kind: operation.kind,
    registrationId: operation.registrationId,
    registrationDigest: operation.registrationDigest,
    requestDigest: operation.requestDigest,
    request: operation.request,
    sequence: 4,
    stage: "completed",
    priorRecordDigest: operation.latestRecordDigest,
    terminalState: terminalStateForResult(result),
    result,
  });
  storeOperationState(state, completed);
}

function conflictResult(
  code: FixtureDiagnosticCodeV1,
): ValidationResult<NamedCheckResultV1> {
  return {
    valid: false,
    errors: [
      {
        path: "/",
        code,
        message: FIXTURE_DIAGNOSTIC_MESSAGES_V1[code],
      },
    ],
  };
}

function syntheticNamedCheckUnknown(
  state: HarnessStateV1,
  request: {
    readonly operationId: string;
    readonly registrationId: string;
    readonly checkId: string;
    readonly attempt: number;
    readonly candidateCommit: string;
    readonly candidateTree: string;
    readonly requestDigest: string;
  },
): ValidationResult<NamedCheckResultV1> {
  const unsigned: NamedCheckResultV1 = {
    contract: "spts.named-check-result",
    version: "1.0.0",
    runId: state.runId,
    operationId: request.operationId,
    checkId: request.checkId,
    registrationId: request.registrationId,
    attempt: request.attempt,
    candidateCommit: request.candidateCommit,
    candidateTree: request.candidateTree,
    workspaceTreeBefore: request.candidateTree,
    workspaceTreeAfter: request.candidateTree,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    elapsedMs: 0,
    outcome: "outcome-unknown",
    exitCode: null,
    signal: null,
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutDigest: createHash("sha256").digest("hex"),
    stderrDigest: createHash("sha256").digest("hex"),
    diagnostic: createFixtureDiagnosticV1("outcome-unknown"),
    requestDigest: request.requestDigest,
    resultDigest: "",
  };
  const result: NamedCheckResultV1 = Object.freeze({
    ...unsigned,
    resultDigest: computeGitCheckFixtureDigestV1(
      "spts.named-check-result/1.0.0",
      unsigned,
    ),
  });
  return { valid: true, value: result };
}

function sourceRegistration(
  state: HarnessStateV1,
  registrationId: string,
): RegistrationStateV1 {
  const registration = state.registrations.get(registrationId);
  if (!registration || registration.state === "removed") {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["registration-conflict"],
    );
  }
  return registration;
}

function maybeReplay<T>(
  state: HarnessStateV1,
  operationId: string,
  requestDigest: string,
): T | null {
  const operation = state.operations.get(operationId);
  if (!operation || !operation.completed) return null;
  if (operation.requestDigest !== requestDigest) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["operation-replay-conflict"],
    );
  }
  return operation.result as T;
}

function createRegistrationState(
  state: HarnessStateV1,
  input: {
    readonly registrationId: string;
    readonly role: RegistrationStateV1["role"];
    readonly checkId: string | null;
    readonly sourceRegistrationId: string | null;
    readonly path: string;
    readonly commonDirectory: string;
    readonly adminDirectory: string;
    readonly sourceCommonDirectoryDigest: string | null;
    readonly candidateCommit: string | null;
    readonly candidateTree: string | null;
    readonly lifecycleState: RegistrationStateV1["state"];
  },
): RegistrationStateV1 {
  const registrationDigest = registrationDigestV1({
    registrationId: input.registrationId,
  });
  const configState = validateExactGitConfig(input.path);
  return {
    registrationId: input.registrationId,
    registrationDigest,
    role: input.role,
    checkId: input.checkId,
    sourceRegistrationId: input.sourceRegistrationId,
    path: input.path,
    commonDirectory: input.commonDirectory,
    adminDirectory: input.adminDirectory,
    commonDirectoryDigest: directoryDigest(
      snapshotDirectoryIdentity(input.commonDirectory),
    ),
    rootIdentity: snapshotTargetRootIdentity(state, input.path),
    sourceCommonDirectoryDigest: input.sourceCommonDirectoryDigest,
    commonConfigDigest:
      configState?.digest ??
      computeGitCheckFixtureDigestV1(
        "spts.fixture-common-directory/1.0.0",
        input.path,
      ),
    candidateCommit: input.candidateCommit,
    candidateTree: input.candidateTree,
    state: input.lifecycleState,
    generation: 1,
    cleanupBlockedReason: null,
  };
}

function createRepositoryOperationRequest(
  request: CreateRepositoryRequestV1,
  files: readonly Readonly<FixtureFileV1>[],
): CreateRepositoryOperationRequestV1 {
  return Object.freeze({
    registrationId: request.registrationId,
    files: Object.freeze(
      files
        .map((file) =>
          Object.freeze({
            pathComponents: Object.freeze([...file.pathComponents]),
            pathDigest: digestRelativePathV1(file.pathComponents),
            mode: file.mode,
            contentDigest: createHash("sha256")
              .update(file.content)
              .digest("hex"),
          }),
        )
        .sort((left, right) =>
          left.pathComponents
            .join("/")
            .localeCompare(right.pathComponents.join("/")),
        ),
    ),
    expectedConfigDigest: expectedGitConfigDigest(false),
    expectedObjectFormat: "sha256",
    expectedBranch: "fixture-main",
  });
}

function readCreateRepositoryOperationRequest(
  value: unknown,
): CreateRepositoryOperationRequestV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const request = value as Record<string, unknown>;
  if (
    typeof request.registrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.registrationId) ||
    request.expectedConfigDigest !== expectedGitConfigDigest(false) ||
    request.expectedObjectFormat !== "sha256" ||
    request.expectedBranch !== "fixture-main" ||
    !Array.isArray(request.files)
  ) {
    return null;
  }
  const files = request.files
    .map((entry) => {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        return null;
      }
      const file = entry as Record<string, unknown>;
      if (
        !Array.isArray(file.pathComponents) ||
        file.pathComponents.length === 0 ||
        file.pathComponents.some(
          (component) => typeof component !== "string",
        ) ||
        (file.mode !== "100644" && file.mode !== "100755") ||
        typeof file.pathDigest !== "string" ||
        !SHA256_HEX_PATTERN.test(file.pathDigest) ||
        typeof file.contentDigest !== "string" ||
        !SHA256_HEX_PATTERN.test(file.contentDigest)
      ) {
        return null;
      }
      const pathComponents = Object.freeze([
        ...file.pathComponents,
      ]) as readonly string[];
      if (digestRelativePathV1(pathComponents) !== file.pathDigest) return null;
      return Object.freeze({
        pathComponents,
        pathDigest: file.pathDigest,
        mode: file.mode,
        contentDigest: file.contentDigest,
      });
    })
    .filter(
      (entry): entry is RepositoryFixtureProjectionFileV1 => entry !== null,
    );
  if (files.length !== request.files.length) return null;
  return Object.freeze({
    registrationId: request.registrationId,
    files: Object.freeze(files),
    expectedConfigDigest: request.expectedConfigDigest,
    expectedObjectFormat: request.expectedObjectFormat,
    expectedBranch: request.expectedBranch,
  });
}

function collectRepositoryWorkspaceProjection(
  rootPath: string,
  pathComponents: readonly string[] = [],
): {
  readonly directories: readonly string[];
  readonly files: readonly {
    readonly path: string;
    readonly mode: FixtureFileV1["mode"];
    readonly contentDigest: string;
  }[];
} {
  const directories: string[] = [];
  const files: Array<{
    readonly path: string;
    readonly mode: FixtureFileV1["mode"];
    readonly contentDigest: string;
  }> = [];
  const entries = readdirSync(rootPath, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  for (const entry of entries) {
    if (pathComponents.length === 0 && entry.name === ".git") continue;
    const absolutePath = join(rootPath, entry.name);
    const stat = lstatSync(absolutePath);
    if (stat.isSymbolicLink() || !(stat.isDirectory() || stat.isFile())) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    const relativePath = [...pathComponents, entry.name].join("/");
    if (stat.isDirectory()) {
      directories.push(relativePath);
      const nested = collectRepositoryWorkspaceProjection(absolutePath, [
        ...pathComponents,
        entry.name,
      ]);
      directories.push(...nested.directories);
      files.push(...nested.files);
      continue;
    }
    files.push({
      path: relativePath,
      mode: (stat.mode & 0o111) === 0 ? "100644" : "100755",
      contentDigest: digestFileContent(absolutePath),
    });
  }
  return Object.freeze({
    directories: Object.freeze(
      directories.sort((left, right) => left.localeCompare(right)),
    ),
    files: Object.freeze(
      files.sort((left, right) => left.path.localeCompare(right.path)),
    ),
  });
}

function repositoryProjectionMatchesRequest(
  repositoryPath: string,
  request: CreateRepositoryOperationRequestV1,
): boolean {
  const expectedDirectories = new Set<string>();
  const expectedFiles = request.files
    .map((file) => {
      for (let index = 1; index < file.pathComponents.length; index += 1) {
        expectedDirectories.add(file.pathComponents.slice(0, index).join("/"));
      }
      return {
        path: file.pathComponents.join("/"),
        mode: file.mode,
        contentDigest: file.contentDigest,
      };
    })
    .sort((left, right) => left.path.localeCompare(right.path));
  const actual = collectRepositoryWorkspaceProjection(repositoryPath);
  const actualDirectories = [...actual.directories];
  const expectedDirectoryList = [...expectedDirectories].sort((left, right) =>
    left.localeCompare(right),
  );
  if (
    actualDirectories.length !== expectedDirectoryList.length ||
    actualDirectories.some(
      (entry, index) => entry !== expectedDirectoryList[index],
    )
  ) {
    return false;
  }
  if (actual.files.length !== expectedFiles.length) return false;
  return actual.files.every((file, index) => {
    const expected = expectedFiles[index];
    return (
      file.path === expected?.path &&
      file.mode === expected.mode &&
      file.contentDigest === expected.contentDigest
    );
  });
}

function repositoryRecoveryPostcondition(operation: OperationStateV1): {
  readonly headCommit: string;
  readonly headTree: string;
  readonly objectFormat: "sha1" | "sha256";
} | null {
  if (operation.latestStage !== "effect-observed") return null;
  const result =
    operation.result as Partial<FixtureRepositoryObservationV1> | null;
  if (
    !result ||
    result.operationKind !== "create-repository" ||
    result.outcome !== "applied" ||
    result.post === null ||
    result.post === undefined ||
    result.repositoryIdentity === null ||
    result.repositoryIdentity === undefined
  ) {
    return null;
  }
  return {
    headCommit: result.post.headCommit,
    headTree: result.post.headTree,
    objectFormat: result.repositoryIdentity.objectFormat,
  };
}

function createRepositoryRecoveryConflict(
  state: HarnessStateV1,
  operation: OperationStateV1,
  registrationId: string,
  repositoryIdentity?: FixtureRepositoryObservationV1["repositoryIdentity"],
): OperationStageRecordV1 {
  return writeOperationStage(state, {
    operationId: operation.operationId,
    kind: operation.kind,
    registrationId,
    registrationDigest: operation.registrationDigest,
    requestDigest: operation.requestDigest,
    request: operation.request,
    sequence: 4,
    stage: "completed",
    priorRecordDigest: operation.latestRecordDigest,
    terminalState: "outcome-unknown",
    result: operationConflictObservation(state, {
      operationId: operation.operationId,
      registrationId,
      operationKind: "create-repository",
      purpose: "principal-candidate",
      requestDigest: operation.requestDigest,
      diagnosticCode: "outcome-unknown",
      repositoryIdentity,
    }),
  });
}

function sameFixtureValue(left: unknown, right: unknown): boolean {
  return (
    canonicalizeGitCheckFixtureValueV1(left) ===
    canonicalizeGitCheckFixtureValueV1(right)
  );
}

function bareRemoteRefEntry(
  refname: string,
  objectId: string,
): BareRemoteRefEntryV1 {
  if (
    !refname.startsWith("refs/") ||
    hasControlCharacter(refname) ||
    !OBJECT_ID_PATTERN.test(objectId)
  ) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return Object.freeze({ refname, objectId });
}

function expectedBareRemoteRefs(
  expectedCommit: string,
): readonly BareRemoteRefEntryV1[] {
  return Object.freeze([
    bareRemoteRefEntry("refs/heads/fixture-main", expectedCommit),
  ]);
}

function readBareRemoteRefEntryValue(
  value: unknown,
): BareRemoteRefEntryV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const entry = value as Record<string, unknown>;
  if (
    typeof entry.refname !== "string" ||
    !entry.refname.startsWith("refs/") ||
    hasControlCharacter(entry.refname) ||
    typeof entry.objectId !== "string" ||
    !OBJECT_ID_PATTERN.test(entry.objectId)
  ) {
    return null;
  }
  return Object.freeze({
    refname: entry.refname,
    objectId: entry.objectId,
  });
}

function readBareRemoteRefEntries(
  value: unknown,
): readonly BareRemoteRefEntryV1[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const refs = value.map((entry) => readBareRemoteRefEntryValue(entry));
  if (refs.some((entry) => entry === null)) {
    return null;
  }
  return Object.freeze(refs as BareRemoteRefEntryV1[]);
}

function readWorktreePorcelainEntryValue(
  value: unknown,
): WorktreePorcelainEntryV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const entry = value as Record<string, unknown>;
  if (
    typeof entry.pathDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(entry.pathDigest) ||
    typeof entry.head !== "string" ||
    !OBJECT_ID_PATTERN.test(entry.head)
  ) {
    return null;
  }
  if (typeof entry.branch === "string") {
    if (
      entry.detached !== undefined ||
      !entry.branch.startsWith("refs/") ||
      hasControlCharacter(entry.branch)
    ) {
      return null;
    }
    return Object.freeze({
      pathDigest: entry.pathDigest,
      head: entry.head,
      branch: entry.branch,
    });
  }
  if (entry.detached !== true) {
    return null;
  }
  return Object.freeze({
    pathDigest: entry.pathDigest,
    head: entry.head,
    detached: true,
  });
}

function readWorktreePorcelainEntries(
  value: unknown,
): readonly WorktreePorcelainEntryV1[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const entries = value.map((entry) => readWorktreePorcelainEntryValue(entry));
  if (entries.some((entry) => entry === null)) {
    return null;
  }
  return Object.freeze(entries as WorktreePorcelainEntryV1[]);
}

function worktreeAdminRegistrationEntry(
  registrationDigest: string,
  path: string,
): WorktreeAdminRegistrationEntryV1 {
  if (!SHA256_HEX_PATTERN.test(registrationDigest)) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return Object.freeze({
    registrationDigest,
    pathDigest: pathDigestForRelative(path),
  });
}

function readWorktreeAdminRegistrationEntryValue(
  value: unknown,
): WorktreeAdminRegistrationEntryV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const entry = value as Record<string, unknown>;
  if (
    typeof entry.registrationDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(entry.registrationDigest) ||
    typeof entry.pathDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(entry.pathDigest)
  ) {
    return null;
  }
  return Object.freeze({
    registrationDigest: entry.registrationDigest,
    pathDigest: entry.pathDigest,
  });
}

function readWorktreeAdminRegistrationEntries(
  value: unknown,
): readonly WorktreeAdminRegistrationEntryV1[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const entries = value.map((entry) =>
    readWorktreeAdminRegistrationEntryValue(entry),
  );
  if (entries.some((entry) => entry === null)) {
    return null;
  }
  return Object.freeze(entries as WorktreeAdminRegistrationEntryV1[]);
}

function expectedCreateWorktreeSet(
  state: HarnessStateV1,
  source: RegistrationStateV1,
  request: RegisterWorktreeRequestV1,
): readonly WorktreePorcelainEntryV1[] {
  const principal = [...state.registrations.values()].find(
    (registration) =>
      registration.role === "principal-candidate" &&
      registration.commonDirectoryDigest === source.commonDirectoryDigest &&
      registration.state === "retained",
  );
  if (!principal || principal.candidateCommit === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["registration-conflict"],
    );
  }
  const entries = [
    worktreePorcelainEntry({
      path: principal.path,
      head: principal.candidateCommit,
      branch: "refs/heads/fixture-main",
    }),
    ...[...state.registrations.values()]
      .filter(
        (registration) =>
          registration.role !== "principal-candidate" &&
          registration.role !== "fixture-remote" &&
          registration.commonDirectoryDigest === source.commonDirectoryDigest &&
          registration.state === "active",
      )
      .map((registration) => {
        if (registration.candidateCommit === null) {
          throw new TypeError(
            FIXTURE_DIAGNOSTIC_MESSAGES_V1["registration-conflict"],
          );
        }
        return worktreePorcelainEntry({
          path: registration.path,
          head: registration.candidateCommit,
          detached: true,
        });
      }),
    worktreePorcelainEntry({
      path: join(
        state.directories.worktrees,
        registrationDigestV1({ registrationId: request.registrationId }),
      ),
      head: request.candidateCommit,
      detached: true,
    }),
  ].sort((left, right) => left.pathDigest.localeCompare(right.pathDigest));
  return Object.freeze(entries);
}

function expectedCreateWorktreeAdminRegistrationSet(
  state: HarnessStateV1,
  source: RegistrationStateV1,
  request: RegisterWorktreeRequestV1,
): readonly WorktreeAdminRegistrationEntryV1[] {
  const targetDigest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const targetPath = join(state.directories.worktrees, targetDigest);
  const entries = [
    ...[...state.registrations.values()]
      .filter(
        (registration) =>
          registration.role !== "principal-candidate" &&
          registration.role !== "fixture-remote" &&
          registration.commonDirectoryDigest === source.commonDirectoryDigest &&
          registration.state === "active",
      )
      .map((registration) =>
        worktreeAdminRegistrationEntry(
          registration.registrationDigest,
          registration.path,
        ),
      ),
    worktreeAdminRegistrationEntry(targetDigest, targetPath),
  ].sort((left, right) =>
    left.registrationDigest.localeCompare(right.registrationDigest),
  );
  return Object.freeze(entries);
}

function readWorktreeRole(value: unknown): FixtureWorktreeRoleV1 | null {
  return value === "principal-candidate" ||
    value === "independent-verifier" ||
    value === "named-check"
    ? value
    : null;
}

function createBareRemoteOperationRequest(
  request: CreateBareRemoteRequestV1,
  source: RegistrationStateV1,
): CreateBareRemoteOperationRequestV1 {
  if (source.candidateCommit === null || source.candidateTree === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["registration-conflict"],
    );
  }
  const expectedRefs = expectedBareRemoteRefs(source.candidateCommit);
  return Object.freeze({
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
    expectedConfigDigest: expectedGitConfigDigest(true),
    expectedObjectFormat: "sha256",
    expectedBranch: "fixture-main",
    expectedHeadRef: "refs/heads/fixture-main",
    expectedRefs,
    expectedRefSetDigest: bareRemoteRefSetDigest(expectedRefs),
    expectedCommit: source.candidateCommit,
    expectedTree: source.candidateTree,
    expectedSourceCommonDirectoryDigest: source.commonDirectoryDigest,
  });
}

function readCreateBareRemoteOperationRequest(
  value: unknown,
): CreateBareRemoteOperationRequestV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const request = value as Record<string, unknown>;
  const expectedRefs = readBareRemoteRefEntries(request.expectedRefs);
  if (
    typeof request.registrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.registrationId) ||
    typeof request.sourceRegistrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.sourceRegistrationId) ||
    request.expectedConfigDigest !== expectedGitConfigDigest(true) ||
    request.expectedObjectFormat !== "sha256" ||
    request.expectedBranch !== "fixture-main" ||
    request.expectedHeadRef !== "refs/heads/fixture-main" ||
    expectedRefs === null ||
    typeof request.expectedRefSetDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(request.expectedRefSetDigest) ||
    typeof request.expectedCommit !== "string" ||
    !OBJECT_ID_PATTERN.test(request.expectedCommit) ||
    typeof request.expectedTree !== "string" ||
    !OBJECT_ID_PATTERN.test(request.expectedTree) ||
    typeof request.expectedSourceCommonDirectoryDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(request.expectedSourceCommonDirectoryDigest) ||
    !sameFixtureValue(
      expectedRefs,
      expectedBareRemoteRefs(request.expectedCommit),
    ) ||
    request.expectedRefSetDigest !== bareRemoteRefSetDigest(expectedRefs)
  ) {
    return null;
  }
  return Object.freeze({
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
    expectedConfigDigest: request.expectedConfigDigest,
    expectedObjectFormat: request.expectedObjectFormat,
    expectedBranch: request.expectedBranch,
    expectedHeadRef: request.expectedHeadRef,
    expectedRefs,
    expectedRefSetDigest: request.expectedRefSetDigest,
    expectedCommit: request.expectedCommit,
    expectedTree: request.expectedTree,
    expectedSourceCommonDirectoryDigest:
      request.expectedSourceCommonDirectoryDigest,
  });
}

function createWorktreeOperationRequest(
  request: RegisterWorktreeRequestV1,
  source: RegistrationStateV1,
  state: HarnessStateV1,
): CreateWorktreeOperationRequestV1 {
  const expectedWorktreeSet = expectedCreateWorktreeSet(state, source, request);
  const expectedAdminRegistrationSet =
    expectedCreateWorktreeAdminRegistrationSet(state, source, request);
  return Object.freeze({
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
    role: request.role,
    checkId: request.checkId,
    candidateCommit: request.candidateCommit,
    candidateTree: request.candidateTree,
    expectedConfigDigest: expectedGitConfigDigest(false),
    expectedObjectFormat: "sha256",
    expectedDetached: true,
    expectedCommonDirectoryDigest: source.commonDirectoryDigest,
    expectedWorktreeSet,
    expectedWorktreeSetDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-worktree-set/1.0.0",
      expectedWorktreeSet,
    ),
    expectedAdminRegistrationSet,
    expectedAdminRegistrationSetDigest: worktreeAdminRegistrationSetDigest(
      expectedAdminRegistrationSet,
    ),
  });
}

function readCreateWorktreeOperationRequest(
  value: unknown,
): CreateWorktreeOperationRequestV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const request = value as Record<string, unknown>;
  const role = readWorktreeRole(request.role);
  const expectedWorktreeSet = readWorktreePorcelainEntries(
    request.expectedWorktreeSet,
  );
  const expectedAdminRegistrationSet = readWorktreeAdminRegistrationEntries(
    request.expectedAdminRegistrationSet,
  );
  if (
    typeof request.registrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.registrationId) ||
    typeof request.sourceRegistrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.sourceRegistrationId) ||
    role === null ||
    role === "principal-candidate" ||
    (request.checkId !== null &&
      (typeof request.checkId !== "string" ||
        !SAFE_ID_PATTERN.test(request.checkId))) ||
    typeof request.candidateCommit !== "string" ||
    !OBJECT_ID_PATTERN.test(request.candidateCommit) ||
    typeof request.candidateTree !== "string" ||
    !OBJECT_ID_PATTERN.test(request.candidateTree) ||
    request.expectedConfigDigest !== expectedGitConfigDigest(false) ||
    request.expectedObjectFormat !== "sha256" ||
    request.expectedDetached !== true ||
    typeof request.expectedCommonDirectoryDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(request.expectedCommonDirectoryDigest) ||
    expectedWorktreeSet === null ||
    typeof request.expectedWorktreeSetDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(request.expectedWorktreeSetDigest) ||
    request.expectedWorktreeSetDigest !==
      computeGitCheckFixtureDigestV1(
        "spts.fixture-worktree-set/1.0.0",
        expectedWorktreeSet,
      ) ||
    expectedAdminRegistrationSet === null ||
    typeof request.expectedAdminRegistrationSetDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(request.expectedAdminRegistrationSetDigest) ||
    request.expectedAdminRegistrationSetDigest !==
      worktreeAdminRegistrationSetDigest(expectedAdminRegistrationSet)
  ) {
    return null;
  }
  return Object.freeze({
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
    role,
    checkId: request.checkId,
    candidateCommit: request.candidateCommit,
    candidateTree: request.candidateTree,
    expectedConfigDigest: request.expectedConfigDigest,
    expectedObjectFormat: request.expectedObjectFormat,
    expectedDetached: request.expectedDetached,
    expectedCommonDirectoryDigest: request.expectedCommonDirectoryDigest,
    expectedWorktreeSet,
    expectedWorktreeSetDigest: request.expectedWorktreeSetDigest,
    expectedAdminRegistrationSet,
    expectedAdminRegistrationSetDigest:
      request.expectedAdminRegistrationSetDigest,
  });
}

function createRemoveWorktreeOperationRequest(
  registration: RegistrationStateV1,
): RemoveWorktreeOperationRequestV1 {
  if (
    registration.sourceRegistrationId === null ||
    registration.role === "principal-candidate" ||
    registration.role === "fixture-remote" ||
    registration.candidateCommit === null ||
    registration.candidateTree === null
  ) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["registration-conflict"],
    );
  }
  return Object.freeze({
    registrationId: registration.registrationId,
    sourceRegistrationId: registration.sourceRegistrationId,
    role: registration.role,
    checkId: registration.checkId,
    candidateCommit: registration.candidateCommit,
    candidateTree: registration.candidateTree,
    expectedConfigDigest: expectedGitConfigDigest(false),
    expectedObjectFormat: "sha256",
    expectedDetached: true,
    expectedCommonDirectoryDigest: registration.commonDirectoryDigest,
  });
}

function readRemoveWorktreeOperationRequest(
  value: unknown,
): RemoveWorktreeOperationRequestV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const request = value as Record<string, unknown>;
  const role = readWorktreeRole(request.role);
  if (
    typeof request.registrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.registrationId) ||
    typeof request.sourceRegistrationId !== "string" ||
    !SAFE_ID_PATTERN.test(request.sourceRegistrationId) ||
    role === null ||
    role === "principal-candidate" ||
    (request.checkId !== null &&
      (typeof request.checkId !== "string" ||
        !SAFE_ID_PATTERN.test(request.checkId))) ||
    typeof request.candidateCommit !== "string" ||
    !OBJECT_ID_PATTERN.test(request.candidateCommit) ||
    typeof request.candidateTree !== "string" ||
    !OBJECT_ID_PATTERN.test(request.candidateTree) ||
    request.expectedConfigDigest !== expectedGitConfigDigest(false) ||
    request.expectedObjectFormat !== "sha256" ||
    request.expectedDetached !== true ||
    typeof request.expectedCommonDirectoryDigest !== "string" ||
    !SHA256_HEX_PATTERN.test(request.expectedCommonDirectoryDigest)
  ) {
    return null;
  }
  return Object.freeze({
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
    role,
    checkId: request.checkId,
    candidateCommit: request.candidateCommit,
    candidateTree: request.candidateTree,
    expectedConfigDigest: request.expectedConfigDigest,
    expectedObjectFormat: request.expectedObjectFormat,
    expectedDetached: request.expectedDetached,
    expectedCommonDirectoryDigest: request.expectedCommonDirectoryDigest,
  });
}

function createRecoveryUnknownObservation(
  state: HarnessStateV1,
  operation: OperationStateV1,
  registrationId: string,
  operationKind: FixtureRepositoryObservationV1["operationKind"],
  purpose: FixtureRepositoryObservationV1["purpose"],
  repositoryIdentity?: FixtureRepositoryObservationV1["repositoryIdentity"],
): FixtureRepositoryObservationV1 {
  return operationConflictObservation(state, {
    operationId: operation.operationId,
    registrationId,
    operationKind,
    purpose,
    requestDigest: operation.requestDigest,
    diagnosticCode: "outcome-unknown",
    repositoryIdentity,
  });
}

function registrationMatchesWorktreeRequest(
  registration: RegistrationStateV1,
  request: CreateWorktreeOperationRequestV1 | RemoveWorktreeOperationRequestV1,
  expectedState: RegistrationStateV1["state"],
): boolean {
  return (
    registration.state === expectedState &&
    registration.role === request.role &&
    registration.sourceRegistrationId === request.sourceRegistrationId &&
    registration.checkId === request.checkId &&
    registration.candidateCommit === request.candidateCommit &&
    registration.candidateTree === request.candidateTree &&
    registration.commonDirectoryDigest === request.expectedCommonDirectoryDigest
  );
}

function requestDigestForRepository(
  policyId: string,
  request: CreateRepositoryRequestV1,
  files: readonly Readonly<FixtureFileV1>[],
): string {
  return computeFixtureRepositoryRequestDigestV1({
    policyId,
    operationId: request.operationId,
    registrationId: request.registrationId,
    files: files.map((file) => ({
      pathDigest: digestRelativePathV1(file.pathComponents),
      mode: file.mode,
      contentDigest: createHash("sha256").update(file.content).digest("hex"),
    })),
  });
}

function requestDigestForRemote(
  policyId: string,
  request: CreateBareRemoteRequestV1,
): string {
  return computeFixtureRepositoryRequestDigestV1({
    policyId,
    operationId: request.operationId,
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
  });
}

function requestDigestForWorktree(
  policyId: string,
  request: RegisterWorktreeRequestV1,
): string {
  return computeFixtureRepositoryRequestDigestV1({
    policyId,
    operationId: request.operationId,
    registrationId: request.registrationId,
    sourceRegistrationId: request.sourceRegistrationId,
    role: request.role,
    checkId: request.checkId,
    candidateCommit: request.candidateCommit,
    candidateTree: request.candidateTree,
  });
}

function validateRepositoryRequest(
  request: CreateRepositoryRequestV1,
): readonly Readonly<FixtureFileV1>[] {
  validateSafeId("operationId", request.operationId);
  validateSafeId("registrationId", request.registrationId);
  return snapshotFixtureFilesV1(request.files);
}

function validateRemoteRequest(request: CreateBareRemoteRequestV1): void {
  validateSafeId("operationId", request.operationId);
  validateSafeId("registrationId", request.registrationId);
  validateSafeId("sourceRegistrationId", request.sourceRegistrationId);
}

function validateWorktreeRequest(request: RegisterWorktreeRequestV1): void {
  validateSafeId("operationId", request.operationId);
  validateSafeId("registrationId", request.registrationId);
  validateSafeId("sourceRegistrationId", request.sourceRegistrationId);
  validateObjectId("candidateCommit", request.candidateCommit);
  validateObjectId("candidateTree", request.candidateTree);
  if (request.role === "named-check" && request.checkId === null) {
    throw new TypeError("named-check registrations require a check identifier");
  }
  if (request.checkId !== null) validateSafeId("checkId", request.checkId);
}

function hasTargetCollision(path: string): boolean {
  return existsSync(path);
}

function fixtureFileRelativePath(file: Readonly<FixtureFileV1>): string {
  return file.pathComponents.join("/");
}

function writeFixtureFile(path: string, file: Readonly<FixtureFileV1>): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, file.content, {
    mode: file.mode === "100755" ? 0o755 : 0o644,
  });
}

function candidateTreeForCommit(
  state: HarnessStateV1,
  registration: RegistrationStateV1,
  commit: string,
): string {
  const result = runGit(
    state,
    registration.path,
    ["rev-parse", `${commit}^{tree}`],
    {
      allowFailure: true,
      failureCode: "candidate-identity-drift",
    },
  );
  if (result.status !== 0) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["candidate-identity-drift"],
    );
  }
  return result.stdout.trim();
}

function operationConflictObservation(
  state: HarnessStateV1,
  input: {
    readonly operationId: string;
    readonly registrationId: string;
    readonly operationKind: FixtureRepositoryObservationV1["operationKind"];
    readonly purpose: FixtureRepositoryObservationV1["purpose"];
    readonly requestDigest: string;
    readonly diagnosticCode: FixtureDiagnosticCodeV1;
    readonly repositoryIdentity?: FixtureRepositoryObservationV1["repositoryIdentity"];
  },
): FixtureRepositoryObservationV1 {
  return createObservation(state, {
    operationId: input.operationId,
    registrationId: input.registrationId,
    operationKind: input.operationKind,
    purpose: input.purpose,
    sequence: currentSequence(state),
    repositoryIdentity: input.repositoryIdentity ?? {
      commonDirectoryDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-common-directory/1.0.0",
        "conflict",
      ),
      objectFormat: "sha256",
    },
    pre: null,
    post: null,
    outcome: input.diagnosticCode === "cancelled" ? "cancelled" : "blocked",
    diagnostic: createFixtureDiagnosticV1(input.diagnosticCode),
    requestDigest: input.requestDigest,
  });
}

function makeOperationState(record: OperationStageRecordV1): OperationStateV1 {
  return Object.freeze({
    operationId: record.operationId,
    kind: record.kind,
    requestDigest: record.requestDigest,
    latestStage: record.stage,
    latestSequence: record.sequence,
    latestRecordDigest: record.recordDigest,
    request: record.request,
    registrationId: record.registrationId,
    registrationDigest: record.registrationDigest,
    completed: record.stage === "completed",
    result: record.result,
  });
}

function storeOperationState(
  state: HarnessStateV1,
  record: OperationStageRecordV1,
): void {
  const operation = makeOperationState(record);
  state.operations.set(operation.operationId, operation);
  let registrations = state.operationsByRegistration.get(
    operation.registrationId,
  );
  if (!registrations) {
    registrations = new Set<string>();
    state.operationsByRegistration.set(operation.registrationId, registrations);
  }
  registrations.add(operation.operationId);
}

async function executeOperationWithLedger<T>(
  state: HarnessStateV1,
  input: {
    readonly operationId: string;
    readonly kind: OperationKindV1;
    readonly registrationId: string;
    readonly registrationDigest: string;
    readonly requestDigest: string;
    readonly request: unknown;
    readonly effect: () => Promise<T> | T;
  },
): Promise<T> {
  const existing = state.operations.get(input.operationId);
  if (existing && existing.completed) {
    if (existing.requestDigest !== input.requestDigest) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["operation-replay-conflict"],
      );
    }
    return existing.result as T;
  }
  let priorRecordDigest: string | null = null;
  const prepared = writeOperationStage(state, {
    operationId: input.operationId,
    kind: input.kind,
    registrationId: input.registrationId,
    registrationDigest: input.registrationDigest,
    requestDigest: input.requestDigest,
    request: input.request,
    sequence: 1,
    stage: "prepared",
    priorRecordDigest,
    terminalState: "pending",
    result: null,
  });
  storeOperationState(state, prepared);
  priorRecordDigest = prepared.recordDigest;
  maybeInjectFault(state, `${input.kind}:after-prepared`);

  const effectStarted = writeOperationStage(state, {
    operationId: input.operationId,
    kind: input.kind,
    registrationId: input.registrationId,
    registrationDigest: input.registrationDigest,
    requestDigest: input.requestDigest,
    request: input.request,
    sequence: 2,
    stage: "effect-started",
    priorRecordDigest,
    terminalState: "pending",
    result: null,
  });
  storeOperationState(state, effectStarted);
  priorRecordDigest = effectStarted.recordDigest;
  maybeInjectFault(state, `${input.kind}:after-effect-started`);

  const result = await input.effect();
  const effectObserved = writeOperationStage(state, {
    operationId: input.operationId,
    kind: input.kind,
    registrationId: input.registrationId,
    registrationDigest: input.registrationDigest,
    requestDigest: input.requestDigest,
    request: input.request,
    sequence: 3,
    stage: "effect-observed",
    priorRecordDigest,
    terminalState: terminalStateForResult(result),
    result,
  });
  storeOperationState(state, effectObserved);
  priorRecordDigest = effectObserved.recordDigest;
  maybeInjectFault(state, `${input.kind}:after-effect-observed`);

  const completed = writeOperationStage(state, {
    operationId: input.operationId,
    kind: input.kind,
    registrationId: input.registrationId,
    registrationDigest: input.registrationDigest,
    requestDigest: input.requestDigest,
    request: input.request,
    sequence: 4,
    stage: "completed",
    priorRecordDigest,
    terminalState: terminalStateForResult(result),
    result,
  });
  storeOperationState(state, completed);
  return result;
}

function terminalStateForResult(result: unknown): OperationTerminalStateV1 {
  if (
    typeof result === "object" &&
    result !== null &&
    "outcome" in result &&
    typeof (result as { outcome?: unknown }).outcome === "string"
  ) {
    const outcome = (result as { outcome: string }).outcome;
    if (
      outcome === "applied" ||
      outcome === "already-applied" ||
      outcome === "not-applied"
    ) {
      return outcome;
    }
    return outcome === "outcome-unknown" ? "outcome-unknown" : "blocked";
  }
  if (
    typeof result === "object" &&
    result !== null &&
    "valid" in result &&
    typeof (result as { valid?: unknown }).valid === "boolean"
  ) {
    const validationResult = result as ValidationResult<NamedCheckResultV1>;
    if (!validationResult.valid) return "blocked";
    return validationResult.value.outcome === "outcome-unknown"
      ? "outcome-unknown"
      : "applied";
  }
  return "applied";
}

function defaultRegistrationTuple(
  operationKind: OperationKindV1,
  request: unknown,
): { readonly registrationId: string; readonly registrationDigest: string } {
  const registrationId = String(
    (request as { readonly registrationId?: unknown }).registrationId ??
      "operation",
  );
  return {
    registrationId,
    registrationDigest: registrationDigestV1({ registrationId }),
  };
}

function hasIssuedNamedCheckPermit(
  state: HarnessStateV1,
  registrationId: string,
): boolean {
  return [...state.issuedPermits].some(
    (permit) => permit.registrationId === registrationId,
  );
}

function hasActiveNamedCheck(
  state: HarnessStateV1,
  registrationId: string,
): boolean {
  return [...state.activeNamedChecks.values()].some(
    (entry) => entry.registrationId === registrationId,
  );
}

function namedCheckRetentionDiagnostic(
  result: ValidationResult<NamedCheckResultV1> | null,
): "workspace-mutated" | "outcome-unknown" | null {
  if (!result || !result.valid) return null;
  if (result.value.outcome === "mutation-detected") {
    return "workspace-mutated";
  }
  if (result.value.outcome === "outcome-unknown") {
    return "outcome-unknown";
  }
  return null;
}

function observationRetentionDiagnostic(
  result: FixtureRepositoryObservationV1 | null,
): "outcome-unknown" | null {
  return result?.outcome === "outcome-unknown" ||
    result?.diagnostic?.code === "outcome-unknown"
    ? "outcome-unknown"
    : null;
}

function operationRetentionDiagnostic(
  operation: OperationStateV1,
): "workspace-mutated" | "outcome-unknown" | null {
  if (!operation.completed) return "outcome-unknown";
  if (operation.kind === "named-check") {
    return namedCheckRetentionDiagnostic(
      operation.result as ValidationResult<NamedCheckResultV1> | null,
    );
  }
  return observationRetentionDiagnostic(
    operation.result as FixtureRepositoryObservationV1 | null,
  );
}

function combineRetentionDiagnostic(
  current: "workspace-mutated" | "outcome-unknown" | null,
  candidate: "workspace-mutated" | "outcome-unknown" | null,
): "workspace-mutated" | "outcome-unknown" | null {
  if (current === "outcome-unknown" || candidate === "outcome-unknown") {
    return "outcome-unknown";
  }
  return current ?? candidate;
}

function registrationRetentionDiagnostic(
  state: HarnessStateV1,
  registrationId: string,
): "workspace-mutated" | "outcome-unknown" | null {
  let diagnostic: "workspace-mutated" | "outcome-unknown" | null = null;
  for (const operationId of state.operationsByRegistration.get(
    registrationId,
  ) ?? []) {
    const operation = state.operations.get(operationId);
    if (!operation) continue;
    diagnostic = combineRetentionDiagnostic(
      diagnostic,
      operationRetentionDiagnostic(operation),
    );
    if (diagnostic === "outcome-unknown") return diagnostic;
  }
  return diagnostic;
}

function runRetentionDiagnostic(
  state: HarnessStateV1,
): "workspace-mutated" | "outcome-unknown" | null {
  if (state.status === "recovery-required") return "outcome-unknown";
  let diagnostic: "workspace-mutated" | "outcome-unknown" | null = null;
  for (const operation of state.operations.values()) {
    diagnostic = combineRetentionDiagnostic(
      diagnostic,
      operationRetentionDiagnostic(operation),
    );
    if (diagnostic === "outcome-unknown") return diagnostic;
  }
  return diagnostic;
}

async function settleNamedCheckCancellation(
  state: HarnessStateV1,
): Promise<boolean> {
  for (const permit of state.issuedPermits) {
    cancelNamedCheckPermitV1(permit);
  }
  for (const execution of state.activeNamedChecks.values()) {
    execution.controller.abort();
  }
  const settled = await Promise.allSettled(
    [...state.activeNamedChecks.values()].map((entry) => entry.promise),
  );
  let recoveryRequired = false;
  for (const result of settled) {
    if (result.status === "rejected") {
      recoveryRequired = true;
      continue;
    }
    if (!result.value.valid) {
      recoveryRequired = true;
      continue;
    }
    if (result.value.value.outcome === "outcome-unknown") {
      recoveryRequired = true;
    }
  }
  state.issuedPermits.clear();
  return recoveryRequired;
}

async function cancelHarnessState(state: HarnessStateV1): Promise<void> {
  if (!state.policyState.revoked) ensureHarnessState(state, true);
  if (state.status === "removed" || state.status === "recovery-required")
    return;
  if (state.status === "cancelled") return;
  state.status = "cancelling";
  const recoveryRequired = await settleNamedCheckCancellation(state);
  state.status = recoveryRequired ? "recovery-required" : "cancelled";
}

async function closeHarnessState(state: HarnessStateV1): Promise<void> {
  if (!state.policyState.revoked) ensureHarnessState(state, true);
  if (state.status === "removed" || state.status === "recovery-required")
    return;
  if (state.status === "closed") return;
  state.status = "closing";
  const recoveryRequired = await settleNamedCheckCancellation(state);
  state.status = recoveryRequired ? "recovery-required" : "closed";
}

function cleanupRootProofError(): TypeError {
  return new TypeError("fixture cleanup root proof is invalid");
}

function validateCleanupRegistrationState(state: HarnessStateV1): void {
  for (const registration of state.registrations.values()) {
    if (
      registration.role === "independent-verifier" ||
      registration.role === "named-check"
    ) {
      if (registration.state !== "removed" || existsSync(registration.path)) {
        throw cleanupRootProofError();
      }
      continue;
    }
    if (registration.state !== "retained" || !existsSync(registration.path)) {
      throw cleanupRootProofError();
    }
    const configState = validateExactGitConfig(registration.path);
    if (
      configState === null ||
      configState.bare !== (registration.role === "fixture-remote") ||
      configState.digest !== registration.commonConfigDigest
    ) {
      throw cleanupRootProofError();
    }
    if (registration.role === "fixture-remote") {
      assertHostileStateAbsent(state, registration.path, true);
      countGitObjects(state, registration.path, true);
      const objectFormat = readObjectFormat(state, registration.path, true);
      const branch = readBranch(state, registration.path, true);
      const headCommit = runGit(
        state,
        registration.path,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        { allowClosed: true },
      ).stdout.trim();
      const headTree = runGit(
        state,
        registration.path,
        ["rev-parse", "HEAD^{tree}"],
        {
          allowClosed: true,
        },
      ).stdout.trim();
      if (
        directoryDigest(snapshotDirectoryIdentity(registration.path)) !==
          registration.commonDirectoryDigest ||
        objectFormat !== "sha256" ||
        branch !== "fixture-main" ||
        (registration.candidateCommit !== null &&
          headCommit !== registration.candidateCommit) ||
        (registration.candidateTree !== null &&
          headTree !== registration.candidateTree)
      ) {
        throw cleanupRootProofError();
      }
      continue;
    }
    const observation = observeRepositoryState(state, registration.path, true);
    if (
      observation.repositoryIdentity.commonDirectoryDigest !==
        registration.commonDirectoryDigest ||
      observation.repositoryIdentity.objectFormat !== "sha256" ||
      observation.state.branch !== "fixture-main" ||
      !observation.state.clean ||
      (registration.candidateCommit !== null &&
        observation.state.headCommit !== registration.candidateCommit) ||
      (registration.candidateTree !== null &&
        observation.state.headTree !== registration.candidateTree)
    ) {
      throw cleanupRootProofError();
    }
  }
}

type CleanupEntryKindV1 = "directory" | "file" | "opaque-directory";

function expectedCleanupEntries(
  state: HarnessStateV1,
  relativePath: readonly string[],
): ReadonlyMap<string, CleanupEntryKindV1> | null {
  const entries = new Map<string, CleanupEntryKindV1>();
  if (relativePath.length === 0) {
    for (const name of ROOT_DIR_NAMES) entries.set(name, "directory");
    return entries;
  }
  const [head, second, third] = relativePath;
  if (
    head === "home" ||
    head === "hooks-disabled" ||
    head === "quarantine" ||
    head === "worktrees"
  ) {
    return relativePath.length === 1 ? entries : null;
  }
  if (head === "repositories") {
    if (relativePath.length === 1) {
      for (const registration of state.registrations.values()) {
        if (registration.role === "principal-candidate") {
          entries.set(registration.registrationDigest, "opaque-directory");
        }
      }
      return entries;
    }
    return null;
  }
  if (head === "remotes") {
    if (relativePath.length === 1) {
      for (const registration of state.registrations.values()) {
        if (registration.role === "fixture-remote") {
          entries.set(
            `${registration.registrationDigest}.git`,
            "opaque-directory",
          );
        }
      }
      return entries;
    }
    return null;
  }
  if (head === "transactions") {
    if (relativePath.length === 1) {
      for (const operation of state.operations.values()) {
        entries.set(
          `${operationDigest(state.runDigest, operation.operationId)}.head`,
          "file",
        );
      }
      return entries;
    }
    return null;
  }
  if (head !== "metadata") return null;
  if (relativePath.length === 1) {
    entries.set(ROOT_MANIFEST_FILE, "file");
    entries.set("operations", "directory");
    entries.set("registrations", "directory");
    return entries;
  }
  if (second === "operations") {
    if (relativePath.length === 2) {
      for (const operation of state.operations.values()) {
        entries.set(
          operationDigest(state.runDigest, operation.operationId),
          "directory",
        );
      }
      return entries;
    }
    if (relativePath.length === 3) {
      const operation = [...state.operations.values()].find(
        (entry) =>
          operationDigest(state.runDigest, entry.operationId) === third,
      );
      if (!operation) return null;
      entries.set("000001-prepared.json", "file");
      entries.set("000002-effect-started.json", "file");
      entries.set("000003-effect-observed.json", "file");
      entries.set("000004-completed.json", "file");
      return entries;
    }
    return null;
  }
  if (second !== "registrations") return null;
  if (relativePath.length === 2) {
    for (const registration of state.registrations.values()) {
      entries.set(registration.registrationDigest, "directory");
    }
    return entries;
  }
  if (relativePath.length === 3) {
    const registration = [...state.registrations.values()].find(
      (entry) => entry.registrationDigest === third,
    );
    if (!registration) return null;
    for (
      let generation = 1;
      generation <= registration.generation;
      generation += 1
    ) {
      entries.set(`${generation}.json`, "file");
    }
    return entries;
  }
  return null;
}

function validateCleanupOpaqueDirectory(
  rootDevice: number,
  limits: Readonly<FixtureLimitsV1>,
  path: string,
  counters: { entries: number; bytes: number },
): void {
  const entries = readdirSync(path, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  for (const entry of entries) {
    const absolutePath = join(path, entry.name);
    const stat = lstatSync(absolutePath);
    counters.entries += 1;
    counters.bytes += stat.size;
    if (
      counters.entries > limits.maxCleanupEntries ||
      counters.bytes > limits.maxCleanupBytes ||
      stat.dev !== rootDevice ||
      stat.isSymbolicLink() ||
      !(stat.isDirectory() || stat.isFile()) ||
      (stat.isFile() && stat.nlink !== 1)
    ) {
      throw cleanupRootProofError();
    }
    if (stat.isDirectory()) {
      validateCleanupOpaqueDirectory(
        rootDevice,
        limits,
        absolutePath,
        counters,
      );
    }
  }
}

function validateCleanupRootContents(state: HarnessStateV1): void {
  validateCleanupRegistrationState(state);
  const counters = { entries: 0, bytes: 0 };
  const rootDevice = state.rootIdentity.device;
  const walk = (absolutePath: string, relativePath: readonly string[]) => {
    const expected = expectedCleanupEntries(state, relativePath);
    if (!expected) throw cleanupRootProofError();
    const entries = readdirSync(absolutePath, { withFileTypes: true }).sort(
      (left, right) => left.name.localeCompare(right.name),
    );
    if (entries.length !== expected.size) throw cleanupRootProofError();
    for (const entry of entries) {
      const kind = expected.get(entry.name);
      if (!kind) throw cleanupRootProofError();
      const entryPath = join(absolutePath, entry.name);
      const stat = lstatSync(entryPath);
      counters.entries += 1;
      counters.bytes += stat.size;
      if (
        counters.entries > state.policyState.limits.maxCleanupEntries ||
        counters.bytes > state.policyState.limits.maxCleanupBytes ||
        stat.dev !== rootDevice ||
        stat.isSymbolicLink() ||
        !(stat.isDirectory() || stat.isFile()) ||
        (stat.isFile() && stat.nlink !== 1)
      ) {
        throw cleanupRootProofError();
      }
      if (kind === "file") {
        if (!stat.isFile()) throw cleanupRootProofError();
        continue;
      }
      if (!stat.isDirectory()) throw cleanupRootProofError();
      if (kind === "opaque-directory") {
        validateCleanupOpaqueDirectory(
          rootDevice,
          state.policyState.limits,
          entryPath,
          counters,
        );
        continue;
      }
      walk(entryPath, [...relativePath, entry.name]);
    }
  };
  walk(state.rootPath, []);
}

function createHarnessObject(
  policy: TrustedFixtureGitPolicyV1,
  state: HarnessStateV1,
): FixtureRepositoryHarnessV1 {
  const harness: FixtureRepositoryHarnessV1 = Object.freeze({
    runId: state.runId,
    taskId: state.taskId,
    expectedBaseCommit: state.expectedBaseCommit,
    expectedBaseTree: state.expectedBaseTree,
    policyId: policy.policyId,
    createRepository: async (request: CreateRepositoryRequestV1) =>
      createRepository(harness, request),
    createBareRemote: async (request: CreateBareRemoteRequestV1) =>
      createBareRemote(harness, request),
    createWorktree: async (request: RegisterWorktreeRequestV1) =>
      createWorktree(harness, request),
    inspectWorktrees: async (operationId: string) =>
      inspectWorktrees(harness, operationId),
    removeWorktree: async (operationId: string, registrationId: string) =>
      removeWorktree(harness, operationId, registrationId),
    issueNamedCheckPermitV1: async (
      request: IssueHarnessNamedCheckPermitV1Input,
    ) => issueHarnessNamedCheckPermitV1(harness, request),
    runNamedCheckV1: async (request: RunNamedCheckRequestV1) =>
      runHarnessNamedCheckV1(harness, request),
    cancel: async () => cancelHarnessState(requireHarnessState(harness)),
    close: async () => closeHarnessState(requireHarnessState(harness)),
    cleanup: async () => cleanupHarness(harness),
  });
  HARNESS_STATE.set(harness, state);
  state.policyState.harnesses.add(harness);
  return harness;
}

function cleanupHarness(harness: FixtureRepositoryHarnessV1): void {
  const state = requireHarnessState(harness);
  ensureHarnessState(state, true);
  if (state.status === "recovery-required") {
    throw new TypeError(
      "fixture cleanup must retain recovery-required evidence",
    );
  }
  if (state.status !== "closed" && state.status !== "cancelled") {
    throw new TypeError("fixture cleanup requires a closed harness");
  }
  if (state.issuedPermits.size > 0 || state.activeNamedChecks.size > 0) {
    throw new TypeError(
      "fixture cleanup must retain live named-check authority evidence",
    );
  }
  if (
    [...state.operations.values()].some((operation) => !operation.completed)
  ) {
    throw new TypeError(
      "fixture cleanup must retain recovery-required evidence",
    );
  }
  if (runRetentionDiagnostic(state) !== null) {
    throw new TypeError(
      "fixture cleanup must retain mutation or unknown evidence",
    );
  }
  for (const registration of state.registrations.values()) {
    if (
      (registration.role === "independent-verifier" ||
        registration.role === "named-check") &&
      registration.state !== "removed"
    ) {
      throw new TypeError(
        "fixture cleanup requires disposable worktrees to be removed",
      );
    }
  }
  validateCleanupRootContents(state);
  rmSync(state.rootPath, { recursive: true, force: false });
  state.status = "removed";
}

function validateRootManifest(
  manifest: RootManifestV1,
  expected: HarnessStateV1,
): void {
  if (
    manifest.policyId !== expected.policyState.publicPolicy.policyId ||
    manifest.runId !== expected.runId ||
    manifest.taskId !== expected.taskId ||
    manifest.expectedBaseCommit !== expected.expectedBaseCommit ||
    manifest.expectedBaseTree !== expected.expectedBaseTree ||
    manifest.runDigest !== expected.runDigest ||
    manifest.manifestDigest !==
      computeGitCheckFixtureDigestV1("spts.fixture-operation-record/1.0.0", {
        contract: manifest.contract,
        version: manifest.version,
        policyId: manifest.policyId,
        runId: manifest.runId,
        taskId: manifest.taskId,
        expectedBaseCommit: manifest.expectedBaseCommit,
        expectedBaseTree: manifest.expectedBaseTree,
        runDigest: manifest.runDigest,
        parentDigest: manifest.parentDigest,
        rootDigest: manifest.rootDigest,
        limitsDigest: manifest.limitsDigest,
      })
  ) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["run-identity-conflict"],
    );
  }
}

function loadRegistrationState(state: HarnessStateV1): void {
  if (!existsSync(state.directories.registrations)) return;
  for (const digest of readdirSync(state.directories.registrations)) {
    const directory = join(state.directories.registrations, digest);
    if (!statSync(directory).isDirectory()) continue;
    const generations = readdirSync(directory)
      .filter((entry) => entry.endsWith(".json"))
      .map((entry) => Number.parseInt(entry.replace(/\.json$/u, ""), 10))
      .filter((value) => Number.isSafeInteger(value))
      .sort((left, right) => left - right);
    const latest = generations.at(-1);
    if (latest === undefined) continue;
    const record = readCanonicalJson<
      ReturnType<typeof createRegistrationRecordV1>
    >(join(directory, `${latest}.json`));
    const path =
      record.role === "fixture-remote"
        ? join(state.directories.remotes, `${digest}.git`)
        : record.role === "principal-candidate"
          ? join(state.directories.repositories, digest)
          : join(state.directories.worktrees, digest);
    let commonDirectory = path;
    let adminDirectory = path;
    if (existsSync(path)) {
      try {
        commonDirectory =
          record.role === "fixture-remote"
            ? path
            : readGitCommonDir(state, path);
        adminDirectory =
          record.role === "fixture-remote"
            ? path
            : readGitAbsoluteDir(state, path);
      } catch {
        commonDirectory = path;
        adminDirectory = path;
      }
    }
    let configState: {
      readonly digest: string;
      readonly bare: boolean;
    } | null = null;
    if (existsSync(path)) {
      try {
        configState = validateExactGitConfig(path);
      } catch {
        configState = null;
      }
    }
    state.registrations.set(record.registrationId, {
      registrationId: record.registrationId,
      registrationDigest: record.registrationDigest,
      role: record.role,
      checkId: record.checkId,
      sourceRegistrationId: record.sourceRegistrationId,
      path,
      commonDirectory,
      adminDirectory,
      commonDirectoryDigest: record.commonDirectoryDigest,
      rootIdentity: readStoredTargetRootIdentity(record.rootIdentity),
      sourceCommonDirectoryDigest: null,
      commonConfigDigest:
        configState?.digest ??
        expectedGitConfigDigest(record.role === "fixture-remote"),
      candidateCommit: record.candidateCommit,
      candidateTree: record.candidateTree,
      state: record.state,
      generation: record.generation,
      cleanupBlockedReason: null,
    });
  }
}

function validateLoadedOperationRecords(
  state: HarnessStateV1,
  operationDigestValue: string,
  filenames: readonly string[],
  records: readonly OperationStageRecordV1[],
): void {
  const expectedPrefix: readonly OperationStageV1[] = [
    "prepared",
    "effect-started",
    "effect-observed",
  ];
  if (records.length === 0 || records.length > 4) {
    throw recoveryIntegrityError();
  }
  const expectedPairs: Array<readonly [number, OperationStageV1]> = [];
  for (let index = 0; index < records.length; index += 1) {
    if (
      index === records.length - 1 &&
      records.length > 1 &&
      records[index]!.stage === "completed"
    ) {
      expectedPairs.push([4, "completed"]);
      break;
    }
    if (index >= expectedPrefix.length) {
      throw recoveryIntegrityError();
    }
    expectedPairs.push([index + 1, expectedPrefix[index]!]);
  }
  if (expectedPairs.length !== records.length || expectedPairs[0]?.[0] !== 1) {
    throw recoveryIntegrityError();
  }
  let priorRecordDigest: string | null = null;
  const first = records[0]!;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index]!;
    const [expectedSequence, expectedStage] = expectedPairs[index]!;
    if (
      filenames[index] !== stageFilename(expectedSequence, expectedStage) ||
      record.runDigest !== state.runDigest ||
      record.manifestDigest !== state.manifest.manifestDigest ||
      record.operationDigest !== operationDigestValue ||
      record.operationDigest !==
        operationDigest(state.runDigest, record.operationId) ||
      record.sequence !== expectedSequence ||
      record.stage !== expectedStage ||
      record.kind !== first.kind ||
      record.registrationId !== first.registrationId ||
      record.registrationDigest !== first.registrationDigest ||
      record.requestDigest !== first.requestDigest ||
      canonicalizeGitCheckFixtureValueV1(record.request) !==
        canonicalizeGitCheckFixtureValueV1(first.request) ||
      record.priorRecordDigest !== priorRecordDigest ||
      (record.result === null) !== (record.resultDigest === null) ||
      (record.result !== null &&
        record.resultDigest !== stageResultDigest(record.result))
    ) {
      throw recoveryIntegrityError();
    }
    priorRecordDigest = record.recordDigest;
  }
}

function validateTransactionHints(state: HarnessStateV1): void {
  const entries = readdirSync(state.directories.transactions, {
    withFileTypes: true,
  }).sort((left, right) => left.name.localeCompare(right.name));
  const expectedNames = [...state.operations.values()]
    .map((operation) => ({
      name: `${operationDigest(state.runDigest, operation.operationId)}.head`,
      operation,
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (entries.length !== expectedNames.length) throw recoveryIntegrityError();
  for (const [index, entry] of entries.entries()) {
    const expected = expectedNames[index];
    if (!expected || entry.name !== expected.name) {
      throw recoveryIntegrityError();
    }
    const stat = lstatSync(join(state.directories.transactions, entry.name));
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw recoveryIntegrityError();
    }
    const hint = readCanonicalJson<{
      readonly sequence: number;
      readonly recordDigest: string;
    }>(join(state.directories.transactions, entry.name));
    if (
      hint.sequence !== expected.operation.latestSequence ||
      hint.recordDigest !== expected.operation.latestRecordDigest
    ) {
      throw recoveryIntegrityError();
    }
  }
}

function loadOperationStates(state: HarnessStateV1): void {
  const operationEntries = readdirSync(state.directories.operations, {
    withFileTypes: true,
  }).sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of operationEntries) {
    const directory = join(state.directories.operations, entry.name);
    const stat = lstatSync(directory);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw recoveryIntegrityError();
    }
    const filenames = readdirSync(directory).sort((left, right) =>
      left.localeCompare(right),
    );
    if (
      filenames.length === 0 ||
      filenames.some((filename) => !filename.endsWith(".json"))
    ) {
      throw recoveryIntegrityError();
    }
    const records = filenames.map((filename) =>
      loadStageRecord(join(directory, filename)),
    );
    validateLoadedOperationRecords(state, entry.name, filenames, records);
    storeOperationState(state, records.at(-1)!);
  }
  if (state.registrations.size > 0 && state.operations.size === 0) {
    throw recoveryIntegrityError();
  }
  validateTransactionHints(state);
}

function recoverIncompleteOperations(state: HarnessStateV1): void {
  for (const operation of [...state.operations.values()]) {
    if (operation.completed) {
      if (operation.kind === "named-check" && operation.result) {
        const request = operation.request as {
          readonly registrationId: string;
        };
        const registration = state.registrations.get(request.registrationId);
        if (registration) {
          updateRegistrationCleanupState(
            registration,
            operation.result as ValidationResult<NamedCheckResultV1>,
          );
        }
      }
      continue;
    }
    const tuple = defaultRegistrationTuple(operation.kind, operation.request);
    if (operation.kind === "create-repository") {
      const repositoryPath = join(
        state.directories.repositories,
        tuple.registrationDigest,
      );
      const request = readCreateRepositoryOperationRequest(operation.request);
      if (!existsSync(repositoryPath)) {
        const result =
          operation.latestStage === "prepared"
            ? createObservation(state, {
                operationId: operation.operationId,
                registrationId: tuple.registrationId,
                operationKind: "create-repository",
                purpose: "principal-candidate",
                sequence: currentSequence(state),
                repositoryIdentity: {
                  commonDirectoryDigest: computeGitCheckFixtureDigestV1(
                    "spts.fixture-common-directory/1.0.0",
                    repositoryPath,
                  ),
                  objectFormat: "sha256",
                },
                pre: null,
                post: null,
                outcome: "not-applied",
                diagnostic: null,
                requestDigest: operation.requestDigest,
              })
            : operationConflictObservation(state, {
                operationId: operation.operationId,
                registrationId: tuple.registrationId,
                operationKind: "create-repository",
                purpose: "principal-candidate",
                requestDigest: operation.requestDigest,
                diagnosticCode: "outcome-unknown",
              });
        const completed = writeOperationStage(state, {
          operationId: operation.operationId,
          kind: operation.kind,
          registrationId: tuple.registrationId,
          registrationDigest: tuple.registrationDigest,
          requestDigest: operation.requestDigest,
          request: operation.request,
          sequence: 4,
          stage: "completed",
          priorRecordDigest: operation.latestRecordDigest,
          terminalState: terminalStateForResult(result),
          result,
        });
        storeOperationState(state, completed);
        continue;
      }
      if (!request) {
        storeOperationState(
          state,
          createRepositoryRecoveryConflict(
            state,
            operation,
            tuple.registrationId,
          ),
        );
        continue;
      }
      let observation;
      let configState;
      try {
        configState = validateExactGitConfig(repositoryPath);
        observation = observeRepositoryState(state, repositoryPath, true);
      } catch {
        storeOperationState(
          state,
          createRepositoryRecoveryConflict(
            state,
            operation,
            tuple.registrationId,
          ),
        );
        continue;
      }
      const expectedPostcondition = repositoryRecoveryPostcondition(operation);
      const registration = state.registrations.get(tuple.registrationId);
      const exactMatch =
        registration !== undefined &&
        registration.role === "principal-candidate" &&
        registration.state === "retained" &&
        registration.sourceRegistrationId === null &&
        registration.candidateCommit === observation.state.headCommit &&
        registration.candidateTree === observation.state.headTree &&
        registration.commonDirectoryDigest ===
          observation.repositoryIdentity.commonDirectoryDigest &&
        registrationRootIdentityMatches(state, registration) &&
        configState !== null &&
        configState.bare === false &&
        configState.digest === request.expectedConfigDigest &&
        observation.repositoryIdentity.objectFormat ===
          request.expectedObjectFormat &&
        observation.state.branch === request.expectedBranch &&
        observation.state.clean &&
        repositoryProjectionMatchesRequest(repositoryPath, request) &&
        expectedPostcondition !== null &&
        observation.state.headCommit === expectedPostcondition.headCommit &&
        observation.state.headTree === expectedPostcondition.headTree &&
        observation.repositoryIdentity.objectFormat ===
          expectedPostcondition.objectFormat;
      if (!exactMatch) {
        storeOperationState(
          state,
          createRepositoryRecoveryConflict(
            state,
            operation,
            tuple.registrationId,
            observation.repositoryIdentity,
          ),
        );
        continue;
      }
      const result = createObservation(state, {
        operationId: operation.operationId,
        registrationId: tuple.registrationId,
        operationKind: "create-repository",
        purpose: "principal-candidate",
        sequence: currentSequence(state),
        repositoryIdentity: observation.repositoryIdentity,
        pre: null,
        post: observation.state,
        outcome: "already-applied",
        diagnostic: null,
        requestDigest: operation.requestDigest,
      });
      const completed = writeOperationStage(state, {
        operationId: operation.operationId,
        kind: operation.kind,
        registrationId: tuple.registrationId,
        registrationDigest: tuple.registrationDigest,
        requestDigest: operation.requestDigest,
        request: operation.request,
        sequence: 4,
        stage: "completed",
        priorRecordDigest: operation.latestRecordDigest,
        terminalState: terminalStateForResult(result),
        result,
      });
      storeOperationState(state, completed);
      continue;
    }
    if (operation.kind === "create-bare-remote") {
      const request = readCreateBareRemoteOperationRequest(operation.request);
      const remotePath = join(
        state.directories.remotes,
        `${tuple.registrationDigest}.git`,
      );
      const registration = state.registrations.get(tuple.registrationId);
      if (!existsSync(remotePath)) {
        const result =
          operation.latestStage === "prepared" && registration === undefined
            ? createObservation(state, {
                operationId: operation.operationId,
                registrationId: tuple.registrationId,
                operationKind: "create-bare-remote",
                purpose: "fixture-remote",
                sequence: currentSequence(state),
                repositoryIdentity: {
                  commonDirectoryDigest: computeGitCheckFixtureDigestV1(
                    "spts.fixture-common-directory/1.0.0",
                    remotePath,
                  ),
                  objectFormat: "sha256",
                },
                pre: null,
                post: null,
                outcome: "not-applied",
                diagnostic: null,
                requestDigest: operation.requestDigest,
              })
            : createRecoveryUnknownObservation(
                state,
                operation,
                tuple.registrationId,
                "create-bare-remote",
                "fixture-remote",
              );
        completeRecoveredOperation(state, operation, result);
        continue;
      }
      if (!request) {
        completeRecoveredOperation(
          state,
          operation,
          createRecoveryUnknownObservation(
            state,
            operation,
            tuple.registrationId,
            "create-bare-remote",
            "fixture-remote",
          ),
        );
        continue;
      }
      try {
        const configState = validateExactGitConfig(remotePath);
        const observation = observeBareRepositoryState(state, remotePath, true);
        const source = state.registrations.get(request.sourceRegistrationId);
        const headReference = readHeadReference(state, remotePath, true);
        const refs = readBareRemoteRefs(state, remotePath, true);
        const exactMatch =
          registration !== undefined &&
          registration.state === "retained" &&
          registration.role === "fixture-remote" &&
          registration.sourceRegistrationId === request.sourceRegistrationId &&
          registration.candidateCommit === request.expectedCommit &&
          registration.candidateTree === request.expectedTree &&
          registrationRootIdentityMatches(state, registration) &&
          registration.commonDirectoryDigest ===
            observation.repositoryIdentity.commonDirectoryDigest &&
          configState !== null &&
          configState.bare &&
          configState.digest === request.expectedConfigDigest &&
          observation.repositoryIdentity.objectFormat ===
            request.expectedObjectFormat &&
          observation.branch === request.expectedBranch &&
          headReference === request.expectedHeadRef &&
          sameFixtureValue(refs, request.expectedRefs) &&
          bareRemoteRefSetDigest(refs) === request.expectedRefSetDigest &&
          observation.headCommit === request.expectedCommit &&
          observation.headTree === request.expectedTree &&
          source?.commonDirectoryDigest ===
            request.expectedSourceCommonDirectoryDigest;
        const result = exactMatch
          ? createObservation(state, {
              operationId: operation.operationId,
              registrationId: tuple.registrationId,
              operationKind: "create-bare-remote",
              purpose: "fixture-remote",
              sequence: currentSequence(state),
              repositoryIdentity: observation.repositoryIdentity,
              pre: null,
              post: null,
              outcome: "already-applied",
              diagnostic: null,
              requestDigest: operation.requestDigest,
            })
          : createRecoveryUnknownObservation(
              state,
              operation,
              tuple.registrationId,
              "create-bare-remote",
              "fixture-remote",
              observation.repositoryIdentity,
            );
        completeRecoveredOperation(state, operation, result);
      } catch {
        completeRecoveredOperation(
          state,
          operation,
          createRecoveryUnknownObservation(
            state,
            operation,
            tuple.registrationId,
            "create-bare-remote",
            "fixture-remote",
          ),
        );
      }
      continue;
    }
    if (operation.kind === "create-worktree") {
      const request = readCreateWorktreeOperationRequest(operation.request);
      const worktreePath = join(
        state.directories.worktrees,
        tuple.registrationDigest,
      );
      const registration = state.registrations.get(tuple.registrationId);
      if (!existsSync(worktreePath)) {
        const result =
          operation.latestStage === "prepared" && registration === undefined
            ? createObservation(state, {
                operationId: operation.operationId,
                registrationId: tuple.registrationId,
                operationKind: "create-worktree",
                purpose: request?.role ?? "named-check",
                sequence: currentSequence(state),
                repositoryIdentity: {
                  commonDirectoryDigest:
                    request?.expectedCommonDirectoryDigest ??
                    computeGitCheckFixtureDigestV1(
                      "spts.fixture-common-directory/1.0.0",
                      worktreePath,
                    ),
                  objectFormat: "sha256",
                },
                pre: null,
                post: null,
                outcome: "not-applied",
                diagnostic: null,
                requestDigest: operation.requestDigest,
              })
            : createRecoveryUnknownObservation(
                state,
                operation,
                tuple.registrationId,
                "create-worktree",
                request?.role ?? "named-check",
              );
        completeRecoveredOperation(state, operation, result);
        continue;
      }
      if (!request) {
        completeRecoveredOperation(
          state,
          operation,
          createRecoveryUnknownObservation(
            state,
            operation,
            tuple.registrationId,
            "create-worktree",
            "named-check",
          ),
        );
        continue;
      }
      try {
        const configState = validateExactGitConfig(worktreePath);
        const observation = observeRepositoryState(state, worktreePath, true);
        const source = state.registrations.get(request.sourceRegistrationId);
        const actualWorktreeSet =
          source === undefined
            ? null
            : parseWorktreeList(state, source.path, true);
        const actualAdminRegistrationSet =
          source === undefined
            ? null
            : observeAdminWorktreeRegistrationSet(
                state,
                source.commonDirectory,
              );
        const exactMatch =
          registration !== undefined &&
          registrationMatchesWorktreeRequest(registration, request, "active") &&
          registrationRootIdentityMatches(state, registration) &&
          configState !== null &&
          !configState.bare &&
          configState.digest === request.expectedConfigDigest &&
          observation.repositoryIdentity.commonDirectoryDigest ===
            request.expectedCommonDirectoryDigest &&
          observation.repositoryIdentity.objectFormat ===
            request.expectedObjectFormat &&
          observation.state.branch === null &&
          observation.state.detached === request.expectedDetached &&
          observation.state.clean &&
          observation.state.headCommit === request.candidateCommit &&
          observation.state.headTree === request.candidateTree &&
          observation.state.worktreeSetDigest ===
            request.expectedWorktreeSetDigest &&
          source !== undefined &&
          source.commonDirectoryDigest ===
            request.expectedCommonDirectoryDigest &&
          actualWorktreeSet !== null &&
          sameFixtureValue(actualWorktreeSet, request.expectedWorktreeSet) &&
          computeGitCheckFixtureDigestV1(
            "spts.fixture-worktree-set/1.0.0",
            actualWorktreeSet,
          ) === request.expectedWorktreeSetDigest &&
          actualAdminRegistrationSet !== null &&
          sameFixtureValue(
            actualAdminRegistrationSet,
            request.expectedAdminRegistrationSet,
          ) &&
          worktreeAdminRegistrationSetDigest(actualAdminRegistrationSet) ===
            request.expectedAdminRegistrationSetDigest;
        const result = exactMatch
          ? createObservation(state, {
              operationId: operation.operationId,
              registrationId: tuple.registrationId,
              operationKind: "create-worktree",
              purpose: request.role,
              sequence: currentSequence(state),
              repositoryIdentity: observation.repositoryIdentity,
              pre: null,
              post: observation.state,
              outcome: "already-applied",
              diagnostic: null,
              requestDigest: operation.requestDigest,
            })
          : createRecoveryUnknownObservation(
              state,
              operation,
              tuple.registrationId,
              "create-worktree",
              request.role,
              observation.repositoryIdentity,
            );
        completeRecoveredOperation(state, operation, result);
      } catch {
        completeRecoveredOperation(
          state,
          operation,
          createRecoveryUnknownObservation(
            state,
            operation,
            tuple.registrationId,
            "create-worktree",
            request.role,
          ),
        );
      }
      continue;
    }
    if (operation.kind === "remove-worktree") {
      const request = readRemoveWorktreeOperationRequest(operation.request);
      const registration = state.registrations.get(tuple.registrationId);
      const source = request
        ? state.registrations.get(request.sourceRegistrationId)
        : undefined;
      const worktreePath = join(
        state.directories.worktrees,
        tuple.registrationDigest,
      );
      const effectObserved =
        operation.result as FixtureRepositoryObservationV1 | null;
      if (!request) {
        completeRecoveredOperation(
          state,
          operation,
          createRecoveryUnknownObservation(
            state,
            operation,
            tuple.registrationId,
            "remove-worktree",
            "named-check",
          ),
        );
        continue;
      }
      const adminPath =
        source === undefined
          ? null
          : join(source.commonDirectory, "worktrees", tuple.registrationDigest);
      if (operation.latestStage === "prepared") {
        try {
          const observation = observeRepositoryState(state, worktreePath, true);
          const configState = validateExactGitConfig(worktreePath);
          const exactMatch =
            registration !== undefined &&
            registrationMatchesWorktreeRequest(
              registration,
              request,
              "active",
            ) &&
            registrationRootIdentityMatches(state, registration) &&
            source !== undefined &&
            source.commonDirectoryDigest ===
              request.expectedCommonDirectoryDigest &&
            configState !== null &&
            !configState.bare &&
            configState.digest === request.expectedConfigDigest &&
            observation.repositoryIdentity.commonDirectoryDigest ===
              request.expectedCommonDirectoryDigest &&
            observation.repositoryIdentity.objectFormat ===
              request.expectedObjectFormat &&
            observation.state.branch === null &&
            observation.state.detached === request.expectedDetached &&
            observation.state.clean &&
            observation.state.headCommit === request.candidateCommit &&
            observation.state.headTree === request.candidateTree &&
            worktreeSetContainsPath(state, source.path, worktreePath, true);
          const result = exactMatch
            ? createObservation(state, {
                operationId: operation.operationId,
                registrationId: tuple.registrationId,
                operationKind: "remove-worktree",
                purpose: request.role,
                sequence: currentSequence(state),
                repositoryIdentity: observation.repositoryIdentity,
                pre: observation.state,
                post: observation.state,
                outcome: "not-applied",
                diagnostic: null,
                requestDigest: operation.requestDigest,
              })
            : createRecoveryUnknownObservation(
                state,
                operation,
                tuple.registrationId,
                "remove-worktree",
                request.role,
                observation.repositoryIdentity,
              );
          completeRecoveredOperation(state, operation, result);
        } catch {
          completeRecoveredOperation(
            state,
            operation,
            createRecoveryUnknownObservation(
              state,
              operation,
              tuple.registrationId,
              "remove-worktree",
              request.role,
            ),
          );
        }
        continue;
      }
      const exactAbsent =
        registration !== undefined &&
        registrationMatchesWorktreeRequest(registration, request, "removed") &&
        source !== undefined &&
        source.commonDirectoryDigest ===
          request.expectedCommonDirectoryDigest &&
        !existsSync(worktreePath) &&
        adminPath !== null &&
        !existsSync(adminPath) &&
        !worktreeSetContainsPath(state, source.path, worktreePath, true);
      const result = exactAbsent
        ? createObservation(state, {
            operationId: operation.operationId,
            registrationId: tuple.registrationId,
            operationKind: "remove-worktree",
            purpose: request.role,
            sequence: currentSequence(state),
            repositoryIdentity: effectObserved?.repositoryIdentity ?? {
              commonDirectoryDigest: request.expectedCommonDirectoryDigest,
              objectFormat: "sha256",
            },
            pre: effectObserved?.pre ?? null,
            post: null,
            outcome: "already-applied",
            diagnostic: null,
            requestDigest: operation.requestDigest,
          })
        : createRecoveryUnknownObservation(
            state,
            operation,
            tuple.registrationId,
            "remove-worktree",
            request.role,
            effectObserved?.repositoryIdentity,
          );
      completeRecoveredOperation(state, operation, result);
      continue;
    }
    if (operation.kind === "named-check") {
      const request = operation.request as {
        readonly registrationId: string;
        readonly checkId: string;
        readonly attempt: number;
        readonly candidateCommit: string;
        readonly candidateTree: string;
      };
      const unknown = syntheticNamedCheckUnknown(state, {
        operationId: operation.operationId,
        registrationId: request.registrationId,
        checkId: request.checkId,
        attempt: request.attempt,
        candidateCommit: request.candidateCommit,
        candidateTree: request.candidateTree,
        requestDigest: operation.requestDigest,
      });
      const completed = writeOperationStage(state, {
        operationId: operation.operationId,
        kind: operation.kind,
        registrationId: tuple.registrationId,
        registrationDigest: tuple.registrationDigest,
        requestDigest: operation.requestDigest,
        request: operation.request,
        sequence: 4,
        stage: "completed",
        priorRecordDigest: operation.latestRecordDigest,
        terminalState: terminalStateForResult(unknown),
        result: unknown,
      });
      storeOperationState(state, completed);
      const registration = state.registrations.get(request.registrationId);
      if (registration) updateRegistrationCleanupState(registration, unknown);
      continue;
    }
    if (operation.kind === "inspect-worktrees") {
      const registration = state.registrations.get(tuple.registrationId);
      if (!registration) continue;
      const observation = observeRepositoryState(state, registration.path);
      const result = createObservation(state, {
        operationId: operation.operationId,
        registrationId: tuple.registrationId,
        operationKind: "inspect-worktrees",
        purpose: "principal-candidate",
        sequence: currentSequence(state),
        repositoryIdentity: observation.repositoryIdentity,
        pre: observation.state,
        post: observation.state,
        outcome: "already-applied",
        diagnostic: null,
        requestDigest: operation.requestDigest,
      });
      const completed = writeOperationStage(state, {
        operationId: operation.operationId,
        kind: operation.kind,
        registrationId: tuple.registrationId,
        registrationDigest: tuple.registrationDigest,
        requestDigest: operation.requestDigest,
        request: operation.request,
        sequence: 4,
        stage: "completed",
        priorRecordDigest: operation.latestRecordDigest,
        terminalState: terminalStateForResult(result),
        result,
      });
      storeOperationState(state, completed);
      continue;
    }
    const completed = writeOperationStage(state, {
      operationId: operation.operationId,
      kind: operation.kind,
      registrationId: tuple.registrationId,
      registrationDigest: tuple.registrationDigest,
      requestDigest: operation.requestDigest,
      request: operation.request,
      sequence: 4,
      stage: "completed",
      priorRecordDigest: operation.latestRecordDigest,
      terminalState: "outcome-unknown",
      result: operationConflictObservation(state, {
        operationId: operation.operationId,
        registrationId: tuple.registrationId,
        operationKind:
          operation.kind === "create-bare-remote"
            ? "create-bare-remote"
            : operation.kind === "create-worktree"
              ? "create-worktree"
              : operation.kind === "remove-worktree"
                ? "remove-worktree"
                : "inspect-worktrees",
        purpose:
          operation.kind === "create-bare-remote"
            ? "fixture-remote"
            : "named-check",
        requestDigest: operation.requestDigest,
        diagnosticCode: "outcome-unknown",
      }),
    });
    storeOperationState(state, completed);
  }
}

export function createTrustedFixtureGitPolicyV1(
  definition: TrustedFixtureGitPolicyV1Definition,
): TrustedFixtureGitPolicyV1 {
  validateSafeId("policyId", definition.policyId);
  const trustedParent = normalize(definition.trustedParent);
  if (
    !isAbsolute(trustedParent) ||
    containsCredentialShapedContent(trustedParent)
  ) {
    throw new TypeError("trusted parent is invalid");
  }
  const currentCheckout = normalize(process.cwd());
  if (
    containsPath(trustedParent, currentCheckout) ||
    containsPath(currentCheckout, trustedParent)
  ) {
    throw new TypeError("trusted parent overlaps the current checkout");
  }
  const limits = validateLimits(definition.limits);
  if (definition.namedChecks.length > limits.maxNamedChecks) {
    throw new TypeError("named check policy exceeds the permitted size");
  }
  const namedChecks = definition.namedChecks
    .map((entry) => validateNamedCheckEntry(entry, limits))
    .sort((left, right) => left.checkId.localeCompare(right.checkId));
  const seen = new Set<string>();
  for (const entry of namedChecks) {
    if (seen.has(entry.checkId)) {
      throw new TypeError("named check identifiers must be unique");
    }
    seen.add(entry.checkId);
  }
  const authority = createNamedCheckAuthorityV1({
    policyId: definition.policyId,
    checks: namedChecks,
    resolveWorkspaceExecution: (workspaceIdentityToken: object) => {
      const token = workspaceIdentityToken as {
        readonly cwd?: unknown;
        readonly homeDirectory?: unknown;
      };
      return {
        cwd: validateAbsoluteDirectory("cwd", token.cwd),
        homeDirectory: validateAbsoluteDirectory(
          "homeDirectory",
          token.homeDirectory,
        ),
      };
    },
  });
  const policy: TrustedFixtureGitPolicyV1 = Object.freeze({
    policyId: definition.policyId,
    limits,
    namedChecks: Object.freeze(
      namedChecks.map((entry) =>
        Object.freeze({
          checkId: entry.checkId,
          maxDurationMs: entry.maxDurationMs,
          maxOutputBytes: entry.maxOutputBytes,
        }),
      ),
    ),
    async revoke() {
      const state = requirePolicyState(policy);
      state.revoked = true;
      for (const harness of state.harnesses) {
        const harnessState = requireHarnessState(harness);
        if (harnessState.status !== "removed") {
          await closeHarnessState(harnessState);
        }
      }
    },
  });
  POLICY_STATE.set(policy, {
    publicPolicy: policy,
    parentIdentity: snapshotDirectoryIdentity(trustedParent),
    gitExecutableIdentity: snapshotFileIdentity(definition.gitExecutable),
    gitExecPathIdentity: snapshotDirectoryIdentity(definition.gitExecPath),
    namedChecks,
    limits,
    authority,
    revoked: false,
    harnesses: new Set(),
  });
  return policy;
}

export const isTrustedFixtureGitPolicyV1 = (
  value: unknown,
): value is TrustedFixtureGitPolicyV1 =>
  typeof value === "object" && value !== null && POLICY_STATE.has(value);

export async function createFixtureRepositoryHarnessV1(
  policy: TrustedFixtureGitPolicyV1,
  options: CreateFixtureRepositoryHarnessV1Options,
): Promise<FixtureRepositoryHarnessV1> {
  const policyState = requirePolicyState(policy);
  revalidateTrustedPolicyState(policyState);
  validateSafeId("runId", options.runId);
  validateSafeId("taskId", options.taskId);
  validateObjectId("expectedBaseCommit", options.expectedBaseCommit);
  validateObjectId("expectedBaseTree", options.expectedBaseTree);
  const runDigest = deriveRunDigest(policy.policyId, options);
  if (
    findMatchingHarnessRoots(policyState.parentIdentity.path, runDigest)
      .length > 0
  ) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["run-identity-conflict"],
    );
  }
  const rootPath = join(
    policyState.parentIdentity.path,
    `spts-fixture-${randomBytes(16).toString("hex")}`,
  );
  mkdirSync(rootPath, { mode: 0o700 });
  const directories = createRunDirectories(rootPath);
  const state: HarnessStateV1 = {
    policyState,
    runId: options.runId,
    taskId: options.taskId,
    expectedBaseCommit: options.expectedBaseCommit,
    expectedBaseTree: options.expectedBaseTree,
    runDigest,
    rootPath,
    rootIdentity: snapshotDirectoryIdentity(rootPath),
    manifest: undefined as never,
    directories,
    operations: new Map(),
    operationsByRegistration: new Map(),
    registrations: new Map(),
    issuedPermits: new Set(),
    activeNamedChecks: new Map(),
    faultPoint: null,
    status: "active",
  };
  validateGitVersion(state);
  state.manifest = createRootManifest(state);
  writeCanonicalFileImmutable(
    join(state.directories.metadata, ROOT_MANIFEST_FILE),
    state.manifest,
  );
  return createHarnessObject(policy, state);
}

export async function recoverFixtureRepositoryHarnessV1(
  policy: TrustedFixtureGitPolicyV1,
  options: CreateFixtureRepositoryHarnessV1Options,
): Promise<FixtureRepositoryHarnessV1> {
  const policyState = requirePolicyState(policy);
  revalidateTrustedPolicyState(policyState);
  validateSafeId("runId", options.runId);
  validateSafeId("taskId", options.taskId);
  validateObjectId("expectedBaseCommit", options.expectedBaseCommit);
  validateObjectId("expectedBaseTree", options.expectedBaseTree);
  const runDigest = deriveRunDigest(policy.policyId, options);
  const candidates = findMatchingHarnessRoots(
    policyState.parentIdentity.path,
    runDigest,
  );
  if (candidates.length !== 1) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1[
        candidates.length === 0
          ? "storage-unavailable"
          : "run-identity-conflict"
      ],
    );
  }
  for (const rootPath of candidates) {
    try {
      const directories = buildRunDirectories(rootPath);
      validateRecoveryRootTopology(rootPath, directories);
      const state: HarnessStateV1 = {
        policyState,
        runId: options.runId,
        taskId: options.taskId,
        expectedBaseCommit: options.expectedBaseCommit,
        expectedBaseTree: options.expectedBaseTree,
        runDigest,
        rootPath,
        rootIdentity: snapshotDirectoryIdentity(rootPath),
        manifest: readCanonicalJson<RootManifestV1>(
          join(directories.metadata, ROOT_MANIFEST_FILE),
        ),
        directories,
        operations: new Map(),
        operationsByRegistration: new Map(),
        registrations: new Map(),
        issuedPermits: new Set(),
        activeNamedChecks: new Map(),
        faultPoint: null,
        status: "active",
      };
      if (state.manifest.runDigest !== runDigest) continue;
      validateRootManifest(state.manifest, state);
      loadRegistrationState(state);
      loadOperationStates(state);
      recoverIncompleteOperations(state);
      return createHarnessObject(policy, state);
    } catch (error) {
      if (
        error instanceof TypeError &&
        error.message ===
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["run-identity-conflict"]
      ) {
        throw error;
      }
      throw recoveryIntegrityError();
    }
  }
  throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["storage-unavailable"]);
}

async function createRepository(
  harness: FixtureRepositoryHarnessV1,
  request: CreateRepositoryRequestV1,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  const files = validateRepositoryRequest(request);
  const requestDigest = requestDigestForRepository(
    state.policyState.publicPolicy.policyId,
    request,
    files,
  );
  try {
    const replay = maybeReplay<FixtureRepositoryObservationV1>(
      state,
      request.operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-repository",
      purpose: "principal-candidate",
      requestDigest,
      diagnosticCode: "operation-replay-conflict",
    });
  }
  if (state.registrations.has(request.registrationId)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-repository",
      purpose: "principal-candidate",
      requestDigest,
      diagnosticCode: "registration-conflict",
    });
  }
  const registrationDigest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const repositoryPath = join(
    state.directories.repositories,
    registrationDigest,
  );
  if (hasTargetCollision(repositoryPath)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-repository",
      purpose: "principal-candidate",
      requestDigest,
      diagnosticCode: "workspace-collision",
    });
  }
  return executeOperationWithLedger(state, {
    operationId: request.operationId,
    kind: "create-repository",
    registrationId: request.registrationId,
    registrationDigest,
    requestDigest,
    request: createRepositoryOperationRequest(request, files),
    effect: () => {
      runGit(
        state,
        state.rootPath,
        [
          "init",
          "--object-format=sha256",
          "--initial-branch=fixture-main",
          repositoryPath,
        ],
        { failureCode: "outcome-unknown" },
      );
      for (const file of files) {
        writeFixtureFile(
          join(repositoryPath, fixtureFileRelativePath(file)),
          file,
        );
      }
      runGit(state, repositoryPath, ["add", "--all", "--"], {
        failureCode: "outcome-unknown",
      });
      runGit(
        state,
        repositoryPath,
        [
          "commit",
          "--no-verify",
          "--no-gpg-sign",
          "-m",
          "Initialize SPTS fixture",
        ],
        {
          environment: {
            GIT_AUTHOR_NAME: "SPTS Fixture",
            GIT_AUTHOR_EMAIL: "fixture.invalid",
            GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
            GIT_COMMITTER_NAME: "SPTS Fixture",
            GIT_COMMITTER_EMAIL: "fixture.invalid",
            GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
          },
          failureCode: "outcome-unknown",
        },
      );
      const observation = observeRepositoryState(state, repositoryPath);
      const registration = createRegistrationState(state, {
        registrationId: request.registrationId,
        role: "principal-candidate",
        checkId: null,
        sourceRegistrationId: null,
        path: repositoryPath,
        commonDirectory: readGitCommonDir(state, repositoryPath),
        adminDirectory: readGitAbsoluteDir(state, repositoryPath),
        sourceCommonDirectoryDigest: null,
        candidateCommit: observation.state.headCommit,
        candidateTree: observation.state.headTree,
        lifecycleState: "retained",
      });
      writeRegistrationRecord(state, registration);
      state.registrations.set(request.registrationId, registration);
      return createObservation(state, {
        operationId: request.operationId,
        registrationId: request.registrationId,
        operationKind: "create-repository",
        purpose: "principal-candidate",
        sequence: currentSequence(state),
        repositoryIdentity: observation.repositoryIdentity,
        pre: null,
        post: observation.state,
        outcome: "applied",
        diagnostic: null,
        requestDigest,
      });
    },
  });
}

async function createBareRemote(
  harness: FixtureRepositoryHarnessV1,
  request: CreateBareRemoteRequestV1,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  validateRemoteRequest(request);
  const requestDigest = requestDigestForRemote(
    state.policyState.publicPolicy.policyId,
    request,
  );
  try {
    const replay = maybeReplay<FixtureRepositoryObservationV1>(
      state,
      request.operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-bare-remote",
      purpose: "fixture-remote",
      requestDigest,
      diagnosticCode: "operation-replay-conflict",
    });
  }
  if (state.registrations.has(request.registrationId)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-bare-remote",
      purpose: "fixture-remote",
      requestDigest,
      diagnosticCode: "registration-conflict",
    });
  }
  const source = sourceRegistration(state, request.sourceRegistrationId);
  if (!registrationRootIdentityMatches(state, source)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-bare-remote",
      purpose: "fixture-remote",
      requestDigest,
      diagnosticCode: "repository-identity-drift",
    });
  }
  const registrationDigest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const remotePath = join(
    state.directories.remotes,
    `${registrationDigest}.git`,
  );
  if (hasTargetCollision(remotePath)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-bare-remote",
      purpose: "fixture-remote",
      requestDigest,
      diagnosticCode: "workspace-collision",
    });
  }
  return executeOperationWithLedger(state, {
    operationId: request.operationId,
    kind: "create-bare-remote",
    registrationId: request.registrationId,
    registrationDigest,
    requestDigest,
    request: createBareRemoteOperationRequest(request, source),
    effect: () => {
      runGit(
        state,
        state.rootPath,
        [
          "init",
          "--bare",
          "--object-format=sha256",
          "--initial-branch=fixture-main",
          remotePath,
        ],
        { failureCode: "outcome-unknown" },
      );
      runGit(
        state,
        source.path,
        [
          "push",
          "--no-verify",
          remotePath,
          "refs/heads/fixture-main:refs/heads/fixture-main",
        ],
        {
          allowFileProtocol: true,
          failureCode: "outcome-unknown",
        },
      );
      const registration = createRegistrationState(state, {
        registrationId: request.registrationId,
        role: "fixture-remote",
        checkId: null,
        sourceRegistrationId: request.sourceRegistrationId,
        path: remotePath,
        commonDirectory: remotePath,
        adminDirectory: remotePath,
        sourceCommonDirectoryDigest: source.commonDirectoryDigest,
        candidateCommit: source.candidateCommit,
        candidateTree: source.candidateTree,
        lifecycleState: "retained",
      });
      writeRegistrationRecord(state, registration);
      state.registrations.set(request.registrationId, registration);
      return createObservation(state, {
        operationId: request.operationId,
        registrationId: request.registrationId,
        operationKind: "create-bare-remote",
        purpose: "fixture-remote",
        sequence: currentSequence(state),
        repositoryIdentity: {
          commonDirectoryDigest: directoryDigest(
            snapshotDirectoryIdentity(remotePath),
          ),
          objectFormat: "sha256",
        },
        pre: null,
        post: null,
        outcome: "applied",
        diagnostic: null,
        requestDigest,
      });
    },
  });
}

async function createWorktree(
  harness: FixtureRepositoryHarnessV1,
  request: RegisterWorktreeRequestV1,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  validateWorktreeRequest(request);
  const requestDigest = requestDigestForWorktree(
    state.policyState.publicPolicy.policyId,
    request,
  );
  try {
    const replay = maybeReplay<FixtureRepositoryObservationV1>(
      state,
      request.operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-worktree",
      purpose: request.role,
      requestDigest,
      diagnosticCode: "operation-replay-conflict",
    });
  }
  if (state.registrations.has(request.registrationId)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-worktree",
      purpose: request.role,
      requestDigest,
      diagnosticCode: "registration-conflict",
    });
  }
  const source = sourceRegistration(state, request.sourceRegistrationId);
  if (!registrationRootIdentityMatches(state, source)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-worktree",
      purpose: request.role,
      requestDigest,
      diagnosticCode: "repository-identity-drift",
    });
  }
  if (
    candidateTreeForCommit(state, source, request.candidateCommit) !==
    request.candidateTree
  ) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-worktree",
      purpose: request.role,
      requestDigest,
      diagnosticCode: "candidate-identity-drift",
    });
  }
  const registrationDigest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const worktreePath = join(state.directories.worktrees, registrationDigest);
  if (hasTargetCollision(worktreePath)) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-worktree",
      purpose: request.role,
      requestDigest,
      diagnosticCode: "workspace-collision",
    });
  }
  return executeOperationWithLedger(state, {
    operationId: request.operationId,
    kind: "create-worktree",
    registrationId: request.registrationId,
    registrationDigest,
    requestDigest,
    request: createWorktreeOperationRequest(request, source, state),
    effect: () => {
      runGit(
        state,
        source.path,
        ["worktree", "add", "--detach", worktreePath, request.candidateCommit],
        { failureCode: "outcome-unknown" },
      );
      const observation = observeRepositoryState(state, worktreePath);
      const registration = createRegistrationState(state, {
        registrationId: request.registrationId,
        role: request.role,
        checkId: request.checkId,
        sourceRegistrationId: request.sourceRegistrationId,
        path: worktreePath,
        commonDirectory: readGitCommonDir(state, worktreePath),
        adminDirectory: readGitAbsoluteDir(state, worktreePath),
        sourceCommonDirectoryDigest: source.commonDirectoryDigest,
        candidateCommit: request.candidateCommit,
        candidateTree: request.candidateTree,
        lifecycleState: "active",
      });
      writeRegistrationRecord(state, registration);
      state.registrations.set(request.registrationId, registration);
      return createObservation(state, {
        operationId: request.operationId,
        registrationId: request.registrationId,
        operationKind: "create-worktree",
        purpose: request.role,
        sequence: currentSequence(state),
        repositoryIdentity: observation.repositoryIdentity,
        pre: null,
        post: observation.state,
        outcome: "applied",
        diagnostic: null,
        requestDigest,
      });
    },
  });
}

async function inspectWorktrees(
  harness: FixtureRepositoryHarnessV1,
  operationId: string,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  validateSafeId("operationId", operationId);
  const rootRegistration = [...state.registrations.values()].find(
    (registration) => registration.role === "principal-candidate",
  );
  if (!rootRegistration) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["registration-conflict"],
    );
  }
  const requestDigest = computeFixtureRepositoryRequestDigestV1({
    policyId: state.policyState.publicPolicy.policyId,
    operationId,
    registrationId: rootRegistration.registrationId,
  });
  try {
    const replay = maybeReplay<FixtureRepositoryObservationV1>(
      state,
      operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return operationConflictObservation(state, {
      operationId,
      registrationId: rootRegistration.registrationId,
      operationKind: "inspect-worktrees",
      purpose: "principal-candidate",
      requestDigest,
      diagnosticCode: "operation-replay-conflict",
    });
  }
  if (!registrationRootIdentityMatches(state, rootRegistration)) {
    return createObservation(state, {
      operationId,
      registrationId: rootRegistration.registrationId,
      operationKind: "inspect-worktrees",
      purpose: "principal-candidate",
      sequence: currentSequence(state),
      repositoryIdentity: {
        commonDirectoryDigest: rootRegistration.commonDirectoryDigest,
        objectFormat: "sha256",
      },
      pre: null,
      post: null,
      outcome: "blocked",
      diagnostic: createFixtureDiagnosticV1("repository-identity-drift"),
      requestDigest,
    });
  }
  return executeOperationWithLedger(state, {
    operationId,
    kind: "inspect-worktrees",
    registrationId: rootRegistration.registrationId,
    registrationDigest: rootRegistration.registrationDigest,
    requestDigest,
    request: {
      registrationId: rootRegistration.registrationId,
    },
    effect: () => {
      const observation = observeRepositoryState(state, rootRegistration.path);
      return createObservation(state, {
        operationId,
        registrationId: rootRegistration.registrationId,
        operationKind: "inspect-worktrees",
        purpose: "principal-candidate",
        sequence: currentSequence(state),
        repositoryIdentity: observation.repositoryIdentity,
        pre: observation.state,
        post: observation.state,
        outcome: "applied",
        diagnostic: null,
        requestDigest,
      });
    },
  });
}

async function removeWorktree(
  harness: FixtureRepositoryHarnessV1,
  operationId: string,
  registrationId: string,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  validateSafeId("operationId", operationId);
  validateSafeId("registrationId", registrationId);
  const existingRegistration = state.registrations.get(registrationId);
  const requestDigest = computeFixtureRepositoryRequestDigestV1({
    policyId: state.policyState.publicPolicy.policyId,
    operationId,
    registrationId,
    sourceRegistrationId: existingRegistration?.sourceRegistrationId ?? null,
  });
  try {
    const replay = maybeReplay<FixtureRepositoryObservationV1>(
      state,
      operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return operationConflictObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: existingRegistration?.role ?? "named-check",
      requestDigest,
      diagnosticCode: "operation-replay-conflict",
    });
  }
  const registration = sourceRegistration(state, registrationId);
  if (
    registration.role === "principal-candidate" ||
    registration.role === "fixture-remote"
  ) {
    return operationConflictObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose:
        registration.role === "fixture-remote"
          ? "fixture-remote"
          : "principal-candidate",
      requestDigest: computeFixtureRepositoryRequestDigestV1({
        policyId: state.policyState.publicPolicy.policyId,
        operationId,
        registrationId,
      }),
      diagnosticCode: "registration-conflict",
    });
  }
  if (!registrationRootIdentityMatches(state, registration)) {
    return createObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      sequence: currentSequence(state),
      repositoryIdentity: {
        commonDirectoryDigest: registration.commonDirectoryDigest,
        objectFormat: "sha256",
      },
      pre: null,
      post: null,
      outcome: "blocked",
      diagnostic: createFixtureDiagnosticV1("repository-identity-drift"),
      requestDigest,
    });
  }
  const retentionDiagnostic = registrationRetentionDiagnostic(
    state,
    registrationId,
  );
  if (retentionDiagnostic ?? registration.cleanupBlockedReason) {
    return operationConflictObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      requestDigest,
      diagnosticCode:
        retentionDiagnostic ??
        registration.cleanupBlockedReason ??
        "outcome-unknown",
    });
  }
  if (
    hasIssuedNamedCheckPermit(state, registrationId) ||
    hasActiveNamedCheck(state, registrationId)
  ) {
    return operationConflictObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      requestDigest,
      diagnosticCode: "live-agent-ambiguous",
    });
  }
  let pre;
  try {
    pre = observeRepositoryState(state, registration.path);
  } catch {
    return createObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      sequence: currentSequence(state),
      repositoryIdentity: {
        commonDirectoryDigest: registration.commonDirectoryDigest,
        objectFormat: "sha256",
      },
      pre: null,
      post: null,
      outcome: "blocked",
      diagnostic: createFixtureDiagnosticV1("repository-identity-drift"),
      requestDigest,
    });
  }
  if (!pre.state.clean) {
    return createObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      sequence: currentSequence(state),
      repositoryIdentity: pre.repositoryIdentity,
      pre: pre.state,
      post: pre.state,
      outcome: "blocked",
      diagnostic: createFixtureDiagnosticV1("workspace-dirty"),
      requestDigest,
    });
  }
  if (
    pre.repositoryIdentity.commonDirectoryDigest !==
    registration.commonDirectoryDigest
  ) {
    return createObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      sequence: currentSequence(state),
      repositoryIdentity: pre.repositoryIdentity,
      pre: pre.state,
      post: pre.state,
      outcome: "blocked",
      diagnostic: createFixtureDiagnosticV1("repository-identity-drift"),
      requestDigest,
    });
  }
  if (
    registration.candidateCommit !== null &&
    registration.candidateTree !== null &&
    (pre.state.headCommit !== registration.candidateCommit ||
      pre.state.headTree !== registration.candidateTree)
  ) {
    return createObservation(state, {
      operationId,
      registrationId,
      operationKind: "remove-worktree",
      purpose: registration.role,
      sequence: currentSequence(state),
      repositoryIdentity: pre.repositoryIdentity,
      pre: pre.state,
      post: pre.state,
      outcome: "blocked",
      diagnostic: createFixtureDiagnosticV1("candidate-identity-drift"),
      requestDigest,
    });
  }
  return executeOperationWithLedger(state, {
    operationId,
    kind: "remove-worktree",
    registrationId,
    registrationDigest: registration.registrationDigest,
    requestDigest,
    request: createRemoveWorktreeOperationRequest(registration),
    effect: () => {
      registration.state = "cleanup-pending";
      registration.generation += 1;
      writeRegistrationRecord(state, registration);
      runGit(
        state,
        registration.path,
        ["worktree", "remove", "--force", registration.path],
        {
          allowClosed: true,
          failureCode: "outcome-unknown",
        },
      );
      registration.state = "removed";
      registration.generation += 1;
      writeRegistrationRecord(state, registration);
      return createObservation(state, {
        operationId,
        registrationId,
        operationKind: "remove-worktree",
        purpose: registration.role,
        sequence: currentSequence(state),
        repositoryIdentity: pre.repositoryIdentity,
        pre: pre.state,
        post: null,
        outcome: "applied",
        diagnostic: null,
        requestDigest,
      });
    },
  });
}

async function issueHarnessNamedCheckPermitV1(
  harness: FixtureRepositoryHarnessV1,
  request: IssueHarnessNamedCheckPermitV1Input,
): Promise<NamedCheckPermitV1> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  validateSafeId("operationId", request.operationId);
  validateSafeId("registrationId", request.registrationId);
  validateSafeId("checkId", request.checkId);
  if (
    !Number.isSafeInteger(request.attempt) ||
    request.attempt < 1 ||
    request.attempt > state.policyState.limits.maxAttempts
  ) {
    throw new TypeError("named check attempt is invalid");
  }
  const registration = sourceRegistration(state, request.registrationId);
  if (!registrationRootIdentityMatches(state, registration)) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  if (
    registration.role !== "named-check" ||
    registration.checkId !== request.checkId ||
    registration.candidateCommit === null ||
    registration.candidateTree === null
  ) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["check-not-allowed"]);
  }
  const observation = observeRepositoryState(state, registration.path);
  if (!observation.state.clean) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["workspace-dirty"]);
  }
  const requestDigest = computeNamedCheckRequestDigestV1({
    policyId: state.policyState.publicPolicy.policyId,
    operationId: request.operationId,
    registrationId: request.registrationId,
    checkId: request.checkId,
    attempt: request.attempt,
    candidateCommit: registration.candidateCommit,
    candidateTree: registration.candidateTree,
  });
  const options: IssueNamedCheckPermitV1Options = {
    beforeObservation: toNamedCheckRepositoryObservation(
      observation,
      registration.path,
      registration.adminDirectory,
    ),
    observeAfter: () =>
      toNamedCheckRepositoryObservation(
        observeRepositoryState(state, registration.path, true),
        registration.path,
        registration.adminDirectory,
      ),
  };
  const permit = issueRuntimeNamedCheckPermitV1(
    state.policyState.authority,
    {
      operationId: request.operationId,
      runId: state.runId,
      registrationId: request.registrationId,
      checkId: request.checkId,
      attempt: request.attempt,
      candidateCommit: registration.candidateCommit,
      candidateTree: registration.candidateTree,
      workspaceIdentityToken: Object.freeze({
        cwd: registration.path,
        homeDirectory: state.directories.home,
        registration,
      }),
      requestDigest,
    },
    options,
  );
  state.issuedPermits.add(permit);
  return permit;
}

async function runHarnessNamedCheckV1(
  harness: FixtureRepositoryHarnessV1,
  request: RunNamedCheckRequestV1,
): Promise<ValidationResult<NamedCheckResultV1>> {
  const state = requireHarnessState(harness);
  ensureHarnessState(state);
  validateSafeId("operationId", request.operationId);
  validateSafeId("registrationId", request.registrationId);
  validateSafeId("checkId", request.checkId);
  const registration = sourceRegistration(state, request.registrationId);
  if (!registrationRootIdentityMatches(state, registration)) {
    return conflictResult("repository-identity-drift");
  }
  if (
    registration.candidateCommit === null ||
    registration.candidateTree === null
  ) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["check-not-allowed"]);
  }
  const requestDigest = computeNamedCheckRequestDigestV1({
    policyId: state.policyState.publicPolicy.policyId,
    operationId: request.operationId,
    registrationId: request.registrationId,
    checkId: request.checkId,
    attempt: request.attempt,
    candidateCommit: registration.candidateCommit,
    candidateTree: registration.candidateTree,
  });
  try {
    const replay = maybeReplay<ValidationResult<NamedCheckResultV1>>(
      state,
      request.operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return conflictResult("operation-replay-conflict");
  }
  if (hasActiveNamedCheck(state, request.registrationId)) {
    return conflictResult("live-agent-ambiguous");
  }
  const result = await executeOperationWithLedger(state, {
    operationId: request.operationId,
    kind: "named-check",
    registrationId: request.registrationId,
    registrationDigest: registration.registrationDigest,
    requestDigest,
    request: {
      registrationId: request.registrationId,
      checkId: request.checkId,
      attempt: request.attempt,
      candidateCommit: registration.candidateCommit,
      candidateTree: registration.candidateTree,
    },
    effect: async () => {
      const permit = await issueHarnessNamedCheckPermitV1(harness, request);
      const controller = new AbortController();
      let abortListener: (() => void) | undefined;
      if (request.signal) {
        abortListener = () => controller.abort();
        if (request.signal.aborted) abortListener();
        else {
          request.signal.addEventListener("abort", abortListener, {
            once: true,
          });
        }
      }
      const promise = runExactNamedCheckV1({
        permit,
        signal: controller.signal,
      });
      state.activeNamedChecks.set(request.operationId, {
        operationId: request.operationId,
        registrationId: request.registrationId,
        controller,
        promise,
      });
      try {
        return await promise;
      } finally {
        state.issuedPermits.delete(permit);
        state.activeNamedChecks.delete(request.operationId);
        if (abortListener && request.signal) {
          request.signal.removeEventListener("abort", abortListener);
        }
      }
    },
  });
  updateRegistrationCleanupState(registration, result);
  return result;
}

export function __testOnlySetFixtureFaultV1(
  harness: FixtureRepositoryHarnessV1,
  point: string | null,
): void {
  const state = requireHarnessState(harness);
  state.faultPoint = point;
}

export function __testOnlyDescribeFixtureHarnessV1(
  harness: FixtureRepositoryHarnessV1,
): {
  readonly rootPath: string;
  readonly registrations: readonly {
    readonly registrationId: string;
    readonly role: RegistrationStateV1["role"];
    readonly path: string;
    readonly state: RegistrationStateV1["state"];
  }[];
} {
  const state = requireHarnessState(harness);
  return Object.freeze({
    rootPath: state.rootPath,
    registrations: Object.freeze(
      [...state.registrations.values()].map((registration) =>
        Object.freeze({
          registrationId: registration.registrationId,
          role: registration.role,
          path: registration.path,
          state: registration.state,
        }),
      ),
    ),
  });
}

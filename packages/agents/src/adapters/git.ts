import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { randomBytes, createHash } from "node:crypto";
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
  createNamedCheckAuthorityV1,
  issueNamedCheckPermitV1 as issueRuntimeNamedCheckPermitV1,
  runExactNamedCheckV1,
  type IssueNamedCheckPermitV1Options,
  type NamedCheckAuthorityV1,
  type NamedCheckPermitV1,
} from "@scrum-pi-team-skills/runtime";

import {
  createRegistrationRecordV1,
  digestRelativePathV1,
  registrationDigestV1,
  snapshotFixtureFilesV1,
  type CreateBareRemoteRequestV1,
  type CreateRepositoryRequestV1,
  type FixtureFileV1,
  type FixtureRegistrationRecordV1,
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
}

interface GitProcessResultV1 {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

interface OperationRecordV1 {
  readonly operationId: string;
  readonly kind:
    | "create-repository"
    | "create-bare-remote"
    | "create-worktree"
    | "inspect-worktrees"
    | "remove-worktree"
    | "named-check";
  readonly requestDigest: string;
  readonly result: unknown;
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
  candidateCommit: string | null;
  candidateTree: string | null;
  state: "active" | "cleanup-pending" | "retained" | "removed";
  generation: number;
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

interface HarnessStateV1 {
  readonly policyState: PolicyStateV1;
  readonly runId: string;
  readonly taskId: string;
  readonly expectedBaseCommit: string;
  readonly expectedBaseTree: string;
  readonly runDigest: string;
  readonly rootPath: string;
  readonly rootIdentity: DirectoryIdentityV1;
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
  readonly operations: Map<string, OperationRecordV1>;
  readonly registrations: Map<string, RegistrationStateV1>;
  status:
    "active" | "cancelling" | "cancelled" | "closing" | "closed" | "removed";
}

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const VERSION_PATTERN = /^git version (\d+)\.(\d+)\.(\d+)/;
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

function containsPath(left: string, right: string): boolean {
  const relation = relative(left, right);
  return (
    relation === "" || (!relation.startsWith(`..${sep}`) && relation !== "..")
  );
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

function snapshotDirectoryIdentity(path: string): DirectoryIdentityV1 {
  walkWithoutSymlinks(path);
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    !isAbsolute(path) ||
    (stat.mode & 0o022) !== 0
  ) {
    throw new TypeError("trusted root is invalid");
  }
  return Object.freeze({
    path,
    realpath: realpathSync(path),
    device: stat.dev,
    inode: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode,
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
    throw new TypeError("trusted root is invalid");
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
  expected: DirectoryIdentityV1,
  actual: DirectoryIdentityV1,
): boolean {
  return (
    expected.realpath === actual.realpath &&
    expected.device === actual.device &&
    expected.inode === actual.inode &&
    expected.uid === actual.uid &&
    expected.gid === actual.gid &&
    expected.mode === actual.mode
  );
}

function sameFileIdentity(
  expected: FileIdentityV1,
  actual: FileIdentityV1,
): boolean {
  return (
    expected.realpath === actual.realpath &&
    expected.device === actual.device &&
    expected.inode === actual.inode &&
    expected.uid === actual.uid &&
    expected.gid === actual.gid &&
    expected.mode === actual.mode &&
    expected.size === actual.size &&
    expected.mtimeMs === actual.mtimeMs &&
    expected.ctimeMs === actual.ctimeMs &&
    expected.sha256 === actual.sha256
  );
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

function revalidateTrustedPolicyState(state: PolicyStateV1): void {
  if (state.revoked) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  const parentIdentity = snapshotDirectoryIdentity(state.parentIdentity.path);
  const gitExecutableIdentity = snapshotFileIdentity(
    state.gitExecutableIdentity.path,
  );
  const gitExecPathIdentity = snapshotDirectoryIdentity(
    state.gitExecPathIdentity.path,
  );
  if (
    !sameDirectoryIdentity(state.parentIdentity, parentIdentity) ||
    !sameFileIdentity(state.gitExecutableIdentity, gitExecutableIdentity) ||
    !sameDirectoryIdentity(state.gitExecPathIdentity, gitExecPathIdentity)
  ) {
    state.revoked = true;
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
}

function ensureDirectory(path: string, mode = 0o700): void {
  mkdirSync(path, { recursive: true, mode });
}

function writeCanonicalJson(path: string, value: unknown): void {
  writeFileSync(path, canonicalizeGitCheckFixtureValueV1(value), {
    encoding: "utf8",
    mode: 0o600,
  });
}

function readCanonicalJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function fixedGitEnvironment(
  harness: HarnessStateV1,
  extra?: Readonly<Record<string, string>>,
): Record<string, string> {
  const env = Object.create(null) as Record<string, string>;
  env.HOME = harness.directories.home;
  env.XDG_CONFIG_HOME = harness.directories.home;
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_TERMINAL_PROMPT = "0";
  env.GCM_INTERACTIVE = "never";
  env.GIT_ASKPASS = "/bin/false";
  env.SSH_ASKPASS = "/bin/false";
  env.GIT_PAGER = "cat";
  env.PAGER = "cat";
  env.GIT_EDITOR = "/bin/false";
  env.GIT_SEQUENCE_EDITOR = "/bin/false";
  env.GIT_MERGE_AUTOEDIT = "no";
  env.GIT_EXEC_PATH = harness.policyState.gitExecPathIdentity.path;
  env.LANG = "C";
  env.LC_ALL = "C";
  env.TZ = "UTC";
  if (extra) {
    for (const [key, value] of Object.entries(extra)) env[key] = value;
  }
  return env;
}

function fixedGitConfig(cwd: string, harness: HarnessStateV1): string[] {
  return [
    "--no-pager",
    "-c",
    `core.hooksPath=${harness.directories.hooksDisabled}`,
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
}

function runGit(
  harness: HarnessStateV1,
  cwd: string,
  arguments_: readonly string[],
  options?: {
    readonly allowFailure?: boolean;
    readonly allowFileProtocol?: string | null;
    readonly environment?: Readonly<Record<string, string>>;
  },
): GitProcessResultV1 {
  revalidateTrustedPolicyState(harness.policyState);
  const gitExecutable = snapshotFileIdentity(
    harness.policyState.gitExecutableIdentity.path,
  );
  if (
    !sameFileIdentity(harness.policyState.gitExecutableIdentity, gitExecutable)
  ) {
    harness.policyState.revoked = true;
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
  const argv = [...fixedGitConfig(cwd, harness)];
  if (options?.allowFileProtocol) {
    argv.push("-c", "protocol.file.allow=always");
  }
  argv.push(...arguments_);
  const env = fixedGitEnvironment(harness, options?.environment);
  const result = spawnSync(
    harness.policyState.gitExecutableIdentity.path,
    argv,
    {
      cwd,
      env,
      shell: false,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.error) throw result.error;
  const status = result.status ?? 1;
  if (!options?.allowFailure && status !== 0) {
    throw new Error(result.stderr || "git operation failed");
  }
  return {
    status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function validateGitVersion(harness: HarnessStateV1): void {
  const version = runGit(harness, harness.rootPath, ["--version"]);
  const match = VERSION_PATTERN.exec(version.stdout.trim());
  if (!match)
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["platform-unsupported"]);
  const major = Number.parseInt(match[1] ?? "0", 10);
  const minor = Number.parseInt(match[2] ?? "0", 10);
  if (major !== 2 || minor < 43 || minor > 60) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["platform-unsupported"]);
  }
}

function rootManifest(state: HarnessStateV1): unknown {
  const unsigned = {
    contract: "spts.fixture-root-manifest",
    version: "1.0.0",
    policyId: state.policyState.publicPolicy.policyId,
    runId: state.runId,
    taskId: state.taskId,
    expectedBaseCommit: state.expectedBaseCommit,
    expectedBaseTree: state.expectedBaseTree,
    runDigest: state.runDigest,
    rootDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-common-directory/1.0.0",
      {
        path: state.rootIdentity.realpath,
        device: state.rootIdentity.device,
        inode: state.rootIdentity.inode,
        uid: state.rootIdentity.uid,
        mode: state.rootIdentity.mode,
      },
    ),
    status: state.status,
  };
  return {
    ...unsigned,
    manifestDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-operation-record/1.0.0",
      unsigned,
    ),
  };
}

function writeRootManifest(state: HarnessStateV1): void {
  writeCanonicalJson(
    join(state.directories.metadata, ROOT_MANIFEST_FILE),
    rootManifest(state),
  );
}

function createRunDirectories(rootPath: string): HarnessStateV1["directories"] {
  const directories = {
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
  for (const directory of ROOT_DIR_NAMES)
    ensureDirectory(join(rootPath, directory), 0o700);
  ensureDirectory(directories.operations, 0o700);
  ensureDirectory(directories.registrations, 0o700);
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

function commonDirectoryDigest(path: string): string {
  const stat = statSync(path);
  return computeGitCheckFixtureDigestV1("spts.fixture-common-directory/1.0.0", {
    path: realpathSync(path),
    device: stat.dev,
    inode: stat.ino,
    uid: stat.uid,
    mode: stat.mode,
  });
}

function ensureContained(root: string, candidate: string): void {
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(candidate);
  if (!containsPath(resolvedRoot, resolvedCandidate)) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
}

function digestFileContent(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function readGitAbsoluteDir(harness: HarnessStateV1, cwd: string): string {
  return runGit(harness, cwd, [
    "rev-parse",
    "--absolute-git-dir",
  ]).stdout.trim();
}

function readGitCommonDir(harness: HarnessStateV1, cwd: string): string {
  return resolve(
    cwd,
    runGit(harness, cwd, ["rev-parse", "--git-common-dir"]).stdout.trim(),
  );
}

function readObjectFormat(
  harness: HarnessStateV1,
  cwd: string,
): "sha1" | "sha256" {
  const value = runGit(harness, cwd, [
    "rev-parse",
    "--show-object-format",
  ]).stdout.trim();
  if (value !== "sha1" && value !== "sha256") {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  return value;
}

function readBranch(harness: HarnessStateV1, cwd: string): string | null {
  const result = runGit(
    harness,
    cwd,
    ["symbolic-ref", "--quiet", "--short", "HEAD"],
    { allowFailure: true },
  );
  return result.status === 0 ? result.stdout.trim() : null;
}

function assertGitConfigSafe(path: string): void {
  const configPath = join(path, "config");
  if (!existsSync(configPath)) return;
  const content = readFileSync(configPath, "utf8");
  const denied = [
    /^\[include/i,
    /^\[includeif/i,
    /credential\.helper/i,
    /core\.fsmonitor/i,
    /extensions\.worktreeconfig/i,
    /filter\./i,
    /diff\.external/i,
    /externaldiff/i,
    /pager\./i,
    /core\.pager/i,
    /hooksPath/i,
    /ssh/i,
    /proxy/i,
  ];
  if (denied.some((pattern) => pattern.test(content))) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
}

function assertHostileStateAbsent(harness: HarnessStateV1, cwd: string): void {
  const gitDir = readGitAbsoluteDir(harness, cwd);
  const commonDir = readGitCommonDir(harness, cwd);
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
  ];
  if (hostilePaths.some((path) => existsSync(path))) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  assertGitConfigSafe(commonDir);
  const fsck = runGit(harness, cwd, ["fsck", "--strict", "--no-progress"], {
    allowFailure: true,
  });
  if (fsck.status !== 0) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
    );
  }
  if (gitDir !== commonDir) {
    ensureContained(commonDir, gitDir);
  }
}

function pathDigestForRelative(relativePath: string): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-path/1.0.0",
    relativePath,
  );
}

function walkTree(rootPath: string, prefix = ""): unknown[] {
  const entries = readdirSync(rootPath, { withFileTypes: true }).sort(
    (left, right) => left.name.localeCompare(right.name),
  );
  const observations: unknown[] = [];
  for (const entry of entries) {
    const absolute = join(rootPath, entry.name);
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink() || !(stat.isDirectory() || stat.isFile())) {
      throw new TypeError(
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
      );
    }
    observations.push({
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
      contentDigest: stat.isFile() ? digestFileContent(absolute) : null,
    });
    if (stat.isDirectory())
      observations.push(...walkTree(absolute, relativePath));
  }
  return observations;
}

function workspaceOnlySentinelDigest(path: string): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-filesystem-sentinel/1.0.0",
    walkTree(path),
  );
}

function countGitObjects(harness: HarnessStateV1, cwd: string): void {
  const count = Number.parseInt(
    runGit(harness, cwd, ["count-objects", "-v"])
      .stdout.split(/\r?\n/u)
      .find((line) => line.startsWith("count: "))
      ?.slice(7) ?? "0",
    10,
  );
  if (
    !Number.isSafeInteger(count) ||
    count > harness.policyState.limits.maxGitObjects
  ) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["limit-exhausted"]);
  }
}

function observeRepositoryState(
  harness: HarnessStateV1,
  cwd: string,
): {
  readonly repositoryIdentity: FixtureRepositoryObservationV1["repositoryIdentity"];
  readonly state: RepositoryStateV1;
} {
  assertHostileStateAbsent(harness, cwd);
  const objectFormat = readObjectFormat(harness, cwd);
  const headCommit = runGit(harness, cwd, [
    "rev-parse",
    "--verify",
    "HEAD^{commit}",
  ]).stdout.trim();
  const headTree = runGit(harness, cwd, [
    "rev-parse",
    "HEAD^{tree}",
  ]).stdout.trim();
  const branch = readBranch(harness, cwd);
  const status = runGit(harness, cwd, [
    "status",
    "--porcelain=v2",
    "-z",
    "--branch",
    "--untracked-files=all",
    "--ignored=matching",
  ]).stdout;
  const indexEntries = runGit(harness, cwd, ["ls-files", "--stage", "-z"])
    .stdout.split("\0")
    .filter(Boolean)
    .map((entry) => {
      const match = /^(\d{6}) ([a-f0-9]{40,64}) (\d)\t(.+)$/u.exec(entry);
      if (!match)
        throw new TypeError(
          FIXTURE_DIAGNOSTIC_MESSAGES_V1["repository-identity-drift"],
        );
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
    indexEntries.map((entry) => {
      const relative = indexEntries.find(
        (candidate) => candidate.pathDigest === entry.pathDigest,
      )?.pathDigest;
      const actualPath = relative;
      return {
        ...entry,
        size: actualPath,
      };
    }),
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
  const clean =
    dirtyTracked.length === 0 &&
    untracked.length === 0 &&
    ignored.length === 0 &&
    conflicts.length === 0;
  const worktreeSetDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-worktree-set/1.0.0",
    parseWorktreeList(harness, cwd),
  );
  const untrackedSetDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-untracked-set/1.0.0",
    untracked.map((entry) => pathDigestForRelative(entry)),
  );
  const ignoredSetDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-ignored-set/1.0.0",
    ignored.map((entry) => pathDigestForRelative(entry)),
  );
  const conflictSetDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-conflict-set/1.0.0",
    conflicts.map((entry) => pathDigestForRelative(entry)),
  );
  const submoduleSetDigest = CLEAN_REPOSITORY_DIGESTS_V1.submoduleSetDigest;
  const filesystemObservations: unknown[] = walkTree(cwd);
  const gitDir = readGitAbsoluteDir(harness, cwd);
  if (gitDir !== cwd && !containsPath(cwd, gitDir)) {
    filesystemObservations.push(...walkTree(gitDir, "__admin__"));
  }
  const filesystemSentinelDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-filesystem-sentinel/1.0.0",
    filesystemObservations,
  );
  countGitObjects(harness, cwd);
  return {
    repositoryIdentity: {
      commonDirectoryDigest: commonDirectoryDigest(
        readGitCommonDir(harness, cwd),
      ),
      objectFormat,
    },
    state: Object.freeze({
      headCommit,
      headTree,
      branch,
      detached: branch === null,
      clean,
      indexDigest,
      trackedWorktreeDigest,
      untrackedSetDigest,
      ignoredSetDigest,
      conflictSetDigest,
      submoduleSetDigest,
      filesystemSentinelDigest,
      worktreeSetDigest,
    }),
  };
}

function parseWorktreeList(
  harness: HarnessStateV1,
  cwd: string,
): readonly unknown[] {
  const output = runGit(harness, cwd, [
    "worktree",
    "list",
    "--porcelain",
    "-z",
  ]).stdout;
  const records = output.split("\0").filter(Boolean);
  const worktrees: Array<Record<string, unknown>> = [];
  let current: Record<string, unknown> | null = null;
  for (const record of records) {
    if (record.startsWith("worktree ")) {
      if (current) worktrees.push(current);
      current = Object.create(null) as Record<string, unknown>;
      current.pathDigest = computeGitCheckFixtureDigestV1(
        "spts.fixture-path/1.0.0",
        record.slice(9),
      );
      continue;
    }
    if (!current) continue;
    if (record.startsWith("HEAD ")) current.head = record.slice(5);
    else if (record.startsWith("branch ")) current.branch = record.slice(7);
    else if (record === "detached") current.detached = true;
  }
  if (current) worktrees.push(current);
  worktrees.sort((left, right) =>
    String(left.pathDigest).localeCompare(String(right.pathDigest)),
  );
  return worktrees;
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

function operationDirectory(
  state: HarnessStateV1,
  operationId: string,
): string {
  const digest = createHash("sha256").update(operationId, "utf8").digest("hex");
  return join(state.directories.operations, digest);
}

function writeOperationRecord(
  state: HarnessStateV1,
  record: OperationRecordV1,
): void {
  const directory = operationDirectory(state, record.operationId);
  ensureDirectory(directory, 0o700);
  const path = join(directory, "completed.json");
  writeCanonicalJson(path, {
    ...record,
    recordDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-operation-record/1.0.0",
      record,
    ),
  });
  writeCanonicalJson(
    join(
      state.directories.transactions,
      `${createHash("sha256").update(record.operationId).digest("hex")}.head`,
    ),
    {
      operationId: record.operationId,
      requestDigest: record.requestDigest,
    },
  );
  state.operations.set(record.operationId, record);
}

function loadOperationRecords(state: HarnessStateV1): void {
  if (!existsSync(state.directories.operations)) return;
  for (const directory of readdirSync(state.directories.operations)) {
    const completedPath = join(
      state.directories.operations,
      directory,
      "completed.json",
    );
    if (!existsSync(completedPath)) continue;
    const record = readCanonicalJson<
      OperationRecordV1 & { readonly recordDigest: string }
    >(completedPath);
    state.operations.set(record.operationId, {
      operationId: record.operationId,
      kind: record.kind,
      requestDigest: record.requestDigest,
      result: record.result,
    });
  }
}

function registrationDirectory(
  state: HarnessStateV1,
  registrationDigest: string,
): string {
  return join(state.directories.registrations, registrationDigest);
}

function writeRegistrationRecord(
  state: HarnessStateV1,
  registration: RegistrationStateV1,
): void {
  const directory = registrationDirectory(
    state,
    registration.registrationDigest,
  );
  ensureDirectory(directory, 0o700);
  const previousDigest =
    registration.generation > 1
      ? readCanonicalJson<FixtureRegistrationRecordV1>(
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
    workspacePathDigest: digestRelativePathV1([
      registration.registrationDigest,
    ]),
    adminDirectoryDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-common-directory/1.0.0",
      registration.adminDirectory,
    ),
    state: registration.state,
    generation: registration.generation,
    previousDigest,
  });
  writeCanonicalJson(
    join(directory, `${registration.generation}.json`),
    record,
  );
}

function loadRegistrationRecords(state: HarnessStateV1): void {
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
    const record = readCanonicalJson<FixtureRegistrationRecordV1>(
      join(directory, `${latest}.json`),
    );
    const role = record.role;
    const path =
      role === "fixture-remote"
        ? join(state.directories.remotes, `${digest}.git`)
        : role === "principal-candidate"
          ? join(state.directories.repositories, digest)
          : join(state.directories.worktrees, digest);
    const commonDirectory =
      role === "fixture-remote"
        ? path
        : existsSync(path)
          ? readGitCommonDir(state, path)
          : path;
    const adminDirectory =
      role === "fixture-remote"
        ? path
        : existsSync(path)
          ? readGitAbsoluteDir(state, path)
          : path;
    state.registrations.set(record.registrationId, {
      registrationId: record.registrationId,
      registrationDigest: record.registrationDigest,
      role,
      checkId: record.checkId,
      sourceRegistrationId: record.sourceRegistrationId,
      path,
      commonDirectory,
      adminDirectory,
      commonDirectoryDigest: record.commonDirectoryDigest,
      candidateCommit: record.candidateCommit,
      candidateTree: record.candidateTree,
      state: record.state,
      generation: record.generation,
    });
  }
}

function checkReplay<
  T extends
    FixtureRepositoryObservationV1 | ValidationResult<NamedCheckResultV1>,
>(state: HarnessStateV1, operationId: string, requestDigest: string): T | null {
  const record = state.operations.get(operationId);
  if (!record) return null;
  if (record.requestDigest !== requestDigest) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["operation-replay-conflict"],
    );
  }
  return record.result as T;
}

function currentSequence(state: HarnessStateV1): number {
  return state.operations.size + 1;
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
    readonly candidateCommit: string | null;
    readonly candidateTree: string | null;
    readonly lifecycleState: RegistrationStateV1["state"];
  },
): RegistrationStateV1 {
  const registrationDigest = registrationDigestV1({
    registrationId: input.registrationId,
  });
  return {
    registrationId: input.registrationId,
    registrationDigest,
    role: input.role,
    checkId: input.checkId,
    sourceRegistrationId: input.sourceRegistrationId,
    path: input.path,
    commonDirectory: input.commonDirectory,
    adminDirectory: input.adminDirectory,
    commonDirectoryDigest: commonDirectoryDigest(input.commonDirectory),
    candidateCommit: input.candidateCommit,
    candidateTree: input.candidateTree,
    state: input.lifecycleState,
    generation: 1,
  };
}

function ensureHarnessActive(state: HarnessStateV1): void {
  if (state.status !== "active") {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  revalidateTrustedPolicyState(state.policyState);
  const rootIdentity = snapshotDirectoryIdentity(state.rootPath);
  if (!sameDirectoryIdentity(state.rootIdentity, rootIdentity)) {
    state.policyState.revoked = true;
    state.status = "cancelled";
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["trusted-root-invalid"]);
  }
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
  if (request.checkId !== null) validateSafeId("checkId", request.checkId);
  if (request.role === "named-check" && request.checkId === null) {
    throw new TypeError("named-check registrations require a check identifier");
  }
}

function fixtureFileRelativePath(file: Readonly<FixtureFileV1>): string {
  return file.pathComponents.join("/");
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

function writeFixtureFile(path: string, file: Readonly<FixtureFileV1>): void {
  ensureDirectory(dirname(path), 0o700);
  writeFileSync(path, file.content, {
    mode: file.mode === "100755" ? 0o755 : 0o644,
  });
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

function candidateTreeForCommit(
  state: HarnessStateV1,
  registration: RegistrationStateV1,
  commit: string,
): string {
  return runGit(state, registration.path, [
    "rev-parse",
    `${commit}^{tree}`,
  ]).stdout.trim();
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
  const parentIdentity = snapshotDirectoryIdentity(trustedParent);
  const gitExecutableIdentity = snapshotFileIdentity(definition.gitExecutable);
  const gitExecPathIdentity = snapshotDirectoryIdentity(definition.gitExecPath);
  const seen = new Set<string>();
  const namedChecks = definition.namedChecks
    .map((entry) => validateNamedCheckEntry(entry, limits))
    .sort((left, right) => left.checkId.localeCompare(right.checkId));
  for (const entry of namedChecks) {
    if (seen.has(entry.checkId)) {
      throw new TypeError("named check identifiers must be unique");
    }
    seen.add(entry.checkId);
  }
  const authority = createNamedCheckAuthorityV1({
    policyId: definition.policyId,
    checks: namedChecks,
  });
  const publicPolicy: TrustedFixtureGitPolicyV1 = Object.freeze({
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
      const state = requirePolicyState(publicPolicy);
      state.revoked = true;
      for (const harness of state.harnesses) {
        const harnessState = requireHarnessState(harness);
        if (harnessState.status === "active") harnessState.status = "closing";
        writeRootManifest(harnessState);
        if (harnessState.status !== "removed") harnessState.status = "closed";
        writeRootManifest(harnessState);
      }
    },
  });
  POLICY_STATE.set(publicPolicy, {
    publicPolicy,
    parentIdentity,
    gitExecutableIdentity,
    gitExecPathIdentity,
    namedChecks,
    limits,
    authority,
    revoked: false,
    harnesses: new Set(),
  });
  return publicPolicy;
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
  const suffix = randomBytes(16).toString("hex");
  const rootPath = join(
    policyState.parentIdentity.path,
    `spts-fixture-${suffix}`,
  );
  ensureDirectory(rootPath, 0o700);
  const directories = createRunDirectories(rootPath);
  const rootIdentity = snapshotDirectoryIdentity(rootPath);
  const harnessState: HarnessStateV1 = {
    policyState,
    runId: options.runId,
    taskId: options.taskId,
    expectedBaseCommit: options.expectedBaseCommit,
    expectedBaseTree: options.expectedBaseTree,
    runDigest,
    rootPath,
    rootIdentity,
    directories,
    operations: new Map(),
    registrations: new Map(),
    status: "active",
  };
  validateGitVersion(harnessState);
  writeRootManifest(harnessState);

  const harness: FixtureRepositoryHarnessV1 = Object.freeze({
    runId: options.runId,
    taskId: options.taskId,
    expectedBaseCommit: options.expectedBaseCommit,
    expectedBaseTree: options.expectedBaseTree,
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
    cancel: async () => {
      const state = requireHarnessState(harness);
      if (state.status === "active") state.status = "cancelled";
      writeRootManifest(state);
    },
    close: async () => {
      const state = requireHarnessState(harness);
      if (state.status === "active" || state.status === "cancelled") {
        state.status = "closed";
        writeRootManifest(state);
      }
    },
    cleanup: async () => {
      const state = requireHarnessState(harness);
      if (state.status !== "closed" && state.status !== "cancelled") {
        throw new TypeError("fixture harness must be closed before cleanup");
      }
      rmSync(state.rootPath, { recursive: true, force: true });
      state.status = "removed";
    },
  });
  HARNESS_STATE.set(harness, harnessState);
  policyState.harnesses.add(harness);
  return harness;
}

export async function recoverFixtureRepositoryHarnessV1(
  policy: TrustedFixtureGitPolicyV1,
  options: CreateFixtureRepositoryHarnessV1Options,
): Promise<FixtureRepositoryHarnessV1> {
  const policyState = requirePolicyState(policy);
  revalidateTrustedPolicyState(policyState);
  const runDigest = deriveRunDigest(policy.policyId, options);
  const matches = readdirSync(policyState.parentIdentity.path)
    .map((entry) => join(policyState.parentIdentity.path, entry))
    .filter((entry) => existsSync(join(entry, "metadata", ROOT_MANIFEST_FILE)));
  for (const candidate of matches) {
    const manifestPath = join(candidate, "metadata", ROOT_MANIFEST_FILE);
    const manifest = readCanonicalJson<{ readonly runDigest: string }>(
      manifestPath,
    );
    if (manifest.runDigest !== runDigest) continue;
    const directories = createRunDirectories(candidate);
    const harnessState: HarnessStateV1 = {
      policyState,
      runId: options.runId,
      taskId: options.taskId,
      expectedBaseCommit: options.expectedBaseCommit,
      expectedBaseTree: options.expectedBaseTree,
      runDigest,
      rootPath: candidate,
      rootIdentity: snapshotDirectoryIdentity(candidate),
      directories,
      operations: new Map(),
      registrations: new Map(),
      status: "closed",
    };
    loadOperationRecords(harnessState);
    loadRegistrationRecords(harnessState);
    const harness = await createFixtureRepositoryHarnessV1(policy, options);
    const createdState = requireHarnessState(harness);
    rmSync(createdState.rootPath, { recursive: true, force: true });
    HARNESS_STATE.set(harness, harnessState);
    return harness;
  }
  throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["storage-unavailable"]);
}

async function createRepository(
  harness: FixtureRepositoryHarnessV1,
  request: CreateRepositoryRequestV1,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessActive(state);
  const files = validateRepositoryRequest(request);
  const requestDigest = requestDigestForRepository(
    state.policyState.publicPolicy.policyId,
    request,
    files,
  );
  try {
    const replay = checkReplay<FixtureRepositoryObservationV1>(
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
  const digest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const repositoryPath = join(state.directories.repositories, digest);
  ensureContained(state.directories.repositories, repositoryPath);
  runGit(state, state.rootPath, [
    "init",
    "--object-format=sha256",
    "--initial-branch=fixture-main",
    repositoryPath,
  ]);
  for (const file of files) {
    writeFixtureFile(join(repositoryPath, fixtureFileRelativePath(file)), file);
  }
  runGit(state, repositoryPath, ["add", "--all", "--"]);
  runGit(
    state,
    repositoryPath,
    ["commit", "--no-verify", "--no-gpg-sign", "-m", "Initialize SPTS fixture"],
    {
      environment: {
        GIT_AUTHOR_NAME: "SPTS Fixture",
        GIT_AUTHOR_EMAIL: "fixture.invalid",
        GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
        GIT_COMMITTER_NAME: "SPTS Fixture",
        GIT_COMMITTER_EMAIL: "fixture.invalid",
        GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
      },
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
    candidateCommit: observation.state.headCommit,
    candidateTree: observation.state.headTree,
    lifecycleState: "retained",
  });
  state.registrations.set(request.registrationId, registration);
  writeRegistrationRecord(state, registration);
  const completed = createObservation(state, {
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
  writeOperationRecord(state, {
    operationId: request.operationId,
    kind: "create-repository",
    requestDigest,
    result: completed,
  });
  return completed;
}

async function createBareRemote(
  harness: FixtureRepositoryHarnessV1,
  request: CreateBareRemoteRequestV1,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessActive(state);
  validateRemoteRequest(request);
  const requestDigest = requestDigestForRemote(
    state.policyState.publicPolicy.policyId,
    request,
  );
  try {
    const replay = checkReplay<FixtureRepositoryObservationV1>(
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
  const source = sourceRegistration(state, request.sourceRegistrationId);
  const digest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const remotePath = join(state.directories.remotes, `${digest}.git`);
  runGit(state, state.rootPath, [
    "init",
    "--bare",
    "--object-format=sha256",
    "--initial-branch=fixture-main",
    remotePath,
  ]);
  runGit(
    state,
    source.path,
    [
      "push",
      "--no-verify",
      remotePath,
      "refs/heads/fixture-main:refs/heads/fixture-main",
    ],
    { allowFileProtocol: remotePath },
  );
  const registration = createRegistrationState(state, {
    registrationId: request.registrationId,
    role: "fixture-remote",
    checkId: null,
    sourceRegistrationId: request.sourceRegistrationId,
    path: remotePath,
    commonDirectory: remotePath,
    adminDirectory: remotePath,
    candidateCommit: source.candidateCommit,
    candidateTree: source.candidateTree,
    lifecycleState: "retained",
  });
  state.registrations.set(request.registrationId, registration);
  writeRegistrationRecord(state, registration);
  const completed = createObservation(state, {
    operationId: request.operationId,
    registrationId: request.registrationId,
    operationKind: "create-bare-remote",
    purpose: "fixture-remote",
    sequence: currentSequence(state),
    repositoryIdentity: {
      commonDirectoryDigest: commonDirectoryDigest(remotePath),
      objectFormat: "sha256",
    },
    pre: null,
    post: null,
    outcome: "applied",
    diagnostic: null,
    requestDigest,
  });
  writeOperationRecord(state, {
    operationId: request.operationId,
    kind: "create-bare-remote",
    requestDigest,
    result: completed,
  });
  return completed;
}

async function createWorktree(
  harness: FixtureRepositoryHarnessV1,
  request: RegisterWorktreeRequestV1,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessActive(state);
  validateWorktreeRequest(request);
  const requestDigest = requestDigestForWorktree(
    state.policyState.publicPolicy.policyId,
    request,
  );
  try {
    const replay = checkReplay<FixtureRepositoryObservationV1>(
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
  const candidateTree = candidateTreeForCommit(
    state,
    source,
    request.candidateCommit,
  );
  if (candidateTree !== request.candidateTree) {
    return operationConflictObservation(state, {
      operationId: request.operationId,
      registrationId: request.registrationId,
      operationKind: "create-worktree",
      purpose: request.role,
      requestDigest,
      diagnosticCode: "candidate-identity-drift",
    });
  }
  const digest = registrationDigestV1({
    registrationId: request.registrationId,
  });
  const worktreePath = join(state.directories.worktrees, digest);
  runGit(state, source.path, [
    "worktree",
    "add",
    "--detach",
    worktreePath,
    request.candidateCommit,
  ]);
  const observation = observeRepositoryState(state, worktreePath);
  const registration = createRegistrationState(state, {
    registrationId: request.registrationId,
    role: request.role,
    checkId: request.checkId,
    sourceRegistrationId: request.sourceRegistrationId,
    path: worktreePath,
    commonDirectory: readGitCommonDir(state, worktreePath),
    adminDirectory: readGitAbsoluteDir(state, worktreePath),
    candidateCommit: request.candidateCommit,
    candidateTree: request.candidateTree,
    lifecycleState: "active",
  });
  state.registrations.set(request.registrationId, registration);
  writeRegistrationRecord(state, registration);
  const completed = createObservation(state, {
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
  writeOperationRecord(state, {
    operationId: request.operationId,
    kind: "create-worktree",
    requestDigest,
    result: completed,
  });
  return completed;
}

async function inspectWorktrees(
  harness: FixtureRepositoryHarnessV1,
  operationId: string,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  ensureHarnessActive(state);
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
    purpose: "inspect-worktrees",
  });
  try {
    const replay = checkReplay<FixtureRepositoryObservationV1>(
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
  const observation = observeRepositoryState(state, rootRegistration.path);
  const completed = createObservation(state, {
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
  writeOperationRecord(state, {
    operationId,
    kind: "inspect-worktrees",
    requestDigest,
    result: completed,
  });
  return completed;
}

async function removeWorktree(
  harness: FixtureRepositoryHarnessV1,
  operationId: string,
  registrationId: string,
): Promise<FixtureRepositoryObservationV1> {
  const state = requireHarnessState(harness);
  validateSafeId("operationId", operationId);
  validateSafeId("registrationId", registrationId);
  ensureHarnessActive(state);
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
  const requestDigest = computeFixtureRepositoryRequestDigestV1({
    policyId: state.policyState.publicPolicy.policyId,
    operationId,
    registrationId,
    sourceRegistrationId: registration.sourceRegistrationId,
  });
  const pre = observeRepositoryState(state, registration.path);
  runGit(state, registration.path, [
    "worktree",
    "remove",
    "--force",
    registration.path,
  ]);
  registration.state = "removed";
  registration.generation += 1;
  writeRegistrationRecord(state, registration);
  const completed = createObservation(state, {
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
  writeOperationRecord(state, {
    operationId,
    kind: "remove-worktree",
    requestDigest,
    result: completed,
  });
  return completed;
}

async function issueHarnessNamedCheckPermitV1(
  harness: FixtureRepositoryHarnessV1,
  request: IssueHarnessNamedCheckPermitV1Input,
): Promise<NamedCheckPermitV1> {
  const state = requireHarnessState(harness);
  ensureHarnessActive(state);
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
  if (
    registration.role !== "named-check" ||
    registration.checkId !== request.checkId
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
    cwd: registration.path,
    homeDirectory: state.directories.home,
    beforeObservation: {
      workspaceTree: observation.state.headTree,
      sentinelDigest: workspaceOnlySentinelDigest(registration.path),
    },
    observeAfter: () => {
      const after = observeRepositoryState(state, registration.path);
      return {
        workspaceTree: after.state.headTree,
        sentinelDigest: workspaceOnlySentinelDigest(registration.path),
      };
    },
  };
  return issueRuntimeNamedCheckPermitV1(
    state.policyState.authority,
    {
      operationId: request.operationId,
      runId: state.runId,
      registrationId: request.registrationId,
      checkId: request.checkId,
      attempt: request.attempt,
      candidateCommit: registration.candidateCommit ?? "",
      candidateTree: registration.candidateTree ?? "",
      workspaceIdentityToken: registration,
      requestDigest,
    },
    options,
  );
}

async function runHarnessNamedCheckV1(
  harness: FixtureRepositoryHarnessV1,
  request: RunNamedCheckRequestV1,
): Promise<ValidationResult<NamedCheckResultV1>> {
  const state = requireHarnessState(harness);
  ensureHarnessActive(state);
  const registration = sourceRegistration(state, request.registrationId);
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
    const replay = checkReplay<ValidationResult<NamedCheckResultV1>>(
      state,
      request.operationId,
      requestDigest,
    );
    if (replay) return replay;
  } catch {
    return {
      valid: true,
      value: Object.freeze({
        contract: "spts.named-check-result",
        version: "1.0.0",
        runId: state.runId,
        operationId: request.operationId,
        checkId: request.checkId,
        registrationId: request.registrationId,
        attempt: request.attempt,
        candidateCommit: registration.candidateCommit ?? "0".repeat(64),
        candidateTree: registration.candidateTree ?? "0".repeat(64),
        workspaceTreeBefore: registration.candidateTree ?? "0".repeat(64),
        workspaceTreeAfter: registration.candidateTree ?? "0".repeat(64),
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
        diagnostic: createFixtureDiagnosticV1(
          "operation-replay-conflict" as FixtureDiagnosticCodeV1,
        ),
        requestDigest,
        resultDigest: computeGitCheckFixtureDigestV1(
          "spts.named-check-result/1.0.0",
          {
            replayConflict: true,
            requestDigest,
          },
        ),
      } as NamedCheckResultV1),
    };
  }
  const permit = await issueHarnessNamedCheckPermitV1(harness, request);
  const result = await runExactNamedCheckV1({ permit, signal: request.signal });
  writeOperationRecord(state, {
    operationId: request.operationId,
    kind: "named-check",
    requestDigest,
    result,
  });
  return result;
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

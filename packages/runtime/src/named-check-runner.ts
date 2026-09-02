import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { SpawnOptions } from "node:child_process";

import {
  CLEAN_REPOSITORY_DIGESTS_V1,
  FIXTURE_DIAGNOSTIC_MESSAGES_V1,
  computeGitCheckFixtureDigestV1,
  computeNamedCheckResultDigestV1,
  containsCredentialShapedContent,
  createFixtureDiagnosticV1,
  validateNamedCheckResultV1,
  type NamedCheckResultV1,
  type RepositoryStateV1,
  type ValidationResult,
} from "@scrum-pi-team-skills/contracts";

import {
  createNodeProcessAdapter,
  type ProcessAdapter,
  type RuntimeClock,
} from "./process-host.js";

export interface NamedCheckAuthorityV1Definition {
  readonly checkId: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly maxDurationMs: number;
  readonly maxOutputBytes: number;
}

export interface NamedCheckWorkspaceBindingV1 {
  readonly cwd: string;
  readonly homeDirectory: string;
}

export interface NamedCheckAuthorityCreationV1 {
  readonly policyId: string;
  readonly checks: readonly NamedCheckAuthorityV1Definition[];
  readonly resolveWorkspaceExecution: (
    workspaceIdentityToken: object,
  ) => NamedCheckWorkspaceBindingV1;
}

export interface NamedCheckAuthorityV1 {
  readonly policyId: string;
  readonly checkIds: readonly string[];
}

export interface IssueNamedCheckPermitV1Input {
  readonly operationId: string;
  readonly runId: string;
  readonly registrationId: string;
  readonly checkId: string;
  readonly attempt: number;
  readonly candidateCommit: string;
  readonly candidateTree: string;
  readonly workspaceIdentityToken: object;
  readonly requestDigest: string;
}

export interface NamedCheckRepositoryObservationV1 {
  readonly repositoryIdentity: {
    readonly commonDirectoryDigest: string;
    readonly objectFormat: "sha1" | "sha256";
  };
  readonly state: RepositoryStateV1;
  readonly workspaceSentinelDigest?: string;
  readonly adminSentinelDigest?: string;
}

export interface IssueNamedCheckPermitV1Options {
  readonly beforeObservation?: NamedCheckRepositoryObservationV1;
  readonly observeAfter?: () =>
    | NamedCheckRepositoryObservationV1
    | Promise<NamedCheckRepositoryObservationV1>;
}

export interface NamedCheckPermitV1 {
  readonly operationId: string;
  readonly runId: string;
  readonly registrationId: string;
  readonly checkId: string;
  readonly attempt: number;
  readonly candidateCommit: string;
  readonly candidateTree: string;
  readonly requestDigest: string;
}

export interface RunExactNamedCheckV1Input {
  readonly permit: NamedCheckPermitV1;
  readonly signal?: AbortSignal;
  readonly clock?: RuntimeClock;
  readonly processAdapter?: ProcessAdapter;
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

interface CheckDefinitionStateV1 {
  readonly checkId: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly executableIdentity: FileIdentityV1;
  readonly maxDurationMs: number;
  readonly maxOutputBytes: number;
}

interface NamedCheckAuthorityStateV1 {
  readonly policyId: string;
  readonly checks: ReadonlyMap<string, CheckDefinitionStateV1>;
  readonly resolveWorkspaceExecution: (
    workspaceIdentityToken: object,
  ) => NamedCheckWorkspaceBindingV1;
}

type PermitStateStatusV1 =
  | "issued"
  | "consumed-before-spawn"
  | "started"
  | "observing"
  | "completed"
  | "consumed-cancelled"
  | "recovery-required";

interface NamedCheckPermitStateV1 {
  readonly authority: NamedCheckAuthorityStateV1;
  readonly check: CheckDefinitionStateV1;
  readonly input: IssueNamedCheckPermitV1Input;
  readonly cwd: string;
  readonly homeDirectory: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly before: Readonly<NamedCheckRepositoryObservationV1>;
  readonly observeAfter: () =>
    | NamedCheckRepositoryObservationV1
    | Promise<NamedCheckRepositoryObservationV1>;
  readonly issuedAtMs: number;
  readonly deadlineMs: number;
  status: PermitStateStatusV1;
}

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const FORBIDDEN_ARGV_PATTERN = /(?:[`$;&|<>]|\$\(|^@)/;
const MAX_ARG_COUNT = 32;
const MAX_ARG_BYTES = 1024;
const MAX_ARGV_BYTES = 8192;
const MAX_OUTPUT_BYTES_PER_STREAM = 1024 * 1024;
const MAX_COMBINED_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_DURATION_MS = 15 * 60 * 1000;
const TERMINATION_GRACE_MS = 5_000;
const KILL_CONFIRMATION_MS = 5_000;
const PROCESS_POLL_MS = 50;

const defaultClock: RuntimeClock = Object.freeze({
  now: () => new Date().toISOString(),
  setTimeout: (callback: () => void, milliseconds: number) =>
    setTimeout(callback, milliseconds),
  clearTimeout: (timer: unknown) => clearTimeout(timer as NodeJS.Timeout),
});

const authorityStates = new WeakMap<object, NamedCheckAuthorityStateV1>();
const permitStates = new WeakMap<object, NamedCheckPermitStateV1>();

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

function validateDigest(label: string, value: unknown): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
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

function snapshotExecutableIdentity(path: string): FileIdentityV1 {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) {
    throw new TypeError("named check executable is invalid");
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

function sameExecutableIdentity(
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

function validateArgv(argv: readonly string[]): readonly string[] {
  if (argv.length > MAX_ARG_COUNT) {
    throw new TypeError("named check argv exceeds the permitted size");
  }
  let total = 0;
  const snapshot = argv.map((value) => {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      utf8Bytes(value) > MAX_ARG_BYTES ||
      FORBIDDEN_ARGV_PATTERN.test(value) ||
      hasControlCharacter(value)
    ) {
      throw new TypeError("named check argv is invalid");
    }
    total += utf8Bytes(value);
    return value;
  });
  if (total > MAX_ARGV_BYTES) {
    throw new TypeError("named check argv exceeds the permitted size");
  }
  return Object.freeze([...snapshot]);
}

function validateNamedCheckDefinition(
  value: NamedCheckAuthorityV1Definition,
): CheckDefinitionStateV1 {
  validateSafeId("checkId", value.checkId);
  if (typeof value.executable !== "string" || !isAbsolute(value.executable)) {
    throw new TypeError("named check executable is invalid");
  }
  if (
    !Number.isSafeInteger(value.maxDurationMs) ||
    value.maxDurationMs <= 0 ||
    value.maxDurationMs > MAX_DURATION_MS
  ) {
    throw new TypeError("named check duration is invalid");
  }
  if (
    !Number.isSafeInteger(value.maxOutputBytes) ||
    value.maxOutputBytes <= 0 ||
    value.maxOutputBytes > MAX_OUTPUT_BYTES_PER_STREAM
  ) {
    throw new TypeError("named check output limit is invalid");
  }
  return Object.freeze({
    checkId: value.checkId,
    executable: value.executable,
    argv: validateArgv(value.argv),
    executableIdentity: snapshotExecutableIdentity(value.executable),
    maxDurationMs: value.maxDurationMs,
    maxOutputBytes: value.maxOutputBytes,
  });
}

function defaultObservationFor(
  candidateTree: string,
): NamedCheckRepositoryObservationV1 {
  return Object.freeze({
    repositoryIdentity: Object.freeze({
      commonDirectoryDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-common-directory/1.0.0",
        candidateTree,
      ),
      objectFormat: "sha256",
    }),
    state: Object.freeze({
      headCommit: candidateTree,
      headTree: candidateTree,
      branch: null,
      detached: true,
      clean: true,
      indexDigest: CLEAN_REPOSITORY_DIGESTS_V1.indexDigest,
      trackedWorktreeDigest: CLEAN_REPOSITORY_DIGESTS_V1.trackedWorktreeDigest,
      untrackedSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.untrackedSetDigest,
      ignoredSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.ignoredSetDigest,
      conflictSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.conflictSetDigest,
      submoduleSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.submoduleSetDigest,
      filesystemSentinelDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-filesystem-sentinel/1.0.0",
        [],
      ),
      worktreeSetDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-worktree-set/1.0.0",
        [],
      ),
    }),
    workspaceSentinelDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-filesystem-sentinel/1.0.0",
      [],
    ),
    adminSentinelDigest: computeGitCheckFixtureDigestV1(
      "spts.fixture-filesystem-sentinel/1.0.0",
      [],
    ),
  });
}

function validateRepositoryState(
  value: RepositoryStateV1,
): Readonly<RepositoryStateV1> {
  validateObjectId("headCommit", value.headCommit);
  validateObjectId("headTree", value.headTree);
  if (value.branch !== null) validateSafeId("branch", value.branch);
  if (value.detached !== (value.branch === null)) {
    throw new TypeError("named check repository observation is invalid");
  }
  if (typeof value.clean !== "boolean") {
    throw new TypeError("named check repository observation is invalid");
  }
  validateDigest("indexDigest", value.indexDigest);
  validateDigest("trackedWorktreeDigest", value.trackedWorktreeDigest);
  validateDigest("untrackedSetDigest", value.untrackedSetDigest);
  validateDigest("ignoredSetDigest", value.ignoredSetDigest);
  validateDigest("conflictSetDigest", value.conflictSetDigest);
  validateDigest("submoduleSetDigest", value.submoduleSetDigest);
  validateDigest("filesystemSentinelDigest", value.filesystemSentinelDigest);
  validateDigest("worktreeSetDigest", value.worktreeSetDigest);
  return Object.freeze({ ...value });
}

function validateRepositoryObservation(
  value: NamedCheckRepositoryObservationV1,
): Readonly<NamedCheckRepositoryObservationV1> {
  validateDigest(
    "commonDirectoryDigest",
    value.repositoryIdentity.commonDirectoryDigest,
  );
  if (
    value.repositoryIdentity.objectFormat !== "sha1" &&
    value.repositoryIdentity.objectFormat !== "sha256"
  ) {
    throw new TypeError("named check repository observation is invalid");
  }
  return Object.freeze({
    repositoryIdentity: Object.freeze({
      commonDirectoryDigest: value.repositoryIdentity.commonDirectoryDigest,
      objectFormat: value.repositoryIdentity.objectFormat,
    }),
    state: validateRepositoryState(value.state),
    workspaceSentinelDigest:
      value.workspaceSentinelDigest === undefined
        ? undefined
        : validateDigest(
            "workspaceSentinelDigest",
            value.workspaceSentinelDigest,
          ),
    adminSentinelDigest:
      value.adminSentinelDigest === undefined
        ? undefined
        : validateDigest("adminSentinelDigest", value.adminSentinelDigest),
  });
}

function copyExactEnvironment(
  homeDirectory: string,
): Readonly<Record<string, string>> {
  const result = Object.create(null) as Record<string, string>;
  result.HOME = homeDirectory;
  result.XDG_CONFIG_HOME = homeDirectory;
  result.LANG = "C";
  result.LC_ALL = "C";
  result.TZ = "UTC";
  result.CI = "1";
  result.NO_COLOR = "1";
  result.GIT_CONFIG_NOSYSTEM = "1";
  result.GIT_CONFIG_GLOBAL = "/dev/null";
  result.GIT_TERMINAL_PROMPT = "0";
  result.GCM_INTERACTIVE = "never";
  result.GIT_ASKPASS = "/bin/false";
  result.SSH_ASKPASS = "/bin/false";
  result.GIT_PAGER = "cat";
  result.PAGER = "cat";
  return Object.freeze(result);
}

function requireAuthority(value: unknown): NamedCheckAuthorityStateV1 {
  if (typeof value !== "object" || value === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  const authority = authorityStates.get(value);
  if (!authority) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  return authority;
}

function requirePermit(value: unknown): NamedCheckPermitStateV1 {
  if (typeof value !== "object" || value === null) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  const state = permitStates.get(value);
  if (!state) {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  return state;
}

function normalizeSignal(
  signal: NodeJS.Signals | null,
): "SIGINT" | "SIGTERM" | "SIGKILL" | null {
  return signal === "SIGINT" || signal === "SIGTERM" || signal === "SIGKILL"
    ? signal
    : null;
}

function observeOutputDigest(): ReturnType<typeof createHash> {
  return createHash("sha256");
}

function nowMs(clock: RuntimeClock): number {
  return Date.parse(clock.now());
}

function wait(clock: RuntimeClock, milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = clock.setTimeout(resolve, milliseconds);
    void timer;
  });
}

function observationsMatchCore(
  before: NamedCheckRepositoryObservationV1,
  after: NamedCheckRepositoryObservationV1,
): boolean {
  return (
    before.repositoryIdentity.commonDirectoryDigest ===
      after.repositoryIdentity.commonDirectoryDigest &&
    before.repositoryIdentity.objectFormat ===
      after.repositoryIdentity.objectFormat &&
    before.state.headCommit === after.state.headCommit &&
    before.state.headTree === after.state.headTree &&
    before.state.branch === after.state.branch &&
    before.state.detached === after.state.detached &&
    before.state.clean === after.state.clean &&
    before.state.indexDigest === after.state.indexDigest &&
    before.state.trackedWorktreeDigest === after.state.trackedWorktreeDigest &&
    before.state.untrackedSetDigest === after.state.untrackedSetDigest &&
    before.state.ignoredSetDigest === after.state.ignoredSetDigest &&
    before.state.conflictSetDigest === after.state.conflictSetDigest &&
    before.state.submoduleSetDigest === after.state.submoduleSetDigest &&
    before.state.worktreeSetDigest === after.state.worktreeSetDigest
  );
}

function observationsMatch(
  before: NamedCheckRepositoryObservationV1,
  after: NamedCheckRepositoryObservationV1,
): boolean {
  return (
    observationsMatchCore(before, after) &&
    before.workspaceSentinelDigest === after.workspaceSentinelDigest &&
    before.adminSentinelDigest === after.adminSentinelDigest
  );
}

function observationsMatchCoreOnly(
  before: NamedCheckRepositoryObservationV1,
  after: NamedCheckRepositoryObservationV1,
): boolean {
  return observationsMatchCore(before, after);
}

export function createNamedCheckAuthorityV1(
  definition: NamedCheckAuthorityCreationV1,
): NamedCheckAuthorityV1 {
  validateSafeId("policyId", definition.policyId);
  if (typeof definition.resolveWorkspaceExecution !== "function") {
    throw new TypeError("named check workspace resolution is invalid");
  }
  if (!Array.isArray(definition.checks) || definition.checks.length === 0) {
    throw new TypeError("named check definitions are required");
  }
  const seenCheckIds = new Set<string>();
  const checkStates = definition.checks.map((entry) => {
    const state = validateNamedCheckDefinition(entry);
    if (seenCheckIds.has(state.checkId)) {
      throw new TypeError("named check identifiers must be unique");
    }
    seenCheckIds.add(state.checkId);
    return state;
  });
  checkStates.sort((left, right) => left.checkId.localeCompare(right.checkId));
  const authority = Object.freeze({
    policyId: definition.policyId,
    checkIds: Object.freeze(checkStates.map((entry) => entry.checkId)),
  });
  authorityStates.set(
    authority,
    Object.freeze({
      policyId: definition.policyId,
      checks: new Map(checkStates.map((entry) => [entry.checkId, entry])),
      resolveWorkspaceExecution: definition.resolveWorkspaceExecution,
    }),
  );
  return authority;
}

export function issueNamedCheckPermitV1(
  authority: NamedCheckAuthorityV1,
  input: IssueNamedCheckPermitV1Input,
  options: IssueNamedCheckPermitV1Options,
): NamedCheckPermitV1 {
  const authorityState = requireAuthority(authority);
  validateSafeId("operationId", input.operationId);
  validateSafeId("runId", input.runId);
  validateSafeId("registrationId", input.registrationId);
  validateSafeId("checkId", input.checkId);
  validateObjectId("candidateCommit", input.candidateCommit);
  validateObjectId("candidateTree", input.candidateTree);
  validateDigest("requestDigest", input.requestDigest);
  if (
    !Number.isSafeInteger(input.attempt) ||
    input.attempt < 1 ||
    input.attempt > 32 ||
    typeof input.workspaceIdentityToken !== "object" ||
    input.workspaceIdentityToken === null
  ) {
    throw new TypeError("named check permit input is invalid");
  }
  const check = authorityState.checks.get(input.checkId);
  if (!check) {
    throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1["check-not-allowed"]);
  }
  const resolvedWorkspace = authorityState.resolveWorkspaceExecution(
    input.workspaceIdentityToken,
  );
  const cwd = validateAbsoluteDirectory("cwd", resolvedWorkspace.cwd);
  const homeDirectory = validateAbsoluteDirectory(
    "homeDirectory",
    resolvedWorkspace.homeDirectory,
  );
  const before = validateRepositoryObservation(
    options.beforeObservation ?? defaultObservationFor(input.candidateTree),
  );
  const permit = Object.freeze({
    operationId: input.operationId,
    runId: input.runId,
    registrationId: input.registrationId,
    checkId: input.checkId,
    attempt: input.attempt,
    candidateCommit: input.candidateCommit,
    candidateTree: input.candidateTree,
    requestDigest: input.requestDigest,
  });
  const issuedAtMs = Date.now();
  permitStates.set(permit, {
    authority: authorityState,
    check,
    input,
    cwd,
    homeDirectory,
    environment: copyExactEnvironment(homeDirectory),
    before,
    observeAfter: options.observeAfter ?? (() => before),
    issuedAtMs,
    deadlineMs: issuedAtMs + check.maxDurationMs,
    status: "issued",
  });
  return permit;
}

export function cancelNamedCheckPermitV1(permit: NamedCheckPermitV1): void {
  const state = requirePermit(permit);
  if (state.status === "issued") {
    state.status = "consumed-cancelled";
    return;
  }
  if (state.status === "consumed-before-spawn") {
    state.status = "recovery-required";
  }
}

export async function runExactNamedCheckV1(
  input: RunExactNamedCheckV1Input,
): Promise<ValidationResult<NamedCheckResultV1>> {
  const state = requirePermit(input.permit);
  const clock = input.clock ?? defaultClock;
  if (state.status === "consumed-cancelled") {
    return buildResult(state, {
      startedAt: clock.now(),
      completedAt: clock.now(),
      elapsedMs: 0,
      outcome: "cancelled",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: observeOutputDigest().digest("hex"),
      stderrDigest: observeOutputDigest().digest("hex"),
      diagnostic: createFixtureDiagnosticV1("cancelled"),
      workspaceTreeAfter: state.before.state.headTree,
    });
  }
  if (state.status !== "issued") {
    throw new TypeError(
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["fixture-policy-unavailable"],
    );
  }
  if (input.signal?.aborted) {
    state.status = "consumed-cancelled";
    const cancelledAt = clock.now();
    return buildResult(state, {
      startedAt: cancelledAt,
      completedAt: cancelledAt,
      elapsedMs: 0,
      outcome: "cancelled",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: observeOutputDigest().digest("hex"),
      stderrDigest: observeOutputDigest().digest("hex"),
      diagnostic: createFixtureDiagnosticV1("cancelled"),
      workspaceTreeAfter: state.before.state.headTree,
    });
  }
  const adapter = input.processAdapter ?? createNodeProcessAdapter();
  const startedAt = clock.now();
  if (adapter.platform !== "linux") {
    const unsupported = buildResult(state, {
      startedAt,
      completedAt: clock.now(),
      elapsedMs: 0,
      outcome: "outcome-unknown",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: observeOutputDigest().digest("hex"),
      stderrDigest: observeOutputDigest().digest("hex"),
      diagnostic: createFixtureDiagnosticV1("outcome-unknown"),
      workspaceTreeAfter: state.before.state.headTree,
    });
    return unsupported;
  }

  const now = nowMs(clock);
  if (Number.isFinite(now) && now > state.deadlineMs) {
    state.status = "consumed-cancelled";
    return buildResult(state, {
      startedAt,
      completedAt: clock.now(),
      elapsedMs: 0,
      outcome: "cancelled",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: observeOutputDigest().digest("hex"),
      stderrDigest: observeOutputDigest().digest("hex"),
      diagnostic: createFixtureDiagnosticV1("cancelled"),
      workspaceTreeAfter: state.before.state.headTree,
    });
  }

  const currentIdentity = snapshotExecutableIdentity(state.check.executable);
  if (
    !sameExecutableIdentity(state.check.executableIdentity, currentIdentity)
  ) {
    state.status = "recovery-required";
    return buildResult(state, {
      startedAt,
      completedAt: clock.now(),
      elapsedMs: 0,
      outcome: "outcome-unknown",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: observeOutputDigest().digest("hex"),
      stderrDigest: observeOutputDigest().digest("hex"),
      diagnostic: createFixtureDiagnosticV1("outcome-unknown"),
      workspaceTreeAfter: state.before.state.headTree,
    });
  }

  state.status = "consumed-before-spawn";
  const stdoutHash = observeOutputDigest();
  const stderrHash = observeOutputDigest();
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let combinedBytes = 0;
  let outputOverflow = false;
  let timedOut = false;
  let cancelled = false;
  let descendantCleanupRequired = false;

  const spawnOptions: SpawnOptions = {
    shell: false,
    detached: true,
    cwd: state.cwd,
    env: state.environment,
    stdio: ["ignore", "pipe", "pipe"],
  };

  let child;
  try {
    child = adapter.spawn(
      state.check.executable,
      state.check.argv,
      spawnOptions,
    );
  } catch {
    state.status = "completed";
    return buildResult(state, {
      startedAt,
      completedAt: clock.now(),
      elapsedMs: 0,
      outcome: "spawn-failed",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: stdoutHash.digest("hex"),
      stderrDigest: stderrHash.digest("hex"),
      diagnostic: createFixtureDiagnosticV1("spawn-failed"),
      workspaceTreeAfter: state.before.state.headTree,
    });
  }

  const processGroupId = child.pid;
  if (
    processGroupId === undefined ||
    !Number.isSafeInteger(processGroupId) ||
    processGroupId <= 0 ||
    processGroupId === process.pid
  ) {
    state.status = "recovery-required";
    return buildResult(state, {
      startedAt,
      completedAt: clock.now(),
      elapsedMs: 0,
      outcome: "outcome-unknown",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: stdoutHash.digest("hex"),
      stderrDigest: stderrHash.digest("hex"),
      diagnostic: createFixtureDiagnosticV1("outcome-unknown"),
      workspaceTreeAfter: state.before.state.headTree,
    });
  }
  state.status = "started";

  const timer = clock.setTimeout(() => {
    void beginCancellation("timeout");
  }, state.check.maxDurationMs);
  let abortListener: (() => void) | undefined;

  const terminateGroup = async (): Promise<boolean> => {
    const probe = () => {
      try {
        return adapter.isProcessGroupAlive(processGroupId)
          ? "present"
          : "absent";
      } catch {
        return "unknown" as const;
      }
    };
    const signalGroup = (signal: "SIGTERM" | "SIGKILL") => {
      try {
        adapter.killProcessGroup(processGroupId, signal);
      } catch {
        // Confirmation loop is authoritative.
      }
    };

    const waitForAbsence = async (
      maximumMs: number,
    ): Promise<"absent" | "present" | "unknown"> => {
      let elapsed = 0;
      while (elapsed <= maximumMs) {
        const status = probe();
        if (status !== "present") return status;
        await wait(clock, PROCESS_POLL_MS);
        elapsed += PROCESS_POLL_MS;
      }
      return probe();
    };

    let status = await waitForAbsence(0);
    if (status === "absent") return true;
    if (status === "unknown") return false;
    signalGroup("SIGTERM");
    status = await waitForAbsence(TERMINATION_GRACE_MS);
    if (status === "absent") return true;
    descendantCleanupRequired = true;
    if (status === "unknown") return false;
    signalGroup("SIGKILL");
    status = await waitForAbsence(KILL_CONFIRMATION_MS);
    return status === "absent";
  };

  const beginCancellation = async (
    reason: "timeout" | "cancelled" | "overflow",
  ) => {
    if (reason === "timeout") timedOut = true;
    else if (reason === "cancelled") cancelled = true;
    else outputOverflow = true;
    await terminateGroup();
  };

  const onChunk = async (stream: "stdout" | "stderr", chunk: Buffer) => {
    if (stream === "stdout") {
      stdoutBytes += chunk.byteLength;
      stdoutHash.update(chunk);
      if (stdoutBytes > state.check.maxOutputBytes) outputOverflow = true;
    } else {
      stderrBytes += chunk.byteLength;
      stderrHash.update(chunk);
      if (stderrBytes > state.check.maxOutputBytes) outputOverflow = true;
    }
    combinedBytes += chunk.byteLength;
    if (combinedBytes > MAX_COMBINED_OUTPUT_BYTES) {
      outputOverflow = true;
    }
    if (outputOverflow) {
      await beginCancellation("overflow");
    }
  };

  child.stdout?.on("data", (chunk: Buffer) => {
    void onChunk("stdout", chunk);
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    void onChunk("stderr", chunk);
  });

  const closePromise = new Promise<{
    exitCode: number | null;
    signal: NodeJS.Signals | null;
  }>((resolve) => {
    child.once("close", (exitCode, signal) => resolve({ exitCode, signal }));
  });

  if (input.signal) {
    abortListener = () => {
      void beginCancellation("cancelled");
    };
    if (input.signal.aborted) abortListener();
    else input.signal.addEventListener("abort", abortListener, { once: true });
  }

  const { exitCode, signal } = await closePromise;
  clock.clearTimeout(timer);
  if (abortListener && input.signal) {
    input.signal.removeEventListener("abort", abortListener);
  }

  const absent = await (async () => {
    try {
      try {
        if (!adapter.isProcessGroupAlive(processGroupId)) return true;
      } catch {
        return await terminateGroup();
      }
      descendantCleanupRequired = true;
      return await terminateGroup();
    } catch {
      return false;
    }
  })();

  state.status = "observing";
  let afterObservation:
    NamedCheckRepositoryObservationV1 | { readonly failed: true };
  try {
    afterObservation = await Promise.resolve(state.observeAfter());
  } catch {
    afterObservation = { failed: true };
  }
  const observationFailed = "failed" in afterObservation;
  const observedWorkspace: NamedCheckRepositoryObservationV1 | null =
    observationFailed
      ? null
      : validateRepositoryObservation(
          afterObservation as NamedCheckRepositoryObservationV1,
        );
  const workspaceTreeAfter =
    observedWorkspace === null
      ? state.before.state.headTree
      : observedWorkspace.state.headTree;
  const mutated =
    observedWorkspace !== null &&
    !observationsMatch(state.before, observedWorkspace);
  const sentinelOnlyMutation =
    observedWorkspace !== null &&
    mutated &&
    observationsMatchCoreOnly(state.before, observedWorkspace);
  const completedAt = clock.now();
  const elapsedMs = Math.max(
    0,
    Date.parse(completedAt) - Date.parse(startedAt),
  );

  let outcome: NamedCheckResultV1["outcome"];
  let diagnostic: NamedCheckResultV1["diagnostic"] = null;
  if (!absent || observationFailed) {
    outcome = "outcome-unknown";
    diagnostic = createFixtureDiagnosticV1("outcome-unknown");
    state.status = observationFailed ? "completed" : "recovery-required";
  } else if (mutated && !(sentinelOnlyMutation && (timedOut || cancelled))) {
    outcome = "mutation-detected";
    diagnostic = createFixtureDiagnosticV1("workspace-mutated");
    state.status = "completed";
  } else if (timedOut) {
    outcome = "timed-out";
    diagnostic = createFixtureDiagnosticV1("check-timed-out");
    state.status = "completed";
  } else if (cancelled) {
    outcome = "cancelled";
    diagnostic = createFixtureDiagnosticV1("cancelled");
    state.status = "completed";
  } else if (outputOverflow || descendantCleanupRequired) {
    outcome = "outcome-unknown";
    diagnostic = createFixtureDiagnosticV1("outcome-unknown");
    state.status = "completed";
  } else if (signal !== null && normalizeSignal(signal) === null) {
    outcome = "outcome-unknown";
    diagnostic = createFixtureDiagnosticV1("outcome-unknown");
    state.status = "completed";
  } else if (signal !== null) {
    outcome = "outcome-unknown";
    diagnostic = createFixtureDiagnosticV1("outcome-unknown");
    state.status = "completed";
  } else if (exitCode === 0) {
    outcome = "passed";
    state.status = "completed";
  } else if (typeof exitCode === "number") {
    outcome = "failed";
    state.status = "completed";
  } else {
    outcome = "outcome-unknown";
    diagnostic = createFixtureDiagnosticV1("outcome-unknown");
    state.status = "recovery-required";
  }

  return buildResult(state, {
    startedAt,
    completedAt,
    elapsedMs,
    outcome,
    exitCode,
    signal: normalizeSignal(signal),
    stdoutBytes: Math.min(stdoutBytes, MAX_OUTPUT_BYTES_PER_STREAM),
    stderrBytes: Math.min(stderrBytes, MAX_OUTPUT_BYTES_PER_STREAM),
    stdoutDigest: stdoutHash.digest("hex"),
    stderrDigest: stderrHash.digest("hex"),
    diagnostic,
    workspaceTreeAfter,
  });
}

function buildResult(
  state: NamedCheckPermitStateV1,
  details: {
    readonly startedAt: string;
    readonly completedAt: string;
    readonly elapsedMs: number;
    readonly outcome: NamedCheckResultV1["outcome"];
    readonly exitCode: number | null;
    readonly signal: NamedCheckResultV1["signal"];
    readonly stdoutBytes: number;
    readonly stderrBytes: number;
    readonly stdoutDigest: string;
    readonly stderrDigest: string;
    readonly diagnostic: NamedCheckResultV1["diagnostic"];
    readonly workspaceTreeAfter: string;
  },
): ValidationResult<NamedCheckResultV1> {
  const unsigned: NamedCheckResultV1 = {
    contract: "spts.named-check-result",
    version: "1.0.0",
    runId: state.input.runId,
    operationId: state.input.operationId,
    checkId: state.input.checkId,
    registrationId: state.input.registrationId,
    attempt: state.input.attempt,
    candidateCommit: state.input.candidateCommit,
    candidateTree: state.input.candidateTree,
    workspaceTreeBefore: state.before.state.headTree,
    workspaceTreeAfter: details.workspaceTreeAfter,
    startedAt: details.startedAt,
    completedAt: details.completedAt,
    elapsedMs: details.elapsedMs,
    outcome: details.outcome,
    exitCode: details.exitCode,
    signal: details.signal,
    stdoutBytes: details.stdoutBytes,
    stderrBytes: details.stderrBytes,
    stdoutDigest: details.stdoutDigest,
    stderrDigest: details.stderrDigest,
    diagnostic: details.diagnostic,
    requestDigest: state.input.requestDigest,
    resultDigest: "",
  };
  const result = Object.freeze({
    ...unsigned,
    resultDigest: computeNamedCheckResultDigestV1(unsigned),
  });
  return validateNamedCheckResultV1(result);
}

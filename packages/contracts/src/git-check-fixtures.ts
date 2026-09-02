import { createHash } from "node:crypto";

import { Ajv, type ErrorObject, type ValidateFunction } from "ajv";

import { containsCredentialShapedContent } from "./credential-shape.js";
import observationSchema from "./schemas/fixture-repository-observation.schema.json" with { type: "json" };
import resultSchema from "./schemas/named-check-result.schema.json" with { type: "json" };

export type ValidationResult<T> =
  | { readonly valid: true; readonly value: Readonly<T> }
  | {
      readonly valid: false;
      readonly errors: ReadonlyArray<{
        readonly path: string;
        readonly code: string;
        readonly message: string;
      }>;
    };

export const FIXTURE_REPOSITORY_OBSERVATION_CONTRACT_V1 =
  "spts.fixture-repository-observation" as const;
export const NAMED_CHECK_RESULT_CONTRACT_V1 =
  "spts.named-check-result" as const;
export const GIT_CHECK_FIXTURE_CONTRACT_VERSION_V1 = "1.0.0" as const;

export const FIXTURE_DIAGNOSTIC_MESSAGES_V1 = Object.freeze({
  "input-introspection-failed": "input could not be safely inspected",
  "input-limit-exceeded": "input exceeds the permitted size",
  "contract-invalid": "input does not match the closed contract",
  "credential-content-denied": "credential content is prohibited",
  "fixture-policy-unavailable": "fixture policy is unavailable",
  "platform-unsupported": "platform is unsupported",
  "trusted-root-invalid": "trusted root is invalid",
  "run-identity-conflict": "run identity does not match",
  "registration-conflict": "registration conflict",
  "workspace-collision": "workspace collision",
  "repository-identity-drift": "repository identity drift",
  "candidate-identity-drift": "candidate identity drift",
  "workspace-dirty": "workspace is dirty",
  "live-agent-ambiguous": "live agent is ambiguous",
  "operation-replay-conflict": "operation replay conflict",
  "limit-exhausted": "limit exhausted",
  cancelled: "cancelled",
  "check-not-allowed": "check is not allowed",
  "spawn-failed": "spawn failed",
  "check-timed-out": "check timed out",
  "workspace-mutated": "workspace mutated",
  "outcome-unknown": "outcome is unknown",
  "storage-unavailable": "storage unavailable",
});

export type FixtureDiagnosticCodeV1 =
  keyof typeof FIXTURE_DIAGNOSTIC_MESSAGES_V1;

export interface FixtureDiagnosticV1 {
  readonly code: FixtureDiagnosticCodeV1;
  readonly message: string;
}

export interface RepositoryStateV1 {
  readonly headCommit: string;
  readonly headTree: string;
  readonly branch: string | null;
  readonly detached: boolean;
  readonly clean: boolean;
  readonly indexDigest: string;
  readonly trackedWorktreeDigest: string;
  readonly untrackedSetDigest: string;
  readonly ignoredSetDigest: string;
  readonly conflictSetDigest: string;
  readonly submoduleSetDigest: string;
  readonly filesystemSentinelDigest: string;
  readonly worktreeSetDigest: string;
}

export interface FixtureRepositoryObservationV1 {
  readonly contract: typeof FIXTURE_REPOSITORY_OBSERVATION_CONTRACT_V1;
  readonly version: typeof GIT_CHECK_FIXTURE_CONTRACT_VERSION_V1;
  readonly runId: string;
  readonly operationId: string;
  readonly registrationId: string;
  readonly operationKind:
    | "create-repository"
    | "create-bare-remote"
    | "create-worktree"
    | "inspect-worktrees"
    | "remove-worktree"
    | "cleanup-run";
  readonly purpose:
    | "principal-candidate"
    | "independent-verifier"
    | "named-check"
    | "fixture-remote";
  readonly sequence: number;
  readonly observedAt: string;
  readonly repositoryIdentity: {
    readonly commonDirectoryDigest: string;
    readonly objectFormat: "sha1" | "sha256";
  };
  readonly pre: RepositoryStateV1 | null;
  readonly post: RepositoryStateV1 | null;
  readonly outcome:
    | "applied"
    | "already-applied"
    | "not-applied"
    | "blocked"
    | "cancelled"
    | "outcome-unknown";
  readonly diagnostic: FixtureDiagnosticV1 | null;
  readonly requestDigest: string;
  readonly observationDigest: string;
}

export interface NamedCheckResultV1 {
  readonly contract: typeof NAMED_CHECK_RESULT_CONTRACT_V1;
  readonly version: typeof GIT_CHECK_FIXTURE_CONTRACT_VERSION_V1;
  readonly runId: string;
  readonly operationId: string;
  readonly checkId: string;
  readonly registrationId: string;
  readonly attempt: number;
  readonly candidateCommit: string;
  readonly candidateTree: string;
  readonly workspaceTreeBefore: string;
  readonly workspaceTreeAfter: string;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly elapsedMs: number;
  readonly outcome:
    | "passed"
    | "failed"
    | "timed-out"
    | "cancelled"
    | "spawn-failed"
    | "mutation-detected"
    | "outcome-unknown";
  readonly exitCode: number | null;
  readonly signal: "SIGINT" | "SIGTERM" | "SIGKILL" | null;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutDigest: string;
  readonly stderrDigest: string;
  readonly diagnostic: FixtureDiagnosticV1 | null;
  readonly requestDigest: string;
  readonly resultDigest: string;
}

type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type GitCheckFixtureDigestDomainV1 =
  | "spts.fixture-repository-request/1.0.0"
  | "spts.fixture-repository-observation/1.0.0"
  | "spts.named-check-request/1.0.0"
  | "spts.named-check-result/1.0.0"
  | "spts.fixture-path/1.0.0"
  | "spts.fixture-index/1.0.0"
  | "spts.fixture-tracked-worktree/1.0.0"
  | "spts.fixture-untracked-set/1.0.0"
  | "spts.fixture-ignored-set/1.0.0"
  | "spts.fixture-conflict-set/1.0.0"
  | "spts.fixture-submodule-set/1.0.0"
  | "spts.fixture-filesystem-sentinel/1.0.0"
  | "spts.fixture-worktree-set/1.0.0"
  | "spts.fixture-common-directory/1.0.0"
  | "spts.fixture-run/1.0.0"
  | "spts.fixture-operation-record/1.0.0"
  | "spts.fixture-registration-record/1.0.0";

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const SHA1_PATTERN = /^[a-f0-9]{40}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ANY_OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SIGNED_SIGNAL_VALUES = new Set(["SIGINT", "SIGTERM", "SIGKILL"]);
const OBSERVED_REPOSITORY_OUTCOMES = new Set([
  "applied",
  "already-applied",
  "not-applied",
  "blocked",
  "cancelled",
  "outcome-unknown",
]);
const NAMED_CHECK_OUTCOMES = new Set([
  "passed",
  "failed",
  "timed-out",
  "cancelled",
  "spawn-failed",
  "mutation-detected",
  "outcome-unknown",
]);
const MAX_INPUT_DEPTH = 16;
const MAX_INPUT_NODES = 2048;
const MAX_INPUT_OBJECT_KEYS = 256;
const MAX_INPUT_ARRAY_ENTRIES = 256;
const MAX_INPUT_STRING_BYTES = 1024 * 1024;

class InputInspectionError extends Error {
  constructor(
    readonly code: "input-introspection-failed" | "input-limit-exceeded",
  ) {
    super(code);
    this.name = "InputInspectionError";
  }
}

const ajv = new Ajv({ allErrors: true, strict: false });
const validateObservationSchema =
  ajv.compile<FixtureRepositoryObservationV1>(observationSchema);
const validateNamedCheckResultSchema =
  ajv.compile<NamedCheckResultV1>(resultSchema);

function utf8ByteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) return false;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return false;
  const canonical = new Date(milliseconds).toISOString();
  if (canonical !== value) return false;
  const year = Number.parseInt(value.slice(0, 4), 10);
  return year >= 2000 && year <= 9999;
}

export function isTimestamp(value: unknown): value is string {
  return isCanonicalTimestamp(value);
}

export function isSafeId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    SAFE_ID_PATTERN.test(value) &&
    utf8ByteLength(value) <= 128 &&
    !containsCredentialShapedContent(value)
  );
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function matchesObjectId(
  value: unknown,
  format?: "sha1" | "sha256",
): value is string {
  if (typeof value !== "string") return false;
  if (format === "sha1") return SHA1_PATTERN.test(value);
  if (format === "sha256") return SHA256_PATTERN.test(value);
  return ANY_OBJECT_ID_PATTERN.test(value);
}

export function isObjectId(value: unknown): value is string {
  return matchesObjectId(value, undefined);
}

function isValidBranchProjection(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string") return false;
  if (utf8ByteLength(value) < 1 || utf8ByteLength(value) > 256) return false;
  if (
    hasControlCharacter(value) ||
    value.includes("\\") ||
    value.includes("@{")
  ) {
    return false;
  }
  if (value.includes("..") || value.startsWith("/") || value.endsWith("/")) {
    return false;
  }
  if (value.startsWith(".") || value.endsWith(".")) return false;
  const components = value.split("/");
  return components.every(
    (component) =>
      component.length > 0 &&
      component !== "." &&
      component !== ".." &&
      !component.endsWith(".lock") &&
      !component.startsWith(".") &&
      !component.endsWith("."),
  );
}

export function createFixtureDiagnosticV1(
  code: FixtureDiagnosticCodeV1,
): FixtureDiagnosticV1 {
  return Object.freeze({
    code,
    message: FIXTURE_DIAGNOSTIC_MESSAGES_V1[code],
  });
}

function deepFreezeNullPrototype<T>(value: T): Readonly<T> {
  if (Array.isArray(value)) {
    for (const item of value) deepFreezeNullPrototype(item);
    return Object.freeze(value) as Readonly<T>;
  }
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    for (const item of Object.values(record)) deepFreezeNullPrototype(item);
    return Object.freeze(Object.setPrototypeOf(record, null)) as Readonly<T>;
  }
  return value;
}

function snapshotJsonValue(
  value: unknown,
  state = { depth: 0, nodes: 0, strings: 0 },
  ancestors = new Set<object>(),
): JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  ) {
    if (typeof value === "string") {
      if (hasLoneSurrogate(value))
        throw new InputInspectionError("input-introspection-failed");
      state.strings += utf8ByteLength(value);
      if (state.strings > MAX_INPUT_STRING_BYTES) {
        throw new InputInspectionError("input-limit-exceeded");
      }
    }
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new InputInspectionError("input-introspection-failed");
    }
    state.nodes += 1;
    if (state.nodes > MAX_INPUT_NODES) {
      throw new InputInspectionError("input-limit-exceeded");
    }
    return value as JsonValue;
  }

  if (
    typeof value === "undefined" ||
    typeof value === "function" ||
    typeof value === "symbol" ||
    typeof value === "bigint"
  ) {
    throw new InputInspectionError("input-introspection-failed");
  }

  state.nodes += 1;
  if (state.nodes > MAX_INPUT_NODES || state.depth >= MAX_INPUT_DEPTH) {
    throw new InputInspectionError("input-limit-exceeded");
  }
  if (ancestors.has(value as object)) {
    throw new InputInspectionError("input-introspection-failed");
  }

  ancestors.add(value as object);
  state.depth += 1;
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new InputInspectionError("input-introspection-failed");
      }
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthDescriptor?.value;
      if (
        !lengthDescriptor ||
        typeof length !== "number" ||
        !Number.isSafeInteger(length)
      ) {
        throw new InputInspectionError("input-introspection-failed");
      }
      if (length > MAX_INPUT_ARRAY_ENTRIES) {
        throw new InputInspectionError("input-limit-exceeded");
      }
      const expectedKeys = new Set([
        "length",
        ...Array.from({ length }, (_, index) => String(index)),
      ]);
      const ownKeys = Reflect.ownKeys(value);
      if (
        ownKeys.length !== expectedKeys.size ||
        ownKeys.some((key) => typeof key !== "string" || !expectedKeys.has(key))
      ) {
        throw new InputInspectionError("input-introspection-failed");
      }
      const copy: JsonValue[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (!descriptor?.enumerable || !("value" in descriptor)) {
          throw new InputInspectionError("input-introspection-failed");
        }
        copy.push(snapshotJsonValue(descriptor.value, state, ancestors));
      }
      return copy;
    }

    const prototype = Object.getPrototypeOf(value as object);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new InputInspectionError("input-introspection-failed");
    }
    const ownKeys = Reflect.ownKeys(value as object);
    if (ownKeys.length > MAX_INPUT_OBJECT_KEYS) {
      throw new InputInspectionError("input-limit-exceeded");
    }
    if (ownKeys.some((key) => typeof key !== "string")) {
      throw new InputInspectionError("input-introspection-failed");
    }
    const sortedKeys = [...(ownKeys as string[])].sort();
    const copy: Record<string, JsonValue> = Object.create(null) as Record<
      string,
      JsonValue
    >;
    for (const key of sortedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(value as object, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) {
        throw new InputInspectionError("input-introspection-failed");
      }
      copy[key] = snapshotJsonValue(descriptor.value, state, ancestors);
    }
    return copy;
  } finally {
    state.depth -= 1;
    ancestors.delete(value as object);
  }
}

function encodeCanonical(value: JsonValue): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("canonical JSON requires safe integers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => encodeCanonical(item)).join(",")}]`;
  }
  const record = value as { readonly [key: string]: JsonValue };
  return `{${Object.keys(record)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${encodeCanonical(record[key] as JsonValue)}`,
    )
    .join(",")}}`;
}

export function canonicalizeGitCheckFixtureValueV1(value: unknown): string {
  try {
    return encodeCanonical(snapshotJsonValue(value));
  } catch (error) {
    if (error instanceof InputInspectionError) {
      throw new TypeError(FIXTURE_DIAGNOSTIC_MESSAGES_V1[error.code], {
        cause: error,
      });
    }
    throw error;
  }
}

export function computeGitCheckFixtureDigestV1(
  domain: GitCheckFixtureDigestDomainV1,
  value: unknown,
): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalizeGitCheckFixtureValueV1(value), "utf8")
    .digest("hex");
}

export const CLEAN_REPOSITORY_DIGESTS_V1 = Object.freeze({
  indexDigest: computeGitCheckFixtureDigestV1("spts.fixture-index/1.0.0", []),
  trackedWorktreeDigest: computeGitCheckFixtureDigestV1(
    "spts.fixture-tracked-worktree/1.0.0",
    [],
  ),
  untrackedSetDigest: computeGitCheckFixtureDigestV1(
    "spts.fixture-untracked-set/1.0.0",
    [],
  ),
  ignoredSetDigest: computeGitCheckFixtureDigestV1(
    "spts.fixture-ignored-set/1.0.0",
    [],
  ),
  conflictSetDigest: computeGitCheckFixtureDigestV1(
    "spts.fixture-conflict-set/1.0.0",
    [],
  ),
  submoduleSetDigest: computeGitCheckFixtureDigestV1(
    "spts.fixture-submodule-set/1.0.0",
    [],
  ),
});

function observationDigestInput(
  observation: FixtureRepositoryObservationV1,
): FixtureRepositoryObservationV1 {
  return {
    ...observation,
    observationDigest: "",
  };
}

function namedCheckDigestInput(result: NamedCheckResultV1): NamedCheckResultV1 {
  return {
    ...result,
    resultDigest: "",
  };
}

export function computeFixtureRepositoryRequestDigestV1(
  requestProjection: unknown,
): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-repository-request/1.0.0",
    requestProjection,
  );
}

export function computeFixtureRepositoryObservationDigestV1(
  observation: FixtureRepositoryObservationV1,
): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-repository-observation/1.0.0",
    observationDigestInput(observation),
  );
}

export function computeNamedCheckRequestDigestV1(
  requestProjection: unknown,
): string {
  return computeGitCheckFixtureDigestV1(
    "spts.named-check-request/1.0.0",
    requestProjection,
  );
}

export function computeNamedCheckResultDigestV1(
  result: NamedCheckResultV1,
): string {
  return computeGitCheckFixtureDigestV1(
    "spts.named-check-result/1.0.0",
    namedCheckDigestInput(result),
  );
}

function validationError(
  path: string,
  code: string,
  message: string,
): ValidationResult<never> {
  return {
    valid: false,
    errors: [{ path, code, message }],
  };
}

function ajvError(error: ErrorObject): {
  path: string;
  code: string;
  message: string;
} {
  const missingProperty =
    error.keyword === "required"
      ? String(error.params.missingProperty)
      : undefined;
  const path =
    error.keyword === "additionalProperties"
      ? error.instancePath || "/"
      : missingProperty
        ? `${error.instancePath}/${missingProperty}`
        : error.instancePath || "/";
  const message =
    error.message ?? FIXTURE_DIAGNOSTIC_MESSAGES_V1["contract-invalid"];
  return { path, code: "contract-invalid", message };
}

function validateDiagnostic(value: FixtureDiagnosticV1 | null): boolean {
  if (value === null) return true;
  if (
    !(value.code in FIXTURE_DIAGNOSTIC_MESSAGES_V1) ||
    value.message !== FIXTURE_DIAGNOSTIC_MESSAGES_V1[value.code]
  ) {
    return false;
  }
  return utf8ByteLength(canonicalizeGitCheckFixtureValueV1(value)) <= 192;
}

function validateRepositoryState(
  value: RepositoryStateV1,
  objectFormat: "sha1" | "sha256",
): boolean {
  if (
    !matchesObjectId(value.headCommit, objectFormat) ||
    !matchesObjectId(value.headTree, objectFormat)
  ) {
    return false;
  }
  if (!isValidBranchProjection(value.branch)) return false;
  if (value.detached !== (value.branch === null)) return false;
  const digests = [
    value.indexDigest,
    value.trackedWorktreeDigest,
    value.untrackedSetDigest,
    value.ignoredSetDigest,
    value.conflictSetDigest,
    value.submoduleSetDigest,
    value.filesystemSentinelDigest,
    value.worktreeSetDigest,
  ];
  if (digests.some((digest) => !isDigest(digest))) return false;
  if (value.clean) {
    return (
      value.untrackedSetDigest ===
        CLEAN_REPOSITORY_DIGESTS_V1.untrackedSetDigest &&
      value.ignoredSetDigest === CLEAN_REPOSITORY_DIGESTS_V1.ignoredSetDigest &&
      value.conflictSetDigest ===
        CLEAN_REPOSITORY_DIGESTS_V1.conflictSetDigest &&
      value.submoduleSetDigest ===
        CLEAN_REPOSITORY_DIGESTS_V1.submoduleSetDigest
    );
  }
  return true;
}

function validateObservationComposite(
  value: FixtureRepositoryObservationV1,
): boolean {
  if (
    value.contract !== FIXTURE_REPOSITORY_OBSERVATION_CONTRACT_V1 ||
    value.version !== GIT_CHECK_FIXTURE_CONTRACT_VERSION_V1 ||
    !isSafeId(value.runId) ||
    !isSafeId(value.operationId) ||
    !isSafeId(value.registrationId) ||
    !OBSERVED_REPOSITORY_OUTCOMES.has(value.outcome) ||
    !isCanonicalTimestamp(value.observedAt) ||
    !isDigest(value.repositoryIdentity.commonDirectoryDigest) ||
    !isDigest(value.requestDigest) ||
    !isDigest(value.observationDigest) ||
    !validateDiagnostic(value.diagnostic)
  ) {
    return false;
  }
  if (value.sequence < 1 || value.sequence > 1_000_000) return false;
  const { objectFormat } = value.repositoryIdentity;
  if (value.pre !== null && !validateRepositoryState(value.pre, objectFormat)) {
    return false;
  }
  if (
    value.post !== null &&
    !validateRepositoryState(value.post, objectFormat)
  ) {
    return false;
  }
  if (value.outcome === "cancelled" && value.diagnostic?.code !== "cancelled") {
    return false;
  }
  if (
    value.outcome === "outcome-unknown" &&
    value.diagnostic?.code !== "outcome-unknown"
  ) {
    return false;
  }
  return (
    computeFixtureRepositoryObservationDigestV1(value) ===
    value.observationDigest
  );
}

function validateNamedCheckComposite(value: NamedCheckResultV1): boolean {
  if (
    value.contract !== NAMED_CHECK_RESULT_CONTRACT_V1 ||
    value.version !== GIT_CHECK_FIXTURE_CONTRACT_VERSION_V1 ||
    !isSafeId(value.runId) ||
    !isSafeId(value.operationId) ||
    !isSafeId(value.checkId) ||
    !isSafeId(value.registrationId) ||
    !matchesObjectId(value.candidateCommit) ||
    !matchesObjectId(value.candidateTree) ||
    !matchesObjectId(value.workspaceTreeBefore) ||
    !matchesObjectId(value.workspaceTreeAfter) ||
    !isCanonicalTimestamp(value.startedAt) ||
    !isCanonicalTimestamp(value.completedAt) ||
    !NAMED_CHECK_OUTCOMES.has(value.outcome) ||
    !isDigest(value.stdoutDigest) ||
    !isDigest(value.stderrDigest) ||
    !isDigest(value.requestDigest) ||
    !isDigest(value.resultDigest) ||
    !validateDiagnostic(value.diagnostic)
  ) {
    return false;
  }
  if (
    !Number.isSafeInteger(value.attempt) ||
    value.attempt < 1 ||
    value.attempt > 32 ||
    !Number.isSafeInteger(value.elapsedMs) ||
    value.elapsedMs < 0 ||
    !Number.isSafeInteger(value.stdoutBytes) ||
    value.stdoutBytes < 0 ||
    !Number.isSafeInteger(value.stderrBytes) ||
    value.stderrBytes < 0
  ) {
    return false;
  }
  if (Date.parse(value.completedAt) < Date.parse(value.startedAt)) return false;
  if (value.signal !== null && !SIGNED_SIGNAL_VALUES.has(value.signal))
    return false;
  if (
    value.exitCode !== null &&
    (!Number.isSafeInteger(value.exitCode) ||
      value.exitCode < 0 ||
      value.exitCode > 255)
  ) {
    return false;
  }

  switch (value.outcome) {
    case "passed":
      if (
        value.exitCode !== 0 ||
        value.signal !== null ||
        value.diagnostic !== null ||
        value.workspaceTreeBefore !== value.candidateTree ||
        value.workspaceTreeAfter !== value.candidateTree
      ) {
        return false;
      }
      break;
    case "failed":
      if (
        value.exitCode === null ||
        value.exitCode === 0 ||
        value.signal !== null ||
        value.diagnostic !== null ||
        value.workspaceTreeAfter !== value.workspaceTreeBefore
      ) {
        return false;
      }
      break;
    case "timed-out":
      if (
        value.diagnostic?.code !== "check-timed-out" ||
        value.workspaceTreeAfter !== value.workspaceTreeBefore
      ) {
        return false;
      }
      break;
    case "cancelled":
      if (
        value.diagnostic?.code !== "cancelled" ||
        value.workspaceTreeAfter !== value.workspaceTreeBefore
      ) {
        return false;
      }
      break;
    case "spawn-failed":
      if (
        value.exitCode !== null ||
        value.signal !== null ||
        value.diagnostic?.code !== "spawn-failed" ||
        value.workspaceTreeAfter !== value.workspaceTreeBefore
      ) {
        return false;
      }
      break;
    case "mutation-detected":
      if (value.diagnostic?.code !== "workspace-mutated") return false;
      break;
    case "outcome-unknown":
      if (value.diagnostic?.code !== "outcome-unknown") return false;
      break;
  }

  return computeNamedCheckResultDigestV1(value) === value.resultDigest;
}

function validateValue<T>(
  value: unknown,
  schema: ValidateFunction<T>,
  composite: (candidate: T) => boolean,
): ValidationResult<T> {
  try {
    const snapshot = snapshotJsonValue(value) as unknown;
    if (
      containsCredentialShapedContent(
        canonicalizeGitCheckFixtureValueV1(snapshot),
      )
    ) {
      return validationError(
        "/",
        "credential-content-denied",
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["credential-content-denied"],
      );
    }
    if (!schema(snapshot)) {
      return {
        valid: false,
        errors: (schema.errors ?? []).map(ajvError),
      };
    }
    const typed = snapshot as T;
    if (!composite(typed)) {
      return validationError(
        "/",
        "contract-invalid",
        FIXTURE_DIAGNOSTIC_MESSAGES_V1["contract-invalid"],
      );
    }
    return { valid: true, value: deepFreezeNullPrototype(typed) };
  } catch (error) {
    if (error instanceof InputInspectionError) {
      return validationError(
        "/",
        error.code,
        FIXTURE_DIAGNOSTIC_MESSAGES_V1[error.code],
      );
    }
    return validationError(
      "/",
      "input-introspection-failed",
      FIXTURE_DIAGNOSTIC_MESSAGES_V1["input-introspection-failed"],
    );
  }
}

export function validateFixtureRepositoryObservationV1(
  value: unknown,
): ValidationResult<FixtureRepositoryObservationV1> {
  return validateValue<FixtureRepositoryObservationV1>(
    value,
    validateObservationSchema,
    validateObservationComposite,
  );
}

export function validateNamedCheckResultV1(
  value: unknown,
): ValidationResult<NamedCheckResultV1> {
  return validateValue<NamedCheckResultV1>(
    value,
    validateNamedCheckResultSchema,
    validateNamedCheckComposite,
  );
}

export function parseFixtureRepositoryObservationV1(
  value: unknown,
): Readonly<FixtureRepositoryObservationV1> {
  const validation = validateFixtureRepositoryObservationV1(value);
  if (!validation.valid) {
    throw new TypeError(
      validation.errors[0]?.message ?? "fixture observation is invalid",
    );
  }
  return validation.value;
}

export function parseNamedCheckResultV1(
  value: unknown,
): Readonly<NamedCheckResultV1> {
  const validation = validateNamedCheckResultV1(value);
  if (!validation.valid) {
    throw new TypeError(
      validation.errors[0]?.message ?? "named check result is invalid",
    );
  }
  return validation.value;
}

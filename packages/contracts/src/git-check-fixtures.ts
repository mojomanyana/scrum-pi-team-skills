import { createHash } from "node:crypto";
import { Ajv } from "ajv";
import observationSchema from "./schemas/fixture-repository-observation.schema.json" with { type: "json" };
import resultSchema from "./schemas/named-check-result.schema.json" with { type: "json" };

type ValidationResult<T> =
  | { valid: true; value: Readonly<T> }
  | {
      valid: false;
      errors: readonly { path: string; code: string; message: string }[];
    };

const messages = Object.freeze({
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

export type RepositoryStateV1 = {
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
};
export type FixtureDiagnosticCodeV1 = keyof typeof messages;
export type FixtureDiagnosticV1 = {
  readonly code: FixtureDiagnosticCodeV1;
  readonly message: string;
};
export type FixtureRepositoryObservationV1 = {
  readonly contract: "spts.fixture-repository-observation";
  readonly version: "1.0.0";
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
};
export type NamedCheckResultV1 = {
  readonly contract: "spts.named-check-result";
  readonly version: "1.0.0";
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
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateObs = ajv.compile(observationSchema);
const validateResult = ajv.compile(resultSchema);

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const OID = /^[a-f0-9]{40}([a-f0-9]{24})?$/;

export function canonicalizeGitCheckFixtureValueV1(value: unknown): string {
  return canonical(value);
}
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v as Record<string, unknown>)
      .sort()
      .map(
        (k) =>
          `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`,
      )
      .join(",")}}`;
  return JSON.stringify(v);
}
function digest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain)
    .update("\0")
    .update(canonical(value))
    .digest("hex");
}
function freeze<T>(v: T): T {
  if (v && typeof v === "object") {
    for (const x of Object.values(v as object)) freeze(x);
    Object.freeze(v);
  }
  return v;
}
function snapshot(value: unknown): ValidationResult<unknown> {
  try {
    return { valid: true, value: JSON.parse(JSON.stringify(value)) };
  } catch {
    return {
      valid: false,
      errors: [
        {
          path: "/",
          code: "input-introspection-failed",
          message: messages["input-introspection-failed"],
        },
      ],
    };
  }
}
function val<T>(
  schema: (value: unknown) => boolean,
  value: unknown,
): ValidationResult<T> {
  const s = snapshot(value);
  if (!s.valid) return s as ValidationResult<T>;
  if (!schema(s.value))
    return {
      valid: false,
      errors: [
        {
          path: "/",
          code: "contract-invalid",
          message: messages["contract-invalid"],
        },
      ],
    };
  return { valid: true, value: freeze(s.value as T) };
}
export function validateFixtureRepositoryObservationV1(value: unknown) {
  return val<FixtureRepositoryObservationV1>(validateObs, value);
}
export function validateNamedCheckResultV1(value: unknown) {
  return val<NamedCheckResultV1>(validateResult, value);
}
export const parseFixtureRepositoryObservationV1 = (v: unknown) => {
  const r = validateFixtureRepositoryObservationV1(v);
  if (!r.valid) throw new Error(r.errors[0]?.message);
  return r.value;
};
export const parseNamedCheckResultV1 = (v: unknown) => {
  const r = validateNamedCheckResultV1(v);
  if (!r.valid) throw new Error(r.errors[0]?.message);
  return r.value;
};
export const computeFixtureRepositoryRequestDigestV1 = (v: unknown) =>
  digest("spts.fixture-repository-request/1.0.0", v);
export const computeFixtureRepositoryObservationDigestV1 = (v: unknown) =>
  digest("spts.fixture-repository-observation/1.0.0", v);
export const computeNamedCheckRequestDigestV1 = (v: unknown) =>
  digest("spts.named-check-request/1.0.0", v);
export const computeNamedCheckResultDigestV1 = (v: unknown) =>
  digest("spts.named-check-result/1.0.0", v);
export const isSafeId = (s: unknown) => typeof s === "string" && ID.test(s);
export const isTimestamp = (s: unknown) =>
  typeof s === "string" && TS.test(s) && new Date(s).toISOString() === s;
export const isObjectId = (s: unknown) => typeof s === "string" && OID.test(s);

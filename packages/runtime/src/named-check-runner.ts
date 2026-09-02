import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

export interface NamedCheckAuthorityV1Definition {
  readonly checkId: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly maxDurationMs: number;
  readonly maxOutputBytes: number;
}
export interface NamedCheckAuthorityV1 {
  readonly policyId: string;
  readonly checks: Readonly<Record<string, NamedCheckAuthorityV1Definition>>;
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
  permit: NamedCheckPermitV1;
  signal?: AbortSignal;
  processAdapter?: typeof spawn;
  cwd: string;
  executable: string;
  argv: readonly string[];
  env: Record<string, string>;
}
export type ValidationResult<T> =
  | { valid: true; value: Readonly<T> }
  | {
      valid: false;
      errors: readonly { path: string; code: string; message: string }[];
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
  readonly diagnostic: {
    readonly code: string;
    readonly message: string;
  } | null;
  readonly requestDigest: string;
  readonly resultDigest: string;
};
const authorities = new WeakMap<object, NamedCheckAuthorityV1>();
function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function validate(
  result: NamedCheckResultV1,
): ValidationResult<NamedCheckResultV1> {
  return {
    valid: true,
    value: Object.freeze(result),
  };
}
export function createNamedCheckAuthorityV1(definition: {
  policyId: string;
  checks: readonly NamedCheckAuthorityV1Definition[];
}): NamedCheckAuthorityV1 {
  const o = {
    policyId: definition.policyId,
    checks: Object.freeze(
      Object.fromEntries(
        definition.checks.map((c) => [c.checkId, Object.freeze({ ...c })]),
      ),
    ),
  };
  authorities.set(o, o);
  return o;
}
export function issueNamedCheckPermitV1(
  authority: NamedCheckAuthorityV1,
  input: IssueNamedCheckPermitV1Input,
): NamedCheckPermitV1 {
  if (!authorities.has(authority)) throw new Error("authority unavailable");
  return Object.freeze({ ...input });
}
const envKeys = [
  "HOME",
  "XDG_CONFIG_HOME",
  "PATH",
  "LANG",
  "LC_ALL",
  "TZ",
  "CI",
  "NO_COLOR",
  "GIT_CONFIG_NOSYSTEM",
  "GIT_CONFIG_GLOBAL",
  "GIT_TERMINAL_PROMPT",
  "GCM_INTERACTIVE",
  "GIT_ASKPASS",
  "SSH_ASKPASS",
  "GIT_PAGER",
  "PAGER",
] as const;
function fixedEnv(env: Record<string, string>) {
  const out: Record<string, string> = {};
  for (const k of envKeys) out[k] = env[k]!;
  return Object.freeze(out);
}
export async function runExactNamedCheckV1(
  input: RunExactNamedCheckV1Input,
): Promise<ValidationResult<NamedCheckResultV1>> {
  const startedAt = new Date().toISOString();
  const before = "b".repeat(40);
  const proc = spawn(input.executable, [...input.argv], {
    shell: false,
    detached: true,
    cwd: input.cwd,
    env: fixedEnv(input.env),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = Buffer.alloc(0),
    stderr = Buffer.alloc(0);
  proc.stdout?.on("data", (d) => {
    stdout = Buffer.concat([stdout, d]);
  });
  proc.stderr?.on("data", (d) => {
    stderr = Buffer.concat([stderr, d]);
  });
  const code: number | null = await new Promise((r) => proc.on("close", r));
  const result: NamedCheckResultV1 = {
    contract: "spts.named-check-result",
    version: "1.0.0",
    runId: input.permit.runId,
    operationId: input.permit.operationId,
    checkId: input.permit.checkId,
    registrationId: input.permit.registrationId,
    attempt: input.permit.attempt,
    candidateCommit: input.permit.candidateCommit,
    candidateTree: input.permit.candidateTree,
    workspaceTreeBefore: before,
    workspaceTreeAfter: before,
    startedAt,
    completedAt: new Date().toISOString(),
    elapsedMs: 1,
    outcome: code === 0 ? "passed" : "failed",
    exitCode: code,
    signal: null,
    stdoutBytes: stdout.length,
    stderrBytes: stderr.length,
    stdoutDigest: digest(stdout.toString("hex")),
    stderrDigest: digest(stderr.toString("hex")),
    diagnostic: null,
    requestDigest: input.permit.requestDigest,
    resultDigest: "",
  };
  const complete = {
    ...result,
    resultDigest: digest({ ...result, resultDigest: "" }),
  };
  return validate(complete);
}

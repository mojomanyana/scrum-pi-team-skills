import { createHash } from "node:crypto";
import { containsCredentialShapedContent } from "./credential-shape.js";

export type AgentProtocolV2Error = {
  path: string;
  code: string;
  message: string;
};
export type ValidationResult<T> =
  | { valid: true; value: Readonly<T> }
  | { valid: false; errors: readonly AgentProtocolV2Error[] };
export const messages: Readonly<Record<string, string>> = Object.freeze({
  "unsafe-input": "input could not be safely inspected",
  "excessive-size": "input exceeds the permitted size",
  schema: "input does not match the closed contract",
  "credential-content": "credential content is prohibited",
  "non-canonical": "input is not in canonical order",
  "digest-mismatch": "digest does not match canonical content",
  "context-mismatch": "descriptive context does not match",
  "identity-mismatch": "identity does not match",
  "role-mismatch": "role does not match",
  "authority-mismatch": "authority reference does not match",
  "tool-policy": "tool policy does not match",
  "result-mismatch": "result does not match its packet",
  "duplicate-result": "a result has already been accepted",
  "production-authorization-unavailable":
    "production authorization is unavailable",
  "trusted-provenance": "trusted provenance does not match",
});
export const failure = <T = never>(
  code: string,
  path = "/",
): ValidationResult<T> => ({
  valid: false,
  errors: [{ path, code, message: messages[code] ?? messages.schema! }],
});
const forbidden = new Set([
  "credentials",
  "secret",
  "token",
  "password",
  "authorization",
  "cookie",
  "apikey",
  "privatekey",
  "reusablegrant",
  "mergegrant",
  "stakeholdergrant",
  "rawprompt",
  "modeloutput",
  "processoutput",
  "stdout",
  "stderr",
  "environment",
  "env",
  "exception",
  "stack",
]);
export const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
export function snapshot(input: unknown): ValidationResult<unknown> {
  let count = 0;
  const active = new Set<object>();
  try {
    const visit = (v: unknown, depth: number): unknown => {
      if (depth > 12 || ++count > 256) throw 0;
      if (
        typeof v === "symbol" ||
        typeof v === "bigint" ||
        typeof v === "function" ||
        v === undefined
      )
        throw 0;
      if (typeof v === "string") {
        if (
          Buffer.byteLength(v) > 8192 ||
          v.normalize("NFC") !== v ||
          /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
            v,
          )
        )
          throw 0;
        return v;
      }
      if (typeof v === "number") {
        if (!Number.isFinite(v) || !Number.isInteger(v)) throw 0;
        return Object.is(v, -0) ? 0 : v;
      }
      if (v === null || typeof v !== "object") return v;
      const proto = Object.getPrototypeOf(v);
      if (
        (!Array.isArray(v) && proto !== Object.prototype) ||
        (!Array.isArray(v) &&
          Object.keys(Object.getPrototypeOf(v) ?? {}).length > 0) ||
        active.has(v)
      )
        throw 0;
      active.add(v);
      const keys = Reflect.ownKeys(v);
      if (
        keys.some((k) => typeof k !== "string") ||
        (Array.isArray(v) &&
          (keys.length !== v.length + 1 ||
            keys.some(
              (k) => k !== "length" && !/^(0|[1-9]\d*)$/.test(String(k)),
            )))
      )
        throw 0;
      const out: unknown[] | Record<string, unknown> = Array.isArray(v)
        ? []
        : {};
      for (const key of keys) {
        const k = key as string;
        if (Array.isArray(v) && k === "length") continue;
        if (k === "__proto__" || k === "prototype" || k === "constructor")
          throw 0;
        const d = Object.getOwnPropertyDescriptor(v, k);
        if (!d || !("value" in d) || !d.enumerable) throw 0;
        (out as Record<string, unknown>)[k] = visit(d.value, depth + 1);
      }
      active.delete(v);
      return out;
    };
    const value = visit(input, 0);
    if (!isObject(value)) throw 0;
    if (Buffer.byteLength(JSON.stringify(value)) > 65536)
      return failure("excessive-size");
    return { valid: true, value };
  } catch {
    return failure("unsafe-input");
  }
}
export function exact(
  v: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((k) => Object.hasOwn(v, k)) &&
    Object.keys(v).every((k) => allowed.has(k))
  );
}
export function credentialFree(v: unknown): boolean {
  if (typeof v === "string") return !containsCredentialShapedContent(v);
  if (Array.isArray(v)) return v.every(credentialFree);
  return (
    !isObject(v) ||
    Object.entries(v).every(
      ([k, x]) => !forbidden.has(k.toLowerCase()) && credentialFree(x),
    )
  );
}
export function deepFreeze<T>(v: T): Readonly<T> {
  if (v && typeof v === "object") {
    for (const x of Object.values(v as object)) deepFreeze(x);
    Object.freeze(v);
  }
  return v;
}
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isObject(value))
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
export const sha256 = (v: unknown, omitted: string) => {
  const copy = { ...(v as Record<string, unknown>) };
  delete copy[omitted];
  return createHash("sha256").update(canonical(copy)).digest("hex");
};
export const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
export const SHA = /^[a-f0-9]{64}$/;
export const SHA1 = /^[a-f0-9]{40}$/;
export const timestamp = (s: unknown): s is string =>
  typeof s === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s) &&
  new Date(s).toISOString() === s;
export const strings = (
  v: unknown,
  min: number,
  max: number,
  itemMax = 8192,
): v is string[] =>
  Array.isArray(v) &&
  v.length >= min &&
  v.length <= max &&
  v.every((x) => typeof x === "string" && x.length > 0 && x.length <= itemMax);
export const utf16OrdinalCompare = (a: string, b: string): number =>
  a < b ? -1 : a > b ? 1 : 0;
const orderedUnique = (v: readonly string[]) =>
  new Set(v).size === v.length &&
  v.every((x, i) => i === 0 || utf16OrdinalCompare(v[i - 1]!, x) < 0);

export const FLOW_TASK_PACKET_ID = "spts.flow-task-packet" as const;
export const FLOW_TASK_PACKET_VERSION = "2.0.0" as const;
export type FlowRoleV2 =
  "product" | "flow" | "principal-developer" | "independent-verifier";
export interface FlowTaskPacketV2 {
  contractId: typeof FLOW_TASK_PACKET_ID;
  schemaVersion: typeof FLOW_TASK_PACKET_VERSION;
  packetId: string;
  packetDigest: string;
  issuedAt: string;
  task: { projectId: string; taskId: string; sliceId: string };
  repository: {
    repositoryId: string;
    rootId: string;
    baseBranch: string;
    headBranch: string;
    baseCommit: string;
    baseTree: string;
    candidateCommit: string;
    candidateTree: string;
  };
  run: { runId: string; parentExecutionId?: string };
  subject: {
    role: FlowRoleV2;
    actorId: string;
    executionId: string;
    workspaceId: string;
    access: string;
  };
  assurance: {
    profile: "lean" | "standard" | "critical";
    phase: "planning" | "implementation" | "verification";
  };
  authorityDigest: string;
  controllerStateDigest: string;
  work: {
    objective: string;
    acceptanceCriteria: string[];
    allowedPaths: string[];
    outOfScope: string[];
    resources: { skills: string[]; promptTemplates: string[] };
  };
}
export type UnsignedFlowTaskPacketV2 = Omit<FlowTaskPacketV2, "packetDigest">;
export interface TrustedPacketExpectedContextV2 {
  projectId: string;
  taskId: string;
  sliceId: string;
  repositoryId: string;
  rootId: string;
  runId: string;
  baseBranch: string;
  headBranch: string;
  baseCommit: string;
  baseTree: string;
  candidateCommit: string;
  candidateTree: string;
  role: FlowRoleV2;
  actorId: string;
  executionId: string;
  workspaceId: string;
  access: string;
  assurance: "lean" | "standard" | "critical";
  phase: "planning" | "implementation" | "verification";
  parentExecutionId?: string;
  authorityDigest: string;
  controllerStateDigest: string;
}
/* eslint-disable no-control-regex, no-useless-escape -- protocol excludes controls */
export const isFlowBranch = (x: unknown): x is string =>
  typeof x === "string" &&
  x.length >= 1 &&
  x.length <= 255 &&
  x !== "@" &&
  !/[\x00-\x20\x7f~^:?*\[\\]/.test(x) &&
  !x.startsWith("-") &&
  !x.startsWith("/") &&
  !x.includes("//") &&
  !x.includes("..") &&
  !x.includes("@{") &&
  !x.endsWith("/") &&
  !x.endsWith(".") &&
  x
    .split("/")
    .every(
      (component) => !component.startsWith(".") && !component.endsWith(".lock"),
    );
const path = (x: string) =>
  x.length <= 1024 &&
  !x.startsWith("/") &&
  !x.includes("\\") &&
  !x.includes("//") &&
  !/[\x00-\x1f\x7f*?\[\]{}]/.test(x) &&
  x
    .split("/")
    .filter(Boolean)
    .every((s) => s !== "." && s !== "..");
/* eslint-enable no-control-regex, no-useless-escape */
function shape(x: Record<string, unknown>): boolean {
  const t = x.task,
    r = x.repository,
    n = x.run,
    s = x.subject,
    a = x.assurance,
    w = x.work;
  return (
    exact(x, [
      "contractId",
      "schemaVersion",
      "packetId",
      "packetDigest",
      "issuedAt",
      "task",
      "repository",
      "run",
      "subject",
      "assurance",
      "authorityDigest",
      "controllerStateDigest",
      "work",
    ]) &&
    isObject(t) &&
    exact(t, ["projectId", "taskId", "sliceId"]) &&
    isObject(r) &&
    exact(r, [
      "repositoryId",
      "rootId",
      "baseBranch",
      "headBranch",
      "baseCommit",
      "baseTree",
      "candidateCommit",
      "candidateTree",
    ]) &&
    isObject(n) &&
    exact(n, ["runId"], ["parentExecutionId"]) &&
    isObject(s) &&
    exact(s, ["role", "actorId", "executionId", "workspaceId", "access"]) &&
    isObject(a) &&
    exact(a, ["profile", "phase"]) &&
    isObject(w) &&
    exact(w, [
      "objective",
      "acceptanceCriteria",
      "allowedPaths",
      "outOfScope",
      "resources",
    ]) &&
    isObject(w.resources) &&
    exact(w.resources, ["skills", "promptTemplates"])
  );
}
export function validateFlowTaskPacket(
  input: unknown,
  expected?: unknown,
): ValidationResult<FlowTaskPacketV2> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<FlowTaskPacketV2>;
  const x = q.value as Record<string, unknown>;
  if (!shape(x)) return failure("schema");
  if (Buffer.byteLength(JSON.stringify(x)) > 32768)
    return failure("excessive-size");
  const p = x as unknown as FlowTaskPacketV2;
  const ids = [
    p.packetId,
    ...Object.values(p.task),
    p.repository.repositoryId,
    p.repository.rootId,
    p.run.runId,
    p.subject.actorId,
    p.subject.executionId,
    p.subject.workspaceId,
    p.subject.access,
    ...p.work.resources.skills,
    ...p.work.resources.promptTemplates,
  ];
  if (
    p.contractId !== FLOW_TASK_PACKET_ID ||
    p.schemaVersion !== FLOW_TASK_PACKET_VERSION ||
    !ids.every((v) => ID.test(v)) ||
    !SHA.test(p.packetDigest) ||
    !SHA.test(p.authorityDigest) ||
    !SHA.test(p.controllerStateDigest) ||
    !timestamp(p.issuedAt) ||
    ![
      p.repository.baseCommit,
      p.repository.baseTree,
      p.repository.candidateCommit,
      p.repository.candidateTree,
    ].every((v) => SHA1.test(v)) ||
    !isFlowBranch(p.repository.baseBranch) ||
    !isFlowBranch(p.repository.headBranch) ||
    !(
      [
        "product",
        "flow",
        "principal-developer",
        "independent-verifier",
      ] as string[]
    ).includes(p.subject.role) ||
    !(["lean", "standard", "critical"] as string[]).includes(
      p.assurance.profile,
    ) ||
    !(["planning", "implementation", "verification"] as string[]).includes(
      p.assurance.phase,
    ) ||
    p.work.objective.length < 1 ||
    p.work.objective.length > 4096 ||
    !strings(p.work.acceptanceCriteria, 1, 32, 1024) ||
    !strings(p.work.allowedPaths, 1, 64, 1024) ||
    !p.work.allowedPaths.every(path) ||
    !strings(p.work.outOfScope, 0, 32) ||
    !strings(p.work.resources.skills, 0, 16) ||
    !strings(p.work.resources.promptTemplates, 0, 16)
  )
    return failure("schema");
  if (!credentialFree(p)) return failure("credential-content");
  if (
    ![
      p.work.acceptanceCriteria,
      p.work.allowedPaths,
      p.work.outOfScope,
      p.work.resources.skills,
      p.work.resources.promptTemplates,
    ].every(orderedUnique)
  )
    return failure("non-canonical");
  if (p.packetDigest !== sha256(p, "packetDigest"))
    return failure("digest-mismatch", "/packetDigest");
  if (expected !== undefined) {
    const e = snapshot(expected);
    if (!e.valid) return e as ValidationResult<FlowTaskPacketV2>;
    const expectedKeys = [
      "projectId",
      "taskId",
      "sliceId",
      "repositoryId",
      "rootId",
      "runId",
      "baseBranch",
      "headBranch",
      "baseCommit",
      "baseTree",
      "candidateCommit",
      "candidateTree",
      "role",
      "actorId",
      "executionId",
      "workspaceId",
      "access",
      "assurance",
      "phase",
      "authorityDigest",
      "controllerStateDigest",
    ];
    if (
      !exact(e.value as Record<string, unknown>, expectedKeys, [
        "parentExecutionId",
      ])
    )
      return failure("schema");
    const actual: TrustedPacketExpectedContextV2 = {
      ...p.task,
      repositoryId: p.repository.repositoryId,
      rootId: p.repository.rootId,
      runId: p.run.runId,
      baseBranch: p.repository.baseBranch,
      headBranch: p.repository.headBranch,
      baseCommit: p.repository.baseCommit,
      baseTree: p.repository.baseTree,
      candidateCommit: p.repository.candidateCommit,
      candidateTree: p.repository.candidateTree,
      ...p.subject,
      assurance: p.assurance.profile,
      phase: p.assurance.phase,
      ...(p.run.parentExecutionId === undefined
        ? {}
        : { parentExecutionId: p.run.parentExecutionId }),
      authorityDigest: p.authorityDigest,
      controllerStateDigest: p.controllerStateDigest,
    };
    if (canonical(e.value) !== canonical(actual))
      return failure("context-mismatch");
  }
  return { valid: true, value: deepFreeze(p) };
}
export function canonicalizeFlowTaskPacket(input: unknown) {
  return validateFlowTaskPacket(input);
}
export function digestFlowTaskPacket(input: unknown): ValidationResult<string> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<string>;
  const unsigned = q.value as Record<string, unknown>;
  if (Object.hasOwn(unsigned, "packetDigest")) return failure("schema");
  const digest = sha256(unsigned, "packetDigest");
  const checked = validateFlowTaskPacket({ ...unsigned, packetDigest: digest });
  return checked.valid
    ? { valid: true, value: digest }
    : (checked as ValidationResult<string>);
}
export function isFlowPathAuthorized(
  allowed: readonly string[],
  changed: string,
): boolean {
  return (
    path(changed) &&
    allowed.some((a) =>
      a.endsWith("/") ? changed.startsWith(a) : changed === a,
    )
  );
}

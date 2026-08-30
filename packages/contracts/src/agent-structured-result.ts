import {
  credentialFree,
  deepFreeze,
  exact,
  failure,
  ID,
  isObject,
  isFlowBranch,
  SHA,
  SHA1,
  sha256,
  snapshot,
  type ValidationResult,
} from "./flow-task-packet.js";
import { FLOW_SUBMIT_RESULT_TOOL } from "./agent-execution-manifest-v2.js";
import {
  validateFlowTaskPacket,
  type FlowRoleV2,
  isFlowPathAuthorized,
  utf16OrdinalCompare,
} from "./flow-task-packet.js";
export const AGENT_STRUCTURED_RESULT_ID =
  "spts.agent-structured-result" as const;
export const AGENT_STRUCTURED_RESULT_VERSION = "2.0.0" as const;
export interface AgentStructuredResultV2 {
  contractId: typeof AGENT_STRUCTURED_RESULT_ID;
  schemaVersion: typeof AGENT_STRUCTURED_RESULT_VERSION;
  resultId: string;
  resultDigest: string;
  packetId: string;
  packetDigest: string;
  projectId: string;
  taskId: string;
  repositoryId: string;
  runId: string;
  baseBranch: string;
  baseCommit: string;
  baseTree: string;
  headBranch: string;
  candidateCommit: string;
  candidateTree: string;
  role: FlowRoleV2;
  actorId: string;
  executionId: string;
  workspaceId: string;
  access: string;
  assurance: "lean" | "standard" | "critical";
  authorityDigest: string;
  controllerStateDigest: string;
  status: string;
  payload: Record<string, unknown>;
}
export type UnsignedAgentStructuredResultV2 = Omit<
  AgentStructuredResultV2,
  "resultDigest"
>;
const common = [
  "contractId",
  "schemaVersion",
  "resultId",
  "resultDigest",
  "packetId",
  "packetDigest",
  "projectId",
  "taskId",
  "repositoryId",
  "runId",
  "baseBranch",
  "baseCommit",
  "baseTree",
  "headBranch",
  "candidateCommit",
  "candidateTree",
  "role",
  "actorId",
  "executionId",
  "workspaceId",
  "access",
  "assurance",
  "authorityDigest",
  "controllerStateDigest",
  "status",
  "payload",
] as const;
const combinations: Record<FlowRoleV2, Record<string, string>> = {
  product: { planned: "plan-ready", blocked: "stakeholder-blocked" },
  flow: {
    accepted: "review-approved",
    "changes-requested": "changes-requested",
    blocked: "authority-blocked",
  },
  "principal-developer": {
    completed: "implementation-ready",
    blocked: "implementation-blocked",
  },
  "independent-verifier": {
    approved: "verified",
    rejected: "rejected",
    blocked: "verification-blocked",
  },
};
const enumValue = (v: unknown, a: readonly string[]) =>
  typeof v === "string" && a.includes(v);
const text = (v: unknown, max: number) =>
  typeof v === "string" && v.length >= 1 && v.length <= max;
const orderedUnique = (
  values: readonly unknown[],
  order?: readonly string[],
) => {
  if (!values.every((v) => typeof v === "string")) return false;
  const strings = values as string[];
  if (new Set(strings).size !== strings.length) return false;
  const rank = order ? (v: string) => order.indexOf(v) : undefined;
  return strings.every(
    (v, i) =>
      i === 0 ||
      (rank
        ? rank(strings[i - 1]!) < rank(v)
        : utf16OrdinalCompare(strings[i - 1]!, v) < 0),
  );
};
const checkOrder = [
  "format-check",
  "lint",
  "typecheck",
  "test",
  "build",
  "quality",
] as const;
const axisOrder = [
  "plan-specification",
  "security",
  "correctness",
  "simplicity",
] as const;
const findingCodes = [
  "incomplete-specification",
  "security-boundary",
  "scope-violation",
  "test-gap",
  "authority-gap",
] as const;
function validPayload(r: AgentStructuredResultV2): boolean {
  const p = r.payload,
    o = p.outcomeCode;
  if (typeof o !== "string" || combinations[r.role]?.[r.status] !== o)
    return false;
  if (r.role === "product") {
    if (o === "stakeholder-blocked")
      return (
        exact(p, ["kind", "outcomeCode", "blocker"]) &&
        p.kind === "product" &&
        enumValue(p.blocker, [
          "stakeholder-decision-required",
          "architecture-decision-required",
          "authority-unavailable",
        ])
      );
    if (
      !exact(p, ["kind", "outcomeCode", "planDigest", "taskDefinitions"]) ||
      p.kind !== "product" ||
      typeof p.planDigest !== "string" ||
      !SHA.test(p.planDigest) ||
      !Array.isArray(p.taskDefinitions) ||
      p.taskDefinitions.length < 1 ||
      p.taskDefinitions.length > 32
    )
      return false;
    return p.taskDefinitions.every(
      (d) =>
        isObject(d) &&
        exact(d, [
          "taskId",
          "objective",
          "allowedPaths",
          "acceptanceTests",
          "dependencies",
        ]) &&
        typeof d.taskId === "string" &&
        ID.test(d.taskId) &&
        text(d.objective, 1024) &&
        Array.isArray(d.allowedPaths) &&
        d.allowedPaths.length >= 1 &&
        d.allowedPaths.length <= 64 &&
        orderedUnique(d.allowedPaths) &&
        d.allowedPaths.every(
          (x) => typeof x === "string" && isFlowPathAuthorized([x], x),
        ) &&
        Array.isArray(d.acceptanceTests) &&
        d.acceptanceTests.length >= 1 &&
        d.acceptanceTests.length <= 32 &&
        d.acceptanceTests.every((x) => text(x, 512)) &&
        orderedUnique(d.acceptanceTests) &&
        Array.isArray(d.dependencies) &&
        d.dependencies.length <= 32 &&
        d.dependencies.every((x) => typeof x === "string" && ID.test(x)) &&
        orderedUnique(d.dependencies),
    );
  }
  if (r.role === "flow") {
    const blocked = o === "authority-blocked";
    if (
      !exact(
        p,
        blocked
          ? ["kind", "outcomeCode", "reviewedDigest", "findings", "blocker"]
          : ["kind", "outcomeCode", "reviewedDigest", "findings"],
      ) ||
      p.kind !== "flow" ||
      typeof p.reviewedDigest !== "string" ||
      !SHA.test(p.reviewedDigest) ||
      !Array.isArray(p.findings) ||
      p.findings.length > 32
    )
      return false;
    if (blocked)
      return (
        p.findings.length === 0 &&
        enumValue(p.blocker, [
          "stakeholder-authority-required",
          "trusted-input-unavailable",
          "architecture-decision-required",
        ])
      );
    if (o === "changes-requested" && p.findings.length < 1) return false;
    return (
      p.findings.every(
        (f) =>
          isObject(f) &&
          exact(f, ["code", "severity", "location", "remediation"]) &&
          enumValue(f.code, [
            "incomplete-specification",
            "security-boundary",
            "scope-violation",
            "test-gap",
            "authority-gap",
          ]) &&
          enumValue(f.severity, ["material", "advisory"]) &&
          text(f.location, 256) &&
          text(f.remediation, 1024),
      ) &&
      (o !== "changes-requested" ||
        p.findings.some(
          (f) => (f as Record<string, unknown>).severity === "material",
        )) &&
      (o !== "review-approved" ||
        p.findings.every(
          (f) => (f as Record<string, unknown>).severity === "advisory",
        ))
    );
  }
  if (r.role === "principal-developer") {
    const blocked = o === "implementation-blocked";
    const required = blocked
      ? [
          "kind",
          "outcomeCode",
          "baseCommit",
          "changedPaths",
          "checks",
          "blocker",
        ]
      : [
          "kind",
          "outcomeCode",
          "baseCommit",
          "baseTree",
          "resultCommit",
          "resultTree",
          "changedPaths",
          "checks",
        ];
    if (
      !exact(p, required) ||
      p.kind !== "principal-developer" ||
      typeof p.baseCommit !== "string" ||
      !SHA1.test(p.baseCommit) ||
      !Array.isArray(p.changedPaths) ||
      !Array.isArray(p.checks) ||
      p.checks.length > 6 ||
      !p.checks.every(
        (c) =>
          isObject(c) &&
          exact(c, ["commandId", "outcome", "evidenceDigest"]) &&
          enumValue(c.commandId, checkOrder) &&
          enumValue(c.outcome, ["passed", "failed"]) &&
          typeof c.evidenceDigest === "string" &&
          SHA.test(c.evidenceDigest),
      ) ||
      !orderedUnique(
        p.checks.map((c) => (c as Record<string, unknown>).commandId),
        checkOrder,
      )
    )
      return false;
    if (blocked)
      return (
        p.changedPaths.length === 0 &&
        p.checks.every(
          (c) => (c as Record<string, unknown>).outcome === "failed",
        ) &&
        enumValue(p.blocker, [
          "baseline-failure",
          "implementation-failure",
          "authority-unavailable",
          "path-scope-conflict",
        ])
      );
    return (
      p.changedPaths.length >= 1 &&
      p.changedPaths.length <= 128 &&
      orderedUnique(p.changedPaths) &&
      p.changedPaths.every(
        (x) => typeof x === "string" && isFlowPathAuthorized([x], x),
      ) &&
      p.checks.length >= 1 &&
      p.checks.every(
        (c) => (c as Record<string, unknown>).outcome === "passed",
      ) &&
      [p.baseTree, p.resultCommit, p.resultTree].every(
        (x) => typeof x === "string" && SHA1.test(x),
      )
    );
  }
  const blocked = o === "verification-blocked";
  if (
    !exact(
      p,
      blocked
        ? ["kind", "outcomeCode", "subjectDigest", "blocker"]
        : ["kind", "outcomeCode", "subjectDigest", "axes"],
    ) ||
    p.kind !== "independent-verifier" ||
    typeof p.subjectDigest !== "string" ||
    !SHA.test(p.subjectDigest)
  )
    return false;
  if (blocked)
    return enumValue(p.blocker, [
      "subject-unavailable",
      "trusted-input-unavailable",
      "isolation-unavailable",
    ]);
  if (!Array.isArray(p.axes) || p.axes.length < 1 || p.axes.length > 4)
    return false;
  const axes = p.axes as Record<string, unknown>[];
  return (
    axes.every(
      (a) =>
        isObject(a) &&
        exact(a, ["axis", "verdict", "findingCodes"]) &&
        enumValue(a.axis, axisOrder) &&
        enumValue(a.verdict, ["approve", "reject"]) &&
        Array.isArray(a.findingCodes) &&
        a.findingCodes.length <= 32 &&
        a.findingCodes.every((x) => enumValue(x, findingCodes)) &&
        orderedUnique(a.findingCodes, findingCodes),
    ) &&
    orderedUnique(
      axes.map((a) => a.axis),
      axisOrder,
    ) &&
    (o !== "verified" || axes.every((a) => a.verdict === "approve")) &&
    (o !== "rejected" || axes.some((a) => a.verdict === "reject"))
  );
}
export function validateAgentStructuredResult(
  input: unknown,
): ValidationResult<AgentStructuredResultV2> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<AgentStructuredResultV2>;
  const x = q.value as Record<string, unknown>;
  if (!exact(x, common) || !isObject(x.payload)) return failure("schema");
  if (Buffer.byteLength(JSON.stringify(x)) > 16384)
    return failure("excessive-size");
  const r = x as unknown as AgentStructuredResultV2;
  if (
    r.contractId !== AGENT_STRUCTURED_RESULT_ID ||
    r.schemaVersion !== AGENT_STRUCTURED_RESULT_VERSION ||
    ![
      r.resultId,
      r.packetId,
      r.projectId,
      r.taskId,
      r.repositoryId,
      r.runId,
      r.actorId,
      r.executionId,
      r.workspaceId,
      r.access,
    ].every((v) => typeof v === "string" && ID.test(v)) ||
    ![
      r.resultDigest,
      r.packetDigest,
      r.authorityDigest,
      r.controllerStateDigest,
    ].every((v) => typeof v === "string" && SHA.test(v)) ||
    ![r.baseCommit, r.baseTree, r.candidateCommit, r.candidateTree].every(
      (v) => typeof v === "string" && SHA1.test(v),
    ) ||
    !isFlowBranch(r.baseBranch) ||
    !isFlowBranch(r.headBranch) ||
    !enumValue(r.assurance, ["lean", "standard", "critical"]) ||
    !validPayload(r)
  )
    return failure("schema");
  if (!credentialFree(r)) return failure("credential-content");
  if (r.resultDigest !== sha256(r, "resultDigest"))
    return failure("digest-mismatch", "/resultDigest");
  return { valid: true, value: deepFreeze(r) };
}
export const canonicalizeAgentStructuredResult = validateAgentStructuredResult;
export function digestAgentStructuredResult(
  input: unknown,
): ValidationResult<string> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<string>;
  const unsigned = q.value as Record<string, unknown>;
  if (Object.hasOwn(unsigned, "resultDigest")) return failure("schema");
  const digest = sha256(unsigned, "resultDigest");
  const checked = validateAgentStructuredResult({
    ...unsigned,
    resultDigest: digest,
  });
  return checked.valid
    ? { valid: true, value: digest }
    : (checked as ValidationResult<string>);
}
export interface ResultSubmissionState {
  executionId: string;
  acceptedResultDigest: string | null;
}
export type SubmissionResult =
  | {
      accepted: true;
      state: Readonly<ResultSubmissionState>;
      result: Readonly<AgentStructuredResultV2>;
    }
  | {
      accepted: false;
      errors: readonly { path: string; code: string; message: string }[];
    };
export function acceptStructuredResultSubmission(
  stateInput: unknown,
  toolNameInput: unknown,
  candidate: unknown,
  packetInput: unknown,
  expected?: unknown,
): SubmissionResult {
  const packet = validateFlowTaskPacket(packetInput, expected);
  if (!packet.valid) return { accepted: false, errors: packet.errors };
  const result = validateAgentStructuredResult(candidate);
  if (!result.valid) return { accepted: false, errors: result.errors };
  const stateSnapshot = snapshot(stateInput);
  if (!stateSnapshot.valid)
    return { accepted: false, errors: stateSnapshot.errors };
  const state = stateSnapshot.value as Record<string, unknown>;
  if (
    !exact(state, ["executionId", "acceptedResultDigest"]) ||
    typeof state.executionId !== "string" ||
    !ID.test(state.executionId) ||
    !(
      state.acceptedResultDigest === null ||
      (typeof state.acceptedResultDigest === "string" &&
        SHA.test(state.acceptedResultDigest))
    )
  )
    return {
      accepted: false,
      errors: [
        {
          path: "/",
          code: "schema",
          message: "input does not match the closed contract",
        },
      ],
    };
  if (typeof toolNameInput !== "string")
    return {
      accepted: false,
      errors: [
        {
          path: "/",
          code: "schema",
          message: "input does not match the closed contract",
        },
      ],
    };
  if (toolNameInput !== FLOW_SUBMIT_RESULT_TOOL)
    return {
      accepted: false,
      errors: [
        {
          path: "/",
          code: "result-mismatch",
          message: "result does not match its packet",
        },
      ],
    };
  if (state.acceptedResultDigest !== null)
    return {
      accepted: false,
      errors: [
        {
          path: "/",
          code: "duplicate-result",
          message: "a result has already been accepted",
        },
      ],
    };
  const p = packet.value,
    r = result.value;
  const same =
    r.packetId === p.packetId &&
    r.packetDigest === p.packetDigest &&
    r.projectId === p.task.projectId &&
    r.taskId === p.task.taskId &&
    r.repositoryId === p.repository.repositoryId &&
    r.runId === p.run.runId &&
    r.baseBranch === p.repository.baseBranch &&
    r.baseCommit === p.repository.baseCommit &&
    r.baseTree === p.repository.baseTree &&
    r.headBranch === p.repository.headBranch &&
    r.candidateCommit === p.repository.candidateCommit &&
    r.candidateTree === p.repository.candidateTree &&
    r.role === p.subject.role &&
    r.actorId === p.subject.actorId &&
    r.executionId === p.subject.executionId &&
    r.workspaceId === p.subject.workspaceId &&
    r.access === p.subject.access &&
    r.assurance === p.assurance.profile &&
    r.authorityDigest === p.authorityDigest &&
    r.controllerStateDigest === p.controllerStateDigest;
  const changedPaths =
    r.role === "principal-developer" && Array.isArray(r.payload.changedPaths)
      ? r.payload.changedPaths
      : [];
  const pathsAuthorized = changedPaths.every(
    (changed) =>
      typeof changed === "string" &&
      isFlowPathAuthorized(p.work.allowedPaths, changed),
  );
  if (!same || !pathsAuthorized || state.executionId !== r.executionId)
    return {
      accepted: false,
      errors: [
        {
          path: "/",
          code: "result-mismatch",
          message: "result does not match its packet",
        },
      ],
    };
  return {
    accepted: true,
    state: deepFreeze({
      executionId: state.executionId,
      acceptedResultDigest: r.resultDigest,
    }),
    result: r,
  };
}

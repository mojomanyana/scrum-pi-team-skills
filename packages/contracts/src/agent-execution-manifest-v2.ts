import {
  credentialFree,
  deepFreeze,
  exact,
  failure,
  ID,
  isObject,
  SHA,
  sha256,
  snapshot,
  type ValidationResult,
} from "./flow-task-packet.js";
import {
  validateFlowTaskPacket,
  type FlowTaskPacketV2,
  type FlowRoleV2,
} from "./flow-task-packet.js";
export const AGENT_EXECUTION_MANIFEST_V2_ID =
  "spts.agent-execution-manifest" as const;
export const AGENT_EXECUTION_MANIFEST_V2_VERSION = "2.0.0" as const;
export const FLOW_SUBMIT_RESULT_TOOL = "flow_submit_result" as const;
export const AGENT_ROLE_PROFILES_V2 = {
  product: {
    toolProfileId: "product-v2",
    workspaceProfileId: "read-only-v2",
    tools: ["read", "grep", "find", "ls", FLOW_SUBMIT_RESULT_TOOL],
  },
  flow: {
    toolProfileId: "flow-v2",
    workspaceProfileId: "read-only-v2",
    tools: ["read", "grep", "find", "ls", FLOW_SUBMIT_RESULT_TOOL],
  },
  "principal-developer": {
    toolProfileId: "principal-developer-v2",
    workspaceProfileId: "bounded-writer-v2",
    tools: ["read", "grep", "find", "ls", "bash", FLOW_SUBMIT_RESULT_TOOL],
  },
  "independent-verifier": {
    toolProfileId: "independent-verifier-v2",
    workspaceProfileId: "fresh-detached-read-only-v2",
    tools: ["read", "grep", "find", "ls", FLOW_SUBMIT_RESULT_TOOL],
  },
} as const;
export interface AgentExecutionManifestV2 {
  contractId: typeof AGENT_EXECUTION_MANIFEST_V2_ID;
  schemaVersion: typeof AGENT_EXECUTION_MANIFEST_V2_VERSION;
  manifestId: string;
  manifestDigest: string;
  packet: FlowTaskPacketV2;
  role: FlowRoleV2;
  actorId: string;
  executionId: string;
  workspaceId: string;
  access: string;
  resources: { skills: string[]; promptTemplates: string[] };
  toolProfileId: string;
  workspaceProfileId: string;
  tools: string[];
  resultProtocol: {
    toolName: typeof FLOW_SUBMIT_RESULT_TOOL;
    contractId: "spts.agent-structured-result";
    schemaVersion: "2.0.0";
    minimum: 1;
    maximum: 1;
  };
}
export type UnsignedAgentExecutionManifestV2 = Omit<
  AgentExecutionManifestV2,
  "manifestDigest"
>;
function embeddedPacketHasShape(x: unknown): x is Record<string, unknown> {
  if (!isObject(x)) return false;
  const task = x.task,
    repository = x.repository,
    run = x.run,
    subject = x.subject,
    assurance = x.assurance,
    work = x.work;
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
    isObject(task) &&
    exact(task, ["projectId", "taskId", "sliceId"]) &&
    isObject(repository) &&
    exact(repository, [
      "repositoryId",
      "rootId",
      "baseBranch",
      "headBranch",
      "baseCommit",
      "baseTree",
      "candidateCommit",
      "candidateTree",
    ]) &&
    isObject(run) &&
    exact(run, ["runId"], ["parentExecutionId"]) &&
    isObject(subject) &&
    exact(subject, [
      "role",
      "actorId",
      "executionId",
      "workspaceId",
      "access",
    ]) &&
    isObject(assurance) &&
    exact(assurance, ["profile", "phase"]) &&
    isObject(work) &&
    exact(work, [
      "objective",
      "acceptanceCriteria",
      "allowedPaths",
      "outOfScope",
      "resources",
    ]) &&
    isObject(work.resources) &&
    exact(work.resources, ["skills", "promptTemplates"])
  );
}

export function validateAgentExecutionManifestV2(
  input: unknown,
): ValidationResult<AgentExecutionManifestV2> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<AgentExecutionManifestV2>;
  const x = q.value as Record<string, unknown>;
  if (
    !exact(x, [
      "contractId",
      "schemaVersion",
      "manifestId",
      "manifestDigest",
      "packet",
      "role",
      "actorId",
      "executionId",
      "workspaceId",
      "access",
      "resources",
      "toolProfileId",
      "workspaceProfileId",
      "tools",
      "resultProtocol",
    ]) ||
    !isObject(x.resources) ||
    !exact(x.resources, ["skills", "promptTemplates"]) ||
    !isObject(x.resultProtocol) ||
    !exact(x.resultProtocol, [
      "toolName",
      "contractId",
      "schemaVersion",
      "minimum",
      "maximum",
    ])
  )
    return failure("schema");
  // Structural diagnostics are deliberately deterministic: the envelope is
  // checked first, then the complete embedded packet, before either contract's
  // content, canonicalization, digest, or correlation checks.
  if (!embeddedPacketHasShape(x.packet)) return failure("schema");
  const m = x as unknown as AgentExecutionManifestV2;
  if (
    m.contractId !== AGENT_EXECUTION_MANIFEST_V2_ID ||
    m.schemaVersion !== AGENT_EXECUTION_MANIFEST_V2_VERSION ||
    ![
      m.manifestId,
      m.actorId,
      m.executionId,
      m.workspaceId,
      m.access,
      m.toolProfileId,
      m.workspaceProfileId,
    ].every((v) => typeof v === "string" && ID.test(v)) ||
    !SHA.test(m.manifestDigest) ||
    !Array.isArray(m.tools) ||
    !Array.isArray(m.resources.skills) ||
    !Array.isArray(m.resources.promptTemplates) ||
    m.resources.skills.length > 16 ||
    m.resources.promptTemplates.length > 16 ||
    ![...m.resources.skills, ...m.resources.promptTemplates].every(
      (v) => typeof v === "string" && ID.test(v),
    ) ||
    new Set(m.resources.skills).size !== m.resources.skills.length ||
    new Set(m.resources.promptTemplates).size !==
      m.resources.promptTemplates.length ||
    m.resultProtocol.toolName !== FLOW_SUBMIT_RESULT_TOOL ||
    m.resultProtocol.contractId !== "spts.agent-structured-result" ||
    m.resultProtocol.schemaVersion !== "2.0.0" ||
    m.resultProtocol.minimum !== 1 ||
    m.resultProtocol.maximum !== 1
  )
    return failure("schema");
  if (!credentialFree(m)) return failure("credential-content");
  const packet = validateFlowTaskPacket(m.packet);
  if (!packet.valid)
    return packet as ValidationResult<AgentExecutionManifestV2>;
  if (m.manifestDigest !== sha256(m, "manifestDigest"))
    return failure("digest-mismatch", "/manifestDigest");
  if (
    m.role !== m.packet.subject.role ||
    m.actorId !== m.packet.subject.actorId ||
    m.executionId !== m.packet.subject.executionId ||
    m.workspaceId !== m.packet.subject.workspaceId ||
    m.access !== m.packet.subject.access ||
    JSON.stringify(m.resources) !== JSON.stringify(m.packet.work.resources)
  )
    return failure("identity-mismatch");
  const profile = AGENT_ROLE_PROFILES_V2[m.role];
  if (!profile) return failure("role-mismatch");
  if (
    m.toolProfileId !== profile.toolProfileId ||
    m.workspaceProfileId !== profile.workspaceProfileId ||
    JSON.stringify(m.tools) !== JSON.stringify(profile.tools)
  )
    return failure("tool-policy");
  return { valid: true, value: deepFreeze(m) };
}
export const canonicalizeAgentExecutionManifestV2 =
  validateAgentExecutionManifestV2;
export function digestAgentExecutionManifestV2(
  input: unknown,
): ValidationResult<string> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<string>;
  const unsigned = q.value as Record<string, unknown>;
  if (Object.hasOwn(unsigned, "manifestDigest")) return failure("schema");
  const digest = sha256(unsigned, "manifestDigest");
  const checked = validateAgentExecutionManifestV2({
    ...unsigned,
    manifestDigest: digest,
  });
  return checked.valid
    ? { valid: true, value: digest }
    : (checked as ValidationResult<string>);
}

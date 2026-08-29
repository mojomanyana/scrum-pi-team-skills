import {
  canonicalSerializeLifecycleValue,
  isCanonicalLifecycleTimestamp,
} from "./lifecycle-receipt.js";
export interface CandidateIdentityV2 {
  commit: string;
  tree: string;
}
export interface VerifierVerdictV2 {
  verdict: "APPROVE" | "REQUEST_CHANGES";
  candidate: CandidateIdentityV2;
  role: string;
  access: string;
  actorId: string;
  executionId: string;
  workspaceId: string;
  evidenceIds: string[];
  controllerRevision: number;
  fresh: boolean;
}
export interface DeliveryVerifierVerdictsV2 {
  specification: VerifierVerdictV2;
  quality: VerifierVerdictV2;
}
export interface DeliveryCiEvidenceV2 {
  repositoryId: string;
  pullRequest: number;
  headBranch: string;
  candidate: CandidateIdentityV2;
  workflowId: string;
  checkId: string;
  runId: string;
  attempt: number;
  conclusion: "success" | "failure";
  observedAt: string;
  fresh: boolean;
  requiredCheckPolicyDigest: string;
}
const invalid = (code: string) => ({
  valid: false as const,
  errors: [{ path: "/", code, message: "trusted evidence is invalid" }],
});
const same = (a: unknown, b: unknown) => {
  try {
    return (
      canonicalSerializeLifecycleValue(a) ===
      canonicalSerializeLifecycleValue(b)
    );
  } catch {
    return false;
  }
};
function exactKeys(value: unknown, keys: string[]): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === Object.prototype &&
    same(Object.keys(value).sort(), [...keys].sort())
  );
}
export function validateDeliveryVerifierVerdictsV2(
  value: unknown,
  candidate: CandidateIdentityV2,
) {
  if (!exactKeys(value, ["specification", "quality"]))
    return invalid("verdict-envelope");
  const v = value as DeliveryVerifierVerdictsV2;
  for (const verdict of [v.specification, v.quality]) {
    if (
      !exactKeys(verdict, [
        "verdict",
        "candidate",
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
        "evidenceIds",
        "controllerRevision",
        "fresh",
      ]) ||
      verdict.role !== "independent-verifier" ||
      verdict.access !== "read-only" ||
      !verdict.fresh ||
      !same(verdict.candidate, candidate) ||
      !Array.isArray(verdict.evidenceIds) ||
      verdict.evidenceIds.length === 0 ||
      !Number.isSafeInteger(verdict.controllerRevision)
    )
      return invalid("verdict-binding");
  }
  if (
    v.specification.actorId !== v.quality.actorId ||
    v.specification.executionId !== v.quality.executionId ||
    v.specification.workspaceId !== v.quality.workspaceId ||
    v.specification.controllerRevision !== v.quality.controllerRevision
  )
    return invalid("split-verifier");
  return { valid: true as const, value: v };
}
export function validateDeliveryCiEvidenceV2(
  value: unknown,
  trusted: {
    repositoryId: string;
    pullRequest: number;
    headBranch: string;
    candidate: CandidateIdentityV2;
    requiredCheckPolicyDigest: string;
  },
) {
  if (
    !exactKeys(value, [
      "repositoryId",
      "pullRequest",
      "headBranch",
      "candidate",
      "workflowId",
      "checkId",
      "runId",
      "attempt",
      "conclusion",
      "observedAt",
      "fresh",
      "requiredCheckPolicyDigest",
    ])
  )
    return invalid("ci-envelope");
  const ci = value as DeliveryCiEvidenceV2;
  if (
    !same(
      {
        repositoryId: ci.repositoryId,
        pullRequest: ci.pullRequest,
        headBranch: ci.headBranch,
        candidate: ci.candidate,
        requiredCheckPolicyDigest: ci.requiredCheckPolicyDigest,
      },
      trusted,
    ) ||
    !ci.fresh ||
    !Number.isSafeInteger(ci.attempt) ||
    ci.attempt < 1 ||
    !isCanonicalLifecycleTimestamp(ci.observedAt) ||
    !ci.workflowId ||
    !ci.checkId ||
    !ci.runId ||
    !["success", "failure"].includes(ci.conclusion)
  )
    return invalid("ci-binding");
  return { valid: true as const, value: ci };
}
export function evaluateDeliveryPublicationV2(
  verdicts: unknown,
  ci: unknown,
  candidate: CandidateIdentityV2,
) {
  const v = validateDeliveryVerifierVerdictsV2(verdicts, candidate);
  if (!v.valid) return { allowed: false, code: "verdicts-required" as const };
  const c = ci as DeliveryCiEvidenceV2;
  const cv = validateDeliveryCiEvidenceV2(ci, {
    repositoryId: c.repositoryId,
    pullRequest: c.pullRequest,
    headBranch: c.headBranch,
    candidate,
    requiredCheckPolicyDigest: c.requiredCheckPolicyDigest,
  });
  return v.value.specification.verdict === "APPROVE" &&
    v.value.quality.verdict === "APPROVE" &&
    cv.valid &&
    cv.value.conclusion === "success"
    ? { allowed: true, code: "accepted" as const }
    : { allowed: false, code: "evidence-required" as const };
}

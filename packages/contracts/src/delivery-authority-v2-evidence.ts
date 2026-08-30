import { isCanonicalLifecycleTimestamp } from "./lifecycle-receipt.js";
import {
  sameDeliveryV2Value,
  snapshotDeliveryV2Input,
} from "./delivery-authority-v2-input.js";
import type { DeliveryIdentityV2 } from "./delivery-authority-v2.js";
export interface CandidateIdentityV2 {
  commit: string;
  tree: string;
}
export interface VerifierVerdictV2 {
  axis: "specification" | "quality";
  verdict: "APPROVE" | "REQUEST_CHANGES";
  identity: DeliveryIdentityV2;
  candidate: CandidateIdentityV2;
  controllerRevision: number;
  observedAt: string;
  freshThroughEventId: string;
  evidenceIds: string[];
}
export interface DeliveryVerifierVerdictsV2 {
  specification: VerifierVerdictV2;
  quality: VerifierVerdictV2;
}
export interface TrustedVerifierProvenanceV2 {
  identity: DeliveryIdentityV2;
  candidate: CandidateIdentityV2;
  controllerRevision: number;
  observedAt: string;
  freshThroughEventId: string;
  evidenceIds: string[];
}
export interface DeliveryCiEvidenceV2 {
  projectId: string;
  taskId: string;
  repositoryId: string;
  runId: string;
  pullRequest: number;
  baseBranch: string;
  headBranch: string;
  candidate: CandidateIdentityV2;
  workflowId: string;
  checkId: string;
  ciRunId: string;
  attempt: number;
  conclusion: "success" | "failure";
  observedAt: string;
  freshThroughEventId: string;
  requiredCheckPolicyDigest: string;
  fresh: boolean;
}
const invalid = (code: string) => ({
  valid: false as const,
  errors: [{ path: "/", code, message: "trusted evidence is invalid" }],
});
const exactKeys = (value: unknown, keys: string[]) =>
  typeof value === "object" &&
  value !== null &&
  sameDeliveryV2Value(Object.keys(value).sort(), [...keys].sort());
export function validateDeliveryVerifierVerdictsV2(
  input: unknown,
  trustedInput: unknown,
) {
  const vs = snapshotDeliveryV2Input(input),
    ts = snapshotDeliveryV2Input(trustedInput);
  if (!vs.ok || !ts.ok)
    return invalid(!vs.ok ? vs.code : ts.ok ? "input-introspection" : ts.code);
  if (!exactKeys(vs.value, ["specification", "quality"]))
    return invalid("verdict-envelope");
  const v = vs.value as DeliveryVerifierVerdictsV2,
    t = ts.value as TrustedVerifierProvenanceV2;
  if (
    !exactKeys(t, [
      "identity",
      "candidate",
      "controllerRevision",
      "observedAt",
      "freshThroughEventId",
      "evidenceIds",
    ]) ||
    t.identity.role !== "independent-verifier" ||
    t.identity.access !== "read-only" ||
    !isCanonicalLifecycleTimestamp(t.observedAt) ||
    !Number.isSafeInteger(t.controllerRevision) ||
    t.controllerRevision < 0 ||
    !Array.isArray(t.evidenceIds) ||
    t.evidenceIds.length < 2
  )
    return invalid("trusted-verifier");
  for (const [axis, verdict] of [
    ["specification", v.specification],
    ["quality", v.quality],
  ] as const) {
    if (
      !exactKeys(verdict, [
        "axis",
        "verdict",
        "identity",
        "candidate",
        "controllerRevision",
        "observedAt",
        "freshThroughEventId",
        "evidenceIds",
      ]) ||
      verdict.axis !== axis ||
      !sameDeliveryV2Value(verdict.identity, t.identity) ||
      !sameDeliveryV2Value(verdict.candidate, t.candidate) ||
      verdict.controllerRevision !== t.controllerRevision ||
      verdict.observedAt !== t.observedAt ||
      verdict.freshThroughEventId !== t.freshThroughEventId ||
      !Array.isArray(verdict.evidenceIds) ||
      verdict.evidenceIds.length === 0 ||
      verdict.evidenceIds.some((id) => !t.evidenceIds.includes(id))
    )
      return invalid("verdict-provenance");
  }
  return { valid: true as const, value: v };
}
export function validateDeliveryCiEvidenceV2(
  input: unknown,
  trustedInput: unknown,
) {
  const cs = snapshotDeliveryV2Input(input),
    ts = snapshotDeliveryV2Input(trustedInput);
  if (!cs.ok || !ts.ok)
    return invalid(!cs.ok ? cs.code : ts.ok ? "input-introspection" : ts.code);
  const keys = [
    "projectId",
    "taskId",
    "repositoryId",
    "runId",
    "pullRequest",
    "baseBranch",
    "headBranch",
    "candidate",
    "workflowId",
    "checkId",
    "ciRunId",
    "attempt",
    "conclusion",
    "observedAt",
    "freshThroughEventId",
    "requiredCheckPolicyDigest",
    "fresh",
  ];
  if (!exactKeys(cs.value, keys) || !exactKeys(ts.value, keys))
    return invalid("ci-envelope");
  const c = cs.value as DeliveryCiEvidenceV2,
    t = ts.value as DeliveryCiEvidenceV2;
  if (
    !sameDeliveryV2Value(c, t) ||
    !c.fresh ||
    c.conclusion !== "success" ||
    !Number.isSafeInteger(c.pullRequest) ||
    c.pullRequest < 1 ||
    !Number.isSafeInteger(c.attempt) ||
    c.attempt < 1 ||
    !isCanonicalLifecycleTimestamp(c.observedAt) ||
    ![
      c.projectId,
      c.taskId,
      c.repositoryId,
      c.runId,
      c.baseBranch,
      c.headBranch,
      c.workflowId,
      c.checkId,
      c.ciRunId,
      c.freshThroughEventId,
    ].every((x) => typeof x === "string" && x.length > 0) ||
    !c.requiredCheckPolicyDigest.match(/^[0-9a-f]{64}$/)
  )
    return invalid("ci-provenance");
  return { valid: true as const, value: c };
}
export function evaluateDeliveryPublicationV2(
  verdicts: unknown,
  trustedVerifier: unknown,
  ci: unknown,
  trustedCi: unknown,
) {
  const v = validateDeliveryVerifierVerdictsV2(verdicts, trustedVerifier),
    c = validateDeliveryCiEvidenceV2(ci, trustedCi);
  if (!v.valid || !c.valid)
    return { allowed: false, code: "evidence-required" as const };
  return v.value.specification.verdict === "APPROVE" &&
    v.value.quality.verdict === "APPROVE" &&
    sameDeliveryV2Value(v.value.specification.candidate, c.value.candidate)
    ? { allowed: true, code: "accepted" as const }
    : { allowed: false, code: "evidence-required" as const };
}

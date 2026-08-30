import { isCanonicalLifecycleTimestamp } from "./lifecycle-receipt.js";
import {
  hasExactDeliveryV2Keys,
  isSha1DeliveryV2,
  isSha256DeliveryV2,
  sameDeliveryV2Value,
  snapshotDeliveryV2Input,
} from "./delivery-authority-v2-input.js";
import {
  deliveryIdentityContextsMatchV2,
  isDeliveryIdentityV2,
  type DeliveryIdentityV2,
} from "./delivery-authority-v2.js";
export interface CandidateIdentityV2 {
  commit: string;
  tree: string;
}
export interface TrustedCurrentDeliveryIdentityV2 {
  delivery: DeliveryIdentityV2;
  controller: DeliveryIdentityV2;
}
export interface VerifierVerdictV2 {
  axis: "specification" | "quality";
  verdict: "APPROVE" | "REQUEST_CHANGES";
  currentIdentity: TrustedCurrentDeliveryIdentityV2;
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
  currentIdentity: TrustedCurrentDeliveryIdentityV2;
  identity: DeliveryIdentityV2;
  candidate: CandidateIdentityV2;
  controllerRevision: number;
  observedAt: string;
  freshThroughEventId: string;
  evidenceIds: string[];
}
export interface DeliveryCiEvidenceV2 {
  currentIdentity: TrustedCurrentDeliveryIdentityV2;
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
const candidateKeys = ["commit", "tree"],
  identityKeys = ["delivery", "controller"];
const validCandidate = (v: unknown): v is CandidateIdentityV2 =>
  hasExactDeliveryV2Keys(v, candidateKeys) &&
  isSha1DeliveryV2((v as CandidateIdentityV2).commit) &&
  isSha1DeliveryV2((v as CandidateIdentityV2).tree);
const validCurrent = (v: unknown): v is TrustedCurrentDeliveryIdentityV2 =>
  hasExactDeliveryV2Keys(v, identityKeys) &&
  isDeliveryIdentityV2((v as TrustedCurrentDeliveryIdentityV2).delivery) &&
  isDeliveryIdentityV2((v as TrustedCurrentDeliveryIdentityV2).controller) &&
  (v as TrustedCurrentDeliveryIdentityV2).controller.role === "controller" &&
  deliveryIdentityContextsMatchV2(
    (v as TrustedCurrentDeliveryIdentityV2).delivery,
    (v as TrustedCurrentDeliveryIdentityV2).controller,
  );
const currentMatchesCandidate = (
  current: TrustedCurrentDeliveryIdentityV2,
  candidate: CandidateIdentityV2,
) =>
  current.delivery.candidateCommit === candidate.commit &&
  current.delivery.candidateTree === candidate.tree;
export function validateDeliveryVerifierVerdictsV2(
  input: unknown,
  trustedInput: unknown,
) {
  const vs = snapshotDeliveryV2Input(input),
    ts = snapshotDeliveryV2Input(trustedInput);
  if (!vs.ok || !ts.ok)
    return invalid(!vs.ok ? vs.code : ts.ok ? "input-introspection" : ts.code);
  if (!hasExactDeliveryV2Keys(vs.value, ["specification", "quality"]))
    return invalid("verdict-envelope");
  const v = vs.value as DeliveryVerifierVerdictsV2,
    t = ts.value as TrustedVerifierProvenanceV2;
  const trustedKeys = [
    "currentIdentity",
    "identity",
    "candidate",
    "controllerRevision",
    "observedAt",
    "freshThroughEventId",
    "evidenceIds",
  ];
  if (
    !hasExactDeliveryV2Keys(t, trustedKeys) ||
    !validCurrent(t.currentIdentity) ||
    !isDeliveryIdentityV2(t.identity) ||
    t.identity.role !== "independent-verifier" ||
    !deliveryIdentityContextsMatchV2(
      t.currentIdentity.delivery,
      t.currentIdentity.controller,
      t.identity,
    ) ||
    !validCandidate(t.candidate) ||
    !currentMatchesCandidate(t.currentIdentity, t.candidate) ||
    !Number.isSafeInteger(t.controllerRevision) ||
    t.controllerRevision < 0 ||
    !isCanonicalLifecycleTimestamp(t.observedAt) ||
    !Array.isArray(t.evidenceIds) ||
    t.evidenceIds.length < 2
  )
    return invalid("trusted-verifier");
  for (const [axis, item] of [
    ["specification", v.specification],
    ["quality", v.quality],
  ] as const) {
    if (
      !hasExactDeliveryV2Keys(item, ["axis", "verdict", ...trustedKeys]) ||
      item.axis !== axis ||
      !["APPROVE", "REQUEST_CHANGES"].includes(item.verdict) ||
      !sameDeliveryV2Value(item.currentIdentity, t.currentIdentity) ||
      !sameDeliveryV2Value(item.identity, t.identity) ||
      !sameDeliveryV2Value(item.candidate, t.candidate) ||
      item.controllerRevision !== t.controllerRevision ||
      item.observedAt !== t.observedAt ||
      item.freshThroughEventId !== t.freshThroughEventId ||
      !Array.isArray(item.evidenceIds) ||
      item.evidenceIds.length === 0 ||
      item.evidenceIds.some((id) => !t.evidenceIds.includes(id))
    )
      return invalid("verdict-provenance");
  }
  return { valid: true as const, value: v };
}
const ciKeys = [
  "currentIdentity",
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
export function validateDeliveryCiEvidenceV2(
  input: unknown,
  trustedInput: unknown,
) {
  const cs = snapshotDeliveryV2Input(input),
    ts = snapshotDeliveryV2Input(trustedInput);
  if (!cs.ok || !ts.ok)
    return invalid(!cs.ok ? cs.code : ts.ok ? "input-introspection" : ts.code);
  if (
    !hasExactDeliveryV2Keys(cs.value, ciKeys) ||
    !hasExactDeliveryV2Keys(ts.value, ciKeys)
  )
    return invalid("ci-envelope");
  const c = cs.value as DeliveryCiEvidenceV2,
    t = ts.value as DeliveryCiEvidenceV2;
  const d = c.currentIdentity?.delivery;
  if (
    !sameDeliveryV2Value(c, t) ||
    !validCurrent(c.currentIdentity) ||
    !validCandidate(c.candidate) ||
    !d ||
    c.projectId !== d.projectId ||
    c.taskId !== d.taskId ||
    c.repositoryId !== d.repositoryId ||
    c.runId !== d.runId ||
    c.baseBranch !== d.baseBranch ||
    c.headBranch !== d.headBranch ||
    !currentMatchesCandidate(c.currentIdentity, c.candidate) ||
    !c.fresh ||
    c.conclusion !== "success" ||
    !Number.isSafeInteger(c.pullRequest) ||
    c.pullRequest < 1 ||
    !Number.isSafeInteger(c.attempt) ||
    c.attempt < 1 ||
    !isCanonicalLifecycleTimestamp(c.observedAt) ||
    !isSha256DeliveryV2(c.requiredCheckPolicyDigest) ||
    ![c.workflowId, c.checkId, c.ciRunId, c.freshThroughEventId].every(
      (x) => typeof x === "string" && x.length > 0,
    )
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
    sameDeliveryV2Value(
      v.value.specification.currentIdentity,
      c.value.currentIdentity,
    )
    ? { allowed: true, code: "accepted" as const }
    : { allowed: false, code: "evidence-required" as const };
}

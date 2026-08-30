import { describe, expect, it } from "vitest";
import {
  evaluateDeliveryPublicationV2,
  validateDeliveryCiEvidenceV2,
  validateDeliveryVerifierVerdictsV2,
  type DeliveryIdentityV2,
} from "../src/index.js";
const candidate = { commit: "a".repeat(40), tree: "b".repeat(40) };
const identity = {
  projectId: "SPTS",
  taskId: "SPTS-10",
  repositoryId: "repo",
  runId: "run",
  baseBranch: "main",
  baseCommit: "c".repeat(40),
  baseTree: "d".repeat(40),
  headBranch: "feature/spts-10",
  candidateCommit: candidate.commit,
  candidateTree: candidate.tree,
  role: "independent-verifier",
  actorId: "verifier",
  executionId: "verify-exec",
  workspaceId: "fresh-check",
  access: "read-only",
} satisfies DeliveryIdentityV2;
const delivery = {
  ...identity,
  role: "flow",
  access: "orchestrate",
  actorId: "flow",
  executionId: "flow-exec",
  workspaceId: "flow-work",
} satisfies DeliveryIdentityV2;
const controller = {
  ...identity,
  role: "controller",
  access: "controller",
  actorId: "controller",
  executionId: "controller-exec",
  workspaceId: "controller-work",
} satisfies DeliveryIdentityV2;
const currentIdentity = { delivery, controller };
const trustedVerifier = {
  currentIdentity,
  identity,
  candidate,
  controllerRevision: 3,
  observedAt: "2026-08-29T01:00:00.000Z",
  freshThroughEventId: "verify-boundary",
  evidenceIds: ["spec-check", "quality-check"],
};
const make = (axis: "specification" | "quality") => ({
  axis,
  verdict: "APPROVE" as const,
  currentIdentity,
  identity,
  candidate,
  controllerRevision: 3,
  observedAt: trustedVerifier.observedAt,
  freshThroughEventId: trustedVerifier.freshThroughEventId,
  evidenceIds: [axis === "specification" ? "spec-check" : "quality-check"],
});
const verdicts = {
  specification: make("specification"),
  quality: make("quality"),
};
const ci = {
  currentIdentity,
  projectId: "SPTS",
  taskId: "SPTS-10",
  repositoryId: "repo",
  runId: "run",
  pullRequest: 10,
  baseBranch: "main",
  headBranch: "feature/spts-10",
  candidate,
  workflowId: "quality",
  checkId: "quality",
  ciRunId: "ci-run",
  attempt: 1,
  conclusion: "success" as const,
  observedAt: "2026-08-29T01:10:00.000Z",
  freshThroughEventId: "ci-boundary",
  requiredCheckPolicyDigest: "e".repeat(64),
  fresh: true,
};
describe("v2 verifier and CI boundaries", () => {
  it("accepts complete separately trusted verifier provenance", () =>
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, trustedVerifier).valid,
    ).toBe(true));
  it("rejects split identity and candidate provenance", () =>
    expect(
      validateDeliveryVerifierVerdictsV2(
        {
          ...verdicts,
          quality: {
            ...verdicts.quality,
            identity: { ...identity, workspaceId: "other" },
          },
        },
        trustedVerifier,
      ).valid,
    ).toBe(false));
  it("requires exact trusted CI provenance", () => {
    expect(validateDeliveryCiEvidenceV2(ci, { ...ci }).valid).toBe(true);
    expect(
      validateDeliveryCiEvidenceV2({ ...ci, attempt: 2 }, { ...ci }).valid,
    ).toBe(false);
  });
  it("publishes only with both trusted boundaries", () => {
    expect(
      evaluateDeliveryPublicationV2(verdicts, trustedVerifier, ci, { ...ci }),
    ).toEqual({ allowed: true, code: "accepted" });
    expect(
      evaluateDeliveryPublicationV2(
        {
          ...verdicts,
          quality: { ...verdicts.quality, verdict: "REQUEST_CHANGES" },
        },
        trustedVerifier,
        ci,
        { ...ci },
      ).allowed,
    ).toBe(false);
  });
});

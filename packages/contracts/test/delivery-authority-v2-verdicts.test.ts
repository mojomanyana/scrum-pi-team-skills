import { describe, expect, it } from "vitest";
import {
  evaluateDeliveryPublicationV2,
  validateDeliveryCiEvidenceV2,
  validateDeliveryVerifierVerdictsV2,
  type DeliveryIdentityV2,
} from "../src/index.js";
const candidate = { commit: "a".repeat(40), tree: "b".repeat(40) };
const verifier = {
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
const verdicts = {
  specification: {
    verdict: "APPROVE",
    candidate,
    ...verifier,
    evidenceIds: ["spec-check"],
    controllerRevision: 3,
    fresh: true,
  },
  quality: {
    verdict: "APPROVE",
    candidate,
    ...verifier,
    evidenceIds: ["quality-check"],
    controllerRevision: 3,
    fresh: true,
  },
} as const;
const ci = {
  repositoryId: "repo",
  pullRequest: 10,
  headBranch: "feature/spts-10",
  candidate,
  workflowId: "quality",
  checkId: "quality",
  runId: "run-10",
  attempt: 1,
  conclusion: "success",
  observedAt: "2026-08-29T01:00:00.000Z",
  fresh: true,
  requiredCheckPolicyDigest: "e".repeat(64),
};
describe("v2 verifier and CI boundaries", () => {
  it("accepts verifier-owned dual verdicts for one exact candidate", () =>
    expect(validateDeliveryVerifierVerdictsV2(verdicts, candidate).valid).toBe(
      true,
    ));
  it("rejects controller authorship, split candidates, stale evidence, and writable verifier", () => {
    expect(
      validateDeliveryVerifierVerdictsV2(
        {
          ...verdicts,
          quality: {
            ...verdicts.quality,
            candidate: { ...candidate, tree: "f".repeat(40) },
          },
        },
        candidate,
      ).valid,
    ).toBe(false);
    expect(
      validateDeliveryVerifierVerdictsV2(
        { ...verdicts, quality: { ...verdicts.quality, fresh: false } },
        candidate,
      ).valid,
    ).toBe(false);
    expect(
      validateDeliveryVerifierVerdictsV2(
        { ...verdicts, quality: { ...verdicts.quality, role: "controller" } },
        candidate,
      ).valid,
    ).toBe(false);
    expect(
      validateDeliveryVerifierVerdictsV2(
        { ...verdicts, quality: { ...verdicts.quality, access: "read-write" } },
        candidate,
      ).valid,
    ).toBe(false);
  });
  it("binds minimal trusted CI identity and required-check policy", () => {
    expect(
      validateDeliveryCiEvidenceV2(ci, {
        repositoryId: "repo",
        pullRequest: 10,
        headBranch: "feature/spts-10",
        candidate,
        requiredCheckPolicyDigest: "e".repeat(64),
      }).valid,
    ).toBe(true);
    expect(
      validateDeliveryCiEvidenceV2(
        { ...ci, attempt: 0 },
        {
          repositoryId: "repo",
          pullRequest: 10,
          headBranch: "feature/spts-10",
          candidate,
          requiredCheckPolicyDigest: "e".repeat(64),
        },
      ).valid,
    ).toBe(false);
  });
  it("requires both fresh approvals and exact CI success", () => {
    expect(evaluateDeliveryPublicationV2(verdicts, ci, candidate)).toEqual({
      allowed: true,
      code: "accepted",
    });
    expect(
      evaluateDeliveryPublicationV2(
        {
          ...verdicts,
          quality: { ...verdicts.quality, verdict: "REQUEST_CHANGES" },
        },
        ci,
        candidate,
      ).allowed,
    ).toBe(false);
  });
});

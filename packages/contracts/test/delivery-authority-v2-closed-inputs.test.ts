import { describe, expect, it } from "vitest";
import {
  evaluateDeliveryEffectV2,
  evaluateDeliveryRecoveryV2,
  evaluateDeliveryTransitionV2,
  validateDeliveryAuthorityContractV2,
  validateDeliveryCiEvidenceV2,
  validateDeliveryVerifierVerdictsV2,
  type DeliveryIdentityV2,
} from "../src/index.js";
import { identity, v2 } from "./delivery-authority-v2.test.js";
const controller = {
  ...identity,
  role: "controller",
  access: "controller",
  actorId: "controller",
  executionId: "controller-exec",
  workspaceId: "controller-work",
} satisfies DeliveryIdentityV2;
const current = { delivery: identity, controller };
const trusted = {
  authorityDigest: v2.authorityDigest,
  meteringDigest: v2.meteringDigest,
  controllerStateDigest: v2.controllerStateDigest,
  identity,
};
const baseEffect = {
  kind: "prepare-branch-worktree",
  identity,
  idempotencyKey: "effect",
  requestDigest: "a".repeat(64),
  preconditionDigest: "b".repeat(64),
  postconditionDigest: "c".repeat(64),
  remainingBudget: 1,
};
const candidate = {
  commit: identity.candidateCommit,
  tree: identity.candidateTree,
};
const verifier = {
  ...identity,
  role: "independent-verifier",
  access: "read-only",
  actorId: "verifier",
  executionId: "verify",
  workspaceId: "verify-work",
} satisfies DeliveryIdentityV2;
const trustedVerifier = {
  currentIdentity: current,
  identity: verifier,
  candidate,
  controllerRevision: 3,
  observedAt: "2026-08-29T01:00:00.000Z",
  freshThroughEventId: "verify-event",
  evidenceIds: ["spec", "quality"],
};
const verdict = (axis: "specification" | "quality") => ({
  axis,
  verdict: "APPROVE",
  currentIdentity: current,
  identity: verifier,
  candidate,
  controllerRevision: 3,
  observedAt: trustedVerifier.observedAt,
  freshThroughEventId: "verify-event",
  evidenceIds: [axis === "specification" ? "spec" : "quality"],
});
const verdicts = {
  specification: verdict("specification"),
  quality: verdict("quality"),
};
const ci = {
  currentIdentity: current,
  projectId: identity.projectId,
  taskId: identity.taskId,
  repositoryId: identity.repositoryId,
  runId: identity.runId,
  pullRequest: 7,
  baseBranch: identity.baseBranch,
  headBranch: identity.headBranch,
  candidate,
  workflowId: "quality",
  checkId: "quality",
  ciRunId: "ci-run",
  attempt: 1,
  conclusion: "success",
  observedAt: "2026-08-29T01:10:00.000Z",
  freshThroughEventId: "ci-event",
  requiredCheckPolicyDigest: "e".repeat(64),
  fresh: true,
};
describe("closed decision boundaries", () => {
  it("rejects incomplete transition/effect requests and invalid role/access", () => {
    expect(
      evaluateDeliveryTransitionV2(
        v2,
        { from: "ready", to: "implementation", identity },
        trusted,
      ).accepted,
    ).toBe(false);
    for (const key of [
      "idempotencyKey",
      "requestDigest",
      "preconditionDigest",
      "postconditionDigest",
    ]) {
      const request = { ...baseEffect } as Record<string, unknown>;
      delete request[key];
      expect(evaluateDeliveryEffectV2(v2, request, trusted, []).allowed).toBe(
        false,
      );
    }
    expect(
      validateDeliveryAuthorityContractV2({
        ...v2,
        identity: {
          ...identity,
          role: "principal-developer",
          access: "orchestrate",
        },
      }).valid,
    ).toBe(false);
  });
  it("rejects transparent proxies, symbol authority, and malformed SHA candidates", () => {
    expect(
      evaluateDeliveryEffectV2(v2, new Proxy(baseEffect, {}), trusted, [])
        .allowed,
    ).toBe(false);
    expect(
      evaluateDeliveryEffectV2(
        v2,
        { ...baseEffect, [Symbol("grant")]: true },
        trusted,
        [],
      ).allowed,
    ).toBe(false);
    expect(
      validateDeliveryAuthorityContractV2({
        ...v2,
        identity: { ...identity, candidateTree: "bad" },
      }).valid,
    ).toBe(false);
  });
  it("requires an exact trusted unexpired single-use merge grant and method", () => {
    const stakeholder = {
      ...identity,
      role: "stakeholder",
      access: "authorize-merge",
      actorId: "stakeholder",
      executionId: "stakeholder-exec",
      workspaceId: "stakeholder-work",
    } satisfies DeliveryIdentityV2;
    const contract = { ...v2, state: "merge-gate", identity: stakeholder };
    const request = {
      ...baseEffect,
      kind: "merge",
      identity: stakeholder,
      repositoryId: identity.repositoryId,
      pullRequest: 7,
      headBranch: identity.headBranch,
      candidateCommit: identity.candidateCommit,
      candidateTree: identity.candidateTree,
      mergeMethod: "squash",
      observedAt: "2026-08-29T01:00:00.000Z",
    };
    const grant = {
      grantId: "merge-grant",
      repositoryId: identity.repositoryId,
      pullRequest: 7,
      headBranch: identity.headBranch,
      candidateCommit: identity.candidateCommit,
      candidateTree: identity.candidateTree,
      mergeMethod: "squash",
      stakeholderIdentity: stakeholder,
      notBefore: "2026-08-29T00:00:00.000Z",
      expiresAt: "2026-08-29T02:00:00.000Z",
      consumed: false,
    };
    const mergeTrusted = {
      ...trusted,
      identity: stakeholder,
      trustedNow: "2026-08-29T01:00:00.000Z",
      mergeGrant: grant,
    };
    expect(
      evaluateDeliveryEffectV2(
        contract,
        request,
        { ...trusted, identity: stakeholder },
        [],
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDeliveryEffectV2(contract, request, mergeTrusted, []),
    ).toMatchObject({ allowed: true, code: "accepted" });
    expect(
      evaluateDeliveryEffectV2(
        contract,
        { ...request, mergeMethod: "merge" },
        mergeTrusted,
        [],
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDeliveryEffectV2(
        contract,
        request,
        { ...mergeTrusted, mergeGrant: { ...grant, consumed: true } },
        [],
      ).allowed,
    ).toBe(false);
  });
  it("recovers from blocked only through exact authenticated suspended boundary", () => {
    const request = {
      kind: "disappeared-verifier",
      identity: controller,
      idempotencyKey: "recover",
      boundaryId: "blocked-boundary",
      boundaryConsumed: false,
      identityRevalidated: true,
      immutableIdentity: identity,
      worktreeClean: true,
      evidenceIds: [
        "authoritative-absence",
        "exact-candidate",
        "isolated-verifier-workspace",
      ],
      staleEvidenceIds: [],
      remainingAttempts: 1,
      requestedResumeState: "independent-verification",
    };
    const boundary = {
      boundaryId: request.boundaryId,
      idempotencyKey: request.idempotencyKey,
      kind: request.kind,
      suspendedState: "independent-verification",
      candidate,
      controllerRevision: 9,
      consumed: false,
      identity,
      controllerIdentity: controller,
    };
    const recoveryTrusted = {
      ...trusted,
      recoveryBoundary: boundary,
      currentCandidate: candidate,
      controllerRevision: 9,
    };
    expect(
      evaluateDeliveryRecoveryV2(
        { ...v2, state: "blocked" },
        request,
        recoveryTrusted,
      ),
    ).toMatchObject({
      allowed: true,
      resumeState: "independent-verification",
      boundaryConsumed: true,
    });
    for (const changed of [
      { ...boundary, consumed: true },
      { ...boundary, kind: "disappeared-flow" },
      { ...boundary, candidate: { ...candidate, tree: "f".repeat(40) } },
    ])
      expect(
        evaluateDeliveryRecoveryV2({ ...v2, state: "blocked" }, request, {
          ...recoveryTrusted,
          recoveryBoundary: changed,
        }).allowed,
      ).toBe(false);
  });
  it("binds verdict and CI to separately trusted complete current identity", () => {
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, trustedVerifier).valid,
    ).toBe(true);
    expect(
      validateDeliveryVerifierVerdictsV2(
        {
          ...verdicts,
          quality: {
            ...verdicts.quality,
            currentIdentity: {
              ...current,
              delivery: { ...identity, runId: "other" },
            },
          },
        },
        trustedVerifier,
      ).valid,
    ).toBe(false);
    expect(validateDeliveryCiEvidenceV2(ci, { ...ci }).valid).toBe(true);
    expect(
      validateDeliveryCiEvidenceV2(
        {
          ...ci,
          currentIdentity: {
            ...current,
            delivery: { ...identity, taskId: "other" },
          },
        },
        { ...ci },
      ).valid,
    ).toBe(false);
  });
  it("validates all history before lookup", () => {
    for (const history of [
      [null],
      [{ idempotencyKey: "effect" }],
      [
        {
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "accepted",
          postcondition: "applied",
          extra: true,
        },
      ],
    ])
      expect(
        evaluateDeliveryEffectV2(v2, baseEffect, trusted, history).allowed,
      ).toBe(false);
    expect(() =>
      evaluateDeliveryEffectV2(v2, baseEffect, trusted, [
        new Proxy(
          {},
          {
            get() {
              throw new Error("raw attacker");
            },
          },
        ),
      ]),
    ).not.toThrow();
  });
  it("allows only cleanup while cancelling", () => {
    const contract = { ...v2, state: "cancelling", cancelled: true };
    expect(
      evaluateDeliveryEffectV2(
        contract,
        { ...baseEffect, kind: "cleanup" },
        trusted,
        [],
      ),
    ).toMatchObject({ allowed: true, code: "accepted" });
    for (const kind of [
      "launch-principal",
      "launch-verifier",
      "push-feature",
      "poll-ci",
      "merge",
    ])
      expect(
        evaluateDeliveryEffectV2(contract, { ...baseEffect, kind }, trusted, [])
          .allowed,
      ).toBe(false);
  });
});

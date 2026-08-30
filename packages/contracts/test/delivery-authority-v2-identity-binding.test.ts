import { describe, expect, it } from "vitest";
import {
  evaluateDeliveryEffectV2,
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
const verifier = {
  ...identity,
  role: "independent-verifier",
  access: "read-only",
  actorId: "verifier",
  executionId: "verifier-exec",
  workspaceId: "verifier-work",
} satisfies DeliveryIdentityV2;
const currentIdentity = { delivery: identity, controller };
const candidate = {
  commit: identity.candidateCommit,
  tree: identity.candidateTree,
};
const trustedVerifier = {
  currentIdentity,
  identity: verifier,
  candidate,
  controllerRevision: 4,
  observedAt: "2026-08-29T01:00:00.000Z",
  freshThroughEventId: "verify",
  evidenceIds: ["spec", "quality"],
};
const item = (axis: "specification" | "quality") => ({
  axis,
  verdict: "APPROVE",
  currentIdentity,
  identity: verifier,
  candidate,
  controllerRevision: 4,
  observedAt: trustedVerifier.observedAt,
  freshThroughEventId: "verify",
  evidenceIds: [axis === "specification" ? "spec" : "quality"],
});
const verdicts = {
  specification: item("specification"),
  quality: item("quality"),
};
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
describe("delivery identity and history binding", () => {
  it("rejects unrelated controller and verifier immutable contexts", () => {
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, trustedVerifier).valid,
    ).toBe(true);
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, {
        ...trustedVerifier,
        currentIdentity: {
          ...currentIdentity,
          controller: { ...controller, taskId: "OTHER" },
        },
      }).valid,
    ).toBe(false);
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, {
        ...trustedVerifier,
        identity: { ...verifier, repositoryId: "other-repo" },
      }).valid,
    ).toBe(false);
  });
  it("binds merge request and grant independently to current delivery", () => {
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
      projectId: identity.projectId,
      taskId: identity.taskId,
      repositoryId: identity.repositoryId,
      runId: identity.runId,
      pullRequest: 7,
      headBranch: identity.headBranch,
      candidateCommit: identity.candidateCommit,
      candidateTree: identity.candidateTree,
      mergeMethod: "squash",
      observedAt: "2026-08-29T01:00:00.000Z",
    };
    const grant = {
      grantId: "grant",
      projectId: identity.projectId,
      taskId: identity.taskId,
      repositoryId: identity.repositoryId,
      runId: identity.runId,
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
    const mt = {
      ...trusted,
      identity: stakeholder,
      pullRequest: 7,
      trustedNow: "2026-08-29T01:00:00.000Z",
      mergeGrant: grant,
    };
    expect(evaluateDeliveryEffectV2(contract, request, mt, []).allowed).toBe(
      true,
    );
    for (const mergeMethod of ["octopus", "", 1, null])
      expect(
        evaluateDeliveryEffectV2(
          contract,
          { ...request, mergeMethod } as never,
          { ...mt, mergeGrant: { ...grant, mergeMethod } } as never,
          [],
        ),
      ).toMatchObject({ allowed: false, executable: false });
    for (const observedAt of [
      "not-a-time",
      1,
      "2026-08-28T23:59:59.999Z",
      "2026-08-29T02:00:00.000Z",
      "2026-08-29T02:00:00.001Z",
      "2026-08-29T01:00:00.001Z",
    ])
      expect(
        evaluateDeliveryEffectV2(
          contract,
          { ...request, observedAt } as never,
          mt,
          [],
        ),
      ).toMatchObject({ allowed: false, executable: false });
    expect(
      evaluateDeliveryEffectV2(
        contract,
        { ...request, observedAt: "2026-08-29T00:00:00.000Z" },
        mt,
        [],
      ).allowed,
    ).toBe(true);
    expect(
      evaluateDeliveryEffectV2(
        contract,
        { ...request, observedAt: "2026-08-29T01:59:59.999Z" },
        { ...mt, trustedNow: "2026-08-29T01:59:59.999Z" },
        [],
      ).allowed,
    ).toBe(true);
    for (const field of [
      "projectId",
      "taskId",
      "repositoryId",
      "runId",
      "headBranch",
      "candidateCommit",
      "candidateTree",
    ] as const) {
      const other =
        field.includes("Commit") || field.includes("Tree")
          ? "f".repeat(40)
          : "other";
      expect(
        evaluateDeliveryEffectV2(
          contract,
          { ...request, [field]: other },
          { ...mt, mergeGrant: { ...grant, [field]: other } },
          [],
        ).allowed,
        field,
      ).toBe(false);
    }
    expect(
      evaluateDeliveryEffectV2(
        contract,
        { ...request, pullRequest: 8 },
        { ...mt, mergeGrant: { ...grant, pullRequest: 8 } },
        [],
      ).allowed,
    ).toBe(false);
  });
  it.each([
    [
      [
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "accepted",
          postcondition: "applied",
        },
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "unknown",
          postcondition: "unknown",
        },
      ],
    ],
    [
      [
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "accepted",
          postcondition: "applied",
        },
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "rejected",
          postcondition: "not-applied",
        },
      ],
    ],
    [
      [
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "accepted",
          postcondition: "applied",
        },
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "b".repeat(64),
          outcome: "accepted",
          postcondition: "applied",
        },
      ],
    ],
  ])("rejects ambiguous duplicate history %#", (history) => {
    expect(
      evaluateDeliveryEffectV2(v2, baseEffect, trusted, history),
    ).toMatchObject({
      allowed: false,
      code: "history-ambiguous",
      executable: false,
    });
    expect(
      evaluateDeliveryEffectV2(v2, baseEffect, trusted, [...history].reverse())
        .code,
    ).toBe("history-ambiguous");
  });
  it("rejects malformed duplicate history before lookup", () =>
    expect(
      evaluateDeliveryEffectV2(v2, baseEffect, trusted, [
        {
          namespace: "effect",
          idempotencyKey: "effect",
          requestDigest: "a".repeat(64),
          outcome: "accepted",
          postcondition: "applied",
        },
        { namespace: "effect", idempotencyKey: "effect" },
      ]).code,
    ).toBe("history-invalid"));
});

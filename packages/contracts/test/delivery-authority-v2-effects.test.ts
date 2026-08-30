import { describe, expect, it } from "vitest";
import {
  DELIVERY_RECOVERY_KINDS_V2,
  DELIVERY_RECOVERY_EVIDENCE_V2,
  evaluateDeliveryEffectV2,
  evaluateDeliveryRecoveryV2,
  type DeliveryAuthorityV2State,
  type DeliveryIdentityV2,
} from "../src/index.js";
import { identity, v2 } from "./delivery-authority-v2.test.js";
const trusted = {
  authorityDigest: v2.authorityDigest,
  meteringDigest: v2.meteringDigest,
  controllerStateDigest: v2.controllerStateDigest,
  identity,
};
const effect = {
  kind: "prepare-branch-worktree",
  identity,
  idempotencyKey: "effect",
  requestDigest: "a".repeat(64),
  preconditionDigest: "b".repeat(64),
  postconditionDigest: "c".repeat(64),
  remainingBudget: 1,
};
const controller = {
  ...identity,
  role: "controller",
  access: "controller",
  actorId: "controller",
  executionId: "controller-exec",
  workspaceId: "controller-work",
} satisfies DeliveryIdentityV2;
const cases: Record<
  string,
  {
    state: DeliveryAuthorityV2State;
    resume: DeliveryAuthorityV2State;
    evidence: number;
  }
> = {
  "redundant-assurance-downgrade": {
    state: "ready",
    resume: "ready",
    evidence: 2,
  },
  "missing-keep-branch-choice": {
    state: "implementation",
    resume: "implementation",
    evidence: 3,
  },
  "repair-order-correction": {
    state: "repair-required",
    resume: "repair-required",
    evidence: 3,
  },
  "completed-repair-missing-receipt": {
    state: "repair-required",
    resume: "repair-required",
    evidence: 3,
  },
  "stale-evidence-regeneration": {
    state: "publication-authorized",
    resume: "independent-verification",
    evidence: 3,
  },
  "canonical-digest-retransmission": {
    state: "ready",
    resume: "ready",
    evidence: 3,
  },
  "disappeared-product": { state: "intake", resume: "intake", evidence: 2 },
  "disappeared-flow": { state: "ready", resume: "ready", evidence: 2 },
  "disappeared-principal": {
    state: "implementation",
    resume: "implementation",
    evidence: 3,
  },
  "disappeared-verifier": {
    state: "independent-verification",
    resume: "independent-verification",
    evidence: 3,
  },
  "already-completed-feature-push": {
    state: "publication-authorized",
    resume: "published",
    evidence: 2,
  },
  "already-created-or-updated-pr": {
    state: "published",
    resume: "ci-monitoring",
    evidence: 2,
  },
  "interrupted-ci-polling": {
    state: "ci-monitoring",
    resume: "ci-monitoring",
    evidence: 2,
  },
  "interrupted-paca-update": {
    state: "published",
    resume: "published",
    evidence: 2,
  },
  "cancellation-cleanup": {
    state: "cancelling",
    resume: "cancelled",
    evidence: 3,
  },
};
describe("v2 effects and recovery", () => {
  it("issues executable intent only for exact role/state", () =>
    expect(evaluateDeliveryEffectV2(v2, effect, trusted, [])).toMatchObject({
      allowed: true,
      code: "accepted",
      executable: true,
    }));
  it("makes replay non-executable and ambiguous outcomes reconcilable", () => {
    expect(
      evaluateDeliveryEffectV2(v2, effect, trusted, [
        {
          idempotencyKey: "effect",
          requestDigest: effect.requestDigest,
          outcome: "accepted",
          postcondition: "applied",
        },
      ]),
    ).toMatchObject({
      allowed: false,
      code: "idempotent-replay",
      executable: false,
    });
    expect(
      evaluateDeliveryEffectV2(v2, effect, trusted, [
        {
          idempotencyKey: "effect",
          requestDigest: effect.requestDigest,
          outcome: "unknown",
          postcondition: "unknown",
        },
      ]),
    ).toMatchObject({ allowed: false, code: "reconciliation-required" });
  });
  it.each(DELIVERY_RECOVERY_KINDS_V2)("enforces table row %s", (kind) => {
    const row = cases[kind]!;
    const contract = { ...v2, state: row.state };
    const request = {
      kind,
      suspendedState: row.state,
      identity: controller,
      idempotencyKey: `recovery-${kind}`,
      boundaryId: `boundary-${kind}`,
      boundaryConsumed: false,
      authenticatedBoundary: true,
      identityRevalidated: true,
      immutableIdentity: identity,
      worktreeClean: true,
      evidenceIds: [...DELIVERY_RECOVERY_EVIDENCE_V2[kind]!],
      staleEvidenceIds: [],
      remainingAttempts: 1,
      requestedResumeState: row.resume,
    };
    const recoveryTrusted = {
      ...trusted,
      recoveryBoundary: {
        boundaryId: request.boundaryId,
        idempotencyKey: request.idempotencyKey,
        kind: request.kind,
        suspendedState: request.suspendedState,
        consumed: false,
        identity: request.immutableIdentity,
      },
    };
    expect(
      evaluateDeliveryRecoveryV2(contract, request, recoveryTrusted),
    ).toMatchObject({
      allowed: true,
      code: "accepted",
      resumeState: row.resume,
    });
    expect(
      evaluateDeliveryRecoveryV2(
        contract,
        { ...request, boundaryConsumed: true },
        recoveryTrusted,
      ).allowed,
    ).toBe(false);
  });
  it("rejects dirty, drifted, skipped, or unknown recovery", () => {
    const request = {
      kind: "disappeared-verifier",
      suspendedState: "independent-verification",
      identity: controller,
      idempotencyKey: "r",
      boundaryId: "b",
      boundaryConsumed: false,
      authenticatedBoundary: true,
      identityRevalidated: true,
      immutableIdentity: identity,
      worktreeClean: true,
      evidenceIds: [...DELIVERY_RECOVERY_EVIDENCE_V2["disappeared-verifier"]!],
      staleEvidenceIds: [],
      remainingAttempts: 1,
      requestedResumeState: "independent-verification",
    };
    const recoveryTrusted = {
      ...trusted,
      recoveryBoundary: {
        boundaryId: request.boundaryId,
        idempotencyKey: request.idempotencyKey,
        kind: request.kind,
        suspendedState: request.suspendedState,
        consumed: false,
        identity: request.immutableIdentity,
      },
    };
    for (const r of [
      { ...request, worktreeClean: false },
      { ...request, identityRevalidated: false },
      { ...request, requestedResumeState: "published" },
      { ...request, kind: "remote-main-drift" },
    ])
      expect(
        evaluateDeliveryRecoveryV2(
          { ...v2, state: "independent-verification" },
          r,
          recoveryTrusted,
        ).allowed,
      ).toBe(false);
  });
});

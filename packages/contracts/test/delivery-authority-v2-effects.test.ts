import { describe, expect, it } from "vitest";
import {
  DELIVERY_RECOVERY_EVIDENCE_V2,
  DELIVERY_RECOVERY_KINDS_V2,
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
const controller = {
  ...identity,
  role: "controller",
  access: "controller",
  actorId: "controller",
  executionId: "controller-exec",
  workspaceId: "controller-work",
} satisfies DeliveryIdentityV2;
const candidate = {
  commit: identity.candidateCommit,
  tree: identity.candidateTree,
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
const rows: Record<
  string,
  { state: DeliveryAuthorityV2State; resume: DeliveryAuthorityV2State }
> = {
  "redundant-assurance-downgrade": { state: "ready", resume: "ready" },
  "missing-keep-branch-choice": {
    state: "implementation",
    resume: "implementation",
  },
  "repair-order-correction": {
    state: "repair-required",
    resume: "repair-required",
  },
  "completed-repair-missing-receipt": {
    state: "repair-required",
    resume: "repair-required",
  },
  "stale-evidence-regeneration": {
    state: "publication-authorized",
    resume: "independent-verification",
  },
  "canonical-digest-retransmission": { state: "ready", resume: "ready" },
  "disappeared-product": { state: "intake", resume: "intake" },
  "disappeared-flow": { state: "ready", resume: "ready" },
  "disappeared-principal": {
    state: "implementation",
    resume: "implementation",
  },
  "disappeared-verifier": {
    state: "independent-verification",
    resume: "independent-verification",
  },
  "already-completed-feature-push": {
    state: "publication-authorized",
    resume: "published",
  },
  "already-created-or-updated-pr": {
    state: "published",
    resume: "ci-monitoring",
  },
  "interrupted-ci-polling": { state: "ci-monitoring", resume: "ci-monitoring" },
  "interrupted-paca-update": { state: "published", resume: "published" },
  "cancellation-cleanup": { state: "cancelling", resume: "cancelled" },
};
describe("v2 effects and blocked recovery", () => {
  it("issues exact executable intent", () =>
    expect(evaluateDeliveryEffectV2(v2, effect, trusted, [])).toMatchObject({
      allowed: true,
      executable: true,
    }));
  it("makes replay non-executable and unknown outcomes reconcilable", () => {
    expect(
      evaluateDeliveryEffectV2(v2, effect, trusted, [
        {
          idempotencyKey: "effect",
          requestDigest: effect.requestDigest,
          outcome: "accepted",
          postcondition: "applied",
        },
      ]),
    ).toMatchObject({ allowed: false, code: "idempotent-replay" });
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
  it.each(DELIVERY_RECOVERY_KINDS_V2)("enforces blocked row %s", (kind) => {
    const row = rows[kind]!;
    const request = {
      kind,
      identity: controller,
      idempotencyKey: `recovery-${kind}`,
      boundaryId: `boundary-${kind}`,
      boundaryConsumed: false,
      identityRevalidated: true,
      immutableIdentity: identity,
      worktreeClean: true,
      evidenceIds: [...DELIVERY_RECOVERY_EVIDENCE_V2[kind]!],
      staleEvidenceIds: [],
      remainingAttempts: 1,
      requestedResumeState: row.resume,
    };
    const boundary = {
      boundaryId: request.boundaryId,
      idempotencyKey: request.idempotencyKey,
      kind,
      suspendedState: row.state,
      candidate,
      controllerRevision: 3,
      consumed: false,
      identity,
      controllerIdentity: controller,
    };
    const rt = {
      ...trusted,
      recoveryBoundary: boundary,
      currentCandidate: candidate,
      controllerRevision: 3,
    };
    expect(
      evaluateDeliveryRecoveryV2({ ...v2, state: "blocked" }, request, rt),
    ).toMatchObject({ allowed: true, resumeState: row.resume });
    expect(
      evaluateDeliveryRecoveryV2(
        { ...v2, state: "blocked" },
        { ...request, boundaryConsumed: true },
        rt,
      ).allowed,
    ).toBe(false);
  });
});

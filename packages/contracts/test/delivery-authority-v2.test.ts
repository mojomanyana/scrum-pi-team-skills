import { describe, expect, it } from "vitest";
import {
  validateDeliveryAuthorityContractByVersion,
  validateDeliveryAuthorityContractForExecution,
  validateDeliveryAuthorityContractV2,
  validateFrozenDeliveryAuthorityContractV2,
  evaluateDeliveryTransitionV2,
  type DeliveryIdentityV2,
} from "../src/index.js";

export const identity = {
  projectId: "SPTS",
  taskId: "SPTS-10",
  repositoryId: "repo",
  runId: "run",
  baseBranch: "main",
  baseCommit: "a".repeat(40),
  baseTree: "b".repeat(40),
  headBranch: "feature/spts-10",
  candidateCommit: "c".repeat(40),
  candidateTree: "d".repeat(40),
  role: "flow",
  actorId: "flow-1",
  executionId: "exec-1",
  workspaceId: "work-1",
  access: "orchestrate",
} satisfies DeliveryIdentityV2;
export const v2 = {
  contractId: "spts.delivery-authority",
  contractVersion: "2.0.0",
  authorityDigest: "a".repeat(64),
  meteringDigest: "b".repeat(64),
  controllerStateDigest: "c".repeat(64),
  identity,
  state: "ready",
  limits: {
    implementationAttempts: 2,
    verificationRepairCycles: 2,
    ciRepairCycles: 2,
    durationMinutes: 60,
    concurrentAgents: 2,
    worktrees: 3,
    evidenceBytes: 10000,
  },
  usage: {
    implementationAttempts: 0,
    verificationRepairCycles: 0,
    ciRepairCycles: 0,
    elapsedMinutes: 0,
    concurrentAgents: 0,
    worktrees: 0,
    evidenceBytes: 0,
  },
  cancelled: false,
};
const trusted = {
  authorityDigest: v2.authorityDigest,
  meteringDigest: v2.meteringDigest,
  controllerStateDigest: v2.controllerStateDigest,
  identity,
};

describe("delivery authority v2", () => {
  it("validates exact v2 and requires separate trusted inputs", () => {
    const validation = validateDeliveryAuthorityContractV2(v2);
    expect(validation.valid, JSON.stringify(validation)).toBe(true);
    expect(validateFrozenDeliveryAuthorityContractV2(v2, trusted).valid).toBe(
      true,
    );
    expect(
      validateFrozenDeliveryAuthorityContractV2(v2, {
        ...trusted,
        authorityDigest: "f".repeat(64),
      }).valid,
    ).toBe(false);
  });
  it("dispatches exact versions without upgrade or fallback", () => {
    expect(
      validateDeliveryAuthorityContractByVersion(
        v2,
        "spts.delivery-authority",
        "2.0.0",
      ).valid,
    ).toBe(true);
    expect(
      validateDeliveryAuthorityContractByVersion(
        { ...v2, contractVersion: "1.0.0" },
        "spts.delivery-authority",
        "2.0.0",
      ).valid,
    ).toBe(false);
    expect(
      validateDeliveryAuthorityContractForExecution(
        v2,
        "spts.delivery-authority",
        "9.0.0",
        trusted,
      ).valid,
    ).toBe(false);
  });
  it("rejects unknown fields, identity drift, limit bypass, and hostile input", () => {
    expect(
      validateDeliveryAuthorityContractV2({ ...v2, extra: true }).valid,
    ).toBe(false);
    expect(
      validateFrozenDeliveryAuthorityContractV2(v2, {
        ...trusted,
        identity: { ...identity, workspaceId: "other" },
      }).valid,
    ).toBe(false);
    expect(
      validateDeliveryAuthorityContractV2({
        ...v2,
        usage: { ...v2.usage, worktrees: 4 },
      }).valid,
    ).toBe(false);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(validateDeliveryAuthorityContractV2(cyclic).valid).toBe(false);
  });
  it("evaluates only exact normal transitions and meters attempts", () => {
    expect(
      evaluateDeliveryTransitionV2(
        v2,
        {
          from: "ready",
          to: "implementation",
          identity,
          idempotencyKey: "transition-1",
        },
        trusted,
      ),
    ).toMatchObject({
      accepted: true,
      code: "accepted",
      nextState: "implementation",
    });
    expect(
      evaluateDeliveryTransitionV2(
        v2,
        { from: "ready", to: "merge-gate", identity, idempotencyKey: "skip" },
        trusted,
      ),
    ).toMatchObject({ accepted: false, code: "transition-denied" });
    const exhausted = {
      ...v2,
      usage: { ...v2.usage, implementationAttempts: 2 },
    };
    expect(
      evaluateDeliveryTransitionV2(
        exhausted,
        {
          from: "ready",
          to: "implementation",
          identity,
          idempotencyKey: "limit",
        },
        { ...trusted },
      ),
    ).toMatchObject({ accepted: false, code: "autonomy-exhausted" });
  });
});

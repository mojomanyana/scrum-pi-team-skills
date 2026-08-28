import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import completeExample from "../examples/delivery-authority.complete.json" with { type: "json" };
import flowExample from "../examples/delivery-authority.role-flow.json" with { type: "json" };
import controllerBoundaries from "./fixtures/invalid/delivery-authority-controller-state-boundaries.json" with { type: "json" };
import {
  authorizeDeliveryEffect,
  canonicalSerializeLifecycleValue,
  computeDeliveryAuthorityDigest,
  computeDeliveryControllerStateDigest,
  computeDeliveryDecisionChainDigest,
  computeDeliveryDecisionCheckpointDigest,
  computeDeliveryDecisionContextDigest,
  computeDeliveryDecisionResultDigest,
  computeDeliveryEvidenceDigest,
  computeDeliveryMeteringDigest,
  evaluateAdministrativeRecovery,
  evaluateDeliveryTransition,
  validateDeliveryAuthorityContract,
  validateFrozenDeliveryAuthorityContract,
  type DeliveryAuthorityContract,
  type DeliveryDecisionContext,
  type DeliveryEffect,
  type DeliveryEvidence,
  type DeliveryTransitionAuditRecord,
  type DistinctGrantEffect,
} from "../src/index.js";

function clone(): DeliveryAuthorityContract {
  return structuredClone(completeExample) as DeliveryAuthorityContract;
}

function digest(value: unknown): string {
  return createHash("sha256")
    .update(canonicalSerializeLifecycleValue(value))
    .digest("hex");
}

function decisionContext(
  contract: DeliveryAuthorityContract,
): DeliveryDecisionContext {
  return structuredClone({
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    controllerStateDigest: contract.controllerStateDigest,
    authorityDigest: contract.authorityDigest,
    meteringDigest: contract.meteringDigest,
    meteringObservedAt: contract.meteringObservedAt,
    activeRole: contract.activeRole,
    governance: contract.governance,
    task: contract.task,
    roles: contract.roles,
    workflowCheckpoint: contract.workflow.checkpoint,
    workflowState: contract.workflow.state,
    activeRepairBudget: contract.workflow.checkpoint.activeRepairBudget,
    observations: contract.workflow.observations,
    candidate: contract.workflow.candidate,
    evidence: contract.evidence,
    autonomy: contract.autonomy,
    effectGrants: contract.effectGrants,
    requestedEffects: contract.requestedEffects,
    activeEscalations: contract.activeEscalations,
  });
}

function refreshEvidence(contract: DeliveryAuthorityContract): void {
  for (const evidence of contract.evidence)
    evidence.evidenceDigest = computeDeliveryEvidenceDigest(evidence);
  contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
    canonicalSerializeLifecycleValue(contract.evidence),
    "utf8",
  );
}

function rehash(contract: DeliveryAuthorityContract): void {
  refreshEvidence(contract);
  contract.authorityDigest = computeDeliveryAuthorityDigest(contract);
  contract.meteringDigest = computeDeliveryMeteringDigest(contract);
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
}

function resetAtState(
  contract: DeliveryAuthorityContract,
  state: DeliveryAuthorityContract["workflow"]["state"],
  activeRole: DeliveryAuthorityContract["activeRole"],
): void {
  contract.activeRole = activeRole;
  contract.workflow.audit = [];
  contract.effectAudit = [];
  contract.administrativeRecoveries = [];
  contract.workflow.state = state;
  contract.workflow.checkpoint.state = state;
  contract.workflow.checkpoint.candidateTree = contract.workflow.candidate.tree;
  contract.workflow.checkpoint.activeRepairBudget = "implementation";
  contract.workflow.checkpoint.attemptUsage = {
    implementationAttempts: contract.autonomy.usage.implementationAttempts,
    verificationRepairAttempts:
      contract.autonomy.usage.verificationRepairAttempts,
    ciRepairAttempts: contract.autonomy.usage.ciRepairAttempts,
  };
  contract.workflow.checkpoint.decisionSequence = 0;
  contract.workflow.checkpoint.decisionChainDigest = "0".repeat(64);
  contract.workflow.checkpoint.decisionChainDigest =
    computeDeliveryDecisionCheckpointDigest(contract);
  contract.workflow.decisionChain = {
    sequence: 0,
    digest: contract.workflow.checkpoint.decisionChainDigest,
  };
  contract.evidence[0]!.freshThroughEventId =
    contract.workflow.checkpoint.checkpointId;
  rehash(contract);
}

function advanceMetering(contract: DeliveryAuthorityContract): void {
  contract.meteringObservedAt = new Date(
    Date.parse(contract.meteringObservedAt) + 1,
  ).toISOString();
  contract.meteringDigest = computeDeliveryMeteringDigest(contract);
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
}

function flowIdentity(contract: DeliveryAuthorityContract) {
  const flow = contract.roles.flow;
  return {
    actorRole: "flow" as const,
    actorId: flow.actorId,
    executionId: flow.executionId,
    workspaceId: flow.workspaceId,
  };
}

function appendFlowTransition(
  contract: DeliveryAuthorityContract,
  to: DeliveryAuthorityContract["workflow"]["state"],
  eventId: string,
) {
  advanceMetering(contract);
  const from = contract.workflow.state;
  const decision = evaluateDeliveryTransition(
    contract,
    {
      eventId,
      idempotencyKey: eventId,
      from,
      to,
      ...flowIdentity(contract),
      candidateTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    },
    contract.authorityDigest,
    contract.meteringDigest,
    contract.controllerStateDigest,
  );
  expect(decision).toMatchObject({ accepted: true, code: "accepted" });
  contract.workflow.audit.push(decision.audit);
  contract.workflow.state = decision.nextState;
  contract.workflow.decisionChain = {
    sequence: decision.audit.authentication!.sequence,
    digest: decision.audit.authentication!.resultingChainDigest,
  };
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
  return decision.audit;
}

function addEffectGrant(
  contract: DeliveryAuthorityContract,
  effect: DistinctGrantEffect,
): void {
  if (!contract.requestedEffects.includes(effect))
    contract.requestedEffects.push(effect);
  if (!contract.effectGrants.some((grant) => grant.effect === effect))
    contract.effectGrants.push({
      effect,
      grantId: `controller-state-matrix-${effect}`,
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: `controller-state-matrix-${effect}-grant`,
    });
  rehash(contract);
}

function passingCiEvidence(contract: DeliveryAuthorityContract): void {
  const evidence = structuredClone(contract.evidence[0]!) as DeliveryEvidence;
  evidence.evidenceId = "controller-state-matrix-ci";
  evidence.assurance.phase = "ci";
  evidence.verification = {
    verdict: null,
    reviewedTree: null,
    approvalId: null,
  };
  evidence.ci = {
    runId: "controller-state-matrix-ci-run",
    checkId: "controller-state-matrix-ci-check",
    verdict: "PASS",
  };
  evidence.freshThroughEventId = contract.workflow.checkpoint.checkpointId;
  evidence.correlationId = "controller-state-matrix-ci-correlation";
  evidence.idempotencyKey = "controller-state-matrix-ci";
  evidence.pacaUpdateId = "controller-state-matrix-ci-paca";
  contract.evidence.push(evidence);
  contract.workflow.observations.ci = "passed";
  rehash(contract);
}

function mergeGateContract(): DeliveryAuthorityContract {
  const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
  resetAtState(contract, "pr-ci-monitoring", "flow");
  passingCiEvidence(contract);
  addEffectGrant(contract, "merge");
  appendFlowTransition(
    contract,
    "merge-gate",
    "controller-state-matrix-merge-gate",
  );
  return contract;
}

function completedContract(): DeliveryAuthorityContract {
  const contract = mergeGateContract();
  advanceMetering(contract);
  const gate = contract.workflow.audit.at(-1)!;
  contract.workflow.observations.merge = {
    status: "merged",
    targetTree: contract.workflow.candidate.tree,
    pullRequestNumber: contract.workflow.candidate.pullRequest.number,
    mergeCommit: "a".repeat(40),
    observedAt: contract.meteringObservedAt,
    receiptId: "controller-state-matrix-merge-receipt",
    freshThroughEventId: gate.eventId,
  };
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
  appendFlowTransition(
    contract,
    "completed",
    "controller-state-matrix-completed",
  );
  return contract;
}

describe("trusted delivery controller state", () => {
  it("declares the complete adversarial controller-state fixture matrix", () => {
    expect(
      new Set(controllerBoundaries.map((fixture) => fixture.operation)),
    ).toEqual(
      new Set([
        "attacker-recomputed-controller-state",
        "forged-approval-tree",
        "truncated-exhausted-attempt-trace",
        "reordered-decision-chain",
        "historical-push-before-approval",
        "publication-safety-gate-bypass",
        "future-merge-completion",
        "recovery-without-prior-effect",
        "recovery-rejected-or-wrong-tree",
        "protected-effect-during-intake",
        "exact-retry-after-role-handoff",
        "idempotency-key-changed-request",
      ]),
    );
  });
  it("keeps static authority stable while active controller role evolves", () => {
    const contract = clone();
    const authorityDigest = contract.authorityDigest;
    const controllerStateDigest = contract.controllerStateDigest;

    contract.activeRole = "flow";
    expect(computeDeliveryAuthorityDigest(contract)).toBe(authorityDigest);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    expect(contract.controllerStateDigest).not.toBe(controllerStateDigest);
  });

  it("rejects attacker-recomputed mutable state under the prior external anchor", () => {
    const contract = clone();
    const trustedControllerStateDigest = contract.controllerStateDigest;

    contract.workflow.observations.ci = "pending";
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
    expect(
      validateFrozenDeliveryAuthorityContract(
        contract,
        contract.authorityDigest,
        contract.meteringDigest,
        trustedControllerStateDigest,
      ),
    ).toMatchObject({
      valid: false,
      errors: [expect.objectContaining({ code: "frozen-controller-state" })],
    });
    expect(
      validateFrozenDeliveryAuthorityContract(
        contract,
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ).valid,
    ).toBe(true);
  });

  it("rejects a forged approval and tree with unchanged static and metering anchors", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    contract.meteringObservedAt = "2026-08-25T23:00:00.010Z";
    contract.meteringDigest = computeDeliveryMeteringDigest(contract);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    const trustedAuthorityDigest = contract.authorityDigest;
    const trustedMeteringDigest = contract.meteringDigest;
    const trustedControllerStateDigest = contract.controllerStateDigest;
    const forgedTree = "b".repeat(40);
    const forgedCommit = "a".repeat(40);

    contract.meteringObservedAt = "2026-08-25T23:00:00.004Z";
    contract.meteringDigest = computeDeliveryMeteringDigest(contract);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    const rejected = evaluateDeliveryTransition(
      contract,
      {
        eventId: "controller-state-forged-tree-observation",
        idempotencyKey: "controller-state-forged-tree-observation",
        from: "publication-authorized",
        to: "blocked",
        ...flowIdentity(contract),
        candidateTree: forgedTree,
        observedAt: contract.meteringObservedAt,
      },
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(rejected).toMatchObject({ accepted: false, code: "identity-drift" });
    contract.workflow.audit.push(rejected.audit);
    contract.workflow.decisionChain = {
      sequence: rejected.audit.authentication!.sequence,
      digest: rejected.audit.authentication!.resultingChainDigest,
    };

    contract.workflow.candidate.headCommit = forgedCommit;
    contract.workflow.candidate.tree = forgedTree;
    contract.workflow.candidate.pullRequest.expectedHeadCommit = forgedCommit;
    contract.workflow.candidate.pullRequest.observedHeadCommit = forgedCommit;
    contract.workflow.candidate.verification = {
      verdict: "APPROVE",
      reviewedTree: forgedTree,
      approvalId: "controller-state-forged-approval",
      executionId: contract.roles["independent-verifier"].executionId,
      workspaceId: contract.roles["independent-verifier"].workspaceId,
      observedAt: "2026-08-25T23:00:00.004Z",
    };
    const forgedEvidence = structuredClone(contract.evidence[0]!);
    forgedEvidence.evidenceId = "controller-state-forged-approval-evidence";
    forgedEvidence.repository.commit = forgedCommit;
    forgedEvidence.repository.tree = forgedTree;
    forgedEvidence.verification = {
      verdict: "APPROVE",
      reviewedTree: forgedTree,
      approvalId: "controller-state-forged-approval",
    };
    forgedEvidence.pullRequest.headCommit = forgedCommit;
    forgedEvidence.observedAt = "2026-08-25T23:00:00.004Z";
    forgedEvidence.freshThroughEventId = rejected.audit.eventId;
    forgedEvidence.correlationId = "controller-state-forged-correlation";
    forgedEvidence.idempotencyKey = "controller-state-forged-evidence";
    forgedEvidence.pacaUpdateId = "controller-state-forged-paca";
    contract.evidence.push(forgedEvidence);
    refreshEvidence(contract);
    contract.meteringObservedAt = "2026-08-25T23:00:00.005Z";
    contract.meteringDigest = computeDeliveryMeteringDigest(contract);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    const request = {
      eventId: "controller-state-forged-tree-accepted",
      idempotencyKey: "controller-state-forged-tree-accepted",
      from: "publication-authorized" as const,
      to: "blocked" as const,
      ...flowIdentity(contract),
      candidateTree: forgedTree,
      observedAt: contract.meteringObservedAt,
    };
    const historicalContext = decisionContext(contract);
    const resultContext = structuredClone(historicalContext);
    resultContext.workflowState = "blocked";
    const forgedAudit: DeliveryTransitionAuditRecord = {
      authentication: {
        sequence: contract.workflow.decisionChain.sequence + 1,
        previousChainDigest: contract.workflow.decisionChain.digest,
        controllerStateDigest: contract.controllerStateDigest,
        historicalContext,
        historicalContextDigest:
          computeDeliveryDecisionContextDigest(historicalContext),
        resultingStateDigest:
          computeDeliveryDecisionResultDigest(resultContext),
        resultingChainDigest: "0".repeat(64),
      },
      ...request,
      requestDigest: digest(request),
      accepted: true,
      code: "accepted",
    };
    forgedAudit.authentication!.resultingChainDigest =
      computeDeliveryDecisionChainDigest("transition", forgedAudit);
    contract.workflow.audit.push(forgedAudit);
    contract.workflow.state = "blocked";
    contract.workflow.decisionChain = {
      sequence: forgedAudit.authentication!.sequence,
      digest: forgedAudit.authentication!.resultingChainDigest,
    };
    contract.meteringObservedAt = "2026-08-25T23:00:00.010Z";
    contract.meteringDigest = computeDeliveryMeteringDigest(contract);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    expect(contract.authorityDigest).toBe(trustedAuthorityDigest);
    expect(contract.meteringDigest).toBe(trustedMeteringDigest);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
    expect(
      validateFrozenDeliveryAuthorityContract(
        contract,
        trustedAuthorityDigest,
        trustedMeteringDigest,
        trustedControllerStateDigest,
      ),
    ).toMatchObject({
      valid: false,
      errors: [expect.objectContaining({ code: "frozen-controller-state" })],
    });
  });

  it("never treats the digest reported by the untrusted contract as an implicit anchor", () => {
    const contract = clone();

    expect(
      validateFrozenDeliveryAuthorityContract(
        contract,
        contract.authorityDigest,
        contract.meteringDigest,
        undefined,
      ),
    ).toMatchObject({
      valid: false,
      errors: [expect.objectContaining({ code: "frozen-controller-state" })],
    });
  });

  it("rejects a truncated trace even when the attacker recomputes every internal digest", () => {
    const contract = clone();
    const trustedControllerStateDigest = contract.controllerStateDigest;

    contract.workflow.audit = [];
    contract.workflow.state = contract.workflow.checkpoint.state;
    contract.workflow.decisionChain = {
      sequence: contract.workflow.checkpoint.decisionSequence,
      digest: contract.workflow.checkpoint.decisionChainDigest,
    };
    contract.evidence[0]!.freshThroughEventId =
      contract.workflow.checkpoint.checkpointId;
    refreshEvidence(contract);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
    expect(
      validateFrozenDeliveryAuthorityContract(
        contract,
        contract.authorityDigest,
        contract.meteringDigest,
        trustedControllerStateDigest,
      ),
    ).toMatchObject({
      valid: false,
      errors: [expect.objectContaining({ code: "frozen-controller-state" })],
    });
  });

  it("prevents an exhausted attempt from being restored by trace truncation", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    contract.autonomy.limits.implementationAttempts = 1;
    contract.autonomy.usage.implementationAttempts = 0;
    contract.autonomy.usage.verificationRepairAttempts = 0;
    contract.autonomy.usage.ciRepairAttempts = 0;
    resetAtState(contract, "ready", "flow");

    const apply = (
      to: DeliveryAuthorityContract["workflow"]["state"],
      eventId: string,
    ) => {
      advanceMetering(contract);
      const from = contract.workflow.state;
      const decision = evaluateDeliveryTransition(
        contract,
        {
          eventId,
          idempotencyKey: eventId,
          from,
          to,
          ...flowIdentity(contract),
          candidateTree: contract.workflow.candidate.tree,
          observedAt: contract.meteringObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      );
      expect(decision).toMatchObject({ accepted: true, code: "accepted" });
      contract.workflow.audit.push(decision.audit);
      contract.workflow.state = decision.nextState;
      if (from === "ready" && to === "implementation")
        contract.autonomy.usage.implementationAttempts += 1;
      contract.workflow.decisionChain = {
        sequence: decision.audit.authentication!.sequence,
        digest: decision.audit.authentication!.resultingChainDigest,
      };
      contract.controllerStateDigest =
        computeDeliveryControllerStateDigest(contract);
    };
    apply("implementation", "controller-state-spent-attempt");
    apply("blocked", "controller-state-spent-attempt-blocked");
    apply("ready", "controller-state-spent-attempt-ready");
    advanceMetering(contract);
    const request = {
      eventId: "controller-state-attempt-after-exhaustion",
      idempotencyKey: "controller-state-attempt-after-exhaustion",
      from: "ready" as const,
      to: "implementation" as const,
      ...flowIdentity(contract),
      candidateTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    };
    expect(
      evaluateDeliveryTransition(
        contract,
        request,
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ accepted: false, code: "autonomy-exhausted" });
    const trustedControllerStateDigest = contract.controllerStateDigest;

    const truncated = structuredClone(contract);
    truncated.workflow.audit = [];
    truncated.workflow.state = "ready";
    truncated.workflow.decisionChain = {
      sequence: truncated.workflow.checkpoint.decisionSequence,
      digest: truncated.workflow.checkpoint.decisionChainDigest,
    };
    truncated.autonomy.usage.implementationAttempts = 0;
    truncated.controllerStateDigest =
      computeDeliveryControllerStateDigest(truncated);
    expect(validateDeliveryAuthorityContract(truncated).valid).toBe(true);
    expect(
      validateFrozenDeliveryAuthorityContract(
        truncated,
        contract.authorityDigest,
        contract.meteringDigest,
        trustedControllerStateDigest,
      ),
    ).toMatchObject({
      valid: false,
      errors: [expect.objectContaining({ code: "frozen-controller-state" })],
    });
  });

  it("rejects reordered authenticated decisions before authorization", () => {
    const contract = clone();
    advanceMetering(contract);
    const principal = contract.roles["principal-developer"];
    const rejected = evaluateDeliveryTransition(
      contract,
      {
        eventId: "controller-chain-rejected-event",
        idempotencyKey: "controller-chain-rejected-event",
        from: contract.workflow.state,
        to: "completed",
        actorRole: "principal-developer",
        actorId: principal.actorId,
        executionId: principal.executionId,
        workspaceId: principal.workspaceId,
        candidateTree: contract.workflow.candidate.tree,
        observedAt: contract.meteringObservedAt,
      },
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(rejected).toMatchObject({
      accepted: false,
      code: "transition-denied",
    });
    expect(rejected.audit.authentication).not.toBeNull();
    contract.workflow.audit.push(rejected.audit);
    contract.workflow.decisionChain = {
      sequence: rejected.audit.authentication!.sequence,
      digest: rejected.audit.authentication!.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);

    contract.workflow.audit.reverse();
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    const reordered = validateDeliveryAuthorityContract(contract);
    expect(reordered.valid).toBe(false);
    if (!reordered.valid)
      expect(reordered.errors.map((error) => error.code)).toContain(
        "decision-order",
      );
  });

  it("rejects a future-dated merge receipt before completion", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    resetAtState(contract, "pr-ci-monitoring", "flow");
    contract.workflow.observations.ci = "passed";
    const ciEvidence = structuredClone(
      contract.evidence[0]!,
    ) as DeliveryEvidence;
    ciEvidence.evidenceId = "controller-state-future-merge-ci";
    ciEvidence.assurance.phase = "ci";
    ciEvidence.verification = {
      verdict: null,
      reviewedTree: null,
      approvalId: null,
    };
    ciEvidence.ci = {
      runId: "controller-state-future-merge-run",
      checkId: "controller-state-future-merge-check",
      verdict: "PASS",
    };
    ciEvidence.freshThroughEventId = contract.workflow.checkpoint.checkpointId;
    ciEvidence.correlationId = "controller-state-future-merge-correlation";
    ciEvidence.idempotencyKey = "controller-state-future-merge-ci";
    ciEvidence.pacaUpdateId = "controller-state-future-merge-paca";
    contract.evidence.push(ciEvidence);
    contract.effectGrants.push({
      effect: "merge",
      grantId: "controller-state-future-merge-grant",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "controller-state-future-merge-grant",
    });
    contract.requestedEffects = ["merge"];
    rehash(contract);
    advanceMetering(contract);
    const gate = evaluateDeliveryTransition(
      contract,
      {
        eventId: "controller-state-future-merge-gate",
        idempotencyKey: "controller-state-future-merge-gate",
        from: "pr-ci-monitoring",
        to: "merge-gate",
        ...flowIdentity(contract),
        candidateTree: contract.workflow.candidate.tree,
        observedAt: contract.meteringObservedAt,
      },
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(gate).toMatchObject({ accepted: true, code: "accepted" });
    contract.workflow.audit.push(gate.audit);
    contract.workflow.state = gate.nextState;
    contract.workflow.decisionChain = {
      sequence: gate.audit.authentication!.sequence,
      digest: gate.audit.authentication!.resultingChainDigest,
    };
    contract.workflow.observations.merge = {
      status: "merged",
      targetTree: contract.workflow.candidate.tree,
      pullRequestNumber: contract.workflow.candidate.pullRequest.number,
      mergeCommit: "a".repeat(40),
      observedAt: "2099-01-01T00:00:00.000Z",
      receiptId: "controller-state-future-merge-receipt",
      freshThroughEventId: gate.audit.eventId,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    const validation = validateDeliveryAuthorityContract(contract);
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      const codes = validation.errors.map((error) => error.code);
      expect(codes).toContain("metering-order");
      expect(codes).toContain("merge-observation");
    }
    expect(
      evaluateDeliveryTransition(
        contract,
        {
          eventId: "controller-state-complete-before-future-merge",
          idempotencyKey: "controller-state-complete-before-future-merge",
          from: "merge-gate",
          to: "completed",
          ...flowIdentity(contract),
          candidateTree: contract.workflow.candidate.tree,
          observedAt: contract.meteringObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ accepted: false, code: "contract-invalid" });
  });

  it("enforces the complete protected effect/state matrix", () => {
    const cases: Array<{
      effect: DeliveryEffect;
      grant: DistinctGrantEffect;
      state: "merge-gate" | "completed" | "blocked" | "ready";
    }> = [
      { effect: "merge", grant: "merge", state: "merge-gate" },
      { effect: "release", grant: "release", state: "completed" },
      { effect: "tag", grant: "release", state: "completed" },
      {
        effect: "artifact-publication",
        grant: "release",
        state: "completed",
      },
      { effect: "production", grant: "production", state: "completed" },
      {
        effect: "production-access",
        grant: "production",
        state: "completed",
      },
      { effect: "deployment", grant: "production", state: "completed" },
      {
        effect: "destructive-git",
        grant: "destructive-git",
        state: "blocked",
      },
      {
        effect: "force-push",
        grant: "destructive-git",
        state: "blocked",
      },
      {
        effect: "history-rewrite",
        grant: "destructive-git",
        state: "blocked",
      },
      {
        effect: "branch-delete",
        grant: "destructive-git",
        state: "blocked",
      },
      { effect: "real-pi", grant: "real-pi", state: "ready" },
      {
        effect: "real-pi-execution",
        grant: "real-pi",
        state: "ready",
      },
    ];
    for (const item of cases) {
      const allowed =
        item.state === "merge-gate"
          ? mergeGateContract()
          : item.state === "completed"
            ? completedContract()
            : (structuredClone(flowExample) as DeliveryAuthorityContract);
      if (item.state === "blocked" || item.state === "ready")
        resetAtState(allowed, item.state, "flow");
      addEffectGrant(allowed, item.grant);
      if (item.grant === "real-pi") {
        allowed.autonomy.usage.concurrentAgents =
          allowed.autonomy.limits.concurrentAgents - 1;
        rehash(allowed);
      }
      advanceMetering(allowed);
      expect(
        authorizeDeliveryEffect(
          allowed,
          {
            effect: item.effect,
            idempotencyKey: `controller-state-matrix-allow-${item.effect}`,
            ...flowIdentity(allowed),
            targetTree: allowed.workflow.candidate.tree,
            observedAt: allowed.meteringObservedAt,
          },
          allowed.authorityDigest,
          allowed.meteringDigest,
          allowed.controllerStateDigest,
        ),
        `${item.effect} should be allowed in ${item.state}`,
      ).toMatchObject({ allowed: true, code: "accepted" });

      const intake = structuredClone(flowExample) as DeliveryAuthorityContract;
      resetAtState(intake, "intake", "flow");
      addEffectGrant(intake, item.grant);
      if (item.grant === "real-pi") {
        intake.autonomy.usage.concurrentAgents =
          intake.autonomy.limits.concurrentAgents - 1;
        rehash(intake);
      }
      advanceMetering(intake);
      expect(
        authorizeDeliveryEffect(
          intake,
          {
            effect: item.effect,
            idempotencyKey: `controller-state-matrix-deny-${item.effect}`,
            ...flowIdentity(intake),
            targetTree: intake.workflow.candidate.tree,
            observedAt: intake.meteringObservedAt,
          },
          intake.authorityDigest,
          intake.meteringDigest,
          intake.controllerStateDigest,
        ),
        `${item.effect} should be denied during intake`,
      ).toMatchObject({ allowed: false, code: "effect-state-denied" });
    }

    const publication = structuredClone(
      flowExample,
    ) as DeliveryAuthorityContract;
    advanceMetering(publication);
    expect(
      authorizeDeliveryEffect(
        publication,
        {
          effect: "publication",
          idempotencyKey: "controller-state-matrix-publication-allowed",
          ...flowIdentity(publication),
          targetTree: publication.workflow.candidate.tree,
          observedAt: publication.meteringObservedAt,
        },
        publication.authorityDigest,
        publication.meteringDigest,
        publication.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: true, code: "accepted" });
    resetAtState(publication, "intake", "flow");
    advanceMetering(publication);
    expect(
      authorizeDeliveryEffect(
        publication,
        {
          effect: "publication",
          idempotencyKey: "controller-state-matrix-publication-intake",
          ...flowIdentity(publication),
          targetTree: publication.workflow.candidate.tree,
          observedAt: publication.meteringObservedAt,
        },
        publication.authorityDigest,
        publication.meteringDigest,
        publication.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "publication-denied" });
  });

  it("denies real-Pi authority at the concurrent-agent capacity", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    resetAtState(contract, "ready", "flow");
    addEffectGrant(contract, "real-pi");
    contract.autonomy.usage.concurrentAgents =
      contract.autonomy.limits.concurrentAgents;
    rehash(contract);
    advanceMetering(contract);
    expect(
      authorizeDeliveryEffect(
        contract,
        {
          effect: "real-pi-execution",
          idempotencyKey: "controller-state-real-pi-capacity",
          ...flowIdentity(contract),
          targetTree: contract.workflow.candidate.tree,
          observedAt: contract.meteringObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "escalation-required" });
  });

  it("denies release during intake despite a matching stakeholder grant", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    resetAtState(contract, "intake", "flow");
    contract.effectGrants.push({
      effect: "release",
      grantId: "controller-state-intake-release",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "controller-state-intake-release-grant",
    });
    contract.requestedEffects = ["release"];
    rehash(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);

    expect(
      authorizeDeliveryEffect(
        contract,
        {
          effect: "release",
          idempotencyKey: "controller-state-intake-release-effect",
          ...flowIdentity(contract),
          targetTree: contract.workflow.candidate.tree,
          observedAt: contract.meteringObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "effect-state-denied" });
  });

  it("applies duration, escalation, and cancellation gates to publication effects", () => {
    const expired = structuredClone(flowExample) as DeliveryAuthorityContract;
    expired.autonomy.usage.elapsedMinutes =
      expired.autonomy.limits.durationMinutes;
    rehash(expired);
    advanceMetering(expired);
    expect(
      authorizeDeliveryEffect(
        expired,
        {
          effect: "feature-push",
          idempotencyKey: "controller-state-expired-publication",
          ...flowIdentity(expired),
          targetTree: expired.workflow.candidate.tree,
          observedAt: expired.meteringObservedAt,
        },
        expired.authorityDigest,
        expired.meteringDigest,
        expired.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "escalation-required" });

    for (const mode of ["escalated", "cancelled"] as const) {
      const blocked = structuredClone(flowExample) as DeliveryAuthorityContract;
      resetAtState(blocked, "blocked", "flow");
      if (mode === "escalated") blocked.activeEscalations = ["identity-drift"];
      else blocked.autonomy.usage.cancelled = true;
      rehash(blocked);
      advanceMetering(blocked);
      expect(
        authorizeDeliveryEffect(
          blocked,
          {
            effect: "feature-push",
            idempotencyKey: `controller-state-${mode}-publication`,
            ...flowIdentity(blocked),
            targetTree: blocked.workflow.candidate.tree,
            observedAt: blocked.meteringObservedAt,
          },
          blocked.authorityDigest,
          blocked.meteringDigest,
          blocked.controllerStateDigest,
        ),
      ).toMatchObject({ allowed: false, code: "escalation-required" });
    }
  });

  it("rejects an authenticated historical push that precedes approval", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    advanceMetering(contract);
    const decision = authorizeDeliveryEffect(
      contract,
      {
        effect: "feature-push",
        idempotencyKey: "controller-state-preapproval-push",
        ...flowIdentity(contract),
        targetTree: contract.workflow.candidate.tree,
        observedAt: contract.meteringObservedAt,
      },
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(decision.allowed).toBe(true);
    const authentication = decision.audit.authentication!;
    const historical = authentication.historicalContext;
    const futureApproval = new Date(
      Date.parse(decision.audit.observedAt) + 1,
    ).toISOString();
    historical.candidate.verification.observedAt = futureApproval;
    historical.evidence[0]!.observedAt = futureApproval;
    historical.evidence[0]!.evidenceDigest = computeDeliveryEvidenceDigest(
      historical.evidence[0]!,
    );
    historical.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(historical.evidence),
      "utf8",
    );
    authentication.historicalContextDigest =
      computeDeliveryDecisionContextDigest(historical);
    authentication.resultingStateDigest =
      computeDeliveryDecisionResultDigest(historical);
    authentication.resultingChainDigest = computeDeliveryDecisionChainDigest(
      "effect",
      decision.audit,
    );
    contract.effectAudit.push(decision.audit);
    contract.workflow.decisionChain = {
      sequence: authentication.sequence,
      digest: authentication.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    const validation = validateDeliveryAuthorityContract(contract);
    expect(validation.valid).toBe(false);
    if (!validation.valid)
      expect(validation.errors.map((error) => error.code)).toContain(
        "historical-effect-authority",
      );
  });

  it("preserves Product authority for an explicitly safe blocked recovery", () => {
    const contract = clone();
    resetAtState(contract, "blocked", "product");
    advanceMetering(contract);
    const product = contract.roles.product;
    expect(
      evaluateAdministrativeRecovery(
        contract,
        {
          recoveryId: "controller-state-product-digest-refetch",
          kind: "canonical-digest-refetch",
          idempotencyKey: "controller-state-product-digest-refetch",
          actorRole: "product",
          actorId: product.actorId,
          executionId: product.executionId,
          workspaceId: product.workspaceId,
          identityRevalidated: true,
          targetGate: "administrative",
          details: {
            authorityDigest: contract.authorityDigest,
            meteringDigest: contract.meteringDigest,
            controllerStateDigest: contract.controllerStateDigest,
          },
          observedAt: contract.meteringObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: true, code: "accepted" });
  });

  it("denies publication reconciliation without an authenticated prior effect", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    resetAtState(contract, "blocked", "flow");
    advanceMetering(contract);
    expect(
      evaluateAdministrativeRecovery(
        contract,
        {
          recoveryId: "controller-state-reconcile-without-effect",
          kind: "idempotent-push-pr-reconciliation",
          idempotencyKey: "controller-state-reconcile-without-effect",
          ...flowIdentity(contract),
          identityRevalidated: true,
          targetGate: "administrative",
          details: {
            candidateTree: contract.workflow.candidate.tree,
            candidateCommit: contract.workflow.candidate.headCommit,
            pullRequestNumber: contract.workflow.candidate.pullRequest.number,
            priorEffectSequence: 999,
            originalIdempotencyKey: "missing-publication-effect",
            originalRequestDigest: "a".repeat(64),
            priorOutcome: "authorization-issued-outcome-unknown",
          },
          observedAt: contract.meteringObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "recovery-gate-denied" });
  });

  it("allows only exact authenticated publication reconciliation and rejects wrong-tree or rejected candidates", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    advanceMetering(contract);
    const effect = authorizeDeliveryEffect(
      contract,
      {
        effect: "feature-push",
        idempotencyKey: "controller-state-reconcile-prior-push",
        ...flowIdentity(contract),
        targetTree: contract.workflow.candidate.tree,
        observedAt: contract.meteringObservedAt,
      },
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(effect.allowed).toBe(true);
    contract.effectAudit.push(effect.audit);
    contract.workflow.decisionChain = {
      sequence: effect.audit.authentication!.sequence,
      digest: effect.audit.authentication!.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    advanceMetering(contract);
    const blocked = evaluateDeliveryTransition(
      contract,
      {
        eventId: "controller-state-reconcile-blocked",
        idempotencyKey: "controller-state-reconcile-blocked",
        from: "publication-authorized",
        to: "blocked",
        ...flowIdentity(contract),
        candidateTree: contract.workflow.candidate.tree,
        observedAt: contract.meteringObservedAt,
      },
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(blocked.accepted).toBe(true);
    contract.workflow.audit.push(blocked.audit);
    contract.workflow.state = blocked.nextState;
    contract.workflow.decisionChain = {
      sequence: blocked.audit.authentication!.sequence,
      digest: blocked.audit.authentication!.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    advanceMetering(contract);

    const details = {
      candidateTree: contract.workflow.candidate.tree,
      candidateCommit: contract.workflow.candidate.headCommit,
      pullRequestNumber: contract.workflow.candidate.pullRequest.number,
      priorEffectSequence: effect.audit.authentication!.sequence,
      originalIdempotencyKey: effect.audit.idempotencyKey,
      originalRequestDigest: effect.audit.requestDigest,
      priorOutcome: "authorization-issued-outcome-unknown" as const,
    };
    const request = {
      recoveryId: "controller-state-reconcile-exact",
      kind: "idempotent-push-pr-reconciliation" as const,
      idempotencyKey: "controller-state-reconcile-exact",
      ...flowIdentity(contract),
      identityRevalidated: true,
      targetGate: "administrative" as const,
      details,
      observedAt: contract.meteringObservedAt,
    };
    expect(
      evaluateAdministrativeRecovery(
        contract,
        request,
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: true, code: "accepted" });
    expect(
      evaluateAdministrativeRecovery(
        contract,
        {
          ...request,
          recoveryId: "controller-state-reconcile-wrong-tree",
          idempotencyKey: "controller-state-reconcile-wrong-tree",
          details: { ...details, candidateTree: "b".repeat(40) },
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "recovery-gate-denied" });

    const rejected = structuredClone(contract);
    rejected.workflow.candidate.verification.verdict = "REJECT";
    rejected.controllerStateDigest =
      computeDeliveryControllerStateDigest(rejected);
    expect(
      evaluateAdministrativeRecovery(
        rejected,
        {
          ...request,
          recoveryId: "controller-state-reconcile-rejected",
          idempotencyKey: "controller-state-reconcile-rejected",
        },
        rejected.authorityDigest,
        rejected.meteringDigest,
        rejected.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "recovery-gate-denied" });
  });

  it("returns an authenticated prior recovery after role handoff", () => {
    const contract = clone();
    resetAtState(contract, "blocked", "product");
    advanceMetering(contract);
    const product = contract.roles.product;
    const request = {
      recoveryId: "controller-state-product-retry",
      kind: "canonical-digest-refetch" as const,
      idempotencyKey: "controller-state-product-retry",
      actorRole: "product" as const,
      actorId: product.actorId,
      executionId: product.executionId,
      workspaceId: product.workspaceId,
      identityRevalidated: true,
      targetGate: "administrative" as const,
      details: {
        authorityDigest: contract.authorityDigest,
        meteringDigest: contract.meteringDigest,
        controllerStateDigest: contract.controllerStateDigest,
      },
      observedAt: contract.meteringObservedAt,
    };
    const first = evaluateAdministrativeRecovery(
      contract,
      request,
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(first).toMatchObject({ allowed: true, code: "accepted" });
    contract.administrativeRecoveries.push(first.audit);
    contract.workflow.decisionChain = {
      sequence: first.audit.authentication!.sequence,
      digest: first.audit.authentication!.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    contract.activeRole = "flow";
    rehash(contract);

    expect(
      evaluateAdministrativeRecovery(
        contract,
        request,
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({
      allowed: false,
      idempotent: true,
      code: "accepted",
      audit: { accepted: true },
    });
    expect(
      evaluateAdministrativeRecovery(
        contract,
        { ...request, recoveryId: "controller-state-product-retry-changed" },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({
      allowed: false,
      idempotent: false,
      code: "idempotency-conflict",
    });
  });

  it("returns an authenticated prior effect after role handoff and conflicts on changed input", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    advanceMetering(contract);
    const request = {
      effect: "feature-push" as const,
      idempotencyKey: "controller-state-role-handoff-push",
      ...flowIdentity(contract),
      targetTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    };
    const first = authorizeDeliveryEffect(
      contract,
      request,
      contract.authorityDigest,
      contract.meteringDigest,
      contract.controllerStateDigest,
    );
    expect(first).toMatchObject({ allowed: true, code: "accepted" });
    contract.effectAudit.push(first.audit);
    contract.workflow.decisionChain = {
      sequence: first.audit.authentication!.sequence,
      digest: first.audit.authentication!.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);

    contract.activeRole = "principal-developer";
    rehash(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
    expect(
      authorizeDeliveryEffect(
        contract,
        request,
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({
      allowed: false,
      idempotent: true,
      code: "accepted",
      audit: { allowed: true },
    });
    expect(
      authorizeDeliveryEffect(
        contract,
        { ...request, effect: "pr-create-update" },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({
      allowed: false,
      idempotent: false,
      code: "idempotency-conflict",
    });
  });
});

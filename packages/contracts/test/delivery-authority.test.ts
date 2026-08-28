import { createHash } from "node:crypto";

import { Ajv } from "ajv";
import { describe, expect, it } from "vitest";

import completeExample from "../examples/delivery-authority.complete.json" with { type: "json" };
import flowExample from "../examples/delivery-authority.role-flow.json" with { type: "json" };
import principalExample from "../examples/delivery-authority.role-principal-developer.json" with { type: "json" };
import productExample from "../examples/delivery-authority.role-product.json" with { type: "json" };
import verifierExample from "../examples/delivery-authority.role-verifier.json" with { type: "json" };
import schema from "../src/schemas/delivery-authority.schema.json" with { type: "json" };
import boundaryFixtures from "./fixtures/invalid/delivery-authority-boundaries.json" with { type: "json" };
import {
  ADMINISTRATIVE_RECOVERY_KINDS,
  AUTOMATIC_DELIVERY_ACTIONS,
  DELIVERY_AUTHORITY_CONTRACT_ID,
  DELIVERY_AUTHORITY_CONTRACT_VERSION,
  DELIVERY_ROLES,
  DISTINCT_GRANT_EFFECTS,
  HUMAN_GATED_DELIVERY_ACTIONS,
  MANDATORY_ESCALATION_REASONS,
  WORKFLOW_STATES,
  authorizeDeliveryEffect as authorizeDeliveryEffectWithAnchor,
  canonicalSerializeLifecycleValue,
  computeDeliveryAuthorityDigest,
  computeDeliveryControllerStateDigest,
  computeDeliveryDecisionCheckpointDigest,
  computeDeliveryEvidenceDigest,
  computeDeliveryMeteringDigest,
  evaluateAdministrativeRecovery as evaluateAdministrativeRecoveryWithAnchor,
  evaluateDeliveryTransition as evaluateDeliveryTransitionWithAnchor,
  validateDeliveryAuthorityContract,
  type AdministrativeRecoveryDetails,
  type DeliveryAuthorityContract,
  type DeliveryDecisionAuthentication,
  type DeliveryEvidence,
} from "../src/index.js";

const examples = [
  productExample,
  flowExample,
  principalExample,
  verifierExample,
  completeExample,
] as const;

function clone(): DeliveryAuthorityContract {
  return structuredClone(completeExample) as DeliveryAuthorityContract;
}

function nextDecisionTimestamp(contract: DeliveryAuthorityContract): string {
  const values = [
    contract.meteringObservedAt,
    contract.workflow.checkpoint.observedAt,
    contract.workflow.candidate.verification.observedAt,
    ...contract.workflow.audit.map((record) => record.observedAt),
    ...contract.effectAudit.map((record) => record.observedAt),
    ...contract.administrativeRecoveries.map((record) => record.observedAt),
    ...contract.evidence.map((record) => record.observedAt),
    ...(contract.workflow.observations.merge.observedAt === null
      ? []
      : [contract.workflow.observations.merge.observedAt]),
  ];
  const latest = values.reduce((current, value) =>
    value > current ? value : current,
  );
  return new Date(Date.parse(latest) + 1).toISOString();
}

function stampRequest(
  contract: DeliveryAuthorityContract,
  request: unknown,
): unknown {
  try {
    if (
      typeof request === "object" &&
      request !== null &&
      Object.getPrototypeOf(request) === Object.prototype &&
      !("observedAt" in request)
    ) {
      const observedAt = nextDecisionTimestamp(contract);
      contract.meteringObservedAt = observedAt;
      contract.meteringDigest = computeDeliveryMeteringDigest(contract);
      contract.controllerStateDigest =
        computeDeliveryControllerStateDigest(contract);
      return Object.assign(request, { observedAt });
    }
  } catch {
    return request;
  }
  return request;
}

function authorizeDeliveryEffect(
  contract: DeliveryAuthorityContract,
  request: unknown,
) {
  return authorizeDeliveryEffectWithAnchor(
    contract,
    stampRequest(contract, request),
    contract.authorityDigest,
    contract.meteringDigest,
    contract.controllerStateDigest,
  );
}

function evaluateDeliveryTransition(
  contract: DeliveryAuthorityContract,
  request: unknown,
) {
  return evaluateDeliveryTransitionWithAnchor(
    contract,
    stampRequest(contract, request),
    contract.authorityDigest,
    contract.meteringDigest,
    contract.controllerStateDigest,
  );
}

function recoveryDetails(
  contract: DeliveryAuthorityContract,
  kind: string,
): AdministrativeRecoveryDetails {
  if (kind === "redundant-profile-downgrade")
    return {
      fromProfile: contract.task.assurance.profile,
      toProfile: "lean",
    };
  if (kind === "missing-keep-branch-finish")
    return {
      branch: contract.task.repository.featureBranch,
      headCommit: contract.workflow.candidate.headCommit,
      targetTree: contract.workflow.candidate.tree,
    };
  if (kind === "repair-receipt-sequencing")
    return {
      priorDecisionSequence: contract.workflow.decisionChain.sequence,
      priorDecisionChainDigest: contract.workflow.decisionChain.digest,
    };
  if (kind === "stale-evidence-after-controller-event")
    return {
      evidenceId: contract.evidence[0]!.evidenceId,
      freshThroughEventId: contract.evidence[0]!.freshThroughEventId,
    };
  if (kind === "canonical-digest-refetch")
    return {
      authorityDigest: contract.authorityDigest,
      meteringDigest: contract.meteringDigest,
      controllerStateDigest: contract.controllerStateDigest,
    };
  if (kind === "disappeared-agent-clean-worktree")
    return {
      agentExecutionId: contract.roles["principal-developer"].executionId,
      agentWorkspaceId: contract.roles["principal-developer"].workspaceId,
    };
  if (kind === "idempotent-push-pr-reconciliation")
    return {
      candidateTree: contract.workflow.candidate.tree,
      candidateCommit: contract.workflow.candidate.headCommit,
      pullRequestNumber: contract.workflow.candidate.pullRequest.number,
      priorEffectSequence: 1,
      originalIdempotencyKey: "missing-prior-effect",
      originalRequestDigest: "a".repeat(64),
      priorOutcome: "authorization-issued-outcome-unknown",
    };
  return { ciRunId: "missing-ci-run", ciCheckId: "missing-ci-check" };
}

function evaluateAdministrativeRecovery(
  contract: DeliveryAuthorityContract,
  request: unknown,
) {
  const stamped = stampRequest(contract, request);
  let normalized = stamped;
  try {
    if (
      typeof stamped === "object" &&
      stamped !== null &&
      Object.getPrototypeOf(stamped) === Object.prototype &&
      !("details" in stamped) &&
      "kind" in stamped &&
      typeof stamped.kind === "string"
    )
      normalized = Object.assign(stamped, {
        details: recoveryDetails(contract, stamped.kind),
      });
  } catch {
    normalized = stamped;
  }
  return evaluateAdministrativeRecoveryWithAnchor(
    contract,
    normalized,
    contract.authorityDigest,
    contract.meteringDigest,
    contract.controllerStateDigest,
  );
}

function rehash(contract: DeliveryAuthorityContract): void {
  for (const evidence of contract.evidence as DeliveryEvidence[]) {
    (evidence as { evidenceDigest: string }).evidenceDigest =
      computeDeliveryEvidenceDigest(evidence);
  }
  if (
    contract.workflow.audit.length === 0 &&
    contract.effectAudit.length === 0 &&
    contract.administrativeRecoveries.length === 0
  ) {
    contract.workflow.checkpoint.decisionChainDigest =
      computeDeliveryDecisionCheckpointDigest(contract);
    contract.workflow.decisionChain = {
      sequence: contract.workflow.checkpoint.decisionSequence,
      digest: contract.workflow.checkpoint.decisionChainDigest,
    };
  }
  (contract as { authorityDigest: string }).authorityDigest =
    computeDeliveryAuthorityDigest(contract);
  contract.meteringDigest = computeDeliveryMeteringDigest(contract);
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
}

function updateDecisionHead(
  contract: DeliveryAuthorityContract,
  authentication: DeliveryDecisionAuthentication | null,
): void {
  if (authentication !== null)
    contract.workflow.decisionChain = {
      sequence: authentication.sequence,
      digest: authentication.resultingChainDigest,
    };
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
}

function setState(
  contract: DeliveryAuthorityContract,
  from: DeliveryAuthorityContract["workflow"]["state"],
  to: DeliveryAuthorityContract["workflow"]["state"],
): void {
  const finalRole = contract.activeRole;
  contract.activeRole = "flow";
  contract.workflow.audit = [];
  contract.effectAudit = [];
  contract.administrativeRecoveries = [];
  contract.workflow.state = from;
  const startsImplementation = from === "ready" && to === "implementation";
  const startsRepair = from === "repair-required" && to === "implementation";
  const repairBudget =
    contract.workflow.observations.ci === "failed" ? "ci" : "verification";
  if (startsImplementation) contract.autonomy.usage.implementationAttempts -= 1;
  if (startsRepair && repairBudget === "ci")
    contract.autonomy.usage.ciRepairAttempts -= 1;
  if (startsRepair && repairBudget === "verification")
    contract.autonomy.usage.verificationRepairAttempts -= 1;
  contract.workflow.checkpoint.state = from;
  if (startsRepair)
    contract.workflow.checkpoint.activeRepairBudget = repairBudget;
  contract.workflow.checkpoint.candidateTree = contract.workflow.candidate.tree;
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
  contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
    canonicalSerializeLifecycleValue(contract.evidence),
    "utf8",
  );
  rehash(contract);
  const decision = evaluateDeliveryTransition(contract, {
    eventId: `set-state-${from}-${to}`,
    idempotencyKey: `set-state-${from}-${to}`,
    from,
    to,
    actorRole: "flow",
    ...decisionIdentity(contract, "flow"),
    candidateTree: contract.workflow.candidate.tree,
  });
  contract.workflow.audit.push(decision.audit);
  if (decision.audit.authentication !== null)
    contract.workflow.decisionChain = {
      sequence: decision.audit.authentication.sequence,
      digest: decision.audit.authentication.resultingChainDigest,
    };
  contract.workflow.state = to;
  if (decision.accepted && startsImplementation)
    contract.autonomy.usage.implementationAttempts += 1;
  if (decision.accepted && startsRepair && repairBudget === "ci")
    contract.autonomy.usage.ciRepairAttempts += 1;
  if (decision.accepted && startsRepair && repairBudget === "verification")
    contract.autonomy.usage.verificationRepairAttempts += 1;
  contract.activeRole = finalRole;
  rehash(contract);
}

function decisionIdentity(
  contract: DeliveryAuthorityContract,
  role: DeliveryAuthorityContract["activeRole"],
) {
  const binding = contract.roles[role];
  return {
    actorId: binding.actorId,
    executionId: binding.executionId,
    workspaceId: binding.workspaceId,
  };
}

function recordMergeObservation(
  contract: DeliveryAuthorityContract,
  freshThroughEventId: string,
): void {
  const observedAt = nextDecisionTimestamp(contract);
  contract.meteringObservedAt = observedAt;
  contract.meteringDigest = computeDeliveryMeteringDigest(contract);
  contract.workflow.observations.merge = {
    status: "merged",
    targetTree: contract.workflow.candidate.tree,
    pullRequestNumber: contract.workflow.candidate.pullRequest.number,
    mergeCommit: "a".repeat(40),
    observedAt,
    receiptId: `receipt-${freshThroughEventId}`,
    freshThroughEventId,
  };
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
}

function recordPassingCiEvidence(
  contract: DeliveryAuthorityContract,
  freshThroughEventId: string,
): void {
  const evidence = structuredClone(contract.evidence[0]!);
  evidence.evidenceId = `evidence-ci-${freshThroughEventId}`;
  evidence.observedAt = nextDecisionTimestamp(contract);
  contract.meteringObservedAt = evidence.observedAt;
  contract.meteringDigest = computeDeliveryMeteringDigest(contract);
  evidence.assurance.phase = "ci";
  evidence.verification = {
    verdict: null,
    reviewedTree: null,
    approvalId: null,
  };
  evidence.ci = {
    runId: `run-${freshThroughEventId}`,
    checkId: `check-${freshThroughEventId}`,
    verdict: "PASS",
  };
  evidence.freshThroughEventId = freshThroughEventId;
  evidence.correlationId = `correlation-${freshThroughEventId}`;
  evidence.idempotencyKey = `evidence-ci-${freshThroughEventId}`;
  evidence.pacaUpdateId = `paca-ci-${freshThroughEventId}`;
  evidence.evidenceDigest = computeDeliveryEvidenceDigest(evidence);
  contract.evidence.push(evidence);
  contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
    canonicalSerializeLifecycleValue(contract.evidence),
  );
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
}

function advanceFlow(
  contract: DeliveryAuthorityContract,
  to: DeliveryAuthorityContract["workflow"]["state"],
  eventId: string,
): string {
  const decision = evaluateDeliveryTransition(contract, {
    eventId,
    idempotencyKey: `transition-${eventId}`,
    from: contract.workflow.state,
    to,
    actorRole: "flow",
    ...decisionIdentity(contract, "flow"),
    candidateTree: contract.workflow.candidate.tree,
  });
  expect(decision).toMatchObject({ accepted: true, code: "accepted" });
  const from = contract.workflow.state;
  let repairBudget = contract.workflow.checkpoint.activeRepairBudget;
  for (let index = contract.workflow.audit.length - 1; index >= 0; index -= 1) {
    const audit = contract.workflow.audit[index]!;
    if (audit.accepted && audit.to === "repair-required") {
      repairBudget = audit.from === "pr-ci-monitoring" ? "ci" : "verification";
      break;
    }
  }
  contract.workflow.audit.push(decision.audit);
  if (decision.audit.authentication !== null)
    contract.workflow.decisionChain = {
      sequence: decision.audit.authentication.sequence,
      digest: decision.audit.authentication.resultingChainDigest,
    };
  contract.workflow.state = decision.nextState;
  if (from === "ready" && to === "implementation")
    contract.autonomy.usage.implementationAttempts += 1;
  else if (from === "repair-required" && to === "implementation") {
    if (repairBudget === "ci") contract.autonomy.usage.ciRepairAttempts += 1;
    else if (repairBudget === "verification")
      contract.autonomy.usage.verificationRepairAttempts += 1;
  }
  contract.controllerStateDigest =
    computeDeliveryControllerStateDigest(contract);
  return decision.audit.eventId;
}

function recoveryIdentity(contract: DeliveryAuthorityContract) {
  return {
    actorRole: contract.activeRole,
    ...decisionIdentity(contract, contract.activeRole),
  };
}

function expectDenied(contract: DeliveryAuthorityContract, code: string): void {
  const result = validateDeliveryAuthorityContract(contract);
  expect(result.valid).toBe(false);
  if (!result.valid)
    expect(
      result.errors.map((error) => error.code),
      JSON.stringify(result.errors),
    ).toContain(code);
}

const immutableEnumerations = [
  DELIVERY_ROLES,
  AUTOMATIC_DELIVERY_ACTIONS,
  HUMAN_GATED_DELIVERY_ACTIONS,
  WORKFLOW_STATES,
  ADMINISTRATIVE_RECOVERY_KINDS,
  MANDATORY_ESCALATION_REASONS,
  DISTINCT_GRANT_EFFECTS,
] as const;

describe("spts.delivery-authority", () => {
  it("accepts the complete contract and positive Product, Flow, Principal Developer, and Verifier examples", () => {
    for (const example of examples) {
      expect(validateDeliveryAuthorityContract(example)).toEqual({
        valid: true,
        value: example,
      });
    }
  });

  it("exports immutable canonical identity, governance, and enumerations", () => {
    expect(DELIVERY_AUTHORITY_CONTRACT_ID).toBe("spts.delivery-authority");
    expect(completeExample.governance).toEqual({
      systemOfRecord: "paca",
      process: "local-pi",
      governedBy: "pi-daddy",
      supervisor: "herdr",
      externalEffects: "decision-only",
    });
    expect(DELIVERY_AUTHORITY_CONTRACT_VERSION).toBe("1.0.0");
    for (const values of immutableEnumerations) {
      expect(Object.isFrozen(values)).toBe(true);
      expect(() => (values as unknown as string[]).reverse()).toThrow(
        TypeError,
      );
    }
    expect(DELIVERY_ROLES).toEqual([
      "product",
      "flow",
      "principal-developer",
      "independent-verifier",
      "stakeholder",
    ]);
  });

  it("labels AJV validation as structural and nonauthorizing", () => {
    const metadata = schema as Record<string, unknown>;
    expect(metadata.title).toContain("structural");
    expect(metadata.description).toContain("does not authorize");
    expect(metadata.$comment).toContain("validateDeliveryAuthorityContract");

    const structurallyValid = clone();
    structurallyValid.workflow.candidate.verification.reviewedTree = "f".repeat(
      40,
    );
    rehash(structurallyValid);
    expect(
      new Ajv({ allErrors: true, formats: { "date-time": true } }).compile(
        schema,
      )(structurallyValid),
    ).toBe(true);
    expect(validateDeliveryAuthorityContract(structurallyValid).valid).toBe(
      false,
    );
  });

  it("binds immutable authority and evidence to deterministic canonical SHA-256 digests", () => {
    const contract = clone();
    expect(computeDeliveryAuthorityDigest(contract)).toBe(
      contract.authorityDigest,
    );
    for (const evidence of contract.evidence)
      expect(computeDeliveryEvidenceDigest(evidence)).toBe(
        evidence.evidenceDigest,
      );

    const reordered = {
      ...contract,
      task: { ...contract.task },
    } as DeliveryAuthorityContract;
    expect(computeDeliveryAuthorityDigest(reordered)).toBe(
      contract.authorityDigest,
    );

    const changedCheckpoint = clone();
    changedCheckpoint.workflow.checkpoint.activeRepairBudget = "ci";
    expect(computeDeliveryAuthorityDigest(changedCheckpoint)).not.toBe(
      changedCheckpoint.authorityDigest,
    );
    expectDenied(changedCheckpoint, "authority-digest");
  });

  it("freezes stakeholder grants into authority and rejects duplicate grant identities", () => {
    const contract = clone();
    const grant = {
      effect: "release" as const,
      grantId: "grant-frozen-release",
      authorizedByRole: "stakeholder" as const,
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-frozen-release",
    };
    contract.effectGrants.push(grant);
    expectDenied(contract, "authority-digest");

    const originalAuthorityDigest = contract.authorityDigest;
    rehash(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
    contract.activeRole = "flow";
    rehash(contract);
    expect(
      authorizeDeliveryEffectWithAnchor(
        contract,
        {
          effect: "release",
          idempotencyKey: "stale-authority-anchor",
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          targetTree: contract.workflow.candidate.tree,
          observedAt: nextDecisionTimestamp(contract),
        },
        originalAuthorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "contract-invalid" });
    contract.activeRole = "principal-developer";
    rehash(contract);
    expect(
      authorizeDeliveryEffect(contract, {
        effect: "release",
        idempotencyKey: "principal-cannot-release",
        actorRole: "principal-developer",
        ...decisionIdentity(contract, "principal-developer"),
        targetTree: contract.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });
    contract.effectGrants.push({ ...grant });
    rehash(contract);
    expectDenied(contract, "grant-duplicate");
  });

  it("enforces author, orchestrator, verifier, and merger separation and read-only verifier authority", () => {
    const sameExecution = clone();
    sameExecution.roles["independent-verifier"].executionId =
      sameExecution.roles["principal-developer"].executionId;
    rehash(sameExecution);
    expectDenied(sameExecution, "role-separation");

    const sameWorkspace = clone();
    sameWorkspace.roles["independent-verifier"].workspaceId =
      sameWorkspace.roles["principal-developer"].workspaceId;
    rehash(sameWorkspace);
    expectDenied(sameWorkspace, "role-separation");

    const writable = clone();
    writable.roles["independent-verifier"].access = "read-write";
    rehash(writable);
    expectDenied(writable, "verifier-read-only");
  });

  it("enforces the active role at every decision boundary", () => {
    const verifierContract = structuredClone(
      verifierExample,
    ) as DeliveryAuthorityContract;
    expect(
      authorizeDeliveryEffect(verifierContract, {
        effect: "edit",
        idempotencyKey: "active-role-bypass",
        actorRole: "principal-developer",
        ...decisionIdentity(verifierContract, "principal-developer"),
        targetTree: verifierContract.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });

    expect(
      authorizeDeliveryEffect(verifierContract, {
        effect: "test",
        idempotencyKey: "workspace-identity-drift",
        actorRole: "independent-verifier",
        actorId: verifierContract.roles["independent-verifier"].actorId,
        executionId: verifierContract.roles["independent-verifier"].executionId,
        workspaceId: verifierContract.roles.flow.workspaceId,
        targetTree: verifierContract.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "identity-drift" });

    expect(
      evaluateDeliveryTransition(verifierContract, {
        eventId: "active-role-transition",
        idempotencyKey: "active-role-transition",
        from: "publication-authorized",
        to: "pr-ci-monitoring",
        actorRole: "flow",
        ...decisionIdentity(verifierContract, "flow"),
        candidateTree: verifierContract.workflow.candidate.tree,
      }),
    ).toMatchObject({ accepted: false, code: "identity-drift" });

    expect(
      evaluateAdministrativeRecovery(verifierContract, {
        recoveryId: "active-role-recovery",
        kind: "canonical-digest-refetch",
        idempotencyKey: "active-role-recovery",
        identityRevalidated: true,
        targetGate: "administrative",
        actorRole: "principal-developer",
        actorId: verifierContract.roles["principal-developer"].actorId,
        executionId: verifierContract.roles["principal-developer"].executionId,
        workspaceId: verifierContract.roles["principal-developer"].workspaceId,
      }),
    ).toMatchObject({ allowed: false, code: "identity-not-revalidated" });
  });

  it("requires independent APPROVE bound to the exact candidate tree", () => {
    for (const mutate of [
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.verification.verdict = "REJECT";
      },
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.verification.reviewedTree = "e".repeat(40);
      },
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.verification.executionId =
          contract.roles["principal-developer"].executionId;
      },
    ]) {
      const contract = clone();
      mutate(contract);
      rehash(contract);
      expectDenied(contract, "publication-approval");
    }
  });

  it("invalidates publication after candidate, remote-main, or PR-head drift", () => {
    const mutations = [
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.tree = "a".repeat(40);
      },
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.remoteBase.observedCommit = "a".repeat(40);
      },
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.remoteBase.expectedCommit = "a".repeat(40);
        contract.workflow.candidate.remoteBase.observedCommit = "a".repeat(40);
        contract.workflow.candidate.remoteBase.expectedTree = "b".repeat(40);
        contract.workflow.candidate.remoteBase.observedTree = "b".repeat(40);
      },
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.remoteBase.observedTree = "a".repeat(40);
      },
      (contract: DeliveryAuthorityContract) => {
        contract.workflow.candidate.pullRequest.observedHeadCommit = "a".repeat(
          40,
        );
      },
    ];
    for (const mutate of mutations) {
      const contract = clone();
      mutate(contract);
      rehash(contract);
      expectDenied(contract, "publication-drift");
      expect(
        authorizeDeliveryEffect(contract, {
          effect: "publication",
          idempotencyKey: "effect-publication-retry",
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          targetTree: contract.workflow.candidate.tree,
        }).allowed,
      ).toBe(false);
    }
  });

  it("requires distinct stakeholder merge authority and distinct grants for release, production, destructive Git, and real Pi", () => {
    const merge = clone();
    merge.workflow.observations.ci = "passed";
    setState(merge, "pr-ci-monitoring", "merge-gate");
    expectDenied(merge, "missing-effect-grant");

    for (const effect of DISTINCT_GRANT_EFFECTS) {
      const contract = clone();
      contract.activeRole = "flow";
      contract.requestedEffects = [effect];
      rehash(contract);
      expectDenied(contract, "missing-effect-grant");

      contract.effectGrants.push({
        effect,
        grantId: `grant-${effect}`,
        authorizedByRole: "stakeholder",
        authorizedByActorId: contract.roles.stakeholder.actorId,
        targetTree: contract.workflow.candidate.tree,
        idempotencyKey: `grant-${effect}-tree`,
      });
      rehash(contract);
      expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
      expect(
        authorizeDeliveryEffect(contract, {
          effect,
          idempotencyKey: `wrong-phase-effect-${effect}`,
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          targetTree: contract.workflow.candidate.tree,
        }),
      ).toMatchObject({ allowed: false, code: "effect-state-denied" });
    }
  });

  it("allows automatic actions only for their active role and workflow phase", () => {
    const effectContext: Record<
      (typeof AUTOMATIC_DELIVERY_ACTIONS)[number],
      {
        role: DeliveryAuthorityContract["activeRole"];
        from: DeliveryAuthorityContract["workflow"]["state"];
        state: DeliveryAuthorityContract["workflow"]["state"];
      }
    > = {
      "diagnose-repair": {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      edit: {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      test: {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      build: {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      format: {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      "worktree-create": {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      "worktree-inspect": {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      "worktree-cleanup": {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      "feature-branch-commit": {
        role: "principal-developer",
        from: "ready",
        state: "implementation",
      },
      "independent-verification": {
        role: "independent-verifier",
        from: "internal-review",
        state: "independent-verification",
      },
      "feature-push": {
        role: "flow",
        from: "independent-verification",
        state: "publication-authorized",
      },
      "pr-create-update": {
        role: "flow",
        from: "independent-verification",
        state: "publication-authorized",
      },
      "ci-monitor": {
        role: "principal-developer",
        from: "publication-authorized",
        state: "pr-ci-monitoring",
      },
      "ci-repair": {
        role: "principal-developer",
        from: "repair-required",
        state: "implementation",
      },
      "paca-evidence-update": {
        role: "principal-developer",
        from: "independent-verification",
        state: "publication-authorized",
      },
      "paca-status-update": {
        role: "principal-developer",
        from: "independent-verification",
        state: "publication-authorized",
      },
      "administrative-recovery": {
        role: "flow",
        from: "ready",
        state: "blocked",
      },
    };
    for (const effect of AUTOMATIC_DELIVERY_ACTIONS) {
      const context = effectContext[effect];
      const contract = clone();
      contract.activeRole = context.role;
      if (effect === "ci-monitor")
        contract.workflow.observations.ci = "pending";
      if (effect === "ci-repair") {
        contract.workflow.observations.ci = "failed";
        contract.autonomy.usage.ciRepairAttempts = 1;
      }
      setState(contract, context.from, context.state);
      if (effect === "ci-repair") {
        contract.workflow.checkpoint.activeRepairBudget = "ci";
        contract.workflow.checkpoint.attemptUsage.ciRepairAttempts = 0;
        rehash(contract);
      }
      const decision = authorizeDeliveryEffect(contract, {
        effect,
        idempotencyKey: `automatic-${effect}`,
        actorRole: context.role,
        ...decisionIdentity(contract, context.role),
        targetTree: contract.workflow.candidate.tree,
      });
      if (effect === "administrative-recovery")
        expect(decision).toMatchObject({
          allowed: false,
          code: "role-authority-denied",
        });
      else expect(decision.allowed, `${effect}:${decision.code}`).toBe(true);
    }

    const contract = clone();
    contract.activeRole = "independent-verifier";
    rehash(contract);
    expect(
      authorizeDeliveryEffect(contract, {
        effect: "edit",
        idempotencyKey: "verifier-edit-denied",
        actorRole: "independent-verifier",
        ...decisionIdentity(contract, "independent-verifier"),
        targetTree: contract.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });
    for (const effect of HUMAN_GATED_DELIVERY_ACTIONS) {
      expect(AUTOMATIC_DELIVERY_ACTIONS).not.toContain(effect);
    }

    contract.activeRole = "principal-developer";
    setState(contract, "ready", "implementation");
    for (const effect of ["feature-push", "pr-create-update"] as const) {
      expect(
        authorizeDeliveryEffect(contract, {
          effect,
          idempotencyKey: `preapproval-${effect}`,
          actorRole: "principal-developer",
          ...decisionIdentity(contract, "principal-developer"),
          targetTree: contract.workflow.candidate.tree,
        }),
      ).toMatchObject({ allowed: false, code: "publication-denied" });
    }
  });

  it("rejects noncanonical attacker-selected decision codes", () => {
    const transition = clone();
    transition.workflow.audit[0]!.code = "attacker-code" as "accepted";
    rehash(transition);
    expectDenied(transition, "enum");

    const effect = clone();
    const effectDecision = authorizeDeliveryEffect(effect, {
      effect: "test",
      idempotencyKey: "effect-code-test",
      actorRole: "principal-developer",
      ...decisionIdentity(effect, "principal-developer"),
      targetTree: effect.workflow.candidate.tree,
    });
    effect.effectAudit.push(effectDecision.audit);
    effect.effectAudit[0]!.code = "attacker-code" as "accepted";
    rehash(effect);
    expectDenied(effect, "enum");

    const recovery = clone();
    const recoveryDecision = evaluateAdministrativeRecovery(recovery, {
      recoveryId: "recovery-code-test",
      kind: "canonical-digest-refetch",
      idempotencyKey: "recovery-code-test-key",
      identityRevalidated: true,
      targetGate: "administrative",
      ...recoveryIdentity(recovery),
    });
    recovery.administrativeRecoveries.push(recoveryDecision.audit);
    recovery.administrativeRecoveries[0]!.code = "attacker-code" as "accepted";
    rehash(recovery);
    expectDenied(recovery, "enum");
  });

  it("rejects forged audit verdicts and noncanonical evidence freshness timestamps", () => {
    const forged = clone();
    forged.workflow.audit[0]!.to = "completed";
    rehash(forged);
    expectDenied(forged, "audit-verdict");

    const badTimestamp = clone();
    badTimestamp.evidence[0]!.observedAt = "2026-08-25T23:00:00Z";
    rehash(badTimestamp);
    expectDenied(badTimestamp, "canonical-timestamp");
  });

  it("binds every decision receipt to a fresh controller timestamp", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    const staleObservedAt = contract.workflow.candidate.verification.observedAt;
    expect(
      evaluateDeliveryTransitionWithAnchor(
        contract,
        {
          eventId: "stale-transition-time",
          idempotencyKey: "stale-transition-time",
          from: "publication-authorized",
          to: "pr-ci-monitoring",
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          candidateTree: contract.workflow.candidate.tree,
          observedAt: staleObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ accepted: false, code: "stale-observation" });
    expect(
      evaluateDeliveryTransitionWithAnchor(
        contract,
        {
          eventId: "future-transition-time",
          idempotencyKey: "future-transition-time",
          from: "publication-authorized",
          to: "pr-ci-monitoring",
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          candidateTree: contract.workflow.candidate.tree,
          observedAt: "9999-12-31T23:59:59.999Z",
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ accepted: false, code: "stale-observation" });
    expect(
      authorizeDeliveryEffectWithAnchor(
        contract,
        {
          effect: "feature-push",
          idempotencyKey: "stale-effect-time",
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          targetTree: contract.workflow.candidate.tree,
          observedAt: staleObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "stale-observation" });

    setState(contract, "publication-authorized", "blocked");
    expect(
      evaluateAdministrativeRecoveryWithAnchor(
        contract,
        {
          recoveryId: "stale-recovery-time",
          kind: "canonical-digest-refetch",
          idempotencyKey: "stale-recovery-time",
          actorRole: "flow",
          ...decisionIdentity(contract, "flow"),
          identityRevalidated: true,
          targetGate: "administrative",
          details: {
            authorityDigest: contract.authorityDigest,
            meteringDigest: contract.meteringDigest,
            controllerStateDigest: contract.controllerStateDigest,
          },
          observedAt: staleObservedAt,
        },
        contract.authorityDigest,
        contract.meteringDigest,
        contract.controllerStateDigest,
      ),
    ).toMatchObject({ allowed: false, code: "stale-observation" });
  });

  it("enforces the workflow state machine and records rejected controller events auditably", () => {
    const contract = clone();
    setState(contract, "ready", "implementation");

    const accepted = evaluateDeliveryTransition(contract, {
      eventId: "event-review",
      idempotencyKey: "transition-review",
      from: "implementation",
      to: "internal-review",
      actorRole: "principal-developer",
      ...decisionIdentity(contract, "principal-developer"),
      candidateTree: contract.workflow.candidate.tree,
    });
    expect(accepted).toMatchObject({
      accepted: true,
      idempotent: false,
      nextState: "internal-review",
    });
    expect(accepted.audit).toMatchObject({ accepted: true, code: "accepted" });

    const rejected = evaluateDeliveryTransition(contract, {
      eventId: "event-skip",
      idempotencyKey: "transition-skip",
      from: "implementation",
      to: "completed",
      actorRole: "principal-developer",
      ...decisionIdentity(contract, "principal-developer"),
      candidateTree: contract.workflow.candidate.tree,
    });
    expect(rejected).toMatchObject({
      accepted: false,
      code: "transition-denied",
    });
    expect(rejected.audit).toMatchObject({
      accepted: false,
      code: "transition-denied",
    });
  });

  it("retains rejected controller events without corrupting the accepted audit chain", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    contract.meteringObservedAt = nextDecisionTimestamp(contract);
    contract.meteringDigest = computeDeliveryMeteringDigest(contract);
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    const rejected = evaluateDeliveryTransition(contract, {
      eventId: "rejected-wrong-from",
      idempotencyKey: "rejected-wrong-from",
      from: "intake",
      to: "ready",
      actorRole: "flow",
      ...decisionIdentity(contract, "flow"),
      candidateTree: contract.workflow.candidate.tree,
    });
    expect(rejected).toMatchObject({
      accepted: false,
      code: "identity-drift",
    });
    contract.workflow.audit.push(rejected.audit);
    contract.workflow.decisionChain = {
      sequence: rejected.audit.authentication!.sequence,
      digest: rejected.audit.authentication!.resultingChainDigest,
    };
    contract.controllerStateDigest =
      computeDeliveryControllerStateDigest(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
  });

  it("binds current state to the ordered audit trace and blocks unresolved escalation resume", () => {
    const untraced = clone();
    untraced.workflow.state = "completed";
    untraced.workflow.observations.ci = "passed";
    untraced.effectGrants.push({
      effect: "merge",
      grantId: "grant-untraced-completion",
      authorizedByRole: "stakeholder",
      authorizedByActorId: untraced.roles.stakeholder.actorId,
      targetTree: untraced.workflow.candidate.tree,
      idempotencyKey: "grant-untraced-completion",
    });
    rehash(untraced);
    expectDenied(untraced, "audit-state-mismatch");

    const escalated = clone();
    escalated.activeRole = "flow";
    setState(escalated, "ready", "blocked");
    escalated.activeEscalations = ["identity-drift"];
    rehash(escalated);
    expect(
      evaluateDeliveryTransition(escalated, {
        eventId: "event-unsafe-resume",
        idempotencyKey: "transition-unsafe-resume",
        from: "blocked",
        to: "ready",
        actorRole: "flow",
        ...decisionIdentity(escalated, "flow"),
        candidateTree: escalated.workflow.candidate.tree,
      }),
    ).toMatchObject({ accepted: false, code: "transition-denied" });

    const emptyTrace = clone();
    emptyTrace.workflow.audit = [];
    emptyTrace.workflow.state = "implementation";
    emptyTrace.evidence[0]!.freshThroughEventId =
      emptyTrace.workflow.checkpoint.checkpointId;
    rehash(emptyTrace);
    emptyTrace.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(emptyTrace.evidence),
    );
    expectDenied(emptyTrace, "checkpoint-mismatch");
  });

  it("requires immutable passing CI evidence before merge", () => {
    const contract = clone();
    contract.workflow.observations.ci = "passed";
    setState(contract, "pr-ci-monitoring", "merge-gate");
    contract.effectGrants.push({
      effect: "merge",
      grantId: "grant-missing-ci-evidence",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-missing-ci-evidence",
    });
    contract.evidence[0]!.ci = {
      runId: null,
      checkId: null,
      verdict: null,
    };
    rehash(contract);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    expectDenied(contract, "ci-evidence");
  });

  it("rejects passing CI evidence from a superseded monitoring cycle", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    contract.effectGrants.push({
      effect: "merge",
      grantId: "grant-stale-ci",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-stale-ci",
    });
    rehash(contract);
    const oldBoundary = advanceFlow(
      contract,
      "pr-ci-monitoring",
      "stale-ci-old-boundary",
    );
    recordPassingCiEvidence(contract, oldBoundary);
    contract.workflow.observations.ci = "failed";
    for (const [to, eventId] of [
      ["repair-required", "stale-ci-repair"],
      ["implementation", "stale-ci-implementation"],
      ["internal-review", "stale-ci-internal"],
      ["independent-verification", "stale-ci-verification"],
      ["publication-authorized", "stale-ci-publication"],
      ["pr-ci-monitoring", "stale-ci-new-boundary"],
    ] as const)
      advanceFlow(contract, to, eventId);
    contract.workflow.observations.ci = "passed";

    const mergeRequest = {
      eventId: "stale-ci-merge",
      idempotencyKey: "transition-stale-ci-merge",
      from: "pr-ci-monitoring" as const,
      to: "merge-gate" as const,
      actorRole: "flow" as const,
      ...decisionIdentity(contract, "flow"),
      candidateTree: contract.workflow.candidate.tree,
    };
    expect(evaluateDeliveryTransition(contract, mergeRequest)).toMatchObject({
      accepted: false,
      code: "ci-evidence-required",
    });

    const relabelledEvidence = structuredClone(contract.evidence.at(-1)!);
    relabelledEvidence.evidenceId = "evidence-ci-relabelled-old-run";
    relabelledEvidence.freshThroughEventId = "stale-ci-new-boundary";
    relabelledEvidence.correlationId = "correlation-ci-relabelled-old-run";
    relabelledEvidence.idempotencyKey = "evidence-ci-relabelled-old-run";
    relabelledEvidence.pacaUpdateId = "paca-ci-relabelled-old-run";
    relabelledEvidence.evidenceDigest =
      computeDeliveryEvidenceDigest(relabelledEvidence);
    contract.evidence.push(relabelledEvidence);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    expectDenied(contract, "ci-identity-reuse");
    expect(evaluateDeliveryTransition(contract, mergeRequest)).toMatchObject({
      accepted: false,
      code: "contract-invalid",
    });
    contract.evidence.pop();
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );

    recordPassingCiEvidence(contract, "stale-ci-new-boundary");
    const failedEvidence = structuredClone(contract.evidence.at(-1)!);
    failedEvidence.evidenceId = "evidence-ci-later-failure";
    failedEvidence.ci = {
      runId: "run-ci-later-failure",
      checkId: "check-ci-later-failure",
      verdict: "FAIL",
    };
    failedEvidence.correlationId = "correlation-ci-later-failure";
    failedEvidence.idempotencyKey = "evidence-ci-later-failure";
    failedEvidence.pacaUpdateId = "paca-ci-later-failure";
    failedEvidence.evidenceDigest =
      computeDeliveryEvidenceDigest(failedEvidence);
    contract.evidence.push(failedEvidence);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    delete (mergeRequest as { observedAt?: string }).observedAt;
    expect(evaluateDeliveryTransition(contract, mergeRequest)).toMatchObject({
      accepted: false,
      code: "ci-evidence-required",
    });
  });

  it("rejects a merge receipt from a superseded merge gate", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    contract.effectGrants.push({
      effect: "merge",
      grantId: "grant-stale-merge-receipt",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-stale-merge-receipt",
    });
    rehash(contract);
    const firstCiBoundary = advanceFlow(
      contract,
      "pr-ci-monitoring",
      "stale-merge-first-ci",
    );
    recordPassingCiEvidence(contract, firstCiBoundary);
    contract.workflow.observations.ci = "passed";
    const oldMergeGate = advanceFlow(
      contract,
      "merge-gate",
      "stale-merge-old-gate",
    );
    recordMergeObservation(contract, oldMergeGate);
    for (const [to, eventId] of [
      ["blocked", "stale-merge-blocked"],
      ["ready", "stale-merge-ready"],
      ["implementation", "stale-merge-implementation"],
      ["internal-review", "stale-merge-internal"],
      ["independent-verification", "stale-merge-verification"],
      ["publication-authorized", "stale-merge-publication"],
      ["pr-ci-monitoring", "stale-merge-second-ci"],
    ] as const)
      advanceFlow(contract, to, eventId);
    recordPassingCiEvidence(contract, "stale-merge-second-ci");
    advanceFlow(contract, "merge-gate", "stale-merge-current-gate");
    expectDenied(contract, "merge-observation");

    expect(
      evaluateDeliveryTransition(contract, {
        eventId: "stale-merge-completion",
        idempotencyKey: "transition-stale-merge-completion",
        from: "merge-gate",
        to: "completed",
        actorRole: "flow",
        ...decisionIdentity(contract, "flow"),
        candidateTree: contract.workflow.candidate.tree,
      }),
    ).toMatchObject({
      accepted: false,
      code: "contract-invalid",
    });
  });

  it("requires passing CI before merge or completion", () => {
    const contract = clone();
    setState(contract, "pr-ci-monitoring", "merge-gate");
    contract.effectGrants.push({
      effect: "merge",
      grantId: "grant-ci-gate",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-ci-gate",
    });
    rehash(contract);
    expectDenied(contract, "ci-gate");
  });

  it("requires a fresh exact-tree merge receipt before completion", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    contract.workflow.observations.ci = "passed";
    contract.effectGrants.push({
      effect: "merge",
      grantId: "grant-completion-receipt",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-completion-receipt",
    });
    rehash(contract);

    for (const [from, to, suffix] of [
      ["publication-authorized", "pr-ci-monitoring", "ci"],
      ["pr-ci-monitoring", "merge-gate", "merge"],
    ] as const) {
      if (to === "merge-gate")
        recordPassingCiEvidence(contract, "event-completion-ci");
      const decision = evaluateDeliveryTransition(contract, {
        eventId: `event-completion-${suffix}`,
        idempotencyKey: `transition-completion-${suffix}`,
        from,
        to,
        actorRole: "flow",
        ...decisionIdentity(contract, "flow"),
        candidateTree: contract.workflow.candidate.tree,
      });
      contract.workflow.audit.push(decision.audit);
      updateDecisionHead(contract, decision.audit.authentication);
      contract.workflow.state = decision.nextState;
      contract.controllerStateDigest =
        computeDeliveryControllerStateDigest(contract);
    }
    rehash(contract);

    const completionRequest = {
      eventId: "event-completion-without-receipt",
      idempotencyKey: "transition-completion-without-receipt",
      from: "merge-gate" as const,
      to: "completed" as const,
      actorRole: "flow" as const,
      ...decisionIdentity(contract, "flow"),
      candidateTree: contract.workflow.candidate.tree,
    };
    expect(
      evaluateDeliveryTransition(contract, completionRequest),
    ).toMatchObject({
      accepted: false,
      code: "merge-observation-required",
    });

    recordMergeObservation(contract, "event-completion-merge");
    delete (completionRequest as { observedAt?: string }).observedAt;
    const completed = evaluateDeliveryTransition(contract, completionRequest);
    expect(completed).toMatchObject({ accepted: true, code: "accepted" });
    contract.workflow.audit.push(completed.audit);
    updateDecisionHead(contract, completed.audit.authentication);
    contract.workflow.state = completed.nextState;
    rehash(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
  });

  it("rejects completed workflow state without its exact-tree stakeholder merge grant", () => {
    const contract = clone();
    contract.workflow.state = "completed";
    rehash(contract);
    expectDenied(contract, "missing-effect-grant");
  });

  it("rejects verification evidence detached from the exact reviewed candidate", () => {
    const contract = clone();
    contract.evidence[0]!.repository.tree = "a".repeat(40);
    rehash(contract);
    expectDenied(contract, "verification-evidence-binding");
  });

  it("retains rejected verification evidence alongside authenticated history", () => {
    const contract = clone();
    const historical = structuredClone(contract.evidence[0]!);
    historical.evidenceId = "evidence-retained-rejection";
    historical.verification = {
      verdict: "REJECT",
      reviewedTree: historical.repository.tree,
      approvalId: null,
    };
    historical.observedAt = contract.workflow.checkpoint.observedAt;
    historical.freshThroughEventId = contract.workflow.checkpoint.checkpointId;
    historical.correlationId = "correlation-retained-rejection";
    historical.idempotencyKey = "evidence-retained-rejection";
    historical.pacaUpdateId = "paca-retained-rejection";
    contract.evidence.unshift(historical);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
      "utf8",
    );
    rehash(contract);

    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
  });

  it("rejects persisted allowed effects that violate live safety gates", () => {
    const contract = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    contract.workflow.audit = [];
    contract.workflow.state = "implementation";
    contract.workflow.checkpoint.state = "implementation";
    contract.evidence[0]!.freshThroughEventId =
      contract.workflow.checkpoint.checkpointId;
    contract.autonomy.usage.elapsedMinutes =
      contract.autonomy.limits.durationMinutes;
    contract.meteringObservedAt = nextDecisionTimestamp(contract);
    const request = {
      effect: "edit" as const,
      idempotencyKey: "forged-expired-edit",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      targetTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    };
    contract.effectAudit.push({
      authentication: null,
      ...request,
      requestDigest: createHash("sha256")
        .update(canonicalSerializeLifecycleValue(request))
        .digest("hex"),
      workflowState: "implementation",
      allowed: true,
      code: "accepted",
    });
    rehash(contract);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    expectDenied(contract, "type");
  });

  it("rejects persisted allowed effects at capacity budgets", () => {
    const contract = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    contract.workflow.audit = [];
    contract.workflow.state = "implementation";
    contract.workflow.checkpoint.state = "implementation";
    contract.evidence[0]!.freshThroughEventId =
      contract.workflow.checkpoint.checkpointId;
    contract.autonomy.usage.worktrees = contract.autonomy.limits.worktrees;
    contract.meteringObservedAt = nextDecisionTimestamp(contract);
    const request = {
      effect: "worktree-create" as const,
      idempotencyKey: "forged-worktree-capacity",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      targetTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    };
    contract.effectAudit.push({
      authentication: null,
      ...request,
      requestDigest: createHash("sha256")
        .update(canonicalSerializeLifecycleValue(request))
        .digest("hex"),
      workflowState: "implementation",
      allowed: true,
      code: "accepted",
    });
    rehash(contract);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    expectDenied(contract, "type");
  });

  it("rejects persisted CI actions without their required CI observation", () => {
    const contract = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    contract.workflow.audit = [];
    contract.workflow.state = "implementation";
    contract.workflow.checkpoint.state = "implementation";
    contract.evidence[0]!.freshThroughEventId =
      contract.workflow.checkpoint.checkpointId;
    contract.workflow.observations.ci = "not-started";
    contract.meteringObservedAt = nextDecisionTimestamp(contract);
    const request = {
      effect: "ci-repair" as const,
      idempotencyKey: "forged-ci-repair",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      targetTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    };
    contract.effectAudit.push({
      authentication: null,
      ...request,
      requestDigest: createHash("sha256")
        .update(canonicalSerializeLifecycleValue(request))
        .digest("hex"),
      workflowState: "implementation",
      allowed: true,
      code: "accepted",
    });
    rehash(contract);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    expectDenied(contract, "type");

    const monitor = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    monitor.workflow.audit = [];
    monitor.workflow.state = "pr-ci-monitoring";
    monitor.workflow.checkpoint.state = "pr-ci-monitoring";
    monitor.evidence[0]!.freshThroughEventId =
      monitor.workflow.checkpoint.checkpointId;
    monitor.workflow.observations.ci = "not-started";
    monitor.meteringObservedAt = nextDecisionTimestamp(monitor);
    const monitorRequest = {
      effect: "ci-monitor" as const,
      idempotencyKey: "forged-ci-monitor",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(monitor, "principal-developer"),
      targetTree: monitor.workflow.candidate.tree,
      observedAt: monitor.meteringObservedAt,
    };
    monitor.effectAudit.push({
      authentication: null,
      ...monitorRequest,
      requestDigest: createHash("sha256")
        .update(canonicalSerializeLifecycleValue(monitorRequest))
        .digest("hex"),
      workflowState: "pr-ci-monitoring",
      allowed: true,
      code: "accepted",
    });
    rehash(monitor);
    monitor.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(monitor.evidence),
    );
    expectDenied(monitor, "type");
  });

  it("retains historically authorized effects after the active role changes", () => {
    const contract = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    setState(contract, "ready", "implementation");
    const request = {
      effect: "edit" as const,
      idempotencyKey: "historical-principal-edit",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      targetTree: contract.workflow.candidate.tree,
    };
    const decision = authorizeDeliveryEffect(contract, request);
    expect(decision).toMatchObject({ allowed: true, code: "accepted" });
    contract.effectAudit.push(decision.audit);
    updateDecisionHead(contract, decision.audit.authentication);
    contract.activeRole = "flow";
    rehash(contract);
    expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
  });

  it("rejects persisted effects with a tampered role identity", () => {
    const contract = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    contract.workflow.audit = [];
    contract.workflow.state = "implementation";
    contract.workflow.checkpoint.state = "implementation";
    contract.evidence[0]!.freshThroughEventId =
      contract.workflow.checkpoint.checkpointId;
    contract.meteringObservedAt = nextDecisionTimestamp(contract);
    const request = {
      effect: "edit" as const,
      idempotencyKey: "forged-tampered-role-identity",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      actorId: contract.roles.flow.actorId,
      targetTree: contract.workflow.candidate.tree,
      observedAt: contract.meteringObservedAt,
    };
    contract.effectAudit.push({
      authentication: null,
      ...request,
      requestDigest: createHash("sha256")
        .update(canonicalSerializeLifecycleValue(request))
        .digest("hex"),
      workflowState: "implementation",
      allowed: true,
      code: "accepted",
    });
    rehash(contract);
    contract.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(contract.evidence),
    );
    expectDenied(contract, "type");
  });

  it("makes repeated effects and transitions idempotent while rejecting key collisions", () => {
    const contract = clone();
    setState(contract, "ready", "implementation");
    const request = {
      eventId: "event-review",
      idempotencyKey: "same-transition",
      from: "implementation" as const,
      to: "internal-review" as const,
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      candidateTree: contract.workflow.candidate.tree,
    };
    const first = evaluateDeliveryTransition(contract, request);
    contract.workflow.audit.push(first.audit);
    updateDecisionHead(contract, first.audit.authentication);
    contract.workflow.state = first.nextState;
    rehash(contract);
    expect(evaluateDeliveryTransition(contract, request)).toMatchObject({
      accepted: true,
      idempotent: true,
    });
    expect(
      evaluateDeliveryTransition(contract, { ...request, to: "blocked" }),
    ).toMatchObject({ accepted: false, code: "idempotency-conflict" });

    const effectRequest = {
      effect: "test" as const,
      idempotencyKey: "same-effect",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      targetTree: contract.workflow.candidate.tree,
    };
    const effect = authorizeDeliveryEffect(contract, effectRequest);
    contract.effectAudit.push(effect.audit);
    updateDecisionHead(contract, effect.audit.authentication);
    rehash(contract);
    expect(authorizeDeliveryEffect(contract, effectRequest)).toMatchObject({
      allowed: false,
      idempotent: true,
      audit: { allowed: true, code: "accepted" },
    });
    expect(
      authorizeDeliveryEffect(contract, { ...effectRequest, effect: "build" }),
    ).toMatchObject({ allowed: false, code: "idempotency-conflict" });
  });

  it("keeps historical transition replays at the current workflow state", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    const publicationRequest = {
      eventId: "event-pr-monitoring",
      idempotencyKey: "transition-pr-monitoring",
      from: "publication-authorized" as const,
      to: "pr-ci-monitoring" as const,
      actorRole: "flow" as const,
      ...decisionIdentity(contract, "flow"),
      candidateTree: contract.workflow.candidate.tree,
    };
    const publication = evaluateDeliveryTransition(
      contract,
      publicationRequest,
    );
    contract.workflow.audit.push(publication.audit);
    updateDecisionHead(contract, publication.audit.authentication);
    contract.workflow.state = publication.nextState;
    contract.workflow.observations.ci = "passed";
    recordPassingCiEvidence(contract, publication.audit.eventId);
    contract.effectGrants.push({
      effect: "merge",
      grantId: "grant-replay-merge",
      authorizedByRole: "stakeholder",
      authorizedByActorId: contract.roles.stakeholder.actorId,
      targetTree: contract.workflow.candidate.tree,
      idempotencyKey: "grant-replay-merge",
    });
    rehash(contract);

    const mergeRequest = {
      eventId: "event-merge-gate",
      idempotencyKey: "transition-merge-gate-replay",
      from: "pr-ci-monitoring" as const,
      to: "merge-gate" as const,
      actorRole: "flow" as const,
      ...decisionIdentity(contract, "flow"),
      candidateTree: contract.workflow.candidate.tree,
    };
    const merge = evaluateDeliveryTransition(contract, mergeRequest);
    contract.workflow.audit.push(merge.audit);
    updateDecisionHead(contract, merge.audit.authentication);
    contract.workflow.state = merge.nextState;
    rehash(contract);

    expect(
      evaluateDeliveryTransition(contract, publicationRequest),
    ).toMatchObject({
      accepted: true,
      idempotent: true,
      nextState: "merge-gate",
    });
  });

  it("allows only phase-safe administrative recovery after exact identity revalidation", () => {
    const contract = clone();
    contract.workflow.observations.ci = "pending";
    setState(contract, "ready", "blocked");
    for (const kind of ADMINISTRATIVE_RECOVERY_KINDS) {
      const decision = evaluateAdministrativeRecovery(contract, {
        recoveryId: `recovery-${kind}`,
        kind,
        idempotencyKey: `recovery-key-${kind}`,
        identityRevalidated: true,
        targetGate: "administrative",
        ...recoveryIdentity(contract),
      });
      if (
        kind === "repair-receipt-sequencing" ||
        kind === "canonical-digest-refetch" ||
        kind === "disappeared-agent-clean-worktree"
      )
        expect(decision).toMatchObject({ allowed: true, code: "accepted" });
      else
        expect(decision).toMatchObject({
          allowed: false,
          code: "recovery-gate-denied",
        });
    }
    const wrongPhase = clone();
    expect(
      evaluateAdministrativeRecovery(wrongPhase, {
        recoveryId: "recovery-wrong-phase",
        kind: "interrupted-ci-polling",
        idempotencyKey: "recovery-wrong-phase",
        identityRevalidated: true,
        targetGate: "administrative",
        ...recoveryIdentity(wrongPhase),
      }),
    ).toMatchObject({ allowed: false, code: "recovery-gate-denied" });

    expect(
      evaluateAdministrativeRecovery(contract, {
        recoveryId: "recovery-unsafe",
        kind: "canonical-digest-refetch",
        idempotencyKey: "recovery-unsafe",
        identityRevalidated: true,
        targetGate: "security",
        ...recoveryIdentity(contract),
      }),
    ).toMatchObject({ allowed: false, code: "recovery-gate-denied" });
    expect(
      evaluateAdministrativeRecovery(contract, {
        recoveryId: "recovery-drift",
        kind: "canonical-digest-refetch",
        idempotencyKey: "recovery-drift",
        identityRevalidated: false,
        targetGate: "administrative",
        ...recoveryIdentity(contract),
      }),
    ).toMatchObject({ allowed: false, code: "identity-not-revalidated" });

    const request = {
      recoveryId: "recovery-repeat",
      kind: "canonical-digest-refetch" as const,
      idempotencyKey: "recovery-repeat-key",
      identityRevalidated: true,
      targetGate: "administrative" as const,
      ...recoveryIdentity(contract),
    };
    const first = evaluateAdministrativeRecovery(contract, request);
    contract.administrativeRecoveries.push(first.audit);
    updateDecisionHead(contract, first.audit.authentication);
    rehash(contract);
    expect(evaluateAdministrativeRecovery(contract, request)).toMatchObject({
      allowed: false,
      idempotent: true,
      audit: { accepted: true, code: "accepted" },
    });
    expect(
      evaluateAdministrativeRecovery(contract, {
        ...request,
        recoveryId: "recovery-repeat-changed",
      }),
    ).toMatchObject({ allowed: false, code: "idempotency-conflict" });
  });

  it("denies mutating effects after completion and at exhausted repair budgets", () => {
    const completed = clone();
    completed.activeRole = "flow";
    completed.workflow.observations.ci = "passed";
    completed.effectGrants.push({
      effect: "merge",
      grantId: "grant-completed-effect-test",
      authorizedByRole: "stakeholder",
      authorizedByActorId: completed.roles.stakeholder.actorId,
      targetTree: completed.workflow.candidate.tree,
      idempotencyKey: "grant-completed-effect-test",
    });
    setState(completed, "publication-authorized", "pr-ci-monitoring");
    recordPassingCiEvidence(completed, completed.workflow.audit[0]!.eventId);
    const mergeGateEvent = advanceFlow(
      completed,
      "merge-gate",
      "event-completed-effect-merge-gate",
    );
    recordMergeObservation(completed, mergeGateEvent);
    rehash(completed);
    const completion = evaluateDeliveryTransition(completed, {
      eventId: "event-completed-effect-test",
      idempotencyKey: "transition-completed-effect-test",
      from: "merge-gate",
      to: "completed",
      actorRole: "flow",
      ...decisionIdentity(completed, "flow"),
      candidateTree: completed.workflow.candidate.tree,
    });
    completed.workflow.audit.push(completion.audit);
    updateDecisionHead(completed, completion.audit.authentication);
    completed.workflow.state = completion.nextState;
    completed.activeRole = "principal-developer";
    rehash(completed);
    expect(validateDeliveryAuthorityContract(completed).valid).toBe(true);
    expect(
      authorizeDeliveryEffect(completed, {
        effect: "edit",
        idempotencyKey: "post-completion-edit",
        actorRole: "principal-developer",
        ...decisionIdentity(completed, "principal-developer"),
        targetTree: completed.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });

    completed.activeRole = "flow";
    rehash(completed);
    expect(
      authorizeDeliveryEffect(completed, {
        effect: "feature-push",
        idempotencyKey: "post-completion-push",
        actorRole: "flow",
        ...decisionIdentity(completed, "flow"),
        targetTree: completed.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "publication-denied" });

    const exhausted = clone();
    exhausted.autonomy.usage.implementationAttempts =
      exhausted.autonomy.limits.implementationAttempts;
    setState(exhausted, "ready", "implementation");
    expect(
      authorizeDeliveryEffect(exhausted, {
        effect: "edit",
        idempotencyKey: "final-implementation-attempt-edit",
        actorRole: "principal-developer",
        ...decisionIdentity(exhausted, "principal-developer"),
        targetTree: exhausted.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: true, code: "accepted" });

    const unstartedRepair = clone();
    unstartedRepair.workflow.observations.ci = "failed";
    setState(unstartedRepair, "pr-ci-monitoring", "repair-required");
    expect(
      authorizeDeliveryEffect(unstartedRepair, {
        effect: "edit",
        idempotencyKey: "unstarted-repair-edit",
        actorRole: "principal-developer",
        ...decisionIdentity(unstartedRepair, "principal-developer"),
        targetTree: unstartedRepair.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });

    const ciExhausted = clone();
    ciExhausted.workflow.observations.ci = "not-started";
    ciExhausted.autonomy.usage.ciRepairAttempts =
      ciExhausted.autonomy.limits.ciRepairAttempts;
    ciExhausted.autonomy.usage.verificationRepairAttempts = 0;
    setState(ciExhausted, "pr-ci-monitoring", "repair-required");
    expect(
      authorizeDeliveryEffect(ciExhausted, {
        effect: "edit",
        idempotencyKey: "exhausted-ci-edit",
        actorRole: "principal-developer",
        ...decisionIdentity(ciExhausted, "principal-developer"),
        targetTree: ciExhausted.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });
    expect(
      evaluateDeliveryTransition(ciExhausted, {
        eventId: "exhausted-ci-transition",
        idempotencyKey: "exhausted-ci-transition",
        from: "repair-required",
        to: "implementation",
        actorRole: "principal-developer",
        ...decisionIdentity(ciExhausted, "principal-developer"),
        candidateTree: ciExhausted.workflow.candidate.tree,
      }),
    ).toMatchObject({ accepted: false, code: "autonomy-exhausted" });

    const rewrittenUsage = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    rewrittenUsage.workflow.audit = [];
    rewrittenUsage.workflow.state = "implementation";
    rewrittenUsage.workflow.checkpoint.state = "implementation";
    rewrittenUsage.workflow.checkpoint.activeRepairBudget = "ci";
    rewrittenUsage.evidence[0]!.freshThroughEventId =
      rewrittenUsage.workflow.checkpoint.checkpointId;
    rewrittenUsage.autonomy.usage.ciRepairAttempts =
      rewrittenUsage.autonomy.limits.ciRepairAttempts;
    rewrittenUsage.workflow.checkpoint.attemptUsage.ciRepairAttempts =
      rewrittenUsage.autonomy.limits.ciRepairAttempts;
    rehash(rewrittenUsage);
    rewrittenUsage.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(rewrittenUsage.evidence),
    );
    const rewrittenUsageRequest = {
      effect: "edit" as const,
      idempotencyKey: "rewritten-usage-edit",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(rewrittenUsage, "principal-developer"),
      targetTree: rewrittenUsage.workflow.candidate.tree,
      observedAt: nextDecisionTimestamp(rewrittenUsage),
    };
    rewrittenUsage.meteringObservedAt = rewrittenUsageRequest.observedAt;
    rewrittenUsage.meteringDigest =
      computeDeliveryMeteringDigest(rewrittenUsage);
    rewrittenUsage.controllerStateDigest =
      computeDeliveryControllerStateDigest(rewrittenUsage);
    const exhaustedAuthority = rewrittenUsage.authorityDigest;
    const exhaustedMetering = rewrittenUsage.meteringDigest;
    const exhaustedControllerState = rewrittenUsage.controllerStateDigest;
    expect(validateDeliveryAuthorityContract(rewrittenUsage).valid).toBe(true);
    expect(
      authorizeDeliveryEffectWithAnchor(
        rewrittenUsage,
        rewrittenUsageRequest,
        exhaustedAuthority,
        exhaustedMetering,
        exhaustedControllerState,
      ),
    ).toMatchObject({ allowed: true, code: "accepted" });
    rewrittenUsage.autonomy.usage.ciRepairAttempts = 0;
    expect(
      authorizeDeliveryEffectWithAnchor(
        rewrittenUsage,
        rewrittenUsageRequest,
        exhaustedAuthority,
        exhaustedMetering,
        exhaustedControllerState,
      ),
    ).toMatchObject({ allowed: false, code: "contract-invalid" });

    const truncatedCiRepair = clone();
    truncatedCiRepair.workflow.observations.ci = "failed";
    truncatedCiRepair.autonomy.usage.ciRepairAttempts =
      truncatedCiRepair.autonomy.limits.ciRepairAttempts;
    truncatedCiRepair.autonomy.usage.verificationRepairAttempts = 0;
    setState(truncatedCiRepair, "repair-required", "implementation");
    truncatedCiRepair.workflow.observations.ci = "not-started";
    rehash(truncatedCiRepair);
    expect(
      authorizeDeliveryEffect(truncatedCiRepair, {
        effect: "edit",
        idempotencyKey: "truncated-ci-repair-edit",
        actorRole: "principal-developer",
        ...decisionIdentity(truncatedCiRepair, "principal-developer"),
        targetTree: truncatedCiRepair.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: true, code: "accepted" });

    const expired = structuredClone(flowExample) as DeliveryAuthorityContract;
    expired.autonomy.usage.elapsedMinutes =
      expired.autonomy.limits.durationMinutes;
    rehash(expired);
    for (const effect of [
      "feature-push",
      "pr-create-update",
      "publication",
    ] as const) {
      expect(
        authorizeDeliveryEffect(expired, {
          effect,
          idempotencyKey: `expired-${effect}`,
          actorRole: "flow",
          ...decisionIdentity(expired, "flow"),
          targetTree: expired.workflow.candidate.tree,
        }),
      ).toMatchObject({ allowed: false, code: "escalation-required" });
    }
  });

  it("freezes monotonic metering and sticky cancellation at the decision boundary", () => {
    const metered = structuredClone(
      principalExample,
    ) as DeliveryAuthorityContract;
    metered.workflow.audit = [];
    metered.workflow.state = "implementation";
    metered.workflow.checkpoint.state = "implementation";
    metered.evidence[0]!.freshThroughEventId =
      metered.workflow.checkpoint.checkpointId;
    metered.autonomy.usage.elapsedMinutes =
      metered.autonomy.limits.durationMinutes;
    rehash(metered);
    metered.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(metered.evidence),
    );
    const meteredAuthority = metered.authorityDigest;
    const meteredState = metered.meteringDigest;
    const meteredControllerState = metered.controllerStateDigest;
    metered.autonomy.usage.elapsedMinutes = 0;
    metered.meteringDigest = computeDeliveryMeteringDigest(metered);
    expect(computeDeliveryAuthorityDigest(metered)).toBe(meteredAuthority);
    expect(metered.meteringDigest).not.toBe(meteredState);
    expect(
      authorizeDeliveryEffectWithAnchor(
        metered,
        {
          effect: "edit",
          idempotencyKey: "rolled-back-elapsed-edit",
          actorRole: "principal-developer",
          ...decisionIdentity(metered, "principal-developer"),
          targetTree: metered.workflow.candidate.tree,
          observedAt: nextDecisionTimestamp(metered),
        },
        meteredAuthority,
        meteredState,
        meteredControllerState,
      ),
    ).toMatchObject({ allowed: false, code: "contract-invalid" });

    const cancelled = structuredClone(flowExample) as DeliveryAuthorityContract;
    cancelled.workflow.audit = [];
    cancelled.workflow.state = "blocked";
    cancelled.workflow.checkpoint.state = "blocked";
    cancelled.evidence[0]!.freshThroughEventId =
      cancelled.workflow.checkpoint.checkpointId;
    cancelled.autonomy.usage.cancelled = true;
    rehash(cancelled);
    cancelled.autonomy.usage.evidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(cancelled.evidence),
    );
    const cancelledAuthority = cancelled.authorityDigest;
    const cancelledState = cancelled.meteringDigest;
    const cancelledControllerState = cancelled.controllerStateDigest;
    cancelled.autonomy.usage.cancelled = false;
    cancelled.meteringDigest = computeDeliveryMeteringDigest(cancelled);
    expect(computeDeliveryAuthorityDigest(cancelled)).toBe(cancelledAuthority);
    expect(cancelled.meteringDigest).not.toBe(cancelledState);
    expect(
      evaluateDeliveryTransitionWithAnchor(
        cancelled,
        {
          eventId: "resume-after-cancellation-rollback",
          idempotencyKey: "resume-after-cancellation-rollback",
          from: "blocked",
          to: "ready",
          actorRole: "flow",
          ...decisionIdentity(cancelled, "flow"),
          candidateTree: cancelled.workflow.candidate.tree,
          observedAt: nextDecisionTimestamp(cancelled),
        },
        cancelledAuthority,
        cancelledState,
        cancelledControllerState,
      ),
    ).toMatchObject({ accepted: false, code: "contract-invalid" });
  });

  it("checks actual evidence bytes and bounds hostile contract collections", () => {
    const contract = clone();
    contract.autonomy.usage.evidenceBytes = 1;
    for (let index = 0; index < 20; index += 1) {
      const evidence = structuredClone(contract.evidence[0]!);
      evidence.evidenceId = `bulk-evidence-${String(index)}`;
      evidence.correlationId = `bulk-evidence-${String(index)}`;
      evidence.idempotencyKey = `bulk-evidence-${String(index)}`;
      evidence.pacaUpdateId = `bulk-evidence-${String(index)}`;
      evidence.evidenceDigest = computeDeliveryEvidenceDigest(evidence);
      contract.evidence.push(evidence);
    }
    rehash(contract);
    expectDenied(contract, "evidence-bytes");

    const collections = clone();
    collections.task.scope.included = Array.from(
      { length: 101 },
      (_, index) => `Included scope item ${String(index)}`,
    );
    rehash(collections);
    expectDenied(collections, "maxItems");
  });

  it("enforces autonomy limits and cancellation behavior", () => {
    for (const field of [
      "implementationAttempts",
      "verificationRepairAttempts",
      "ciRepairAttempts",
      "elapsedMinutes",
      "concurrentAgents",
      "worktrees",
      "evidenceBytes",
    ] as const) {
      const contract = clone();
      const limitField = field === "elapsedMinutes" ? "durationMinutes" : field;
      contract.autonomy.usage[field] = contract.autonomy.limits[limitField] + 1;
      rehash(contract);
      expectDenied(contract, "autonomy-limit-exhausted");
    }
    const cancelled = clone();
    cancelled.autonomy.usage.cancelled = true;
    rehash(cancelled);
    expectDenied(cancelled, "cancellation-state");

    const cancelledBlocked = structuredClone(
      flowExample,
    ) as DeliveryAuthorityContract;
    setState(cancelledBlocked, "ready", "blocked");
    cancelledBlocked.autonomy.usage.cancelled = true;
    rehash(cancelledBlocked);
    expect(
      evaluateDeliveryTransition(cancelledBlocked, {
        eventId: "event-cancelled-resume",
        idempotencyKey: "transition-cancelled-resume",
        from: "blocked",
        to: "ready",
        actorRole: "flow",
        ...decisionIdentity(cancelledBlocked, "flow"),
        candidateTree: cancelledBlocked.workflow.candidate.tree,
      }),
    ).toMatchObject({ accepted: false, code: "transition-denied" });
  });

  it("denies decision-time reuse from another idempotency namespace", () => {
    const contract = structuredClone(flowExample) as DeliveryAuthorityContract;
    const reusedKey = contract.evidence[0]!.idempotencyKey;
    expect(
      authorizeDeliveryEffect(contract, {
        effect: "feature-push",
        idempotencyKey: reusedKey,
        actorRole: "flow",
        ...decisionIdentity(contract, "flow"),
        targetTree: contract.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "idempotency-conflict" });
    expect(
      evaluateDeliveryTransition(contract, {
        eventId: "cross-namespace-transition",
        idempotencyKey: reusedKey,
        from: "publication-authorized",
        to: "pr-ci-monitoring",
        actorRole: "flow",
        ...decisionIdentity(contract, "flow"),
        candidateTree: contract.workflow.candidate.tree,
      }),
    ).toMatchObject({ accepted: false, code: "idempotency-conflict" });

    setState(contract, "publication-authorized", "blocked");
    expect(
      evaluateAdministrativeRecovery(contract, {
        recoveryId: "cross-namespace-recovery",
        kind: "canonical-digest-refetch",
        idempotencyKey: reusedKey,
        actorRole: "flow",
        ...decisionIdentity(contract, "flow"),
        identityRevalidated: true,
        targetGate: "administrative",
      }),
    ).toMatchObject({ allowed: false, code: "idempotency-conflict" });
  });

  it("uses one idempotency namespace across transitions, effects, recoveries, grants, and evidence", () => {
    const contract = clone();
    contract.administrativeRecoveries.push({
      authentication: null,
      recoveryId: "cross-domain-recovery",
      kind: "canonical-digest-refetch",
      idempotencyKey: contract.workflow.audit[0]!.idempotencyKey,
      requestDigest: "a".repeat(64),
      details: recoveryDetails(contract, "canonical-digest-refetch"),
      identityRevalidated: true,
      targetGate: "administrative",
      ...recoveryIdentity(contract),
      workflowState: contract.workflow.state,
      ciStatus: contract.workflow.observations.ci,
      accepted: true,
      code: "accepted",
      observedAt: "2026-08-25T23:00:00.000Z",
    });
    rehash(contract);
    expectDenied(contract, "type");
  });

  it("rejects contradictory persisted decisions for one idempotency key", () => {
    const contract = clone();
    const request = {
      effect: "paca-status-update" as const,
      idempotencyKey: "contradictory-effect-decision",
      actorRole: "principal-developer" as const,
      ...decisionIdentity(contract, "principal-developer"),
      targetTree: contract.workflow.candidate.tree,
    };
    const accepted = authorizeDeliveryEffect(contract, request).audit;
    contract.effectAudit.push(
      { ...accepted, allowed: false, code: "role-authority-denied" },
      accepted,
    );
    rehash(contract);
    expectDenied(contract, "idempotency-conflict");
  });

  it.each(MANDATORY_ESCALATION_REASONS)(
    "requires escalated or blocked state for %s",
    (reason) => {
      const contract = clone();
      contract.activeEscalations = [reason];
      rehash(contract);
      expectDenied(contract, "mandatory-escalation");
      contract.activeEscalations = [];
      setState(contract, "ready", "escalated");
      contract.activeEscalations = [reason];
      rehash(contract);
      const validation = validateDeliveryAuthorityContract(contract);
      expect(
        validation.valid,
        validation.valid ? "valid" : JSON.stringify(validation.errors),
      ).toBe(true);
    },
  );

  it("covers every denied boundary with an executable mutation fixture", () => {
    const operations = new Set(
      boundaryFixtures.map((fixture) => fixture.operation),
    );
    expect(operations).toEqual(
      new Set([
        "identity-drift",
        "dirty-worktree",
        "verifier-modified-candidate",
        "candidate-changed-after-approval",
        "unknown-security-assurance-elevation",
        "credential-scope-expansion",
        "destructive-or-production-effect",
        "autonomy-limit-exhausted",
        "unsafe-authority-path",
        "remote-main-drift",
        "pr-head-drift",
        "missing-stakeholder-merge-grant",
        "recovery-security-bypass",
      ]),
    );
    for (const fixture of boundaryFixtures) {
      const contract = clone();
      switch (fixture.operation) {
        case "identity-drift":
          contract.roles.flow.actorId = contract.roles.product.actorId;
          break;
        case "dirty-worktree":
          contract.workflow.observations.worktree = "dirty-unexpected";
          break;
        case "verifier-modified-candidate":
          contract.workflow.observations.verifierCandidate = "modified";
          break;
        case "unknown-security-assurance-elevation":
          contract.workflow.observations.security = "unknown";
          break;
        case "credential-scope-expansion":
          contract.workflow.observations.credentialScope = "expanded";
          break;
        case "candidate-changed-after-approval":
          contract.workflow.candidate.tree = "a".repeat(40);
          break;
        case "destructive-or-production-effect":
          contract.requestedEffects = ["production"];
          break;
        case "autonomy-limit-exhausted":
          contract.autonomy.usage.implementationAttempts =
            contract.autonomy.limits.implementationAttempts + 1;
          break;
        case "unsafe-authority-path":
          contract.task.repository.root = "/home/operator/work/../private";
          break;
        case "remote-main-drift":
          contract.workflow.candidate.remoteBase.observedCommit = "a".repeat(
            40,
          );
          break;
        case "pr-head-drift":
          contract.workflow.candidate.pullRequest.observedHeadCommit =
            "a".repeat(40);
          break;
        case "missing-stakeholder-merge-grant":
          contract.workflow.state = "merge-gate";
          break;
        case "recovery-security-bypass":
          contract.administrativeRecoveries.push({
            authentication: null,
            recoveryId: "recovery-security-bypass",
            kind: "canonical-digest-refetch",
            idempotencyKey: "recovery-security-bypass-key",
            requestDigest: "a".repeat(64),
            details: recoveryDetails(contract, "canonical-digest-refetch"),
            identityRevalidated: true,
            targetGate: "security",
            ...recoveryIdentity(contract),
            workflowState: contract.workflow.state,
            ciStatus: contract.workflow.observations.ci,
            accepted: true,
            code: "accepted",
            observedAt: "2026-08-25T23:00:00.000Z",
          });
          break;
        default:
          throw new Error("unknown denied-boundary fixture operation");
      }
      rehash(contract);
      expect(
        validateDeliveryAuthorityContract(contract).valid,
        fixture.operation,
      ).toBe(false);
    }
  });

  it("rejects unsafe authority paths and credential-shaped content with fixed redacted diagnostics", () => {
    const unsafe = clone();
    unsafe.task.repository.root = "/home/operator/work/../private";
    rehash(unsafe);
    expectDenied(unsafe, "pattern");

    const suspected = `sk-proj-${"SENSITIVEVALUEDONOTECHO".repeat(2)}`;
    const credential = clone();
    credential.task.paca.taskId = suspected;
    rehash(credential);
    const result = validateDeliveryAuthorityContract(credential);
    expect(result.valid).toBe(false);
    expect(JSON.stringify(result)).not.toContain(suspected);
    if (!result.valid)
      expect(result.errors).toContainEqual({
        path: "/task/paca/taskId",
        code: "credential-shaped",
        message: "must not contain credential-shaped content",
      });
  });

  it("fails malformed and hostile decision requests closed without coercion", () => {
    const contract = clone();
    const marker = ["PASSWORD", "HOSTILE_REQUEST_DO_NOT_ECHO"].join("=");
    const hostileRequest = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error(marker);
        },
      },
    );
    for (const request of [{}, hostileRequest]) {
      expect(evaluateDeliveryTransition(contract, request)).toMatchObject({
        accepted: false,
        code: "contract-invalid",
      });
      expect(authorizeDeliveryEffect(contract, request)).toMatchObject({
        allowed: false,
        code: "contract-invalid",
      });
      expect(evaluateAdministrativeRecovery(contract, request)).toMatchObject({
        allowed: false,
        code: "contract-invalid",
      });
    }
  });

  it("fails hostile object boundaries closed without attacker material", () => {
    const marker = ["PASSWORD", "HOSTILE_DO_NOT_ECHO"].join("=");
    const hostile = clone();
    Object.defineProperty(hostile.task, "scope", {
      enumerable: true,
      get() {
        throw new Error(marker);
      },
    });
    const proxied = new Proxy(clone(), {
      ownKeys() {
        throw new Error(marker);
      },
    });
    for (const input of [hostile, proxied]) {
      const result = validateDeliveryAuthorityContract(input);
      expect(result).toEqual({
        valid: false,
        errors: [
          {
            path: "/",
            code: "input-introspection",
            message: "delivery authority input could not be safely inspected",
          },
        ],
      });
      expect(JSON.stringify(result)).not.toContain(marker);
      expect(evaluateDeliveryTransition(input, {})).toMatchObject({
        accepted: false,
        code: "contract-invalid",
      });
      expect(authorizeDeliveryEffect(input, {})).toMatchObject({
        allowed: false,
        code: "contract-invalid",
      });
      expect(evaluateAdministrativeRecovery(input, {})).toMatchObject({
        allowed: false,
        code: "contract-invalid",
      });
    }
  });
});

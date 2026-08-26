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
  authorizeDeliveryEffect,
  computeDeliveryAuthorityDigest,
  computeDeliveryEvidenceDigest,
  evaluateAdministrativeRecovery,
  evaluateDeliveryTransition,
  validateDeliveryAuthorityContract,
  type DeliveryAuthorityContract,
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

function rehash(contract: DeliveryAuthorityContract): void {
  for (const evidence of contract.evidence as DeliveryEvidence[]) {
    (evidence as { evidenceDigest: string }).evidenceDigest =
      computeDeliveryEvidenceDigest(evidence);
  }
  (contract as { authorityDigest: string }).authorityDigest =
    computeDeliveryAuthorityDigest(contract);
}

function expectDenied(contract: DeliveryAuthorityContract, code: string): void {
  const result = validateDeliveryAuthorityContract(contract);
  expect(result.valid).toBe(false);
  if (!result.valid)
    expect(result.errors.map((error) => error.code)).toContain(code);
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
          actorId: contract.roles.flow.actorId,
          targetTree: contract.workflow.candidate.tree,
        }).allowed,
      ).toBe(false);
    }
  });

  it("requires distinct stakeholder merge authority and distinct grants for release, production, destructive Git, and real Pi", () => {
    const merge = clone();
    merge.workflow.state = "merge-gate";
    rehash(merge);
    expectDenied(merge, "missing-effect-grant");

    for (const effect of DISTINCT_GRANT_EFFECTS) {
      const contract = clone();
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
          idempotencyKey: `effect-${effect}`,
          actorRole: "flow",
          actorId: contract.roles.flow.actorId,
          targetTree: contract.workflow.candidate.tree,
        }).allowed,
      ).toBe(true);
    }
  });

  it("allows automatic actions but gates feature publication on exact-tree approval", () => {
    const contract = clone();
    for (const effect of AUTOMATIC_DELIVERY_ACTIONS) {
      const actorRole =
        effect === "independent-verification"
          ? ("independent-verifier" as const)
          : (
                [
                  "feature-push",
                  "pr-create-update",
                  "administrative-recovery",
                ] as const
              ).includes(
                effect as
                  | "feature-push"
                  | "pr-create-update"
                  | "administrative-recovery",
              )
            ? ("flow" as const)
            : ("principal-developer" as const);
      expect(
        authorizeDeliveryEffect(contract, {
          effect,
          idempotencyKey: `automatic-${effect}`,
          actorRole,
          actorId: contract.roles[actorRole].actorId,
          targetTree: contract.workflow.candidate.tree,
        }).allowed,
      ).toBe(true);
    }
    expect(
      authorizeDeliveryEffect(contract, {
        effect: "edit",
        idempotencyKey: "verifier-edit-denied",
        actorRole: "independent-verifier",
        actorId: contract.roles["independent-verifier"].actorId,
        targetTree: contract.workflow.candidate.tree,
      }),
    ).toMatchObject({ allowed: false, code: "role-authority-denied" });
    for (const effect of HUMAN_GATED_DELIVERY_ACTIONS) {
      expect(AUTOMATIC_DELIVERY_ACTIONS).not.toContain(effect);
    }

    contract.workflow.state = "implementation";
    rehash(contract);
    for (const effect of ["feature-push", "pr-create-update"] as const) {
      expect(
        authorizeDeliveryEffect(contract, {
          effect,
          idempotencyKey: `preapproval-${effect}`,
          actorRole: "principal-developer",
          actorId: contract.roles["principal-developer"].actorId,
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
      actorId: effect.roles["principal-developer"].actorId,
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

  it("enforces the workflow state machine and records rejected controller events auditably", () => {
    const contract = clone();
    contract.workflow.state = "implementation";
    rehash(contract);

    const accepted = evaluateDeliveryTransition(contract, {
      eventId: "event-review",
      idempotencyKey: "transition-review",
      from: "implementation",
      to: "internal-review",
      actorRole: "principal-developer",
      actorId: contract.roles["principal-developer"].actorId,
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
      actorId: contract.roles["principal-developer"].actorId,
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

  it("makes repeated effects and transitions idempotent while rejecting key collisions", () => {
    const contract = clone();
    contract.workflow.state = "implementation";
    const request = {
      eventId: "event-review",
      idempotencyKey: "same-transition",
      from: "implementation" as const,
      to: "internal-review" as const,
      actorRole: "principal-developer" as const,
      actorId: contract.roles["principal-developer"].actorId,
      candidateTree: contract.workflow.candidate.tree,
    };
    const first = evaluateDeliveryTransition(contract, request);
    contract.workflow.audit.push(first.audit);
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
      actorId: contract.roles["principal-developer"].actorId,
      targetTree: contract.workflow.candidate.tree,
    };
    const effect = authorizeDeliveryEffect(contract, effectRequest);
    contract.effectAudit.push(effect.audit);
    rehash(contract);
    expect(authorizeDeliveryEffect(contract, effectRequest)).toMatchObject({
      allowed: true,
      idempotent: true,
    });
    expect(
      authorizeDeliveryEffect(contract, { ...effectRequest, effect: "build" }),
    ).toMatchObject({ allowed: false, code: "idempotency-conflict" });
  });

  it("allows only administrative recovery after identity revalidation and cannot bypass protected gates", () => {
    const contract = clone();
    for (const kind of ADMINISTRATIVE_RECOVERY_KINDS) {
      expect(
        evaluateAdministrativeRecovery(contract, {
          recoveryId: `recovery-${kind}`,
          kind,
          idempotencyKey: `recovery-key-${kind}`,
          identityRevalidated: true,
          targetGate: "administrative",
        }),
      ).toMatchObject({ allowed: true, code: "accepted" });
    }
    expect(
      evaluateAdministrativeRecovery(contract, {
        recoveryId: "recovery-unsafe",
        kind: "canonical-digest-refetch",
        idempotencyKey: "recovery-unsafe",
        identityRevalidated: true,
        targetGate: "security",
      }),
    ).toMatchObject({ allowed: false, code: "recovery-gate-denied" });
    expect(
      evaluateAdministrativeRecovery(contract, {
        recoveryId: "recovery-drift",
        kind: "canonical-digest-refetch",
        idempotencyKey: "recovery-drift",
        identityRevalidated: false,
        targetGate: "administrative",
      }),
    ).toMatchObject({ allowed: false, code: "identity-not-revalidated" });

    const request = {
      recoveryId: "recovery-repeat",
      kind: "interrupted-ci-polling" as const,
      idempotencyKey: "recovery-repeat-key",
      identityRevalidated: true,
      targetGate: "administrative" as const,
    };
    const first = evaluateAdministrativeRecovery(contract, request);
    contract.administrativeRecoveries.push(first.audit);
    rehash(contract);
    expect(evaluateAdministrativeRecovery(contract, request)).toMatchObject({
      allowed: true,
      idempotent: true,
    });
    expect(
      evaluateAdministrativeRecovery(contract, {
        ...request,
        kind: "canonical-digest-refetch",
      }),
    ).toMatchObject({ allowed: false, code: "idempotency-conflict" });
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
  });

  it.each(MANDATORY_ESCALATION_REASONS)(
    "requires escalated or blocked state for %s",
    (reason) => {
      const contract = clone();
      contract.activeEscalations = [reason];
      rehash(contract);
      expectDenied(contract, "mandatory-escalation");
      contract.workflow.state = "escalated";
      rehash(contract);
      expect(validateDeliveryAuthorityContract(contract).valid).toBe(true);
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
        case "verifier-modified-candidate":
        case "unknown-security-assurance-elevation":
        case "credential-scope-expansion":
          contract.activeEscalations = [
            fixture.escalationReason as DeliveryAuthorityContract["activeEscalations"][number],
          ];
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
            recoveryId: "recovery-security-bypass",
            kind: "canonical-digest-refetch",
            idempotencyKey: "recovery-security-bypass-key",
            identityRevalidated: true,
            targetGate: "security",
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

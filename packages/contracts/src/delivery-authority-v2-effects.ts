import {
  sameDeliveryV2Value,
  snapshotDeliveryV2Input,
} from "./delivery-authority-v2-input.js";
import {
  validateFrozenDeliveryAuthorityContractV2,
  type DeliveryAuthorityContractV2,
  type DeliveryIdentityV2,
  type TrustedDeliveryInputsV2,
  type DeliveryAuthorityV2State,
} from "./delivery-authority-v2.js";
export const DELIVERY_EFFECT_KINDS_V2 = [
  "prepare-branch-worktree",
  "launch-principal",
  "launch-verifier",
  "test",
  "build",
  "record-evidence",
  "push-feature",
  "create-update-pr",
  "poll-ci",
  "update-paca",
  "cleanup",
  "merge",
] as const;
export const DELIVERY_RECOVERY_KINDS_V2 = [
  "redundant-assurance-downgrade",
  "missing-keep-branch-choice",
  "repair-order-correction",
  "completed-repair-missing-receipt",
  "stale-evidence-regeneration",
  "canonical-digest-retransmission",
  "disappeared-product",
  "disappeared-flow",
  "disappeared-principal",
  "disappeared-verifier",
  "already-completed-feature-push",
  "already-created-or-updated-pr",
  "interrupted-ci-polling",
  "interrupted-paca-update",
  "cancellation-cleanup",
] as const;
interface EffectRequest {
  kind: string;
  identity: DeliveryIdentityV2;
  idempotencyKey: string;
  requestDigest: string;
  preconditionDigest: string;
  postconditionDigest: string;
  remainingBudget: number;
}
interface PriorEffect {
  idempotencyKey: string;
  requestDigest: string;
  outcome: "accepted" | "rejected" | "unknown";
  postcondition: "applied" | "not-applied" | "unknown";
}
const effectPolicy: Record<
  string,
  {
    roles: readonly DeliveryIdentityV2["role"][];
    states: readonly DeliveryAuthorityV2State[];
    meter?: "concurrentAgents" | "worktrees" | "evidenceBytes";
  }
> = {
  "prepare-branch-worktree": {
    roles: ["flow", "controller"],
    states: ["ready", "implementation"],
    meter: "worktrees",
  },
  "launch-principal": {
    roles: ["flow", "controller"],
    states: ["implementation", "repair-required"],
    meter: "concurrentAgents",
  },
  "launch-verifier": {
    roles: ["flow", "controller"],
    states: ["independent-verification"],
    meter: "concurrentAgents",
  },
  test: {
    roles: ["principal-developer", "independent-verifier"],
    states: [
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
    ],
  },
  build: {
    roles: ["principal-developer"],
    states: ["implementation", "repair-required"],
  },
  "record-evidence": {
    roles: ["flow", "controller", "independent-verifier"],
    states: [
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
      "published",
      "ci-monitoring",
    ],
    meter: "evidenceBytes",
  },
  "push-feature": {
    roles: ["flow", "controller"],
    states: ["publication-authorized"],
  },
  "create-update-pr": { roles: ["flow", "controller"], states: ["published"] },
  "poll-ci": { roles: ["flow", "controller"], states: ["ci-monitoring"] },
  "update-paca": {
    roles: ["flow", "controller"],
    states: [
      "published",
      "ci-monitoring",
      "merge-gate",
      "post-merge-verification",
    ],
    meter: "evidenceBytes",
  },
  cleanup: {
    roles: ["flow", "controller"],
    states: ["cancelling", "cancelled", "escalated"],
  },
  merge: { roles: ["stakeholder"], states: ["merge-gate"] },
};
const denied = (code: string) => ({
  allowed: false as const,
  code,
  executable: false as const,
});
export function evaluateDeliveryEffectV2(
  contractInput: unknown,
  requestInput: unknown,
  trustedInput: unknown,
  historyInput: unknown,
) {
  const rs = snapshotDeliveryV2Input(requestInput),
    ts = snapshotDeliveryV2Input(trustedInput),
    hs = snapshotDeliveryV2Input(historyInput);
  if (!rs.ok || !ts.ok || !hs.ok)
    return denied(
      !rs.ok
        ? rs.code
        : !ts.ok
          ? ts.code
          : hs.ok
            ? "input-introspection"
            : hs.code,
    );
  const request = rs.value as EffectRequest,
    trusted = ts.value as TrustedDeliveryInputsV2,
    history = hs.value as PriorEffect[];
  const valid = validateFrozenDeliveryAuthorityContractV2(
    contractInput,
    trusted,
  );
  if (!valid.valid) return denied("contract-invalid");
  const c = valid.value;
  if (c.cancelled || c.state === "cancelling" || c.state === "cancelled")
    return denied("cancelled");
  if (!sameDeliveryV2Value(request.identity, c.identity))
    return denied("identity-drift");
  if (!Array.isArray(history)) return denied("history-invalid");
  const prior = history.find(
    (x) => x.idempotencyKey === request.idempotencyKey,
  );
  if (prior) {
    if (prior.requestDigest !== request.requestDigest)
      return denied("idempotency-conflict");
    if (prior.outcome === "unknown" || prior.postcondition === "unknown")
      return denied("reconciliation-required");
    return {
      allowed: false as const,
      code: "idempotent-replay" as const,
      executable: false as const,
      priorResult: prior,
    };
  }
  const policy = effectPolicy[request.kind];
  if (!policy) return denied("effect-denied");
  if (!policy.roles.includes(request.identity.role))
    return denied("role-authority-denied");
  if (!policy.states.includes(c.state)) return denied("effect-state-denied");
  if (
    !Number.isSafeInteger(request.remainingBudget) ||
    request.remainingBudget <= 0
  )
    return denied("autonomy-exhausted");
  if (policy.meter && c.usage[policy.meter] >= c.limits[policy.meter])
    return denied("autonomy-exhausted");
  return {
    allowed: true as const,
    code: "accepted" as const,
    executable: true as const,
    intent: request,
  };
}
interface RecoveryRequest {
  kind: string;
  suspendedState: DeliveryAuthorityV2State;
  identity: DeliveryIdentityV2;
  idempotencyKey: string;
  boundaryId: string;
  boundaryConsumed: boolean;
  authenticatedBoundary: boolean;
  identityRevalidated: boolean;
  immutableIdentity: DeliveryIdentityV2;
  worktreeClean: boolean;
  evidenceIds: string[];
  staleEvidenceIds: string[];
  remainingAttempts: number;
  requestedResumeState: DeliveryAuthorityV2State;
}
const recoveryPolicy: Record<
  string,
  {
    states: readonly DeliveryAuthorityV2State[];
    resume: (s: DeliveryAuthorityV2State) => DeliveryAuthorityV2State;
    required: number;
    stale: boolean;
    clear: boolean;
  }
> = {
  "redundant-assurance-downgrade": {
    states: [
      "ready",
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
      "publication-authorized",
      "published",
      "ci-monitoring",
      "merge-gate",
      "post-merge-verification",
    ],
    resume: (s) => s,
    required: 2,
    stale: false,
    clear: false,
  },
  "missing-keep-branch-choice": {
    states: ["implementation"],
    resume: (s) => s,
    required: 3,
    stale: false,
    clear: false,
  },
  "repair-order-correction": {
    states: ["repair-required"],
    resume: (s) => s,
    required: 3,
    stale: true,
    clear: true,
  },
  "completed-repair-missing-receipt": {
    states: ["repair-required"],
    resume: (s) => s,
    required: 3,
    stale: true,
    clear: true,
  },
  "stale-evidence-regeneration": {
    states: [
      "ready",
      "internal-review",
      "independent-verification",
      "publication-authorized",
      "published",
      "ci-monitoring",
      "merge-gate",
      "post-merge-verification",
    ],
    resume: (s) =>
      s === "ci-monitoring"
        ? "published"
        : s === "merge-gate"
          ? "ci-monitoring"
          : s === "publication-authorized"
            ? "independent-verification"
            : s,
    required: 3,
    stale: true,
    clear: true,
  },
  "canonical-digest-retransmission": {
    states: [
      "intake",
      "ready",
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
      "publication-authorized",
      "published",
      "ci-monitoring",
      "merge-gate",
      "post-merge-verification",
    ],
    resume: (s) => s,
    required: 3,
    stale: false,
    clear: false,
  },
  "disappeared-product": {
    states: ["intake"],
    resume: (s) => s,
    required: 2,
    stale: true,
    clear: false,
  },
  "disappeared-flow": {
    states: [
      "intake",
      "ready",
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
      "publication-authorized",
      "published",
      "ci-monitoring",
      "merge-gate",
      "post-merge-verification",
    ],
    resume: (s) => s,
    required: 2,
    stale: true,
    clear: false,
  },
  "disappeared-principal": {
    states: ["implementation", "repair-required"],
    resume: (s) => s,
    required: 3,
    stale: true,
    clear: true,
  },
  "disappeared-verifier": {
    states: ["independent-verification"],
    resume: () => "independent-verification",
    required: 3,
    stale: true,
    clear: true,
  },
  "already-completed-feature-push": {
    states: ["publication-authorized"],
    resume: () => "published",
    required: 2,
    stale: false,
    clear: false,
  },
  "already-created-or-updated-pr": {
    states: ["published"],
    resume: () => "ci-monitoring",
    required: 2,
    stale: false,
    clear: false,
  },
  "interrupted-ci-polling": {
    states: ["ci-monitoring"],
    resume: (s) => s,
    required: 2,
    stale: true,
    clear: false,
  },
  "interrupted-paca-update": {
    states: [
      "published",
      "ci-monitoring",
      "merge-gate",
      "post-merge-verification",
    ],
    resume: (s) => s,
    required: 2,
    stale: true,
    clear: false,
  },
  "cancellation-cleanup": {
    states: ["cancelling"],
    resume: () => "cancelled",
    required: 3,
    stale: true,
    clear: true,
  },
};
export const DELIVERY_RECOVERY_EVIDENCE_V2: Record<string, readonly string[]> =
  {
    "redundant-assurance-downgrade": [
      "effective-assurance-profile",
      "rejected-downgrade-event",
    ],
    "missing-keep-branch-choice": [
      "principal-terminal-result",
      "clean-implementation-worktree",
      "authenticated-finish-choice",
    ],
    "repair-order-correction": [
      "ordered-findings",
      "clean-implementation-worktree",
      "rejected-order-event",
    ],
    "completed-repair-missing-receipt": [
      "clean-implementation-worktree",
      "principal-terminal-evidence",
      "missing-receipt-event",
    ],
    "stale-evidence-regeneration": [
      "staling-event",
      "stale-evidence-set",
      "current-immutable-identity",
    ],
    "canonical-digest-retransmission": [
      "canonical-source",
      "trusted-expected-digest",
      "failed-transmission-event",
    ],
    "disappeared-product": [
      "authoritative-absence",
      "no-accepted-product-result",
    ],
    "disappeared-flow": [
      "authoritative-absence",
      "last-accepted-controller-event",
    ],
    "disappeared-principal": [
      "authoritative-absence",
      "clean-implementation-worktree",
      "candidate-status",
    ],
    "disappeared-verifier": [
      "authoritative-absence",
      "exact-candidate",
      "isolated-verifier-workspace",
    ],
    "already-completed-feature-push": [
      "authenticated-remote-ref",
      "original-effect-request",
    ],
    "already-created-or-updated-pr": [
      "authenticated-pr-observation",
      "original-effect-request",
    ],
    "interrupted-ci-polling": [
      "authenticated-ci-cursor",
      "required-check-policy",
    ],
    "interrupted-paca-update": [
      "original-cas-request",
      "authenticated-paca-observation",
    ],
    "cancellation-cleanup": [
      "processes-absent",
      "writers-closed",
      "resource-inventory-clean",
    ],
  };
export function evaluateDeliveryRecoveryV2(
  contractInput: unknown,
  requestInput: unknown,
  trustedInput: unknown,
) {
  const rs = snapshotDeliveryV2Input(requestInput),
    ts = snapshotDeliveryV2Input(trustedInput);
  if (!rs.ok || !ts.ok)
    return denied(!rs.ok ? rs.code : ts.ok ? "input-introspection" : ts.code);
  const r = rs.value as RecoveryRequest,
    t = ts.value as TrustedDeliveryInputsV2;
  const valid = validateFrozenDeliveryAuthorityContractV2(contractInput, t);
  if (!valid.valid) return denied("contract-invalid");
  const c = valid.value,
    p = recoveryPolicy[r.kind];
  if (
    !p ||
    r.suspendedState !== c.state ||
    !p.states.includes(c.state) ||
    r.identity.role !== "controller" ||
    r.identity.access !== "controller" ||
    r.boundaryConsumed ||
    !r.authenticatedBoundary ||
    !t.recoveryBoundary ||
    !sameDeliveryV2Value(t.recoveryBoundary, {
      boundaryId: r.boundaryId,
      idempotencyKey: r.idempotencyKey,
      kind: r.kind,
      suspendedState: r.suspendedState,
      consumed: false,
      identity: r.immutableIdentity,
    }) ||
    !r.identityRevalidated ||
    !sameDeliveryV2Value(r.immutableIdentity, t.identity) ||
    !r.worktreeClean ||
    !Array.isArray(r.evidenceIds) ||
    r.evidenceIds.length < p.required ||
    !(DELIVERY_RECOVERY_EVIDENCE_V2[r.kind] ?? []).every((item) =>
      r.evidenceIds.includes(item),
    ) ||
    !Number.isSafeInteger(r.remainingAttempts) ||
    r.remainingAttempts <= 0
  )
    return denied("recovery-denied");
  const resume = p.resume(c.state);
  if (r.requestedResumeState !== resume) return denied("phase-skip-denied");
  return {
    allowed: true as const,
    code: "accepted" as const,
    executable: false as const,
    boundaryConsumed: true,
    resumeState: resume,
    clearVerifierApproval: p.clear,
    regenerateEvidence: p.stale || r.staleEvidenceIds.length > 0,
  };
}
export type { DeliveryAuthorityContractV2 };

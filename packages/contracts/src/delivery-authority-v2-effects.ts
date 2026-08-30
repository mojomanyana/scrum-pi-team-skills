import {
  hasExactDeliveryV2Keys,
  isSha1DeliveryV2,
  isSha256DeliveryV2,
  sameDeliveryV2Value,
  snapshotDeliveryV2Input,
} from "./delivery-authority-v2-input.js";
import { isCanonicalLifecycleTimestamp } from "./lifecycle-receipt.js";
import {
  deliveryIdentityContextsMatchV2,
  isDeliveryIdentityV2,
  validateFrozenDeliveryAuthorityContractV2,
  type DeliveryAuthorityContractV2,
  type DeliveryIdentityV2,
  type TrustedDeliveryInputsV2,
  type TrustedMergeGrantV2,
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
  projectId?: string;
  taskId?: string;
  repositoryId?: string;
  runId?: string;
  pullRequest?: number;
  headBranch?: string;
  candidateCommit?: string;
  candidateTree?: string;
  mergeMethod?: "merge" | "squash" | "rebase";
  observedAt?: string;
}
interface PriorEffect {
  namespace: string;
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
const mergeGrantKeys = [
  "grantId",
  "projectId",
  "taskId",
  "repositoryId",
  "runId",
  "pullRequest",
  "headBranch",
  "candidateCommit",
  "candidateTree",
  "mergeMethod",
  "stakeholderIdentity",
  "notBefore",
  "expiresAt",
  "consumed",
];
const isValidMergeGrantV2 = (value: unknown): value is TrustedMergeGrantV2 => {
  if (!hasExactDeliveryV2Keys(value, mergeGrantKeys)) return false;
  const grant = value as TrustedMergeGrantV2;
  return (
    typeof grant.grantId === "string" &&
    grant.grantId.trim().length > 0 &&
    [
      grant.projectId,
      grant.taskId,
      grant.repositoryId,
      grant.runId,
      grant.headBranch,
    ].every((field) => typeof field === "string" && field.trim().length > 0) &&
    Number.isSafeInteger(grant.pullRequest) &&
    grant.pullRequest > 0 &&
    isSha1DeliveryV2(grant.candidateCommit) &&
    isSha1DeliveryV2(grant.candidateTree) &&
    ["merge", "squash", "rebase"].includes(grant.mergeMethod) &&
    isDeliveryIdentityV2(grant.stakeholderIdentity) &&
    grant.stakeholderIdentity.role === "stakeholder" &&
    isCanonicalLifecycleTimestamp(grant.notBefore) &&
    isCanonicalLifecycleTimestamp(grant.expiresAt) &&
    grant.notBefore < grant.expiresAt &&
    grant.consumed === false
  );
};
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
  const baseKeys = [
    "kind",
    "identity",
    "idempotencyKey",
    "requestDigest",
    "preconditionDigest",
    "postconditionDigest",
    "remainingBudget",
  ];
  const requestKeys =
    request.kind === "merge"
      ? [
          ...baseKeys,
          "projectId",
          "taskId",
          "repositoryId",
          "runId",
          "pullRequest",
          "headBranch",
          "candidateCommit",
          "candidateTree",
          "mergeMethod",
          "observedAt",
        ]
      : baseKeys;
  if (
    !hasExactDeliveryV2Keys(request, requestKeys) ||
    !isDeliveryIdentityV2(request.identity) ||
    typeof request.idempotencyKey !== "string" ||
    request.idempotencyKey.length === 0 ||
    ![
      request.requestDigest,
      request.preconditionDigest,
      request.postconditionDigest,
    ].every(isSha256DeliveryV2) ||
    !Number.isSafeInteger(request.remainingBudget)
  )
    return denied("request-invalid");
  if (
    (c.cancelled || c.state === "cancelling" || c.state === "cancelled") &&
    !(c.state === "cancelling" && request.kind === "cleanup")
  )
    return denied("cancelled");
  if (!sameDeliveryV2Value(request.identity, c.identity))
    return denied("identity-drift");
  if (request.kind === "merge" && !isValidMergeGrantV2(trusted.mergeGrant))
    return denied("merge-grant-required");
  if (!Array.isArray(history)) return denied("history-invalid");
  for (const entry of history)
    if (
      !hasExactDeliveryV2Keys(entry, [
        "namespace",
        "idempotencyKey",
        "requestDigest",
        "outcome",
        "postcondition",
      ]) ||
      typeof entry.namespace !== "string" ||
      entry.namespace.length === 0 ||
      typeof entry.idempotencyKey !== "string" ||
      !isSha256DeliveryV2(entry.requestDigest) ||
      !["accepted", "rejected", "unknown"].includes(entry.outcome) ||
      !["applied", "not-applied", "unknown"].includes(entry.postcondition)
    )
      return denied("history-invalid");
  const matches = history.filter(
    (x) =>
      x.namespace === "effect" && x.idempotencyKey === request.idempotencyKey,
  );
  if (matches.length > 1) return denied("history-ambiguous");
  const prior = matches[0];
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
  if (request.kind === "merge") {
    const grant = trusted.mergeGrant;
    if (
      !grant ||
      !isValidMergeGrantV2(grant) ||
      !sameDeliveryV2Value(grant.stakeholderIdentity, request.identity) ||
      !deliveryIdentityContextsMatchV2(
        c.identity,
        request.identity,
        grant.stakeholderIdentity,
      ) ||
      !isCanonicalLifecycleTimestamp(grant.notBefore) ||
      !isCanonicalLifecycleTimestamp(grant.expiresAt) ||
      grant.notBefore >= grant.expiresAt ||
      !(["merge", "squash", "rebase"] as unknown[]).includes(
        request.mergeMethod,
      ) ||
      !(["merge", "squash", "rebase"] as unknown[]).includes(
        grant.mergeMethod,
      ) ||
      typeof request.observedAt !== "string" ||
      !isCanonicalLifecycleTimestamp(request.observedAt) ||
      request.observedAt < grant.notBefore ||
      request.observedAt >= grant.expiresAt ||
      typeof trusted.trustedNow !== "string" ||
      !isCanonicalLifecycleTimestamp(trusted.trustedNow) ||
      trusted.trustedNow < grant.notBefore ||
      trusted.trustedNow >= grant.expiresAt ||
      request.observedAt > trusted.trustedNow ||
      request.projectId !== c.identity.projectId ||
      request.taskId !== c.identity.taskId ||
      request.repositoryId !== c.identity.repositoryId ||
      request.runId !== c.identity.runId ||
      request.headBranch !== c.identity.headBranch ||
      request.candidateCommit !== c.identity.candidateCommit ||
      request.candidateTree !== c.identity.candidateTree ||
      grant.projectId !== c.identity.projectId ||
      grant.taskId !== c.identity.taskId ||
      grant.repositoryId !== c.identity.repositoryId ||
      grant.runId !== c.identity.runId ||
      grant.headBranch !== c.identity.headBranch ||
      grant.candidateCommit !== c.identity.candidateCommit ||
      grant.candidateTree !== c.identity.candidateTree ||
      grant.projectId !== request.projectId ||
      grant.taskId !== request.taskId ||
      grant.runId !== request.runId ||
      grant.repositoryId !== request.repositoryId ||
      !Number.isSafeInteger(trusted.pullRequest) ||
      trusted.pullRequest !== request.pullRequest ||
      grant.pullRequest !== request.pullRequest ||
      grant.headBranch !== request.headBranch ||
      grant.candidateCommit !== request.candidateCommit ||
      grant.candidateTree !== request.candidateTree ||
      grant.mergeMethod !== request.mergeMethod ||
      !isSha1DeliveryV2(request.candidateCommit) ||
      !isSha1DeliveryV2(request.candidateTree)
    )
      return denied("merge-grant-required");
  }
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
  identity: DeliveryIdentityV2;
  idempotencyKey: string;
  boundaryId: string;
  boundaryConsumed: boolean;
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
    b = t.recoveryBoundary;
  const requestKeys = [
    "kind",
    "identity",
    "idempotencyKey",
    "boundaryId",
    "boundaryConsumed",
    "identityRevalidated",
    "immutableIdentity",
    "worktreeClean",
    "evidenceIds",
    "staleEvidenceIds",
    "remainingAttempts",
    "requestedResumeState",
  ];
  if (
    !hasExactDeliveryV2Keys(r, requestKeys) ||
    c.state !== "blocked" ||
    !b ||
    !hasExactDeliveryV2Keys(b, [
      "boundaryId",
      "idempotencyKey",
      "kind",
      "suspendedState",
      "candidate",
      "controllerRevision",
      "consumed",
      "identity",
      "controllerIdentity",
    ]) ||
    !isDeliveryIdentityV2(r.identity) ||
    !isDeliveryIdentityV2(r.immutableIdentity) ||
    !isDeliveryIdentityV2(b.controllerIdentity) ||
    !sameDeliveryV2Value(r.identity, b.controllerIdentity) ||
    !sameDeliveryV2Value(r.immutableIdentity, b.identity) ||
    !sameDeliveryV2Value(r.immutableIdentity, t.identity) ||
    !sameDeliveryV2Value(b.candidate, t.currentCandidate) ||
    b.controllerRevision !== t.controllerRevision ||
    b.boundaryId !== r.boundaryId ||
    b.idempotencyKey !== r.idempotencyKey ||
    b.kind !== r.kind ||
    b.consumed ||
    r.boundaryConsumed ||
    !r.identityRevalidated ||
    !r.worktreeClean ||
    !Array.isArray(r.evidenceIds) ||
    !Array.isArray(r.staleEvidenceIds) ||
    !Number.isSafeInteger(r.remainingAttempts) ||
    r.remainingAttempts <= 0
  )
    return denied("recovery-denied");
  const p = recoveryPolicy[b.kind];
  if (
    !p ||
    !p.states.includes(b.suspendedState) ||
    r.evidenceIds.length < p.required ||
    !(DELIVERY_RECOVERY_EVIDENCE_V2[b.kind] ?? []).every((item) =>
      r.evidenceIds.includes(item),
    )
  )
    return denied("recovery-denied");
  const resume = p.resume(b.suspendedState);
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

import { canonicalSerializeLifecycleValue } from "./lifecycle-receipt.js";
import {
  validateFrozenDeliveryAuthorityContractV2,
  type DeliveryAuthorityContractV2,
  type DeliveryIdentityV2,
  type TrustedDeliveryInputsV2,
} from "./delivery-authority-v2.js";
export const DELIVERY_EFFECT_KINDS_V2 = [
  "prepare-branch-worktree",
  "launch-principal",
  "launch-verifier",
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
  outcome: string;
}
const same = (a: unknown, b: unknown) => {
  try {
    return (
      canonicalSerializeLifecycleValue(a) ===
      canonicalSerializeLifecycleValue(b)
    );
  } catch {
    return false;
  }
};
export function evaluateDeliveryEffectV2(
  contract: unknown,
  request: EffectRequest,
  trusted: TrustedDeliveryInputsV2,
  history: PriorEffect[],
) {
  const valid = validateFrozenDeliveryAuthorityContractV2(contract, trusted);
  if (!valid.valid)
    return { allowed: false, code: "contract-invalid" as const };
  const c = valid.value;
  if (c.cancelled || c.state === "cancelling" || c.state === "cancelled")
    return { allowed: false, code: "cancelled" as const };
  if (!same(request.identity, c.identity))
    return { allowed: false, code: "identity-drift" as const };
  const prior = history.find(
    (x) => x.idempotencyKey === request.idempotencyKey,
  );
  if (prior)
    return prior.requestDigest === request.requestDigest
      ? {
          allowed: prior.outcome === "accepted",
          code: "idempotent-replay" as const,
        }
      : { allowed: false, code: "idempotency-conflict" as const };
  if (
    !(DELIVERY_EFFECT_KINDS_V2 as readonly string[]).includes(request.kind) ||
    !Number.isSafeInteger(request.remainingBudget) ||
    request.remainingBudget <= 0
  )
    return { allowed: false, code: "effect-denied" as const };
  if (
    request.kind === "merge" ||
    request.kind === "push-feature" ||
    request.kind === "create-update-pr"
  )
    return { allowed: false, code: "stakeholder-or-later-slice-gate" as const };
  return { allowed: true, code: "accepted" as const, intent: { ...request } };
}
interface RecoveryRequest {
  kind: string;
  suspendedState: string;
  identity: DeliveryIdentityV2;
  idempotencyKey: string;
  boundaryId: string;
  boundaryConsumed: boolean;
  identityRevalidated: boolean;
  worktreeClean: boolean;
  evidenceIds: string[];
  staleEvidenceIds: string[];
  remainingAttempts: number;
}
export function evaluateDeliveryRecoveryV2(
  contract: unknown,
  request: RecoveryRequest,
  trusted: TrustedDeliveryInputsV2,
) {
  const valid = validateFrozenDeliveryAuthorityContractV2(contract, trusted);
  if (!valid.valid)
    return { allowed: false, code: "contract-invalid" as const };
  const c = valid.value;
  if (
    !(DELIVERY_RECOVERY_KINDS_V2 as readonly string[]).includes(request.kind) ||
    request.suspendedState !== c.state ||
    request.identity.role !== "controller" ||
    request.identity.access !== "controller" ||
    request.boundaryConsumed ||
    !request.identityRevalidated ||
    !request.worktreeClean ||
    !Array.isArray(request.evidenceIds) ||
    request.evidenceIds.length === 0 ||
    !Number.isSafeInteger(request.remainingAttempts) ||
    request.remainingAttempts <= 0
  )
    return { allowed: false, code: "recovery-denied" as const };
  const clearsApproval =
    request.kind === "disappeared-verifier" ||
    request.kind === "stale-evidence-regeneration" ||
    request.kind === "completed-repair-missing-receipt";
  return {
    allowed: true,
    code: "accepted" as const,
    boundaryConsumed: true,
    resumeState:
      request.kind === "cancellation-cleanup"
        ? "cancelled"
        : request.suspendedState,
    clearVerifierApproval: clearsApproval,
    regenerateEvidence: clearsApproval || request.staleEvidenceIds.length > 0,
  };
}
export type { DeliveryAuthorityContractV2 };

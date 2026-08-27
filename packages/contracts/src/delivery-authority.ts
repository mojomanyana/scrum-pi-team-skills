import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { Ajv, type ErrorObject } from "ajv";

import { containsCredentialShapedContent } from "./credential-shape.js";
import {
  canonicalSerializeLifecycleValue,
  isCanonicalLifecycleTimestamp,
} from "./lifecycle-receipt.js";
import deliveryAuthoritySchema from "./schemas/delivery-authority.schema.json" with { type: "json" };

export const DELIVERY_AUTHORITY_CONTRACT_ID =
  "spts.delivery-authority" as const;
export const DELIVERY_AUTHORITY_CONTRACT_VERSION = "1.0.0" as const;

const freeze = <const T extends readonly string[]>(values: T): T =>
  Object.freeze(values);

export const DELIVERY_ROLES = freeze([
  "product",
  "flow",
  "principal-developer",
  "independent-verifier",
  "stakeholder",
] as const);
export type DeliveryRole = (typeof DELIVERY_ROLES)[number];

export const AUTOMATIC_DELIVERY_ACTIONS = freeze([
  "diagnose-repair",
  "edit",
  "test",
  "build",
  "format",
  "worktree-create",
  "worktree-inspect",
  "worktree-cleanup",
  "feature-branch-commit",
  "independent-verification",
  "feature-push",
  "pr-create-update",
  "ci-monitor",
  "ci-repair",
  "paca-evidence-update",
  "paca-status-update",
  "administrative-recovery",
] as const);
export type AutomaticDeliveryAction =
  (typeof AUTOMATIC_DELIVERY_ACTIONS)[number];

export const HUMAN_GATED_DELIVERY_ACTIONS = freeze([
  "merge",
  "force-push",
  "history-rewrite",
  "branch-delete",
  "tag",
  "release",
  "artifact-publication",
  "production-access",
  "deployment",
  "real-pi-execution",
  "credential-expansion",
  "scope-expansion",
  "material-architecture-change",
  "material-product-change",
  "unknown-assurance-escalation",
  "unknown-security-escalation",
] as const);
export type HumanGatedDeliveryAction =
  (typeof HUMAN_GATED_DELIVERY_ACTIONS)[number];

export const WORKFLOW_STATES = freeze([
  "intake",
  "ready",
  "implementation",
  "internal-review",
  "independent-verification",
  "repair-required",
  "publication-authorized",
  "pr-ci-monitoring",
  "merge-gate",
  "completed",
  "blocked",
  "escalated",
] as const);
export type DeliveryWorkflowState = (typeof WORKFLOW_STATES)[number];

export const ADMINISTRATIVE_RECOVERY_KINDS = freeze([
  "redundant-profile-downgrade",
  "missing-keep-branch-finish",
  "repair-receipt-sequencing",
  "stale-evidence-after-controller-event",
  "canonical-digest-refetch",
  "disappeared-agent-clean-worktree",
  "idempotent-push-pr-reconciliation",
  "interrupted-ci-polling",
] as const);
export type AdministrativeRecoveryKind =
  (typeof ADMINISTRATIVE_RECOVERY_KINDS)[number];

export const MANDATORY_ESCALATION_REASONS = freeze([
  "identity-drift",
  "dirty-unexpected-worktree",
  "verifier-modified-candidate",
  "candidate-changed-after-approval",
  "unknown-security-assurance-elevation",
  "credential-scope-expansion",
  "destructive-git-or-production-effect",
  "autonomy-limits-exhausted",
] as const);
export type MandatoryEscalationReason =
  (typeof MANDATORY_ESCALATION_REASONS)[number];

export const DISTINCT_GRANT_EFFECTS = freeze([
  "merge",
  "release",
  "production",
  "destructive-git",
  "real-pi",
] as const);
export type DistinctGrantEffect = (typeof DISTINCT_GRANT_EFFECTS)[number];

export type DeliveryEffect =
  | AutomaticDeliveryAction
  | HumanGatedDeliveryAction
  | DistinctGrantEffect
  | "publication";

export interface DeliveryRoleBinding {
  role: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  access:
    | "product-control"
    | "orchestrate"
    | "read-write"
    | "read-only"
    | "authorize-merge";
}

export interface DeliveryCandidate {
  headCommit: string;
  tree: string;
  remoteBase: {
    expectedCommit: string;
    expectedTree: string;
    observedCommit: string;
    observedTree: string;
  };
  pullRequest: {
    number: number;
    baseBranch: string;
    headBranch: string;
    expectedHeadCommit: string;
    observedHeadCommit: string;
  };
  verification: {
    verdict: "APPROVE" | "REJECT" | "UNVERIFIED";
    reviewedTree: string;
    approvalId: string;
    executionId: string;
    workspaceId: string;
    observedAt: string;
  };
}

export type DeliveryTransitionDecisionCode =
  | "accepted"
  | "contract-invalid"
  | "idempotency-conflict"
  | "request-denied"
  | "stale-observation"
  | "identity-drift"
  | "transition-denied"
  | "publication-denied"
  | "autonomy-exhausted"
  | "ci-evidence-required"
  | "merge-grant-required"
  | "merge-observation-required";

export type DeliveryEffectDecisionCode =
  | "accepted"
  | "contract-invalid"
  | "idempotency-conflict"
  | "identity-drift"
  | "stale-observation"
  | "escalation-required"
  | "publication-denied"
  | "role-authority-denied"
  | "distinct-grant-required";

export type AdministrativeRecoveryDecisionCode =
  | "accepted"
  | "contract-invalid"
  | "idempotency-conflict"
  | "identity-not-revalidated"
  | "stale-observation"
  | "recovery-gate-denied";

export interface DeliveryTransitionAuditRecord {
  eventId: string;
  idempotencyKey: string;
  requestDigest: string;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  candidateTree: string;
  accepted: boolean;
  code: DeliveryTransitionDecisionCode;
  from: DeliveryWorkflowState;
  to: DeliveryWorkflowState;
  observedAt: string;
}

export interface DeliveryEvidence {
  evidenceId: string;
  task: { projectId: string; taskId: string };
  repository: {
    repositoryId: string;
    branch: string;
    commit: string;
    tree: string;
  };
  actor: {
    role: DeliveryRole;
    actorId: string;
    executionId: string;
    workspaceId: string;
  };
  assurance: {
    runId: string;
    profile: "lean" | "standard" | "critical";
    phase:
      | "plan"
      | "build"
      | "review"
      | "git-ops"
      | "verification"
      | "ci"
      | "paca-update";
  };
  verification: {
    verdict: "APPROVE" | "REJECT" | "UNVERIFIED" | null;
    reviewedTree: string | null;
    approvalId: string | null;
  };
  pullRequest: {
    number: number | null;
    baseBranch: string | null;
    headBranch: string | null;
    headCommit: string | null;
  };
  ci: {
    runId: string | null;
    checkId: string | null;
    verdict: "PASS" | "FAIL" | null;
  };
  pacaUpdateId: string | null;
  observedAt: string;
  freshThroughEventId: string;
  correlationId: string;
  idempotencyKey: string;
  evidenceDigest: string;
}

export interface DeliveryEffectGrant {
  effect: DistinctGrantEffect;
  grantId: string;
  authorizedByRole: "stakeholder";
  authorizedByActorId: string;
  targetTree: string;
  idempotencyKey: string;
}

export interface AdministrativeRecoveryRecord {
  recoveryId: string;
  kind: AdministrativeRecoveryKind;
  idempotencyKey: string;
  requestDigest: string;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  workflowState: DeliveryWorkflowState;
  ciStatus: DeliveryAuthorityContract["workflow"]["observations"]["ci"];
  identityRevalidated: boolean;
  targetGate:
    | "administrative"
    | "identity"
    | "security"
    | "scope"
    | "destructive-effect"
    | "production";
  accepted: boolean;
  code: AdministrativeRecoveryDecisionCode;
  observedAt: string;
}

export interface DeliveryEffectAuditRecord {
  idempotencyKey: string;
  requestDigest: string;
  effect: string;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  targetTree: string;
  workflowState: DeliveryWorkflowState;
  allowed: boolean;
  code: DeliveryEffectDecisionCode;
  observedAt: string;
}

export interface DeliveryAuthorityContract {
  contractId: typeof DELIVERY_AUTHORITY_CONTRACT_ID;
  contractVersion: typeof DELIVERY_AUTHORITY_CONTRACT_VERSION;
  authorityDigest: string;
  meteringDigest: string;
  meteringObservedAt: string;
  activeRole: DeliveryRole;
  governance: {
    systemOfRecord: "paca";
    process: "local-pi";
    governedBy: "pi-daddy";
    supervisor: "herdr";
    externalEffects: "decision-only";
  };
  task: {
    paca: { projectId: string; taskId: string };
    repository: {
      repositoryId: string;
      remoteName: string;
      remoteUrl: string;
      root: string;
      baseBranch: string;
      baseCommit: string;
      baseTree: string;
      featureBranch: string;
    };
    assurance: {
      profile: "lean" | "standard" | "critical";
      runId: string;
      scope: string;
    };
    scope: { objective: string; included: string[]; excluded: string[] };
  };
  roles: Record<DeliveryRole, DeliveryRoleBinding>;
  automaticActions: AutomaticDeliveryAction[];
  humanGatedActions: HumanGatedDeliveryAction[];
  workflow: {
    state: DeliveryWorkflowState;
    checkpoint: {
      checkpointId: string;
      state: DeliveryWorkflowState;
      candidateTree: string;
      activeRepairBudget: "implementation" | "verification" | "ci";
      attemptUsage: {
        implementationAttempts: number;
        verificationRepairAttempts: number;
        ciRepairAttempts: number;
      };
      observedAt: string;
    };
    observations: {
      worktree: "clean" | "dirty-unexpected";
      verifierCandidate: "unchanged" | "modified";
      assurance: "known" | "unknown";
      security: "known" | "unknown";
      credentialScope: "unchanged" | "expanded";
      ci: "not-started" | "pending" | "passed" | "failed";
      merge: {
        status: "not-merged" | "merged";
        targetTree: string | null;
        pullRequestNumber: number | null;
        mergeCommit: string | null;
        observedAt: string | null;
        receiptId: string | null;
        freshThroughEventId: string | null;
      };
    };
    candidate: DeliveryCandidate;
    audit: DeliveryTransitionAuditRecord[];
  };
  evidence: DeliveryEvidence[];
  autonomy: {
    limits: {
      implementationAttempts: number;
      verificationRepairAttempts: number;
      ciRepairAttempts: number;
      durationMinutes: number;
      concurrentAgents: number;
      worktrees: number;
      evidenceBytes: number;
      cancellationBehavior: "stop-after-current-atomic-operation";
    };
    usage: {
      implementationAttempts: number;
      verificationRepairAttempts: number;
      ciRepairAttempts: number;
      elapsedMinutes: number;
      concurrentAgents: number;
      worktrees: number;
      evidenceBytes: number;
      cancelled: boolean;
    };
  };
  effectGrants: DeliveryEffectGrant[];
  requestedEffects: DistinctGrantEffect[];
  administrativeRecoveries: AdministrativeRecoveryRecord[];
  activeEscalations: MandatoryEscalationReason[];
  effectAudit: DeliveryEffectAuditRecord[];
}

export interface DeliveryContractError {
  path: string;
  code: string;
  message: string;
}

export type DeliveryAuthorityValidationResult =
  | { valid: true; value: DeliveryAuthorityContract }
  | { valid: false; errors: DeliveryContractError[] };

const ajv = new Ajv({ allErrors: true, formats: { "date-time": true } });
const validateStructure = ajv.compile<DeliveryAuthorityContract>(
  deliveryAuthoritySchema,
);

const exceptionalInputError: DeliveryContractError = {
  path: "/",
  code: "input-introspection",
  message: "delivery authority input could not be safely inspected",
};

function fixedError(
  path: string,
  code: string,
  message: string,
): DeliveryContractError {
  return { path, code, message };
}

function structuralError(error: ErrorObject): DeliveryContractError {
  const missing =
    error.keyword === "required" ? String(error.params.missingProperty) : null;
  const path = missing
    ? `${error.instancePath}/${missing}`
    : error.keyword === "additionalProperties"
      ? error.instancePath || "/"
      : error.instancePath || "/";
  let message = "is invalid";
  if (error.keyword === "required") message = "is required";
  else if (error.keyword === "additionalProperties")
    message = "must not include undeclared properties";
  else if (error.keyword === "pattern")
    message = "must match the required safe format";
  else if (error.keyword === "const")
    message = "must equal the required constant";
  else if (error.keyword === "enum") message = "must be a canonical value";
  else if (error.keyword === "uniqueItems")
    message = "must not contain duplicate items";
  else if (error.keyword === "minItems")
    message = "must contain the complete required set";
  else if (error.keyword === "maxItems")
    message = "must contain only the complete required set";
  else if (error.keyword === "format")
    message = "must use the required canonical format";
  return fixedError(path, error.keyword, message);
}

const MAX_INPUT_NODES = 50_000;
const MAX_INPUT_DEPTH = 64;
const MAX_INPUT_ARRAY_ITEMS = 1_024;
const MAX_INPUT_OBJECT_KEYS = 128;
const MAX_INPUT_STRING_BYTES = 10 * 1024 * 1024;

function isWithinInputBounds(root: unknown): boolean {
  try {
    const pending: Array<{ value: unknown; depth: number }> = [
      { value: root, depth: 0 },
    ];
    const seen = new WeakSet<object>();
    let nodes = 0;
    let stringBytes = 0;
    while (pending.length > 0) {
      const current = pending.pop()!;
      nodes += 1;
      if (nodes > MAX_INPUT_NODES || current.depth > MAX_INPUT_DEPTH)
        return false;
      if (typeof current.value === "string") {
        stringBytes += Buffer.byteLength(current.value, "utf8");
        if (stringBytes > MAX_INPUT_STRING_BYTES) return false;
        continue;
      }
      if (typeof current.value !== "object" || current.value === null) continue;
      if (seen.has(current.value)) continue;
      seen.add(current.value);
      if (
        Array.isArray(current.value) &&
        current.value.length > MAX_INPUT_ARRAY_ITEMS
      )
        return false;
      const keys = Reflect.ownKeys(current.value);
      if (!Array.isArray(current.value) && keys.length > MAX_INPUT_OBJECT_KEYS)
        return false;
      for (const key of keys) {
        if (typeof key !== "string") return false;
        stringBytes += Buffer.byteLength(key, "utf8");
        if (stringBytes > MAX_INPUT_STRING_BYTES) return false;
        const descriptor = Object.getOwnPropertyDescriptor(current.value, key);
        if (descriptor === undefined || !("value" in descriptor)) return false;
        pending.push({ value: descriptor.value, depth: current.depth + 1 });
      }
    }
    return true;
  } catch {
    return false;
  }
}

function canonicalSnapshot<T>(value: unknown): T | null {
  if (!isWithinInputBounds(value)) return null;
  try {
    return JSON.parse(canonicalSerializeLifecycleValue(value)) as T;
  } catch {
    return null;
  }
}

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalSerializeLifecycleValue(value))
    .digest("hex");
}

function authorityIdentity(contract: DeliveryAuthorityContract): unknown {
  return {
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    activeRole: contract.activeRole,
    governance: contract.governance,
    task: contract.task,
    roles: contract.roles,
    automaticActions: contract.automaticActions,
    humanGatedActions: contract.humanGatedActions,
    autonomyLimits: contract.autonomy.limits,
    workflowCheckpoint: contract.workflow.checkpoint,
    effectGrants: contract.effectGrants,
    requestedEffects: contract.requestedEffects,
  };
}

export function computeDeliveryAuthorityDigest(
  contract: DeliveryAuthorityContract,
): string {
  return sha256(authorityIdentity(contract));
}

export function computeDeliveryMeteringDigest(
  contract: DeliveryAuthorityContract,
): string {
  return sha256({
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    projectId: contract.task.paca.projectId,
    taskId: contract.task.paca.taskId,
    checkpointId: contract.workflow.checkpoint.checkpointId,
    meteringObservedAt: contract.meteringObservedAt,
    elapsedMinutes: contract.autonomy.usage.elapsedMinutes,
    concurrentAgents: contract.autonomy.usage.concurrentAgents,
    worktrees: contract.autonomy.usage.worktrees,
    cancelled: contract.autonomy.usage.cancelled,
  });
}

export function computeDeliveryEvidenceDigest(
  evidence: DeliveryEvidence,
): string {
  const unsigned = { ...evidence } as Record<string, unknown>;
  delete unsigned.evidenceDigest;
  return sha256(unsigned);
}

function escapePointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function credentialErrors(value: unknown, path = ""): DeliveryContractError[] {
  if (typeof value === "string") {
    return containsCredentialShapedContent(value)
      ? [
          fixedError(
            path || "/",
            "credential-shaped",
            "must not contain credential-shaped content",
          ),
        ]
      : [];
  }
  if (Array.isArray(value))
    return value.flatMap((item, index) =>
      credentialErrors(item, `${path}/${String(index)}`),
    );
  if (typeof value === "object" && value !== null)
    return Object.entries(value).flatMap(([key, item]) =>
      credentialErrors(item, `${path}/${escapePointer(key)}`),
    );
  return [];
}

function equalsCanonical(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((item, index) => item === right[index])
  );
}

const roleAccess: Record<DeliveryRole, DeliveryRoleBinding["access"]> = {
  product: "product-control",
  flow: "orchestrate",
  "principal-developer": "read-write",
  "independent-verifier": "read-only",
  stakeholder: "authorize-merge",
};

function roleMayPerformAutomatic(
  role: DeliveryRole,
  effect: AutomaticDeliveryAction,
): boolean {
  if (role === "principal-developer")
    return new Set<AutomaticDeliveryAction>([
      "diagnose-repair",
      "edit",
      "test",
      "build",
      "format",
      "worktree-create",
      "worktree-inspect",
      "worktree-cleanup",
      "feature-branch-commit",
      "ci-monitor",
      "ci-repair",
      "paca-evidence-update",
      "paca-status-update",
    ]).has(effect);
  if (role === "independent-verifier")
    return new Set<AutomaticDeliveryAction>([
      "test",
      "worktree-inspect",
      "independent-verification",
      "ci-monitor",
    ]).has(effect);
  if (role === "flow")
    return new Set<AutomaticDeliveryAction>([
      "diagnose-repair",
      "worktree-create",
      "worktree-inspect",
      "worktree-cleanup",
      "feature-push",
      "pr-create-update",
      "ci-monitor",
      "paca-evidence-update",
      "paca-status-update",
      "administrative-recovery",
    ]).has(effect);
  if (role === "product")
    return effect === "paca-evidence-update" || effect === "paca-status-update";
  return false;
}

const publicationStates = new Set<DeliveryWorkflowState>([
  "publication-authorized",
  "pr-ci-monitoring",
  "merge-gate",
  "completed",
]);

const publicationEffectStates = new Set<DeliveryWorkflowState>([
  "publication-authorized",
  "pr-ci-monitoring",
  "merge-gate",
]);

function roleMayTransition(
  role: DeliveryRole,
  from: DeliveryWorkflowState,
  to: DeliveryWorkflowState,
): boolean {
  if (role === "flow") return true;
  if (role === "principal-developer")
    return (
      (from === "implementation" && to === "internal-review") ||
      (from === "repair-required" && to === "implementation") ||
      to === "blocked" ||
      to === "escalated"
    );
  if (role === "product")
    return (
      (from === "intake" && to === "ready") ||
      to === "blocked" ||
      to === "escalated"
    );
  if (role === "stakeholder")
    return from === "merge-gate" && to === "completed";
  return false;
}

function effectAllowedInState(
  effect: AutomaticDeliveryAction,
  state: DeliveryWorkflowState,
): boolean {
  if (effect === "diagnose-repair")
    return state === "implementation" || state === "repair-required";
  if (
    new Set<AutomaticDeliveryAction>([
      "edit",
      "format",
      "feature-branch-commit",
      "ci-repair",
    ]).has(effect)
  )
    return state === "implementation";
  if (effect === "test" || effect === "build")
    return new Set<DeliveryWorkflowState>([
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
      "pr-ci-monitoring",
    ]).has(state);
  if (effect === "worktree-create")
    return new Set<DeliveryWorkflowState>([
      "ready",
      "implementation",
      "internal-review",
      "independent-verification",
      "repair-required",
    ]).has(state);
  if (effect === "worktree-inspect") return state !== "completed";
  if (effect === "worktree-cleanup") return state !== "intake";
  if (effect === "independent-verification")
    return state === "independent-verification";
  if (effect === "feature-push" || effect === "pr-create-update")
    return publicationEffectStates.has(state);
  if (effect === "ci-monitor")
    return state === "pr-ci-monitoring" || state === "merge-gate";
  if (effect === "administrative-recovery")
    return state === "blocked" || state === "escalated";
  if (effect === "paca-evidence-update" || effect === "paca-status-update")
    return state !== "intake";
  return false;
}

function activeRepairBudget(
  contract: DeliveryAuthorityContract,
): "implementation" | "verification" | "ci" {
  for (let index = contract.workflow.audit.length - 1; index >= 0; index -= 1) {
    const audit = contract.workflow.audit[index]!;
    if (audit.accepted && audit.to === "repair-required")
      return audit.from === "pr-ci-monitoring" ? "ci" : "verification";
  }
  return contract.workflow.checkpoint.activeRepairBudget;
}

function latestAcceptedBoundary(
  contract: DeliveryAuthorityContract,
  state: DeliveryWorkflowState,
): { eventId: string; candidateTree: string; observedAt: string } | null {
  for (let index = contract.workflow.audit.length - 1; index >= 0; index -= 1) {
    const audit = contract.workflow.audit[index]!;
    if (audit.accepted && audit.to === state) return audit;
  }
  const checkpoint = contract.workflow.checkpoint;
  return checkpoint.state === state
    ? {
        eventId: checkpoint.checkpointId,
        candidateTree: checkpoint.candidateTree,
        observedAt: checkpoint.observedAt,
      }
    : null;
}

function transitionBudgetExhausted(
  contract: DeliveryAuthorityContract,
  from: DeliveryWorkflowState,
  to: DeliveryWorkflowState,
): boolean {
  if (to !== "implementation") return false;
  if (from === "ready")
    return (
      contract.autonomy.usage.implementationAttempts >=
      contract.autonomy.limits.implementationAttempts
    );
  if (from !== "repair-required") return false;
  const budget = activeRepairBudget(contract);
  if (budget === "ci")
    return (
      contract.autonomy.usage.ciRepairAttempts >=
      contract.autonomy.limits.ciRepairAttempts
    );
  if (budget === "verification")
    return (
      contract.autonomy.usage.verificationRepairAttempts >=
      contract.autonomy.limits.verificationRepairAttempts
    );
  return (
    contract.autonomy.usage.implementationAttempts >=
    contract.autonomy.limits.implementationAttempts
  );
}

function mergeObservationIsFresh(contract: DeliveryAuthorityContract): boolean {
  const merge = contract.workflow.observations.merge;
  if (
    merge.status !== "merged" ||
    merge.targetTree === null ||
    merge.pullRequestNumber === null ||
    merge.mergeCommit === null ||
    merge.observedAt === null ||
    merge.receiptId === null ||
    merge.freshThroughEventId === null ||
    !isCanonicalLifecycleTimestamp(merge.observedAt) ||
    merge.targetTree !== contract.workflow.candidate.tree ||
    merge.pullRequestNumber !== contract.workflow.candidate.pullRequest.number
  )
    return false;
  const gateBoundary = latestAcceptedBoundary(contract, "merge-gate");
  return (
    gateBoundary !== null &&
    gateBoundary.eventId === merge.freshThroughEventId &&
    gateBoundary.candidateTree === merge.targetTree &&
    gateBoundary.observedAt <= merge.observedAt
  );
}

function effectBudgetExhausted(
  contract: DeliveryAuthorityContract,
  effect: AutomaticDeliveryAction,
): boolean {
  const { limits, usage } = contract.autonomy;
  if (effect === "worktree-create" && usage.worktrees >= limits.worktrees)
    return true;
  if (
    (effect === "paca-evidence-update" || effect === "paca-status-update") &&
    usage.evidenceBytes >= limits.evidenceBytes
  )
    return true;
  return false;
}

function publicationIsFresh(contract: DeliveryAuthorityContract): boolean {
  const candidate = contract.workflow.candidate;
  const verifier = contract.roles["independent-verifier"];
  return (
    candidate.verification.verdict === "APPROVE" &&
    candidate.verification.reviewedTree === candidate.tree &&
    candidate.verification.executionId === verifier.executionId &&
    candidate.verification.workspaceId === verifier.workspaceId &&
    candidate.remoteBase.expectedCommit ===
      contract.task.repository.baseCommit &&
    candidate.remoteBase.expectedTree === contract.task.repository.baseTree &&
    candidate.remoteBase.expectedCommit ===
      candidate.remoteBase.observedCommit &&
    candidate.remoteBase.expectedTree === candidate.remoteBase.observedTree &&
    candidate.pullRequest.expectedHeadCommit ===
      candidate.pullRequest.observedHeadCommit &&
    candidate.pullRequest.expectedHeadCommit === candidate.headCommit &&
    candidate.pullRequest.baseBranch === contract.task.repository.baseBranch &&
    candidate.pullRequest.headBranch === contract.task.repository.featureBranch
  );
}

function hasGrant(
  contract: DeliveryAuthorityContract,
  effect: DistinctGrantEffect,
  tree = contract.workflow.candidate.tree,
): boolean {
  const stakeholder = contract.roles.stakeholder;
  return contract.effectGrants.some(
    (grant) =>
      grant.effect === effect &&
      grant.authorizedByRole === "stakeholder" &&
      grant.authorizedByActorId === stakeholder.actorId &&
      grant.authorizedByActorId !==
        contract.roles["principal-developer"].actorId &&
      grant.targetTree === tree,
  );
}

function hasApprovalEvidenceForTree(
  contract: DeliveryAuthorityContract,
  tree: string,
): boolean {
  const verifier = contract.roles["independent-verifier"];
  return contract.evidence.some(
    (evidence) =>
      evidence.verification.verdict === "APPROVE" &&
      evidence.verification.approvalId !== null &&
      evidence.verification.reviewedTree === tree &&
      evidence.repository.tree === tree &&
      evidence.actor.role === "independent-verifier" &&
      evidence.actor.actorId === verifier.actorId &&
      evidence.actor.executionId === verifier.executionId &&
      evidence.actor.workspaceId === verifier.workspaceId,
  );
}

function hasFreshPassingCiEvidence(
  contract: DeliveryAuthorityContract,
): boolean {
  const candidate = contract.workflow.candidate;
  const boundary = latestAcceptedBoundary(contract, "pr-ci-monitoring");
  if (boundary === null || boundary.candidateTree !== candidate.tree)
    return false;
  const currentEvidence = contract.evidence.filter(
    (evidence) =>
      evidence.assurance.phase === "ci" &&
      evidence.freshThroughEventId === boundary.eventId &&
      boundary.observedAt <= evidence.observedAt &&
      evidence.repository.commit === candidate.headCommit &&
      evidence.repository.tree === candidate.tree &&
      evidence.pullRequest.number === candidate.pullRequest.number &&
      evidence.pullRequest.baseBranch === candidate.pullRequest.baseBranch &&
      evidence.pullRequest.headBranch === candidate.pullRequest.headBranch &&
      evidence.pullRequest.headCommit === candidate.headCommit,
  );
  if (currentEvidence.length === 0) return false;
  const latestObservedAt = currentEvidence.reduce(
    (latest, evidence) =>
      evidence.observedAt > latest ? evidence.observedAt : latest,
    currentEvidence[0]!.observedAt,
  );
  return currentEvidence
    .filter((evidence) => evidence.observedAt === latestObservedAt)
    .every(
      (evidence) =>
        evidence.ci.verdict === "PASS" &&
        evidence.ci.runId !== null &&
        evidence.ci.checkId !== null,
    );
}

function expectedAttemptUsage(contract: DeliveryAuthorityContract): {
  implementationAttempts: number;
  verificationRepairAttempts: number;
  ciRepairAttempts: number;
} {
  const usage = { ...contract.workflow.checkpoint.attemptUsage };
  let repairBudget = contract.workflow.checkpoint.activeRepairBudget;
  for (const audit of contract.workflow.audit) {
    if (!audit.accepted) continue;
    if (audit.to === "repair-required")
      repairBudget = audit.from === "pr-ci-monitoring" ? "ci" : "verification";
    if (audit.to !== "implementation") continue;
    if (audit.from === "ready") usage.implementationAttempts += 1;
    else if (audit.from === "repair-required") {
      if (repairBudget === "ci") usage.ciRepairAttempts += 1;
      else if (repairBudget === "verification")
        usage.verificationRepairAttempts += 1;
    }
  }
  return usage;
}

function semanticErrors(
  contract: DeliveryAuthorityContract,
): DeliveryContractError[] {
  const errors: DeliveryContractError[] = [];
  const observations = contract.workflow.observations;
  const requiredEscalations: Array<
    readonly [boolean, MandatoryEscalationReason]
  > = [
    [observations.worktree === "dirty-unexpected", "dirty-unexpected-worktree"],
    [
      observations.verifierCandidate === "modified",
      "verifier-modified-candidate",
    ],
    [
      observations.assurance === "unknown" ||
        observations.security === "unknown",
      "unknown-security-assurance-elevation",
    ],
    [observations.credentialScope === "expanded", "credential-scope-expansion"],
  ];
  for (const [unsafe, reason] of requiredEscalations) {
    if (unsafe && !contract.activeEscalations.includes(reason))
      errors.push(
        fixedError(
          "/workflow/observations",
          "mandatory-escalation",
          "unsafe observations must activate their canonical escalation gate",
        ),
      );
  }
  if (
    (contract.workflow.state === "merge-gate" ||
      contract.workflow.state === "completed") &&
    observations.ci !== "passed"
  )
    errors.push(
      fixedError(
        "/workflow/observations/ci",
        "ci-gate",
        "merge and completion require a passing CI observation",
      ),
    );
  if (
    (contract.workflow.state === "merge-gate" ||
      contract.workflow.state === "completed") &&
    !hasFreshPassingCiEvidence(contract)
  )
    errors.push(
      fixedError(
        "/evidence",
        "ci-evidence",
        "merge and completion require fresh exact-candidate passing CI evidence",
      ),
    );
  const merge = observations.merge;
  const emptyMergeObservation =
    merge.status === "not-merged" &&
    merge.targetTree === null &&
    merge.pullRequestNumber === null &&
    merge.mergeCommit === null &&
    merge.observedAt === null &&
    merge.receiptId === null &&
    merge.freshThroughEventId === null;
  if (
    (!emptyMergeObservation && !mergeObservationIsFresh(contract)) ||
    (contract.workflow.state === "completed" &&
      !mergeObservationIsFresh(contract))
  )
    errors.push(
      fixedError(
        "/workflow/observations/merge",
        "merge-observation",
        "completion requires a fresh exact-tree merge success receipt",
      ),
    );

  if (contract.authorityDigest !== computeDeliveryAuthorityDigest(contract))
    errors.push(
      fixedError(
        "/authorityDigest",
        "authority-digest",
        "must match the canonical immutable authority digest",
      ),
    );
  if (!isCanonicalLifecycleTimestamp(contract.meteringObservedAt))
    errors.push(
      fixedError(
        "/meteringObservedAt",
        "canonical-timestamp",
        "must use a canonical trusted metering timestamp with milliseconds",
      ),
    );
  if (contract.meteringObservedAt < latestRecordedTimestamp(contract))
    errors.push(
      fixedError(
        "/meteringObservedAt",
        "metering-order",
        "trusted metering time cannot precede retained evidence or decisions",
      ),
    );
  if (contract.meteringDigest !== computeDeliveryMeteringDigest(contract))
    errors.push(
      fixedError(
        "/meteringDigest",
        "metering-digest",
        "must match the canonical monotonic metering state digest",
      ),
    );

  if (!equalsCanonical(contract.automaticActions, AUTOMATIC_DELIVERY_ACTIONS))
    errors.push(
      fixedError(
        "/automaticActions",
        "canonical-enumeration",
        "must equal the canonical automatic action set",
      ),
    );
  if (
    !equalsCanonical(contract.humanGatedActions, HUMAN_GATED_DELIVERY_ACTIONS)
  )
    errors.push(
      fixedError(
        "/humanGatedActions",
        "canonical-enumeration",
        "must equal the canonical human-gated action set",
      ),
    );

  const bindings = DELIVERY_ROLES.map((role) => contract.roles[role]);
  for (const role of DELIVERY_ROLES) {
    const binding = contract.roles[role];
    if (binding.role !== role || binding.access !== roleAccess[role])
      errors.push(
        fixedError(
          `/roles/${escapePointer(role)}`,
          role === "independent-verifier"
            ? "verifier-read-only"
            : "role-authority",
          "must use the canonical separated role authority",
        ),
      );
  }
  for (const property of ["actorId", "executionId", "workspaceId"] as const) {
    if (
      new Set(bindings.map((binding) => binding[property])).size !==
      bindings.length
    )
      errors.push(
        fixedError(
          "/roles",
          "role-separation",
          "author, orchestrator, verifier, and merger identities must remain distinct",
        ),
      );
  }

  const candidate = contract.workflow.candidate;
  const verifier = contract.roles["independent-verifier"];
  const approvalBound =
    candidate.verification.verdict === "APPROVE" &&
    candidate.verification.reviewedTree === candidate.tree &&
    candidate.verification.executionId === verifier.executionId &&
    candidate.verification.workspaceId === verifier.workspaceId;
  const driftFree =
    candidate.verification.reviewedTree === candidate.tree &&
    candidate.remoteBase.expectedCommit ===
      contract.task.repository.baseCommit &&
    candidate.remoteBase.expectedTree === contract.task.repository.baseTree &&
    candidate.remoteBase.expectedCommit ===
      candidate.remoteBase.observedCommit &&
    candidate.remoteBase.expectedTree === candidate.remoteBase.observedTree &&
    candidate.pullRequest.expectedHeadCommit ===
      candidate.pullRequest.observedHeadCommit &&
    candidate.pullRequest.expectedHeadCommit === candidate.headCommit;
  if (publicationStates.has(contract.workflow.state) && !approvalBound)
    errors.push(
      fixedError(
        "/workflow/candidate/verification",
        "publication-approval",
        "publication requires independent APPROVE for the exact candidate tree",
      ),
    );
  if (publicationStates.has(contract.workflow.state) && !driftFree)
    errors.push(
      fixedError(
        "/workflow/candidate",
        "publication-drift",
        "candidate, remote base, and pull request head must match their approved identities",
      ),
    );
  if (!isCanonicalLifecycleTimestamp(candidate.verification.observedAt))
    errors.push(
      fixedError(
        "/workflow/candidate/verification/observedAt",
        "canonical-timestamp",
        "must be a canonical UTC timestamp with milliseconds",
      ),
    );

  if (
    (contract.workflow.state === "merge-gate" ||
      contract.workflow.state === "completed") &&
    !hasGrant(contract, "merge")
  )
    errors.push(
      fixedError(
        "/effectGrants",
        "missing-effect-grant",
        "merge requires a distinct stakeholder grant for the exact candidate tree",
      ),
    );
  for (const effect of contract.requestedEffects) {
    if (!hasGrant(contract, effect))
      errors.push(
        fixedError(
          "/effectGrants",
          "missing-effect-grant",
          "the requested protected effect requires its own stakeholder grant for the exact candidate tree",
        ),
      );
  }

  for (const recovery of contract.administrativeRecoveries) {
    const recoveryBinding = contract.roles[recovery.actorRole];
    const reconstructedRecovery: AdministrativeRecoveryRequest = {
      recoveryId: recovery.recoveryId,
      kind: recovery.kind,
      idempotencyKey: recovery.idempotencyKey,
      actorRole: recovery.actorRole,
      actorId: recovery.actorId,
      executionId: recovery.executionId,
      workspaceId: recovery.workspaceId,
      identityRevalidated: recovery.identityRevalidated,
      targetGate: recovery.targetGate,
      observedAt: recovery.observedAt,
    };
    if (recovery.requestDigest !== sha256(reconstructedRecovery))
      errors.push(
        fixedError(
          "/administrativeRecoveries",
          "audit-digest",
          "recovery request digest must match its immutable request fields",
        ),
      );
    if (
      recovery.accepted &&
      (!recovery.identityRevalidated ||
        recovery.targetGate !== "administrative" ||
        recovery.actorId !== recoveryBinding.actorId ||
        recovery.executionId !== recoveryBinding.executionId ||
        recovery.workspaceId !== recoveryBinding.workspaceId ||
        (recovery.workflowState !== "blocked" &&
          recovery.workflowState !== "escalated") ||
        (recovery.kind === "interrupted-ci-polling" &&
          recovery.ciStatus !== "pending" &&
          recovery.ciStatus !== "failed"))
    )
      errors.push(
        fixedError(
          "/administrativeRecoveries",
          "recovery-gate-denied",
          "administrative recovery cannot bypass identity, security, scope, destructive-effect, or production gates",
        ),
      );
    if (
      (recovery.accepted && recovery.code !== "accepted") ||
      (!recovery.accepted && recovery.code === "accepted")
    )
      errors.push(
        fixedError(
          "/administrativeRecoveries",
          "audit-verdict",
          "accepted and rejected recovery records must retain their fixed verdict code",
        ),
      );
    if (!isCanonicalLifecycleTimestamp(recovery.observedAt))
      errors.push(
        fixedError(
          "/administrativeRecoveries",
          "canonical-timestamp",
          "must use canonical UTC timestamps with milliseconds",
        ),
      );
  }

  const limitPairs = [
    ["implementationAttempts", "implementationAttempts"],
    ["verificationRepairAttempts", "verificationRepairAttempts"],
    ["ciRepairAttempts", "ciRepairAttempts"],
    ["elapsedMinutes", "durationMinutes"],
    ["concurrentAgents", "concurrentAgents"],
    ["worktrees", "worktrees"],
    ["evidenceBytes", "evidenceBytes"],
  ] as const;
  for (const [usage, limit] of limitPairs) {
    if (contract.autonomy.usage[usage] > contract.autonomy.limits[limit])
      errors.push(
        fixedError(
          `/autonomy/usage/${usage}`,
          "autonomy-limit-exhausted",
          "must not exceed the bounded autonomy limit",
        ),
      );
  }
  const derivedAttemptUsage = expectedAttemptUsage(contract);
  for (const field of [
    "implementationAttempts",
    "verificationRepairAttempts",
    "ciRepairAttempts",
  ] as const) {
    if (contract.autonomy.usage[field] !== derivedAttemptUsage[field])
      errors.push(
        fixedError(
          `/autonomy/usage/${field}`,
          "attempt-usage-provenance",
          "attempt usage must equal the frozen checkpoint plus accepted attempt transitions",
        ),
      );
  }
  if (
    contract.autonomy.usage.cancelled &&
    !new Set<DeliveryWorkflowState>(["blocked", "completed"]).has(
      contract.workflow.state,
    )
  )
    errors.push(
      fixedError(
        "/autonomy/usage/cancelled",
        "cancellation-state",
        "cancellation must stop further work in a terminal safe state",
      ),
    );

  if (
    contract.activeEscalations.length > 0 &&
    contract.workflow.state !== "escalated" &&
    contract.workflow.state !== "blocked"
  )
    errors.push(
      fixedError(
        "/activeEscalations",
        "mandatory-escalation",
        "an active mandatory escalation requires escalated or blocked workflow state",
      ),
    );

  const checkpoint = contract.workflow.checkpoint;
  if (!isCanonicalLifecycleTimestamp(checkpoint.observedAt))
    errors.push(
      fixedError(
        "/workflow/checkpoint/observedAt",
        "canonical-timestamp",
        "checkpoint must use a canonical UTC timestamp with milliseconds",
      ),
    );
  if (
    checkpoint.state === "repair-required" &&
    checkpoint.activeRepairBudget === "implementation"
  )
    errors.push(
      fixedError(
        "/workflow/checkpoint/activeRepairBudget",
        "repair-provenance",
        "a repair-required checkpoint must retain its repair budget provenance",
      ),
    );

  const auditByKey = new Map<string, string>();
  const auditEventIdsSeen = new Set<string>();
  let auditState: DeliveryWorkflowState | null = null;
  let auditTimestamp: string | null = null;
  let terminalCandidateTree: string | null = null;
  for (const audit of contract.workflow.audit) {
    const reconstructedRequest: DeliveryTransitionRequest = {
      eventId: audit.eventId,
      idempotencyKey: audit.idempotencyKey,
      from: audit.from,
      to: audit.to,
      actorRole: audit.actorRole,
      actorId: audit.actorId,
      executionId: audit.executionId,
      workspaceId: audit.workspaceId,
      candidateTree: audit.candidateTree,
      observedAt: audit.observedAt,
    };
    if (audit.requestDigest !== sha256(reconstructedRequest))
      errors.push(
        fixedError(
          "/workflow/audit",
          "audit-digest",
          "controller audit request digest must match its immutable request fields",
        ),
      );
    if (auditEventIdsSeen.has(audit.eventId))
      errors.push(
        fixedError(
          "/workflow/audit",
          "audit-event-duplicate",
          "controller event identities must be unique",
        ),
      );
    auditEventIdsSeen.add(audit.eventId);
    if (
      (audit.accepted &&
        (audit.code !== "accepted" ||
          !transitions[audit.from].includes(audit.to) ||
          !roleMayTransition(audit.actorRole, audit.from, audit.to) ||
          contract.roles[audit.actorRole].actorId !== audit.actorId ||
          contract.roles[audit.actorRole].executionId !== audit.executionId ||
          contract.roles[audit.actorRole].workspaceId !== audit.workspaceId)) ||
      (!audit.accepted && audit.code === "accepted")
    )
      errors.push(
        fixedError(
          "/workflow/audit",
          "audit-verdict",
          "accepted and rejected controller events must retain a valid transition verdict",
        ),
      );
    if (!isCanonicalLifecycleTimestamp(audit.observedAt))
      errors.push(
        fixedError(
          "/workflow/audit",
          "canonical-timestamp",
          "must use canonical UTC timestamps with milliseconds",
        ),
      );
    if (auditTimestamp !== null && audit.observedAt < auditTimestamp)
      errors.push(
        fixedError(
          "/workflow/audit",
          "audit-order",
          "controller audit timestamps must be nondecreasing",
        ),
      );
    auditTimestamp = audit.observedAt;
    if (!audit.accepted) continue;
    if (auditState === null) auditState = audit.from;
    if (audit.from !== auditState)
      errors.push(
        fixedError(
          "/workflow/audit",
          "audit-chain",
          "accepted controller events must form one contiguous state transition chain",
        ),
      );
    auditState = audit.to;
    terminalCandidateTree = audit.candidateTree;
  }
  const firstAcceptedAudit = contract.workflow.audit.find(
    (audit) => audit.accepted,
  );
  if (
    (firstAcceptedAudit === undefined &&
      (contract.workflow.state !== checkpoint.state ||
        candidate.tree !== checkpoint.candidateTree)) ||
    (firstAcceptedAudit !== undefined &&
      (firstAcceptedAudit.from !== checkpoint.state ||
        firstAcceptedAudit.candidateTree !== checkpoint.candidateTree ||
        firstAcceptedAudit.observedAt < checkpoint.observedAt))
  )
    errors.push(
      fixedError(
        "/workflow/checkpoint",
        "checkpoint-mismatch",
        "the audit trace must continue from its frozen workflow checkpoint",
      ),
    );
  if (auditState !== null && auditState !== contract.workflow.state)
    errors.push(
      fixedError(
        "/workflow/state",
        "audit-state-mismatch",
        "workflow state must equal the terminal accepted controller event",
      ),
    );
  if (
    terminalCandidateTree !== null &&
    terminalCandidateTree !== candidate.tree
  )
    errors.push(
      fixedError(
        "/workflow/candidate/tree",
        "audit-candidate-mismatch",
        "current candidate tree must equal the terminal accepted controller event tree",
      ),
    );
  for (const audit of contract.effectAudit) {
    const effect = audit.effect as DeliveryEffect;
    const reconstructedRequest: DeliveryEffectRequest = {
      effect,
      idempotencyKey: audit.idempotencyKey,
      actorRole: audit.actorRole,
      actorId: audit.actorId,
      executionId: audit.executionId,
      workspaceId: audit.workspaceId,
      targetTree: audit.targetTree,
      observedAt: audit.observedAt,
    };
    if (audit.requestDigest !== sha256(reconstructedRequest))
      errors.push(
        fixedError(
          "/effectAudit",
          "audit-digest",
          "effect audit request digest must match its immutable request fields",
        ),
      );
    const protectedEffect = protectedGrantFor(effect);
    const publicationEffect =
      effect === "publication" ||
      effect === "feature-push" ||
      effect === "pr-create-update";
    const automaticEffect = (
      AUTOMATIC_DELIVERY_ACTIONS as readonly string[]
    ).includes(effect)
      ? (effect as AutomaticDeliveryAction)
      : null;
    const automaticOrPublicationEffect =
      automaticEffect !== null || effect === "publication";
    const auditSafetyGatesHold =
      audit.observedAt <= contract.meteringObservedAt &&
      contract.activeEscalations.length === 0 &&
      !contract.autonomy.usage.cancelled &&
      (!automaticOrPublicationEffect ||
        contract.autonomy.usage.elapsedMinutes <
          contract.autonomy.limits.durationMinutes) &&
      (automaticEffect === null ||
        !effectBudgetExhausted(contract, automaticEffect)) &&
      (automaticEffect !== "ci-repair" ||
        contract.workflow.observations.ci === "failed") &&
      (automaticEffect !== "ci-monitor" ||
        contract.workflow.observations.ci === "pending" ||
        contract.workflow.observations.ci === "failed");
    const validAllowedEffect =
      (auditSafetyGatesHold &&
        (AUTOMATIC_DELIVERY_ACTIONS as readonly string[]).includes(effect) &&
        roleMayPerformAutomatic(
          audit.actorRole,
          effect as AutomaticDeliveryAction,
        ) &&
        effectAllowedInState(
          effect as AutomaticDeliveryAction,
          audit.workflowState,
        ) &&
        !publicationEffect) ||
      (publicationEffect &&
        publicationEffectStates.has(audit.workflowState) &&
        hasApprovalEvidenceForTree(contract, audit.targetTree) &&
        ((effect === "publication" && audit.actorRole === "flow") ||
          (effect !== "publication" &&
            roleMayPerformAutomatic(
              audit.actorRole,
              effect as AutomaticDeliveryAction,
            )))) ||
      (protectedEffect !== null &&
        audit.actorRole === "flow" &&
        protectedEffectAllowedInState(effect, audit.workflowState) &&
        hasGrant(contract, protectedEffect, audit.targetTree));
    if (
      (audit.allowed &&
        (audit.code !== "accepted" ||
          !validAllowedEffect ||
          contract.roles[audit.actorRole].actorId !== audit.actorId ||
          contract.roles[audit.actorRole].executionId !== audit.executionId ||
          contract.roles[audit.actorRole].workspaceId !== audit.workspaceId)) ||
      (!audit.allowed && audit.code === "accepted")
    )
      errors.push(
        fixedError(
          "/effectAudit",
          "audit-verdict",
          "accepted and rejected effects must retain an enforceable fixed verdict",
        ),
      );
    if (!isCanonicalLifecycleTimestamp(audit.observedAt))
      errors.push(
        fixedError(
          "/effectAudit",
          "canonical-timestamp",
          "must use canonical UTC timestamps with milliseconds",
        ),
      );
  }
  const registerIdempotency = (key: string, digest: string): void => {
    const previous = auditByKey.get(key);
    if (previous !== undefined)
      errors.push(
        fixedError(
          "/",
          "idempotency-conflict",
          "an idempotency key must identify exactly one request",
        ),
      );
    auditByKey.set(key, digest);
  };
  for (const audit of [...contract.workflow.audit, ...contract.effectAudit])
    registerIdempotency(audit.idempotencyKey, audit.requestDigest);
  for (const recovery of contract.administrativeRecoveries)
    registerIdempotency(recovery.idempotencyKey, recovery.requestDigest);
  const grantIds = new Set<string>();
  const grantKeys = new Set<string>();
  for (const grant of contract.effectGrants) {
    if (grantIds.has(grant.grantId) || grantKeys.has(grant.idempotencyKey))
      errors.push(
        fixedError(
          "/effectGrants",
          "grant-duplicate",
          "stakeholder grant and idempotency identities must be unique",
        ),
      );
    grantIds.add(grant.grantId);
    grantKeys.add(grant.idempotencyKey);
    registerIdempotency(grant.idempotencyKey, sha256(grant));
  }

  const actualEvidenceBytes = Buffer.byteLength(
    canonicalSerializeLifecycleValue(contract.evidence),
    "utf8",
  );
  if (contract.autonomy.usage.evidenceBytes !== actualEvidenceBytes)
    errors.push(
      fixedError(
        "/autonomy/usage/evidenceBytes",
        "evidence-bytes",
        "must equal the canonical serialized evidence byte count",
      ),
    );

  const auditEvents = new Map(
    contract.workflow.audit.map((audit) => [audit.eventId, audit] as const),
  );
  const evidenceKeys = new Set<string>();
  const ciRunBoundaries = new Map<string, string>();
  const ciCheckBoundaries = new Map<string, string>();
  let currentApprovalEvidenceFound = false;
  for (let index = 0; index < contract.evidence.length; index += 1) {
    const evidence = contract.evidence[index]!;
    const path = `/evidence/${String(index)}`;
    if (evidence.evidenceDigest !== computeDeliveryEvidenceDigest(evidence))
      errors.push(
        fixedError(
          `${path}/evidenceDigest`,
          "evidence-digest",
          "must match the canonical immutable evidence digest",
        ),
      );
    if (!isCanonicalLifecycleTimestamp(evidence.observedAt))
      errors.push(
        fixedError(
          `${path}/observedAt`,
          "canonical-timestamp",
          "must be a canonical UTC timestamp with milliseconds",
        ),
      );
    const ciEvidenceIsConsistent =
      evidence.ci.verdict === null
        ? (evidence.ci.runId === null) === (evidence.ci.checkId === null)
        : evidence.ci.runId !== null && evidence.ci.checkId !== null;
    if (!ciEvidenceIsConsistent)
      errors.push(
        fixedError(
          `${path}/ci`,
          "ci-evidence",
          "CI verdicts must retain their run and check identities",
        ),
      );
    for (const [identity, boundaries] of [
      [evidence.ci.runId, ciRunBoundaries],
      [evidence.ci.checkId, ciCheckBoundaries],
    ] as const) {
      if (identity === null) continue;
      const priorBoundary = boundaries.get(identity);
      if (
        priorBoundary !== undefined &&
        priorBoundary !== evidence.freshThroughEventId
      )
        errors.push(
          fixedError(
            `${path}/ci`,
            "ci-identity-reuse",
            "CI run and check identities cannot move between monitoring boundaries",
          ),
        );
      else boundaries.set(identity, evidence.freshThroughEventId);
    }
    const binding = contract.roles[evidence.actor.role];
    if (
      evidence.task.projectId !== contract.task.paca.projectId ||
      evidence.task.taskId !== contract.task.paca.taskId ||
      evidence.repository.repositoryId !==
        contract.task.repository.repositoryId ||
      evidence.repository.branch !== contract.task.repository.featureBranch ||
      evidence.actor.actorId !== binding.actorId ||
      evidence.actor.executionId !== binding.executionId ||
      evidence.actor.workspaceId !== binding.workspaceId ||
      evidence.assurance.runId !== contract.task.assurance.runId ||
      evidence.assurance.profile !== contract.task.assurance.profile
    )
      errors.push(
        fixedError(
          path,
          "evidence-correlation",
          "must match the immutable task, repository, role, execution, workspace, and assurance identity",
        ),
      );
    const freshEvent = auditEvents.get(evidence.freshThroughEventId);
    const freshCheckpoint =
      evidence.freshThroughEventId === checkpoint.checkpointId &&
      checkpoint.candidateTree === evidence.repository.tree &&
      checkpoint.observedAt <= evidence.observedAt;
    if (
      (freshEvent === undefined ||
        freshEvent.candidateTree !== evidence.repository.tree) &&
      !freshCheckpoint
    )
      errors.push(
        fixedError(
          `${path}/freshThroughEventId`,
          "evidence-freshness",
          "must identify an auditable controller event for the evidence tree",
        ),
      );
    const hasVerification = evidence.verification.verdict !== null;
    const approvalIdIsValid =
      evidence.verification.verdict === "APPROVE"
        ? evidence.verification.approvalId !== null
        : evidence.verification.approvalId === null;
    if (
      (hasVerification &&
        (evidence.actor.role !== "independent-verifier" ||
          evidence.verification.reviewedTree !== evidence.repository.tree ||
          evidence.pullRequest.number === null ||
          evidence.pullRequest.baseBranch !==
            contract.task.repository.baseBranch ||
          evidence.pullRequest.headBranch !==
            contract.task.repository.featureBranch ||
          evidence.pullRequest.headCommit !== evidence.repository.commit ||
          !approvalIdIsValid)) ||
      (!hasVerification &&
        (evidence.verification.reviewedTree !== null ||
          evidence.verification.approvalId !== null))
    )
      errors.push(
        fixedError(
          `${path}/verification`,
          "verification-evidence-binding",
          "verification evidence must bind its verifier, candidate, approval, and pull request identities",
        ),
      );
    if (
      evidence.verification.verdict === "APPROVE" &&
      evidence.verification.approvalId === candidate.verification.approvalId &&
      evidence.verification.reviewedTree === candidate.tree &&
      evidence.repository.commit === candidate.headCommit &&
      evidence.repository.tree === candidate.tree &&
      evidence.pullRequest.number === candidate.pullRequest.number &&
      evidence.pullRequest.baseBranch === candidate.pullRequest.baseBranch &&
      evidence.pullRequest.headBranch === candidate.pullRequest.headBranch &&
      evidence.pullRequest.headCommit === candidate.headCommit &&
      evidence.observedAt === candidate.verification.observedAt
    )
      currentApprovalEvidenceFound = true;
    if (evidenceKeys.has(evidence.idempotencyKey))
      errors.push(
        fixedError(
          `${path}/idempotencyKey`,
          "idempotency-conflict",
          "evidence idempotency keys must be unique",
        ),
      );
    evidenceKeys.add(evidence.idempotencyKey);
    registerIdempotency(evidence.idempotencyKey, evidence.evidenceDigest);
  }
  if (
    publicationStates.has(contract.workflow.state) &&
    !currentApprovalEvidenceFound
  )
    errors.push(
      fixedError(
        "/evidence",
        "publication-evidence",
        "publication requires fresh exact-tree verifier approval evidence",
      ),
    );

  return errors;
}

/**
 * Authoritative acceptance boundary for governed task-scoped delivery authority.
 * Direct JSON Schema success is structural only and never authorizes an effect.
 */
export function validateDeliveryAuthorityContract(
  value: unknown,
): DeliveryAuthorityValidationResult {
  const contract = canonicalSnapshot<DeliveryAuthorityContract>(value);
  if (contract === null)
    return { valid: false, errors: [{ ...exceptionalInputError }] };
  if (!validateStructure(contract))
    return {
      valid: false,
      errors: (validateStructure.errors ?? []).map(structuralError),
    };
  const errors = credentialErrors(contract);
  if (errors.length === 0) errors.push(...semanticErrors(contract));
  return errors.length === 0
    ? { valid: true, value: contract }
    : { valid: false, errors };
}

export function validateFrozenDeliveryAuthorityContract(
  value: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
): DeliveryAuthorityValidationResult {
  const validation = validateDeliveryAuthorityContract(value);
  if (!validation.valid) return validation;
  if (
    typeof expectedAuthorityDigest === "string" &&
    /^[0-9a-f]{64}$/.test(expectedAuthorityDigest) &&
    validation.value.authorityDigest === expectedAuthorityDigest &&
    typeof expectedMeteringDigest === "string" &&
    /^[0-9a-f]{64}$/.test(expectedMeteringDigest) &&
    validation.value.meteringDigest === expectedMeteringDigest
  )
    return validation;
  return {
    valid: false,
    errors: [
      fixedError(
        "/authorityDigest",
        "frozen-authority",
        "must match the trusted frozen authority and monotonic metering digests",
      ),
    ],
  };
}

export function isDeliveryAuthorityContract(
  value: unknown,
): value is DeliveryAuthorityContract {
  return validateDeliveryAuthorityContract(value).valid;
}

const transitions: Readonly<
  Record<DeliveryWorkflowState, readonly DeliveryWorkflowState[]>
> = Object.freeze({
  intake: freeze(["ready", "blocked", "escalated"]),
  ready: freeze(["implementation", "blocked", "escalated"]),
  implementation: freeze(["internal-review", "blocked", "escalated"]),
  "internal-review": freeze([
    "independent-verification",
    "repair-required",
    "blocked",
    "escalated",
  ]),
  "independent-verification": freeze([
    "publication-authorized",
    "repair-required",
    "blocked",
    "escalated",
  ]),
  "repair-required": freeze(["implementation", "blocked", "escalated"]),
  "publication-authorized": freeze([
    "pr-ci-monitoring",
    "blocked",
    "escalated",
  ]),
  "pr-ci-monitoring": freeze([
    "merge-gate",
    "repair-required",
    "blocked",
    "escalated",
  ]),
  "merge-gate": freeze(["completed", "blocked", "escalated"]),
  completed: freeze([]),
  blocked: freeze(["ready", "escalated"]),
  escalated: freeze(["blocked"]),
});

export interface DeliveryTransitionRequest {
  eventId: string;
  idempotencyKey: string;
  from: DeliveryWorkflowState;
  to: DeliveryWorkflowState;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  candidateTree: string;
  observedAt: string;
}

export interface DeliveryTransitionDecision {
  accepted: boolean;
  idempotent: boolean;
  code: DeliveryTransitionDecisionCode;
  nextState: DeliveryWorkflowState;
  audit: DeliveryTransitionAuditRecord;
}

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => expected.includes(key))
  );
}

function isSafeRequestId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(value) &&
    !containsCredentialShapedContent(value)
  );
}

function isDeliveryTransitionRequest(
  value: unknown,
): value is DeliveryTransitionRequest {
  if (
    typeof value !== "object" ||
    value === null ||
    !hasExactKeys(value, [
      "eventId",
      "idempotencyKey",
      "from",
      "to",
      "actorRole",
      "actorId",
      "executionId",
      "workspaceId",
      "candidateTree",
      "observedAt",
    ])
  )
    return false;
  const request = value as Record<string, unknown>;
  return (
    isSafeRequestId(request.eventId) &&
    isSafeRequestId(request.idempotencyKey) &&
    (WORKFLOW_STATES as readonly unknown[]).includes(request.from) &&
    (WORKFLOW_STATES as readonly unknown[]).includes(request.to) &&
    (DELIVERY_ROLES as readonly unknown[]).includes(request.actorRole) &&
    isSafeRequestId(request.actorId) &&
    isSafeRequestId(request.executionId) &&
    isSafeRequestId(request.workspaceId) &&
    typeof request.candidateTree === "string" &&
    /^[0-9a-f]{40}$/.test(request.candidateTree) &&
    typeof request.observedAt === "string" &&
    isCanonicalLifecycleTimestamp(request.observedAt)
  );
}

function latestRecordedTimestamp(contract: DeliveryAuthorityContract): string {
  const timestamps = [
    contract.workflow.checkpoint.observedAt,
    contract.workflow.candidate.verification.observedAt,
    ...contract.workflow.audit.map((record) => record.observedAt),
    ...contract.effectAudit.map((record) => record.observedAt),
    ...contract.administrativeRecoveries.map((record) => record.observedAt),
    ...contract.evidence.map((record) => record.observedAt),
  ];
  return timestamps.reduce((latest, value) =>
    value > latest ? value : latest,
  );
}

function idempotencyKeyExists(
  contract: DeliveryAuthorityContract,
  key: string,
): boolean {
  return (
    contract.workflow.audit.some((record) => record.idempotencyKey === key) ||
    contract.effectAudit.some((record) => record.idempotencyKey === key) ||
    contract.administrativeRecoveries.some(
      (record) => record.idempotencyKey === key,
    ) ||
    contract.effectGrants.some((grant) => grant.idempotencyKey === key) ||
    contract.evidence.some((evidence) => evidence.idempotencyKey === key)
  );
}

function decisionAudit(
  request: DeliveryTransitionRequest,
  requestDigest: string,
  accepted: boolean,
  code: DeliveryTransitionDecisionCode,
): DeliveryTransitionAuditRecord {
  return {
    eventId: request.eventId,
    idempotencyKey: request.idempotencyKey,
    requestDigest,
    actorRole: request.actorRole,
    actorId: request.actorId,
    executionId: request.executionId,
    workspaceId: request.workspaceId,
    candidateTree: request.candidateTree,
    accepted,
    code,
    from: request.from,
    to: request.to,
    observedAt: request.observedAt,
  };
}

export function evaluateDeliveryTransition(
  value: unknown,
  requestValue: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
): DeliveryTransitionDecision {
  const validation = validateFrozenDeliveryAuthorityContract(
    value,
    expectedAuthorityDigest,
    expectedMeteringDigest,
  );
  const requestSnapshot = canonicalSnapshot<unknown>(requestValue);
  const request = isDeliveryTransitionRequest(requestSnapshot)
    ? requestSnapshot
    : null;
  const fallbackState = validation.valid
    ? validation.value.workflow.state
    : "blocked";
  if (!validation.valid || request === null) {
    const fallback: DeliveryTransitionRequest = {
      eventId: "rejected-event",
      idempotencyKey: "rejected-request",
      from: fallbackState,
      to: "blocked",
      actorRole: "flow",
      actorId: "rejected-actor",
      executionId: "rejected-execution",
      workspaceId: "rejected-workspace",
      candidateTree: "0".repeat(40),
      observedAt: "1970-01-01T00:00:00.000Z",
    };
    return {
      accepted: false,
      idempotent: false,
      code: "contract-invalid",
      nextState: fallbackState,
      audit: decisionAudit(
        fallback,
        sha256(fallback),
        false,
        "contract-invalid",
      ),
    };
  }
  const contract = validation.value;
  const requestDigest = sha256(request);
  if (request.actorRole !== contract.activeRole) {
    return {
      accepted: false,
      idempotent: false,
      code: "identity-drift",
      nextState: contract.workflow.state,
      audit: decisionAudit(request, requestDigest, false, "identity-drift"),
    };
  }
  const prior = contract.workflow.audit.find(
    (record) => record.idempotencyKey === request.idempotencyKey,
  );
  if (prior) {
    const same = prior.requestDigest === requestDigest;
    return {
      accepted: same && prior.accepted,
      idempotent: same,
      code: same ? prior.code : "idempotency-conflict",
      nextState: contract.workflow.state,
      audit: same
        ? prior
        : decisionAudit(request, requestDigest, false, "idempotency-conflict"),
    };
  }
  if (
    idempotencyKeyExists(contract, request.idempotencyKey) ||
    contract.workflow.audit.some((record) => record.eventId === request.eventId)
  )
    return {
      accepted: false,
      idempotent: false,
      code: "idempotency-conflict",
      nextState: contract.workflow.state,
      audit: decisionAudit(
        request,
        requestDigest,
        false,
        "idempotency-conflict",
      ),
    };

  let code: DeliveryTransitionDecisionCode = "accepted";
  const binding = contract.roles[request.actorRole];
  if (containsCredentialShapedContent(request.actorId)) code = "request-denied";
  else if (
    request.observedAt !== contract.meteringObservedAt ||
    request.observedAt <= latestRecordedTimestamp(contract)
  )
    code = "stale-observation";
  else if (
    request.from !== contract.workflow.state ||
    request.candidateTree !== contract.workflow.candidate.tree ||
    binding.actorId !== request.actorId ||
    binding.executionId !== request.executionId ||
    binding.workspaceId !== request.workspaceId
  )
    code = "identity-drift";
  else if (
    !transitions[request.from].includes(request.to) ||
    !roleMayTransition(request.actorRole, request.from, request.to) ||
    contract.autonomy.usage.cancelled ||
    (contract.activeEscalations.length > 0 && request.to === "ready")
  )
    code = "transition-denied";
  else if (transitionBudgetExhausted(contract, request.from, request.to))
    code = "autonomy-exhausted";
  else if (
    request.to === "publication-authorized" &&
    !publicationIsFresh(contract)
  )
    code = "publication-denied";
  else if (
    (request.to === "merge-gate" || request.to === "completed") &&
    !hasFreshPassingCiEvidence(contract)
  )
    code = "ci-evidence-required";
  else if (request.to === "merge-gate" && !hasGrant(contract, "merge"))
    code = "merge-grant-required";
  else if (request.to === "completed" && !hasGrant(contract, "merge"))
    code = "merge-grant-required";
  else if (request.to === "completed" && !mergeObservationIsFresh(contract))
    code = "merge-observation-required";
  const accepted = code === "accepted";
  return {
    accepted,
    idempotent: false,
    code,
    nextState: accepted ? request.to : contract.workflow.state,
    audit: decisionAudit(request, requestDigest, accepted, code),
  };
}

export interface DeliveryEffectRequest {
  effect: DeliveryEffect;
  idempotencyKey: string;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  targetTree: string;
  observedAt: string;
}

export interface DeliveryEffectDecision {
  allowed: boolean;
  idempotent: boolean;
  code: DeliveryEffectDecisionCode;
  audit: DeliveryEffectAuditRecord;
}

const deliveryEffects = new Set<string>([
  ...AUTOMATIC_DELIVERY_ACTIONS,
  ...HUMAN_GATED_DELIVERY_ACTIONS,
  ...DISTINCT_GRANT_EFFECTS,
  "publication",
]);

function isDeliveryEffectRequest(
  value: unknown,
): value is DeliveryEffectRequest {
  if (
    typeof value !== "object" ||
    value === null ||
    !hasExactKeys(value, [
      "effect",
      "idempotencyKey",
      "actorRole",
      "actorId",
      "executionId",
      "workspaceId",
      "targetTree",
      "observedAt",
    ])
  )
    return false;
  const request = value as Record<string, unknown>;
  return (
    typeof request.effect === "string" &&
    deliveryEffects.has(request.effect) &&
    isSafeRequestId(request.idempotencyKey) &&
    (DELIVERY_ROLES as readonly unknown[]).includes(request.actorRole) &&
    isSafeRequestId(request.actorId) &&
    isSafeRequestId(request.executionId) &&
    isSafeRequestId(request.workspaceId) &&
    typeof request.targetTree === "string" &&
    /^[0-9a-f]{40}$/.test(request.targetTree) &&
    typeof request.observedAt === "string" &&
    isCanonicalLifecycleTimestamp(request.observedAt)
  );
}

function protectedEffectAllowedInState(
  effect: DeliveryEffect,
  state: DeliveryWorkflowState,
): boolean {
  if (effect === "merge") return state === "merge-gate";
  return true;
}

function protectedGrantFor(effect: DeliveryEffect): DistinctGrantEffect | null {
  if (effect === "merge") return "merge";
  if (
    effect === "release" ||
    effect === "tag" ||
    effect === "artifact-publication"
  )
    return "release";
  if (
    effect === "production" ||
    effect === "production-access" ||
    effect === "deployment"
  )
    return "production";
  if (
    effect === "destructive-git" ||
    effect === "force-push" ||
    effect === "history-rewrite" ||
    effect === "branch-delete"
  )
    return "destructive-git";
  if (effect === "real-pi" || effect === "real-pi-execution") return "real-pi";
  return null;
}

export function authorizeDeliveryEffect(
  value: unknown,
  requestValue: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
): DeliveryEffectDecision {
  const validation = validateFrozenDeliveryAuthorityContract(
    value,
    expectedAuthorityDigest,
    expectedMeteringDigest,
  );
  const requestSnapshot = canonicalSnapshot<unknown>(requestValue);
  const request = isDeliveryEffectRequest(requestSnapshot)
    ? requestSnapshot
    : null;
  const observedAt = request?.observedAt ?? "1970-01-01T00:00:00.000Z";
  const fallbackRequest: DeliveryEffectRequest = request ?? {
    effect: "diagnose-repair",
    idempotencyKey: "rejected-effect",
    actorRole: "flow",
    actorId: "rejected-actor",
    executionId: "rejected-execution",
    workspaceId: "rejected-workspace",
    targetTree: "0".repeat(40),
    observedAt: "1970-01-01T00:00:00.000Z",
  };
  const requestDigest = sha256(fallbackRequest);
  const make = (
    allowed: boolean,
    idempotent: boolean,
    code: DeliveryEffectDecisionCode,
  ): DeliveryEffectDecision => ({
    allowed,
    idempotent,
    code,
    audit: {
      idempotencyKey: fallbackRequest.idempotencyKey,
      requestDigest,
      effect: fallbackRequest.effect,
      actorRole: fallbackRequest.actorRole,
      actorId: fallbackRequest.actorId,
      executionId: fallbackRequest.executionId,
      workspaceId: fallbackRequest.workspaceId,
      targetTree: fallbackRequest.targetTree,
      workflowState: validation.valid
        ? validation.value.workflow.state
        : "blocked",
      allowed,
      code,
      observedAt,
    },
  });
  if (!validation.valid || request === null)
    return make(false, false, "contract-invalid");
  const contract = validation.value;
  if (request.actorRole !== contract.activeRole)
    return make(false, false, "role-authority-denied");
  const prior = contract.effectAudit.find(
    (record) => record.idempotencyKey === request.idempotencyKey,
  );
  if (prior)
    return prior.requestDigest === requestDigest
      ? {
          allowed: false,
          idempotent: true,
          code: prior.code,
          audit: prior,
        }
      : make(false, false, "idempotency-conflict");
  if (idempotencyKeyExists(contract, request.idempotencyKey))
    return make(false, false, "idempotency-conflict");
  if (
    contract.roles[request.actorRole].actorId !== request.actorId ||
    contract.roles[request.actorRole].executionId !== request.executionId ||
    contract.roles[request.actorRole].workspaceId !== request.workspaceId ||
    request.targetTree !== contract.workflow.candidate.tree ||
    containsCredentialShapedContent(request.actorId)
  )
    return make(false, false, "identity-drift");
  if (
    request.observedAt !== contract.meteringObservedAt ||
    request.observedAt <= latestRecordedTimestamp(contract)
  )
    return make(false, false, "stale-observation");
  if (
    contract.activeEscalations.length > 0 ||
    contract.autonomy.usage.cancelled
  )
    return make(false, false, "escalation-required");
  if (
    ((AUTOMATIC_DELIVERY_ACTIONS as readonly string[]).includes(
      request.effect,
    ) ||
      request.effect === "publication") &&
    contract.autonomy.usage.elapsedMinutes >=
      contract.autonomy.limits.durationMinutes
  )
    return make(false, false, "escalation-required");
  if (
    request.effect === "feature-push" ||
    request.effect === "pr-create-update"
  )
    return publicationEffectStates.has(contract.workflow.state) &&
      publicationIsFresh(contract) &&
      roleMayPerformAutomatic(
        request.actorRole,
        request.effect as AutomaticDeliveryAction,
      )
      ? make(true, false, "accepted")
      : make(false, false, "publication-denied");
  if (
    (AUTOMATIC_DELIVERY_ACTIONS as readonly string[]).includes(request.effect)
  ) {
    const automaticEffect = request.effect as AutomaticDeliveryAction;
    if (effectBudgetExhausted(contract, automaticEffect))
      return make(false, false, "escalation-required");
    if (
      (automaticEffect === "ci-repair" &&
        contract.workflow.observations.ci !== "failed") ||
      (automaticEffect === "ci-monitor" &&
        contract.workflow.observations.ci !== "pending" &&
        contract.workflow.observations.ci !== "failed")
    )
      return make(false, false, "role-authority-denied");
    return roleMayPerformAutomatic(request.actorRole, automaticEffect) &&
      effectAllowedInState(automaticEffect, contract.workflow.state)
      ? make(true, false, "accepted")
      : make(false, false, "role-authority-denied");
  }
  if (request.effect === "publication")
    return publicationEffectStates.has(contract.workflow.state) &&
      publicationIsFresh(contract) &&
      request.actorRole === "flow"
      ? make(true, false, "accepted")
      : make(false, false, "publication-denied");
  const protectedEffect = protectedGrantFor(request.effect);
  if (
    protectedEffect !== null &&
    hasGrant(contract, protectedEffect, request.targetTree)
  ) {
    if (request.actorRole !== "flow")
      return make(false, false, "role-authority-denied");
    return protectedEffectAllowedInState(
      request.effect,
      contract.workflow.state,
    )
      ? make(true, false, "accepted")
      : make(false, false, "publication-denied");
  }
  return make(false, false, "distinct-grant-required");
}

export interface AdministrativeRecoveryRequest {
  recoveryId: string;
  kind: AdministrativeRecoveryKind;
  idempotencyKey: string;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  identityRevalidated: boolean;
  targetGate: AdministrativeRecoveryRecord["targetGate"];
  observedAt: string;
}

export interface AdministrativeRecoveryDecision {
  allowed: boolean;
  idempotent: boolean;
  code: AdministrativeRecoveryDecisionCode;
  audit: AdministrativeRecoveryRecord;
}

const recoveryTargets = new Set<AdministrativeRecoveryRecord["targetGate"]>([
  "administrative",
  "identity",
  "security",
  "scope",
  "destructive-effect",
  "production",
]);

function isAdministrativeRecoveryRequest(
  value: unknown,
): value is AdministrativeRecoveryRequest {
  if (
    typeof value !== "object" ||
    value === null ||
    !hasExactKeys(value, [
      "recoveryId",
      "kind",
      "idempotencyKey",
      "actorRole",
      "actorId",
      "executionId",
      "workspaceId",
      "identityRevalidated",
      "targetGate",
      "observedAt",
    ])
  )
    return false;
  const request = value as Record<string, unknown>;
  return (
    isSafeRequestId(request.recoveryId) &&
    (ADMINISTRATIVE_RECOVERY_KINDS as readonly unknown[]).includes(
      request.kind,
    ) &&
    isSafeRequestId(request.idempotencyKey) &&
    (DELIVERY_ROLES as readonly unknown[]).includes(request.actorRole) &&
    isSafeRequestId(request.actorId) &&
    isSafeRequestId(request.executionId) &&
    isSafeRequestId(request.workspaceId) &&
    typeof request.identityRevalidated === "boolean" &&
    recoveryTargets.has(
      request.targetGate as AdministrativeRecoveryRecord["targetGate"],
    ) &&
    typeof request.observedAt === "string" &&
    isCanonicalLifecycleTimestamp(request.observedAt)
  );
}

export function evaluateAdministrativeRecovery(
  value: unknown,
  requestValue: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
): AdministrativeRecoveryDecision {
  const validation = validateFrozenDeliveryAuthorityContract(
    value,
    expectedAuthorityDigest,
    expectedMeteringDigest,
  );
  const requestSnapshot = canonicalSnapshot<unknown>(requestValue);
  const request = isAdministrativeRecoveryRequest(requestSnapshot)
    ? requestSnapshot
    : null;
  const observedAt = request?.observedAt ?? "1970-01-01T00:00:00.000Z";
  const fallback: AdministrativeRecoveryRequest = request ?? {
    recoveryId: "rejected-recovery",
    kind: "canonical-digest-refetch",
    idempotencyKey: "rejected-recovery",
    actorRole: "flow",
    actorId: "rejected-actor",
    executionId: "rejected-execution",
    workspaceId: "rejected-workspace",
    identityRevalidated: false,
    targetGate: "identity",
    observedAt: "1970-01-01T00:00:00.000Z",
  };
  const make = (
    allowed: boolean,
    idempotent: boolean,
    code: AdministrativeRecoveryDecisionCode,
  ): AdministrativeRecoveryDecision => ({
    allowed,
    idempotent,
    code,
    audit: {
      ...fallback,
      requestDigest: sha256(fallback),
      workflowState: validation.valid
        ? validation.value.workflow.state
        : "blocked",
      ciStatus: validation.valid
        ? validation.value.workflow.observations.ci
        : "not-started",
      accepted: allowed,
      code,
      observedAt,
    },
  });
  if (!validation.valid || request === null)
    return make(false, false, "contract-invalid");
  const contract = validation.value;
  const binding = contract.roles[request.actorRole];
  if (
    !request.identityRevalidated ||
    request.actorRole !== contract.activeRole ||
    request.actorId !== binding.actorId ||
    request.executionId !== binding.executionId ||
    request.workspaceId !== binding.workspaceId
  )
    return make(false, false, "identity-not-revalidated");
  const prior = contract.administrativeRecoveries.find(
    (record) => record.idempotencyKey === request.idempotencyKey,
  );
  const requestDigest = sha256(request);
  if (prior) {
    const priorDigest = sha256({
      recoveryId: prior.recoveryId,
      kind: prior.kind,
      idempotencyKey: prior.idempotencyKey,
      actorRole: prior.actorRole,
      actorId: prior.actorId,
      executionId: prior.executionId,
      workspaceId: prior.workspaceId,
      identityRevalidated: prior.identityRevalidated,
      targetGate: prior.targetGate,
      observedAt: prior.observedAt,
    });
    return priorDigest === requestDigest
      ? {
          allowed: false,
          idempotent: true,
          code: prior.code,
          audit: prior,
        }
      : make(false, false, "idempotency-conflict");
  }
  if (idempotencyKeyExists(contract, request.idempotencyKey))
    return make(false, false, "idempotency-conflict");
  if (
    request.observedAt !== contract.meteringObservedAt ||
    request.observedAt <= latestRecordedTimestamp(contract)
  )
    return make(false, false, "stale-observation");
  if (
    request.targetGate !== "administrative" ||
    (contract.workflow.state !== "blocked" &&
      contract.workflow.state !== "escalated") ||
    (request.kind === "interrupted-ci-polling" &&
      contract.workflow.observations.ci !== "pending" &&
      contract.workflow.observations.ci !== "failed")
  )
    return make(false, false, "recovery-gate-denied");
  return make(true, false, "accepted");
}

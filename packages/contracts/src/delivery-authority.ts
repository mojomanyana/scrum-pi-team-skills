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
export const DELIVERY_CONTROLLER_STATE_DIGEST_DOMAIN =
  "spts.delivery-authority/controller-state/1.0.0" as const;
export const DELIVERY_DECISION_CHECKPOINT_DIGEST_DOMAIN =
  "spts.delivery-authority/decision-checkpoint/1.0.0" as const;
export const DELIVERY_DECISION_CONTEXT_DIGEST_DOMAIN =
  "spts.delivery-authority/decision-context/1.0.0" as const;
export const DELIVERY_DECISION_RESULT_DIGEST_DOMAIN =
  "spts.delivery-authority/decision-result/1.0.0" as const;
export const DELIVERY_DECISION_CHAIN_DIGEST_DOMAIN =
  "spts.delivery-authority/decision-chain/1.0.0" as const;

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
  | "effect-state-denied"
  | "role-authority-denied"
  | "distinct-grant-required";

export type AdministrativeRecoveryDecisionCode =
  | "accepted"
  | "contract-invalid"
  | "idempotency-conflict"
  | "identity-not-revalidated"
  | "stale-observation"
  | "recovery-gate-denied";

export type DeliveryDecisionNamespace = "transition" | "effect" | "recovery";

export interface DeliveryDecisionContext {
  contractId: typeof DELIVERY_AUTHORITY_CONTRACT_ID;
  contractVersion: typeof DELIVERY_AUTHORITY_CONTRACT_VERSION;
  controllerStateDigest: string;
  authorityDigest: string;
  meteringDigest: string;
  meteringObservedAt: string;
  activeRole: DeliveryRole;
  governance: DeliveryAuthorityContract["governance"];
  task: DeliveryAuthorityContract["task"];
  roles: DeliveryAuthorityContract["roles"];
  workflowCheckpoint: DeliveryAuthorityContract["workflow"]["checkpoint"];
  workflowState: DeliveryWorkflowState;
  activeRepairBudget: "implementation" | "verification" | "ci";
  observations: DeliveryAuthorityContract["workflow"]["observations"];
  candidate: DeliveryCandidate;
  evidence: DeliveryEvidence[];
  autonomy: DeliveryAuthorityContract["autonomy"];
  effectGrants: DeliveryEffectGrant[];
  requestedEffects: DistinctGrantEffect[];
  activeEscalations: MandatoryEscalationReason[];
}

export interface DeliveryDecisionAuthentication {
  sequence: number;
  previousChainDigest: string;
  controllerStateDigest: string;
  historicalContext: DeliveryDecisionContext;
  historicalContextDigest: string;
  resultingStateDigest: string;
  resultingChainDigest: string;
}

export interface DeliveryTransitionAuditRecord {
  authentication: DeliveryDecisionAuthentication | null;
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

export type AdministrativeRecoveryDetails =
  | {
      fromProfile: "lean" | "standard" | "critical";
      toProfile: "lean" | "standard";
    }
  | { branch: string; headCommit: string; targetTree: string }
  | { priorDecisionSequence: number; priorDecisionChainDigest: string }
  | { evidenceId: string; freshThroughEventId: string }
  | {
      authorityDigest: string;
      meteringDigest: string;
      controllerStateDigest: string;
    }
  | { agentExecutionId: string; agentWorkspaceId: string }
  | {
      candidateTree: string;
      candidateCommit: string;
      pullRequestNumber: number;
      priorEffectSequence: number;
      originalIdempotencyKey: string;
      originalRequestDigest: string;
      priorOutcome: "authorization-issued-outcome-unknown";
    }
  | { ciRunId: string; ciCheckId: string };

export interface AdministrativeRecoveryRecord {
  authentication: DeliveryDecisionAuthentication | null;
  recoveryId: string;
  kind: AdministrativeRecoveryKind;
  idempotencyKey: string;
  requestDigest: string;
  details: AdministrativeRecoveryDetails;
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
  authentication: DeliveryDecisionAuthentication | null;
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
  controllerStateDigest: string;
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
      decisionSequence: number;
      decisionChainDigest: string;
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
    decisionChain: {
      sequence: number;
      digest: string;
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

/**
 * Canonical digest claim for the complete evolving controller state. This
 * value is not a trust anchor by itself: decision boundaries compare it with
 * a separately supplied digest from the trusted controller.
 */
export function computeDeliveryControllerStateDigest(
  contract: DeliveryAuthorityContract,
): string {
  const state = { ...contract } as Record<string, unknown>;
  delete state.controllerStateDigest;
  return sha256({
    domain: DELIVERY_CONTROLLER_STATE_DIGEST_DOMAIN,
    state,
  });
}

export function computeDeliveryDecisionCheckpointDigest(
  contract: DeliveryAuthorityContract,
): string {
  const checkpoint = { ...contract.workflow.checkpoint } as Record<
    string,
    unknown
  >;
  delete checkpoint.decisionChainDigest;
  return sha256({
    domain: DELIVERY_DECISION_CHECKPOINT_DIGEST_DOMAIN,
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    projectId: contract.task.paca.projectId,
    taskId: contract.task.paca.taskId,
    repositoryId: contract.task.repository.repositoryId,
    checkpoint,
  });
}

export function computeDeliveryDecisionContextDigest(
  context: DeliveryDecisionContext,
): string {
  return sha256({
    domain: DELIVERY_DECISION_CONTEXT_DIGEST_DOMAIN,
    context,
  });
}

export function computeDeliveryDecisionResultDigest(
  context: DeliveryDecisionContext,
): string {
  return sha256({
    domain: DELIVERY_DECISION_RESULT_DIGEST_DOMAIN,
    context,
  });
}

export function computeDeliveryDecisionChainDigest(
  namespace: DeliveryDecisionNamespace,
  record:
    | DeliveryTransitionAuditRecord
    | DeliveryEffectAuditRecord
    | AdministrativeRecoveryRecord,
): string {
  const unsigned = { ...record } as Record<string, unknown>;
  const authentication = record.authentication;
  if (authentication !== null) {
    const unsignedAuthentication = { ...authentication } as Record<
      string,
      unknown
    >;
    delete unsignedAuthentication.resultingChainDigest;
    unsigned.authentication = unsignedAuthentication;
  }
  return sha256({
    domain: DELIVERY_DECISION_CHAIN_DIGEST_DOMAIN,
    namespace,
    record: unsigned,
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

function createDeliveryDecisionContext(
  contract: DeliveryAuthorityContract,
  trustedControllerStateDigest: string,
): DeliveryDecisionContext {
  const context = canonicalSnapshot<DeliveryDecisionContext>({
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    controllerStateDigest: trustedControllerStateDigest,
    authorityDigest: contract.authorityDigest,
    meteringDigest: contract.meteringDigest,
    meteringObservedAt: contract.meteringObservedAt,
    activeRole: contract.activeRole,
    governance: contract.governance,
    task: contract.task,
    roles: contract.roles,
    workflowCheckpoint: contract.workflow.checkpoint,
    workflowState: contract.workflow.state,
    activeRepairBudget: activeRepairBudget(contract),
    observations: contract.workflow.observations,
    candidate: contract.workflow.candidate,
    evidence: contract.evidence,
    autonomy: contract.autonomy,
    effectGrants: contract.effectGrants,
    requestedEffects: contract.requestedEffects,
    activeEscalations: contract.activeEscalations,
  });
  if (context === null)
    throw new TypeError("validated controller state could not be snapshotted");
  return context;
}

function transitionResultContext(
  context: DeliveryDecisionContext,
  from: DeliveryWorkflowState,
  to: DeliveryWorkflowState,
  accepted: boolean,
): DeliveryDecisionContext {
  const result = canonicalSnapshot<DeliveryDecisionContext>(context);
  if (result === null)
    throw new TypeError("validated decision context could not be snapshotted");
  if (!accepted) return result;
  result.workflowState = to;
  if (to === "repair-required")
    result.activeRepairBudget =
      from === "pr-ci-monitoring" ? "ci" : "verification";
  if (to === "implementation") {
    if (from === "ready") result.autonomy.usage.implementationAttempts += 1;
    else if (from === "repair-required") {
      if (result.activeRepairBudget === "ci")
        result.autonomy.usage.ciRepairAttempts += 1;
      else if (result.activeRepairBudget === "verification")
        result.autonomy.usage.verificationRepairAttempts += 1;
    }
  }
  return result;
}

function authenticateDecisionRecord(
  contract: DeliveryAuthorityContract,
  trustedControllerStateDigest: string,
  namespace: DeliveryDecisionNamespace,
  record:
    | DeliveryTransitionAuditRecord
    | DeliveryEffectAuditRecord
    | AdministrativeRecoveryRecord,
  resultingContext: DeliveryDecisionContext,
): void {
  const historicalContext = createDeliveryDecisionContext(
    contract,
    trustedControllerStateDigest,
  );
  const authentication: DeliveryDecisionAuthentication = {
    sequence: contract.workflow.decisionChain.sequence + 1,
    previousChainDigest: contract.workflow.decisionChain.digest,
    controllerStateDigest: trustedControllerStateDigest,
    historicalContext,
    historicalContextDigest:
      computeDeliveryDecisionContextDigest(historicalContext),
    resultingStateDigest: computeDeliveryDecisionResultDigest(resultingContext),
    resultingChainDigest: "0".repeat(64),
  };
  record.authentication = authentication;
  authentication.resultingChainDigest = computeDeliveryDecisionChainDigest(
    namespace,
    record,
  );
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
  if (
    contract.autonomy.usage.elapsedMinutes >=
    contract.autonomy.limits.durationMinutes
  )
    return true;
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
    gateBoundary.observedAt <= merge.observedAt &&
    merge.observedAt <= contract.meteringObservedAt
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

function hasCurrentApprovalEvidence(
  contract: DeliveryAuthorityContract,
): boolean {
  const candidate = contract.workflow.candidate;
  return contract.evidence.some(
    (evidence) =>
      evidence.verification.verdict === "APPROVE" &&
      evidence.verification.approvalId === candidate.verification.approvalId &&
      evidence.verification.reviewedTree === candidate.tree &&
      evidence.repository.commit === candidate.headCommit &&
      evidence.repository.tree === candidate.tree &&
      evidence.pullRequest.number === candidate.pullRequest.number &&
      evidence.pullRequest.baseBranch === candidate.pullRequest.baseBranch &&
      evidence.pullRequest.headBranch === candidate.pullRequest.headBranch &&
      evidence.pullRequest.headCommit === candidate.headCommit &&
      evidence.observedAt === candidate.verification.observedAt,
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

interface AuthenticatedDecisionEntry {
  namespace: DeliveryDecisionNamespace;
  record:
    | DeliveryTransitionAuditRecord
    | DeliveryEffectAuditRecord
    | AdministrativeRecoveryRecord;
  authentication: DeliveryDecisionAuthentication;
}

function decisionContextAsContract(
  context: DeliveryDecisionContext,
  transitionsBefore: DeliveryTransitionAuditRecord[] = [],
  effectsBefore: DeliveryEffectAuditRecord[] = [],
  recoveriesBefore: AdministrativeRecoveryRecord[] = [],
): DeliveryAuthorityContract {
  return {
    contractId: context.contractId,
    contractVersion: context.contractVersion,
    authorityDigest: context.authorityDigest,
    controllerStateDigest: context.controllerStateDigest,
    meteringDigest: context.meteringDigest,
    meteringObservedAt: context.meteringObservedAt,
    activeRole: context.activeRole,
    governance: context.governance,
    task: context.task,
    roles: context.roles,
    automaticActions: [...AUTOMATIC_DELIVERY_ACTIONS],
    humanGatedActions: [...HUMAN_GATED_DELIVERY_ACTIONS],
    workflow: {
      state: context.workflowState,
      checkpoint: context.workflowCheckpoint,
      decisionChain: {
        sequence: context.workflowCheckpoint.decisionSequence,
        digest: context.workflowCheckpoint.decisionChainDigest,
      },
      observations: context.observations,
      candidate: context.candidate,
      audit: transitionsBefore,
    },
    evidence: context.evidence,
    autonomy: context.autonomy,
    effectGrants: context.effectGrants,
    requestedEffects: context.requestedEffects,
    administrativeRecoveries: recoveriesBefore,
    activeEscalations: context.activeEscalations,
    effectAudit: effectsBefore,
  };
}

function historicalDecisionContextIsBound(
  context: DeliveryDecisionContext,
  current: DeliveryAuthorityContract,
  transitionsBefore: DeliveryTransitionAuditRecord[],
): boolean {
  if (
    sha256(context.governance) !== sha256(current.governance) ||
    sha256(context.task) !== sha256(current.task) ||
    sha256(context.roles) !== sha256(current.roles) ||
    sha256(context.autonomy.limits) !== sha256(current.autonomy.limits)
  )
    return false;
  const bindings = DELIVERY_ROLES.map((role) => context.roles[role]);
  for (const role of DELIVERY_ROLES) {
    const binding = context.roles[role];
    if (binding.role !== role || binding.access !== roleAccess[role])
      return false;
  }
  for (const property of ["actorId", "executionId", "workspaceId"] as const)
    if (
      new Set(bindings.map((binding) => binding[property])).size !==
      bindings.length
    )
      return false;
  if (
    context.activeEscalations.length > 0 &&
    context.workflowState !== "blocked" &&
    context.workflowState !== "escalated"
  )
    return false;
  const candidateVerifier = context.roles["independent-verifier"];
  if (
    !isCanonicalLifecycleTimestamp(context.candidate.verification.observedAt) ||
    context.candidate.verification.observedAt > context.meteringObservedAt ||
    context.candidate.verification.executionId !==
      candidateVerifier.executionId ||
    context.candidate.verification.workspaceId !== candidateVerifier.workspaceId
  )
    return false;
  const transitionEvents = new Map(
    transitionsBefore.map((transition) => [transition.eventId, transition]),
  );
  for (const evidence of context.evidence) {
    if (
      !isCanonicalLifecycleTimestamp(evidence.observedAt) ||
      evidence.observedAt > context.meteringObservedAt
    )
      return false;
    const binding = context.roles[evidence.actor.role];
    if (
      evidence.task.projectId !== context.task.paca.projectId ||
      evidence.task.taskId !== context.task.paca.taskId ||
      evidence.repository.repositoryId !==
        context.task.repository.repositoryId ||
      evidence.repository.branch !== context.task.repository.featureBranch ||
      evidence.actor.actorId !== binding.actorId ||
      evidence.actor.executionId !== binding.executionId ||
      evidence.actor.workspaceId !== binding.workspaceId ||
      evidence.assurance.runId !== context.task.assurance.runId ||
      evidence.assurance.profile !== context.task.assurance.profile
    )
      return false;
    const event = transitionEvents.get(evidence.freshThroughEventId);
    const checkpointFresh =
      evidence.freshThroughEventId ===
        context.workflowCheckpoint.checkpointId &&
      context.workflowCheckpoint.candidateTree === evidence.repository.tree &&
      context.workflowCheckpoint.observedAt <= evidence.observedAt;
    const eventFresh =
      event !== undefined &&
      event.candidateTree === evidence.repository.tree &&
      event.observedAt <= evidence.observedAt;
    if (!checkpointFresh && !eventFresh) return false;
    const hasVerification = evidence.verification.verdict !== null;
    if (
      hasVerification &&
      (evidence.actor.role !== "independent-verifier" ||
        evidence.verification.reviewedTree !== evidence.repository.tree ||
        evidence.pullRequest.number === null ||
        evidence.pullRequest.baseBranch !==
          context.task.repository.baseBranch ||
        evidence.pullRequest.headBranch !==
          context.task.repository.featureBranch ||
        evidence.pullRequest.headCommit !== evidence.repository.commit ||
        (evidence.verification.verdict === "APPROVE") !==
          (evidence.verification.approvalId !== null))
    )
      return false;
    if (
      !hasVerification &&
      (evidence.verification.reviewedTree !== null ||
        evidence.verification.approvalId !== null)
    )
      return false;
    if (
      evidence.ci.verdict === null
        ? (evidence.ci.runId === null) !== (evidence.ci.checkId === null)
        : evidence.ci.runId === null || evidence.ci.checkId === null
    )
      return false;
  }
  const mergeObservedAt = context.observations.merge.observedAt;
  if (
    mergeObservedAt !== null &&
    (!isCanonicalLifecycleTimestamp(mergeObservedAt) ||
      mergeObservedAt > context.meteringObservedAt)
  )
    return false;
  for (const [usage, limit] of [
    ["implementationAttempts", "implementationAttempts"],
    ["verificationRepairAttempts", "verificationRepairAttempts"],
    ["ciRepairAttempts", "ciRepairAttempts"],
    ["elapsedMinutes", "durationMinutes"],
    ["concurrentAgents", "concurrentAgents"],
    ["worktrees", "worktrees"],
    ["evidenceBytes", "evidenceBytes"],
  ] as const)
    if (context.autonomy.usage[usage] > context.autonomy.limits[limit])
      return false;
  return true;
}

function authenticatedDecisionEntries(
  contract: DeliveryAuthorityContract,
  errors: DeliveryContractError[],
): AuthenticatedDecisionEntry[] {
  const groups: Array<{
    namespace: DeliveryDecisionNamespace;
    records: Array<
      | DeliveryTransitionAuditRecord
      | DeliveryEffectAuditRecord
      | AdministrativeRecoveryRecord
    >;
  }> = [
    { namespace: "transition", records: contract.workflow.audit },
    { namespace: "effect", records: contract.effectAudit },
    { namespace: "recovery", records: contract.administrativeRecoveries },
  ];
  const entries: AuthenticatedDecisionEntry[] = [];
  for (const group of groups) {
    let priorSequence = -1;
    for (const record of group.records) {
      const authentication = record.authentication;
      if (authentication === null) {
        errors.push(
          fixedError(
            "/",
            "decision-authentication",
            "persisted decisions require authenticated controller context",
          ),
        );
        continue;
      }
      if (authentication.sequence <= priorSequence)
        errors.push(
          fixedError(
            "/",
            "decision-order",
            "decision records must retain increasing authenticated sequence order",
          ),
        );
      priorSequence = authentication.sequence;
      entries.push({ namespace: group.namespace, record, authentication });
    }
  }
  entries.sort(
    (left, right) =>
      left.authentication.sequence - right.authentication.sequence,
  );
  let expectedSequence = contract.workflow.checkpoint.decisionSequence + 1;
  let previousChainDigest = contract.workflow.checkpoint.decisionChainDigest;
  let previousTimestamp = contract.workflow.checkpoint.observedAt;
  const sequenceSeen = new Set<number>();
  const transitionsBefore: DeliveryTransitionAuditRecord[] = [];
  const effectsBefore: DeliveryEffectAuditRecord[] = [];
  const recoveriesBefore: AdministrativeRecoveryRecord[] = [];
  for (const entry of entries) {
    const { authentication, namespace, record } = entry;
    if (
      sequenceSeen.has(authentication.sequence) ||
      authentication.sequence !== expectedSequence
    )
      errors.push(
        fixedError(
          "/",
          "decision-sequence",
          "authenticated decision sequences must be unique and contiguous",
        ),
      );
    sequenceSeen.add(authentication.sequence);
    expectedSequence += 1;
    if (authentication.previousChainDigest !== previousChainDigest)
      errors.push(
        fixedError(
          "/",
          "decision-chain",
          "authenticated decisions must retain exact previous-chain continuity",
        ),
      );
    if (record.observedAt <= previousTimestamp)
      errors.push(
        fixedError(
          "/",
          "decision-time-order",
          "authenticated decision timestamps must increase monotonically",
        ),
      );
    previousTimestamp = record.observedAt;
    const context = authentication.historicalContext;
    if (
      authentication.controllerStateDigest !== context.controllerStateDigest ||
      authentication.historicalContextDigest !==
        computeDeliveryDecisionContextDigest(context)
    )
      errors.push(
        fixedError(
          "/",
          "decision-context-digest",
          "historical decision context must match its authenticated digest",
        ),
      );
    const contextContract = decisionContextAsContract(context);
    if (
      context.authorityDigest !==
        computeDeliveryAuthorityDigest(contextContract) ||
      context.meteringDigest !== computeDeliveryMeteringDigest(contextContract)
    )
      errors.push(
        fixedError(
          "/",
          "decision-context-authority",
          "historical decision context must retain canonical authority and metering digests",
        ),
      );
    if (
      context.workflowCheckpoint.decisionChainDigest !==
        computeDeliveryDecisionCheckpointDigest(contextContract) ||
      sha256(context.workflowCheckpoint) !==
        sha256(contract.workflow.checkpoint)
    )
      errors.push(
        fixedError(
          "/",
          "decision-checkpoint",
          "historical decisions must descend from the frozen decision checkpoint",
        ),
      );
    const contextEvidenceBytes = Buffer.byteLength(
      canonicalSerializeLifecycleValue(context.evidence),
      "utf8",
    );
    if (
      context.autonomy.usage.evidenceBytes !== contextEvidenceBytes ||
      context.evidence.some(
        (evidence) =>
          evidence.evidenceDigest !== computeDeliveryEvidenceDigest(evidence),
      ) ||
      !historicalDecisionContextIsBound(context, contract, transitionsBefore)
    )
      errors.push(
        fixedError(
          "/",
          "decision-context-evidence",
          "historical context must retain canonical role, evidence, time, and capacity bindings",
        ),
      );
    if (
      context.meteringObservedAt !== record.observedAt ||
      record.observedAt > contract.meteringObservedAt
    )
      errors.push(
        fixedError(
          "/",
          "decision-time-authority",
          "historical decision time must equal its trusted metering context and not exceed current controller time",
        ),
      );
    let resultingContext = canonicalSnapshot<DeliveryDecisionContext>(context);
    if (resultingContext === null) resultingContext = context;
    if (namespace === "transition") {
      const transition = record as DeliveryTransitionAuditRecord;
      const transitionRequest: DeliveryTransitionRequest = {
        eventId: transition.eventId,
        idempotencyKey: transition.idempotencyKey,
        from: transition.from,
        to: transition.to,
        actorRole: transition.actorRole,
        actorId: transition.actorId,
        executionId: transition.executionId,
        workspaceId: transition.workspaceId,
        candidateTree: transition.candidateTree,
        observedAt: transition.observedAt,
      };
      const historicalContract = decisionContextAsContract(
        context,
        transitionsBefore,
      );
      const expectedUsage = expectedAttemptUsage(historicalContract);
      if (
        context.activeRepairBudget !== activeRepairBudget(historicalContract) ||
        context.autonomy.usage.implementationAttempts !==
          expectedUsage.implementationAttempts ||
        context.autonomy.usage.verificationRepairAttempts !==
          expectedUsage.verificationRepairAttempts ||
        context.autonomy.usage.ciRepairAttempts !==
          expectedUsage.ciRepairAttempts
      )
        errors.push(
          fixedError(
            "/",
            "decision-attempt-provenance",
            "historical attempt usage must follow the authenticated transition prefix",
          ),
        );
      const expectedCode = deliveryTransitionPolicyCode(
        historicalContract,
        transitionRequest,
      );
      if (
        transition.requestDigest !== sha256(transitionRequest) ||
        transition.code !== expectedCode ||
        transition.accepted !== (expectedCode === "accepted")
      )
        errors.push(
          fixedError(
            "/workflow/audit",
            "historical-transition-authority",
            "transition receipt must match its authenticated historical policy decision",
          ),
        );
      resultingContext = transitionResultContext(
        context,
        transition.from,
        transition.to,
        transition.accepted,
      );
      transitionsBefore.push(transition);
    } else if (namespace === "effect") {
      const effect = record as DeliveryEffectAuditRecord;
      const effectRequest: DeliveryEffectRequest = {
        effect: effect.effect as DeliveryEffect,
        idempotencyKey: effect.idempotencyKey,
        actorRole: effect.actorRole,
        actorId: effect.actorId,
        executionId: effect.executionId,
        workspaceId: effect.workspaceId,
        targetTree: effect.targetTree,
        observedAt: effect.observedAt,
      };
      const historicalContract = decisionContextAsContract(
        context,
        transitionsBefore,
        effectsBefore,
        recoveriesBefore,
      );
      const expectedCode = deliveryEffectPolicyCode(
        historicalContract,
        effectRequest,
      );
      if (
        effect.workflowState !== context.workflowState ||
        effect.requestDigest !== sha256(effectRequest) ||
        effect.code !== expectedCode ||
        effect.allowed !== (expectedCode === "accepted")
      )
        errors.push(
          fixedError(
            "/effectAudit",
            "historical-effect-authority",
            "effect receipt must match its authenticated historical policy decision",
          ),
        );
      effectsBefore.push(effect);
    } else {
      const recovery = record as AdministrativeRecoveryRecord;
      const recoveryRequest = {
        recoveryId: recovery.recoveryId,
        kind: recovery.kind,
        idempotencyKey: recovery.idempotencyKey,
        actorRole: recovery.actorRole,
        actorId: recovery.actorId,
        executionId: recovery.executionId,
        workspaceId: recovery.workspaceId,
        identityRevalidated: recovery.identityRevalidated,
        targetGate: recovery.targetGate,
        details: recovery.details,
        observedAt: recovery.observedAt,
      } as AdministrativeRecoveryRequest;
      const historicalContract = decisionContextAsContract(
        context,
        transitionsBefore,
        effectsBefore,
        recoveriesBefore,
      );
      const expectedCode = deliveryRecoveryPolicyCode(
        historicalContract,
        recoveryRequest,
      );
      if (
        recovery.workflowState !== context.workflowState ||
        recovery.ciStatus !== context.observations.ci ||
        recovery.requestDigest !== sha256(recoveryRequest) ||
        recovery.code !== expectedCode ||
        recovery.accepted !== (expectedCode === "accepted")
      )
        errors.push(
          fixedError(
            "/administrativeRecoveries",
            "historical-recovery-authority",
            "recovery receipt must match its authenticated kind-specific historical policy decision",
          ),
        );
      recoveriesBefore.push(recovery);
    }
    if (
      authentication.resultingStateDigest !==
      computeDeliveryDecisionResultDigest(resultingContext)
    )
      errors.push(
        fixedError(
          "/",
          "decision-result-digest",
          "decision result must match its authenticated resulting state digest",
        ),
      );
    if (
      authentication.resultingChainDigest !==
      computeDeliveryDecisionChainDigest(namespace, record)
    )
      errors.push(
        fixedError(
          "/",
          "decision-chain-digest",
          "decision receipt must match its authenticated chain digest",
        ),
      );
    previousChainDigest = authentication.resultingChainDigest;
  }
  const expectedHeadSequence = expectedSequence - 1;
  if (
    contract.workflow.checkpoint.decisionChainDigest !==
    computeDeliveryDecisionCheckpointDigest(contract)
  )
    errors.push(
      fixedError(
        "/workflow/checkpoint/decisionChainDigest",
        "decision-checkpoint",
        "decision checkpoint must match its canonical domain-separated digest",
      ),
    );
  if (
    contract.workflow.decisionChain.sequence !== expectedHeadSequence ||
    contract.workflow.decisionChain.digest !== previousChainDigest
  )
    errors.push(
      fixedError(
        "/workflow/decisionChain",
        "decision-chain-head",
        "decision chain head must equal the complete authenticated history",
      ),
    );
  return entries;
}

function semanticErrors(
  contract: DeliveryAuthorityContract,
): DeliveryContractError[] {
  const errors: DeliveryContractError[] = [];
  authenticatedDecisionEntries(contract, errors);
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
  if (
    contract.controllerStateDigest !==
    computeDeliveryControllerStateDigest(contract)
  )
    errors.push(
      fixedError(
        "/controllerStateDigest",
        "controller-state-digest",
        "must match the canonical complete controller state digest",
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
    const reconstructedRecovery = {
      recoveryId: recovery.recoveryId,
      kind: recovery.kind,
      idempotencyKey: recovery.idempotencyKey,
      actorRole: recovery.actorRole,
      actorId: recovery.actorId,
      executionId: recovery.executionId,
      workspaceId: recovery.workspaceId,
      identityRevalidated: recovery.identityRevalidated,
      targetGate: recovery.targetGate,
      details: recovery.details,
      observedAt: recovery.observedAt,
    } as AdministrativeRecoveryRequest;
    if (!isAdministrativeRecoveryDetails(recovery.kind, recovery.details))
      errors.push(
        fixedError(
          "/administrativeRecoveries",
          "recovery-details",
          "recovery details must match the selected canonical recovery kind",
        ),
      );
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
        freshEvent.candidateTree !== evidence.repository.tree ||
        freshEvent.observedAt > evidence.observedAt) &&
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
  expectedControllerStateDigest: unknown,
): DeliveryAuthorityValidationResult {
  const validation = validateDeliveryAuthorityContract(value);
  if (!validation.valid) return validation;
  if (
    typeof expectedAuthorityDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(expectedAuthorityDigest) ||
    validation.value.authorityDigest !== expectedAuthorityDigest
  )
    return {
      valid: false,
      errors: [
        fixedError(
          "/authorityDigest",
          "frozen-authority",
          "must match the separately trusted static authority digest",
        ),
      ],
    };
  if (
    typeof expectedMeteringDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(expectedMeteringDigest) ||
    validation.value.meteringDigest !== expectedMeteringDigest
  )
    return {
      valid: false,
      errors: [
        fixedError(
          "/meteringDigest",
          "frozen-metering",
          "must match the separately trusted monotonic metering digest",
        ),
      ],
    };
  if (
    typeof expectedControllerStateDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(expectedControllerStateDigest) ||
    validation.value.controllerStateDigest !== expectedControllerStateDigest
  )
    return {
      valid: false,
      errors: [
        fixedError(
          "/controllerStateDigest",
          "frozen-controller-state",
          "must match the separately trusted complete controller state digest",
        ),
      ],
    };
  return validation;
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
    ...(contract.workflow.observations.merge.observedAt === null
      ? []
      : [contract.workflow.observations.merge.observedAt]),
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
  contract: DeliveryAuthorityContract | null,
  trustedControllerStateDigest: string | null,
  request: DeliveryTransitionRequest,
  requestDigest: string,
  accepted: boolean,
  code: DeliveryTransitionDecisionCode,
): DeliveryTransitionAuditRecord {
  const record: DeliveryTransitionAuditRecord = {
    authentication: null,
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
  if (contract !== null && trustedControllerStateDigest !== null) {
    const historicalContext = createDeliveryDecisionContext(
      contract,
      trustedControllerStateDigest,
    );
    authenticateDecisionRecord(
      contract,
      trustedControllerStateDigest,
      "transition",
      record,
      transitionResultContext(
        historicalContext,
        request.from,
        request.to,
        accepted,
      ),
    );
  }
  return record;
}

function deliveryTransitionPolicyCode(
  contract: DeliveryAuthorityContract,
  request: DeliveryTransitionRequest,
): DeliveryTransitionDecisionCode {
  const binding = contract.roles[request.actorRole];
  if (request.actorRole !== contract.activeRole) return "identity-drift";
  if (containsCredentialShapedContent(request.actorId)) return "request-denied";
  if (
    request.observedAt !== contract.meteringObservedAt ||
    request.observedAt <= latestRecordedTimestamp(contract)
  )
    return "stale-observation";
  if (
    request.from !== contract.workflow.state ||
    request.candidateTree !== contract.workflow.candidate.tree ||
    binding.actorId !== request.actorId ||
    binding.executionId !== request.executionId ||
    binding.workspaceId !== request.workspaceId
  )
    return "identity-drift";
  if (
    !transitions[request.from].includes(request.to) ||
    !roleMayTransition(request.actorRole, request.from, request.to) ||
    contract.autonomy.usage.cancelled ||
    (contract.activeEscalations.length > 0 && request.to === "ready")
  )
    return "transition-denied";
  if (transitionBudgetExhausted(contract, request.from, request.to))
    return "autonomy-exhausted";
  if (
    request.to === "publication-authorized" &&
    (!publicationIsFresh(contract) || !hasCurrentApprovalEvidence(contract))
  )
    return "publication-denied";
  if (
    (request.to === "merge-gate" || request.to === "completed") &&
    !hasFreshPassingCiEvidence(contract)
  )
    return "ci-evidence-required";
  if (
    (request.to === "merge-gate" || request.to === "completed") &&
    !hasGrant(contract, "merge")
  )
    return "merge-grant-required";
  if (request.to === "completed" && !mergeObservationIsFresh(contract))
    return "merge-observation-required";
  return "accepted";
}

export function evaluateDeliveryTransition(
  value: unknown,
  requestValue: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
  expectedControllerStateDigest: unknown,
): DeliveryTransitionDecision {
  const validation = validateFrozenDeliveryAuthorityContract(
    value,
    expectedAuthorityDigest,
    expectedMeteringDigest,
    expectedControllerStateDigest,
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
        null,
        null,
        fallback,
        sha256(fallback),
        false,
        "contract-invalid",
      ),
    };
  }
  const contract = validation.value;
  const requestDigest = sha256(request);
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
        : decisionAudit(
            contract,
            expectedControllerStateDigest as string,
            request,
            requestDigest,
            false,
            "idempotency-conflict",
          ),
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
        contract,
        expectedControllerStateDigest as string,
        request,
        requestDigest,
        false,
        "idempotency-conflict",
      ),
    };

  const code = deliveryTransitionPolicyCode(contract, request);
  const accepted = code === "accepted";
  return {
    accepted,
    idempotent: false,
    code,
    nextState: accepted ? request.to : contract.workflow.state,
    audit: decisionAudit(
      contract,
      expectedControllerStateDigest as string,
      request,
      requestDigest,
      accepted,
      code,
    ),
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
  if (
    effect === "release" ||
    effect === "tag" ||
    effect === "artifact-publication" ||
    effect === "production" ||
    effect === "production-access" ||
    effect === "deployment"
  )
    return state === "completed";
  if (
    effect === "destructive-git" ||
    effect === "force-push" ||
    effect === "history-rewrite" ||
    effect === "branch-delete"
  )
    return state === "blocked";
  if (effect === "real-pi" || effect === "real-pi-execution")
    return state === "ready" || state === "implementation";
  return false;
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

function deliveryEffectPolicyCode(
  contract: DeliveryAuthorityContract,
  request: DeliveryEffectRequest,
): DeliveryEffectDecisionCode {
  if (request.actorRole !== contract.activeRole) return "role-authority-denied";
  const binding = contract.roles[request.actorRole];
  if (
    binding.actorId !== request.actorId ||
    binding.executionId !== request.executionId ||
    binding.workspaceId !== request.workspaceId ||
    request.targetTree !== contract.workflow.candidate.tree ||
    containsCredentialShapedContent(request.actorId)
  )
    return "identity-drift";
  if (
    request.observedAt !== contract.meteringObservedAt ||
    request.observedAt <= latestRecordedTimestamp(contract)
  )
    return "stale-observation";
  if (
    contract.activeEscalations.length > 0 ||
    contract.autonomy.usage.cancelled ||
    contract.autonomy.usage.elapsedMinutes >=
      contract.autonomy.limits.durationMinutes
  )
    return "escalation-required";

  if (
    request.effect === "feature-push" ||
    request.effect === "pr-create-update"
  )
    return publicationEffectStates.has(contract.workflow.state) &&
      publicationIsFresh(contract) &&
      hasCurrentApprovalEvidence(contract) &&
      roleMayPerformAutomatic(
        request.actorRole,
        request.effect as AutomaticDeliveryAction,
      )
      ? "accepted"
      : "publication-denied";

  if (
    (AUTOMATIC_DELIVERY_ACTIONS as readonly string[]).includes(request.effect)
  ) {
    const automaticEffect = request.effect as AutomaticDeliveryAction;
    if (automaticEffect === "administrative-recovery")
      return "role-authority-denied";
    if (effectBudgetExhausted(contract, automaticEffect))
      return "escalation-required";
    if (
      (automaticEffect === "ci-repair" &&
        contract.workflow.observations.ci !== "failed") ||
      (automaticEffect === "ci-monitor" &&
        contract.workflow.observations.ci !== "pending" &&
        contract.workflow.observations.ci !== "failed")
    )
      return "role-authority-denied";
    return roleMayPerformAutomatic(request.actorRole, automaticEffect) &&
      effectAllowedInState(automaticEffect, contract.workflow.state)
      ? "accepted"
      : "role-authority-denied";
  }

  if (request.effect === "publication")
    return publicationEffectStates.has(contract.workflow.state) &&
      publicationIsFresh(contract) &&
      hasCurrentApprovalEvidence(contract) &&
      request.actorRole === "flow"
      ? "accepted"
      : "publication-denied";

  const protectedEffect = protectedGrantFor(request.effect);
  if (protectedEffect === null) return "distinct-grant-required";
  if (request.actorRole !== "flow") return "role-authority-denied";
  if (
    !contract.requestedEffects.includes(protectedEffect) ||
    !hasGrant(contract, protectedEffect, request.targetTree)
  )
    return "distinct-grant-required";
  if (!protectedEffectAllowedInState(request.effect, contract.workflow.state))
    return "effect-state-denied";
  if (
    protectedEffect === "real-pi" &&
    contract.autonomy.usage.concurrentAgents >=
      contract.autonomy.limits.concurrentAgents
  )
    return "escalation-required";
  if (
    (protectedEffect === "merge" ||
      protectedEffect === "release" ||
      protectedEffect === "production") &&
    (!hasFreshPassingCiEvidence(contract) ||
      (contract.workflow.state === "completed" &&
        !mergeObservationIsFresh(contract)))
  )
    return "publication-denied";
  return "accepted";
}

export function authorizeDeliveryEffect(
  value: unknown,
  requestValue: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
  expectedControllerStateDigest: unknown,
): DeliveryEffectDecision {
  const validation = validateFrozenDeliveryAuthorityContract(
    value,
    expectedAuthorityDigest,
    expectedMeteringDigest,
    expectedControllerStateDigest,
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
  ): DeliveryEffectDecision => {
    const audit: DeliveryEffectAuditRecord = {
      authentication: null,
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
    };
    if (
      validation.valid &&
      request !== null &&
      typeof expectedControllerStateDigest === "string"
    ) {
      const context = createDeliveryDecisionContext(
        validation.value,
        expectedControllerStateDigest,
      );
      authenticateDecisionRecord(
        validation.value,
        expectedControllerStateDigest,
        "effect",
        audit,
        context,
      );
    }
    return { allowed, idempotent, code, audit };
  };
  if (!validation.valid || request === null)
    return make(false, false, "contract-invalid");
  const contract = validation.value;
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
  const code = deliveryEffectPolicyCode(contract, request);
  return make(code === "accepted", false, code);
}

interface AdministrativeRecoveryRequestBase {
  recoveryId: string;
  idempotencyKey: string;
  actorRole: DeliveryRole;
  actorId: string;
  executionId: string;
  workspaceId: string;
  identityRevalidated: boolean;
  targetGate: AdministrativeRecoveryRecord["targetGate"];
  observedAt: string;
}

export type AdministrativeRecoveryRequest = AdministrativeRecoveryRequestBase &
  (
    | {
        kind: "redundant-profile-downgrade";
        details: Extract<
          AdministrativeRecoveryDetails,
          { fromProfile: string }
        >;
      }
    | {
        kind: "missing-keep-branch-finish";
        details: Extract<AdministrativeRecoveryDetails, { branch: string }>;
      }
    | {
        kind: "repair-receipt-sequencing";
        details: Extract<
          AdministrativeRecoveryDetails,
          { priorDecisionSequence: number }
        >;
      }
    | {
        kind: "stale-evidence-after-controller-event";
        details: Extract<AdministrativeRecoveryDetails, { evidenceId: string }>;
      }
    | {
        kind: "canonical-digest-refetch";
        details: Extract<
          AdministrativeRecoveryDetails,
          { authorityDigest: string }
        >;
      }
    | {
        kind: "disappeared-agent-clean-worktree";
        details: Extract<
          AdministrativeRecoveryDetails,
          { agentExecutionId: string }
        >;
      }
    | {
        kind: "idempotent-push-pr-reconciliation";
        details: Extract<
          AdministrativeRecoveryDetails,
          { priorEffectSequence: number }
        >;
      }
    | {
        kind: "interrupted-ci-polling";
        details: Extract<AdministrativeRecoveryDetails, { ciRunId: string }>;
      }
  );

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

function isSha1(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isAdministrativeRecoveryDetails(
  kind: AdministrativeRecoveryKind,
  value: unknown,
): value is AdministrativeRecoveryDetails {
  if (typeof value !== "object" || value === null) return false;
  const details = value as Record<string, unknown>;
  if (kind === "redundant-profile-downgrade")
    return (
      hasExactKeys(value, ["fromProfile", "toProfile"]) &&
      ["lean", "standard", "critical"].includes(String(details.fromProfile)) &&
      ["lean", "standard"].includes(String(details.toProfile))
    );
  if (kind === "missing-keep-branch-finish")
    return (
      hasExactKeys(value, ["branch", "headCommit", "targetTree"]) &&
      typeof details.branch === "string" &&
      isSha1(details.headCommit) &&
      isSha1(details.targetTree)
    );
  if (kind === "repair-receipt-sequencing")
    return (
      hasExactKeys(value, [
        "priorDecisionSequence",
        "priorDecisionChainDigest",
      ]) &&
      Number.isInteger(details.priorDecisionSequence) &&
      Number(details.priorDecisionSequence) >= 0 &&
      isSha256(details.priorDecisionChainDigest)
    );
  if (kind === "stale-evidence-after-controller-event")
    return (
      hasExactKeys(value, ["evidenceId", "freshThroughEventId"]) &&
      isSafeRequestId(details.evidenceId) &&
      isSafeRequestId(details.freshThroughEventId)
    );
  if (kind === "canonical-digest-refetch")
    return (
      hasExactKeys(value, [
        "authorityDigest",
        "meteringDigest",
        "controllerStateDigest",
      ]) &&
      isSha256(details.authorityDigest) &&
      isSha256(details.meteringDigest) &&
      isSha256(details.controllerStateDigest)
    );
  if (kind === "disappeared-agent-clean-worktree")
    return (
      hasExactKeys(value, ["agentExecutionId", "agentWorkspaceId"]) &&
      isSafeRequestId(details.agentExecutionId) &&
      isSafeRequestId(details.agentWorkspaceId)
    );
  if (kind === "idempotent-push-pr-reconciliation")
    return (
      hasExactKeys(value, [
        "candidateTree",
        "candidateCommit",
        "pullRequestNumber",
        "priorEffectSequence",
        "originalIdempotencyKey",
        "originalRequestDigest",
        "priorOutcome",
      ]) &&
      isSha1(details.candidateTree) &&
      isSha1(details.candidateCommit) &&
      Number.isInteger(details.pullRequestNumber) &&
      Number(details.pullRequestNumber) >= 1 &&
      Number.isInteger(details.priorEffectSequence) &&
      Number(details.priorEffectSequence) >= 1 &&
      isSafeRequestId(details.originalIdempotencyKey) &&
      isSha256(details.originalRequestDigest) &&
      details.priorOutcome === "authorization-issued-outcome-unknown"
    );
  return (
    hasExactKeys(value, ["ciRunId", "ciCheckId"]) &&
    isSafeRequestId(details.ciRunId) &&
    isSafeRequestId(details.ciCheckId)
  );
}

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
      "details",
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
    isAdministrativeRecoveryDetails(
      request.kind as AdministrativeRecoveryKind,
      request.details,
    ) &&
    typeof request.observedAt === "string" &&
    isCanonicalLifecycleTimestamp(request.observedAt)
  );
}

function roleMayPerformRecovery(
  role: DeliveryRole,
  kind: AdministrativeRecoveryKind,
): boolean {
  if (role === "flow") return true;
  if (role === "product")
    return new Set<AdministrativeRecoveryKind>([
      "redundant-profile-downgrade",
      "missing-keep-branch-finish",
      "stale-evidence-after-controller-event",
      "canonical-digest-refetch",
    ]).has(kind);
  if (role === "principal-developer")
    return new Set<AdministrativeRecoveryKind>([
      "repair-receipt-sequencing",
      "canonical-digest-refetch",
      "disappeared-agent-clean-worktree",
      "interrupted-ci-polling",
    ]).has(kind);
  if (role === "independent-verifier")
    return (
      kind === "stale-evidence-after-controller-event" ||
      kind === "canonical-digest-refetch"
    );
  return kind === "canonical-digest-refetch";
}

function deliveryRecoveryPolicyCode(
  contract: DeliveryAuthorityContract,
  request: AdministrativeRecoveryRequest,
): AdministrativeRecoveryDecisionCode {
  const binding = contract.roles[request.actorRole];
  if (
    !request.identityRevalidated ||
    request.actorRole !== contract.activeRole ||
    request.actorId !== binding.actorId ||
    request.executionId !== binding.executionId ||
    request.workspaceId !== binding.workspaceId
  )
    return "identity-not-revalidated";
  if (
    request.observedAt !== contract.meteringObservedAt ||
    request.observedAt <= latestRecordedTimestamp(contract)
  )
    return "stale-observation";
  if (
    request.targetGate !== "administrative" ||
    (contract.workflow.state !== "blocked" &&
      contract.workflow.state !== "escalated") ||
    !roleMayPerformRecovery(request.actorRole, request.kind)
  )
    return "recovery-gate-denied";

  if (request.kind === "redundant-profile-downgrade") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { fromProfile: string }
    >;
    const ranks = { lean: 0, standard: 1, critical: 2 } as const;
    return details.fromProfile === contract.task.assurance.profile &&
      ranks[details.toProfile] < ranks[details.fromProfile]
      ? "accepted"
      : "recovery-gate-denied";
  }
  if (request.kind === "missing-keep-branch-finish") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { branch: string }
    >;
    return details.branch === contract.task.repository.featureBranch &&
      details.headCommit === contract.workflow.candidate.headCommit &&
      details.targetTree === contract.workflow.candidate.tree
      ? "accepted"
      : "recovery-gate-denied";
  }
  if (request.kind === "repair-receipt-sequencing") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { priorDecisionSequence: number }
    >;
    const records = [
      ...contract.workflow.audit,
      ...contract.effectAudit,
      ...contract.administrativeRecoveries,
    ];
    return records.some((record) => {
      const authentication = record.authentication;
      return (
        authentication !== null &&
        authentication.sequence === details.priorDecisionSequence &&
        authentication.resultingChainDigest === details.priorDecisionChainDigest
      );
    })
      ? "accepted"
      : "recovery-gate-denied";
  }
  if (request.kind === "stale-evidence-after-controller-event") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { evidenceId: string }
    >;
    return contract.evidence.some(
      (evidence) =>
        evidence.evidenceId === details.evidenceId &&
        evidence.freshThroughEventId === details.freshThroughEventId,
    )
      ? "accepted"
      : "recovery-gate-denied";
  }
  if (request.kind === "canonical-digest-refetch") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { authorityDigest: string }
    >;
    return details.authorityDigest === contract.authorityDigest &&
      details.meteringDigest === contract.meteringDigest &&
      details.controllerStateDigest === contract.controllerStateDigest
      ? "accepted"
      : "recovery-gate-denied";
  }
  if (request.kind === "disappeared-agent-clean-worktree") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { agentExecutionId: string }
    >;
    return Object.values(contract.roles).some(
      (role) =>
        role.executionId === details.agentExecutionId &&
        role.workspaceId === details.agentWorkspaceId,
    )
      ? "accepted"
      : "recovery-gate-denied";
  }
  if (request.kind === "interrupted-ci-polling") {
    const details = request.details as Extract<
      AdministrativeRecoveryDetails,
      { ciRunId: string }
    >;
    return (contract.workflow.observations.ci === "pending" ||
      contract.workflow.observations.ci === "failed") &&
      contract.evidence.some(
        (evidence) =>
          evidence.ci.runId === details.ciRunId &&
          evidence.ci.checkId === details.ciCheckId,
      )
      ? "accepted"
      : "recovery-gate-denied";
  }

  if (contract.autonomy.usage.cancelled) return "recovery-gate-denied";
  const details = request.details as Extract<
    AdministrativeRecoveryDetails,
    { priorEffectSequence: number }
  >;
  const candidate = contract.workflow.candidate;
  const prior = contract.effectAudit.find(
    (effect) =>
      effect.authentication?.sequence === details.priorEffectSequence &&
      effect.idempotencyKey === details.originalIdempotencyKey &&
      effect.requestDigest === details.originalRequestDigest,
  );
  if (
    request.actorRole !== "flow" ||
    details.candidateTree !== candidate.tree ||
    details.candidateCommit !== candidate.headCommit ||
    details.pullRequestNumber !== candidate.pullRequest.number ||
    !publicationIsFresh(contract) ||
    !hasCurrentApprovalEvidence(contract) ||
    prior === undefined ||
    !prior.allowed ||
    prior.code !== "accepted" ||
    prior.targetTree !== details.candidateTree ||
    (prior.effect !== "feature-push" && prior.effect !== "pr-create-update") ||
    prior.authentication === null ||
    !publicationEffectStates.has(
      prior.authentication.historicalContext.workflowState,
    )
  )
    return "recovery-gate-denied";
  const priorContext = decisionContextAsContract(
    prior.authentication.historicalContext,
  );
  return publicationIsFresh(priorContext) &&
    hasCurrentApprovalEvidence(priorContext)
    ? "accepted"
    : "recovery-gate-denied";
}

export function evaluateAdministrativeRecovery(
  value: unknown,
  requestValue: unknown,
  expectedAuthorityDigest: unknown,
  expectedMeteringDigest: unknown,
  expectedControllerStateDigest: unknown,
): AdministrativeRecoveryDecision {
  const validation = validateFrozenDeliveryAuthorityContract(
    value,
    expectedAuthorityDigest,
    expectedMeteringDigest,
    expectedControllerStateDigest,
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
    details: {
      authorityDigest: "0".repeat(64),
      meteringDigest: "0".repeat(64),
      controllerStateDigest: "0".repeat(64),
    },
    observedAt: "1970-01-01T00:00:00.000Z",
  };
  const make = (
    allowed: boolean,
    idempotent: boolean,
    code: AdministrativeRecoveryDecisionCode,
  ): AdministrativeRecoveryDecision => {
    const audit: AdministrativeRecoveryRecord = {
      authentication: null,
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
    };
    if (
      validation.valid &&
      request !== null &&
      typeof expectedControllerStateDigest === "string"
    ) {
      const context = createDeliveryDecisionContext(
        validation.value,
        expectedControllerStateDigest,
      );
      authenticateDecisionRecord(
        validation.value,
        expectedControllerStateDigest,
        "recovery",
        audit,
        context,
      );
    }
    return { allowed, idempotent, code, audit };
  };
  if (!validation.valid || request === null)
    return make(false, false, "contract-invalid");
  const contract = validation.value;
  const prior = contract.administrativeRecoveries.find(
    (record) => record.idempotencyKey === request.idempotencyKey,
  );
  const requestDigest = sha256(request);
  if (prior) {
    return prior.requestDigest === requestDigest
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
  const code = deliveryRecoveryPolicyCode(contract, request);
  return make(code === "accepted", false, code);
}

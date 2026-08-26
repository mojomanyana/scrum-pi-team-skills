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
  | "identity-drift"
  | "transition-denied"
  | "publication-denied"
  | "merge-grant-required";

export type DeliveryEffectDecisionCode =
  | "accepted"
  | "contract-invalid"
  | "idempotency-conflict"
  | "identity-drift"
  | "escalation-required"
  | "publication-denied"
  | "role-authority-denied"
  | "distinct-grant-required";

export type AdministrativeRecoveryDecisionCode =
  | "accepted"
  | "contract-invalid"
  | "idempotency-conflict"
  | "identity-not-revalidated"
  | "recovery-gate-denied";

export interface DeliveryTransitionAuditRecord {
  eventId: string;
  idempotencyKey: string;
  requestDigest: string;
  actorRole: DeliveryRole;
  actorId: string;
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
  };
  pullRequest: {
    number: number | null;
    baseBranch: string | null;
    headBranch: string | null;
    headCommit: string | null;
  };
  ci: { runId: string | null; checkId: string | null };
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
  targetTree: string;
  allowed: boolean;
  code: DeliveryEffectDecisionCode;
  observedAt: string;
}

export interface DeliveryAuthorityContract {
  contractId: typeof DELIVERY_AUTHORITY_CONTRACT_ID;
  contractVersion: typeof DELIVERY_AUTHORITY_CONTRACT_VERSION;
  authorityDigest: string;
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

function canonicalSnapshot<T>(value: unknown): T | null {
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
  };
}

export function computeDeliveryAuthorityDigest(
  contract: DeliveryAuthorityContract,
): string {
  return sha256(authorityIdentity(contract));
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

function publicationIsFresh(contract: DeliveryAuthorityContract): boolean {
  const candidate = contract.workflow.candidate;
  const verifier = contract.roles["independent-verifier"];
  return (
    candidate.verification.verdict === "APPROVE" &&
    candidate.verification.reviewedTree === candidate.tree &&
    candidate.verification.executionId === verifier.executionId &&
    candidate.verification.workspaceId === verifier.workspaceId &&
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

function semanticErrors(
  contract: DeliveryAuthorityContract,
): DeliveryContractError[] {
  const errors: DeliveryContractError[] = [];

  if (contract.authorityDigest !== computeDeliveryAuthorityDigest(contract))
    errors.push(
      fixedError(
        "/authorityDigest",
        "authority-digest",
        "must match the canonical immutable authority digest",
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
    if (
      recovery.accepted &&
      (!recovery.identityRevalidated ||
        recovery.targetGate !== "administrative")
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

  const auditByKey = new Map<string, string>();
  const auditEventIdsSeen = new Set<string>();
  for (const audit of contract.workflow.audit) {
    const reconstructedRequest: DeliveryTransitionRequest = {
      eventId: audit.eventId,
      idempotencyKey: audit.idempotencyKey,
      from: audit.from,
      to: audit.to,
      actorRole: audit.actorRole,
      actorId: audit.actorId,
      candidateTree: audit.candidateTree,
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
          contract.roles[audit.actorRole].actorId !== audit.actorId ||
          audit.candidateTree !== candidate.tree)) ||
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
  }
  for (const audit of contract.effectAudit) {
    const effect = audit.effect as DeliveryEffect;
    const reconstructedRequest: DeliveryEffectRequest = {
      effect,
      idempotencyKey: audit.idempotencyKey,
      actorRole: audit.actorRole,
      actorId: audit.actorId,
      targetTree: audit.targetTree,
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
    const validAllowedEffect =
      ((AUTOMATIC_DELIVERY_ACTIONS as readonly string[]).includes(effect) &&
        roleMayPerformAutomatic(
          audit.actorRole,
          effect as AutomaticDeliveryAction,
        ) &&
        !publicationEffect) ||
      (publicationEffect &&
        publicationStates.has(contract.workflow.state) &&
        publicationIsFresh(contract) &&
        ((effect === "publication" && audit.actorRole === "flow") ||
          (effect !== "publication" &&
            roleMayPerformAutomatic(
              audit.actorRole,
              effect as AutomaticDeliveryAction,
            )))) ||
      (protectedEffect !== null && hasGrant(contract, protectedEffect));
    if (
      (audit.allowed &&
        (audit.code !== "accepted" ||
          !validAllowedEffect ||
          contract.roles[audit.actorRole].actorId !== audit.actorId ||
          audit.targetTree !== candidate.tree)) ||
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
  for (const audit of [...contract.workflow.audit, ...contract.effectAudit]) {
    const previous = auditByKey.get(audit.idempotencyKey);
    if (previous !== undefined && previous !== audit.requestDigest)
      errors.push(
        fixedError(
          "/",
          "idempotency-conflict",
          "an idempotency key must identify exactly one request",
        ),
      );
    auditByKey.set(audit.idempotencyKey, audit.requestDigest);
  }

  const auditEventIds = new Set(
    contract.workflow.audit.map((audit) => audit.eventId),
  );
  const evidenceKeys = new Set<string>();
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
    if (!auditEventIds.has(evidence.freshThroughEventId))
      errors.push(
        fixedError(
          `${path}/freshThroughEventId`,
          "evidence-freshness",
          "must identify an auditable controller event",
        ),
      );
    if (
      evidence.verification.verdict !== null &&
      (evidence.actor.role !== "independent-verifier" ||
        evidence.verification.reviewedTree !== candidate.tree ||
        evidence.repository.commit !== candidate.headCommit ||
        evidence.repository.tree !== candidate.tree ||
        evidence.pullRequest.baseBranch !==
          contract.task.repository.baseBranch ||
        evidence.pullRequest.headBranch !==
          contract.task.repository.featureBranch ||
        evidence.pullRequest.headCommit !== candidate.headCommit)
    )
      errors.push(
        fixedError(
          `${path}/verification`,
          "verification-evidence-binding",
          "verification evidence must bind the independent verifier and exact candidate and pull request identities",
        ),
      );
    if (evidenceKeys.has(evidence.idempotencyKey))
      errors.push(
        fixedError(
          `${path}/idempotencyKey`,
          "idempotency-conflict",
          "evidence idempotency keys must be unique",
        ),
      );
    evidenceKeys.add(evidence.idempotencyKey);
  }

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
  candidateTree: string;
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
      "candidateTree",
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
    typeof request.candidateTree === "string" &&
    /^[0-9a-f]{40}$/.test(request.candidateTree)
  );
}

function decisionAudit(
  contract: DeliveryAuthorityContract | null,
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
    candidateTree: request.candidateTree,
    accepted,
    code,
    from: request.from,
    to: request.to,
    observedAt:
      contract?.workflow.candidate.verification.observedAt ??
      "1970-01-01T00:00:00.000Z",
  };
}

export function evaluateDeliveryTransition(
  value: unknown,
  requestValue: unknown,
): DeliveryTransitionDecision {
  const validation = validateDeliveryAuthorityContract(value);
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
      candidateTree: "0".repeat(40),
    };
    return {
      accepted: false,
      idempotent: false,
      code: "contract-invalid",
      nextState: fallbackState,
      audit: decisionAudit(
        validation.valid ? validation.value : null,
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
      nextState: same && prior.accepted ? prior.to : contract.workflow.state,
      audit: same
        ? prior
        : decisionAudit(
            contract,
            request,
            requestDigest,
            false,
            "idempotency-conflict",
          ),
    };
  }

  let code: DeliveryTransitionDecisionCode = "accepted";
  const binding = contract.roles[request.actorRole];
  if (containsCredentialShapedContent(request.actorId)) code = "request-denied";
  else if (
    request.from !== contract.workflow.state ||
    request.candidateTree !== contract.workflow.candidate.tree ||
    binding.actorId !== request.actorId
  )
    code = "identity-drift";
  else if (!transitions[request.from].includes(request.to))
    code = "transition-denied";
  else if (
    request.to === "publication-authorized" &&
    !publicationIsFresh(contract)
  )
    code = "publication-denied";
  else if (request.to === "merge-gate" && !hasGrant(contract, "merge"))
    code = "merge-grant-required";
  else if (request.to === "completed" && !hasGrant(contract, "merge"))
    code = "merge-grant-required";
  const accepted = code === "accepted";
  return {
    accepted,
    idempotent: false,
    code,
    nextState: accepted ? request.to : contract.workflow.state,
    audit: decisionAudit(contract, request, requestDigest, accepted, code),
  };
}

export interface DeliveryEffectRequest {
  effect: DeliveryEffect;
  idempotencyKey: string;
  actorRole: DeliveryRole;
  actorId: string;
  targetTree: string;
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
      "targetTree",
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
    typeof request.targetTree === "string" &&
    /^[0-9a-f]{40}$/.test(request.targetTree)
  );
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
): DeliveryEffectDecision {
  const validation = validateDeliveryAuthorityContract(value);
  const requestSnapshot = canonicalSnapshot<unknown>(requestValue);
  const request = isDeliveryEffectRequest(requestSnapshot)
    ? requestSnapshot
    : null;
  const observedAt = validation.valid
    ? validation.value.workflow.candidate.verification.observedAt
    : "1970-01-01T00:00:00.000Z";
  const fallbackRequest: DeliveryEffectRequest = request ?? {
    effect: "diagnose-repair",
    idempotencyKey: "rejected-effect",
    actorRole: "flow",
    actorId: "rejected-actor",
    targetTree: "0".repeat(40),
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
      targetTree: fallbackRequest.targetTree,
      allowed,
      code,
      observedAt,
    },
  });
  if (!validation.valid || request === null)
    return make(false, false, "contract-invalid");
  const contract = validation.value;
  const prior = contract.effectAudit.find(
    (record) => record.idempotencyKey === request.idempotencyKey,
  );
  if (prior)
    return prior.requestDigest === requestDigest
      ? {
          allowed: prior.allowed,
          idempotent: true,
          code: prior.code,
          audit: prior,
        }
      : make(false, false, "idempotency-conflict");
  if (
    contract.roles[request.actorRole].actorId !== request.actorId ||
    request.targetTree !== contract.workflow.candidate.tree ||
    containsCredentialShapedContent(request.actorId)
  )
    return make(false, false, "identity-drift");
  if (
    contract.activeEscalations.length > 0 ||
    contract.autonomy.usage.cancelled
  )
    return make(false, false, "escalation-required");
  if (
    request.effect === "feature-push" ||
    request.effect === "pr-create-update"
  )
    return publicationStates.has(contract.workflow.state) &&
      publicationIsFresh(contract) &&
      roleMayPerformAutomatic(
        request.actorRole,
        request.effect as AutomaticDeliveryAction,
      )
      ? make(true, false, "accepted")
      : make(false, false, "publication-denied");
  if (
    (AUTOMATIC_DELIVERY_ACTIONS as readonly string[]).includes(request.effect)
  )
    return roleMayPerformAutomatic(
      request.actorRole,
      request.effect as AutomaticDeliveryAction,
    )
      ? make(true, false, "accepted")
      : make(false, false, "role-authority-denied");
  if (request.effect === "publication")
    return publicationStates.has(contract.workflow.state) &&
      publicationIsFresh(contract) &&
      request.actorRole === "flow"
      ? make(true, false, "accepted")
      : make(false, false, "publication-denied");
  const protectedEffect = protectedGrantFor(request.effect);
  if (
    protectedEffect !== null &&
    hasGrant(contract, protectedEffect, request.targetTree)
  )
    return make(true, false, "accepted");
  return make(false, false, "distinct-grant-required");
}

export interface AdministrativeRecoveryRequest {
  recoveryId: string;
  kind: AdministrativeRecoveryKind;
  idempotencyKey: string;
  identityRevalidated: boolean;
  targetGate: AdministrativeRecoveryRecord["targetGate"];
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
      "identityRevalidated",
      "targetGate",
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
    typeof request.identityRevalidated === "boolean" &&
    recoveryTargets.has(
      request.targetGate as AdministrativeRecoveryRecord["targetGate"],
    )
  );
}

export function evaluateAdministrativeRecovery(
  value: unknown,
  requestValue: unknown,
): AdministrativeRecoveryDecision {
  const validation = validateDeliveryAuthorityContract(value);
  const requestSnapshot = canonicalSnapshot<unknown>(requestValue);
  const request = isAdministrativeRecoveryRequest(requestSnapshot)
    ? requestSnapshot
    : null;
  const observedAt = validation.valid
    ? validation.value.workflow.candidate.verification.observedAt
    : "1970-01-01T00:00:00.000Z";
  const fallback: AdministrativeRecoveryRequest = request ?? {
    recoveryId: "rejected-recovery",
    kind: "canonical-digest-refetch",
    idempotencyKey: "rejected-recovery",
    identityRevalidated: false,
    targetGate: "identity",
  };
  const make = (
    allowed: boolean,
    idempotent: boolean,
    code: AdministrativeRecoveryDecisionCode,
  ): AdministrativeRecoveryDecision => ({
    allowed,
    idempotent,
    code,
    audit: { ...fallback, accepted: allowed, code, observedAt },
  });
  if (!validation.valid || request === null)
    return make(false, false, "contract-invalid");
  const prior = validation.value.administrativeRecoveries.find(
    (record) => record.idempotencyKey === request.idempotencyKey,
  );
  const requestDigest = sha256(request);
  if (prior) {
    const priorDigest = sha256({
      recoveryId: prior.recoveryId,
      kind: prior.kind,
      idempotencyKey: prior.idempotencyKey,
      identityRevalidated: prior.identityRevalidated,
      targetGate: prior.targetGate,
    });
    return priorDigest === requestDigest
      ? {
          allowed: prior.accepted,
          idempotent: true,
          code: prior.code,
          audit: prior,
        }
      : make(false, false, "idempotency-conflict");
  }
  if (!request.identityRevalidated)
    return make(false, false, "identity-not-revalidated");
  if (request.targetGate !== "administrative")
    return make(false, false, "recovery-gate-denied");
  return make(true, false, "accepted");
}

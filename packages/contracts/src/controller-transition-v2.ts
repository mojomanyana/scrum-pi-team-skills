import type {
  ControllerCommandV2,
  ControllerTargetV2,
  DigestSha256V2,
  ProtocolIdV2,
  SafeRevisionV2,
  TimestampV2,
} from "./controller-command-v2.js";
import type { FlowRoleV2 } from "./flow-task-packet.js";
import type {
  AcceptedCommandV2,
  CiStateV2,
  ControllerCandidateV2,
  ControllerPhaseV2,
  ControllerSnapshotV2,
  PublicationStateV2,
  RepairSourceV2,
  VerificationStateV2,
} from "./controller-snapshot-v2.js";
import { snapshotControllerInputV2 } from "./controller-command-v2.js";
import { validateControllerSnapshotV2 } from "./controller-snapshot-v2.js";
export interface ControllerEvaluationContextV2 {
  contractId: "spts.controller-evaluation-context";
  schemaVersion: "2.0.0";
  evaluationId: ProtocolIdV2;
  evaluatedAt: TimestampV2;
  snapshotDigest: DigestSha256V2;
  authorityDigest: DigestSha256V2;
  meteringDigest: DigestSha256V2;
  controllerStateDigest: DigestSha256V2;
}
export type ControllerRejectionCodeV2 =
  | "snapshot-input-invalid"
  | "command-input-invalid"
  | "context-input-invalid"
  | "snapshot-invalid"
  | "command-invalid"
  | "context-invalid"
  | "digest-mismatch"
  | "identity-mismatch"
  | "idempotency-conflict"
  | "revision-conflict"
  | "terminal"
  | "cancelled"
  | "revision-overflow"
  | "actor-denied"
  | "publication-binding-invalid"
  | "recovery-denied"
  | "evidence-required"
  | "attempt-limit-exhausted"
  | "transition-denied"
  | "history-full"
  | "output-invalid";
export type ControllerTransitionCodeV2 =
  "transition-proposed" | "duplicate-command" | ControllerRejectionCodeV2;
export interface ControllerDiagnosticV2 {
  code: ControllerRejectionCodeV2;
  message: string;
  path: string;
}
export type ControllerChangeV2 =
  | { kind: "accepted-command-added"; value: AcceptedCommandV2 }
  | { kind: "revision-set"; from: SafeRevisionV2; to: SafeRevisionV2 }
  | {
      kind: "previous-transition-digest-set";
      from: DigestSha256V2 | null;
      to: DigestSha256V2;
    }
  | {
      kind: "candidate-set";
      from: ControllerCandidateV2;
      to: ControllerCandidateV2;
    }
  | { kind: "phase-set"; from: ControllerPhaseV2; to: ControllerPhaseV2 }
  | { kind: "active-role-set"; from: FlowRoleV2; to: FlowRoleV2 }
  | {
      kind: "verification-set";
      from: VerificationStateV2;
      to: VerificationStateV2;
    }
  | { kind: "ci-set"; from: CiStateV2; to: CiStateV2 }
  | {
      kind: "publication-set";
      from: PublicationStateV2;
      to: PublicationStateV2;
    }
  | { kind: "merged-set"; from: boolean; to: boolean }
  | { kind: "cancelled-set"; from: boolean; to: boolean }
  | { kind: "terminal-set"; from: boolean; to: boolean }
  | { kind: "repair-source-set"; from: RepairSourceV2; to: RepairSourceV2 }
  | {
      kind: "usage-set";
      counter: "implementationAttempts" | "verificationRepairs" | "ciRepairs";
      from: number;
      to: number;
    };
export type EffectIntentKindV2 =
  | "run-implementation"
  | "run-independent-verification"
  | "publish-candidate"
  | "monitor-ci"
  | "merge-candidate"
  | "update-paca"
  | "reconcile-publication";
export interface RunImplementationPayloadV2 {
  kind: "run-implementation";
  mode: "implementation" | "repair";
  repairSource: RepairSourceV2;
}
export interface RunIndependentVerificationPayloadV2 {
  kind: "run-independent-verification";
}
export interface PublishCandidatePayloadV2 {
  kind: "publish-candidate";
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
}
export interface MonitorCiPayloadV2 {
  kind: "monitor-ci";
  publicationId: ProtocolIdV2;
}
export interface MergeCandidatePayloadV2 {
  kind: "merge-candidate";
  publicationId: ProtocolIdV2;
}
export interface UpdatePacaPayloadV2 {
  kind: "update-paca";
  fromPhase: ControllerPhaseV2;
  toPhase: ControllerPhaseV2;
}
export interface ReconcilePublicationIntentPayloadV2 {
  kind: "reconcile-publication";
  publicationId: ProtocolIdV2;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  priorUnknownObservationDigest: DigestSha256V2;
}
type IntentBase<K extends EffectIntentKindV2, P> = {
  intentId: ProtocolIdV2;
  kind: K;
  commandDigest: DigestSha256V2;
  proposalDigestBinding: DigestSha256V2;
  target: ControllerTargetV2;
  payload: P;
  executableAuthority: false;
};
export type EffectIntentV2 =
  | IntentBase<"run-implementation", RunImplementationPayloadV2>
  | IntentBase<
      "run-independent-verification",
      RunIndependentVerificationPayloadV2
    >
  | IntentBase<"publish-candidate", PublishCandidatePayloadV2>
  | IntentBase<"monitor-ci", MonitorCiPayloadV2>
  | IntentBase<"merge-candidate", MergeCandidatePayloadV2>
  | IntentBase<"update-paca", UpdatePacaPayloadV2>
  | IntentBase<"reconcile-publication", ReconcilePublicationIntentPayloadV2>;
export interface ControllerTransitionV2 {
  contractId: "spts.controller-transition";
  schemaVersion: "2.0.0";
  disposition: "proposed" | "duplicate" | "rejected";
  code: ControllerTransitionCodeV2;
  proposalId: ProtocolIdV2;
  proposalDigest: DigestSha256V2;
  commandId: ProtocolIdV2 | null;
  commandDigest: DigestSha256V2 | null;
  snapshotId: ProtocolIdV2 | null;
  snapshotDigest: DigestSha256V2 | null;
  fromRevision: SafeRevisionV2 | null;
  toRevision: SafeRevisionV2 | null;
  fromPhase: ControllerPhaseV2 | null;
  toPhase: ControllerPhaseV2 | null;
  evaluationId: ProtocolIdV2 | null;
  evaluatedAt: TimestampV2 | null;
  target: ControllerTargetV2 | null;
  priorTransitionDigest: DigestSha256V2 | null;
  transitionDigest: DigestSha256V2 | null;
  changes: readonly ControllerChangeV2[];
  intents: readonly EffectIntentV2[];
  diagnostics: readonly ControllerDiagnosticV2[];
  proposedNextSnapshot: ControllerSnapshotV2 | null;
  executableAuthority: false;
}
export type ProposedControllerTransitionV2 = ControllerTransitionV2 & {
  disposition: "proposed";
  code: "transition-proposed";
  commandId: ProtocolIdV2;
  commandDigest: DigestSha256V2;
  snapshotId: ProtocolIdV2;
  snapshotDigest: DigestSha256V2;
  fromRevision: SafeRevisionV2;
  toRevision: SafeRevisionV2;
  fromPhase: ControllerPhaseV2;
  toPhase: ControllerPhaseV2;
  evaluationId: ProtocolIdV2;
  evaluatedAt: TimestampV2;
  target: ControllerTargetV2;
  transitionDigest: DigestSha256V2;
  diagnostics: readonly [];
  proposedNextSnapshot: ControllerSnapshotV2;
};
export type DuplicateControllerTransitionV2 = ControllerTransitionV2 & {
  disposition: "duplicate";
  code: "duplicate-command";
  transitionDigest: DigestSha256V2;
  changes: readonly [];
  intents: readonly [];
  diagnostics: readonly [];
  proposedNextSnapshot: null;
};
export type RejectedControllerTransitionV2 = ControllerTransitionV2 & {
  disposition: "rejected";
  code: ControllerRejectionCodeV2;
  transitionDigest: null;
  changes: readonly [];
  intents: readonly [];
  diagnostics: readonly [ControllerDiagnosticV2];
  proposedNextSnapshot: null;
};
export type UnsignedIntentV2<T = EffectIntentV2> = T extends unknown
  ? Omit<T, "intentId" | "proposalDigestBinding">
  : never;
export interface TransitionSemanticDeltaV2 {
  fromPhase: ControllerPhaseV2;
  toPhase: ControllerPhaseV2;
  target: ControllerTargetV2;
  stateChanges: readonly ControllerChangeV2[];
  unsignedIntents: readonly UnsignedIntentV2[];
}
export const CONTROLLER_DIAGNOSTICS_V2: Readonly<
  Record<ControllerRejectionCodeV2, Readonly<ControllerDiagnosticV2>>
> = Object.freeze({
  "snapshot-input-invalid": {
    code: "snapshot-input-invalid",
    message: "Snapshot input is invalid.",
    path: "/snapshot",
  },
  "command-input-invalid": {
    code: "command-input-invalid",
    message: "Command input is invalid.",
    path: "/command",
  },
  "context-input-invalid": {
    code: "context-input-invalid",
    message: "Context input is invalid.",
    path: "/context",
  },
  "snapshot-invalid": {
    code: "snapshot-invalid",
    message: "Snapshot contract is invalid.",
    path: "/snapshot",
  },
  "command-invalid": {
    code: "command-invalid",
    message: "Command contract is invalid.",
    path: "/command",
  },
  "context-invalid": {
    code: "context-invalid",
    message: "Evaluation context contract is invalid.",
    path: "/context",
  },
  "digest-mismatch": {
    code: "digest-mismatch",
    message: "Evaluation context digest binding does not match.",
    path: "/context",
  },
  "identity-mismatch": {
    code: "identity-mismatch",
    message: "Command target identity does not match the snapshot.",
    path: "/command/target",
  },
  "idempotency-conflict": {
    code: "idempotency-conflict",
    message: "Idempotency key is already bound to another command.",
    path: "/command/idempotencyKey",
  },
  "revision-conflict": {
    code: "revision-conflict",
    message: "Expected revision does not match.",
    path: "/command/expectedRevision",
  },
  terminal: {
    code: "terminal",
    message: "Snapshot is terminal.",
    path: "/snapshot/status/terminal",
  },
  cancelled: {
    code: "cancelled",
    message: "Snapshot is cancelled.",
    path: "/snapshot/status/cancelled",
  },
  "revision-overflow": {
    code: "revision-overflow",
    message: "Snapshot revision cannot be incremented safely.",
    path: "/snapshot/revision",
  },
  "actor-denied": {
    code: "actor-denied",
    message: "Actor role is not permitted for this transition.",
    path: "/command/actor/role",
  },
  "publication-binding-invalid": {
    code: "publication-binding-invalid",
    message: "Publication binding does not match.",
    path: "/command/payload",
  },
  "recovery-denied": {
    code: "recovery-denied",
    message: "Publication recovery is not permitted.",
    path: "/command/payload",
  },
  "evidence-required": {
    code: "evidence-required",
    message: "Evidence cardinality or kind is not permitted.",
    path: "/command/evidence",
  },
  "attempt-limit-exhausted": {
    code: "attempt-limit-exhausted",
    message: "Attempt limit is exhausted.",
    path: "/snapshot/usage",
  },
  "transition-denied": {
    code: "transition-denied",
    message: "Transition is not permitted from this state.",
    path: "/snapshot/phase",
  },
  "history-full": {
    code: "history-full",
    message: "Accepted-command history is full.",
    path: "/snapshot/acceptedCommands",
  },
  "output-invalid": {
    code: "output-invalid",
    message: "Internal transition construction failed validation.",
    path: "",
  },
});
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/,
  digestPattern = /^[0-9a-f]{64}$/;
export function validateControllerEvaluationContextV2(
  value: unknown,
): value is ControllerEvaluationContextV2 {
  try {
    const v = snapshotControllerInputV2(value) as Record<string, unknown>;
    return (
      typeof v === "object" &&
      v !== null &&
      Object.keys(v).length === 8 &&
      v.contractId === "spts.controller-evaluation-context" &&
      v.schemaVersion === "2.0.0" &&
      typeof v.evaluationId === "string" &&
      idPattern.test(v.evaluationId) &&
      typeof v.evaluatedAt === "string" &&
      new Date(v.evaluatedAt).toISOString() === v.evaluatedAt &&
      [
        v.snapshotDigest,
        v.authorityDigest,
        v.meteringDigest,
        v.controllerStateDigest,
      ].every((x) => typeof x === "string" && digestPattern.test(x))
    );
  } catch {
    return false;
  }
}
export function validateControllerTransitionV2(
  value: unknown,
): value is ControllerTransitionV2 {
  try {
    const v = snapshotControllerInputV2(value) as Record<string, unknown>;
    if (
      typeof v !== "object" ||
      v === null ||
      Object.keys(v).length !== 24 ||
      v.contractId !== "spts.controller-transition" ||
      v.schemaVersion !== "2.0.0" ||
      v.executableAuthority !== false ||
      !Array.isArray(v.changes) ||
      !Array.isArray(v.intents) ||
      !Array.isArray(v.diagnostics)
    )
      return false;
    if (v.disposition === "proposed")
      return (
        v.code === "transition-proposed" &&
        v.transitionDigest !== null &&
        validateControllerSnapshotV2(v.proposedNextSnapshot) &&
        v.diagnostics.length === 0
      );
    if (v.disposition === "duplicate")
      return (
        v.code === "duplicate-command" &&
        typeof v.transitionDigest === "string" &&
        v.changes.length === 0 &&
        v.intents.length === 0 &&
        v.diagnostics.length === 0 &&
        v.proposedNextSnapshot === null
      );
    if (
      v.disposition !== "rejected" ||
      v.transitionDigest !== null ||
      v.changes.length ||
      v.intents.length ||
      v.proposedNextSnapshot !== null ||
      v.diagnostics.length !== 1
    )
      return false;
    const d = v.diagnostics[0] as ControllerDiagnosticV2,
      expected = CONTROLLER_DIAGNOSTICS_V2[v.code as ControllerRejectionCodeV2];
    return (
      expected !== undefined &&
      d.code === expected.code &&
      d.message === expected.message &&
      d.path === expected.path
    );
  } catch {
    return false;
  }
}
export const isControllerTransitionV2 = validateControllerTransitionV2;
export type { ControllerCommandV2, ControllerCandidateV2 };

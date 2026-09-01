import type {
  DigestSha256V2,
  GitSha1V2,
  PositiveLimitV2,
  ProtocolIdV2,
  SafeRevisionV2,
  UsageCountV2,
} from "./controller-command-v2.js";
import {
  digestControllerValueV2,
  snapshotControllerInputV2,
} from "./controller-command-v2.js";
import type { FlowRoleV2 } from "./flow-task-packet.js";
export type ControllerPhaseV2 =
  | "ready"
  | "implementation"
  | "internal-review"
  | "independent-verification"
  | "repair-required"
  | "publication"
  | "pr-ci-monitoring"
  | "merge-gate"
  | "completed"
  | "cancelled";
export type VerificationStateV2 = "unverified" | "approved" | "rejected";
export type CiStateV2 = "not-started" | "pending" | "passed" | "failed";
export type RepairSourceV2 = "verification" | "ci" | null;
export interface PublicationNotRequestedV2 {
  state: "not-requested";
  publicationId: null;
  publicationIntentId: null;
  publicationIntentDigest: null;
  unknownObservationDigest: null;
}
export interface PublicationIntentCommittedV2 {
  state: "intent-committed";
  publicationId: null;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  unknownObservationDigest: null;
}
export interface PublicationOutcomeUnknownV2 {
  state: "outcome-unknown";
  publicationId: ProtocolIdV2;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  unknownObservationDigest: DigestSha256V2;
}
export interface PublicationSucceededV2 {
  state: "succeeded";
  publicationId: ProtocolIdV2;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  unknownObservationDigest: null;
}
export type PublicationStateV2 =
  | PublicationNotRequestedV2
  | PublicationIntentCommittedV2
  | PublicationOutcomeUnknownV2
  | PublicationSucceededV2;
export interface ControllerIdentityV2 {
  projectId: ProtocolIdV2;
  taskId: ProtocolIdV2;
  repositoryId: ProtocolIdV2;
  baseCommit: GitSha1V2;
  baseTree: GitSha1V2;
  headBranch: ProtocolIdV2;
}
export interface ControllerCandidateV2 {
  commit: GitSha1V2;
  tree: GitSha1V2;
}
export interface ControllerStatusV2 {
  verification: VerificationStateV2;
  ci: CiStateV2;
  publication: PublicationStateV2;
  merged: boolean;
  cancelled: boolean;
  terminal: boolean;
  repairSource: RepairSourceV2;
}
export interface ControllerLimitsV2 {
  implementationAttempts: PositiveLimitV2;
  verificationRepairs: PositiveLimitV2;
  ciRepairs: PositiveLimitV2;
}
export interface ControllerUsageV2 {
  implementationAttempts: UsageCountV2;
  verificationRepairs: UsageCountV2;
  ciRepairs: UsageCountV2;
}
export interface AcceptedCommandV2 {
  idempotencyKey: ProtocolIdV2;
  commandDigest: DigestSha256V2;
  transitionDigest: DigestSha256V2;
}
export interface ControllerSnapshotV2 {
  contractId: "spts.controller-snapshot";
  schemaVersion: "2.0.0";
  snapshotId: ProtocolIdV2;
  revision: SafeRevisionV2;
  previousTransitionDigest: DigestSha256V2 | null;
  authorityDigest: DigestSha256V2;
  meteringDigest: DigestSha256V2;
  controllerStateDigest: DigestSha256V2;
  identity: ControllerIdentityV2;
  candidate: ControllerCandidateV2;
  phase: ControllerPhaseV2;
  activeRole: FlowRoleV2;
  status: ControllerStatusV2;
  limits: ControllerLimitsV2;
  usage: ControllerUsageV2;
  acceptedCommands: readonly AcceptedCommandV2[];
}

const id = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const sha1 = /^[0-9a-f]{40}$/;
const sha256 = /^[0-9a-f]{64}$/;
const phases = new Set<ControllerPhaseV2>([
  "ready",
  "implementation",
  "internal-review",
  "independent-verification",
  "repair-required",
  "publication",
  "pr-ci-monitoring",
  "merge-gate",
  "completed",
  "cancelled",
]);
const objectKeys = (
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const string = (value: unknown, pattern: RegExp): value is string =>
  typeof value === "string" &&
  pattern.test(value) &&
  value.normalize("NFC") === value;
const publicationValid = (p: unknown): p is PublicationStateV2 => {
  if (
    !objectKeys(p, [
      "state",
      "publicationId",
      "publicationIntentId",
      "publicationIntentDigest",
      "unknownObservationDigest",
    ])
  )
    return false;
  if (p.state === "not-requested")
    return (
      p.publicationId === null &&
      p.publicationIntentId === null &&
      p.publicationIntentDigest === null &&
      p.unknownObservationDigest === null
    );
  if (p.state === "intent-committed")
    return (
      p.publicationId === null &&
      string(p.publicationIntentId, id) &&
      string(p.publicationIntentDigest, sha256) &&
      p.unknownObservationDigest === null
    );
  if (p.state === "outcome-unknown")
    return (
      string(p.publicationId, id) &&
      string(p.publicationIntentId, id) &&
      string(p.publicationIntentDigest, sha256) &&
      string(p.unknownObservationDigest, sha256)
    );
  return (
    p.state === "succeeded" &&
    string(p.publicationId, id) &&
    string(p.publicationIntentId, id) &&
    string(p.publicationIntentDigest, sha256) &&
    p.unknownObservationDigest === null
  );
};
function validSnapshot(v: unknown): v is ControllerSnapshotV2 {
  if (
    !objectKeys(v, [
      "contractId",
      "schemaVersion",
      "snapshotId",
      "revision",
      "previousTransitionDigest",
      "authorityDigest",
      "meteringDigest",
      "controllerStateDigest",
      "identity",
      "candidate",
      "phase",
      "activeRole",
      "status",
      "limits",
      "usage",
      "acceptedCommands",
    ])
  )
    return false;
  if (
    v.contractId !== "spts.controller-snapshot" ||
    v.schemaVersion !== "2.0.0" ||
    !string(v.snapshotId, id) ||
    !Number.isSafeInteger(v.revision) ||
    (v.revision as number) < 0 ||
    (v.revision === 0) !== (v.previousTransitionDigest === null) ||
    !(
      v.previousTransitionDigest === null ||
      string(v.previousTransitionDigest, sha256)
    ) ||
    !string(v.authorityDigest, sha256) ||
    !string(v.meteringDigest, sha256) ||
    !string(v.controllerStateDigest, sha256) ||
    !phases.has(v.phase as ControllerPhaseV2)
  )
    return false;
  if (
    !objectKeys(v.identity, [
      "projectId",
      "taskId",
      "repositoryId",
      "baseCommit",
      "baseTree",
      "headBranch",
    ]) ||
    ![
      v.identity.projectId,
      v.identity.taskId,
      v.identity.repositoryId,
      v.identity.headBranch,
    ].every((x) => string(x, id)) ||
    !string(v.identity.baseCommit, sha1) ||
    !string(v.identity.baseTree, sha1)
  )
    return false;
  if (
    !objectKeys(v.candidate, ["commit", "tree"]) ||
    !string(v.candidate.commit, sha1) ||
    !string(v.candidate.tree, sha1)
  )
    return false;
  if (
    !objectKeys(v.limits, [
      "implementationAttempts",
      "verificationRepairs",
      "ciRepairs",
    ]) ||
    !objectKeys(v.usage, [
      "implementationAttempts",
      "verificationRepairs",
      "ciRepairs",
    ])
  )
    return false;
  for (const key of [
    "implementationAttempts",
    "verificationRepairs",
    "ciRepairs",
  ] as const)
    if (
      !Number.isInteger(v.limits[key]) ||
      (v.limits[key] as number) < 1 ||
      (v.limits[key] as number) > 1000000 ||
      !Number.isInteger(v.usage[key]) ||
      (v.usage[key] as number) < 0 ||
      (v.usage[key] as number) > (v.limits[key] as number)
    )
      return false;
  if (
    !objectKeys(v.status, [
      "verification",
      "ci",
      "publication",
      "merged",
      "cancelled",
      "terminal",
      "repairSource",
    ]) ||
    !publicationValid(v.status.publication) ||
    !["unverified", "approved", "rejected"].includes(
      v.status.verification as string,
    ) ||
    !["not-started", "pending", "passed", "failed"].includes(
      v.status.ci as string,
    ) ||
    typeof v.status.merged !== "boolean" ||
    typeof v.status.cancelled !== "boolean" ||
    typeof v.status.terminal !== "boolean" ||
    ![null, "verification", "ci"].includes(v.status.repairSource as null)
  )
    return false;
  if (!Array.isArray(v.acceptedCommands) || v.acceptedCommands.length > 256)
    return false;
  let prior = "";
  for (const entry of v.acceptedCommands) {
    if (
      !objectKeys(entry, [
        "idempotencyKey",
        "commandDigest",
        "transitionDigest",
      ]) ||
      !string(entry.idempotencyKey, id) ||
      !string(entry.commandDigest, sha256) ||
      !string(entry.transitionDigest, sha256) ||
      entry.idempotencyKey <= prior
    )
      return false;
    prior = entry.idempotencyKey;
  }
  const p = v.phase as ControllerPhaseV2,
    s = v.status as unknown as ControllerStatusV2,
    pub = s.publication.state;
  if (p === "completed")
    return (
      v.activeRole === "product" &&
      s.verification === "approved" &&
      s.ci === "passed" &&
      pub === "succeeded" &&
      s.merged &&
      !s.cancelled &&
      s.terminal &&
      s.repairSource === null
    );
  if (p === "cancelled") {
    const reachableTriple =
      (s.verification === "unverified" &&
        s.ci === "not-started" &&
        pub === "not-requested") ||
      (["unverified", "rejected", "approved"].includes(s.verification) &&
        ["not-started", "failed"].includes(s.ci) &&
        ["not-requested", "succeeded"].includes(pub)) ||
      (s.verification === "rejected" &&
        s.ci === "not-started" &&
        pub === "not-requested") ||
      (s.verification === "approved" &&
        s.ci === "failed" &&
        pub === "succeeded") ||
      (s.verification === "approved" &&
        s.ci === "not-started" &&
        ["not-requested", "intent-committed", "outcome-unknown"].includes(
          pub,
        )) ||
      (s.verification === "approved" &&
        ["pending", "passed"].includes(s.ci) &&
        pub === "succeeded");
    return (
      v.activeRole === "product" &&
      !s.merged &&
      s.cancelled &&
      s.terminal &&
      s.repairSource === null &&
      reachableTriple
    );
  }
  if (s.merged || s.cancelled || s.terminal) return false;
  return (
    (p === "ready" &&
      v.activeRole === "principal-developer" &&
      s.verification === "unverified" &&
      s.ci === "not-started" &&
      pub === "not-requested" &&
      s.repairSource === null) ||
    (p === "implementation" &&
      v.activeRole === "principal-developer" &&
      s.ci !== "pending" &&
      s.ci !== "passed" &&
      s.repairSource === null) ||
    (p === "internal-review" &&
      v.activeRole === "flow" &&
      s.ci !== "pending" &&
      s.ci !== "passed" &&
      s.repairSource === null) ||
    (p === "independent-verification" &&
      v.activeRole === "independent-verifier" &&
      s.verification === "unverified" &&
      s.ci === "not-started" &&
      pub === "not-requested" &&
      s.repairSource === null) ||
    (p === "repair-required" &&
      v.activeRole === "principal-developer" &&
      ((s.verification === "rejected" &&
        s.ci === "not-started" &&
        pub === "not-requested" &&
        s.repairSource === "verification") ||
        (s.verification === "approved" &&
          s.ci === "failed" &&
          pub === "succeeded" &&
          s.repairSource === "ci"))) ||
    (p === "publication" &&
      v.activeRole === "flow" &&
      s.verification === "approved" &&
      s.ci === "not-started" &&
      ["not-requested", "intent-committed", "outcome-unknown"].includes(pub) &&
      s.repairSource === null) ||
    (p === "pr-ci-monitoring" &&
      v.activeRole === "flow" &&
      s.verification === "approved" &&
      s.ci === "pending" &&
      pub === "succeeded" &&
      s.repairSource === null) ||
    (p === "merge-gate" &&
      v.activeRole === "product" &&
      s.verification === "approved" &&
      s.ci === "passed" &&
      pub === "succeeded" &&
      s.repairSource === null)
  );
}
export function validateControllerSnapshotV2(
  value: unknown,
): value is ControllerSnapshotV2 {
  try {
    return validSnapshot(snapshotControllerInputV2(value));
  } catch {
    return false;
  }
}
export const isControllerSnapshotV2 = validateControllerSnapshotV2;
export function digestControllerSnapshotV2(value: unknown): DigestSha256V2 {
  const copy = snapshotControllerInputV2(value);
  if (!validSnapshot(copy)) throw new TypeError("invalid controller snapshot");
  return digestControllerValueV2("spts.controller-snapshot/2.0.0", copy);
}

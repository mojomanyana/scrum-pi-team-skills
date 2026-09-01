import { createHash } from "node:crypto";

import type { FlowRoleV2 } from "./flow-task-packet.js";
export type ProtocolIdV2 = string;
export type GitSha1V2 = string;
export type DigestSha256V2 = string;
export type TimestampV2 = string;
export type SafeRevisionV2 = number;
export type PositiveLimitV2 = number;
export type UsageCountV2 = number;
export type ControllerCommandKindV2 =
  | "begin-implementation"
  | "submit-review"
  | "request-verification"
  | "record-verification-approved"
  | "record-verification-rejected"
  | "begin-repair"
  | "authorize-publication"
  | "record-publication-unknown"
  | "record-publication-succeeded"
  | "recover-reconcile-publication"
  | "record-ci-passed"
  | "record-ci-failed"
  | "request-merge"
  | "record-merged"
  | "cancel";
export type ControllerEvidenceKindV2 =
  | "implementation"
  | "review"
  | "verification"
  | "publication-observation"
  | "ci-observation"
  | "merge-request"
  | "merge-observation"
  | "cancellation";
export interface ControllerEvidenceReferenceV2 {
  evidenceId: ProtocolIdV2;
  kind: ControllerEvidenceKindV2;
  digest: DigestSha256V2;
}
export interface ControllerActorV2 {
  role: FlowRoleV2;
  actorId: ProtocolIdV2;
  executionId: ProtocolIdV2;
  workspaceId: ProtocolIdV2;
}
export interface ControllerTargetV2 {
  projectId: ProtocolIdV2;
  taskId: ProtocolIdV2;
  repositoryId: ProtocolIdV2;
  candidateCommit: GitSha1V2;
  candidateTree: GitSha1V2;
}
export type EmptyCommandPayloadV2 = Record<string, never>;
export interface PublicationUnknownPayloadV2 {
  publicationId: ProtocolIdV2;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  priorUnknownObservationDigest: null;
}
export interface PublicationSucceededPayloadV2 {
  publicationId: ProtocolIdV2;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  priorUnknownObservationDigest: DigestSha256V2 | null;
}
export interface ReconcilePublicationPayloadV2 {
  publicationId: ProtocolIdV2;
  publicationIntentId: ProtocolIdV2;
  publicationIntentDigest: DigestSha256V2;
  priorUnknownObservationDigest: DigestSha256V2;
}
type Payload<K extends ControllerCommandKindV2> =
  K extends "record-publication-unknown"
    ? PublicationUnknownPayloadV2
    : K extends "record-publication-succeeded"
      ? PublicationSucceededPayloadV2
      : K extends "recover-reconcile-publication"
        ? ReconcilePublicationPayloadV2
        : EmptyCommandPayloadV2;
export type ControllerCommandV2 = {
  [K in ControllerCommandKindV2]: {
    contractId: "spts.controller-command";
    schemaVersion: "2.0.0";
    commandId: ProtocolIdV2;
    idempotencyKey: ProtocolIdV2;
    kind: K;
    expectedRevision: SafeRevisionV2;
    actor: ControllerActorV2;
    target: ControllerTargetV2;
    evidence: readonly ControllerEvidenceReferenceV2[];
    payload: Payload<K>;
  };
}[ControllerCommandKindV2];

const encoder = new TextEncoder();
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const sha1Pattern = /^[0-9a-f]{40}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const roles = new Set([
  "product",
  "flow",
  "principal-developer",
  "independent-verifier",
]);
const commandKinds = new Set<ControllerCommandKindV2>([
  "begin-implementation",
  "submit-review",
  "request-verification",
  "record-verification-approved",
  "record-verification-rejected",
  "begin-repair",
  "authorize-publication",
  "record-publication-unknown",
  "record-publication-succeeded",
  "recover-reconcile-publication",
  "record-ci-passed",
  "record-ci-failed",
  "request-merge",
  "record-merged",
  "cancel",
]);
const evidenceKinds = new Set<ControllerEvidenceKindV2>([
  "implementation",
  "review",
  "verification",
  "publication-observation",
  "ci-observation",
  "merge-request",
  "merge-observation",
  "cancellation",
]);

function safeString(value: unknown, pattern?: RegExp): value is string {
  return (
    typeof value === "string" &&
    value.normalize("NFC") === value &&
    encoder.encode(value).length <= 4096 &&
    !/[\uD800-\uDFFF]/u.test(value) &&
    (pattern === undefined || pattern.test(value))
  );
}
function exactObject(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    return false;
  const own = Reflect.ownKeys(value);
  if (own.some((key) => typeof key !== "string") || own.length !== keys.length)
    return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && "value" in descriptor;
  });
}
export function snapshotControllerInputV2(value: unknown): unknown {
  let nodes = 0;
  let bytes = 0;
  const ancestors = new Set<object>();
  const copy = (item: unknown, depth: number): unknown => {
    if (++nodes > 10000 || depth > 32)
      throw new TypeError("invalid controller input");
    if (typeof item === "string") {
      const size = encoder.encode(item).length;
      bytes += size;
      if (size > 4096 || bytes > 1048576 || !safeString(item))
        throw new TypeError("invalid controller input");
      return item;
    }
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item) || Object.is(item, -0))
        throw new TypeError("invalid controller input");
      return item;
    }
    if (typeof item !== "object" || ancestors.has(item))
      throw new TypeError("invalid controller input");
    ancestors.add(item);
    try {
      const keys = Reflect.ownKeys(item);
      if (keys.some((key) => typeof key !== "string"))
        throw new TypeError("invalid controller input");
      if (Array.isArray(item)) {
        const lengthDescriptor = Object.getOwnPropertyDescriptor(
          item,
          "length",
        );
        const length =
          lengthDescriptor && "value" in lengthDescriptor
            ? lengthDescriptor.value
            : -1;
        if (
          !Number.isSafeInteger(length) ||
          length < 0 ||
          length > 256 ||
          keys.length !== length + 1 ||
          !lengthDescriptor ||
          lengthDescriptor.configurable ||
          lengthDescriptor.enumerable ||
          !lengthDescriptor.writable
        )
          throw new TypeError("invalid controller input");
        const result: unknown[] = [];
        for (let index = 0; index < length; index++) {
          const key = String(index);
          bytes += encoder.encode(key).length;
          const descriptor = Object.getOwnPropertyDescriptor(item, key);
          if (!descriptor?.enumerable || !("value" in descriptor))
            throw new TypeError("invalid controller input");
          result.push(copy(descriptor.value, depth + 1));
        }
        bytes += 6;
        if (bytes > 1048576) throw new TypeError("invalid controller input");
        return result;
      }
      if (Object.getPrototypeOf(item) !== Object.prototype || keys.length > 64)
        throw new TypeError("invalid controller input");
      const result: Record<string, unknown> = {};
      for (const key of keys as string[]) {
        const size = encoder.encode(key).length;
        bytes += size;
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (
          size > 4096 ||
          bytes > 1048576 ||
          !safeString(key) ||
          !descriptor?.enumerable ||
          !("value" in descriptor)
        )
          throw new TypeError("invalid controller input");
        result[key] = copy(descriptor.value, depth + 1);
      }
      return result;
    } finally {
      ancestors.delete(item);
    }
  };
  return copy(value, 0);
}

export function canonicalizeControllerValueV2(value: unknown): string {
  const item = snapshotControllerInputV2(value);
  const render = (v: unknown): string =>
    Array.isArray(v)
      ? `[${v.map(render).join(",")}]`
      : typeof v === "object" && v !== null
        ? `{${Object.keys(v)
            .sort()
            .map(
              (key) =>
                `${JSON.stringify(key)}:${render((v as Record<string, unknown>)[key])}`,
            )
            .join(",")}}`
        : JSON.stringify(v);
  return render(item);
}
export function digestControllerValueV2(
  domain: string,
  value: unknown,
): DigestSha256V2 {
  return createHash("sha256")
    .update(domain)
    .update("\0")
    .update(canonicalizeControllerValueV2(value))
    .digest("hex");
}

function isId(value: unknown): value is string {
  return safeString(value, idPattern);
}
function isDigest(value: unknown): value is string {
  return safeString(value, sha256Pattern);
}
function structurallyValidCommand(
  value: unknown,
): value is ControllerCommandV2 {
  if (
    !exactObject(value, [
      "contractId",
      "schemaVersion",
      "commandId",
      "idempotencyKey",
      "kind",
      "expectedRevision",
      "actor",
      "target",
      "evidence",
      "payload",
    ])
  )
    return false;
  if (
    value.contractId !== "spts.controller-command" ||
    value.schemaVersion !== "2.0.0" ||
    !isId(value.commandId) ||
    !isId(value.idempotencyKey) ||
    !commandKinds.has(value.kind as ControllerCommandKindV2) ||
    !Number.isSafeInteger(value.expectedRevision) ||
    (value.expectedRevision as number) < 0
  )
    return false;
  const actor = value.actor;
  if (
    !exactObject(actor, ["role", "actorId", "executionId", "workspaceId"]) ||
    !roles.has(actor.role as string) ||
    !isId(actor.actorId) ||
    !isId(actor.executionId) ||
    !isId(actor.workspaceId)
  )
    return false;
  const target = value.target;
  if (
    !exactObject(target, [
      "projectId",
      "taskId",
      "repositoryId",
      "candidateCommit",
      "candidateTree",
    ]) ||
    !isId(target.projectId) ||
    !isId(target.taskId) ||
    !isId(target.repositoryId) ||
    !safeString(target.candidateCommit, sha1Pattern) ||
    !safeString(target.candidateTree, sha1Pattern)
  )
    return false;
  if (
    !Array.isArray(value.evidence) ||
    value.evidence.length > 32 ||
    !value.evidence.every(
      (entry) =>
        exactObject(entry, ["evidenceId", "kind", "digest"]) &&
        isId(entry.evidenceId) &&
        evidenceKinds.has(entry.kind as ControllerEvidenceKindV2) &&
        isDigest(entry.digest),
    )
  )
    return false;
  const publication =
    value.kind === "record-publication-unknown" ||
    value.kind === "record-publication-succeeded" ||
    value.kind === "recover-reconcile-publication";
  if (!publication) return exactObject(value.payload, []);
  const payload = value.payload;
  if (
    !exactObject(payload, [
      "publicationId",
      "publicationIntentId",
      "publicationIntentDigest",
      "priorUnknownObservationDigest",
    ]) ||
    !isId(payload.publicationId) ||
    !isId(payload.publicationIntentId) ||
    !isDigest(payload.publicationIntentDigest)
  )
    return false;
  return value.kind === "record-publication-unknown"
    ? payload.priorUnknownObservationDigest === null
    : value.kind === "recover-reconcile-publication"
      ? isDigest(payload.priorUnknownObservationDigest)
      : payload.priorUnknownObservationDigest === null ||
        isDigest(payload.priorUnknownObservationDigest);
}
export function validateControllerCommandV2(
  value: unknown,
): value is ControllerCommandV2 {
  try {
    return structurallyValidCommand(snapshotControllerInputV2(value));
  } catch {
    return false;
  }
}
export const isControllerCommandV2 = validateControllerCommandV2;
export function digestControllerCommandV2(value: unknown): DigestSha256V2 {
  const snapshot = snapshotControllerInputV2(value);
  if (!structurallyValidCommand(snapshot))
    throw new TypeError("invalid controller command");
  return digestControllerValueV2("spts.controller-command/2.0.0", snapshot);
}

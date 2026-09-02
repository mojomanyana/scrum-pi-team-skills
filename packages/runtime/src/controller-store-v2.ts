import { createHash } from "node:crypto";

import {
  canonicalizeControllerStoreValueV2,
  controllerStoreValueContainsCredentialV2,
  deriveControllerRunIdentityDigestV2,
  digestControllerCommandV2,
  digestControllerSnapshotV2,
  digestControllerStoreValueV2,
  validateControllerCommandV2,
  validateControllerRunIdentityV2,
  validateControllerSnapshotV2,
  validateControllerTransitionV2,
  type CommittedControllerTransitionReceiptV2,
  type ControllerCommandV2,
  type ControllerRunIdentityV2,
  type ControllerSnapshotV2,
  type ControllerStoreDiagnosticV2,
  type ControllerStoreStatusV2,
  type DigestSha256V2,
  type EffectIntentV2,
  type ProposedControllerTransitionV2,
  type ReadyControllerStoreStatusV2,
} from "@scrum-pi-team-skills/contracts";

const digestPattern = /^[0-9a-f]{64}$/;
const timestampPattern =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;
const encoder = new TextEncoder();
const zeroDigest = "0".repeat(64);

export interface ControllerStoreOperationOptionsV2 {
  readonly operationId: string;
  readonly requestDigest: DigestSha256V2;
  readonly abortSignal?: AbortSignal;
}

export interface ControllerStoreRecoveryOptionsV2 {
  readonly operationId: string;
  readonly abortSignal?: AbortSignal;
}

export type ControllerStoreResultV2<T> =
  | {
      readonly disposition: "ok";
      readonly value: Readonly<T>;
    }
  | {
      readonly disposition: "denied";
      readonly diagnostic: Readonly<ControllerStoreDiagnosticV2>;
    };

export interface ReconstructedControllerStoreProposalV2 {
  readonly identity: Readonly<ControllerRunIdentityV2>;
  readonly previousSnapshot: Readonly<ControllerSnapshotV2>;
  readonly sourceCommand: Readonly<ControllerCommandV2>;
  readonly proposal: Readonly<ProposedControllerTransitionV2>;
  readonly committedSnapshot: Readonly<ControllerSnapshotV2>;
  readonly changes: ProposedControllerTransitionV2["changes"];
  readonly intents: readonly EffectIntentV2[];
  readonly previousSnapshotDigest: DigestSha256V2;
  readonly sourceCommandDigest: DigestSha256V2;
  readonly transitionDigest: DigestSha256V2;
  readonly proposalDigest: DigestSha256V2;
  readonly orderedChangesDigest: DigestSha256V2;
  readonly orderedIntentsDigest: DigestSha256V2;
  readonly transitionChainDigest: DigestSha256V2;
  readonly committedSnapshotDigest: DigestSha256V2;
}

export interface ControllerStoreCreationRequestV2 {
  readonly kind: "create";
  readonly identity: Readonly<ControllerRunIdentityV2>;
  readonly operationIdentity: string;
  readonly operationIdentityDigest: DigestSha256V2;
  readonly idempotencyIdentity: `op-${string}`;
  readonly initialSnapshotDigest: DigestSha256V2;
  readonly canonicalRequestDigest: DigestSha256V2;
}

export interface ControllerStoreCommitRequestV2 extends ReconstructedControllerStoreProposalV2 {
  readonly kind: "commit";
  readonly operationIdentity: string;
  readonly operationIdentityDigest: DigestSha256V2;
  readonly idempotencyIdentity: `op-${string}`;
  readonly expectedRevision: number;
  readonly canonicalRequestDigest: DigestSha256V2;
}

export interface CreatedControllerRunV2 {
  readonly kind: "create";
  readonly replayed: boolean;
  readonly revision: number;
  readonly snapshot: Readonly<ControllerSnapshotV2>;
  readonly status: Readonly<ReadyControllerStoreStatusV2>;
}

export interface LoadedControllerRunV2 {
  readonly kind: "load";
  readonly snapshot: Readonly<ControllerSnapshotV2>;
  readonly status: Readonly<ReadyControllerStoreStatusV2>;
}

export interface CommittedControllerTransitionV2 {
  readonly kind: "commit";
  readonly replayed: boolean;
  readonly revision: number;
  readonly snapshot: Readonly<ControllerSnapshotV2>;
  readonly intents: readonly EffectIntentV2[];
  readonly receipt: Readonly<CommittedControllerTransitionReceiptV2>;
  readonly status: Readonly<ReadyControllerStoreStatusV2>;
}

export interface RecoveredControllerRunV2 {
  readonly kind: "recovery";
  readonly outcome: "ready" | "old-head-restored" | "new-head-preserved";
  readonly status: Readonly<ReadyControllerStoreStatusV2>;
}

export interface ClosedControllerStoreV2 {
  readonly kind: "closed";
}

export interface ControllerStoreV2 {
  createControllerRunV2(
    initialSnapshot: unknown,
    options: ControllerStoreOperationOptionsV2,
  ): Promise<ControllerStoreResultV2<CreatedControllerRunV2>>;
  loadControllerRunV2(
    identity: unknown,
  ): Promise<ControllerStoreResultV2<LoadedControllerRunV2>>;
  inspectControllerRunV2(
    identity: unknown,
  ): Promise<ControllerStoreResultV2<ControllerStoreStatusV2>>;
  commitControllerTransitionV2(
    previousSnapshot: unknown,
    sourceCommand: unknown,
    proposal: unknown,
    options: ControllerStoreOperationOptionsV2,
  ): Promise<ControllerStoreResultV2<CommittedControllerTransitionV2>>;
  recoverControllerRunV2(
    identity: unknown,
    options: ControllerStoreRecoveryOptionsV2,
  ): Promise<ControllerStoreResultV2<RecoveredControllerRunV2>>;
  closeControllerStoreV2(): Promise<
    ControllerStoreResultV2<ClosedControllerStoreV2>
  >;
}

type Dynamic = Record<string, unknown>;

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function clonePublicValue<T>(value: unknown): T {
  return JSON.parse(canonicalizeControllerStoreValueV2(value)) as T;
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  return (
    canonicalizeControllerStoreValueV2(left) ===
    canonicalizeControllerStoreValueV2(right)
  );
}

function exactKeys(value: unknown, keys: readonly string[]): value is Dynamic {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function hasUnsafeIdentifierCodeUnit(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function validIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.normalize("NFC") === value &&
    !hasUnsafeIdentifierCodeUnit(value) &&
    encoder.encode(value).length <= 128 &&
    !controllerStoreValueContainsCredentialV2(value)
  );
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !timestampPattern.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function hashRaw(domain: string, value: string): DigestSha256V2 {
  return createHash("sha256")
    .update(domain)
    .update("\0")
    .update(value)
    .digest("hex");
}

function proposalError(): TypeError {
  return new TypeError("Controller store proposal is invalid.");
}

function creationError(): TypeError {
  return new TypeError("Controller store creation request is invalid.");
}

function deriveRunIdentity(
  namespaceDigest: DigestSha256V2,
  snapshot: ControllerSnapshotV2,
): ControllerRunIdentityV2 {
  const identitySeed: ControllerRunIdentityV2 = {
    namespaceDigest,
    projectId: snapshot.identity.projectId,
    taskId: snapshot.identity.taskId,
    repositoryId: snapshot.identity.repositoryId,
    snapshotId: snapshot.snapshotId,
    headBranch: snapshot.identity.headBranch,
    runIdentityDigest: zeroDigest,
  };
  const identity: ControllerRunIdentityV2 = {
    ...identitySeed,
    runIdentityDigest: deriveControllerRunIdentityDigestV2(identitySeed),
  };
  if (!validateControllerRunIdentityV2(identity)) throw proposalError();
  return identity;
}

function requireNamespaceDigest(
  value: unknown,
): asserts value is DigestSha256V2 {
  if (typeof value !== "string" || !digestPattern.test(value)) {
    throw proposalError();
  }
}

function unsignedIntent(intent: Dynamic): Dynamic {
  const copy = { ...intent };
  delete copy.intentId;
  delete copy.proposalDigestBinding;
  return copy;
}

const transitionKeys = Object.freeze([
  "contractId",
  "schemaVersion",
  "disposition",
  "code",
  "proposalId",
  "proposalDigest",
  "commandId",
  "commandDigest",
  "snapshotId",
  "snapshotDigest",
  "fromRevision",
  "toRevision",
  "fromPhase",
  "toPhase",
  "evaluationId",
  "evaluatedAt",
  "target",
  "priorTransitionDigest",
  "transitionDigest",
  "changes",
  "intents",
  "diagnostics",
  "proposedNextSnapshot",
  "executableAuthority",
] as const);

function applyStateChanges(
  snapshot: ControllerSnapshotV2,
  changes: readonly unknown[],
): ControllerSnapshotV2 {
  const next = structuredClone(snapshot);
  const changed = new Set<string>();
  const applyField = (
    change: Dynamic,
    kind: string,
    owner: Dynamic,
    field: string,
  ): void => {
    if (
      change.kind !== kind ||
      !exactKeys(change, ["kind", "from", "to"]) ||
      changed.has(field) ||
      !canonicalEqual(change.from, owner[field]) ||
      canonicalEqual(change.from, change.to)
    ) {
      throw proposalError();
    }
    changed.add(field);
    owner[field] = clonePublicValue(change.to);
  };

  for (const item of changes) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw proposalError();
    }
    const change = item as Dynamic;
    switch (change.kind) {
      case "candidate-set":
        applyField(
          change,
          "candidate-set",
          next as unknown as Dynamic,
          "candidate",
        );
        break;
      case "phase-set":
        applyField(change, "phase-set", next as unknown as Dynamic, "phase");
        break;
      case "active-role-set":
        applyField(
          change,
          "active-role-set",
          next as unknown as Dynamic,
          "activeRole",
        );
        break;
      case "verification-set":
        applyField(
          change,
          "verification-set",
          next.status as unknown as Dynamic,
          "verification",
        );
        break;
      case "ci-set":
        applyField(change, "ci-set", next.status as unknown as Dynamic, "ci");
        break;
      case "publication-set":
        applyField(
          change,
          "publication-set",
          next.status as unknown as Dynamic,
          "publication",
        );
        break;
      case "merged-set":
        applyField(
          change,
          "merged-set",
          next.status as unknown as Dynamic,
          "merged",
        );
        break;
      case "cancelled-set":
        applyField(
          change,
          "cancelled-set",
          next.status as unknown as Dynamic,
          "cancelled",
        );
        break;
      case "terminal-set":
        applyField(
          change,
          "terminal-set",
          next.status as unknown as Dynamic,
          "terminal",
        );
        break;
      case "repair-source-set":
        applyField(
          change,
          "repair-source-set",
          next.status as unknown as Dynamic,
          "repairSource",
        );
        break;
      case "usage-set": {
        if (
          !exactKeys(change, ["kind", "counter", "from", "to"]) ||
          ![
            "implementationAttempts",
            "verificationRepairs",
            "ciRepairs",
          ].includes(change.counter as string)
        ) {
          throw proposalError();
        }
        const counter = change.counter as keyof ControllerSnapshotV2["usage"];
        const field = `usage.${counter}`;
        if (
          changed.has(field) ||
          change.from !== next.usage[counter] ||
          !Number.isSafeInteger(change.to) ||
          change.to !== next.usage[counter] + 1 ||
          (change.to as number) > next.limits[counter]
        ) {
          throw proposalError();
        }
        changed.add(field);
        (next.usage as Record<typeof counter, number>)[counter] =
          change.to as number;
        break;
      }
      default:
        throw proposalError();
    }
  }
  return next;
}

function verifyCommonChanges(
  changes: readonly unknown[],
  snapshot: ControllerSnapshotV2,
  source: ControllerCommandV2,
  transitionDigest: DigestSha256V2,
): void {
  const accepted = {
    idempotencyKey: source.idempotencyKey,
    commandDigest: digestControllerCommandV2(source),
    transitionDigest,
  };
  const expected = [
    { kind: "accepted-command-added", value: accepted },
    {
      kind: "revision-set",
      from: snapshot.revision,
      to: snapshot.revision + 1,
    },
    {
      kind: "previous-transition-digest-set",
      from: snapshot.previousTransitionDigest,
      to: transitionDigest,
    },
  ];
  if (!canonicalEqual(changes.slice(0, 3), expected)) throw proposalError();
}

function finishAppliedSnapshot(
  next: ControllerSnapshotV2,
  source: ControllerCommandV2,
  transitionDigest: DigestSha256V2,
): ControllerSnapshotV2 {
  const accepted = {
    idempotencyKey: source.idempotencyKey,
    commandDigest: digestControllerCommandV2(source),
    transitionDigest,
  };
  next.acceptedCommands = [...next.acceptedCommands, accepted].sort(
    (left, right) => (left.idempotencyKey < right.idempotencyKey ? -1 : 1),
  );
  next.revision += 1;
  next.previousTransitionDigest = transitionDigest;
  return next;
}

/**
 * Reconstruct the authenticated persistence projection without invoking policy
 * evaluation. A self-consistent proposal remains data, never effect authority.
 */
export function reconstructControllerStoreProposalV2(
  namespaceDigestInput: unknown,
  previousSnapshotInput: unknown,
  sourceCommandInput: unknown,
  proposalInput: unknown,
): Readonly<ReconstructedControllerStoreProposalV2> {
  try {
    requireNamespaceDigest(namespaceDigestInput);
    const namespaceDigest = namespaceDigestInput;
    const previousSnapshot = clonePublicValue<ControllerSnapshotV2>(
      previousSnapshotInput,
    );
    const sourceCommand =
      clonePublicValue<ControllerCommandV2>(sourceCommandInput);
    const proposal =
      clonePublicValue<ProposedControllerTransitionV2>(proposalInput);
    if (
      !validateControllerSnapshotV2(previousSnapshot) ||
      !validateControllerCommandV2(sourceCommand) ||
      !validateControllerTransitionV2(proposal) ||
      !exactKeys(proposal, transitionKeys) ||
      proposal.disposition !== "proposed" ||
      proposal.code !== "transition-proposed" ||
      controllerStoreValueContainsCredentialV2(previousSnapshot) ||
      controllerStoreValueContainsCredentialV2(sourceCommand) ||
      controllerStoreValueContainsCredentialV2(proposal) ||
      previousSnapshot.revision === Number.MAX_SAFE_INTEGER ||
      sourceCommand.expectedRevision !== previousSnapshot.revision ||
      sourceCommand.target.projectId !== previousSnapshot.identity.projectId ||
      sourceCommand.target.taskId !== previousSnapshot.identity.taskId ||
      sourceCommand.target.repositoryId !==
        previousSnapshot.identity.repositoryId
    ) {
      throw proposalError();
    }

    const previousSnapshotDigest = digestControllerSnapshotV2(previousSnapshot);
    const sourceCommandDigest = digestControllerCommandV2(sourceCommand);
    if (
      proposal.commandId !== sourceCommand.commandId ||
      proposal.commandDigest !== sourceCommandDigest ||
      proposal.snapshotId !== previousSnapshot.snapshotId ||
      proposal.snapshotDigest !== previousSnapshotDigest ||
      proposal.fromRevision !== previousSnapshot.revision ||
      proposal.toRevision !== previousSnapshot.revision + 1 ||
      proposal.fromPhase !== previousSnapshot.phase ||
      proposal.priorTransitionDigest !==
        previousSnapshot.previousTransitionDigest ||
      !canonicalEqual(proposal.target, sourceCommand.target) ||
      !validIdentifier(proposal.evaluationId) ||
      !validTimestamp(proposal.evaluatedAt) ||
      !Array.isArray(proposal.changes) ||
      proposal.changes.length < 3 ||
      !Array.isArray(proposal.intents) ||
      proposal.diagnostics.length !== 0 ||
      proposal.executableAuthority !== false
    ) {
      throw proposalError();
    }

    const tailChanges = proposal.changes.slice(3);
    const unsignedIntents = proposal.intents.map((intent) => {
      if (
        !exactKeys(intent, [
          "kind",
          "payload",
          "intentId",
          "commandDigest",
          "proposalDigestBinding",
          "target",
          "executableAuthority",
        ]) ||
        intent.commandDigest !== sourceCommandDigest ||
        !canonicalEqual(intent.target, sourceCommand.target) ||
        intent.executableAuthority !== false ||
        !validIdentifier(intent.intentId)
      ) {
        throw proposalError();
      }
      return unsignedIntent(intent);
    });
    const semanticDelta = {
      fromPhase: previousSnapshot.phase,
      toPhase: proposal.proposedNextSnapshot.phase,
      target: sourceCommand.target,
      stateChanges: tailChanges,
      unsignedIntents,
    };
    const transitionDigest = hashRaw(
      "spts.controller-transition-chain/2.0.0",
      `${previousSnapshot.previousTransitionDigest ?? zeroDigest}\0${sourceCommandDigest}\0${previousSnapshot.revision}\0${previousSnapshot.revision + 1}\0${canonicalizeControllerStoreValueV2(semanticDelta)}`,
    );
    if (proposal.transitionDigest !== transitionDigest) throw proposalError();
    verifyCommonChanges(
      proposal.changes,
      previousSnapshot,
      sourceCommand,
      transitionDigest,
    );

    const applied = finishAppliedSnapshot(
      applyStateChanges(previousSnapshot, tailChanges),
      sourceCommand,
      transitionDigest,
    );
    if (
      !validateControllerSnapshotV2(applied) ||
      !canonicalEqual(applied, proposal.proposedNextSnapshot) ||
      proposal.toPhase !== applied.phase ||
      proposal.transitionDigest !== applied.previousTransitionDigest
    ) {
      throw proposalError();
    }

    const proposalProjection = clonePublicValue<Dynamic>(proposal);
    delete proposalProjection.proposalId;
    delete proposalProjection.proposalDigest;
    proposalProjection.intents = proposal.intents.map((intent) =>
      unsignedIntent(intent as unknown as Dynamic),
    );
    const proposalDigest = digestControllerStoreValueV2(
      "spts.controller-transition-proposal/2.0.0",
      proposalProjection,
    );
    if (
      proposal.proposalDigest !== proposalDigest ||
      proposal.proposalId !== `proposal-${proposalDigest.slice(0, 32)}`
    ) {
      throw proposalError();
    }
    proposal.intents.forEach((intent, index) => {
      const expectedIntentId = `intent-${hashRaw(
        "spts.controller-intent/2.0.0",
        `${proposalDigest}\0${String(index).padStart(4, "0")}\0${intent.kind}`,
      ).slice(0, 32)}`;
      if (
        intent.intentId !== expectedIntentId ||
        intent.proposalDigestBinding !== proposalDigest
      ) {
        throw proposalError();
      }
    });

    const identity = deriveRunIdentity(namespaceDigest, previousSnapshot);
    const committedSnapshotDigest = digestControllerSnapshotV2(applied);
    const reconstructed: ReconstructedControllerStoreProposalV2 = {
      identity,
      previousSnapshot,
      sourceCommand,
      proposal,
      committedSnapshot: applied,
      changes: proposal.changes,
      intents: proposal.intents,
      previousSnapshotDigest,
      sourceCommandDigest,
      transitionDigest,
      proposalDigest,
      orderedChangesDigest: digestControllerStoreValueV2(
        "spts/controller-store-ordered-changes/v2",
        proposal.changes,
      ),
      orderedIntentsDigest: digestControllerStoreValueV2(
        "spts/controller-store-ordered-intents/v2",
        proposal.intents,
      ),
      transitionChainDigest: transitionDigest,
      committedSnapshotDigest,
    };
    return deepFreeze(reconstructed);
  } catch {
    throw proposalError();
  }
}

function operationProjection(
  namespaceDigest: DigestSha256V2,
  runIdentityDigest: DigestSha256V2,
  operationIdentity: string,
): {
  readonly operationIdentityDigest: DigestSha256V2;
  readonly idempotencyIdentity: `op-${string}`;
} {
  if (!validIdentifier(operationIdentity)) throw creationError();
  const operationIdentityDigest = digestControllerStoreValueV2(
    "spts/controller-store-operation-identity/v2",
    { namespaceDigest, runIdentityDigest, operationId: operationIdentity },
  );
  return {
    operationIdentityDigest,
    idempotencyIdentity: `op-${operationIdentityDigest}`,
  };
}

export function deriveControllerStoreCreationRequestV2(
  namespaceDigestInput: unknown,
  initialSnapshotInput: unknown,
  operationIdentityInput: unknown,
): Readonly<ControllerStoreCreationRequestV2> {
  try {
    requireNamespaceDigest(namespaceDigestInput);
    if (!validIdentifier(operationIdentityInput)) throw creationError();
    const initialSnapshot =
      clonePublicValue<ControllerSnapshotV2>(initialSnapshotInput);
    if (
      !validateControllerSnapshotV2(initialSnapshot) ||
      initialSnapshot.revision !== 0 ||
      initialSnapshot.previousTransitionDigest !== null ||
      controllerStoreValueContainsCredentialV2(initialSnapshot)
    ) {
      throw creationError();
    }
    const identity = deriveRunIdentity(namespaceDigestInput, initialSnapshot);
    const operation = operationProjection(
      namespaceDigestInput,
      identity.runIdentityDigest,
      operationIdentityInput,
    );
    const initialSnapshotDigest = digestControllerSnapshotV2(initialSnapshot);
    const requestProjection = {
      kind: "create" as const,
      identity,
      operationIdentity: operationIdentityInput,
      operationIdentityDigest: operation.operationIdentityDigest,
      idempotencyIdentity: operation.idempotencyIdentity,
      initialSnapshotDigest,
    };
    return deepFreeze({
      ...requestProjection,
      canonicalRequestDigest: digestControllerStoreValueV2(
        "spts/controller-store-create-request/v2",
        requestProjection,
      ),
    });
  } catch {
    throw creationError();
  }
}

export function deriveControllerStoreCommitRequestV2(
  namespaceDigestInput: unknown,
  previousSnapshotInput: unknown,
  sourceCommandInput: unknown,
  proposalInput: unknown,
  operationIdentityInput: unknown,
): Readonly<ControllerStoreCommitRequestV2> {
  try {
    if (!validIdentifier(operationIdentityInput)) throw proposalError();
    const reconstructed = reconstructControllerStoreProposalV2(
      namespaceDigestInput,
      previousSnapshotInput,
      sourceCommandInput,
      proposalInput,
    );
    const operation = operationProjection(
      reconstructed.identity.namespaceDigest,
      reconstructed.identity.runIdentityDigest,
      operationIdentityInput,
    );
    const requestProjection = {
      kind: "commit" as const,
      identity: reconstructed.identity,
      operationIdentity: operationIdentityInput,
      operationIdentityDigest: operation.operationIdentityDigest,
      idempotencyIdentity: operation.idempotencyIdentity,
      expectedRevision: reconstructed.previousSnapshot.revision,
      previousSnapshotDigest: reconstructed.previousSnapshotDigest,
      sourceCommandDigest: reconstructed.sourceCommandDigest,
      transitionDigest: reconstructed.transitionDigest,
      proposalDigest: reconstructed.proposalDigest,
      orderedChangesDigest: reconstructed.orderedChangesDigest,
      orderedIntentsDigest: reconstructed.orderedIntentsDigest,
      transitionChainDigest: reconstructed.transitionChainDigest,
      committedSnapshotDigest: reconstructed.committedSnapshotDigest,
    };
    return deepFreeze({
      ...reconstructed,
      ...requestProjection,
      canonicalRequestDigest: digestControllerStoreValueV2(
        "spts/controller-store-commit-request/v2",
        requestProjection,
      ),
    });
  } catch {
    throw proposalError();
  }
}

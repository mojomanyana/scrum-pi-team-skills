import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  digestControllerSnapshotV2,
  type ControllerCommandKindV2,
  type ControllerCommandV2,
  type ControllerSnapshotV2,
  type ProposedControllerTransitionV2,
} from "../../contracts/src/index.js";
import { evaluateControllerTransitionV2 } from "../src/controller-core-v2.js";
import {
  deriveControllerStoreCommitRequestV2,
  deriveControllerStoreCreationRequestV2,
  reconstructControllerStoreProposalV2,
} from "../src/controller-store-v2.js";

const zero = "0".repeat(64);
const namespaceDigest =
  "befaab798f2cec8585ed4bbc7c876320d3f27fe7b5d78074a342e90a873948b8";

function initialSnapshot(): ControllerSnapshotV2 {
  return {
    contractId: "spts.controller-snapshot",
    schemaVersion: "2.0.0",
    snapshotId: "store-run-1",
    revision: 0,
    previousTransitionDigest: null,
    authorityDigest: "1".repeat(64),
    meteringDigest: "2".repeat(64),
    controllerStateDigest: "3".repeat(64),
    identity: {
      projectId: "project-1",
      taskId: "task-1",
      repositoryId: "repo-1",
      baseCommit: "0".repeat(40),
      baseTree: "1".repeat(40),
      headBranch: "main",
    },
    candidate: { commit: "2".repeat(40), tree: "3".repeat(40) },
    phase: "ready",
    activeRole: "principal-developer",
    status: {
      verification: "unverified",
      ci: "not-started",
      publication: {
        state: "not-requested",
        publicationId: null,
        publicationIntentId: null,
        publicationIntentDigest: null,
        unknownObservationDigest: null,
      },
      merged: false,
      cancelled: false,
      terminal: false,
      repairSource: null,
    },
    limits: {
      implementationAttempts: 5,
      verificationRepairs: 5,
      ciRepairs: 5,
    },
    usage: {
      implementationAttempts: 0,
      verificationRepairs: 0,
      ciRepairs: 0,
    },
    acceptedCommands: [],
  };
}

const roles: Record<
  ControllerCommandKindV2,
  ControllerCommandV2["actor"]["role"]
> = {
  "begin-implementation": "principal-developer",
  "submit-review": "principal-developer",
  "request-verification": "flow",
  "record-verification-approved": "independent-verifier",
  "record-verification-rejected": "independent-verifier",
  "begin-repair": "principal-developer",
  "authorize-publication": "flow",
  "record-publication-unknown": "flow",
  "record-publication-succeeded": "flow",
  "recover-reconcile-publication": "flow",
  "record-ci-passed": "flow",
  "record-ci-failed": "flow",
  "request-merge": "product",
  "record-merged": "flow",
  cancel: "product",
};
const evidenceKinds: Partial<Record<ControllerCommandKindV2, string>> = {
  "submit-review": "implementation",
  "request-verification": "review",
  "record-verification-approved": "verification",
  "record-verification-rejected": "verification",
  "record-publication-unknown": "publication-observation",
  "record-publication-succeeded": "publication-observation",
  "record-ci-passed": "ci-observation",
  "record-ci-failed": "ci-observation",
  "request-merge": "merge-request",
  "record-merged": "merge-observation",
  cancel: "cancellation",
};

function command(
  snapshot: ControllerSnapshotV2,
  kind: ControllerCommandKindV2,
  serial: number,
): ControllerCommandV2 {
  const publication = snapshot.status.publication;
  const payload = [
    "record-publication-unknown",
    "record-publication-succeeded",
    "recover-reconcile-publication",
  ].includes(kind)
    ? {
        publicationId: publication.publicationId ?? "publication-1",
        publicationIntentId: publication.publicationIntentId!,
        publicationIntentDigest: publication.publicationIntentDigest!,
        priorUnknownObservationDigest: publication.unknownObservationDigest,
      }
    : {};
  const evidenceKind = evidenceKinds[kind];
  return {
    contractId: "spts.controller-command",
    schemaVersion: "2.0.0",
    commandId: `command-${serial}`,
    idempotencyKey: `key-${String(serial).padStart(3, "0")}`,
    kind,
    expectedRevision: snapshot.revision,
    actor: {
      role: roles[kind],
      actorId: "actor-1",
      executionId: "execution-1",
      workspaceId: "workspace-1",
    },
    target: {
      projectId: snapshot.identity.projectId,
      taskId: snapshot.identity.taskId,
      repositoryId: snapshot.identity.repositoryId,
      candidateCommit:
        kind === "submit-review" ? "4".repeat(40) : snapshot.candidate.commit,
      candidateTree:
        kind === "submit-review" ? "5".repeat(40) : snapshot.candidate.tree,
    },
    evidence: evidenceKind
      ? [
          {
            evidenceId: `evidence-${serial}`,
            kind: evidenceKind as never,
            digest: createHash("sha256").update(String(serial)).digest("hex"),
          },
        ]
      : [],
    payload: payload as never,
  } as ControllerCommandV2;
}

function propose(
  snapshot: ControllerSnapshotV2,
  kind: ControllerCommandKindV2,
  serial: number,
): readonly [ControllerCommandV2, ProposedControllerTransitionV2] {
  const source = command(snapshot, kind, serial);
  const proposal = evaluateControllerTransitionV2(snapshot, source, {
    contractId: "spts.controller-evaluation-context",
    schemaVersion: "2.0.0",
    evaluationId: `evaluation-${serial}`,
    evaluatedAt: `2026-09-02T00:00:${String(serial).padStart(2, "0")}.000Z`,
    snapshotDigest: digestControllerSnapshotV2(snapshot),
    authorityDigest: snapshot.authorityDigest,
    meteringDigest: snapshot.meteringDigest,
    controllerStateDigest: snapshot.controllerStateDigest,
  });
  if (proposal.disposition !== "proposed") {
    throw new Error(`fixture failed: ${proposal.code}`);
  }
  return [source, proposal as ProposedControllerTransitionV2] as const;
}

function variants(): Array<
  readonly [
    ControllerSnapshotV2,
    ControllerCommandV2,
    ProposedControllerTransitionV2,
  ]
> {
  const values: Array<
    readonly [
      ControllerSnapshotV2,
      ControllerCommandV2,
      ProposedControllerTransitionV2,
    ]
  > = [];
  let serial = 1;
  const step = (
    snapshot: ControllerSnapshotV2,
    kind: ControllerCommandKindV2,
  ): ControllerSnapshotV2 => {
    const [source, proposal] = propose(snapshot, kind, serial++);
    values.push([snapshot, source, proposal]);
    return structuredClone(proposal.proposedNextSnapshot);
  };

  const ready = initialSnapshot();
  const implementation = step(ready, "begin-implementation");
  const review = step(implementation, "submit-review");
  const verification = step(review, "request-verification");

  const publication = step(verification, "record-verification-approved");
  const intentCommitted = step(publication, "authorize-publication");
  const outcomeUnknown = step(intentCommitted, "record-publication-unknown");
  step(outcomeUnknown, "recover-reconcile-publication");
  const monitoringFromUnknown = step(
    outcomeUnknown,
    "record-publication-succeeded",
  );
  const mergeGate = step(monitoringFromUnknown, "record-ci-passed");
  step(mergeGate, "request-merge");
  step(mergeGate, "record-merged");

  const monitoringDirect = step(
    intentCommitted,
    "record-publication-succeeded",
  );
  const ciRepairRequired = step(monitoringDirect, "record-ci-failed");
  step(ciRepairRequired, "begin-repair");

  const verificationRepair = step(verification, "record-verification-rejected");
  step(verificationRepair, "begin-repair");
  step(review, "cancel");
  return values;
}

describe("controller store pure protocol seam", () => {
  it("reconstructs every nominal Slice 3 change/intent variant without policy evaluation", () => {
    const rows = variants();
    expect(rows).toHaveLength(17);
    for (const [snapshot, source, proposal] of rows) {
      const reconstructed = reconstructControllerStoreProposalV2(
        namespaceDigest,
        snapshot,
        source,
        proposal,
      );
      expect(reconstructed.transitionDigest).toBe(proposal.transitionDigest);
      expect(reconstructed.transitionChainDigest).toBe(
        proposal.transitionDigest,
      );
      expect(reconstructed.proposalDigest).toBe(proposal.proposalDigest);
      expect(reconstructed.committedSnapshot).toEqual(
        proposal.proposedNextSnapshot,
      );
      expect(reconstructed.intents).toEqual(proposal.intents);
      expect(
        reconstructed.intents.every(
          (intent) => intent.executableAuthority === false,
        ),
      ).toBe(true);
    }

    const sourceText = readFileSync(
      fileURLToPath(new URL("../src/controller-store-v2.ts", import.meta.url)),
      "utf8",
    );
    expect(sourceText).not.toContain("evaluateControllerTransitionV2");
    expect(sourceText).not.toMatch(/node:(?:child_process|net|http|https)/);
  });

  it("derives creation and commit identities and canonical requests from reconstructed data", () => {
    const snapshot = initialSnapshot();
    const creation = deriveControllerStoreCreationRequestV2(
      namespaceDigest,
      snapshot,
      "create-operation-1",
    );
    expect(creation.identity.runIdentityDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(creation.operationIdentityDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(creation.idempotencyIdentity).toBe(
      `op-${creation.operationIdentityDigest}`,
    );
    expect(creation.canonicalRequestDigest).toMatch(/^[0-9a-f]{64}$/);

    const [source, proposal] = propose(snapshot, "begin-implementation", 1);
    const commit = deriveControllerStoreCommitRequestV2(
      namespaceDigest,
      snapshot,
      source,
      proposal,
      "commit-operation-1",
    );
    expect(commit.identity).toEqual(creation.identity);
    expect(commit.expectedRevision).toBe(0);
    expect(commit.committedSnapshotDigest).toBe(
      digestControllerSnapshotV2(
        structuredClone(proposal.proposedNextSnapshot),
      ),
    );
    expect(commit.canonicalRequestDigest).not.toBe(
      creation.canonicalRequestDigest,
    );
  });

  it("accepts paired surrogate identifiers while rejecting controls and lone surrogates", () => {
    expect(
      deriveControllerStoreCreationRequestV2(
        namespaceDigest,
        initialSnapshot(),
        "create-😀",
      ).operationIdentity,
    ).toBe("create-😀");

    for (const operationId of ["bad\0id", "bad\nline", "\ud800"]) {
      expect(() =>
        deriveControllerStoreCreationRequestV2(
          namespaceDigest,
          initialSnapshot(),
          operationId,
        ),
      ).toThrow("Controller store creation request is invalid.");
    }
  });

  it("rejects wrong order, changed projections, malformed inputs, and non-proposed dispositions", () => {
    const snapshot = initialSnapshot();
    const [source, proposal] = propose(snapshot, "begin-implementation", 1);

    const proposalCopy = structuredClone(proposal);
    const reordered = {
      ...proposalCopy,
      changes: [
        proposalCopy.changes[1]!,
        proposalCopy.changes[0]!,
        ...proposalCopy.changes.slice(2),
      ],
    };
    expect(() =>
      reconstructControllerStoreProposalV2(
        namespaceDigest,
        snapshot,
        source,
        reordered,
      ),
    ).toThrow("Controller store proposal is invalid.");

    const changedIntent = structuredClone(proposal);
    changedIntent.intents[0]!.intentId = "intent-forged";
    expect(() =>
      reconstructControllerStoreProposalV2(
        namespaceDigest,
        snapshot,
        source,
        changedIntent,
      ),
    ).toThrow("Controller store proposal is invalid.");

    for (const disposition of ["duplicate", "rejected"] as const) {
      expect(() =>
        reconstructControllerStoreProposalV2(
          namespaceDigest,
          snapshot,
          source,
          {
            ...proposal,
            disposition,
          },
        ),
      ).toThrow("Controller store proposal is invalid.");
    }

    const getter = Object.defineProperty({}, "contractId", {
      enumerable: true,
      get() {
        throw new Error("must not run");
      },
    });
    expect(() =>
      reconstructControllerStoreProposalV2(
        namespaceDigest,
        getter,
        source,
        proposal,
      ),
    ).toThrow("Controller store proposal is invalid.");
  });

  it("documents that a structurally self-consistent proposed object has no evaluator provenance", () => {
    const snapshot = initialSnapshot();
    const [source, proposal] = propose(snapshot, "begin-implementation", 1);
    const copiedWithoutProvenance = structuredClone(proposal);
    expect(
      reconstructControllerStoreProposalV2(
        namespaceDigest,
        snapshot,
        source,
        copiedWithoutProvenance,
      ).proposalDigest,
    ).toBe(proposal.proposalDigest);
  });

  it("rejects revision overflow at request derivation", () => {
    const snapshot = initialSnapshot();
    (snapshot as { revision: number }).revision = Number.MAX_SAFE_INTEGER;
    (
      snapshot as { previousTransitionDigest: string | null }
    ).previousTransitionDigest = zero;
    expect(() =>
      deriveControllerStoreCommitRequestV2(
        namespaceDigest,
        snapshot,
        {},
        {},
        "overflow-operation",
      ),
    ).toThrow("Controller store proposal is invalid.");
  });
});

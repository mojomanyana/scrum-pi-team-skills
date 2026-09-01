import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { evaluateControllerTransitionV2 } from "../src/controller-core-v2.js";

const canonical = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
    .join(",")}}`;
};
const digest = (domain: string, value: unknown) =>
  createHash("sha256")
    .update(`${domain}\0${canonical(value)}`)
    .digest("hex");

describe("controller core v2", () => {
  it("rejects malformed inputs with a frozen, non-authoritative result", () => {
    const result = evaluateControllerTransitionV2(undefined, null, null);
    expect(result).toMatchObject({
      disposition: "rejected",
      code: "snapshot-input-invalid",
      executableAuthority: false,
      diagnostics: [{ code: "snapshot-input-invalid", path: "/snapshot" }],
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.diagnostics)).toBe(true);
  });

  it("rejects structurally open snapshots rather than laundering unknown fields", () => {
    const result = evaluateControllerTransitionV2({ unexpected: true }, {}, {});
    expect(result.code).toBe("snapshot-invalid");
  });

  it("never throws while resolving an equal duplicate", () => {
    const zero = "0".repeat(64);
    const snapshot = {
      contractId: "spts.controller-snapshot",
      schemaVersion: "2.0.0",
      snapshotId: "s",
      revision: 0,
      previousTransitionDigest: null,
      authorityDigest: zero,
      meteringDigest: zero,
      controllerStateDigest: zero,
      identity: {
        projectId: "p",
        taskId: "t",
        repositoryId: "r",
        baseCommit: "0".repeat(40),
        baseTree: "0".repeat(40),
        headBranch: "h",
      },
      candidate: { commit: "1".repeat(40), tree: "2".repeat(40) },
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
        implementationAttempts: 1,
        verificationRepairs: 1,
        ciRepairs: 1,
      },
      usage: {
        implementationAttempts: 0,
        verificationRepairs: 0,
        ciRepairs: 0,
      },
      acceptedCommands: [],
    };
    const command = {
      contractId: "spts.controller-command",
      schemaVersion: "2.0.0",
      commandId: "c",
      idempotencyKey: "k",
      kind: "begin-implementation",
      expectedRevision: 0,
      actor: {
        role: "principal-developer",
        actorId: "a",
        executionId: "e",
        workspaceId: "w",
      },
      target: {
        projectId: "p",
        taskId: "t",
        repositoryId: "r",
        candidateCommit: "1".repeat(40),
        candidateTree: "2".repeat(40),
      },
      evidence: [],
      payload: {},
    };
    const firstContext = {
      contractId: "spts.controller-evaluation-context",
      schemaVersion: "2.0.0",
      evaluationId: "x",
      evaluatedAt: "2026-01-01T00:00:00.000Z",
      snapshotDigest: digest("spts.controller-snapshot/2.0.0", snapshot),
      authorityDigest: zero,
      meteringDigest: zero,
      controllerStateDigest: zero,
    };
    const first = evaluateControllerTransitionV2(
      snapshot,
      command,
      firstContext,
    );
    expect(first.disposition).toBe("proposed");
    const next = structuredClone(first.proposedNextSnapshot!);
    const retry = { ...command, expectedRevision: 0 };
    const retryContext = {
      ...firstContext,
      snapshotDigest: digest("spts.controller-snapshot/2.0.0", next),
    };
    expect(() =>
      evaluateControllerTransitionV2(next, retry, retryContext),
    ).not.toThrow();
    expect(evaluateControllerTransitionV2(next, retry, retryContext).code).toBe(
      "duplicate-command",
    );
  });
});

const zero = "0".repeat(64);
const hash = (domain: string, value: unknown) =>
  createHash("sha256")
    .update(`${domain}\0${canonical(value)}`)
    .digest("hex");
function snapshot(state: "intent-committed" | "outcome-unknown") {
  const intent = "1".repeat(64),
    observation = "2".repeat(64);
  return {
    contractId: "spts.controller-snapshot",
    schemaVersion: "2.0.0",
    snapshotId: "s",
    revision: 1,
    previousTransitionDigest: zero,
    authorityDigest: zero,
    meteringDigest: zero,
    controllerStateDigest: zero,
    identity: {
      projectId: "p",
      taskId: "t",
      repositoryId: "r",
      baseCommit: "0".repeat(40),
      baseTree: "0".repeat(40),
      headBranch: "h",
    },
    candidate: { commit: "1".repeat(40), tree: "2".repeat(40) },
    phase: "publication",
    activeRole: "flow",
    status: {
      verification: "approved",
      ci: "not-started",
      publication: {
        state,
        publicationId: state === "outcome-unknown" ? "pub" : null,
        publicationIntentId: "pi",
        publicationIntentDigest: intent,
        unknownObservationDigest:
          state === "outcome-unknown" ? observation : null,
      },
      merged: false,
      cancelled: false,
      terminal: false,
      repairSource: null,
    },
    limits: { implementationAttempts: 2, verificationRepairs: 2, ciRepairs: 2 },
    usage: { implementationAttempts: 1, verificationRepairs: 0, ciRepairs: 0 },
    acceptedCommands: [],
  };
}
function command(s: ReturnType<typeof snapshot>, kind: string) {
  return {
    contractId: "spts.controller-command",
    schemaVersion: "2.0.0",
    commandId: `c-${kind}`,
    idempotencyKey: `k-${kind}`,
    kind,
    expectedRevision: s.revision,
    actor: { role: "flow", actorId: "a", executionId: "e", workspaceId: "w" },
    target: {
      projectId: "p",
      taskId: "t",
      repositoryId: "r",
      candidateCommit: s.candidate.commit,
      candidateTree: s.candidate.tree,
    },
    evidence:
      kind === "recover-reconcile-publication"
        ? []
        : [
            {
              evidenceId: "e",
              kind: "publication-observation",
              digest: "3".repeat(64),
            },
          ],
    payload: {
      publicationId: "pub",
      publicationIntentId: "pi",
      publicationIntentDigest: "1".repeat(64),
      priorUnknownObservationDigest:
        s.status.publication.unknownObservationDigest,
    },
  };
}
function context(s: ReturnType<typeof snapshot>) {
  return {
    contractId: "spts.controller-evaluation-context",
    schemaVersion: "2.0.0",
    evaluationId: "x",
    evaluatedAt: "2026-01-01T00:00:00.000Z",
    snapshotDigest: hash("spts.controller-snapshot/2.0.0", s),
    authorityDigest: zero,
    meteringDigest: zero,
    controllerStateDigest: zero,
  };
}

describe("controller publication rows 9-12", () => {
  it.each([
    [
      "intent-committed",
      "record-publication-unknown",
      "publication",
      "outcome-unknown",
    ],
    [
      "intent-committed",
      "record-publication-succeeded",
      "pr-ci-monitoring",
      "succeeded",
    ],
    [
      "outcome-unknown",
      "recover-reconcile-publication",
      "publication",
      "outcome-unknown",
    ],
    [
      "outcome-unknown",
      "record-publication-succeeded",
      "pr-ci-monitoring",
      "succeeded",
    ],
  ] as const)("handles %s / %s", (state, kind, phase, publication) => {
    const s = snapshot(state),
      result = evaluateControllerTransitionV2(s, command(s, kind), context(s));
    expect(result.code).toBe("transition-proposed");
    expect(result.toPhase).toBe(phase);
    expect(result.proposedNextSnapshot?.status.publication.state).toBe(
      publication,
    );
  });

  it("classifies a mismatched publication binding before evidence", () => {
    const s = snapshot("intent-committed"),
      c = command(s, "record-publication-succeeded");
    c.payload.publicationIntentDigest = zero;
    c.evidence = [];
    expect(evaluateControllerTransitionV2(s, c, context(s)).code).toBe(
      "publication-binding-invalid",
    );
  });

  it("checks publication bindings only for an applicable row", () => {
    const s = snapshot("intent-committed"),
      c = command(s, "recover-reconcile-publication");
    c.payload.publicationIntentDigest = zero;
    c.payload.priorUnknownObservationDigest = "2".repeat(64);
    expect(evaluateControllerTransitionV2(s, c, context(s)).code).toBe(
      "transition-denied",
    );
  });

  it("accepts ordered evidence batches and rejects duplicate IDs and bad order", () => {
    const s = snapshot("intent-committed"),
      c = command(s, "record-publication-unknown");
    c.evidence = [
      {
        evidenceId: "a",
        kind: "publication-observation",
        digest: "3".repeat(64),
      },
      {
        evidenceId: "b",
        kind: "publication-observation",
        digest: "4".repeat(64),
      },
    ];
    expect(evaluateControllerTransitionV2(s, c, context(s)).code).toBe(
      "transition-proposed",
    );
    c.evidence = [c.evidence[1]!, c.evidence[0]!];
    expect(evaluateControllerTransitionV2(s, c, context(s)).code).toBe(
      "evidence-required",
    );
    c.evidence = [
      {
        evidenceId: "a",
        kind: "publication-observation",
        digest: "3".repeat(64),
      },
      {
        evidenceId: "a",
        kind: "publication-observation",
        digest: "4".repeat(64),
      },
    ];
    expect(evaluateControllerTransitionV2(s, c, context(s)).code).toBe(
      "evidence-required",
    );
  });

  it("hashes the complete unknown observation projection and requests a Paca update", () => {
    const s = snapshot("intent-committed"),
      c = command(s, "record-publication-unknown"),
      result = evaluateControllerTransitionV2(s, c, context(s));
    const commandDigest = hash("spts.controller-command/2.0.0", c);
    const projection = {
      domain: "spts.publication-unknown-observation/2.0.0",
      projectId: c.target.projectId,
      taskId: c.target.taskId,
      repositoryId: c.target.repositoryId,
      candidateCommit: c.target.candidateCommit,
      candidateTree: c.target.candidateTree,
      commandId: c.commandId,
      commandDigest,
      publicationId: c.payload.publicationId,
      publicationIntentId: c.payload.publicationIntentId,
      publicationIntentDigest: c.payload.publicationIntentDigest,
      evidence: c.evidence,
    };
    expect(
      result.proposedNextSnapshot?.status.publication.unknownObservationDigest,
    ).toBe(hash("spts.publication-unknown-observation/2.0.0", projection));
    expect(result.intents.map((intent) => intent.kind)).toContain(
      "update-paca",
    );
  });

  it("rejects non-NFC and surrogate property names before contract validation", () => {
    const s = snapshot("intent-committed") as Record<string, unknown>;
    s["e\u0301"] = true;
    expect(evaluateControllerTransitionV2(s, {}, {}).code).toBe(
      "snapshot-input-invalid",
    );
    delete s["e\u0301"];
    s["\ud800"] = true;
    expect(evaluateControllerTransitionV2(s, {}, {}).code).toBe(
      "snapshot-input-invalid",
    );
  });
});

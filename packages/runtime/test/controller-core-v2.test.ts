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
    expect(
      result.proposedNextSnapshot?.status.publication.unknownObservationDigest,
    ).toBe("a5e8cebf07bf4251aac9a668c4df8ed721b625ab695e30436da46c7be89cd941");
    expect(result.intents.map((intent) => intent.kind)).toContain(
      "update-paca",
    );
  });

  it("rejects non-NFC and unpaired surrogates in names and values at isolation", () => {
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
    delete s["\ud800"];
    (s.identity as Record<string, unknown>).projectId = "p\ud800";
    expect(evaluateControllerTransitionV2(s, {}, {}).code).toBe(
      "snapshot-input-invalid",
    );
  });

  it.each([
    ["actor-denied", true, false, false],
    ["publication-binding-invalid", false, true, false],
    ["evidence-required", false, false, true],
  ] as const)(
    "reports %s before a candidate mismatch",
    (expected, wrongActor, wrongBinding, wrongEvidence) => {
      const s = snapshot("intent-committed"),
        c = command(s, "record-publication-succeeded");
      c.target.candidateCommit = "9".repeat(40);
      if (wrongActor) c.actor.role = "product";
      if (wrongBinding) c.payload.publicationIntentDigest = zero;
      if (wrongEvidence) c.evidence = [];
      expect(evaluateControllerTransitionV2(s, c, context(s)).code).toBe(
        expected,
      );
    },
  );
});

/* Test builders deliberately use dynamic records to exercise the JSON boundary. */
/* eslint-disable @typescript-eslint/no-explicit-any */
type Fixture = any;
const allKinds = [
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
] as const;
const evidenceKind: Record<string, string | null> = {
  "begin-implementation": null,
  "submit-review": "implementation",
  "request-verification": "review",
  "record-verification-approved": "verification",
  "record-verification-rejected": "verification",
  "begin-repair": null,
  "authorize-publication": null,
  "record-publication-unknown": "publication-observation",
  "record-publication-succeeded": "publication-observation",
  "recover-reconcile-publication": null,
  "record-ci-passed": "ci-observation",
  "record-ci-failed": "ci-observation",
  "request-merge": "merge-request",
  "record-merged": "merge-observation",
  cancel: "cancellation",
};
function rowFixture(
  phase: string,
  role: string,
  publication = "not-requested",
  repairSource: string | null | undefined = undefined,
): Fixture {
  const s = snapshot("intent-committed") as Fixture;
  s.phase = phase;
  s.activeRole = (
    {
      ready: "principal-developer",
      implementation: "principal-developer",
      "internal-review": "flow",
      "independent-verification": "independent-verifier",
      "repair-required": "principal-developer",
      publication: "flow",
      "pr-ci-monitoring": "flow",
      "merge-gate": "product",
    } as Record<string, string>
  )[phase];
  s.status.repairSource = repairSource ?? null;
  s.status.verification =
    repairSource === "verification"
      ? "rejected"
      : ["publication", "pr-ci-monitoring", "merge-gate"].includes(phase) ||
          repairSource === "ci"
        ? "approved"
        : "unverified";
  s.status.ci =
    repairSource === "ci"
      ? "failed"
      : phase === "pr-ci-monitoring"
        ? "pending"
        : phase === "merge-gate"
          ? "passed"
          : "not-started";
  s.status.publication =
    publication === "not-requested"
      ? {
          state: publication,
          publicationId: null,
          publicationIntentId: null,
          publicationIntentDigest: null,
          unknownObservationDigest: null,
        }
      : {
          state: publication,
          publicationId:
            publication === "outcome-unknown" || publication === "succeeded"
              ? "pub"
              : null,
          publicationIntentId: "pi",
          publicationIntentDigest: "1".repeat(64),
          unknownObservationDigest:
            publication === "outcome-unknown" ? "2".repeat(64) : null,
        };
  return s;
}
function rowCommand(s: Fixture, kind: string, role: string) {
  const c = command(s as ReturnType<typeof snapshot>, kind) as Record<
    string,
    any
  >;
  c.actor.role = role;
  if (
    !kind.startsWith("record-publication-") &&
    kind !== "recover-reconcile-publication"
  )
    c.payload = {};
  if (
    kind === "recover-reconcile-publication" &&
    c.payload.priorUnknownObservationDigest === null
  )
    c.payload.priorUnknownObservationDigest = "2".repeat(64);
  const ek = evidenceKind[kind];
  c.evidence =
    ek === null ? [] : [{ evidenceId: "e", kind: ek, digest: "3".repeat(64) }];
  return c;
}
const transitionRows = [
  [
    "ready",
    "begin-implementation",
    "principal-developer",
    "implementation",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "usage-set",
      "phase-set",
    ],
    ["run-implementation", "update-paca"],
  ],
  [
    "implementation",
    "submit-review",
    "principal-developer",
    "internal-review",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "phase-set",
      "active-role-set",
    ],
    ["update-paca"],
  ],
  [
    "internal-review",
    "request-verification",
    "flow",
    "independent-verification",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "phase-set",
      "active-role-set",
    ],
    ["run-independent-verification", "update-paca"],
  ],
  [
    "independent-verification",
    "record-verification-approved",
    "independent-verifier",
    "publication",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "verification-set",
      "phase-set",
      "active-role-set",
    ],
    ["update-paca"],
  ],
  [
    "independent-verification",
    "record-verification-rejected",
    "independent-verifier",
    "repair-required",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "verification-set",
      "repair-source-set",
      "phase-set",
      "active-role-set",
    ],
    ["update-paca"],
  ],
  [
    "repair-required",
    "begin-repair",
    "principal-developer",
    "implementation",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "usage-set",
      "repair-source-set",
      "phase-set",
    ],
    ["run-implementation", "update-paca"],
    "not-requested",
    "verification",
  ],
  [
    "repair-required",
    "begin-repair",
    "principal-developer",
    "implementation",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "usage-set",
      "repair-source-set",
      "phase-set",
    ],
    ["run-implementation", "update-paca"],
    "succeeded",
    "ci",
  ],
  [
    "publication",
    "authorize-publication",
    "flow",
    "publication",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "publication-set",
    ],
    ["publish-candidate"],
    "not-requested",
  ],
  [
    "publication",
    "record-publication-unknown",
    "flow",
    "publication",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "publication-set",
    ],
    ["update-paca"],
    "intent-committed",
  ],
  [
    "publication",
    "record-publication-succeeded",
    "flow",
    "pr-ci-monitoring",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "publication-set",
      "ci-set",
      "phase-set",
    ],
    ["monitor-ci", "update-paca"],
    "intent-committed",
  ],
  [
    "publication",
    "record-publication-succeeded",
    "flow",
    "pr-ci-monitoring",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "publication-set",
      "ci-set",
      "phase-set",
    ],
    ["monitor-ci", "update-paca"],
    "outcome-unknown",
  ],
  [
    "publication",
    "recover-reconcile-publication",
    "flow",
    "publication",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
    ],
    ["reconcile-publication"],
    "outcome-unknown",
  ],
  [
    "pr-ci-monitoring",
    "record-ci-passed",
    "flow",
    "merge-gate",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "ci-set",
      "phase-set",
      "active-role-set",
    ],
    ["update-paca"],
    "succeeded",
  ],
  [
    "pr-ci-monitoring",
    "record-ci-failed",
    "flow",
    "repair-required",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "ci-set",
      "repair-source-set",
      "phase-set",
      "active-role-set",
    ],
    ["update-paca"],
    "succeeded",
  ],
  [
    "merge-gate",
    "request-merge",
    "product",
    "merge-gate",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
    ],
    ["merge-candidate"],
    "succeeded",
  ],
  [
    "merge-gate",
    "record-merged",
    "flow",
    "completed",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "merged-set",
      "terminal-set",
      "phase-set",
    ],
    ["update-paca"],
    "succeeded",
  ],
  [
    "ready",
    "cancel",
    "product",
    "cancelled",
    [
      "accepted-command-added",
      "revision-set",
      "previous-transition-digest-set",
      "cancelled-set",
      "terminal-set",
      "phase-set",
      "active-role-set",
    ],
    ["update-paca"],
  ],
] as const;

describe("complete controller transition matrix", () => {
  it.each(transitionRows)(
    "evaluates %s / %s",
    (
      phase,
      kind,
      role,
      to,
      changes,
      intents,
      publication = "not-requested",
      repair = undefined,
    ) => {
      const s = rowFixture(phase, role, publication, repair),
        before = structuredClone(s);
      const result = evaluateControllerTransitionV2(
        s,
        rowCommand(s, kind, role),
        context(s as ReturnType<typeof snapshot>),
      );
      expect({
        disposition: result.disposition,
        from: result.fromPhase,
        to: result.toPhase,
      }).toEqual({ disposition: "proposed", from: phase, to });
      expect(result.changes.map((x) => x.kind)).toEqual(changes);
      expect(result.intents.map((x) => x.kind)).toEqual(intents);
      expect(result.toRevision).toBe(s.revision + 1);
      expect(result.proposedNextSnapshot?.revision).toBe(s.revision + 1);
      expect(s).toEqual(before);
    },
  );

  it("denies every row for a wrong role and commands unrelated to its phase", () => {
    for (const [
      phase,
      kind,
      role,
      ,
      ,
      ,
      publication = "not-requested",
      repair = undefined,
    ] of transitionRows) {
      const s = rowFixture(phase, role, publication, repair);
      const wrongRole =
        kind === "cancel"
          ? "principal-developer"
          : role === "product"
            ? "flow"
            : "product";
      expect(
        evaluateControllerTransitionV2(
          s,
          rowCommand(s, kind, wrongRole),
          context(s as any),
        ).code,
      ).toBe("actor-denied");
      const commandsForPhase = new Set(
        transitionRows.filter((row) => row[0] === phase).map((row) => row[1]),
      );
      for (const other of allKinds.filter(
        (k) => !commandsForPhase.has(k as any) && k !== "cancel",
      ))
        expect(
          evaluateControllerTransitionV2(
            s,
            rowCommand(s, other, role),
            context(s as any),
          ).code,
        ).toBe("transition-denied");
    }
  });

  it.each([
    [4096, "snapshot-invalid"],
    [4097, "snapshot-input-invalid"],
  ] as const)(
    "enforces the hostile exact string boundary %i",
    (size, expected) => {
      const s = rowFixture("ready", "principal-developer"),
        c = rowCommand(s, "begin-implementation", "principal-developer"),
        hostile = { ...s, ["x".repeat(size)]: true };
      expect(
        evaluateControllerTransitionV2(hostile, c, context(s as any)).code,
      ).toBe(expected);
    },
  );

  it("rejects accessor laundering and leaves production inputs pure under monkeypatch observation", () => {
    const s = rowFixture("ready", "principal-developer"),
      c = rowCommand(s, "begin-implementation", "principal-developer"),
      before = canonical([s, c]);
    let reads = 0;
    const hostile = Object.defineProperty({}, "contractId", {
      enumerable: true,
      get() {
        reads++;
        return "spts.controller-snapshot";
      },
    });
    expect(
      evaluateControllerTransitionV2(hostile, c, context(s as any)).code,
    ).toBe("snapshot-input-invalid");
    expect(reads).toBe(0);
    const originalFreeze = Object.freeze,
      frozen: object[] = [];
    Object.freeze = ((value: object) => {
      frozen.push(value);
      return originalFreeze(value);
    }) as typeof Object.freeze;
    try {
      expect(
        evaluateControllerTransitionV2(s, c, context(s as any)).disposition,
      ).toBe("proposed");
    } finally {
      Object.freeze = originalFreeze;
    }
    expect(frozen.length).toBeGreaterThan(0);
    expect(canonical([s, c])).toBe(before);
  });

  it("has a second literal cryptographic golden including chain, proposal and intent IDs", () => {
    const s = rowFixture("ready", "principal-developer"),
      c = rowCommand(s, "begin-implementation", "principal-developer");
    const r = evaluateControllerTransitionV2(s, c, context(s as any));
    expect([
      r.transitionDigest,
      r.proposalId,
      ...r.intents.map((i) => i.intentId),
    ]).toEqual([
      "4bb73937f91aa04610f46625bce1e3feaee6220c3e25c25fe53c32955a1a623f",
      "proposal-c09e50e39c439ba5abcdc061ad3cc902",
      "intent-1fda522c0c127facec2c275aea1ea825",
      "intent-80ac15accfee703d20a745e7370ae572",
    ]);
  });
});

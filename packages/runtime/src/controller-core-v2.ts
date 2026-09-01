import { createHash } from "node:crypto";
import {
  validateControllerCommandV2,
  validateControllerEvaluationContextV2,
  validateControllerSnapshotV2,
} from "@scrum-pi-team-skills/contracts";
import type {
  ControllerCommandV2,
  ControllerEvaluationContextV2,
  ControllerRejectionCodeV2,
  ControllerSnapshotV2,
  ControllerTransitionV2,
} from "@scrum-pi-team-skills/contracts";

const messages: Record<ControllerRejectionCodeV2, readonly [string, string]> = {
  "snapshot-input-invalid": ["Snapshot input is invalid.", "/snapshot"],
  "command-input-invalid": ["Command input is invalid.", "/command"],
  "context-input-invalid": ["Context input is invalid.", "/context"],
  "snapshot-invalid": ["Snapshot contract is invalid.", "/snapshot"],
  "command-invalid": ["Command contract is invalid.", "/command"],
  "context-invalid": ["Evaluation context contract is invalid.", "/context"],
  "digest-mismatch": [
    "Evaluation context digest binding does not match.",
    "/context",
  ],
  "identity-mismatch": [
    "Command target identity does not match the snapshot.",
    "/command/target",
  ],
  "idempotency-conflict": [
    "Idempotency key is already bound to another command.",
    "/command/idempotencyKey",
  ],
  "revision-conflict": [
    "Expected revision does not match.",
    "/command/expectedRevision",
  ],
  terminal: ["Snapshot is terminal.", "/snapshot/status/terminal"],
  cancelled: ["Snapshot is cancelled.", "/snapshot/status/cancelled"],
  "revision-overflow": [
    "Snapshot revision cannot be incremented safely.",
    "/snapshot/revision",
  ],
  "actor-denied": [
    "Actor role is not permitted for this transition.",
    "/command/actor/role",
  ],
  "publication-binding-invalid": [
    "Publication binding does not match.",
    "/command/payload",
  ],
  "recovery-denied": [
    "Publication recovery is not permitted.",
    "/command/payload",
  ],
  "evidence-required": [
    "Evidence cardinality or kind is not permitted.",
    "/command/evidence",
  ],
  "attempt-limit-exhausted": ["Attempt limit is exhausted.", "/snapshot/usage"],
  "transition-denied": [
    "Transition is not permitted from this state.",
    "/snapshot/phase",
  ],
  "history-full": [
    "Accepted-command history is full.",
    "/snapshot/acceptedCommands",
  ],
  "output-invalid": ["Internal transition construction failed validation.", ""],
};
const enc = new TextEncoder();
function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  return `{${Object.keys(v)
    .sort()
    .map(
      (k) =>
        `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`,
    )
    .join(",")}}`;
}
function hash(domain: string, v: string) {
  return createHash("sha256")
    .update(domain + "\0" + v)
    .digest("hex");
}
function deepFreeze<T>(v: T): Readonly<T> {
  if (v && typeof v === "object" && !Object.isFrozen(v)) {
    for (const x of Object.values(v)) deepFreeze(x);
    Object.freeze(v);
  }
  return v;
}
function isolate(input: unknown): unknown {
  let nodes = 0,
    bytes = 0;
  const ancestors = new Set<object>();
  const walk = (v: unknown, depth: number): unknown => {
    if (depth > 32 || ++nodes > 10000) throw 0;
    if (typeof v === "string") {
      const n = enc.encode(v).length;
      if (n > 4096 || (bytes += n) > 1048576 || v.normalize("NFC") !== v)
        throw 0;
      return v;
    }
    if (v === null || typeof v === "boolean") return v;
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || Object.is(v, -0)) throw 0;
      return v;
    }
    if (typeof v !== "object" || ancestors.has(v)) throw 0;
    ancestors.add(v);
    try {
      const keys = Reflect.ownKeys(v);
      if (keys.some((k) => typeof k !== "string")) throw 0;
      if (Array.isArray(v)) {
        const ld = Object.getOwnPropertyDescriptor(v, "length");
        if (
          !ld ||
          ld.configurable ||
          ld.enumerable ||
          !ld.writable ||
          !("value" in ld) ||
          ld.value > 256
        )
          throw 0;
        const out: unknown[] = [];
        for (const k of keys) {
          bytes += enc.encode(String(k)).length;
          if (k === "length") continue;
          if (!/^(0|[1-9]\d*)$/.test(String(k)) || Number(k) >= ld.value)
            throw 0;
        }
        for (let i = 0; i < ld.value; i++) {
          const d = Object.getOwnPropertyDescriptor(v, String(i));
          if (!d || !("value" in d) || !d.enumerable) throw 0;
          out.push(walk(d.value, depth + 1));
        }
        return out;
      }
      if (
        Object.getPrototypeOf(v) !== Object.prototype &&
        Object.getPrototypeOf(v) !== null
      )
        throw 0;
      if (keys.length > 64) throw 0;
      const out: Record<string, unknown> = {};
      for (const k of keys as string[]) {
        const n = enc.encode(k).length;
        if (n > 4096 || (bytes += n) > 1048576) throw 0;
        const d = Object.getOwnPropertyDescriptor(v, k);
        if (!d || !("value" in d) || !d.enumerable) throw 0;
        out[k] = walk(d.value, depth + 1);
      }
      return out;
    } finally {
      ancestors.delete(v);
    }
  };
  return walk(input, 0);
}
const id = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/,
  sha = /^[0-9a-f]{64}$/,
  git = /^[0-9a-f]{40}$/;
type Dynamic = Record<string, unknown>;
function record(v: unknown): v is Dynamic {
  return !!v && typeof v === "object" && !Array.isArray(v);
}
function validSnapshot(v: unknown): v is ControllerSnapshotV2 {
  if (!validateControllerSnapshotV2(v)) return false;
  if (
    !record(v) ||
    v.contractId !== "spts.controller-snapshot" ||
    v.schemaVersion !== "2.0.0" ||
    !id.test(v.snapshotId) ||
    !Number.isSafeInteger(v.revision) ||
    v.revision < 0 ||
    !record(v.identity) ||
    !record(v.candidate) ||
    !record(v.status) ||
    !record(v.limits) ||
    !record(v.usage) ||
    !Array.isArray(v.acceptedCommands) ||
    v.acceptedCommands.length > 256
  )
    return false;
  if (
    !git.test(v.candidate.commit) ||
    !git.test(v.candidate.tree) ||
    !sha.test(v.authorityDigest) ||
    !sha.test(v.meteringDigest) ||
    !sha.test(v.controllerStateDigest) ||
    (v.revision === 0) !== (v.previousTransitionDigest === null)
  )
    return false;
  return (
    (
      ["implementationAttempts", "verificationRepairs", "ciRepairs"] as const
    ).every(
      (k) =>
        Number.isInteger(v.limits[k]) &&
        v.limits[k] >= 1 &&
        v.limits[k] <= 1e6 &&
        Number.isInteger(v.usage[k]) &&
        v.usage[k] >= 0 &&
        v.usage[k] <= v.limits[k],
    ) &&
    v.acceptedCommands.every(
      (x) =>
        record(x) &&
        typeof x.idempotencyKey === "string" &&
        id.test(x.idempotencyKey) &&
        typeof x.commandDigest === "string" &&
        sha.test(x.commandDigest) &&
        typeof x.transitionDigest === "string" &&
        sha.test(x.transitionDigest),
    )
  );
}
const kinds = [
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
];
function validCommand(v: unknown): v is ControllerCommandV2 {
  return (
    validateControllerCommandV2(v) &&
    record(v) &&
    v.contractId === "spts.controller-command" &&
    v.schemaVersion === "2.0.0" &&
    kinds.includes(v.kind) &&
    id.test(v.commandId) &&
    id.test(v.idempotencyKey) &&
    Number.isSafeInteger(v.expectedRevision) &&
    record(v.actor) &&
    record(v.target) &&
    id.test(v.target.projectId) &&
    git.test(v.target.candidateCommit) &&
    git.test(v.target.candidateTree) &&
    Array.isArray(v.evidence) &&
    v.evidence.length <= 32 &&
    record(v.payload)
  );
}
function validContext(v: unknown): v is ControllerEvaluationContextV2 {
  return (
    validateControllerEvaluationContextV2(v) &&
    record(v) &&
    v.contractId === "spts.controller-evaluation-context" &&
    v.schemaVersion === "2.0.0" &&
    id.test(v.evaluationId) &&
    typeof v.evaluatedAt === "string" &&
    (() => {
      try {
        return new Date(v.evaluatedAt).toISOString() === v.evaluatedAt;
      } catch {
        return false;
      }
    })() &&
    [
      v.snapshotDigest,
      v.authorityDigest,
      v.meteringDigest,
      v.controllerStateDigest,
    ].every((x) => typeof x === "string" && sha.test(x))
  );
}
function base(
  code: ControllerRejectionCodeV2,
  known: Partial<ControllerTransitionV2> = {},
): ControllerTransitionV2 {
  const [message, path] = messages[code];
  const seed = {
    contractId: "spts.controller-transition",
    schemaVersion: "2.0.0",
    disposition: "rejected",
    code,
    proposalId: "",
    proposalDigest: "",
    commandId: null,
    commandDigest: null,
    snapshotId: null,
    snapshotDigest: null,
    fromRevision: null,
    toRevision: null,
    fromPhase: null,
    toPhase: null,
    evaluationId: null,
    evaluatedAt: null,
    target: null,
    priorTransitionDigest: null,
    transitionDigest: null,
    changes: [],
    intents: [],
    diagnostics: [{ code, message, path }],
    proposedNextSnapshot: null,
    executableAuthority: false,
    ...known,
  } as ControllerTransitionV2;
  return finalize(seed);
}
function finalize(result: ControllerTransitionV2): ControllerTransitionV2 {
  const projection = {
    ...result,
    proposalId: undefined,
    proposalDigest: undefined,
    intents: result.intents.map((intent) => {
      const projected: Partial<typeof intent> = { ...intent };
      delete projected.intentId;
      delete projected.proposalDigestBinding;
      return projected;
    }),
  };
  result.proposalDigest = hash(
    "spts.controller-transition-proposal/2.0.0",
    canonical(projection),
  );
  result.proposalId = `proposal-${result.proposalDigest.slice(0, 32)}`;
  return deepFreeze(result);
}
function evidenceOkay(c: ControllerCommandV2) {
  const map: Record<string, string | null> = {
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
  const expected = map[c.kind];
  if (expected === null) return c.evidence.length === 0;
  if (c.evidence.length !== 1) return false;
  let prev = "";
  const ids = new Set<string>();
  return c.evidence.every(
    (e) =>
      e.kind === expected &&
      id.test(e.evidenceId) &&
      sha.test(e.digest) &&
      !ids.has(e.evidenceId) &&
      !!ids.add(e.evidenceId) &&
      e.evidenceId > prev &&
      (prev = e.evidenceId),
  );
}
export function evaluateControllerTransitionV2(
  snapshot: unknown,
  command: unknown,
  context: unknown,
): Readonly<ControllerTransitionV2> {
  let s0, c0, x0;
  try {
    s0 = isolate(snapshot);
  } catch {
    return base("snapshot-input-invalid");
  }
  try {
    c0 = isolate(command);
  } catch {
    return base("command-input-invalid");
  }
  try {
    x0 = isolate(context);
  } catch {
    return base("context-input-invalid");
  }
  if (!validSnapshot(s0)) return base("snapshot-invalid");
  const s = s0;
  if (!validCommand(c0))
    return base("command-invalid", {
      snapshotId: s.snapshotId,
      fromRevision: s.revision,
      fromPhase: s.phase,
    });
  const c = c0;
  const cd = hash("spts.controller-command/2.0.0", canonical(c));
  const sd = hash("spts.controller-snapshot/2.0.0", canonical(s));
  const known = {
    snapshotId: s.snapshotId,
    snapshotDigest: sd,
    fromRevision: s.revision,
    fromPhase: s.phase,
    commandId: c.commandId,
    commandDigest: cd,
    target: c.target,
  };
  if (!validContext(x0)) return base("context-invalid", known);
  const x = x0;
  Object.assign(known, {
    evaluationId: x.evaluationId,
    evaluatedAt: x.evaluatedAt,
  });
  if (
    x.snapshotDigest !== sd ||
    x.authorityDigest !== s.authorityDigest ||
    x.meteringDigest !== s.meteringDigest ||
    x.controllerStateDigest !== s.controllerStateDigest
  )
    return base("digest-mismatch", known);
  if (
    c.target.projectId !== s.identity.projectId ||
    c.target.taskId !== s.identity.taskId ||
    c.target.repositoryId !== s.identity.repositoryId
  )
    return base("identity-mismatch", known);
  const old = s.acceptedCommands.find(
    (a) => a.idempotencyKey === c.idempotencyKey,
  );
  if (old) {
    if (old.commandDigest !== cd) return base("idempotency-conflict", known);
    return duplicate(s, c, x, sd, cd, old.transitionDigest);
  }
  if (c.expectedRevision !== s.revision)
    return base("revision-conflict", known);
  if (s.status.cancelled) return base("cancelled", known);
  if (s.status.terminal) return base("terminal", known);
  if (s.revision === Number.MAX_SAFE_INTEGER)
    return base("revision-overflow", known);
  const row = selectRow(s, c);
  if (row?.actor && !row.actor.includes(c.actor.role))
    return base("actor-denied", known);
  const publicationError = publicationBindingError(s, c);
  if (publicationError) return base(publicationError, known);
  if (!evidenceOkay(c)) return base("evidence-required", known);
  if (row?.capacity && !row.capacity())
    return base("attempt-limit-exhausted", known);
  if (
    !row ||
    (c.target.candidateCommit !== s.candidate.commit &&
      c.kind !== "submit-review") ||
    (c.target.candidateTree !== s.candidate.tree && c.kind !== "submit-review")
  )
    return base("transition-denied", known);
  if (s.acceptedCommands.length === 256) return base("history-full", known);
  return propose(s, c, x, sd, cd, row.apply);
}
type MutableSnapshot = ControllerSnapshotV2 & Dynamic;
type DynamicList = Dynamic[];
type Apply = (
  n: MutableSnapshot,
  changes: DynamicList,
  intents: DynamicList,
) => void;
function publicationBindingError(
  s: ControllerSnapshotV2,
  c: ControllerCommandV2,
): "publication-binding-invalid" | "recovery-denied" | null {
  if (
    ![
      "record-publication-unknown",
      "record-publication-succeeded",
      "recover-reconcile-publication",
    ].includes(c.kind)
  )
    return null;
  const publication = s.status.publication;
  const payload = c.payload as {
    publicationId: string;
    publicationIntentId: string;
    publicationIntentDigest: string;
    priorUnknownObservationDigest: string | null;
  };
  if (
    publication.state === "not-requested" ||
    payload.publicationIntentId !== publication.publicationIntentId ||
    payload.publicationIntentDigest !== publication.publicationIntentDigest ||
    (publication.publicationId !== null &&
      payload.publicationId !== publication.publicationId)
  )
    return "publication-binding-invalid";
  if (c.kind === "recover-reconcile-publication") {
    if (
      publication.state !== "outcome-unknown" ||
      payload.priorUnknownObservationDigest !==
        publication.unknownObservationDigest
    )
      return "recovery-denied";
  } else if (
    payload.priorUnknownObservationDigest !==
    publication.unknownObservationDigest
  )
    return "publication-binding-invalid";
  return null;
}
function selectRow(
  s: ControllerSnapshotV2,
  c: ControllerCommandV2,
): { actor: string[]; capacity?: () => boolean; apply: Apply } | null {
  const k = `${s.phase}:${c.kind}`;
  const simple = (actor: string[], apply: Apply, capacity?: () => boolean) => ({
    actor,
    apply,
    capacity,
  });
  switch (k) {
    case "ready:begin-implementation":
      return simple(
        ["principal-developer"],
        (n, ch, i) => {
          setUsage(n, ch, "implementationAttempts");
          set(n, ch, "phase", "implementation");
          i.push(
            {
              kind: "run-implementation",
              payload: {
                kind: "run-implementation",
                mode: "implementation",
                repairSource: null,
              },
            },
            {
              kind: "update-paca",
              payload: {
                kind: "update-paca",
                fromPhase: "ready",
                toPhase: "implementation",
              },
            },
          );
        },
        () => s.usage.implementationAttempts < s.limits.implementationAttempts,
      );
    case "implementation:submit-review":
      return simple(["principal-developer"], (n, ch, i) => {
        set(
          n,
          ch,
          "candidate",
          { commit: c.target.candidateCommit, tree: c.target.candidateTree },
          "candidate-set",
        );
        set(n, ch, "verification", "unverified");
        set(n, ch, "ci", "not-started");
        set(n, ch, "publication", {
          state: "not-requested",
          publicationId: null,
          publicationIntentId: null,
          publicationIntentDigest: null,
          unknownObservationDigest: null,
        });
        set(n, ch, "repairSource", null);
        set(n, ch, "phase", "internal-review");
        set(n, ch, "activeRole", "flow");
        i.push({
          kind: "update-paca",
          payload: {
            kind: "update-paca",
            fromPhase: "implementation",
            toPhase: "internal-review",
          },
        });
      });
    case "internal-review:request-verification":
      return simple(["flow"], (n, ch, i) => {
        set(n, ch, "phase", "independent-verification");
        set(n, ch, "activeRole", "independent-verifier");
        i.push(
          {
            kind: "run-independent-verification",
            payload: { kind: "run-independent-verification" },
          },
          {
            kind: "update-paca",
            payload: {
              kind: "update-paca",
              fromPhase: "internal-review",
              toPhase: "independent-verification",
            },
          },
        );
      });
    case "independent-verification:record-verification-approved":
      return simple(["independent-verifier"], (n, ch, i) => {
        set(n, ch, "verification", "approved");
        set(n, ch, "phase", "publication");
        set(n, ch, "activeRole", "flow");
        i.push({
          kind: "update-paca",
          payload: {
            kind: "update-paca",
            fromPhase: "independent-verification",
            toPhase: "publication",
          },
        });
      });
    case "independent-verification:record-verification-rejected":
      return simple(
        ["independent-verifier"],
        (n, ch, i) => {
          set(n, ch, "verification", "rejected");
          set(n, ch, "repairSource", "verification");
          set(n, ch, "phase", "repair-required");
          set(n, ch, "activeRole", "principal-developer");
          i.push({
            kind: "update-paca",
            payload: {
              kind: "update-paca",
              fromPhase: "independent-verification",
              toPhase: "repair-required",
            },
          });
        },
        () => s.usage.verificationRepairs < s.limits.verificationRepairs,
      );
    case "repair-required:begin-repair": {
      const src = s.status.repairSource;
      const counter = src === "ci" ? "ciRepairs" : "verificationRepairs";
      return simple(
        ["principal-developer"],
        (n, ch, i) => {
          setUsage(n, ch, counter);
          set(n, ch, "repairSource", null);
          set(n, ch, "phase", "implementation");
          i.push(
            {
              kind: "run-implementation",
              payload: {
                kind: "run-implementation",
                mode: "repair",
                repairSource: src,
              },
            },
            {
              kind: "update-paca",
              payload: {
                kind: "update-paca",
                fromPhase: "repair-required",
                toPhase: "implementation",
              },
            },
          );
        },
        () => s.usage[counter] < s.limits[counter],
      );
    }
    case "publication:authorize-publication":
      if (s.status.publication.state !== "not-requested") return null;
      return simple(["flow"], (n, ch, i) => {
        const iid = `publication-intent-${hash("spts.publication-intent-id/2.0.0", hash("spts.controller-command/2.0.0", canonical(c))).slice(0, 32)}`;
        const dig = hash(
          "spts.publication-intent/2.0.0",
          canonical({
            domain: "spts.publication-intent/2.0.0",
            projectId: c.target.projectId,
            taskId: c.target.taskId,
            repositoryId: c.target.repositoryId,
            candidateCommit: c.target.candidateCommit,
            candidateTree: c.target.candidateTree,
            commandId: c.commandId,
            commandDigest: hash("spts.controller-command/2.0.0", canonical(c)),
            publicationIntentId: iid,
            intentKind: "publish-candidate",
            evidence: c.evidence,
          }),
        );
        set(n, ch, "publication", {
          state: "intent-committed",
          publicationId: null,
          publicationIntentId: iid,
          publicationIntentDigest: dig,
          unknownObservationDigest: null,
        });
        i.push({
          kind: "publish-candidate",
          payload: {
            kind: "publish-candidate",
            publicationIntentId: iid,
            publicationIntentDigest: dig,
          },
        });
      });
    case "publication:record-publication-unknown":
      if (s.status.publication.state !== "intent-committed") return null;
      return simple(["flow"], (n, ch) => {
        const payload = c.payload as { publicationId: string };
        set(n, ch, "publication", {
          ...s.status.publication,
          state: "outcome-unknown",
          publicationId: payload.publicationId,
          unknownObservationDigest: c.evidence[0]!.digest,
        });
      });
    case "publication:record-publication-succeeded":
      if (
        !["intent-committed", "outcome-unknown"].includes(
          s.status.publication.state,
        )
      )
        return null;
      return simple(["flow"], (n, ch, i) => {
        const payload = c.payload as { publicationId: string };
        set(n, ch, "publication", {
          ...s.status.publication,
          state: "succeeded",
          publicationId: payload.publicationId,
          unknownObservationDigest: null,
        });
        set(n, ch, "ci", "pending");
        set(n, ch, "phase", "pr-ci-monitoring");
        i.push(
          {
            kind: "monitor-ci",
            payload: {
              kind: "monitor-ci",
              publicationId: payload.publicationId,
            },
          },
          {
            kind: "update-paca",
            payload: {
              kind: "update-paca",
              fromPhase: "publication",
              toPhase: "pr-ci-monitoring",
            },
          },
        );
      });
    case "publication:recover-reconcile-publication":
      if (s.status.publication.state !== "outcome-unknown") return null;
      return simple(["flow"], (_n, _ch, i) => {
        const p = s.status.publication;
        i.push({
          kind: "reconcile-publication",
          payload: {
            kind: "reconcile-publication",
            publicationId: p.publicationId,
            publicationIntentId: p.publicationIntentId,
            publicationIntentDigest: p.publicationIntentDigest,
            priorUnknownObservationDigest: p.unknownObservationDigest,
          },
        });
      });
    case "pr-ci-monitoring:record-ci-passed":
      return simple(["flow"], (n, ch, i) => {
        set(n, ch, "ci", "passed");
        set(n, ch, "phase", "merge-gate");
        set(n, ch, "activeRole", "product");
        i.push({
          kind: "update-paca",
          payload: {
            kind: "update-paca",
            fromPhase: "pr-ci-monitoring",
            toPhase: "merge-gate",
          },
        });
      });
    case "pr-ci-monitoring:record-ci-failed":
      return simple(
        ["flow"],
        (n, ch, i) => {
          set(n, ch, "ci", "failed");
          set(n, ch, "repairSource", "ci");
          set(n, ch, "phase", "repair-required");
          set(n, ch, "activeRole", "principal-developer");
          i.push({
            kind: "update-paca",
            payload: {
              kind: "update-paca",
              fromPhase: "pr-ci-monitoring",
              toPhase: "repair-required",
            },
          });
        },
        () => s.usage.ciRepairs < s.limits.ciRepairs,
      );
    case "merge-gate:request-merge":
      return simple(["product"], (_n, _ch, i) =>
        i.push({
          kind: "merge-candidate",
          payload: {
            kind: "merge-candidate",
            publicationId: s.status.publication.publicationId,
          },
        }),
      );
    case "merge-gate:record-merged":
      return simple(["flow"], (n, ch, i) => {
        set(n, ch, "merged", true);
        set(n, ch, "terminal", true);
        set(n, ch, "phase", "completed");
        i.push({
          kind: "update-paca",
          payload: {
            kind: "update-paca",
            fromPhase: "merge-gate",
            toPhase: "completed",
          },
        });
      });
    default:
      if (c.kind === "cancel")
        return simple(["product", "flow"], (n, ch, i) => {
          set(n, ch, "cancelled", true);
          set(n, ch, "terminal", true);
          set(n, ch, "repairSource", null);
          set(n, ch, "phase", "cancelled");
          set(n, ch, "activeRole", "product");
          i.push({
            kind: "update-paca",
            payload: {
              kind: "update-paca",
              fromPhase: s.phase,
              toPhase: "cancelled",
            },
          });
        });
      return null;
  }
}
function set(
  n: MutableSnapshot,
  ch: DynamicList,
  key: string,
  to: unknown,
  kind?: string,
) {
  let owner = n.status as unknown as Dynamic,
    from = owner[key];
  if (key === "phase" || key === "activeRole" || key === "candidate") {
    owner = n as Dynamic;
    from = n[key];
  }
  if (canonical(from) === canonical(to)) return;
  ch.push({
    kind: kind ?? `${key.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`)}-set`,
    from,
    to,
  });
  owner[key] = to;
}
function setUsage(
  n: MutableSnapshot,
  ch: DynamicList,
  counter: "implementationAttempts" | "verificationRepairs" | "ciRepairs",
) {
  const from = n.usage[counter];
  ch.push({ kind: "usage-set", counter, from, to: from + 1 });
  n.usage[counter]++;
}
function duplicate(
  s: ControllerSnapshotV2,
  c: ControllerCommandV2,
  x: ControllerEvaluationContextV2,
  sd: string,
  cd: string,
  td: string,
) {
  const r = structuredClone(base("output-invalid")) as ControllerTransitionV2;
  Object.assign(r, {
    disposition: "duplicate",
    code: "duplicate-command",
    commandId: c.commandId,
    commandDigest: cd,
    snapshotId: s.snapshotId,
    snapshotDigest: sd,
    fromRevision: s.revision,
    toRevision: s.revision,
    fromPhase: s.phase,
    toPhase: s.phase,
    evaluationId: x.evaluationId,
    evaluatedAt: x.evaluatedAt,
    target: c.target,
    priorTransitionDigest: td,
    transitionDigest: td,
    diagnostics: [],
  });
  return finalize(r);
}
function propose(
  s: ControllerSnapshotV2,
  c: ControllerCommandV2,
  x: ControllerEvaluationContextV2,
  sd: string,
  cd: string,
  apply: Apply,
) {
  const n = structuredClone(s) as MutableSnapshot,
    changes: DynamicList = [],
    unsigned: DynamicList = [];
  apply(n, changes, unsigned);
  const delta = {
    fromPhase: s.phase,
    toPhase: n.phase,
    target: c.target,
    stateChanges: changes,
    unsignedIntents: unsigned.map((z) => ({
      ...z,
      commandDigest: cd,
      target: c.target,
      executableAuthority: false,
    })),
  };
  const td = hash(
    "spts.controller-transition-chain/2.0.0",
    `${s.previousTransitionDigest ?? "0".repeat(64)}\0${cd}\0${s.revision}\0${s.revision + 1}\0${canonical(delta)}`,
  );
  const accepted = {
    idempotencyKey: c.idempotencyKey,
    commandDigest: cd,
    transitionDigest: td,
  };
  changes.unshift(
    { kind: "accepted-command-added", value: accepted },
    { kind: "revision-set", from: s.revision, to: s.revision + 1 },
    {
      kind: "previous-transition-digest-set",
      from: s.previousTransitionDigest,
      to: td,
    },
  );
  n.acceptedCommands = [...n.acceptedCommands, accepted].sort((a, b) =>
    a.idempotencyKey < b.idempotencyKey ? -1 : 1,
  );
  n.revision++;
  n.previousTransitionDigest = td;
  const r: Dynamic = {
    contractId: "spts.controller-transition",
    schemaVersion: "2.0.0",
    disposition: "proposed",
    code: "transition-proposed",
    proposalId: "",
    proposalDigest: "",
    commandId: c.commandId,
    commandDigest: cd,
    snapshotId: s.snapshotId,
    snapshotDigest: sd,
    fromRevision: s.revision,
    toRevision: n.revision,
    fromPhase: s.phase,
    toPhase: n.phase,
    evaluationId: x.evaluationId,
    evaluatedAt: x.evaluatedAt,
    target: c.target,
    priorTransitionDigest: s.previousTransitionDigest,
    transitionDigest: td,
    changes,
    intents: unsigned.map((z) => ({
      ...z,
      intentId: "",
      commandDigest: cd,
      proposalDigestBinding: "",
      target: c.target,
      executableAuthority: false,
    })),
    diagnostics: [],
    proposedNextSnapshot: n,
    executableAuthority: false,
  };
  const projection = {
    ...r,
    proposalId: undefined,
    proposalDigest: undefined,
    intents: (r.intents as DynamicList).map((intent) => {
      const projected = { ...intent };
      delete projected.intentId;
      delete projected.proposalDigestBinding;
      return projected;
    }),
  };
  const proposalDigest = hash(
    "spts.controller-transition-proposal/2.0.0",
    canonical(projection),
  );
  r.proposalDigest = proposalDigest;
  r.proposalId = `proposal-${proposalDigest.slice(0, 32)}`;
  (r.intents as DynamicList).forEach((z, i) => {
    z.intentId = `intent-${hash("spts.controller-intent/2.0.0", `${r.proposalDigest}\0${String(i).padStart(4, "0")}\0${z.kind}`).slice(0, 32)}`;
    z.proposalDigestBinding = r.proposalDigest;
  });
  return deepFreeze(r) as unknown as Readonly<ControllerTransitionV2>;
}

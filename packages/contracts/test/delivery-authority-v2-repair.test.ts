import { describe, expect, it } from "vitest";
import {
  authorizeBootstrapRead,
  computeDeliveryAuthorityBootstrapDigest,
  evaluateDeliveryEffectV2,
  evaluateDeliveryRecoveryV2,
  evaluateDeliveryTransitionV2,
  validateDeliveryAuthorityBootstrap,
  validateDeliveryCiEvidenceV2,
  validateDeliveryVerifierVerdictsV2,
  type DeliveryIdentityV2,
} from "../src/index.js";
import { identity, v2 } from "./delivery-authority-v2.test.js";

const trustedContract = {
  authorityDigest: v2.authorityDigest,
  meteringDigest: v2.meteringDigest,
  controllerStateDigest: v2.controllerStateDigest,
  identity,
};
const candidate = {
  commit: identity.candidateCommit,
  tree: identity.candidateTree,
};
const currentController = {
  ...identity,
  role: "controller",
  access: "controller",
  actorId: "controller",
  executionId: "controller-exec",
  workspaceId: "controller-work",
} satisfies DeliveryIdentityV2;
const currentIdentity = { delivery: identity, controller: currentController };
const verifierIdentity = {
  ...identity,
  role: "independent-verifier",
  access: "read-only",
  actorId: "verifier",
  executionId: "verify-exec",
  workspaceId: "verify-work",
} satisfies DeliveryIdentityV2;
const trustedVerifier = {
  currentIdentity,
  identity: verifierIdentity,
  candidate,
  controllerRevision: 4,
  observedAt: "2026-08-29T01:00:00.000Z",
  freshThroughEventId: "verify-boundary",
  evidenceIds: ["specification-check", "quality-check"],
};
const verdict = (axis: "specification" | "quality") => ({
  axis,
  verdict: "APPROVE",
  currentIdentity,
  identity: verifierIdentity,
  candidate,
  controllerRevision: 4,
  observedAt: "2026-08-29T01:00:00.000Z",
  freshThroughEventId: "verify-boundary",
  evidenceIds: [`${axis}-check`],
});
const verdicts = {
  specification: verdict("specification"),
  quality: verdict("quality"),
};
const ci = {
  currentIdentity,
  repositoryId: "repo",
  projectId: "SPTS",
  taskId: "SPTS-10",
  runId: "run",
  pullRequest: 10,
  baseBranch: "main",
  headBranch: identity.headBranch,
  candidate,
  workflowId: "quality",
  checkId: "quality",
  ciRunId: "ci-run",
  attempt: 2,
  conclusion: "success",
  observedAt: "2026-08-29T01:10:00.000Z",
  freshThroughEventId: "ci-boundary",
  requiredCheckPolicyDigest: "e".repeat(64),
  fresh: true,
};
const trustedCi = { ...ci };
const effect = {
  kind: "poll-ci",
  identity: {
    ...identity,
    role: "flow",
    access: "orchestrate",
  } as DeliveryIdentityV2,
  idempotencyKey: "poll",
  requestDigest: "a".repeat(64),
  preconditionDigest: "b".repeat(64),
  postconditionDigest: "c".repeat(64),
  remainingBudget: 1,
};
const controller = currentController;

describe("review repair boundaries", () => {
  it("requires separately trusted verifier identity and rejects mismatch or self assertion", () => {
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, trustedVerifier).valid,
    ).toBe(true);
    expect(
      validateDeliveryVerifierVerdictsV2(verdicts, {
        ...trustedVerifier,
        identity: { ...verifierIdentity, actorId: "other" },
      }).valid,
    ).toBe(false);
    expect(
      validateDeliveryVerifierVerdictsV2(
        {
          ...verdicts,
          quality: {
            ...verdicts.quality,
            identity: { ...verifierIdentity, executionId: "other" },
          },
        },
        trustedVerifier,
      ).valid,
    ).toBe(false);
  });
  it("rejects substituted and stale CI against separately trusted provenance", () => {
    expect(validateDeliveryCiEvidenceV2(ci, trustedCi).valid).toBe(true);
    expect(
      validateDeliveryCiEvidenceV2({ ...ci, ciRunId: "substitute" }, trustedCi)
        .valid,
    ).toBe(false);
    expect(
      validateDeliveryCiEvidenceV2({ ...ci, fresh: false }, trustedCi).valid,
    ).toBe(false);
  });
  it("enforces state/effect roles and returns non-executable replay", () => {
    expect(evaluateDeliveryEffectV2(v2, effect, trustedContract, []).code).toBe(
      "effect-state-denied",
    );
    const principalIdentity = {
      ...identity,
      role: "principal-developer",
      access: "read-write",
    } as DeliveryIdentityV2;
    const implementation = {
      ...v2,
      state: "implementation" as const,
      identity: principalIdentity,
    };
    const principalTrusted = {
      ...trustedContract,
      identity: principalIdentity,
    };
    const merge = { ...effect, kind: "merge", identity: principalIdentity };
    expect(
      evaluateDeliveryEffectV2(implementation, merge, principalTrusted, [])
        .allowed,
    ).toBe(false);
    const request = { ...effect, kind: "test", identity: principalIdentity };
    const replay = evaluateDeliveryEffectV2(
      implementation,
      request,
      principalTrusted,
      [
        {
          idempotencyKey: request.idempotencyKey,
          requestDigest: request.requestDigest,
          outcome: "accepted",
          postcondition: "applied",
        },
      ],
    );
    expect(replay).toMatchObject({
      allowed: false,
      code: "idempotent-replay",
      executable: false,
    });
    expect(
      evaluateDeliveryEffectV2(implementation, request, principalTrusted, [
        {
          idempotencyKey: request.idempotencyKey,
          requestDigest: request.requestDigest,
          outcome: "unknown",
          postcondition: "unknown",
        },
      ]),
    ).toMatchObject({ allowed: false, code: "reconciliation-required" });
  });
  it("supports blocked/cancellation transitions and prevents metering bypass", () => {
    expect(
      evaluateDeliveryTransitionV2(
        { ...v2, state: "implementation" },
        {
          from: "implementation",
          to: "blocked",
          identity: {
            ...identity,
            role: "flow",
            access: "orchestrate",
          } as DeliveryIdentityV2,
          idempotencyKey: "block",
        },
        trustedContract,
      ).accepted,
    ).toBe(true);
    expect(
      evaluateDeliveryTransitionV2(
        { ...v2, state: "implementation" },
        {
          from: "implementation",
          to: "cancelling",
          identity: {
            ...identity,
            role: "flow",
            access: "orchestrate",
          } as DeliveryIdentityV2,
          idempotencyKey: "cancel",
        },
        trustedContract,
      ).accepted,
    ).toBe(true);
    expect(
      evaluateDeliveryTransitionV2(
        { ...v2, state: "cancelling", cancelled: true },
        {
          from: "cancelling",
          to: "cancelled",
          identity: {
            ...identity,
            role: "flow",
            access: "orchestrate",
          } as DeliveryIdentityV2,
          idempotencyKey: "cancelled",
        },
        trustedContract,
      ).accepted,
    ).toBe(true);
    expect(
      evaluateDeliveryEffectV2(
        {
          ...v2,
          state: "implementation",
          usage: { ...v2.usage, concurrentAgents: 2 },
        },
        {
          ...effect,
          kind: "launch-principal",
          identity: {
            ...identity,
            role: "flow",
            access: "orchestrate",
          } as DeliveryIdentityV2,
        },
        trustedContract,
        [],
      ).code,
    ).toBe("autonomy-exhausted");
  });
  it("enforces per-kind recovery state, identity, boundary, resume and replay", () => {
    const contract = { ...v2, state: "blocked" as const };
    const request = {
      kind: "disappeared-verifier",
      identity: controller,
      idempotencyKey: "recover",
      boundaryId: "boundary",
      boundaryConsumed: false,
      identityRevalidated: true,
      immutableIdentity: identity,
      worktreeClean: true,
      evidenceIds: [
        "authoritative-absence",
        "exact-candidate",
        "isolated-verifier-workspace",
      ],
      staleEvidenceIds: [],
      remainingAttempts: 1,
      requestedResumeState: "independent-verification",
    };
    const recoveryBoundary = {
      boundaryId: request.boundaryId,
      idempotencyKey: request.idempotencyKey,
      kind: request.kind,
      suspendedState: "independent-verification" as const,
      candidate,
      controllerRevision: 4,
      consumed: false,
      identity: request.immutableIdentity,
      controllerIdentity: controller,
    };
    const recoveryTrusted = {
      ...trustedContract,
      recoveryBoundary,
      currentCandidate: candidate,
      controllerRevision: 4,
    };
    expect(
      evaluateDeliveryRecoveryV2(contract, request, recoveryTrusted),
    ).toMatchObject({
      allowed: true,
      resumeState: "independent-verification",
      clearVerifierApproval: true,
    });
    expect(
      evaluateDeliveryRecoveryV2(
        contract,
        { ...request, boundaryConsumed: true },
        recoveryTrusted,
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDeliveryRecoveryV2(
        contract,
        {
          ...request,
          immutableIdentity: { ...identity, workspaceId: "other" },
        },
        recoveryTrusted,
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDeliveryRecoveryV2(
        contract,
        { ...request, requestedResumeState: "publication-authorized" },
        recoveryTrusted,
      ).allowed,
    ).toBe(false);
  });
  it("contains hostile objects and rejects credential-shaped strings at public boundaries", () => {
    const hostile = Object.defineProperty({}, "contractId", {
      get() {
        throw new Error("attacker detail");
      },
    });
    const proxy = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("attacker detail");
        },
      },
    );
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const call of [
      () => validateDeliveryAuthorityBootstrap(hostile),
      () => validateDeliveryVerifierVerdictsV2(proxy, trustedVerifier),
      () => validateDeliveryCiEvidenceV2(cycle, trustedCi),
      () =>
        evaluateDeliveryTransitionV2(
          hostile,
          {
            from: "ready",
            to: "implementation",
            identity,
            idempotencyKey: "x",
          },
          trustedContract,
        ),
      () =>
        evaluateDeliveryEffectV2(
          v2,
          {
            ...effect,
            identity: {
              ...effect.identity,
              actorId: "Bearer abcdefghijklmnopqrstuvwxyz123456",
            },
          },
          trustedContract,
          [],
        ),
      () => evaluateDeliveryRecoveryV2(v2, hostile as never, trustedContract),
    ])
      expect(() => call()).not.toThrow();
    expect(
      evaluateDeliveryEffectV2(
        v2,
        {
          ...effect,
          identity: {
            ...effect.identity,
            actorId: "Bearer abcdefghijklmnopqrstuvwxyz123456",
          },
        },
        trustedContract,
        [],
      ).allowed,
    ).toBe(false);
  });
  it("accepts canonical IPv6 loopback and expires exactly at expiresAt", () => {
    const bootstrap = {
      contractId: "spts.delivery-authority-bootstrap",
      contractVersion: "1.0.0",
      projectId: "SPTS",
      taskId: "SPTS-10",
      authorityAnchor: "a".repeat(64),
      origin: "http://[::1]:4815",
      taskPath: "/task",
      anchorPath: "/anchor",
      notBefore: "2026-08-29T00:00:00.000Z",
      expiresAt: "2026-08-29T01:00:00.000Z",
    };
    const valid = validateDeliveryAuthorityBootstrap(bootstrap);
    expect(valid.valid).toBe(true);
    if (!valid.valid) return;
    const digest = computeDeliveryAuthorityBootstrapDigest(valid.value);
    expect(
      authorizeBootstrapRead(
        valid.value,
        { method: "GET", url: "http://[::1]:4815/task", redirect: false },
        digest,
        "2026-08-29T00:59:59.999Z",
      ).allowed,
    ).toBe(true);
    expect(
      authorizeBootstrapRead(
        valid.value,
        { method: "GET", url: "http://[::1]:4815/task", redirect: false },
        digest,
        bootstrap.expiresAt,
      ).code,
    ).toBe("stale-authority");
  });
});

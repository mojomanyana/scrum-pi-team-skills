/* eslint-disable @typescript-eslint/no-explicit-any -- mutation fixtures intentionally cross type boundaries */
import { describe, expect, it, vi } from "vitest";
vi.mock(
  "@scrum-pi-team-skills/contracts",
  async () => import("../../contracts/src/index.js"),
);
import raw from "../../contracts/examples/flow-task-packet.principal-developer.json" with { type: "json" };
import {
  AGENT_ROLE_PROFILES_V2,
  digestAgentExecutionManifestV2,
  digestFlowTaskPacket,
  sha256,
} from "../../contracts/src/index.js";
import {
  __testOnlyCreateLaunchPlanV2Preview,
  createPiLaunchPlanV2,
  digestTrustedConcreteLaunchDecisionV2,
  digestTrustedLaunchPolicyV2,
  digestTrustedToolProfileV2,
} from "../src/launch-plan-v2.js";
const ordered = (value: any): any => {
  if (Array.isArray(value)) return value.map(ordered);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      .map((key) => [key, ordered(value[key])]),
  );
};
const signed = (x: any, key: string, digest: (v: any) => any) => {
  const y = structuredClone(x);
  delete y[key];
  const r = digest(y);
  if (!r.valid) throw 0;
  return ordered({ ...y, [key]: r.value });
};
const packet = signed(raw, "packetDigest", digestFlowTaskPacket);
const profile = AGENT_ROLE_PROFILES_V2["principal-developer"];
const manifest = signed(
  {
    contractId: "spts.agent-execution-manifest",
    schemaVersion: "2.0.0",
    manifestId: "manifest-principal",
    packet,
    role: packet.subject.role,
    actorId: packet.subject.actorId,
    executionId: packet.subject.executionId,
    workspaceId: packet.subject.workspaceId,
    access: packet.subject.access,
    resources: packet.work.resources,
    toolProfileId: profile.toolProfileId,
    workspaceProfileId: profile.workspaceProfileId,
    tools: [...profile.tools],
    resultProtocol: {
      toolName: "flow_submit_result",
      contractId: "spts.agent-structured-result",
      schemaVersion: "2.0.0",
      minimum: 1,
      maximum: 1,
    },
  },
  "manifestDigest",
  digestAgentExecutionManifestV2,
);
const identity = {
  projectId: packet.task.projectId,
  taskId: packet.task.taskId,
  repositoryId: packet.repository.repositoryId,
  runId: packet.run.runId,
  baseBranch: packet.repository.baseBranch,
  baseCommit: packet.repository.baseCommit,
  baseTree: packet.repository.baseTree,
  headBranch: packet.repository.headBranch,
  candidateCommit: packet.repository.candidateCommit,
  candidateTree: packet.repository.candidateTree,
  role: packet.subject.role,
  actorId: packet.subject.actorId,
  executionId: packet.subject.executionId,
  workspaceId: packet.subject.workspaceId,
  access: packet.subject.access,
};
const H = "e".repeat(64);
const profileDigests = Object.fromEntries(
  Object.entries(AGENT_ROLE_PROFILES_V2).map(([role, p]) => {
    const r = digestTrustedToolProfileV2(p);
    if (!r.valid) throw 0;
    return [role, r.value];
  }),
);
const profileDigest = profileDigests["principal-developer"]!;
const policy = ordered({
  policyId: "policy-v2",
  piExecutable: "/trusted/pi",
  extensions: [
    { identity: "spts.pi-daddy-grants", path: "/trusted/grants.ts", digest: H },
    {
      identity: "spts.flow-submit-result",
      path: "/trusted/result.ts",
      digest: H,
    },
  ],
  skills: { "skill-build": "/trusted/build.md" },
  promptTemplates: { "prompt-build": "/trusted/build-prompt.md" },
  systemPrompt: "/trusted/system.md",
  appendSystemPrompt: "/trusted/append.md",
  packetInstruction: "Perform only the packet work.",
  roles: Object.fromEntries(
    Object.entries(AGENT_ROLE_PROFILES_V2).map(([role, p]) => [
      role,
      {
        ...p,
        tools: [...p.tools],
        profileDigest: profileDigests[role],
      },
    ]),
  ),
});
const policyDigestResult = digestTrustedLaunchPolicyV2(policy);
if (!policyDigestResult.valid) throw 0;
const policyDigest = policyDigestResult.value;
const resultExtensionDigest = sha256(policy.extensions[1], "__none__");
const decision = signed(
  {
    decisionId: "decision-1",
    controllerRevision: 1,
    controllerStateDigest: packet.controllerStateDigest,
    effect: {
      kind: "real-pi-execution",
      slice1EffectKind: "launch-principal",
      requestDigest: H,
      outcome: "allowed",
    },
    identity,
    executionMode: "run",
    grantReference: {
      kind: "single-use",
      referenceId: "grant-1",
      referenceDigest: H,
    },
    packetDigest: packet.packetDigest,
    manifestDigest: manifest.manifestDigest,
    launchPolicyId: policy.policyId,
    launchPolicyDigest: policyDigest,
    toolProfileId: profile.toolProfileId,
    toolProfileDigest: profileDigest,
    resultExtensionPolicyId: "spts.flow-submit-result",
    resultExtensionPolicyDigest: resultExtensionDigest,
    isolationAttestationId: "isolation-1",
    isolationAttestationDigest: H,
    attempt: 1,
    idempotencyKey: "attempt-1",
    issuedAt: "2026-08-30T23:00:00.000Z",
    notBefore: "2026-08-30T23:00:00.000Z",
    expiresAt: "2026-08-31T00:00:00.000Z",
    observedAt: "2026-08-30T23:30:00.000Z",
    outcome: "allowed",
  },
  "decisionDigest",
  digestTrustedConcreteLaunchDecisionV2,
);
const trusted = ordered({
  expectedControllerDecisionDigest: decision.decisionDigest,
  expectedControllerStateDigest: decision.controllerStateDigest,
  expectedCurrentDeliveryIdentity: identity,
  expectedLaunchPolicyDigest: policyDigest,
  expectedToolProfileDigest: profileDigest,
  expectedIsolationAttestationDigest: H,
  trustedObservedAt: decision.observedAt,
  source: "controlled-test" as const,
});
describe("launch plan v2", () => {
  it("fails closed for the unavailable authenticated controller/store source", () => {
    const authenticated = ordered({
      ...trusted,
      source: "authenticated-controller-store",
    });
    expect(
      __testOnlyCreateLaunchPlanV2Preview(
        manifest,
        decision,
        authenticated,
        policy,
      ),
    ).toMatchObject({
      valid: false,
      errors: [{ code: "production-authorization-unavailable" }],
    });
  });
  it("builds deterministic explicit argv without executable authority", () => {
    const r = __testOnlyCreateLaunchPlanV2Preview(
      manifest,
      decision,
      trusted,
      policy,
    );
    expect(r.valid).toBe(true);
    if (!r.valid) return;
    expect(r.value.arguments).toEqual(
      expect.arrayContaining([
        "--no-extensions",
        "--no-session",
        "--no-context-files",
        "--extension",
        "/trusted/grants.ts",
      ]),
    );
    expect(r.value.arguments.join(" ")).toContain("flow_submit_result");
    expect(r.value).not.toHaveProperty("executable");
    expect(r.value).not.toHaveProperty("environment");
    expect(Object.isFrozen(r.value.arguments)).toBe(true);
  });
  it.each([
    ["controller digest", { expectedControllerDecisionDigest: H }],
    ["state", { expectedControllerStateDigest: H }],
    [
      "identity",
      {
        expectedCurrentDeliveryIdentity: {
          ...trusted.expectedCurrentDeliveryIdentity,
          baseTree: "a".repeat(40),
        },
      },
    ],
    ["policy", { expectedLaunchPolicyDigest: "a".repeat(64) }],
    ["tool profile", { expectedToolProfileDigest: H }],
    ["isolation", { expectedIsolationAttestationDigest: "a".repeat(64) }],
    ["time", { trustedObservedAt: "2026-08-30T23:31:00.000Z" }],
  ])("rejects independently trusted %s mismatch", (_n, change) =>
    expect(
      __testOnlyCreateLaunchPlanV2Preview(
        manifest,
        decision,
        { ...trusted, ...change },
        policy,
      ),
    ).toMatchObject({ valid: false, errors: [{ code: "trusted-provenance" }] }),
  );
  it.each([
    ["project id", "projectId", "bad id!"],
    ["task id", "taskId", "bad id!"],
    ["repository id", "repositoryId", "bad id!"],
    ["run id", "runId", "bad id!"],
    ["actor id", "actorId", "bad id!"],
    ["execution id", "executionId", "bad id!"],
    ["workspace id", "workspaceId", "bad id!"],
    ["base commit", "baseCommit", "a".repeat(39)],
    ["base tree", "baseTree", "A".repeat(40)],
    ["candidate commit", "candidateCommit", "a".repeat(64)],
    ["candidate tree", "candidateTree", "not-a-sha1"],
    ["base branch", "baseBranch", "feature..hidden"],
    ["head branch", "headBranch", "feature@{hidden"],
    ["closed role", "role", "stakeholder"],
    ["role/access mapping", "access", "read-only"],
  ])(
    "rejects malformed identity table mutation: %s before provenance",
    (_n, key, value) => {
      const badIdentity = { ...identity, [key]: value };
      const badDecision = signed(
        { ...decision, identity: badIdentity },
        "decisionDigest",
        digestTrustedConcreteLaunchDecisionV2,
      );
      expect(
        __testOnlyCreateLaunchPlanV2Preview(
          manifest,
          badDecision,
          trusted,
          policy,
        ),
      ).toMatchObject({ valid: false, errors: [{ code: "schema" }] });
      expect(
        __testOnlyCreateLaunchPlanV2Preview(
          manifest,
          decision,
          { ...trusted, expectedCurrentDeliveryIdentity: badIdentity },
          policy,
        ),
      ).toMatchObject({ valid: false, errors: [{ code: "schema" }] });
    },
  );
  it("rejects non-canonical direct trusted-decision validator inputs", async () => {
    const { validateTrustedConcreteLaunchDecisionV2 } =
      await import("../src/launch-plan-v2.js");
    expect(
      validateTrustedConcreteLaunchDecisionV2(
        Object.fromEntries(Object.entries(decision).reverse()),
        trusted,
      ),
    ).toMatchObject({ valid: false, errors: [{ code: "non-canonical" }] });
    expect(
      validateTrustedConcreteLaunchDecisionV2(
        decision,
        Object.fromEntries(Object.entries(trusted).reverse()),
      ),
    ).toMatchObject({ valid: false, errors: [{ code: "non-canonical" }] });
  });
  it.each([
    [
      "decision identity",
      decision,
      {
        ...decision,
        identity: Object.fromEntries(
          Object.entries(decision.identity).reverse(),
        ),
      },
      trusted,
      policy,
    ],
    [
      "trusted current identity",
      decision,
      decision,
      {
        ...trusted,
        expectedCurrentDeliveryIdentity: Object.fromEntries(
          Object.entries(trusted.expectedCurrentDeliveryIdentity).reverse(),
        ),
      },
      policy,
    ],
    [
      "policy role row",
      decision,
      decision,
      trusted,
      {
        ...policy,
        roles: {
          ...policy.roles,
          "principal-developer": Object.fromEntries(
            Object.entries(policy.roles["principal-developer"]).reverse(),
          ),
        },
      },
    ],
  ])(
    "rejects non-canonical nested authority object: %s",
    (
      _name,
      _baseline,
      candidateDecision,
      candidateTrusted,
      candidatePolicy,
    ) => {
      expect(
        __testOnlyCreateLaunchPlanV2Preview(
          manifest,
          candidateDecision,
          candidateTrusted,
          candidatePolicy,
        ),
      ).toMatchObject({ valid: false, errors: [{ code: "non-canonical" }] });
    },
  );
  it.each([
    ["outer manifest", Object.fromEntries(Object.entries(manifest).reverse())],
    [
      "embedded packet",
      {
        ...manifest,
        packet: Object.fromEntries(Object.entries(manifest.packet).reverse()),
      },
    ],
  ])("rejects non-canonical %s object-key order", (_name, candidate) => {
    expect(
      __testOnlyCreateLaunchPlanV2Preview(candidate, decision, trusted, policy),
    ).toMatchObject({ valid: false, errors: [{ code: "non-canonical" }] });
  });
  it("rejects non-canonical signed manifests instead of normalizing them", () => {
    const nonCanonicalPacket = structuredClone(packet);
    nonCanonicalPacket.work.allowedPaths.reverse();
    nonCanonicalPacket.packetDigest = sha256(
      nonCanonicalPacket,
      "packetDigest",
    );
    const nonCanonicalManifest = structuredClone(manifest);
    nonCanonicalManifest.packet = nonCanonicalPacket;
    nonCanonicalManifest.manifestDigest = sha256(
      nonCanonicalManifest,
      "manifestDigest",
    );
    expect(
      __testOnlyCreateLaunchPlanV2Preview(
        nonCanonicalManifest,
        decision,
        trusted,
        policy,
      ),
    ).toMatchObject({ valid: false, errors: [{ code: "non-canonical" }] });
  });
  it.each([
    [
      "tool",
      "manifest",
      () => ({ ...manifest, tools: [...manifest.tools, "write"] }),
    ],
    ["role", "manifest", () => ({ ...manifest, role: "flow" })],
    [
      "packet digest",
      "manifest",
      () => ({ ...manifest, packet: { ...packet, packetDigest: H } }),
    ],
    [
      "extension order",
      "policy",
      () => ({ ...policy, extensions: [...policy.extensions].reverse() }),
    ],
    [
      "extension path",
      "policy",
      () => ({
        ...policy,
        extensions: [
          { ...policy.extensions[0], path: "relative" },
          policy.extensions[1],
        ],
      }),
    ],
  ])("rejects %s laundering", (_n, source, make) =>
    expect(
      __testOnlyCreateLaunchPlanV2Preview(
        source === "manifest" ? make() : manifest,
        decision,
        trusted,
        source === "policy" ? make() : policy,
      ).valid,
    ).toBe(false),
  );
  it("accepts the packet's optional parent execution identity at stage one", () => {
    const packetWithParent = signed(
      { ...packet, run: { ...packet.run, parentExecutionId: "exec-parent" } },
      "packetDigest",
      digestFlowTaskPacket,
    );
    const manifestWithParent = signed(
      { ...manifest, packet: packetWithParent },
      "manifestDigest",
      digestAgentExecutionManifestV2,
    );
    const decisionWithParent = signed(
      {
        ...decision,
        packetDigest: packetWithParent.packetDigest,
        manifestDigest: manifestWithParent.manifestDigest,
      },
      "decisionDigest",
      digestTrustedConcreteLaunchDecisionV2,
    );
    const trustedWithParent = {
      ...trusted,
      expectedControllerDecisionDigest: decisionWithParent.decisionDigest,
    };
    expect(
      __testOnlyCreateLaunchPlanV2Preview(
        manifestWithParent,
        decisionWithParent,
        trustedWithParent,
        policy,
      ).valid,
    ).toBe(true);
  });
  it("preserves earlier malformed-source precedence over a later hostile source", () => {
    const hostile = Object.defineProperty({}, "effect", {
      enumerable: true,
      get() {
        throw Error("must not run");
      },
    });
    expect(
      __testOnlyCreateLaunchPlanV2Preview({}, hostile, trusted, policy),
    ).toMatchObject({ valid: false, errors: [{ code: "schema" }] });
  });
  it.each([
    [null, "unsafe-input"],
    [{ ...policy, skills: null }, "schema"],
    [{ ...policy, promptTemplates: null }, "schema"],
  ])(
    "rejects malformed policy objects without throwing",
    (badPolicy, expectedCode) => {
      expect(() =>
        createPiLaunchPlanV2(manifest, decision, trusted, badPolicy),
      ).not.toThrow();
      expect(
        createPiLaunchPlanV2(manifest, decision, trusted, badPolicy),
      ).toMatchObject({
        valid: false,
        errors: [{ code: expectedCode }],
      });
    },
  );
  it.each([
    [
      "decision",
      Object.fromEntries(
        Object.entries(decision).filter(([key]) => key !== "effect"),
      ),
      trusted,
      policy,
    ],
    [
      "trusted inputs",
      decision,
      Object.fromEntries(
        Object.entries(trusted).filter(([key]) => key !== "source"),
      ),
      policy,
    ],
    [
      "policy",
      decision,
      trusted,
      {
        ...policy,
        roles: {
          ...policy.roles,
          product: { ...policy.roles.product, tools: {} },
        },
      },
    ],
  ])(
    "checks every %s shape before an earlier manifest digest error",
    (_name, badDecision, badTrusted, badPolicy) => {
      expect(
        __testOnlyCreateLaunchPlanV2Preview(
          { ...manifest, manifestDigest: "f".repeat(64) },
          badDecision,
          badTrusted as any,
          badPolicy,
        ),
      ).toMatchObject({ valid: false, errors: [{ code: "schema" }] });
    },
  );
  it("rejects malformed nested production inputs before fixed denial", () => {
    expect(
      createPiLaunchPlanV2(manifest, decision, trusted, {
        ...policy,
        extensions: [
          { ...policy.extensions[0], path: 42 },
          policy.extensions[1],
        ],
      }),
    ).toMatchObject({ valid: false, errors: [{ code: "schema" }] });
  });
  it("always denies structurally valid production requests and reveals no argv", () =>
    expect(createPiLaunchPlanV2(manifest, decision, trusted, policy)).toEqual({
      valid: false,
      errors: [
        {
          path: "/",
          code: "production-authorization-unavailable",
          message: "production authorization is unavailable",
        },
      ],
    }));
  it("returns fixed hostile diagnostics without invoking getters", () => {
    const hostile = Object.defineProperty({}, "env", {
      enumerable: true,
      get() {
        throw Error("secret");
      },
    });
    expect(createPiLaunchPlanV2(hostile)).toEqual({
      valid: false,
      errors: [
        {
          path: "/",
          code: "unsafe-input",
          message: "input could not be safely inspected",
        },
      ],
    });
  });
  it("preserves v1 exports", async () =>
    expect(typeof (await import("../src/index.js")).createPiLaunchPlan).toBe(
      "function",
    ));
});

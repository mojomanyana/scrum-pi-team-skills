/* eslint-disable @typescript-eslint/no-explicit-any -- mutation fixtures intentionally cross type boundaries */
import { describe, expect, it } from "vitest";
import p0 from "../examples/flow-task-packet.product.json" with { type: "json" };
import p1 from "../examples/flow-task-packet.flow.json" with { type: "json" };
import p2 from "../examples/flow-task-packet.principal-developer.json" with { type: "json" };
import p3 from "../examples/flow-task-packet.independent-verifier.json" with { type: "json" };
import {
  AGENT_ROLE_PROFILES_V2,
  canonicalizeAgentExecutionManifestV2,
  digestAgentExecutionManifestV2,
  digestFlowTaskPacket,
  validateAgentExecutionManifestV2,
} from "../src/index.js";
const packet = (v: any) => {
  const x = structuredClone(v);
  delete x.packetDigest;
  const d = digestFlowTaskPacket(x);
  if (!d.valid) throw 0;
  return { ...x, packetDigest: d.value };
};
const manifest = (v: any) => {
  const p = packet(v),
    profile =
      AGENT_ROLE_PROFILES_V2[
        p.subject.role as keyof typeof AGENT_ROLE_PROFILES_V2
      ];
  const x: any = {
    contractId: "spts.agent-execution-manifest",
    schemaVersion: "2.0.0",
    manifestId: `manifest-${p.subject.role}`,
    packet: p,
    role: p.subject.role,
    actorId: p.subject.actorId,
    executionId: p.subject.executionId,
    workspaceId: p.subject.workspaceId,
    access: p.subject.access,
    resources: p.work.resources,
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
  };
  const d = digestAgentExecutionManifestV2(x);
  if (!d.valid) throw 0;
  return { ...x, manifestDigest: d.value };
};
const fixtures = [p0, p1, p2, p3].map(manifest);
describe("agent execution manifest v2", () => {
  it.each(fixtures)("validates all fixed role profiles", (m) => {
    const r = validateAgentExecutionManifestV2(m);
    expect(r.valid).toBe(true);
    if (r.valid) expect(Object.isFrozen(r.value.packet.work)).toBe(true);
  });
  it.each([
    ["added tool", (x: any) => x.tools.push("bash")],
    ["removed result tool", (x: any) => x.tools.pop()],
    ["reordered tools", (x: any) => x.tools.reverse()],
    ["profile", (x: any) => (x.toolProfileId = "root-v2")],
    ["workspace", (x: any) => (x.workspaceProfileId = "writer-v2")],
    ["role", (x: any) => (x.role = "flow")],
    ["actor", (x: any) => (x.actorId = "other")],
    ["resources", (x: any) => (x.resources.skills = [])],
    ["result protocol", (x: any) => (x.resultProtocol.maximum = 2)],
    ["credential", (x: any) => (x.resources.secret = "token")],
    ["unknown", (x: any) => (x.extension = "/tmp/x")],
  ])("rejects %s mutation", (_n, mut) => {
    const x = structuredClone(fixtures[2]);
    mut(x);
    expect(validateAgentExecutionManifestV2(x).valid).toBe(false);
  });
  it("denies bash for product, flow, and verifier", () => {
    for (const i of [0, 1, 3]) expect(fixtures[i]!.tools).not.toContain("bash");
    expect(fixtures[2]!.tools).toContain("bash");
  });
  it("canonicalizes producer set arrays while strict wire validation stays ordered", () => {
    const wire: any = structuredClone(fixtures[2]);
    wire.tools.reverse();
    expect(validateAgentExecutionManifestV2(wire).valid).toBe(false);

    const unsigned = structuredClone(wire);
    delete unsigned.manifestDigest;
    const result = canonicalizeAgentExecutionManifestV2(unsigned);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.value.tools).toEqual([
      ...AGENT_ROLE_PROFILES_V2["principal-developer"].tools,
    ]);
    expect(Object.isFrozen(result.value.tools)).toBe(true);
    const { manifestDigest, ...canonicalUnsigned } = result.value;
    expect(digestAgentExecutionManifestV2(canonicalUnsigned)).toEqual({
      valid: true,
      value: manifestDigest,
    });

    unsigned.tools = [unsigned.tools[0], unsigned.tools[0]];
    expect(canonicalizeAgentExecutionManifestV2(unsigned).valid).toBe(false);
  });
  it("orders embedded packet validation before manifest correlation", () => {
    const x: any = structuredClone(fixtures[0]);
    x.packet.packetDigest = "f".repeat(64);
    x.role = "flow";
    expect(validateAgentExecutionManifestV2(x)).toMatchObject({
      valid: false,
      errors: [{ code: "digest-mismatch" }],
    });
  });
  it("reports malformed embedded packet shape before outer credentials", () => {
    const x: any = structuredClone(fixtures[0]);
    delete x.packet.subject;
    x.resources.skills = [`sk-${"a".repeat(24)}`];
    expect(validateAgentExecutionManifestV2(x)).toEqual({
      valid: false,
      errors: [
        {
          path: "/",
          code: "schema",
          message: "input does not match the closed contract",
        },
      ],
    });
  });
  it.each([
    () => {
      const x: any = {};
      x.x = x;
      return x;
    },
    () =>
      Object.defineProperty({}, "x", {
        enumerable: true,
        get() {
          throw Error("credential");
        },
      }),
    () =>
      new Proxy(
        {},
        {
          ownKeys() {
            throw Error("credential");
          },
        },
      ),
  ])("safely rejects hostile input", (make) =>
    expect(validateAgentExecutionManifestV2(make())).toEqual({
      valid: false,
      errors: [
        {
          path: "/",
          code: "unsafe-input",
          message: "input could not be safely inspected",
        },
      ],
    }),
  );
});

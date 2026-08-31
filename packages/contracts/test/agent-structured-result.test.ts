/* eslint-disable @typescript-eslint/no-explicit-any -- mutation fixtures intentionally cross type boundaries */
import { describe, expect, it } from "vitest";
import p0 from "../examples/flow-task-packet.product.json" with { type: "json" };
import r0 from "../examples/agent-structured-result.product.json" with { type: "json" };
import p1 from "../examples/flow-task-packet.flow.json" with { type: "json" };
import r1 from "../examples/agent-structured-result.flow.json" with { type: "json" };
import p2 from "../examples/flow-task-packet.principal-developer.json" with { type: "json" };
import r2 from "../examples/agent-structured-result.principal-developer.json" with { type: "json" };
import p3 from "../examples/flow-task-packet.independent-verifier.json" with { type: "json" };
import r3 from "../examples/agent-structured-result.independent-verifier.json" with { type: "json" };
import {
  acceptStructuredResultSubmission,
  canonicalizeAgentStructuredResult,
  canonicalizeFlowTaskPacket,
  digestAgentStructuredResult,
  validateAgentStructuredResult,
} from "../src/index.js";
const signPacket = (v: any) => {
  const x = structuredClone(v);
  delete x.packetDigest;
  const canonical = canonicalizeFlowTaskPacket(x);
  if (!canonical.valid) throw 0;
  return canonical.value;
};
const signResult = (v: any, p: any) => {
  const x = { ...structuredClone(v), packetDigest: p.packetDigest };
  delete x.resultDigest;
  const canonical = canonicalizeAgentStructuredResult(x);
  if (!canonical.valid) throw 0;
  return canonical.value;
};
const fixtures = [
  [p0, r0],
  [p1, r1],
  [p2, r2],
  [p3, r3],
].map(([p, r]) => {
  const packet = signPacket(p);
  return [packet, signResult(r, packet)] as const;
});
describe("agent structured result v2", () => {
  it.each(fixtures)("accepts each closed role union", (_p, r) => {
    const v = validateAgentStructuredResult(r);
    expect(v.valid).toBe(true);
    if (v.valid) expect(Object.isFrozen(v.value.payload)).toBe(true);
  });
  it.each([
    ["crossed role", (x: any) => (x.role = "flow")],
    ["status", (x: any) => (x.status = "blocked")],
    ["outcome", (x: any) => (x.payload.outcomeCode = "rejected")],
    ["forbidden", (x: any) => (x.payload.stdout = "raw")],
    [
      "credential",
      (x: any) =>
        (x.payload.token = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"),
    ],
    ["cardinality", (x: any) => (x.payload.taskDefinitions = [])],
    ["tree", (x: any) => (x.baseTree = "x")],
  ])("rejects %s", (_n, mut) => {
    const x = structuredClone(fixtures[0]![1]);
    mut(x);
    expect(validateAgentStructuredResult(x).valid).toBe(false);
  });
  it("uses UTF-16 ordinal ordering independently of locale", () => {
    const [p, r] = fixtures[0]!;
    const x: any = structuredClone(r);
    x.payload.taskDefinitions[0].allowedPaths = ["z", "ä"];
    const signed: any = structuredClone(signResult(x, p));
    expect(validateAgentStructuredResult(signed).valid).toBe(true);
    signed.payload.taskDefinitions[0].allowedPaths.reverse();
    expect(validateAgentStructuredResult(signed).valid).toBe(false);
  });
  it("canonicalizes producer set arrays while strict wire validation stays ordered", () => {
    const [p, fixture] = fixtures[0]!;
    const ordered: any = structuredClone(fixture);
    ordered.payload.taskDefinitions[0].allowedPaths = ["a/", "z/"];
    const wire: any = structuredClone(signResult(ordered, p));
    wire.payload.taskDefinitions[0].allowedPaths.reverse();
    expect(validateAgentStructuredResult(wire).valid).toBe(false);

    const unsigned = structuredClone(wire);
    delete unsigned.resultDigest;
    const result = canonicalizeAgentStructuredResult(unsigned);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    const paths = (result.value.payload.taskDefinitions as any[])[0]
      .allowedPaths;
    expect(paths).toEqual(["a/", "z/"]);
    expect(Object.isFrozen(paths)).toBe(true);
    const { resultDigest, ...canonicalUnsigned } = result.value;
    expect(digestAgentStructuredResult(canonicalUnsigned)).toEqual({
      valid: true,
      value: resultDigest,
    });

    unsigned.payload.taskDefinitions[0].allowedPaths = ["a/", "a/"];
    expect(canonicalizeAgentStructuredResult(unsigned).valid).toBe(false);
  });
  it.each([
    "",
    "@",
    "-topic",
    "/topic",
    "topic/",
    "a//b",
    ".hidden",
    "a/.hidden",
    "a..b",
    "a@{b",
    "a.lock",
    "a/b.lock",
    "a b",
    "a~b",
    "a^b",
    "a:b",
    "a?b",
    "a*b",
    "a[b",
    "a\\b",
  ])("rejects invalid branch grammar: %s", (branch) => {
    const x: any = structuredClone(fixtures[0]![1]);
    x.headBranch = branch;
    expect(validateAgentStructuredResult(x).valid).toBe(false);
  });
  it("enforces exact tool, correlation, execution and exactly once", () => {
    const [p, r] = fixtures[0]!;
    const state = { executionId: r.executionId, acceptedResultDigest: null };
    expect(
      acceptStructuredResultSubmission(state, "wrong", r, p).accepted,
    ).toBe(false);
    const first = acceptStructuredResultSubmission(
      state,
      "flow_submit_result",
      r,
      p,
    );
    expect(first.accepted).toBe(true);
    if (!first.accepted) return;
    expect(Object.isFrozen(first.state)).toBe(true);
    for (const candidate of [r, signResult({ ...r, resultId: "different" }, p)])
      expect(
        acceptStructuredResultSubmission(
          first.state,
          "flow_submit_result",
          candidate,
          p,
        ),
      ).toMatchObject({
        accepted: false,
        errors: [{ code: "duplicate-result" }],
      });
    expect(
      acceptStructuredResultSubmission(
        { ...state, executionId: "other" },
        "flow_submit_result",
        r,
        p,
      ).accepted,
    ).toBe(false);
  });
  it("gives digest failure precedence over correlation", () => {
    const [p, r] = fixtures[0]!;
    expect(
      acceptStructuredResultSubmission(
        { executionId: r.executionId, acceptedResultDigest: null },
        "flow_submit_result",
        { ...r, taskId: "other" },
        p,
      ),
    ).toMatchObject({ accepted: false, errors: [{ code: "digest-mismatch" }] });
  });
  it.each([
    () => {
      const x: any = {};
      x.x = x;
      return x;
    },
    () =>
      Object.defineProperty({}, "secret", {
        enumerable: true,
        get() {
          throw Error("value");
        },
      }),
    () =>
      new Proxy(
        {},
        {
          ownKeys() {
            throw Error("value");
          },
        },
      ),
  ])("rejects hostile values with fixed redaction", (make) =>
    expect(validateAgentStructuredResult(make())).toEqual({
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

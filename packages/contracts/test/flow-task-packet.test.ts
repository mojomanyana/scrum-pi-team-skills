/* eslint-disable @typescript-eslint/no-explicit-any -- mutation fixtures intentionally cross type boundaries */
import { describe, expect, it } from "vitest";
import product from "../examples/flow-task-packet.product.json" with { type: "json" };
import flow from "../examples/flow-task-packet.flow.json" with { type: "json" };
import principal from "../examples/flow-task-packet.principal-developer.json" with { type: "json" };
import verifier from "../examples/flow-task-packet.independent-verifier.json" with { type: "json" };
import {
  canonicalizeFlowTaskPacket,
  digestFlowTaskPacket,
  isFlowPathAuthorized,
  validateFlowTaskPacket,
} from "../src/index.js";
const examples = [product, flow, principal, verifier];
const sign = (input: unknown) => {
  const x = structuredClone(input) as Record<string, unknown>;
  delete x.packetDigest;
  const canonical = canonicalizeFlowTaskPacket(x);
  if (!canonical.valid) throw new Error("fixture");
  return canonical.value;
};
const code = (x: unknown) => {
  const r = validateFlowTaskPacket(x);
  return r.valid ? "valid" : r.errors[0]?.code;
};
describe("flow task packet v2", () => {
  it.each(examples.map((x, i) => [i, x]))(
    "validates and freezes role example %s",
    (_i, x) => {
      const r = validateFlowTaskPacket(sign(x));
      expect(r.valid).toBe(true);
      if (r.valid) expect(Object.isFrozen(r.value.work.resources)).toBe(true);
    },
  );
  it.each([
    ["unknown", (x: any) => (x.extra = true)],
    ["tree", (x: any) => (x.repository.baseTree = "x")],
    ["role", (x: any) => (x.subject.role = "root")],
    [
      "credential",
      (x: any) =>
        (x.work.secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"),
    ],
    ["size", (x: any) => (x.work.objective = "x".repeat(4097))],
  ])("rejects %s mutation", (_n, mutate) => {
    const x = structuredClone(sign(product));
    mutate(x);
    expect(code(x)).not.toBe("valid");
  });
  it("uses UTF-16 ordinal ordering independently of locale", () => {
    const x: any = structuredClone(product);
    x.work.acceptanceCriteria = ["z", "ä"];
    const signed: any = structuredClone(sign(x));
    expect(code(signed)).toBe("valid");
    signed.work.acceptanceCriteria.reverse();
    expect(code(signed)).toBe("non-canonical");
  });
  it("canonicalizes producer set arrays while strict wire validation stays ordered", () => {
    const wire: any = structuredClone(
      sign({
        ...structuredClone(product),
        work: {
          ...structuredClone(product.work),
          acceptanceCriteria: ["a", "z"],
        },
      }),
    );
    wire.work.acceptanceCriteria.reverse();
    expect(code(wire)).toBe("non-canonical");

    const unsigned = structuredClone(wire);
    delete unsigned.packetDigest;
    const result = canonicalizeFlowTaskPacket(unsigned);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.value.work.acceptanceCriteria).toEqual(["a", "z"]);
    expect(Object.isFrozen(result.value.work.acceptanceCriteria)).toBe(true);
    const { packetDigest, ...canonicalUnsigned } = result.value;
    expect(digestFlowTaskPacket(canonicalUnsigned)).toEqual({
      valid: true,
      value: packetDigest,
    });

    unsigned.work.acceptanceCriteria = ["a", "a"];
    expect(canonicalizeFlowTaskPacket(unsigned).valid).toBe(false);
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
    const x: any = structuredClone(sign(product));
    x.repository.headBranch = branch;
    expect(code(x)).not.toBe("valid");
  });
  it("binds every descriptive identity only after a valid digest", () => {
    const x: any = sign(product);
    const expected = Object.fromEntries(
      Object.entries({
        ...x.task,
        repositoryId: x.repository.repositoryId,
        rootId: x.repository.rootId,
        runId: x.run.runId,
        baseBranch: x.repository.baseBranch,
        headBranch: x.repository.headBranch,
        baseCommit: x.repository.baseCommit,
        baseTree: x.repository.baseTree,
        candidateCommit: x.repository.candidateCommit,
        candidateTree: x.repository.candidateTree,
        ...x.subject,
        assurance: x.assurance.profile,
        phase: x.assurance.phase,
        authorityDigest: x.authorityDigest,
        controllerStateDigest: x.controllerStateDigest,
      }).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    expect(validateFlowTaskPacket(x, expected).valid).toBe(true);
    expect(
      validateFlowTaskPacket(
        x,
        Object.fromEntries(Object.entries(expected).reverse()),
      ),
    ).toMatchObject({ valid: false, errors: [{ code: "non-canonical" }] });
    expect(code({ ...x, packetDigest: "f".repeat(64) })).toBe(
      "digest-mismatch",
    );
    expect(
      validateFlowTaskPacket(x, { ...expected, taskId: "other" }).valid,
    ).toBe(false);
  });
  it.each([
    ["exact", ["a"], "a", true],
    ["subtree", ["a/"], "a/b", true],
    ["sibling", ["a/"], "ab/b", false],
    ["rename old/new", ["old/", "new/"], "new/file", true],
    ["traversal", ["a/"], "a/../secret", false],
  ])("applies lexical path authority: %s", (_n, a, p, want) =>
    expect(isFlowPathAuthorized(a as string[], p as string)).toBe(want),
  );
  it.each([
    () => {
      const x: any = {};
      x.self = x;
      return x;
    },
    () =>
      Object.defineProperty({}, "x", {
        enumerable: true,
        get() {
          throw Error("secret");
        },
      }),
    () =>
      new Proxy(
        {},
        {
          ownKeys() {
            throw Error("token");
          },
        },
      ),
    () => Object.assign(Object.create({ polluted: true }), {}),
  ])("redacts hostile input deterministically", (make) => {
    expect(validateFlowTaskPacket(make())).toEqual({
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
});

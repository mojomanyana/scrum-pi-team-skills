import { describe, expect, it } from "vitest";
import { registerWorktree } from "../src/adapters/worktrees.js";

describe("worktree adapter", () => {
  it("registers a worktree", () => {
    const result = registerWorktree({
      operationId: "op-1",
      registrationId: "reg-1",
      sourceRegistrationId: "src-1",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: "a".repeat(40),
      candidateTree: "b".repeat(40),
    });
    expect(result.registrationDigest).toMatch(/^[a-f0-9]{64}$/);
  });
});

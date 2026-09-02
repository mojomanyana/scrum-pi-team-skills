import { describe, expect, it } from "vitest";
import {
  createTrustedFixtureGitPolicyV1,
  isTrustedFixtureGitPolicyV1,
} from "../src/adapters/git.js";

describe("git adapter", () => {
  it("issues trusted policy", () => {
    const policy = createTrustedFixtureGitPolicyV1({
      policyId: "policy-1",
      trustedParent: "/tmp",
      gitExecutable: "/usr/bin/git",
      gitExecPath: "/usr/lib/git-core",
      namedChecks: [],
      limits: {},
    });
    expect(isTrustedFixtureGitPolicyV1(policy)).toBe(true);
  });
});

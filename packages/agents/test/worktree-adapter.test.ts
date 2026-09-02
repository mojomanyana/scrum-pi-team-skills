import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

import {
  __testOnlyDescribeFixtureHarnessV1,
  createFixtureRepositoryHarnessV1,
  createTrustedFixtureGitPolicyV1,
  type FixtureLimitsV1,
} from "../src/adapters/git.js";
import type {
  NamedCheckResultV1,
  ValidationResult,
} from "@scrum-pi-team-skills/contracts";

const fixtureScriptPath = new URL(
  "../../runtime/test/fixtures/named-check.mjs",
  import.meta.url,
).pathname;

function requireValid(
  result: ValidationResult<NamedCheckResultV1>,
): NamedCheckResultV1 {
  if (!result.valid) throw new Error(JSON.stringify(result.errors));
  return result.value;
}

function gitExecutable(): string {
  const resolved = spawnSync("bash", ["-lc", "command -v git"], {
    encoding: "utf8",
  });
  return resolved.stdout.trim();
}

function gitExecPath(): string {
  const resolved = spawnSync(gitExecutable(), ["--exec-path"], {
    encoding: "utf8",
  });
  return resolved.stdout.trim();
}

function fixtureLimits(): FixtureLimitsV1 {
  return {
    maxRootPathBytes: 4096,
    maxComponentBytes: 255,
    maxContainmentDepth: 16,
    maxArgvCount: 32,
    maxArgvEntryBytes: 1024,
    maxArgvBytes: 8192,
    maxEnvironmentEntries: 16,
    maxEnvironmentEntryBytes: 1024,
    maxEnvironmentBytes: 4096,
    maxFixtureFiles: 256,
    maxFixtureFileBytes: 1024 * 1024,
    maxFixtureBytes: 8 * 1024 * 1024,
    maxGitObjects: 4096,
    maxGitObjectBytes: 32 * 1024 * 1024,
    maxActiveWorktrees: 32,
    maxObservedWorktrees: 128,
    maxOperations: 10_000,
    maxNamedChecks: 256,
    maxAttempts: 32,
    maxOutputBytesPerStream: 1024 * 1024,
    maxCombinedOutputBytes: 2 * 1024 * 1024,
    maxDurationMs: 15 * 60 * 1000,
    terminationGraceMs: 5_000,
    killConfirmationMs: 5_000,
    processPollMs: 50,
    maxCleanupEntries: 4096,
    maxCleanupBytes: 64 * 1024 * 1024,
    maxRecoveryRecords: 10_000,
    maxRecoveryBytes: 16 * 1024 * 1024,
    maxInputDepth: 16,
    maxInputNodes: 2048,
    maxInputObjectKeys: 256,
    maxInputArrayEntries: 256,
    maxInputStringBytes: 1024 * 1024,
  };
}

function createPolicy(parent: string) {
  return createTrustedFixtureGitPolicyV1({
    policyId: "policy-worktrees",
    trustedParent: parent,
    gitExecutable: gitExecutable(),
    gitExecPath: gitExecPath(),
    namedChecks: [
      {
        checkId: "fixture-pass",
        executable: process.execPath,
        argv: [fixtureScriptPath, "pass"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-mutate",
        executable: process.execPath,
        argv: [fixtureScriptPath, "mutate"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
    ],
    limits: fixtureLimits(),
  });
}

describe("worktree adapter", () => {
  it("creates detached verifier and named-check worktrees and detects mutation", async () => {
    const parent = mkdtempSync(join(tmpdir(), "fixture-worktrees-parent-"));
    chmodSync(parent, 0o700);
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-worktree-1",
      taskId: "task-worktree-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });

    const repository = await harness.createRepository({
      operationId: "repo-1",
      registrationId: "repo-main",
      files: [
        {
          pathComponents: ["named-check-fixture.txt"],
          mode: "100644",
          content: new TextEncoder().encode("original\n"),
        },
      ],
    });

    const verifier = await harness.createWorktree({
      operationId: "worktree-verify-1",
      registrationId: "verify-1",
      sourceRegistrationId: "repo-main",
      role: "independent-verifier",
      checkId: null,
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    expect(verifier.outcome).toBe("applied");
    expect(verifier.post?.detached).toBe(true);

    const checkWorktree = await harness.createWorktree({
      operationId: "worktree-check-1",
      registrationId: "check-1",
      sourceRegistrationId: "repo-main",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    expect(checkWorktree.outcome).toBe("applied");

    const pass = await harness.runNamedCheckV1({
      operationId: "named-check-pass-1",
      registrationId: "check-1",
      checkId: "fixture-pass",
      attempt: 1,
    });
    const passValue = requireValid(pass);
    expect(pass.valid).toBe(true);
    expect(passValue.outcome).toBe("passed");

    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const checkRegistration = described.registrations.find(
      (entry) => entry.registrationId === "check-1",
    );
    expect(checkRegistration?.path).toBeDefined();
    expect(
      readFileSync(
        join(checkRegistration!.path, "named-check-fixture.txt"),
        "utf8",
      ),
    ).toBe("original\n");

    const mutatingCheckWorktree = await harness.createWorktree({
      operationId: "worktree-check-2",
      registrationId: "check-2",
      sourceRegistrationId: "repo-main",
      role: "named-check",
      checkId: "fixture-mutate",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    expect(mutatingCheckWorktree.outcome).toBe("applied");

    const mutated = await harness.runNamedCheckV1({
      operationId: "named-check-mutate-1",
      registrationId: "check-2",
      checkId: "fixture-mutate",
      attempt: 1,
    });
    const mutatedValue = requireValid(mutated);
    expect(mutated.valid).toBe(true);
    expect(mutatedValue.outcome).toBe("mutation-detected");

    const removed = await harness.removeWorktree("cleanup-check-1", "check-1");
    expect(removed.outcome).toBe("applied");

    await harness.close();
    await harness.cleanup();
    rmSync(parent, { recursive: true, force: true });
  }, 15_000);
});

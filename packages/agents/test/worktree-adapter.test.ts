import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
  it("blocks dirty worktree removal and retains evidence", async () => {
    const parent = mkdtempSync(
      join(tmpdir(), "fixture-worktrees-guard-parent-"),
    );
    chmodSync(parent, 0o700);
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-worktree-guard-1",
      taskId: "task-worktree-guard-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });

    const repository = await harness.createRepository({
      operationId: "repo-guard-1",
      registrationId: "repo-guard-main",
      files: [
        {
          pathComponents: ["named-check-fixture.txt"],
          mode: "100644",
          content: new TextEncoder().encode("original\n"),
        },
      ],
    });

    const dirtyWorktree = await harness.createWorktree({
      operationId: "worktree-guard-dirty-1",
      registrationId: "check-guard-dirty-1",
      sourceRegistrationId: "repo-guard-main",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    expect(dirtyWorktree.outcome).toBe("applied");

    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const dirtyPath = described.registrations.find(
      (entry) => entry.registrationId === "check-guard-dirty-1",
    )?.path;
    expect(dirtyPath).toBeDefined();
    writeFileSync(
      join(dirtyPath!, "named-check-fixture.txt"),
      "dirty\n",
      "utf8",
    );
    const dirtyRemoval = await harness.removeWorktree(
      "cleanup-guard-dirty-1",
      "check-guard-dirty-1",
    );
    expect(dirtyRemoval.outcome).toBe("blocked");
    expect(dirtyRemoval.diagnostic?.code).toBe("workspace-dirty");
    expect(existsSync(dirtyPath!)).toBe(true);

    await harness.close();
    rmSync(parent, { recursive: true, force: true });
  }, 15_000);

  it("blocks drifted worktree removal and retains evidence", async () => {
    const parent = mkdtempSync(
      join(tmpdir(), "fixture-worktrees-drift-parent-"),
    );
    chmodSync(parent, 0o700);
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-worktree-drift-1",
      taskId: "task-worktree-drift-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });

    const repository = await harness.createRepository({
      operationId: "repo-drift-1",
      registrationId: "repo-drift-main",
      files: [
        {
          pathComponents: ["named-check-fixture.txt"],
          mode: "100644",
          content: new TextEncoder().encode("original\n"),
        },
      ],
    });

    const driftedWorktree = await harness.createWorktree({
      operationId: "worktree-guard-drift-1",
      registrationId: "check-guard-drift-1",
      sourceRegistrationId: "repo-drift-main",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    expect(driftedWorktree.outcome).toBe("applied");
    const driftPath = __testOnlyDescribeFixtureHarnessV1(
      harness,
    ).registrations.find(
      (entry) => entry.registrationId === "check-guard-drift-1",
    )?.path;
    expect(driftPath).toBeDefined();
    writeFileSync(
      join(driftPath!, ".git"),
      `${readFileSync(join(driftPath!, ".git"), "utf8")}# drift\n`,
      "utf8",
    );
    const driftRemoval = await harness.removeWorktree(
      "cleanup-guard-drift-1",
      "check-guard-drift-1",
    );
    expect(driftRemoval.outcome).toBe("blocked");
    expect(driftRemoval.diagnostic?.code).toBe("repository-identity-drift");
    expect(existsSync(driftPath!)).toBe(true);

    await harness.close();
    rmSync(parent, { recursive: true, force: true });
  }, 15_000);

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
    const removedVerifier = await harness.removeWorktree(
      "cleanup-verify-1",
      "verify-1",
    );
    expect(removedVerifier.outcome).toBe("applied");

    await harness.close();
    const rootPath = described.rootPath;
    await expect(harness.cleanup()).rejects.toThrow(
      /cleanup|retain|mutat|unknown/i,
    );
    expect(existsSync(rootPath)).toBe(true);
    rmSync(parent, { recursive: true, force: true });
  }, 15_000);
});

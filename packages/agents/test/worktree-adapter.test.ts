import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  __testOnlyDescribeFixtureHarnessV1,
  __testOnlySetFixtureFaultV1,
  createFixtureRepositoryHarnessV1,
  createTrustedFixtureGitPolicyV1,
  recoverFixtureRepositoryHarnessV1,
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
const heavySuiteLockPath = join(tmpdir(), "spts10-s5-heavy-suite.lock");
const heavySuiteOwnerPath = join(heavySuiteLockPath, "owner.json");

function requireValid(
  result: ValidationResult<NamedCheckResultV1>,
): NamedCheckResultV1 {
  if (!result.valid) throw new Error(JSON.stringify(result.errors));
  return result.value;
}

function resolveGitExecutable(): string {
  const resolved = spawnSync("bash", ["-lc", "command -v git"], {
    encoding: "utf8",
  });
  return resolved.stdout.trim();
}

function resolveGitExecPath(executable: string): string {
  const resolved = spawnSync(executable, ["--exec-path"], {
    encoding: "utf8",
  });
  return resolved.stdout.trim();
}

const gitExecutablePath = resolveGitExecutable();
const gitExecPathValue = resolveGitExecPath(gitExecutablePath);

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code === "ESRCH") return false;
    throw error;
  }
}

async function acquireHeavySuiteLock(owner: string): Promise<() => void> {
  while (true) {
    try {
      mkdirSync(heavySuiteLockPath, { mode: 0o700 });
      writeFileSync(
        heavySuiteOwnerPath,
        JSON.stringify({ owner, pid: process.pid }),
        "utf8",
      );
      return () => {
        rmSync(heavySuiteLockPath, { recursive: true, force: true });
      };
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code !== "EEXIST") throw error;
      let stale: boolean;
      try {
        const holder = JSON.parse(
          readFileSync(heavySuiteOwnerPath, "utf8"),
        ) as {
          pid?: unknown;
        };
        stale =
          typeof holder.pid !== "number" ||
          !Number.isSafeInteger(holder.pid) ||
          !isProcessAlive(holder.pid);
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 50));
        continue;
      }
      if (stale) {
        try {
          rmSync(heavySuiteLockPath, { recursive: true, force: true });
        } catch (removeError) {
          const removeCode =
            typeof removeError === "object" &&
            removeError !== null &&
            "code" in removeError
              ? (removeError as { code?: unknown }).code
              : undefined;
          if (removeCode !== "ENOENT" && removeCode !== "ENOTEMPTY") {
            throw removeError;
          }
        }
        continue;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

let releaseHeavySuiteLock: (() => void) | undefined;

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

function createTrustedParent(): string {
  const path = mkdtempSync(join(tmpdir(), "fixture-worktrees-parent-"));
  chmodSync(path, 0o700);
  return path;
}

function createPolicy(parent: string) {
  return createTrustedFixtureGitPolicyV1({
    policyId: "policy-worktrees",
    trustedParent: parent,
    gitExecutable: gitExecutablePath,
    gitExecPath: gitExecPathValue,
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

function replaceDirectoryAtSamePath(path: string): {
  readonly beforeInode: number;
  readonly afterInode: number;
} {
  const snapshotPath = `${path}-snapshot`;
  const beforeInode = statSync(path).ino;
  cpSync(path, snapshotPath, { recursive: true });
  rmSync(path, { recursive: true, force: false });
  cpSync(snapshotPath, path, { recursive: true });
  rmSync(snapshotPath, { recursive: true, force: true });
  const afterInode = statSync(path).ino;
  return Object.freeze({ beforeInode, afterInode });
}

beforeAll(async () => {
  await new Promise((resolve) => setTimeout(resolve, 5_000));
  releaseHeavySuiteLock = await acquireHeavySuiteLock(
    new URL(import.meta.url).pathname,
  );
}, 120_000);

afterAll(() => {
  releaseHeavySuiteLock?.();
  releaseHeavySuiteLock = undefined;
});

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

  it("blocks worktree root-field drift and same-path replacement during removal", async () => {
    const parent = mkdtempSync(
      join(tmpdir(), "fixture-worktrees-root-drift-parent-"),
    );
    chmodSync(parent, 0o700);
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-worktree-root-drift-1",
      taskId: "task-worktree-root-drift-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });

    try {
      const repository = await harness.createRepository({
        operationId: "repo-root-drift-1",
        registrationId: "repo-root-drift-main",
        files: [
          {
            pathComponents: ["named-check-fixture.txt"],
            mode: "100644",
            content: new TextEncoder().encode("original\n"),
          },
        ],
      });

      const worktree = await harness.createWorktree({
        operationId: "worktree-root-drift-1",
        registrationId: "check-root-drift-1",
        sourceRegistrationId: "repo-root-drift-main",
        role: "named-check",
        checkId: "fixture-pass",
        candidateCommit: repository.post!.headCommit,
        candidateTree: repository.post!.headTree,
      });
      expect(worktree.outcome).toBe("applied");

      const worktreePath = __testOnlyDescribeFixtureHarnessV1(
        harness,
      ).registrations.find(
        (entry) => entry.registrationId === "check-root-drift-1",
      )?.path;
      expect(worktreePath).toBeDefined();

      const originalMode = statSync(worktreePath!).mode & 0o777;
      const driftMode = originalMode === 0o700 ? 0o755 : 0o700;
      chmodSync(worktreePath!, driftMode);
      const modeRemoval = await harness.removeWorktree(
        "cleanup-root-drift-mode-1",
        "check-root-drift-1",
      );
      expect(modeRemoval.outcome).toBe("blocked");
      expect(modeRemoval.diagnostic?.code).toBe("repository-identity-drift");
      expect(existsSync(worktreePath!)).toBe(true);

      chmodSync(worktreePath!, originalMode);
      const replacement = replaceDirectoryAtSamePath(worktreePath!);
      expect(replacement.afterInode).not.toBe(replacement.beforeInode);
      const replacementRemoval = await harness.removeWorktree(
        "cleanup-root-drift-replaced-1",
        "check-root-drift-1",
      );
      expect(replacementRemoval.outcome).toBe("blocked");
      expect(replacementRemoval.diagnostic?.code).toBe(
        "repository-identity-drift",
      );
      expect(existsSync(worktreePath!)).toBe(true);

      await harness.close();
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  }, 15_000);

  it("detects linked admin-dir mutation and blocks cleanup", async () => {
    const parent = mkdtempSync(
      join(tmpdir(), "fixture-worktrees-admin-parent-"),
    );
    chmodSync(parent, 0o700);
    const adminDriftScript = join(parent, "admin-drift-check.mjs");
    writeFileSync(
      adminDriftScript,
      [
        'import { readFileSync, writeFileSync } from "node:fs";',
        'import { join, resolve } from "node:path";',
        'const gitFile = readFileSync(join(process.cwd(), ".git"), "utf8").trim();',
        'if (!gitFile.startsWith("gitdir: ")) process.exit(91);',
        "const adminDir = resolve(process.cwd(), gitFile.slice(8));",
        'writeFileSync(join(adminDir, "probe-marker.txt"), "marker\\n", "utf8");',
        "process.exit(0);",
      ].join("\n"),
      "utf8",
    );
    const policy = createTrustedFixtureGitPolicyV1({
      policyId: "policy-admin-drift",
      trustedParent: parent,
      gitExecutable: gitExecutablePath,
      gitExecPath: gitExecPathValue,
      namedChecks: [
        {
          checkId: "fixture-admin-drift",
          executable: process.execPath,
          argv: [adminDriftScript],
          maxDurationMs: 5_000,
          maxOutputBytes: 1_048_576,
        },
      ],
      limits: fixtureLimits(),
    });
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-worktree-admin-1",
      taskId: "task-worktree-admin-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });

    const repository = await harness.createRepository({
      operationId: "repo-admin-1",
      registrationId: "repo-admin-main",
      files: [
        {
          pathComponents: ["named-check-fixture.txt"],
          mode: "100644",
          content: new TextEncoder().encode("original\n"),
        },
      ],
    });
    await harness.createWorktree({
      operationId: "worktree-admin-1",
      registrationId: "check-admin-1",
      sourceRegistrationId: "repo-admin-main",
      role: "named-check",
      checkId: "fixture-admin-drift",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const checkPath = described.registrations.find(
      (entry) => entry.registrationId === "check-admin-1",
    )?.path;
    expect(checkPath).toBeDefined();
    const gitFile = readFileSync(join(checkPath!, ".git"), "utf8").trim();
    const adminDir = resolve(checkPath!, gitFile.slice(8));
    const markerPath = join(adminDir, "probe-marker.txt");

    const result = await harness.runNamedCheckV1({
      operationId: "named-check-admin-1",
      registrationId: "check-admin-1",
      checkId: "fixture-admin-drift",
      attempt: 1,
    });
    const value = requireValid(result);
    expect(value.outcome).toBe("mutation-detected");
    expect(value.diagnostic?.code).toBe("workspace-mutated");
    expect(existsSync(markerPath)).toBe(true);

    const removal = await harness.removeWorktree(
      "cleanup-admin-1",
      "check-admin-1",
    );
    expect(removal.outcome).toBe("blocked");
    expect(removal.diagnostic?.code).toBe("workspace-mutated");
    expect(existsSync(checkPath!)).toBe(true);

    await harness.close();
    rmSync(parent, { recursive: true, force: true });
  }, 15_000);

  it("reconciles staged remote and worktree recovery across prepared, started, and observed states", async () => {
    const expectations = {
      prepared: { outcome: "not-applied", diagnostic: null },
      "effect-started": { outcome: "blocked", diagnostic: "outcome-unknown" },
      "effect-observed": { outcome: "already-applied", diagnostic: null },
    } as const;
    const stages = ["prepared", "effect-started", "effect-observed"] as const;

    for (const stage of stages) {
      const remoteParent = createTrustedParent();
      const remotePolicy = createPolicy(remoteParent);
      const remoteOptions = {
        runId: `run-remote-recovery-${stage}`,
        taskId: `task-remote-recovery-${stage}`,
        expectedBaseCommit: "a".repeat(64),
        expectedBaseTree: "b".repeat(64),
      };
      const remoteHarness = await createFixtureRepositoryHarnessV1(
        remotePolicy,
        remoteOptions,
      );
      try {
        await remoteHarness.createRepository({
          operationId: `repo-remote-recovery-${stage}`,
          registrationId: "repo-main",
          files: [
            {
              pathComponents: ["named-check-fixture.txt"],
              mode: "100644",
              content: new TextEncoder().encode("original\n"),
            },
          ],
        });
        __testOnlySetFixtureFaultV1(
          remoteHarness,
          `create-bare-remote:after-${stage}`,
        );
        const request = {
          operationId: `remote-recovery-${stage}`,
          registrationId: "remote-main",
          sourceRegistrationId: "repo-main",
        };
        await expect(remoteHarness.createBareRemote(request)).rejects.toThrow(
          /fixture injected fault/i,
        );
        await remoteHarness.close();

        const recovered = await recoverFixtureRepositoryHarnessV1(
          remotePolicy,
          remoteOptions,
        );
        const replay = await recovered.createBareRemote(request);
        expect(replay.outcome, `remote ${stage}`).toBe(
          expectations[stage].outcome,
        );
        expect(replay.diagnostic?.code ?? null, `remote ${stage}`).toBe(
          expectations[stage].diagnostic,
        );
      } finally {
        rmSync(remoteParent, { recursive: true, force: true });
      }

      const worktreeParent = createTrustedParent();
      const worktreePolicy = createPolicy(worktreeParent);
      const worktreeOptions = {
        runId: `run-worktree-recovery-${stage}`,
        taskId: `task-worktree-recovery-${stage}`,
        expectedBaseCommit: "a".repeat(64),
        expectedBaseTree: "b".repeat(64),
      };
      const worktreeHarness = await createFixtureRepositoryHarnessV1(
        worktreePolicy,
        worktreeOptions,
      );
      try {
        const repository = await worktreeHarness.createRepository({
          operationId: `repo-worktree-recovery-${stage}`,
          registrationId: "repo-main",
          files: [
            {
              pathComponents: ["named-check-fixture.txt"],
              mode: "100644",
              content: new TextEncoder().encode("original\n"),
            },
          ],
        });
        __testOnlySetFixtureFaultV1(
          worktreeHarness,
          `create-worktree:after-${stage}`,
        );
        const request = {
          operationId: `worktree-recovery-${stage}`,
          registrationId: "check-main",
          sourceRegistrationId: "repo-main",
          role: "named-check" as const,
          checkId: "fixture-pass",
          candidateCommit: repository.post!.headCommit,
          candidateTree: repository.post!.headTree,
        };
        await expect(worktreeHarness.createWorktree(request)).rejects.toThrow(
          /fixture injected fault/i,
        );
        await worktreeHarness.close();

        const recovered = await recoverFixtureRepositoryHarnessV1(
          worktreePolicy,
          worktreeOptions,
        );
        const replay = await recovered.createWorktree(request);
        expect(replay.outcome, `worktree ${stage}`).toBe(
          expectations[stage].outcome,
        );
        expect(replay.diagnostic?.code ?? null, `worktree ${stage}`).toBe(
          expectations[stage].diagnostic,
        );
      } finally {
        rmSync(worktreeParent, { recursive: true, force: true });
      }

      const removeParent = createTrustedParent();
      const removePolicy = createPolicy(removeParent);
      const removeOptions = {
        runId: `run-remove-recovery-${stage}`,
        taskId: `task-remove-recovery-${stage}`,
        expectedBaseCommit: "a".repeat(64),
        expectedBaseTree: "b".repeat(64),
      };
      const removeHarness = await createFixtureRepositoryHarnessV1(
        removePolicy,
        removeOptions,
      );
      try {
        const repository = await removeHarness.createRepository({
          operationId: `repo-remove-recovery-${stage}`,
          registrationId: "repo-main",
          files: [
            {
              pathComponents: ["named-check-fixture.txt"],
              mode: "100644",
              content: new TextEncoder().encode("original\n"),
            },
          ],
        });
        await removeHarness.createWorktree({
          operationId: `worktree-remove-recovery-${stage}`,
          registrationId: "check-main",
          sourceRegistrationId: "repo-main",
          role: "named-check",
          checkId: "fixture-pass",
          candidateCommit: repository.post!.headCommit,
          candidateTree: repository.post!.headTree,
        });
        __testOnlySetFixtureFaultV1(
          removeHarness,
          `remove-worktree:after-${stage}`,
        );
        await expect(
          removeHarness.removeWorktree(
            `remove-recovery-${stage}`,
            "check-main",
          ),
        ).rejects.toThrow(/fixture injected fault/i);
        await removeHarness.close();

        const recovered = await recoverFixtureRepositoryHarnessV1(
          removePolicy,
          removeOptions,
        );
        const replay = await recovered.removeWorktree(
          `remove-recovery-${stage}`,
          "check-main",
        );
        expect(replay.outcome, `remove ${stage}`).toBe(
          expectations[stage].outcome,
        );
        expect(replay.diagnostic?.code ?? null, `remove ${stage}`).toBe(
          expectations[stage].diagnostic,
        );
      } finally {
        rmSync(removeParent, { recursive: true, force: true });
      }
    }
  }, 60_000);

  it("blocks replaced remote and worktree recovery after effect-observed faults", async () => {
    const remoteParent = createTrustedParent();
    const remotePolicy = createPolicy(remoteParent);
    const remoteOptions = {
      runId: "run-remote-replaced-1",
      taskId: "task-remote-replaced-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    };
    const remoteHarness = await createFixtureRepositoryHarnessV1(
      remotePolicy,
      remoteOptions,
    );
    try {
      await remoteHarness.createRepository({
        operationId: "repo-remote-replaced-1",
        registrationId: "repo-main",
        files: [
          {
            pathComponents: ["named-check-fixture.txt"],
            mode: "100644",
            content: new TextEncoder().encode("original\n"),
          },
        ],
      });
      const remoteRequest = {
        operationId: "remote-replaced-1",
        registrationId: "remote-main",
        sourceRegistrationId: "repo-main",
      };
      __testOnlySetFixtureFaultV1(
        remoteHarness,
        "create-bare-remote:after-effect-observed",
      );
      await expect(
        remoteHarness.createBareRemote(remoteRequest),
      ).rejects.toThrow(/fixture injected fault/i);
      const remotePath = __testOnlyDescribeFixtureHarnessV1(
        remoteHarness,
      ).registrations.find(
        (entry) => entry.registrationId === "remote-main",
      )?.path;
      expect(remotePath).toBeDefined();
      const replacement = replaceDirectoryAtSamePath(remotePath!);
      expect(replacement.afterInode).not.toBe(replacement.beforeInode);
      await remoteHarness.close();

      const recovered = await recoverFixtureRepositoryHarnessV1(
        remotePolicy,
        remoteOptions,
      );
      const replay = await recovered.createBareRemote(remoteRequest);
      expect(replay.outcome).toBe("blocked");
      expect(replay.diagnostic?.code).toBe("outcome-unknown");
    } finally {
      rmSync(remoteParent, { recursive: true, force: true });
    }

    const worktreeParent = createTrustedParent();
    const worktreePolicy = createPolicy(worktreeParent);
    const worktreeOptions = {
      runId: "run-worktree-replaced-1",
      taskId: "task-worktree-replaced-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    };
    const worktreeHarness = await createFixtureRepositoryHarnessV1(
      worktreePolicy,
      worktreeOptions,
    );
    try {
      const repository = await worktreeHarness.createRepository({
        operationId: "repo-worktree-replaced-1",
        registrationId: "repo-main",
        files: [
          {
            pathComponents: ["named-check-fixture.txt"],
            mode: "100644",
            content: new TextEncoder().encode("original\n"),
          },
        ],
      });
      const worktreeRequest = {
        operationId: "worktree-replaced-1",
        registrationId: "check-main",
        sourceRegistrationId: "repo-main",
        role: "named-check" as const,
        checkId: "fixture-pass",
        candidateCommit: repository.post!.headCommit,
        candidateTree: repository.post!.headTree,
      };
      __testOnlySetFixtureFaultV1(
        worktreeHarness,
        "create-worktree:after-effect-observed",
      );
      await expect(
        worktreeHarness.createWorktree(worktreeRequest),
      ).rejects.toThrow(/fixture injected fault/i);
      const worktreePath = __testOnlyDescribeFixtureHarnessV1(
        worktreeHarness,
      ).registrations.find(
        (entry) => entry.registrationId === "check-main",
      )?.path;
      expect(worktreePath).toBeDefined();
      const replacement = replaceDirectoryAtSamePath(worktreePath!);
      expect(replacement.afterInode).not.toBe(replacement.beforeInode);
      await worktreeHarness.close();

      const recovered = await recoverFixtureRepositoryHarnessV1(
        worktreePolicy,
        worktreeOptions,
      );
      const replay = await recovered.createWorktree(worktreeRequest);
      expect(replay.outcome).toBe("blocked");
      expect(replay.diagnostic?.code).toBe("outcome-unknown");
    } finally {
      rmSync(worktreeParent, { recursive: true, force: true });
    }
  }, 30_000);

  it("blocks drifted remote and worktree recovery after effect-observed faults", async () => {
    const remoteParent = createTrustedParent();
    const remotePolicy = createPolicy(remoteParent);
    const remoteOptions = {
      runId: "run-remote-drift-1",
      taskId: "task-remote-drift-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    };
    const remoteHarness = await createFixtureRepositoryHarnessV1(
      remotePolicy,
      remoteOptions,
    );
    try {
      const repository = await remoteHarness.createRepository({
        operationId: "repo-remote-drift-1",
        registrationId: "repo-main",
        files: [
          {
            pathComponents: ["named-check-fixture.txt"],
            mode: "100644",
            content: new TextEncoder().encode("original\n"),
          },
        ],
      });
      const remoteRequest = {
        operationId: "remote-drift-1",
        registrationId: "remote-main",
        sourceRegistrationId: "repo-main",
      };
      __testOnlySetFixtureFaultV1(
        remoteHarness,
        "create-bare-remote:after-effect-observed",
      );
      await expect(
        remoteHarness.createBareRemote(remoteRequest),
      ).rejects.toThrow(/fixture injected fault/i);
      const remotePath = __testOnlyDescribeFixtureHarnessV1(
        remoteHarness,
      ).registrations.find(
        (entry) => entry.registrationId === "remote-main",
      )?.path;
      expect(remotePath).toBeDefined();
      expect(
        spawnSync(
          gitExecutablePath,
          [
            "-C",
            remotePath!,
            "update-ref",
            "refs/heads/evil",
            repository.post!.headCommit,
          ],
          { encoding: "utf8" },
        ).status,
      ).toBe(0);
      await remoteHarness.close();
      const recovered = await recoverFixtureRepositoryHarnessV1(
        remotePolicy,
        remoteOptions,
      );
      const replay = await recovered.createBareRemote(remoteRequest);
      expect(replay.outcome).toBe("blocked");
      expect(replay.diagnostic?.code).toBe("outcome-unknown");
    } finally {
      rmSync(remoteParent, { recursive: true, force: true });
    }

    const worktreeDriftCases = [
      {
        name: "rogue-extra-worktree",
        seedVerifier: false,
        mutate: (input: {
          readonly parent: string;
          readonly repoPath: string;
          readonly verifierPath: string | undefined;
          readonly candidateCommit: string;
        }) =>
          spawnSync(
            gitExecutablePath,
            [
              "-C",
              input.repoPath,
              "worktree",
              "add",
              "--detach",
              join(input.parent, "rogue-extra-worktree"),
              input.candidateCommit,
            ],
            { encoding: "utf8" },
          ),
      },
      {
        name: "missing-sibling-registration",
        seedVerifier: true,
        mutate: (input: {
          readonly parent: string;
          readonly repoPath: string;
          readonly verifierPath: string | undefined;
          readonly candidateCommit: string;
        }) =>
          spawnSync(
            gitExecutablePath,
            [
              "-C",
              input.repoPath,
              "worktree",
              "remove",
              "--force",
              input.verifierPath!,
            ],
            { encoding: "utf8" },
          ),
      },
      {
        name: "drifted-sibling-fields",
        seedVerifier: true,
        mutate: (input: {
          readonly parent: string;
          readonly repoPath: string;
          readonly verifierPath: string | undefined;
          readonly candidateCommit: string;
        }) =>
          spawnSync(
            gitExecutablePath,
            ["-C", input.verifierPath!, "switch", "-c", "drift-branch"],
            { encoding: "utf8" },
          ),
      },
    ] as const;

    for (const [index, testCase] of worktreeDriftCases.entries()) {
      const worktreeParent = createTrustedParent();
      const worktreePolicy = createPolicy(worktreeParent);
      const worktreeOptions = {
        runId: `run-worktree-drift-${index + 1}`,
        taskId: `task-worktree-drift-${index + 1}`,
        expectedBaseCommit: "a".repeat(64),
        expectedBaseTree: "b".repeat(64),
      };
      const worktreeHarness = await createFixtureRepositoryHarnessV1(
        worktreePolicy,
        worktreeOptions,
      );
      try {
        const repository = await worktreeHarness.createRepository({
          operationId: `repo-worktree-drift-${index + 1}`,
          registrationId: "repo-main",
          files: [
            {
              pathComponents: ["named-check-fixture.txt"],
              mode: "100644",
              content: new TextEncoder().encode("original\n"),
            },
          ],
        });
        if (testCase.seedVerifier) {
          await worktreeHarness.createWorktree({
            operationId: `verifier-worktree-drift-${index + 1}`,
            registrationId: "verifier-main",
            sourceRegistrationId: "repo-main",
            role: "independent-verifier",
            checkId: null,
            candidateCommit: repository.post!.headCommit,
            candidateTree: repository.post!.headTree,
          });
        }
        const worktreeRequest = {
          operationId: `worktree-drift-${index + 1}`,
          registrationId: "check-main",
          sourceRegistrationId: "repo-main",
          role: "named-check" as const,
          checkId: "fixture-pass",
          candidateCommit: repository.post!.headCommit,
          candidateTree: repository.post!.headTree,
        };
        __testOnlySetFixtureFaultV1(
          worktreeHarness,
          "create-worktree:after-effect-observed",
        );
        await expect(
          worktreeHarness.createWorktree(worktreeRequest),
        ).rejects.toThrow(/fixture injected fault/i);
        const registrations =
          __testOnlyDescribeFixtureHarnessV1(worktreeHarness).registrations;
        const repoPath = registrations.find(
          (entry) => entry.registrationId === "repo-main",
        )?.path;
        const verifierPath = registrations.find(
          (entry) => entry.registrationId === "verifier-main",
        )?.path;
        expect(repoPath, testCase.name).toBeDefined();
        expect(
          testCase.mutate({
            parent: worktreeParent,
            repoPath: repoPath!,
            verifierPath,
            candidateCommit: repository.post!.headCommit,
          }).status,
          testCase.name,
        ).toBe(0);
        await worktreeHarness.close();
        const recovered = await recoverFixtureRepositoryHarnessV1(
          worktreePolicy,
          worktreeOptions,
        );
        const replay = await recovered.createWorktree(worktreeRequest);
        expect(replay.outcome, testCase.name).toBe("blocked");
        expect(replay.diagnostic?.code, testCase.name).toBe("outcome-unknown");
      } finally {
        rmSync(worktreeParent, { recursive: true, force: true });
      }
    }

    const removeParent = createTrustedParent();
    const removePolicy = createPolicy(removeParent);
    const removeOptions = {
      runId: "run-remove-drift-1",
      taskId: "task-remove-drift-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    };
    const removeHarness = await createFixtureRepositoryHarnessV1(
      removePolicy,
      removeOptions,
    );
    try {
      const repository = await removeHarness.createRepository({
        operationId: "repo-remove-drift-1",
        registrationId: "repo-main",
        files: [
          {
            pathComponents: ["named-check-fixture.txt"],
            mode: "100644",
            content: new TextEncoder().encode("original\n"),
          },
        ],
      });
      await removeHarness.createWorktree({
        operationId: "worktree-remove-drift-1",
        registrationId: "check-main",
        sourceRegistrationId: "repo-main",
        role: "named-check",
        checkId: "fixture-pass",
        candidateCommit: repository.post!.headCommit,
        candidateTree: repository.post!.headTree,
      });
      const worktreePath = __testOnlyDescribeFixtureHarnessV1(
        removeHarness,
      ).registrations.find(
        (entry) => entry.registrationId === "check-main",
      )?.path;
      expect(worktreePath).toBeDefined();
      __testOnlySetFixtureFaultV1(
        removeHarness,
        "remove-worktree:after-effect-observed",
      );
      await expect(
        removeHarness.removeWorktree("remove-drift-1", "check-main"),
      ).rejects.toThrow(/fixture injected fault/i);
      mkdirSync(worktreePath!, { recursive: true, mode: 0o700 });
      writeFileSync(join(worktreePath!, "resurrected.txt"), "drift\n", "utf8");
      await removeHarness.close();
      const recovered = await recoverFixtureRepositoryHarnessV1(
        removePolicy,
        removeOptions,
      );
      const replay = await recovered.removeWorktree(
        "remove-drift-1",
        "check-main",
      );
      expect(replay.outcome).toBe("blocked");
      expect(replay.diagnostic?.code).toBe("outcome-unknown");
    } finally {
      rmSync(removeParent, { recursive: true, force: true });
    }
  }, 45_000);

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

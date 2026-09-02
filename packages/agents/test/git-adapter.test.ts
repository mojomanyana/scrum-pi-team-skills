import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

import {
  __testOnlyDescribeFixtureHarnessV1,
  __testOnlySetFixtureFaultV1,
  createFixtureRepositoryHarnessV1,
  createTrustedFixtureGitPolicyV1,
  isTrustedFixtureGitPolicyV1,
  recoverFixtureRepositoryHarnessV1,
  type FixtureLimitsV1,
} from "../src/adapters/git.js";
import {
  createRegistrationRecordV1,
  registrationDigestV1,
} from "../src/adapters/worktrees.js";
import { runExactNamedCheckV1 } from "@scrum-pi-team-skills/runtime";

const fixtureScriptPath = new URL(
  "../../runtime/test/fixtures/named-check.mjs",
  import.meta.url,
).pathname;

function gitExecutable(): string {
  const resolved = spawnSync("bash", ["-lc", "command -v git"], {
    encoding: "utf8",
  });
  if ((resolved.status ?? 1) !== 0) throw new Error("git not found");
  return resolved.stdout.trim();
}

function gitExecPath(): string {
  const resolved = spawnSync(gitExecutable(), ["--exec-path"], {
    encoding: "utf8",
  });
  if ((resolved.status ?? 1) !== 0) throw new Error("git exec-path not found");
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

function createTrustedParent(): string {
  const path = mkdtempSync(join(tmpdir(), "fixture-policy-parent-"));
  chmodSync(path, 0o700);
  return path;
}

function createPolicy(parent: string) {
  return createTrustedFixtureGitPolicyV1({
    policyId: "policy-1",
    trustedParent: parent,
    gitExecutable: gitExecutable(),
    gitExecPath: gitExecPath(),
    namedChecks: [
      {
        checkId: "fixture-hang",
        executable: process.execPath,
        argv: [fixtureScriptPath, "hang"],
        maxDurationMs: 2_000,
        maxOutputBytes: 1_048_576,
      },
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

async function createHarnessWithRepository(parent = createTrustedParent()) {
  const policy = createPolicy(parent);
  const harness = await createFixtureRepositoryHarnessV1(policy, {
    runId: "run-1",
    taskId: "task-1",
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
  return { parent, policy, harness, repository };
}

describe("git adapter", () => {
  it("issues trusted policies and rejects duplicate check identifiers", async () => {
    const parent = createTrustedParent();
    const policy = createPolicy(parent);
    expect(isTrustedFixtureGitPolicyV1(policy)).toBe(true);
    expect(policy.namedChecks.map((entry) => entry.checkId)).toEqual([
      "fixture-hang",
      "fixture-mutate",
      "fixture-pass",
    ]);

    expect(() =>
      createTrustedFixtureGitPolicyV1({
        policyId: "policy-2",
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
            checkId: "fixture-pass",
            executable: process.execPath,
            argv: [fixtureScriptPath, "pass"],
            maxDurationMs: 5_000,
            maxOutputBytes: 1_048_576,
          },
        ],
        limits: fixtureLimits(),
      }),
    ).toThrow(/unique/i);

    await policy.revoke();
    rmSync(parent, { recursive: true, force: true });
  });

  it("creates a sha256 repository, a bare remote, and recovers durable metadata", async () => {
    const parent = createTrustedParent();
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-1",
      taskId: "task-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });

    const repository = await harness.createRepository({
      operationId: "repo-1",
      registrationId: "repo-main",
      files: [
        {
          pathComponents: ["README.md"],
          mode: "100644",
          content: new TextEncoder().encode("fixture\n"),
        },
        {
          pathComponents: ["bin", "run.sh"],
          mode: "100755",
          content: new TextEncoder().encode("#!/bin/sh\necho fixture\n"),
        },
      ],
    });
    expect(repository.outcome).toBe("applied");
    expect(repository.repositoryIdentity.objectFormat).toBe("sha256");
    expect(repository.post?.headCommit).toMatch(/^[a-f0-9]{64}$/);
    expect(repository.post?.headTree).toMatch(/^[a-f0-9]{64}$/);

    const replay = await harness.createRepository({
      operationId: "repo-1",
      registrationId: "repo-main",
      files: [
        {
          pathComponents: ["README.md"],
          mode: "100644",
          content: new TextEncoder().encode("fixture\n"),
        },
        {
          pathComponents: ["bin", "run.sh"],
          mode: "100755",
          content: new TextEncoder().encode("#!/bin/sh\necho fixture\n"),
        },
      ],
    });
    expect(replay.observationDigest).toBe(repository.observationDigest);

    const remote = await harness.createBareRemote({
      operationId: "remote-1",
      registrationId: "remote-main",
      sourceRegistrationId: "repo-main",
    });
    expect(remote.outcome).toBe("applied");

    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    expect(statSync(described.rootPath).isDirectory()).toBe(true);
    const repoPath = described.registrations.find(
      (entry) => entry.registrationId === "repo-main",
    )?.path;
    const remotePath = described.registrations.find(
      (entry) => entry.registrationId === "remote-main",
    )?.path;
    expect(repoPath).toBeDefined();
    expect(remotePath).toBeDefined();
    expect(
      readFileSync(
        join(described.rootPath, "metadata", "root-manifest.json"),
        "utf8",
      ),
    ).toContain('"runId":"run-1"');

    await harness.close();
    const recovered = await recoverFixtureRepositoryHarnessV1(policy, {
      runId: "run-1",
      taskId: "task-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });
    const recoveredDescription = __testOnlyDescribeFixtureHarnessV1(recovered);
    expect(
      recoveredDescription.registrations
        .map((entry) => entry.registrationId)
        .sort(),
    ).toEqual(["remote-main", "repo-main"]);

    await recovered.close();
    await recovered.cleanup();
    rmSync(parent, { recursive: true, force: true });
  });

  it("blocks duplicate bare-remote registration ids before any effect", async () => {
    const { parent, harness } = await createHarnessWithRepository();
    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const registrationDigest = registrationDigestV1({
      registrationId: "repo-main",
    });
    const remotePath = join(
      described.rootPath,
      "remotes",
      `${registrationDigest}.git`,
    );

    const remote = await harness.createBareRemote({
      operationId: "remote-duplicate-registration-1",
      registrationId: "repo-main",
      sourceRegistrationId: "repo-main",
    });
    expect(remote.outcome).toBe("blocked");
    expect(remote.diagnostic?.code).toBe("registration-conflict");
    expect(existsSync(remotePath)).toBe(false);

    rmSync(parent, { recursive: true, force: true });
  });

  it("redacts bare-remote storage collisions and retains recovery evidence", async () => {
    const parent = createTrustedParent();
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-remote-storage-1",
      taskId: "task-remote-storage-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });
    const repository = await harness.createRepository({
      operationId: "repo-remote-storage-1",
      registrationId: "repo-remote-storage-main",
      files: [
        {
          pathComponents: ["named-check-fixture.txt"],
          mode: "100644",
          content: new TextEncoder().encode("original\n"),
        },
      ],
    });
    expect(repository.outcome).toBe("applied");

    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const registrationDigest = registrationDigestV1({
      registrationId: "remote-storage-main",
    });
    const registrationDir = join(
      described.rootPath,
      "metadata",
      "registrations",
      registrationDigest,
    );
    mkdirSync(registrationDir, { recursive: true, mode: 0o700 });
    writeFileSync(
      join(registrationDir, "1.json"),
      JSON.stringify(
        createRegistrationRecordV1({
          registrationId: "remote-storage-main",
          sourceRegistrationId: "repo-remote-storage-main",
          role: "fixture-remote",
          checkId: null,
          candidateCommit: repository.post!.headCommit,
          candidateTree: repository.post!.headTree,
          commonDirectoryDigest: "d".repeat(64),
          workspacePathDigest: "e".repeat(64),
          adminDirectoryDigest: "f".repeat(64),
          state: "retained",
          generation: 1,
          previousDigest: null,
        }),
      ),
      "utf8",
    );

    await expect(
      harness.createBareRemote({
        operationId: "remote-storage-collision-1",
        registrationId: "remote-storage-main",
        sourceRegistrationId: "repo-remote-storage-main",
      }),
    ).rejects.toThrow(/storage unavailable/i);

    const remotePath = join(
      described.rootPath,
      "remotes",
      `${registrationDigest}.git`,
    );
    expect(existsSync(remotePath)).toBe(true);

    const recovered = await recoverFixtureRepositoryHarnessV1(policy, {
      runId: "run-remote-storage-1",
      taskId: "task-remote-storage-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });
    const replay = await recovered.createBareRemote({
      operationId: "remote-storage-collision-1",
      registrationId: "remote-storage-main",
      sourceRegistrationId: "repo-remote-storage-main",
    });
    expect(replay.outcome).toBe("blocked");
    expect(replay.diagnostic?.code).toBe("outcome-unknown");

    rmSync(parent, { recursive: true, force: true });
  });

  it("rejects duplicate same-run roots and ambiguous recovery matches", async () => {
    const parent = createTrustedParent();
    const policy = createPolicy(parent);
    const options = {
      runId: "run-dupe",
      taskId: "task-dupe",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    };
    const harness = await createFixtureRepositoryHarnessV1(policy, options);
    await expect(
      createFixtureRepositoryHarnessV1(policy, options),
    ).rejects.toThrow(/run identity/i);

    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    cpSync(described.rootPath, join(parent, "copied-root"), {
      recursive: true,
    });
    await expect(
      recoverFixtureRepositoryHarnessV1(policy, options),
    ).rejects.toThrow(/run identity/i);

    rmSync(parent, { recursive: true, force: true });
  });

  it("detects index-only mutation before a passing named check result", async () => {
    const { parent, harness, repository } = await createHarnessWithRepository();
    await harness.createWorktree({
      operationId: "worktree-index-only-1",
      registrationId: "check-index-only-1",
      sourceRegistrationId: "repo-main",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const checkPath = described.registrations.find(
      (entry) => entry.registrationId === "check-index-only-1",
    )?.path;
    expect(checkPath).toBeDefined();

    const permit = await harness.issueNamedCheckPermitV1({
      operationId: "named-check-index-only-1",
      registrationId: "check-index-only-1",
      checkId: "fixture-pass",
      attempt: 1,
    });
    const blobId = spawnSync(
      gitExecutable(),
      ["-C", checkPath!, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "ghost\n" },
    ).stdout.trim();
    expect(blobId).toMatch(/^[a-f0-9]{64}$/);
    expect(
      spawnSync(
        gitExecutable(),
        [
          "-C",
          checkPath!,
          "update-index",
          "--add",
          "--cacheinfo",
          "100644",
          blobId,
          "ghost.txt",
        ],
        { encoding: "utf8" },
      ).status,
    ).toBe(0);

    const result = await runExactNamedCheckV1({ permit });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.value.outcome).toBe("mutation-detected");
      expect(result.value.diagnostic?.code).toBe("workspace-mutated");
    }

    rmSync(parent, { recursive: true, force: true });
  });

  it("cancels active named checks promptly and blocks later issuance", async () => {
    const { parent, harness, repository } = await createHarnessWithRepository();
    await harness.createWorktree({
      operationId: "worktree-cancel-1",
      registrationId: "check-cancel-1",
      sourceRegistrationId: "repo-main",
      role: "named-check",
      checkId: "fixture-hang",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });

    const startedAt = Date.now();
    const running = harness.runNamedCheckV1({
      operationId: "named-check-cancel-1",
      registrationId: "check-cancel-1",
      checkId: "fixture-hang",
      attempt: 1,
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    await harness.cancel();
    const result = await running;
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.value.outcome).toBe("cancelled");
      expect(result.value.diagnostic?.code).toBe("cancelled");
    }
    expect(Date.now() - startedAt).toBeLessThan(1_500);
    await expect(
      harness.issueNamedCheckPermitV1({
        operationId: "named-check-cancel-2",
        registrationId: "check-cancel-1",
        checkId: "fixture-hang",
        attempt: 2,
      }),
    ).rejects.toThrow(/fixture policy/i);

    rmSync(parent, { recursive: true, force: true });
  }, 20_000);

  it("fails named-check replay conflicts closed instead of fabricating valid results", async () => {
    const { parent, harness, repository } = await createHarnessWithRepository();
    await harness.createWorktree({
      operationId: "worktree-check-replay-1",
      registrationId: "check-replay-1",
      sourceRegistrationId: "repo-main",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: repository.post!.headCommit,
      candidateTree: repository.post!.headTree,
    });
    const first = await harness.runNamedCheckV1({
      operationId: "check-op",
      registrationId: "check-replay-1",
      checkId: "fixture-pass",
      attempt: 1,
    });
    expect(first.valid).toBe(true);
    const conflict = await harness.runNamedCheckV1({
      operationId: "check-op",
      registrationId: "check-replay-1",
      checkId: "fixture-pass",
      attempt: 2,
    });
    expect(conflict.valid).toBe(false);
    if (!conflict.valid) {
      expect(conflict.errors[0]?.code).toBe("operation-replay-conflict");
    }
    rmSync(parent, { recursive: true, force: true });
  });

  it("rejects undeclared git config before later operations", async () => {
    const { parent, harness } = await createHarnessWithRepository();
    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const repoPath = described.registrations.find(
      (entry) => entry.registrationId === "repo-main",
    )?.path;
    expect(repoPath).toBeDefined();
    writeFileSync(
      join(repoPath!, ".git", "config"),
      `${readFileSync(join(repoPath!, ".git", "config"), "utf8")}\n[alias]\n\tzzz = status\n`,
      "utf8",
    );
    await expect(harness.inspectWorktrees("inspect-alias-1")).rejects.toThrow(
      /repository identity drift/i,
    );
    rmSync(parent, { recursive: true, force: true });
  });

  it("writes staged immutable ledger records and recovers prepared or unknown operations", async () => {
    const parent = createTrustedParent();
    const policy = createPolicy(parent);
    const harness = await createFixtureRepositoryHarnessV1(policy, {
      runId: "run-ledger-1",
      taskId: "task-ledger-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });
    const repo = await harness.createRepository({
      operationId: "repo-ledger-1",
      registrationId: "repo-ledger-main",
      files: [
        {
          pathComponents: ["README.md"],
          mode: "100644",
          content: new TextEncoder().encode("fixture\n"),
        },
      ],
    });
    expect(repo.outcome).toBe("applied");
    const described = __testOnlyDescribeFixtureHarnessV1(harness);
    const operationRoots = readdirSync(
      join(described.rootPath, "metadata", "operations"),
    );
    const stageFiles = readdirSync(
      join(described.rootPath, "metadata", "operations", operationRoots[0]!),
    ).sort();
    expect(stageFiles).toEqual([
      "000001-prepared.json",
      "000002-effect-started.json",
      "000003-effect-observed.json",
      "000004-completed.json",
    ]);

    __testOnlySetFixtureFaultV1(harness, "create-repository:after-prepared");
    await expect(
      harness.createRepository({
        operationId: "repo-ledger-prepared",
        registrationId: "repo-ledger-prepared",
        files: [
          {
            pathComponents: ["file.txt"],
            mode: "100644",
            content: new TextEncoder().encode("x"),
          },
        ],
      }),
    ).rejects.toThrow(/fixture injected fault/i);
    const recoveredPrepared = await recoverFixtureRepositoryHarnessV1(policy, {
      runId: "run-ledger-1",
      taskId: "task-ledger-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });
    const preparedReplay = await recoveredPrepared.createRepository({
      operationId: "repo-ledger-prepared",
      registrationId: "repo-ledger-prepared",
      files: [
        {
          pathComponents: ["file.txt"],
          mode: "100644",
          content: new TextEncoder().encode("x"),
        },
      ],
    });
    expect(preparedReplay.outcome).toBe("not-applied");

    const recoveredDesc = __testOnlyDescribeFixtureHarnessV1(recoveredPrepared);
    const repoMainPath = recoveredDesc.registrations.find(
      (entry) => entry.registrationId === "repo-ledger-main",
    )?.path;
    const headCommit = spawnSync(
      gitExecutable(),
      ["-C", repoMainPath!, "rev-parse", "HEAD^{commit}"],
      { encoding: "utf8" },
    ).stdout.trim();
    const headTree = spawnSync(
      gitExecutable(),
      ["-C", repoMainPath!, "rev-parse", "HEAD^{tree}"],
      { encoding: "utf8" },
    ).stdout.trim();
    await recoveredPrepared.createWorktree({
      operationId: "worktree-ledger-check",
      registrationId: "check-ledger-1",
      sourceRegistrationId: "repo-ledger-main",
      role: "named-check",
      checkId: "fixture-pass",
      candidateCommit: headCommit,
      candidateTree: headTree,
    });
    __testOnlySetFixtureFaultV1(
      recoveredPrepared,
      "named-check:after-effect-started",
    );
    await expect(
      recoveredPrepared.runNamedCheckV1({
        operationId: "named-check-ledger-1",
        registrationId: "check-ledger-1",
        checkId: "fixture-pass",
        attempt: 1,
      }),
    ).rejects.toThrow(/fixture injected fault/i);
    const recoveredUnknown = await recoverFixtureRepositoryHarnessV1(policy, {
      runId: "run-ledger-1",
      taskId: "task-ledger-1",
      expectedBaseCommit: "a".repeat(64),
      expectedBaseTree: "b".repeat(64),
    });
    const unknown = await recoveredUnknown.runNamedCheckV1({
      operationId: "named-check-ledger-1",
      registrationId: "check-ledger-1",
      checkId: "fixture-pass",
      attempt: 1,
    });
    expect(unknown.valid).toBe(true);
    if (unknown.valid) {
      expect(unknown.value.outcome).toBe("outcome-unknown");
      expect(unknown.value.diagnostic?.code).toBe("outcome-unknown");
    }
    rmSync(parent, { recursive: true, force: true });
  }, 20_000);
});

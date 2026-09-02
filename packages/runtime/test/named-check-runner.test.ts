import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawn, spawnSync, type SpawnOptions } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  createNamedCheckAuthorityV1,
  issueNamedCheckPermitV1,
  runExactNamedCheckV1,
  type NamedCheckRepositoryObservationV1,
} from "../src/named-check-runner.js";
import {
  CLEAN_REPOSITORY_DIGESTS_V1,
  computeGitCheckFixtureDigestV1,
  type NamedCheckResultV1,
  type ValidationResult,
} from "@scrum-pi-team-skills/contracts";
import { createNodeProcessAdapter } from "../src/process-host.js";

const fixtureScriptPath = new URL("./fixtures/named-check.mjs", import.meta.url)
  .pathname;
const emptyDigest = createHash("sha256").digest("hex");

function requireValid(
  result: ValidationResult<NamedCheckResultV1>,
): NamedCheckResultV1 {
  if (!result.valid) {
    throw new Error(JSON.stringify(result.errors));
  }
  return result.value;
}

const workspaceBindings = new WeakMap<
  object,
  { readonly cwd: string; readonly homeDirectory: string }
>();

function bindWorkspaceExecution(root: string): object {
  const token = {};
  workspaceBindings.set(token, {
    cwd: root,
    homeDirectory: join(root, "home"),
  });
  return token;
}

function workspaceObservation(
  path: string,
  overrides?: Partial<NamedCheckRepositoryObservationV1>,
): NamedCheckRepositoryObservationV1 {
  const file = join(path, "named-check-fixture.txt");
  const content = readFileSync(file, "utf8");
  const sentinelDigest = createHash("sha256")
    .update(content)
    .update(String(readFileSync(file).byteLength))
    .digest("hex");
  return {
    repositoryIdentity: {
      commonDirectoryDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-common-directory/1.0.0",
        path,
      ),
      objectFormat: "sha256",
      ...overrides?.repositoryIdentity,
    },
    state: {
      headCommit: "a".repeat(64),
      headTree: "b".repeat(64),
      branch: null,
      detached: true,
      clean: true,
      indexDigest: CLEAN_REPOSITORY_DIGESTS_V1.indexDigest,
      trackedWorktreeDigest: CLEAN_REPOSITORY_DIGESTS_V1.trackedWorktreeDigest,
      untrackedSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.untrackedSetDigest,
      ignoredSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.ignoredSetDigest,
      conflictSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.conflictSetDigest,
      submoduleSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.submoduleSetDigest,
      filesystemSentinelDigest: sentinelDigest,
      worktreeSetDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-worktree-set/1.0.0",
        [],
      ),
      ...overrides?.state,
    },
    workspaceSentinelDigest: sentinelDigest,
    ...overrides,
  };
}

function createWorkspace(): { readonly root: string; cleanup(): void } {
  const root = mkdtempSync(join(tmpdir(), "named-check-runner-"));
  mkdirSync(join(root, "home"), { recursive: true });
  writeFileSync(join(root, "named-check-fixture.txt"), "original\n", "utf8");
  return {
    root,
    cleanup() {
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function createAuthority() {
  return createNamedCheckAuthorityV1({
    policyId: "policy-1",
    resolveWorkspaceExecution: (workspaceIdentityToken: object) => {
      const binding = workspaceBindings.get(workspaceIdentityToken);
      if (!binding) throw new TypeError("missing workspace binding");
      return binding;
    },
    checks: [
      {
        checkId: "fixture-pass",
        executable: process.execPath,
        argv: [fixtureScriptPath, "pass"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-fail",
        executable: process.execPath,
        argv: [fixtureScriptPath, "fail"],
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
      {
        checkId: "fixture-mutate-restore",
        executable: process.execPath,
        argv: [fixtureScriptPath, "mutate-restore"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-hang",
        executable: process.execPath,
        argv: [fixtureScriptPath, "hang"],
        maxDurationMs: 250,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-descendant",
        executable: process.execPath,
        argv: [fixtureScriptPath, "spawn-descendant"],
        maxDurationMs: 1_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-overflow",
        executable: process.execPath,
        argv: [fixtureScriptPath, "emit-overflow"],
        maxDurationMs: 5_000,
        maxOutputBytes: 16 * 1024,
      },
    ],
  });
}

describe("named-check-runner", () => {
  it("runs an exact passing fixture with fixed spawn options", async () => {
    const workspace = createWorkspace();
    const authority = createAuthority();
    const before = workspaceObservation(workspace.root);
    let captured:
      | {
          readonly executable: string;
          readonly argv: readonly string[];
          readonly options: SpawnOptions;
        }
      | undefined;
    const nodeAdapter = createNodeProcessAdapter();
    const processAdapter = {
      ...nodeAdapter,
      spawn(
        executable: string,
        argv: readonly string[],
        options: SpawnOptions,
      ) {
        captured = { executable, argv: [...argv], options };
        return spawn(executable, [...argv], options) as ReturnType<
          typeof nodeAdapter.spawn
        >;
      },
    };
    const permit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-pass-1",
        runId: "run-1",
        registrationId: "reg-1",
        checkId: "fixture-pass",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(workspace.root),
        requestDigest: "c".repeat(64),
      },
      {
        beforeObservation: before,
        observeAfter: () => workspaceObservation(workspace.root),
      },
    );

    const result = await runExactNamedCheckV1({
      permit,
      processAdapter,
    });
    const value = requireValid(result);

    expect(result.valid).toBe(true);
    expect(value.outcome).toBe("passed");
    expect(value.exitCode).toBe(0);
    expect(value.stdoutBytes).toBeGreaterThan(0);
    expect(value.stderrBytes).toBe(0);
    expect(value.workspaceTreeBefore).toBe("b".repeat(64));
    expect(value.workspaceTreeAfter).toBe("b".repeat(64));
    expect(value.stdoutDigest).not.toBe(emptyDigest);
    expect(captured).toMatchObject({
      executable: process.execPath,
      argv: [fixtureScriptPath, "pass"],
      options: {
        cwd: workspace.root,
        shell: false,
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
      },
    });
    expect(Object.keys(captured?.options.env ?? {}).sort()).toEqual([
      "CI",
      "GCM_INTERACTIVE",
      "GIT_ASKPASS",
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "GIT_PAGER",
      "GIT_TERMINAL_PROMPT",
      "HOME",
      "LANG",
      "LC_ALL",
      "NO_COLOR",
      "PAGER",
      "SSH_ASKPASS",
      "TZ",
      "XDG_CONFIG_HOME",
    ]);

    workspace.cleanup();
  }, 15_000);

  it("rejects public cwd, home, and environment override attempts", async () => {
    const workspace = createWorkspace();
    const evilRoot = createWorkspace();
    const authority = createAuthority();
    const before = workspaceObservation(workspace.root);
    let captured:
      | {
          readonly executable: string;
          readonly argv: readonly string[];
          readonly options: SpawnOptions;
        }
      | undefined;
    const nodeAdapter = createNodeProcessAdapter();
    const processAdapter = {
      ...nodeAdapter,
      spawn(
        executable: string,
        argv: readonly string[],
        options: SpawnOptions,
      ) {
        captured = { executable, argv: [...argv], options };
        return spawn(executable, [...argv], options) as ReturnType<
          typeof nodeAdapter.spawn
        >;
      },
    };

    const permit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-override-1",
        runId: "run-1",
        registrationId: "reg-override",
        checkId: "fixture-pass",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(workspace.root),
        requestDigest: "7".repeat(64),
      },
      {
        beforeObservation: before,
        observeAfter: () => before,
        cwd: evilRoot.root,
        homeDirectory: join(evilRoot.root, "home"),
        environment: {
          HOME: evilRoot.root,
          XDG_CONFIG_HOME: join(evilRoot.root, "home"),
          GIT_TERMINAL_PROMPT: "1",
        },
      } as never,
    );

    const result = await runExactNamedCheckV1({ permit, processAdapter });
    const value = requireValid(result);
    expect(value.outcome).toBe("passed");
    expect(captured?.options.cwd).toBe(workspace.root);
    expect(captured?.options.env?.HOME).toBe(join(workspace.root, "home"));
    expect(captured?.options.env?.GIT_TERMINAL_PROMPT).toBe("0");

    workspace.cleanup();
    evilRoot.cleanup();
  });

  it("treats index-only repository drift as mutation-detected", async () => {
    const workspace = createWorkspace();
    const authority = createAuthority();
    const before = workspaceObservation(workspace.root);
    const permit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-index-only-1",
        runId: "run-1",
        registrationId: "reg-index-only",
        checkId: "fixture-pass",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(workspace.root),
        requestDigest: "8".repeat(64),
      },
      {
        beforeObservation: before,
        observeAfter: () => ({
          repositoryIdentity: before.repositoryIdentity,
          state: {
            ...before.state,
            clean: false,
            indexDigest: computeGitCheckFixtureDigestV1(
              "spts.fixture-index/1.0.0",
              [{ pathDigest: "ghost" }],
            ),
          },
        }),
      },
    );

    const result = await runExactNamedCheckV1({ permit });
    const value = requireValid(result);
    expect(value.outcome).toBe("mutation-detected");
    expect(value.diagnostic?.code).toBe("workspace-mutated");

    workspace.cleanup();
  });

  it("classifies failure, timeout, mutation, and descendant cleanup safely", async () => {
    const authority = createAuthority();

    const failureWorkspace = createWorkspace();
    const failurePermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-fail-1",
        runId: "run-1",
        registrationId: "reg-fail",
        checkId: "fixture-fail",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(failureWorkspace.root),
        requestDigest: "d".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(failureWorkspace.root),
        observeAfter: () => workspaceObservation(failureWorkspace.root),
      },
    );
    const failed = await runExactNamedCheckV1({ permit: failurePermit });
    const failedValue = requireValid(failed);
    expect(failed.valid).toBe(true);
    expect(failedValue.outcome).toBe("failed");
    expect(failedValue.exitCode).toBe(23);
    expect(failedValue.signal).toBe(null);
    failureWorkspace.cleanup();

    const timeoutWorkspace = createWorkspace();
    const timeoutPermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-hang-1",
        runId: "run-1",
        registrationId: "reg-timeout",
        checkId: "fixture-hang",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(timeoutWorkspace.root),
        requestDigest: "e".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(timeoutWorkspace.root),
        observeAfter: () => workspaceObservation(timeoutWorkspace.root),
      },
    );
    const timedOut = await runExactNamedCheckV1({ permit: timeoutPermit });
    const timedOutValue = requireValid(timedOut);
    expect(timedOut.valid).toBe(true);
    expect(timedOutValue.outcome).toBe("timed-out");
    expect(timedOutValue.diagnostic?.code).toBe("check-timed-out");
    timeoutWorkspace.cleanup();

    const mutateWorkspace = createWorkspace();
    const mutatePermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-mutate-1",
        runId: "run-1",
        registrationId: "reg-mutate",
        checkId: "fixture-mutate",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(mutateWorkspace.root),
        requestDigest: "f".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(mutateWorkspace.root),
        observeAfter: () => workspaceObservation(mutateWorkspace.root),
      },
    );
    const mutated = await runExactNamedCheckV1({ permit: mutatePermit });
    const mutatedValue = requireValid(mutated);
    expect(mutated.valid).toBe(true);
    expect(mutatedValue.outcome).toBe("mutation-detected");
    expect(mutatedValue.diagnostic?.code).toBe("workspace-mutated");
    mutateWorkspace.cleanup();

    const restoreWorkspace = createWorkspace();
    const beforeRestore = workspaceObservation(restoreWorkspace.root);
    const restorePermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-restore-1",
        runId: "run-1",
        registrationId: "reg-restore",
        checkId: "fixture-mutate-restore",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(restoreWorkspace.root),
        requestDigest: "1".repeat(64),
      },
      {
        beforeObservation: beforeRestore,
        observeAfter: () => ({
          repositoryIdentity: beforeRestore.repositoryIdentity,
          state: beforeRestore.state,
          workspaceSentinelDigest: `${beforeRestore.workspaceSentinelDigest?.slice(0, 63) ?? ""}0`,
        }),
      },
    );
    const restoredMutation = await runExactNamedCheckV1({
      permit: restorePermit,
    });
    const restoredValue = requireValid(restoredMutation);
    expect(restoredMutation.valid).toBe(true);
    expect(restoredValue.outcome).toBe("mutation-detected");
    restoreWorkspace.cleanup();

    const descendantWorkspace = createWorkspace();
    const descendantPermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-descendant-1",
        runId: "run-1",
        registrationId: "reg-descendant",
        checkId: "fixture-descendant",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(
          descendantWorkspace.root,
        ),
        requestDigest: "2".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(descendantWorkspace.root),
        observeAfter: () => workspaceObservation(descendantWorkspace.root),
      },
    );
    const descendant = await runExactNamedCheckV1({ permit: descendantPermit });
    const descendantValue = requireValid(descendant);
    expect(descendant.valid).toBe(true);
    expect(descendantValue.outcome).toBe("outcome-unknown");
    const descendantScan = spawnSync(
      "bash",
      [
        "-lc",
        "pgrep -af '__SPTS_NAMED_CHECK_DESCENDANT__' | grep -v 'pgrep -af' | grep -v 'npx vitest run' || true",
      ],
      { encoding: "utf8" },
    );
    expect(descendantScan.stdout.trim()).toBe("");
    descendantWorkspace.cleanup();
  });

  it("fails closed when observeAfter throws or rejects", async () => {
    const authority = createAuthority();

    const syncWorkspace = createWorkspace();
    const syncPermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-observe-sync-1",
        runId: "run-1",
        registrationId: "reg-observe-sync",
        checkId: "fixture-pass",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(syncWorkspace.root),
        requestDigest: "5".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(syncWorkspace.root),
        observeAfter: () => {
          const secret = ["api_key", "sk-secret"].join("=");
          throw new Error(`boom observeAfter secret ${secret}`);
        },
      },
    );
    const syncResult = await runExactNamedCheckV1({ permit: syncPermit });
    const syncValue = requireValid(syncResult);
    expect(syncValue.outcome).toBe("outcome-unknown");
    expect(syncValue.diagnostic?.code).toBe("outcome-unknown");
    expect(JSON.stringify(syncValue)).not.toContain("sk-secret");
    syncWorkspace.cleanup();

    const asyncWorkspace = createWorkspace();
    const asyncPermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-observe-async-1",
        runId: "run-1",
        registrationId: "reg-observe-async",
        checkId: "fixture-pass",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(asyncWorkspace.root),
        requestDigest: "6".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(asyncWorkspace.root),
        observeAfter: async () => {
          const secret = ["api_key", "sk-secret"].join("=");
          throw new Error(`boom observeAfter secret ${secret}`);
        },
      },
    );
    const asyncResult = await runExactNamedCheckV1({ permit: asyncPermit });
    const asyncValue = requireValid(asyncResult);
    expect(asyncValue.outcome).toBe("outcome-unknown");
    expect(asyncValue.diagnostic?.code).toBe("outcome-unknown");
    expect(JSON.stringify(asyncValue)).not.toContain("sk-secret");
    asyncWorkspace.cleanup();
  });

  it("supports sticky cancellation and output overflow without leaking raw output", async () => {
    const authority = createAuthority();

    const cancelledWorkspace = createWorkspace();
    const controller = new AbortController();
    const cancelledPermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-cancel-1",
        runId: "run-1",
        registrationId: "reg-cancel",
        checkId: "fixture-hang",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(cancelledWorkspace.root),
        requestDigest: "3".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(cancelledWorkspace.root),
        observeAfter: () => workspaceObservation(cancelledWorkspace.root),
      },
    );
    setTimeout(() => controller.abort(), 50);
    const cancelled = await runExactNamedCheckV1({
      permit: cancelledPermit,
      signal: controller.signal,
    });
    const cancelledValue = requireValid(cancelled);
    expect(cancelled.valid).toBe(true);
    expect(cancelledValue.outcome).toBe("cancelled");
    expect(cancelledValue.diagnostic?.code).toBe("cancelled");
    cancelledWorkspace.cleanup();

    const overflowWorkspace = createWorkspace();
    const overflowPermit = issueNamedCheckPermitV1(
      authority,
      {
        operationId: "check-overflow-1",
        runId: "run-1",
        registrationId: "reg-overflow",
        checkId: "fixture-overflow",
        attempt: 1,
        candidateCommit: "a".repeat(64),
        candidateTree: "b".repeat(64),
        workspaceIdentityToken: bindWorkspaceExecution(overflowWorkspace.root),
        requestDigest: "4".repeat(64),
      },
      {
        beforeObservation: workspaceObservation(overflowWorkspace.root),
        observeAfter: () => workspaceObservation(overflowWorkspace.root),
      },
    );
    const overflow = await runExactNamedCheckV1({ permit: overflowPermit });
    const overflowValue = requireValid(overflow);
    expect(overflow.valid).toBe(true);
    expect(overflowValue.outcome).toBe("outcome-unknown");
    expect(JSON.stringify(overflowValue)).not.toContain("x".repeat(32));
    overflowWorkspace.cleanup();
  });
});

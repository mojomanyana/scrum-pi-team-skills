import { spawn, spawnSync, type SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  CLEAN_REPOSITORY_DIGESTS_V1,
  computeGitCheckFixtureDigestV1,
  type NamedCheckResultV1,
  type ValidationResult,
} from "@scrum-pi-team-skills/contracts";

import {
  createNamedCheckAuthorityV1,
  issueNamedCheckPermitV1,
  runExactNamedCheckV1,
  type NamedCheckPermitV1,
  type NamedCheckRepositoryObservationV1,
} from "../src/named-check-runner.js";
import {
  createNodeProcessAdapter,
  type ProcessAdapter,
} from "../src/process-host.js";

const fixtureScriptPath = new URL("./fixtures/named-check.mjs", import.meta.url)
  .pathname;
const trustedCheckRoot = mkdtempSync(
  join(tmpdir(), "named-check-trusted-executable-"),
);
chmodSync(trustedCheckRoot, 0o700);
const trustedCheckExecutable = join(trustedCheckRoot, "named-check.mjs");
writeFileSync(
  trustedCheckExecutable,
  [
    `#!${process.execPath}`,
    `await import(${JSON.stringify(new URL(`file://${fixtureScriptPath}`).href)});`,
  ].join("\n"),
  { encoding: "utf8", mode: 0o755 },
);
chmodSync(trustedCheckExecutable, 0o755);
const emptyDigest = createHash("sha256").digest("hex");
const candidateCommit = "a".repeat(64);
const candidateTree = "b".repeat(64);
const defaultWorkspaceContent = "original\n";
const textEncoder = new TextEncoder();

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

function sentinelDigestFor(value: string): string {
  return createHash("sha256")
    .update(value)
    .update(String(Buffer.byteLength(value, "utf8")))
    .digest("hex");
}

function buildObservation(
  path: string,
  sentinelDigest: string,
  overrides?: Partial<NamedCheckRepositoryObservationV1>,
): NamedCheckRepositoryObservationV1 {
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
      headCommit: candidateCommit,
      headTree: candidateTree,
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
    adminSentinelDigest: sentinelDigest,
    ...overrides,
  };
}

function workspaceObservation(
  path: string,
  overrides?: Partial<NamedCheckRepositoryObservationV1>,
): NamedCheckRepositoryObservationV1 {
  const content = readFileSync(join(path, "named-check-fixture.txt"), "utf8");
  return buildObservation(path, sentinelDigestFor(content), overrides);
}

function syntheticObservation(
  label: string,
  overrides?: Partial<NamedCheckRepositoryObservationV1>,
): NamedCheckRepositoryObservationV1 {
  const root = join(tmpdir(), `named-check-runner-synthetic-${label}`);
  return buildObservation(
    root,
    sentinelDigestFor(`synthetic:${label}`),
    overrides,
  );
}

function createWorkspace(): { readonly root: string; cleanup(): void } {
  const root = mkdtempSync(join(tmpdir(), "named-check-runner-"));
  mkdirSync(join(root, "home"), { recursive: true });
  writeFileSync(
    join(root, "named-check-fixture.txt"),
    defaultWorkspaceContent,
    "utf8",
  );
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
        executable: trustedCheckExecutable,
        argv: ["pass"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-fail",
        executable: trustedCheckExecutable,
        argv: ["fail"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-mutate",
        executable: trustedCheckExecutable,
        argv: ["mutate"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-mutate-restore",
        executable: trustedCheckExecutable,
        argv: ["mutate-restore"],
        maxDurationMs: 5_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-hang",
        executable: trustedCheckExecutable,
        argv: ["hang"],
        maxDurationMs: 250,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-descendant",
        executable: trustedCheckExecutable,
        argv: ["spawn-descendant"],
        maxDurationMs: 1_000,
        maxOutputBytes: 1_048_576,
      },
      {
        checkId: "fixture-overflow",
        executable: trustedCheckExecutable,
        argv: ["emit-overflow"],
        maxDurationMs: 5_000,
        maxOutputBytes: 16 * 1024,
      },
    ],
  });
}

const authority = createAuthority();
const heavySuiteLockPath = join(tmpdir(), "spts10-s5-heavy-suite.lock");
const heavySuiteOwnerPath = join(heavySuiteLockPath, "owner.json");

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

interface PermitOptions {
  readonly operationId: string;
  readonly registrationId: string;
  readonly checkId: string;
  readonly requestDigest: string;
  readonly root: string;
  readonly beforeObservation: NamedCheckRepositoryObservationV1;
  readonly observeAfter?: () =>
    | NamedCheckRepositoryObservationV1
    | Promise<NamedCheckRepositoryObservationV1>;
}

function issuePermit(options: PermitOptions): NamedCheckPermitV1 {
  return issueNamedCheckPermitV1(
    authority,
    {
      operationId: options.operationId,
      runId: "run-1",
      registrationId: options.registrationId,
      checkId: options.checkId,
      attempt: 1,
      candidateCommit,
      candidateTree,
      workspaceIdentityToken: bindWorkspaceExecution(options.root),
      requestDigest: options.requestDigest,
    },
    {
      beforeObservation: options.beforeObservation,
      observeAfter: options.observeAfter ?? (() => options.beforeObservation),
    },
  );
}

interface ScriptedProcessPlan {
  readonly stdoutChunks?: readonly Uint8Array[];
  readonly stderrChunks?: readonly Uint8Array[];
  readonly exitCode?: number | null;
  readonly signal?: NodeJS.Signals | null;
  readonly close: "spawn" | "SIGTERM" | "SIGKILL";
  readonly keepAliveAfterClose?: boolean;
  readonly aliveAfterSignal?: Partial<Record<"SIGTERM" | "SIGKILL", boolean>>;
}

function createScriptedProcessAdapter(
  plan: ScriptedProcessPlan,
  capture?: (spawn: {
    readonly executable: string;
    readonly argv: readonly string[];
    readonly options: SpawnOptions;
  }) => void,
): ProcessAdapter {
  const pid = 42_000;
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const emitter = new EventEmitter();
  let alive = true;
  let closed = false;

  const emitClose = () => {
    if (closed) return;
    closed = true;
    if (!plan.keepAliveAfterClose) alive = false;
    queueMicrotask(() => {
      stdout.end();
      stderr.end();
      emitter.emit("close", plan.exitCode ?? 0, plan.signal ?? null);
    });
  };

  const child = Object.assign(emitter, {
    pid,
    stdout,
    stderr,
  }) as unknown as ReturnType<ProcessAdapter["spawn"]>;

  return {
    platform: "linux",
    spawn(executable, argv, options) {
      capture?.({ executable, argv: [...argv], options });
      queueMicrotask(() => {
        for (const chunk of plan.stdoutChunks ?? []) stdout.write(chunk);
        for (const chunk of plan.stderrChunks ?? []) stderr.write(chunk);
        if (plan.close === "spawn") emitClose();
      });
      return child;
    },
    isProcessGroupAlive() {
      return alive;
    },
    killProcessGroup(_processGroupId, signal) {
      alive = plan.aliveAfterSignal?.[signal] ?? false;
      if (plan.close === signal) emitClose();
    },
  };
}

beforeAll(async () => {
  await new Promise((resolve) => setTimeout(resolve, 15_000));
  releaseHeavySuiteLock = await acquireHeavySuiteLock(
    new URL(import.meta.url).pathname,
  );
}, 120_000);

afterAll(() => {
  releaseHeavySuiteLock?.();
  releaseHeavySuiteLock = undefined;
  rmSync(trustedCheckRoot, { recursive: true, force: true });
});

describe("named-check-runner", () => {
  it("runs an exact passing fixture with fixed spawn options", async () => {
    const workspace = createWorkspace();
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
    const permit = issuePermit({
      operationId: "check-pass-1",
      registrationId: "reg-1",
      checkId: "fixture-pass",
      requestDigest: "c".repeat(64),
      root: workspace.root,
      beforeObservation: before,
      observeAfter: () => workspaceObservation(workspace.root),
    });

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
    expect(value.workspaceTreeBefore).toBe(candidateTree);
    expect(value.workspaceTreeAfter).toBe(candidateTree);
    expect(value.stdoutDigest).not.toBe(emptyDigest);
    expect(captured).toMatchObject({
      executable: trustedCheckExecutable,
      argv: ["pass"],
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
    const before = workspaceObservation(workspace.root);
    let captured:
      | {
          readonly executable: string;
          readonly argv: readonly string[];
          readonly options: SpawnOptions;
        }
      | undefined;
    const permit = issuePermit({
      operationId: "check-override-1",
      registrationId: "reg-override",
      checkId: "fixture-pass",
      requestDigest: "7".repeat(64),
      root: workspace.root,
      beforeObservation: before,
      observeAfter: () => before,
    });

    const result = await runExactNamedCheckV1({
      permit,
      processAdapter: createScriptedProcessAdapter(
        {
          close: "spawn",
          stdoutChunks: [textEncoder.encode("fixture-pass\n")],
        },
        (spawn) => {
          captured = spawn;
        },
      ),
    });
    const value = requireValid(result);
    expect(value.outcome).toBe("passed");
    expect(captured?.options.cwd).toBe(workspace.root);
    expect(captured?.options.env?.HOME).toBe(join(workspace.root, "home"));
    expect(captured?.options.env?.GIT_TERMINAL_PROMPT).toBe("0");
    expect(captured?.options.env?.HOME).not.toBe(evilRoot.root);

    workspace.cleanup();
    evilRoot.cleanup();
  });

  it("treats admin sentinel drift as mutation-detected", async () => {
    const before = syntheticObservation("admin-sentinel");
    const permit = issuePermit({
      operationId: "check-admin-sentinel-1",
      registrationId: "reg-admin-sentinel",
      checkId: "fixture-pass",
      requestDigest: "9".repeat(64),
      root: join(tmpdir(), "named-check-runner-admin-sentinel"),
      beforeObservation: before,
      observeAfter: () => ({
        repositoryIdentity: before.repositoryIdentity,
        state: before.state,
        workspaceSentinelDigest: before.workspaceSentinelDigest,
        adminSentinelDigest: computeGitCheckFixtureDigestV1(
          "spts.fixture-filesystem-sentinel/1.0.0",
          [{ pathDigest: "admin" }],
        ),
      }),
    });

    const result = await runExactNamedCheckV1({
      permit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
        stdoutChunks: [textEncoder.encode("fixture-pass\n")],
      }),
    });
    const value = requireValid(result);
    expect(value.outcome).toBe("mutation-detected");
    expect(value.diagnostic?.code).toBe("workspace-mutated");
  });

  it("treats index-only repository drift as mutation-detected", async () => {
    const before = syntheticObservation("index-only");
    const permit = issuePermit({
      operationId: "check-index-only-1",
      registrationId: "reg-index-only",
      checkId: "fixture-pass",
      requestDigest: "8".repeat(64),
      root: join(tmpdir(), "named-check-runner-index-only"),
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
    });

    const result = await runExactNamedCheckV1({
      permit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
        stdoutChunks: [textEncoder.encode("fixture-pass\n")],
      }),
    });
    const value = requireValid(result);
    expect(value.outcome).toBe("mutation-detected");
    expect(value.diagnostic?.code).toBe("workspace-mutated");
  });

  it("classifies failure, timeout, and mutation safely via injected adapters", async () => {
    const failureBefore = syntheticObservation("failure");
    const failurePermit = issuePermit({
      operationId: "check-fail-1",
      registrationId: "reg-fail",
      checkId: "fixture-fail",
      requestDigest: "d".repeat(64),
      root: join(tmpdir(), "named-check-runner-failure"),
      beforeObservation: failureBefore,
    });
    const failed = await runExactNamedCheckV1({
      permit: failurePermit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
        exitCode: 23,
        stderrChunks: [textEncoder.encode("fixture-fail\n")],
      }),
    });
    const failedValue = requireValid(failed);
    expect(failed.valid).toBe(true);
    expect(failedValue.outcome).toBe("failed");
    expect(failedValue.exitCode).toBe(23);
    expect(failedValue.signal).toBe(null);

    const timeoutBefore = syntheticObservation("timeout");
    const timeoutPermit = issuePermit({
      operationId: "check-hang-1",
      registrationId: "reg-timeout",
      checkId: "fixture-hang",
      requestDigest: "e".repeat(64),
      root: join(tmpdir(), "named-check-runner-timeout"),
      beforeObservation: timeoutBefore,
    });
    const timedOut = await runExactNamedCheckV1({
      permit: timeoutPermit,
      processAdapter: createScriptedProcessAdapter({
        close: "SIGTERM",
      }),
    });
    const timedOutValue = requireValid(timedOut);
    expect(timedOut.valid).toBe(true);
    expect(timedOutValue.outcome).toBe("timed-out");
    expect(timedOutValue.diagnostic?.code).toBe("check-timed-out");

    const mutateBefore = syntheticObservation("mutate");
    const mutatePermit = issuePermit({
      operationId: "check-mutate-1",
      registrationId: "reg-mutate",
      checkId: "fixture-mutate",
      requestDigest: "f".repeat(64),
      root: join(tmpdir(), "named-check-runner-mutate"),
      beforeObservation: mutateBefore,
      observeAfter: () =>
        syntheticObservation("mutate-after", {
          state: {
            ...mutateBefore.state,
            filesystemSentinelDigest: sentinelDigestFor("mutated\n"),
          },
          workspaceSentinelDigest: sentinelDigestFor("mutated\n"),
          adminSentinelDigest: sentinelDigestFor("mutated\n"),
        }),
    });
    const mutated = await runExactNamedCheckV1({
      permit: mutatePermit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
      }),
    });
    const mutatedValue = requireValid(mutated);
    expect(mutated.valid).toBe(true);
    expect(mutatedValue.outcome).toBe("mutation-detected");
    expect(mutatedValue.diagnostic?.code).toBe("workspace-mutated");

    const restoreBefore = syntheticObservation("restore");
    const restorePermit = issuePermit({
      operationId: "check-restore-1",
      registrationId: "reg-restore",
      checkId: "fixture-mutate-restore",
      requestDigest: "1".repeat(64),
      root: join(tmpdir(), "named-check-runner-restore"),
      beforeObservation: restoreBefore,
      observeAfter: () => ({
        repositoryIdentity: restoreBefore.repositoryIdentity,
        state: restoreBefore.state,
        workspaceSentinelDigest: `${restoreBefore.workspaceSentinelDigest?.slice(0, 63) ?? ""}0`,
      }),
    });
    const restoredMutation = await runExactNamedCheckV1({
      permit: restorePermit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
      }),
    });
    const restoredValue = requireValid(restoredMutation);
    expect(restoredMutation.valid).toBe(true);
    expect(restoredValue.outcome).toBe("mutation-detected");
  });

  it("treats descendant-only cleanup as outcome-unknown", async () => {
    const workspace = createWorkspace();
    const permit = issuePermit({
      operationId: "check-descendant-1",
      registrationId: "reg-descendant",
      checkId: "fixture-descendant",
      requestDigest: "2".repeat(64),
      root: workspace.root,
      beforeObservation: workspaceObservation(workspace.root),
      observeAfter: () => workspaceObservation(workspace.root),
    });

    const descendant = await runExactNamedCheckV1({ permit });
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

    workspace.cleanup();
  }, 15_000);

  it("fails closed when observeAfter throws or rejects", async () => {
    const syncBefore = syntheticObservation("observe-sync");
    const syncPermit = issuePermit({
      operationId: "check-observe-sync-1",
      registrationId: "reg-observe-sync",
      checkId: "fixture-pass",
      requestDigest: "5".repeat(64),
      root: join(tmpdir(), "named-check-runner-observe-sync"),
      beforeObservation: syncBefore,
      observeAfter: () => {
        const opaque = ["fixture", "observe-redaction-value"].join("=");
        throw new Error(`boom observeAfter opaque ${opaque}`);
      },
    });
    const syncResult = await runExactNamedCheckV1({
      permit: syncPermit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
        stdoutChunks: [textEncoder.encode("fixture-pass\n")],
      }),
    });
    const syncValue = requireValid(syncResult);
    expect(syncValue.outcome).toBe("outcome-unknown");
    expect(syncValue.diagnostic?.code).toBe("outcome-unknown");
    expect(JSON.stringify(syncValue)).not.toContain("observe-redaction-value");

    const asyncBefore = syntheticObservation("observe-async");
    const asyncPermit = issuePermit({
      operationId: "check-observe-async-1",
      registrationId: "reg-observe-async",
      checkId: "fixture-pass",
      requestDigest: "6".repeat(64),
      root: join(tmpdir(), "named-check-runner-observe-async"),
      beforeObservation: asyncBefore,
      observeAfter: async () => {
        const opaque = ["fixture", "observe-redaction-value"].join("=");
        throw new Error(`boom observeAfter opaque ${opaque}`);
      },
    });
    const asyncResult = await runExactNamedCheckV1({
      permit: asyncPermit,
      processAdapter: createScriptedProcessAdapter({
        close: "spawn",
        stdoutChunks: [textEncoder.encode("fixture-pass\n")],
      }),
    });
    const asyncValue = requireValid(asyncResult);
    expect(asyncValue.outcome).toBe("outcome-unknown");
    expect(asyncValue.diagnostic?.code).toBe("outcome-unknown");
    expect(JSON.stringify(asyncValue)).not.toContain("observe-redaction-value");
  });

  it("supports sticky cancellation and output overflow without leaking raw output", async () => {
    const preAbortedController = new AbortController();
    preAbortedController.abort();
    const preAbortedPermit = issuePermit({
      operationId: "check-pre-aborted-1",
      registrationId: "reg-pre-aborted",
      checkId: "fixture-pass",
      requestDigest: "9".repeat(64),
      root: join(tmpdir(), "named-check-runner-pre-aborted"),
      beforeObservation: syntheticObservation("pre-aborted"),
    });
    let preAbortedSpawned = false;
    const scriptedPreAbortedAdapter = createScriptedProcessAdapter({
      close: "spawn",
    });
    const preAborted = await runExactNamedCheckV1({
      permit: preAbortedPermit,
      signal: preAbortedController.signal,
      processAdapter: {
        ...scriptedPreAbortedAdapter,
        spawn(executable, arguments_, options) {
          preAbortedSpawned = true;
          return scriptedPreAbortedAdapter.spawn(
            executable,
            arguments_,
            options,
          );
        },
      },
    });
    expect(requireValid(preAborted).outcome).toBe("cancelled");
    expect(preAbortedSpawned).toBe(false);

    const cancelledBefore = syntheticObservation("cancelled");
    const controller = new AbortController();
    const cancelledPermit = issuePermit({
      operationId: "check-cancel-1",
      registrationId: "reg-cancel",
      checkId: "fixture-hang",
      requestDigest: "3".repeat(64),
      root: join(tmpdir(), "named-check-runner-cancel"),
      beforeObservation: cancelledBefore,
    });
    const cancelledPromise = runExactNamedCheckV1({
      permit: cancelledPermit,
      signal: controller.signal,
      processAdapter: createScriptedProcessAdapter({
        close: "SIGTERM",
      }),
    });
    controller.abort();
    const cancelled = await cancelledPromise;
    const cancelledValue = requireValid(cancelled);
    expect(cancelled.valid).toBe(true);
    expect(cancelledValue.outcome).toBe("cancelled");
    expect(cancelledValue.diagnostic?.code).toBe("cancelled");

    const overflowBefore = syntheticObservation("overflow");
    const overflowPermit = issuePermit({
      operationId: "check-overflow-1",
      registrationId: "reg-overflow",
      checkId: "fixture-overflow",
      requestDigest: "4".repeat(64),
      root: join(tmpdir(), "named-check-runner-overflow"),
      beforeObservation: overflowBefore,
    });
    const overflow = await runExactNamedCheckV1({
      permit: overflowPermit,
      processAdapter: createScriptedProcessAdapter({
        close: "SIGTERM",
        stdoutChunks: [textEncoder.encode("x".repeat(32 * 1024))],
      }),
    });
    const overflowValue = requireValid(overflow);
    expect(overflow.valid).toBe(true);
    expect(overflowValue.outcome).toBe("outcome-unknown");
    expect(JSON.stringify(overflowValue)).not.toContain("x".repeat(32));
  });
});

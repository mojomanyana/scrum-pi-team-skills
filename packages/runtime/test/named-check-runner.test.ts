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
  type NamedCheckWorkspaceObservationV1,
} from "../src/named-check-runner.js";
import type {
  NamedCheckResultV1,
  ValidationResult,
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

function workspaceObservation(path: string): NamedCheckWorkspaceObservationV1 {
  const file = join(path, "named-check-fixture.txt");
  const content = readFileSync(file, "utf8");
  return {
    workspaceTree: "b".repeat(64),
    sentinelDigest: createHash("sha256")
      .update(content)
      .update(String(readFileSync(file).byteLength))
      .digest("hex"),
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
        workspaceIdentityToken: {},
        requestDigest: "c".repeat(64),
      },
      {
        cwd: workspace.root,
        homeDirectory: join(workspace.root, "home"),
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
        workspaceIdentityToken: {},
        requestDigest: "d".repeat(64),
      },
      {
        cwd: failureWorkspace.root,
        homeDirectory: join(failureWorkspace.root, "home"),
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
        workspaceIdentityToken: {},
        requestDigest: "e".repeat(64),
      },
      {
        cwd: timeoutWorkspace.root,
        homeDirectory: join(timeoutWorkspace.root, "home"),
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
        workspaceIdentityToken: {},
        requestDigest: "f".repeat(64),
      },
      {
        cwd: mutateWorkspace.root,
        homeDirectory: join(mutateWorkspace.root, "home"),
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
        workspaceIdentityToken: {},
        requestDigest: "1".repeat(64),
      },
      {
        cwd: restoreWorkspace.root,
        homeDirectory: join(restoreWorkspace.root, "home"),
        beforeObservation: beforeRestore,
        observeAfter: () => ({
          workspaceTree: beforeRestore.workspaceTree,
          sentinelDigest: `${beforeRestore.sentinelDigest}-changed`,
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
        workspaceIdentityToken: {},
        requestDigest: "2".repeat(64),
      },
      {
        cwd: descendantWorkspace.root,
        homeDirectory: join(descendantWorkspace.root, "home"),
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
        workspaceIdentityToken: {},
        requestDigest: "3".repeat(64),
      },
      {
        cwd: cancelledWorkspace.root,
        homeDirectory: join(cancelledWorkspace.root, "home"),
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
        workspaceIdentityToken: {},
        requestDigest: "4".repeat(64),
      },
      {
        cwd: overflowWorkspace.root,
        homeDirectory: join(overflowWorkspace.root, "home"),
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

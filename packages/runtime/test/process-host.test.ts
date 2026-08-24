import { existsSync } from "node:fs";
import type { SpawnOptions } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

vi.mock(
  "@scrum-pi-team-skills/contracts",
  async () => import("../../contracts/src/index.js"),
);

import manifestJson from "../../contracts/examples/agent-execution-manifest.principal-developer.json" with { type: "json" };
import {
  verifyLifecycleReceiptChain,
  type LifecycleReceipt,
} from "../../contracts/src/index.js";
import {
  createNodeProcessAdapter,
  createOperatorEnvironmentPolicy,
  createPiLaunchPlan,
  createRuntimePolicy,
  createTrustedLaunchPolicy,
  RuntimeHostError,
  startGovernedLocalProcess,
  type PiLaunchPlan,
  type ReceiptSink,
} from "../src/index.js";

const fixture = fileURLToPath(
  new URL("./fixtures/governed-process.mjs", import.meta.url),
);
const marker = "OPAQUE_MODEL_PROVIDER_VALUE_DO_NOT_PERSIST";

function manifest(): Record<string, unknown> {
  const value = structuredClone(manifestJson) as unknown as Record<
    string,
    unknown
  >;
  (value.repository as { root: string }).root = process.cwd();
  (value.paca as { taskId: string }).taskId = "SPTS-8";
  return value;
}

function plan(mode: string, value = "0", executable = fixture): PiLaunchPlan {
  const policy = createTrustedLaunchPolicy({
    policyId: `launch-policy-${mode}`,
    piExecutable: executable,
    piDaddyExtension: "/fixture/pi-daddy.ts",
    governanceLedgerPath: "/fixture/governance.jsonl",
    skillResources: {
      "skill:build": "/fixture/skills/build.md",
      "skill:review": "/fixture/skills/review.md",
    },
    promptTemplateResources: {
      "prompt:principal-feature": "/fixture/prompts/feature.md",
    },
    systemPrompt: `/fixture/mode/${mode}`,
    appendSystemPrompt: `/fixture/value/${value}`,
  });
  return createPiLaunchPlan(manifest(), policy);
}

function environment(
  baseline: Record<string, string> = {
    MODEL_PROVIDER_VALUE: marker,
    PATH: dirname(process.execPath),
  },
) {
  return createOperatorEnvironmentPolicy({
    policyId: "environment-policy-test",
    baseline,
    allowlist: Object.keys(baseline),
  });
}

function runtime(overrides: Record<string, unknown> = {}) {
  return createRuntimePolicy({
    policyId: "runtime-policy-test",
    maximumRuntimeMs: 2_000,
    terminationGraceMs: 40,
    killConfirmationMs: 500,
    processGroupPollIntervalMs: 5,
    maximumArgvCount: 128,
    maximumArgvBytes: 64_000,
    maximumEnvironmentEntries: 32,
    maximumEnvironmentBytes: 64_000,
    maximumReceiptPayloadBytes: 4_096,
    maximumListeners: 16,
    ...overrides,
  });
}

function memorySink(): ReceiptSink & {
  lines: string[];
  closed: boolean;
  closeCount: number;
} {
  const state = { lines: [] as string[], closed: false, closeCount: 0 };
  return {
    ...state,
    async open() {
      return {
        append(line) {
          state.lines.push(line);
        },
        close() {
          state.closed = true;
          state.closeCount += 1;
        },
      };
    },
    get lines() {
      return state.lines;
    },
    get closed() {
      return state.closed;
    },
    get closeCount() {
      return state.closeCount;
    },
  };
}

function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function eventuallyNotRunning(pid: number): Promise<boolean> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (!isRunning(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

function forceSignal(pid: number, signal: "SIGKILL"): void {
  try {
    process.kill(pid, signal);
  } catch (error) {
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code !== "ESRCH") throw error;
  }
}

describe("governed local process host", () => {
  it("spawns an authentic plan exactly without a shell or inherited environment", async () => {
    const sink = memorySink();
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const handle = await startGovernedLocalProcess({
      plan: plan("stream"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-stream",
      onStdout: (chunk) => {
        stdout.push(Buffer.from(chunk));
      },
      onStderr: (chunk) => {
        stderr.push(Buffer.from(chunk));
      },
    });

    await handle.started;
    const result = await handle.exit;

    expect(result.outcome).toBe("succeeded");
    expect(Buffer.concat(stdout).toString()).toBe("fixture-stdout");
    expect(Buffer.concat(stderr).toString()).toBe("fixture-stderr");
    expect(sink.closed).toBe(true);
    expect(sink.closeCount).toBe(1);
    expect(sink.lines.join("\n")).not.toContain(marker);
    const receipts = sink.lines.map(
      (line) => JSON.parse(line) as { eventType: string },
    );
    expect(receipts.map((receipt) => receipt.eventType)).toEqual([
      "launch_requested",
      "process_started",
      "process_exited",
    ]);
  });

  it("passes exact executable, argv, cwd, environment, and containment options to spawn", async () => {
    const expectedPlan = plan("success");
    const nodeAdapter = createNodeProcessAdapter();
    const probedGroupIds: number[] = [];
    let spawnedPid = 0;
    let captured:
      | {
          executable: string;
          arguments_: readonly string[];
          options: SpawnOptions;
        }
      | undefined;
    const handle = await startGovernedLocalProcess({
      plan: expectedPlan,
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-adapter",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          captured = { executable, arguments_: [...arguments_], options };
          const child = nodeAdapter.spawn(executable, arguments_, options);
          spawnedPid = child.pid ?? 0;
          return child;
        },
        isProcessGroupAlive(processGroupId) {
          probedGroupIds.push(processGroupId);
          return nodeAdapter.isProcessGroupAlive(processGroupId);
        },
        killProcessGroup: nodeAdapter.killProcessGroup,
      },
    });
    await handle.exit;

    expect(captured?.executable).toBe(expectedPlan.executable);
    expect(captured?.arguments_).toEqual(expectedPlan.arguments);
    expect(captured?.options).toMatchObject({
      cwd: expectedPlan.workingDirectory,
      shell: false,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    expect(captured?.options.env).toEqual({
      MODEL_PROVIDER_VALUE: marker,
      PATH: dirname(process.execPath),
      ...expectedPlan.environment,
    });
    expect(spawnedPid).toBeGreaterThan(0);
    expect(spawnedPid).not.toBe(process.pid);
    expect(probedGroupIds).toEqual([spawnedPid]);
  });

  it.each([
    ["spread", (value: PiLaunchPlan) => ({ ...value })],
    ["clone", (value: PiLaunchPlan) => structuredClone(value)],
    ["proxy", (value: PiLaunchPlan) => new Proxy(value, {})],
    ["prototype", (value: PiLaunchPlan) => Object.create(value)],
  ])(
    "rejects a %s forged launch plan before spawning",
    async (_label, forge) => {
      const authentic = plan("success");
      await expect(
        startGovernedLocalProcess({
          plan: forge(authentic) as PiLaunchPlan,
          environmentPolicy: environment(),
          runtimePolicy: runtime(),
          receiptSink: memorySink(),
          executionIdSource: () => "runtime-execution-forged",
        }),
      ).rejects.toThrow("launch plan must be issued");
    },
  );

  it.each([
    ["invalid name", { "BAD=NAME": "opaque" }],
    ["NUL value", { GOOD_NAME: "opaque\0value" }],
  ])("rejects an %s without exposing values", (_label, baseline) => {
    expect(() => environment(baseline)).toThrow(RuntimeHostError);
  });

  it("rejects credential-shaped policy and runtime execution identifiers", async () => {
    const suspected = `sk-proj-${"x".repeat(32)}`;
    expect(() =>
      createOperatorEnvironmentPolicy({
        policyId: suspected,
        baseline: {},
        allowlist: [],
      }),
    ).toThrow("environment policy identifier is invalid");
    expect(() =>
      createRuntimePolicy({
        ...runtime(),
        policyId: suspected,
      }),
    ).toThrow("runtime policy identifier is invalid");
    await expect(
      startGovernedLocalProcess({
        plan: plan("success"),
        environmentPolicy: environment(),
        runtimePolicy: runtime(),
        receiptSink: memorySink(),
        executionIdSource: () => suspected,
      }),
    ).rejects.toThrow("execution identifier source returned an invalid value");
  });

  it("copies and freezes environment and runtime policies", () => {
    const baseline = { SAFE_NAME: "opaque" };
    const definition = {
      policyId: "environment-policy-copy",
      baseline,
      allowlist: ["SAFE_NAME"],
    };
    const environmentPolicy = createOperatorEnvironmentPolicy(definition);
    const runtimePolicy = runtime();
    baseline.SAFE_NAME = marker;

    expect(environmentPolicy.names).toEqual(["SAFE_NAME"]);
    expect(Object.isFrozen(environmentPolicy)).toBe(true);
    expect(Object.isFrozen(environmentPolicy.names)).toBe(true);
    expect(Object.isFrozen(runtimePolicy)).toBe(true);
    expect(runtimePolicy.killConfirmationMs).toBe(500);
    expect(runtimePolicy.processGroupPollIntervalMs).toBe(5);
    expect(() =>
      Object.assign(environmentPolicy as unknown as Record<string, unknown>, {
        policyId: "forged",
      }),
    ).toThrow(TypeError);
  });

  it.each([
    ["missing kill confirmation", { killConfirmationMs: undefined }],
    ["unbounded kill confirmation", { killConfirmationMs: 60_001 }],
    ["zero kill confirmation", { killConfirmationMs: 0 }],
    ["unbounded poll interval", { processGroupPollIntervalMs: 1_001 }],
    ["zero poll interval", { processGroupPollIntervalMs: 0 }],
  ])("rejects a %s runtime policy", (_label, overrides) => {
    expect(() => runtime(overrides)).toThrow(RuntimeHostError);
  });

  it("fails closed off Linux and on bounded argv overflow", async () => {
    const common = {
      plan: plan("success"),
      environmentPolicy: environment(),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-policy-limit",
    };
    await expect(
      startGovernedLocalProcess({
        ...common,
        runtimePolicy: runtime(),
        processAdapter: {
          platform: "darwin",
          spawn() {
            throw new Error("must not spawn");
          },
          isProcessGroupAlive() {
            return false;
          },
          killProcessGroup() {},
        },
      }),
    ).rejects.toThrow("supports Linux/WSL only");
    await expect(
      startGovernedLocalProcess({
        ...common,
        runtimePolicy: runtime({ maximumArgvCount: 1 }),
      }),
    ).rejects.toThrow("launch argv exceeds");
  });

  it("rejects environment collisions and never exposes opaque values", async () => {
    const policy = environment({ PI_GRANTS_GRANT: marker });
    expect(policy).not.toHaveProperty("baseline");
    expect(JSON.stringify(policy)).not.toContain(marker);

    await expect(
      startGovernedLocalProcess({
        plan: plan("success"),
        environmentPolicy: policy,
        runtimePolicy: runtime(),
        receiptSink: memorySink(),
        executionIdSource: () => "runtime-execution-collision",
      }),
    ).rejects.toThrow(
      new RuntimeHostError("environment policy collides with launch additions"),
    );
  });

  it("times out and escalates an ignored SIGTERM to the complete process group", async () => {
    const sink = memorySink();
    const handle = await startGovernedLocalProcess({
      plan: plan("ignore-term"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ maximumRuntimeMs: 100, terminationGraceMs: 20 }),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-timeout",
    });

    const result = await handle.exit;
    expect(result.outcome).toBe("timed_out");
    expect(sink.closeCount).toBe(1);
    expect(sink.lines.map((line) => JSON.parse(line).eventType)).toEqual([
      "launch_requested",
      "process_started",
      "process_timed_out",
      "termination_requested",
      "process_killed",
      "process_exited",
    ]);
  });

  it("waits for a SIGTERM-surviving descendant after its group leader exits", async () => {
    const sink = memorySink();
    const nodeAdapter = createNodeProcessAdapter();
    const signals: Array<{ signal: string; leaderClosed: boolean }> = [];
    let leaderPid = 0;
    let descendantPid = 0;
    let leaderClosed = false;
    const handle = await startGovernedLocalProcess({
      plan: plan("leader-exit-tree"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-leader-exit-tree",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          const child = nodeAdapter.spawn(executable, arguments_, options);
          leaderPid = child.pid ?? 0;
          child.once("close", () => {
            leaderClosed = true;
          });
          return child;
        },
        isProcessGroupAlive: nodeAdapter.isProcessGroupAlive,
        killProcessGroup(processGroupId, signal) {
          signals.push({ signal, leaderClosed });
          nodeAdapter.killProcessGroup(processGroupId, signal);
        },
      },
      onStdout(chunk) {
        descendantPid = Number(Buffer.from(chunk).toString().trim());
      },
    });

    try {
      await handle.started;
      while (descendantPid === 0)
        await new Promise((resolve) => setTimeout(resolve, 5));

      await handle.terminate("caller");
      const result = await handle.exit;
      const receipts = sink.lines.map((line) => JSON.parse(line));

      expect(result.outcome).toBe("supervisor_failed");
      expect(descendantPid).toBeGreaterThan(0);
      expect(isRunning(descendantPid)).toBe(false);
      expect(signals).toContainEqual({
        signal: "SIGTERM",
        leaderClosed: false,
      });
      expect(signals).toContainEqual({ signal: "SIGKILL", leaderClosed: true });
      expect(receipts.map((receipt) => receipt.eventType)).toEqual([
        "launch_requested",
        "process_started",
        "termination_requested",
        "supervisor_failed",
        "process_killed",
        "process_exited",
      ]);
      expect(
        verifyLifecycleReceiptChain(receipts as LifecycleReceipt[]).valid,
      ).toBe(true);
      expect(sink.closeCount).toBe(1);
    } finally {
      if (leaderPid > 0) forceSignal(-leaderPid, "SIGKILL");
      if (descendantPid > 0 && isRunning(descendantPid))
        forceSignal(descendantPid, "SIGKILL");
      if (descendantPid > 0) await eventuallyNotRunning(descendantPid);
    }
  });

  it("terminates a child-process tree idempotently without leaving the child", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    const signals: Array<{ signal: string; leaderClosed: boolean }> = [];
    let leaderPid = 0;
    let childPid = 0;
    let leaderClosed = false;
    const handle = await startGovernedLocalProcess({
      plan: plan("tree"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-tree",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          const child = nodeAdapter.spawn(executable, arguments_, options);
          leaderPid = child.pid ?? 0;
          child.once("close", () => {
            leaderClosed = true;
          });
          return child;
        },
        isProcessGroupAlive: nodeAdapter.isProcessGroupAlive,
        killProcessGroup(processGroupId, signal) {
          signals.push({ signal, leaderClosed });
          nodeAdapter.killProcessGroup(processGroupId, signal);
        },
      },
      onStdout(chunk) {
        childPid = Number(Buffer.from(chunk).toString().trim());
      },
    });
    try {
      await handle.started;
      while (childPid === 0)
        await new Promise((resolve) => setTimeout(resolve, 5));

      await Promise.all([
        handle.terminate("caller"),
        handle.terminate("caller"),
      ]);
      await handle.exit;

      expect(childPid).toBeGreaterThan(0);
      expect(await eventuallyNotRunning(childPid)).toBe(true);
      expect(signals).toContainEqual({
        signal: "SIGKILL",
        leaderClosed: false,
      });
    } finally {
      if (leaderPid > 0) forceSignal(-leaderPid, "SIGKILL");
      if (childPid > 0 && isRunning(childPid)) forceSignal(childPid, "SIGKILL");
      if (childPid > 0) await eventuallyNotRunning(childPid);
    }
  });

  it("uses the injected clock and clears runtime timers", async () => {
    const timers = new Set<NodeJS.Timeout>();
    const sink = memorySink();
    const handle = await startGovernedLocalProcess({
      plan: plan("success"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-clock",
      clock: {
        now: () => "2026-08-23T12:00:00.000Z",
        setTimeout(callback, milliseconds) {
          const timer = setTimeout(() => {
            timers.delete(timer);
            callback();
          }, milliseconds);
          timers.add(timer);
          return timer;
        },
        clearTimeout(timer) {
          clearTimeout(timer as NodeJS.Timeout);
          timers.delete(timer as NodeJS.Timeout);
        },
      },
    });
    await handle.exit;

    expect(timers.size).toBe(0);
    expect(
      sink.lines.every(
        (line) => JSON.parse(line).timestamp === "2026-08-23T12:00:00.000Z",
      ),
    ).toBe(true);
  });

  it("stops probing and signaling permanently after confirmed group absence", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    const signals: string[] = [];
    let probes = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("delay", "20"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-absence-sticky",
      processAdapter: {
        platform: "linux",
        spawn: nodeAdapter.spawn,
        isProcessGroupAlive() {
          probes += 1;
          return false;
        },
        killProcessGroup(_processGroupId, signal) {
          signals.push(signal);
        },
      },
    });

    await handle.started;
    await handle.terminate();
    expect((await handle.exit).outcome).toBe("succeeded");
    expect(probes).toBe(1);
    expect(signals).toEqual([]);
  });

  it("observes group absence during grace polling without escalating", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    const signals: string[] = [];
    let probes = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("delay", "10000"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-absence-during-grace",
      processAdapter: {
        platform: "linux",
        spawn: nodeAdapter.spawn,
        isProcessGroupAlive() {
          probes += 1;
          return probes === 1;
        },
        killProcessGroup(processGroupId, signal) {
          signals.push(signal);
          nodeAdapter.killProcessGroup(processGroupId, signal);
        },
      },
    });

    await handle.started;
    await handle.terminate();
    await handle.exit;
    expect(signals).toEqual(["SIGTERM"]);
    expect(probes).toBe(2);
  });

  it("fails closed on bounded SIGKILL confirmation and clears every poll timer", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    const timers = new Set<object>();
    const signals: string[] = [];
    let leaderPid = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("delay", "10000"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({
        terminationGraceMs: 2,
        killConfirmationMs: 3,
        processGroupPollIntervalMs: 1,
      }),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-kill-confirmation-timeout",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          const child = nodeAdapter.spawn(executable, arguments_, options);
          leaderPid = child.pid ?? 0;
          return child;
        },
        isProcessGroupAlive() {
          return true;
        },
        killProcessGroup(_processGroupId, signal) {
          signals.push(signal);
        },
      },
      clock: {
        now: () => "2026-08-23T12:00:00.000Z",
        setTimeout(callback, milliseconds) {
          const timer = {};
          if (milliseconds < 100) {
            timers.add(timer);
            callback();
          }
          return timer;
        },
        clearTimeout(timer) {
          timers.delete(timer as object);
        },
      },
    });

    await handle.started;
    try {
      await expect(handle.terminate()).rejects.toThrow(
        "process-group absence confirmation timed out",
      );
      expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
      expect(timers.size).toBe(0);
    } finally {
      if (leaderPid > 0) forceSignal(-leaderPid, "SIGKILL");
    }
    await expect(handle.exit).rejects.toThrow(
      "process-group absence confirmation timed out",
    );
    expect(timers.size).toBe(0);
  });

  it.each([
    ["EPERM", ["present", "absent"]],
    ["EIO", ["absent"]],
  ])(
    "continues cleanup after an initial %s probe and accepts later confirmed absence",
    async (code, laterStates) => {
      const nodeAdapter = createNodeProcessAdapter();
      const signals: string[] = [];
      let leaderPid = 0;
      let probes = 0;
      const sink = memorySink();
      const handle = await startGovernedLocalProcess({
        plan: plan("delay", "10000"),
        environmentPolicy: environment(),
        runtimePolicy: runtime({ terminationGraceMs: 10 }),
        receiptSink: sink,
        executionIdSource: () =>
          `runtime-execution-transient-${code.toLowerCase()}`,
        processAdapter: {
          platform: "linux",
          spawn(executable, arguments_, options) {
            const child = nodeAdapter.spawn(executable, arguments_, options);
            leaderPid = child.pid ?? 0;
            return child;
          },
          isProcessGroupAlive() {
            probes += 1;
            if (probes === 1) throw Object.assign(new Error(marker), { code });
            return laterStates[probes - 2] === "present";
          },
          killProcessGroup(processGroupId, signal) {
            signals.push(signal);
            nodeAdapter.killProcessGroup(processGroupId, signal);
          },
        },
      });

      try {
        await handle.started;
        await Promise.all([
          handle.terminate(),
          handle.terminate(),
          handle.terminate(),
        ]);
        const result = await handle.exit;
        expect(result.outcome).toBe("supervisor_failed");
        expect(signals).toEqual(["SIGTERM"]);
        expect(probes).toBe(code === "EPERM" ? 3 : 2);
        const receipts = sink.lines.map((line) => JSON.parse(line));
        expect(
          receipts.filter(
            (receipt) => receipt.eventType === "supervisor_failed",
          ),
        ).toEqual([
          expect.objectContaining({
            payload: { code: "group_liveness_failed" },
          }),
        ]);
        expect(
          verifyLifecycleReceiptChain(receipts as LifecycleReceipt[]).valid,
        ).toBe(true);
        expect(sink.lines.join("\n")).not.toContain(marker);
        expect(sink.closeCount).toBe(1);
      } finally {
        if (leaderPid > 0 && isRunning(leaderPid))
          forceSignal(-leaderPid, "SIGKILL");
        if (leaderPid > 0)
          expect(await eventuallyNotRunning(leaderPid)).toBe(true);
      }
    },
  );

  it.each(["EPERM", "EIO"])(
    "attempts bounded SIGTERM and SIGKILL for persistent %s liveness uncertainty",
    async (code) => {
      const nodeAdapter = createNodeProcessAdapter();
      const signals: string[] = [];
      const timers = new Set<object>();
      let leaderPid = 0;
      const sink = memorySink();
      const handle = await startGovernedLocalProcess({
        plan: plan("delay", "10000"),
        environmentPolicy: environment(),
        runtimePolicy: runtime({
          terminationGraceMs: 2,
          killConfirmationMs: 3,
          processGroupPollIntervalMs: 1,
        }),
        receiptSink: sink,
        executionIdSource: () =>
          `runtime-execution-persistent-${code.toLowerCase()}`,
        processAdapter: {
          platform: "linux",
          spawn(executable, arguments_, options) {
            const child = nodeAdapter.spawn(executable, arguments_, options);
            leaderPid = child.pid ?? 0;
            return child;
          },
          isProcessGroupAlive() {
            throw Object.assign(new Error(marker), { code });
          },
          killProcessGroup(_processGroupId, signal) {
            signals.push(signal);
          },
        },
        clock: {
          now: () => "2026-08-23T12:00:00.000Z",
          setTimeout(callback, milliseconds) {
            const timer = {};
            if (milliseconds < 100) {
              timers.add(timer);
              callback();
            }
            return timer;
          },
          clearTimeout(timer) {
            timers.delete(timer as object);
          },
        },
      });

      await handle.started;
      const exitExpectation = expect(handle.exit).rejects.toThrow(
        "process-group absence confirmation timed out",
      );
      try {
        await expect(handle.terminate()).rejects.toThrow(
          "process-group absence confirmation timed out",
        );
        expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
        expect(timers.size).toBe(0);
        expect(sink.lines.join("\n")).not.toContain(marker);
        expect(sink.lines.join("\n")).toContain("group_liveness_failed");
        expect(sink.lines.join("\n")).not.toContain('"outcome":"succeeded"');
      } finally {
        if (leaderPid > 0) forceSignal(-leaderPid, "SIGKILL");
        if (leaderPid > 0)
          expect(await eventuallyNotRunning(leaderPid)).toBe(true);
      }
      await exitExpectation;
      expect(sink.closeCount).toBe(1);
      expect(timers.size).toBe(0);
    },
  );

  it("lets the host confirm and own cleanup after a transient unexpected probe failure", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    const signals: string[] = [];
    let leaderPid = 0;
    let probes = 0;
    let ready = false;
    const handle = await startGovernedLocalProcess({
      plan: plan("ignore-term-ready"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 10 }),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-host-owned-unknown",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          const child = nodeAdapter.spawn(executable, arguments_, options);
          leaderPid = child.pid ?? 0;
          return child;
        },
        isProcessGroupAlive(processGroupId) {
          probes += 1;
          if (probes === 1) throw new Error(marker);
          return nodeAdapter.isProcessGroupAlive(processGroupId);
        },
        killProcessGroup(processGroupId, signal) {
          signals.push(signal);
          nodeAdapter.killProcessGroup(processGroupId, signal);
        },
      },
      onStdout() {
        ready = true;
      },
    });

    try {
      await handle.started;
      while (!ready) await new Promise((resolve) => setTimeout(resolve, 5));
      await Promise.all([handle.terminate(), handle.exit]);
      expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
      expect(probes).toBeGreaterThan(2);
      expect(await eventuallyNotRunning(leaderPid)).toBe(true);
    } finally {
      if (leaderPid > 0 && isRunning(leaderPid))
        forceSignal(-leaderPid, "SIGKILL");
      if (leaderPid > 0)
        expect(await eventuallyNotRunning(leaderPid)).toBe(true);
    }
  });

  it("reports a normal non-zero exit", async () => {
    const handle = await startGovernedLocalProcess({
      plan: plan("nonzero", "9"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-nonzero",
    });

    const result = await handle.exit;
    expect(result.outcome).toBe("nonzero");
    expect(result.exitCode).toBe(9);
  });

  it("honors an immediate AbortSignal and removes its listener", async () => {
    const controller = new AbortController();
    const add = vi.spyOn(controller.signal, "addEventListener");
    const remove = vi.spyOn(controller.signal, "removeEventListener");
    const handle = await startGovernedLocalProcess({
      plan: plan("delay", "10000"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-abort",
      signal: controller.signal,
    });
    controller.abort();

    const result = await handle.exit;
    expect(result.outcome).toBe("signaled");
    expect(add).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it("converges simultaneous abort and caller termination on exactly one cleanup", async () => {
    const controller = new AbortController();
    const sink = memorySink();
    let ready = false;
    const handle = await startGovernedLocalProcess({
      plan: plan("ignore-term-ready"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 10 }),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-abort-caller-race",
      signal: controller.signal,
      onStdout() {
        ready = true;
      },
    });
    await handle.started;
    while (!ready) await new Promise((resolve) => setTimeout(resolve, 5));

    controller.abort();
    await Promise.all([handle.terminate("caller"), handle.terminate("caller")]);
    await handle.exit;

    const events = sink.lines.map((line) => JSON.parse(line).eventType);
    expect(
      events.filter((event) => event === "termination_requested"),
    ).toHaveLength(1);
    expect(events.filter((event) => event === "process_killed")).toHaveLength(
      1,
    );
    expect(sink.closeCount).toBe(1);
  });

  it("clears the maximum-runtime timer as soon as termination owns cleanup", async () => {
    const timers = new Map<NodeJS.Timeout, number>();
    let ready = false;
    const handle = await startGovernedLocalProcess({
      plan: plan("ignore-term-ready"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({
        maximumRuntimeMs: 300_000,
        terminationGraceMs: 10,
      }),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-termination-clears-runtime",
      clock: {
        now: () => "2026-08-23T12:00:00.000Z",
        setTimeout(callback, milliseconds) {
          const timer = setTimeout(callback, milliseconds);
          timers.set(timer, milliseconds);
          return timer;
        },
        clearTimeout(timer) {
          clearTimeout(timer as NodeJS.Timeout);
          timers.delete(timer as NodeJS.Timeout);
        },
      },
      onStdout() {
        ready = true;
      },
    });
    await handle.started;
    while (!ready) await new Promise((resolve) => setTimeout(resolve, 5));

    const termination = handle.terminate();
    expect([...timers.values()]).not.toContain(300_000);
    await termination;
    await handle.exit;
    expect(timers.size).toBe(0);
  });

  it("does not allocate a grace timer after raw close wins termination receipt recording", async () => {
    const timers = new Set<object>();
    const sink = memorySink();
    sink.open = async () => ({
      async append(line) {
        sink.lines.push(line);
        if (JSON.parse(line).eventType === "termination_requested") {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      },
      close() {},
    });
    const handle = await startGovernedLocalProcess({
      plan: plan("delay", "10"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 300_000 }),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-close-race",
      clock: {
        now: () => "2026-08-23T12:00:00.000Z",
        setTimeout() {
          const timer = {};
          timers.add(timer);
          return timer;
        },
        clearTimeout(timer) {
          timers.delete(timer as object);
        },
      },
    });
    await handle.started;
    await Promise.all([handle.terminate(), handle.exit]);
    expect(timers.size).toBe(0);
  });

  it("closes the receipt writer exactly once when launch_requested append fails", async () => {
    let closeCount = 0;
    await expect(
      startGovernedLocalProcess({
        plan: plan("success"),
        environmentPolicy: environment(),
        runtimePolicy: runtime(),
        receiptSink: {
          open() {
            return {
              append() {
                throw new Error(marker);
              },
              close() {
                closeCount += 1;
              },
            };
          },
        },
        executionIdSource: () => "runtime-execution-launch-receipt-failure",
      }),
    ).rejects.toThrow("receipt sink failed");
    expect(closeCount).toBe(1);
  });

  it("closes the receipt writer exactly once after a post-open append failure", async () => {
    let appendCount = 0;
    let closeCount = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("ignore-term"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: {
        open() {
          return {
            append() {
              appendCount += 1;
              if (appendCount === 2) throw new Error(marker);
            },
            close() {
              closeCount += 1;
            },
          };
        },
      },
      executionIdSource: () => "runtime-execution-close-on-failure",
    });
    await expect(handle.started).rejects.toThrow("receipt sink failed");
    await expect(handle.exit).rejects.toThrow("receipt sink failed");
    expect(closeCount).toBe(1);
  });

  it("finishes descendant cleanup when the process_killed receipt append fails", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    let leaderPid = 0;
    let descendantPid = 0;
    let closeCount = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("leader-exit-tree"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: {
        open() {
          return {
            append(line) {
              if (JSON.parse(line).eventType === "process_killed")
                throw new Error(marker);
            },
            close() {
              closeCount += 1;
            },
          };
        },
      },
      executionIdSource: () => "runtime-execution-descendant-receipt-failure",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          const child = nodeAdapter.spawn(executable, arguments_, options);
          leaderPid = child.pid ?? 0;
          return child;
        },
        isProcessGroupAlive: nodeAdapter.isProcessGroupAlive,
        killProcessGroup: nodeAdapter.killProcessGroup,
      },
      onStdout(chunk) {
        descendantPid = Number(Buffer.from(chunk).toString().trim());
      },
    });

    try {
      await handle.started;
      while (descendantPid === 0)
        await new Promise((resolve) => setTimeout(resolve, 5));
      await handle.terminate();
      expect(isRunning(descendantPid)).toBe(false);
      await expect(handle.exit).rejects.toThrow("receipt sink failed");
      expect(closeCount).toBe(1);
    } finally {
      if (leaderPid > 0) forceSignal(-leaderPid, "SIGKILL");
      if (descendantPid > 0 && isRunning(descendantPid))
        forceSignal(descendantPid, "SIGKILL");
      if (descendantPid > 0) await eventuallyNotRunning(descendantPid);
    }
  });

  it("retains the primary spawn diagnostic when writer close also fails", async () => {
    let closeCount = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("success", "0", "/fixture/does-not-exist"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: {
        open() {
          return {
            append() {},
            close() {
              closeCount += 1;
              throw new Error(marker);
            },
          };
        },
      },
      executionIdSource: () => "runtime-execution-spawn-close-failure",
    });
    await expect(handle.started).rejects.toThrow("process spawn failed");
    expect((await handle.exit).outcome).toBe("spawn_failed");
    expect(closeCount).toBe(1);
  });

  it("contains a receipt sink failure and does not abandon the child", async () => {
    const nodeAdapter = createNodeProcessAdapter();
    let pid = 0;
    let appendCount = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("ignore-term"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: {
        open() {
          return {
            append() {
              appendCount += 1;
              if (appendCount === 2) throw new Error(marker);
            },
            close() {},
          };
        },
      },
      executionIdSource: () => "runtime-execution-sink-failure",
      processAdapter: {
        platform: "linux",
        spawn(executable, arguments_, options) {
          const child = nodeAdapter.spawn(executable, arguments_, options);
          pid = child.pid ?? 0;
          return child;
        },
        isProcessGroupAlive: nodeAdapter.isProcessGroupAlive,
        killProcessGroup: nodeAdapter.killProcessGroup,
      },
    });

    await expect(handle.started).rejects.toThrow("receipt sink failed");
    await expect(handle.exit).rejects.toThrow("receipt sink failed");
    expect(pid).toBeGreaterThan(0);
    expect(await eventuallyNotRunning(pid)).toBe(true);
  });

  it("contains callback failure and still cleans up the process", async () => {
    const sink = memorySink();
    const handle = await startGovernedLocalProcess({
      plan: plan("stream"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-callback",
      onStdout() {
        throw new Error(marker);
      },
    });

    const result = await handle.exit;
    expect(result.outcome).toBe("supervisor_failed");
    expect(sink.lines.join("\n")).not.toContain(marker);
    expect(sink.lines.some((line) => line.includes("supervisor_failed"))).toBe(
      true,
    );
    expect(sink.closeCount).toBe(1);
  });

  it("records a fixed spawn failure without echoing exception details", async () => {
    const sink = memorySink();
    const handle = await startGovernedLocalProcess({
      plan: plan("success", "0", "/fixture/does-not-exist"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-spawn-failure",
    });

    await expect(handle.started).rejects.toThrow("process spawn failed");
    const result = await handle.exit;
    expect(result.outcome).toBe("spawn_failed");
    expect(sink.closeCount).toBe(1);
    expect(sink.lines.join("\n")).not.toContain("does-not-exist");
  });

  it("streams large output with digest evidence rather than persistence", async () => {
    const sink = memorySink();
    let bytes = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("large", "1000000"),
      environmentPolicy: environment(),
      runtimePolicy: runtime(),
      receiptSink: sink,
      executionIdSource: () => "runtime-execution-large",
      onStdout: (chunk) => {
        bytes += chunk.byteLength;
      },
    });
    const result = await handle.exit;

    expect(bytes).toBe(1_000_000);
    expect(result.stdout.bytes).toBe(bytes);
    expect(sink.lines.join("\n")).not.toContain("xxxxxxxx");
    expect(existsSync(fixture)).toBe(true);
  });
});

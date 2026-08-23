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

async function eventuallyNotRunning(pid: number): Promise<boolean> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
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
          return nodeAdapter.spawn(executable, arguments_, options);
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
    expect(() =>
      Object.assign(environmentPolicy as unknown as Record<string, unknown>, {
        policyId: "forged",
      }),
    ).toThrow(TypeError);
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

  it("terminates a child-process tree idempotently without leaving the child", async () => {
    let childPid = 0;
    const handle = await startGovernedLocalProcess({
      plan: plan("tree"),
      environmentPolicy: environment(),
      runtimePolicy: runtime({ terminationGraceMs: 20 }),
      receiptSink: memorySink(),
      executionIdSource: () => "runtime-execution-tree",
      onStdout(chunk) {
        childPid = Number(Buffer.from(chunk).toString().trim());
      },
    });
    await handle.started;
    while (childPid === 0)
      await new Promise((resolve) => setTimeout(resolve, 5));

    await Promise.all([handle.terminate("caller"), handle.terminate("caller")]);
    await handle.exit;

    expect(childPid).toBeGreaterThan(0);
    expect(await eventuallyNotRunning(childPid)).toBe(true);
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

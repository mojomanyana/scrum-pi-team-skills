import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import {
  chmodSync,
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import manifestExample from "../../contracts/examples/agent-execution-manifest.principal-developer.json" with { type: "json" };
import {
  createNodeProcessAdapter,
  startGovernedLocalProcess,
  type ExecutionResult,
} from "@scrum-pi-team-skills/runtime";
import { runCli } from "../src/index.js";

const fixture = fileURLToPath(
  new URL("../../runtime/test/fixtures/governed-process.mjs", import.meta.url),
);
const roots: string[] = [];
const authenticationKey = Buffer.alloc(32, 0x5a).toString("base64");

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

class ScriptedWritable extends EventEmitter {
  readonly chunks: Buffer[] = [];
  writes = 0;

  constructor(
    private readonly script: (
      stream: ScriptedWritable,
      callback: (error?: Error | null) => void,
    ) => boolean,
  ) {
    super();
  }

  write(chunk: Uint8Array, callback: (error?: Error | null) => void): boolean {
    this.writes += 1;
    this.chunks.push(Buffer.from(chunk));
    return this.script(this, callback);
  }
}

function successfulResult(executionId: string): ExecutionResult {
  return {
    executionId,
    outcome: "succeeded",
    exitCode: 0,
    signal: null,
    stdout: { bytes: 0, sha256: "0".repeat(64) },
    stderr: { bytes: 0, sha256: "0".repeat(64) },
  };
}

function cliEnvironment(name: string): string | undefined {
  if (name === "PATH") return dirname(process.execPath);
  if (name === "MODEL_PROVIDER_VALUE") return "opaque";
  if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
  return undefined;
}

async function runWithWritable(
  streamName: "stdout" | "stderr",
  stream: ScriptedWritable,
  errors: string[],
  terminate = vi.fn(async () => {}),
): Promise<number> {
  const files = setup();
  const executionId = `cli-writable-${streamName}`;
  return runCli(
    [
      "run",
      "--manifest",
      files.manifestPath,
      "--operator-config",
      files.configPath,
    ],
    {
      [streamName]: stream as unknown as Writable,
      writeOutput: () => {},
      writeError: (value) => errors.push(value),
      readEnvironment: cliEnvironment,
      startGovernedLocalProcess: async (options) => {
        const exit = (async (): Promise<ExecutionResult> => {
          try {
            await options[streamName === "stdout" ? "onStdout" : "onStderr"]?.(
              Buffer.from("governed-output"),
            );
            return successfulResult(executionId);
          } catch {
            return {
              ...successfulResult(executionId),
              outcome: "supervisor_failed",
            };
          }
        })();
        return {
          executionId,
          started: Promise.resolve(),
          exit,
          terminate,
        };
      },
    },
  );
}

function isProcessAlive(processId: number): boolean {
  try {
    process.kill(processId, 0);
    return true;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ESRCH"
    ) {
      return false;
    }
    throw error;
  }
}

function setup(mode = "success", value = "0") {
  const root = join(tmpdir(), `spts-cli-${process.pid}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const trustedReceiptParent = join(root, "receipts");
  mkdirSync(trustedReceiptParent, { mode: 0o700 });
  const manifest = structuredClone(manifestExample);
  manifest.repository.root = process.cwd();
  manifest.paca.taskId = "SPTS-8";
  const manifestPath = join(root, "manifest.json");
  const configPath = join(root, "operator.json");
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(
    configPath,
    JSON.stringify({
      trustedLaunchPolicy: {
        policyId: `cli-launch-${mode}`,
        piExecutable: fixture,
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
      },
      environment: {
        policyId: "cli-environment",
        importNames: ["PATH", "MODEL_PROVIDER_VALUE"],
      },
      runtimePolicy: {
        policyId: "cli-runtime",
        maximumRuntimeMs: 2000,
        terminationGraceMs: 50,
        killConfirmationMs: 500,
        processGroupPollIntervalMs: 5,
        maximumArgvCount: 128,
        maximumArgvBytes: 64000,
        maximumEnvironmentEntries: 32,
        maximumEnvironmentBytes: 64000,
        maximumReceiptPayloadBytes: 4096,
        maximumListeners: 16,
      },
      trustedReceiptParent,
      authentication: {
        authenticatorId: "cli-receipt-authenticator",
        keyEnvironmentVariable: "SPTS_RECEIPT_AUTH_KEY",
      },
    }),
  );
  chmodSync(fixture, 0o755);
  return { root, manifestPath, configPath };
}

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    roots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("private governed runtime CLI", () => {
  it("prints a redacted non-executable plan preview", async () => {
    const files = setup();
    const output: string[] = [];
    const code = await runCli(
      [
        "plan",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: (value) => output.push(value),
        writeError: () => {},
        readEnvironment: () => {
          throw new Error("plan must not read shell environment");
        },
      },
    );

    expect(code).toBe(0);
    expect(output.join("\n")).toContain('"executableAuthority": false');
    expect(output.join("\n")).not.toContain(fixture);
  });

  it("run imports only configured names, executes the fixture, and writes receipts", async () => {
    const files = setup("success");
    const reads: string[] = [];
    const code = await runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment(name) {
          reads.push(name);
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "OPAQUE_DO_NOT_PERSIST";
          if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
          return undefined;
        },
      },
    );

    expect(code).toBe(0);
    expect(reads).toEqual([
      "PATH",
      "MODEL_PROVIDER_VALUE",
      "SPTS_RECEIPT_AUTH_KEY",
    ]);
    const { readdir, readFile } = await import("node:fs/promises");
    const names = await readdir(join(files.root, "receipts"));
    const receiptText = await readFile(
      join(files.root, "receipts", names[0]!, "receipts.jsonl"),
      "utf8",
    );
    expect(receiptText).not.toContain("OPAQUE_DO_NOT_PERSIST");
  });

  it.each([undefined, "not-base64", Buffer.alloc(31).toString("base64")])(
    "fails run with a fixed redacted diagnostic for a missing or malformed authentication key",
    async (authenticationValue) => {
      const files = setup();
      const errors: string[] = [];
      const reads: string[] = [];
      expect(
        await runCli(
          [
            "run",
            "--manifest",
            files.manifestPath,
            "--operator-config",
            files.configPath,
          ],
          {
            writeOutput: () => {},
            writeError: (value) => errors.push(value),
            readEnvironment(name) {
              reads.push(name);
              if (name === "PATH") return dirname(process.execPath);
              if (name === "MODEL_PROVIDER_VALUE") return "opaque";
              if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationValue;
              return undefined;
            },
          },
        ),
      ).toBe(3);
      expect(reads).toEqual([
        "PATH",
        "MODEL_PROVIDER_VALUE",
        "SPTS_RECEIPT_AUTH_KEY",
      ]);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(authenticationValue ?? "never");
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "contains synchronous %s write throws with a fixed failure",
    async (streamName) => {
      const attackerMessage = "ATTACKER_SYNC_WRITE_DETAIL_DO_NOT_ESCAPE";
      const errors: string[] = [];
      const terminate = vi.fn(async () => {});
      const stream = new ScriptedWritable(() => {
        throw new Error(attackerMessage);
      });

      expect(await runWithWritable(streamName, stream, errors, terminate)).toBe(
        3,
      );
      expect(terminate).toHaveBeenCalledTimes(1);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
      expect(stream.listenerCount("error")).toBe(0);
      expect(stream.listenerCount("close")).toBe(0);
      expect(stream.listenerCount("drain")).toBe(0);
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "contains %s write-callback errors",
    async (streamName) => {
      const attackerMessage = "ATTACKER_CALLBACK_DETAIL_DO_NOT_ESCAPE";
      const errors: string[] = [];
      const stream = new ScriptedWritable((_target, callback) => {
        callback(new Error(attackerMessage));
        return true;
      });

      expect(await runWithWritable(streamName, stream, errors)).toBe(3);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
      expect(stream.eventNames()).toEqual([]);
    },
  );

  it.each([
    ["stdout", true],
    ["stderr", true],
    ["stdout", false],
    ["stderr", false],
  ] as const)(
    "contains asynchronous %s errors after write returns %s",
    async (streamName, writeResult) => {
      const attackerMessage = "ATTACKER_ASYNC_EPIPE_DETAIL_DO_NOT_ESCAPE";
      const errors: string[] = [];
      const applicationErrors: unknown[] = [];
      const stream = new ScriptedWritable((target) => {
        setImmediate(() =>
          target.emit(
            "error",
            Object.assign(new Error(attackerMessage), { code: "EPIPE" }),
          ),
        );
        return writeResult;
      });
      const applicationListener = (error: unknown) =>
        applicationErrors.push(error);
      stream.on("error", applicationListener);
      const baseline = {
        error: stream.listenerCount("error"),
        close: stream.listenerCount("close"),
        drain: stream.listenerCount("drain"),
      };

      expect(await runWithWritable(streamName, stream, errors)).toBe(3);
      expect(applicationErrors).toHaveLength(1);
      expect(stream.listeners("error")).toEqual([applicationListener]);
      expect(stream.listenerCount("error")).toBe(baseline.error);
      expect(stream.listenerCount("close")).toBe(baseline.close);
      expect(stream.listenerCount("drain")).toBe(baseline.drain);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "rejects %s close before write completion or drain",
    async (streamName) => {
      const errors: string[] = [];
      const stream = new ScriptedWritable((target) => {
        setImmediate(() => target.emit("close"));
        return false;
      });

      expect(await runWithWritable(streamName, stream, errors)).toBe(3);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(stream.eventNames()).toEqual([]);
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "settles %s write races once and removes only temporary listeners",
    async (streamName) => {
      const attackerMessage = "ATTACKER_WRITE_RACE_DETAIL_DO_NOT_ESCAPE";
      const errors: string[] = [];
      const applicationErrors: unknown[] = [];
      const terminate = vi.fn(async () => {});
      const stream = new ScriptedWritable((target, callback) => {
        setImmediate(() => {
          target.emit("error", new Error(attackerMessage));
          callback(new Error(attackerMessage));
          target.emit("drain");
          target.emit("close");
          target.emit("error", new Error(attackerMessage));
          callback();
        });
        return false;
      });
      const applicationListener = (error: unknown) =>
        applicationErrors.push(error);
      const unrelatedClose = () => {};
      const unrelatedDrain = () => {};
      stream.on("error", applicationListener);
      stream.on("close", unrelatedClose);
      stream.on("drain", unrelatedDrain);
      const baseline = {
        error: stream.listenerCount("error"),
        close: stream.listenerCount("close"),
        drain: stream.listenerCount("drain"),
        beforeExit: process.listenerCount("beforeExit"),
      };
      const processErrors: unknown[] = [];
      const onUnhandled = (error: unknown) => processErrors.push(error);
      const onUncaught = (error: unknown) => processErrors.push(error);
      process.on("unhandledRejection", onUnhandled);
      process.on("uncaughtException", onUncaught);

      try {
        expect(
          await runWithWritable(streamName, stream, errors, terminate),
        ).toBe(3);
        await new Promise((resolve) => setImmediate(resolve));
        expect(terminate).toHaveBeenCalledTimes(1);
        expect(applicationErrors).toHaveLength(2);
        expect(stream.listenerCount("error")).toBe(baseline.error);
        expect(stream.listenerCount("close")).toBe(baseline.close);
        expect(stream.listenerCount("drain")).toBe(baseline.drain);
        expect(process.listenerCount("beforeExit")).toBe(baseline.beforeExit);
        expect(stream.listeners("error")).toContain(applicationListener);
        expect(stream.listeners("close")).toContain(unrelatedClose);
        expect(stream.listeners("drain")).toContain(unrelatedDrain);
        expect(errors).toEqual(["governed runtime operation failed"]);
        expect(errors.join("\n")).not.toContain(attackerMessage);
        expect(processErrors).toEqual([]);
      } finally {
        process.off("unhandledRejection", onUnhandled);
        process.off("uncaughtException", onUncaught);
      }
    },
  );

  it("waits for drain after a completed backpressured write", async () => {
    const errors: string[] = [];
    let writeCallback!: (error?: Error | null) => void;
    let writable!: ScriptedWritable;
    const stream = new ScriptedWritable((target, callback) => {
      writable = target;
      writeCallback = callback;
      return false;
    });
    let settled = false;
    const run = runWithWritable("stdout", stream, errors).finally(() => {
      settled = true;
    });
    while (stream.writes === 0)
      await new Promise((resolve) => setImmediate(resolve));

    writeCallback();
    expect(settled).toBe(false);
    writable.emit("drain");
    expect(await run).toBe(0);
    expect(errors).toEqual([]);
  });

  it.each(["stdout", "stderr"] as const)(
    "preserves normal ordered %s output through backpressure",
    async (streamName) => {
      const errors: string[] = [];
      const stream = new ScriptedWritable((target, callback) => {
        setImmediate(() => {
          callback();
          target.emit("drain");
        });
        return false;
      });

      expect(await runWithWritable(streamName, stream, errors)).toBe(0);
      expect(stream.writes).toBe(1);
      expect(Buffer.concat(stream.chunks).toString()).toBe("governed-output");
      expect(stream.eventNames()).toEqual([]);
      expect(errors).toEqual([]);
    },
  );

  it("terminates and finalizes a real process after an asynchronous output error", async () => {
    const files = setup("ignore-term-ready", "0");
    const adapter = createNodeProcessAdapter();
    const spawnedProcessIds: number[] = [];
    const applicationErrors: unknown[] = [];
    const errors: string[] = [];
    const stream = new ScriptedWritable((target) => {
      setImmediate(() =>
        target.emit(
          "error",
          Object.assign(new Error("ATTACKER_REAL_EPIPE_DO_NOT_ESCAPE"), {
            code: "EPIPE",
          }),
        ),
      );
      return true;
    });
    const applicationListener = (error: unknown) =>
      applicationErrors.push(error);
    stream.on("error", applicationListener);
    let terminate: ReturnType<typeof vi.fn> | undefined;

    expect(
      await runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          stdout: stream as unknown as Writable,
          writeError: (value) => errors.push(value),
          writeStderr: () => {},
          readEnvironment: cliEnvironment,
          startGovernedLocalProcess: async (options) => {
            const handle = await startGovernedLocalProcess({
              ...options,
              processAdapter: {
                platform: adapter.platform,
                spawn(executable, arguments_, spawnOptions) {
                  const child = adapter.spawn(
                    executable,
                    arguments_,
                    spawnOptions,
                  );
                  if (child.pid !== undefined)
                    spawnedProcessIds.push(child.pid);
                  return child;
                },
                isProcessGroupAlive: adapter.isProcessGroupAlive,
                killProcessGroup: adapter.killProcessGroup,
              },
            });
            terminate = vi.fn((reason) => handle.terminate(reason));
            return { ...handle, terminate };
          },
        },
      ),
    ).toBe(3);

    expect(spawnedProcessIds).toHaveLength(1);
    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate).toHaveBeenCalledWith("supervisor_failure");
    expect(spawnedProcessIds.every((pid) => !isProcessAlive(pid))).toBe(true);
    expect(stream.listeners("error")).toEqual([applicationListener]);
    expect(applicationErrors).toHaveLength(1);
    expect(errors).toEqual(["governed runtime operation failed"]);
    expect(errors.join("\n")).not.toContain(
      "ATTACKER_REAL_EPIPE_DO_NOT_ESCAPE",
    );

    const { readdir } = await import("node:fs/promises");
    const [executionId] = await readdir(join(files.root, "receipts"));
    const receiptText = readFileSync(
      join(files.root, "receipts", executionId!, "receipts.jsonl"),
      "utf8",
    );
    const events = receiptText
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line).eventType as string);
    expect(
      events.filter((event) => event === "termination_requested"),
    ).toHaveLength(1);
    expect(events).toContain("supervisor_failed");
    expect(events.at(-1)).toBe("process_exited");
  });

  it.each([
    ["stdout", "large"],
    ["stderr", "large-stderr"],
  ] as const)(
    "contains an end-to-end early-closing %s pipe",
    async (streamName, mode) => {
      const files = setup(mode, "4000000");
      const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
      const command =
        streamName === "stdout"
          ? '"$@" | head -c 1 >/dev/null; status=${PIPESTATUS[0]}; exit "$status"'
          : '"$@" 3>&1 1>/dev/null 2>&3 | head -c 1 >/dev/null; status=${PIPESTATUS[0]}; exit "$status"';
      const stdoutPath = join(files.root, "cli-stdout.log");
      const stderrPath = join(files.root, "cli-stderr.log");
      const stdoutDescriptor = openSync(stdoutPath, "w", 0o600);
      const stderrDescriptor = openSync(stderrPath, "w", 0o600);
      const child = spawn(
        "bash",
        [
          "-o",
          "pipefail",
          "-c",
          command,
          "spts-early-close",
          "env",
          "MODEL_PROVIDER_VALUE=opaque",
          `SPTS_RECEIPT_AUTH_KEY=${authenticationKey}`,
          process.execPath,
          cli,
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          detached: true,
          env: process.env,
          stdio: ["ignore", stdoutDescriptor, stderrDescriptor],
        },
      );
      const processErrors: unknown[] = [];
      child.on("error", (error) => processErrors.push(error));
      const result = await new Promise<{
        readonly code: number | null;
        readonly signal: NodeJS.Signals | null;
      }>((resolve, reject) => {
        const timer = setTimeout(() => {
          try {
            if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
          } catch {
            // The close handler may have won the timeout race.
          }
          reject(new Error("early-closing pipe fixture timed out"));
        }, 10_000);
        child.once("close", (code, signal) => {
          clearTimeout(timer);
          resolve({ code, signal });
        });
      });
      closeSync(stdoutDescriptor);
      closeSync(stderrDescriptor);
      const stdoutText = readFileSync(stdoutPath, "utf8");
      const stderrText = readFileSync(stderrPath, "utf8");
      const visibleText = `${stdoutText}${stderrText}`;

      expect(result, visibleText).toEqual({ code: 3, signal: null });
      expect(processErrors).toEqual([]);
      expect(visibleText).not.toContain("EPIPE");
      expect(visibleText).not.toContain("Error:");
      if (streamName === "stdout")
        expect(stderrText).toBe("governed runtime operation failed\n");

      const { readdir } = await import("node:fs/promises");
      const executionIds = await readdir(join(files.root, "receipts"));
      expect(executionIds).toHaveLength(1);
      const receiptText = readFileSync(
        join(files.root, "receipts", executionIds[0]!, "receipts.jsonl"),
        "utf8",
      );
      expect(receiptText).toContain('"code":"output_callback_failed"');
      expect(receiptText).not.toContain("EPIPE");
    },
    15_000,
  );

  it.each([
    ["both registrations succeed", "both-succeed"],
    ["the first registration throws before its side effect", "first-before"],
    ["the first registration installs and then throws", "first-after"],
    ["the second registration throws before its side effect", "second-before"],
    ["the second registration installs and then throws", "second-after"],
  ] as const)(
    "conservatively finalizes signal ownership when %s",
    async (_label, scenario) => {
      const files = setup();
      const attackerMessage = "ATTACKER_REGISTRATION_DETAIL_DO_NOT_ESCAPE";
      const emitter = new EventEmitter();
      const baseline = {
        SIGINT: emitter.listenerCount("SIGINT"),
        SIGTERM: emitter.listenerCount("SIGTERM"),
      };
      const registrationAttempts: string[] = [];
      const removalAttempts: string[] = [];
      const errors: string[] = [];
      const terminate = vi.fn(async () => {});
      const fails = scenario !== "both-succeed";
      const expectedSignals = scenario.startsWith("first-")
        ? ["SIGINT"]
        : ["SIGINT", "SIGTERM"];

      try {
        expect(
          await runCli(
            [
              "run",
              "--manifest",
              files.manifestPath,
              "--operator-config",
              files.configPath,
            ],
            {
              writeOutput: () => {},
              writeError: (value) => errors.push(value),
              readEnvironment(name) {
                if (name === "PATH") return dirname(process.execPath);
                if (name === "MODEL_PROVIDER_VALUE") return "opaque";
                if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
                return undefined;
              },
              startGovernedLocalProcess: async () => ({
                executionId: `cli-registration-${scenario}`,
                started: Promise.resolve(),
                exit: Promise.resolve(
                  successfulResult(`cli-registration-${scenario}`),
                ),
                terminate,
              }),
              addSignalListener(signal, listener) {
                registrationAttempts.push(signal);
                if (
                  (signal === "SIGINT" && scenario === "first-before") ||
                  (signal === "SIGTERM" && scenario === "second-before")
                ) {
                  throw new Error(attackerMessage);
                }
                emitter.on(signal, listener);
                if (
                  (signal === "SIGINT" && scenario === "first-after") ||
                  (signal === "SIGTERM" && scenario === "second-after")
                ) {
                  throw new Error(attackerMessage);
                }
              },
              removeSignalListener(signal, listener) {
                removalAttempts.push(signal);
                emitter.off(signal, listener);
              },
            },
          ),
        ).toBe(fails ? 3 : 0);
        expect(registrationAttempts).toEqual(expectedSignals);
        expect(removalAttempts).toEqual(expectedSignals);
        expect(emitter.listenerCount("SIGINT")).toBe(baseline.SIGINT);
        expect(emitter.listenerCount("SIGTERM")).toBe(baseline.SIGTERM);
        expect(errors).toEqual(
          fails ? ["governed runtime operation failed"] : [],
        );
        expect(errors.join("\n")).not.toContain(attackerMessage);
        expect(terminate).toHaveBeenCalledTimes(fails ? 1 : 0);
        if (fails) expect(terminate).toHaveBeenCalledWith("supervisor_failure");
      } finally {
        emitter.removeAllListeners("SIGINT");
        emitter.removeAllListeners("SIGTERM");
      }

      expect(emitter.listenerCount("SIGINT")).toBe(baseline.SIGINT);
      expect(emitter.listenerCount("SIGTERM")).toBe(baseline.SIGTERM);
    },
  );

  it("continues conservative cleanup after an earlier removal throws", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_CONSERVATIVE_CLEANUP_DO_NOT_ESCAPE";
    const emitter = new EventEmitter();
    const baseline = {
      SIGINT: emitter.listenerCount("SIGINT"),
      SIGTERM: emitter.listenerCount("SIGTERM"),
    };
    const removalAttempts: string[] = [];
    const errors: string[] = [];

    try {
      expect(
        await runCli(
          [
            "run",
            "--manifest",
            files.manifestPath,
            "--operator-config",
            files.configPath,
          ],
          {
            writeOutput: () => {},
            writeError: (value) => errors.push(value),
            readEnvironment(name) {
              if (name === "PATH") return dirname(process.execPath);
              if (name === "MODEL_PROVIDER_VALUE") return "opaque";
              if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
              return undefined;
            },
            startGovernedLocalProcess: async () => ({
              executionId: "cli-conservative-cleanup-failure",
              started: Promise.resolve(),
              exit: Promise.resolve(
                successfulResult("cli-conservative-cleanup-failure"),
              ),
              terminate: vi.fn(async () => {}),
            }),
            addSignalListener(signal, listener) {
              emitter.on(signal, listener);
              if (signal === "SIGTERM") throw new Error(attackerMessage);
            },
            removeSignalListener(signal, listener) {
              removalAttempts.push(signal);
              emitter.off(signal, listener);
              if (signal === "SIGINT") throw new Error(attackerMessage);
            },
          },
        ),
      ).toBe(3);
      expect(removalAttempts).toEqual(["SIGINT", "SIGTERM"]);
      expect(emitter.listenerCount("SIGINT")).toBe(baseline.SIGINT);
      expect(emitter.listenerCount("SIGTERM")).toBe(baseline.SIGTERM);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
    } finally {
      emitter.removeAllListeners("SIGINT");
      emitter.removeAllListeners("SIGTERM");
    }

    expect(emitter.listenerCount("SIGINT")).toBe(baseline.SIGINT);
    expect(emitter.listenerCount("SIGTERM")).toBe(baseline.SIGTERM);
  });

  it("retains a partially registered live execution until termination and rejecting exit settle", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_DELAYED_EXIT_MESSAGE_DO_NOT_ESCAPE";
    const termination = deferred<void>();
    const exit = deferred<ExecutionResult>();
    const terminate = vi.fn(() => termination.promise);
    const removed: string[] = [];
    const errors: string[] = [];
    const processErrors: unknown[] = [];
    let runSettled = false;
    const onUnhandled = (error: unknown) => processErrors.push(error);
    const onUncaught = (error: unknown) => processErrors.push(error);
    process.on("unhandledRejection", onUnhandled);
    process.on("uncaughtException", onUncaught);

    try {
      const run = runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: () => {},
          writeError: (value) => errors.push(value),
          readEnvironment(name) {
            if (name === "PATH") return dirname(process.execPath);
            if (name === "MODEL_PROVIDER_VALUE") return "opaque";
            if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
            return undefined;
          },
          startGovernedLocalProcess: async () => ({
            executionId: "cli-pending-registration-failure",
            started: Promise.resolve(),
            exit: exit.promise,
            terminate,
          }),
          addSignalListener(signal) {
            if (signal === "SIGTERM") throw new Error(attackerMessage);
          },
          removeSignalListener(signal) {
            removed.push(signal);
          },
        },
      ).finally(() => {
        runSettled = true;
      });

      await new Promise((resolve) => setImmediate(resolve));
      expect(terminate).toHaveBeenCalledTimes(1);
      expect(terminate).toHaveBeenCalledWith("supervisor_failure");
      expect(runSettled).toBe(false);

      termination.resolve();
      await new Promise((resolve) => setImmediate(resolve));
      expect(runSettled).toBe(false);

      exit.reject(new Error(attackerMessage));
      expect(await run).toBe(3);
      await new Promise((resolve) => setImmediate(resolve));
      expect(removed).toEqual(["SIGINT", "SIGTERM"]);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
      expect(processErrors).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      process.off("uncaughtException", onUncaught);
    }
  });

  it.each([
    [
      "termination rejects before exit resolves",
      "reject",
      "resolve",
      "termination",
    ],
    [
      "termination resolves before exit rejects",
      "resolve",
      "reject",
      "termination",
    ],
    ["termination and exit both reject", "reject", "reject", "termination"],
  ] as const)(
    "contains %s after partial registration",
    async (_label, terminationMode, exitMode, firstSettlement) => {
      const files = setup();
      const attackerMessage = "ATTACKER_FINALIZATION_MESSAGE_DO_NOT_ESCAPE";
      const termination = deferred<void>();
      const exit = deferred<ExecutionResult>();
      const terminate = vi.fn(() => termination.promise);
      const errors: string[] = [];
      const removed: string[] = [];
      const processErrors: unknown[] = [];
      let runSettled = false;
      const onUnhandled = (error: unknown) => processErrors.push(error);
      const onUncaught = (error: unknown) => processErrors.push(error);
      process.on("unhandledRejection", onUnhandled);
      process.on("uncaughtException", onUncaught);

      const settleTermination = () => {
        if (terminationMode === "resolve") termination.resolve();
        else termination.reject(new Error(attackerMessage));
      };
      const settleExit = () => {
        if (exitMode === "resolve")
          exit.resolve(successfulResult("cli-finalization-matrix"));
        else exit.reject(new Error(attackerMessage));
      };

      try {
        const run = runCli(
          [
            "run",
            "--manifest",
            files.manifestPath,
            "--operator-config",
            files.configPath,
          ],
          {
            writeOutput: () => {},
            writeError: (value) => errors.push(value),
            readEnvironment(name) {
              if (name === "PATH") return dirname(process.execPath);
              if (name === "MODEL_PROVIDER_VALUE") return "opaque";
              if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
              return undefined;
            },
            startGovernedLocalProcess: async () => ({
              executionId: "cli-finalization-matrix",
              started: Promise.resolve(),
              exit: exit.promise,
              terminate,
            }),
            addSignalListener(signal) {
              if (signal === "SIGTERM") throw new Error(attackerMessage);
            },
            removeSignalListener(signal) {
              removed.push(signal);
            },
          },
        ).finally(() => {
          runSettled = true;
        });

        await new Promise((resolve) => setImmediate(resolve));
        expect(terminate).toHaveBeenCalledTimes(1);
        expect(runSettled).toBe(false);

        if (firstSettlement === "termination") settleTermination();
        else settleExit();
        await new Promise((resolve) => setImmediate(resolve));
        expect(runSettled).toBe(false);

        if (firstSettlement === "termination") settleExit();
        else settleTermination();
        expect(await run).toBe(3);
        await new Promise((resolve) => setImmediate(resolve));
        expect(removed).toEqual(["SIGINT", "SIGTERM"]);
        expect(errors).toEqual(["governed runtime operation failed"]);
        expect(errors.join("\n")).not.toContain(attackerMessage);
        expect(processErrors).toEqual([]);
      } finally {
        process.off("unhandledRejection", onUnhandled);
        process.off("uncaughtException", onUncaught);
      }
    },
  );

  it("contains an exit rejection that occurs during partial registration", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_EARLY_EXIT_MESSAGE_DO_NOT_ESCAPE";
    const exit = deferred<ExecutionResult>();
    const terminate = vi.fn(async () => {});
    const listeners = new Map<string, () => void>();
    const errors: string[] = [];
    const processErrors: unknown[] = [];
    const onUnhandled = (error: unknown) => processErrors.push(error);
    const onUncaught = (error: unknown) => processErrors.push(error);
    process.on("unhandledRejection", onUnhandled);
    process.on("uncaughtException", onUncaught);

    try {
      expect(
        await runCli(
          [
            "run",
            "--manifest",
            files.manifestPath,
            "--operator-config",
            files.configPath,
          ],
          {
            writeOutput: () => {},
            writeError: (value) => errors.push(value),
            readEnvironment(name) {
              if (name === "PATH") return dirname(process.execPath);
              if (name === "MODEL_PROVIDER_VALUE") return "opaque";
              if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
              return undefined;
            },
            startGovernedLocalProcess: async () => ({
              executionId: "cli-early-exit-rejection",
              started: Promise.resolve(),
              exit: exit.promise,
              terminate,
            }),
            addSignalListener(signal, listener) {
              listeners.set(signal, listener);
              if (signal === "SIGINT") exit.reject(new Error(attackerMessage));
              if (signal === "SIGTERM") throw new Error(attackerMessage);
            },
            removeSignalListener: () => {},
          },
        ),
      ).toBe(3);
      await new Promise((resolve) => setImmediate(resolve));
      expect(terminate).toHaveBeenCalledTimes(1);
      expect(terminate).toHaveBeenCalledWith("supervisor_failure");
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
      expect(processErrors).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      process.off("uncaughtException", onUncaught);
    }
  });

  it("deduplicates a repeated-signal and registration-failure race", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_REGISTRATION_RACE_DO_NOT_ESCAPE";
    const exit = deferred<ExecutionResult>();
    const listeners = new Map<string, () => void>();
    const terminate = vi.fn(async () => {
      exit.resolve(successfulResult("cli-registration-race"));
    });

    expect(
      await runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: () => {},
          writeError: () => {},
          readEnvironment(name) {
            if (name === "PATH") return dirname(process.execPath);
            if (name === "MODEL_PROVIDER_VALUE") return "opaque";
            if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
            return undefined;
          },
          startGovernedLocalProcess: async () => ({
            executionId: "cli-registration-race",
            started: Promise.resolve(),
            exit: exit.promise,
            terminate,
          }),
          addSignalListener(signal, listener) {
            listeners.set(signal, listener);
            if (signal === "SIGTERM") {
              listeners.get("SIGINT")!();
              listeners.get("SIGINT")!();
              throw new Error(attackerMessage);
            }
          },
          removeSignalListener: () => {},
        },
      ),
    ).toBe(3);
    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate).toHaveBeenCalledWith("supervisor_failure");
  });

  it("finalizes a controlled real process after partial registration", async () => {
    const files = setup("delay", "10000");
    const adapter = createNodeProcessAdapter();
    const emitter = new EventEmitter();
    const baseline = {
      SIGINT: emitter.listenerCount("SIGINT"),
      SIGTERM: emitter.listenerCount("SIGTERM"),
    };
    const spawnedProcessIds: number[] = [];
    const removed: string[] = [];
    let terminate: ReturnType<typeof vi.fn> | undefined;

    try {
      expect(
        await runCli(
          [
            "run",
            "--manifest",
            files.manifestPath,
            "--operator-config",
            files.configPath,
          ],
          {
            writeOutput: () => {},
            writeError: () => {},
            readEnvironment(name) {
              if (name === "PATH") return dirname(process.execPath);
              if (name === "MODEL_PROVIDER_VALUE") return "opaque";
              if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
              return undefined;
            },
            startGovernedLocalProcess: async (options) => {
              const handle = await startGovernedLocalProcess({
                ...options,
                processAdapter: {
                  platform: adapter.platform,
                  spawn(executable, arguments_, spawnOptions) {
                    const child = adapter.spawn(
                      executable,
                      arguments_,
                      spawnOptions,
                    );
                    if (child.pid !== undefined)
                      spawnedProcessIds.push(child.pid);
                    return child;
                  },
                  isProcessGroupAlive: (processGroupId) =>
                    adapter.isProcessGroupAlive(processGroupId),
                  killProcessGroup: (processGroupId, signal) =>
                    adapter.killProcessGroup(processGroupId, signal),
                },
              });
              terminate = vi.fn((reason) => handle.terminate(reason));
              return { ...handle, terminate };
            },
            addSignalListener(signal, listener) {
              emitter.on(signal, listener);
              if (signal === "SIGTERM") throw new Error("fixture registration");
            },
            removeSignalListener(signal, listener) {
              removed.push(signal);
              emitter.off(signal, listener);
            },
          },
        ),
      ).toBe(3);
      expect(spawnedProcessIds).toHaveLength(1);
      expect(terminate).toHaveBeenCalledTimes(1);
      expect(terminate).toHaveBeenCalledWith("supervisor_failure");
      expect(removed).toEqual(["SIGINT", "SIGTERM"]);
      expect(emitter.listenerCount("SIGINT")).toBe(baseline.SIGINT);
      expect(emitter.listenerCount("SIGTERM")).toBe(baseline.SIGTERM);
      expect(
        spawnedProcessIds.every((processId) => !isProcessAlive(processId)),
      ).toBe(true);
    } finally {
      emitter.removeAllListeners("SIGINT");
      emitter.removeAllListeners("SIGTERM");
    }

    expect(emitter.listenerCount("SIGINT")).toBe(baseline.SIGINT);
    expect(emitter.listenerCount("SIGTERM")).toBe(baseline.SIGTERM);
  });

  it("cleans an earlier listener when later signal registration fails", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_REGISTRATION_MESSAGE_DO_NOT_ESCAPE";
    const listeners = new Map<string, () => void>();
    const removed: string[] = [];
    const errors: string[] = [];

    expect(
      await runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: () => {},
          writeError: (value) => errors.push(value),
          readEnvironment(name) {
            if (name === "PATH") return dirname(process.execPath);
            if (name === "MODEL_PROVIDER_VALUE") return "opaque";
            if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
            return undefined;
          },
          startGovernedLocalProcess: async () => ({
            executionId: "cli-registration-failure",
            started: Promise.resolve(),
            exit: Promise.resolve({
              executionId: "cli-registration-failure",
              outcome: "succeeded" as const,
              exitCode: 0,
              signal: null,
              stdout: { bytes: 0, sha256: "0".repeat(64) },
              stderr: { bytes: 0, sha256: "0".repeat(64) },
            }),
            terminate: vi.fn(async () => {}),
          }),
          addSignalListener(signal, listener) {
            if (signal === "SIGTERM") throw new Error(attackerMessage);
            listeners.set(signal, listener);
          },
          removeSignalListener(signal) {
            removed.push(signal);
          },
        },
      ),
    ).toBe(3);
    expect(removed).toEqual(["SIGINT", "SIGTERM"]);
    expect(errors).toEqual(["governed runtime operation failed"]);
    expect(errors.join("\n")).not.toContain(attackerMessage);
  });

  it("still reports a controlled failure when partial-registration cleanup fails", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_PARTIAL_CLEANUP_MESSAGE_DO_NOT_ESCAPE";
    const removed: string[] = [];
    const errors: string[] = [];

    expect(
      await runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: () => {},
          writeError: (value) => errors.push(value),
          readEnvironment(name) {
            if (name === "PATH") return dirname(process.execPath);
            if (name === "MODEL_PROVIDER_VALUE") return "opaque";
            if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
            return undefined;
          },
          startGovernedLocalProcess: async () => ({
            executionId: "cli-registration-cleanup-failure",
            started: Promise.resolve(),
            exit: Promise.resolve({
              executionId: "cli-registration-cleanup-failure",
              outcome: "succeeded" as const,
              exitCode: 0,
              signal: null,
              stdout: { bytes: 0, sha256: "0".repeat(64) },
              stderr: { bytes: 0, sha256: "0".repeat(64) },
            }),
            terminate: vi.fn(async () => {}),
          }),
          addSignalListener(signal) {
            if (signal === "SIGTERM") throw new Error(attackerMessage);
          },
          removeSignalListener(signal) {
            removed.push(signal);
            throw new Error(attackerMessage);
          },
        },
      ),
    ).toBe(3);
    expect(removed).toEqual(["SIGINT", "SIGTERM"]);
    expect(errors).toEqual(["governed runtime operation failed"]);
    expect(errors.join("\n")).not.toContain(attackerMessage);
  });

  it.each([
    ["the first removal", new Set(["SIGINT"])],
    ["both removals", new Set(["SIGINT", "SIGTERM"])],
  ])(
    "attempts every installed listener once when %s throws",
    async (_label, failingSignals) => {
      const files = setup();
      const attackerMessage = "ATTACKER_REMOVAL_MESSAGE_DO_NOT_ESCAPE";
      const removed: string[] = [];
      const errors: string[] = [];

      expect(
        await runCli(
          [
            "run",
            "--manifest",
            files.manifestPath,
            "--operator-config",
            files.configPath,
          ],
          {
            writeOutput: () => {},
            writeError: (value) => errors.push(value),
            readEnvironment(name) {
              if (name === "PATH") return dirname(process.execPath);
              if (name === "MODEL_PROVIDER_VALUE") return "opaque";
              if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
              return undefined;
            },
            startGovernedLocalProcess: async () => ({
              executionId: "cli-removal-failure",
              started: Promise.resolve(),
              exit: Promise.resolve({
                executionId: "cli-removal-failure",
                outcome: "succeeded" as const,
                exitCode: 0,
                signal: null,
                stdout: { bytes: 0, sha256: "0".repeat(64) },
                stderr: { bytes: 0, sha256: "0".repeat(64) },
              }),
              terminate: vi.fn(async () => {}),
            }),
            addSignalListener: () => {},
            removeSignalListener(signal) {
              removed.push(signal);
              if (failingSignals.has(signal)) throw new Error(attackerMessage);
            },
          },
        ),
      ).toBe(3);
      expect(removed).toEqual(["SIGINT", "SIGTERM"]);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
    },
  );

  it("attempts every listener after runtime and cleanup failures", async () => {
    const files = setup();
    const attackerMessage = "ATTACKER_RUNTIME_CLEANUP_MESSAGE_DO_NOT_ESCAPE";
    const listeners = new Map<string, () => void>();
    const removed: string[] = [];
    const errors: string[] = [];
    let rejectExit!: (reason: unknown) => void;
    const exit = new Promise<never>((_resolve, reject) => {
      rejectExit = reject;
    });
    const run = runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: (value) => errors.push(value),
        readEnvironment(name) {
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "opaque";
          if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
          return undefined;
        },
        startGovernedLocalProcess: async () => ({
          executionId: "cli-runtime-cleanup-failure",
          started: Promise.resolve(),
          exit,
          terminate: vi.fn(async () => {}),
        }),
        addSignalListener(signal, listener) {
          listeners.set(signal, listener);
        },
        removeSignalListener(signal) {
          removed.push(signal);
          if (signal === "SIGINT") throw new Error(attackerMessage);
        },
      },
    );
    while (!listeners.has("SIGTERM"))
      await new Promise((resolve) => setTimeout(resolve, 1));
    rejectExit(new Error(attackerMessage));

    expect(await run).toBe(3);
    expect(removed).toEqual(["SIGINT", "SIGTERM"]);
    expect(errors).toEqual(["governed runtime operation failed"]);
    expect(errors.join("\n")).not.toContain(attackerMessage);
  });

  it("forwards supervisor signals through the live handle and cleans listeners", async () => {
    const files = setup("delay", "10000");
    const listeners = new Map<string, () => void>();
    const removed: string[] = [];
    const run = runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment(name) {
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "opaque";
          if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
          return undefined;
        },
        addSignalListener(signal, listener) {
          listeners.set(signal, listener);
        },
        removeSignalListener(signal) {
          removed.push(signal);
        },
      },
    );
    while (!listeners.has("SIGINT")) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    listeners.get("SIGINT")!();

    expect(await run).toBe(11);
    expect(removed.sort()).toEqual(["SIGINT", "SIGTERM"]);
  });

  it("observes signal termination rejection without leaking it or emitting process errors", async () => {
    const files = setup("delay", "10000");
    const attackerMessage = "ATTACKER_TERMINATION_MESSAGE_DO_NOT_ESCAPE";
    const listeners = new Map<string, () => void>();
    const removed: Array<{ signal: string; listener: () => void }> = [];
    const errors: string[] = [];
    const processErrors: unknown[] = [];
    let rejectTermination!: (reason: unknown) => void;
    let resolveExit!: (result: {
      executionId: string;
      outcome: "succeeded";
      exitCode: number;
      signal: null;
      stdout: { bytes: number; sha256: string };
      stderr: { bytes: number; sha256: string };
    }) => void;
    const termination = new Promise<void>((_resolve, reject) => {
      rejectTermination = reject;
    });
    const exit = new Promise<{
      executionId: string;
      outcome: "succeeded";
      exitCode: number;
      signal: null;
      stdout: { bytes: number; sha256: string };
      stderr: { bytes: number; sha256: string };
    }>((resolve) => {
      resolveExit = resolve;
    });
    const terminate = vi.fn(() => termination);
    const onUnhandled = (error: unknown) => processErrors.push(error);
    const onUncaught = (error: unknown) => processErrors.push(error);
    process.on("unhandledRejection", onUnhandled);
    process.on("uncaughtException", onUncaught);

    try {
      const run = runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: () => {},
          writeError: (value) => errors.push(value),
          readEnvironment(name) {
            if (name === "PATH") return dirname(process.execPath);
            if (name === "MODEL_PROVIDER_VALUE") return "opaque";
            if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
            return undefined;
          },
          startGovernedLocalProcess: async () => ({
            executionId: "cli-signal-rejection",
            started: Promise.resolve(),
            exit,
            terminate,
          }),
          addSignalListener(signal, listener) {
            listeners.set(signal, listener);
          },
          removeSignalListener(signal, listener) {
            removed.push({ signal, listener });
          },
        },
      );
      while (!listeners.has("SIGTERM"))
        await new Promise((resolve) => setTimeout(resolve, 1));

      listeners.get("SIGTERM")!();
      listeners.get("SIGTERM")!();
      resolveExit({
        executionId: "cli-signal-rejection",
        outcome: "succeeded",
        exitCode: 0,
        signal: null,
        stdout: { bytes: 0, sha256: "0".repeat(64) },
        stderr: { bytes: 0, sha256: "0".repeat(64) },
      });
      rejectTermination(new Error(attackerMessage));

      expect(await run).toBe(3);
      await new Promise((resolve) => setImmediate(resolve));
      expect(terminate).toHaveBeenCalledTimes(1);
      expect(errors).toEqual(["governed runtime operation failed"]);
      expect(errors.join("\n")).not.toContain(attackerMessage);
      expect(processErrors).toEqual([]);
      expect(removed).toEqual([
        { signal: "SIGINT", listener: listeners.get("SIGINT")! },
        { signal: "SIGTERM", listener: listeners.get("SIGTERM")! },
      ]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      process.off("uncaughtException", onUncaught);
    }
  });

  it("deduplicates successful repeated signals and still awaits normal finalization", async () => {
    const files = setup("delay", "10000");
    const listeners = new Map<string, () => void>();
    const removed: string[] = [];
    let resolveExit!: (result: {
      executionId: string;
      outcome: "signaled";
      exitCode: null;
      signal: "SIGTERM";
      stdout: { bytes: number; sha256: string };
      stderr: { bytes: number; sha256: string };
    }) => void;
    const exit = new Promise<{
      executionId: string;
      outcome: "signaled";
      exitCode: null;
      signal: "SIGTERM";
      stdout: { bytes: number; sha256: string };
      stderr: { bytes: number; sha256: string };
    }>((resolve) => {
      resolveExit = resolve;
    });
    const terminate = vi.fn(async () => {});
    const run = runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment(name) {
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "opaque";
          if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
          return undefined;
        },
        startGovernedLocalProcess: async () => ({
          executionId: "cli-signal-success",
          started: Promise.resolve(),
          exit,
          terminate,
        }),
        addSignalListener(signal, listener) {
          listeners.set(signal, listener);
        },
        removeSignalListener(signal) {
          removed.push(signal);
        },
      },
    );
    while (!listeners.has("SIGINT"))
      await new Promise((resolve) => setTimeout(resolve, 1));

    listeners.get("SIGINT")!();
    listeners.get("SIGTERM")!();
    resolveExit({
      executionId: "cli-signal-success",
      outcome: "signaled",
      exitCode: null,
      signal: "SIGTERM",
      stdout: { bytes: 0, sha256: "0".repeat(64) },
      stderr: { bytes: 0, sha256: "0".repeat(64) },
    });

    expect(await run).toBe(11);
    expect(terminate).toHaveBeenCalledTimes(1);
    expect(removed).toEqual(["SIGINT", "SIGTERM"]);
  });

  it("preserves a normal exit that wins a simultaneous signal race", async () => {
    const files = setup();
    const listeners = new Map<string, () => void>();
    const removed: string[] = [];
    let resolveExit!: (result: {
      executionId: string;
      outcome: "succeeded";
      exitCode: number;
      signal: null;
      stdout: { bytes: number; sha256: string };
      stderr: { bytes: number; sha256: string };
    }) => void;
    const exit = new Promise<{
      executionId: string;
      outcome: "succeeded";
      exitCode: number;
      signal: null;
      stdout: { bytes: number; sha256: string };
      stderr: { bytes: number; sha256: string };
    }>((resolve) => {
      resolveExit = resolve;
    });
    const terminate = vi.fn(async () => {});
    const run = runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment(name) {
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "opaque";
          if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
          return undefined;
        },
        startGovernedLocalProcess: async () => ({
          executionId: "cli-exit-signal-race",
          started: Promise.resolve(),
          exit,
          terminate,
        }),
        addSignalListener(signal, listener) {
          listeners.set(signal, listener);
        },
        removeSignalListener(signal) {
          removed.push(signal);
        },
      },
    );
    while (!listeners.has("SIGTERM"))
      await new Promise((resolve) => setTimeout(resolve, 1));

    resolveExit({
      executionId: "cli-exit-signal-race",
      outcome: "succeeded",
      exitCode: 0,
      signal: null,
      stdout: { bytes: 0, sha256: "0".repeat(64) },
      stderr: { bytes: 0, sha256: "0".repeat(64) },
    });
    listeners.get("SIGTERM")!();

    expect(await run).toBe(0);
    expect(terminate).toHaveBeenCalledTimes(1);
    expect(removed).toEqual(["SIGINT", "SIGTERM"]);
  });

  it("requires authenticated trusted-parent inspection and has stable usage codes", async () => {
    const files = setup();
    const environment = (name: string) => {
      if (name === "PATH") return dirname(process.execPath);
      if (name === "MODEL_PROVIDER_VALUE") return "opaque";
      if (name === "SPTS_RECEIPT_AUTH_KEY") return authenticationKey;
      return undefined;
    };
    expect(
      await runCli(
        [
          "run",
          "--manifest",
          files.manifestPath,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: () => {},
          writeError: () => {},
          readEnvironment: environment,
        },
      ),
    ).toBe(0);
    const { readdir } = await import("node:fs/promises");
    const [executionId] = await readdir(join(files.root, "receipts"));
    const output: string[] = [];
    const reads: string[] = [];
    expect(
      await runCli(
        [
          "inspect",
          "--execution-id",
          executionId!,
          "--operator-config",
          files.configPath,
        ],
        {
          writeOutput: (value) => output.push(value),
          writeError: () => {},
          readEnvironment(name) {
            reads.push(name);
            return name === "SPTS_RECEIPT_AUTH_KEY"
              ? authenticationKey
              : undefined;
          },
        },
      ),
    ).toBe(0);
    expect(reads).toEqual(["SPTS_RECEIPT_AUTH_KEY"]);
    expect(output.join("\n")).toContain('"valid": true');
    expect(
      await runCli(["unknown"], {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment: () => undefined,
      }),
    ).toBe(2);
  });
});

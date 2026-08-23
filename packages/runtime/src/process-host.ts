import {
  spawn,
  type ChildProcessByStdio,
  type SpawnOptions,
} from "node:child_process";
import { createHash } from "node:crypto";
import type { Readable } from "node:stream";

import {
  LIFECYCLE_RECEIPT_CONTRACT_ID,
  LIFECYCLE_RECEIPT_VERSION,
  canonicalSerializeLifecycleValue,
  computeLifecycleReceiptDigest,
  containsCredentialShapedContent,
  validateLifecycleReceipt,
  type LifecycleEventPayload,
  type LifecycleEventType,
  type LifecycleReceipt,
  type StreamEvidence,
  type TerminationReason,
} from "@scrum-pi-team-skills/contracts";

import {
  constructEnvironment,
  requireRuntimePolicy,
  RuntimeHostError,
  type OperatorEnvironmentPolicy,
  type RuntimePolicy,
} from "./policies.js";
import { requireIssuedPiLaunchPlan, type PiLaunchPlan } from "./index.js";

export interface ReceiptWriter {
  append(line: string): void | Promise<void>;
  close(): void | Promise<void>;
}

export interface ReceiptSink {
  open(execution: {
    readonly executionId: string;
    readonly contractId: typeof LIFECYCLE_RECEIPT_CONTRACT_ID;
    readonly contractVersion: typeof LIFECYCLE_RECEIPT_VERSION;
  }): ReceiptWriter | Promise<ReceiptWriter>;
}

type ManagedChild = ChildProcessByStdio<null, Readable, Readable>;

export interface ProcessAdapter {
  readonly platform: NodeJS.Platform;
  spawn(
    executable: string,
    arguments_: readonly string[],
    options: SpawnOptions,
  ): ManagedChild;
  killProcessGroup(processGroupId: number, signal: "SIGTERM" | "SIGKILL"): void;
}

export interface RuntimeClock {
  now(): string;
  setTimeout(callback: () => void, milliseconds: number): unknown;
  clearTimeout(timer: unknown): void;
}

export type ExecutionOutcome =
  | "succeeded"
  | "nonzero"
  | "signaled"
  | "timed_out"
  | "supervisor_failed"
  | "spawn_failed";

export interface ExecutionResult {
  readonly executionId: string;
  readonly outcome: ExecutionOutcome;
  readonly exitCode: number | null;
  readonly signal: "SIGINT" | "SIGTERM" | "SIGKILL" | null;
  readonly stdout: StreamEvidence;
  readonly stderr: StreamEvidence;
}

export interface SupervisedExecution {
  readonly executionId: string;
  readonly started: Promise<void>;
  readonly exit: Promise<ExecutionResult>;
  terminate(reason?: TerminationReason): Promise<void>;
}

export interface StartGovernedLocalProcessOptions {
  readonly plan: PiLaunchPlan;
  readonly environmentPolicy: OperatorEnvironmentPolicy;
  readonly runtimePolicy: RuntimePolicy;
  readonly receiptSink: ReceiptSink;
  readonly executionIdSource: () => string;
  readonly clock?: RuntimeClock;
  readonly processAdapter?: ProcessAdapter;
  readonly signal?: AbortSignal;
  readonly onStdout?: (chunk: Uint8Array) => void | Promise<void>;
  readonly onStderr?: (chunk: Uint8Array) => void | Promise<void>;
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const defaultClock: RuntimeClock = Object.freeze({
  now: () => new Date().toISOString(),
  setTimeout: (callback: () => void, milliseconds: number) =>
    setTimeout(callback, milliseconds),
  clearTimeout: (timer: unknown) => clearTimeout(timer as NodeJS.Timeout),
});

/**
 * detached:true is used only to make the child the leader of a dedicated POSIX
 * process group. The child is never unref'ed: pipes, listeners, and the wait
 * lifecycle stay owned by this foreground supervisor.
 */
export function createNodeProcessAdapter(): ProcessAdapter {
  return Object.freeze({
    platform: process.platform,
    spawn(
      executable: string,
      arguments_: readonly string[],
      options: SpawnOptions,
    ) {
      return spawn(
        executable,
        [...arguments_],
        options,
      ) as unknown as ManagedChild;
    },
    killProcessGroup(processGroupId: number, signal: "SIGTERM" | "SIGKILL") {
      process.kill(-processGroupId, signal);
    },
  });
}

function byteLength(values: readonly string[]): number {
  return values.reduce((total, value) => total + Buffer.byteLength(value), 0);
}

function normalizeSignal(
  signal: NodeJS.Signals | null,
): "SIGINT" | "SIGTERM" | "SIGKILL" | null {
  return signal === "SIGINT" || signal === "SIGTERM" || signal === "SIGKILL"
    ? signal
    : null;
}

function streamEvidence(
  bytes: number,
  hash: ReturnType<typeof createHash>,
): StreamEvidence {
  return Object.freeze({ bytes, sha256: hash.digest("hex") });
}

function outcomeFor(
  exitCode: number | null,
  signal: NodeJS.Signals | null,
  timedOut: boolean,
  supervisorFailed: boolean,
): Exclude<ExecutionOutcome, "spawn_failed"> {
  if (supervisorFailed) return "supervisor_failed";
  if (timedOut) return "timed_out";
  if (signal !== null) return "signaled";
  return exitCode === 0 ? "succeeded" : "nonzero";
}

function fixedSinkError(): RuntimeHostError {
  return new RuntimeHostError("receipt sink failed");
}

/** Launch one authentic plan and retain sole live authority over its process group. */
export async function startGovernedLocalProcess(
  options: StartGovernedLocalProcessOptions,
): Promise<SupervisedExecution> {
  const authority = requireIssuedPiLaunchPlan(options.plan);
  requireRuntimePolicy(options.runtimePolicy);
  const adapter = options.processAdapter ?? createNodeProcessAdapter();
  if (adapter.platform !== "linux") {
    throw new RuntimeHostError(
      "governed local runtime supports Linux/WSL only",
    );
  }
  const requiredListenerBudget = options.signal ? 7 : 6;
  if (requiredListenerBudget > options.runtimePolicy.maximumListeners) {
    throw new RuntimeHostError("runtime listener budget is too small");
  }
  if (
    options.plan.arguments.length > options.runtimePolicy.maximumArgvCount ||
    byteLength([options.plan.executable, ...options.plan.arguments]) >
      options.runtimePolicy.maximumArgvBytes
  ) {
    throw new RuntimeHostError("launch argv exceeds the runtime policy");
  }
  const environment = constructEnvironment(
    options.environmentPolicy,
    options.plan.environment,
    options.runtimePolicy,
  );
  const executionId = options.executionIdSource();
  if (
    typeof executionId !== "string" ||
    !SAFE_ID.test(executionId) ||
    containsCredentialShapedContent(executionId)
  ) {
    throw new RuntimeHostError(
      "execution identifier source returned an invalid value",
    );
  }

  const clock = options.clock ?? defaultClock;
  let writer: ReceiptWriter;
  try {
    writer = await options.receiptSink.open({
      executionId,
      contractId: LIFECYCLE_RECEIPT_CONTRACT_ID,
      contractVersion: LIFECYCLE_RECEIPT_VERSION,
    });
  } catch {
    throw fixedSinkError();
  }

  let sequence = 0;
  let previousReceiptDigest: string | null = null;
  let receiptQueue = Promise.resolve();
  let sinkFailed = false;
  const record = (
    eventType: LifecycleEventType,
    payload: LifecycleEventPayload,
  ): Promise<void> => {
    const operation = receiptQueue.then(async () => {
      if (sinkFailed) throw fixedSinkError();
      if (
        Buffer.byteLength(canonicalSerializeLifecycleValue(payload)) >
        options.runtimePolicy.maximumReceiptPayloadBytes
      ) {
        throw new RuntimeHostError(
          "receipt payload exceeds the runtime policy",
        );
      }
      const unsigned = {
        contractId: LIFECYCLE_RECEIPT_CONTRACT_ID,
        contractVersion: LIFECYCLE_RECEIPT_VERSION,
        executionId,
        correlation: {
          manifestExecutionId: options.plan.correlation.executionId,
          pacaProjectId: options.plan.correlation.pacaProjectId,
          pacaTaskId: options.plan.correlation.pacaTaskId,
        },
        planDigest: authority.planDigest,
        trustedPolicyIds: {
          launch: authority.launchPolicyId,
          environment: options.environmentPolicy.policyId,
          runtime: options.runtimePolicy.policyId,
        },
        sequence: sequence + 1,
        timestamp: clock.now(),
        eventType,
        payload,
        previousReceiptDigest,
      };
      const receipt = {
        ...unsigned,
        receiptDigest: "",
      } as LifecycleReceipt;
      const completed = {
        ...unsigned,
        receiptDigest: computeLifecycleReceiptDigest(receipt),
      } as LifecycleReceipt;
      if (!validateLifecycleReceipt(completed).valid) {
        throw new RuntimeHostError("lifecycle receipt validation failed");
      }
      try {
        await writer.append(canonicalSerializeLifecycleValue(completed));
      } catch {
        sinkFailed = true;
        throw fixedSinkError();
      }
      sequence += 1;
      previousReceiptDigest = completed.receiptDigest;
    });
    receiptQueue = operation.catch(() => {});
    return operation;
  };

  try {
    await record("launch_requested", {});
  } catch (error) {
    try {
      await writer.close();
    } catch {
      // The fixed sink error below remains the only exposed diagnostic.
    }
    throw error;
  }

  const started = deferred<void>();
  const exited = deferred<ExecutionResult>();
  const rawClosed = deferred<void>();
  const stdoutHash = createHash("sha256");
  const stderrHash = createHash("sha256");
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let child: ManagedChild;
  let spawned = false;
  let closed = false;
  let finalized = false;
  let timedOut = false;
  let supervisorFailed = false;
  let terminationPromise: Promise<void> | null = null;
  let runtimeTimer: unknown;
  let graceTimer: unknown;
  let abortListener: (() => void) | null = null;
  let stdoutPending = Promise.resolve();
  let stderrPending = Promise.resolve();

  const cleanup = (): void => {
    if (runtimeTimer !== undefined) clock.clearTimeout(runtimeTimer);
    if (graceTimer !== undefined) clock.clearTimeout(graceTimer);
    if (abortListener && options.signal) {
      options.signal.removeEventListener("abort", abortListener);
    }
    abortListener = null;
  };

  const closeWriter = async (): Promise<void> => {
    try {
      await writer.close();
    } catch {
      sinkFailed = true;
      throw fixedSinkError();
    }
  };

  const sendGroupSignal = async (
    signal: "SIGTERM" | "SIGKILL",
  ): Promise<void> => {
    if (
      closed ||
      !spawned ||
      child.pid === undefined ||
      child.exitCode !== null ||
      child.signalCode !== null
    ) {
      return;
    }
    try {
      adapter.killProcessGroup(child.pid, signal);
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code === "ESRCH" || closed) return;
      supervisorFailed = true;
      try {
        await record("supervisor_failed", { code: "signal_failed" });
      } catch {
        // Cleanup continues even when the receipt sink is the failing component.
      }
      throw new RuntimeHostError("process-group signaling failed");
    }
  };

  const waitGrace = (): Promise<void> =>
    new Promise((resolve) => {
      graceTimer = clock.setTimeout(
        resolve,
        options.runtimePolicy.terminationGraceMs,
      );
    });

  const terminate = (reason: TerminationReason = "caller"): Promise<void> => {
    if (terminationPromise) return terminationPromise;
    terminationPromise = (async () => {
      if (!spawned && !closed) {
        await Promise.race([
          started.promise.catch(() => {}),
          rawClosed.promise,
        ]);
      }
      if (closed || !spawned) return;
      try {
        await record("termination_requested", { reason });
      } catch {
        supervisorFailed = true;
      }
      try {
        await sendGroupSignal("SIGTERM");
      } catch {
        // Escalation still runs so a supervision failure cannot abandon the group.
      }
      await Promise.race([rawClosed.promise, waitGrace()]);
      if (!closed) {
        try {
          await record("process_killed", { signal: "SIGKILL" });
        } catch {
          supervisorFailed = true;
        }
        try {
          await sendGroupSignal("SIGKILL");
        } catch {
          // The final wait and fixed failure reporting remain deterministic.
        }
      }
      await rawClosed.promise;
    })();
    return terminationPromise;
  };

  const supervisorFailure = async (
    stream: "stdout" | "stderr",
  ): Promise<void> => {
    if (supervisorFailed) return;
    supervisorFailed = true;
    try {
      await record("supervisor_failed", {
        code: "output_callback_failed",
        stream,
      });
    } catch {
      sinkFailed = true;
    }
    await terminate("supervisor_failure");
  };

  const consume = (
    stream: Readable,
    name: "stdout" | "stderr",
    callback: ((chunk: Uint8Array) => void | Promise<void>) | undefined,
    chunk: Buffer,
  ): void => {
    if (name === "stdout") {
      stdoutBytes += chunk.byteLength;
      stdoutHash.update(chunk);
    } else {
      stderrBytes += chunk.byteLength;
      stderrHash.update(chunk);
    }
    if (!callback) return;
    stream.pause();
    const pending = Promise.resolve()
      .then(() => callback(chunk))
      .catch(() => supervisorFailure(name))
      .finally(() => {
        if (!closed) stream.resume();
      });
    if (name === "stdout") stdoutPending = pending;
    else stderrPending = pending;
  };

  try {
    child = adapter.spawn(options.plan.executable, options.plan.arguments, {
      cwd: options.plan.workingDirectory,
      env: environment,
      shell: false,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    await record("process_failed", { code: "spawn_failed" });
    await closeWriter();
    const error = new RuntimeHostError("process spawn failed");
    started.reject(error);
    started.promise.catch(() => {});
    rawClosed.resolve();
    exited.resolve({
      executionId,
      outcome: "spawn_failed",
      exitCode: null,
      signal: null,
      stdout: streamEvidence(stdoutBytes, stdoutHash),
      stderr: streamEvidence(stderrBytes, stderrHash),
    });
    return Object.freeze({
      executionId,
      started: started.promise,
      exit: exited.promise,
      terminate,
    });
  }

  child.stdout.on("data", (chunk: Buffer) =>
    consume(child.stdout, "stdout", options.onStdout, chunk),
  );
  child.stderr.on("data", (chunk: Buffer) =>
    consume(child.stderr, "stderr", options.onStderr, chunk),
  );

  child.once("spawn", () => {
    spawned = true;
    void record("process_started", {})
      .then(() => {
        started.resolve();
        if (!closed) {
          runtimeTimer = clock.setTimeout(() => {
            if (closed || terminationPromise) return;
            timedOut = true;
            void record("process_timed_out", {
              maximumRuntimeMs: options.runtimePolicy.maximumRuntimeMs,
            })
              .catch(() => {
                supervisorFailed = true;
              })
              .then(() => terminate("timeout"));
          }, options.runtimePolicy.maximumRuntimeMs);
        }
      })
      .catch(async () => {
        supervisorFailed = true;
        started.reject(fixedSinkError());
        started.promise.catch(() => {});
        await terminate("supervisor_failure");
      });
  });

  child.once("error", () => {
    if (spawned) {
      void supervisorFailure("stderr");
      return;
    }
    if (finalized) return;
    finalized = true;
    closed = true;
    rawClosed.resolve();
    cleanup();
    void record("process_failed", { code: "spawn_failed" })
      .then(closeWriter)
      .then(() => {
        const error = new RuntimeHostError("process spawn failed");
        started.reject(error);
        started.promise.catch(() => {});
        exited.resolve({
          executionId,
          outcome: "spawn_failed",
          exitCode: null,
          signal: null,
          stdout: streamEvidence(stdoutBytes, stdoutHash),
          stderr: streamEvidence(stderrBytes, stderrHash),
        });
      })
      .catch((error) => {
        started.reject(error);
        started.promise.catch(() => {});
        exited.reject(error);
      });
  });

  child.once("close", (exitCode, signal) => {
    if (finalized) return;
    finalized = true;
    closed = true;
    rawClosed.resolve();
    cleanup();
    void Promise.all([stdoutPending, stderrPending, receiptQueue])
      .then(async () => {
        const stdout = streamEvidence(stdoutBytes, stdoutHash);
        const stderr = streamEvidence(stderrBytes, stderrHash);
        const outcome = outcomeFor(
          exitCode,
          signal,
          timedOut,
          supervisorFailed,
        );
        await record("process_exited", {
          exitCode,
          signal: normalizeSignal(signal),
          outcome,
          stdout,
          stderr,
        });
        await closeWriter();
        exited.resolve({
          executionId,
          outcome,
          exitCode,
          signal: normalizeSignal(signal),
          stdout,
          stderr,
        });
      })
      .catch((error) => exited.reject(error));
  });

  if (options.signal) {
    abortListener = () => {
      if (closed || terminationPromise) return;
      void terminate("abort");
    };
    if (options.signal.aborted) {
      abortListener();
    } else {
      options.signal.addEventListener("abort", abortListener, { once: true });
    }
  }

  return Object.freeze({
    executionId,
    started: started.promise,
    exit: exited.promise,
    terminate,
  });
}

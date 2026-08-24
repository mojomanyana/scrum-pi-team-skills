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
  isProcessGroupAlive(processGroupId: number): boolean;
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
    isProcessGroupAlive(processGroupId: number) {
      try {
        process.kill(-processGroupId, 0);
        return true;
      } catch (error) {
        const code =
          typeof error === "object" && error !== null && "code" in error
            ? (error as { code?: unknown }).code
            : undefined;
        if (code === "ESRCH") return false;
        throw error;
      }
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

  let writerFinalization: Promise<void> | null = null;
  let sinkFailed = false;
  const finalizeWriter = (): Promise<void> => {
    if (writerFinalization) return writerFinalization;
    writerFinalization = Promise.resolve()
      .then(() => writer.close())
      .catch(() => {
        sinkFailed = true;
        throw fixedSinkError();
      });
    return writerFinalization;
  };
  const withWriterFinalization = async (
    operation: () => void | Promise<void>,
  ): Promise<void> => {
    let primary: unknown;
    try {
      await operation();
    } catch (error) {
      primary = error;
    }
    try {
      await finalizeWriter();
    } catch (error) {
      if (primary === undefined) primary = error;
    }
    if (primary !== undefined) throw primary;
  };

  let sequence = 0;
  let previousReceiptDigest: string | null = null;
  let receiptQueue = Promise.resolve();
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
      await finalizeWriter();
    } catch {
      // The primary fixed receipt diagnostic remains authoritative.
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
  let rawCloseObserved = false;
  let finalized = false;
  let timedOut = false;
  let supervisorFailed = false;
  let supervisorFailureRecorded = false;
  let processGroupId: number | null = null;
  let processGroupAbsent = false;
  let groupKillDelivered = false;
  let terminationPromise: Promise<void> | null = null;
  let runtimeTimer: unknown;
  let abortListener: (() => void) | null = null;
  let stdoutPending = Promise.resolve();
  let stderrPending = Promise.resolve();
  let stdoutCallbackFailed = false;
  let stderrCallbackFailed = false;

  const cleanup = (): void => {
    if (runtimeTimer !== undefined) {
      clock.clearTimeout(runtimeTimer);
      runtimeTimer = undefined;
    }
    if (abortListener && options.signal) {
      options.signal.removeEventListener("abort", abortListener);
    }
    abortListener = null;
  };

  type SupervisorFailureCode =
    | "output_callback_failed"
    | "signal_failed"
    | "group_liveness_failed"
    | "group_cleanup_unconfirmed"
    | "descendant_cleanup_required";

  const markSupervisorFailure = async (
    code: SupervisorFailureCode,
    stream?: "stdout" | "stderr",
  ): Promise<void> => {
    supervisorFailed = true;
    if (supervisorFailureRecorded) return;
    supervisorFailureRecorded = true;
    try {
      await record("supervisor_failed", {
        code,
        ...(stream === undefined ? {} : { stream }),
      });
    } catch {
      sinkFailed = true;
    }
  };

  const requireProcessGroupId = (): number => {
    if (
      processGroupId === null ||
      !Number.isSafeInteger(processGroupId) ||
      processGroupId <= 0 ||
      processGroupId === process.pid
    ) {
      throw new RuntimeHostError("spawned process group is invalid");
    }
    return processGroupId;
  };

  type ProcessGroupLiveness = "absent" | "present" | "unknown";

  const observeProcessGroup = async (): Promise<ProcessGroupLiveness> => {
    if (processGroupAbsent) return "absent";
    const groupId = requireProcessGroupId();
    try {
      if (adapter.isProcessGroupAlive(groupId)) return "present";
      processGroupAbsent = true;
      return "absent";
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code === "ESRCH") {
        processGroupAbsent = true;
        return "absent";
      }
      await markSupervisorFailure("group_liveness_failed");
      return "unknown";
    }
  };

  const waitForProcessGroupAbsence = async (
    maximumWaitMs: number,
  ): Promise<boolean> => {
    let elapsed = 0;
    while ((await observeProcessGroup()) !== "absent") {
      if (elapsed >= maximumWaitMs) return false;
      const delay = Math.min(
        options.runtimePolicy.processGroupPollIntervalMs,
        maximumWaitMs - elapsed,
      );
      let timer: unknown;
      try {
        await new Promise<void>((resolve) => {
          timer = clock.setTimeout(resolve, delay);
        });
      } finally {
        if (timer !== undefined) clock.clearTimeout(timer);
      }
      elapsed += delay;
    }
    return true;
  };

  const sendGroupSignal = async (
    signal: "SIGTERM" | "SIGKILL",
  ): Promise<boolean> => {
    if (processGroupAbsent || !spawned) return false;
    const groupId = requireProcessGroupId();
    try {
      adapter.killProcessGroup(groupId, signal);
      return true;
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code === "ESRCH") {
        processGroupAbsent = true;
        return false;
      }
      await markSupervisorFailure("signal_failed");
      throw new RuntimeHostError("process-group signaling failed");
    }
  };

  const terminate = (reason: TerminationReason = "caller"): Promise<void> => {
    if (terminationPromise) return terminationPromise;
    terminationPromise = (async () => {
      cleanup();
      if (!spawned && !closed) {
        await Promise.race([
          started.promise.catch(() => {}),
          rawClosed.promise,
        ]);
      }
      if (!spawned) return;
      if ((await observeProcessGroup()) === "absent") {
        await rawClosed.promise;
        return;
      }
      try {
        await record("termination_requested", { reason });
      } catch {
        supervisorFailed = true;
      }
      try {
        await sendGroupSignal("SIGTERM");
      } catch {
        // Bounded escalation still runs so signaling failure cannot claim cleanup.
      }
      if (
        !processGroupAbsent &&
        !(await waitForProcessGroupAbsence(
          options.runtimePolicy.terminationGraceMs,
        ))
      ) {
        if (
          rawCloseObserved ||
          child.exitCode !== null ||
          child.signalCode !== null
        ) {
          await markSupervisorFailure("descendant_cleanup_required");
        }
        let killDelivered = false;
        try {
          killDelivered = await sendGroupSignal("SIGKILL");
        } catch {
          // Confirmation below remains authoritative and fails closed.
        }
        if (killDelivered) {
          groupKillDelivered = true;
          try {
            await record("process_killed", { signal: "SIGKILL" });
          } catch {
            supervisorFailed = true;
          }
        }
        if (
          !processGroupAbsent &&
          !(await waitForProcessGroupAbsence(
            options.runtimePolicy.killConfirmationMs,
          ))
        ) {
          await markSupervisorFailure("group_cleanup_unconfirmed");
          throw new RuntimeHostError(
            "process-group absence confirmation timed out",
          );
        }
      }
      await rawClosed.promise;
    })();
    return terminationPromise;
  };

  const supervisorFailure = async (
    stream: "stdout" | "stderr",
  ): Promise<void> => {
    await markSupervisorFailure("output_callback_failed", stream);
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
    if (
      !callback ||
      (name === "stdout" ? stdoutCallbackFailed : stderrCallbackFailed)
    )
      return;
    stream.pause();
    let resumed = false;
    const resume = () => {
      if (!closed && !resumed) {
        resumed = true;
        stream.resume();
      }
    };
    const pending = Promise.resolve()
      .then(() => callback(chunk))
      .catch(() => {
        if (name === "stdout") stdoutCallbackFailed = true;
        else stderrCallbackFailed = true;
        // A paused full pipe can prevent child close. Drain remaining metadata-only
        // bytes before governed termination waits for raw close and finalization.
        resume();
        return supervisorFailure(name);
      })
      .finally(resume);
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
    let receiptFailure: unknown;
    try {
      await record("process_failed", { code: "spawn_failed" });
    } catch (error) {
      receiptFailure = error;
    }
    try {
      await finalizeWriter();
    } catch {
      // Writer-close failure does not replace spawn or receipt-append failure.
    }
    if (receiptFailure !== undefined) throw receiptFailure;
    const error = new RuntimeHostError("process spawn failed");
    started.reject(error);
    started.promise.catch(() => {});
    finalized = true;
    closed = true;
    rawCloseObserved = true;
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
    const spawnedProcessGroupId = child.pid;
    if (
      spawnedProcessGroupId === undefined ||
      !Number.isSafeInteger(spawnedProcessGroupId) ||
      spawnedProcessGroupId <= 0 ||
      spawnedProcessGroupId === process.pid
    ) {
      const error = new RuntimeHostError("spawned process group is invalid");
      supervisorFailed = true;
      started.reject(error);
      started.promise.catch(() => {});
      child.kill("SIGKILL");
      return;
    }
    processGroupId = spawnedProcessGroupId;
    spawned = true;
    void record("process_started", {})
      .then(() => {
        started.resolve();
        if (!closed && !terminationPromise) {
          runtimeTimer = clock.setTimeout(() => {
            if (closed || terminationPromise) return;
            timedOut = true;
            void record("process_timed_out", {
              maximumRuntimeMs: options.runtimePolicy.maximumRuntimeMs,
            })
              .catch(() => {
                supervisorFailed = true;
              })
              .then(() => terminate("timeout"))
              .catch(() => {
                // The close/finalization path reports the fixed cleanup failure.
              });
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
    rawCloseObserved = true;
    rawClosed.resolve();
    cleanup();
    void (async () => {
      let receiptFailure: unknown;
      try {
        await record("process_failed", { code: "spawn_failed" });
      } catch (error) {
        receiptFailure = error;
      }
      try {
        await finalizeWriter();
      } catch {
        // Writer-close failure does not replace spawn or receipt-append failure.
      }
      if (receiptFailure !== undefined) throw receiptFailure;
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
    })().catch((error) => {
      started.reject(error);
      started.promise.catch(() => {});
      exited.reject(error);
    });
  });

  child.once("close", (exitCode, signal) => {
    if (finalized) return;
    finalized = true;
    closed = true;
    rawCloseObserved = true;
    rawClosed.resolve();
    cleanup();
    void (async () => {
      let result: ExecutionResult | undefined;
      await withWriterFinalization(async () => {
        await Promise.all([stdoutPending, stderrPending]);
        if (groupKillDelivered && exitCode !== null) {
          await markSupervisorFailure("descendant_cleanup_required");
        }
        const livenessBeforeCleanup = await observeProcessGroup();
        if (livenessBeforeCleanup !== "absent") {
          if (livenessBeforeCleanup === "present" && !groupKillDelivered) {
            await markSupervisorFailure("descendant_cleanup_required");
          }
          await terminate("supervisor_failure");
        } else if (terminationPromise) {
          await terminationPromise;
        }
        if ((await observeProcessGroup()) !== "absent") {
          throw new RuntimeHostError("process-group cleanup was not confirmed");
        }
        await receiptQueue;
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
        result = {
          executionId,
          outcome,
          exitCode,
          signal: normalizeSignal(signal),
          stdout,
          stderr,
        };
      });
      exited.resolve(result!);
    })().catch((error) => exited.reject(error));
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

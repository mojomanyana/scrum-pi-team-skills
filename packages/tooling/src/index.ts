import { readFileSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import type { Writable } from "node:stream";

import {
  createLocalFilesystemReceiptSink,
  createOperatorEnvironmentPolicy,
  createReceiptAuthenticator,
  createPiLaunchPlan,
  createRuntimePolicy,
  createTrustedLaunchPolicy,
  inspectLifecycleReceipts,
  startGovernedLocalProcess,
} from "@scrum-pi-team-skills/runtime";

export const GOVERNED_RUNTIME_USAGE = `Usage:
  spts-runtime plan --manifest FILE --operator-config FILE
  spts-runtime run --manifest FILE --operator-config FILE
  spts-runtime inspect --execution-id ID --operator-config FILE

plan prints redacted preview evidence only. run rebuilds authority in-process.
inspect verifies one trusted-parent lifecycle receipt chain and authenticated anchor.
Exit codes: 0 success, 2 usage, 3 validation/storage, 4 invalid chain,
10 child non-zero, 11 signal exit, 12 timeout, 13 spawn/supervisor failure.`;

export interface CliDependencies {
  readonly writeOutput?: (value: string) => void;
  readonly writeError?: (value: string) => void;
  readonly writeStdout?: (chunk: Uint8Array) => void | Promise<void>;
  readonly writeStderr?: (chunk: Uint8Array) => void | Promise<void>;
  readonly stdout?: Writable;
  readonly stderr?: Writable;
  readonly readEnvironment?: (name: string) => string | undefined;
  readonly addSignalListener?: (
    signal: "SIGINT" | "SIGTERM",
    listener: () => void,
  ) => void;
  readonly removeSignalListener?: (
    signal: "SIGINT" | "SIGTERM",
    listener: () => void,
  ) => void;
  readonly startGovernedLocalProcess?: typeof startGovernedLocalProcess;
}

interface ParsedOptions {
  readonly command: "plan" | "run" | "inspect";
  readonly manifest?: string;
  readonly operatorConfig?: string;
  readonly executionId?: string;
}

function parseArguments(argv: readonly string[]): ParsedOptions | null {
  const [command, ...rest] = argv;
  if (command !== "plan" && command !== "run" && command !== "inspect") {
    return null;
  }
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (
      !flag ||
      !value ||
      !flag.startsWith("--") ||
      value.startsWith("--") ||
      values.has(flag)
    ) {
      return null;
    }
    values.set(flag, value);
  }
  if (command === "inspect") {
    if (
      values.size !== 2 ||
      !values.has("--execution-id") ||
      !values.has("--operator-config")
    )
      return null;
    return {
      command,
      executionId: values.get("--execution-id"),
      operatorConfig: values.get("--operator-config"),
    };
  }
  if (
    values.size !== 2 ||
    !values.has("--manifest") ||
    !values.has("--operator-config")
  ) {
    return null;
  }
  return {
    command,
    manifest: values.get("--manifest"),
    operatorConfig: values.get("--operator-config"),
  };
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readOperatorConfig(path: string): {
  trustedLaunchPolicy: unknown;
  environment: { policyId: unknown; importNames: unknown };
  runtimePolicy: unknown;
  trustedReceiptParent: unknown;
  authentication: {
    authenticatorId: unknown;
    keyEnvironmentVariable: unknown;
  };
} {
  const value = readJson(path);
  if (!isRecord(value)) throw new TypeError();
  const allowed = new Set([
    "trustedLaunchPolicy",
    "environment",
    "runtimePolicy",
    "trustedReceiptParent",
    "authentication",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)))
    throw new TypeError();
  if (!isRecord(value.environment) || !isRecord(value.authentication))
    throw new TypeError();
  if (
    Object.keys(value.environment).some(
      (key) => key !== "policyId" && key !== "importNames",
    )
  ) {
    throw new TypeError();
  }
  if (
    Object.keys(value.authentication).some(
      (key) => key !== "authenticatorId" && key !== "keyEnvironmentVariable",
    )
  )
    throw new TypeError();
  return {
    trustedLaunchPolicy: value.trustedLaunchPolicy,
    environment: {
      policyId: value.environment.policyId,
      importNames: value.environment.importNames,
    },
    runtimePolicy: value.runtimePolicy,
    trustedReceiptParent: value.trustedReceiptParent,
    authentication: {
      authenticatorId: value.authentication.authenticatorId,
      keyEnvironmentVariable: value.authentication.keyEnvironmentVariable,
    },
  };
}

function buildPlan(manifestPath: string, operatorConfigPath: string) {
  const manifest = readJson(manifestPath);
  const config = readOperatorConfig(operatorConfigPath);
  const launchPolicy = createTrustedLaunchPolicy(config.trustedLaunchPolicy);
  return { plan: createPiLaunchPlan(manifest, launchPolicy), config };
}

function createConfiguredAuthenticator(
  config: ReturnType<typeof readOperatorConfig>,
  readEnvironment: (name: string) => string | undefined,
) {
  if (
    typeof config.authentication.authenticatorId !== "string" ||
    typeof config.authentication.keyEnvironmentVariable !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(
      config.authentication.keyEnvironmentVariable,
    )
  )
    throw new TypeError();
  const encoded = readEnvironment(config.authentication.keyEnvironmentVariable);
  if (
    typeof encoded !== "string" ||
    encoded.length === 0 ||
    encoded.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      encoded,
    )
  )
    throw new TypeError();
  const temporary = Buffer.from(encoded, "base64");
  try {
    if (temporary.byteLength < 32 || temporary.toString("base64") !== encoded)
      throw new TypeError();
    return createReceiptAuthenticator({
      authenticatorId: config.authentication.authenticatorId,
      key: temporary,
    });
  } finally {
    temporary.fill(0);
  }
}

function exitCodeFor(outcome: string): number {
  if (outcome === "succeeded") return 0;
  if (outcome === "nonzero") return 10;
  if (outcome === "signaled") return 11;
  if (outcome === "timed_out") return 12;
  return 13;
}

function writeGovernedStream(
  stream: Writable,
  chunk: Uint8Array,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    let writeReturned = false;
    let callbackCompleted = false;
    let drainRequired = false;
    let drainCompleted = false;

    const settle = (succeeded: boolean) => {
      if (settled) return;
      settled = true;
      let cleanupFailed = false;
      for (const [event, listener] of [
        ["error", onError],
        ["close", onClose],
        ["drain", onDrain],
      ] as const) {
        try {
          stream.off(event, listener);
        } catch {
          cleanupFailed = true;
        }
      }
      if (succeeded && !cleanupFailed) resolve();
      else reject(new TypeError("governed stream write failed"));
    };
    const completeIfReady = () => {
      if (
        writeReturned &&
        callbackCompleted &&
        (!drainRequired || drainCompleted)
      )
        settle(true);
    };
    const onError = () => settle(false);
    const onClose = () => settle(false);
    const onDrain = () => {
      drainCompleted = true;
      completeIfReady();
    };

    try {
      stream.on("error", onError);
      stream.on("close", onClose);
      stream.on("drain", onDrain);
      drainRequired = !stream.write(chunk, (error) => {
        if (error) {
          // Node Writable reports a write callback error before emitting its paired
          // error event. Keep observation installed through that event-loop turn.
          setImmediate(() => settle(false));
          return;
        }
        callbackCompleted = true;
        completeIfReady();
      });
      writeReturned = true;
      completeIfReady();
    } catch {
      settle(false);
    }
  });
}

export async function runCli(
  argv: readonly string[],
  dependencies: CliDependencies = {},
): Promise<number> {
  const writeOutput =
    dependencies.writeOutput ?? ((value) => console.log(value));
  const writeError =
    dependencies.writeError ?? ((value) => console.error(value));
  const readEnvironment =
    dependencies.readEnvironment ?? ((name: string) => process.env[name]);
  const writeStdout =
    dependencies.writeStdout ??
    ((chunk: Uint8Array) =>
      writeGovernedStream(dependencies.stdout ?? process.stdout, chunk));
  const writeStderr =
    dependencies.writeStderr ??
    ((chunk: Uint8Array) =>
      writeGovernedStream(dependencies.stderr ?? process.stderr, chunk));
  const addSignalListener =
    dependencies.addSignalListener ??
    ((signal: "SIGINT" | "SIGTERM", listener: () => void) =>
      process.on(signal, listener));
  const removeSignalListener =
    dependencies.removeSignalListener ??
    ((signal: "SIGINT" | "SIGTERM", listener: () => void) =>
      process.off(signal, listener));
  const startProcess =
    dependencies.startGovernedLocalProcess ?? startGovernedLocalProcess;

  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "help")) {
    writeOutput(GOVERNED_RUNTIME_USAGE);
    return 0;
  }
  const parsed = parseArguments(argv);
  if (!parsed) {
    writeError(GOVERNED_RUNTIME_USAGE);
    return 2;
  }

  try {
    if (parsed.command === "inspect") {
      const config = readOperatorConfig(parsed.operatorConfig!);
      if (typeof config.trustedReceiptParent !== "string")
        throw new TypeError();
      const authenticator = createConfiguredAuthenticator(
        config,
        readEnvironment,
      );
      const result = inspectLifecycleReceipts({
        trustedParent: config.trustedReceiptParent,
        executionId: parsed.executionId!,
        authenticator,
      });
      writeOutput(JSON.stringify(result, null, 2));
      return result.valid ? 0 : 4;
    }

    const { plan, config } = buildPlan(
      parsed.manifest!,
      parsed.operatorConfig!,
    );
    if (parsed.command === "plan") {
      writeOutput(
        JSON.stringify(
          {
            contractVersion: "1.0.0",
            executableAuthority: false,
            preview: plan.redactedOperatorPreview,
            correlation: plan.correlation,
          },
          null,
          2,
        ),
      );
      return 0;
    }

    if (
      !Array.isArray(config.environment.importNames) ||
      config.environment.importNames.some((name) => typeof name !== "string")
    ) {
      throw new TypeError();
    }
    const importNames = config.environment.importNames as string[];
    if (
      typeof config.authentication.keyEnvironmentVariable !== "string" ||
      importNames.includes(config.authentication.keyEnvironmentVariable)
    )
      throw new TypeError();
    const baseline: Record<string, string> = Object.create(null) as Record<
      string,
      string
    >;
    for (const name of importNames) {
      const value = readEnvironment(name);
      if (value === undefined) throw new TypeError();
      baseline[name] = value;
    }
    const environmentPolicy = createOperatorEnvironmentPolicy({
      policyId: config.environment.policyId,
      baseline,
      allowlist: importNames,
    });
    const runtimePolicy = createRuntimePolicy(config.runtimePolicy);
    if (typeof config.trustedReceiptParent !== "string") throw new TypeError();
    const authenticator = createConfiguredAuthenticator(
      config,
      readEnvironment,
    );
    const sink = createLocalFilesystemReceiptSink({
      trustedParent: config.trustedReceiptParent,
      authenticator,
    });
    let outputFailed = false;
    const controlledWrite = async (
      write: (chunk: Uint8Array) => void | Promise<void>,
      chunk: Uint8Array,
    ): Promise<void> => {
      try {
        await write(chunk);
      } catch {
        outputFailed = true;
        throw new TypeError("governed output callback failed");
      }
    };
    const handle = await startProcess({
      plan,
      environmentPolicy,
      runtimePolicy,
      receiptSink: sink,
      executionIdSource: () => `runtime-${randomUUID()}`,
      onStdout: (chunk) => controlledWrite(writeStdout, chunk),
      onStderr: (chunk) => controlledWrite(writeStderr, chunk),
    });
    type ControlledSettlement<T> =
      | { readonly succeeded: true; readonly value: T }
      | { readonly succeeded: false };
    const observe = <T>(
      promise: Promise<T>,
    ): Promise<ControlledSettlement<T>> =>
      promise.then(
        (value) => ({ succeeded: true, value }),
        () => ({ succeeded: false }),
      );

    // An acquired handle is live authority. Observe both lifecycle promises before
    // any injected setup operation can throw or synchronously trigger a signal.
    const exitSettlement = observe(handle.exit);
    const startedSettlement = observe(handle.started);
    const signalState: {
      termination: Promise<ControlledSettlement<void>> | null;
    } = { termination: null };
    const requestTermination = (
      reason: "supervisor_failure" | "supervisor_signal",
    ): Promise<ControlledSettlement<void>> => {
      if (!signalState.termination) {
        signalState.termination = observe(
          Promise.resolve().then(() => handle.terminate(reason)),
        );
      }
      return signalState.termination;
    };
    let announceSignal!: (value: {
      readonly completion: Promise<ControlledSettlement<void>>;
    }) => void;
    const signalStarted = new Promise<{
      readonly completion: Promise<ControlledSettlement<void>>;
    }>((resolve) => {
      announceSignal = resolve;
    });
    let registrationComplete = false;
    let acceptSignals = true;
    const forwardSignal = () => {
      if (!acceptSignals || signalState.termination) return;
      const completion = requestTermination(
        registrationComplete ? "supervisor_signal" : "supervisor_failure",
      );
      announceSignal({ completion });
    };
    const potentiallyInstalledSignals: Array<"SIGINT" | "SIGTERM"> = [];
    let operationResult: number | undefined;
    let operationFailed = false;

    try {
      potentiallyInstalledSignals.push("SIGINT");
      addSignalListener("SIGINT", forwardSignal);
      potentiallyInstalledSignals.push("SIGTERM");
      addSignalListener("SIGTERM", forwardSignal);
      registrationComplete = true;
    } catch {
      operationFailed = true;
      requestTermination("supervisor_failure");
    }

    if (!operationFailed) {
      const started = await startedSettlement;
      if (!started.succeeded) {
        operationFailed = true;
      } else {
        const first = await Promise.race([
          exitSettlement.then((settlement) => ({
            kind: "exit" as const,
            settlement,
          })),
          signalStarted.then(({ completion }) => ({
            kind: "signal" as const,
            completion,
          })),
        ]);
        if (first.kind === "signal") {
          if (!(await first.completion).succeeded) operationFailed = true;
          const exit = await exitSettlement;
          if (exit.succeeded) operationResult = exitCodeFor(exit.value.outcome);
          else operationFailed = true;
        } else if (first.settlement.succeeded) {
          operationResult = exitCodeFor(first.settlement.value.outcome);
          if (
            signalState.termination &&
            !(await signalState.termination).succeeded
          ) {
            operationFailed = true;
          }
        } else {
          operationFailed = true;
        }
      }
    }

    if (outputFailed) operationFailed = true;
    if (operationFailed) {
      const termination = requestTermination("supervisor_failure");
      await Promise.all([termination, exitSettlement]);
    }

    acceptSignals = false;
    let cleanupFailed = false;
    for (const signal of potentiallyInstalledSignals.splice(0)) {
      try {
        removeSignalListener(signal, forwardSignal);
      } catch {
        cleanupFailed = true;
      }
    }
    if (operationFailed || cleanupFailed || operationResult === undefined)
      throw new TypeError();
    return operationResult;
  } catch {
    try {
      if (dependencies.writeError) {
        writeError("governed runtime operation failed");
      } else {
        writeFileSync(2, "governed runtime operation failed\n");
      }
    } catch {
      // A failed diagnostic stream cannot replace the fixed controlled result.
    }
    return 3;
  }
}

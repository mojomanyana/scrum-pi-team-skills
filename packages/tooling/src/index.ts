import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

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
  readonly readEnvironment?: (name: string) => string | undefined;
  readonly addSignalListener?: (
    signal: "SIGINT" | "SIGTERM",
    listener: () => void,
  ) => void;
  readonly removeSignalListener?: (
    signal: "SIGINT" | "SIGTERM",
    listener: () => void,
  ) => void;
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
    ((chunk: Uint8Array) => {
      if (process.stdout.write(chunk)) return;
      return new Promise<void>((resolve) =>
        process.stdout.once("drain", resolve),
      );
    });
  const writeStderr =
    dependencies.writeStderr ??
    ((chunk: Uint8Array) => {
      if (process.stderr.write(chunk)) return;
      return new Promise<void>((resolve) =>
        process.stderr.once("drain", resolve),
      );
    });
  const addSignalListener =
    dependencies.addSignalListener ??
    ((signal: "SIGINT" | "SIGTERM", listener: () => void) =>
      process.on(signal, listener));
  const removeSignalListener =
    dependencies.removeSignalListener ??
    ((signal: "SIGINT" | "SIGTERM", listener: () => void) =>
      process.off(signal, listener));

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
    const handle = await startGovernedLocalProcess({
      plan,
      environmentPolicy,
      runtimePolicy,
      receiptSink: sink,
      executionIdSource: () => `runtime-${randomUUID()}`,
      onStdout: writeStdout,
      onStderr: writeStderr,
    });
    const forwardSignal = () => {
      void handle.terminate("supervisor_signal");
    };
    addSignalListener("SIGINT", forwardSignal);
    addSignalListener("SIGTERM", forwardSignal);
    try {
      await handle.started.catch(() => {});
      const result = await handle.exit;
      return exitCodeFor(result.outcome);
    } finally {
      removeSignalListener("SIGINT", forwardSignal);
      removeSignalListener("SIGTERM", forwardSignal);
    }
  } catch {
    writeError("governed runtime operation failed");
    return 3;
  }
}

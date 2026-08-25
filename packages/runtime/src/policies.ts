import { containsCredentialShapedContent } from "@scrum-pi-team-skills/contracts";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const environmentValues = new WeakMap<
  object,
  Readonly<Record<string, string>>
>();
const issuedEnvironmentPolicies = new WeakSet<object>();
const issuedRuntimePolicies = new WeakSet<object>();

export class RuntimeHostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeHostError";
  }
}

export interface OperatorEnvironmentPolicyDefinition {
  readonly policyId: string;
  readonly baseline: Readonly<Record<string, string>>;
  readonly allowlist: readonly string[];
}

export interface OperatorEnvironmentPolicy {
  readonly policyId: string;
  readonly names: readonly string[];
}

export interface RuntimePolicyDefinition {
  readonly policyId: string;
  readonly maximumRuntimeMs: number;
  readonly terminationGraceMs: number;
  readonly killConfirmationMs: number;
  readonly processGroupPollIntervalMs: number;
  readonly maximumArgvCount: number;
  readonly maximumArgvBytes: number;
  readonly maximumEnvironmentEntries: number;
  readonly maximumEnvironmentBytes: number;
  readonly maximumReceiptPayloadBytes: number;
  readonly maximumListeners: number;
}

export type RuntimePolicy = RuntimePolicyDefinition;

type Snapshot = { ok: true; value: unknown } | { ok: false };

function copyInput(value: unknown, ancestors = new Set<object>()): unknown {
  if (typeof value !== "object" || value === null) return value;
  if (ancestors.has(value)) throw new TypeError();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const copy: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new TypeError();
        copy.push(copyInput(value[index], ancestors));
      }
      return copy;
    }
    const copy: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor))
        throw new TypeError();
      copy[key] = copyInput(descriptor.value, ancestors);
    }
    return copy;
  } finally {
    ancestors.delete(value);
  }
}

function snapshot(value: unknown): Snapshot {
  try {
    return { ok: true, value: copyInput(value) };
  } catch {
    return { ok: false };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireId(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !SAFE_ID.test(value) ||
    containsCredentialShapedContent(value)
  ) {
    throw new RuntimeHostError(`${label} identifier is invalid`);
  }
  return value;
}

function rejectUnknownProperties(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const authority = new Set(allowed);
  if (Object.keys(value).some((key) => !authority.has(key))) {
    throw new RuntimeHostError(`${label} contains undeclared properties`);
  }
}

function requireEnvironmentName(value: unknown): string {
  if (
    typeof value !== "string" ||
    !ENVIRONMENT_NAME.test(value) ||
    value.includes("\0")
  ) {
    throw new RuntimeHostError("environment policy contains an invalid name");
  }
  return value;
}

/** Copies opaque values into private storage and exposes names only. */
export function createOperatorEnvironmentPolicy(
  input: unknown,
): OperatorEnvironmentPolicy {
  const result = snapshot(input);
  if (!result.ok || !isRecord(result.value)) {
    throw new RuntimeHostError(
      "environment policy input could not be safely inspected",
    );
  }
  const definition = result.value;
  rejectUnknownProperties(
    definition,
    ["policyId", "baseline", "allowlist"],
    "environment policy",
  );
  const policyId = requireId(definition.policyId, "environment policy");
  if (!isRecord(definition.baseline) || !Array.isArray(definition.allowlist)) {
    throw new RuntimeHostError(
      "environment policy baseline and allowlist are required",
    );
  }
  if (definition.allowlist.length > 256) {
    throw new RuntimeHostError("environment policy exceeds the entry limit");
  }

  const names = definition.allowlist.map(requireEnvironmentName);
  if (new Set(names).size !== names.length) {
    throw new RuntimeHostError(
      "environment policy allowlist contains duplicates",
    );
  }
  const baselineKeys = Object.keys(definition.baseline);
  if (
    baselineKeys.length !== names.length ||
    baselineKeys.some((name) => !names.includes(name))
  ) {
    throw new RuntimeHostError(
      "environment policy baseline must exactly match its allowlist",
    );
  }

  const values: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  let totalBytes = 0;
  for (const name of names) {
    const value = definition.baseline[name];
    if (typeof value !== "string" || value.includes("\0")) {
      throw new RuntimeHostError(
        "environment policy contains an invalid opaque value",
      );
    }
    totalBytes += Buffer.byteLength(name) + Buffer.byteLength(value);
    values[name] = value;
  }
  if (totalBytes > 1_048_576) {
    throw new RuntimeHostError("environment policy exceeds the byte limit");
  }

  Object.freeze(values);
  const frozenNames = Object.freeze([...names]);
  const policy = Object.freeze({ policyId, names: frozenNames });
  environmentValues.set(policy, values);
  issuedEnvironmentPolicies.add(policy);
  return policy;
}

const RUNTIME_PROPERTIES = [
  "policyId",
  "maximumRuntimeMs",
  "terminationGraceMs",
  "killConfirmationMs",
  "processGroupPollIntervalMs",
  "maximumArgvCount",
  "maximumArgvBytes",
  "maximumEnvironmentEntries",
  "maximumEnvironmentBytes",
  "maximumReceiptPayloadBytes",
  "maximumListeners",
] as const;

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    throw new RuntimeHostError(`${label} is outside the supported bounds`);
  }
  return value as number;
}

export function createRuntimePolicy(input: unknown): RuntimePolicy {
  const result = snapshot(input);
  if (!result.ok || !isRecord(result.value)) {
    throw new RuntimeHostError(
      "runtime policy input could not be safely inspected",
    );
  }
  const value = result.value;
  rejectUnknownProperties(value, RUNTIME_PROPERTIES, "runtime policy");
  const policy: RuntimePolicy = Object.freeze({
    policyId: requireId(value.policyId, "runtime policy"),
    maximumRuntimeMs: boundedInteger(
      value.maximumRuntimeMs,
      1,
      86_400_000,
      "maximum runtime",
    ),
    terminationGraceMs: boundedInteger(
      value.terminationGraceMs,
      1,
      300_000,
      "termination grace",
    ),
    killConfirmationMs: boundedInteger(
      value.killConfirmationMs,
      1,
      60_000,
      "kill confirmation",
    ),
    processGroupPollIntervalMs: boundedInteger(
      value.processGroupPollIntervalMs,
      1,
      1_000,
      "process group poll interval",
    ),
    maximumArgvCount: boundedInteger(
      value.maximumArgvCount,
      1,
      4_096,
      "maximum argv count",
    ),
    maximumArgvBytes: boundedInteger(
      value.maximumArgvBytes,
      1,
      1_048_576,
      "maximum argv bytes",
    ),
    maximumEnvironmentEntries: boundedInteger(
      value.maximumEnvironmentEntries,
      1,
      1_024,
      "maximum environment entries",
    ),
    maximumEnvironmentBytes: boundedInteger(
      value.maximumEnvironmentBytes,
      1,
      4_194_304,
      "maximum environment bytes",
    ),
    maximumReceiptPayloadBytes: boundedInteger(
      value.maximumReceiptPayloadBytes,
      256,
      65_536,
      "maximum receipt payload bytes",
    ),
    maximumListeners: boundedInteger(
      value.maximumListeners,
      8,
      64,
      "maximum listeners",
    ),
  });
  issuedRuntimePolicies.add(policy);
  return policy;
}

export function requireRuntimePolicy(
  value: unknown,
): asserts value is RuntimePolicy {
  if (
    typeof value !== "object" ||
    value === null ||
    !issuedRuntimePolicies.has(value)
  ) {
    throw new RuntimeHostError(
      "runtime policy must be issued by createRuntimePolicy",
    );
  }
}

export function constructEnvironment(
  policy: unknown,
  additions: Readonly<Record<string, string>>,
  runtimePolicy: RuntimePolicy,
): Readonly<Record<string, string>> {
  if (
    typeof policy !== "object" ||
    policy === null ||
    !issuedEnvironmentPolicies.has(policy)
  ) {
    throw new RuntimeHostError(
      "environment policy must be issued by createOperatorEnvironmentPolicy",
    );
  }
  const baseline = environmentValues.get(policy)!;
  const additionNames = Object.keys(additions);
  for (const name of additionNames) {
    requireEnvironmentName(name);
    const value = additions[name];
    if (typeof value !== "string" || value.includes("\0")) {
      throw new RuntimeHostError("launch environment addition is invalid");
    }
    if (Object.hasOwn(baseline, name)) {
      throw new RuntimeHostError(
        "environment policy collides with launch additions",
      );
    }
  }

  const names = [...Object.keys(baseline), ...additionNames];
  if (names.length > runtimePolicy.maximumEnvironmentEntries) {
    throw new RuntimeHostError(
      "constructed environment exceeds the entry limit",
    );
  }
  let bytes = 0;
  const environment: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  for (const name of names) {
    const value = Object.hasOwn(baseline, name)
      ? baseline[name]!
      : additions[name]!;
    bytes += Buffer.byteLength(name) + Buffer.byteLength(value);
    environment[name] = value;
  }
  if (bytes > runtimePolicy.maximumEnvironmentBytes) {
    throw new RuntimeHostError(
      "constructed environment exceeds the byte limit",
    );
  }
  return Object.freeze(environment);
}

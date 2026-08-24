import { createHash } from "node:crypto";

import { Ajv, type ErrorObject } from "ajv";

import { containsCredentialShapedContent } from "./credential-shape.js";
import lifecycleReceiptSchema from "./schemas/lifecycle-receipt.schema.json" with { type: "json" };

export const LIFECYCLE_RECEIPT_CONTRACT_ID = "spts.lifecycle-receipt" as const;
export const LIFECYCLE_RECEIPT_VERSION = "1.0.0" as const;

export type LifecycleEventType =
  | "launch_requested"
  | "process_started"
  | "termination_requested"
  | "process_exited"
  | "process_failed"
  | "process_timed_out"
  | "process_killed"
  | "supervisor_failed";

export type TerminationReason =
  "caller" | "timeout" | "abort" | "supervisor_signal" | "supervisor_failure";

export interface StreamEvidence {
  readonly bytes: number;
  readonly sha256: string;
}

export interface ProcessExitPayload {
  readonly exitCode: number | null;
  readonly signal: "SIGINT" | "SIGTERM" | "SIGKILL" | null;
  readonly outcome:
    "succeeded" | "nonzero" | "signaled" | "timed_out" | "supervisor_failed";
  readonly stdout: StreamEvidence;
  readonly stderr: StreamEvidence;
}

export type LifecycleEventPayload =
  | Record<string, never>
  | { readonly reason: TerminationReason }
  | ProcessExitPayload
  | { readonly code: "spawn_failed" }
  | { readonly maximumRuntimeMs: number }
  | { readonly signal: "SIGKILL" }
  | {
      readonly code:
        | "output_callback_failed"
        | "receipt_sink_failed"
        | "signal_failed"
        | "group_liveness_failed"
        | "group_cleanup_unconfirmed"
        | "descendant_cleanup_required";
      readonly stream?: "stdout" | "stderr";
    };

export interface LifecycleReceipt {
  readonly contractId: typeof LIFECYCLE_RECEIPT_CONTRACT_ID;
  readonly contractVersion: typeof LIFECYCLE_RECEIPT_VERSION;
  readonly executionId: string;
  readonly correlation: {
    readonly manifestExecutionId: string;
    readonly pacaProjectId: string;
    readonly pacaTaskId: string;
  };
  readonly planDigest: string;
  readonly trustedPolicyIds: {
    readonly launch: string;
    readonly environment: string;
    readonly runtime: string;
  };
  readonly sequence: number;
  readonly timestamp: string;
  readonly eventType: LifecycleEventType;
  readonly payload: LifecycleEventPayload;
  readonly previousReceiptDigest: string | null;
  readonly receiptDigest: string;
}

export type LifecycleReceiptValidationResult =
  | { readonly valid: true; readonly value: LifecycleReceipt }
  | {
      readonly valid: false;
      readonly errors: ReadonlyArray<{
        readonly path: string;
        readonly code: string;
        readonly message: string;
      }>;
    };

export type LifecycleReceiptChainFailureCode =
  | "receipt-invalid"
  | "receipt-sequence-invalid"
  | "receipt-chain-mismatch"
  | "receipt-digest-mismatch"
  | "receipt-chain-incomplete"
  | "receipt-lifecycle-invalid"
  | "receipt-timestamp-invalid"
  | "receipt-anchor-invalid"
  | "receipt-authentication-failed";

export type LifecycleReceiptChainResult =
  | { readonly valid: true; readonly receipts: readonly LifecycleReceipt[] }
  | { readonly valid: false; readonly code: LifecycleReceiptChainFailureCode };

type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

const ajv = new Ajv({ allErrors: true });
const validateReceiptSchema = ajv.compile<LifecycleReceipt>(
  lifecycleReceiptSchema,
);

function encodeCanonical(value: JsonValue, ancestors: Set<object>): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError("canonical JSON requires finite numbers");
    return JSON.stringify(value);
  }
  if (typeof value !== "object")
    throw new TypeError("canonical JSON requires JSON values");
  if (ancestors.has(value))
    throw new TypeError("canonical JSON rejects circular values");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype)
        throw new TypeError();
      const expectedKeys = new Set([
        "length",
        ...Array.from({ length: value.length }, (_, index) => String(index)),
      ]);
      if (
        Reflect.ownKeys(value).some(
          (key) => typeof key !== "string" || !expectedKeys.has(key),
        )
      )
        throw new TypeError();
      const encoded: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, index);
        if (!descriptor?.enumerable || !("value" in descriptor))
          throw new TypeError();
        encoded.push(encodeCanonical(descriptor.value as JsonValue, ancestors));
      }
      return `[${encoded.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      throw new TypeError();
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError();
    const record = value as { readonly [key: string]: JsonValue };
    for (const key of keys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (!descriptor?.enumerable || !("value" in descriptor))
        throw new TypeError();
    }
    return `{${(keys as string[])
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${encodeCanonical(record[key] as JsonValue, ancestors)}`,
      )
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

/** RFC-8785-style deterministic JSON for the contracts' JSON subset. */
export function canonicalSerializeLifecycleValue(value: unknown): string {
  return encodeCanonical(value as JsonValue, new Set<object>());
}

export function computeLifecycleReceiptDigest(
  receipt: LifecycleReceipt,
): string {
  const unsigned = { ...receipt } as Record<string, unknown>;
  delete unsigned.receiptDigest;
  return createHash("sha256")
    .update(canonicalSerializeLifecycleValue(unsigned as JsonValue))
    .digest("hex");
}

function receiptError(error: ErrorObject): {
  path: string;
  code: string;
  message: string;
} {
  return {
    path: error.instancePath || "/",
    code: error.keyword,
    message: error.message ?? "is invalid",
  };
}

export function isCanonicalLifecycleTimestamp(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    return false;
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

export function validateLifecycleReceipt(
  value: unknown,
): LifecycleReceiptValidationResult {
  try {
    const snapshot = JSON.parse(
      canonicalSerializeLifecycleValue(value),
    ) as LifecycleReceipt;
    if (!validateReceiptSchema(snapshot)) {
      return {
        valid: false,
        errors: (validateReceiptSchema.errors ?? []).map(receiptError),
      };
    }
    const identityValues = [
      snapshot.executionId,
      snapshot.correlation.manifestExecutionId,
      snapshot.correlation.pacaProjectId,
      snapshot.correlation.pacaTaskId,
      snapshot.trustedPolicyIds.launch,
      snapshot.trustedPolicyIds.environment,
      snapshot.trustedPolicyIds.runtime,
    ];
    if (identityValues.some(containsCredentialShapedContent)) {
      return {
        valid: false,
        errors: [
          {
            path: "/",
            code: "credential-shaped",
            message:
              "receipt identity must not contain credential-shaped content",
          },
        ],
      };
    }
    if (!isCanonicalLifecycleTimestamp(snapshot.timestamp)) {
      return {
        valid: false,
        errors: [
          {
            path: "/timestamp",
            code: "date-time",
            message: "must be a canonical UTC timestamp with milliseconds",
          },
        ],
      };
    }
    return { valid: true, value: snapshot };
  } catch {
    return {
      valid: false,
      errors: [
        {
          path: "/",
          code: "input-introspection",
          message: "receipt input could not be safely inspected",
        },
      ],
    };
  }
}

function validExitOutcome(
  payload: ProcessExitPayload,
  evidence: {
    timedOut: boolean;
    terminationReason: TerminationReason | null;
    killed: boolean;
    supervisorFailed: boolean;
  },
): boolean {
  const hasExitCode = payload.exitCode !== null;
  const hasSignal = payload.signal !== null;
  if (
    hasExitCode === hasSignal ||
    (evidence.timedOut && evidence.terminationReason !== "timeout")
  )
    return false;
  if (payload.outcome === "succeeded") {
    return (
      payload.exitCode === 0 &&
      !hasSignal &&
      !evidence.timedOut &&
      !evidence.killed &&
      !evidence.supervisorFailed
    );
  }
  if (payload.outcome === "nonzero") {
    return (
      typeof payload.exitCode === "number" &&
      payload.exitCode !== 0 &&
      !hasSignal &&
      !evidence.timedOut &&
      !evidence.killed &&
      !evidence.supervisorFailed
    );
  }
  if (payload.outcome === "signaled") {
    return (
      !hasExitCode &&
      hasSignal &&
      !evidence.timedOut &&
      !evidence.supervisorFailed &&
      (payload.signal !== "SIGKILL" || evidence.killed)
    );
  }
  if (payload.outcome === "timed_out") {
    return (
      !hasExitCode &&
      hasSignal &&
      evidence.timedOut &&
      evidence.terminationReason === "timeout" &&
      !evidence.supervisorFailed &&
      (payload.signal !== "SIGKILL" || evidence.killed)
    );
  }
  return evidence.supervisorFailed;
}

const terminalEvents = new Set<LifecycleEventType>([
  "process_exited",
  "process_failed",
]);

export function verifyLifecycleReceiptChain(
  values: readonly unknown[],
): LifecycleReceiptChainResult {
  if (!Array.isArray(values) || values.length === 0)
    return { valid: false, code: "receipt-chain-incomplete" };

  const receipts: LifecycleReceipt[] = [];
  let previousDigest: string | null = null;
  let previousTimestamp = -Infinity;
  let identity: string | null = null;
  let state: "initial" | "launch-requested" | "started" | "terminal" =
    "initial";
  let timedOut = false;
  let terminationReason: TerminationReason | null = null;
  let killed = false;
  let supervisorFailed = false;

  for (let index = 0; index < values.length; index += 1) {
    const validation = validateLifecycleReceipt(values[index]);
    if (!validation.valid) return { valid: false, code: "receipt-invalid" };
    const receipt = validation.value;
    if (receipt.sequence !== index + 1)
      return { valid: false, code: "receipt-sequence-invalid" };
    const timestamp = Date.parse(receipt.timestamp);
    if (timestamp < previousTimestamp)
      return { valid: false, code: "receipt-timestamp-invalid" };
    previousTimestamp = timestamp;

    const currentIdentity = canonicalSerializeLifecycleValue({
      executionId: receipt.executionId,
      correlation: receipt.correlation,
      planDigest: receipt.planDigest,
      trustedPolicyIds: receipt.trustedPolicyIds,
    });
    if (identity !== null && currentIdentity !== identity)
      return { valid: false, code: "receipt-chain-mismatch" };
    identity = currentIdentity;
    if (receipt.previousReceiptDigest !== previousDigest)
      return { valid: false, code: "receipt-chain-mismatch" };
    if (computeLifecycleReceiptDigest(receipt) !== receipt.receiptDigest)
      return { valid: false, code: "receipt-digest-mismatch" };
    if (state === "terminal")
      return { valid: false, code: "receipt-lifecycle-invalid" };

    switch (receipt.eventType) {
      case "launch_requested":
        if (state !== "initial")
          return { valid: false, code: "receipt-lifecycle-invalid" };
        state = "launch-requested";
        break;
      case "process_started":
        if (state !== "launch-requested")
          return { valid: false, code: "receipt-lifecycle-invalid" };
        state = "started";
        break;
      case "process_failed":
        if (state !== "launch-requested")
          return { valid: false, code: "receipt-lifecycle-invalid" };
        state = "terminal";
        break;
      case "process_timed_out":
        if (state !== "started" || timedOut || terminationReason !== null)
          return { valid: false, code: "receipt-lifecycle-invalid" };
        timedOut = true;
        break;
      case "termination_requested": {
        const reason = (receipt.payload as { reason: TerminationReason })
          .reason;
        if (
          state !== "started" ||
          terminationReason !== null ||
          (reason === "timeout") !== timedOut
        )
          return { valid: false, code: "receipt-lifecycle-invalid" };
        terminationReason = reason;
        break;
      }
      case "process_killed":
        if (state !== "started" || terminationReason === null || killed)
          return { valid: false, code: "receipt-lifecycle-invalid" };
        killed = true;
        break;
      case "supervisor_failed":
        if (state !== "started" || supervisorFailed)
          return { valid: false, code: "receipt-lifecycle-invalid" };
        supervisorFailed = true;
        break;
      case "process_exited":
        if (
          state !== "started" ||
          !validExitOutcome(receipt.payload as ProcessExitPayload, {
            timedOut,
            terminationReason,
            killed,
            supervisorFailed,
          })
        )
          return { valid: false, code: "receipt-lifecycle-invalid" };
        state = "terminal";
        break;
    }
    previousDigest = receipt.receiptDigest;
    receipts.push(receipt);
  }

  if (state !== "terminal" || !terminalEvents.has(receipts.at(-1)!.eventType))
    return { valid: false, code: "receipt-chain-incomplete" };
  return { valid: true, receipts };
}

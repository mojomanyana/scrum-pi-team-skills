import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";

import {
  canonicalSerializeLifecycleValue,
  computeLifecycleReceiptDigest,
  validateLifecycleReceipt,
  verifyLifecycleReceiptChain,
  type LifecycleReceiptChainResult,
} from "@scrum-pi-team-skills/contracts";

import type { ReceiptSink } from "./process-host.js";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_RECEIPT_FILE_BYTES = 16 * 1024 * 1024;
const MAX_RECEIPT_LINES = 100_000;

export class ReceiptStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReceiptStorageError";
  }
}

function fixedStorageError(): ReceiptStorageError {
  return new ReceiptStorageError("receipt storage operation failed");
}

export function createLocalFilesystemReceiptSink(options: {
  readonly root: string;
}): ReceiptSink {
  if (
    typeof options.root !== "string" ||
    !isAbsolute(options.root) ||
    options.root.includes("\0")
  ) {
    throw fixedStorageError();
  }
  const root = options.root;
  return Object.freeze({
    async open(execution: {
      readonly executionId: string;
      readonly contractId: "spts.lifecycle-receipt";
      readonly contractVersion: "1.0.0";
    }) {
      if (!SAFE_ID.test(execution.executionId)) throw fixedStorageError();
      let descriptor: number;
      try {
        mkdirSync(root, { recursive: true, mode: 0o700 });
        const rootStat = lstatSync(root);
        if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
          throw new Error();
        }
        chmodSync(root, 0o700);
        const path = join(root, `${execution.executionId}.jsonl`);
        descriptor = openSync(
          path,
          constants.O_WRONLY |
            constants.O_CREAT |
            constants.O_EXCL |
            constants.O_APPEND |
            constants.O_NOFOLLOW,
          0o600,
        );
        fchmodSync(descriptor, 0o600);
      } catch {
        throw fixedStorageError();
      }

      let closed = false;
      let sequence = 0;
      let previousDigest: string | null = null;
      let identity: string | null = null;
      let terminal = false;
      return Object.freeze({
        append(line: string) {
          if (
            closed ||
            terminal ||
            typeof line !== "string" ||
            line.length === 0 ||
            line.includes("\n") ||
            Buffer.byteLength(line) > 65_536
          ) {
            throw fixedStorageError();
          }
          try {
            const parsed = JSON.parse(line) as unknown;
            const validation = validateLifecycleReceipt(parsed);
            const currentIdentity = validation.valid
              ? canonicalSerializeLifecycleValue({
                  executionId: validation.value.executionId,
                  correlation: validation.value.correlation,
                  planDigest: validation.value.planDigest,
                  trustedPolicyIds: validation.value.trustedPolicyIds,
                })
              : null;
            if (
              !validation.valid ||
              canonicalSerializeLifecycleValue(validation.value) !== line ||
              validation.value.executionId !== execution.executionId ||
              validation.value.contractId !== execution.contractId ||
              validation.value.contractVersion !== execution.contractVersion ||
              validation.value.sequence !== sequence + 1 ||
              validation.value.previousReceiptDigest !== previousDigest ||
              (identity !== null && currentIdentity !== identity) ||
              computeLifecycleReceiptDigest(validation.value) !==
                validation.value.receiptDigest
            ) {
              throw new Error();
            }
            writeSync(descriptor, `${line}\n`, undefined, "utf8");
            sequence += 1;
            identity = currentIdentity;
            previousDigest = validation.value.receiptDigest;
            terminal =
              validation.value.eventType === "process_exited" ||
              validation.value.eventType === "process_failed";
          } catch {
            throw fixedStorageError();
          }
        },
        close() {
          if (closed) return;
          closed = true;
          try {
            closeSync(descriptor);
            if (!terminal) throw new Error();
          } catch {
            throw fixedStorageError();
          }
        },
      });
    },
  });
}

export function inspectLifecycleReceiptFile(
  path: string,
): LifecycleReceiptChainResult {
  try {
    if (typeof path !== "string" || !isAbsolute(path) || path.includes("\0")) {
      throw new Error();
    }
    const stat = lstatSync(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size > MAX_RECEIPT_FILE_BYTES
    ) {
      throw new Error();
    }
    const text = readFileSync(path, "utf8");
    if (!text.endsWith("\n")) {
      return { valid: false, code: "receipt-chain-incomplete" };
    }
    const lines = text.split("\n").slice(0, -1);
    if (lines.length === 0 || lines.length > MAX_RECEIPT_LINES) {
      return { valid: false, code: "receipt-chain-incomplete" };
    }
    const values = lines.map((line) => JSON.parse(line) as unknown);
    if (
      values.some(
        (value, index) =>
          canonicalSerializeLifecycleValue(value) !== lines[index],
      )
    ) {
      return { valid: false, code: "receipt-invalid" };
    }
    return verifyLifecycleReceiptChain(values);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return { valid: false, code: "receipt-invalid" };
    }
    throw fixedStorageError();
  }
}

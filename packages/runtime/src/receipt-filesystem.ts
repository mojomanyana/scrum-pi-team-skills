import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join, normalize, parse, sep } from "node:path";

import {
  LIFECYCLE_RECEIPT_ANCHOR_CONTRACT_ID,
  LIFECYCLE_RECEIPT_ANCHOR_VERSION,
  canonicalSerializeLifecycleValue,
  computeLifecycleReceiptDigest,
  lifecycleReceiptAnchorPayload,
  validateLifecycleReceipt,
  validateLifecycleReceiptAnchor,
  verifyLifecycleReceiptChain,
  type LifecycleReceipt,
  type LifecycleReceiptAnchor,
  type LifecycleReceiptChainResult,
} from "@scrum-pi-team-skills/contracts";

import {
  authenticateLifecycleReceiptAnchor,
  verifyLifecycleReceiptAnchorAuthentication,
  type ReceiptAuthenticator,
} from "./receipt-authenticator.js";
import type { ReceiptSink } from "./process-host.js";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_RECEIPT_FILE_BYTES = 16 * 1024 * 1024;
const MAX_ANCHOR_FILE_BYTES = 16 * 1024;
const MAX_RECEIPT_LINES = 100_000;
const RECEIPT_BASENAME = "receipts.jsonl";
const ANCHOR_BASENAME = "anchor.json";

export interface ReceiptFileOperations {
  readonly write: (
    descriptor: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
  ) => number;
  readonly sync: (descriptor: number) => void;
  readonly close: (descriptor: number) => void;
}

const nodeFileOperations: ReceiptFileOperations = Object.freeze({
  write: (
    descriptor: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
  ) => writeSync(descriptor, buffer, offset, length, null),
  sync: fsyncSync,
  close: closeSync,
});

export class ReceiptStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReceiptStorageError";
  }
}

function fixedStorageError(): ReceiptStorageError {
  return new ReceiptStorageError("receipt storage operation failed");
}

function validateTrustedParentLexically(
  value: unknown,
): asserts value is string {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    value.includes("\0") ||
    value === parse(value).root ||
    value.endsWith(sep) ||
    value.split(sep).some((segment) => segment === "." || segment === "..") ||
    normalize(value) !== value
  ) {
    throw fixedStorageError();
  }
}

function expectedOwner(): number {
  if (process.platform !== "linux" || typeof process.getuid !== "function")
    throw fixedStorageError();
  return process.getuid();
}

function walkWithoutSymlinks(path: string): void {
  const root = parse(path).root;
  let current = root;
  for (const segment of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error();
  }
}

function requireTrustedParent(path: string): void {
  walkWithoutSymlinks(path);
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== expectedOwner() ||
    (stat.mode & 0o777) !== 0o700 ||
    realpathSync(path) !== path
  ) {
    throw new Error();
  }
}

function requirePrivateDirectory(path: string): void {
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== expectedOwner() ||
    (stat.mode & 0o777) !== 0o700
  )
    throw new Error();
}

function noFollowFlag(): number {
  return typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
}

function sameIdentity(descriptor: number, path: string): boolean {
  const descriptorStat = fstatSync(descriptor);
  const pathStat = lstatSync(path);
  return (
    descriptorStat.isFile() &&
    !pathStat.isSymbolicLink() &&
    pathStat.isFile() &&
    descriptorStat.dev === pathStat.dev &&
    descriptorStat.ino === pathStat.ino
  );
}

function openExclusivePrivateFile(path: string): number {
  const descriptor = openSync(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_APPEND |
      noFollowFlag(),
    0o600,
  );
  try {
    fchmodSync(descriptor, 0o600);
    if (!sameIdentity(descriptor, path)) throw new Error();
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function openPrivateFileForInspection(
  path: string,
  maximumBytes: number,
): number {
  const stat = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== expectedOwner() ||
    (stat.mode & 0o777) !== 0o600 ||
    stat.size > maximumBytes
  )
    throw new Error();
  const descriptor = openSync(path, constants.O_RDONLY | noFollowFlag());
  if (!sameIdentity(descriptor, path)) {
    closeSync(descriptor);
    throw new Error();
  }
  return descriptor;
}

/** Complete one buffer or throw; successful return is the commit boundary. */
export function writeAllReceiptBytes(
  descriptor: number,
  buffer: Uint8Array,
  operations: ReceiptFileOperations = nodeFileOperations,
): void {
  let offset = 0;
  while (offset < buffer.byteLength) {
    let written: number;
    try {
      written = operations.write(
        descriptor,
        buffer,
        offset,
        buffer.byteLength - offset,
      );
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        (error as { code?: unknown }).code === "EINTR"
      )
        continue;
      throw error;
    }
    if (
      !Number.isSafeInteger(written) ||
      written <= 0 ||
      written > buffer.byteLength - offset
    )
      throw new Error();
    offset += written;
  }
}

function canonicalReceiptLines(text: string): unknown[] | null {
  if (!text.endsWith("\n")) return null;
  const lines = text.split("\n").slice(0, -1);
  if (lines.length === 0 || lines.length > MAX_RECEIPT_LINES) return null;
  const values = lines.map((line) => JSON.parse(line) as unknown);
  if (
    values.some(
      (value, index) =>
        canonicalSerializeLifecycleValue(value) !== lines[index],
    )
  )
    return null;
  return values;
}

export function createLocalFilesystemReceiptSink(options: {
  readonly trustedParent: string;
  readonly authenticator: ReceiptAuthenticator;
  /** Deterministic fault seam; production callers omit this. */
  readonly fileOperations?: ReceiptFileOperations;
}): ReceiptSink {
  validateTrustedParentLexically(options.trustedParent);
  const trustedParent = options.trustedParent;
  const operations = options.fileOperations ?? nodeFileOperations;
  try {
    requireTrustedParent(trustedParent);
  } catch {
    throw fixedStorageError();
  }

  return Object.freeze({
    async open(execution: {
      readonly executionId: string;
      readonly contractId: "spts.lifecycle-receipt";
      readonly contractVersion: "1.0.0";
    }) {
      if (!SAFE_ID.test(execution.executionId)) throw fixedStorageError();
      let descriptor: number;
      const executionDirectory = join(trustedParent, execution.executionId);
      const receiptPath = join(executionDirectory, RECEIPT_BASENAME);
      try {
        requireTrustedParent(trustedParent);
        mkdirSync(executionDirectory, { mode: 0o700 });
        requirePrivateDirectory(executionDirectory);
        descriptor = openExclusivePrivateFile(receiptPath);
      } catch {
        throw fixedStorageError();
      }

      let descriptorClosed = false;
      let closed = false;
      let failed = false;
      let terminal = false;
      let sequence = 0;
      let previousDigest: string | null = null;
      let identity: string | null = null;
      const receipts: LifecycleReceipt[] = [];

      const closeDescriptor = (): void => {
        if (descriptorClosed) return;
        descriptorClosed = true;
        operations.close(descriptor);
      };
      const poison = (): never => {
        failed = true;
        try {
          closeDescriptor();
        } catch {
          // The fixed storage diagnostic remains authoritative.
        }
        throw fixedStorageError();
      };

      return Object.freeze({
        append(line: string) {
          if (
            closed ||
            failed ||
            terminal ||
            typeof line !== "string" ||
            line.length === 0 ||
            line.includes("\n") ||
            Buffer.byteLength(line) > 65_536
          )
            throw fixedStorageError();
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
            )
              throw new Error();

            const bytes = Buffer.from(`${line}\n`, "utf8");
            try {
              writeAllReceiptBytes(descriptor, bytes, operations);
              operations.sync(descriptor);
            } finally {
              bytes.fill(0);
            }
            sequence += 1;
            identity = currentIdentity;
            previousDigest = validation.value.receiptDigest;
            receipts.push(validation.value);
            terminal =
              validation.value.eventType === "process_exited" ||
              validation.value.eventType === "process_failed";
          } catch {
            poison();
          }
        },
        close() {
          if (closed) return;
          closed = true;
          if (failed) {
            try {
              closeDescriptor();
            } catch {
              // An earlier append failure remains authoritative.
            }
            return;
          }
          try {
            if (!terminal || !verifyLifecycleReceiptChain(receipts).valid)
              throw new Error();
            operations.sync(descriptor);
            closeDescriptor();
            const terminalReceipt = receipts.at(-1)!;
            const anchorPayload = {
              contractId: LIFECYCLE_RECEIPT_ANCHOR_CONTRACT_ID,
              contractVersion: LIFECYCLE_RECEIPT_ANCHOR_VERSION,
              executionId: execution.executionId,
              receiptCount: receipts.length,
              terminalReceiptDigest: terminalReceipt.receiptDigest,
              planDigest: terminalReceipt.planDigest,
              environmentPolicyId: terminalReceipt.trustedPolicyIds.environment,
              runtimePolicyId: terminalReceipt.trustedPolicyIds.runtime,
              authenticatorId: options.authenticator.authenticatorId,
            } as const;
            const anchor: LifecycleReceiptAnchor = {
              ...anchorPayload,
              authenticationTag: authenticateLifecycleReceiptAnchor(
                options.authenticator,
                anchorPayload,
              ),
            };
            const anchorBytes = Buffer.from(
              `${canonicalSerializeLifecycleValue(anchor)}\n`,
              "utf8",
            );
            const anchorPath = join(executionDirectory, ANCHOR_BASENAME);
            const anchorDescriptor = openExclusivePrivateFile(anchorPath);
            try {
              writeAllReceiptBytes(anchorDescriptor, anchorBytes, operations);
              operations.sync(anchorDescriptor);
            } finally {
              anchorBytes.fill(0);
              operations.close(anchorDescriptor);
            }
          } catch {
            failed = true;
            try {
              closeDescriptor();
            } catch {
              // The fixed storage diagnostic remains authoritative.
            }
            throw fixedStorageError();
          }
        },
      });
    },
  });
}

export function inspectLifecycleReceipts(options: {
  readonly trustedParent: string;
  readonly executionId: string;
  readonly authenticator: ReceiptAuthenticator;
}): LifecycleReceiptChainResult {
  try {
    validateTrustedParentLexically(options.trustedParent);
    if (!SAFE_ID.test(options.executionId)) throw new Error();
    requireTrustedParent(options.trustedParent);
    const executionDirectory = join(options.trustedParent, options.executionId);
    requirePrivateDirectory(executionDirectory);

    const receiptDescriptor = openPrivateFileForInspection(
      join(executionDirectory, RECEIPT_BASENAME),
      MAX_RECEIPT_FILE_BYTES,
    );
    let text: string;
    try {
      text = readFileSync(receiptDescriptor, "utf8");
    } finally {
      closeSync(receiptDescriptor);
    }
    const values = canonicalReceiptLines(text);
    if (!values) return { valid: false, code: "receipt-chain-incomplete" };
    const chain = verifyLifecycleReceiptChain(values);
    if (!chain.valid) return chain;

    const anchorDescriptor = openPrivateFileForInspection(
      join(executionDirectory, ANCHOR_BASENAME),
      MAX_ANCHOR_FILE_BYTES,
    );
    let anchorText: string;
    try {
      anchorText = readFileSync(anchorDescriptor, "utf8");
    } finally {
      closeSync(anchorDescriptor);
    }
    if (!anchorText.endsWith("\n") || anchorText.slice(0, -1).includes("\n")) {
      return { valid: false, code: "receipt-anchor-invalid" };
    }
    const parsedAnchor = JSON.parse(anchorText.slice(0, -1)) as unknown;
    if (
      canonicalSerializeLifecycleValue(parsedAnchor) !== anchorText.slice(0, -1)
    )
      return { valid: false, code: "receipt-anchor-invalid" };
    const validation = validateLifecycleReceiptAnchor(parsedAnchor);
    if (!validation.valid)
      return { valid: false, code: "receipt-anchor-invalid" };
    const anchor = validation.value;
    const terminal = chain.receipts.at(-1)!;
    if (
      anchor.executionId !== options.executionId ||
      anchor.receiptCount !== chain.receipts.length ||
      anchor.terminalReceiptDigest !== terminal.receiptDigest ||
      anchor.planDigest !== terminal.planDigest ||
      anchor.environmentPolicyId !== terminal.trustedPolicyIds.environment ||
      anchor.runtimePolicyId !== terminal.trustedPolicyIds.runtime ||
      anchor.authenticatorId !== options.authenticator.authenticatorId
    )
      return { valid: false, code: "receipt-anchor-invalid" };
    if (
      !verifyLifecycleReceiptAnchorAuthentication(
        options.authenticator,
        lifecycleReceiptAnchorPayload(anchor),
        anchor.authenticationTag,
      )
    )
      return { valid: false, code: "receipt-authentication-failed" };
    return chain;
  } catch (error) {
    if (error instanceof SyntaxError)
      return { valid: false, code: "receipt-invalid" };
    throw fixedStorageError();
  }
}

import { lstatSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import receipts from "../../contracts/examples/lifecycle-receipts.success.json" with { type: "json" };
import { canonicalSerializeLifecycleValue } from "../../contracts/src/index.js";
import {
  createLocalFilesystemReceiptSink,
  inspectLifecycleReceiptFile,
  ReceiptStorageError,
} from "../src/index.js";

const roots: string[] = [];

function root(): string {
  const value = join(tmpdir(), `spts-receipts-${process.pid}-${roots.length}`);
  roots.push(value);
  return value;
}

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    roots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("local filesystem receipt sink", () => {
  it("creates a private directory and exclusive append-only receipt file", async () => {
    const receiptRoot = root();
    const sink = createLocalFilesystemReceiptSink({ root: receiptRoot });
    const writer = await sink.open({
      executionId: "runtime-example-001",
      contractId: "spts.lifecycle-receipt",
      contractVersion: "1.0.0",
    });
    for (const receipt of receipts) {
      await writer.append(canonicalSerializeLifecycleValue(receipt));
    }
    await writer.close();

    const path = join(receiptRoot, "runtime-example-001.jsonl");
    expect(lstatSync(receiptRoot).mode & 0o777).toBe(0o700);
    expect(lstatSync(path).mode & 0o777).toBe(0o600);
    expect(inspectLifecycleReceiptFile(path).valid).toBe(true);
    await expect(
      sink.open({
        executionId: "runtime-example-001",
        contractId: "spts.lifecycle-receipt",
        contractVersion: "1.0.0",
      }),
    ).rejects.toEqual(
      new ReceiptStorageError("receipt storage operation failed"),
    );
  });

  it("refuses an existing symlink as the receipt file", async () => {
    const receiptRoot = root();
    mkdirSync(receiptRoot, { recursive: true });
    const target = join(receiptRoot, "target");
    writeFileSync(target, "untouched");
    symlinkSync(target, join(receiptRoot, "runtime-link.jsonl"));

    const sink = createLocalFilesystemReceiptSink({ root: receiptRoot });
    await expect(
      sink.open({
        executionId: "runtime-link",
        contractId: "spts.lifecycle-receipt",
        contractVersion: "1.0.0",
      }),
    ).rejects.toEqual(
      new ReceiptStorageError("receipt storage operation failed"),
    );
  });

  it("reports tampering and truncation deterministically", () => {
    const receiptRoot = root();
    mkdirSync(receiptRoot, { recursive: true });
    const path = join(receiptRoot, "tampered.jsonl");
    writeFileSync(path, `${canonicalSerializeLifecycleValue(receipts[0])}\n`);

    expect(inspectLifecycleReceiptFile(path)).toEqual({
      valid: false,
      code: "receipt-chain-incomplete",
    });
  });
});

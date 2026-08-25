import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync,
  fsyncSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import receiptsExample from "../../contracts/examples/lifecycle-receipts.success.json" with { type: "json" };
import {
  canonicalSerializeLifecycleValue,
  computeLifecycleReceiptDigest,
  verifyLifecycleReceiptChain,
  type LifecycleReceipt,
} from "../../contracts/src/index.js";
import {
  createLocalFilesystemReceiptSink,
  createReceiptAuthenticator,
  inspectLifecycleReceipts,
  ReceiptStorageError,
  type ReceiptFileOperations,
} from "../src/index.js";

const roots: string[] = [];
const key = Buffer.alloc(32, 0x5a);

function root(): string {
  const value = join(
    tmpdir(),
    `spts-receipts-${process.pid}-${roots.length}-${Date.now()}`,
  );
  roots.push(value);
  return value;
}

function trustedParent(mode = 0o700): string {
  const value = root();
  mkdirSync(value, { recursive: true, mode });
  chmodSync(value, mode);
  return value;
}

function authenticator(id = "authenticator-test") {
  return createReceiptAuthenticator({ authenticatorId: id, key });
}

function operations(
  write: ReceiptFileOperations["write"],
  onClose: (descriptor: number) => void = closeSync,
): ReceiptFileOperations {
  return { write, sync: fsyncSync, close: onClose };
}

function timeoutReceipts(graceful: boolean): LifecycleReceipt[] {
  const receipts = [
    structuredClone(receiptsExample[0]),
    structuredClone(receiptsExample[1]),
    {
      ...structuredClone(receiptsExample[1]),
      eventType: "process_timed_out",
      payload: { maximumRuntimeMs: 10 },
    },
    ...(graceful
      ? [
          {
            ...structuredClone(receiptsExample[1]),
            eventType: "termination_requested" as const,
            payload: { reason: "timeout" as const },
          },
        ]
      : []),
    {
      ...structuredClone(receiptsExample.at(-1)!),
      payload: {
        ...structuredClone(receiptsExample.at(-1)!.payload),
        exitCode: graceful ? 0 : null,
        signal: graceful ? null : "SIGTERM",
        outcome: "timed_out",
      },
    },
  ] as LifecycleReceipt[];
  let previous: string | null = null;
  receipts.forEach((receipt, index) => {
    (receipt as { sequence: number }).sequence = index + 1;
    (receipt as { timestamp: string }).timestamp =
      `2026-08-23T00:00:${String(index).padStart(2, "0")}.000Z`;
    (
      receipt as { previousReceiptDigest: string | null }
    ).previousReceiptDigest = previous;
    (receipt as { receiptDigest: string }).receiptDigest =
      computeLifecycleReceiptDigest(receipt);
    previous = receipt.receiptDigest;
  });
  return receipts;
}

async function writeExample(
  parent: string,
  fileOperations?: ReceiptFileOperations,
): Promise<void> {
  const sink = createLocalFilesystemReceiptSink({
    trustedParent: parent,
    authenticator: authenticator(),
    fileOperations,
  });
  const writer = await sink.open({
    executionId: "runtime-example-001",
    contractId: "spts.lifecycle-receipt",
    contractVersion: "1.0.0",
  });
  for (const receipt of receiptsExample)
    await writer.append(canonicalSerializeLifecycleValue(receipt));
  await writer.close();
}

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    roots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("local filesystem receipt sink", () => {
  it("copies authentication keys into non-exporting factory authority", () => {
    const temporary = Buffer.alloc(32, 0x41);
    const issued = createReceiptAuthenticator({
      authenticatorId: "authenticator-private-copy",
      key: temporary,
    });
    temporary.fill(0);
    expect(issued).toEqual({
      authenticatorId: "authenticator-private-copy",
    });
    expect(JSON.stringify(issued)).not.toContain(
      Buffer.alloc(32, 0x41).toString("hex"),
    );
    expect(() =>
      createReceiptAuthenticator({
        authenticatorId: "authenticator-too-short",
        key: Buffer.alloc(31),
      }),
    ).toThrow("receipt authentication configuration failed");
  });

  it("creates a controlled private execution directory, chain, and authenticated anchor", async () => {
    const parent = trustedParent();
    await writeExample(parent);

    const directory = join(parent, "runtime-example-001");
    expect(lstatSync(parent).mode & 0o777).toBe(0o700);
    expect(lstatSync(directory).mode & 0o777).toBe(0o700);
    expect(lstatSync(join(directory, "receipts.jsonl")).mode & 0o777).toBe(
      0o600,
    );
    expect(lstatSync(join(directory, "anchor.json")).mode & 0o777).toBe(0o600);
    expect(
      inspectLifecycleReceipts({
        trustedParent: parent,
        executionId: "runtime-example-001",
        authenticator: authenticator(),
      }).valid,
    ).toBe(true);
  });

  it("uses authoritative lifecycle semantics for close, anchor creation, and inspection", async () => {
    const closeParent = trustedParent();
    const sink = createLocalFilesystemReceiptSink({
      trustedParent: closeParent,
      authenticator: authenticator(),
    });
    const writer = await sink.open({
      executionId: "runtime-example-001",
      contractId: "spts.lifecycle-receipt",
      contractVersion: "1.0.0",
    });
    for (const receipt of timeoutReceipts(false))
      await writer.append(canonicalSerializeLifecycleValue(receipt));
    expect(() => writer.close()).toThrow(
      new ReceiptStorageError("receipt storage operation failed"),
    );
    expect(
      existsSync(join(closeParent, "runtime-example-001", "anchor.json")),
    ).toBe(false);

    const inspectParent = trustedParent();
    await writeExample(inspectParent);
    const receiptPath = join(
      inspectParent,
      "runtime-example-001",
      "receipts.jsonl",
    );
    writeFileSync(
      receiptPath,
      `${timeoutReceipts(false)
        .map(canonicalSerializeLifecycleValue)
        .join("\n")}\n`,
      { mode: 0o600 },
    );
    expect(
      inspectLifecycleReceipts({
        trustedParent: inspectParent,
        executionId: "runtime-example-001",
        authenticator: authenticator(),
      }),
    ).toEqual({ valid: false, code: "receipt-lifecycle-invalid" });
  });

  it("closes a graceful timeout chain and authenticates its anchor for inspection", async () => {
    const parent = trustedParent();
    const sink = createLocalFilesystemReceiptSink({
      trustedParent: parent,
      authenticator: authenticator(),
    });
    const writer = await sink.open({
      executionId: "runtime-example-001",
      contractId: "spts.lifecycle-receipt",
      contractVersion: "1.0.0",
    });
    const receipts = timeoutReceipts(true);
    expect(verifyLifecycleReceiptChain(receipts).valid).toBe(true);
    for (const receipt of receipts)
      await writer.append(canonicalSerializeLifecycleValue(receipt));

    await writer.close();

    expect(existsSync(join(parent, "runtime-example-001", "anchor.json"))).toBe(
      true,
    );
    const inspection = inspectLifecycleReceipts({
      trustedParent: parent,
      executionId: "runtime-example-001",
      authenticator: authenticator(),
    });
    expect(inspection.valid).toBe(true);
    if (inspection.valid) {
      expect(inspection.receipts.at(-1)!.payload).toMatchObject({
        exitCode: 0,
        signal: null,
        outcome: "timed_out",
      });
    }
  });

  it.each([
    ["one-byte", () => 1],
    [
      "varying",
      (call: number, remaining: number) => Math.min(remaining, (call % 5) + 1),
    ],
  ])(
    "commits complete UTF-8 lines across %s short writes",
    async (_label, size) => {
      const parent = trustedParent();
      let calls = 0;
      await writeExample(
        parent,
        operations((descriptor, buffer, offset, length) => {
          calls += 1;
          const count = size(calls, length);
          return writeSync(descriptor, buffer, offset, count, null);
        }),
      );
      expect(calls).toBeGreaterThan(receiptsExample.length + 1);
      expect(
        inspectLifecycleReceipts({
          trustedParent: parent,
          executionId: "runtime-example-001",
          authenticator: authenticator(),
        }).valid,
      ).toBe(true);
    },
  );

  it("retries EINTR without losing bytes", async () => {
    const parent = trustedParent();
    let interrupted = false;
    await writeExample(
      parent,
      operations((descriptor, buffer, offset, length) => {
        if (!interrupted) {
          interrupted = true;
          throw Object.assign(new Error("interrupted"), { code: "EINTR" });
        }
        return writeSync(descriptor, buffer, offset, length, null);
      }),
    );
    expect(interrupted).toBe(true);
  });

  it.each(["zero", "oversized", "partial-throw"])(
    "poisons and closes a writer after a %s write fault",
    async (fault) => {
      const parent = trustedParent();
      let calls = 0;
      let closes = 0;
      const sink = createLocalFilesystemReceiptSink({
        trustedParent: parent,
        authenticator: authenticator(),
        fileOperations: operations(
          (descriptor, buffer, offset, length) => {
            calls += 1;
            if (fault === "zero") return 0;
            if (fault === "oversized") return length + 1;
            if (calls === 1)
              return writeSync(descriptor, buffer, offset, 1, null);
            throw new Error("injected write failure");
          },
          (descriptor) => {
            closes += 1;
            closeSync(descriptor);
          },
        ),
      });
      const writer = await sink.open({
        executionId: "runtime-write-fault",
        contractId: "spts.lifecycle-receipt",
        contractVersion: "1.0.0",
      });
      expect(() =>
        writer.append(canonicalSerializeLifecycleValue(receiptsExample[0])),
      ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
      expect(() =>
        writer.append(canonicalSerializeLifecycleValue(receiptsExample[0])),
      ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
      await writer.close();
      await writer.close();
      expect(closes).toBe(1);
    },
  );

  it("closes receipt and anchor descriptors once across repeated close", async () => {
    const parent = trustedParent();
    let closes = 0;
    const fileOperations = operations(
      (descriptor, buffer, offset, length) =>
        writeSync(descriptor, buffer, offset, length, null),
      (descriptor) => {
        closes += 1;
        closeSync(descriptor);
      },
    );
    await writeExample(parent, fileOperations);
    expect(closes).toBe(2);
  });

  it.each([
    (parent: string) => `${parent}/../other`,
    (parent: string) => `${parent}/./child`,
    (parent: string) => `${parent}//child`,
    (parent: string) => `${parent}/`,
  ])("rejects traversal or normalized mismatch", (candidate) => {
    const parent = trustedParent();
    expect(() =>
      createLocalFilesystemReceiptSink({
        trustedParent: candidate(parent),
        authenticator: authenticator(),
      }),
    ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
  });

  it("rejects a symlink in every caller-controlled parent position", () => {
    const base = trustedParent();
    const target = join(base, "target");
    mkdirSync(target, { mode: 0o700 });
    const link = join(base, "link");
    symlinkSync(target, link);
    for (const candidate of [link, join(link, "child")]) {
      if (candidate.endsWith("child"))
        mkdirSync(join(target, "child"), { mode: 0o700 });
      expect(() =>
        createLocalFilesystemReceiptSink({
          trustedParent: candidate,
          authenticator: authenticator(),
        }),
      ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
    }
  });

  it("rejects unsafe parent permissions and accepts an owned 0700 parent", () => {
    const unsafe = trustedParent(0o755);
    expect(() =>
      createLocalFilesystemReceiptSink({
        trustedParent: unsafe,
        authenticator: authenticator(),
      }),
    ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
    expect(() =>
      createLocalFilesystemReceiptSink({
        trustedParent: trustedParent(),
        authenticator: authenticator(),
      }),
    ).not.toThrow();
  });

  it.each(["regular", "symlink", "dangling"])(
    "refuses a %s execution-directory collision",
    async (kind) => {
      const parent = trustedParent();
      const collision = join(parent, "runtime-collision");
      if (kind === "regular") writeFileSync(collision, "untouched");
      else
        symlinkSync(
          kind === "symlink" ? parent : join(parent, "missing"),
          collision,
        );
      const sink = createLocalFilesystemReceiptSink({
        trustedParent: parent,
        authenticator: authenticator(),
      });
      await expect(
        sink.open({
          executionId: "runtime-collision",
          contractId: "spts.lifecycle-receipt",
          contractVersion: "1.0.0",
        }),
      ).rejects.toEqual(
        new ReceiptStorageError("receipt storage operation failed"),
      );
    },
  );

  it.each(["receipts.jsonl", "anchor.json"])(
    "refuses inspection through a symlinked %s",
    async (basename) => {
      const parent = trustedParent();
      await writeExample(parent);
      const path = join(parent, "runtime-example-001", basename);
      const moved = `${path}.moved`;
      renameSync(path, moved);
      symlinkSync(moved, path);
      expect(() =>
        inspectLifecycleReceipts({
          trustedParent: parent,
          executionId: "runtime-example-001",
          authenticator: authenticator(),
        }),
      ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
    },
  );

  it("rejects wrong keys, modified anchors, and missing anchors", async () => {
    const parent = trustedParent();
    await writeExample(parent);
    expect(
      inspectLifecycleReceipts({
        trustedParent: parent,
        executionId: "runtime-example-001",
        authenticator: createReceiptAuthenticator({
          authenticatorId: "authenticator-test",
          key: Buffer.alloc(32, 0x33),
        }),
      }),
    ).toEqual({ valid: false, code: "receipt-authentication-failed" });

    const anchorPath = join(parent, "runtime-example-001", "anchor.json");
    const anchor = JSON.parse(readFileSync(anchorPath, "utf8"));
    anchor.authenticationTag = "0".repeat(64);
    writeFileSync(anchorPath, `${canonicalSerializeLifecycleValue(anchor)}\n`, {
      mode: 0o600,
    });
    expect(
      inspectLifecycleReceipts({
        trustedParent: parent,
        executionId: "runtime-example-001",
        authenticator: authenticator(),
      }),
    ).toEqual({ valid: false, code: "receipt-authentication-failed" });

    unlinkSync(anchorPath);
    expect(() =>
      inspectLifecycleReceipts({
        trustedParent: parent,
        executionId: "runtime-example-001",
        authenticator: authenticator(),
      }),
    ).toThrow(new ReceiptStorageError("receipt storage operation failed"));
  });

  it.each(["reordered", "inserted", "deleted", "truncated-terminal"])(
    "rejects an authenticated chain that is %s",
    async (mutation) => {
      const parent = trustedParent();
      await writeExample(parent);
      const path = join(parent, "runtime-example-001", "receipts.jsonl");
      const lines = readFileSync(path, "utf8").trimEnd().split("\n");
      if (mutation === "reordered")
        [lines[0], lines[1]] = [lines[1]!, lines[0]!];
      if (mutation === "inserted") lines.splice(1, 0, lines[0]!);
      if (mutation === "deleted") lines.splice(1, 1);
      if (mutation === "truncated-terminal") lines.pop();
      writeFileSync(path, `${lines.join("\n")}\n`, { mode: 0o600 });
      expect(
        inspectLifecycleReceipts({
          trustedParent: parent,
          executionId: "runtime-example-001",
          authenticator: authenticator(),
        }).valid,
      ).toBe(false);
    },
  );

  it("rejects a modified and fully rehashed receipt chain against its anchor", async () => {
    const parent = trustedParent();
    await writeExample(parent);
    const path = join(parent, "runtime-example-001", "receipts.jsonl");
    const receipts = readFileSync(path, "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as LifecycleReceipt);
    const payload = receipts.at(-1)!.payload as {
      stdout: { bytes: number };
    };
    payload.stdout.bytes += 1;
    let previous: string | null = null;
    for (const receipt of receipts) {
      (
        receipt as { previousReceiptDigest: string | null }
      ).previousReceiptDigest = previous;
      (receipt as { receiptDigest: string }).receiptDigest =
        computeLifecycleReceiptDigest(receipt);
      previous = receipt.receiptDigest;
    }
    writeFileSync(
      path,
      `${receipts.map(canonicalSerializeLifecycleValue).join("\n")}\n`,
      { mode: 0o600 },
    );
    expect(
      inspectLifecycleReceipts({
        trustedParent: parent,
        executionId: "runtime-example-001",
        authenticator: authenticator(),
      }),
    ).toEqual({ valid: false, code: "receipt-anchor-invalid" });
  });

  it("documents the process-local replacement boundary without broad deletion", async () => {
    const parent = trustedParent();
    const replacement = root();
    mkdirSync(replacement, { mode: 0o700 });
    const moved = `${parent}.moved`;
    roots.push(moved);
    renameSync(parent, moved);
    renameSync(replacement, parent);
    await writeExample(parent);
    expect(lstatSync(moved).isDirectory()).toBe(true);
  });
});

import { describe, expect, it } from "vitest";

import anchorExample from "../examples/lifecycle-receipt-anchor.success.json" with { type: "json" };
import example from "../examples/lifecycle-receipts.success.json" with { type: "json" };
import {
  computeLifecycleReceiptDigest,
  validateLifecycleReceipt,
  validateLifecycleReceiptAnchor,
  verifyLifecycleReceiptChain,
  type LifecycleReceipt,
} from "../src/index.js";

function rehash(receipts: LifecycleReceipt[]): void {
  let previous: string | null = null;
  for (const receipt of receipts) {
    (
      receipt as { previousReceiptDigest: string | null }
    ).previousReceiptDigest = previous;
    (receipt as { receiptDigest: string }).receiptDigest =
      computeLifecycleReceiptDigest(receipt);
    previous = receipt.receiptDigest;
  }
}

describe("spts.lifecycle-receipt", () => {
  it("validates the versioned example and its canonical hash chain", () => {
    const receipts = example as LifecycleReceipt[];

    expect(
      receipts.every((receipt) => validateLifecycleReceipt(receipt).valid),
    ).toBe(true);
    expect(verifyLifecycleReceiptChain(receipts)).toEqual({
      valid: true,
      receipts,
    });
    expect(computeLifecycleReceiptDigest(receipts[0]!)).toBe(
      receipts[0]!.receiptDigest,
    );
  });

  it("detects payload tampering and terminal truncation", () => {
    const receipts = structuredClone(example) as LifecycleReceipt[];
    const exitPayload = receipts.at(-1)!.payload as {
      stdout: { bytes: number; sha256: string };
    };
    exitPayload.stdout.bytes = 1;

    expect(verifyLifecycleReceiptChain(receipts)).toEqual({
      valid: false,
      code: "receipt-digest-mismatch",
    });
    expect(
      verifyLifecycleReceiptChain((example as LifecycleReceipt[]).slice(0, 1)),
    ).toEqual({
      valid: false,
      code: "receipt-chain-incomplete",
    });
  });

  it("rejects credential-shaped receipt identities without echoing values", () => {
    const receipt = structuredClone(example[0]) as LifecycleReceipt;
    const suspected = `sk-proj-${"x".repeat(32)}`;
    (receipt.trustedPolicyIds as { environment: string }).environment =
      suspected;

    const result = validateLifecycleReceipt(receipt);
    expect(result.valid).toBe(false);
    expect(JSON.stringify(result)).not.toContain(suspected);
  });

  it("keeps canonical chain verification separate from terminal authentication", () => {
    const receipts = structuredClone(example) as LifecycleReceipt[];
    const exit = receipts.at(-1)!.payload as {
      stdout: { bytes: number };
    };
    exit.stdout.bytes = 1;
    rehash(receipts);

    expect(verifyLifecycleReceiptChain(receipts).valid).toBe(true);
  });

  it("validates the separate versioned anchor example structurally", () => {
    expect(validateLifecycleReceiptAnchor(anchorExample).valid).toBe(true);
  });

  it("enforces lifecycle predecessors and exit outcome consistency", () => {
    const exitAsSequenceOne = [
      structuredClone((example as LifecycleReceipt[]).at(-1)!),
    ];
    (exitAsSequenceOne[0] as { sequence: number }).sequence = 1;
    (
      exitAsSequenceOne[0] as { previousReceiptDigest: string | null }
    ).previousReceiptDigest = null;
    rehash(exitAsSequenceOne);
    expect(verifyLifecycleReceiptChain(exitAsSequenceOne).valid).toBe(false);

    const contradictory = structuredClone(example) as LifecycleReceipt[];
    const payload = contradictory.at(-1)!.payload as {
      exitCode: number | null;
      outcome: string;
    };
    payload.exitCode = 9;
    payload.outcome = "succeeded";
    rehash(contradictory);
    expect(verifyLifecycleReceiptChain(contradictory).valid).toBe(false);
  });

  it("rejects terminal suffixes, timeout-before-start, and kill-without-termination", () => {
    const terminalSuffix = structuredClone(example) as LifecycleReceipt[];
    const suffix = structuredClone(terminalSuffix.at(-1)!);
    (suffix as { sequence: number }).sequence = terminalSuffix.length + 1;
    (suffix as { timestamp: string }).timestamp = "2026-08-23T00:00:03.000Z";
    terminalSuffix.push(suffix);
    rehash(terminalSuffix);
    expect(verifyLifecycleReceiptChain(terminalSuffix).valid).toBe(false);

    const timeoutWithoutStart = structuredClone(example) as LifecycleReceipt[];
    (timeoutWithoutStart[1] as { eventType: string }).eventType =
      "process_timed_out";
    (timeoutWithoutStart[1] as { payload: unknown }).payload = {
      maximumRuntimeMs: 10,
    };
    const timeoutExit = timeoutWithoutStart.at(-1)!.payload as {
      exitCode: number | null;
      signal: string | null;
      outcome: string;
    };
    timeoutExit.exitCode = null;
    timeoutExit.signal = "SIGTERM";
    timeoutExit.outcome = "timed_out";
    rehash(timeoutWithoutStart);
    expect(verifyLifecycleReceiptChain(timeoutWithoutStart).valid).toBe(false);

    const killedWithoutTermination = structuredClone(
      example,
    ) as LifecycleReceipt[];
    const killed = structuredClone(killedWithoutTermination[1]!);
    (killed as { sequence: number }).sequence = 3;
    (killed as { timestamp: string }).timestamp = "2026-08-23T00:00:02.000Z";
    (killed as { eventType: string }).eventType = "process_killed";
    (killed as { payload: unknown }).payload = { signal: "SIGKILL" };
    const killedExit = killedWithoutTermination.at(-1)!;
    (killedExit as { sequence: number }).sequence = 4;
    (killedExit as { timestamp: string }).timestamp =
      "2026-08-23T00:00:03.000Z";
    const killedPayload = killedExit.payload as {
      exitCode: number | null;
      signal: string | null;
      outcome: string;
    };
    killedPayload.exitCode = null;
    killedPayload.signal = "SIGKILL";
    killedPayload.outcome = "signaled";
    killedWithoutTermination.splice(2, 0, killed);
    rehash(killedWithoutTermination);
    expect(verifyLifecycleReceiptChain(killedWithoutTermination).valid).toBe(
      false,
    );
  });

  it("rejects reordered and missing predecessor events", () => {
    const reordered = structuredClone(example) as LifecycleReceipt[];
    [reordered[0], reordered[1]] = [reordered[1]!, reordered[0]!];
    reordered.forEach((receipt, index) => {
      (receipt as { sequence: number }).sequence = index + 1;
    });
    rehash(reordered);
    expect(verifyLifecycleReceiptChain(reordered).valid).toBe(false);

    const missing = structuredClone(example) as LifecycleReceipt[];
    missing.splice(1, 1);
    missing.forEach((receipt, index) => {
      (receipt as { sequence: number }).sequence = index + 1;
    });
    rehash(missing);
    expect(verifyLifecycleReceiptChain(missing).valid).toBe(false);
  });

  it.each([
    "2026-02-30T12:00:00.000Z",
    "2026-08-23T12:00:00Z",
    "2026-08-23T12:00:00.000+00:00",
    "2026-08-23t12:00:00.000z",
    "2026-08-23T12:00:00.000Ztrailing",
  ])("rejects non-canonical timestamp %s", (timestamp) => {
    const receipt = structuredClone(example[0]) as LifecycleReceipt;
    (receipt as { timestamp: string }).timestamp = timestamp;
    expect(validateLifecycleReceipt(receipt).valid).toBe(false);
  });

  it("rejects decreasing timestamps", () => {
    const receipts = structuredClone(example) as LifecycleReceipt[];
    (receipts.at(-1) as { timestamp: string }).timestamp =
      "2026-08-22T00:00:00.000Z";
    rehash(receipts);
    expect(verifyLifecycleReceiptChain(receipts).valid).toBe(false);
  });

  it("rejects secret-bearing or raw-output payload fields", () => {
    const receipt = structuredClone(example[0]) as unknown as Record<
      string,
      unknown
    >;
    receipt.payload = { stdout: "raw", environment: { TOKEN: "opaque" } };

    expect(validateLifecycleReceipt(receipt).valid).toBe(false);
  });
});

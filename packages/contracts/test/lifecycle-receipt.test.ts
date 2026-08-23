import { describe, expect, it } from "vitest";

import example from "../examples/lifecycle-receipts.success.json" with { type: "json" };
import {
  computeLifecycleReceiptDigest,
  validateLifecycleReceipt,
  verifyLifecycleReceiptChain,
  type LifecycleReceipt,
} from "../src/index.js";

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
    const exitPayload = receipts[1]!.payload as {
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

  it("rejects secret-bearing or raw-output payload fields", () => {
    const receipt = structuredClone(example[0]) as unknown as Record<
      string,
      unknown
    >;
    receipt.payload = { stdout: "raw", environment: { TOKEN: "opaque" } };

    expect(validateLifecycleReceipt(receipt).valid).toBe(false);
  });
});

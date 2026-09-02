import { createHmac } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import example from "../examples/controller-store-receipt-v2.committed.json" with { type: "json" };
import {
  canonicalControllerStoreAuthenticationInputV2,
  committedControllerTransitionReceiptPayloadV2,
  computeCommittedControllerTransitionReceiptDigestV2,
  controllerStoreAuthenticationInputV2,
  parseCommittedControllerTransitionReceiptV2,
  validateCommittedControllerTransitionReceiptV2,
} from "../src/controller-store-receipt-v2.js";
import schema from "../src/schemas/controller-store-receipt-v2.schema.json" with { type: "json" };

const literalReceiptDigest =
  "d9d0dbc22df0314ef7b101873832ecdd91e3483c1375b383def41980bb7df023";
const literalAuthenticationTag =
  "e798287513a64b7251868ce3a34b0e889fa353c50b85281e9c556022e47228a6";

describe("committed controller transition receipt v2", () => {
  it("validates the committed example against schema and runtime semantics", () => {
    const validate = new Ajv2020({ allErrors: true }).compile(schema);
    expect(validate(example), JSON.stringify(validate.errors)).toBe(true);
    expect(validateCommittedControllerTransitionReceiptV2(example)).toBe(true);
    expect(computeCommittedControllerTransitionReceiptDigestV2(example)).toBe(
      example.receiptDigest,
    );
    const parsed = parseCommittedControllerTransitionReceiptV2(example);
    expect(parsed).toEqual(example);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it("locks an independent literal receipt digest and HMAC vector", () => {
    expect(example.receiptDigest).toBe(literalReceiptDigest);
    const input = controllerStoreAuthenticationInputV2(
      "test-key-1",
      "committed-transition-receipt",
      example.receiptDigest,
    );
    expect(input).toEqual({
      domain: "spts/controller-store-auth/v1",
      algorithm: "hmac-sha256",
      algorithmVersion: 1,
      keyId: "test-key-1",
      recordType: "committed-transition-receipt",
      bodyDigest: literalReceiptDigest,
    });
    expect(
      createHmac("sha256", Buffer.alloc(32, 0x41))
        .update(canonicalControllerStoreAuthenticationInputV2(input))
        .digest("hex"),
    ).toBe(literalAuthenticationTag);
    expect(example.authenticationTag).toBe(literalAuthenticationTag);
  });

  it("uses an exact payload that excludes only digest and authentication tag", () => {
    const payload = committedControllerTransitionReceiptPayloadV2(example);
    expect(Object.keys(payload).sort()).toEqual(
      Object.keys(example)
        .filter((key) => key !== "receiptDigest" && key !== "authenticationTag")
        .sort(),
    );
    expect(payload).not.toHaveProperty("receiptDigest");
    expect(payload).not.toHaveProperty("authenticationTag");
  });

  it("rejects unknown keys, malformed digests, aliases, timestamps, and hostile values", () => {
    expect(
      validateCommittedControllerTransitionReceiptV2({
        ...example,
        executableAuthority: false,
      }),
    ).toBe(false);
    expect(
      validateCommittedControllerTransitionReceiptV2({
        ...example,
        transitionChainDigest: "f".repeat(64),
      }),
    ).toBe(false);
    expect(
      validateCommittedControllerTransitionReceiptV2({
        ...example,
        committedRevision: example.previousRevision,
      }),
    ).toBe(false);
    expect(
      validateCommittedControllerTransitionReceiptV2({
        ...example,
        committedAt: "2026-09-02T00:00:00Z",
      }),
    ).toBe(false);
    expect(
      validateCommittedControllerTransitionReceiptV2({
        ...example,
        authenticationTag: "A".repeat(64),
      }),
    ).toBe(false);

    const getter = Object.defineProperty({}, "contractId", {
      enumerable: true,
      get() {
        throw new Error("must not execute");
      },
    });
    expect(validateCommittedControllerTransitionReceiptV2(getter)).toBe(false);
  });

  it("detects mutation of every authenticated payload binding", () => {
    const payload = committedControllerTransitionReceiptPayloadV2(example);
    for (const key of Object.keys(payload)) {
      const changed = structuredClone(example) as Record<string, unknown>;
      const original = changed[key];
      changed[key] =
        typeof original === "number"
          ? original + 1
          : original === null
            ? "0".repeat(64)
            : typeof original === "string" && /^[0-9a-f]{64}$/.test(original)
              ? `${original.slice(0, 63)}${original.endsWith("0") ? "1" : "0"}`
              : `${String(original)}-changed`;
      expect(
        computeCommittedControllerTransitionReceiptDigestV2(changed),
        key,
      ).not.toBe(example.receiptDigest);
    }
  });
});

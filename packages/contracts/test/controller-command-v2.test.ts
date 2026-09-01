import { describe, expect, it } from "vitest";
import example from "../examples/controller-command-v2.example.json" with { type: "json" };
import {
  canonicalizeControllerValueV2,
  digestControllerCommandV2,
  validateControllerCommandV2,
} from "../src/controller-command-v2.js";
import schema from "../src/schemas/controller-command-v2.schema.json" with { type: "json" };

describe("controller command v2 contract", () => {
  it("validates and hashes the complete example canonically", () => {
    expect(validateControllerCommandV2(example)).toBe(true);
    expect(digestControllerCommandV2(example)).toMatch(/^[0-9a-f]{64}$/);
    expect(canonicalizeControllerValueV2({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(schema.oneOf).toHaveLength(15);
  });

  it("rejects mutation, malformed evidence, and hostile values safely", () => {
    expect(validateControllerCommandV2({ ...example, extra: true })).toBe(
      false,
    );
    expect(
      validateControllerCommandV2({ ...example, expectedRevision: -0 }),
    ).toBe(false);
    const getter = Object.defineProperty({}, "contractId", {
      enumerable: true,
      get: () => {
        throw new Error("must not execute");
      },
    });
    expect(validateControllerCommandV2(getter)).toBe(false);
    expect(() => digestControllerCommandV2(getter)).toThrow(TypeError);
  });
});

import { describe, expect, it } from "vitest";
import example from "../examples/controller-snapshot-v2.example.json" with { type: "json" };
import {
  digestControllerSnapshotV2,
  validateControllerSnapshotV2,
} from "../src/controller-snapshot-v2.js";
import schema from "../src/schemas/controller-snapshot-v2.schema.json" with { type: "json" };
describe("controller snapshot v2 contract", () => {
  it("validates reachable snapshots and semantic limits", () => {
    expect(schema.additionalProperties).toBe(false);
    expect(validateControllerSnapshotV2(example)).toBe(true);
    expect(digestControllerSnapshotV2(example)).toMatch(/^[0-9a-f]{64}$/);
    expect(
      validateControllerSnapshotV2({
        ...example,
        usage: { ...example.usage, ciRepairs: 3 },
      }),
    ).toBe(false);
    expect(
      validateControllerSnapshotV2({
        ...example,
        previousTransitionDigest: "0".repeat(64),
      }),
    ).toBe(false);
  });
});

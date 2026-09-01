import { describe, expect, it } from "vitest";
import example from "../examples/controller-transition-v2.example.json" with { type: "json" };
import {
  CONTROLLER_DIAGNOSTICS_V2,
  validateControllerTransitionV2,
} from "../src/controller-transition-v2.js";
import schema from "../src/schemas/controller-transition-v2.schema.json" with { type: "json" };
describe("controller transition v2 contract", () => {
  it("enforces fixed diagnostics and closed dispositions", () => {
    expect(schema.additionalProperties).toBe(false);
    expect(validateControllerTransitionV2(example)).toBe(true);
    expect(Object.keys(CONTROLLER_DIAGNOSTICS_V2)).toHaveLength(21);
    expect(
      validateControllerTransitionV2({
        ...example,
        diagnostics: [{ ...example.diagnostics[0], message: "attacker" }],
      }),
    ).toBe(false);
  });
});

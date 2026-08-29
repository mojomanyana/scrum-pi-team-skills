import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import bootstrap from "../examples/delivery-authority-bootstrap.valid.json" with { type: "json" };
import v2 from "../examples/delivery-authority-v2.valid.json" with { type: "json" };
import invalidBootstrap from "./fixtures/invalid/delivery-authority-bootstrap-traversal.json" with { type: "json" };
import invalidV2 from "./fixtures/invalid/delivery-authority-v2-version-fallback.json" with { type: "json" };
import {
  validateDeliveryAuthorityBootstrap,
  validateDeliveryAuthorityContractV2,
  DELIVERY_AUTHORITY_CONTRACT_VERSION,
  DELIVERY_AUTHORITY_V2_VERSION,
} from "../src/index.js";
describe("v2 examples, compatibility, redaction, and scope", () => {
  it("validates new examples while retaining v1", () => {
    expect(validateDeliveryAuthorityBootstrap(bootstrap).valid).toBe(true);
    expect(validateDeliveryAuthorityContractV2(v2).valid).toBe(true);
    expect(DELIVERY_AUTHORITY_CONTRACT_VERSION).toBe("1.0.0");
    expect(DELIVERY_AUTHORITY_V2_VERSION).toBe("2.0.0");
    expect(validateDeliveryAuthorityBootstrap(invalidBootstrap).valid).toBe(
      false,
    );
    expect(validateDeliveryAuthorityContractV2(invalidV2).valid).toBe(false);
  });
  it("documents non-authorizing Slice 1 and deferred effects", () => {
    const readme = readFileSync(
      new URL("../../../README.md", import.meta.url),
      "utf8",
    );
    expect(readme).toContain("SPTS-10 Slice 1");
    expect(readme).toContain("does not launch");
    expect(readme).toContain("fresh independent Critical");
  });
  it("keeps diagnostics fixed and excludes raw output or credentials", () => {
    for (const result of [
      validateDeliveryAuthorityBootstrap({ secret: "attacker exception" }),
      validateDeliveryAuthorityContractV2({ secret: "attacker exception" }),
    ]) {
      expect(result.valid).toBe(false);
      if (!result.valid)
        expect(JSON.stringify(result.errors)).not.toContain(
          "attacker exception",
        );
    }
  });
});

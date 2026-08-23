import { describe, expect, it } from "vitest";

import { isExecutionContext } from "../src/index.js";

describe("isExecutionContext", () => {
  it("accepts the approved local execution model", () => {
    expect(
      isExecutionContext({
        process: "local-pi",
        governedBy: "pi-daddy",
        systemOfRecord: "paca",
      }),
    ).toBe(true);
  });

  it("rejects an agent outside pi-daddy governance", () => {
    expect(
      isExecutionContext({
        process: "local-pi",
        governedBy: "standalone",
        systemOfRecord: "paca",
      }),
    ).toBe(false);
  });

  it("rejects undeclared fields", () => {
    expect(
      isExecutionContext({
        process: "local-pi",
        governedBy: "pi-daddy",
        systemOfRecord: "paca",
        remote: true,
      }),
    ).toBe(false);
  });

  it("returns false rather than propagating exceptional input introspection", () => {
    const exceptional = new Proxy(
      {
        process: "local-pi",
        governedBy: "pi-daddy",
        systemOfRecord: "paca",
      },
      {
        ownKeys() {
          throw new Error(["OPENAI_API_KEY", "secret"].join("="));
        },
      },
    );

    expect(isExecutionContext(exceptional)).toBe(false);
  });
});

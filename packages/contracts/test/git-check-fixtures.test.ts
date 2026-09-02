import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  canonicalizeGitCheckFixtureValueV1,
  computeFixtureRepositoryObservationDigestV1,
  computeNamedCheckResultDigestV1,
  parseFixtureRepositoryObservationV1,
  parseNamedCheckResultV1,
  validateFixtureRepositoryObservationV1,
  validateNamedCheckResultV1,
} from "../src/git-check-fixtures.js";

describe("git-check-fixtures", () => {
  it("validates examples and digests", () => {
    const obs = JSON.parse(
      readFileSync(
        new URL(
          "../examples/fixture-repository-observation.applied.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const res = JSON.parse(
      readFileSync(
        new URL("../examples/named-check-result.passed.json", import.meta.url),
        "utf8",
      ),
    );
    expect(validateFixtureRepositoryObservationV1(obs).valid).toBe(true);
    expect(validateNamedCheckResultV1(res).valid).toBe(true);
    expect(parseFixtureRepositoryObservationV1(obs).contract).toBe(
      "spts.fixture-repository-observation",
    );
    expect(parseNamedCheckResultV1(res).contract).toBe(
      "spts.named-check-result",
    );
    expect(canonicalizeGitCheckFixtureValueV1({ b: 1, a: 2 })).toBe(
      '{"a":2,"b":1}',
    );
    expect(computeFixtureRepositoryObservationDigestV1(obs)).toMatch(
      /^[a-f0-9]{64}$/,
    );
    expect(computeNamedCheckResultDigestV1(res)).toMatch(/^[a-f0-9]{64}$/);
  });
});

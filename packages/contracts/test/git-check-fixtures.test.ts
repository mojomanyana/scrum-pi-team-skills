import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  CLEAN_REPOSITORY_DIGESTS_V1,
  canonicalizeGitCheckFixtureValueV1,
  computeFixtureRepositoryObservationDigestV1,
  computeGitCheckFixtureDigestV1,
  computeNamedCheckResultDigestV1,
  createFixtureDiagnosticV1,
  parseFixtureRepositoryObservationV1,
  parseNamedCheckResultV1,
  validateFixtureRepositoryObservationV1,
  validateNamedCheckResultV1,
  type FixtureRepositoryObservationV1,
  type NamedCheckResultV1,
} from "../src/git-check-fixtures.js";

function sampleObservation(): FixtureRepositoryObservationV1 {
  const unsigned: FixtureRepositoryObservationV1 = {
    contract: "spts.fixture-repository-observation",
    version: "1.0.0",
    runId: "run-1",
    operationId: "op-1",
    registrationId: "reg-1",
    operationKind: "create-repository",
    purpose: "principal-candidate",
    sequence: 1,
    observedAt: "2000-01-01T00:00:00.000Z",
    repositoryIdentity: {
      commonDirectoryDigest: "a".repeat(64),
      objectFormat: "sha256",
    },
    pre: null,
    post: {
      headCommit: "b".repeat(64),
      headTree: "c".repeat(64),
      branch: "fixture-main",
      detached: false,
      clean: true,
      indexDigest: computeGitCheckFixtureDigestV1("spts.fixture-index/1.0.0", [
        ["100644", "c".repeat(64), "README.md"],
      ]),
      trackedWorktreeDigest: computeGitCheckFixtureDigestV1(
        "spts.fixture-tracked-worktree/1.0.0",
        [["100644", "c".repeat(64), "README.md"]],
      ),
      untrackedSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.untrackedSetDigest,
      ignoredSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.ignoredSetDigest,
      conflictSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.conflictSetDigest,
      submoduleSetDigest: CLEAN_REPOSITORY_DIGESTS_V1.submoduleSetDigest,
      filesystemSentinelDigest: "d".repeat(64),
      worktreeSetDigest: "e".repeat(64),
    },
    outcome: "applied",
    diagnostic: null,
    requestDigest: "f".repeat(64),
    observationDigest: "",
  };
  return {
    ...unsigned,
    observationDigest: computeFixtureRepositoryObservationDigestV1(unsigned),
  };
}

function sampleResult(
  overrides: Partial<NamedCheckResultV1> = {},
): NamedCheckResultV1 {
  const unsigned: NamedCheckResultV1 = {
    contract: "spts.named-check-result",
    version: "1.0.0",
    runId: "run-1",
    operationId: "check-1",
    checkId: "fixture-pass",
    registrationId: "reg-check",
    attempt: 1,
    candidateCommit: "a".repeat(64),
    candidateTree: "b".repeat(64),
    workspaceTreeBefore: "b".repeat(64),
    workspaceTreeAfter: "b".repeat(64),
    startedAt: "2000-01-01T00:00:00.000Z",
    completedAt: "2000-01-01T00:00:01.000Z",
    elapsedMs: 1000,
    outcome: "passed",
    exitCode: 0,
    signal: null,
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutDigest: createHash("sha256").digest("hex"),
    stderrDigest: createHash("sha256").digest("hex"),
    diagnostic: null,
    requestDigest: "c".repeat(64),
    resultDigest: "",
    ...overrides,
  };
  return {
    ...unsigned,
    resultDigest: computeNamedCheckResultDigestV1(unsigned),
  };
}

describe("git-check-fixtures contracts", () => {
  it("validates examples and recomputes digests", () => {
    const observation = JSON.parse(
      readFileSync(
        new URL(
          "../examples/fixture-repository-observation.applied.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const result = JSON.parse(
      readFileSync(
        new URL("../examples/named-check-result.passed.json", import.meta.url),
        "utf8",
      ),
    );

    expect(validateFixtureRepositoryObservationV1(observation).valid).toBe(
      true,
    );
    expect(validateNamedCheckResultV1(result).valid).toBe(true);
    expect(
      parseFixtureRepositoryObservationV1(observation).observationDigest,
    ).toBe(computeFixtureRepositoryObservationDigestV1(observation));
    expect(parseNamedCheckResultV1(result).resultDigest).toBe(
      computeNamedCheckResultDigestV1(result),
    );
  });

  it("canonicalizes deterministically and separates digest domains", () => {
    expect(canonicalizeGitCheckFixtureValueV1({ b: 1, a: [true, null] })).toBe(
      '{"a":[true,null],"b":1}',
    );
    expect(() =>
      canonicalizeGitCheckFixtureValueV1({ value: () => "nope" }),
    ).toThrow(/inspected|canonical/i);
    const sparse = new Array<number>(2);
    sparse[1] = 1;
    expect(() => canonicalizeGitCheckFixtureValueV1(sparse)).toThrow();
    expect(
      computeGitCheckFixtureDigestV1("spts.fixture-index/1.0.0", { value: 1 }),
    ).not.toBe(
      computeGitCheckFixtureDigestV1("spts.fixture-tracked-worktree/1.0.0", {
        value: 1,
      }),
    );
  });

  it("enforces observation composite rules", () => {
    const valid = sampleObservation();
    expect(validateFixtureRepositoryObservationV1(valid).valid).toBe(true);

    const invalidDigest = {
      ...valid,
      observationDigest: "0".repeat(64),
    };
    expect(validateFixtureRepositoryObservationV1(invalidDigest).valid).toBe(
      false,
    );

    const invalidDetached = {
      ...valid,
      post: { ...valid.post!, branch: null, detached: false },
      observationDigest: "",
    };
    invalidDetached.observationDigest =
      computeFixtureRepositoryObservationDigestV1(invalidDetached);
    expect(validateFixtureRepositoryObservationV1(invalidDetached).valid).toBe(
      false,
    );

    const cancelled = {
      ...valid,
      outcome: "cancelled" as const,
      diagnostic: createFixtureDiagnosticV1("cancelled"),
      observationDigest: "",
    };
    cancelled.observationDigest =
      computeFixtureRepositoryObservationDigestV1(cancelled);
    expect(validateFixtureRepositoryObservationV1(cancelled).valid).toBe(true);
  });

  it("enforces named-check truth-table rows", () => {
    expect(validateNamedCheckResultV1(sampleResult()).valid).toBe(true);

    const failed = sampleResult({
      outcome: "failed",
      exitCode: 23,
      diagnostic: null,
    });
    expect(validateNamedCheckResultV1(failed).valid).toBe(true);

    const invalidFailed = sampleResult({
      outcome: "failed",
      exitCode: 0,
    });
    expect(validateNamedCheckResultV1(invalidFailed).valid).toBe(false);

    const timedOut = sampleResult({
      outcome: "timed-out",
      exitCode: null,
      diagnostic: createFixtureDiagnosticV1("check-timed-out"),
    });
    expect(validateNamedCheckResultV1(timedOut).valid).toBe(true);

    const mutated = sampleResult({
      outcome: "mutation-detected",
      exitCode: 0,
      diagnostic: createFixtureDiagnosticV1("workspace-mutated"),
      workspaceTreeAfter: "d".repeat(64),
    });
    expect(validateNamedCheckResultV1(mutated).valid).toBe(true);

    const invalidSignal = sampleResult({ signal: "SIGTERM", exitCode: 0 });
    expect(validateNamedCheckResultV1(invalidSignal).valid).toBe(false);
  });

  it("rejects hostile credential-shaped input safely", () => {
    const observation = sampleObservation();
    const hostile = {
      ...observation,
      runId: "api_key=sk-secret",
      observationDigest: "",
    };
    hostile.observationDigest =
      computeFixtureRepositoryObservationDigestV1(hostile);
    expect(validateFixtureRepositoryObservationV1(hostile)).toEqual({
      valid: false,
      errors: [
        {
          path: "/",
          code: "credential-content-denied",
          message: "credential content is prohibited",
        },
      ],
    });
  });
});

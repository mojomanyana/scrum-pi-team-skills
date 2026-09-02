import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import example from "../examples/controller-store-v2.status.json" with { type: "json" };
import {
  CONTROLLER_STORE_DIAGNOSTIC_CODES_V2,
  CONTROLLER_STORE_DIAGNOSTICS_V2,
  CONTROLLER_STORE_LIMITS_V2,
  canonicalizeControllerStoreValueV2,
  deriveControllerRunIdentityDigestV2,
  deriveControllerStoreNamespaceDigestV2,
  parseControllerStoreStatusV2,
  projectPersistedRunIdentityV2,
  validateControllerRunIdentityV2,
  validateControllerStoreStatusV2,
} from "../src/controller-store-v2.js";
import schema from "../src/schemas/controller-store-v2.schema.json" with { type: "json" };

const namespaceDigest =
  "befaab798f2cec8585ed4bbc7c876320d3f27fe7b5d78074a342e90a873948b8";
const runIdentityDigest =
  "1b5466fd8b87936c355662b9881e7d0736336ac3e3e9a51a5f32ae219ad7a1fd";

function hostileGetter(): object {
  return Object.defineProperty({}, "kind", {
    enumerable: true,
    get() {
      throw new Error("caller code must not run");
    },
  });
}

describe("controller store v2 contracts", () => {
  it("derives the literal key-independent namespace and mapped run identity vectors", () => {
    expect(deriveControllerStoreNamespaceDigestV2(Buffer.alloc(32, 0x5a))).toBe(
      namespaceDigest,
    );
    const identity = {
      namespaceDigest,
      projectId: "project-1",
      taskId: "task-1",
      repositoryId: "repo-1",
      snapshotId: "snapshot-1",
      headBranch: "main",
      runIdentityDigest,
    };
    expect(projectPersistedRunIdentityV2(identity)).toEqual({
      namespaceDigest,
      projectId: "project-1",
      taskId: "task-1",
      repository: "repo-1",
      runId: "snapshot-1",
      branch: "main",
    });
    expect(deriveControllerRunIdentityDigestV2(identity)).toBe(
      runIdentityDigest,
    );
    expect(validateControllerRunIdentityV2(identity)).toBe(true);
  });

  it("keeps schema, runtime validation, examples, and frozen reconstruction aligned", () => {
    const validate = new Ajv2020({ allErrors: true }).compile(schema);
    expect(validate(example), validate.errors?.map(String).join("\n")).toBe(
      true,
    );
    expect(validateControllerStoreStatusV2(example)).toBe(true);
    const parsed = parseControllerStoreStatusV2(example);
    expect(parsed).toEqual(example);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.identity)).toBe(true);
    expect(Object.isFrozen(parsed.runIdentity)).toBe(true);
  });

  it("defines fixed redacted diagnostics and fixed public resource limits", () => {
    expect(CONTROLLER_STORE_DIAGNOSTIC_CODES_V2).toHaveLength(24);
    for (const code of CONTROLLER_STORE_DIAGNOSTIC_CODES_V2) {
      expect(CONTROLLER_STORE_DIAGNOSTICS_V2[code]).toEqual({
        code,
        message: "Controller store request denied.",
      });
    }
    expect(CONTROLLER_STORE_LIMITS_V2).toMatchObject({
      maximumDepth: 16,
      maximumNodes: 2048,
      maximumArrayLength: 256,
      maximumIdentifierBytes: 128,
      maximumCanonicalValueBytes: 1024 * 1024,
      maximumRecordBytes: 4 * 1024 * 1024,
      maximumReceiptBytes: 64 * 1024,
      maximumHistoryRevisions: 100_000,
    });
  });

  it("rejects open, inherited, accessor, symbol, sparse, cyclic, and noncanonical input", () => {
    expect(
      validateControllerStoreStatusV2({ ...example, rootPath: "/secret" }),
    ).toBe(false);
    expect(
      validateControllerStoreStatusV2(Object.create(example) as unknown),
    ).toBe(false);
    expect(validateControllerStoreStatusV2(hostileGetter())).toBe(false);
    expect(
      validateControllerStoreStatusV2(
        Object.assign(structuredClone(example), { [Symbol("hidden")]: true }),
      ),
    ).toBe(false);

    const sparse = structuredClone(example) as Record<string, unknown>;
    sparse.runIdentity = {
      ...(sparse.runIdentity as object),
      extra: new Array(1),
    };
    expect(validateControllerStoreStatusV2(sparse)).toBe(false);

    const cyclic = structuredClone(example) as Record<string, unknown>;
    cyclic.self = cyclic;
    expect(validateControllerStoreStatusV2(cyclic)).toBe(false);

    for (const value of ["bad\0id", "bad\nline", "e\u0301", "\ud800"]) {
      const status = structuredClone(example) as {
        runIdentity: { taskId: string };
      };
      status.runIdentity.taskId = value;
      expect(validateControllerStoreStatusV2(status)).toBe(false);
    }
  });

  it("enforces byte rather than UTF-16 identifier limits at the boundary", () => {
    const status = structuredClone(example) as {
      runIdentity: { taskId: string };
    };
    status.runIdentity.taskId = `a${"é".repeat(63)}`;
    expect(validateControllerStoreStatusV2(status)).toBe(true);
    status.runIdentity.taskId += "é";
    expect(validateControllerStoreStatusV2(status)).toBe(false);
  });

  it("canonicalizes only safely isolated public values", () => {
    expect(canonicalizeControllerStoreValueV2({ b: 1, a: [true, null] })).toBe(
      '{"a":[true,null],"b":1}',
    );
    expect(() => canonicalizeControllerStoreValueV2(hostileGetter())).toThrow(
      TypeError,
    );
    expect(() => canonicalizeControllerStoreValueV2(new Array(2))).toThrow(
      TypeError,
    );
  });
});

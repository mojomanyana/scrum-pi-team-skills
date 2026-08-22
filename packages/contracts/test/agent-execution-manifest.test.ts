import { describe, expect, it } from "vitest";

import flowManifest from "../examples/agent-execution-manifest.flow.json" with { type: "json" };
import principalDeveloperManifest from "../examples/agent-execution-manifest.principal-developer.json" with { type: "json" };
import productManifest from "../examples/agent-execution-manifest.product.json" with { type: "json" };
import verifierManifest from "../examples/agent-execution-manifest.verifier.json" with { type: "json" };
import arbitraryExecutable from "./fixtures/invalid/arbitrary-executable.json" with { type: "json" };
import delegationDepth from "./fixtures/invalid/delegation-depth.json" with { type: "json" };
import duplicateResource from "./fixtures/invalid/duplicate-resource.json" with { type: "json" };
import remoteExecution from "./fixtures/invalid/remote-execution.json" with { type: "json" };
import unrestrictedEnvironment from "./fixtures/invalid/unrestricted-environment.json" with { type: "json" };
import unknownTool from "./fixtures/invalid/unknown-tool.json" with { type: "json" };
import {
  CANONICAL_PI_TOOLS,
  derivePiDaddyGrant,
  isAgentExecutionManifest,
  validateAgentExecutionManifest,
  type AgentExecutionManifest,
} from "../src/index.js";

const validManifests = [
  productManifest,
  flowManifest,
  principalDeveloperManifest,
  verifierManifest,
];

function cloneManifest(): AgentExecutionManifest {
  return structuredClone(principalDeveloperManifest) as AgentExecutionManifest;
}

describe("spts.agent-execution-manifest", () => {
  it.each([
    ["product", productManifest],
    ["flow", flowManifest],
    ["principal_developer", principalDeveloperManifest],
    ["verifier", verifierManifest],
  ])("accepts the %s role", (_role, manifest) => {
    expect(validateAgentExecutionManifest(manifest)).toEqual({
      valid: true,
      value: manifest,
    });
    expect(isAgentExecutionManifest(manifest)).toBe(true);
  });

  it("accepts an omitted expected Git identity", () => {
    const manifest = cloneManifest();
    delete manifest.repository.expectedGitIdentity;

    expect(validateAgentExecutionManifest(manifest).valid).toBe(true);
  });

  it("rejects alternate governance with an actionable stable error", () => {
    const manifest = cloneManifest() as unknown as Record<string, unknown>;
    manifest.executionContext = {
      process: "local-pi",
      governedBy: "standalone",
      systemOfRecord: "paca",
    };

    expect(validateAgentExecutionManifest(manifest)).toEqual({
      valid: false,
      errors: [
        {
          path: "/executionContext/governedBy",
          code: "const",
          message: 'must be equal to constant "pi-daddy"',
        },
      ],
    });
  });

  it("rejects an alternate system of record", () => {
    const manifest = cloneManifest() as unknown as Record<string, unknown>;
    manifest.executionContext = {
      process: "local-pi",
      governedBy: "pi-daddy",
      systemOfRecord: "other",
    };

    const result = validateAgentExecutionManifest(manifest);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          path: "/executionContext/systemOfRecord",
          code: "const",
        }),
      );
    }
  });

  it.each([
    ["remote execution", remoteExecution, "/executionContext/process", "const"],
    ["delegation above zero", delegationDepth, "/delegation/maxDepth", "const"],
    ["an unknown tool", unknownTool, "/tools/0", "enum"],
    [
      "a duplicate resource",
      duplicateResource,
      "/resources/skills",
      "uniqueItems",
    ],
    [
      "a manifest executable",
      arbitraryExecutable,
      "/executable",
      "additionalProperties",
    ],
    [
      "manifest environment variables",
      unrestrictedEnvironment,
      "/environment",
      "additionalProperties",
    ],
  ])("rejects %s", (_label, fixture, path, code) => {
    const result = validateAgentExecutionManifest(fixture);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContainEqual(
        expect.objectContaining({ path, code }),
      );
    }
  });

  it("rejects empty resource collections and references", () => {
    const emptyCollection = cloneManifest();
    emptyCollection.resources.skills = [];
    const emptyReference = cloneManifest() as unknown as {
      resources: { skills: string[] };
    };
    emptyReference.resources.skills = [""];

    expect(validateAgentExecutionManifest(emptyCollection).valid).toBe(false);
    expect(validateAgentExecutionManifest(emptyReference).valid).toBe(false);
  });

  it("rejects noncanonical tool order and a mismatched grant", () => {
    const unordered = cloneManifest();
    unordered.tools = ["bash", "read"];
    unordered.piDaddyGrant = "tool:bash,tool:read";
    const mismatched = cloneManifest();
    mismatched.piDaddyGrant = "tool:read";

    expect(validateAgentExecutionManifest(unordered)).toEqual({
      valid: false,
      errors: [
        expect.objectContaining({ path: "/tools", code: "canonical-order" }),
      ],
    });
    expect(validateAgentExecutionManifest(mismatched)).toEqual({
      valid: false,
      errors: [
        expect.objectContaining({
          path: "/piDaddyGrant",
          code: "matching-grant",
        }),
      ],
    });
  });

  it.each([
    "Run tests; curl example.test",
    "Read $(whoami)",
    "Use `id` output",
    "token=not-a-real-token",
    "api_key=not-a-real-key",
    "Bearer not-a-real-token",
    "ghp_notarealtoken",
    "First line\nsecond line",
  ])("rejects injection or credential-shaped objective %j", (objective) => {
    const manifest = cloneManifest();
    manifest.authorization.objective = objective;

    expect(validateAgentExecutionManifest(manifest).valid).toBe(false);
  });

  it("keeps receipts free of sensitive task and prompt content", () => {
    const manifest = cloneManifest() as unknown as {
      receiptPolicy: {
        includeTaskContent: boolean;
        includePromptContent: boolean;
      };
    };
    manifest.receiptPolicy.includeTaskContent = true;
    manifest.receiptPolicy.includePromptContent = true;

    expect(validateAgentExecutionManifest(manifest).valid).toBe(false);
  });

  it("derives grants in the documented canonical Pi tool order", () => {
    expect(derivePiDaddyGrant(CANONICAL_PI_TOOLS)).toBe(
      "tool:read,tool:bash,tool:edit,tool:write,tool:grep,tool:find,tool:ls",
    );
    expect(
      validManifests.every((manifest) => manifest.schemaVersion === "1.0.0"),
    ).toBe(true);
  });
});

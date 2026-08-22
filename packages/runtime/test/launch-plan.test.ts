import { describe, expect, it, vi } from "vitest";

vi.mock(
  "@scrum-pi-team-skills/contracts",
  async () => import("../../contracts/src/index.js"),
);

import flowManifestJson from "../../contracts/examples/agent-execution-manifest.flow.json" with { type: "json" };
import principalDeveloperManifestJson from "../../contracts/examples/agent-execution-manifest.principal-developer.json" with { type: "json" };
import productManifestJson from "../../contracts/examples/agent-execution-manifest.product.json" with { type: "json" };
import verifierManifestJson from "../../contracts/examples/agent-execution-manifest.verifier.json" with { type: "json" };
import type { AgentExecutionManifest } from "../../contracts/src/index.js";
import {
  createPiLaunchPlan,
  LaunchPlanInputError,
  type LocalPiResources,
} from "../src/index.js";

const principalDeveloperManifest =
  principalDeveloperManifestJson as AgentExecutionManifest;

const localResources: LocalPiResources = {
  executable: "/home/paca/.local/bin/pi",
  piDaddyExtension: "/home/paca/.pi/agent/extensions/pi-daddy-grants.ts",
  governanceLedgerPath: "/home/paca/.local/state/pi-daddy/exec-spts7-001.jsonl",
  skillRegistry: {
    "skill:build": "/home/paca/.pi/agent/skills/build/SKILL.md",
    "skill:review": "/home/paca/.pi/agent/skills/review/SKILL.md",
    "skill:unused": "/home/paca/.pi/agent/skills/unused/SKILL.md",
  },
  promptTemplateRegistry: {
    "prompt:principal-feature":
      "/home/paca/.pi/agent/prompts/principal-feature.md",
    "prompt:unused": "/home/paca/.pi/agent/prompts/unused.md",
  },
};

function cloneManifest(): AgentExecutionManifest {
  return structuredClone(principalDeveloperManifest);
}

describe("createPiLaunchPlan", () => {
  it("builds an explicit governed argv plan without a shell command", () => {
    expect(
      createPiLaunchPlan(principalDeveloperManifest, localResources),
    ).toEqual({
      executable: "/home/paca/.local/bin/pi",
      arguments: [
        "--no-extensions",
        "--extension",
        "/home/paca/.pi/agent/extensions/pi-daddy-grants.ts",
        "--no-skills",
        "--skill",
        "/home/paca/.pi/agent/skills/build/SKILL.md",
        "--skill",
        "/home/paca/.pi/agent/skills/review/SKILL.md",
        "--no-prompt-templates",
        "--prompt-template",
        "/home/paca/.pi/agent/prompts/principal-feature.md",
        "--tools",
        "read,bash,edit,write",
      ],
      workingDirectory: "/home/paca/work/scrum-pi-team-skills",
      environment: {
        PI_GRANTS_GRANT: "tool:read,tool:bash,tool:edit,tool:write",
        PI_GRANTS_MAX_DEPTH: "0",
        PI_GRANTS_LEDGER:
          "/home/paca/.local/state/pi-daddy/exec-spts7-001.jsonl",
      },
      redactedOperatorPreview: {
        executable: "<pi-executable>",
        arguments: [
          "--no-extensions",
          "--extension",
          "<pi-daddy-grants>",
          "--no-skills",
          "--skill",
          "<skill:build>",
          "--skill",
          "<skill:review>",
          "--no-prompt-templates",
          "--prompt-template",
          "<prompt:principal-feature>",
          "--tools",
          "read,bash,edit,write",
        ],
        workingDirectory: "<repository-root>",
        environment: {
          PI_GRANTS_GRANT: "tool:read,tool:bash,tool:edit,tool:write",
          PI_GRANTS_MAX_DEPTH: "0",
          PI_GRANTS_LEDGER: "<governance-ledger>",
        },
      },
      correlation: {
        executionId: "exec-spts7-001",
        pacaProjectId: "SCRUM-PI",
        pacaTaskId: "SPTS-7",
      },
    });
  });

  it.each([
    ["product", productManifestJson],
    ["flow", flowManifestJson],
    ["principal_developer", principalDeveloperManifestJson],
    ["verifier", verifierManifestJson],
  ])("plans the %s role from the same governed contract", (_role, manifest) => {
    const plan = createPiLaunchPlan(
      manifest as AgentExecutionManifest,
      localResources,
    );

    expect(plan.correlation.executionId).toBe(manifest.executionId);
  });

  it("is deterministic, preserves resource order, and does not mutate inputs", () => {
    const manifest = cloneManifest();
    manifest.resources.skills = ["skill:review", "skill:build"];
    const manifestBefore = structuredClone(manifest);
    const resourcesBefore = structuredClone(localResources);

    const first = createPiLaunchPlan(manifest, localResources);
    const second = createPiLaunchPlan(manifest, localResources);

    expect(first).toEqual(second);
    expect(first.arguments).toContain("read,bash,edit,write");
    expect(first.arguments.slice(4, 9)).toEqual([
      "--skill",
      "/home/paca/.pi/agent/skills/review/SKILL.md",
      "--skill",
      "/home/paca/.pi/agent/skills/build/SKILL.md",
      "--no-prompt-templates",
    ]);
    expect(first.arguments).not.toContain(
      "/home/paca/.pi/agent/skills/unused/SKILL.md",
    );
    expect(manifest).toEqual(manifestBefore);
    expect(localResources).toEqual(resourcesBefore);
    expect("command" in first).toBe(false);
    expect(Array.isArray(first.arguments)).toBe(true);
  });

  it("fails when an approved logical resource has no local registry entry", () => {
    expect(() =>
      createPiLaunchPlan(principalDeveloperManifest, {
        ...localResources,
        skillRegistry: {},
      }),
    ).toThrow(
      new LaunchPlanInputError(
        'skill registry has no approved path for "skill:build"',
      ),
    );
  });

  it.each([
    ["null object", null, "local resources must be an object"],
    [
      "missing skill registry",
      {
        executable: localResources.executable,
        piDaddyExtension: localResources.piDaddyExtension,
        governanceLedgerPath: localResources.governanceLedgerPath,
        promptTemplateRegistry: localResources.promptTemplateRegistry,
      },
      "skill registry must be an object",
    ],
    [
      "null skill registry",
      { ...localResources, skillRegistry: null },
      "skill registry must be an object",
    ],
    [
      "missing prompt-template registry",
      {
        executable: localResources.executable,
        piDaddyExtension: localResources.piDaddyExtension,
        governanceLedgerPath: localResources.governanceLedgerPath,
        skillRegistry: localResources.skillRegistry,
      },
      "prompt template registry must be an object",
    ],
    [
      "null prompt-template registry",
      { ...localResources, promptTemplateRegistry: null },
      "prompt template registry must be an object",
    ],
    [
      "malformed nested registry value",
      {
        ...localResources,
        skillRegistry: {
          ...localResources.skillRegistry,
          "skill:unused": null,
        },
      },
      "skill registry paths must be strings",
    ],
    [
      "malformed executable value",
      { ...localResources, executable: null },
      "Pi executable must be a string",
    ],
  ])(
    "returns a stable LaunchPlanInputError for local-resource %s",
    (_label, resources, message) => {
      expect(() =>
        createPiLaunchPlan(
          principalDeveloperManifest,
          resources as unknown as LocalPiResources,
        ),
      ).toThrow(new LaunchPlanInputError(message as string));
    },
  );

  it("validates unused nested local-resource paths", () => {
    expect(() =>
      createPiLaunchPlan(principalDeveloperManifest, {
        ...localResources,
        skillRegistry: {
          ...localResources.skillRegistry,
          "skill:unused": "/home/paca/skills/../private/SKILL.md",
        },
      }),
    ).toThrow(LaunchPlanInputError);
  });

  it("accepts normalized absolute WSL local-resource paths", () => {
    expect(() =>
      createPiLaunchPlan(principalDeveloperManifest, localResources),
    ).not.toThrow();
  });

  it.each([
    ["executable", "/home/paca/bin/pi;touch-bad"],
    ["piDaddyExtension", "/home/paca/ext/$(id).ts"],
    ["governanceLedgerPath", "relative/ledger.jsonl"],
    ["executable", "/home/paca/bin/../evil"],
    ["piDaddyExtension", "/home/paca/ext/./pi-daddy.ts"],
    ["governanceLedgerPath", "/home/paca/state/../private.jsonl"],
  ] as const)(
    "rejects injection or traversal-shaped local %s",
    (field, value) => {
      expect(() =>
        createPiLaunchPlan(principalDeveloperManifest, {
          ...localResources,
          [field]: value,
        }),
      ).toThrow(LaunchPlanInputError);
    },
  );

  it.each([
    ["skill", { "skill:build": "/home/paca/skills/../evil.md" }],
    [
      "prompt template",
      {
        "prompt:principal-feature": "/home/paca/prompts/../evil.md",
      },
    ],
  ] as const)("rejects traversal in a resolved %s path", (kind, registry) => {
    expect(() =>
      createPiLaunchPlan(principalDeveloperManifest, {
        ...localResources,
        ...(kind === "skill"
          ? {
              skillRegistry: {
                ...localResources.skillRegistry,
                ...registry,
              },
            }
          : {
              promptTemplateRegistry: {
                ...localResources.promptTemplateRegistry,
                ...registry,
              },
            }),
      }),
    ).toThrow(LaunchPlanInputError);
  });

  it("rejects credential-shaped execution paths with redacted diagnostics", () => {
    const suspected = "GHP_SUSPECTEDVALUEDONOTECHO";
    const cases: LocalPiResources[] = [
      {
        ...localResources,
        executable: `/home/paca/bin/${suspected}`,
      },
      {
        ...localResources,
        skillRegistry: {
          ...localResources.skillRegistry,
          "skill:build": `/home/paca/skills/${suspected}/SKILL.md`,
        },
      },
    ];

    for (const resources of cases) {
      try {
        createPiLaunchPlan(principalDeveloperManifest, resources);
        throw new Error("expected LaunchPlanInputError");
      } catch (error) {
        expect(error).toBeInstanceOf(LaunchPlanInputError);
        expect(String(error)).not.toContain("SUSPECTED");
      }
    }
  });

  it("refuses an unvalidated manifest", () => {
    const manifest = cloneManifest() as unknown as AgentExecutionManifest & {
      environment: Record<string, string>;
    };
    manifest.environment = { ANYTHING: "allowed" };

    expect(() => createPiLaunchPlan(manifest, localResources)).toThrow(
      /manifest is invalid/,
    );
  });
});

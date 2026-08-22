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
        "--no-context-files",
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
          "--no-context-files",
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

  it("disables implicit context discovery without adding another prompt source", () => {
    const plan = createPiLaunchPlan(principalDeveloperManifest, localResources);

    expect(
      plan.arguments.filter((value) => value === "--no-context-files"),
    ).toHaveLength(1);
    expect(plan.redactedOperatorPreview.arguments).toContain(
      "--no-context-files",
    );
    expect(
      plan.arguments.slice(
        plan.arguments.indexOf("--prompt-template"),
        plan.arguments.indexOf("--tools") + 1,
      ),
    ).toEqual([
      "--prompt-template",
      "/home/paca/.pi/agent/prompts/principal-feature.md",
      "--no-context-files",
      "--tools",
    ]);
    expect(plan.arguments).not.toContain("--context-file");
    expect(plan.arguments).not.toContain("--system-prompt");
    expect(plan.arguments).not.toContain("--append-system-prompt");
    expect(
      plan.arguments.some((value) => /(?:AGENTS|CLAUDE)\.md$/i.test(value)),
    ).toBe(false);
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

  it("preserves spaces in normalized WSL paths across all launch inputs", () => {
    const manifest = cloneManifest();
    manifest.repository.root = "/home/paca/My Workspace/project";
    const spacedResources: LocalPiResources = {
      executable: "/home/paca/My Tools/pi",
      piDaddyExtension: "/home/paca/My Extensions/pi daddy.ts",
      governanceLedgerPath: "/home/paca/Local State/pi daddy/ledger.jsonl",
      skillRegistry: {
        "skill:build": "/home/paca/My Skills/build skill/SKILL.md",
        "skill:review": "/home/paca/My Skills/review skill/SKILL.md",
      },
      promptTemplateRegistry: {
        "prompt:principal-feature":
          "/home/paca/My Prompts/principal feature.md",
      },
    };

    const plan = createPiLaunchPlan(manifest, spacedResources);

    expect(plan.executable).toBe(spacedResources.executable);
    expect(plan.workingDirectory).toBe(manifest.repository.root);
    expect(plan.environment.PI_GRANTS_LEDGER).toBe(
      spacedResources.governanceLedgerPath,
    );
    expect(plan.arguments).toContain(spacedResources.piDaddyExtension);
    expect(plan.arguments).toContain(
      spacedResources.skillRegistry["skill:build"],
    );
    expect(plan.arguments).toContain(
      spacedResources.promptTemplateRegistry["prompt:principal-feature"],
    );
  });

  it.each([
    ["workspace duplicate separator", { manifestRoot: "/home/paca//work" }],
    [
      "executable trailing separator",
      { resources: { executable: "/home/paca/My Tools/pi/" } },
    ],
    [
      "extension control character",
      {
        resources: {
          piDaddyExtension: "/home/paca/My Extensions/pi\u0001daddy.ts",
        },
      },
    ],
    [
      "ledger execution metacharacter",
      {
        resources: {
          governanceLedgerPath: "/home/paca/Local State/ledger|touch-bad",
        },
      },
    ],
    [
      "skill backslash separator",
      {
        resources: {
          skillRegistry: {
            ...localResources.skillRegistry,
            "skill:build": "/home/paca/My Skills\\build/SKILL.md",
          },
        },
      },
    ],
    [
      "prompt duplicate separator",
      {
        resources: {
          promptTemplateRegistry: {
            ...localResources.promptTemplateRegistry,
            "prompt:principal-feature":
              "/home/paca/My Prompts//principal feature.md",
          },
        },
      },
    ],
  ] satisfies ReadonlyArray<
    readonly [
      string,
      {
        manifestRoot?: string;
        resources?: Partial<LocalPiResources>;
      },
    ]
  >)(
    "rejects non-normalized or unsafe WSL path form in %s",
    (_label, input) => {
      const manifest = cloneManifest();
      if ("manifestRoot" in input) {
        manifest.repository.root = input.manifestRoot;
      }
      const resourceOverrides = "resources" in input ? input.resources : {};

      expect(() =>
        createPiLaunchPlan(manifest, {
          ...localResources,
          ...resourceOverrides,
        }),
      ).toThrow(LaunchPlanInputError);
    },
  );

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

  it.each([
    [
      "credential-shaped objective",
      (manifest: AgentExecutionManifest) => {
        const marker = ["PRIVATE", "INPUT"].join("-");
        manifest.authorization.objective = `token ${marker}`;
      },
    ],
    [
      "noncanonical tool ordering",
      (manifest: AgentExecutionManifest) => {
        manifest.tools = ["bash", "read"];
        manifest.piDaddyGrant = "tool:bash,tool:read";
      },
    ],
    [
      "mismatched pi-daddy grant",
      (manifest: AgentExecutionManifest) => {
        manifest.piDaddyGrant = "tool:read";
      },
    ],
  ] satisfies ReadonlyArray<
    readonly [string, (manifest: AgentExecutionManifest) => void]
  >)("rejects structural-only validation for %s", (_label, mutate) => {
    const manifest = cloneManifest();
    mutate(manifest);

    expect(() => createPiLaunchPlan(manifest, localResources)).toThrow(
      LaunchPlanInputError,
    );
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

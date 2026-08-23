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
  createTrustedLaunchPolicy,
  LaunchPlanInputError,
  type TrustedLaunchPolicy,
  type TrustedLaunchPolicyDefinition,
} from "../src/index.js";

const principalDeveloperManifest =
  principalDeveloperManifestJson as AgentExecutionManifest;

const trustedPolicyDefinition: TrustedLaunchPolicyDefinition = {
  piExecutable: "/home/paca/.local/bin/pi",
  piDaddyExtension: "/home/paca/.pi/agent/extensions/pi-daddy-grants.ts",
  governanceLedgerPath: "/home/paca/.local/state/pi-daddy/exec-spts7-001.jsonl",
  skillResources: {
    "skill:build": "/home/paca/.pi/agent/skills/build/SKILL.md",
    "skill:review": "/home/paca/.pi/agent/skills/review/SKILL.md",
    "skill:unused": "/home/paca/.pi/agent/skills/unused/SKILL.md",
  },
  promptTemplateResources: {
    "prompt:principal-feature":
      "/home/paca/.pi/agent/prompts/principal-feature.md",
    "prompt:unused": "/home/paca/.pi/agent/prompts/unused.md",
  },
  systemPrompt: "/home/paca/.pi/agent/prompts/governed-system.md",
  appendSystemPrompt: "/home/paca/.pi/agent/prompts/governed-append-system.md",
};

const trustedPolicy = createTrustedLaunchPolicy(trustedPolicyDefinition);

function cloneManifest(): AgentExecutionManifest {
  return structuredClone(principalDeveloperManifest);
}

function createPolicy(
  overrides: Partial<TrustedLaunchPolicyDefinition> = {},
): TrustedLaunchPolicy {
  return createTrustedLaunchPolicy({
    ...trustedPolicyDefinition,
    ...overrides,
  });
}

interface DiscoveredPiPromptSources {
  globalSystemPrompt: string;
  projectSystemPrompt: string;
  globalAppendSystemPrompt: string;
  projectAppendSystemPrompt: string;
  contextFiles: string[];
}

function modelPi0842PromptDiscovery(
  arguments_: readonly string[],
  discovered: DiscoveredPiPromptSources,
): {
  systemPrompt: string;
  appendSystemPrompts: string[];
  contextFiles: string[];
} {
  const systemPromptIndex = arguments_.indexOf("--system-prompt");
  const explicitAppendSystemPrompts = arguments_.flatMap((argument, index) =>
    argument === "--append-system-prompt" ? [arguments_[index + 1] ?? ""] : [],
  );

  return {
    systemPrompt:
      systemPromptIndex >= 0
        ? (arguments_[systemPromptIndex + 1] ?? "")
        : discovered.projectSystemPrompt || discovered.globalSystemPrompt,
    appendSystemPrompts:
      explicitAppendSystemPrompts.length > 0
        ? explicitAppendSystemPrompts
        : [
            discovered.projectAppendSystemPrompt ||
              discovered.globalAppendSystemPrompt,
          ].filter((value) => value.length > 0),
    contextFiles: arguments_.includes("--no-context-files")
      ? []
      : discovered.contextFiles,
  };
}

describe("TrustedLaunchPolicy", () => {
  it("validates, copies, brands, and deeply freezes operator authority", () => {
    const mutableDefinition = {
      ...trustedPolicyDefinition,
      skillResources: { ...trustedPolicyDefinition.skillResources },
      promptTemplateResources: {
        ...trustedPolicyDefinition.promptTemplateResources,
      },
    };
    const policy = createTrustedLaunchPolicy(mutableDefinition);

    mutableDefinition.skillResources["skill:build"] = "/tmp/rebound-skill";

    expect(policy.skillResources["skill:build"]).toBe(
      trustedPolicyDefinition.skillResources["skill:build"],
    );
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.skillResources)).toBe(true);
    expect(Object.isFrozen(policy.promptTemplateResources)).toBe(true);
  });

  it.each([
    ["null policy", null],
    [
      "missing executable",
      { ...trustedPolicyDefinition, piExecutable: undefined },
    ],
    [
      "malformed nested registry",
      {
        ...trustedPolicyDefinition,
        skillResources: {
          ...trustedPolicyDefinition.skillResources,
          "skill:unused": null,
        },
      },
    ],
  ])("rejects malformed operator policy input: %s", (_label, definition) => {
    expect(() => createTrustedLaunchPolicy(definition)).toThrow(
      LaunchPlanInputError,
    );
  });

  it.each([
    ["skill", "skillResources", "skill:build", "skill:review"],
    [
      "prompt template",
      "promptTemplateResources",
      "prompt:principal-feature",
      "prompt:unused",
    ],
  ] as const)(
    "rejects duplicate physical %s resources before planning",
    (_label, registryName, firstReference, secondReference) => {
      const registry = {
        ...trustedPolicyDefinition[registryName],
        [secondReference]:
          trustedPolicyDefinition[registryName][firstReference],
      };

      expect(() => createPolicy({ [registryName]: registry })).toThrow(
        new LaunchPlanInputError(
          `${_label} resources must not bind multiple logical references to one physical path`,
        ),
      );
    },
  );

  it("redacts credential-shaped policy paths from errors", () => {
    const suspected = "GHP_SUSPECTEDVALUEDONOTECHO";

    try {
      createPolicy({ piExecutable: `/home/paca/bin/${suspected}` });
      throw new Error("expected LaunchPlanInputError");
    } catch (error) {
      expect(error).toBeInstanceOf(LaunchPlanInputError);
      expect(String(error)).not.toContain("SUSPECTED");
    }
  });
});

describe("createPiLaunchPlan", () => {
  it("builds an explicit governed argv plan from trusted operator authority", () => {
    expect(
      createPiLaunchPlan(principalDeveloperManifest, trustedPolicy),
    ).toEqual({
      executable: trustedPolicyDefinition.piExecutable,
      arguments: [
        "--no-extensions",
        "--extension",
        trustedPolicyDefinition.piDaddyExtension,
        "--no-skills",
        "--skill",
        trustedPolicyDefinition.skillResources["skill:build"],
        "--skill",
        trustedPolicyDefinition.skillResources["skill:review"],
        "--no-prompt-templates",
        "--prompt-template",
        trustedPolicyDefinition.promptTemplateResources[
          "prompt:principal-feature"
        ],
        "--no-context-files",
        "--system-prompt",
        trustedPolicyDefinition.systemPrompt,
        "--append-system-prompt",
        trustedPolicyDefinition.appendSystemPrompt,
        "--tools",
        "read,bash,edit,write",
      ],
      workingDirectory: "/home/paca/work/scrum-pi-team-skills",
      environment: {
        PI_GRANTS_GRANT: "tool:read,tool:bash,tool:edit,tool:write",
        PI_GRANTS_MAX_DEPTH: "0",
        PI_GRANTS_LEDGER: trustedPolicyDefinition.governanceLedgerPath,
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
          "--system-prompt",
          "<system-prompt>",
          "--append-system-prompt",
          "<append-system-prompt>",
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

  it("models Pi 0.84.2 precedence and suppresses every implicit prompt source", () => {
    const plan = createPiLaunchPlan(principalDeveloperManifest, trustedPolicy);
    const resolved = modelPi0842PromptDiscovery(plan.arguments, {
      globalSystemPrompt: "/undeclared/global/SYSTEM.md",
      projectSystemPrompt: "/undeclared/project/.pi/SYSTEM.md",
      globalAppendSystemPrompt: "/undeclared/global/APPEND_SYSTEM.md",
      projectAppendSystemPrompt: "/undeclared/project/.pi/APPEND_SYSTEM.md",
      contextFiles: [
        "/undeclared/global/AGENTS.md",
        "/undeclared/ancestor/CLAUDE.md",
        "/undeclared/project/AGENTS.md",
      ],
    });

    expect(resolved).toEqual({
      systemPrompt: trustedPolicyDefinition.systemPrompt,
      appendSystemPrompts: [trustedPolicyDefinition.appendSystemPrompt],
      contextFiles: [],
    });
    expect(
      plan.arguments.filter((value) => value === "--system-prompt"),
    ).toHaveLength(1);
    expect(
      plan.arguments.filter((value) => value === "--append-system-prompt"),
    ).toHaveLength(1);
    expect(
      plan.arguments.filter((value) => value === "--no-context-files"),
    ).toHaveLength(1);
  });

  it.each([
    ["product", productManifestJson],
    ["flow", flowManifestJson],
    ["principal_developer", principalDeveloperManifestJson],
    ["verifier", verifierManifestJson],
  ])("plans the %s role from the same governed contract", (_role, manifest) => {
    const plan = createPiLaunchPlan(
      manifest as AgentExecutionManifest,
      trustedPolicy,
    );

    expect(plan.correlation.executionId).toBe(manifest.executionId);
  });

  it("is deterministic, preserves unique resource order, and does not mutate inputs", () => {
    const manifest = cloneManifest();
    manifest.resources.skills = ["skill:review", "skill:build"];
    const manifestBefore = structuredClone(manifest);

    const first = createPiLaunchPlan(manifest, trustedPolicy);
    const second = createPiLaunchPlan(manifest, trustedPolicy);

    expect(first).toEqual(second);
    expect(first.arguments.slice(4, 9)).toEqual([
      "--skill",
      trustedPolicyDefinition.skillResources["skill:review"],
      "--skill",
      trustedPolicyDefinition.skillResources["skill:build"],
      "--no-prompt-templates",
    ]);
    expect(first.arguments).not.toContain(
      trustedPolicyDefinition.skillResources["skill:unused"],
    );
    expect(manifest).toEqual(manifestBefore);
    expect("command" in first).toBe(false);
    expect(Array.isArray(first.arguments)).toBe(true);
  });

  it("rejects an unbound logical resource", () => {
    expect(() =>
      createPiLaunchPlan(
        principalDeveloperManifest,
        createPolicy({ skillResources: {} }),
      ),
    ).toThrow(
      new LaunchPlanInputError("skill policy has no trusted physical resource"),
    );
  });

  it.each([
    ["Pi executable", { piExecutable: "/tmp/arbitrary-agent" }],
    [
      "pi-daddy extension",
      { piDaddyExtension: "/tmp/arbitrary-governance.ts" },
    ],
  ])(
    "rejects caller-relabelled %s paths not produced by the policy factory",
    (_label, override) => {
      const relabelled = {
        ...trustedPolicy,
        ...override,
        trusted: true,
      } as unknown as TrustedLaunchPolicy;

      expect(() =>
        createPiLaunchPlan(principalDeveloperManifest, relabelled),
      ).toThrow(
        new LaunchPlanInputError(
          "trusted launch policy must be created by createTrustedLaunchPolicy",
        ),
      );
    },
  );

  it("preserves spaces in every normalized trusted WSL path", () => {
    const manifest = cloneManifest();
    manifest.repository.root = "/home/paca/My Workspace/project";
    const spacedPolicy = createTrustedLaunchPolicy({
      piExecutable: "/home/paca/My Tools/pi",
      piDaddyExtension: "/home/paca/My Extensions/pi daddy.ts",
      governanceLedgerPath: "/home/paca/Local State/pi daddy/ledger.jsonl",
      skillResources: {
        "skill:build": "/home/paca/My Skills/build skill/SKILL.md",
        "skill:review": "/home/paca/My Skills/review skill/SKILL.md",
      },
      promptTemplateResources: {
        "prompt:principal-feature":
          "/home/paca/My Prompts/principal feature.md",
      },
      systemPrompt: "/home/paca/My Prompts/governed SYSTEM.md",
      appendSystemPrompt: "/home/paca/My Prompts/governed APPEND SYSTEM.md",
    });

    const plan = createPiLaunchPlan(manifest, spacedPolicy);

    expect(plan.executable).toBe(spacedPolicy.piExecutable);
    expect(plan.workingDirectory).toBe(manifest.repository.root);
    expect(plan.environment.PI_GRANTS_LEDGER).toBe(
      spacedPolicy.governanceLedgerPath,
    );
    expect(plan.arguments).toContain(spacedPolicy.piDaddyExtension);
    expect(plan.arguments).toContain(spacedPolicy.systemPrompt);
    expect(plan.arguments).toContain(spacedPolicy.appendSystemPrompt);
  });

  it.each([
    ["relative executable", { piExecutable: "relative/pi" }],
    ["executable traversal", { piExecutable: "/home/paca/bin/../pi" }],
    ["extension traversal", { piDaddyExtension: "/home/paca/ext/./pi.ts" }],
    [
      "ledger metacharacter",
      { governanceLedgerPath: "/home/paca/state/ledger|touch-bad" },
    ],
    [
      "system prompt control",
      { systemPrompt: "/home/paca/prompts/\u0001SYSTEM.md" },
    ],
    [
      "append prompt duplicate separator",
      { appendSystemPrompt: "/home/paca/prompts//APPEND_SYSTEM.md" },
    ],
  ])("rejects unsafe trusted path input: %s", (_label, override) => {
    expect(() => createPolicy(override)).toThrow(LaunchPlanInputError);
  });

  it.each([
    [
      "credential-shaped execution ID",
      (manifest: AgentExecutionManifest) => {
        manifest.executionId = "token:SENSITIVE_CORRELATION";
      },
    ],
    [
      "credential-shaped Paca project ID",
      (manifest: AgentExecutionManifest) => {
        manifest.paca.projectId = "token:SENSITIVE_CORRELATION";
      },
    ],
    [
      "credential-shaped Paca task ID",
      (manifest: AgentExecutionManifest) => {
        manifest.paca.taskId = "token:SENSITIVE_CORRELATION";
      },
    ],
  ] satisfies ReadonlyArray<
    readonly [string, (manifest: AgentExecutionManifest) => void]
  >)(
    "rejects %s before producing correlation or preview data",
    (_label, mutate) => {
      const manifest = cloneManifest();
      mutate(manifest);

      try {
        createPiLaunchPlan(manifest, trustedPolicy);
        throw new Error("expected LaunchPlanInputError");
      } catch (error) {
        expect(error).toBeInstanceOf(LaunchPlanInputError);
        expect(String(error)).not.toContain("SENSITIVE_CORRELATION");
      }
    },
  );

  it.each([
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
    [
      "structurally undeclared input",
      (manifest: AgentExecutionManifest) => {
        (manifest as unknown as Record<string, unknown>)["environment"] = {
          ANYTHING: "allowed",
        };
      },
    ],
  ] satisfies ReadonlyArray<
    readonly [string, (manifest: AgentExecutionManifest) => void]
  >)(
    "revalidates the authoritative composite boundary for %s",
    (_label, mutate) => {
      const manifest = cloneManifest();
      mutate(manifest);

      expect(() => createPiLaunchPlan(manifest, trustedPolicy)).toThrow(
        LaunchPlanInputError,
      );
    },
  );
});

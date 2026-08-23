import { describe, expect, it, vi } from "vitest";

vi.mock(
  "@scrum-pi-team-skills/contracts",
  async () => import("../../contracts/src/index.js"),
);

import flowManifestJson from "../../contracts/examples/agent-execution-manifest.flow.json" with { type: "json" };
import principalDeveloperManifestJson from "../../contracts/examples/agent-execution-manifest.principal-developer.json" with { type: "json" };
import productManifestJson from "../../contracts/examples/agent-execution-manifest.product.json" with { type: "json" };
import verifierManifestJson from "../../contracts/examples/agent-execution-manifest.verifier.json" with { type: "json" };
import {
  CANONICAL_PI_TOOLS,
  derivePiDaddyGrant,
  type AgentExecutionManifest,
} from "../../contracts/src/index.js";
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
const canonicalGrant =
  "tool:read,tool:bash,tool:edit,tool:write,tool:grep,tool:find,tool:ls";
const canonicalToolMutationAttempts = [
  ["splice", () => (CANONICAL_PI_TOOLS as unknown as string[]).splice(0, 2)],
  ["reverse", () => (CANONICAL_PI_TOOLS as unknown as string[]).reverse()],
  ["push", () => (CANONICAL_PI_TOOLS as unknown as string[]).push("read")],
  [
    "index assignment",
    () => {
      (CANONICAL_PI_TOOLS as unknown as { 0: string })[0] = "bash";
    },
  ],
  [
    "deletion",
    () => {
      delete (CANONICAL_PI_TOOLS as unknown as { 0?: string })[0];
    },
  ],
  [
    "prototype manipulation",
    () => Object.setPrototypeOf(CANONICAL_PI_TOOLS, []),
  ],
  [
    "mutation through a TypeScript cast",
    () =>
      Object.assign(CANONICAL_PI_TOOLS as unknown as string[], { 0: "bash" }),
  ],
] as const;

const credentialLikePayload = "abcdefghijklmnopqrstuvwxyz0123456789";
const providerTokenCases = [
  ["OpenAI project", `sk-proj-${credentialLikePayload}`],
  ["Anthropic API03", `sk-ant-api03-${credentialLikePayload}`],
  ["Anthropic", `sk-ant-${credentialLikePayload}`],
  ["OpenAI service account", `sk-svcacct-${credentialLikePayload}`],
  ["legacy OpenAI", `sk-${credentialLikePayload}`],
] as const;

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

interface MutablePolicyDefinition {
  piExecutable: string;
  piDaddyExtension: string;
  governanceLedgerPath: string;
  skillResources: Record<string, string>;
  promptTemplateResources: Record<string, string>;
  systemPrompt: string;
  appendSystemPrompt: string;
}

interface PhysicalResourceSlot {
  label: string;
  get: (definition: MutablePolicyDefinition) => string;
  set: (definition: MutablePolicyDefinition, path: string) => void;
}

const physicalResourceSlots: readonly PhysicalResourceSlot[] = [
  {
    label: "Pi executable",
    get: (definition) => definition.piExecutable,
    set: (definition, path) => {
      definition.piExecutable = path;
    },
  },
  {
    label: "pi-daddy extension",
    get: (definition) => definition.piDaddyExtension,
    set: (definition, path) => {
      definition.piDaddyExtension = path;
    },
  },
  {
    label: "governance ledger",
    get: (definition) => definition.governanceLedgerPath,
    set: (definition, path) => {
      definition.governanceLedgerPath = path;
    },
  },
  {
    label: "skill:build",
    get: (definition) => definition.skillResources["skill:build"] ?? "",
    set: (definition, path) => {
      definition.skillResources["skill:build"] = path;
    },
  },
  {
    label: "skill:review",
    get: (definition) => definition.skillResources["skill:review"] ?? "",
    set: (definition, path) => {
      definition.skillResources["skill:review"] = path;
    },
  },
  {
    label: "prompt:principal-feature",
    get: (definition) =>
      definition.promptTemplateResources["prompt:principal-feature"] ?? "",
    set: (definition, path) => {
      definition.promptTemplateResources["prompt:principal-feature"] = path;
    },
  },
  {
    label: "prompt:unused",
    get: (definition) =>
      definition.promptTemplateResources["prompt:unused"] ?? "",
    set: (definition, path) => {
      definition.promptTemplateResources["prompt:unused"] = path;
    },
  },
  {
    label: "system prompt",
    get: (definition) => definition.systemPrompt,
    set: (definition, path) => {
      definition.systemPrompt = path;
    },
  },
  {
    label: "append-system prompt",
    get: (definition) => definition.appendSystemPrompt,
    set: (definition, path) => {
      definition.appendSystemPrompt = path;
    },
  },
];

const physicalResourcePairs = physicalResourceSlots.flatMap((first, index) =>
  physicalResourceSlots
    .slice(index + 1)
    .map(
      (second) => [`${first.label} / ${second.label}`, first, second] as const,
    ),
);

function exceptionalMarker(): string {
  return ["OPENAI_API_KEY", "secret"].join("=");
}

function throwExceptionalInput(): never {
  const error = new Error(
    `${exceptionalMarker()} piExecutable hostile property value`,
  );
  error.name = "HostileCredentialTrap";
  throw error;
}

const exceptionalPolicyCases: ReadonlyArray<readonly [string, () => unknown]> =
  [
    [
      "top-level getter",
      () => {
        const definition = structuredClone(trustedPolicyDefinition);
        Object.defineProperty(definition, "piExecutable", {
          enumerable: true,
          get: throwExceptionalInput,
        });
        return definition;
      },
    ],
    [
      "nested resource-registry getter",
      () => {
        const definition = structuredClone(trustedPolicyDefinition);
        Object.defineProperty(definition.skillResources, "skill:build", {
          enumerable: true,
          get: throwExceptionalInput,
        });
        return definition;
      },
    ],
    [
      "Proxy get trap",
      () =>
        new Proxy(structuredClone(trustedPolicyDefinition), {
          get: throwExceptionalInput,
        }),
    ],
    [
      "Proxy ownKeys trap",
      () =>
        new Proxy(structuredClone(trustedPolicyDefinition), {
          ownKeys: throwExceptionalInput,
        }),
    ],
    [
      "Proxy getOwnPropertyDescriptor trap",
      () =>
        new Proxy(structuredClone(trustedPolicyDefinition), {
          getOwnPropertyDescriptor: throwExceptionalInput,
        }),
    ],
  ];

const exceptionalManifestCases: ReadonlyArray<
  readonly [string, () => unknown]
> = [
  [
    "top-level getter",
    () => {
      const manifest = cloneManifest();
      Object.defineProperty(manifest, "schemaVersion", {
        enumerable: true,
        get: throwExceptionalInput,
      });
      return manifest;
    },
  ],
  [
    "nested getter",
    () => {
      const manifest = cloneManifest();
      Object.defineProperty(manifest.resources, "skills", {
        enumerable: true,
        get: throwExceptionalInput,
      });
      return manifest;
    },
  ],
  [
    "Proxy get trap",
    () =>
      new Proxy(cloneManifest(), {
        get: throwExceptionalInput,
      }),
  ],
  [
    "Proxy ownKeys trap",
    () =>
      new Proxy(cloneManifest(), {
        ownKeys: throwExceptionalInput,
      }),
  ],
  [
    "Proxy getOwnPropertyDescriptor trap",
    () =>
      new Proxy(cloneManifest(), {
        getOwnPropertyDescriptor: throwExceptionalInput,
      }),
  ],
];

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

  it.each(physicalResourcePairs)(
    "rejects a policy-wide exact physical alias: %s",
    (_label, first, second) => {
      const definition = structuredClone(
        trustedPolicyDefinition,
      ) as MutablePolicyDefinition;
      second.set(definition, first.get(definition));

      expect(() => createTrustedLaunchPolicy(definition)).toThrow(
        new LaunchPlanInputError(
          "trusted launch policy must bind each logical resource to a unique physical path",
        ),
      );
    },
  );

  it.each(
    providerTokenCases.flatMap(([provider, token]) =>
      physicalResourceSlots.map(
        (slot) => [`${provider} in ${slot.label}`, token, slot] as const,
      ),
    ),
  )("rejects and redacts a provider token path: %s", (_label, token, slot) => {
    const definition = structuredClone(
      trustedPolicyDefinition,
    ) as MutablePolicyDefinition;
    slot.set(definition, `/home/paca/resources/${token}/resource`);

    try {
      createTrustedLaunchPolicy(definition);
      throw new Error("expected LaunchPlanInputError");
    } catch (error) {
      expect(error).toBeInstanceOf(LaunchPlanInputError);
      expect(String(error)).toContain(
        "must be an absolute local WSL path without traversal, credential, or injection characters",
      );
      expect(String(error)).not.toContain(token);
      expect(String(error)).not.toContain(credentialLikePayload);
    }
  });

  it.each([
    ["skill", "skillResources", `skill:sk-proj-${credentialLikePayload}`],
    [
      "prompt template",
      "promptTemplateResources",
      `prompt:sk-ant-${credentialLikePayload}`,
    ],
  ] as const)(
    "rejects and redacts a provider token in a %s registry identity",
    (label, registryName, reference) => {
      const definition = structuredClone(
        trustedPolicyDefinition,
      ) as MutablePolicyDefinition;
      definition[registryName] = {
        [reference]: `/home/paca/resources/${label}/resource`,
      };

      try {
        createTrustedLaunchPolicy(definition);
        throw new Error("expected LaunchPlanInputError");
      } catch (error) {
        expect(error).toEqual(
          new LaunchPlanInputError(
            `${label} resources contain an invalid logical resource identity`,
          ),
        );
        expect(String(error)).not.toContain(reference);
        expect(String(error)).not.toContain(credentialLikePayload);
      }
    },
  );

  it("accepts harmless sk fragments in ordinary filenames and WSL paths", () => {
    expect(() =>
      createTrustedLaunchPolicy({
        piExecutable: "/home/paca/sk-tools/pi",
        piDaddyExtension: "/home/paca/mask-work/pi-daddy.ts",
        governanceLedgerPath: "/home/paca/state/task-sketch-ledger.jsonl",
        skillResources: {
          "skill:risk-review": "/home/paca/My Skills/sk-review/SKILL.md",
        },
        promptTemplateResources: {
          "prompt:risk-report": "/home/paca/My Prompts/sk-notes.md",
        },
        systemPrompt: "/home/paca/prompts/risk-system.md",
        appendSystemPrompt: "/home/paca/prompts/task-append-sk.md",
      }),
    ).not.toThrow();
  });

  it.each(exceptionalPolicyCases)(
    "converts a policy %s to one fixed redacted domain error",
    (_label, createInput) => {
      try {
        createTrustedLaunchPolicy(createInput());
        throw new Error("expected LaunchPlanInputError");
      } catch (error) {
        expect(error).toEqual(
          new LaunchPlanInputError(
            "trusted launch policy input could not be safely inspected",
          ),
        );
        expect(String(error)).not.toContain(exceptionalMarker());
        expect(String(error)).not.toContain("HostileCredentialTrap");
        expect(String(error)).not.toContain("piExecutable");
      }
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

  it.each(canonicalToolMutationAttempts)(
    "keeps canonical planning unchanged after exported-state mutation attempt: %s",
    (_label, attemptMutation) => {
      const before = createPiLaunchPlan(
        principalDeveloperManifest,
        trustedPolicy,
      );
      let thrown: unknown;
      try {
        attemptMutation();
      } catch (error) {
        thrown = error;
      }

      const after = createPiLaunchPlan(
        principalDeveloperManifest,
        trustedPolicy,
      );

      expect(thrown).toBeInstanceOf(TypeError);
      expect(after).toEqual(before);
      expect(after.arguments.at(-1)).toBe("read,bash,edit,write");
      expect(after.environment.PI_GRANTS_GRANT).toBe(
        "tool:read,tool:bash,tool:edit,tool:write",
      );
      expect(derivePiDaddyGrant(CANONICAL_PI_TOOLS)).toBe(canonicalGrant);
    },
  );

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

  it("is deterministic, preserves unique skill and prompt order, and does not mutate inputs", () => {
    const manifest = cloneManifest();
    manifest.resources.skills = ["skill:review", "skill:build"];
    manifest.resources.promptTemplates = [
      "prompt:unused",
      "prompt:principal-feature",
    ];
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
    expect(first.arguments.slice(9, 14)).toEqual([
      "--prompt-template",
      trustedPolicyDefinition.promptTemplateResources["prompt:unused"],
      "--prompt-template",
      trustedPolicyDefinition.promptTemplateResources[
        "prompt:principal-feature"
      ],
      "--no-context-files",
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

  it.each(providerTokenCases)(
    "rejects and redacts %s input before producing a launch result",
    (_provider, token) => {
      const manifest = cloneManifest();
      manifest.authorization.objective = `Use ${token}`;
      let result: ReturnType<typeof createPiLaunchPlan> | undefined;

      try {
        result = createPiLaunchPlan(manifest, trustedPolicy);
        throw new Error("expected LaunchPlanInputError");
      } catch (error) {
        expect(error).toEqual(
          new LaunchPlanInputError(
            "manifest is invalid: /authorization/objective must not contain credential-shaped content",
          ),
        );
        expect(String(error)).not.toContain(token);
        expect(String(error)).not.toContain(credentialLikePayload);
        expect(String(error)).not.toContain("correlation");
        expect(String(error)).not.toContain("redactedOperatorPreview");
        expect(result).toBeUndefined();
      }
    },
  );

  it.each(exceptionalManifestCases)(
    "converts a manifest %s to one fixed redacted launch-plan error",
    (_label, createInput) => {
      try {
        createPiLaunchPlan(createInput(), trustedPolicy);
        throw new Error("expected LaunchPlanInputError");
      } catch (error) {
        expect(error).toEqual(
          new LaunchPlanInputError(
            "manifest input could not be safely inspected",
          ),
        );
        expect(String(error)).not.toContain(exceptionalMarker());
        expect(String(error)).not.toContain("HostileCredentialTrap");
        expect(String(error)).not.toContain("piExecutable");
      }
    },
  );

  it.each([null, undefined, 42, "manifest", []])(
    "returns a domain error for malformed launch-plan manifest input %j",
    (manifest) => {
      expect(() => createPiLaunchPlan(manifest, trustedPolicy)).toThrow(
        LaunchPlanInputError,
      );
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

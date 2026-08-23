import { Ajv } from "ajv";
import { describe, expect, it } from "vitest";

import * as contractApi from "../src/index.js";
import agentExecutionManifestSchema from "../src/schemas/agent-execution-manifest.schema.json" with { type: "json" };
import executionContextSchema from "../src/schemas/execution-context.schema.json" with { type: "json" };
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
  containsCredentialShapedContent,
  derivePiDaddyGrant,
  isAgentExecutionManifest,
  isGovernedAgentExecutionManifest,
  validateAgentExecutionManifest,
  validateGovernedAgentExecutionManifest,
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

const credentialLikePayload = "abcdefghijklmnopqrstuvwxyz0123456789";
const providerTokenCases = [
  ["OpenAI project", `sk-proj-${credentialLikePayload}`],
  ["Anthropic API03", `sk-ant-api03-${credentialLikePayload}`],
  ["Anthropic", `sk-ant-${credentialLikePayload}`],
  ["OpenAI service account", `sk-svcacct-${credentialLikePayload}`],
  ["legacy OpenAI", `sk-${credentialLikePayload}`],
] as const;

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

const exceptionalInputError = {
  valid: false,
  errors: [
    {
      path: "/",
      code: "input-introspection",
      message: "input could not be safely inspected",
    },
  ],
} as const;

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
      Object.defineProperty(manifest.authorization, "objective", {
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

function exceptionalMarker(): string {
  return ["OPENAI_API_KEY", "secret"].join("=");
}

function throwExceptionalInput(): never {
  const error = new Error(
    `${exceptionalMarker()} schemaVersion hostile property value`,
  );
  error.name = "HostileCredentialTrap";
  throw error;
}

const structuralAjv = new Ajv({ allErrors: true });
structuralAjv.addSchema(executionContextSchema);
const validateManifestStructure = structuralAjv.compile(
  agentExecutionManifestSchema,
);

describe("spts.agent-execution-manifest", () => {
  it.each([
    ["product", productManifest],
    ["flow", flowManifest],
    ["principal_developer", principalDeveloperManifest],
    ["verifier", verifierManifest],
  ])("accepts the %s role", (_role, manifest) => {
    expect(validateGovernedAgentExecutionManifest(manifest)).toEqual({
      valid: true,
      value: manifest,
    });
    expect(isGovernedAgentExecutionManifest(manifest)).toBe(true);
  });

  it("labels the portable schema as a nonauthorizing structural artifact", () => {
    const metadata = agentExecutionManifestSchema as Record<string, unknown>;

    expect(metadata.title).toContain("structural");
    expect(metadata.description).toContain("does not authorize");
    expect(metadata.$comment).toContain("composite validator");
  });

  it("exports the explicitly named governed contract composite validator", () => {
    expect(contractApi.validateGovernedAgentExecutionManifest).toBeTypeOf(
      "function",
    );
    expect(contractApi.isGovernedAgentExecutionManifest).toBeTypeOf("function");
    expect(validateAgentExecutionManifest).toBe(
      validateGovernedAgentExecutionManifest,
    );
    expect(isAgentExecutionManifest).toBe(isGovernedAgentExecutionManifest);
  });

  it("treats structural success as nonauthorizing", () => {
    const credentialShaped = cloneManifest();
    const marker = ["PRIVATE", "INPUT"].join("-");
    credentialShaped.authorization.objective = `token ${marker}`;
    const noncanonical = cloneManifest();
    noncanonical.tools = ["bash", "read"];
    noncanonical.piDaddyGrant = "tool:bash,tool:read";
    const mismatchedGrant = cloneManifest();
    mismatchedGrant.piDaddyGrant = "tool:read";

    for (const [label, manifest] of [
      ["credential shape", credentialShaped],
      ["noncanonical tools", noncanonical],
      ["mismatched grant", mismatchedGrant],
    ] as const) {
      expect(validateManifestStructure(manifest), label).toBe(true);
      expect(
        validateGovernedAgentExecutionManifest(manifest).valid,
        label,
      ).toBe(false);
    }
  });

  it("accepts every shipped example through the governed composite boundary", () => {
    expect(
      validManifests.every(
        (manifest) => validateGovernedAgentExecutionManifest(manifest).valid,
      ),
    ).toBe(true);
  });

  it("accepts a normalized absolute WSL repository path with spaces", () => {
    const manifest = cloneManifest();
    manifest.repository.root = "/home/paca/My Tools/private workspace";

    expect(validateAgentExecutionManifest(manifest).valid).toBe(true);
  });

  it.each([
    ["parent traversal", "/home/paca/work/../private"],
    ["current-directory traversal", "/home/paca/work/./private"],
    ["relative", "home/paca/work/private"],
    ["duplicate separator", "/home/paca//work/private"],
    ["trailing separator", "/home/paca/work/private/"],
    ["NUL control", "/home/paca/work/\u0000private"],
    ["non-NUL control", "/home/paca/work/\u0001private"],
    ["command substitution", "/home/paca/work/$(id)"],
    ["execution separator", "/home/paca/work/private;touch-bad"],
    ["backslash separator", "/home/paca/work\\private"],
  ])(
    "rejects non-normalized or unsafe WSL repository path: %s",
    (_label, root) => {
      const manifest = cloneManifest();
      manifest.repository.root = root;

      expect(validateAgentExecutionManifest(manifest).valid).toBe(false);
    },
  );

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
    ["a manifest executable", arbitraryExecutable, "/", "additionalProperties"],
    [
      "manifest environment variables",
      unrestrictedEnvironment,
      "/",
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

  it.each(canonicalToolMutationAttempts)(
    "keeps private canonical authority after exported-state mutation attempt: %s",
    (_label, attemptMutation) => {
      let thrown: unknown;
      try {
        attemptMutation();
      } catch (error) {
        thrown = error;
      }

      const canonical = cloneManifest();
      const noncanonical = cloneManifest();
      noncanonical.tools = ["bash", "read"];
      noncanonical.piDaddyGrant = "tool:bash,tool:read";

      expect(thrown).toBeInstanceOf(TypeError);
      expect(CANONICAL_PI_TOOLS).toEqual([
        "read",
        "bash",
        "edit",
        "write",
        "grep",
        "find",
        "ls",
      ]);
      expect(Object.isFrozen(CANONICAL_PI_TOOLS)).toBe(true);
      expect(derivePiDaddyGrant(CANONICAL_PI_TOOLS)).toBe(canonicalGrant);
      expect(derivePiDaddyGrant(["bash", "read"])).toBe("tool:bash,tool:read");
      expect(validateGovernedAgentExecutionManifest(canonical).valid).toBe(
        true,
      );
      expect(validateGovernedAgentExecutionManifest(noncanonical)).toEqual({
        valid: false,
        errors: [
          expect.objectContaining({ path: "/tools", code: "canonical-order" }),
        ],
      });
    },
  );

  it.each([
    "Inspect with curl example.test",
    "Count tokenizer output without logging values",
    "Review bearer-independent authentication prose",
    "Keep ordinary sk fragments in risk-assessment prose",
    "Use sk-not-a-credential while documenting placeholder syntax",
    "Review the sk-notes.md filename",
  ])("accepts inert prose without credential assignments: %s", (objective) => {
    const manifest = cloneManifest();
    manifest.authorization.objective = objective;

    expect(validateAgentExecutionManifest(manifest).valid).toBe(true);
  });

  it.each([
    "/home/paca/work/sk-notes.md",
    "/home/paca/My sk-work/project files",
    "/mnt/c/Users/Operator/risk-assessment/task-sketch",
  ])("accepts harmless sk fragments in a WSL path: %s", (root) => {
    const manifest = cloneManifest();
    manifest.repository.root = root;

    expect(validateGovernedAgentExecutionManifest(manifest).valid).toBe(true);
  });

  it.each(
    providerTokenCases.flatMap(
      ([provider, token]) =>
        [
          [`${provider} at start`, `${token} is configured elsewhere`, token],
          [
            `${provider} in middle`,
            provider === "Anthropic API03"
              ? `Token: ${token}`
              : `Use ${token} for the probe`,
            token,
          ],
          [`${provider} at end`, `Use ${token}`, token],
        ] as const,
    ),
  )(
    "rejects and redacts provider token prose: %s",
    (_label, objective, token) => {
      const manifest = cloneManifest();
      manifest.authorization.objective = objective;

      expect(validateManifestStructure(manifest)).toBe(true);
      const result = validateGovernedAgentExecutionManifest(manifest);

      expect(result).toEqual({
        valid: false,
        errors: [
          {
            path: "/authorization/objective",
            code: "credential-shaped",
            message: "must not contain credential-shaped content",
          },
        ],
      });
      expect(JSON.stringify(result)).not.toContain(token);
      expect(result).not.toHaveProperty("value");
    },
  );

  it("handles mixed-case provider prefixes without echoing the token", () => {
    const token = `SK-AnT-ApI03-${credentialLikePayload}`;
    const manifest = cloneManifest();
    manifest.authorization.objective = `Use ${token}`;

    expect(validateManifestStructure(manifest)).toBe(true);
    const result = validateGovernedAgentExecutionManifest(manifest);

    expect(result.valid).toBe(false);
    expect(JSON.stringify(result)).not.toContain(token);
  });

  const credentialCases: ReadonlyArray<
    readonly [string, (suspectedValue: string) => string]
  > = [
    ["password assignment", (value) => `PASSWORD=${value}`],
    ["password colon", (value) => `password : ${value}`],
    ["password whitespace", (value) => `PaSsWoRd ${value}`],
    ["token assignment", (value) => `ToKeN\t=\t${value}`],
    ["token colon", (value) => `token:\t${value}`],
    ["token whitespace", (value) => `ToKeN\t${value}`],
    ["API key assignment", (value) => `api-key= ${value}`],
    ["API key colon", (value) => `API_KEY : ${value}`],
    ["API key whitespace", (value) => `Api_Key ${value}`],
    ["Bearer assignment", (value) => `Bearer=${value}`],
    ["Bearer colon", (value) => `bEaReR:\t${value}`],
    ["Bearer whitespace", (value) => `Bearer ${value}`],
    ["provider token prefix", (value) => `GHP_${value.replaceAll("-", "")}`],
    ["OpenAI API key", (value) => `OPENAI_API_KEY=${value}`],
    ["Anthropic API key", (value) => `ANTHROPIC_API_KEY=${value}`],
    ["AWS secret access key", (value) => `AWS_SECRET_ACCESS_KEY=${value}`],
    ["client secret", (value) => `CLIENT_SECRET=${value}`],
  ];

  it.each(credentialCases)(
    "rejects and redacts credential-shaped objective: %s",
    (_label, objectiveFor) => {
      const suspectedValue = ["SENSITIVE", "VALUE", "DO", "NOT", "ECHO"].join(
        "-",
      );
      const manifest = cloneManifest();
      manifest.authorization.objective = objectiveFor(suspectedValue);

      const result = validateAgentExecutionManifest(manifest);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors).toContainEqual({
          path: "/authorization/objective",
          code: "credential-shaped",
          message: "must not contain credential-shaped content",
        });
        expect(JSON.stringify(result.errors)).not.toContain(suspectedValue);
      }
    },
  );

  it.each([
    [
      "execution ID",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.executionId = `token:${value}`;
      },
      "/executionId",
    ],
    [
      "Paca project ID",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.paca.projectId = `token:${value}`;
      },
      "/paca/projectId",
    ],
    [
      "Paca task ID",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.paca.taskId = `token:${value}`;
      },
      "/paca/taskId",
    ],
    [
      "agent name",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.agent.name = `PASSWORD ${value}`;
      },
      "/agent/name",
    ],
    [
      "repository root",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.repository.root = `/home/paca/token=${value}/project`;
      },
      "/repository/root",
    ],
    [
      "Git identity name",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.repository.expectedGitIdentity = {
          name: `PASSWORD ${value}`,
          email: "operator@example.test",
        };
      },
      "/repository/expectedGitIdentity/name",
    ],
    [
      "Git identity email",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.repository.expectedGitIdentity = {
          name: "Operator",
          email: `token=${value}@example.test`,
        };
      },
      "/repository/expectedGitIdentity/email",
    ],
    [
      "objective",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.authorization.objective = `PASSWORD ${value}`;
      },
      "/authorization/objective",
    ],
    [
      "out-of-scope prose",
      (manifest: AgentExecutionManifest, value: string) => {
        manifest.authorization.outOfScope[0] = `PASSWORD ${value}`;
      },
      "/authorization/outOfScope/0",
    ],
  ] satisfies ReadonlyArray<
    readonly [
      string,
      (manifest: AgentExecutionManifest, value: string) => void,
      string,
    ]
  >)(
    "rejects and redacts credential-shaped accepted string: %s",
    (_label, mutate, path) => {
      const suspectedValue = "SENSITIVE_VALUE_DO_NOT_ECHO";
      const manifest = cloneManifest();
      mutate(manifest, suspectedValue);

      const result = validateGovernedAgentExecutionManifest(manifest);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors).toContainEqual({
          path,
          code: "credential-shaped",
          message: "must not contain credential-shaped content",
        });
        expect(JSON.stringify(result.errors)).not.toContain(suspectedValue);
      }
    },
  );

  it.each([
    [
      "execution ID",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.executionId = token;
      },
      "/executionId",
    ],
    [
      "Paca project ID",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.paca.projectId = token;
      },
      "/paca/projectId",
    ],
    [
      "Paca task ID",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.paca.taskId = token;
      },
      "/paca/taskId",
    ],
    [
      "agent name",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.agent.name = token;
      },
      "/agent/name",
    ],
    [
      "repository root",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.repository.root = `/home/paca/${token}/project`;
      },
      "/repository/root",
    ],
    [
      "Git identity name",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.repository.expectedGitIdentity = {
          name: token,
          email: "operator@example.test",
        };
      },
      "/repository/expectedGitIdentity/name",
    ],
    [
      "Git identity email",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.repository.expectedGitIdentity = {
          name: "Operator",
          email: `${token}@example.test`,
        };
      },
      "/repository/expectedGitIdentity/email",
    ],
    [
      "skill reference",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.resources.skills = [`skill:${token}`];
      },
      "/resources/skills/0",
    ],
    [
      "prompt reference",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.resources.promptTemplates = [`prompt:${token}`];
      },
      "/resources/promptTemplates/0",
    ],
    [
      "objective",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.authorization.objective = `Use ${token}`;
      },
      "/authorization/objective",
    ],
    [
      "out-of-scope prose",
      (manifest: AgentExecutionManifest, token: string) => {
        manifest.authorization.outOfScope[0] = `Never use ${token}`;
      },
      "/authorization/outOfScope/0",
    ],
  ] satisfies ReadonlyArray<
    readonly [
      string,
      (manifest: AgentExecutionManifest, token: string) => void,
      string,
    ]
  >)(
    "rejects provider tokens in every credential-capable manifest string location: %s",
    (_label, mutate, path) => {
      const token = `sk-proj-${credentialLikePayload}`;
      const manifest = cloneManifest();
      mutate(manifest, token);

      expect(validateManifestStructure(manifest)).toBe(true);
      const result = validateGovernedAgentExecutionManifest(manifest);

      expect(result).toEqual({
        valid: false,
        errors: [
          {
            path,
            code: "credential-shaped",
            message: "must not contain credential-shaped content",
          },
        ],
      });
      expect(JSON.stringify(result)).not.toContain(token);
      expect(result).not.toHaveProperty("value");
    },
  );

  it("sanitizes structural diagnostics for credential-shaped undeclared properties", () => {
    const manifest = cloneManifest() as unknown as Record<string, unknown>;
    const propertyName = "OPENAI_API_KEY=SENSITIVE_PROPERTY_DO_NOT_ECHO";
    manifest[propertyName] = "SENSITIVE_VALUE_DO_NOT_ECHO";

    const result = validateGovernedAgentExecutionManifest(manifest);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      const diagnostics = JSON.stringify(result.errors);
      expect(diagnostics).not.toContain(propertyName);
      expect(diagnostics).not.toContain("SENSITIVE_PROPERTY_DO_NOT_ECHO");
      expect(diagnostics).not.toContain("SENSITIVE_VALUE_DO_NOT_ECHO");
      expect(result.errors).toContainEqual({
        path: "/",
        code: "additionalProperties",
        message: "must not include undeclared properties",
      });
    }
  });

  it.each(exceptionalManifestCases)(
    "returns one fixed redacted domain result for a manifest %s",
    (_label, createInput) => {
      const result = validateGovernedAgentExecutionManifest(createInput());

      expect(result).toEqual(exceptionalInputError);
      expect(JSON.stringify(result)).not.toContain(exceptionalMarker());
      expect(JSON.stringify(result)).not.toContain("HostileCredentialTrap");
      expect(JSON.stringify(result)).not.toContain("schemaVersion");
      expect(isGovernedAgentExecutionManifest(createInput())).toBe(false);
    },
  );

  it("scans logical resource strings without bare credential substrings", () => {
    const manifest = cloneManifest();
    manifest.resources.skills = ["skill:token-review"];
    manifest.resources.promptTemplates = ["prompt:bearer-report"];

    expect(validateGovernedAgentExecutionManifest(manifest).valid).toBe(true);
  });

  it.each([
    "Run tests; curl example.test",
    "Read $(whoami)",
    "Use `id` output",
    "First line\nsecond line",
  ])("rejects injection-shaped objective %j", (objective) => {
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

  it("derives grants without invoking hostile get or iterator traps", () => {
    let getTrapCalled = false;
    let iteratorTrapCalled = false;
    const tools = new Proxy(["read", "edit"] as const, {
      get(_target, property) {
        if (property === Symbol.iterator) {
          iteratorTrapCalled = true;
        } else {
          getTrapCalled = true;
        }
        return throwExceptionalInput();
      },
    });

    expect(derivePiDaddyGrant(tools)).toBe("tool:read,tool:edit");
    expect(getTrapCalled).toBe(false);
    expect(iteratorTrapCalled).toBe(false);
  });

  it.each([
    [
      "throwing element getter",
      () => {
        const tools = ["read"];
        Object.defineProperty(tools, 0, {
          enumerable: true,
          get: throwExceptionalInput,
        });
        return tools;
      },
    ],
    [
      "ownKeys trap",
      () => new Proxy(["read"], { ownKeys: throwExceptionalInput }),
    ],
    [
      "getOwnPropertyDescriptor trap",
      () =>
        new Proxy(["read"], {
          getOwnPropertyDescriptor: throwExceptionalInput,
        }),
    ],
    [
      "own Symbol.iterator getter",
      () => {
        const tools = ["read"];
        Object.defineProperty(tools, Symbol.iterator, {
          get: throwExceptionalInput,
        });
        return tools;
      },
    ],
    [
      "revoked proxy",
      () => {
        const revocable = Proxy.revocable(["read"], {});
        revocable.revoke();
        return revocable.proxy;
      },
    ],
    [
      "hostile array element",
      () => [
        {
          toString: throwExceptionalInput,
          valueOf: throwExceptionalInput,
          [Symbol.toPrimitive]: throwExceptionalInput,
        },
      ],
    ],
    ["ordinary JavaScript null", () => null],
    ["ordinary JavaScript object", () => ({ 0: "read", length: 1 })],
  ] satisfies ReadonlyArray<readonly [string, () => unknown]>)(
    "returns only the fixed redacted grant diagnostic for %s",
    (_label, createInput) => {
      let thrown: unknown;
      try {
        (derivePiDaddyGrant as (value: unknown) => string)(createInput());
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toEqual(
        new TypeError("input could not be safely inspected"),
      );
      expect(String(thrown)).not.toContain(exceptionalMarker());
      expect(String(thrown)).not.toContain("HostileCredentialTrap");
      expect(String(thrown)).not.toContain("schemaVersion");
    },
  );

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["number", 42],
    ["boolean", true],
    ["symbol", Symbol("credential")],
    [
      "hostile coercion object",
      {
        toString: throwExceptionalInput,
        valueOf: throwExceptionalInput,
        [Symbol.toPrimitive]: throwExceptionalInput,
      },
    ],
    ["get-trapping proxy", new Proxy({}, { get: throwExceptionalInput })],
    [
      "revoked proxy",
      (() => {
        const revocable = Proxy.revocable({}, {});
        revocable.revoke();
        return revocable.proxy;
      })(),
    ],
  ] as const)(
    "fails the credential helper closed without coercion for %s",
    (_label, value) => {
      expect(
        (containsCredentialShapedContent as (input: unknown) => boolean)(value),
      ).toBe(true);
    },
  );

  it.each([
    ["assignment", `${exceptionalMarker()}`],
    ["provider token", `sk-proj-${credentialLikePayload}`],
  ])("preserves credential helper detection for %s", (_label, value) => {
    expect(containsCredentialShapedContent(value)).toBe(true);
  });

  it.each([
    "Inspect with curl example.test",
    "Keep ordinary sk fragments in prose",
    "/home/paca/My sk-work/project files",
  ])("preserves harmless credential helper negatives: %s", (value) => {
    expect(containsCredentialShapedContent(value)).toBe(false);
  });

  it("derives grants in the documented canonical Pi tool order", () => {
    expect(derivePiDaddyGrant(CANONICAL_PI_TOOLS)).toBe(canonicalGrant);
    expect(
      validManifests.every((manifest) => manifest.schemaVersion === "1.0.0"),
    ).toBe(true);
  });
});

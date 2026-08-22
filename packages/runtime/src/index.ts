import {
  validateGovernedAgentExecutionManifest,
  type AgentExecutionManifest,
  type PromptTemplateReference,
  type SkillReference,
} from "@scrum-pi-team-skills/contracts";

export interface LocalPiResources {
  executable: string;
  piDaddyExtension: string;
  governanceLedgerPath: string;
  skillRegistry: Readonly<Record<string, string>>;
  promptTemplateRegistry: Readonly<Record<string, string>>;
}

export interface PiLaunchPlan {
  executable: string;
  arguments: string[];
  workingDirectory: string;
  environment: {
    PI_GRANTS_GRANT: string;
    PI_GRANTS_MAX_DEPTH: "0";
    PI_GRANTS_LEDGER: string;
  };
  redactedOperatorPreview: {
    executable: "<pi-executable>";
    arguments: string[];
    workingDirectory: "<repository-root>";
    environment: {
      PI_GRANTS_GRANT: string;
      PI_GRANTS_MAX_DEPTH: "0";
      PI_GRANTS_LEDGER: "<governance-ledger>";
    };
  };
  correlation: {
    executionId: string;
    pacaProjectId: string;
    pacaTaskId: string;
  };
}

export class LaunchPlanInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LaunchPlanInputError";
  }
}

const SKILL_REFERENCE = /^skill:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PROMPT_REFERENCE = /^prompt:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PROHIBITED_LOCAL_PATH_CHARACTER = /[`$;&|<>"'\\]/;
const CREDENTIAL_SHAPE =
  /(?:\b(?:password|token|api[_-]?key|bearer)(?:\s*[:=]\s*|\s+)\S+|(?:sk|ghp|github_pat)_[A-Za-z0-9]+)/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasTraversalSegment(value: string): boolean {
  return value
    .split("/")
    .some((segment) => segment === "." || segment === "..");
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isNormalizedAbsoluteWslPath(value: string): boolean {
  return (
    value.startsWith("/") &&
    value !== "/" &&
    !value.endsWith("/") &&
    !value.includes("//") &&
    !hasTraversalSegment(value) &&
    !hasControlCharacter(value) &&
    !PROHIBITED_LOCAL_PATH_CHARACTER.test(value)
  );
}

function requireLocalPath(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new LaunchPlanInputError(`${label} must be a string`);
  }
  if (!isNormalizedAbsoluteWslPath(value) || CREDENTIAL_SHAPE.test(value)) {
    throw new LaunchPlanInputError(
      `${label} must be an absolute local WSL path without traversal, credential, or injection characters`,
    );
  }
  return value;
}

function validateRegistry(
  value: unknown,
  label: string,
  referencePattern: RegExp,
): asserts value is Readonly<Record<string, string>> {
  if (!isRecord(value)) {
    throw new LaunchPlanInputError(`${label} must be an object`);
  }

  for (const [reference, path] of Object.entries(value)) {
    if (!referencePattern.test(reference) || CREDENTIAL_SHAPE.test(reference)) {
      throw new LaunchPlanInputError(
        `${label} contains an invalid logical resource identity`,
      );
    }
    if (typeof path !== "string") {
      throw new LaunchPlanInputError(`${label} paths must be strings`);
    }
    requireLocalPath(path, `${label} path`);
  }
}

function validateLocalResources(
  value: unknown,
): asserts value is LocalPiResources {
  if (!isRecord(value)) {
    throw new LaunchPlanInputError("local resources must be an object");
  }

  requireLocalPath(value.executable, "Pi executable");
  requireLocalPath(value.piDaddyExtension, "pi-daddy grants extension");
  requireLocalPath(value.governanceLedgerPath, "governance ledger");
  validateRegistry(value.skillRegistry, "skill registry", SKILL_REFERENCE);
  validateRegistry(
    value.promptTemplateRegistry,
    "prompt template registry",
    PROMPT_REFERENCE,
  );
}

function resolveResources(
  references: readonly string[],
  registry: Readonly<Record<string, string>>,
  label: string,
): string[] {
  return references.map((reference) => {
    if (!Object.hasOwn(registry, reference)) {
      throw new LaunchPlanInputError(
        `${label} registry has no approved path for ${JSON.stringify(reference)}`,
      );
    }
    return requireLocalPath(registry[reference] ?? "", `${label} ${reference}`);
  });
}

function resourceArguments(
  flag: "--skill" | "--prompt-template",
  paths: readonly string[],
): string[] {
  return paths.flatMap((path) => [flag, path]);
}

function redactedResourceArguments(
  flag: "--skill" | "--prompt-template",
  references: readonly (SkillReference | PromptTemplateReference)[],
): string[] {
  return references.flatMap((reference) => [flag, `<${reference}>`]);
}

export function createPiLaunchPlan(
  manifest: AgentExecutionManifest,
  localResources: LocalPiResources,
): PiLaunchPlan {
  const validation = validateGovernedAgentExecutionManifest(manifest);
  if (!validation.valid) {
    const summary = validation.errors
      .map((error) => `${error.path} ${error.message}`)
      .join("; ");
    throw new LaunchPlanInputError(`manifest is invalid: ${summary}`);
  }

  validateLocalResources(localResources);

  const executable = requireLocalPath(
    localResources.executable,
    "Pi executable",
  );
  const piDaddyExtension = requireLocalPath(
    localResources.piDaddyExtension,
    "pi-daddy grants extension",
  );
  const governanceLedgerPath = requireLocalPath(
    localResources.governanceLedgerPath,
    "governance ledger",
  );
  const skills = resolveResources(
    manifest.resources.skills,
    localResources.skillRegistry,
    "skill",
  );
  const promptTemplates = resolveResources(
    manifest.resources.promptTemplates,
    localResources.promptTemplateRegistry,
    "prompt template",
  );
  const toolAllowlist = manifest.tools.join(",");

  const arguments_: string[] = [
    "--no-extensions",
    "--extension",
    piDaddyExtension,
    "--no-skills",
    ...resourceArguments("--skill", skills),
    "--no-prompt-templates",
    ...resourceArguments("--prompt-template", promptTemplates),
    "--no-context-files",
    "--tools",
    toolAllowlist,
  ];
  const environment = {
    PI_GRANTS_GRANT: manifest.piDaddyGrant,
    PI_GRANTS_MAX_DEPTH: "0" as const,
    PI_GRANTS_LEDGER: governanceLedgerPath,
  };

  return {
    executable,
    arguments: arguments_,
    workingDirectory: manifest.repository.root,
    environment,
    redactedOperatorPreview: {
      executable: "<pi-executable>",
      arguments: [
        "--no-extensions",
        "--extension",
        "<pi-daddy-grants>",
        "--no-skills",
        ...redactedResourceArguments("--skill", manifest.resources.skills),
        "--no-prompt-templates",
        ...redactedResourceArguments(
          "--prompt-template",
          manifest.resources.promptTemplates,
        ),
        "--no-context-files",
        "--tools",
        toolAllowlist,
      ],
      workingDirectory: "<repository-root>",
      environment: {
        PI_GRANTS_GRANT: manifest.piDaddyGrant,
        PI_GRANTS_MAX_DEPTH: "0",
        PI_GRANTS_LEDGER: "<governance-ledger>",
      },
    },
    correlation: {
      executionId: manifest.executionId,
      pacaProjectId: manifest.paca.projectId,
      pacaTaskId: manifest.paca.taskId,
    },
  };
}

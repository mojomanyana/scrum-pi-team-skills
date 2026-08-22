import {
  validateAgentExecutionManifest,
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

const ABSOLUTE_LOCAL_PATH = /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/;

function requireLocalPath(value: string, label: string): string {
  if (!ABSOLUTE_LOCAL_PATH.test(value)) {
    throw new LaunchPlanInputError(
      `${label} must be an absolute local WSL path without traversal or injection characters`,
    );
  }
  return value;
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
  const validation = validateAgentExecutionManifest(manifest);
  if (!validation.valid) {
    const summary = validation.errors
      .map((error) => `${error.path} ${error.message}`)
      .join("; ");
    throw new LaunchPlanInputError(`manifest is invalid: ${summary}`);
  }

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

import {
  validateGovernedAgentExecutionManifest,
  type AgentExecutionManifest,
  type PromptTemplateReference,
  type SkillReference,
} from "@scrum-pi-team-skills/contracts";

export interface TrustedLaunchPolicyDefinition {
  readonly piExecutable: string;
  readonly piDaddyExtension: string;
  readonly governanceLedgerPath: string;
  readonly skillResources: Readonly<Record<string, string>>;
  readonly promptTemplateResources: Readonly<Record<string, string>>;
  readonly systemPrompt: string;
  readonly appendSystemPrompt: string;
}

const trustedLaunchPolicyBrand: unique symbol = Symbol("TrustedLaunchPolicy");

/** Immutable local operator authority; never construct this from manifest data. */
export interface TrustedLaunchPolicy {
  readonly piExecutable: string;
  readonly piDaddyExtension: string;
  readonly governanceLedgerPath: string;
  readonly skillResources: Readonly<Record<string, string>>;
  readonly promptTemplateResources: Readonly<Record<string, string>>;
  readonly systemPrompt: string;
  readonly appendSystemPrompt: string;
  readonly [trustedLaunchPolicyBrand]: true;
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

const POLICY_PROPERTIES = new Set([
  "piExecutable",
  "piDaddyExtension",
  "governanceLedgerPath",
  "skillResources",
  "promptTemplateResources",
  "systemPrompt",
  "appendSystemPrompt",
]);
const SKILL_REFERENCE = /^skill:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PROMPT_REFERENCE = /^prompt:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PROHIBITED_LOCAL_PATH_CHARACTER = /[`$;&|<>"'\\]/;
const CREDENTIAL_ASSIGNMENT =
  /(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+_)*(?:password|passwd|token|api[_-]?key|bearer|secret(?:[_-]access[_-]key)?)(?:[ \t]*[:=][ \t]*|[ \t]+)\S+/i;
const CREDENTIAL_TOKEN_PREFIX =
  /(?:^|[^A-Za-z0-9])(?:sk|ghp|github_pat)_[A-Za-z0-9]+/i;
const issuedTrustedPolicies = new WeakSet<object>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasCredentialShape(value: string): boolean {
  return (
    CREDENTIAL_ASSIGNMENT.test(value) || CREDENTIAL_TOKEN_PREFIX.test(value)
  );
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
  if (!isNormalizedAbsoluteWslPath(value) || hasCredentialShape(value)) {
    throw new LaunchPlanInputError(
      `${label} must be an absolute local WSL path without traversal, credential, or injection characters`,
    );
  }
  return value;
}

function copyResourceRegistry(
  value: unknown,
  label: "skill" | "prompt template",
  referencePattern: RegExp,
): Readonly<Record<string, string>> {
  if (!isRecord(value)) {
    throw new LaunchPlanInputError(`${label} resources must be an object`);
  }

  const entries: Array<readonly [string, string]> = [];
  const physicalPaths = new Set<string>();
  for (const [reference, pathValue] of Object.entries(value)) {
    if (!referencePattern.test(reference) || hasCredentialShape(reference)) {
      throw new LaunchPlanInputError(
        `${label} resources contain an invalid logical resource identity`,
      );
    }
    const path = requireLocalPath(pathValue, `${label} resource path`);
    if (physicalPaths.has(path)) {
      throw new LaunchPlanInputError(
        `${label} resources must not bind multiple logical references to one physical path`,
      );
    }
    physicalPaths.add(path);
    entries.push([reference, path]);
  }

  return Object.freeze(Object.fromEntries(entries));
}

/** Validate, copy, brand, and deeply freeze local operator-owned launch authority. */
export function createTrustedLaunchPolicy(value: unknown): TrustedLaunchPolicy {
  if (!isRecord(value)) {
    throw new LaunchPlanInputError("trusted launch policy must be an object");
  }
  if (Object.keys(value).some((key) => !POLICY_PROPERTIES.has(key))) {
    throw new LaunchPlanInputError(
      "trusted launch policy must not contain undeclared properties",
    );
  }

  const policy: TrustedLaunchPolicy = Object.freeze({
    piExecutable: requireLocalPath(value.piExecutable, "Pi executable"),
    piDaddyExtension: requireLocalPath(
      value.piDaddyExtension,
      "pi-daddy grants extension",
    ),
    governanceLedgerPath: requireLocalPath(
      value.governanceLedgerPath,
      "governance ledger",
    ),
    skillResources: copyResourceRegistry(
      value.skillResources,
      "skill",
      SKILL_REFERENCE,
    ),
    promptTemplateResources: copyResourceRegistry(
      value.promptTemplateResources,
      "prompt template",
      PROMPT_REFERENCE,
    ),
    systemPrompt: requireLocalPath(value.systemPrompt, "system prompt"),
    appendSystemPrompt: requireLocalPath(
      value.appendSystemPrompt,
      "append system prompt",
    ),
    [trustedLaunchPolicyBrand]: true as const,
  });

  issuedTrustedPolicies.add(policy);
  return policy;
}

function requireTrustedLaunchPolicy(
  value: unknown,
): asserts value is TrustedLaunchPolicy {
  if (!isRecord(value) || !issuedTrustedPolicies.has(value)) {
    throw new LaunchPlanInputError(
      "trusted launch policy must be created by createTrustedLaunchPolicy",
    );
  }
}

function resolveResources(
  references: readonly string[],
  registry: Readonly<Record<string, string>>,
  label: "skill" | "prompt template",
): string[] {
  return references.map((reference) => {
    if (!Object.hasOwn(registry, reference)) {
      throw new LaunchPlanInputError(
        `${label} policy has no trusted physical resource`,
      );
    }
    return registry[reference] ?? "";
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

/**
 * Purely construct a deterministic launch plan from untrusted work intent and
 * separately created local operator authority. This function never launches Pi.
 */
export function createPiLaunchPlan(
  manifest: AgentExecutionManifest,
  trustedPolicy: TrustedLaunchPolicy,
): PiLaunchPlan {
  requireTrustedLaunchPolicy(trustedPolicy);

  const validation = validateGovernedAgentExecutionManifest(manifest);
  if (!validation.valid) {
    const summary = validation.errors
      .map((error) => `${error.path} ${error.message}`)
      .join("; ");
    throw new LaunchPlanInputError(`manifest is invalid: ${summary}`);
  }

  const skills = resolveResources(
    manifest.resources.skills,
    trustedPolicy.skillResources,
    "skill",
  );
  const promptTemplates = resolveResources(
    manifest.resources.promptTemplates,
    trustedPolicy.promptTemplateResources,
    "prompt template",
  );
  const toolAllowlist = manifest.tools.join(",");

  const arguments_: string[] = [
    "--no-extensions",
    "--extension",
    trustedPolicy.piDaddyExtension,
    "--no-skills",
    ...resourceArguments("--skill", skills),
    "--no-prompt-templates",
    ...resourceArguments("--prompt-template", promptTemplates),
    "--no-context-files",
    "--system-prompt",
    trustedPolicy.systemPrompt,
    "--append-system-prompt",
    trustedPolicy.appendSystemPrompt,
    "--tools",
    toolAllowlist,
  ];
  const environment = {
    PI_GRANTS_GRANT: manifest.piDaddyGrant,
    PI_GRANTS_MAX_DEPTH: "0" as const,
    PI_GRANTS_LEDGER: trustedPolicy.governanceLedgerPath,
  };

  return {
    executable: trustedPolicy.piExecutable,
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
        "--system-prompt",
        "<system-prompt>",
        "--append-system-prompt",
        "<append-system-prompt>",
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

import {
  validateGovernedAgentExecutionManifest,
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

type InputSnapshot = { ok: true; value: unknown } | { ok: false };

function copyJsonShapedInput(
  value: unknown,
  ancestors = new Set<object>(),
): unknown {
  if (typeof value !== "object" || value === null) return value;
  if (ancestors.has(value)) throw new TypeError();

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const copy: unknown[] = [];
      const length = value.length;
      for (let index = 0; index < length; index += 1) {
        if (Object.hasOwn(value, index)) {
          copy[index] = copyJsonShapedInput(value[index], ancestors);
        } else {
          copy.length = index + 1;
        }
      }
      return copy;
    }

    const copy: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      Object.defineProperty(copy, key, {
        configurable: true,
        enumerable: true,
        value: copyJsonShapedInput(item, ancestors),
        writable: true,
      });
    }
    return copy;
  } finally {
    ancestors.delete(value);
  }
}

function snapshotInput(value: unknown): InputSnapshot {
  try {
    return { ok: true, value: copyJsonShapedInput(value) };
  } catch {
    return { ok: false };
  }
}

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
  for (const [reference, pathValue] of Object.entries(value)) {
    if (!referencePattern.test(reference) || hasCredentialShape(reference)) {
      throw new LaunchPlanInputError(
        `${label} resources contain an invalid logical resource identity`,
      );
    }
    entries.push([
      reference,
      requireLocalPath(pathValue, `${label} resource path`),
    ]);
  }

  return Object.freeze(Object.fromEntries(entries));
}

function requireUniquePhysicalPaths(paths: readonly string[]): void {
  if (new Set(paths).size !== paths.length) {
    throw new LaunchPlanInputError(
      "trusted launch policy must bind each logical resource to a unique physical path",
    );
  }
}

/** Validate, copy, brand, and deeply freeze local operator-owned launch authority. */
export function createTrustedLaunchPolicy(value: unknown): TrustedLaunchPolicy {
  const snapshot = snapshotInput(value);
  if (!snapshot.ok) {
    throw new LaunchPlanInputError(
      "trusted launch policy input could not be safely inspected",
    );
  }

  const definition = snapshot.value;
  if (!isRecord(definition)) {
    throw new LaunchPlanInputError("trusted launch policy must be an object");
  }
  if (Object.keys(definition).some((key) => !POLICY_PROPERTIES.has(key))) {
    throw new LaunchPlanInputError(
      "trusted launch policy must not contain undeclared properties",
    );
  }

  const piExecutable = requireLocalPath(
    definition.piExecutable,
    "Pi executable",
  );
  const piDaddyExtension = requireLocalPath(
    definition.piDaddyExtension,
    "pi-daddy grants extension",
  );
  const governanceLedgerPath = requireLocalPath(
    definition.governanceLedgerPath,
    "governance ledger",
  );
  const skillResources = copyResourceRegistry(
    definition.skillResources,
    "skill",
    SKILL_REFERENCE,
  );
  const promptTemplateResources = copyResourceRegistry(
    definition.promptTemplateResources,
    "prompt template",
    PROMPT_REFERENCE,
  );
  const systemPrompt = requireLocalPath(
    definition.systemPrompt,
    "system prompt",
  );
  const appendSystemPrompt = requireLocalPath(
    definition.appendSystemPrompt,
    "append system prompt",
  );

  requireUniquePhysicalPaths([
    piExecutable,
    piDaddyExtension,
    governanceLedgerPath,
    ...Object.values(skillResources),
    ...Object.values(promptTemplateResources),
    systemPrompt,
    appendSystemPrompt,
  ]);

  const policy: TrustedLaunchPolicy = Object.freeze({
    piExecutable,
    piDaddyExtension,
    governanceLedgerPath,
    skillResources,
    promptTemplateResources,
    systemPrompt,
    appendSystemPrompt,
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
  manifest: unknown,
  trustedPolicy: unknown,
): PiLaunchPlan {
  try {
    requireTrustedLaunchPolicy(trustedPolicy);
  } catch (error) {
    if (error instanceof LaunchPlanInputError) throw error;
    throw new LaunchPlanInputError(
      "trusted launch policy input could not be safely inspected",
    );
  }

  const validation = validateGovernedAgentExecutionManifest(manifest);
  if (!validation.valid) {
    if (
      validation.errors.some((error) => error.code === "input-introspection")
    ) {
      throw new LaunchPlanInputError(
        "manifest input could not be safely inspected",
      );
    }
    const summary = validation.errors
      .map((error) => `${error.path} ${error.message}`)
      .join("; ");
    throw new LaunchPlanInputError(`manifest is invalid: ${summary}`);
  }

  const validatedManifest = validation.value;
  const skills = resolveResources(
    validatedManifest.resources.skills,
    trustedPolicy.skillResources,
    "skill",
  );
  const promptTemplates = resolveResources(
    validatedManifest.resources.promptTemplates,
    trustedPolicy.promptTemplateResources,
    "prompt template",
  );
  const toolAllowlist = validatedManifest.tools.join(",");

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
    PI_GRANTS_GRANT: validatedManifest.piDaddyGrant,
    PI_GRANTS_MAX_DEPTH: "0" as const,
    PI_GRANTS_LEDGER: trustedPolicy.governanceLedgerPath,
  };

  return {
    executable: trustedPolicy.piExecutable,
    arguments: arguments_,
    workingDirectory: validatedManifest.repository.root,
    environment,
    redactedOperatorPreview: {
      executable: "<pi-executable>",
      arguments: [
        "--no-extensions",
        "--extension",
        "<pi-daddy-grants>",
        "--no-skills",
        ...redactedResourceArguments(
          "--skill",
          validatedManifest.resources.skills,
        ),
        "--no-prompt-templates",
        ...redactedResourceArguments(
          "--prompt-template",
          validatedManifest.resources.promptTemplates,
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
        PI_GRANTS_GRANT: validatedManifest.piDaddyGrant,
        PI_GRANTS_MAX_DEPTH: "0",
        PI_GRANTS_LEDGER: "<governance-ledger>",
      },
    },
    correlation: {
      executionId: validatedManifest.executionId,
      pacaProjectId: validatedManifest.paca.projectId,
      pacaTaskId: validatedManifest.paca.taskId,
    },
  };
}

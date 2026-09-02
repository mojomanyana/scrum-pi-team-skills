import { createHash } from "node:crypto";
export { evaluateControllerTransitionV2 } from "./controller-core-v2.js";
export * from "./controller-store-v2.js";
export { openControllerStoreV2 } from "./file-controller-store-v2.js";
export {
  canonicalizeTrustedConcreteLaunchDecisionV2,
  createPiLaunchPlanV2,
  createTrustedLaunchPolicyV2,
  digestTrustedConcreteLaunchDecisionV2,
  digestTrustedLaunchPolicyV2,
  digestTrustedToolProfileV2,
  validateTrustedConcreteLaunchDecisionV2,
  type TrustedConcreteLaunchDecisionV2,
  type TrustedLaunchInputsV2,
  type TrustedLaunchPolicyV2Definition,
} from "./launch-plan-v2.js";

export {
  createOperatorEnvironmentPolicy,
  createRuntimePolicy,
  RuntimeHostError,
  type OperatorEnvironmentPolicy,
  type OperatorEnvironmentPolicyDefinition,
  type RuntimePolicy,
  type RuntimePolicyDefinition,
} from "./policies.js";
export {
  createLocalFilesystemReceiptSink,
  inspectLifecycleReceipts,
  writeAllReceiptBytes,
  ReceiptStorageError,
  type ReceiptFileOperations,
} from "./receipt-filesystem.js";
export {
  createReceiptAuthenticator,
  ReceiptAuthenticationError,
  type ReceiptAuthenticator,
} from "./receipt-authenticator.js";
export {
  createNodeProcessAdapter,
  startGovernedLocalProcess,
  type ExecutionOutcome,
  type ExecutionResult,
  type ProcessAdapter,
  type ReceiptSink,
  type ReceiptWriter,
  type RuntimeClock,
  type StartGovernedLocalProcessOptions,
  type SupervisedExecution,
} from "./process-host.js";
export * from "./named-check-runner.js";

import {
  canonicalSerializeLifecycleValue,
  containsCredentialShapedContent,
  validateGovernedAgentExecutionManifest,
  type PromptTemplateReference,
  type SkillReference,
} from "@scrum-pi-team-skills/contracts";

export interface TrustedLaunchPolicyDefinition {
  readonly policyId: string;
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
  readonly policyId: string;
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
  "policyId",
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
const issuedTrustedPolicies = new WeakSet<object>();
const issuedLaunchPlans = new WeakMap<object, IssuedLaunchAuthority>();
const SAFE_POLICY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface IssuedLaunchAuthority {
  readonly launchPolicyId: string;
  readonly planDigest: string;
}

function requirePolicyId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !SAFE_POLICY_ID.test(value) ||
    containsCredentialShapedContent(value)
  ) {
    throw new LaunchPlanInputError("launch policy identifier is invalid");
  }
  return value;
}

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
  if (
    !isNormalizedAbsoluteWslPath(value) ||
    containsCredentialShapedContent(value)
  ) {
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
    if (
      !referencePattern.test(reference) ||
      containsCredentialShapedContent(reference)
    ) {
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

  const policyId = requirePolicyId(definition.policyId);
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
    policyId,
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

  const plan: PiLaunchPlan = {
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

  Object.freeze(plan.arguments);
  Object.freeze(plan.environment);
  Object.freeze(plan.redactedOperatorPreview.arguments);
  Object.freeze(plan.redactedOperatorPreview.environment);
  Object.freeze(plan.redactedOperatorPreview);
  Object.freeze(plan.correlation);
  Object.freeze(plan);

  const digestProjection = {
    executable: plan.executable,
    arguments: plan.arguments,
    workingDirectory: plan.workingDirectory,
    environmentNames: Object.keys(plan.environment).sort(),
    correlation: plan.correlation,
    launchPolicyId: trustedPolicy.policyId,
  };
  const planDigest = createHash("sha256")
    .update(canonicalSerializeLifecycleValue(digestProjection))
    .digest("hex");
  issuedLaunchPlans.set(
    plan,
    Object.freeze({ launchPolicyId: trustedPolicy.policyId, planDigest }),
  );
  return plan;
}

/** Fail closed unless this exact immutable object was issued by the trusted planner. */
export function requireIssuedPiLaunchPlan(
  value: unknown,
): IssuedLaunchAuthority {
  try {
    if (typeof value !== "object" || value === null) throw new TypeError();
    const authority = issuedLaunchPlans.get(value);
    if (!authority || !Object.isFrozen(value)) throw new TypeError();
    return authority;
  } catch {
    throw new LaunchPlanInputError(
      "launch plan must be issued by createPiLaunchPlan in this process",
    );
  }
}

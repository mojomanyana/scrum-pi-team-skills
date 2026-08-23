import { Ajv, type ErrorObject } from "ajv";

import agentExecutionManifestSchema from "./schemas/agent-execution-manifest.schema.json" with { type: "json" };
import executionContextSchema from "./schemas/execution-context.schema.json" with { type: "json" };

export interface ExecutionContext {
  process: "local-pi";
  governedBy: "pi-daddy";
  systemOfRecord: "paca";
}

export const AGENT_ROLES = [
  "product",
  "flow",
  "principal_developer",
  "verifier",
] as const;
export type AgentRole = (typeof AGENT_ROLES)[number];

const CANONICAL_PI_TOOL_AUTHORITY = Object.freeze([
  "read",
  "bash",
  "edit",
  "write",
  "grep",
  "find",
  "ls",
] as const);
export type PiTool = (typeof CANONICAL_PI_TOOL_AUTHORITY)[number];

export const CANONICAL_PI_TOOLS = Object.freeze([
  ...CANONICAL_PI_TOOL_AUTHORITY,
]) as typeof CANONICAL_PI_TOOL_AUTHORITY;

export type Assurance = "lean" | "standard" | "critical";
export type SkillReference = `skill:${string}`;
export type PromptTemplateReference = `prompt:${string}`;

export interface AgentExecutionManifest {
  schemaVersion: "1.0.0";
  executionId: string;
  paca: {
    projectId: string;
    taskId: string;
  };
  agent: {
    name: string;
    role: AgentRole;
  };
  repository: {
    root: string;
    expectedGitIdentity?: {
      name: string;
      email: string;
    };
  };
  executionContext: ExecutionContext;
  assurance: Assurance;
  resources: {
    skills: SkillReference[];
    promptTemplates: PromptTemplateReference[];
  };
  tools: PiTool[];
  piDaddyGrant: string;
  delegation: {
    maxDepth: 0;
  };
  authorization: {
    objective: string;
    outOfScope: string[];
    outOfScopeBehavior: "stop-and-report";
    externalEffects: "prohibited" | "explicit-user-approval-required";
  };
  receiptPolicy: {
    mode: "metadata-only";
    includeTaskContent: false;
    includePromptContent: false;
  };
}

export interface ContractValidationError {
  path: string;
  code: string;
  message: string;
}

export type ContractValidationResult<T> =
  | { valid: true; value: T }
  | { valid: false; errors: ContractValidationError[] };

const ajv = new Ajv({ allErrors: true });
ajv.addSchema(executionContextSchema);

const validateExecutionContext = ajv.compile<ExecutionContext>(
  executionContextSchema,
);
const validateManifestSchema = ajv.compile<AgentExecutionManifest>(
  agentExecutionManifestSchema,
);

const exceptionalInputError: ContractValidationError = {
  path: "/",
  code: "input-introspection",
  message: "input could not be safely inspected",
};

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

function toActionableError(error: ErrorObject): ContractValidationError {
  const missingProperty =
    error.keyword === "required"
      ? String(error.params.missingProperty)
      : undefined;
  const path =
    error.keyword === "additionalProperties"
      ? error.instancePath || "/"
      : missingProperty
        ? `${error.instancePath}/${missingProperty}`
        : error.instancePath || "/";

  let message = error.message ?? "is invalid";
  if (error.keyword === "required") {
    message = "is required";
  } else if (error.keyword === "additionalProperties") {
    message = "must not include undeclared properties";
  } else if (error.keyword === "const") {
    message += ` ${JSON.stringify(error.params.allowedValue)}`;
  } else if (error.keyword === "enum") {
    message = `must be one of ${JSON.stringify(error.params.allowedValues)}`;
  } else if (error.keyword === "uniqueItems") {
    message = "must not contain duplicate items";
  } else if (error.keyword === "pattern") {
    message = "must match the required safe format";
  } else if (error.keyword === "minItems") {
    message = `must contain at least ${String(error.params.limit)} item`;
  }

  return { path, code: error.keyword, message };
}

function fixedInputIntrospectionError(): TypeError {
  return new TypeError(exceptionalInputError.message);
}

function snapshotPiTools(value: unknown): readonly PiTool[] {
  try {
    if (!Array.isArray(value)) throw new TypeError();

    const keys = Reflect.ownKeys(value);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      !lengthDescriptor ||
      !("value" in lengthDescriptor) ||
      typeof lengthDescriptor.value !== "number" ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > CANONICAL_PI_TOOL_AUTHORITY.length
    ) {
      throw new TypeError();
    }

    const length = lengthDescriptor.value;
    const expectedKeys = new Set([
      "length",
      ...Array.from({ length }, (_, index) => String(index)),
    ]);
    if (
      keys.length !== expectedKeys.size ||
      keys.some((key) => typeof key !== "string" || !expectedKeys.has(key))
    ) {
      throw new TypeError();
    }

    const snapshot: PiTool[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
      if (
        !descriptor?.enumerable ||
        !("value" in descriptor) ||
        typeof descriptor.value !== "string" ||
        !CANONICAL_PI_TOOL_AUTHORITY.includes(descriptor.value as PiTool)
      ) {
        throw new TypeError();
      }
      snapshot.push(descriptor.value as PiTool);
    }
    return Object.freeze(snapshot);
  } catch {
    throw fixedInputIntrospectionError();
  }
}

export function derivePiDaddyGrant(tools: readonly PiTool[]): string {
  return snapshotPiTools(tools)
    .map((tool) => `tool:${tool}`)
    .join(",");
}

function hasCanonicalToolOrder(tools: readonly PiTool[]): boolean {
  let previousIndex = -1;
  for (const tool of tools) {
    const index = CANONICAL_PI_TOOL_AUTHORITY.indexOf(tool);
    if (index <= previousIndex) return false;
    previousIndex = index;
  }
  return true;
}

const CREDENTIAL_ASSIGNMENT =
  /(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+_)*(?:password|passwd|token|api[_-]?key|bearer|secret(?:[_-]access[_-]key)?)(?:[ \t]*[:=][ \t]*|[ \t]+)\S+/i;
const UNDERSCORE_PROVIDER_TOKEN =
  /(?:^|[^A-Za-z0-9])(?:sk|ghp|github_pat)_[A-Za-z0-9]+/i;
// Provider tokens are standalone, at least 20 payload characters, and include
// a long opaque alphanumeric run; ordinary hyphenated words do not qualify.
const HYPHENATED_SK_PROVIDER_TOKEN =
  /(?:^|[^A-Za-z0-9])sk-(?:(?:proj|ant-api03|ant|svcacct)-)?(?=[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-]))(?=[A-Za-z0-9_-]*[A-Za-z0-9]{16})[A-Za-z0-9_-]+/i;

/** Canonical credential-shaped string decision for governed local inputs. */
export function containsCredentialShapedContent(value: string): boolean {
  if (typeof value !== "string") return true;

  return (
    CREDENTIAL_ASSIGNMENT.test(value) ||
    UNDERSCORE_PROVIDER_TOKEN.test(value) ||
    HYPHENATED_SK_PROVIDER_TOKEN.test(value)
  );
}

function credentialError(path: string): ContractValidationError {
  return {
    path,
    code: "credential-shaped",
    message: "must not contain credential-shaped content",
  };
}

function escapeJsonPointerSegment(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function findCredentialErrors(
  value: unknown,
  path = "",
): ContractValidationError[] {
  if (typeof value === "string") {
    return containsCredentialShapedContent(value)
      ? [credentialError(path || "/")]
      : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      findCredentialErrors(item, `${path}/${String(index)}`),
    );
  }
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).flatMap(([key, item]) =>
      findCredentialErrors(item, `${path}/${escapeJsonPointerSegment(key)}`),
    );
  }
  return [];
}

/**
 * The authoritative acceptance boundary for governed local Pi execution.
 * Structural JSON Schema success alone is not authorization.
 */
export function validateGovernedAgentExecutionManifest(
  value: unknown,
): ContractValidationResult<AgentExecutionManifest> {
  const snapshot = snapshotInput(value);
  if (!snapshot.ok) {
    return { valid: false, errors: [{ ...exceptionalInputError }] };
  }

  if (!validateManifestSchema(snapshot.value)) {
    return {
      valid: false,
      errors: (validateManifestSchema.errors ?? []).map(toActionableError),
    };
  }

  const manifest = snapshot.value;
  const errors = findCredentialErrors(manifest);

  if (!hasCanonicalToolOrder(manifest.tools)) {
    errors.push({
      path: "/tools",
      code: "canonical-order",
      message: `must follow canonical Pi tool order: ${CANONICAL_PI_TOOL_AUTHORITY.join(",")}`,
    });
  }

  const expectedGrant = derivePiDaddyGrant(manifest.tools);
  if (manifest.piDaddyGrant !== expectedGrant) {
    errors.push({
      path: "/piDaddyGrant",
      code: "matching-grant",
      message: `must equal the canonical grant ${JSON.stringify(expectedGrant)}`,
    });
  }

  return errors.length === 0
    ? { valid: true, value: manifest }
    : { valid: false, errors };
}

/** @deprecated Use validateGovernedAgentExecutionManifest. */
export const validateAgentExecutionManifest =
  validateGovernedAgentExecutionManifest;

export function isGovernedAgentExecutionManifest(
  value: unknown,
): value is AgentExecutionManifest {
  return validateGovernedAgentExecutionManifest(value).valid;
}

/** @deprecated Use isGovernedAgentExecutionManifest. */
export const isAgentExecutionManifest = isGovernedAgentExecutionManifest;

export function isExecutionContext(value: unknown): value is ExecutionContext {
  const snapshot = snapshotInput(value);
  return snapshot.ok && validateExecutionContext(snapshot.value);
}

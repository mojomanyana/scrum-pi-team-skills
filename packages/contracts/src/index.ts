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

export const CANONICAL_PI_TOOLS = [
  "read",
  "bash",
  "edit",
  "write",
  "grep",
  "find",
  "ls",
] as const;
export type PiTool = (typeof CANONICAL_PI_TOOLS)[number];

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

function toActionableError(error: ErrorObject): ContractValidationError {
  const property =
    error.keyword === "required"
      ? String(error.params.missingProperty)
      : error.keyword === "additionalProperties"
        ? String(error.params.additionalProperty)
        : undefined;
  const path = property
    ? `${error.instancePath}/${property}`
    : error.instancePath || "/";

  let message = error.message ?? "is invalid";
  if (error.keyword === "required") {
    message = "is required";
  } else if (error.keyword === "additionalProperties") {
    message = `must not include undeclared property ${JSON.stringify(property)}`;
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

export function derivePiDaddyGrant(tools: readonly PiTool[]): string {
  return tools.map((tool) => `tool:${tool}`).join(",");
}

function hasCanonicalToolOrder(tools: readonly PiTool[]): boolean {
  let previousIndex = -1;
  for (const tool of tools) {
    const index = CANONICAL_PI_TOOLS.indexOf(tool);
    if (index <= previousIndex) return false;
    previousIndex = index;
  }
  return true;
}

const CREDENTIAL_SHAPE =
  /(?:\b(?:password|token|api[_-]?key)\s*[:=]\s*\S+|\bbearer(?:\s+|:\s*)\S+|(?:sk|ghp|github_pat)_[A-Za-z0-9]+)/i;

function hasCredentialShape(value: string): boolean {
  return CREDENTIAL_SHAPE.test(value);
}

function credentialError(path: string): ContractValidationError {
  return {
    path,
    code: "credential-shaped",
    message: "must not contain credential-shaped content",
  };
}

export function validateAgentExecutionManifest(
  value: unknown,
): ContractValidationResult<AgentExecutionManifest> {
  if (!validateManifestSchema(value)) {
    return {
      valid: false,
      errors: (validateManifestSchema.errors ?? []).map(toActionableError),
    };
  }

  const errors: ContractValidationError[] = [];
  if (hasCredentialShape(value.repository.root)) {
    errors.push(credentialError("/repository/root"));
  }
  if (hasCredentialShape(value.authorization.objective)) {
    errors.push(credentialError("/authorization/objective"));
  }
  value.authorization.outOfScope.forEach((item, index) => {
    if (hasCredentialShape(item)) {
      errors.push(credentialError(`/authorization/outOfScope/${index}`));
    }
  });

  if (!hasCanonicalToolOrder(value.tools)) {
    errors.push({
      path: "/tools",
      code: "canonical-order",
      message: `must follow canonical Pi tool order: ${CANONICAL_PI_TOOLS.join(",")}`,
    });
  }

  const expectedGrant = derivePiDaddyGrant(value.tools);
  if (value.piDaddyGrant !== expectedGrant) {
    errors.push({
      path: "/piDaddyGrant",
      code: "matching-grant",
      message: `must equal the canonical grant ${JSON.stringify(expectedGrant)}`,
    });
  }

  return errors.length === 0
    ? { valid: true, value }
    : { valid: false, errors };
}

export function isAgentExecutionManifest(
  value: unknown,
): value is AgentExecutionManifest {
  return validateAgentExecutionManifest(value).valid;
}

export function isExecutionContext(value: unknown): value is ExecutionContext {
  return validateExecutionContext(value);
}

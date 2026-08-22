import { Ajv } from "ajv";

import executionContextSchema from "./schemas/execution-context.schema.json" with { type: "json" };

export interface ExecutionContext {
  process: "local-pi";
  governedBy: "pi-daddy";
  systemOfRecord: "paca";
}

const ajv = new Ajv({ allErrors: true });
const validateExecutionContext = ajv.compile<ExecutionContext>(
  executionContextSchema,
);

export function isExecutionContext(value: unknown): value is ExecutionContext {
  return validateExecutionContext(value);
}

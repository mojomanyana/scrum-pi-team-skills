import { Ajv } from "ajv";
import { canonicalSerializeLifecycleValue } from "./lifecycle-receipt.js";
import schema from "./schemas/delivery-authority-v2.schema.json" with { type: "json" };
export const DELIVERY_AUTHORITY_V2_ID = "spts.delivery-authority" as const;
export const DELIVERY_AUTHORITY_V2_VERSION = "2.0.0" as const;
export const DELIVERY_AUTHORITY_V2_STATES = [
  "intake",
  "ready",
  "implementation",
  "internal-review",
  "independent-verification",
  "repair-required",
  "publication-authorized",
  "published",
  "ci-monitoring",
  "merge-gate",
  "post-merge-verification",
  "blocked",
  "cancelling",
  "completed",
  "cancelled",
  "escalated",
] as const;
export type DeliveryAuthorityV2State =
  (typeof DELIVERY_AUTHORITY_V2_STATES)[number];
export interface DeliveryIdentityV2 {
  projectId: string;
  taskId: string;
  repositoryId: string;
  runId: string;
  baseBranch: string;
  baseCommit: string;
  baseTree: string;
  headBranch: string;
  candidateCommit: string;
  candidateTree: string;
  role:
    | "product"
    | "flow"
    | "principal-developer"
    | "independent-verifier"
    | "stakeholder"
    | "controller";
  actorId: string;
  executionId: string;
  workspaceId: string;
  access:
    | "product-control"
    | "orchestrate"
    | "read-write"
    | "read-only"
    | "authorize-merge"
    | "controller";
}
export interface DeliveryMeteringV2 {
  implementationAttempts: number;
  verificationRepairCycles: number;
  ciRepairCycles: number;
  durationMinutes: number;
  concurrentAgents: number;
  worktrees: number;
  evidenceBytes: number;
}
export interface DeliveryUsageV2 {
  implementationAttempts: number;
  verificationRepairCycles: number;
  ciRepairCycles: number;
  elapsedMinutes: number;
  concurrentAgents: number;
  worktrees: number;
  evidenceBytes: number;
}
export interface DeliveryAuthorityContractV2 {
  contractId: typeof DELIVERY_AUTHORITY_V2_ID;
  contractVersion: typeof DELIVERY_AUTHORITY_V2_VERSION;
  authorityDigest: string;
  meteringDigest: string;
  controllerStateDigest: string;
  identity: DeliveryIdentityV2;
  state: DeliveryAuthorityV2State;
  limits: DeliveryMeteringV2;
  usage: DeliveryUsageV2;
  cancelled: boolean;
}
export interface TrustedDeliveryInputsV2 {
  authorityDigest: string;
  meteringDigest: string;
  controllerStateDigest: string;
  identity: DeliveryIdentityV2;
}
export type DeliveryV2Error = { path: string; code: string; message: string };
export type DeliveryV2Validation<T = DeliveryAuthorityContractV2> =
  { valid: true; value: T } | { valid: false; errors: DeliveryV2Error[] };
const validate = new Ajv({
  allErrors: true,
}).compile<DeliveryAuthorityContractV2>(schema);
function snapshot(v: unknown): unknown | null {
  try {
    return JSON.parse(canonicalSerializeLifecycleValue(v));
  } catch {
    return null;
  }
}
const bad = (
  code: string,
  message = "delivery authority v2 is invalid",
): DeliveryV2Validation => ({
  valid: false,
  errors: [{ path: "/", code, message }],
});
export function validateDeliveryAuthorityContractV2(
  value: unknown,
): DeliveryV2Validation {
  const copy = snapshot(value);
  if (copy === null) return bad("input-introspection");
  if (!validate(copy))
    return {
      valid: false,
      errors: (validate.errors ?? []).map((e) => ({
        path: e.instancePath || "/",
        code: e.keyword,
        message: "delivery authority v2 is invalid",
      })),
    };
  const c = copy as DeliveryAuthorityContractV2;
  const pairs: Array<[keyof DeliveryUsageV2, keyof DeliveryMeteringV2]> = [
    ["implementationAttempts", "implementationAttempts"],
    ["verificationRepairCycles", "verificationRepairCycles"],
    ["ciRepairCycles", "ciRepairCycles"],
    ["elapsedMinutes", "durationMinutes"],
    ["concurrentAgents", "concurrentAgents"],
    ["worktrees", "worktrees"],
    ["evidenceBytes", "evidenceBytes"],
  ];
  if (pairs.some(([u, l]) => c.usage[u] > c.limits[l]))
    return bad("autonomy-exhausted");
  return { valid: true, value: c };
}
const same = (a: unknown, b: unknown) =>
  canonicalSerializeLifecycleValue(a) === canonicalSerializeLifecycleValue(b);
export function validateFrozenDeliveryAuthorityContractV2(
  value: unknown,
  trusted: TrustedDeliveryInputsV2,
): DeliveryV2Validation {
  const result = validateDeliveryAuthorityContractV2(value);
  if (!result.valid) return result;
  const c = result.value;
  return c.authorityDigest === trusted.authorityDigest &&
    c.meteringDigest === trusted.meteringDigest &&
    c.controllerStateDigest === trusted.controllerStateDigest &&
    same(c.identity, trusted.identity)
    ? result
    : bad("trusted-identity-mismatch");
}
const transitions = new Set([
  "intake>ready",
  "ready>implementation",
  "implementation>internal-review",
  "internal-review>independent-verification",
  "independent-verification>repair-required",
  "independent-verification>publication-authorized",
  "repair-required>implementation",
  "publication-authorized>published",
  "published>ci-monitoring",
  "ci-monitoring>repair-required",
  "ci-monitoring>merge-gate",
  "merge-gate>post-merge-verification",
  "post-merge-verification>completed",
  "post-merge-verification>escalated",
  "cancelling>cancelled",
  "cancelling>escalated",
]);
export function evaluateDeliveryTransitionV2(
  contract: unknown,
  request: {
    from: DeliveryAuthorityV2State;
    to: DeliveryAuthorityV2State;
    identity: DeliveryIdentityV2;
    idempotencyKey: string;
  },
  trusted: TrustedDeliveryInputsV2,
) {
  const valid = validateFrozenDeliveryAuthorityContractV2(contract, trusted);
  if (!valid.valid)
    return {
      accepted: false,
      code: "contract-invalid" as const,
      nextState: request.from,
    };
  const c = valid.value;
  if (!same(request.identity, c.identity) || request.from !== c.state)
    return {
      accepted: false,
      code: "identity-drift" as const,
      nextState: c.state,
    };
  if (c.cancelled || c.state === "cancelling")
    return {
      accepted: false,
      code: "cancellation-sticky" as const,
      nextState: c.state,
    };
  if (!transitions.has(`${request.from}>${request.to}`))
    return {
      accepted: false,
      code: "transition-denied" as const,
      nextState: c.state,
    };
  if (
    request.to === "implementation" &&
    request.from === "ready" &&
    c.usage.implementationAttempts >= c.limits.implementationAttempts
  )
    return {
      accepted: false,
      code: "autonomy-exhausted" as const,
      nextState: c.state,
    };
  return {
    accepted: true,
    code: "accepted" as const,
    nextState: request.to,
    idempotencyKey: request.idempotencyKey,
  };
}

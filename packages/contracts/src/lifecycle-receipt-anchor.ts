import { Ajv, type ErrorObject } from "ajv";

import { containsCredentialShapedContent } from "./credential-shape.js";
import { canonicalSerializeLifecycleValue } from "./lifecycle-receipt.js";
import anchorSchema from "./schemas/lifecycle-receipt-anchor.schema.json" with { type: "json" };

export const LIFECYCLE_RECEIPT_ANCHOR_CONTRACT_ID =
  "spts.lifecycle-receipt-anchor" as const;
export const LIFECYCLE_RECEIPT_ANCHOR_VERSION = "1.0.0" as const;

export interface LifecycleReceiptAnchorPayload {
  readonly contractId: typeof LIFECYCLE_RECEIPT_ANCHOR_CONTRACT_ID;
  readonly contractVersion: typeof LIFECYCLE_RECEIPT_ANCHOR_VERSION;
  readonly executionId: string;
  readonly receiptCount: number;
  readonly terminalReceiptDigest: string;
  readonly planDigest: string;
  readonly environmentPolicyId: string;
  readonly runtimePolicyId: string;
  readonly authenticatorId: string;
}

export interface LifecycleReceiptAnchor extends LifecycleReceiptAnchorPayload {
  readonly authenticationTag: string;
}

export type LifecycleReceiptAnchorValidationResult =
  | { readonly valid: true; readonly value: LifecycleReceiptAnchor }
  | {
      readonly valid: false;
      readonly errors: ReadonlyArray<{
        readonly path: string;
        readonly code: string;
        readonly message: string;
      }>;
    };

const ajv = new Ajv({ allErrors: true });
const validateSchema = ajv.compile<LifecycleReceiptAnchor>(anchorSchema);

function anchorError(error: ErrorObject): {
  path: string;
  code: string;
  message: string;
} {
  return {
    path: error.instancePath || "/",
    code: error.keyword,
    message: error.message ?? "is invalid",
  };
}

export function lifecycleReceiptAnchorPayload(
  anchor: LifecycleReceiptAnchor,
): LifecycleReceiptAnchorPayload {
  return {
    contractId: anchor.contractId,
    contractVersion: anchor.contractVersion,
    executionId: anchor.executionId,
    receiptCount: anchor.receiptCount,
    terminalReceiptDigest: anchor.terminalReceiptDigest,
    planDigest: anchor.planDigest,
    environmentPolicyId: anchor.environmentPolicyId,
    runtimePolicyId: anchor.runtimePolicyId,
    authenticatorId: anchor.authenticatorId,
  };
}

/** Canonical HMAC input; authenticationTag is deliberately excluded. */
export function canonicalSerializeLifecycleReceiptAnchorPayload(
  payload: LifecycleReceiptAnchorPayload,
): string {
  return canonicalSerializeLifecycleValue(payload);
}

export function validateLifecycleReceiptAnchor(
  value: unknown,
): LifecycleReceiptAnchorValidationResult {
  try {
    const snapshot = JSON.parse(
      canonicalSerializeLifecycleValue(value),
    ) as LifecycleReceiptAnchor;
    if (!validateSchema(snapshot)) {
      return {
        valid: false,
        errors: (validateSchema.errors ?? []).map(anchorError),
      };
    }
    if (
      [
        snapshot.executionId,
        snapshot.environmentPolicyId,
        snapshot.runtimePolicyId,
        snapshot.authenticatorId,
      ].some(containsCredentialShapedContent)
    ) {
      return {
        valid: false,
        errors: [
          {
            path: "/",
            code: "credential-shaped",
            message:
              "anchor identity must not contain credential-shaped content",
          },
        ],
      };
    }
    return { valid: true, value: snapshot };
  } catch {
    return {
      valid: false,
      errors: [
        {
          path: "/",
          code: "input-introspection",
          message: "anchor input could not be safely inspected",
        },
      ],
    };
  }
}

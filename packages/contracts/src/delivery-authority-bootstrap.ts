import { createHash } from "node:crypto";
import { Ajv, type ErrorObject } from "ajv";
import {
  canonicalSerializeLifecycleValue,
  isCanonicalLifecycleTimestamp,
} from "./lifecycle-receipt.js";
import schema from "./schemas/delivery-authority-bootstrap.schema.json" with { type: "json" };
import {
  hasExactDeliveryV2Keys,
  snapshotDeliveryV2Input,
} from "./delivery-authority-v2-input.js";

export const DELIVERY_AUTHORITY_BOOTSTRAP_ID =
  "spts.delivery-authority-bootstrap" as const;
export const DELIVERY_AUTHORITY_BOOTSTRAP_VERSION = "1.0.0" as const;
export interface DeliveryAuthorityBootstrap {
  contractId: typeof DELIVERY_AUTHORITY_BOOTSTRAP_ID;
  contractVersion: typeof DELIVERY_AUTHORITY_BOOTSTRAP_VERSION;
  projectId: string;
  taskId: string;
  authorityAnchor: string;
  origin: string;
  taskPath: string;
  anchorPath: string;
  notBefore: string;
  expiresAt: string;
}
export type BootstrapValidationResult =
  | { valid: true; value: DeliveryAuthorityBootstrap }
  | {
      valid: false;
      errors: Array<{ path: string; code: string; message: string }>;
    };
const ajv = new Ajv({ allErrors: true, formats: { "date-time": true } });
const validate = ajv.compile<DeliveryAuthorityBootstrap>(schema);
const structural = (e: ErrorObject) => ({
  path: e.instancePath || "/",
  code: e.keyword,
  message: "bootstrap contract is invalid",
});
export function validateDeliveryAuthorityBootstrap(
  value: unknown,
): BootstrapValidationResult {
  const snapshot = snapshotDeliveryV2Input(value);
  if (!snapshot.ok)
    return {
      valid: false,
      errors: [
        {
          path: "/",
          code: snapshot.code,
          message: "bootstrap input could not be safely inspected",
        },
      ],
    };
  const frozen = snapshot.value;
  if (!validate(frozen))
    return { valid: false, errors: (validate.errors ?? []).map(structural) };
  const b = frozen as DeliveryAuthorityBootstrap;
  const originValid = (() => {
    try {
      const origin = new URL(b.origin);
      return (
        origin.protocol === "http:" &&
        origin.username === "" &&
        origin.password === "" &&
        origin.port !== "" &&
        (origin.hostname === "127.0.0.1" || origin.hostname === "[::1]") &&
        origin.pathname === "/" &&
        origin.search === "" &&
        origin.hash === "" &&
        origin.origin === b.origin
      );
    } catch {
      return false;
    }
  })();
  if (
    !originValid ||
    !isCanonicalLifecycleTimestamp(b.notBefore) ||
    !isCanonicalLifecycleTimestamp(b.expiresAt) ||
    b.notBefore >= b.expiresAt
  )
    return {
      valid: false,
      errors: [
        {
          path: "/",
          code: "time-window",
          message: "bootstrap time window is invalid",
        },
      ],
    };
  return { valid: true, value: b };
}
export function computeDeliveryAuthorityBootstrapDigest(
  value: DeliveryAuthorityBootstrap,
): string {
  return createHash("sha256")
    .update(canonicalSerializeLifecycleValue(value))
    .digest("hex");
}
export interface BootstrapReadRequest {
  method: string;
  url: string;
  redirect: boolean;
}
export type BootstrapReadDecision = {
  allowed: boolean;
  code: "accepted" | "contract-invalid" | "request-denied" | "stale-authority";
};
export function authorizeBootstrapRead(
  bootstrapInput: DeliveryAuthorityBootstrap,
  requestInput: BootstrapReadRequest,
  trustedDigestInput: string,
  trustedNowInput: string,
): BootstrapReadDecision {
  const requestSnapshot = snapshotDeliveryV2Input(requestInput);
  if (!requestSnapshot.ok) return { allowed: false, code: "request-denied" };
  const requestValue = requestSnapshot.value as Record<string, unknown>;
  if (
    !hasExactDeliveryV2Keys(requestValue, ["method", "url", "redirect"]) ||
    typeof requestValue.method !== "string" ||
    typeof requestValue.url !== "string" ||
    typeof requestValue.redirect !== "boolean"
  )
    return { allowed: false, code: "request-denied" };
  const inputs = snapshotDeliveryV2Input({
    bootstrap: bootstrapInput,
    request: requestValue,
    trustedDigest: trustedDigestInput,
    trustedNow: trustedNowInput,
  });
  if (!inputs.ok) return { allowed: false, code: "contract-invalid" };
  const { bootstrap, request, trustedDigest, trustedNow } = inputs.value as {
    bootstrap: DeliveryAuthorityBootstrap;
    request: BootstrapReadRequest;
    trustedDigest: string;
    trustedNow: string;
  };
  const checked = validateDeliveryAuthorityBootstrap(bootstrap);
  if (
    !checked.valid ||
    computeDeliveryAuthorityBootstrapDigest(checked.value) !== trustedDigest
  )
    return { allowed: false, code: "contract-invalid" };
  if (
    !isCanonicalLifecycleTimestamp(trustedNow) ||
    trustedNow < bootstrap.notBefore ||
    trustedNow >= bootstrap.expiresAt
  )
    return { allowed: false, code: "stale-authority" };
  if (
    !(["GET", "HEAD", "OPTIONS"] as string[]).includes(request.method) ||
    request.redirect ||
    typeof request.url !== "string" ||
    /%(?:2e|2f|5c)/i.test(request.url) ||
    /\/\.\.?(?:\/|$)/.test(request.url)
  )
    return { allowed: false, code: "request-denied" };
  try {
    const url = new URL(request.url);
    const exact =
      `${url.protocol}//${url.host}` === bootstrap.origin &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      (url.pathname === bootstrap.taskPath ||
        url.pathname === bootstrap.anchorPath);
    return exact
      ? { allowed: true, code: "accepted" }
      : { allowed: false, code: "request-denied" };
  } catch {
    return { allowed: false, code: "request-denied" };
  }
}

import { createHash } from "node:crypto";
import { Ajv, type ErrorObject } from "ajv";
import { canonicalSerializeLifecycleValue, isCanonicalLifecycleTimestamp } from "./lifecycle-receipt.js";
import schema from "./schemas/delivery-authority-bootstrap.schema.json" with { type: "json" };

export const DELIVERY_AUTHORITY_BOOTSTRAP_ID = "spts.delivery-authority-bootstrap" as const;
export const DELIVERY_AUTHORITY_BOOTSTRAP_VERSION = "1.0.0" as const;
export interface DeliveryAuthorityBootstrap {
  contractId: typeof DELIVERY_AUTHORITY_BOOTSTRAP_ID;
  contractVersion: typeof DELIVERY_AUTHORITY_BOOTSTRAP_VERSION;
  projectId: string; taskId: string; authorityAnchor: string; origin: string;
  taskPath: string; anchorPath: string; notBefore: string; expiresAt: string;
}
export type BootstrapValidationResult = { valid: true; value: DeliveryAuthorityBootstrap } | { valid: false; errors: Array<{path:string;code:string;message:string}> };
const ajv = new Ajv({ allErrors: true, formats: { "date-time": true } });
const validate = ajv.compile<DeliveryAuthorityBootstrap>(schema);
function snapshot(value: unknown): unknown | null {
  try {
    const seen = new WeakSet<object>(); let nodes = 0;
    const copy = (v: unknown, depth: number): unknown => {
      if (++nodes > 10000 || depth > 32) throw new TypeError();
      if (typeof v !== "object" || v === null) return v;
      if (seen.has(v)) throw new TypeError(); seen.add(v);
      try {
        if (Array.isArray(v)) return v.map(x => copy(x, depth + 1));
        if (Object.getPrototypeOf(v) !== Object.prototype) throw new TypeError();
        const out: Record<string, unknown> = {};
        for (const key of Reflect.ownKeys(v)) {
          if (typeof key !== "string") throw new TypeError();
          const d = Object.getOwnPropertyDescriptor(v, key);
          if (!d || !("value" in d)) throw new TypeError();
          Object.defineProperty(out, key, { enumerable: true, value: copy(d.value, depth + 1) });
        }
        return out;
      } finally { seen.delete(v); }
    };
    return copy(value, 0);
  } catch { return null; }
}
const structural = (e: ErrorObject) => ({ path: e.instancePath || "/", code: e.keyword, message: "bootstrap contract is invalid" });
export function validateDeliveryAuthorityBootstrap(value: unknown): BootstrapValidationResult {
  const frozen = snapshot(value);
  if (frozen === null) return { valid: false, errors: [{ path: "/", code: "input-introspection", message: "bootstrap input could not be safely inspected" }] };
  if (!validate(frozen)) return { valid: false, errors: (validate.errors ?? []).map(structural) };
  const b = frozen as DeliveryAuthorityBootstrap;
  if (!isCanonicalLifecycleTimestamp(b.notBefore) || !isCanonicalLifecycleTimestamp(b.expiresAt) || b.notBefore >= b.expiresAt)
    return { valid: false, errors: [{ path: "/", code: "time-window", message: "bootstrap time window is invalid" }] };
  return { valid: true, value: b };
}
export function computeDeliveryAuthorityBootstrapDigest(value: DeliveryAuthorityBootstrap): string {
  return createHash("sha256").update(canonicalSerializeLifecycleValue(value)).digest("hex");
}
export interface BootstrapReadRequest { method: string; url: string; redirect: boolean }
export type BootstrapReadDecision = { allowed: boolean; code: "accepted" | "contract-invalid" | "request-denied" | "stale-authority" };
export function authorizeBootstrapRead(bootstrap: DeliveryAuthorityBootstrap, request: BootstrapReadRequest, trustedDigest: string, trustedNow: string): BootstrapReadDecision {
  const checked = validateDeliveryAuthorityBootstrap(bootstrap);
  if (!checked.valid || computeDeliveryAuthorityBootstrapDigest(checked.value) !== trustedDigest) return { allowed: false, code: "contract-invalid" };
  if (!isCanonicalLifecycleTimestamp(trustedNow) || trustedNow < bootstrap.notBefore || trustedNow > bootstrap.expiresAt) return { allowed: false, code: "stale-authority" };
  if (!(["GET","HEAD","OPTIONS"] as string[]).includes(request.method) || request.redirect || typeof request.url !== "string" || /%(?:2e|2f|5c)/i.test(request.url) || /\/\.\.?(?:\/|$)/.test(request.url)) return { allowed: false, code: "request-denied" };
  try {
    const url = new URL(request.url);
    const exact = `${url.protocol}//${url.host}` === bootstrap.origin && url.username === "" && url.password === "" && url.search === "" && url.hash === "" && (url.pathname === bootstrap.taskPath || url.pathname === bootstrap.anchorPath);
    return exact ? { allowed: true, code: "accepted" } : { allowed: false, code: "request-denied" };
  } catch { return { allowed: false, code: "request-denied" }; }
}

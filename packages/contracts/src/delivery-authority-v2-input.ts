import { Buffer } from "node:buffer";
import { isProxy } from "node:util/types";
import { containsCredentialShapedContent } from "./credential-shape.js";
import { canonicalSerializeLifecycleValue } from "./lifecycle-receipt.js";

export type SafeSnapshot =
  | { ok: true; value: unknown }
  | { ok: false; code: "input-introspection" | "credential-shaped" };
const MAX_NODES = 20_000,
  MAX_DEPTH = 48,
  MAX_KEYS = 256,
  MAX_ARRAY = 2_048,
  MAX_BYTES = 2 * 1024 * 1024;
export function snapshotDeliveryV2Input(root: unknown): SafeSnapshot {
  try {
    let nodes = 0,
      bytes = 0;
    const ancestors = new WeakSet<object>();
    const copy = (value: unknown, depth: number): unknown => {
      if (++nodes > MAX_NODES || depth > MAX_DEPTH) throw new TypeError();
      if (typeof value === "string") {
        bytes += Buffer.byteLength(value);
        if (bytes > MAX_BYTES) throw new TypeError();
        if (containsCredentialShapedContent(value)) throw new RangeError();
        return value;
      }
      if (typeof value !== "object" || value === null) {
        if (typeof value === "number" && !Number.isFinite(value))
          throw new TypeError();
        return value;
      }
      if (isProxy(value) || ancestors.has(value)) throw new TypeError();
      const prototype = Object.getPrototypeOf(value);
      if (
        Array.isArray(value)
          ? prototype !== Array.prototype
          : prototype !== Object.prototype && prototype !== null
      )
        throw new TypeError();
      ancestors.add(value);
      try {
        const isArray = Array.isArray(value);
        const keys = Reflect.ownKeys(value);
        if (
          keys.length > MAX_KEYS ||
          (isArray && (value as unknown[]).length > MAX_ARRAY)
        )
          throw new TypeError();
        const out: unknown[] | Record<string, unknown> = isArray ? [] : {};
        for (const key of keys) {
          if (typeof key !== "string") throw new TypeError();
          if (key === "length") continue;
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            throw new TypeError();
          const item = copy(descriptor.value, depth + 1);
          if (isArray) {
            if (!/^(0|[1-9][0-9]*)$/.test(key)) throw new TypeError();
            (out as unknown[])[Number(key)] = item;
          } else
            Object.defineProperty(out, key, {
              enumerable: true,
              configurable: true,
              writable: true,
              value: item,
            });
        }
        return out;
      } finally {
        ancestors.delete(value);
      }
    };
    return { ok: true, value: copy(root, 0) };
  } catch (error) {
    return {
      ok: false,
      code:
        error instanceof RangeError
          ? "credential-shaped"
          : "input-introspection",
    };
  }
}
export function hasExactDeliveryV2Keys(
  value: unknown,
  keys: readonly string[],
): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  try {
    return sameDeliveryV2Value(Object.keys(value).sort(), [...keys].sort());
  } catch {
    return false;
  }
}
export function isSha1DeliveryV2(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
}
export function isSha256DeliveryV2(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
export function sameDeliveryV2Value(left: unknown, right: unknown): boolean {
  const a = snapshotDeliveryV2Input(left),
    b = snapshotDeliveryV2Input(right);
  if (!a.ok || !b.ok) return false;
  try {
    return (
      canonicalSerializeLifecycleValue(a.value) ===
      canonicalSerializeLifecycleValue(b.value)
    );
  } catch {
    return false;
  }
}

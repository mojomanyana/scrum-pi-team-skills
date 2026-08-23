import { createHmac, timingSafeEqual } from "node:crypto";

import {
  canonicalSerializeLifecycleReceiptAnchorPayload,
  containsCredentialShapedContent,
  type LifecycleReceiptAnchorPayload,
} from "@scrum-pi-team-skills/contracts";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const authenticatorKeys = new WeakMap<object, Buffer>();

export interface ReceiptAuthenticator {
  readonly authenticatorId: string;
}

export class ReceiptAuthenticationError extends Error {
  constructor() {
    super("receipt authentication configuration failed");
    this.name = "ReceiptAuthenticationError";
  }
}

function fixedAuthenticationError(): ReceiptAuthenticationError {
  return new ReceiptAuthenticationError();
}

/** Copies key bytes into private authority; no API exports key material. */
export function createReceiptAuthenticator(input: {
  readonly authenticatorId: string;
  readonly key: Uint8Array;
}): ReceiptAuthenticator {
  try {
    if (
      typeof input !== "object" ||
      input === null ||
      !SAFE_ID.test(input.authenticatorId) ||
      containsCredentialShapedContent(input.authenticatorId) ||
      !(input.key instanceof Uint8Array) ||
      input.key.byteLength < 32
    ) {
      throw new TypeError();
    }
    const key = Buffer.from(input.key);
    const authenticator = Object.freeze({
      authenticatorId: input.authenticatorId,
    });
    authenticatorKeys.set(authenticator, key);
    return authenticator;
  } catch {
    throw fixedAuthenticationError();
  }
}

function requireKey(authenticator: ReceiptAuthenticator): Buffer {
  const key = authenticatorKeys.get(authenticator);
  if (!key || !Object.isFrozen(authenticator)) throw fixedAuthenticationError();
  return key;
}

export function authenticateLifecycleReceiptAnchor(
  authenticator: ReceiptAuthenticator,
  payload: LifecycleReceiptAnchorPayload,
): string {
  return createHmac("sha256", requireKey(authenticator))
    .update(canonicalSerializeLifecycleReceiptAnchorPayload(payload))
    .digest("hex");
}

export function verifyLifecycleReceiptAnchorAuthentication(
  authenticator: ReceiptAuthenticator,
  payload: LifecycleReceiptAnchorPayload,
  authenticationTag: string,
): boolean {
  if (!/^[a-f0-9]{64}$/.test(authenticationTag)) return false;
  const expected = Buffer.from(
    authenticateLifecycleReceiptAnchor(authenticator, payload),
    "hex",
  );
  const actual = Buffer.from(authenticationTag, "hex");
  try {
    return timingSafeEqual(expected, actual);
  } finally {
    expected.fill(0);
    actual.fill(0);
  }
}

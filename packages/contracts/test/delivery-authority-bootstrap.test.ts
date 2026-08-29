import { describe, expect, it } from "vitest";
import {
  authorizeBootstrapRead,
  computeDeliveryAuthorityBootstrapDigest,
  validateDeliveryAuthorityBootstrap,
} from "../src/index.js";

const bootstrap = {
  contractId: "spts.delivery-authority-bootstrap",
  contractVersion: "1.0.0",
  projectId: "SPTS",
  taskId: "SPTS-10",
  authorityAnchor: "a".repeat(64),
  origin: "http://127.0.0.1:4815",
  taskPath: "/api/tasks/SPTS-10",
  anchorPath: "/api/tasks/SPTS-10/authority-anchor",
  notBefore: "2026-08-29T00:00:00.000Z",
  expiresAt: "2026-08-29T01:00:00.000Z",
};

describe("delivery authority bootstrap", () => {
  it("validates, digests, and authorizes exact loopback reads", () => {
    const valid = validateDeliveryAuthorityBootstrap(bootstrap);
    expect(valid.valid).toBe(true);
    if (!valid.valid) return;
    expect(computeDeliveryAuthorityBootstrapDigest(valid.value)).toMatch(
      /^[a-f0-9]{64}$/,
    );
    expect(
      authorizeBootstrapRead(
        valid.value,
        {
          method: "GET",
          url: "http://127.0.0.1:4815/api/tasks/SPTS-10",
          redirect: false,
        },
        computeDeliveryAuthorityBootstrapDigest(valid.value),
        "2026-08-29T00:30:00.000Z",
      ),
    ).toEqual({ allowed: true, code: "accepted" });
  });

  it.each([
    "http://localhost:4815/api/tasks/SPTS-10",
    "http://127.0.0.1/api/tasks/SPTS-10",
    "http://127.0.0.1:4815/api/tasks/../tasks/SPTS-10",
    "http://127.0.0.1:4815/api/tasks/%2e%2e/tasks/SPTS-10",
    "http://127.0.0.1:4815/api/tasks/SPTS-10?x=1",
    "http://[::ffff:127.0.0.1]:4815/api/tasks/SPTS-10",
  ])("rejects hostile origin or path %s", (url) => {
    const valid = validateDeliveryAuthorityBootstrap(bootstrap);
    expect(valid.valid).toBe(true);
    if (!valid.valid) return;
    expect(
      authorizeBootstrapRead(
        valid.value,
        { method: "GET", url, redirect: false },
        computeDeliveryAuthorityBootstrapDigest(valid.value),
        "2026-08-29T00:30:00.000Z",
      ).allowed,
    ).toBe(false);
  });

  it("rejects mutation, redirects, wrong time, self-claimed digest, and hostile objects", () => {
    const valid = validateDeliveryAuthorityBootstrap(bootstrap);
    expect(valid.valid).toBe(true);
    if (!valid.valid) return;
    const digest = computeDeliveryAuthorityBootstrapDigest(valid.value);
    for (const request of [
      {
        method: "POST",
        url: `${bootstrap.origin}${bootstrap.taskPath}`,
        redirect: false,
      },
      {
        method: "GET",
        url: `${bootstrap.origin}${bootstrap.taskPath}`,
        redirect: true,
      },
    ])
      expect(
        authorizeBootstrapRead(
          valid.value,
          request,
          digest,
          "2026-08-29T00:30:00.000Z",
        ).allowed,
      ).toBe(false);
    expect(
      authorizeBootstrapRead(
        valid.value,
        {
          method: "GET",
          url: `${bootstrap.origin}${bootstrap.taskPath}`,
          redirect: false,
        },
        "b".repeat(64),
        "2026-08-29T00:30:00.000Z",
      ).allowed,
    ).toBe(false);
    expect(
      authorizeBootstrapRead(
        valid.value,
        {
          method: "GET",
          url: `${bootstrap.origin}${bootstrap.taskPath}`,
          redirect: false,
        },
        digest,
        "2027-01-01T00:00:00.000Z",
      ).allowed,
    ).toBe(false);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(validateDeliveryAuthorityBootstrap(cyclic).valid).toBe(false);
  });
});

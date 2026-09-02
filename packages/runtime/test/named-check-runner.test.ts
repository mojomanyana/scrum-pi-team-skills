import { describe, expect, it } from "vitest";
import {
  createNamedCheckAuthorityV1,
  issueNamedCheckPermitV1,
  runExactNamedCheckV1,
} from "../src/named-check-runner.js";

describe("named check runner", () => {
  it("runs a pass fixture", async () => {
    const authority = createNamedCheckAuthorityV1({
      policyId: "policy-1",
      checks: [
        {
          checkId: "fixture-pass",
          executable: process.execPath,
          argv: [
            new URL("./fixtures/named-check.mjs", import.meta.url).pathname,
            "pass",
          ],
          maxDurationMs: 30000,
          maxOutputBytes: 1048576,
        },
      ],
    });
    const permit = issueNamedCheckPermitV1(authority, {
      operationId: "op-1",
      runId: "run-1",
      registrationId: "reg-1",
      checkId: "fixture-pass",
      attempt: 1,
      candidateCommit: "a".repeat(40),
      candidateTree: "b".repeat(40),
      workspaceIdentityToken: {},
      requestDigest: "d".repeat(64),
    });
    const result = await runExactNamedCheckV1({
      permit,
      cwd: process.cwd(),
      executable: process.execPath,
      argv: [
        new URL("./fixtures/named-check.mjs", import.meta.url).pathname,
        "pass",
      ],
      env: {
        HOME: process.cwd(),
        XDG_CONFIG_HOME: process.cwd(),
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        TZ: "UTC",
        CI: "1",
        NO_COLOR: "1",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_TERMINAL_PROMPT: "0",
        GCM_INTERACTIVE: "never",
        GIT_ASKPASS: "/bin/false",
        SSH_ASKPASS: "/bin/false",
        GIT_PAGER: "cat",
        PAGER: "cat",
      },
    });
    expect(result.valid).toBe(true);
  });
});

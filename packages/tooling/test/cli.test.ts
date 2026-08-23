import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import receiptExample from "../../contracts/examples/lifecycle-receipts.success.json" with { type: "json" };
import { canonicalSerializeLifecycleValue } from "../../contracts/src/index.js";
import manifestExample from "../../contracts/examples/agent-execution-manifest.principal-developer.json" with { type: "json" };
import { runCli } from "../src/index.js";

const fixture = fileURLToPath(
  new URL("../../runtime/test/fixtures/governed-process.mjs", import.meta.url),
);
const roots: string[] = [];

function setup(mode = "success", value = "0") {
  const root = join(tmpdir(), `spts-cli-${process.pid}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { recursive: true });
  const manifest = structuredClone(manifestExample);
  manifest.repository.root = process.cwd();
  manifest.paca.taskId = "SPTS-8";
  const manifestPath = join(root, "manifest.json");
  const configPath = join(root, "operator.json");
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(
    configPath,
    JSON.stringify({
      trustedLaunchPolicy: {
        policyId: `cli-launch-${mode}`,
        piExecutable: fixture,
        piDaddyExtension: "/fixture/pi-daddy.ts",
        governanceLedgerPath: "/fixture/governance.jsonl",
        skillResources: {
          "skill:build": "/fixture/skills/build.md",
          "skill:review": "/fixture/skills/review.md",
        },
        promptTemplateResources: {
          "prompt:principal-feature": "/fixture/prompts/feature.md",
        },
        systemPrompt: `/fixture/mode/${mode}`,
        appendSystemPrompt: `/fixture/value/${value}`,
      },
      environment: {
        policyId: "cli-environment",
        importNames: ["PATH", "MODEL_PROVIDER_VALUE"],
      },
      runtimePolicy: {
        policyId: "cli-runtime",
        maximumRuntimeMs: 2000,
        terminationGraceMs: 50,
        maximumArgvCount: 128,
        maximumArgvBytes: 64000,
        maximumEnvironmentEntries: 32,
        maximumEnvironmentBytes: 64000,
        maximumReceiptPayloadBytes: 4096,
        maximumListeners: 16,
      },
      receiptRoot: join(root, "receipts"),
    }),
  );
  chmodSync(fixture, 0o755);
  return { root, manifestPath, configPath };
}

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    roots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("private governed runtime CLI", () => {
  it("prints a redacted non-executable plan preview", async () => {
    const files = setup();
    const output: string[] = [];
    const code = await runCli(
      [
        "plan",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: (value) => output.push(value),
        writeError: () => {},
        readEnvironment: () => {
          throw new Error("plan must not read shell environment");
        },
      },
    );

    expect(code).toBe(0);
    expect(output.join("\n")).toContain('"executableAuthority": false');
    expect(output.join("\n")).not.toContain(fixture);
  });

  it("run imports only configured names, executes the fixture, and writes receipts", async () => {
    const files = setup("success");
    const reads: string[] = [];
    const code = await runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment(name) {
          reads.push(name);
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "OPAQUE_DO_NOT_PERSIST";
          return undefined;
        },
      },
    );

    expect(code).toBe(0);
    expect(reads).toEqual(["PATH", "MODEL_PROVIDER_VALUE"]);
    const { readdir, readFile } = await import("node:fs/promises");
    const names = await readdir(join(files.root, "receipts"));
    const receiptText = await readFile(
      join(files.root, "receipts", names[0]!),
      "utf8",
    );
    expect(receiptText).not.toContain("OPAQUE_DO_NOT_PERSIST");
  });

  it("forwards supervisor signals through the live handle and cleans listeners", async () => {
    const files = setup("delay", "10000");
    const listeners = new Map<string, () => void>();
    const removed: string[] = [];
    const run = runCli(
      [
        "run",
        "--manifest",
        files.manifestPath,
        "--operator-config",
        files.configPath,
      ],
      {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment(name) {
          if (name === "PATH") return dirname(process.execPath);
          if (name === "MODEL_PROVIDER_VALUE") return "opaque";
          return undefined;
        },
        addSignalListener(signal, listener) {
          listeners.set(signal, listener);
        },
        removeSignalListener(signal) {
          removed.push(signal);
        },
      },
    );
    while (!listeners.has("SIGINT")) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    listeners.get("SIGINT")!();

    expect(await run).toBe(11);
    expect(removed.sort()).toEqual(["SIGINT", "SIGTERM"]);
  });

  it("inspects one explicit chain and has stable help/usage codes", async () => {
    const files = setup();
    const receiptPath = join(files.root, "chain.jsonl");
    writeFileSync(
      receiptPath,
      `${receiptExample
        .map((receipt) => canonicalSerializeLifecycleValue(receipt))
        .join("\n")}\n`,
    );
    const output: string[] = [];

    expect(
      await runCli(["inspect", "--receipt-file", receiptPath], {
        writeOutput: (value) => output.push(value),
        writeError: () => {},
        readEnvironment: () => undefined,
      }),
    ).toBe(0);
    expect(output.join("\n")).toContain('"valid": true');
    expect(
      await runCli(["unknown"], {
        writeOutput: () => {},
        writeError: () => {},
        readEnvironment: () => undefined,
      }),
    ).toBe(2);
  });
});

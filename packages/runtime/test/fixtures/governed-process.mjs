#!/usr/bin/env node
import { spawn } from "node:child_process";
import { basename } from "node:path";

const input = process.argv.slice(2);
const knownModes = new Set([
  "success",
  "nonzero",
  "delay",
  "stream",
  "large",
  "large-stderr",
  "ignore-term",
  "ignore-term-ready",
  "tree",
  "leader-exit-tree",
]);
const directMode = input[0];
const systemPromptIndex = input.indexOf("--system-prompt");
const appendPromptIndex = input.indexOf("--append-system-prompt");
const mode =
  directMode && knownModes.has(directMode)
    ? directMode
    : basename(input[systemPromptIndex + 1] ?? "success");
const args =
  directMode && knownModes.has(directMode)
    ? input.slice(1)
    : [basename(input[appendPromptIndex + 1] ?? "0")];

switch (mode) {
  case "success":
    process.exitCode = 0;
    break;
  case "nonzero":
    process.exitCode = Number(args[0] ?? 7);
    break;
  case "delay":
    setTimeout(
      () => {
        process.exitCode = 0;
      },
      Number(args[0] ?? 10_000),
    );
    break;
  case "stream":
    process.stdout.write("fixture-stdout");
    process.stderr.write("fixture-stderr");
    break;
  case "large":
  case "large-stderr": {
    const bytes = Number(args[0] ?? 2_000_000);
    const chunk = Buffer.alloc(16_384, "x");
    const stream = mode === "large" ? process.stdout : process.stderr;
    let remaining = bytes;
    let first = true;
    while (remaining > 0) {
      const size = Math.min(remaining, chunk.length);
      if (!stream.write(chunk.subarray(0, size))) {
        await new Promise((resolve) => stream.once("drain", resolve));
      }
      remaining -= size;
      if (first && remaining > 0) {
        first = false;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }
    break;
  }
  case "ignore-term":
    process.on("SIGTERM", () => {});
    if (process.send) process.send("ready");
    setInterval(() => {}, 1_000);
    break;
  case "ignore-term-ready":
    process.on("SIGTERM", () => {});
    process.stdout.write("ready\n");
    setInterval(() => {}, 1_000);
    break;
  case "tree": {
    const child = spawn(
      process.execPath,
      [new URL(import.meta.url).pathname, "ignore-term"],
      {
        stdio: "ignore",
      },
    );
    process.stdout.write(`${String(child.pid)}\n`);
    process.on("SIGTERM", () => {});
    setInterval(() => {}, 1_000);
    break;
  }
  case "leader-exit-tree": {
    const child = spawn(
      process.execPath,
      [new URL(import.meta.url).pathname, "ignore-term"],
      {
        stdio: ["ignore", "ignore", "ignore", "ipc"],
      },
    );
    child.once("message", () => {
      process.stdout.write(`${String(child.pid)}\n`);
    });
    process.on("SIGTERM", () => process.exit(0));
    setInterval(() => {}, 1_000);
    break;
  }
  default:
    process.exitCode = 64;
}

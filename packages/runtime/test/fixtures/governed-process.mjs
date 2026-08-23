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
  "ignore-term",
  "tree",
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
  case "large": {
    const bytes = Number(args[0] ?? 2_000_000);
    const chunk = Buffer.alloc(16_384, "x");
    let remaining = bytes;
    while (remaining > 0) {
      const size = Math.min(remaining, chunk.length);
      if (!process.stdout.write(chunk.subarray(0, size))) {
        await new Promise((resolve) => process.stdout.once("drain", resolve));
      }
      remaining -= size;
    }
    break;
  }
  case "ignore-term":
    process.on("SIGTERM", () => {});
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
  default:
    process.exitCode = 64;
}

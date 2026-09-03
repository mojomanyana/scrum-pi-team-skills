import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";

const mode = process.argv[2];
const workspaceFile = join(process.cwd(), "named-check-fixture.txt");
const transientFile = join(process.cwd(), "named-check-transient.txt");

switch (mode) {
  case "pass":
    process.stdout.write("fixture-pass\n");
    process.exit(0);
    break;
  case "fail":
    process.stderr.write("fixture-fail\n");
    process.exit(23);
    break;
  case "mutate":
    writeFileSync(workspaceFile, "mutated\n", "utf8");
    process.exit(0);
    break;
  case "mutate-restore": {
    writeFileSync(transientFile, "transient\n", "utf8");
    rmSync(transientFile, { force: true });
    process.exit(0);
    break;
  }
  case "hang":
    setInterval(() => {}, 1000);
    break;
  case "spawn-descendant": {
    const child = spawn(
      process.execPath,
      [
        "-e",
        'globalThis.__SPTS_NAMED_CHECK_DESCENDANT__="alive";setInterval(() => {}, 1000)',
      ],
      {
        cwd: process.cwd(),
        detached: false,
        stdio: "ignore",
      },
    );
    child.unref();
    process.exit(0);
    break;
  }
  case "emit-bounded":
    process.stdout.write("bounded-stdout\n");
    process.stderr.write("bounded-stderr\n");
    process.exit(0);
    break;
  case "emit-overflow": {
    const chunk = "x".repeat(32 * 1024);
    for (let index = 0; index < 64; index += 1) {
      process.stdout.write(chunk);
    }
    process.exit(0);
    break;
  }
  case "emit-secret-error":
    process.stderr.write("api_key=sk-test-secret-value\n");
    process.exit(1);
    break;
  case "signal-self":
    process.kill(process.pid, "SIGTERM");
    break;
  default: {
    const directory = mkdtempSync(join(tmpdir(), "named-check-unknown-"));
    writeFileSync(
      join(directory, "mode.txt"),
      String(mode ?? "undefined"),
      "utf8",
    );
    process.exit(99);
  }
}

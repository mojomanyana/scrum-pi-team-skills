import { writeFileSync } from "node:fs";
const mode = process.argv[2];
if (mode === "pass") process.exit(0);
if (mode === "fail") process.exit(1);
if (mode === "hang") setInterval(() => {}, 1000);
if (mode === "mutate")
  writeFileSync(new URL("./mutated.txt", import.meta.url), "x");

import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
export type FixtureWorktreeRoleV1 =
  "principal-candidate" | "independent-verifier" | "named-check";
export interface RegisterWorktreeRequestV1 {
  readonly operationId: string;
  readonly registrationId: string;
  readonly sourceRegistrationId: string;
  readonly role: FixtureWorktreeRoleV1;
  readonly checkId: string | null;
  readonly candidateCommit: string;
  readonly candidateTree: string;
}
const reg = new Map<string, { root: string; req: RegisterWorktreeRequestV1 }>();
export function createFixtureWorktreeRegistration(
  rootPrefix = mkdtempSync(join(tmpdir(), "spts-wt-")),
) {
  mkdirSync(rootPrefix, { recursive: true });
  return rootPrefix;
}
export function registerWorktree(
  request: RegisterWorktreeRequestV1,
  root = mkdtempSync(join(tmpdir(), "spts-reg-")),
) {
  const digest = createHash("sha256")
    .update(JSON.stringify(request))
    .digest("hex");
  const path = join(root, digest);
  mkdirSync(path, { recursive: true });
  writeFileSync(join(path, "registration.json"), JSON.stringify(request));
  reg.set(digest, { root: path, req: request });
  return { registrationPath: path, registrationDigest: digest };
}

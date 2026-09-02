import { createHash } from "node:crypto";

import {
  computeGitCheckFixtureDigestV1,
  containsCredentialShapedContent,
  type RepositoryStateV1,
} from "@scrum-pi-team-skills/contracts";

export type FixtureWorktreeRoleV1 =
  "principal-candidate" | "independent-verifier" | "named-check";

export interface FixtureFileV1 {
  readonly pathComponents: readonly string[];
  readonly mode: "100644" | "100755";
  readonly content: Uint8Array;
}

export interface CreateRepositoryRequestV1 {
  readonly operationId: string;
  readonly registrationId: string;
  readonly files: readonly FixtureFileV1[];
}

export interface CreateBareRemoteRequestV1 {
  readonly operationId: string;
  readonly registrationId: string;
  readonly sourceRegistrationId: string;
}

export interface RegisterWorktreeRequestV1 {
  readonly operationId: string;
  readonly registrationId: string;
  readonly sourceRegistrationId: string;
  readonly role: FixtureWorktreeRoleV1;
  readonly checkId: string | null;
  readonly candidateCommit: string;
  readonly candidateTree: string;
}

export interface FixtureRootIdentityProofV1 {
  readonly pathDigest: string;
  readonly device: number;
  readonly inode: number;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
  readonly nlink: number;
  readonly mountDigest: string;
}

export interface FixtureRegistrationRecordV1 {
  readonly contract: "spts.fixture-registration-record";
  readonly version: "1.0.0";
  readonly registrationId: string;
  readonly registrationDigest: string;
  readonly sourceRegistrationId: string | null;
  readonly role: FixtureWorktreeRoleV1 | "fixture-remote";
  readonly checkId: string | null;
  readonly candidateCommit: string | null;
  readonly candidateTree: string | null;
  readonly commonDirectoryDigest: string;
  readonly workspacePathDigest: string;
  readonly adminDirectoryDigest: string;
  readonly rootIdentity: FixtureRootIdentityProofV1;
  readonly state: "active" | "cleanup-pending" | "retained" | "removed";
  readonly generation: number;
  readonly previousDigest: string | null;
  readonly recordDigest: string;
}

export interface ObservedWorkspaceStateV1 {
  readonly repositoryState: RepositoryStateV1;
  readonly workspaceTree: string;
}

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const WINDOWS_RESERVED = new Set([
  "con",
  "prn",
  "aux",
  "nul",
  "com1",
  "com2",
  "com3",
  "com4",
  "com5",
  "com6",
  "com7",
  "com8",
  "com9",
  "lpt1",
  "lpt2",
  "lpt3",
  "lpt4",
  "lpt5",
  "lpt6",
  "lpt7",
  "lpt8",
  "lpt9",
]);

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function validateSafeId(label: string, value: unknown): string {
  if (
    typeof value !== "string" ||
    !SAFE_ID_PATTERN.test(value) ||
    utf8Bytes(value) > 128 ||
    containsCredentialShapedContent(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateObjectId(label: string, value: unknown): string {
  if (typeof value !== "string" || !OBJECT_ID_PATTERN.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateDigest(label: string, value: unknown): string {
  if (typeof value !== "string" || !SHA256_HEX_PATTERN.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateSafeInteger(label: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateFixtureRootIdentityProof(
  value: unknown,
): FixtureRootIdentityProofV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("rootIdentity is invalid");
  }
  const rootIdentity = value as Record<string, unknown>;
  return Object.freeze({
    pathDigest: validateDigest(
      "rootIdentity.pathDigest",
      rootIdentity.pathDigest,
    ),
    device: validateSafeInteger("rootIdentity.device", rootIdentity.device),
    inode: validateSafeInteger("rootIdentity.inode", rootIdentity.inode),
    uid: validateSafeInteger("rootIdentity.uid", rootIdentity.uid),
    gid: validateSafeInteger("rootIdentity.gid", rootIdentity.gid),
    mode: validateSafeInteger("rootIdentity.mode", rootIdentity.mode),
    nlink: validateSafeInteger("rootIdentity.nlink", rootIdentity.nlink),
    mountDigest: validateDigest(
      "rootIdentity.mountDigest",
      rootIdentity.mountDigest,
    ),
  });
}

function validateFixtureComponent(component: unknown): string {
  if (typeof component !== "string") {
    throw new TypeError("fixture path component is invalid");
  }
  if (
    component.length === 0 ||
    component === "." ||
    component === ".." ||
    component !== component.normalize("NFC") ||
    hasControlCharacter(component) ||
    component.includes("/") ||
    component.includes("\\") ||
    component.includes("\0") ||
    component.startsWith(" ") ||
    component.endsWith(" ") ||
    component.startsWith(".") ||
    component.endsWith(".") ||
    utf8Bytes(component) > 255
  ) {
    throw new TypeError("fixture path component is invalid");
  }
  const folded = component.toLowerCase();
  if (
    folded === ".git" ||
    folded === ".gitmodules" ||
    folded === ".gitattributes" ||
    folded === ".mailmap" ||
    folded === ".gitignore" ||
    WINDOWS_RESERVED.has(folded)
  ) {
    throw new TypeError("fixture path component is invalid");
  }
  return component;
}

export function validateFixturePathComponentsV1(
  value: unknown,
): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) {
    throw new TypeError("fixture path components are invalid");
  }
  const components = value.map((component) =>
    validateFixtureComponent(component),
  );
  const projection = components.map((component) =>
    component.normalize("NFC").toLowerCase(),
  );
  if (new Set(projection).size !== projection.length) {
    throw new TypeError("fixture path components are invalid");
  }
  return Object.freeze(components);
}

function stableBufferCopy(value: Uint8Array): Uint8Array {
  const initialLength = value.byteLength;
  const copy = new Uint8Array(initialLength);
  copy.set(value);
  if (value.byteLength !== initialLength) {
    throw new TypeError("fixture file content changed during copy");
  }
  return copy;
}

export function snapshotFixtureFileV1(value: unknown): Readonly<FixtureFileV1> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("fixture file is invalid");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== 3 ||
    !Object.hasOwn(value, "pathComponents") ||
    !Object.hasOwn(value, "mode") ||
    !Object.hasOwn(value, "content") ||
    ownKeys.some((key) => typeof key !== "string")
  ) {
    throw new TypeError("fixture file is invalid");
  }
  const pathComponents = validateFixturePathComponentsV1(
    (value as { pathComponents: unknown }).pathComponents,
  );
  const mode = (value as { mode: unknown }).mode;
  if (mode !== "100644" && mode !== "100755") {
    throw new TypeError("fixture file mode is invalid");
  }
  const content = (value as { content: unknown }).content;
  if (!(content instanceof Uint8Array)) {
    throw new TypeError("fixture file content is invalid");
  }
  return Object.freeze({
    pathComponents,
    mode,
    content: stableBufferCopy(content),
  });
}

export function snapshotFixtureFilesV1(
  value: unknown,
): readonly Readonly<FixtureFileV1>[] {
  if (!Array.isArray(value) || value.length > 256) {
    throw new TypeError("fixture files are invalid");
  }
  const files = value.map((entry) => snapshotFixtureFileV1(entry));
  let totalBytes = 0;
  const aliases = new Set<string>();
  for (const file of files) {
    totalBytes += file.content.byteLength;
    if (file.content.byteLength > 1024 * 1024 || totalBytes > 8 * 1024 * 1024) {
      throw new TypeError("fixture files exceed the permitted size");
    }
    const alias = file.pathComponents
      .map((component) => component.normalize("NFC").toLowerCase())
      .join("/");
    if (aliases.has(alias))
      throw new TypeError("fixture files contain aliases");
    aliases.add(alias);
  }
  return Object.freeze(files);
}

export function registrationDigestV1(
  request:
    | Readonly<RegisterWorktreeRequestV1>
    | Readonly<Pick<FixtureRegistrationRecordV1, "registrationId">>,
): string {
  return createHash("sha256")
    .update(
      typeof request === "object" &&
        request !== null &&
        "registrationId" in request
        ? request.registrationId
        : "",
      "utf8",
    )
    .digest("hex");
}

export function createRegistrationRecordV1(input: {
  readonly registrationId: string;
  readonly sourceRegistrationId: string | null;
  readonly role: FixtureRegistrationRecordV1["role"];
  readonly checkId: string | null;
  readonly candidateCommit: string | null;
  readonly candidateTree: string | null;
  readonly commonDirectoryDigest: string;
  readonly workspacePathDigest: string;
  readonly adminDirectoryDigest: string;
  readonly rootIdentity: FixtureRootIdentityProofV1;
  readonly state: FixtureRegistrationRecordV1["state"];
  readonly generation: number;
  readonly previousDigest: string | null;
}): Readonly<FixtureRegistrationRecordV1> {
  validateSafeId("registrationId", input.registrationId);
  if (input.sourceRegistrationId !== null) {
    validateSafeId("sourceRegistrationId", input.sourceRegistrationId);
  }
  if (input.checkId !== null) validateSafeId("checkId", input.checkId);
  if (input.candidateCommit !== null) {
    validateObjectId("candidateCommit", input.candidateCommit);
  }
  if (input.candidateTree !== null)
    validateObjectId("candidateTree", input.candidateTree);
  const rootIdentity = validateFixtureRootIdentityProof(input.rootIdentity);
  const registrationDigest = registrationDigestV1({
    registrationId: input.registrationId,
  });
  const unsigned = {
    contract: "spts.fixture-registration-record" as const,
    version: "1.0.0" as const,
    registrationId: input.registrationId,
    registrationDigest,
    sourceRegistrationId: input.sourceRegistrationId,
    role: input.role,
    checkId: input.checkId,
    candidateCommit: input.candidateCommit,
    candidateTree: input.candidateTree,
    commonDirectoryDigest: input.commonDirectoryDigest,
    workspacePathDigest: input.workspacePathDigest,
    adminDirectoryDigest: input.adminDirectoryDigest,
    rootIdentity,
    state: input.state,
    generation: input.generation,
    previousDigest: input.previousDigest,
  };
  const recordDigest = computeGitCheckFixtureDigestV1(
    "spts.fixture-registration-record/1.0.0",
    unsigned,
  );
  return Object.freeze({
    ...unsigned,
    recordDigest,
  });
}

export function createFixtureWorktreeRegistration(rootPrefix: string): string {
  return rootPrefix;
}

export function registerWorktree(
  request: RegisterWorktreeRequestV1,
  root = "/tmp/spts-worktree-compat",
): { readonly registrationPath: string; readonly registrationDigest: string } {
  validateSafeId("operationId", request.operationId);
  validateSafeId("registrationId", request.registrationId);
  validateSafeId("sourceRegistrationId", request.sourceRegistrationId);
  validateObjectId("candidateCommit", request.candidateCommit);
  validateObjectId("candidateTree", request.candidateTree);
  if (request.role === "named-check" && request.checkId === null) {
    throw new TypeError("named-check worktrees require a check identifier");
  }
  if (request.checkId !== null) validateSafeId("checkId", request.checkId);
  const registrationDigest = registrationDigestV1(request);
  const registrationPath = `${root}/${registrationDigest}`;
  return Object.freeze({ registrationPath, registrationDigest });
}

export function digestRelativePathV1(components: readonly string[]): string {
  return computeGitCheckFixtureDigestV1("spts.fixture-path/1.0.0", components);
}

export function hashWorkspaceObservationV1(value: unknown): string {
  return computeGitCheckFixtureDigestV1(
    "spts.fixture-worktree-set/1.0.0",
    value,
  );
}

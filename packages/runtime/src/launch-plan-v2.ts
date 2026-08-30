import {
  canonical,
  validateAgentExecutionManifestV2,
  credentialFree,
  deepFreeze,
  exact,
  failure,
  ID,
  isObject,
  SHA,
  SHA1,
  sha256,
  snapshot,
  timestamp,
  type AgentExecutionManifestV2,
  type DeliveryIdentityV2,
  type ValidationResult,
} from "@scrum-pi-team-skills/contracts";

export interface TrustedLaunchInputsV2 {
  expectedControllerDecisionDigest: string;
  expectedControllerStateDigest: string;
  expectedCurrentDeliveryIdentity: DeliveryIdentityV2;
  expectedLaunchPolicyDigest: string;
  expectedToolProfileDigest: string;
  expectedIsolationAttestationDigest: string;
  trustedObservedAt: string;
  source: "controlled-test" | "authenticated-controller-store";
}
export interface TrustedConcreteLaunchDecisionV2 {
  decisionId: string;
  decisionDigest: string;
  controllerRevision: number;
  controllerStateDigest: string;
  effect: {
    kind: "real-pi-execution";
    slice1EffectKind:
      | "launch-principal"
      | "launch-verifier"
      | "controller-authorized-role-launch";
    requestDigest: string;
    outcome: "allowed" | "denied";
  };
  identity: DeliveryIdentityV2;
  executionMode: "run" | "ad-hoc";
  grantReference: {
    kind: string;
    referenceId: string;
    referenceDigest: string;
  };
  packetDigest: string;
  manifestDigest: string;
  launchPolicyId: string;
  launchPolicyDigest: string;
  toolProfileId: string;
  toolProfileDigest: string;
  resultExtensionPolicyId: string;
  resultExtensionPolicyDigest: string;
  isolationAttestationId: string;
  isolationAttestationDigest: string;
  attempt: number;
  idempotencyKey: string;
  issuedAt: string;
  notBefore: string;
  expiresAt: string;
  observedAt: string;
  outcome: "allowed" | "denied";
}
export interface TrustedLaunchPolicyV2Definition {
  policyId: string;
  piExecutable: string;
  extensions: { identity: string; path: string; digest: string }[];
  skills: Record<string, string>;
  promptTemplates: Record<string, string>;
  systemPrompt: string;
  appendSystemPrompt: string;
  packetInstruction: string;
  roles: Record<
    string,
    {
      toolProfileId: string;
      workspaceProfileId: string;
      tools: string[];
      profileDigest: string;
    }
  >;
}

const decisionKeys = [
  "decisionId",
  "decisionDigest",
  "controllerRevision",
  "controllerStateDigest",
  "effect",
  "identity",
  "executionMode",
  "grantReference",
  "packetDigest",
  "manifestDigest",
  "launchPolicyId",
  "launchPolicyDigest",
  "toolProfileId",
  "toolProfileDigest",
  "resultExtensionPolicyId",
  "resultExtensionPolicyDigest",
  "isolationAttestationId",
  "isolationAttestationDigest",
  "attempt",
  "idempotencyKey",
  "issuedAt",
  "notBefore",
  "expiresAt",
  "observedAt",
  "outcome",
] as const;
const identityKeys = [
  "projectId",
  "taskId",
  "repositoryId",
  "runId",
  "baseBranch",
  "baseCommit",
  "baseTree",
  "headBranch",
  "candidateCommit",
  "candidateTree",
  "role",
  "actorId",
  "executionId",
  "workspaceId",
  "access",
] as const;
const trustedKeys = [
  "expectedControllerDecisionDigest",
  "expectedControllerStateDigest",
  "expectedCurrentDeliveryIdentity",
  "expectedLaunchPolicyDigest",
  "expectedToolProfileDigest",
  "expectedIsolationAttestationDigest",
  "trustedObservedAt",
  "source",
] as const;
const roles = [
  "product",
  "flow",
  "principal-developer",
  "independent-verifier",
] as const;
const fixed = {
  product: [
    "product-v2",
    "read-only-v2",
    ["read", "grep", "find", "ls", "flow_submit_result"],
  ],
  flow: [
    "flow-v2",
    "read-only-v2",
    ["read", "grep", "find", "ls", "flow_submit_result"],
  ],
  "principal-developer": [
    "principal-developer-v2",
    "bounded-writer-v2",
    ["read", "grep", "find", "ls", "bash", "flow_submit_result"],
  ],
  "independent-verifier": [
    "independent-verifier-v2",
    "fresh-detached-read-only-v2",
    ["read", "grep", "find", "ls", "flow_submit_result"],
  ],
} as const;
const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);
const absolutePath = (x: unknown): x is string =>
  typeof x === "string" &&
  x.length > 1 &&
  x.startsWith("/") &&
  !x.endsWith("/") &&
  !x.includes("//") &&
  !x.includes("\\") &&
  // eslint-disable-next-line no-control-regex -- reject control bytes in trusted filesystem paths
  !/[\x00-\x1f\x7f]/.test(x) &&
  !x.split("/").some((s) => s === "." || s === "..");
const ids = (x: unknown) => typeof x === "string" && ID.test(x);
const hashes = (x: unknown) => typeof x === "string" && SHA.test(x);
const sha1s = (x: unknown) => typeof x === "string" && SHA1.test(x);
const branches = (x: unknown): x is string =>
  typeof x === "string" &&
  ID.test(x) &&
  !x.startsWith("-") &&
  !x.startsWith("/") &&
  !x.endsWith("/") &&
  !x.endsWith(".") &&
  !x.includes("..") &&
  !x.includes("//") &&
  !x.includes("@{") &&
  !x.includes(":") &&
  // eslint-disable-next-line no-control-regex -- Git ref names cannot contain control bytes
  !/[\x00-\x20\x7f]/.test(x);
const identityRoleAccess = {
  product: "product-control",
  flow: "orchestrate",
  "principal-developer": "read-write",
  "independent-verifier": "read-only",
} as const;
const validLaunchIdentity = (x: DeliveryIdentityV2): boolean =>
  [
    x.projectId,
    x.taskId,
    x.repositoryId,
    x.runId,
    x.actorId,
    x.executionId,
    x.workspaceId,
  ].every(ids) &&
  branches(x.baseBranch) &&
  branches(x.headBranch) &&
  [x.baseCommit, x.baseTree, x.candidateCommit, x.candidateTree].every(sha1s) &&
  Object.hasOwn(identityRoleAccess, x.role) &&
  identityRoleAccess[x.role as keyof typeof identityRoleAccess] === x.access;

export function digestTrustedConcreteLaunchDecisionV2(
  input: Omit<TrustedConcreteLaunchDecisionV2, "decisionDigest">,
): ValidationResult<string> {
  const q = snapshot(input);
  return q.valid
    ? { valid: true, value: sha256(q.value, "decisionDigest") }
    : (q as ValidationResult<string>);
}
export function digestTrustedLaunchPolicyV2(
  input: unknown,
): ValidationResult<string> {
  const r = createTrustedLaunchPolicyV2(input);
  return r.valid
    ? { valid: true, value: sha256(r.value, "__none__") }
    : (r as ValidationResult<string>);
}
export function digestTrustedToolProfileV2(
  input: unknown,
): ValidationResult<string> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<string>;
  const x = q.value as Record<string, unknown>;
  if (
    !exact(x, ["toolProfileId", "workspaceProfileId", "tools"]) ||
    !ids(x.toolProfileId) ||
    !ids(x.workspaceProfileId) ||
    !Array.isArray(x.tools) ||
    !x.tools.every(ids)
  )
    return failure("schema");
  return { valid: true, value: sha256(x, "profileDigest") };
}

export function canonicalizeTrustedConcreteLaunchDecisionV2(
  input: unknown,
): ValidationResult<TrustedConcreteLaunchDecisionV2> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<TrustedConcreteLaunchDecisionV2>;
  const x = q.value as unknown as TrustedConcreteLaunchDecisionV2;
  if (
    !exact(q.value as Record<string, unknown>, decisionKeys) ||
    !isObject(x.effect) ||
    !exact(x.effect as unknown as Record<string, unknown>, [
      "kind",
      "slice1EffectKind",
      "requestDigest",
      "outcome",
    ]) ||
    !isObject(x.identity) ||
    !exact(x.identity as unknown as Record<string, unknown>, identityKeys) ||
    !isObject(x.grantReference) ||
    !exact(x.grantReference as unknown as Record<string, unknown>, [
      "kind",
      "referenceId",
      "referenceDigest",
    ])
  )
    return failure("schema");
  const stringIds = [
    x.decisionId,
    x.launchPolicyId,
    x.toolProfileId,
    x.resultExtensionPolicyId,
    x.isolationAttestationId,
    x.idempotencyKey,
    x.grantReference.kind,
    x.grantReference.referenceId,
  ];
  const digestValues = [
    x.decisionDigest,
    x.controllerStateDigest,
    x.effect.requestDigest,
    x.grantReference.referenceDigest,
    x.packetDigest,
    x.manifestDigest,
    x.launchPolicyDigest,
    x.toolProfileDigest,
    x.resultExtensionPolicyDigest,
    x.isolationAttestationDigest,
  ];
  if (
    !stringIds.every(ids) ||
    !digestValues.every(hashes) ||
    !Number.isSafeInteger(x.controllerRevision) ||
    x.controllerRevision < 0 ||
    !Number.isSafeInteger(x.attempt) ||
    x.attempt < 1 ||
    !validLaunchIdentity(x.identity) ||
    !roles.includes(x.identity.role as (typeof roles)[number]) ||
    !timestamp(x.issuedAt) ||
    !timestamp(x.notBefore) ||
    !timestamp(x.observedAt) ||
    !timestamp(x.expiresAt) ||
    x.issuedAt > x.notBefore ||
    x.notBefore > x.observedAt ||
    x.observedAt > x.expiresAt ||
    x.effect.kind !== "real-pi-execution" ||
    ![
      "launch-principal",
      "launch-verifier",
      "controller-authorized-role-launch",
    ].includes(x.effect.slice1EffectKind) ||
    (x.executionMode !== "run" && x.executionMode !== "ad-hoc") ||
    x.outcome !== "allowed" ||
    x.effect.outcome !== "allowed" ||
    !credentialFree(x)
  )
    return failure("schema");
  const expectedEffect =
    x.identity.role === "principal-developer"
      ? "launch-principal"
      : x.identity.role === "independent-verifier"
        ? "launch-verifier"
        : "controller-authorized-role-launch";
  const expectedWorkspace = fixed[x.identity.role as keyof typeof fixed]?.[1];
  if (
    x.effect.slice1EffectKind !== expectedEffect ||
    x.identity.workspaceId.length === 0 ||
    !expectedWorkspace ||
    x.decisionDigest !== sha256(x, "decisionDigest")
  )
    return failure(
      x.decisionDigest !== sha256(x, "decisionDigest")
        ? "digest-mismatch"
        : "schema",
    );
  return { valid: true, value: deepFreeze(x) };
}
function canonicalizeTrustedInputs(
  input: unknown,
): ValidationResult<TrustedLaunchInputsV2> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<TrustedLaunchInputsV2>;
  const x = q.value as unknown as TrustedLaunchInputsV2;
  if (
    !exact(q.value as Record<string, unknown>, trustedKeys) ||
    !isObject(x.expectedCurrentDeliveryIdentity) ||
    !exact(
      x.expectedCurrentDeliveryIdentity as unknown as Record<string, unknown>,
      identityKeys,
    ) ||
    !validLaunchIdentity(x.expectedCurrentDeliveryIdentity) ||
    ![
      x.expectedControllerDecisionDigest,
      x.expectedControllerStateDigest,
      x.expectedLaunchPolicyDigest,
      x.expectedToolProfileDigest,
      x.expectedIsolationAttestationDigest,
    ].every(hashes) ||
    !timestamp(x.trustedObservedAt) ||
    !["controlled-test", "authenticated-controller-store"].includes(x.source)
  )
    return failure("schema");
  return { valid: true, value: deepFreeze(x) };
}
export function validateTrustedConcreteLaunchDecisionV2(
  input: unknown,
  trustedInput: TrustedLaunchInputsV2,
): ValidationResult<TrustedConcreteLaunchDecisionV2> {
  const d = canonicalizeTrustedConcreteLaunchDecisionV2(input);
  if (!d.valid) return d;
  const t = canonicalizeTrustedInputs(trustedInput);
  if (!t.valid) return t as ValidationResult<TrustedConcreteLaunchDecisionV2>;
  const checks = [
    d.value.decisionDigest === t.value.expectedControllerDecisionDigest,
    d.value.controllerStateDigest === t.value.expectedControllerStateDigest,
    same(d.value.identity, t.value.expectedCurrentDeliveryIdentity),
    d.value.launchPolicyDigest === t.value.expectedLaunchPolicyDigest,
    d.value.toolProfileDigest === t.value.expectedToolProfileDigest,
    d.value.isolationAttestationDigest ===
      t.value.expectedIsolationAttestationDigest,
    d.value.observedAt === t.value.trustedObservedAt,
  ];
  return checks.every(Boolean) ? d : failure("trusted-provenance");
}

export function createTrustedLaunchPolicyV2(
  input: unknown,
): ValidationResult<TrustedLaunchPolicyV2Definition> {
  const q = snapshot(input);
  if (!q.valid) return q as ValidationResult<TrustedLaunchPolicyV2Definition>;
  const p = q.value as unknown as TrustedLaunchPolicyV2Definition;
  if (
    !exact(q.value as Record<string, unknown>, [
      "policyId",
      "piExecutable",
      "extensions",
      "skills",
      "promptTemplates",
      "systemPrompt",
      "appendSystemPrompt",
      "packetInstruction",
      "roles",
    ]) ||
    !ids(p.policyId) ||
    !absolutePath(p.piExecutable) ||
    !absolutePath(p.systemPrompt) ||
    !absolutePath(p.appendSystemPrompt) ||
    typeof p.packetInstruction !== "string" ||
    p.packetInstruction.length < 1 ||
    p.packetInstruction.length > 4096 ||
    !Array.isArray(p.extensions) ||
    p.extensions.length !== 2 ||
    !isObject(p.skills) ||
    !isObject(p.promptTemplates) ||
    !isObject(p.roles) ||
    !credentialFree(p)
  )
    return failure("schema");
  if (
    Object.keys(p.roles).sort().join() !== [...roles].sort().join() ||
    !Object.entries(p.skills).every(([k, v]) => ids(k) && absolutePath(v)) ||
    !Object.entries(p.promptTemplates).every(
      ([k, v]) => ids(k) && absolutePath(v),
    )
  )
    return failure("schema");
  for (let i = 0; i < 2; i++) {
    const e = p.extensions[i];
    if (
      !isObject(e) ||
      !exact(e as unknown as Record<string, unknown>, [
        "identity",
        "path",
        "digest",
      ]) ||
      !absolutePath(e.path) ||
      !hashes(e.digest)
    )
      return failure("schema");
  }
  if (
    p.extensions[0]!.identity !== "spts.pi-daddy-grants" ||
    p.extensions[1]!.identity !== "spts.flow-submit-result"
  )
    return failure("schema");
  for (const role of roles) {
    const row = p.roles[role];
    const f = fixed[role];
    if (
      !isObject(row) ||
      !exact(row as unknown as Record<string, unknown>, [
        "toolProfileId",
        "workspaceProfileId",
        "tools",
        "profileDigest",
      ]) ||
      row.toolProfileId !== f[0] ||
      row.workspaceProfileId !== f[1] ||
      !same(row.tools, f[2]) ||
      !hashes(row.profileDigest) ||
      row.profileDigest !==
        sha256(
          {
            toolProfileId: row.toolProfileId,
            workspaceProfileId: row.workspaceProfileId,
            tools: row.tools,
          },
          "profileDigest",
        )
    )
      return failure("tool-policy");
  }
  return { valid: true, value: deepFreeze(p) };
}

const manifestKeys = [
  "contractId",
  "schemaVersion",
  "manifestId",
  "manifestDigest",
  "packet",
  "role",
  "actorId",
  "executionId",
  "workspaceId",
  "access",
  "resources",
  "toolProfileId",
  "workspaceProfileId",
  "tools",
  "resultProtocol",
] as const;
const policyKeys = [
  "policyId",
  "piExecutable",
  "extensions",
  "skills",
  "promptTemplates",
  "systemPrompt",
  "appendSystemPrompt",
  "packetInstruction",
  "roles",
] as const;
const strings = (x: unknown): x is string => typeof x === "string";
const stringArray = (x: unknown): x is string[] =>
  Array.isArray(x) && x.every(strings);
const closed = (
  x: unknown,
  keys: readonly string[],
): x is Record<string, unknown> =>
  isObject(x) && exact(x as Record<string, unknown>, keys);

/* Stage 1 deliberately checks only closed shape and primitive kinds.  Keeping it
 * separate prevents a semantic error in one source from hiding malformed later
 * authority. */
function manifestStage1(x: unknown): boolean {
  if (!closed(x, manifestKeys)) return false;
  const m = x as Record<string, unknown>,
    p = m.packet;
  if (
    !closed(m.resources, ["skills", "promptTemplates"]) ||
    !stringArray((m.resources as Record<string, unknown>).skills) ||
    !stringArray((m.resources as Record<string, unknown>).promptTemplates) ||
    !stringArray(m.tools) ||
    !closed(m.resultProtocol, [
      "toolName",
      "contractId",
      "schemaVersion",
      "minimum",
      "maximum",
    ]) ||
    !closed(p, [
      "contractId",
      "schemaVersion",
      "packetId",
      "packetDigest",
      "issuedAt",
      "task",
      "repository",
      "run",
      "subject",
      "assurance",
      "authorityDigest",
      "controllerStateDigest",
      "work",
    ])
  )
    return false;
  const packet = p as Record<string, unknown>;
  const rows: [unknown, readonly string[]][] = [
    [packet.task, ["projectId", "taskId", "sliceId"]],
    [
      packet.repository,
      [
        "repositoryId",
        "rootId",
        "baseBranch",
        "headBranch",
        "baseCommit",
        "baseTree",
        "candidateCommit",
        "candidateTree",
      ],
    ],
    [
      packet.run,
      Object.hasOwn(packet.run as object, "parentExecutionId")
        ? ["runId", "parentExecutionId"]
        : ["runId"],
    ],
    [
      packet.subject,
      ["role", "actorId", "executionId", "workspaceId", "access"],
    ],
    [packet.assurance, ["profile", "phase"]],
    [
      packet.work,
      [
        "objective",
        "acceptanceCriteria",
        "allowedPaths",
        "outOfScope",
        "resources",
      ],
    ],
  ];
  if (!rows.every(([v, k]) => closed(v, k))) return false;
  const work = packet.work as Record<string, unknown>;
  return (
    closed(work.resources, ["skills", "promptTemplates"]) &&
    [
      work.acceptanceCriteria,
      work.allowedPaths,
      work.outOfScope,
      (work.resources as Record<string, unknown>).skills,
      (work.resources as Record<string, unknown>).promptTemplates,
    ].every(stringArray) &&
    Object.entries(m)
      .filter(
        ([k]) =>
          !["packet", "resources", "tools", "resultProtocol"].includes(k),
      )
      .every(([, v]) => strings(v)) &&
    Object.entries(packet)
      .filter(
        ([k]) =>
          ![
            "task",
            "repository",
            "run",
            "subject",
            "assurance",
            "work",
          ].includes(k),
      )
      .every(([, v]) => strings(v)) &&
    rows
      .slice(0, 5)
      .every(([v]) =>
        Object.values(v as Record<string, unknown>).every(strings),
      ) &&
    strings(work.objective) &&
    ["toolName", "contractId", "schemaVersion"].every((k) =>
      strings((m.resultProtocol as Record<string, unknown>)[k]),
    ) &&
    typeof (m.resultProtocol as Record<string, unknown>).minimum === "number" &&
    typeof (m.resultProtocol as Record<string, unknown>).maximum === "number"
  );
}
function decisionStage1(x: unknown): boolean {
  if (!closed(x, decisionKeys)) return false;
  const d = x as Record<string, unknown>;
  return (
    closed(d.effect, [
      "kind",
      "slice1EffectKind",
      "requestDigest",
      "outcome",
    ]) &&
    closed(d.identity, identityKeys) &&
    closed(d.grantReference, ["kind", "referenceId", "referenceDigest"]) &&
    Object.values(d.effect as Record<string, unknown>).every(strings) &&
    Object.values(d.identity as Record<string, unknown>).every(strings) &&
    Object.values(d.grantReference as Record<string, unknown>).every(strings) &&
    Object.entries(d)
      .filter(
        ([k]) =>
          ![
            "effect",
            "identity",
            "grantReference",
            "controllerRevision",
            "attempt",
          ].includes(k),
      )
      .every(([, v]) => strings(v)) &&
    typeof d.controllerRevision === "number" &&
    typeof d.attempt === "number"
  );
}
function trustedStage1(x: unknown): boolean {
  if (!closed(x, trustedKeys)) return false;
  const t = x as Record<string, unknown>;
  return (
    closed(t.expectedCurrentDeliveryIdentity, identityKeys) &&
    Object.values(
      t.expectedCurrentDeliveryIdentity as Record<string, unknown>,
    ).every(strings) &&
    Object.entries(t)
      .filter(([k]) => k !== "expectedCurrentDeliveryIdentity")
      .every(([, v]) => strings(v))
  );
}
function policyStage1(x: unknown): boolean {
  if (!closed(x, policyKeys)) return false;
  const p = x as Record<string, unknown>;
  if (
    !Array.isArray(p.extensions) ||
    !isObject(p.skills) ||
    !isObject(p.promptTemplates) ||
    !isObject(p.roles) ||
    !closed(p.skills, Object.keys(p.skills)) ||
    !closed(p.promptTemplates, Object.keys(p.promptTemplates)) ||
    !closed(p.roles, roles)
  )
    return false;
  return (
    p.extensions.every(
      (e) =>
        closed(e, ["identity", "path", "digest"]) &&
        Object.values(e).every(strings),
    ) &&
    Object.values(p.skills as Record<string, unknown>).every(strings) &&
    Object.values(p.promptTemplates as Record<string, unknown>).every(
      strings,
    ) &&
    Object.entries(p)
      .filter(
        ([k]) =>
          !["extensions", "skills", "promptTemplates", "roles"].includes(k),
      )
      .every(([, v]) => strings(v)) &&
    Object.values(p.roles as Record<string, unknown>).every((r) => {
      if (
        !closed(r, [
          "toolProfileId",
          "workspaceProfileId",
          "tools",
          "profileDigest",
        ])
      )
        return false;
      return (
        stringArray(r.tools) &&
        [r.toolProfileId, r.workspaceProfileId, r.profileDigest].every(strings)
      );
    })
  );
}
function stage1(
  inputs: readonly unknown[],
): ValidationResult<readonly unknown[]> {
  const values: unknown[] = [];
  const validators = [
    manifestStage1,
    decisionStage1,
    trustedStage1,
    policyStage1,
  ];
  for (let i = 0; i < inputs.length; i++) {
    if (i >= validators.length) return failure("schema");
    const q = snapshot(inputs[i]);
    if (!q.valid) return q as ValidationResult<readonly unknown[]>;
    if (!validators[i]!(q.value)) return failure("schema");
    values.push(q.value);
  }
  if (inputs.length !== validators.length) return failure("schema");
  return { valid: true, value: values };
}

export function createPiLaunchPlanV2(
  ...inputs: unknown[]
): ValidationResult<never> {
  const shaped = stage1(inputs);
  return shaped.valid
    ? failure("production-authorization-unavailable")
    : (shaped as ValidationResult<never>);
}

export function __testOnlyCreateLaunchPlanV2Preview(
  manifestInput: unknown,
  decisionInput: unknown,
  trustedInput: TrustedLaunchInputsV2,
  policyInput: unknown,
): ValidationResult<{
  arguments: readonly string[];
  correlation: Readonly<Record<string, string>>;
  digests: Readonly<Record<string, string>>;
}> {
  const shaped = stage1([
    manifestInput,
    decisionInput,
    trustedInput,
    policyInput,
  ]);
  if (!shaped.valid) return shaped as ValidationResult<never>;
  /* Only after every source passes stage 1 may semantic validators run, in
   * source order. */
  const m = validateAgentExecutionManifestV2(shaped.value[0]);
  if (!m.valid) return m as ValidationResult<never>;
  const dc = canonicalizeTrustedConcreteLaunchDecisionV2(shaped.value[1]);
  if (!dc.valid) return dc as ValidationResult<never>;
  const ti = canonicalizeTrustedInputs(shaped.value[2]);
  if (!ti.valid) return ti as ValidationResult<never>;
  const pr = createTrustedLaunchPolicyV2(shaped.value[3]);
  if (!pr.valid) return pr as ValidationResult<never>;
  const policyDigest = sha256(pr.value, "__none__");
  if (
    dc.value.launchPolicyDigest !== policyDigest ||
    ti.value.expectedLaunchPolicyDigest !== policyDigest
  )
    return failure("trusted-provenance");
  const d = validateTrustedConcreteLaunchDecisionV2(dc.value, ti.value);
  if (!d.valid) return d as ValidationResult<never>;
  const v = m.value as AgentExecutionManifestV2,
    p = v.packet;
  const identity = {
    projectId: p.task.projectId,
    taskId: p.task.taskId,
    repositoryId: p.repository.repositoryId,
    runId: p.run.runId,
    baseBranch: p.repository.baseBranch,
    baseCommit: p.repository.baseCommit,
    baseTree: p.repository.baseTree,
    headBranch: p.repository.headBranch,
    candidateCommit: p.repository.candidateCommit,
    candidateTree: p.repository.candidateTree,
    role: p.subject.role,
    actorId: p.subject.actorId,
    executionId: p.subject.executionId,
    workspaceId: p.subject.workspaceId,
    access: p.subject.access,
  };
  if (
    !same(identity, d.value.identity) ||
    d.value.packetDigest !== p.packetDigest ||
    d.value.manifestDigest !== v.manifestDigest
  )
    return failure("identity-mismatch");
  if (
    d.value.launchPolicyId !== pr.value.policyId ||
    d.value.resultExtensionPolicyId !== pr.value.extensions[1]!.identity ||
    d.value.resultExtensionPolicyDigest !==
      sha256(pr.value.extensions[1], "__none__")
  )
    return failure("authority-mismatch");
  const row = pr.value.roles[d.value.identity.role];
  if (!row || v.role !== d.value.identity.role) return failure("role-mismatch");
  const computedProfile = sha256(
    {
      toolProfileId: row.toolProfileId,
      workspaceProfileId: row.workspaceProfileId,
      tools: row.tools,
    },
    "profileDigest",
  );
  if (
    d.value.toolProfileId !== row.toolProfileId ||
    d.value.toolProfileDigest !== computedProfile ||
    ti.value.expectedToolProfileDigest !== computedProfile ||
    v.toolProfileId !== row.toolProfileId ||
    v.workspaceProfileId !== row.workspaceProfileId ||
    !same(v.tools, row.tools)
  )
    return failure("tool-policy");
  const skills = v.resources.skills.map((x) => pr.value.skills[x] ?? ""),
    prompts = v.resources.promptTemplates.map(
      (x) => pr.value.promptTemplates[x] ?? "",
    );
  if (skills.includes("") || prompts.includes(""))
    return failure("tool-policy");
  if (p.packetDigest !== sha256(p, "packetDigest"))
    return failure("digest-mismatch", "/packetDigest");
  const args = [
    "--no-extensions",
    ...pr.value.extensions.flatMap((e) => ["--extension", e.path]),
    "--no-session",
    "--no-skills",
    ...skills.flatMap((x) => ["--skill", x]),
    "--no-prompt-templates",
    ...prompts.flatMap((x) => ["--prompt-template", x]),
    "--no-context-files",
    "--system-prompt",
    pr.value.systemPrompt,
    "--append-system-prompt",
    pr.value.appendSystemPrompt,
    "--tools",
    v.tools.join(","),
    `${pr.value.packetInstruction}\n${canonical(p)}`,
  ];
  return {
    valid: true,
    value: deepFreeze({
      arguments: args,
      correlation: {
        executionId: v.executionId,
        packetDigest: p.packetDigest,
        manifestDigest: v.manifestDigest,
      },
      digests: {
        decisionDigest: d.value.decisionDigest,
        launchPolicyDigest: policyDigest,
        toolProfileDigest: computedProfile,
        resultExtensionPolicyDigest: d.value.resultExtensionPolicyDigest,
      },
    }),
  };
}

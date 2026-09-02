import { createHmac } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  parseControllerStoreStatusV2 as parsePackagedControllerStoreStatusV2,
  validateControllerSnapshotV2 as validatePackagedControllerSnapshotV2,
} from "@scrum-pi-team-skills/contracts";
import {
  canonicalControllerStoreAuthenticationInputV2,
  controllerStoreAuthenticationInputV2,
  deriveControllerStoreNamespaceDigestV2,
  digestControllerSnapshotV2,
  digestControllerStoreValueV2,
  validateControllerSnapshotV2,
  type ControllerCommandKindV2,
  type ControllerCommandV2,
  type ControllerSnapshotV2,
  type ProposedControllerTransitionV2,
} from "../../contracts/src/index.js";
import { evaluateControllerTransitionV2 } from "../src/controller-core-v2.js";
import {
  deriveControllerStoreCommitRequestV2,
  deriveControllerStoreCreationRequestV2,
  type ControllerStoreResultV2,
  type ControllerStoreV2,
} from "../src/controller-store-v2.js";
import {
  CONTROLLER_STORE_FAULT_POINTS_V2,
  openControllerStoreV2,
  openControllerStoreV2ForTesting,
} from "../src/file-controller-store-v2.js";

const roots: string[] = [];
const key = Buffer.alloc(32, 0x41);
const namespaceSeed = Buffer.alloc(32, 0x5a);
const namespaceDigest = deriveControllerStoreNamespaceDigestV2(namespaceSeed);
const semantics = Object.freeze([
  "exclusive-create",
  "same-filesystem-atomic-rename",
  "file-fsync",
  "directory-fsync",
  "atomic-mkdir",
  "stable-owner-mode",
] as const);
function privateRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "spts-controller-store-"));
  chmodSync(root, 0o700);
  roots.push(root);
  return root;
}

function nullRecord(values: Record<string, unknown>): Record<string, unknown> {
  return Object.assign(Object.create(null) as Record<string, unknown>, values);
}

function configuration(rootPath: string, keyBytes = key): object {
  let randomByte = 0;
  let second = 0;
  const keyProvider = nullRecord({
    keyId: "test-key-1",
    algorithm: "hmac-sha256",
    acquire: () => Uint8Array.from(keyBytes),
    release: () => undefined,
  });
  const clock = nullRecord({
    now: () => `2026-09-02T00:00:${String(second++).padStart(2, "0")}.000Z`,
  });
  const random = nullRecord({
    fill: (target: Uint8Array) => {
      target.fill(randomByte++ & 0xff);
    },
  });
  const deploymentAttestation = Object.freeze(
    nullRecord({
      kind: "trusted-local-filesystem-v1",
      platform: "linux",
      nodeMajor: 24,
      semantics,
      expectedUid: process.geteuid!(),
      rootDevice: statSync(rootPath).dev,
      attestedBy: "controller-store-test",
    }),
  );
  return nullRecord({
    rootPath,
    namespaceSeed: Uint8Array.from(namespaceSeed),
    keyProvider,
    durabilityPolicy: "linux-local-fsync-rename-v1",
    clock,
    random,
    deploymentAttestation,
  });
}

function initialSnapshot(snapshotId = "store-run-1"): ControllerSnapshotV2 {
  return {
    contractId: "spts.controller-snapshot",
    schemaVersion: "2.0.0",
    snapshotId,
    revision: 0,
    previousTransitionDigest: null,
    authorityDigest: "1".repeat(64),
    meteringDigest: "2".repeat(64),
    controllerStateDigest: "3".repeat(64),
    identity: {
      projectId: "project-1",
      taskId: "task-1",
      repositoryId: "repo-1",
      baseCommit: "0".repeat(40),
      baseTree: "1".repeat(40),
      headBranch: "main",
    },
    candidate: { commit: "2".repeat(40), tree: "3".repeat(40) },
    phase: "ready",
    activeRole: "principal-developer",
    status: {
      verification: "unverified",
      ci: "not-started",
      publication: {
        state: "not-requested",
        publicationId: null,
        publicationIntentId: null,
        publicationIntentDigest: null,
        unknownObservationDigest: null,
      },
      merged: false,
      cancelled: false,
      terminal: false,
      repairSource: null,
    },
    limits: {
      implementationAttempts: 5,
      verificationRepairs: 5,
      ciRepairs: 5,
    },
    usage: {
      implementationAttempts: 0,
      verificationRepairs: 0,
      ciRepairs: 0,
    },
    acceptedCommands: [],
  };
}

function sourceCommand(
  snapshot: ControllerSnapshotV2,
  kind: "begin-implementation" | "cancel" = "begin-implementation",
  serial = 1,
): ControllerCommandV2 {
  return {
    contractId: "spts.controller-command",
    schemaVersion: "2.0.0",
    commandId: `command-${serial}`,
    idempotencyKey: `key-${serial}`,
    kind,
    expectedRevision: snapshot.revision,
    actor: {
      role: kind === "cancel" ? "product" : "principal-developer",
      actorId: "actor-1",
      executionId: "execution-1",
      workspaceId: "workspace-1",
    },
    target: {
      projectId: snapshot.identity.projectId,
      taskId: snapshot.identity.taskId,
      repositoryId: snapshot.identity.repositoryId,
      candidateCommit: snapshot.candidate.commit,
      candidateTree: snapshot.candidate.tree,
    },
    evidence:
      kind === "cancel"
        ? [
            {
              evidenceId: `cancel-${serial}`,
              kind: "cancellation",
              digest: "6".repeat(64),
            },
          ]
        : [],
    payload: {},
  } as ControllerCommandV2;
}

function proposal(
  snapshot: ControllerSnapshotV2,
  kind: "begin-implementation" | "cancel" = "begin-implementation",
  serial = 1,
): readonly [ControllerCommandV2, ProposedControllerTransitionV2] {
  const source = sourceCommand(snapshot, kind, serial);
  const result = evaluateControllerTransitionV2(snapshot, source, {
    contractId: "spts.controller-evaluation-context",
    schemaVersion: "2.0.0",
    evaluationId: `evaluation-${serial}`,
    evaluatedAt: `2026-09-02T01:00:${String(serial).padStart(2, "0")}.000Z`,
    snapshotDigest: digestControllerSnapshotV2(snapshot),
    authorityDigest: snapshot.authorityDigest,
    meteringDigest: snapshot.meteringDigest,
    controllerStateDigest: snapshot.controllerStateDigest,
  });
  if (result.disposition !== "proposed") throw new Error(result.code);
  return [source, result as ProposedControllerTransitionV2] as const;
}

function ok<T>(result: ControllerStoreResultV2<T>): T {
  expect(
    result.disposition,
    result.disposition === "denied" ? result.diagnostic.code : undefined,
  ).toBe("ok");
  if (result.disposition !== "ok") throw new Error(result.diagnostic.code);
  return result.value;
}

async function open(
  rootPath: string,
  options?: {
    readonly fault?: (point: string) => void;
    readonly lockOwnerProbe?: () => "live" | "dead" | "ambiguous";
  },
): Promise<ControllerStoreV2> {
  return ok(
    await openControllerStoreV2ForTesting(configuration(rootPath), options),
  );
}

async function create(store: ControllerStoreV2, snapshot = initialSnapshot()) {
  const request = deriveControllerStoreCreationRequestV2(
    namespaceDigest,
    snapshot,
    "create-operation-1",
  );
  return store.createControllerRunV2(snapshot, {
    operationId: "create-operation-1",
    requestDigest: request.canonicalRequestDigest,
  });
}

function identity(snapshot = initialSnapshot()) {
  return deriveControllerStoreCreationRequestV2(
    namespaceDigest,
    snapshot,
    "identity-operation",
  ).identity;
}

async function commit(
  store: ControllerStoreV2,
  snapshot: ControllerSnapshotV2,
  kind: "begin-implementation" | "cancel" = "begin-implementation",
  serial = 1,
  operationId = `commit-operation-${serial}`,
) {
  const [source, proposed] = proposal(snapshot, kind, serial);
  const request = deriveControllerStoreCommitRequestV2(
    namespaceDigest,
    snapshot,
    source,
    proposed,
    operationId,
  );
  return store.commitControllerTransitionV2(snapshot, source, proposed, {
    operationId,
    requestDigest: request.canonicalRequestDigest,
  });
}

function runPathFor(rootPath: string, snapshot = initialSnapshot()): string {
  return join(
    rootPath,
    "controller-store-v2",
    namespaceDigest,
    "runs",
    identity(snapshot).runIdentityDigest,
  );
}

function runPath(rootPath: string): string {
  return runPathFor(rootPath);
}

function fileTree(rootPath: string): string[] {
  const result: string[] = [];
  const walk = (path: string, relative: string) => {
    for (const name of readdirSync(path).sort()) {
      const absolute = join(path, name);
      const next = relative ? `${relative}/${name}` : name;
      const stat = lstatSync(absolute);
      result.push(
        `${next}:${stat.isDirectory() ? "d" : readFileSync(absolute, "hex")}`,
      );
      if (stat.isDirectory()) walk(absolute, next);
    }
  };
  walk(rootPath, "");
  return result;
}

afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("authenticated file controller store v2", () => {
  it("creates, loads, inspects, commits, replays byte-equivalent results, and closes", async () => {
    const root = privateRoot();
    const store = await open(root);
    const creation = ok(await create(store));
    expect(creation).toMatchObject({
      kind: "create",
      replayed: false,
      revision: 0,
    });
    expect(Object.isFrozen(creation.snapshot)).toBe(true);
    expect(creation.status).toMatchObject({
      kind: "ready",
      committedRevision: 0,
      lastReceiptDigest: null,
      operationCount: 1,
    });

    const runPath = join(
      root,
      "controller-store-v2",
      namespaceDigest,
      "runs",
      identity().runIdentityDigest,
    );
    const head = JSON.parse(
      readFileSync(join(runPath, "head.json"), "utf8"),
    ) as {
      authenticationTag: string;
      body: { snapshot: unknown; status: Record<string, unknown> };
      contractId: string;
      keyId: string;
      recordDigest: string;
      recordType: string;
      schemaVersion: number;
    };
    expect(Object.keys(head).sort()).toEqual(
      [
        "authenticationTag",
        "body",
        "contractId",
        "keyId",
        "recordDigest",
        "recordType",
        "schemaVersion",
      ].sort(),
    );
    expect(head).toMatchObject({
      contractId: "spts.controller-store-file.v2",
      keyId: "test-key-1",
      recordType: "head-pointer",
      schemaVersion: 2,
    });
    expect(statSync(join(runPath, "head.json")).mode & 0o777).toBe(0o600);
    expect(validateControllerSnapshotV2(head.body.snapshot)).toBe(true);
    expect(validatePackagedControllerSnapshotV2(head.body.snapshot)).toBe(true);
    expect(Object.keys(head.body.status).sort()).toEqual(
      [
        "cleanupRequired",
        "committedRevision",
        "identity",
        "kind",
        "lastReceiptDigest",
        "operationCount",
        "quarantineCount",
        "runIdentity",
        "snapshotDigest",
      ].sort(),
    );
    expect(
      parsePackagedControllerStoreStatusV2({
        ...head.body.status,
        headRecordDigest: head.recordDigest,
      }),
    ).toBeDefined();
    const bodyDigest = digestControllerStoreValueV2(
      "spts/controller-store-file-body/v2",
      head.body,
    );
    expect(head.recordDigest).toBe(bodyDigest);
    expect(head.authenticationTag).toBe(
      createHmac("sha256", key)
        .update(
          canonicalControllerStoreAuthenticationInputV2(
            controllerStoreAuthenticationInputV2(
              "test-key-1",
              "head-pointer",
              bodyDigest,
            ),
          ),
        )
        .digest("hex"),
    );

    const loaded = ok(await store.loadControllerRunV2(identity()));
    expect(loaded.snapshot).toEqual(initialSnapshot());
    expect(ok(await store.inspectControllerRunV2(identity()))).toEqual(
      loaded.status,
    );

    const committed = ok(await commit(store, initialSnapshot()));
    expect(committed).toMatchObject({
      kind: "commit",
      replayed: false,
      revision: 1,
    });
    expect(committed.receipt.transitionChainDigest).toBe(
      committed.receipt.transitionDigest,
    );
    expect(committed.receipt.previousReceiptDigest).toBeNull();
    expect(committed.receipt.authenticationTag).toMatch(/^[0-9a-f]{64}$/);

    const replayed = ok(await commit(store, initialSnapshot()));
    expect(replayed).toEqual({ ...committed, replayed: true });
    expect(replayed.receipt).toEqual(committed.receipt);

    expect(ok(await store.closeControllerStoreV2())).toEqual({
      kind: "closed",
    });
    expect(ok(await store.closeControllerStoreV2())).toEqual({
      kind: "closed",
    });
    await expect(store.loadControllerRunV2(identity())).resolves.toEqual({
      disposition: "denied",
      diagnostic: {
        code: "store-closed",
        message: "Controller store request denied.",
      },
    });
  });

  it("replays the immutable original creation projection rather than current status", async () => {
    const root = privateRoot();
    const store = await open(root);
    const original = ok(await create(store));
    ok(await commit(store, initialSnapshot()));
    const replay = ok(await create(store));
    expect(replay).toEqual({ ...original, replayed: true });
    expect(replay.status.committedRevision).toBe(0);
    expect(ok(await store.inspectControllerRunV2(identity()))).toMatchObject({
      committedRevision: 1,
      operationCount: 2,
    });
  });

  it("denies a second creation operation for an existing run without publishing bytes", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    const before = fileTree(root);
    const request = deriveControllerStoreCreationRequestV2(
      namespaceDigest,
      initialSnapshot(),
      "create-operation-2",
    );

    await expect(
      store.createControllerRunV2(initialSnapshot(), {
        operationId: "create-operation-2",
        requestDigest: request.canonicalRequestDigest,
      }),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "run-exists" },
    });
    expect(fileTree(root)).toEqual(before);
  });

  it("enforces operation conflict and stale/future CAS without publishing bytes", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    ok(await commit(store, initialSnapshot()));

    const [cancelSource, cancelProposal] = proposal(
      initialSnapshot(),
      "cancel",
      2,
    );
    const cancelRequest = deriveControllerStoreCommitRequestV2(
      namespaceDigest,
      initialSnapshot(),
      cancelSource,
      cancelProposal,
      "commit-operation-1",
    );
    const beforeConflict = fileTree(root);
    await expect(
      store.commitControllerTransitionV2(
        initialSnapshot(),
        cancelSource,
        cancelProposal,
        {
          operationId: "commit-operation-1",
          requestDigest: cancelRequest.canonicalRequestDigest,
        },
      ),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "replay-conflict" },
    });
    expect(fileTree(root)).toEqual(beforeConflict);

    const stale = await commit(
      store,
      initialSnapshot(),
      "begin-implementation",
      3,
      "stale-operation",
    );
    expect(stale).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "stale-revision" },
    });

    const futureSnapshot = structuredClone(initialSnapshot());
    futureSnapshot.revision = 2;
    futureSnapshot.previousTransitionDigest = zeroDigest();
    const future = await commit(
      store,
      futureSnapshot,
      "cancel",
      4,
      "future-operation",
    );
    expect(future).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "future-revision" },
    });
  });

  it("serializes same-instance contenders and gives exactly one CAS winner", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    const [first, second] = await Promise.all([
      commit(store, initialSnapshot(), "begin-implementation", 1, "race-a"),
      commit(store, initialSnapshot(), "cancel", 2, "race-b"),
    ]);
    expect(
      [first, second].filter((value) => value.disposition === "ok"),
    ).toHaveLength(1);
    expect(
      [first, second].filter((value) => value.disposition === "denied"),
    ).toMatchObject([{ diagnostic: { code: "stale-revision" } }]);
  });

  it("coordinates independent handles and converges duplicate contenders", async () => {
    const root = privateRoot();
    const creator = await open(root);
    ok(await create(creator));
    await creator.closeControllerStoreV2();
    const left = await open(root);
    const right = await open(root);
    const results = await Promise.all([
      commit(
        left,
        initialSnapshot(),
        "begin-implementation",
        1,
        "duplicate-race",
      ),
      commit(
        right,
        initialSnapshot(),
        "begin-implementation",
        1,
        "duplicate-race",
      ),
    ]);
    const successful = results.filter((result) => result.disposition === "ok");
    expect(successful).toHaveLength(2);
    if (
      successful[0]?.disposition === "ok" &&
      successful[1]?.disposition === "ok"
    ) {
      expect(successful.map((result) => result.value.replayed).sort()).toEqual([
        false,
        true,
      ]);
      expect(successful[0].value.receipt).toEqual(successful[1].value.receipt);
    }
  });

  it("derives operation-record paths from digests rather than hostile operation IDs", async () => {
    const root = privateRoot();
    const store = await open(root);
    const operationId = "op/../../../../outside";
    const snapshot = initialSnapshot();
    const request = deriveControllerStoreCreationRequestV2(
      namespaceDigest,
      snapshot,
      operationId,
    );
    expect(
      ok(
        await store.createControllerRunV2(snapshot, {
          operationId,
          requestDigest: request.canonicalRequestDigest,
        }),
      ).revision,
    ).toBe(0);
    expect(fileTree(root).some((path) => path.includes("outside"))).toBe(false);
  });

  it("recovers creation after the durable operation precedes genesis head publication", async () => {
    const root = privateRoot();
    let injected = false;
    const faulting = await open(root, {
      fault(point) {
        if (!injected && point === "operation-durable") {
          injected = true;
          throw new Error("injected-create-crash");
        }
      },
    });
    expect(await create(faulting)).toMatchObject({ disposition: "denied" });
    await faulting.closeControllerStoreV2();

    const fresh = await open(root);
    expect(ok(await create(fresh))).toMatchObject({
      kind: "create",
      revision: 0,
      replayed: true,
    });
    expect(ok(await fresh.loadControllerRunV2(identity()))).toMatchObject({
      status: { committedRevision: 0 },
    });
  });

  it("uses and releases a namespace lock while creating a run", async () => {
    const root = privateRoot();
    const store = await open(root);

    ok(await create(store));

    const namespace = join(root, "controller-store-v2", namespaceDigest);
    expect(existsSync(join(namespace, "lock-candidates"))).toBe(true);
    expect(existsSync(join(namespace, "lock"))).toBe(false);
  });

  it("renews transaction stages and excludes independent commit and recovery handles", async () => {
    const root = privateRoot();
    const creator = await open(root);
    ok(await create(creator));
    await creator.closeControllerStoreV2();
    const contender = await open(root);
    let commitContender: ReturnType<typeof commit> | undefined;
    let recoveryContender:
      ReturnType<ControllerStoreV2["recoverControllerRunV2"]> | undefined;
    const observed: Array<{
      readonly point: string;
      readonly renewalCounter: number;
      readonly currentTransaction: Record<string, unknown> | null;
      readonly journalPresent: boolean;
    }> = [];
    const holder = await open(root, {
      fault(point) {
        const owner = JSON.parse(
          readFileSync(
            join(
              root,
              "controller-store-v2",
              namespaceDigest,
              "lock",
              "owner.json",
            ),
            "utf8",
          ),
        ) as {
          readonly body: {
            readonly renewalCounter: number;
            readonly currentTransaction: Record<string, unknown> | null;
          };
        };
        observed.push({
          point,
          renewalCounter: owner.body.renewalCounter,
          currentTransaction: owner.body.currentTransaction,
          journalPresent: existsSync(
            join(runPath(root), "transaction", "journal.json"),
          ),
        });
        if (point === "transaction-announced") {
          commitContender = commit(
            contender,
            initialSnapshot(),
            "cancel",
            2,
            "independent-contender",
          );
          recoveryContender = contender.recoverControllerRunV2(identity(), {
            operationId: "independent-recovery",
          });
        }
      },
    });

    expect(
      ok(
        await commit(
          holder,
          initialSnapshot(),
          "begin-implementation",
          1,
          "lock-holder",
        ),
      ),
    ).toMatchObject({ revision: 1, replayed: false });
    expect(observed.map(({ point }) => point)).toEqual(
      CONTROLLER_STORE_FAULT_POINTS_V2,
    );
    expect(
      observed
        .map(({ renewalCounter }) => renewalCounter)
        .sort((a, b) => a - b),
    ).toEqual([2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(observed[0]).toMatchObject({ journalPresent: true });
    expect(observed[0]?.currentTransaction).toMatchObject({
      kind: "commit",
      operationId: "lock-holder",
      runIdentityDigest: identity().runIdentityDigest,
      fromRevision: 0,
      toRevision: 1,
      relativePath: `runs/${identity().runIdentityDigest}/transaction`,
    });
    expect(observed.at(-1)?.currentTransaction).toBeNull();
    expect(commitContender).toBeDefined();
    expect(recoveryContender).toBeDefined();
    await expect(commitContender).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "busy" },
    });
    await expect(recoveryContender).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "busy" },
    });
    expect(
      existsSync(join(root, "controller-store-v2", namespaceDigest, "lock")),
    ).toBe(false);
  });

  it("recovers absent and ready runs and refuses an aborted call before mutation", async () => {
    const root = privateRoot();
    const store = await open(root);
    expect(ok(await store.inspectControllerRunV2(identity()))).toMatchObject({
      kind: "absent",
    });
    expect(
      await store.recoverControllerRunV2(identity(), {
        operationId: "recover-1",
      }),
    ).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "run-absent" },
    });

    const abort = new AbortController();
    abort.abort();
    const request = deriveControllerStoreCreationRequestV2(
      namespaceDigest,
      initialSnapshot(),
      "aborted-create",
    );
    expect(
      await store.createControllerRunV2(initialSnapshot(), {
        operationId: "aborted-create",
        requestDigest: request.canonicalRequestDigest,
        abortSignal: abort.signal,
      }),
    ).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "abort-before-commit" },
    });
    expect(ok(await store.inspectControllerRunV2(identity()))).toMatchObject({
      kind: "absent",
    });

    ok(await create(store));
    expect(
      ok(
        await store.recoverControllerRunV2(identity(), {
          operationId: "recover-2",
        }),
      ),
    ).toMatchObject({
      kind: "recovery",
      outcome: "ready",
      status: { kind: "ready", committedRevision: 0 },
    });
  });

  it("returns an explicit production capability refusal on the ordinary mixed-owner root chain", async () => {
    const root = privateRoot();
    const result = await openControllerStoreV2(configuration(root));
    expect(result).toEqual({
      disposition: "denied",
      diagnostic: {
        code: "permission-denied",
        message: "Controller store request denied.",
      },
    });
  });

  it("rejects malformed bootstrap, protocol-derived fields, unavailable keys, and wrong keys", async () => {
    const root = privateRoot();
    expect(
      await openControllerStoreV2({ ...configuration(root) }),
    ).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "invalid-bootstrap" },
    });
    const polluted = configuration(root) as Record<string, unknown>;
    polluted.sourceCommand = {
      deploymentAttestation: polluted.deploymentAttestation,
    };
    expect(await openControllerStoreV2ForTesting(polluted)).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "invalid-bootstrap" },
    });

    const unavailable = configuration(root) as Record<string, unknown>;
    const provider = unavailable.keyProvider as Record<string, unknown>;
    provider.acquire = () => {
      throw new Error(`/secret/${"ghp_"}${"x".repeat(40)}`);
    };
    expect(await openControllerStoreV2ForTesting(unavailable)).toEqual({
      disposition: "denied",
      diagnostic: {
        code: "key-unavailable",
        message: "Controller store request denied.",
      },
    });

    const store = await open(root);
    ok(await create(store));
    await store.closeControllerStoreV2();
    expect(
      await openControllerStoreV2ForTesting(
        configuration(root, Buffer.alloc(32, 0x42)),
      ),
    ).toMatchObject({
      disposition: "denied",
      diagnostic: { code: "integrity-failure" },
    });
  });

  it("authenticates head and reports repair-required after bit-flip tampering", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    const run = join(
      root,
      "controller-store-v2",
      namespaceDigest,
      "runs",
      identity().runIdentityDigest,
    );
    const headPath = join(run, "head.json");
    const head = JSON.parse(readFileSync(headPath, "utf8")) as Record<
      string,
      unknown
    >;
    head.authenticationTag = "0".repeat(64);
    writeFileSync(headPath, JSON.stringify(head), { mode: 0o600 });
    expect(ok(await store.inspectControllerRunV2(identity()))).toMatchObject({
      kind: "repair-required",
      code: "integrity-failure",
    });
  });

  it("classifies injected prepublication faults against the authenticated old head", async () => {
    expect(CONTROLLER_STORE_FAULT_POINTS_V2).toEqual(
      expect.arrayContaining([
        "transaction-announced",
        "journal-prepared",
        "records-durable",
        "receipt-durable",
        "operation-durable",
        "head-prepared",
        "head-published",
        "head-durable",
        "journal-committed",
      ]),
    );
    for (const point of [
      "journal-prepared",
      "records-durable",
      "receipt-durable",
      "operation-durable",
      "head-prepared",
    ]) {
      const root = privateRoot();
      const creator = await open(root);
      ok(await create(creator));
      await creator.closeControllerStoreV2();
      let injected = false;
      const faulting = await open(root, {
        fault(current) {
          if (!injected && current === point) {
            injected = true;
            throw Object.assign(new Error("injected secret path"), {
              code: "ENOSPC",
            });
          }
        },
      });
      expect(await commit(faulting, initialSnapshot())).toMatchObject({
        disposition: "denied",
        diagnostic: {
          message: "Controller store request denied.",
        },
      });
      await faulting.closeControllerStoreV2();
      const fresh = await open(root);
      const recovery = ok(
        await fresh.recoverControllerRunV2(identity(), {
          operationId: `recover-${point}`,
        }),
      );
      expect(recovery).toMatchObject({
        kind: "recovery",
        outcome: "old-head-restored",
        status: { committedRevision: 0 },
      });
    }
  });

  it("binds an authenticated head to the exact requested run identity", async () => {
    const root = privateRoot();
    const first = initialSnapshot("run-a");
    const second = initialSnapshot("run-b");
    const store = await open(root);
    ok(await create(store, first));
    ok(await create(store, second));
    copyFileSync(
      join(runPathFor(root, first), "head.json"),
      join(runPathFor(root, second), "head.json"),
    );

    await expect(store.loadControllerRunV2(identity(second))).resolves.toEqual({
      disposition: "denied",
      diagnostic: {
        code: "integrity-failure",
        message: "Controller store request denied.",
      },
    });
  });

  it("creates an authenticated namespace manifest that rejects the wrong key even while empty", async () => {
    const root = privateRoot();
    const store = await open(root);
    await store.closeControllerStoreV2();
    expect(
      existsSync(
        join(root, "controller-store-v2", namespaceDigest, "manifest.json"),
      ),
    ).toBe(true);

    await expect(
      openControllerStoreV2ForTesting(
        configuration(root, Buffer.alloc(32, 0x42)),
      ),
    ).resolves.toEqual({
      disposition: "denied",
      diagnostic: {
        code: "integrity-failure",
        message: "Controller store request denied.",
      },
    });
  });

  it("rejects noncanonical authenticated record bytes", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    await store.closeControllerStoreV2();
    appendFileSync(join(runPath(root), "head.json"), "\n");

    await expect(
      openControllerStoreV2ForTesting(configuration(root)),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "integrity-failure" },
    });
  });

  it("authenticates and validates every final operation while reopening", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    await store.closeControllerStoreV2();
    const operations = join(runPath(root), "operations");
    const name = readdirSync(operations).find((entry) =>
      entry.endsWith(".json"),
    );
    expect(name).toBeDefined();
    const path = join(operations, name!);
    const envelope = JSON.parse(readFileSync(path, "utf8")) as Record<
      string,
      unknown
    >;
    envelope.authenticationTag = "0".repeat(64);
    writeFileSync(path, JSON.stringify(envelope), { mode: 0o600 });

    await expect(
      openControllerStoreV2ForTesting(configuration(root)),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "integrity-failure" },
    });
  });

  it("reports success after the durable head linearization point", async () => {
    const root = privateRoot();
    const creator = await open(root);
    ok(await create(creator));
    await creator.closeControllerStoreV2();
    const faulting = await open(root, {
      fault(point) {
        if (point === "head-published") {
          throw new Error(`/secret/${"ghp_"}${"x".repeat(40)}`);
        }
      },
    });

    expect(await commit(faulting, initialSnapshot())).toMatchObject({
      disposition: "ok",
      value: { kind: "commit", revision: 1, replayed: false },
    });
  });

  it("does not preserve a new head or report a stale retry when operation recovery evidence is missing", async () => {
    const root = privateRoot();
    const creator = await open(root);
    ok(await create(creator));
    await creator.closeControllerStoreV2();
    const faulting = await open(root, {
      fault(point) {
        if (point === "head-published") throw new Error("simulated crash");
      },
    });
    await commit(
      faulting,
      initialSnapshot(),
      "begin-implementation",
      1,
      "missing-operation",
    );
    await faulting.closeControllerStoreV2();
    rmSync(join(runPath(root), "transaction", "operation.json"));
    const fresh = await open(root);

    await expect(
      fresh.recoverControllerRunV2(identity(), {
        operationId: "recover-missing-operation",
      }),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "integrity-failure" },
    });
    await expect(
      commit(
        fresh,
        initialSnapshot(),
        "begin-implementation",
        1,
        "missing-operation",
      ),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "integrity-failure" },
    });
  });

  it("contains hostile operation option accessors in the fixed result union", async () => {
    const root = privateRoot();
    const store = await open(root);
    const hostile = Object.defineProperty({}, "abortSignal", {
      enumerable: true,
      get() {
        throw new Error(`/secret/${"RAW-ghp_"}${"x".repeat(30)}`);
      },
    });

    await expect(
      store.createControllerRunV2(initialSnapshot(), hostile as never),
    ).resolves.toEqual({
      disposition: "denied",
      diagnostic: {
        code: "invalid-input",
        message: "Controller store request denied.",
      },
    });
  });

  it("rejects a symlinked store directory without chmod of its external target", async () => {
    const root = privateRoot();
    const outside = privateRoot();
    chmodSync(outside, 0o755);
    symlinkSync(outside, join(root, "controller-store-v2"));
    const before = lstatSync(outside).mode & 0o777;

    await expect(
      openControllerStoreV2ForTesting(configuration(root)),
    ).resolves.toMatchObject({ disposition: "denied" });
    expect(before).toBe(0o755);
    expect(lstatSync(outside).mode & 0o777).toBe(before);
  });

  it("requires an exact frozen null-prototype deployment attestation", async () => {
    const root = privateRoot();
    const bootstrap = configuration(root) as Record<string, unknown>;
    bootstrap.deploymentAttestation = nullRecord({
      ...(bootstrap.deploymentAttestation as Record<string, unknown>),
    });

    await expect(
      openControllerStoreV2ForTesting(bootstrap),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "durability-unavailable" },
    });
  });

  it("rejects replay from a commit operation unreachable after head rollback", async () => {
    const root = privateRoot();
    const store = await open(root);
    ok(await create(store));
    const headPath = join(runPath(root), "head.json");
    const genesis = readFileSync(headPath);
    ok(
      await commit(
        store,
        initialSnapshot(),
        "begin-implementation",
        1,
        "rolled-back-operation",
      ),
    );
    writeFileSync(headPath, genesis, { mode: 0o600 });

    await expect(
      commit(
        store,
        initialSnapshot(),
        "begin-implementation",
        1,
        "rolled-back-operation",
      ),
    ).resolves.toMatchObject({
      disposition: "denied",
      diagnostic: { code: "integrity-failure" },
    });
    expect(
      JSON.parse(readFileSync(headPath, "utf8")).body.status.committedRevision,
    ).toBe(0);
  });
});

function zeroDigest(): string {
  return "0".repeat(64);
}

void ("cancel" satisfies ControllerCommandKindV2);

# Scrum Pi Team Skills

Development baseline for locally executed Pi agents supporting a Scrum team.

Paca is the Scrum control plane and system of record. Agents are planned and supervised as local Pi processes governed by pi-daddy. The repository implements the governed manifest/planning boundary and a Linux/WSL-local foreground process host; ACP and Paca adapters remain future scope.

## Prerequisites

- WSL 2 with Ubuntu
- Git
- Node.js 24 LTS
- npm 11

## WSL setup

From an Ubuntu shell in WSL:

```bash
sudo apt update
sudo apt install --yes build-essential git curl
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm install 24
nvm use 24
npm install --global npm@11
```

Confirm the major versions before installing dependencies:

```bash
node --version
npm --version
```

Clone the repository within the WSL filesystem rather than `/mnt/c` for faster package installation and file watching:

```bash
git clone https://github.com/mojomanyana/scrum-pi-team-skills.git
cd scrum-pi-team-skills
npm ci
```

## Development commands

| Command                | Purpose                                       |
| ---------------------- | --------------------------------------------- |
| `npm run build`        | Build all TypeScript workspace projects.      |
| `npm test`             | Run the Vitest unit suite once.               |
| `npm run typecheck`    | Type-check source and test files.             |
| `npm run lint`         | Run ESLint with warnings treated as failures. |
| `npm run format`       | Format supported files with Prettier.         |
| `npm run format:check` | Check formatting without changing files.      |
| `npm run quality`      | Run all checks used by CI.                    |
| `npm run clean`        | Remove TypeScript build outputs.              |

## Governed agent execution

`packages/contracts` exports the `AgentExecutionManifest` TypeScript type and the AJV-backed `validateGovernedAgentExecutionManifest` composite validator for version `1.0.0`. That explicitly named composite validator is the authoritative boundary for the untrusted manifest. It composes structural validation with recursive credential checks over every accepted string, canonical Pi tool ordering, and an exactly matching pi-daddy grant, so every accepted manifest remains local Pi work intent governed by pi-daddy, with Paca as the system of record. The older `validateAgentExecutionManifest` name remains only as a deprecated compatibility alias to the same composite function.

> **Warning:** `agent-execution-manifest.schema.json` is a portable, structural data-envelope artifact only. Direct AJV success does **not** authorize governed execution and does not evaluate cross-field invariants. Never use structure-only validation to launch an agent.

```ts
import { validateGovernedAgentExecutionManifest } from "@scrum-pi-team-skills/contracts";

const result = validateGovernedAgentExecutionManifest(candidate);
if (!result.valid)
  throw new Error("manifest is not authorized for governed execution");
```

Valid examples for all four roles are in `packages/contracts/examples`, and every example passes the governed composite validator. Manifests contain logical skill and prompt-template references, never executable or installation paths. They also require zero delegation depth, explicit authorization boundaries, and metadata-only receipts.

Authorized objective and out-of-scope text is inert data: it may name a command such as `curl example.test`, but launch planning never interprets or adds that prose to executable arguments. Credential assignments and recognized token prefixes are prohibited in every structurally accepted manifest string. Contract diagnostics use fixed messages and do not echo suspected values or undeclared property names. Exceptional getters, proxies, and reflection traps are also converted to fixed domain diagnostics before their exception details can escape. Normalized absolute WSL paths may contain spaces, which remain single argument values; execution-shaping paths still reject controls, shell/injection characters, credential shapes, duplicate or trailing separators, and exact `.` or `..` segments without silently normalizing them.

Paca and the manifest provide untrusted work intent; they do not grant trust to physical resources. Local operator authority enters through `createTrustedLaunchPolicy`. The factory validates and copies exact Pi executable, pi-daddy extension, governance-ledger, skill, prompt-template, base-system-prompt, and append-system-prompt paths, requires every logical resource across the entire policy to have a unique exact normalized pathname, brands the result, and deeply freezes its registries. `createPiLaunchPlan` accepts only a policy issued by that factory, resolves logical resources from it, and rejects unbound references; a caller-provided object or label cannot impersonate a trusted policy. Creating the policy is an operator integration responsibility and must never use manifest data as authority. Filesystem existence, content, realpath, symlink, and hardlink checks remain operator integration responsibilities outside the pure planner.

`createPiLaunchPlan` from `@scrum-pi-team-skills/runtime` is a pure planning function. Supply a manifest and a validated `TrustedLaunchPolicy`. It returns:

- the Pi executable, argument array, and repository working directory;
- only the governed `PI_GRANTS_GRANT`, `PI_GRANTS_MAX_DEPTH=0`, and `PI_GRANTS_LEDGER` environment additions;
- an array-based redacted operator preview and execution/Paca correlation identity.

The plan starts with `--no-extensions` and loads only the policy-bound pi-daddy grant extension. It also uses `--no-skills` and `--no-prompt-templates` before adding policy-bound resources in manifest order. Pi 0.84.2 treats these prompt sources separately: `--no-context-files` suppresses global, ancestor, and repository `AGENTS.md`/`CLAUDE.md` discovery, while a CLI `--system-prompt` takes precedence over project `.pi/SYSTEM.md` and global `SYSTEM.md`, and one or more CLI `--append-system-prompt` values prevent project or global `APPEND_SYSTEM.md` discovery. The generated arguments therefore include all three controls and bind both system-prompt arguments to exact trusted-policy paths. Prompt templates remain separately discovered resources and do not replace these controls.

The portable schema intentionally stops at structure. The composite validator owns manifest credential, semantic, cross-field, canonical-order, and exact-grant checks. The runtime policy factory and planner own trusted physical binding and uniqueness checks. A launch is acceptable only after both authoritative stages succeed. The planner passes approved tools through `--tools`, always revalidates the manifest composite, never returns a shell command, and does not spawn a process, inspect the filesystem, modify Git, access the network, or update Paca.

### Governed Linux/WSL runtime (SPTS-8)

SPTS-7 planning and SPTS-8 execution are separate boundaries. `createPiLaunchPlan` remains pure, but each result is now deeply frozen and carries unforgeable in-process issuance authority in a private `WeakMap`. `startGovernedLocalProcess` accepts only the exact live object issued by that planner in the current process. A spread copy, clone, proxy, prototype object, or serialized preview is evidence only and cannot be executed. The CLI `run` path always rebuilds the trusted policy and launch plan from the manifest and operator configuration in the same process.

The runtime exports these primary APIs from `@scrum-pi-team-skills/runtime`:

- `createOperatorEnvironmentPolicy({ policyId, baseline, allowlist })` validates, copies, and freezes operator-owned environment authority while keeping all values in private storage;
- `createRuntimePolicy(...)` issues immutable bounded runtime limits;
- `startGovernedLocalProcess(...)` returns a live `SupervisedExecution` with `started`, `exit`, and idempotent `terminate()` lifecycles;
- `createReceiptAuthenticator({ authenticatorId, key })` copies at least 32 key bytes into private factory-issued authority;
- `createLocalFilesystemReceiptSink({ trustedParent, authenticator })` and `inspectLifecycleReceipts({ trustedParent, executionId, authenticator })` write and authenticate one execution chain.

Core runtime code never reads or enumerates `process.env`. The operator supplies an explicit baseline whose names exactly match an allowlist. Values, including legitimate model-provider credentials, are opaque secrets: they are passed only to the exact child environment and are never returned, logged, hashed, persisted, or included in receipts. Fixed launch-plan additions are validated after the baseline and any name collision is rejected rather than overwritten. Names and values containing NUL, invalid environment names, and configured size-limit overflow fail closed.

Version 1 supports Linux/WSL only. It uses Node `spawn` with the exact executable, argv, cwd, and constructed environment, with `shell:false`. `detached:true` is used specifically to create a dedicated POSIX process group; the child is **not** `unref`'ed or backgrounded, so the supervisor retains pipes and wait ownership. Successful spawn captures the positive child PID as the dedicated PGID in the live in-memory handle; it rejects the supervisor PID and never accepts a caller-supplied PID or PGID. Direct-child close and process-group absence are separate states. The default adapter classifies each `kill(-pgid, 0)` probe as absent, present, or unknown. ESRCH alone establishes confirmed absence, which is sticky; a successful probe establishes presence. EPERM and every unexpected error establish unknown liveness and record a fixed, redacted supervisor failure.

Caller termination, abort, timeout, forwarded CLI SIGINT/SIGTERM, or descendants surviving leader close use one idempotent sequence. Confirmed absence stops all signaling. Presence or unknown liveness drives a conservative group SIGTERM attempt, bounded grace polling, a group SIGKILL attempt when absence remains unconfirmed, and bounded confirmation polling through `killConfirmationMs` using `processGroupPollIntervalMs`. A later ESRCH can turn transient unknown liveness into confirmed absence. Persistent unknown liveness never claims successful cleanup or confirmed absence: terminal receipt creation, authenticated anchor creation, writer close, `terminate()`, and `exit` fail closed when bounded confirmation cannot establish absence. A leader that otherwise exits cleanly but requires descendant containment is reported as `supervisor_failed`, with safe `descendant_cleanup_required` and `process_killed` lifecycle evidence rather than an ordinary success. There is deliberately no cross-process kill-by-PID command.

The first confirmed absence permanently disables further signaling, so long grace or confirmation bounds cannot retain the host after disappearance. POSIX does not provide an unforgeable process-group handle: PGID reuse between any probe and a subsequent signal remains a residual kernel identity race, and orphan/zombie reaping can delay ESRCH until the OS reports the group absent. OS permissions can leave probes persistently unknown or prevent signal delivery; the bounded sequence records only fixed diagnostics and fails closed rather than claiming cleanup when permission or any other condition prevents confirmed absence.

Stdout and stderr are streamed to callbacks with backpressure rather than buffered. The CLI observes each Writable's callback, asynchronous error/close events, and required drain before writing; synchronous throws and completion/error races enter the same fixed output-callback failure path. A broken output pipe triggers governed process-group termination and finalization before fixed exit code `3`; raw stream errors and exception details are never printed. Receipts persist only incremental byte counts and SHA-256 digests. Callback and receipt-sink failures become fixed supervisor failures while process-group cleanup continues.

### Lifecycle receipts

`packages/contracts/src/schemas/lifecycle-receipt.schema.json` defines `spts.lifecycle-receipt/1.0.0`. Its canonical SHA-256 JSONL chain remains ordering and corruption evidence. The authoritative verifier requires `launch_requested` first, the applicable start/termination/timeout/escalation predecessors, exactly one terminal event, contiguous sequences, constant execution/plan/policy identity, canonical UTC timestamps with milliseconds, nondecreasing time, and consistent outcome/exit-code/signal evidence. A terminal `timed_out` outcome specifically requires `process_timed_out`, one later `termination_requested` with reason `timeout`, and any required `process_killed` evidence; a conflicting reason, missing timeout authority, or any `supervisor_failed` event makes `timed_out` invalid. Supervisor failure takes terminal precedence while a complete timeout chain may still end as `supervisor_failed`.

`packages/contracts/src/schemas/lifecycle-receipt-anchor.schema.json` separately defines `spts.lifecycle-receipt-anchor/1.0.0`, avoiding digest circularity. The terminal anchor HMAC covers its contract/version, execution ID, receipt count, terminal receipt digest, plan digest, environment/runtime policy IDs, and non-secret authenticator ID. Inspection requires both the chain and a valid HMAC-SHA256 anchor, so chain modification plus complete rehashing, reorder, insertion, deletion, terminal truncation, missing or modified anchors, and wrong keys fail.

No receipt or anchor contains environment values, authentication keys, raw output, prompts, credentials, arbitrary exception messages, or configuration/file contents. Factory-issued authenticators copy at least 32 bytes into private storage; APIs expose only the immutable non-secret authenticator ID. Tags use timing-safe comparison, and temporary decoded buffers are zeroed where practical. Operator key provisioning and rotation remain operator responsibilities. JavaScript cannot reliably erase the original immutable environment string used by the CLI, so operators should minimize that process lifetime and environment exposure.

The filesystem API accepts an existing absolute, lexically normalized trusted parent, not an arbitrary receipt/file path. It rejects dot/dot-dot/NUL, symlinked components, normalized mismatches, non-Linux operation, and parents not owned by the process uid with mode `0700`. It exclusively creates one mode-`0700` execution child and mode-`0600` receipt/anchor files, uses `O_NOFOLLOW` where available, compares opened descriptor identity, and never recursively deletes storage. Appends write the complete UTF-8 line with EINTR/short-write handling and synchronization; zero, invalid, or failed progress poisons and closes the writer. Replacement of an operator-owned trusted parent by the same privileged owner is outside this process-local boundary and requires stronger OS-level directory-handle/sandbox controls.

### Private operator CLI

After `npm run build`:

```bash
node packages/tooling/dist/cli.js --help
node packages/tooling/dist/cli.js plan --manifest ./operator/manifest.json --operator-config ./operator/runtime.json
node packages/tooling/dist/cli.js run --manifest ./operator/manifest.json --operator-config ./operator/runtime.json
node packages/tooling/dist/cli.js inspect --execution-id runtime-EXAMPLE --operator-config ./operator/runtime.json
```

Operator configuration supplies a `trustedLaunchPolicy`, bounded `runtimePolicy` (including `terminationGraceMs`, `killConfirmationMs`, and `processGroupPollIntervalMs`), and an environment block such as:

```json
{
  "environment": {
    "policyId": "operator-environment-v1",
    "importNames": ["PATH", "MODEL_PROVIDER_API_KEY"]
  },
  "trustedReceiptParent": "/home/operator/.local/state/scrum-pi-team-skills/receipts",
  "authentication": {
    "authenticatorId": "operator-receipts-v1",
    "keyEnvironmentVariable": "SPTS_RECEIPT_AUTH_KEY"
  }
}
```

The CLI adapter reads only the explicitly listed environment names and never enumerates `process.env`; values do not belong in this JSON. For `run` and `inspect`, it additionally reads only the single configured authentication-key variable, requires canonical base64 decoding to at least 32 bytes, never prints it, and uses one fixed redacted failure diagnostic. `plan` does not import the key and prints a redacted object marked `"executableAuthority": false`. `run` stays foregrounded, streams output without persistence, and forwards SIGINT/SIGTERM through its live handle. Exit codes are stable: `0` success, `2` usage, `3` validation/storage failure, `4` invalid inspected chain, `10` child non-zero, `11` signal exit, `12` timeout, and `13` spawn/supervisor failure. The CLI performs no implicit Paca or network call.

Automated tests launch only repository-controlled fixture processes. Launching real Pi, including a smoke test, requires separate stakeholder approval and is not part of normal validation. ACP bridge / `paca-acp-bridge` integration and Paca mutation remain explicitly unimplemented.

## Workspace structure

- `packages/contracts`: JSON Schemas, examples, and AJV-backed validation.
- `packages/runtime`: deterministic launch planning, governed Linux/WSL supervision, and local receipt storage.
- `packages/agents`: reserved for approved agent implementations.
- `packages/tooling`: private plan/run/inspect operator CLI.

All workspaces are private during this baseline phase. Publishing requires a separate Paca task and explicit design.

## License

Licensed under the [MIT License](LICENSE).

# Scrum Pi Team Skills

Development baseline for locally executed Pi agents supporting a Scrum team.

Paca is the Scrum control plane and system of record. Future agents run as local Pi processes governed by pi-daddy. This repository currently contains only the development baseline and a minimal contract that records those constraints; it does not implement the agent system.

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

`packages/contracts` exports the `AgentExecutionManifest` TypeScript type and the AJV-backed `validateGovernedAgentExecutionManifest` composite validator for version `1.0.0`. That explicitly named composite validator is the sole authoritative acceptance boundary for governed execution. It composes structural validation with credential checks, canonical Pi tool ordering, and an exactly matching pi-daddy grant, so every accepted execution remains local Pi, governed by pi-daddy, with Paca as the system of record. The older `validateAgentExecutionManifest` name remains only as a deprecated compatibility alias to the same composite function.

> **Warning:** `agent-execution-manifest.schema.json` is a portable, structural data-envelope artifact only. Direct AJV success does **not** authorize governed execution and does not evaluate cross-field invariants. Never use structure-only validation to launch an agent.

```ts
import { validateGovernedAgentExecutionManifest } from "@scrum-pi-team-skills/contracts";

const result = validateGovernedAgentExecutionManifest(candidate);
if (!result.valid)
  throw new Error("manifest is not authorized for governed execution");
```

Valid examples for all four roles are in `packages/contracts/examples`, and every example passes the governed composite validator. Manifests contain logical skill and prompt-template references, never executable or installation paths. They also require zero delegation depth, explicit authorization boundaries, and metadata-only receipts.

Authorized objective and out-of-scope text is inert data: it may name a command such as `curl example.test`, but launch planning never interprets or adds that prose to executable arguments. Credential-shaped content remains prohibited and its validation diagnostics do not echo the suspected value. Normalized absolute WSL paths may contain spaces, which remain single argument values; execution-shaping paths and registries still reject controls, shell/injection characters, credential shapes, duplicate or trailing separators, and exact `.` or `..` segments without silently normalizing them.

`createPiLaunchPlan` from `@scrum-pi-team-skills/runtime` is a pure planning function. Supply a validated manifest and explicit local Pi, pi-daddy grant-extension, governance-ledger, skill-registry, and prompt-template-registry paths. It returns:

- the Pi executable, argument array, and repository working directory;
- only the governed `PI_GRANTS_GRANT`, `PI_GRANTS_MAX_DEPTH=0`, and `PI_GRANTS_LEDGER` environment additions;
- an array-based redacted operator preview and execution/Paca correlation identity.

The plan starts with `--no-extensions` and loads only the supplied pi-daddy grant extension. It also uses `--no-skills` and `--no-prompt-templates` before adding approved resources in manifest order, then uses `--no-context-files` to disable global, ancestor, and repository `AGENTS.md`/`CLAUDE.md` discovery. No inherited context or undeclared system-prompt file is added: prompt content comes only from governed manifest resource references. The plan passes approved tools through `--tools`, always revalidates through `validateGovernedAgentExecutionManifest`, never returns a shell command, and does not spawn a process, inspect the filesystem, modify Git, access the network, or update Paca.

## Workspace structure

- `packages/contracts`: JSON Schemas, examples, and AJV-backed validation.
- `packages/runtime`: pure deterministic local Pi launch planning.
- `packages/agents`: reserved for approved agent implementations.
- `packages/tooling`: reserved for repository and development tooling.

All workspaces are private during this baseline phase. Publishing requires a separate Paca task and explicit design.

## License

Licensed under the [MIT License](LICENSE).

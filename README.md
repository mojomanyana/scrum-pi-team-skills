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

## Workspace structure

- `packages/contracts`: JSON Schemas and AJV-backed validation.
- `packages/runtime`: reserved for approved local runtime behavior.
- `packages/agents`: reserved for approved agent implementations.
- `packages/tooling`: reserved for repository and development tooling.

All workspaces are private during this baseline phase. Publishing requires a separate Paca task and explicit design.

## License

Licensed under the [MIT License](LICENSE).

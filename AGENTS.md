# Repository operating guidance

## Authority and scope

- Paca is the Scrum control plane and system of record. Work only from an authorized Paca task and keep task status there.
- All agents execute as local Pi processes governed by pi-daddy.
- Do not add remote agent execution, an alternate control plane, or an alternate system of record.
- Do not implement speculative agent, runtime, or tooling abstractions. Add only behavior required by the active task.

## Development baseline

- Use Node.js 24 LTS, npm 11, TypeScript, and ESM.
- Use npm workspaces; do not introduce another package manager or workspace orchestrator without an approved task.
- Keep JSON contracts in `packages/contracts` and validate them with AJV.
- Keep workspace packages private unless publishing is explicitly approved.
- Preserve the MIT license in root and workspace package metadata.

## Change workflow

1. Read the active Paca task and the nearest code and tests before editing.
2. Add or update a failing test before behavior changes when practical.
3. Keep changes small and within the owning workspace.
4. Run targeted tests while developing.
5. Run `npm run quality` before requesting review.
6. Update documentation when commands, prerequisites, contracts, or repository structure change.

Do not commit generated `dist`, coverage, environment, or dependency directories. Never commit credentials or secrets. Do not push, publish, migrate data, or access production unless the active task explicitly authorizes that side effect.

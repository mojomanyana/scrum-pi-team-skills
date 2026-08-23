# Governed local runtime

Private SPTS runtime package for Node 24 on Linux/WSL.

SPTS-7 `createPiLaunchPlan` is pure and issues an immutable in-process authority. SPTS-8 `startGovernedLocalProcess` executes only that exact issued object with `shell:false`, an explicit environment, foreground pipe/wait supervision, and a dedicated POSIX process group. `detached:true` creates the group; `unref()` is never used. Termination is live-handle-only SIGTERM followed by bounded-grace SIGKILL escalation.

Environment values are copied into private policy storage and are never exposed in policy objects or lifecycle receipts. Output is streamed and represented in receipts only by byte counts and SHA-256 digests. The injected clock, execution-ID source, process adapter, and `ReceiptSink` are deterministic test seams.

The local filesystem sink requires an explicit root, creates mode-0700/mode-0600 storage, uses exclusive creation and append semantics, and refuses existing receipt paths. The private tooling package owns XDG/HOME default selection and named shell-variable imports so core runtime never reads `process.env`.

See the root README for APIs, receipt contract `spts.lifecycle-receipt/1.0.0`, CLI usage, platform limits, and approval boundaries.

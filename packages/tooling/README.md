# Private governed-runtime tooling

This private workspace provides `spts-runtime`:

- `plan --manifest FILE --operator-config FILE` validates inputs and prints only a redacted, non-executable preview without importing authentication key material;
- `run --manifest FILE --operator-config FILE` rebuilds trusted launch authority in-process, imports only configured environment names, requires the configured receipt authentication key, supervises the foreground process group, streams output, and writes a lifecycle chain plus terminal anchor;
- `inspect --execution-id ID --operator-config FILE` resolves the controlled child beneath the configured trusted parent and requires successful chain and HMAC-SHA256 anchor verification.

Operator configuration names exactly one environment variable containing the canonical base64 authentication key and a non-secret authenticator ID. `run` and `inspect` read only that named variable, require at least 32 decoded bytes, never enumerate `process.env`, and report missing/malformed values with one fixed redacted diagnostic. Temporary decoded bytes are zeroed, but JavaScript cannot reliably erase the original immutable environment string; provisioning, process-environment hygiene, and rotation remain operator responsibilities.

The trusted receipt parent must already be an absolute normalized Linux path owned by the process uid with mode `0700`. Receipt storage rejects traversal, symlinks, collisions, and unsafe permissions. Replacement by the same privileged owner is outside this process-local path boundary.

There is no terminate-by-PID, Paca, network, remote-execution, publication, or real-Pi smoke command. See the root README for lifecycle invariants, receipt locations, exit behavior, and the stakeholder-approval requirement for any real Pi launch.

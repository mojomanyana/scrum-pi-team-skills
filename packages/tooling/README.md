# Private governed-runtime tooling

This private workspace provides `spts-runtime`:

- `plan --manifest FILE --operator-config FILE` validates inputs and prints only a redacted, non-executable preview;
- `run --manifest FILE --operator-config FILE` rebuilds trusted launch authority in-process, imports only configured shell names, supervises the foreground process group, streams output, and writes lifecycle receipts;
- `inspect --receipt-file FILE` verifies one explicit JSONL chain.

There is no terminate-by-PID, Paca, network, remote-execution, publication, or real-Pi smoke command. See the root README for the operator configuration boundary, receipt locations, exit behavior, and stakeholder-approval requirement for any real Pi launch.

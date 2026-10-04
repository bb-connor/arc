# Inbound authority local evidence

`commands.json` retains every terminal command, its exit, duration, uncompressed
log SHA-256 and test summaries. `*.log.gz` are deterministic compressed originals.
Failures, the CLI test abort, a misaddressed gate command and the interrupted
control-plane campaign remain negative evidence. A later pass does not change
those outcomes. The control-plane campaign did not finish the whole owner suite.

`sources.json` hashes the modified source/configuration/specification files at
qualification before commit; evidence files and preexisting `output/` are excluded.
`binaries.json` identifies current retained binaries from successful final commands;
older binaries were not all retained, so earlier campaigns establish log evidence.
`progress.md` retains design rulings and corrections. `independent-review.md`
retains the original changes-requested verdict and dispositions, without implying
a second reviewer approval.

Commands ran in `/tmp/arc-security-launch` with Rust 1.94.1 on Linux aarch64,
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`,
`CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0` and `CARGO_BUILD_JOBS=4`.
The retained runner and direct CLI control are local reproduction helpers.

This is local source qualification. It does not establish hosted CI, deployment,
release approval, TLS operations, durable replay activation or full workspace
runtime coverage. See the execution record for the exact completed checks.

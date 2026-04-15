# Summary 316-16

Phase `316` added a sixteenth coverage wave focused on the request-handling
surface in `arc-api-protect/src/proxy.rs`.

The implemented coverage wave added new tests in:

- `arc-api-protect/src/proxy.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-api-protect`
- `cargo test -p arc-api-protect`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-api-protect-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-api-protect --json --summary-only --output-path /tmp/arc-phase316-api-protect-coverage.json`
- `git diff --check -- crates/arc-api-protect/src/proxy.rs`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-api-protect` crate total: `350/505` -> `674/762` lines (`+324`,
  `88.45%`)
- `arc-api-protect/src/proxy.rs`: `63/187` -> `387/444` lines (`+324`,
  `87.16%`)

This wave exercises the real proxy behavior instead of only route synthesis:
the handler now has direct coverage for deny-with-receipt responses, successful
upstream forwarding with selective header propagation, early method rejection,
and upstream failure handling after an allowed evaluation.

Applying the measured `arc-api-protect` replacement delta on top of the
isolated workspace `llvm-cov` baseline and the earlier `arc-acp-proxy`,
`arc-policy`, and refreshed `arc-settle` waves moves the estimated local
workspace total to `99074/139557` (`70.99%`). Phase `316` still remains open.

# Summary 316-22

Phase `316` then took a broader trust-control handler/runtime coverage wave
across the report endpoints and reran the comparable filtered full-workspace
coverage lane.

The implemented tests updated:

- `crates/arc-cli/tests/receipt_query.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave22 cargo test -p arc-cli --test receipt_query test_trust_control_report_endpoints_require_service_auth -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave22 cargo test -p arc-cli --test receipt_query test_trust_control_report_endpoints_require_receipt_db_configuration -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace4-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace4-next-coverage.json`
- `git diff --check -- crates/arc-cli/tests/receipt_query.rs`

This wave added two broader live-service integration checks:

- twelve trust-control report endpoints reject missing/invalid bearer auth with
  `401` plus `WWW-Authenticate: Bearer`
- those same report surfaces fail closed without `--receipt-db`, exercising
  both endpoint-specific messages and the shared `trust control service
  requires --receipt-db` path

Those checks cover report handlers in
`crates/arc-cli/src/trust_control/http_handlers_b.rs`, not helper-only
assertions.

Coverage-gate result:

- the comparable filtered full-workspace rerun moved from `108092/147497`
  (`73.28%`) to `109272/148732` (`73.47%`)
- that is `+1180` covered lines against `+1235` total counted lines
- at the current denominator, phase `316` still needs another `9714` covered
  lines to reach `80%`

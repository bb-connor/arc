# Summary 316-21

Phase `316` then took another trust-control handler coverage wave focused on
the credit facility/bond issue endpoints' early fail-closed branches.

The implemented tests updated:

- `crates/arc-cli/tests/receipt_query.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave21 cargo test -p arc-cli --test receipt_query test_credit_issue_endpoints_require_service_auth -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave21 cargo test -p arc-cli --test receipt_query test_credit_issue_endpoints_require_receipt_db_configuration -- --exact`
- `git diff --check -- crates/arc-cli/tests/receipt_query.rs`

This wave added two behaviorally meaningful integration checks against a live
spawned trust service:

- facility and bond issue endpoints reject missing/invalid bearer auth with
  `401` plus `WWW-Authenticate: Bearer`
- facility and bond issue endpoints fail closed with `409` when the service is
  started without `--receipt-db`

These are real handler error paths in
`crates/arc-cli/src/trust_control/http_handlers_b.rs`, not helper-only
assertions.

Coverage-gate note:

- this turn did **not** rerun the comparable filtered full-workspace
  `llvm-cov` artifact
- the latest completed comparable workspace measurement therefore remains
  `108092/147497` lines (`73.28%`)

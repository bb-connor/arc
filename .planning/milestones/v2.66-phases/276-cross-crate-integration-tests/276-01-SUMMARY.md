# Summary 276-01

Phase `276-01` added real hosted-mcp to SIEM integration coverage on the shared
kernel receipt-store seam:

- [support/mod.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-hosted-mcp/tests/support/mod.rs) now exposes the temp `receipt_db_path` used by the hosted-mcp runtime harness
- [cross_crate_pipeline.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-hosted-mcp/tests/cross_crate_pipeline.rs) now proves a real hosted `echo_json` tool call writes a receipt that `arc-siem` can export from the exact same SQLite database
- The same test file also proves the practical `TEST-13` boundary that exists today: a fail-closed hosted-mcp auth error returns `401` and emits neither admin-visible receipts nor SIEM exports from that DB

Verification:

- `cargo test -p arc-hosted-mcp --test cross_crate_pipeline -- --nocapture`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/276-cross-crate-integration-tests/276-01-PLAN.md`

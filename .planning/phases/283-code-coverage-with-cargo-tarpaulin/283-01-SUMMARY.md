# Summary 283-01

Phase `283-01` turned ARC's empty `coverage/` directory into a real CI and
release-qualification signal:

- [scripts/run-coverage.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/run-coverage.sh), [coverage/README.md](/Users/connor/Medica/backbay/standalone/arc/coverage/README.md), [.github/workflows/ci.yml](/Users/connor/Medica/backbay/standalone/arc/.github/workflows/ci.yml), and [scripts/qualify-release.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/qualify-release.sh) now produce, document, upload, and stage tarpaulin HTML/JSON/LCOV artifacts under `coverage/` and `target/release-qualification/coverage/`
- The first full workspace tarpaulin pass measured `67.43%` line coverage, and the enforced floor was set to `67%` in CI and release qualification so future drops fail from a measured baseline instead of a guessed threshold
- The full coverage sweep also exposed stale test and status assumptions, which were hardened in [web3_e2e_qualification.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-settle/tests/web3_e2e_qualification.rs), [runtime_devnet.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-settle/tests/runtime_devnet.rs), [receipt_query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/receipt_query.rs), [mcp_serve_http.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mcp_serve_http.rs), [trust_control.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/trust_control.rs), and [remote_mcp.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/remote_mcp.rs) so the measured run could finish cleanly

Verification:

- `./scripts/run-coverage.sh`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/283-code-coverage-with-cargo-tarpaulin/283-01-PLAN.md`

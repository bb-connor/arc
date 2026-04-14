---
status: passed
---

# Phase 315 Verification

## Outcome

Phase `315` is complete locally. Every workspace crate under `crates/` now has
at least one integration-test file, the security-critical crates have explicit
success/failure/edge coverage, and the A2A/MCP-facing crates now exercise real
protocol exchanges through their exported runtime surfaces.

## Evidence

- `.planning/phases/315-integration-test-coverage-expansion/315-CONTEXT.md`
- `.planning/phases/315-integration-test-coverage-expansion/315-01-SUMMARY.md`
- `.planning/phases/315-integration-test-coverage-expansion/315-02-SUMMARY.md`
- `.planning/phases/315-integration-test-coverage-expansion/315-03-SUMMARY.md`
- `crates/*/tests/integration_smoke.rs`

## Validation

- `for dir in crates/*; do if [ -d "$dir" ]; then if ! find "$dir/tests" -maxdepth 1 -type f >/dev/null 2>&1; then printf '%s\n' "${dir##*/}"; fi; fi; done`
- `cargo test -p arc-credentials --test integration_smoke`
- `cargo test -p arc-policy --test integration_smoke`
- `cargo test -p arc-store-sqlite --test integration_smoke`
- `cargo test -p arc-mcp-edge --test integration_smoke`
- `cargo test -p arc-mcp-adapter --test integration_smoke`
- `cargo test -p arc-a2a-adapter --test integration_smoke`
- `cargo test -p arc-appraisal -p arc-autonomy -p arc-credit -p arc-did -p arc-federation -p arc-governance -p arc-link -p arc-listing -p arc-manifest -p arc-market -p arc-mercury-core -p arc-open-market -p arc-underwriting -p arc-wall-core -p arc-web3 --test integration_smoke`
- `cargo test -p arc-anchor --features web3 --test integration_smoke`
- `git diff --check -- .planning/phases/315-integration-test-coverage-expansion crates/arc-anchor/tests/integration_smoke.rs crates/arc-a2a-adapter/tests/integration_smoke.rs crates/arc-appraisal/tests/integration_smoke.rs crates/arc-autonomy/tests/integration_smoke.rs crates/arc-credentials/tests/integration_smoke.rs crates/arc-credit/tests/integration_smoke.rs crates/arc-did/tests/integration_smoke.rs crates/arc-federation/tests/integration_smoke.rs crates/arc-governance/tests/integration_smoke.rs crates/arc-link/tests/integration_smoke.rs crates/arc-listing/tests/integration_smoke.rs crates/arc-manifest/tests/integration_smoke.rs crates/arc-market/tests/integration_smoke.rs crates/arc-mcp-adapter/tests/integration_smoke.rs crates/arc-mcp-edge/tests/integration_smoke.rs crates/arc-mercury-core/tests/integration_smoke.rs crates/arc-open-market/tests/integration_smoke.rs crates/arc-policy/tests/integration_smoke.rs crates/arc-store-sqlite/tests/integration_smoke.rs crates/arc-underwriting/tests/integration_smoke.rs crates/arc-wall-core/tests/integration_smoke.rs crates/arc-web3/tests/integration_smoke.rs`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`

## Requirement Closure

`PROD-01`, `PROD-02`, and `PROD-03` are satisfied locally: the file-count gap
is closed across the workspace, the explicitly called-out security/storage
crates have behaviorally meaningful integration coverage, and the protocol
crates now execute real exchange flows in integration tests.

## Next Step

Phase `316`: coverage push and SQLite store hardening.

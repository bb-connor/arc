---
phase: 315-integration-test-coverage-expansion
created: 2026-04-13
status: complete
---

# Phase 315 Research

## Sources Reviewed

- `crates/*/Cargo.toml`
- `crates/*/src/lib.rs`
- existing integration-test crates under `crates/*/tests`
- `crates/arc-credentials/src/tests.rs`
- `crates/arc-policy/src/evaluate/tests.rs`
- `crates/arc-store-sqlite/src/receipt_store/tests.rs`
- `crates/arc-mcp-edge/src/runtime/runtime_tests.rs`
- `crates/arc-mcp-adapter/src/lib.rs`
- `crates/arc-a2a-adapter/src/tests/all.rs`

## Findings

1. The workspace currently has `37` crates and `22` of them have zero files in
   `tests/`.
2. The zero-test set is mixed:
   - protocol/runtime crates needing behavioral integration tests
   - storage/security crates needing success/failure/edge-case coverage
   - domain/artifact crates where one narrow public-API smoke lane is enough
     for this phase
3. The targeted crates already have reusable public fixtures and patterns in
   internal test modules, so the integration tests can copy representative
   flows without introducing new test-only production hooks.
4. `arc-anchor` is `web3`-gated, so its integration lane must be explicitly
   feature-gated as well.

## Zero-Test Crates At Phase Start

- `arc-a2a-adapter`
- `arc-anchor`
- `arc-appraisal`
- `arc-autonomy`
- `arc-credentials`
- `arc-credit`
- `arc-did`
- `arc-federation`
- `arc-governance`
- `arc-link`
- `arc-listing`
- `arc-manifest`
- `arc-market`
- `arc-mcp-adapter`
- `arc-mcp-edge`
- `arc-mercury-core`
- `arc-open-market`
- `arc-policy`
- `arc-store-sqlite`
- `arc-underwriting`
- `arc-wall-core`
- `arc-web3`

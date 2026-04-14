---
phase: 315-integration-test-coverage-expansion
created: 2026-04-13
status: in_progress
---

# Phase 315 Validation

## Required Evidence

- Every crate under `crates/` has at least one file under `tests/`.
- `arc-credentials`, `arc-policy`, and `arc-store-sqlite` each have
  integration tests covering:
  - one success path
  - one failure path
  - one edge case
- `arc-a2a-adapter`, `arc-mcp-adapter`, and `arc-mcp-edge` each have
  integration tests that exercise real exported exchange/runtime contracts.

## Verification Commands

- `for f in $(rg --files crates -g 'Cargo.toml' | sort); do d=$(dirname "$f"); test -d "$d/tests" && find "$d/tests" -maxdepth 1 -type f | grep -q . || { echo "missing tests: $d"; exit 1; }; done`
- `cargo test -p arc-credentials --test integration_smoke`
- `cargo test -p arc-policy --test integration_smoke`
- `cargo test -p arc-store-sqlite --test integration_smoke`
- `cargo test -p arc-a2a-adapter --test integration_smoke`
- `cargo test -p arc-mcp-adapter --test integration_smoke`
- `cargo test -p arc-mcp-edge --test integration_smoke`
- `cargo test -p arc-anchor --features web3 --test integration_smoke`
- `git diff --check -- crates .planning/phases/315-integration-test-coverage-expansion`

## Regression Focus

- new integration tests use only exported APIs and do not depend on crate-local
  `#[cfg(test)]` internals
- the broad smoke lane stays lightweight enough to keep the workspace test
  surface practical
- the targeted protocol/storage/security crates get real behavioral assertions
  rather than file-count-only coverage

---
phase: 21
slug: release-hygiene-and-codebase-structure
status: passed
completed: 2026-03-25
---

# Phase 21 Verification

Phase 21 passed targeted verification for source-only release inputs and the
first maintainability split inside the CLI runtime surface.

## Automated Verification

- `./scripts/check-release-inputs.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p pact-cli -- -D warnings`
- `cargo test -p pact-cli --test provider_admin -- --nocapture`
- `cargo test -p pact-cli --test certify -- --nocapture`
- `cargo test -p pact-cli --test federated_issue -- --nocapture`
- `cargo test -p pact-cli --test evidence_export -- --nocapture`
- `cargo test -p pact-cli --test reputation_issuance -- --nocapture`

## Result

Passed. Phase 21 now satisfies `PROD-07` and `PROD-08`:

- generated Python build/cache artifacts are no longer tracked as release inputs
  and the workspace CI lane now fails if those artifact classes return
- the CLI control-plane admin handlers live in `crates/pact-cli/src/admin.rs`
  instead of remaining embedded in the 4,690-line `main.rs` entrypoint
- targeted lint and regression coverage stayed green after the refactor and the
  related small hygiene fixes

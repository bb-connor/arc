status: passed

# Phase 170 Verification

## Outcome

Phase `170` is complete. ARC now fails closed when web3-enabled deployments do
not have local durable receipt storage, kernel-signed checkpoint issuance, and
canonical evidence-bundle completeness across kernel, anchor, and settlement
surfaces.

## Evidence

- `crates/arc-cli/src/policy.rs`
- `crates/arc-control-plane/src/lib.rs`
- `crates/arc-kernel/src/lib.rs`
- `crates/arc-kernel/src/receipt_store.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`
- `crates/arc-anchor/src/lib.rs`
- `crates/arc-settle/src/config.rs`
- `crates/arc-settle/src/solana.rs`
- `crates/arc-settle/src/lib.rs`
- `crates/arc-settle/tests/runtime_devnet.rs`
- `scripts/qualify-web3-runtime.sh`
- `docs/standards/ARC_ANCHOR_PROFILE.md`
- `docs/standards/ARC_SETTLE_PROFILE.md`
- `docs/standards/ARC_WEB3_PROFILE.md`
- `docs/release/ARC_WEB3_READINESS_AUDIT.md`
- `spec/PROTOCOL.md`
- `.planning/phases/170-mandatory-receipt-storage-checkpointing-and-web3-evidence-gates/170-01-SUMMARY.md`
- `.planning/phases/170-mandatory-receipt-storage-checkpointing-and-web3-evidence-gates/170-02-SUMMARY.md`
- `.planning/phases/170-mandatory-receipt-storage-checkpointing-and-web3-evidence-gates/170-03-SUMMARY.md`

## Validation

- `cargo fmt --all --check`
- `env CARGO_TARGET_DIR=target/phase170-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p arc-kernel -p arc-control-plane -p arc-anchor -p arc-settle -p arc-cli --tests`
- `env CARGO_TARGET_DIR=target/arc-cli-web3-evidence CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-cli web3_evidence -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/arc-control-plane-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-control-plane web3_evidence -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/arc-kernel-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-kernel web3_evidence -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/arc-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-anchor evidence_bundle -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/arc-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle evidence_substrate -- --test-threads=1`
- `./scripts/qualify-web3-runtime.sh`
- `git diff --check`

## Requirement Closure

- `W3INT-02` complete

## Next Step

Phase `171`: Bond Reserve Semantics and Oracle Authority Reconciliation.

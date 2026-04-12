status: passed

# Phase 171 Verification

## Outcome

Phase `171` is complete. ARC now tells one truthful money-handling story
across contracts, bindings, runtime config, receipt evidence, and public docs:
the bond vault locks collateral on-chain while preserving reserve requirement
metadata from signed ARC bond terms, and `arc-link` is the sole supported
runtime FX authority for official web3 lanes.

## Evidence

- `contracts/src/interfaces/IArcBondVault.sol`
- `contracts/src/ArcBondVault.sol`
- `crates/arc-web3-bindings/src/interfaces.rs`
- `crates/arc-settle/src/config.rs`
- `crates/arc-settle/src/lib.rs`
- `crates/arc-settle/src/evm.rs`
- `crates/arc-core/src/web3.rs`
- `crates/arc-link/src/lib.rs`
- `contracts/scripts/qualify-devnet.mjs`
- `contracts/README.md`
- `contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md`
- `contracts/deployments/local-devnet.json`
- `contracts/reports/local-devnet-qualification.json`
- `docs/standards/ARC_LINK_PROFILE.md`
- `docs/standards/ARC_LINK_KERNEL_RECEIPT_POLICY.md`
- `docs/standards/ARC_WEB3_PROFILE.md`
- `docs/standards/ARC_SETTLE_PROFILE.md`
- `docs/standards/ARC_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json`
- `docs/release/ARC_WEB3_PARTNER_PROOF.md`
- `docs/release/RELEASE_CANDIDATE.md`
- `spec/PROTOCOL.md`
- `.planning/phases/171-bond-reserve-semantics-and-oracle-authority-reconciliation/171-01-SUMMARY.md`
- `.planning/phases/171-bond-reserve-semantics-and-oracle-authority-reconciliation/171-02-SUMMARY.md`
- `.planning/phases/171-bond-reserve-semantics-and-oracle-authority-reconciliation/171-03-SUMMARY.md`

## Validation

- `cargo fmt --all`
- `pnpm --dir contracts compile`
- `env CARGO_TARGET_DIR=target/phase171-core CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-core web3 -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/phase171-link CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-link -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/phase171-settle CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle --lib -- --test-threads=1`
- `env CARGO_TARGET_DIR=target/phase171-bindings CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-web3-bindings -- --test-threads=1`
- `pnpm --dir contracts devnet:smoke`
- `./scripts/qualify-web3-runtime.sh`
- `jq empty docs/standards/ARC_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json docs/standards/ARC_ANCHOR_INCLUSION_PROOF_EXAMPLE.json docs/standards/ARC_ANCHOR_PROOF_BUNDLE_EXAMPLE.json docs/standards/ARC_WEB3_CHAIN_CONFIGURATION.json docs/standards/ARC_WEB3_CONTRACT_PACKAGE.json`
- `git diff --check`

## Requirement Closure

- `W3INT-03` complete
- `W3INT-05` advanced; final parity closure continues in phase `172`

## Next Step

Phase `172`: Secondary-Lane Verification, Generated Bindings, and
Contract/Runtime Parity Qualification.

---
phase: 316-coverage-push-and-store-hardening
created: 2026-04-13
status: in_progress
---

# Phase 316 Validation

## Required Evidence

- `scripts/run-coverage.sh` reports workspace line coverage at or above `80%`.
- The coverage delta comes from previously weak crates or weak public surfaces,
  not only from trivial additions to already-strong modules.
- `SqliteReceiptStore` is backed by a connection pool on the hot runtime write
  path.
- One test proves concurrent receipt writes succeed through a shared store
  instance.

## Verification Commands

- `cargo check -p arc-store-sqlite`
- `cargo fmt -p arc-store-sqlite`
- `cargo test -p arc-store-sqlite`
- `cargo test -p arc-store-sqlite append_arc_receipt_returning_seq_supports_concurrent_writers -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-store-sqlite-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-store-sqlite --json --summary-only --output-path /tmp/arc-phase316-store-sqlite-coverage.json`
- `cargo test -p arc-store-sqlite --lib liability_claim_lifecycle_persists_package_through_payout_receipt -- --nocapture`
- `cargo test -p arc-store-sqlite --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-store-next cargo llvm-cov -p arc-store-sqlite --lib --json --summary-only --output-path /tmp/arc-phase316-store-sqlite-coverage-next.json`
- `cargo test -p arc-policy`
- `cargo test -p arc-link`
- `cargo test -p arc-settle`
- `cargo test -p arc-market`
- `cargo test -p arc-governance`
- `cargo test -p arc-open-market`
- `cargo test -p arc-autonomy`
- `cargo test -p arc-anchor`
- `cargo test -p arc-listing`
- `cargo test -p arc-federation`
- `cargo test -p arc-appraisal`
- `cargo test -p arc-control-plane --lib`
- `cargo test -p arc-core`
- `cargo test -p arc-core-types`
- `cargo test -p arc-acp-proxy`
- `cargo test -p arc-api-protect`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy cargo test -p arc-policy`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy-llvm cargo llvm-cov -p arc-policy --json --summary-only --output-path /tmp/arc-phase316-policy-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy-validate-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-policy --json --summary-only --output-path /tmp/arc-phase316-policy-validate-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-acp-proxy-llvm cargo llvm-cov -p arc-acp-proxy --json --summary-only --output-path /tmp/arc-phase316-acp-proxy-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-settle-evm-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-settle --json --summary-only --output-path /tmp/arc-phase316-settle-evm-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-settle-evm2-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-settle --json --summary-only --output-path /tmp/arc-phase316-settle-evm2-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-api-protect-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-api-protect --json --summary-only --output-path /tmp/arc-phase316-api-protect-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace2-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace2-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-next cargo llvm-cov --workspace --json --summary-only --output-path /tmp/arc-phase316-workspace-next-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-next cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace2-next-coverage.json`
- `./scripts/run-coverage.sh`
- `python3 - <<'PY' ... coverage/tarpaulin-report.json ... PY`
- `docker run ... cargo tarpaulin -p arc-policy -p arc-link -p arc-settle ...`
- `docker run ... cargo tarpaulin -p arc-market ...`
- `docker run ... cargo tarpaulin -p arc-governance ...`
- `docker run ... cargo tarpaulin -p arc-open-market ...`
- `docker run ... cargo tarpaulin -p arc-autonomy ...`
- `docker run ... cargo tarpaulin -p arc-anchor ...`
- `docker run ... cargo tarpaulin -p arc-listing ...`
- `docker run ... cargo tarpaulin -p arc-federation ...`
- `docker run ... cargo tarpaulin -p arc-appraisal ...`
- `docker run ... cargo tarpaulin -p arc-control-plane --lib ...`
- `docker run ... cargo tarpaulin -p arc-core ...`
- `docker run ... cargo tarpaulin -p arc-core-types ...`
- `git diff --check -- .planning/phases/316-coverage-push-and-store-hardening crates/arc-kernel/src/capability_lineage.rs crates/arc-kernel/src/receipt_store.rs crates/arc-store-sqlite`

## Regression Focus

- pooled connections still apply the same WAL / synchronous / busy-timeout
  setup as the old single-connection store
- receipt sequencing and checkpoint persistence remain stable after the pool
  change
- the coverage push exercises real public behavior in weak crates instead of
  introducing low-signal assertions

## Current Measured State

- Full workspace baseline from `coverage/summary.txt`: `65.39%`
  (`28285/43258` lines covered)
- Targeted crate deltas against that workspace baseline:
  - `arc-policy`: `545/1900` -> `998/1900` (`+453`)
  - `arc-link`: `583/1111` -> `652/1111` (`+69`)
  - `arc-settle`: `479/1461` -> `624/1461` (`+145`)
  - `arc-market`: `397/989` -> `641/989` (`+244`)
  - `arc-governance`: `251/391` -> `275/391` (`+24`)
  - `arc-open-market`: `320/515` -> `332/515` (`+12`)
  - `arc-autonomy`: `329/510` -> `355/510` (`+26`)
  - `arc-anchor`: `476/852` -> `662/852` (`+186`)
  - `arc-listing`: `434/605` -> `530/605` (`+96`)
  - `arc-federation`: `262/450` -> `439/450` (`+177`)
  - `arc-appraisal`: `546/726` -> `721/726` (`+175`)
  - `arc-control-plane`: `118/981` -> `749/981` (`+631`)
  - `arc-core`: `441/718` -> `688/718` (`+247`)
  - `arc-core-types`: `936/1202` -> `1025/1202` (`+89`)
- Additional verified local wave not yet folded into the workspace estimate:
  - `arc-policy/src/conditions.rs`: `403/420` lines (`95.95%`) via
    `cargo llvm-cov`
  - `arc-policy/src/detection.rs`: `529/538` lines (`98.33%`) via
    `cargo llvm-cov`
  - `arc-policy/src/receipt.rs`: `201/201` lines (`100.00%`) via
    `cargo llvm-cov`
  - `arc-policy/src/merge.rs`: `684/727` lines (`94.09%`) via
    `cargo llvm-cov`
  - `arc-policy/src/resolve.rs`: `196/213` lines (`92.02%`) via
    `cargo llvm-cov`
  - Latest local `llvm-cov` crate summary for `arc-policy` after the
    follow-up merge/resolve wave: `3375/4287` lines (`78.73%`)
- Separate isolated local `llvm-cov` workspace baseline for the current dirty
  tree: `95842/137683` lines (`69.61%`)
- Additional verified local wave measured against that `llvm-cov` workspace
  baseline:
  - `arc-acp-proxy`: `483/1298` -> `1134/1298` lines (`+651`)
  - `arc-acp-proxy/src/compliance.rs`: `0/172` -> `158/172` lines (`91.86%`)
  - `arc-acp-proxy/src/kernel_checker.rs`: `0/105` -> `96/105` lines (`91.43%`)
  - `arc-acp-proxy/src/kernel_signer.rs`: `0/150` -> `90/150` lines (`60.00%`)
  - `arc-acp-proxy/src/proxy.rs`: `16/64` -> `63/64` lines (`98.44%`)
  - `arc-acp-proxy/src/telemetry.rs`: `0/224` -> `209/224` lines (`93.30%`)
  - `arc-acp-proxy/src/transport.rs`: `23/89` -> `53/89` lines (`59.55%`)
- Additional verified local wave measured against that same `llvm-cov`
  workspace baseline:
  - `arc-settle`: `1713/3120` -> `3971/4488` lines (`+2258`)
  - `arc-settle/src/observe.rs`: full-workspace baseline `0/229` source
    lines; refreshed crate-local summary `778/809` lines (`96.17%`)
  - `arc-settle/src/evm.rs`: `621/1555` -> `2094/2343` lines (`89.37%`)
- Additional verified local wave measured against that same `llvm-cov`
  workspace baseline:
  - `arc-policy`: `3501/4287` -> `3918/4571` lines (`+417`)
  - `arc-policy/src/validate.rs`: `341/580` -> `793/864` lines (`91.78%`)
- Additional verified local wave measured against that same `llvm-cov`
  workspace baseline:
  - `arc-api-protect`: `263/454` -> `674/762` lines (`+411`)
  - `arc-api-protect/src/proxy.rs`: `58/193` -> `387/444` lines (`87.16%`)
- Additional verified local wave focused on the weakest remaining
  `arc-store-sqlite` liability-market surface:
  - `arc-store-sqlite/src/receipt_store/liability_market.rs`:
    baseline `90/1103` lines from the earlier workspace baseline ->
    refreshed crate-local `761/1103` lines (`+671`, `68.99%`)
- Estimated local workspace coverage after applying the measured
  `arc-acp-proxy` delta to the isolated `llvm-cov` baseline: about `70.08%`
  (`96493/137683`)
- Estimated local workspace coverage after applying both the measured
  `arc-acp-proxy` and `arc-settle` replacement deltas to that isolated
  `llvm-cov` baseline: about `70.49%` (`97461/138263`)
- Estimated local workspace coverage after applying the measured
  `arc-acp-proxy`, `arc-settle`, and `arc-policy` replacement deltas to that
  isolated `llvm-cov` baseline: about `70.65%` (`97878/138547`)
- Estimated local workspace coverage after refreshing the `arc-settle`
  replacement delta and keeping the measured `arc-acp-proxy` plus
  `arc-policy` deltas on that isolated `llvm-cov` baseline: about `70.78%`
  (`98332/138918`)
- Estimated local workspace coverage after the deeper `arc-settle` EVM prep
  wave and the measured `arc-acp-proxy` plus `arc-policy` deltas on that
  isolated `llvm-cov` baseline: about `70.85%` (`98663/139249`)
- Estimated local workspace coverage after the `arc-api-protect` proxy wave
  plus the measured `arc-acp-proxy`, `arc-policy`, and refreshed `arc-settle`
  deltas on that isolated `llvm-cov` baseline: about `70.99%`
  (`99074/139557`)
- Estimated workspace coverage after the measured crate deltas: about `71.34%`
  (`30859/43258`)
- Refreshed full-workspace `llvm-cov` run on the current dirty tree:
  `103913/143293` lines (`72.52%`) written to
  `/tmp/arc-phase316-workspace2-coverage.json`
- Phase `316` remains open because the workspace is still far below the
  required `80%+` threshold, so a full tarpaulin rerun was deferred until the
  next high-yield coverage wave materially changes the denominator.
- The tarpaulin lane remains unreliable in this dirty tree, so the latest
  `arc-policy` validator wave is folded into the isolated local `llvm-cov`
  workspace estimate instead of the older tarpaulin-based running total.
- The refreshed full-workspace `llvm-cov` run confirms the phase is still
  short by roughly `7.48` percentage points despite the pooled SQLite write
  path and the targeted `liability_market.rs` coverage wave.
- Eighteenth verified local wave focused on the receipt-store liability-claims
  and underwriting-credit surfaces:
  - `arc-store-sqlite`: `5740/11437` -> `6805/11437` lines (`50.19%` ->
    `59.50%`)
  - `arc-store-sqlite/src/receipt_store/liability_claims.rs`:
    `0/911` -> `364/911` lines (`39.96%`)
  - `arc-store-sqlite/src/receipt_store/underwriting_credit.rs`:
    `0/879` -> `529/879` lines (`60.18%`)
- Separate unfiltered full-workspace rerun on the current dirty tree after the
  eighteenth wave: `111339/151079` lines (`73.70%`) written to
  `/tmp/arc-phase316-workspace-next-coverage.json`
- Refreshed comparable full-workspace `llvm-cov` rerun after the eighteenth
  wave: `105290/145396` lines (`72.42%`) written to
  `/tmp/arc-phase316-workspace2-next-coverage.json`
- The comparable full-workspace lane improved absolute covered lines by `1377`,
  but the denominator also grew by `2103`, so the measured rate slipped from
  `72.52%` to `72.42%` on the current dirty tree.
- Phase `316` therefore remains open and is now short by roughly `7.58`
  percentage points against the `80%+` target.

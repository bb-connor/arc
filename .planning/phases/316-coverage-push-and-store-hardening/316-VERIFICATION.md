---
phase: 316-coverage-push-and-store-hardening
verified: 2026-04-15T00:51:34Z
status: gaps_found
score: 2/3 must-haves verified
gaps:
  - truth: "`cargo tarpaulin` reports workspace line coverage at or above 80%"
    status: failed
    reason: "The latest completed comparable filtered full-workspace `llvm-cov` rerun on the current tree now reports `109397/149044` lines (`73.40%`), which regressed slightly from the prior `109272/148732` (`73.47%`) artifact and remains well below the required floor. The newest trust-control wrapper tests ran under `arc-control-plane`, which the comparable filtered lane excludes, so they did not materially move the gate. The focused spawned-child shortcuts remain untrustworthy for this path, and the Docker tarpaulin lane still fails to emit its final HTML/JSON/LCOV artifacts reliably on this machine."
    missing:
      - "Add more high-yield tests in still-weak crates/files until full-workspace coverage exceeds 80%"
human_verification: []
---

# Phase 316 Verification

**Phase Goal:** Coverage reaches `80%+` and the SQLite layer supports
concurrent access.
**Verified:** 2026-04-15T00:51:34Z
**Status:** gaps_found
**Re-verification:** Yes -- refreshed after the `316-19` trust-control
auth/error coverage wave, the comparable filtered full-workspace `llvm-cov`
rerun, the `316-21` trust-control credit-issue handler error-path wave, and
the `316-22` trust-control report endpoint auth / receipt-db matrix wave plus
another comparable filtered full-workspace `llvm-cov` rerun, and the
`316-23` trust-control runtime-wrapper coverage wave plus another comparable
filtered full-workspace `llvm-cov` rerun.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Workspace coverage is at or above `80%` on the current tree. | FAILED | The refreshed comparable filtered full-workspace rerun wrote `/tmp/arc-phase316-workspace5-next-coverage.json` with `109397/149044` covered lines (`73.40%`). That regressed slightly from the prior `109272/148732` (`73.47%`) artifact by `-0.07` points and leaves the phase `9839` covered lines short at the current denominator. The newest runtime-wrapper tests execute under `arc-control-plane`, which this comparable lane excludes, so they do not directly attack the measured gate. The per-test spawned-child shortcuts remain untrustworthy for this path, and the Docker tarpaulin lane still does not emit a final comparable report artifact reliably on this machine. |
| 2 | The latest coverage gains come from weak production surfaces rather than trivial assertions in already-strong modules. | VERIFIED | The nineteenth, twenty-first, and twenty-second waves all targeted weak `arc-cli` trust-control handler behavior through live spawned-service checks rather than padding already-strong store paths, and the twenty-third wave stayed on weak trust-control production code by broadening `service_runtime.rs` wrapper coverage across real request encoding/auth behavior. The latest comparable rerun shows that excluded-package `arc-control-plane` work is not the right measured gate mover, but the test content itself remains behaviorally meaningful production-path coverage, not helper-only assertions. |
| 3 | `SqliteReceiptStore` no longer relies on a single cached runtime connection, and one shared store instance proves concurrent writes succeed. | VERIFIED | The pooled SQLite write-path work is already landed in phase `316`, and `cargo test -p arc-store-sqlite append_arc_receipt_returning_seq_supports_concurrent_writers -- --nocapture` continues to pass alongside the full `cargo test -p arc-store-sqlite` suite. |

**Score:** 2/3 truths verified

## Evidence

- `.planning/phases/316-coverage-push-and-store-hardening/316-CONTEXT.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-01-PLAN.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-02-PLAN.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-19-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-20-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-21-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-22-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-23-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-18-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-17-SUMMARY.md`
- `.planning/phases/316-coverage-push-and-store-hardening/316-VALIDATION.md`
- `crates/arc-store-sqlite/src/receipt_store/tests.rs`
- `crates/arc-cli/tests/capability_lineage.rs`
- `crates/arc-cli/tests/receipt_query.rs`
- `crates/arc-cli/src/trust_control/service_runtime.rs`

## Commands Run

- `cargo fmt -p arc-store-sqlite`
- `cargo test -p arc-store-sqlite`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-store-sqlite-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-store-sqlite --json --summary-only --output-path /tmp/arc-phase316-store-sqlite-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace2-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace2-coverage.json`
- `cargo test -p arc-store-sqlite --lib liability_claim_lifecycle_persists_package_through_payout_receipt -- --nocapture`
- `cargo test -p arc-store-sqlite --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-store-next cargo llvm-cov -p arc-store-sqlite --lib --json --summary-only --output-path /tmp/arc-phase316-store-sqlite-coverage-next.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-next cargo llvm-cov --workspace --json --summary-only --output-path /tmp/arc-phase316-workspace-next-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-next cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace2-next-coverage.json`
- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo test -p arc-cli --test capability_lineage`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave19-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-cli --test capability_lineage --json --output-path /tmp/arc-phase316-wave19-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace3-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace3-next-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave21 cargo test -p arc-cli --test receipt_query test_credit_issue_endpoints_require_service_auth -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave21 cargo test -p arc-cli --test receipt_query test_credit_issue_endpoints_require_receipt_db_configuration -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave22 cargo test -p arc-cli --test receipt_query test_trust_control_report_endpoints_require_service_auth -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave22 cargo test -p arc-cli --test receipt_query test_trust_control_report_endpoints_require_receipt_db_configuration -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace4-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace4-next-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave23 cargo test -p arc-control-plane service_runtime_tests --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace5-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace5-next-coverage.json`
- `git diff --check -- crates/arc-store-sqlite/src/receipt_store/tests.rs`
- `git diff --check -- crates/arc-cli/src/cli/runtime.rs crates/arc-cli/src/cli/dispatch.rs crates/arc-cli/tests/capability_lineage.rs`
- `git diff --check -- crates/arc-cli/tests/receipt_query.rs`

## Requirements Coverage

| Requirement | Status | Evidence |
| --- | --- | --- |
| `PROD-04` | GAP | The latest completed comparable filtered full-workspace coverage is now `73.40%`, not `80%+`, and the Docker tarpaulin lane still is not producing its final report artifacts reliably on this machine. |
| `PROD-05` | SATISFIED | The recent counted waves targeted weak `arc-cli` trust-control handler behavior through live-service auth/fail-closed checks, and the newest runtime-wrapper wave stayed on weak production code even though it landed in excluded `arc-control-plane` acreage. |
| `PROD-06` | SATISFIED | The pooled SQLite runtime write path remains in place, and the concurrent-writer regression test passes. |

## Gaps Summary

Phase `316` closes the SQLite hardening half of the roadmap intent, but the
coverage gate is still materially open. The counted trust-control handler waves
were the right directional pivot out of already-improving store paths, and the
new runtime-wrapper tests are still meaningful production-path checks, but the
latest comparable rerun shows a crucial measurement constraint: work that lands
only under excluded `arc-control-plane` does not move the filtered phase gate.

The latest completed comparable filtered full-workspace lane is now `73.40%`,
down slightly from `73.47%`, leaving a `6.60` percentage-point gap to the
roadmap gate and requiring another `9839` covered lines at the current
denominator. The refreshed hotspot inventory still points at the same counted
acreage inside the trust-control handler/config surface, led by
`http_handlers_a.rs`, `http_handlers_b.rs`, and `config_and_public.rs`. The
remaining closure work is therefore straightforward in shape: add behaviorally
meaningful coverage in those counted surfaces, rerun the comparable filtered
workspace lane, and keep iterating until the total crosses `80%`. The separate
Docker tarpaulin lane also still needs hardening if the repository wants the
HTML/LCOV artifacts from `scripts/run-coverage.sh` to be trustworthy again.

_Verified: 2026-04-15T00:51:34Z_
_Verifier: Codex_

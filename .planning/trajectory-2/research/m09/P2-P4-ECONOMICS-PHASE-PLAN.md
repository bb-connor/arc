# M09 P2-P4 Economics Phase Plan

Date: 2026-04-30
Scope: whole-phase readiness plan for M09 P2 settlement hook, P3 reputation
activation, and P4 marketplace surface. This artifact is planning guidance
only. It does not implement tickets, edit tickets or ledgers, touch Cargo
metadata, or open a PR.

## Current Blockers

Implementation is blocked. Do not start P2, P3, or P4 until the dependency
gates below close or the orchestrator records an explicit waiver.

- Local trajectory state is still on `current_wave: "W1"` while M09 is in W4
  and remains `ticket files authored` / `ready_for_p0` in
  `.planning/trajectory-2/EXECUTION-STATE.json`.
- Wave sequencing in `.planning/trajectory-2/EXECUTION-BOARD.md` puts M09
  after W1, W2, and W3, with M09 before M10 as the recommended W4 order.
- Live GitHub metadata observed during this pass still has upstream blockers:
  PR #342 (`wave/W1/m01/p2.bundle-domain-migration`) is UNSTABLE, PR #349
  (`wave/W2/m04/p0.bundle-oracle-scaffold`) is draft and UNSTABLE, PR #359
  (`wave/W3/m08/p0.t1-open-audit-doc-and-snapshot-prereqs`) is UNSTABLE, and
  PR #360 (`codex/m02-p5-closeout-bookkeeping`) is UNSTABLE.
- This checkout is on `main` at `57526d137`; local `main` is 12 commits behind
  and 1 commit ahead of `origin/main`. Do not cut the eventual implementation
  branch from this divergent local base without first preserving local
  bookkeeping and rebasing or creating a clean origin-based worktree.
- P2 depends on P1 closeout. The current checkout does not contain
  `crates/chio-store-sqlite/src/iou_store.rs`, so the IOU lifecycle contract
  that settlement consumes is not available locally yet.

## Current Source Facts

These are source observations from this checkout, not target-state claims.

- `chio-settle` is still entirely gated by `#![cfg(feature = "web3")]` in
  `crates/chio-settle/src/lib.rs`. Any hook module added in P2 must either
  live under the same feature contract or the crate feature layout must be
  deliberately changed in a P2 commit.
- `chio-settle` exports ops controls, lane classification, finality
  observation, payment helpers, EVM, CCIP, and Solana helpers. It does not have
  `crates/chio-settle/src/hook.rs` or `crates/chio-settle/src/retry.rs`.
- The kernel has `ToolEvaluator` in `crates/chio-kernel/src/kernel/evaluator.rs`
  and output-side `PostInvocationHook` in `crates/chio-kernel/src/post_invocation.rs`.
  It does not have a finalized-receipt economic observer module. The current
  receipt finalization point is `record_chio_receipt` in
  `crates/chio-kernel/src/kernel/responses.rs`: append to receipt store,
  maybe checkpoint, then append to the local log.
- SQLite already creates `settlement_reconciliations` and
  `metered_billing_reconciliations` in
  `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs`, but there is no
  `settle_dead_letters` table and no `dead_letters.rs` module.
- `chio-reputation` is storage-agnostic and currently `include!`s
  `model.rs`, `score.rs`, `compare.rs`, `issuance.rs`, and `tests.rs` from
  `crates/chio-reputation/src/lib.rs`. It has no `feed.rs`, `tier.rs`, or
  `feeds/` directory.
- `chio-guard-registry` publishes and pulls three-layer OCI artifacts
  containing WIT, wasm, and raw guard manifest bytes. It does not parse or
  validate marketplace fields in the registry crate, and
  `crates/chio-guard-registry/Cargo.toml` currently has no `marketplace`
  feature.
- `chio-cli` has `guard publish`, `guard pull`, `guard install`, and
  `reputation local/compare` surfaces. It does not have `settle` or
  `guard market` command modules.
- `chio-appraisal` is runtime-attestation focused today. It has no
  `marketplace_pricing.rs`.
- `chio-underwriting` already has reputation evidence, receipt evidence,
  budget recommendations, premium pricing, and settlement-exposure reason
  codes. It has no `marketplace_limits.rs`.

## Phase Dependency Gates

P2, P3, and P4 should execute as one phase-grain branch only after these gates
are true.

1. W4 gate is open: W1, W2, and W3 are merged or explicitly waived.
2. M09 P0 and P1 are merged. Required P1 outputs are a stable
   `CreditEvaluatorHook`, deterministic IOU envelope shape, SQLite IOU store,
   and legacy receipt migration tests.
3. The M05 async evaluator or finalized-receipt observer dependency is
   verified on current main. If the only available hook is output-side
   `PostInvocationHook`, stop and re-scope before wiring settlement because
   P2 needs signed and persisted receipts, not mutable tool output.
4. M08 arena output shape is available for P3.T2. If it is not present,
   unit tests may use empty input, but production feed activation must stay
   blocked until M08 output files or APIs are real.
5. The trajectory-1 M07 verdict-equality oracle is available for P3.T3, or a
   waiver documents the exact fixture path to consume instead.
6. The trajectory-1 M06 guard registry cosign verification path remains intact.
   P4 can add marketplace fields, but publication remains gated by existing
   verification behavior.
7. Root `Cargo.toml` and `Cargo.lock` are not touched by this P2-P4 branch
   unless a prior P0 gate was missed. P2-P4 should add no new direct
   dependencies.
8. Preflight planning gates pass before dispatch:

```bash
cargo xtask trajectory regen-manifest --check
bash .planning/trajectory-2/scripts/validate-manifest.sh
bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh
```

## Branch And Commit Model

Use one W4 M09 phase branch, not ticket-grain branches:

```text
wave/W4/m09/p2-p4.economics-readiness
```

Keep commits ticket-aligned and ordered. Open one PR only after all P2-P4 gates
pass, but this planning task does not open that PR.

1. `feat(m09): define settlement hook contract`
   - M09.P2.T1.
   - Adds `SettlementHook` and the receipt-to-settle request boundary.
2. `feat(m09): observe finalized receipts for settlement`
   - M09.P2.T2.
   - Adds kernel observer registration and routes signed persisted receipts to
     the hook without changing receipt bytes.
3. `feat(m09): persist settlement retries and dead letters`
   - M09.P2.T3.
   - Adds retry policy and permanent failure storage.
4. `test(m09): prove settlement observer byte identity`
   - M09.P2.T4.
   - Exercises ten receipts and checks settlement count plus receipt identity.
5. `feat(m09): add settle status command`
   - M09.P2.T5.
   - Adds pending, settled, and dead-lettered local status output.
6. `docs(m09): record settlement counters`
   - M09.P2.T6.
   - Updates the M09 audit row with throughput and dead letters.
7. `feat(m09): define reputation feed contract`
   - M09.P3.T1.
   - Adds deterministic feed interfaces with no kernel dependency.
8. `feat(m09): score arena survival feed`
   - M09.P3.T2.
   - Consumes M08 arena round summaries.
9. `feat(m09): score cross-provider equality feed`
   - M09.P3.T3.
   - Consumes M07 verdict matrix equality outputs.
10. `feat(m09): add reputation tiers`
    - M09.P3.T4.
    - Defines tier thresholds used by marketplace discovery.
11. `test(m09): prove reputation feed monotonicity`
    - M09.P3.T5.
    - Adds composition property tests.
12. `docs(m09): record reputation tier distribution`
    - M09.P3.T6.
    - Updates audit distribution from the M04 corpus.
13. `feat(m09): extend guard manifests for marketplace metadata`
    - M09.P4.T1.
    - Adds optional price and reputation floor parsing while preserving
      manifests without those fields.
14. `feat(m09): derive marketplace prices`
    - M09.P4.T2.
    - Adds chio-appraisal-backed pricing helper.
15. `feat(m09): derive marketplace credit limits`
    - M09.P4.T3.
    - Adds chio-underwriting-backed limit helper.
16. `feat(m09): list guard marketplace entries`
    - M09.P4.T4.
    - Adds list output filtered by tenant reputation tier.
17. `feat(m09): show guard marketplace detail`
    - M09.P4.T5.
    - Adds detail output with price, floor, cosign status, and settlements.
18. `feat(m09): install priced marketplace guard`
    - M09.P4.T6.
    - Binds pulled guard ref to tenant bundle and price.
19. `test(m09): exercise priced guard market flow`
    - M09.P4.T7.
    - End-to-end demo: install, call, one IOU, one settlement.

## Exact Future Write Set

This is the intended future implementation write set. It is broader than this
planning task, which only writes this file.

P2 settlement:

- `crates/chio-settle/src/hook.rs`
- `crates/chio-settle/src/retry.rs`
- `crates/chio-settle/src/lib.rs`
- `crates/chio-kernel/src/kernel/settlement_observer.rs`
- `crates/chio-kernel/src/kernel/mod.rs`
- `crates/chio-store-sqlite/src/dead_letters.rs`
- `crates/chio-store-sqlite/src/lib.rs`
- additive bootstrap DDL in
  `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs`
- `crates/chio-kernel/tests/settlement_observer_byte_identity.rs`
- `crates/chio-cli/src/settle.rs`
- `crates/chio-cli/src/main.rs`
- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `.planning/audits/M09-economic-layer-and-lineage.md`

P3 reputation:

- `crates/chio-reputation/src/feed.rs`
- `crates/chio-reputation/src/feeds/mod.rs`
- `crates/chio-reputation/src/feeds/arena_survival.rs`
- `crates/chio-reputation/src/feeds/cross_provider_equality.rs`
- `crates/chio-reputation/src/tier.rs`
- `crates/chio-reputation/src/lib.rs`
- `crates/chio-reputation/tests/feed_monotonicity.rs`
- `.planning/audits/M09-economic-layer-and-lineage.md`

P4 marketplace:

- `crates/chio-guard-registry/src/oci.rs`
- `crates/chio-guard-registry/src/publish.rs`
- `crates/chio-guard-registry/src/pull.rs`
- `crates/chio-appraisal/src/marketplace_pricing.rs`
- `crates/chio-appraisal/src/lib.rs`
- `crates/chio-underwriting/src/marketplace_limits.rs`
- `crates/chio-underwriting/src/lib.rs`
- `crates/chio-cli/src/market.rs`
- `crates/chio-cli/src/main.rs`
- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `crates/chio-cli/tests/market_demo.rs`

Do not edit trajectory tickets, `EXECUTION-STATE.json`, `EXECUTION-LOG.ndjson`,
root Cargo metadata, or unrelated crates in this phase branch unless the
orchestrator reopens scope.

## P2 Settlement Design

### Hook Boundary

`SettlementHook` should accept only finalized receipt inputs. Recommended
contract:

- Input: signed `ChioReceipt`, canonical receipt hash or persisted store seq,
  IOU envelope reference from P1, finalization timestamp, and tenant id copied
  from the receipt when present.
- Output: `SettlementHookOutcome` with `Skipped`, `Queued`, `Settled`, and
  `FailedRetryable` or `FailedPermanent`.
- Error class: observable accounting error only. Hook failure must not deny,
  roll back, re-sign, or mutate a receipt.

The hook should not accept raw caller-supplied tenant, price, or tool identity.
Those values must be derived from the signed receipt and P1 IOU envelope.

### Kernel Observer Boundary

P2.T2 should add a finalized-receipt observer slot, not reuse the existing
output-side post-invocation pipeline. The observer must run after this order:

1. receipt body is constructed;
2. receipt is signed;
3. receipt is appended to the receipt store;
4. checkpoint is triggered if due;
5. local receipt log is appended;
6. settlement observer sees the finalized receipt.

If implementation chooses to call the observer before local log append, the
byte-identity test must still prove that settlement cannot affect receipt
storage, checkpoint leaves, or local log content.

### Retry And Dead-Letter Store

Use a separate dead-letter table. Do not overload the existing
`settlement_reconciliations` table, which is a status projection keyed by
receipt id. P2 needs permanent failure detail, retry counters, and operator
review metadata.

Preferred additive schema:

```sql
CREATE TABLE IF NOT EXISTS settle_dead_letters (
    dead_letter_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
    iou_id TEXT,
    tenant_id TEXT,
    hook_name TEXT NOT NULL,
    lane_kind TEXT NOT NULL,
    attempt_count INTEGER NOT NULL,
    first_attempt_at INTEGER NOT NULL,
    last_attempt_at INTEGER NOT NULL,
    next_retry_at INTEGER,
    failure_class TEXT NOT NULL,
    failure_message TEXT NOT NULL,
    state TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    CHECK (attempt_count >= 1),
    CHECK (state IN ('retry_exhausted', 'operator_paused', 'invalid_input', 'replayed_conflict'))
);

CREATE INDEX IF NOT EXISTS idx_settle_dead_letters_receipt
    ON settle_dead_letters(receipt_id);
CREATE INDEX IF NOT EXISTS idx_settle_dead_letters_tenant_state
    ON settle_dead_letters(tenant_id, state, last_attempt_at);
CREATE INDEX IF NOT EXISTS idx_settle_dead_letters_retry
    ON settle_dead_letters(next_retry_at);
```

Retry policy:

- Backoff is deterministic from receipt id and attempt count, with a documented
  max attempt count.
- Permanent validation failures do not retry.
- Emergency controls in `chio-settle::ops` can pause dispatch without mutating
  receipts.
- Dead-letter insertion is idempotent by deterministic `dead_letter_id`, for
  example `settle-dead-letter:v1:<receipt_id>:<hook_name>`.

### P2 Invariants

- Every settlement attempt references a signed receipt id.
- Settlement never changes `ChioReceipt`, canonical JSON, receipt signature,
  checkpoint membership, or claim-log projections.
- A receipt may have zero or one active settlement lifecycle row and zero or
  one terminal dead-letter row for a given hook version.
- Settlement failure is visible through CLI and audit rows.
- Settlement status uses explicit states: pending, settled, retrying,
  dead_lettered, and skipped.
- Denied receipts do not settle unless P1 explicitly minted a payable IOU for
  a governed financial path.
- P2 must run serially against the receipt store in tests that assert ordering.

## P3 Reputation Design

### Feed Boundary

`ReputationFeed` should stay pure and storage-agnostic like the existing
`chio-reputation` scoring model. Recommended contract:

- Input: normalized feed signal plus a stable subject key.
- Output: deterministic `ReputationDelta` with source id, observed window,
  score delta, evidence refs, and saturation flags.
- No kernel dependency and no SQLite dependency inside the feed trait.
- Feed parsing helpers may accept M08 arena summaries and M07 verdict matrix
  reports, but the core trait consumes normalized structs.

### Feed Sources

`ArenaSurvivalFeed`:

- Consumes M08 arena round outputs after W3 closes.
- Scores survival rate, severity-weighted escapes, and replay confidence.
- Empty input returns zero deltas only in tests and fixture isolation. It is
  not a production fallback once M09 opens.

`CrossProviderEqualityFeed`:

- Consumes trajectory-1 M07 verdict equality results.
- Scores equality pass rate and mismatch severity.
- Unknown provider pairs fail closed at parse time rather than contributing
  neutral positive score.

### Tier Model

Define `ReputationTier` as a stable enum with serialized values:

```text
tier_0
tier_1
tier_2
tier_3
```

Recommended threshold policy:

- `tier_0`: default, insufficient data, or score below publish threshold.
- `tier_1`: basic positive evidence with no critical unresolved failures.
- `tier_2`: independent arena and equality evidence clear minimum thresholds.
- `tier_3`: high score, both feeds strong, no active publisher credential
  revocation, and enough corpus size to avoid single-run inflation.

Threshold tables should be data, not hidden constants in marketplace code.
Marketplace discovery consumes tiers; publication continues to require cosign
verification.

### P3 Invariants

- Feeds are deterministic for the same input corpus.
- Feed composition is monotonic for positive observed signals and bounded for
  repeated evidence.
- Negative or failed evidence cannot improve score.
- Missing feed inputs do not produce positive deltas.
- Marketplace tier checks do not bypass guard registry verification.
- P3 must not introduce a kernel dependency into `chio-reputation`.

## P4 Marketplace Design

### Manifest Boundary

Add optional manifest fields behind the intended marketplace feature:

- `price`: per-invocation guard price with amount units, currency, pricing
  basis, and optional appraisal evidence reference.
- `reputation_floor`: minimum `ReputationTier` needed for discovery or install.

Backward compatibility:

- Missing `price` means zero price.
- Missing `reputation_floor` means `tier_0`.
- Existing three-layer artifact ordering stays unchanged.
- Existing cosign bundle verification remains the publication gate.
- Pull should expose parsed marketplace metadata but must still cache and
  verify the raw guard artifact path as before.

### Pricing Helper

`chio-appraisal::marketplace_pricing` should derive price from manifest plus
tenant context. It should not invent new economic primitives.

Inputs:

- parsed guard marketplace metadata;
- tenant reputation tier;
- runtime attestation appraisal evidence when present;
- optional metered billing hints from receipt metadata.

Outputs:

- deterministic price quote;
- reason codes for zero price, missing appraisal, unsupported currency, and
  policy-denied price;
- stable JSON for CLI display and tests.

### Credit-Limit Helper

`chio-underwriting::marketplace_limits` should use existing underwriting
evidence and decision types.

Inputs:

- tenant id;
- reputation tier and score evidence;
- settlement exposure from P2;
- receipt history and failed settlement signals;
- optional revocation oracle result for guard publisher credentials.

Outputs:

- approved limit, reduced limit, step-up review, or denied install;
- reasons using existing underwriting reason-code style;
- no mutation of budgets or settlement rows.

### CLI Boundary

Use `chio-cli/src/market.rs` as the command implementation module and wire it
through the existing clap and dispatch structure in `cli/types.rs` and
`cli/dispatch.rs`. The ticket-level command surface is `arc guard market`;
keep any binary naming compatibility decisions outside this phase plan.

Commands:

- `arc guard market list --tenant <id> --receipt-db <path> --registry-cache <path> --format json|table`
- `arc guard market info --ref <oci-ref> --tenant <id> --receipt-db <path> --format json|table`
- `arc guard market install --ref <oci-ref> --tenant <id> --bundle <path> --receipt-db <path>`

Output contracts:

- JSON is stable and sorted by guard ref.
- Table output is display-only.
- `list` filters by tenant tier and publisher revocation state.
- `info` includes price, floor, cosign status, recent settlement summary, and
  underwriting recommendation.
- `install` is idempotent. Reinstalling the same ref for the same tenant
  produces no diff and no second IOU.

### P4 Invariants

- Marketplace discovery is reputation-gated; publication is cosign-gated.
- Price and reputation metadata are additive and optional.
- Zero-price legacy manifests still install through the existing guard path.
- Install records tenant binding and price source, but the actual IOU is still
  minted only from a finalized signed receipt.
- CLI commands do not make network calls unless the caller requests registry
  pull or verification behavior already present in guard registry commands.
- P4 must not create new currency, chain, bond, or market primitives.

## Pre-PR Verification Gates

Run relevant ticket gates after each commit. Before any PR, run the combined
phase gates serially if there is cargo lock or process contention:

```bash
cargo test -p chio-settle --quiet
cargo clippy -p chio-settle -- -D warnings
cargo test -p chio-kernel --quiet
cargo clippy -p chio-kernel -- -D warnings
cargo test -p chio-store-sqlite --quiet
cargo test -p chio-kernel --test settlement_observer_byte_identity
cargo build -p chio-cli --quiet
cargo test -p chio-cli --quiet
cargo test -p chio-reputation --quiet
cargo clippy -p chio-reputation -- -D warnings
cargo test -p chio-reputation --test feed_monotonicity
cargo test -p chio-guard-registry --features marketplace --quiet
cargo build -p chio-guard-registry --no-default-features --quiet
cargo test -p chio-appraisal --quiet
cargo clippy -p chio-appraisal -- -D warnings
cargo test -p chio-underwriting --quiet
cargo clippy -p chio-underwriting -- -D warnings
cargo test -p chio-cli --test market_demo
cargo fmt --all -- --check
git diff --check
cargo xtask trajectory regen-manifest --check
bash .planning/trajectory-2/scripts/validate-manifest.sh
bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh
```

If `chio-settle` remains fully `web3`-gated, also run at least one explicit
feature-aware gate:

```bash
cargo test -p chio-settle --features web3 --quiet
```

## Open Questions For Implementation Day

- Confirm whether the finalized-receipt observer slot exists after W2/W3
  merges. Current local source has output hooks and `ToolEvaluator`, but no
  dedicated finalized-receipt economic observer module.
- Confirm whether P1 stores IOU settlement state inside IOU rows or leaves all
  settlement mutation to P2. P2 schema should adapt without rewriting P1 data.
- Confirm the exact M08 arena output schema and path before P3.T2 starts.
- Confirm the exact M07 verdict matrix equality output schema and path before
  P3.T3 starts.
- Confirm whether the marketplace feature flag has already landed from P0 on
  current main. Current local `chio-guard-registry` has no feature table.
- Resolve the audit-doc path mismatch before implementation: ticket owner globs
  point to `.planning/audits/M09-economic-layer-and-lineage.md`, while existing
  trajectory-2 audit files live under `.planning/trajectory-2/audits/`.

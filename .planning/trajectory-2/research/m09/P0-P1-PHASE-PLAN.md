# M09 P0+P1 Phase Plan

Date: 2026-04-30
Scope: whole-phase implementation plan for the M09 P0+P1 opener only. This is
research and sequencing guidance. It does not implement code, update tickets,
touch execution ledgers, or open a PR.

## Current Blocker

Do not start implementation yet. Live trajectory state is still on `W1`, while
M09 is assigned to `W4` and remains `ticket files authored` /
`ready_for_p0`: `.planning/trajectory-2/EXECUTION-STATE.json:6`,
`.planning/trajectory-2/EXECUTION-STATE.json:62-67`, and
`.planning/trajectory-2/EXECUTION-STATE.json:90-93`.

The Wave 4 board keeps M09 as a capstone after Wave 1, Wave 2, and Wave 3
drain, and says M09 wakes dormant economic crates while consuming M04
delegation and M06 CanonicalBytes:
`.planning/trajectory-2/EXECUTION-BOARD.md:128-147`. M09 should open before
M10 because later M10 anchoring consumes the M09 lineage surface:
`.planning/trajectory-2/EXECUTION-BOARD.md:150-162`.

## Dependency Gates Before Any P0+P1 Branch

1. W4 gate: W1, W2, and W3 must be merged or explicitly waived by the
   orchestrator. Current state says W1 is still active.
2. M09 direct phase gates from P0 header: trajectory-2 M04 revocation oracle,
   trajectory-2 M06 CanonicalBytes, trajectory-2 M08 arena survival feed,
   trajectory-1 M05 async-kernel evaluator/observer slot, and trajectory-1 M07
   verdict-equality oracle must be present or deliberately scoped as soft deps:
   `.planning/trajectory-2/tickets/M09/P0.yml:6-10`.
3. Manifest/preflight gates must be clean before dispatch:
   `cargo xtask trajectory regen-manifest --check`,
   `bash .planning/trajectory-2/scripts/validate-manifest.sh`, and
   `bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh`.
4. Lockfile lane gate: no other worker may be touching root `Cargo.toml` or
   `Cargo.lock`, because P0.T1 and P0.T2 serialize through those shared paths:
   `.planning/trajectory-2/tickets/M09/P0.yml:12-14`,
   `.planning/trajectory-2/tickets/M09/P0.yml:22-32`, and
   `.planning/trajectory-2/tickets/M09/P0.yml:48-58`.
5. Dependency-version gate: re-check crates.io for `petgraph` and `csv` patch
   versions on the day P0 opens. Do not bake a stale version choice into this
   plan.
6. Branch-shape gate: use one phase branch for P0+P1, for example
   `wave/W4/m09/p0-p1.phase-opener`, and keep ticket commits ordered inside
   that branch. Do not split this into ticket-grain branches or PRs.

## Coordinator Live Checks

Checked 2026-04-30 by replacement R09-R coordinator.

- Open dependency blockers:
  - PR #342 `wave/W1/m01/p2.bundle-domain-migration` is still open and
    unstable.
  - PR #349 `wave/W2/m04/p0.bundle-oracle-scaffold` is draft, unstable, and
    touches `Cargo.toml` plus `Cargo.lock`; this blocks M09.P0.T1/T2 lockfile
    ownership.
  - PR #359 `wave/W3/m08/p0.t1-open-audit-doc-and-snapshot-prereqs` is open
    and unstable; M09 consumes M08 arena outputs later in the milestone.
- Local base blocker: this checkout's `main` is ahead of `origin/main` by one
  local trajectory bookkeeping commit and also behind `origin/main`; the behind
  count changed during coordination as remote main advanced. Do not cut the
  implementation branch from this divergent local `main`; first reconcile or
  start from a clean `origin/main` based worktree after preserving the local
  bookkeeping commit.
- Fresh crate search on 2026-04-30 reported `petgraph = "0.8.3"` and
  `csv = "1.4.0"`. Re-check again when P0 actually opens.
- Validation already run from this checkout:
  - `cargo xtask trajectory regen-manifest --check` passed with the manifest in
    sync across 46 phase files.
  - `bash .planning/trajectory-2/scripts/validate-manifest.sh` passed with 61
    phase files and 325 unique ticket ids.
  - `bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh` passed with
    0 blocking issues and 0 warnings.
  - `cargo test -p chio-credit --quiet` passed.
  - `cargo test -p chio-store-sqlite --quiet` passed.
  - `cargo test -p chio-core-types --test canonical_bytes_vectors --quiet`
    passed.

## Locked Decisions

- D21 is binding: activate existing economic crates as-is and add no new
  economic crates: `.planning/trajectory-2/decisions.yml:314-325`.
- D22 is binding: `chio-lineage` is a SQLite-backed recursive-CTE indexer, not
  a new graph database: `.planning/trajectory-2/decisions.yml:328-338`.

## Current Source Facts

- Root workspace has economics crates but no `crates/chio-lineage` member yet:
  `Cargo.toml:46-58`.
- `chio-credit` currently exports economic reports and types, not P1 hook,
  account, or store-binding modules: `crates/chio-credit/src/lib.rs:16-35`,
  `crates/chio-credit/src/lib.rs:190-216`, and
  `crates/chio-credit/Cargo.toml:14-20`.
- `chio-store-sqlite` currently exports receipt, budget, capability-lineage,
  and other stores, but no `iou_store` module:
  `crates/chio-store-sqlite/src/lib.rs:1-12`.
- `chio-store-sqlite` has no feature table yet for `lineage`:
  `crates/chio-store-sqlite/Cargo.toml:14-31`.
- `chio-guard-registry` has no feature table yet for `marketplace`:
  `crates/chio-guard-registry/Cargo.toml:14-30`.
- Signed receipts carry optional metadata but the receipt body and signature
  remain over the finalized body fields:
  `crates/chio-core-types/src/receipt.rs:92-170`.
- Receipt construction signs in the kernel after tenant resolution and before
  persistence: `crates/chio-kernel/src/kernel/responses.rs:1262-1319`.
- Receipt persistence is serialized behind the kernel receipt-store write lock,
  appends to SQLite, maybe checkpoints, then appends to the in-memory local log:
  `crates/chio-kernel/src/kernel/responses.rs:1337-1351`.
- SQLite receipt writes go through the group commit actor:
  `crates/chio-store-sqlite/src/receipt_store.rs:113-246`.
- `chio_tool_receipts` is append-only by receipt id. Duplicate receipt ids
  return no new source row:
  `crates/chio-store-sqlite/src/receipt_store.rs:390-457`.
- Claim receipt log projections are immutable and trigger-projected from tool
  receipts: `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs:510-587`
  and `crates/chio-store-sqlite/src/receipt_store/support.rs:476-511`.
- Existing receipt metadata already has financial settlement status and
  metered billing quote context that P1 can read without changing receipt
  bytes: `crates/chio-core-types/src/receipt.rs:740-782`,
  `crates/chio-core-types/src/receipt.rs:832-844`,
  `crates/chio-core-types/src/receipt.rs:1040-1069`, and
  `crates/chio-core-types/src/capability.rs:899-950`.

## Exact Future Write Set

This is the implementation write set for the eventual P0+P1 phase branch. It
is intentionally broader than this research task, which only wrote this file.

P0:

- `Cargo.toml`
- `Cargo.lock`
- `crates/chio-lineage/Cargo.toml`
- `crates/chio-lineage/src/lib.rs`
- `crates/chio-guard-registry/Cargo.toml`
- `crates/chio-store-sqlite/Cargo.toml`
- `.planning/audits/M09-economic-layer-and-lineage.md`

P1:

- `crates/chio-credit/src/lib.rs`
- `crates/chio-credit/src/hook.rs`
- `crates/chio-credit/src/local_account.rs`
- `crates/chio-credit/src/store_binding.rs`
- `crates/chio-credit/tests/iou_invariants.rs`
- `crates/chio-credit/tests/legacy_receipt_migration.rs`
- `crates/chio-store-sqlite/src/lib.rs`
- `crates/chio-store-sqlite/src/iou_store.rs`
- additive SQLite bootstrap changes in
  `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs` only if the IOU
  table is created as part of normal store opening rather than a standalone
  module initializer
- `.planning/audits/M09-economic-layer-and-lineage.md`

Avoid touching `crates/chio-kernel` in the opener unless the confirmed M05
observer slot cannot route finalized receipts without a tiny adapter. If kernel
touches become necessary, stop and re-scope because this phase plan assumes P1
can remain observer-side and non-blocking.

## Commit Order Inside One Phase Branch

Use one branch and one final PR after all P0+P1 gates pass. Keep commits
ticket-aligned for review and possible revert.

1. `chore(m09): pin lineage helper dependencies`
   - Implements M09.P0.T1 only.
   - Adds workspace `petgraph` and `csv` pins after fresh version check.
   - Runs the P0.T1 metadata gate.
2. `feat(m09): scaffold chio-lineage crate`
   - Implements M09.P0.T2 only.
   - Registers the crate and adds a minimal public API with no DAG, ingest,
     diff, anchor, or CLI implementation.
   - Runs build and clippy for `chio-lineage`.
3. `feat(m09): add default-off marketplace and lineage features`
   - Implements M09.P0.T3.
   - Adds `marketplace = []` to `chio-guard-registry` and `lineage = []` to
     `chio-store-sqlite`.
   - Keeps features inert unless later commits wire behavior.
4. `docs(m09): open economic lineage audit baseline`
   - Implements M09.P0.T4.
   - Records starting counts from live source: no `chio-lineage` behavior yet,
     no `CreditEvaluatorHook`, no `LocalCreditAccount`, no IOU table, no
     kernel callers, and no P5 recursive CTE surface.
5. `feat(m09): add credit evaluator hook contract`
   - Implements M09.P1.T1.
   - Defines a trait over finalized signed `ChioReceipt` input and a local
     return enum such as `Minted`, `Skipped`, and `Failed`.
   - The hook must be observer-style. Failure must not deny, rollback, or
     mutate the receipt.
6. `feat(m09): mint local IOU envelopes from priced receipts`
   - Implements M09.P1.T2.
   - Adds deterministic `LocalCreditAccount` behavior using receipt id,
     receipt timestamp, capability id, tool identity, decision, tenant id, and
     financial or metered quote metadata.
   - Legacy or unpriced receipts return `Skipped` with no envelope.
7. `feat(m09): persist IOU envelopes idempotently`
   - Implements M09.P1.T3.
   - Adds `SqliteIouStore` or equivalent behind `chio-store-sqlite`.
   - Uses a receipt-id keyed schema so replaying the same finalized receipt
     cannot mint a second IOU.
8. `test(m09): prove IOU mint invariants`
   - Implements M09.P1.T4.
   - Tests exactly one IOU or zero per finalized receipt across generated
     receipt shapes.
9. `test(m09): preserve legacy receipt migration behavior`
   - Implements M09.P1.T5.
   - Uses legacy receipt fixtures without manifest price or metered quote and
     asserts byte-identical receipts plus zero IOUs.
10. `docs(m09): update audit with IOU schema and caller counts`
    - Implements M09.P1.T6.
    - Records the final opener counts and cites the actual hook/store files.

## Receipt And IOU Invariants

- The signed `ChioReceipt` is the only trigger for IOU minting.
- IOU minting happens after receipt signing and persistence. It never mutates
  receipt JSON, canonical bytes, signature inputs, receipt ids, checkpoint
  leaves, or claim-log projections.
- A finalized receipt produces exactly one IOU envelope or zero. It must never
  produce two.
- `Decision::Deny` and receipts with no price, no governed financial metadata,
  and no metered quote produce zero IOUs.
- Receipts with attempted cost only, failed settlement, or pending settlement
  may be represented, but the IOU state must distinguish pending, settled,
  failed, and not-applicable status rather than treating all money-like fields
  as payable.
- Tenant id is copied from the signed receipt when present. Do not let caller
  input choose tenant scope.
- IOU ids must be deterministic from stable signed data. Recommended seed:
  `iou:v1:<receipt_id>`, with a stored schema version to permit future format
  changes.
- IOU envelopes should carry `receipt_id`, `receipt_sha256` or canonical
  receipt hash, `capability_id`, `tool_server`, `tool_name`, `decision_kind`,
  `tenant_id`, `issued_at`, amount units and currency when present,
  `settlement_status`, source kind (`financial`, `metered_billing`, or
  `none`), and raw envelope JSON.
- IOU signatures, if added in P1, are over the envelope only. Do not re-sign or
  wrap the original receipt as a new source of receipt truth.
- Hook errors are observable accounting errors. They must not cause the kernel
  to deny, unpersist, or change an already finalized receipt.

## SQLite Schema And Idempotency Design

Preferred additive table:

```sql
CREATE TABLE IF NOT EXISTS iou_envelopes (
    iou_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
    receipt_sha256 TEXT NOT NULL,
    tenant_id TEXT,
    capability_id TEXT NOT NULL,
    tool_server TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision_kind TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    amount_units INTEGER,
    currency TEXT,
    settlement_status TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    schema_version TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    CHECK (source_kind IN ('financial', 'metered_billing', 'none')),
    CHECK (settlement_status IN ('not_applicable', 'pending', 'settled', 'failed'))
);
```

Recommended indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_iou_envelopes_tenant_issued
    ON iou_envelopes(tenant_id, issued_at);
CREATE INDEX IF NOT EXISTS idx_iou_envelopes_tool_issued
    ON iou_envelopes(tool_server, tool_name, issued_at);
CREATE INDEX IF NOT EXISTS idx_iou_envelopes_settlement_status
    ON iou_envelopes(settlement_status);
```

Insert behavior:

- Use `INSERT ... ON CONFLICT(receipt_id) DO NOTHING` for normal idempotent
  replay.
- If an existing row has the same `receipt_id` but different `receipt_sha256`
  or different `raw_json`, return a conflict. That detects impossible receipt
  id reuse instead of hiding it.
- Keep `iou_envelopes` mutable only if P2 settlement status needs updates.
  If P2 owns settlement mutation, P1 should store immutable IOU envelopes and
  let P2 write settlement attempts to a separate table.
- Do not add triggers that update `chio_tool_receipts`,
  `claim_receipt_log_entries`, checkpoints, or lineage projections.
- Store opening must be backward compatible: existing SQLite files get the new
  table through `CREATE TABLE IF NOT EXISTS`; no destructive migration.

## Pre-PR Verification Gates

Run ticket gates as each commit lands, then run the whole opener gates before
opening one PR:

```bash
cargo metadata --format-version 1 --no-deps --quiet > /dev/null
cargo build -p chio-lineage --quiet
cargo clippy -p chio-lineage -- -D warnings
cargo build -p chio-guard-registry --no-default-features --quiet
cargo build -p chio-guard-registry --features marketplace --quiet
cargo build -p chio-store-sqlite --features lineage --quiet
cargo test -p chio-credit --quiet
cargo clippy -p chio-credit -- -D warnings
cargo test -p chio-store-sqlite --quiet
cargo test -p chio-credit --test iou_invariants
cargo test -p chio-credit --test legacy_receipt_migration
cargo fmt --all -- --check
git diff --check
cargo xtask trajectory regen-manifest --check
bash .planning/trajectory-2/scripts/validate-manifest.sh
bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh
```

If process or lock contention appears, run these serially. The receipt-store
write path already uses a single writer actor and prior trajectory-2 memory
called out split-pool saturation as an explicit risk to preserve.

## Open Questions For Implementation Day

- Confirm the exact M05 observer slot API on main. If no stable finalized
  receipt observer exists, P1 should stop before modifying kernel internals.
- Confirm whether P1 should use existing financial receipt metadata first, or
  prefer governed metered-billing quote metadata when both are present.
- Confirm whether P1 signs IOU envelopes or stores unsigned local accounting
  rows, leaving settlement signing to P2.
- Confirm whether `.planning/audits/M09-economic-layer-and-lineage.md` remains
  the intended audit path, since existing trajectory-2 audits live under
  `.planning/trajectory-2/audits/` while P0/P1 ticket owner globs point to
  `.planning/audits/`.

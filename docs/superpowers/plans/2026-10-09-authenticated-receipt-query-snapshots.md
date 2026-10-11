# Authenticated receipt query snapshots implementation plan

> Use superpowers:executing-plans inline. Tasks 0-5 are authorized (Codex
> 06:09:22Z), memory backend first, with a short progress entry after each
> task. The Linux file backend is a separate deliverable, and its custody is
> not yet accepted.

**Goal:** close V25 under the contracts in the
[spec](../specs/2026-10-09-authenticated-receipt-query-snapshots-design.md).
**Architecture:** an owned, authenticated projection, fixed indexed plans, a
leaf-bound fetch, and an as-of watermark.
**Tech stack:** Rust and rusqlite 0.39 (bundled SQLite 3.51.3), using existing
checkpoint, Merkle, receipt verification and `SqlWorkBudget` primitives. No new
dependencies.

## Constraints

- **Base and order.** Base is a457a89c75. V25-PRE lands before Task 6, and the
  Task 6 hunks are agreed with that lane first.
- **House rules.** Fail closed with typed errors. No `unwrap` or `expect`, no em
  dashes, no new crates, no raised hygiene allowances.
- **Cargo.** Run every cargo command through
  `claude-pr1160-evidence/hammer/bcargo.sh`, which uses a private per-worktree
  target and the coder class on the build host.
- **Logs.** Write to `claude-pr1160-evidence/vfix/v25/snap/<task>-{red,green}.log`.
- **Original RED.** Each task is one commit holding its code and its tests.
  RED is recorded by running the new tests with that task's source withheld,
  which means against a457 for the Task 0 controls. GREEN is recorded on the
  commit.
- **Timing and storage.** Report measured values only. Assertions are
  structural: counts, VM steps, bytes, states and codes. No wall-clock
  deadlines are asserted.

## Modules and interfaces

All paths are under `crates/`.

| Area | Files | Contract |
|---|---|---|
| Kernel | `kernel/chio-kernel/src/receipt_query.rs`, `src/receipt_store.rs` | `ReceiptSnapshotWatermark`, `ReceiptQueryResult.snapshot`, `ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError)` with stable `code()` (spec 11) |
| Snapshot module | `platform/chio-store-sqlite/src/receipt_query_snapshot.rs`, declared next to `pub mod receipt_query;` at `src/lib.rs:93`, with submodules `receipt_query_snapshot/{db,query,project,walk,extend,recertify,fetch,service}.rs` and `tests/`. The `db` module holds the memory backend only | `ReceiptQuerySnapshots::{start, query_receipts, load_receipt, status, shutdown}`. Uses `crate::receipt_store::support::SqlWorkBudget`, defined in `src/receipt_store/reports/analytics/work_budget.rs` |
| Store refactor | `receipt_store/support/checkpoint_validate.rs`, `receipt_store/retained_projection.rs`, `receipt_store.rs` | per-checkpoint step; shared signed projection rule; `pub(crate) fn writer_head_poisoned()`; coalesced commit signal |
| Control plane | `platform/chio-control-plane/src/trust_control/{service_types/state.rs, service_runtime/init.rs, receipt_handlers.rs, service_types/requests.rs, service_types/responses.rs, underwriting_and_support/policy_support.rs}` | state fields, `receipt_query_lane`, `evidence_export_lane`, error mapping, health |
| Docs and SDKs | `spec/WIRE_PROTOCOL.md`, `spec/PROTOCOL.md`, `docs/reference/RECEIPT_QUERY_API.md`, `sdks/typescript/chio-ts/src/receipt_query_client.ts`, `sdks/python/chio-py/src/chio/receipt_query.py`, `products/chio-cli/dashboard/src/api.ts` | as listed in spec 11 |
| Gate inventories | `docs/security/trust-boundary-inventory.json`, `scripts/security-clock-inventory.json` | new readers, decoders and clock consumers |

## Compatibility

- **Receipt database.** No schema or migration change. The snapshot is rebuilt
  at every start.
- **Wire.** Additive. A new optional `snapshot` field and an error `code`; 503,
  422 and 500 statuses per spec 11; seq cursors unchanged.
- **Old SDKs** ignore the new field and surface the new statuses as existing
  errors. **New SDKs** use bounded retries.
- **`chio-cli` integration tests.** Their server-start helper
  (`products/chio-cli/tests/support/`) waits until `/health` reports the
  snapshot as `ready`.

## Failure controls

| Id | Control | Spec |
|---|---|---|
| C1 | After Ready, each tenant page costs at most L signature checks, stays within `query_sql_steps`, and never starts a writer or walker | 6.6 |
| C2 | Unreturned row mutated by SQL (triggers disabled) and by a raw edit that preserves the change counter: answers unchanged, the next pass goes Invalid, and `recertifiedAt` and pass duration are reported | 5.4, 5.5 |
| C3 | Returned row edited, or replaced by another validly signed receipt: refused by the leaf check, state Invalid | 6.4 |
| C4 | Before or between build steps, each of these is refused with the exact error and nothing is published: claim edit, checkpoint row edit, archive projection drift, entry gap, duplicate cursor | 5.2 |
| C5 | A signed live source row with no claim entry is never served, and the final check goes Invalid | 5.2 |
| C6 | Live `tool_name` drift: the filter still uses signed content, and the next pass goes Invalid | 5.2, 5.4 |
| C7 | Differential parity with a457 SQL on clean stores: every filter, empty and unknown values, cursor above `i64::MAX`, uncheckpointed tail, tenant scope. Page and count report one version while extension commits | 4.4, 6 |
| C8a | A checkpoint with a wrong predecessor or `chain_root` is refused at extension | 5.3 |
| C8b | Corruption late in a large batch during Building: no read is served, the build fails, state Invalid | 5.2 |
| C9 | Mixed signers in a pending range are refused with the a457 error. A key rollover between batches is accepted. A checkpoint that straddles the rollover is refused | 5.2, 5.3 |
| C10 | Swapping an ingested tail entry makes the next checkpoint root differ, state Invalid | 5.3 |
| C11b | A checkpoint appended during the build: version 1 stops at T0 and c0, and the next extension accepts the checkpoint | 5.2 |
| C11 | Under continuous appends, the fixed-target build publishes. `observedAt` is the target's observation time. A regressed head or W goes Invalid without refreshing `observedAt`. A stalled extension gives stale after `max_staleness`. A negative point read needs H0 | 5.2, 5.3, 6.5, 7.2 |
| C12 | `waiting_for_writer_seed` has no deadline. Seed poison gives `Invalid(writer_head_poisoned)`. Invalid is never revived, and a rebuild gets a new lineage | 7, 9 |
| C13 | Invalid or poison between selection and return refuses the request. A concurrent extension still serves the request's own version | 4.4 |
| C14 | During recertification, request work stays within its budget, and its wait is at most one walker hold (`hold_sql_steps`) | 5.4, 6.6 |
| C15 | A slow large row near `max_receipt_bytes`, or an external lock on live or archive, gives a busy retry without Invalid. Rotation under walker contention succeeds, or records busy and succeeds on retry. Cancellation in each phase ends in `Stopped`, and walker budget exhaustion ends in `Unavailable(walker_budget)`; neither becomes Invalid | 5.1, 5.6, 9 |
| C16 | An over-budget S5 query returns 422 with no rows and no count | 6.3 |
| C17 | Quota exhausted during build or extension gives `Unavailable(capacity)` with no partial version. Long receipt ids, tool names and subjects are stored verbatim and counted in `used_bytes`. A row over 128 MiB gives `Unavailable(row_cap)` | 4.3 |
| C18 | `EXPLAIN QUERY PLAN` for every fixed plan: no temp b-tree, except a sorter under `LIMIT L` in the S5 cost-range plan | 4.3 |
| C18f | (Linux file backend deliverable, not Tasks 0-5.) The backing file is bound to the custody directory inode, with negative controls that replace the parent and the path | 4.2 |
| C19 | A second concurrent export gets 503 busy. A cancelled export request keeps its permit until the work stops | 12 |
| C20 | Property test: maintained counts equal `GROUP BY` after every generation | 5.4 |
| C21 | Source gate: no `trust_control` handler calls `.query_receipts(`, `.load_chio_receipt_with_context(` or `with_retained_snapshot` | 9 |

## Task 0: Original RED controls (test-only)

- **Files:**
  - a new `platform/chio-store-sqlite/src/receipt_query/tests/snapshot_red.rs`,
    declared in `src/receipt_query/tests.rs`;
  - the V25 lane's test-only counter
    `ALL_THREAD_RECEIPT_SIGNATURE_VERIFICATIONS`
    (`src/receipt_store/support/receipt_verify.rs`).
- **RED expectations at a457:**
  - C1 store form: "a 10-row page verified 620 receipt signatures".
  - C5: the unlogged row is returned.
  - C6: the drifted row is missing from the tool filter.
  - A8: open and seed accept a drifted archive projection.
  - C3: a substituted, validly signed receipt is returned after archive trust.
  - C12: with an unlogged row, the seed poisons the writer, yet a457
    `query_receipts` still succeeds.
- **Command:**
  `cargo test -p chio-store-sqlite --lib receipt_query::tests::snapshot_red -- --test-threads=1`

## Task 1: Kernel types

- **Contract:** spec 11. Existing per-call results set `snapshot: None`.
- **Test:** the code table. This task is a pure addition; Task 6 provides the
  behavioral RED.
- **Command:** `cargo test -p chio-kernel --lib receipt_query`

## Task 2: Snapshot storage and query engine

- **Files:** `receipt_query_snapshot/{backend,schema,query}.rs`.
- **Contract:** spec 4 and 6.2-6.3.
- **RED:** at a457, a tenant-plus-outcome count over a 200,000-row tenant
  through `query_receipts_on_connection` takes more than 100,000 VM steps. The
  snapshot S2 count takes at most 1,000 steps.
- **Controls:** C7, C16, C17 (storage part), C18, and C20 (counts change in the
  insert transaction).
- **Command:**
  `cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::query`

## Task 3: Walker build

- **Files:** `receipt_query_snapshot/{project,walk}.rs` and the two refactors.
- **Contract:** spec 5.1-5.2. The existing `retained_*`, `evidence_export` and
  `receipt_query` suites pass unchanged, which shows the refactor preserved
  behavior.
- **RED:** the Task 0 A8 control.
- **Controls:** C4, C5, C6, C8b, C9 (build part), C11b, C15 (copy and
  contention), C17 (build part). Counters assert one signature check per entry
  and per checkpoint.
- **Command:**
  `cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::build -- --test-threads=1`

## Task 4: Extension, recertification and service

- **Files:** `receipt_query_snapshot/{extend,recertify,service}.rs` and the
  `receipt_store.rs` accessor.
- **Contract:** spec 5.3-5.4, 7 and 9.
- **RED:** the Task 0 C12 control.
- **Controls:** C2, C8a, C9, C10, C11, C12, C13, C14, C15 (shutdown). Counters
  assert extension costs O(delta).
- **Command:**
  `cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::{extend,recertify,lifecycle} -- --test-threads=1`

## Task 5: Fetch and point reads

- **Files:** `receipt_query_snapshot/fetch.rs`.
- **Contract:** spec 6.4-6.5.
- **RED:** the Task 0 C3 control.
- **Controls:** C3; C11 (point-read negatives); C13. A row moved by rotation
  between selection and fetch is still served; a short page continues.
- **Command:**
  `cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::fetch`

## Task 6: Control-plane wiring (after V25-PRE)

- **Files:** the control-plane rows of the module table, plus
  `trust_control/service_runtime/router_tests/receipt_query_snapshot_tests.rs`,
  declared in `router_tests.rs`.
- **Contract:** spec 9 and 11-12.
- **RED (V25 itself):** ten tenant requests to `GET /v1/receipts/query` over
  200 archived and 200 live receipts. At a457 each request costs N + 2M + L
  checks plus a seed (`vfix/v25/f1f2-per-request-open.log`).
- **Controls:** C1 over HTTP, C19, C21, every error code, health, and
  watermarks on all three routes.
- **Commands:**
  - `cargo test -p chio-control-plane --lib trust_control::service_runtime::router::tests::receipt_query_snapshot_tests`
  - `cargo test -p chio-cli --test receipt_query --test receipt_query_filters --test receipt_query_lineage --test receipt_query_export --test receipt_query_redaction`

## Task 7: Spec, docs and SDKs

- **Ownership.** Root owns the TypeScript and Python clients and the dashboard
  types (coordinator 06:12Z), built against the wire contract in spec 11. This
  lane owns the `spec/` and `docs/reference/` edits.
- **Contract.** Spec 11, including the plain as-of and recertification-lag
  statement.

## Task 8: Capacity evidence (`#[ignore]`, labeled)

- **Projection capacity, synthetic.** 10,000,000 projected rows through the
  test-only bulk loader, with a large-field slice. Record:
  - bytes per row;
  - VM steps per shape;
  - the C16 refusal;
  - the C17 quota exhaustion;
  - a full count check (C20).
- **Build capacity, signed.** 1,000,000 signed receipts, half archived and half
  live, with one large batch. Record:
  - throughput with one worker;
  - peak walker memory;
  - step durations;
  - WAL growth;
  - rotation during the build.

  Only the 1M signed build is claimed.
- **Command:**
  `cargo test --release -p chio-store-sqlite --lib receipt_query_snapshot::tests::capacity -- --ignored --test-threads=1`

## Task 9: Gates

- **Shared scanners.** All four pass on this docs commit; logs are in
  `vfix/v25/snap-docs-gates/`.
  - `python3 scripts/check-trust-boundaries.py`
  - `python3 scripts/check-security-clocks.py`
  - `python3 scripts/check-rust-file-hygiene.py`
  - `python3 scripts/check-negative-assertions.py`
- **Rust.**
  - `cargo clippy -p chio-kernel -p chio-store-sqlite -p chio-control-plane --all-targets --locked -- -D warnings`
  - `cargo fmt --all -- --check`
  - the owning suites of Tasks 2-6
- **Handoff.** Commits, RED and GREEN log hashes, and the C1-C21 results. Root
  runs the composed qualification.

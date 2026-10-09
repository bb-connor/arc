# Authenticated receipt query snapshots implementation plan

> Use superpowers:executing-plans inline. Root reviews each task before the next
> one starts.

**Goal:** close V25. Receipt query pages and counts are answered from an owned,
authenticated snapshot with a watermark and bounded freshness, so no request
re-authenticates the corpus.
**Architecture:** a walker authenticates the claim log once into a private SQLite
temporary database with ordinary indexes and maintained counts. The snapshot
extends with O(delta) work, recertifies periodically, and serves leaf-bound pages.
**Tech stack:** Rust, rusqlite 0.39 (bundled), existing checkpoint, Merkle,
receipt-verification and `SqlWorkBudget` primitives. No new dependencies.
**Spec:** [design](../specs/2026-10-09-authenticated-receipt-query-snapshots-design.md).
Acceptance ids A1-A17 and shapes S1-S5 refer to the spec.

## Global constraints

- **Base and prerequisite.** Base a457a89c75. V25-PRE (persistent
  `TrustServiceState` receipt store, writer readiness at startup) lands first.
  Tasks 0-5 and 7-8 do not touch its paths. Task 6 starts after it.
- **House rules.**
  - Fail closed and keep error variants typed.
  - No `unwrap` or `expect`, no em dashes, no raised hygiene allowances, no new
    crates.
- **Builds.**
  - Every cargo command goes through `~/.local/bin/swarm build --class coder --`.
  - Each lane uses its own `CARGO_TARGET_DIR`.
  - Logs go to `claude-pr1160-evidence/vfix/v25/snap/<task>-{red,green}.log`.
- **Original RED.**
  1. The test-only commit lands first.
  2. Run it with the fix withheld, and record the exact failure message.
  3. Apply the fix and re-run for GREEN.
  4. A pure addition with no prior behavior says so, and is covered by the
     nearest behavioral RED.
- **Unchanged paths.** `SqliteReceiptStore::query_receipts` and
  `load_chio_receipt_with_context` keep full per-call authentication. Only
  network handlers move to the snapshot.

## Module ownership and interfaces

| Owner | Files | Interface |
|---|---|---|
| chio-kernel | `src/receipt_query.rs`, `src/receipt_store.rs` | `ReceiptSnapshotWatermark`; `ReceiptQueryResult.snapshot: Option<_>`; `ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError)` with variants `Building{authenticated_entries,target_entries}`, `Stale{observed_at_unix_ms}`, `Invalid{reason}`, `Unavailable{reason}`, `Busy`, `WorkBudgetExhausted{surface}`, each with `code()` |
| chio-store-sqlite (new) | `src/receipt_query_snapshot.rs` and `src/receipt_query_snapshot/{config,schema,project,walk,extend,query,fetch,service}.rs`, plus `tests/` | `ReceiptQuerySnapshots::start(Arc<SqliteReceiptStore>, ReceiptQuerySnapshotConfig, Arc<dyn Clock>) -> Result<Arc<Self>>`; `query_receipts(&ReceiptQuery) -> Result<ReceiptQueryResult>`; `load_receipt(&str, &ReceiptReadContext) -> Result<(Option<ChioReceipt>, ReceiptSnapshotWatermark)>`; `status() -> ReceiptQuerySnapshotStatus`; `shutdown()` |
| chio-store-sqlite (refactor) | `receipt_store/support/checkpoint_validate.rs`, `receipt_store/retained_projection.rs`, `receipt_store.rs` | per-checkpoint verification step shared by the full loop and the walker; one signed tool-projection rule shared by `retained_projection::validate` and the walker; `pub(crate) fn writer_head_poisoned(&self) -> bool`; a commit notification hook for the walker (a `Condvar` signal fired after a writer commit) |
| chio-control-plane | `service_types/state.rs`, `service_runtime/init.rs`, `receipt_handlers.rs`, `service_types/{requests,responses}.rs`, `underwriting_and_support/policy_support.rs` (error mapping), health handler | `TrustServiceState.receipt_query_snapshots`, `receipt_query_lane`; handlers call the service in `spawn_blocking` |
| spec and docs | `spec/WIRE_PROTOCOL.md` section 4.3, `spec/PROTOCOL.md` section 9, `docs/reference/RECEIPT_QUERY_API.md` | response `snapshot` object, error codes, freshness, short-page clarification |
| SDKs | `sdks/typescript/chio-ts/src/receipt_query_client.ts` (+test), `sdks/python/chio-py/src/chio/receipt_query.py` (+test), `crates/products/chio-cli/dashboard/src/api.ts` (type) | optional `snapshot`; `QueryError.code`; bounded retry of building, stale and busy |
| gates | `docs/security/trust-boundary-inventory.json`, `scripts/security-clock-inventory.json` | new readers, decode sites and clock consumers registered |

## Migration and compatibility

- **Receipt database.** No schema change and no migration. The snapshot is an
  ephemeral temporary database rebuilt at each start.
- **Configuration.** `ReceiptQuerySnapshotConfig` defaults (spec 6.6, 7, 10). No
  new CLI flags in this landing. Operators set `SQLITE_TMPDIR` to a private
  volume with at least 600 B per receipt free. The operator guide and the
  `/health` field document it.
- **Wire compatibility.** The new response fields are additive. Error bodies
  gain `code`, also additive. Statuses: 503 for building, stale, busy and
  unavailable; 500 for invalid (as today for integrity); 422 for the work
  budget. Cursors are unchanged.
- **Old SDKs** (TypeScript, Python, C++, Rust client, dashboard):
  - unknown fields are ignored;
  - new statuses surface as the existing non-2xx errors;
  - paginators already continue on a short page with a non-null cursor.
- **New SDKs:**
  - expose `snapshot`;
  - parse `code`;
  - retry building, stale and busy, honoring Retry-After, up to a configurable
    total wait (default 30 s);
  - never retry 422 or 500.
- **Test harnesses.** `chio-cli/tests/receipt_query*.rs` start `chio trust serve`
  and query immediately. Their start helper waits for `/health`
  `receiptQuerySnapshot.state == "ready"`, which is a change to the helper only.

## Failure controls mapped to acceptance

| Control | Asserts | Acceptance |
|---|---|---|
| C1 work bound | after Ready, each tenant page over M archived plus N live costs at most L signature verifications and at most `query_sql_steps`; no request starts a writer or walker | A9, A13, V25 |
| C2 interior tamper | an unreturned checkpointed claim is edited with triggers disabled (SQL), and an archive page is edited in place with the change counter preserved (raw). Answers stay pre-tamper; the next recertification goes Invalid with the exact error; later queries return 500 `receipt_query_snapshot_invalid` | A1, A3, A4 |
| C3 returned-row tamper | a selected row is edited (live and archived, SQL and raw). The fetch leaf check fails closed, and the state becomes Invalid | A3, A4 |
| C4 build-time tamper | claim, checkpoint row, archive projection, mixed signer, entry gap and duplicate cursor are each edited before or between build steps; the build refuses with the exact error and never publishes | A4, A8, A10 |
| C5 unlogged row | a validly signed live source row with no claim entry: a457 `query_receipts` returns it (RED); the snapshot never serves it and the final phase goes Invalid | A6 |
| C6 live projection drift | a live `tool_name` column is edited: a457's tool filter silently drops the row (RED); the snapshot filter keeps it and recertification goes Invalid | A1, A5 |
| C7 one version | randomized differential parity against a457 SQL on clean stores, for every filter, cursor, empty result, unknown value, `cursor > i64::MAX`, uncheckpointed tail and tenant scope; page and total_count report one `snapshot.id` while extension commits concurrently | A5, A16 |
| C8 membership | a validly signed checkpoint with a wrong predecessor or `chain_root`, inserted with triggers disabled, is refused at extension | A10 |
| C9 tail swap | an ingested uncheckpointed entry is swapped on disk; the next checkpoint's owned root differs and the state becomes Invalid | A4, A5 |
| C10 lifecycle | Building returns 503 with progress and no time cutoff; Ready serves; a stalled extension produces stale after `head_wait` plus `max_staleness`; recovery returns to Ready | A2, A12, A17 |
| C11 no revive | a poisoned writer head goes Invalid with no service until reseed; Invalid rebuilds only with a new lineage id; no older `snapshot.id` is ever returned again | A7, A12 |
| C12 bounded work under appends | the build finishes while appends continue; rotation during the build succeeds; every step stays within K entries and 64 MiB; WAL growth is bounded by one step | A11 |
| C13 shutdown | `shutdown()` joins within one step, under a slow-step hook; a drop without shutdown detaches; a panic in a step goes Invalid(internal) | A11, A17 |
| C14 budget refusal | an S5 shape above the budget returns 422 `receipt_query_work_budget_exhausted` with no receipts and no count | A13 |
| C15 capacity | the Task 8 fixture | A15 |

## Task 0: Original RED controls (test-only)

Files: `chio-store-sqlite/src/receipt_query_snapshot/tests/original_red.rs`,
plus the test-only all-thread verification counter on
`decode_verified_{chio,child}_receipt` that the V25 lane already carries.

- [ ] C1 store form: 200 archived plus 200 live receipts, batch 10; ten tenant
  pages each verify at most 10 signatures. Expected RED at a457:
  "a 10-row page verified 620 receipt signatures".
- [ ] C5 and C6 against `SqliteReceiptStore::query_receipts`. Expected RED: the
  unlogged row is returned; the drifted row is missing from the tool filter.
- [ ] A8 control: open plus writer seed on a store whose archive projection
  drifted. Expected RED: open succeeds and reports healthy.
- [ ] Commands:
  `swarm build --class coder -- cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::original_red -- --test-threads=1`.
  RED logs go to `snap/task0-red.log`.

## Task 1: Kernel watermark and typed snapshot errors

Files: `chio-kernel/src/receipt_query.rs`, `chio-kernel/src/receipt_store.rs`,
and the construction sites of `ReceiptQueryResult`.

- [ ] Add the types and stable codes (spec 11). Existing results set
  `snapshot: None`.
- [ ] Test: the code table is stable and the display strings are redaction-safe.
  Pure addition, no Original RED; covered by Task 6.
- [ ] `swarm build --class coder -- cargo test -p chio-kernel --lib receipt_query`.

## Task 2: Snapshot store and query engine

Files: `receipt_query_snapshot/{config,schema,query}.rs`, `tests/query.rs`.
Interface: crate-internal `SnapshotDb` with
`insert_rows(&[ProjectedRow])`, `apply_lineage(..)`,
`select(&ReceiptQuery, budget) -> Selection { rows, total_count, watermark }`,
plus a test-only bulk loader.

- [ ] Schema and indexes (spec 4.3), dimension interning, maintained counts with
  hour buckets, fixed plans S1-S5 with `INDEXED BY`, and `SqlWorkBudget` with a
  typed refusal.
- [ ] Original RED: a tenant plus outcome count over a 200k-row tenant on a457's
  `query_receipts_on_connection` takes more than 100,000 VM steps (measured with
  a progress counter). GREEN: the snapshot takes at most 1,000 steps (S2).
- [ ] C7 parity (seeded random, 2,000 queries over 20k rows), C14, the empty and
  unknown-value cases, and concurrent extension plus query keeping one
  `snapshot.id`.
- [ ] `swarm build --class coder -- cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::query`.

## Task 3: Authentication walker (build)

Files: `receipt_query_snapshot/{project,walk}.rs`, and the refactors in
`checkpoint_validate.rs` and `retained_projection.rs`. Tests in
`tests/build.rs`.

- [ ] Factor the per-checkpoint step out of
  `verify_checkpoint_chain_integrity_with_frontier_at_watermark`, and the tool
  projection rule out of `retained_projection::validate`. The existing retained
  and evidence suites must stay green unchanged, proving behavior equivalence.
- [ ] Chain, tail, newest-first batch and final phases (spec 5.1), with a
  streaming RFC 6962 frontier. Test it against `MerkleTree::from_leaves` for
  sizes 1 through 1,025.
- [ ] Original RED: the Task 0 A8 control. GREEN: the build refuses with the
  exact projection-drift error.
- [ ] C4, C5, C12 and the oversized-row Unavailable case. Counters assert one
  signature verification per entry and one per checkpoint.
- [ ] `swarm build --class coder -- cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::build`.

## Task 4: Extension, recertification and service lifecycle

Files: `receipt_query_snapshot/{extend,service}.rs`, the `receipt_store.rs`
accessor and commit hook, and `tests/{extend,lifecycle}.rs`.

- [ ] Extension (spec 5.2), recertification (5.3), the state machine (7.1),
  freshness (7.2), poison handling (7.3), backoff, cancellation and panic
  containment.
- [ ] Original RED: a457 reads ignore a poisoned writer head. The fixture is a
  store whose live source row has no claim entry, so the writer seed poisons the
  head. a457 `query_receipts` still succeeds, and returns that row. GREEN: C11
  (Invalid, no service until reseed) together with C5.
- [ ] C2, C8, C9, C10, C11, C13. Counters assert extension costs O(delta)
  verifications and never re-reads authenticated history.
- [ ] `swarm build --class coder -- cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::{extend,lifecycle} -- --test-threads=1`.

## Task 5: Leaf-bound fetch and point reads

Files: `receipt_query_snapshot/fetch.rs`, `tests/fetch.rs`.

- [ ] Fetch by `entry_seq` from live, or from the archive at or below W, with
  one retry. Verify the signature, the leaf and the tenant. Enforce the 64 MiB
  page cap with continuation. Point reads wait for the head on a miss and serve
  the newest-first suffix while Building.
- [ ] Original RED: the a457 path reads page rows after verification and checks
  only each row's own signature and tenant. A test hook runs after archive trust
  (`load_retained_chio_receipt_after_archive_trust_for_test` pattern) and
  replaces a returned row's `raw_json` with a different, validly signed receipt
  from the same kernel key. a457 returns the substituted receipt. GREEN: C3
  fails closed with `receipt_query_snapshot_invalid`, because the leaf differs.
- [ ] Also: a row moved by rotation between selection and fetch is served; a
  short page continues with the cursor.
- [ ] `swarm build --class coder -- cargo test -p chio-store-sqlite --lib receipt_query_snapshot::tests::fetch`.

## Task 6: Control-plane wiring (after V25-PRE)

Files: as in the ownership table, plus
`trust_control/receipt_query_snapshot_route_tests.rs`.

- [ ] Start after writer readiness. Add the lane, `spawn_blocking`, error
  mapping (spec 11), health, and shutdown ordering (spec 9).
- [ ] Source gate test: no `trust_control` handler calls
  `.query_receipts(`, `.load_chio_receipt_with_context(` or
  `with_retained_snapshot` on the store.
- [ ] Original RED (V25 itself): ten sequential tenant
  `GET /v1/receipts/query` requests over 200 archived plus 200 live receipts
  through the router. At a457 each costs about N + 2M + L verifications plus a
  per-request seed (`vfix/v25/f1f2-per-request-open.log`). GREEN: C1 at most L
  per request; 503 busy, building and stale; 422 budget; 500 invalid; the
  watermark is present on all three routes and on point reads.
- [ ] Commands:
  - `swarm build --class coder -- cargo test -p chio-control-plane --lib receipt_query_snapshot_route_tests`
  - `swarm build --class coder -- cargo test -p chio-cli --test receipt_query --test receipt_query_filters --test receipt_query_lineage --test receipt_query_export --test receipt_query_redaction`

## Task 7: Spec, docs and SDKs

- [ ] Wire, protocol and reference doc edits (spec 11).
- [ ] TypeScript and Python. Original RED: the new tests fail on today's
  clients. A 503 building response is not retried, and `code` is not exposed.
  GREEN: bounded retry with Retry-After, 422 surfaced without retry, an
  old-shape response still parses, and the short-page cursor continues.
- [ ] Commands:
  - `cd sdks/typescript/chio-ts && npm test`
  - `cd sdks/python/chio-py && uv run pytest tests/test_receipt_query.py`
  - dashboard typecheck as in its README.

## Task 8: Workload and capacity fixture (qualification, `#[ignore]`)

Files: `receipt_query_snapshot/tests/capacity.rs`, plus a runner note in the
evidence directory.

- [ ] **Query capacity.** Load 10,000,000 synthetic projected rows with the
  test-only bulk loader. Distribution:
  - 10,000 tenants, the largest holding 40%, and one sparse tenant with
    3 receipts;
  - 200 servers, 2,000 tools, 50,000 capabilities, 20,000 subjects,
    3 currencies;
  - timestamps disordered by plus or minus 5 s;
  - one adversarially disordered tenant.

  Assert:
  - storage at most 600 B per row (`dbstat`);
  - S1, S2 and S4 at most 2,000 VM steps;
  - S3 at most 50,000 steps at a 24 h window;
  - the sparse-tenant page and count at most 1,000 steps;
  - the adversarial S3 and a wide S5 refuse with exactly C14.

  Record wall times.
- [ ] **Build capacity.** 1,000,000 signed receipts: 500,000 archived and
  500,000 live, in batches of 100, with one 100,000-entry batch.

  Assert:
  - one verification per entry;
  - peak walker allocation within the step cap plus the cache;
  - WAL size bounded during the build;
  - rotation and appends during the build succeed.

  Record entries per second per verify thread. Above 1M the build is
  extrapolated linearly (spec Q6).
- [ ] Commands:
  - `swarm build --class coder -- cargo test --release -p chio-store-sqlite --lib receipt_query_snapshot::tests::capacity -- --ignored --test-threads=1`
  - output goes to `snap/capacity.log`.

## Task 9: Gates and integrated qualification

- [ ] Inventory updates: trust boundaries and security clocks.
- [ ] Commands:
  - `python3 scripts/check-trust-boundaries.py`
  - `python3 scripts/check-security-clocks.py`
  - `python3 scripts/check-rust-file-hygiene.py`
  - `python3 scripts/check-negative-assertions.py`
- [ ] Strict lint and format:
  - `swarm build --class coder -- cargo clippy -p chio-kernel -p chio-store-sqlite -p chio-control-plane --all-targets --locked -- -D warnings`
  - `cargo fmt --all -- --check`
- [ ] Owning suites: `chio-store-sqlite` retained, evidence export and
  `receipt_query`; `chio-control-plane` receipt routes; the `chio-cli`
  `receipt_query*` integration tests.
- [ ] Handoff: commit list, RED and GREEN log hashes, and the C1-C15 table with
  results. Root runs the composed qualification.

## Review focus

- Every answer comes from owned state or from bytes the owned leaf binds. No
  serving path trusts a mutable SQLite handle.
- No version is served unless it was authenticated by a walk from checkpoint 1,
  or extended from such a version by verified checkpoints.
- Work per request is bounded by the lane, the step budget, L and the byte cap.
  Refusals are typed and never partial.
- State transitions never revive an invalid or superseded snapshot. Shutdown
  and drop paths are accounted for.

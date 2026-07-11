# RFC-0003: Durable dispatch-intent journal: closing the effect-before-receipt crash window

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0013 (async receipt durability), ADR-0008 (checkpoint trigger strategy)
- Depends on: RFC-0006 (storage hot path: bounded append cost and single-writer
  discipline for the store this journal rides on; RFC-0006 sequences itself before
  this RFC). Related: RFC-0009 (alert routing for dead-letter incidents), RFC-0013
  (money-path idempotency contract)
- Closes findings: F04, F31. Provides groundwork for F70 only, which is owned
  and closed by RFC-0013 (payment journal and idempotent adapter contract), not
  this RFC (see ./README.md and the wave-3 readiness review)

## Summary

Today a mediated tool call executes its side effect (and, on the money path, moves
funds at `authorize`) strictly before the kernel signs and durably persists the
receipt. A crash, OOM kill, or power loss anywhere in that window leaves an
externally visible effect with no receipt in the append-only log, and recovery has
nothing to reconcile against: the Merkle-committed log verifies clean while missing
an action. This RFC adds a durable dispatch-intent journal. Before a side-effecting
or monetary call dispatches, the kernel writes a small intent row through the
`ReceiptCommitActor` group-commit path and blocks on its durable commit. The receipt
append later consumes that intent row in the same writer transaction as the receipt
insert, so the two either both commit or both do not. Orphaned intents surviving a
restart are reconciled at boot into explicit "outcome-unknown" incidents (and, for
monetary intents, a rail-side query), turning a silent audit hole into a loud,
recoverable operator signal. Read-only calls pay nothing: intent writes are gated on
side-effect class.

## Motivation

The failure is a durability gap in the core product guarantee ("every mediated side
effect has a receipt"), grounded in F04, F31, and F70, and read against the
Ubicloud "PostgreSQL and the OOM Killer" lens: when a component dies mid-operation
you must know the blast radius and be able to recover, and internal accounting must
be trustworthy or loudly broken. Here the accounting is silently broken.

Blast radius:

- Trigger: kernel process death (OOM kill, crash, power loss) in the window between
  the tool server returning a side effect (or the rail moving money) and
  `record_chio_receipt` committing the signed receipt.
- Effect: the effect happened; no receipt exists anywhere. The in-memory local-log
  copy either died with the process or was never written, because on a store-append
  failure the local-log append is skipped (the error propagates first). Recovery has
  no per-call intent record to detect the gap.
- Who is impacted: auditors and dispute resolution (the log verifies clean while
  missing an action); on the money path (F70) the payer was charged with no attested
  record and no local copy of the rail `authorization_id`, so reconciliation requires
  manual rail-side statement matching.

F03 (memory-growth-induced OOM) makes the crash trigger routine rather than rare, so
this is not a tail concern. The existing `PostAdmissionDropGuard`
(`crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs:19`) covers only
in-process future-drop and cancellation; it is memory-only and does not survive
process death, so it cannot close this window.

## Current behavior (verified 2026-07-04)

Ordering in the async evaluation path
(`crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`):

1. Pre-dispatch readiness gates run at lines 219-250
   (`ensure_federated_receipt_persistence_ready`, `ensure_receipt_persistence_ready`).
   Both are configuration-presence checks only. Verified in
   `crates/kernel/chio-kernel/src/kernel/construction.rs:244-251`:

   ```rust
   pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
       if self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log {
           return Ok(());
       }
       Err(KernelError::Internal(
           "durable receipt persistence unavailable: no receipt store configured".to_string(),
       ))
   }
   ```

   Neither gate consults writer counters, queue depth, `last_error`, or thread
   liveness, so a saturated queue or wedged writer passes.

2. Money moves at `authorize_payment_if_needed`
   (`async_evaluation_core.rs:469-492`), which is before dispatch. For the in-tree
   prepaid X402 adapter the real external HTTP call is in `authorize`
   (`crates/kernel/chio-kernel/src/payment.rs:287-310`) and `capture` is a local
   no-op returning `Settled` (`payment.rs:312-329`), so for prepaid rails funds
   move at pre-dispatch authorize. Generic adapters move funds at `capture`
   (`crates/kernel/chio-kernel/src/kernel/validation.rs:1012-1021`), still before
   the receipt persists.

3. The tool side effect executes at `async_evaluation_core.rs:525-527`
   (`dispatch_tool_call_with_cost_after_nonce_check`), guarded only by the
   memory-only `PostAdmissionDropGuard` (lines 513-529).

4. The receipt is built, signed, and only then persisted, strictly afterward
   (`crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs:57-72`):
   `build_and_sign_receipt` at 57-70, then `record_chio_receipt_with_federation` at
   72.

5. `record_chio_receipt` takes the kernel-wide write lock, appends durably, and only
   on success writes the in-memory local log
   (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:164-187`):

   ```rust
   pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
       {
           let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
               KernelError::Internal("receipt store write lock poisoned".to_string())
           })?;
           if let Some(seq) = self
               .with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?
               .flatten()
           {
               if self.should_checkpoint_after_seq(seq) {
                   self.maybe_trigger_checkpoint_locked(seq)?;
               }
           }
           self.append_chio_receipt_to_local_log(receipt.clone());
       }
       let _settlement_status = self.run_settlement_observer(receipt);
       Ok(())
   }
   ```

   The durable append is `SqliteReceiptStore::append_verified_chio_receipt_record`
   (`crates/platform/chio-store-sqlite/src/receipt_store.rs:553-562`), which hands a
   single `Append` command to the `ReceiptCommitActor`
   (`receipt_store.rs:161-200`). The actor group-commits a batch inside one
   `TransactionBehavior::Immediate` transaction in `append_receipt_batch`
   (`receipt_store.rs:376-415`), inserting each row via `append_chio_receipt_tx`
   (`receipt_store.rs:939`), whose statement is:

   ```sql
   INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, subject_key,
       issuer_key, grant_index, tool_server, tool_name, decision_kind, policy_hash,
       content_hash, tenant_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
   ON CONFLICT(receipt_id) DO NOTHING RETURNING seq
   ```

There is no dispatch-intent or write-ahead-intent record anywhere in the store API:
a grep for `intent` in `receipt_store.rs` returns nothing. The only per-call durable
precedent that does the "consume in the same transaction as the receipt insert" move
is `append_chio_receipt_consuming_authorization`
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:564-597`), which runs
`consume_authorization_receipt_tx` (`receipt_store.rs:1017`) and `append_chio_receipt_tx`
inside one `Immediate` transaction. This RFC generalizes exactly that pattern.

Group-commit constants (`receipt_store.rs:121-123`):
`RECEIPT_GROUP_COMMIT_MAX_BATCH = 64`, `RECEIPT_GROUP_COMMIT_FLUSH_DELAY = 500us`,
`RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY = 64 * 16 = 1024`.

Health surface today (`receipt_store.rs:614-631`): `healthy = status.healthy &&
writer_counters().last_error.is_none()`. `ReceiptStoreHealthReport`
(`crates/kernel/chio-kernel/src/receipt_store.rs:100-117`) has no notion of an
in-flight or orphaned call. Its only external consumer is the CLI `trust receipt
health` command (`crates/products/chio-cli/src/cli/trust/receipt/health.rs:60-73`),
which opens its own store via `open_existing` (`health.rs:43`) and therefore cannot
observe the serving kernel's writer state.

Parameter hashing is already canonical (RFC 8785) via
`ToolCallAction::from_parameters`
(`crates/core/chio-core-types/src/receipt/decision.rs:44-51`):
`sha256_hex(canonical_json_bytes(&parameters))`. The intent row reuses this exact
hash so the intent and the eventual receipt bind to the same call.

## Design

### Overview and invariant

Introduce a durable, non-audit operational journal (`chio_dispatch_intents`) that
sits beside the Merkle-committed `chio_tool_receipts` table. The invariant:

> For any side-effecting or monetary mediated call, a durable intent row exists on
> disk before the effect is caused, and it is removed in the same transaction that
> commits the receipt. Therefore, after any crash, `receipt(request_id) XOR
> open_intent(request_id)` holds: either the receipt is durable, or an intent proves
> an effect may have occurred without one.

Intents are operational records, not receipts. They are never signed, never added to
`chio_tool_receipts`, and never advance the checkpoint sequence, so ADR-0008's
count-based checkpoint semantics and the Merkle tree are untouched.

### Schema (new table)

Added in `crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs`
alongside the `chio_tool_receipts` DDL (currently at `open.rs:131-158`):

```sql
CREATE TABLE IF NOT EXISTS chio_dispatch_intents (
    request_id            TEXT PRIMARY KEY,
    capability_id         TEXT NOT NULL,
    tool_server           TEXT NOT NULL,
    tool_name             TEXT NOT NULL,
    parameter_hash        TEXT NOT NULL,
    side_effect_class     TEXT NOT NULL,          -- 'side_effecting' | 'monetary'
    monetary              INTEGER NOT NULL,        -- 0 | 1
    rail                  TEXT,                    -- adapter/rail id, known pre-authorize
    rail_authorization_id TEXT,                    -- attached post-authorize (money path)
    outcome_eligibility_digest TEXT,               -- nullable WS3 signed selector binding
    tenant_id             TEXT,
    created_at_unix_ms    INTEGER NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'dead_letter')),
    incident_id           TEXT,
    resolution_detail     TEXT,                    -- reconciler outcome annotation
    CHECK (
        (state = 'open' AND incident_id IS NULL)
        OR (state = 'dead_letter' AND incident_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_chio_dispatch_intents_state
    ON chio_dispatch_intents(state);

CREATE TABLE IF NOT EXISTS chio_outcome_eligibility_records (
    eligibility_seq       INTEGER PRIMARY KEY,
    request_id            TEXT UNIQUE NOT NULL,
    eligibility_digest    TEXT UNIQUE NOT NULL,
    schema                TEXT NOT NULL
        CHECK (schema = 'chio.outcome.eligibility.v1'),
    canonical_envelope    BLOB NOT NULL,
    lifecycle             TEXT NOT NULL DEFAULT 'prepared'
        CHECK (lifecycle IN (
            'prepared', 'dispatch_started', 'dispatch_accepted', 'receipt_bound',
            'incident_bound', 'not_dispatched'
        )),
    row_version           INTEGER NOT NULL DEFAULT 0 CHECK (row_version >= 0),
    acceptance_digest     TEXT,
    canonical_acceptance_envelope BLOB,
    dispatch_accepted_at_unix_ms INTEGER,
    receipt_id            TEXT,
    incident_id           TEXT,
    incident_class        TEXT CHECK (incident_class IN ('platform', 'provider')),
    created_at_unix_ms    INTEGER NOT NULL,
    resolved_at_unix_ms   INTEGER,
    CHECK (
        (lifecycle IN ('prepared', 'dispatch_started')
            AND acceptance_digest IS NULL
            AND canonical_acceptance_envelope IS NULL
            AND dispatch_accepted_at_unix_ms IS NULL
            AND receipt_id IS NULL AND incident_id IS NULL
            AND incident_class IS NULL
            AND resolved_at_unix_ms IS NULL)
        OR (lifecycle = 'dispatch_accepted'
            AND acceptance_digest IS NOT NULL
            AND canonical_acceptance_envelope IS NOT NULL
            AND dispatch_accepted_at_unix_ms IS NOT NULL
            AND receipt_id IS NULL AND incident_id IS NULL
            AND incident_class IS NULL AND resolved_at_unix_ms IS NULL)
        OR (lifecycle = 'receipt_bound'
            AND acceptance_digest IS NOT NULL
            AND canonical_acceptance_envelope IS NOT NULL
            AND dispatch_accepted_at_unix_ms IS NOT NULL
            AND receipt_id IS NOT NULL AND incident_id IS NULL
            AND incident_class IS NULL AND resolved_at_unix_ms IS NOT NULL)
        OR (lifecycle = 'incident_bound' AND receipt_id IS NULL
            AND incident_id IS NOT NULL AND incident_class = 'provider'
            AND resolved_at_unix_ms IS NOT NULL
            AND acceptance_digest IS NOT NULL
            AND canonical_acceptance_envelope IS NOT NULL
            AND dispatch_accepted_at_unix_ms IS NOT NULL)
        OR (lifecycle = 'not_dispatched'
            AND acceptance_digest IS NULL
            AND canonical_acceptance_envelope IS NULL
            AND dispatch_accepted_at_unix_ms IS NULL
            AND ((receipt_id IS NOT NULL AND incident_id IS NULL
                    AND incident_class IS NULL)
                OR (receipt_id IS NULL AND incident_id IS NOT NULL
                    AND incident_class = 'platform'))
            AND resolved_at_unix_ms IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_chio_outcome_eligibility_lifecycle
    ON chio_outcome_eligibility_records(lifecycle);

CREATE INDEX IF NOT EXISTS idx_chio_outcome_eligibility_time
    ON chio_outcome_eligibility_records(created_at_unix_ms, eligibility_seq);

CREATE INDEX IF NOT EXISTS idx_chio_outcome_eligibility_acceptance_time
    ON chio_outcome_eligibility_records(
        dispatch_accepted_at_unix_ms, eligibility_seq
    ) WHERE dispatch_accepted_at_unix_ms IS NOT NULL;

CREATE TABLE IF NOT EXISTS chio_outcome_eligibility_events (
    event_seq             INTEGER PRIMARY KEY,
    eligibility_seq       INTEGER NOT NULL,
    record_version        INTEGER NOT NULL CHECK (record_version >= 0),
    request_id            TEXT NOT NULL,
    eligibility_digest    TEXT NOT NULL,
    transition            TEXT NOT NULL CHECK (transition IN (
        'prepared', 'dispatch_started', 'dispatch_accepted', 'receipt_bound',
        'incident_bound', 'not_dispatched'
    )),
    acceptance_digest     TEXT,
    dispatch_accepted_at_unix_ms INTEGER,
    receipt_id            TEXT,
    incident_id           TEXT,
    incident_class        TEXT CHECK (incident_class IN ('platform', 'provider')),
    event_at_unix_ms      INTEGER NOT NULL,
    leaf_hash             TEXT NOT NULL,
    UNIQUE (eligibility_seq, record_version)
);

CREATE INDEX IF NOT EXISTS idx_chio_outcome_eligibility_events_request
    ON chio_outcome_eligibility_events(request_id, event_seq);
```

`request_id` is the primary key: at most one open intent per request. A second write
for the same `request_id` (a retry that reused the id) collides and is rejected
fail-closed rather than duplicating an effect record. The row carries no arguments,
only `parameter_hash` and optional digests, so it holds no raw arguments or
additional sensitive payload beyond what the receipt already commits. The
`outcome_eligibility_digest` column is NULL for ordinary calls. When non-NULL,
the WS3 extension requires the matching canonical signed
`chio.outcome.eligibility.v1` row to be inserted in the same intent-writer
transaction; a digest-only row is invalid and denies before dispatch.
The eligibility row is retained after intent consumption because it is the
request-keyed denominator evidence for WS3 SLA proofs. Its lifecycle starts as
`prepared`. After rail authorization and every other pre-tool check succeeds, a
durable compare-and-swap moves it to `dispatch_started` immediately before the
transport handoff. That marker is platform state and is not provider SLA
evidence. A qualified server must durably accept the request and return a
provider-authenticated acceptance before the store may transition to
`dispatch_accepted`. Only `dispatch_accepted` may become `receipt_bound` or a
provider-class `incident_bound`. Ambiguous failure from `dispatch_started`
creates a platform incident on the intent but leaves the eligibility lifecycle
unresolved and makes SLA proof incomplete. Only an authenticated server result
that the request was never durably accepted may move it to `not_dispatched`. A pre-tool abort or recovery moves `prepared` to
`not_dispatched`, retaining a receipt or incident reference but excluding the
request from provider SLA math. A retained terminal eligibility row without an
open intent is therefore expected; only creating `prepared` eligibility without
its matching intent is invalid.

The store allocates `eligibility_seq` and `event_seq` from monotonic,
transactional counters with no gaps among committed rows. Creation inserts the
version-zero `prepared` event. Every lifecycle CAS increments `row_version` and
inserts one immutable event carrying that same version in the same transaction;
event rows cannot be updated or deleted. `eligibility_seq` is the stable record
position, while the event sequence is the append-only consistency history.

### New Rust types

In `crates/kernel/chio-kernel/src/receipt_store.rs`, beside
`AuthorizationReceiptConsumption` (currently at lines 133-149):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    /// Pure/read-only: no durable intent is written; TTFRH is unchanged.
    ReadOnly,
    /// Externally visible effect (file write, message send, non-monetary tool).
    SideEffecting,
    /// Moves funds on a payment rail; carries a rail reference.
    Monetary,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchIntentRecord {
    pub request_id: String,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub parameter_hash: String,
    pub side_effect_class: SideEffectClass,
    pub monetary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_eligibility_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub created_at_unix_ms: u64,
}

/// Key used to consume an intent in the same transaction as the receipt append.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchIntentKey {
    pub request_id: String,
    /// Must equal the receipt's action.parameter_hash; a mismatch fails closed.
    pub parameter_hash: String,
    /// None for the base path; Some for WS3 and must match intent, record, and receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_eligibility_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}
```

### Store trait additions

In the `ReceiptStore` trait
(`crates/kernel/chio-kernel/src/receipt_store.rs:187`), add two defaulted methods so
non-SQLite stores remain compilable and fail closed if used on a side-effecting path:

```rust
fn record_dispatch_intent(
    &self,
    _intent: &DispatchIntentRecord,
) -> Result<(), ReceiptStoreError> {
    Err(ReceiptStoreError::Conflict(
        "durable dispatch-intent journal is not supported by this receipt store".to_string(),
    ))
}

fn append_chio_receipt_consuming_intent(
    &self,
    _receipt: &ChioReceipt,
    _intent: &DispatchIntentKey,
) -> Result<Option<u64>, ReceiptStoreError> {
    Err(ReceiptStoreError::Conflict(
        "durable dispatch-intent consumption is not supported by this receipt store".to_string(),
    ))
}
```

The SQLite implementations live next to
`append_chio_receipt_consuming_authorization`
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:564-597`) but, unlike
that method (which opens its own connection and `Immediate` transaction
directly), both route through the `ReceiptCommitActor`:
`record_dispatch_intent` sends `ReceiptCommitCommand::Intent`, and
`append_chio_receipt_consuming_intent` sends `ReceiptCommitCommand::Append` with
`consume_intent = Some(key)`. This keeps every journal write on the single
writer thread that RFC-0006 establishes.

### ReceiptCommitActor group-commit path

Extend the command enum
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:147-150`) with an `Intent`
variant, and add an optional consume key to `ReceiptCommitRequest` (currently at
`receipt_store.rs:141-145`):

```rust
struct ReceiptCommitRequest {
    receipt: ChioReceipt,
    raw_json: String,
    consume_intent: Option<DispatchIntentKey>, // NEW
    response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
}

enum DispatchIntentOp {
    /// Pre-dispatch durable intent write.
    Insert(DispatchIntentRecord),
    /// WS3 pre-dispatch write; envelope bytes were verified by the kernel.
    InsertOutcomeEligible {
        intent: DispatchIntentRecord,
        eligibility_schema: String,
        eligibility_request_id: String,
        eligibility_digest: String,
        canonical_eligibility_envelope: Vec<u8>,
    },
    /// WS3 durable boundary immediately before invoking the tool dispatcher.
    MarkOutcomeDispatchStarted {
        request_id: String,
        eligibility_digest: String,
        expected_version: u64,
        started_at_unix_ms: u64,
    },
    /// WS3 provider durably accepted ownership of this exact request.
    MarkOutcomeDispatchAccepted {
        request_id: String,
        eligibility_digest: String,
        expected_version: u64,
        acceptance_digest: String,
        canonical_acceptance_envelope: Vec<u8>,
        accepted_at_unix_ms: u64,
    },
    /// Post-authorize best-effort rail reference attach (money path).
    AttachRailRef {
        request_id: String,
        rail_authorization_id: String,
    },
}

struct DispatchIntentRequest {
    op: DispatchIntentOp,
    response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>, // Ok(()) as Ok(0)
}

enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Intent(Box<DispatchIntentRequest>), // NEW
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
}
```

The drain loop (`receipt_commit_actor_loop`, `receipt_store.rs:283-316`) already
coalesces up to `RECEIPT_GROUP_COMMIT_MAX_BATCH` commands. Two arms change, not
one. The outer `match command` at `receipt_store.rs:290` today seeds a batch only
for `Append` (and handles `Flush`); it gains an `Intent` arm so an intent that
arrives while the writer is idle (the common pre-dispatch case, since the intent
write is the first thing an effecting call does) seeds a batch. The inner
`recv_timeout` arm at `receipt_store.rs:295-303` also gains an `Intent` case so
intents coalesce into an in-flight `Append` batch. Because the batch is now
heterogeneous, the homogeneous `requests: Vec<ReceiptCommitRequest>` collection
threaded through `commit_receipt_batch` / `append_receipt_batch`
(`receipt_store.rs:318-415`, response fan-out at `receipt_store.rs:345-347`) becomes
a batch of a two-variant item (append vs. intent), and each variant routes its own
typed response (`Result<u64, ReceiptStoreError>` for appends, `Ok(0)` sentinel for
intents). The batch is then processed inside the single `Immediate` transaction:

- For an `Intent` carrying `DispatchIntentOp::Insert`:
  `insert_dispatch_intent_tx(&tx, &intent)` (a plain `INSERT ... ON
  CONFLICT(request_id) DO NOTHING`; zero rows changed maps to
  `ReceiptStoreError::Conflict`, fail-closed). A base insert requires
  `outcome_eligibility_digest = None`. WS3 adds a sibling typed insert command
  carrying the verified canonical eligibility envelope; that command recomputes
  its digest and inserts both the eligibility record and intent in this same
  transaction. Non-NULL digest without the matching typed attachment, an
  attachment on an ordinary request, or a byte/digest/schema mismatch aborts the
  transaction before dispatch.
- For `DispatchIntentOp::InsertOutcomeEligible`, require the intent's non-NULL
  digest to equal `eligibility_digest`, require both request ids to match,
  require the exact v1 schema, recompute SHA-256 over the canonical envelope,
  decode and reverify its kernel signature and request binding, then insert the
  eligibility row with lifecycle `prepared`, allocate its stable
  `eligibility_seq`, append its immutable version-zero `prepared` event, and
  insert the intent. All three inserts occur in one transaction and use strict
  conflict handling: identical replay returns the existing set only if every
  stored byte and field is equal; any partial, duplicate-but-different, or
  pre-existing subset is a conflict.
- For `DispatchIntentOp::MarkOutcomeDispatchStarted`, select the exact open
  intent and eligibility digest, compare-and-swap `prepared` at
  `expected_version` to `dispatch_started`, increment the version, and append
  the matching immutable transition event. The caller blocks until this
  transaction is durable, then invokes the qualified durable-acceptance
  transport. A failure denies before handoff and enters the typed pre-dispatch
  cancellation path; it never falls through to transport.
- For `DispatchIntentOp::MarkOutcomeDispatchAccepted`, recompute and verify the
  signed `chio.outcome.dispatch-acceptance.v1` envelope against the configured
  provider binding, exact request/eligibility/parameter digests, and transport
  idempotency key. The store assigns `accepted_at_unix_ms` from its trusted
  clock, compare-and-swaps `dispatch_started` at the expected version to
  `dispatch_accepted`, persists the acceptance bytes/digest, and appends the
  immutable event in one commit. Caller timestamps do not set the SLA window.
  Missing or invalid acceptance records a platform incident but leaves
  `dispatch_started` unresolved; it never creates provider SLA evidence and
  blocks the global SLA ambiguity gate until a trusted query resolves it.
- For an `Intent` carrying `DispatchIntentOp::AttachRailRef`:
  `attach_dispatch_intent_rail_ref_tx(&tx, ...)` (an `UPDATE chio_dispatch_intents
  SET rail_authorization_id = ?2 WHERE request_id = ?1 AND state = 'open'`). Zero
  rows changed is reported to the caller as `ReceiptStoreError::NotFound` on that
  request's response channel only; because the attach is best-effort (see the money
  path below), it never aborts the shared batch the way `Insert` and consume
  failures do.
- For an `Append` with `consume_intent = Some(key)`: run
  `finalize_dispatch_intent_tx(&tx, &key, &receipt)` and
  `append_chio_receipt_tx(&tx, ...)` in that order, both inside the one
  transaction. The finalizer first selects the intent by `request_id` and
  requires exact `parameter_hash`, `tenant_id`, and
  `outcome_eligibility_digest` equality. The ordinary path supplies `None` and
  can consume only a NULL-digest intent. The WS3 path supplies `Some(digest)`;
  it recomputes that digest from the stored canonical eligibility envelope,
  verifies its schema, signature, request id, and intent binding, and requires
  the receipt's signed `chio.outcome.verdict.v1` metadata to carry the same
  digest. It also recomputes the stored canonical acceptance-envelope digest,
  reverifies its provider signature and exact request/eligibility/parameter
  binding, and requires verdict metadata to carry that digest. It then compare-and-swaps the eligibility lifecycle from
  `dispatch_accepted` at the exact expected version to `receipt_bound`, increments
  the version, appends the immutable transition event with the receipt id and
  resolution time, and deletes the intent. Only after those checks and
  transition does it append the receipt.
  A missing row, stale lifecycle, NULL/non-NULL mismatch, wrong digest, or
  receipt-metadata mismatch is `ReceiptStoreError::Conflict` and aborts the
  whole batch (fail-closed, no partial commit).
- For an `Append` with `consume_intent = None`: unchanged behavior.

Because the intent DELETE and the receipt INSERT share the one `tx.commit()` at
`receipt_store.rs:411`, they are atomic: a crash before commit leaves the intent open
and the receipt absent; a successful commit removes the intent and persists the
receipt. This is the requirement's "consume in the same writer transaction" property,
built on the existing group-commit machinery rather than a new writer.
For WS3, that same commit also changes the retained eligibility row to
`receipt_bound`; there is no state in which a receipt consumed the intent while
its eligibility evidence still claims `dispatch_accepted`.

WS3 pre-tool termination uses a separate typed transaction, never the outcome
receipt finalizer. After payment release or no-movement proof is durably known,
`cancel_outcome_intent_before_dispatch` compare-and-swaps only `prepared` to
`not_dispatched`, appends its immutable event, binds either the pre-dispatch
denial receipt or terminal incident, and deletes or dead-letters the intent in
  the same commit. A `dispatch_started` or `dispatch_accepted` record cannot take this path. Pending or
unknown payment cleanup remains an incident, but its eligibility lifecycle is
still `not_dispatched` because the durable dispatch boundary proves the tool was
not invoked; provider SLA math never treats a rail or local preflight failure as
a provider outcome failure.

After transport handoff, only
`resolve_outcome_dispatch_not_accepted` may move `dispatch_started` to
`not_dispatched`. It requires the qualified provider's authenticated,
query-bound `NotAccepted` result for the exact idempotency key and eligibility
digest, records that proof digest and the platform incident, increments the
version, and appends the immutable event in one transaction. Local inference,
timeout, connection failure, or an unavailable query cannot invoke this path.

Durability of the pre-dispatch intent write: `record_dispatch_intent` sends an
`Intent` command and blocks on the response channel exactly as `append` does at
`receipt_store.rs:192-199`. The response is sent only after `tx.commit()` returns, so
the caller observes a durable (WAL-fsynced) commit before it proceeds to dispatch.
Saturation and disconnect are surfaced through the same typed errors already defined
at `receipt_store.rs:182-190` and `receipt_store.rs:268-274`.

### Kernel control-flow changes

In `async_evaluation_core.rs`, insert one step after the budget increment
(currently at line 252) and before `authorize_payment_if_needed` (line 469), so the
intent is durable before the earliest possible effect (prepaid authorize at 469, or
tool dispatch at 525-527):

```rust
// Fail-closed: for side-effecting or monetary calls, write and durably commit a
// dispatch-intent row BEFORE any external effect. On failure we deny here, before
// the effect, converting the old post-effect ReceiptPersistence error into a safe
// pre-effect deny. The budget hold (check_and_increment_budget, line 252) is
// already applied at this point, so a persistence failure must reverse it before
// returning, exactly as the other pre-dispatch abort arms do; a bare `?` here
// would leak the hold on a denied-before-dispatch call.
let dispatch_intent = match self.record_dispatch_intent_if_side_effecting(
    request, cap, matched_grant_index,
) {
    Ok(Some(handle)) => Some(handle),
    Ok(None) => None, // read-only class: no journal write, TTFRH unchanged
    Err(error) => {
        // Reverse the pre-execution hold through the same charge-gated primitive
        // the authorize/admission abort arms use (RFC-0002). payment auth is None
        // (authorize runs later, line 469); a non-monetary side-effecting call
        // holds no charge, so this is a no-op. A reversal error is recorded but
        // never masks the deny.
        if let Err(unwind_error) = self.unwind_aborted_monetary_invocation(
            request, cap, budget_mutation.charge_result(), None,
        ) {
            tracing::error!(
                error = %unwind_error,
                "failed to reverse budget hold after dispatch-intent persistence failure"
            );
        }
        return Err(error);
    }
};
```

`record_dispatch_intent_if_side_effecting` (new, on the kernel) computes the
`SideEffectClass` from the tool manifest annotation and `has_monetary`
(`budget_mutation.charge_result().is_some()`, verified at
`async_evaluation_core.rs:512`). The read-only signal is the existing
`ToolAnnotations::read_only` flag (`crates/core/chio-core-types/src/manifest.rs:126`;
`read_only == true` maps to `SideEffectClass::ReadOnly`); `has_monetary` promotes to
`Monetary`, and everything else is `SideEffecting`. Because `read_only` defaults to
`false` (`#[serde(default)]`), an unannotated or unknown tool fails safe: it is
treated as side-effecting and gets a durable intent, never silently skipped. The
sibling `ToolAnnotations::idempotent` flag is the natural input a reconciler consults
before ever returning `SafeToReplay`. Given a class, the method:

- Returns `Ok(None)` for `ReadOnly` (no write, no latency cost).
- Otherwise builds a `DispatchIntentRecord` whose `parameter_hash` comes from
  `ToolCallAction::from_parameters(request.arguments.clone())`
  (`decision.rs:44`), sets `rail` to the configured adapter id for monetary calls
  (leaving `rail_authorization_id = None` until authorize returns and
  `outcome_eligibility_digest = None` for the base path), and calls
  `store.record_dispatch_intent(&intent)`. Any error maps to a new fail-closed
  variant, reverses the already-applied pre-execution budget hold (routed through
  `unwind_aborted_monetary_invocation`, the same charge-gated reversal the
  authorize and admission abort arms use, so no hold leaks), and denies before
  dispatch.

Money path (F70, extended by RFC-0013): after `authorize_payment_if_needed`
(line 469) returns a `PaymentAuthorization`, attach its `authorization_id` to the
open intent via `store.attach_dispatch_intent_rail_ref(request_id, authorization_id)`
(routed through the actor as `DispatchIntentOp::AttachRailRef`). This is
best-effort-durable: even if it fails, the open intent (with `rail` set) already
proves a monetary attempt, and boot reconciliation queries the rail. The full
generic replay-idempotency contract on the `PaymentAdapter` trait
(`crates/kernel/chio-kernel/src/payment.rs:150-181`, which today requires no
idempotency) is specified in RFC-0013, not here.

Consume at receipt time: `record_chio_receipt`
(`receipt_persistence.rs:164-187`) gains a sibling that, when the request carried an
intent, calls `store.append_chio_receipt_consuming_intent(receipt, &key)` instead of
`append_chio_receipt_returning_seq`. Note that `ChioReceipt`
(`crates/core/chio-core-types/src/receipt/body.rs:35-102`) has no `request_id`
field: its `id` is content-addressed and its only call-binding fields are
`capability_id`, `tool_server`, `tool_name`, `action`, and `tenant_id`. The
`DispatchIntentKey` therefore cannot be reconstructed from the receipt alone. Its
`parameter_hash` and `tenant_id` are taken from `receipt.action.parameter_hash` and
`receipt.tenant_id`, but its `request_id` must be threaded forward from the
pre-dispatch dispatch-intent handle (the `dispatch_intent` value produced by
`record_dispatch_intent_if_side_effecting` and carried on the request), not read off
the receipt. Concretely, the sibling method takes both the `&ChioReceipt` and the
already-known `request_id` (or the full `DispatchIntentKey`), so the plumbing from
`async_evaluation_core` through `allow_responses.rs:72`
(`record_chio_receipt_with_federation`) into `record_chio_receipt` must carry the
handle; the receipt is not a sufficient source. The `parameter_hash` binding still
proves the consumed intent matches the exact call the receipt attests. For WS3,
that handle also carries the verified eligibility digest, and the receipt sink
must extract the same digest from signed outcome-verdict metadata; callers cannot
supply an unrelated digest out of band. Placing the
consume decision at the `record_chio_receipt` level is deliberate: post-dispatch
deny receipts and terminal records funnel through the same sink
(`record_chio_receipt_with_federation` is also called from `deny_responses.rs:97`
and `terminal_responses.rs:48,108`), so whichever receipt kind a journaled call
ends in, committing that receipt consumes the intent, and an effecting call that
ends in a post-dispatch deny does not leave a false orphan behind. The existing
lock scope, checkpoint trigger (`should_checkpoint_after_seq`,
`receipt_persistence.rs:189-195`), and local-log append are preserved; the only
change is which store method runs under the lock. Unlike the return type of
`append_chio_receipt_consuming_authorization` (which returns `Result<(), _>` and
cannot advance the checkpoint), `append_chio_receipt_consuming_intent` returns
`Result<Option<u64>, ReceiptStoreError>` precisely so the returned `seq` still drives
`should_checkpoint_after_seq`.

### WS3 durable provider acceptance

Outcome-priced dispatch is allowed only through a tool-server transport that
implements a durable acceptance handshake. Before acknowledging, the server
stores the exact request under its idempotency key in a durable queue that it
owns across client disconnects and restarts. It then returns a signed
`chio.outcome.dispatch-acceptance.v1` envelope binding schema, acceptance id,
request id, eligibility digest, parameter hash, provider/listing binding,
server queue id, idempotency key, and provider key id/epoch. The kernel resolves
that key from the already verified provider binding; an embedded key is never a
trust root. The acceptance ID uses a domain-separated canonical body preimage
excluding its own ID and signature.

The acknowledgement means the provider has durably assumed responsibility to
execute exactly once or expose a terminal signed outcome through an idempotent
status query, regardless of a later kernel crash. A socket write, connection
accept, in-memory queue, or ordinary synchronous function entry is not durable
acceptance. The kernel records the verified envelope and a trusted store receipt
time in the `dispatch_accepted` CAS. If the acknowledgement is lost after server
commit, restart reconciliation queries the qualified server by the exact
idempotency key and eligibility digest and can recover the same envelope. Until
that proof is recovered, the request is a platform incident and provider SLA
math excludes it.

No current in-tree generic tool server is assumed to satisfy this contract.
WS3 activation requires the transport capability, restart/query qualification,
provider-key trust configuration, schema gates, and crash tests. A server that
cannot prove durable acceptance may still serve ordinary Chio calls but cannot
serve outcome-priced calls or contribute provider SLA denominator evidence.

### Boot-time reconciliation

At kernel startup, after the store opens and before serving, run
`store.reconcile_dispatch_intents(reconciler)` (invoked from kernel construction,
immediately after the receipt store is opened and before the kernel accepts
requests). It selects `WHERE state = 'open'` and, per row:

- Defensive receipt cross-check: receipts carry no `request_id` (see above), so an
  exact lookup is impossible. If a receipt matching the intent's call-binding tuple
  (`capability_id`, `tool_server`, `tool_name`, `action.parameter_hash`,
  `tenant_id`, timestamp at or after `created_at_unix_ms`) exists, the effect is
  very likely already attested; the same-tx consume should preclude this state. The
  reconciler still dead-letters the intent (fail-closed: a heuristic match never
  silently deletes evidence) and records the probable receipt id in
  `resolution_detail` so the operator can close it in one look.
- For WS3, signed verdict metadata makes the eligibility-digest lookup exact
  even though the generic receipt lacks `request_id`. Reconciliation verifies
  that metadata and the stored envelope before using the receipt id. Finding a
  receipt while the intent remains open is an invariant violation, so it still
  produces a typed incident rather than silently repairing state.
- For a WS3 row in `dispatch_started`, reconciliation first queries the
  qualified provider's durable queue by idempotency key and eligibility digest.
  A verified recovered acceptance runs the normal `dispatch_accepted` CAS with
  the trusted local recovery time. An authenticated `NotAccepted` result moves
  the row to `not_dispatched` with the platform incident. An unavailable,
  unauthenticated, or ambiguous query records the incident on the dead-letter
  intent but leaves lifecycle `dispatch_started`, so SLA verification remains
  incomplete instead of silently excluding a possibly accepted request.
- Otherwise the intent is an orphan: an effect may have occurred with no receipt.
  The kernel cannot safely re-execute a side effect, so the default action is
  dead-letter, not blind replay. In one transaction it creates the terminal
  incident id, sets `state = 'dead_letter'`, writes the same id into the typed
  `incident_id` column, writes the reconciler's outcome into
  `resolution_detail`, and, for a WS3 intent, compare-and-swaps the matching
  eligibility row from `dispatch_accepted` to `incident_bound` with that
  incident id, `incident_class = 'provider'`, and the immutable transition event.
  If the record is still `prepared`, it transitions to `not_dispatched` with a
  platform incident. A `dispatch_started` row follows the query rule above and
  never becomes terminal merely because the query is unavailable. The
  dead-letter row itself is the durable, operator-visible incident record: it is counted in
  `ReceiptStoreHealthReport`, flips `healthy` to false, and is visible to the CLI
  `trust receipt health` command; alert routing for a nonzero count rides the
  RFC-0009 observability and alerting wiring.
- For a monetary orphan with `rail` (and possibly `rail_authorization_id`) set, the
  reconciler additionally queries the rail via the adapter to determine whether funds
  actually moved (RFC-0013 supplies the idempotent query/reconcile contract), and
  annotates the incident with the outcome.
- Replay is permitted only for operations the reconciler proves idempotent and
  non-side-effecting; the default posture treats every orphan as dead-letter. A
  `SafeToReplay` decision does not resolve or delete the WS3 eligibility row: the
  intent and eligibility remain in their existing nonterminal state until the
  replay commits a bound receipt or a later terminal reconciliation binds an
  incident. Replay cannot skip the durable `dispatch_started` CAS.

```rust
pub trait DispatchIntentReconciler: Send + Sync {
    /// Decide how to resolve an orphaned intent surviving a restart.
    fn resolve(
        &self,
        intent: &DispatchIntentRecord,
    ) -> Result<DispatchIntentResolution, ReceiptStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchIntentResolution {
    /// Effect could not be confirmed; record an outcome-unknown incident.
    DeadLetter { detail: String },
    /// Reconciler proved the effect never occurred and it is safe to retry.
    SafeToReplay,
    /// Rail query confirmed a monetary outcome; incident carries the reference.
    MonetaryReconciled { rail_reference: String },
}
```

### Outcome eligibility checkpoints (WS3 extension)

The mutable eligibility table is not itself a completeness proof. WS3 therefore
adds a domain-separated signed artifact,
`chio.dispatch.recovery-checkpoint.v1`. Its body carries `schema`,
`checkpoint_id`, store generation, configured checkpoint-authority id and key
epoch, previous checkpoint digest, high-water eligibility and event sequences,
record and event counts, a record-state root ordered by `eligibility_seq`, an
append-only event root ordered by `event_seq`, an immutable creation-time index
root ordered by `(created_at_unix_ms, eligibility_seq)`, a write-once provider
acceptance-time index root ordered by
`(dispatch_accepted_at_unix_ms, eligibility_seq)`, an unresolved
`dispatch_started` root and count, and issuance time.
`checkpoint_id` is SHA-256 over the RFC 8785 canonical body excluding
`checkpoint_id`; the detached signature and envelope digest are outside that
preimage. The verifier resolves the authority and epoch from trusted local
configuration. An embedded or self-selected key never establishes trust.

Each event leaf is the domain-separated hash of its complete canonical row,
including sequence, record version, request id, eligibility digest, transition,
acceptance digest/time, incident class, terminal references, and event time.
Each record-state leaf binds its stable
eligibility sequence, canonical envelope digest, current lifecycle and version,
acceptance digest/time, incident class, terminal references, and
creation/resolution times. Creation and acceptance times come from the trusted
store clock and each index enforces a nondecreasing high-water mark; the
eligibility sequence breaks ties. Creation is immutable after version zero and
acceptance is written exactly once by the authenticated acceptance CAS.

Checkpoint creation first places a barrier behind the single writer, then signs
one transactionally consistent snapshot. A later checkpoint proves that its
event tree extends the prior event prefix. The verifier replays every new event
from the earlier state root, requires exactly the next version for its stable
record position, and recomputes the later state root and counts. A missing,
duplicate, reordered, or mutated transition fails verification. This is the
update proof that a mutable lifecycle leaf alone cannot provide.

An SLA window proof supplies the complete global provider-acceptance-time range
for the declared interval, with predecessor and successor boundary leaves, rather than a
submitter-selected provider subset. It also supplies each selected record's
state leaf at the cutoff and the required lifecycle-event proof. The verifier
locally applies the provider/listing/pricing/predicate selector to that complete
range. Prepared, dispatch-started, not-dispatched, and platform-incident rows
remain visible in the record/event roots but have no acceptance-time index entry
and cannot enter this denominator. This can be larger than a provider-specific index, but it is the minimal
v1 design that proves non-omission. A later authenticated provider index may
optimize the proof without changing the denominator.

V1 deliberately uses a global fail-closed ambiguity gate: the checkpoint's
unresolved `dispatch_started` count must be zero before any SLA breach proof is
accepted. This is conservative but prevents an acknowledgement lost outside a
self-selected range from hiding a provider-accepted request. The root lists the
exact unresolved record positions for operations; reconciliation must recover a
valid acceptance or authenticated `NotAccepted` result before aggregation can
resume. A later version may prove a narrower safe exclusion only with an
authenticated temporal contract.

The checkpoint schema, known-schema allowlist entry, JSON schema, positive and
tamper fixtures, registry manifest entry, and unknown-schema negative land with
WS3 before SLA aggregation activates. No API may claim a complete eligibility
range from table scans or cursors without this signed checkpoint contract.

### Health surface

Extend `ReceiptStoreHealthReport`
(`crates/kernel/chio-kernel/src/receipt_store.rs:100-117`) with two counts and fold
them into the `healthy` computation at `receipt_store.rs:614-631`:

```rust
#[serde(default)]
pub open_dispatch_intents: u64,
#[serde(default)]
pub dead_letter_dispatch_intents: u64,
```

```rust
let healthy = status.healthy
    && self.receipt_commit_actor.writer_counters().last_error.is_none()
    && dead_letter_dispatch_intents == 0;
```

This directly closes the "health lies" gap: an orphaned effect now flips the store to
unhealthy and appears in the CLI `trust receipt health` output
(`crates/products/chio-cli/src/cli/trust/receipt/health.rs:60-73`). Note that the
CLI opening its own store still cannot see a live kernel's in-memory writer counters;
persistent orphan and dead-letter rows are visible to any reader because they live in
the database, which is the point of making them durable. On a pre-journal database
opened via `open_existing` (which runs no DDL), the counting queries treat a missing
`chio_dispatch_intents` table as zero rows (see migration notes). Live writer-liveness polling
is out of scope here and tracked separately in the wave-3 program.

### Config

Add to `KernelConfig`
(`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:10`):

```rust
/// Which call classes must write a durable dispatch intent before dispatch.
/// Default fails safe: cover every effecting class, exempt read-only.
pub dispatch_intent_journal: DispatchIntentJournalMode,
```

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchIntentJournalMode {
    /// No intent writes. Reintroduces the F04/F31/F70 window; operator opt-out only.
    Off,
    /// Write intents for SideEffecting and Monetary classes (default).
    SideEffecting,
    /// Write intents for every mediated call, including read-only.
    All,
}

impl Default for DispatchIntentJournalMode {
    fn default() -> Self {
        Self::SideEffecting
    }
}
```

### Error taxonomy (typed, fail-closed)

`ReceiptStoreError` (`crates/kernel/chio-kernel/src/receipt_store.rs:151`) already
carries `Conflict`, `Pool`, `Sqlite`, and `Timeout`, which cover intent insert
collisions, saturation, disconnect, and commit failure. No new store variant is
required; reconciliation surfaces its own outcomes through
`DispatchIntentResolution` and the incident projection.

`KernelError` (`crates/kernel/chio-kernel/src/kernel/error.rs`) already has
`ReceiptPersistence(#[from] ReceiptStoreError)` at lines 156-157. Because a second
`#[from]` from the same source type is not allowed, add a distinct variant and map
into it explicitly at the intent-write site so a pre-effect deny is
distinguishable from a post-effect persistence failure:

```rust
#[error("dispatch intent persistence failed: {0}")]
DispatchIntentPersistence(String),
```

Fail-closed posture: an intent-write failure denies before any effect
(`build_receipt_persistence_failclosed_deny_response_with_metadata` shape). This is
strictly safer than today, where the equivalent failure surfaces only after the
effect has run.

### Crates, dirs, LOC, CI tier

- `crates/platform/chio-store-sqlite`: table DDL, `insert_dispatch_intent_tx`,
  `finalize_dispatch_intent_tx`, `reconcile_dispatch_intents`, actor `Intent`
  variant, batch changes. ~320 LOC + ~250 LOC tests.
- `crates/kernel/chio-kernel`: types (`DispatchIntentRecord`, `SideEffectClass`,
  `DispatchIntentKey`), trait methods, `record_dispatch_intent_if_side_effecting`,
  consume wiring in `record_chio_receipt`, health fields, config, boot hook. ~260
  LOC + ~200 LOC tests.
- No new crate. Unit and property tests run on the PR gate. Crash/kill-injection
  soak (SIGKILL between authorize/dispatch and receipt commit) runs nightly in the
  load-chaos program; the full power-loss simulation runs weekly. Honest PR-gate
  cost: intent unit and property tests add well under a minute; the nightly
  kill-injection soak is budgeted at roughly 15-20 minutes.

## Wire, schema, and receipt impact

- The base RFC adds no receipt kind or payload field. WS3 separately adds signed
  outcome-verdict metadata carrying eligibility and dispatch-acceptance digests,
  as specified in its versioned contract; this remains an ordinary tool receipt,
  not a new receipt kind. Intent and eligibility rows are never entered into
  `chio_tool_receipts` or its Merkle tree, so ADR-0008 receipt checkpoint and
  inclusion-proof semantics are untouched.
- New non-audit SQLite table `chio_dispatch_intents` (schema above), created
  idempotently in the `SqliteReceiptStore::open` / `open_with_pool_config` path
  (the DDL batch at `open.rs:129` runs for both fresh and existing files, so
  existing databases gain the table on next kernel open via `CREATE TABLE IF NOT
  EXISTS`). `open_existing` (`open.rs:102-126`) returns early and runs no DDL by
  design; see migration notes below.
- WS3 reserves the nullable `outcome_eligibility_digest` column and adds the
  request-keyed `chio_outcome_eligibility_records` table plus immutable
  `chio_outcome_eligibility_events` shown above. They remain
  non-audit operational state; the signed eligibility envelope is not inserted
  into the receipt log or counted as a checkpoint receipt. The dispatch and
  recovery checkpoint projection does include an authenticated leaf for every
  eligibility record, binding request id, envelope and acceptance digests,
  lifecycle/version, incident class, bound receipt or incident id, and
  transition time. Its signed state, event, acceptance-time, and unresolved
  roots supply WS3's
  complete eligibility-record root and count without pretending the record is a
  tool receipt.
- `ReceiptStoreHealthReport` gains two `#[serde(default)]` count fields (additive,
  camelCase, backward compatible with existing JSON consumers).
- Any serialized intent record or reconciliation report uses RFC 8785 canonical JSON,
  consistent with `canonical_json_bytes` already used for `parameter_hash`.

## Migration and compatibility

- Backward compatible. The new table is additive; older binaries ignore it (the
  existing-schema check, `require_existing_receipt_schema` at `open.rs:1126-1157`,
  requires a fixed table list and tolerates extra tables). Newer binaries create it
  in the `open` path. `open_existing` (used by the CLI, `health.rs:43`) runs no DDL,
  so any read of `chio_dispatch_intents` must treat a missing table as zero rows: a
  database that never journaled has no orphans, so this is an accurate report, not a
  fail-open of the invariant (the serving kernel always opens through the DDL path
  and always has the table before its first intent write).
- When WS3 lands after this RFC, the serving `open` path checks
  `PRAGMA table_info(chio_dispatch_intents)` and adds
  `outcome_eligibility_digest TEXT` exactly once before accepting traffic.
  Fresh databases receive it in the base DDL. The migration and
  eligibility record/event table and checkpoint-projection metadata creation
  share one startup transaction; a partial migration aborts startup.
  `open_existing` readers treat an absent column or table as unsupported and do
  not claim eligibility or SLA-proof support.
- No eligibility backfill is required. Existing intent rows remain NULL in the
  additive column and can be consumed only through the base `None` path;
  outcome-priced dispatch is available only for newly created, atomically bound
  intent and eligibility rows. Existing receipts are unaffected.
- Eligibility rows and events are never pruned while their intent is open, their
  lifecycle is nonterminal, or any referenced SLA window can still be filed or
  verified. After the maximum applicable SLA
  evidence-retention window and checkpoint finality, compaction may replace a
  resolved row only with a tombstone committed to an archived
  dispatch/recovery checkpoint root that preserves the request id, eligibility
  digest, terminal binding, and range position. A database delete without that
  archived completeness witness is forbidden.
- Staged rollout via `DispatchIntentJournalMode`. Ship defaulting to `Off` in the
  first release to de-risk latency, enable `SideEffecting` in the second once soak
  data is in hand, and make `SideEffecting` the compiled default in the third. The
  money path (F70) can be gated independently: enable intents for `Monetary` first,
  since that is the highest-consequence class.
- Health `healthy` tightening (dead-letter rows flip unhealthy) is behavior-visible
  to operators; document it in the release notes so a newly surfaced orphan is read
  as "recovery working", not "new fault".

## Test and verification plan

- Unit: intent insert collision on duplicate `request_id` fails closed; consume
  DELETE with mismatched `parameter_hash` aborts the batch and rolls back the receipt
  insert; read-only class writes no row.
- WS3 extension: a base insert with a non-NULL eligibility digest rejects;
  typed insert with canonical signed eligibility writes record and intent
  together; forced failure leaves neither; unknown schema, envelope digest
  mismatch, request mismatch, duplicate request with different bytes, and
  creation of a `prepared` eligibility record without its intent all reject. A
  durable exact-version transition marks platform-owned `dispatch_started`
  before transport handoff. Only a valid provider-bound durable acknowledgement
  produces `dispatch_accepted`. A WS3 receipt with the correct digest atomically
  transitions that accepted record to `receipt_bound`, appends the receipt, and deletes
  the intent; wrong or missing
  receipt metadata, record bytes, digest, request, or lifecycle rolls back all
  operations. A pre-tool abort atomically produces `not_dispatched`, while
  terminal recovery from `dispatch_started` produces a platform incident, while
  recovery from `dispatch_accepted` produces a provider incident; resolved
  terminal records without open intents are valid and remain queryable. Existing
  NULL rows round-trip unchanged through the additive migration.
- Property: for a random interleaving of appends and intents in one batch, after
  `commit_receipt_batch` every consumed intent is gone and every receipt is present,
  and no orphan is created for a committed receipt (the `receipt XOR open_intent`
  invariant). For WS3, each eligibility row is exactly one of `prepared` or
  `dispatch_started` with its open intent, `dispatch_accepted` with its signed
  durable acknowledgement and open intent, `receipt_bound` with its digest-bound
  receipt, `incident_bound` with its typed provider incident, or `not_dispatched` with
  typed proof that the provider never durably accepted the call. Every committed
  lifecycle version has exactly one immutable ordered event.
- Checkpoint/range tests prove creation-time and provider-acceptance-time indexes
  independently. Preparation on one side of an SLA boundary and durable
  acceptance on the other is included only by acceptance time. Omitted or
  duplicated acceptance leaves, boundary leaves, acknowledgement digests,
  incident classes, or transition versions reject.
- Loom: model the actor channel with concurrent `Intent` and `Append` (consume)
  commands plus a `Flush`, asserting no lost or double-consumed intent and correct
  `inflight` accounting, extending the existing writer-counter reasoning at
  `receipt_store.rs:168-199`.
- Crash/chaos (load-chaos program): SIGKILL the kernel at three injection points
  (after prepaid authorize at `async_evaluation_core.rs:469`, after transport
  send but before durable acceptance, after provider durable acceptance but
  before the local acceptance CAS, after accepted tool dispatch, and mid-batch
  inside `append_receipt_batch`), restart, run
  `reconcile_dispatch_intents`, and assert every killed request resolves to either a
  durable receipt or a dead-letter incident, never silence. This is the specific test
  that proves the change: `intent_journal_crash_reconciles_every_effect`. The
  provider status query recovers a committed acknowledgement; a pre-acceptance
  crash remains a platform incident and never enters provider SLA math.
- Soak: sustained side-effecting load with periodic kills; assert
  `open_dispatch_intents` returns to zero after each reconciliation and TTFRH for
  read-only calls is unchanged within noise.
- Formal-methods tie-in: the `receipt XOR open_intent` invariant is stated as a state
  predicate for the receipt-durability model in the formal-methods plan; the loom and
  property tests are its executable witnesses.

## Acceptance criteria

- Killing the kernel at any of the three injection points above and restarting yields,
  for every in-flight side-effecting/monetary request, exactly one of: a durable
  receipt, or a dead-letter incident with a recorded `request_id`. Never neither.
- After reconciliation of a clean run, `open_dispatch_intents == 0` and
  `dead_letter_dispatch_intents == 0`, and `receipt_store_health().healthy == true`.
- A monetary orphan produces an incident that names the `rail` and, when available,
  the `rail_authorization_id`, so an operator can reconcile against the rail without
  guessing the reference.
- Read-only calls write no intent row and show no measurable TTFRH regression.
- An intent-write failure denies before dispatch (no effect, no rail call), surfaced
  as `KernelError::DispatchIntentPersistence`.

## Risks and alternatives

- Added latency on effecting paths. Each side-effecting or monetary call pays one
  extra durable round-trip before dispatch. It group-commits with other intents
  (same 64/500us batching) and is dwarfed by the external tool or rail call that
  follows, so relative overhead is small; read-only calls pay nothing. Mitigation:
  the class gate and `DispatchIntentJournalMode` bound the cost precisely, and the
  soak measures it before `SideEffecting` becomes default.
- Write amplification: two extra statements per effecting call (one insert
  pre-dispatch, one delete at consume). Both are keyed on `request_id` and ride
  existing transactions; measured impact is expected to be minor and is a soak gate.
- Reconciler correctness: a wrong `SafeToReplay` decision could re-run a side effect.
  Mitigation: the default is `DeadLetter`; `SafeToReplay` requires the reconciler to
  prove idempotence, and monetary calls never replay blindly (rail query only).
- Alternative considered and rejected: a per-kernel append-only WAL file separate
  from SQLite. Rejected because ADR-0013 already commits to a WAL-fsync-before-allow
  model inside the store, and a second write-ahead surface would duplicate durability
  machinery, complicate recovery ordering, and not give the same-transaction consume
  guarantee that a shared SQLite transaction gives for free.
- Alternative considered and rejected: making the intent a real signed receipt kind.
  Rejected because it would inflate the Merkle-committed log with speculative,
  frequently-consumed rows and disturb ADR-0008's count-based checkpoint sizing; the
  intent is operational state, not attestation.
- Alternative considered and rejected: blind replay of orphaned intents on boot.
  Rejected because side effects are not generally idempotent; replay could double a
  payment. Dead-letter-by-default is the fail-closed choice.

## Rollout and sequencing

1. RFC-0006 lands first: it bounds the receipt-store append cost and fixes
   single-writer discipline for the store this journal rides on (RFC-0006 sequences
   itself ahead of this RFC for exactly that reason). Boot reconciliation and the
   dead-letter incident record are self-contained in this RFC; alert routing for a
   nonzero `dead_letter_dispatch_intents` count rides the RFC-0009 observability and
   alerting wiring.
2. This RFC (RFC-0003) lands next: schema, actor `Intent` variant, same-transaction
   consume, kernel wiring, health fields, config defaulting to `Off`.
3. Enable `Monetary` then `SideEffecting` via config after nightly kill-injection soak
   is green; promote `SideEffecting` to compiled default.
4. RFC-0013 extends the money path: it upgrades `rail_authorization_id` handling into
   a full payment journal and adds the `PaymentAdapter` capture/release idempotency
   contract keyed on `(authorization_id, request_id)`, enabling safe rail-side replay
   during reconciliation. RFC-0003's `rail` / `rail_authorization_id` columns and the
   `MonetaryReconciled` resolution are the durable substrate it builds on.

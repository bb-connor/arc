# RFC-0013: Money-path durability: payment journal, hold sweeper, settlement routing, fail-closed caps

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0006 (monetary budget semantics), ADR-0015 (predeclared escrow circuit breakers)
- Depends on: RFC-0003 (durable dispatch-intent journal)
- Closes findings: F70, F71, F68, F69, F72, F73, F74 (see ./README.md and the wave-3 readiness review)

## Summary

The economy subsystem moves external funds before it writes any durable, attested
record of the movement, leaks budget capacity on every crash, and drops the
settlement outcome on the floor at its only production call site. This RFC makes the
money path crash-safe and fail-closed. It adds a durable `payment_journal` co-located
with the budget holds (written before `adapter.authorize`, advanced around
capture/release, closed after the receipt persists, reconciled on boot via an
idempotent adapter query); a boot-plus-periodic sweeper for orphaned budget holds; a
routing consumer that feeds the discarded settlement-observer outcome into the
existing `classify_attempt` retry envelope and `SqliteDeadLetterStore`; the intended
production `SettlementHook` driver seam; a fail-closed `Deny(CurrencyMismatch)` in
`BudgetTree` instead of a silent skip; a durable SQLite EIP-3009 nonce store; and a
durability caveat plus snapshot seam for the process-local `BudgetEnforcer`. It is the
money-path specialization of RFC-0003: RFC-0003 owns the generic
`receipt XOR open_intent` guarantee and delegates monetary orphans to the reconciler
specified here.

## Motivation

Read against the Ubicloud "PostgreSQL and the OOM Killer" lens: when a component dies
mid-operation, internal accounting must be trustworthy or loudly broken, the blast
radius must be knowable, and recovery must be durable. On the money path today the
accounting is silently broken in five distinct places.

- F70 (high): kernel death (OOM kill, crash, power loss) after the rail moved money
  (capture for generic adapters; pre-execution `authorize` for the in-tree prepaid
  X402/ACP-Commerce adapters) but before `record_chio_receipt` commits leaves external funds
  moved with no receipt row and no stored rail reference. The durable
  `budget_mutation_events` log records exposure units and `hold_id` but not the
  payment `authorization_id`. Trigger: process death in that window. Effect: the payer
  is charged with no attested record. Impact: a direct breach of the receipt-log
  completeness guarantee the system exists to provide; recovery needs manual rail-side
  statement matching, and because `PaymentAdapter` requires no idempotency, no generic
  replay-based recovery can be built.
- F71 (medium): open budget holds have no sweeper. Trigger: crash between
  `authorize_budget_hold` and the post-execution reconcile. Effect: the hold stays
  `disposition='open'` and `total_cost_exposed` stays elevated forever. Impact: each
  crash permanently burns one invocation's worth of capacity per in-flight priced
  call; over months a multi-tenant kernel spuriously hits `BudgetExhausted`. Direction
  is fail-closed (under-spend), so this is availability erosion, not money loss.
- F68 (high): the settlement-observer outcome is discarded at
  `receipt_persistence.rs:185`. Trigger: any deployment wires a settlement hook and it
  returns `Retryable`/`Permanent` or errs for a money-bearing receipt. Effect: the
  outcome is dropped with no retry, no dead-letter row, no log, no metric. Impact:
  tool-server operators are silently never paid, and `chio settle status` reads tables
  no production code populates, so the loss is invisible to the tool built to detect
  it.
- F69 (medium): no production `SettlementHook`/`CreditEvaluatorHook` driver exists
  in-tree. Every implementation is test-only, so "settlement works" is unfalsifiable
  and any embedder inherits F68's silent-drop behavior.
- F72 (medium): `BudgetTree` skips the spend cap on currency mismatch, contradicting
  the module's own fail-closed claim. A EUR-denominated draft walks through USD caps
  with no deny and no warning.
- F73 (low): the durable EIP-3009 nonce store the docs reference does not exist; the
  in-memory store loses replay state on crash and wedges at capacity with no
  scheduled GC.
- F74 (low): `chio-metering::BudgetEnforcer` counters are process-local and reset to
  zero on restart, silently re-opening every tenant's full budget after each restart.

## Current behavior (verified 2026-07-04)

Money-path ordering in the kernel finalize path
(`crates/kernel/chio-kernel/src/kernel/validation.rs`):

1. Pre-execution the budget hold is durably debited. `authorize_budget_hold` is
   called at `validation.rs:784-796`; the sole durable pre-execution write of
   `total_cost_exposed`.
2. Pre-execution the payment rail is authorized. The authorize helper calls
   `adapter.authorize(&PaymentAuthorizeRequest { .. })` at `validation.rs:1274-1284`,
   returning a `PaymentAuthorization` held only in memory. For the prepaid adapters
   the real external HTTP call is in `authorize`
   (`crates/kernel/chio-kernel/src/payment.rs:287-310`) and `capture` is a local
   no-op returning `Settled` (`payment.rs:312-329`), so prepaid funds move here.
3. Post-execution the hold is reconciled and the rail captured/released.
   `reconcile_budget_charge` is called at `validation.rs:1000` (defined at
   `validation.rs:881-899`); then, at `validation.rs:1003-1025`, the generic path
   calls `adapter.release(&authorization.authorization_id, &request.request_id)`
   (line 1013) or `adapter.capture(&authorization.authorization_id, actual_cost,
   &charge.currency, &request.request_id)` (line 1015).
4. The financial metadata is built and the response constructed. `FinancialReceiptMetadata`
   is assembled at `validation.rs:1089-1108` and passed to
   `build_allow_response_with_metadata` at `validation.rs:1131`. Receipts with no
   payment adapter are stamped `ReceiptSettlement::settled()` at `validation.rs:1064`.
5. The signed receipt is persisted by `record_chio_receipt`
   (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:164-187`).
   The final line is the F68 defect:

   ```rust
   let _settlement_status = self.run_settlement_observer(receipt);
   Ok(())
   ```

   The `SettlementObserverStatus` return is bound to `_settlement_status` and dropped.

The `PaymentAdapter` trait (`crates/kernel/chio-kernel/src/payment.rs:150-181`) has
the current signature (no idempotency requirement, no reconcile-query method):

```rust
pub trait PaymentAdapter: Send + Sync {
    fn authorize(&self, request: &PaymentAuthorizeRequest)
        -> Result<PaymentAuthorization, PaymentError>;
    fn capture(&self, authorization_id: &str, amount_units: u64, currency: &str,
        reference: &str) -> Result<PaymentResult, PaymentError>;
    fn release(&self, authorization_id: &str, reference: &str)
        -> Result<PaymentResult, PaymentError>;
    fn refund(&self, transaction_id: &str, amount_units: u64, currency: &str,
        reference: &str) -> Result<PaymentResult, PaymentError>;
}
```

A repo-wide grep for `payment`/`journal`/`pending_payment` in `chio-kernel` finds no
durable record of `authorization_id` before the receipt. The budget hold schema
(`crates/platform/chio-store-sqlite/src/budget_store/store.rs:36-49`) is:

```sql
CREATE TABLE IF NOT EXISTS budget_authorization_holds (
    hold_id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, grant_index INTEGER NOT NULL,
    authorized_exposure_units INTEGER NOT NULL, remaining_exposure_units INTEGER NOT NULL,
    invocation_count_debited INTEGER NOT NULL, disposition TEXT NOT NULL,
    authority_id TEXT, lease_id TEXT, lease_epoch INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
```

There is a `created_at` but no TTL/expiry column and no sweep query. `HoldDisposition`
(`crates/platform/chio-store-sqlite/src/budget_store/model.rs:4-9`) is
`{ Open, Released, Reversed, Reconciled }`. `BudgetMutationKind`
(`crates/kernel/chio-kernel/src/budget_store.rs:34-40`) is `{ IncrementInvocation,
AuthorizeExposure, ReverseExposure, ReleaseExposure, ReconcileSpend }`. No sweeper, no
open-hold listing, no CLI command exist across `chio-store-sqlite` and `chio-cli`.

The settlement machinery exposes a typed routing contract but is not yet wired to
the SQLite outbox. `run_observer` returns `SettlementObserverStatus {
NotRegistered, Skipped { reason }, Observed { outcome }, HookFailed { class,
reason } }`. `classify_attempt` returns `RetryDecision { Accepted, Retry { attempt,
backoff, reason }, DeadLetter { reason }, Skip { reason } }` under `RetryPolicy`
(defaults `max_retries=5`, `initial_backoff_ms=250`, `backoff_multiplier=2`,
`backoff_cap_ms=60_000`). The paired kernel installer requires a receipt store that
reports atomic settlement-observation projection support, verifies that both store
views carry the same fixed-size writer binding, and prevents later store replacement.
`SqliteDeadLetterStore` has `insert`/`get`/`list`/`clear` over
`settle_dead_letters`, but the receipt-side attempt-zero projection and leased
outcome store are not connected yet. The CLI reads
`settle_dead_letters`/`iou_envelope`/`settlement_reconciliations`
(`crates/products/chio-cli/src/settle.rs:89-99`, `181-196`, `260-283`) but only its
own tests populate those tables (the INSERTs at `settle.rs:339-360`).

`BudgetTree::evaluate` skips the spend cap on currency mismatch
(`crates/economy/chio-metering/src/budget_hierarchy.rs:613-637`):

```rust
if let Some(cap) = limits.max_spend_units {
    let currency_matches = match (&limits.currency, &draft.currency) {
        (Some(a), Some(b)) => a == b,
        _ => false, // "mismatched currency means we skip"
    };
    if currency_matches && projected.spend_units > cap { /* deny */ }
}
```

The module doc at `budget_hierarchy.rs:9` claims "the tree renders a fail-closed
`BudgetDecision`". `BudgetDenyReason`
(`budget_hierarchy.rs:334-364`) has `{ NodeDisabled, DimensionExceeded, WindowExpired,
UnknownNode }`, no currency variant.

The only `Eip3009NonceStore` implementation
(`crates/economy/chio-settle/src/payments.rs:406`) is `InMemoryEip3009NonceStore`
(`Mutex<HashMap>`); the doc at `payments.rs:366-371` claims a SQLite store "wired by
default" that does not exist. At `DEFAULT_MAX_EIP3009_NONCE_ENTRIES = 65_536`
(`payments.rs:284`) the record path returns `SettlementError::InvalidBinding`
(`payments.rs:426-432`) and `gc_expired` (`payments.rs:437-442`) has no scheduler.

`BudgetEnforcer` (`crates/economy/chio-metering/src/budget.rs:78-89`) holds a plain
`u64 total_spent` and three `HashMap`s zeroed in `new()` (`budget.rs:91-101`);
`record()` (`budget.rs:167-181`) mutates in memory only. No persistence seam.

## Design

The money path gains one durable state machine (`payment_journal`), one recovery
sweep, and one routing consumer, plus four smaller fail-closed corrections. All new
code uses `?` or explicit typed-error `match`; no `unwrap`/`expect`. Fail-closed is the
posture throughout: on any ambiguity the change denies, dead-letters, or raises a loud
operator incident rather than silently proceeding.

### F70: durable payment journal + idempotent adapter contract

New table in the budget-store database (co-located with the holds so the pre-execution
hold write and the journal write share one `TransactionBehavior::Immediate`
transaction), added in `crates/platform/chio-store-sqlite/src/budget_store/store.rs`
beside the `budget_authorization_holds` DDL:

```sql
CREATE TABLE IF NOT EXISTS payment_journal (
    request_id        TEXT PRIMARY KEY,
    capability_id     TEXT NOT NULL,
    grant_index       INTEGER NOT NULL,
    hold_id           TEXT,
    rail              TEXT NOT NULL,          -- adapter id, known before authorize
    rail_mode         TEXT NOT NULL,          -- reversible_hold|prepaid_final
    authorization_id  TEXT,                   -- attached after authorize returns
    transaction_id    TEXT,                   -- attached after a terminal PaymentResult
    amount_units      INTEGER NOT NULL,       -- preauthorized (hold) amount
    settle_action     TEXT,                   -- capture|release; NULL for final prepayment
    settle_amount_units INTEGER,              -- exact capture amount; NULL for release
    currency          TEXT NOT NULL,
    state             TEXT NOT NULL,          -- see PaymentJournalState
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payment_journal_state ON payment_journal(state);
```

New types in `crates/kernel/chio-kernel/src/payment.rs` (kernel-owned, mirrored into
the store crate):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRailMode {
    /// Authorize creates a reversible hold completed by capture or release.
    ReversibleHold,
    /// Authorize itself moves the fixed prepaid amount.
    PrepaidFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentJournalState {
    /// Row written with the budget hold, before adapter.authorize.
    HoldPlaced,
    /// A reversible adapter hold exists; authorization_id is set. A final
    /// prepayment never enters this state.
    Authorized,
    /// About to call capture/release; the rail may move money next.
    Settling,
    /// The rail's terminal action completed: capture, release, or final prepayment.
    /// Callers inspect rail_mode and settle_action before inferring money movement.
    Settled,
    /// Receipt persisted; terminal success.
    Closed,
    /// Boot reconcile could not settle or determine outcome; operator incident.
    ReconcileFailed,
}

/// Terminal action chosen before entering `Settling`: the rail call boot
/// reconciliation must replay for a `Settling` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSettleAction {
    /// Capture the recorded `amount_units` from the hold.
    Capture,
    /// Release the whole hold without capturing.
    Release,
}

/// The committed settle decision, stamped atomically with the advance to
/// `Settling` so reconciliation replays the exact operation rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentSettleIntent {
    pub action: PaymentSettleAction,
    /// Exact capture amount for `Capture`; `None` for `Release`.
    pub amount_units: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentJournalRecord {
    pub request_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    pub rail: String,
    pub rail_mode: PaymentRailMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub amount_units: u64,
    /// Terminal action stamped before entering `Settling`. Always None for
    /// `PrepaidFinal`, whose authorize operation is already terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_action: Option<PaymentSettleAction>,
    /// Exact capture amount recorded with `Capture`; None for `Release`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_amount_units: Option<u64>,
    pub currency: String,
    pub state: PaymentJournalState,
    pub created_at_unix_ms: u64,
}
```

New `BudgetStore` methods (`crates/kernel/chio-kernel/src/budget_store.rs`, defaulted
so non-SQLite stores stay compilable and fail closed if a monetary call reaches them):

```rust
/// Insert a fresh journal row in `HoldPlaced`. Collides fail-closed on a reused
/// request_id (INSERT ... ON CONFLICT(request_id) DO NOTHING; zero rows -> Conflict).
fn record_payment_journal(&self, _entry: &PaymentJournalRecord)
    -> Result<(), BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal is not supported by this budget store".to_string(),
    ))
}

/// Compare-and-set state advance. `expected` must match the current row state or the
/// call returns Conflict (fail-closed); optional fields are attached when present. When
/// advancing `Authorized -> Settling` the caller MUST pass `settle` (the committed
/// action and, for a capture, the exact amount) so boot reconciliation can replay the
/// exact operation; the store stamps `settle_action`/`settle_amount_units` atomically
/// with the state change. `settle` MUST be None for every other transition, including
/// the `PrepaidFinal` direct `HoldPlaced -> Settled` transition. The implementation
/// validates the transition, rail mode, settle intent, and attached references as one
/// compare-and-set operation rather than accepting arbitrary state pairs.
fn advance_payment_journal(&self, _request_id: &str, _expected: PaymentJournalState,
    _next: PaymentJournalState, _authorization_id: Option<&str>,
    _transaction_id: Option<&str>, _settle: Option<PaymentSettleIntent>)
    -> Result<(), BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal is not supported by this budget store".to_string(),
    ))
}

/// Move the row to Closed. Idempotent: already-Closed returns Ok(false).
fn close_payment_journal(&self, _request_id: &str) -> Result<bool, BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal is not supported by this budget store".to_string(),
    ))
}

/// Rows in a non-terminal state older than `older_than_unix_ms`, for boot reconcile.
/// Fail closed like the write-side journal defaults above: a store that persists
/// `HoldPlaced`/`Settling` rows but leaves listing unimplemented MUST NOT silently
/// report zero incomplete payments, because that would skip boot reconciliation
/// entirely and strand in-flight holds. An unsupported listing is an explicit,
/// operator-visible error, never an empty success.
fn list_incomplete_payment_journal(&self, _older_than_unix_ms: u64)
    -> Result<Vec<PaymentJournalRecord>, BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal listing is not supported by this budget store".to_string(),
    ))
}
```

Kernel control-flow changes in `validation.rs`, all keyed on `request.request_id`:

1. Before `adapter.authorize` at `validation.rs:1274`, write the journal row with
   `state = HoldPlaced`, `rail = adapter.rail_id()`, `authorization_id = None`. The
   kernel sets `PaymentAuthorizeRequest.reference` (payment.rs:91) to this same
   `request_id`, so authorize's idempotency key is durable before the external call
   and the HoldPlaced row is recoverable through `settlement_state(request_id, None)`
   if the process dies before step 2.
   Atomicity note: every SQLite `BudgetStore` method opens its own
   `TransactionBehavior::Immediate` transaction
   (`budget_store/trait_impl.rs`), so calling two trait methods inside one
   `with_budget_store(|store| ...)` closure yields two transactions, not one. To
   make the hold and journal genuinely atomic, `BudgetAuthorizeHoldRequest`
   (`crates/kernel/chio-kernel/src/budget_store.rs:176`, which already carries the
   optional `hold_id`/`event_id`/`authority`) gains an optional
   `payment_journal: Option<PaymentJournalRecord>` field, and the SQLite
   `authorize_budget_hold` inserts the journal row inside the same transaction as
   the hold write. `record_payment_journal` remains the standalone insert for
   recovery tooling and tests.
2. Replace the ambiguous `PaymentAuthorization.settled: bool` with a typed
   `PaymentAuthorizationState::{Held, PrepaidFinal}` and verify it agrees with the
   prevalidated `rail_mode`. The existing `authorization_id` is the stable payment
   reference for final prepayment; the adapter response does not invent a second
   transaction identifier. After `adapter.authorize` returns:
   a reversible `Held` authorization advances `HoldPlaced -> Authorized` with
   its authorization id and no settle intent; a `prepaid_final` authorization
   must return `PrepaidFinal` and advances directly `HoldPlaced -> Settled`, attaching
   its authorization id while leaving `transaction_id`, `settle_action`, and
   `settle_amount_units` NULL. A held result from a final-prepayment profile or a
   final-prepayment result from a reversible-hold profile is a typed invariant failure
   and enters reconciliation. Final prepayment is never represented as a releasable
   hold or as a synthetic capture.
3. For `reversible_hold`, before `adapter.capture`/`adapter.release` at
   `validation.rs:1013-1015`, advance to
   `Settling` PASSING the terminal settle intent
   (`Some(PaymentSettleIntent { action, amount_units })`): `Capture` with the exact
   post-execution cost (which may differ from the preauthorized `amount_units`), or
   `Release` with `None`. The intended rail call and its amount are thus durable
   BEFORE any money can move, so a crash inside the rail call is replayable without
   guessing. Validate the returned `PaymentResult` against the committed action before
   advancing: `Capture` accepts only `Captured` or `Settled`, and `Release` accepts only
   `Released`. `Pending` leaves the row in `Settling` for recovery. `Failed`, or any
   status incompatible with the committed action, advances to `ReconcileFailed` and
   raises an operator incident; it never produces a terminal success receipt. Only a
   compatible terminal result advances to `Settled` and attaches `transaction_id`.
   A `prepaid_final` row is already `Settled`; finalization
   performs no capture or release and must charge the fixed prepaid amount. It is
   ineligible for outcome-contingent or refundable modes.
4. After `record_chio_receipt` commits the signed receipt, call
   `close_payment_journal(request_id)` (best-effort-durable). A crash between the
   receipt commit and the close leaves a `Settled` row that boot reconcile closes,
   because the matching attested receipt exists.

The `PaymentAdapter` trait is amended to make replay-based recovery sound. Three
additions (the idempotency contract plus two defaulted methods, both fail-closed):

```rust
/// Side-effect-free snapshot of the rail's view of a prior authorization, keyed on
/// the durable `reference`. Distinct from `PaymentResult` because the HoldPlaced
/// crash-window query MUST be able to return the rail-assigned `authorization_id`
/// even though no funds have moved and no `transaction_id` exists yet; `PaymentResult`
/// (payment.rs:19-25) carries only `transaction_id`/`settlement_status`/`metadata` and
/// cannot convey the id, which would force adapters to smuggle it through ad hoc
/// metadata and leave reconciliation unable to call `release`/`capture` reliably.
pub enum RailSettlementState {
    /// The rail has no hold or settlement for this reference: `authorize` never took
    /// effect. Reconciliation reverses the local budget hold and closes the journal.
    NoAuthorization,
    /// A hold exists but no funds have moved. Carries the rail-assigned
    /// `authorization_id` so reconciliation can persist it (advance the journal to
    /// `Authorized`) and drive the idempotent `release`/`capture` APIs.
    Held { authorization_id: String },
    /// Funds already moved on the rail. Carries the rail-assigned `authorization_id`
    /// and the settled `PaymentResult` so reconciliation can record the id and emit a
    /// signed receipt for the already-moved amount.
    Settled { authorization_id: String, result: PaymentResult },
}

pub trait PaymentAdapter: Send + Sync {
    // ... authorize / capture / release / refund unchanged in signature ...

    /// CONTRACT: authorize MUST be idempotent keyed on `request.reference`
    /// (payment.rs:91), which the kernel sets to the durable `request_id` written
    /// into the journal BEFORE the call. A repeated authorize with the same
    /// reference returns the same authorization and places AT MOST ONE rail-side
    /// hold. This closes the HoldPlaced crash window: if the process dies after
    /// authorize succeeds but before the post-call journal advance (step 2 below),
    /// no `authorization_id` is durable yet, but reconciliation can still discover
    /// or release the hold via `settlement_state(request_id, None)` because the
    /// reference is durable.

    /// CONTRACT: capture and release MUST be idempotent keyed on
    /// (authorization_id, reference). A repeated call with the same key returns an
    /// equivalent PaymentResult and moves money AT MOST ONCE. Boot reconciliation
    /// relies on this to replay a Settling journal row without double-charging.

    /// Stable rail identifier recorded in the payment journal before authorize
    /// runs (in-tree: "x402", "acp"). Needed because the kernel holds only a
    /// boxed trait object (set_payment_adapter, construction.rs:429) with no
    /// other name for the rail. Defaulted so third-party adapters compile; an
    /// "unspecified" rail makes boot reconciliation fail closed to
    /// ReconcileFailed rather than guessing which rail to query.
    fn rail_id(&self) -> &'static str {
        "unspecified"
    }

    /// Query the current rail-side settlement state for a prior authorization WITHOUT
    /// moving funds. Idempotent and side-effect-free. Keyed on `reference` (the durable
    /// `request_id` written into the journal before authorize), so it stays answerable
    /// in the HoldPlaced crash window where no `authorization_id` is durable yet;
    /// `authorization_id` is an optional refinement passed once known. Returns a
    /// `RailSettlementState` that explicitly carries the rail-assigned `authorization_id`
    /// when a hold or settlement exists, so boot reconciliation can record it and act on
    /// it (persist, release, or capture) instead of discarding it or relying on adapters
    /// to hide it in `PaymentResult.metadata`. Defaulted to `Unavailable` so an adapter
    /// that cannot answer forces a fail-closed operator incident rather than a silent
    /// close during reconciliation.
    fn settlement_state(&self, reference: &str, authorization_id: Option<&str>)
        -> Result<RailSettlementState, PaymentError> {
        let _ = (reference, authorization_id);
        Err(PaymentError::Unavailable(
            "settlement_state query not implemented by this adapter".to_string(),
        ))
    }
}
```

Boot reconciliation (registered into RFC-0003's boot recovery orchestration and
serving RFC-0003's `MonetaryReconciled` resolution) iterates
`list_incomplete_payment_journal(now - horizon)` and, per row, is deterministic (no
discretion, mirroring ADR-0015 D3/D5):

- `HoldPlaced`: authorize may or may not have fired, and no `authorization_id` is
  durable. Query `settlement_state(request_id, None)` by the durable reference.
  `NoAuthorization` closes the journal and releases local exposure because funds never
  moved. For `ReversibleHold`, `Held { authorization_id }` records the returned id,
  advances to `Authorized`, and completes through the release branch below; an already
  settled result before a terminal action was committed is unexpected movement and
  becomes `ReconcileFailed`. For `PrepaidFinal`, only a rail result whose status is
  exactly `Settled` may advance directly to `Settled`, using `authorization_id` as the
  payment reference and leaving settle action NULL; `Held` or any other result is
  `ReconcileFailed`. An `Unavailable` error is `ReconcileFailed`, never a silent close.
  Because the id is carried by the return type, recovery never guesses or reconstructs
  it from ad hoc metadata.
- `Authorized`: authorize succeeded but no terminal action was ever committed (the crash
  predates step 3, so `settle_action` is NULL). No capture amount was chosen, so the only
  sound, price-free completion is to `release` the hold (idempotent) and close; funds
  were only held. Validation treats an `Authorized` row whose `rail_mode` is not
  `reversible_hold` as corrupt and marks it `ReconcileFailed`; a final prepayment
  can never take this release branch.
- `Settling`: a terminal action IS durable. Replay exactly the recorded `settle_action`
  and `settle_amount_units` (idempotent by the amended contract): `Capture` re-captures
  the recorded amount, `Release` releases the hold. This is a predeclared, price-free
  terminal state (ADR-0015 D2): it never selects a new amount, only completes the
  committed one. Apply the same action/status matrix as the live path: a compatible
  terminal result advances to `Settled`, `Pending` remains recoverable, and
  `Failed`/incompatible results become `ReconcileFailed`. A `Settling` row missing its
  `settle_action` is corrupt and is never completed by guessing.
- `Settled`: inspect the durable mode and action before deciding what happened.
  `PrepaidFinal` and `Capture` mean funds moved; if the request receipt is absent, emit
  the signed reconciliation receipt for the recorded amount before closing. `Release`
  means no funds moved; persist the terminal no-movement recovery resolution and close
  without fabricating a money-movement receipt. Any impossible combination of
  `rail_mode`, `settle_action`, references, or amount becomes `ReconcileFailed`.
- Any adapter error or `settlement_state` returning `Unavailable`: set
  `ReconcileFailed` and raise an operator incident. Never silently close.

### F71: open-hold sweeper

Extend `HoldDisposition` (`budget_store/model.rs:4-9`) with `Expired` (`as_str` ->
`"expired"`) and `BudgetMutationKind` (`kernel/budget_store.rs:34-40`) with `ExpireHold`
(`as_str` -> `"expire_hold"`). Add two `BudgetStore` methods:

```rust
/// Open holds whose created_at is older than the horizon, oldest first.
fn list_open_holds_older_than(&self, older_than_unix_ms: u64, limit: usize)
    -> Result<Vec<OpenHoldSummary>, BudgetStoreError>;

/// Release the remaining exposure after the recovery coordinator proves that the
/// request cannot still move money. Idempotent by recovery_resolution_digest.
fn release_recovered_hold(
    &self,
    hold_id: &str,
    expected_hold_version: u64,
    request_id: &str,
    resolution: RecoveredHoldResolution,
    recovery_resolution_digest: &str,
) -> Result<bool, BudgetStoreError>;
```

`OpenHoldSummary` is a new read-model struct carrying `hold_id`, `request_id`,
hold version, `capability_id`, `grant_index`, `remaining_exposure_units`, and
`created_at_unix_ms`. The hold table gains `request_id` and a monotonic version
for all new rows. Legacy rows without a request id are investigation-only and
cannot be auto-expired.

Age is a scan trigger, never release authority. There is no second recovery-
authorization table. `RecoveredHoldResolution` is a closed typed input limited to
`NoAuthorization` and `Released`; captured, settled-prepayment, pending, failed, and
unknown outcomes are not representable as release authority. The registered recovery
coordinator serializes work by `request_id`, reconciles the payment journal first, and
verifies that RFC-0003 has neither an open intent nor a dead-lettered outcome-unknown
intent before it calls `release_recovered_hold`. It derives
`recovery_resolution_digest` from the canonical terminal rail/intent evidence and uses
that digest as the budget mutation event id. A `Settling`, moved-funds `Settled`,
`ReconcileFailed`, open or outcome-unknown dispatch intent, unknown rail state, legacy
hold without `request_id`, or missing resolution never reaches the mutation call.

`release_recovered_hold` runs one `Immediate` transaction that rechecks the hold's
request binding and expected version, requires it still be open, verifies that no
nonterminal or `ReconcileFailed` payment-journal row exists, rejects a resolution that
does not match the terminal local journal state, and inserts the digest-derived mutation
event id before changing exposure. A duplicate event id returns `Ok(false)` without a
second mutation. A fresh valid call subtracts `remaining_exposure_units` from
`capability_grant_budgets.total_cost_exposed`, sets the hold
`disposition = 'expired'`, and appends the `expire_hold` mutation event in that same
transaction. Any stale, missing, or conflicting proof leaves exposure unchanged. It
never touches `total_cost_realized_spend`.

A kernel sweep task (boot-once, then periodic on `hold_sweep_interval`, default
`300s`) first runs RFC-0003 and payment-journal reconciliation, then calls
`list_open_holds_older_than(now - hold_expiry_horizon, batch)`. It expires only
rows for which the recovery coordinator obtains a qualifying terminal resolution;
all other old holds remain frozen and emit an incident. `hold_expiry_horizon` defaults to `3600s`
and controls investigation timing only, not safety. A gauge
metric `chio_budget_open_holds` and a counter `chio_budget_holds_expired_total`
(both declared in `chio-metrics-spec` and exported through the kernel's
Prometheus text exposition, per the F68 note) make the leak visible, and the CLI
gains `chio budget holds list` and `chio budget holds review <hold-id>` to show
the journal/intent and recovery resolution. No age-only manual release command
bypasses the recovery proof.

### F68: route the settlement-observer outcome

Replace the discard at `receipt_persistence.rs:185` with a durable observer
outbox. When a paired observer runtime is installed, the receipt-store append
transaction also inserts a due `pending_observation` attempt-zero row. The
kernel-owned `ReceiptStore` contract exposes this as one atomic append
capability; its default returns `Unsupported`, and installation rejects a
backend that cannot provide it. The observer still runs only after commit and
outside the receipt-store lock.

Both inline routing and F69 claim work through
`chio_settle::SettlementOutcomeStore`. A claim atomically increments a checked
row version and writes a fresh lease owner, opaque token, and deadline.
Completion requires an unexpired exact `(receipt_id, row_version, lease_token)`
match. Accepted or legitimately skipped work deletes the claimed row; retryable
work increments the bounded attempt count, clears the lease, and writes a checked
millisecond visibility deadline; permanent or exhausted work atomically replaces
the row with one canonical dead letter. A stale claimant affects zero rows and
returns `Conflict`. A crash before claim or after the hook but before completion
leaves recoverable work, and startup plus the periodic driver drain expired
leases. Receipt scans are not a recovery substitute.

Only denied, non-economic, and authorized zero-charge receipts are legitimate
skips. Invalid signatures or action hashes, untrusted receipt signers, malformed
positive financial metadata, deterministic binding failures, and unsupported
economic forms are typed permanent outcomes. Transient rail/RPC failures are
typed retryable. Persisted reasons use a closed code plus a fixed SHA-256 detail
digest; raw error strings are neither persisted nor used as metric labels.

The `settle_attempts` schema and object-safe lease/CAS interface are normative
in `docs/superpowers/plans/2026-07-10-ws1-first-light-phase1.md`. The same
`Immediate` transaction owns claim, retry update, and retry-to-dead-letter
transitions. `RetryPolicy` is validated at installation and at the store
boundary, all time arithmetic is checked in milliseconds, and a dead letter is
terminal until an explicit operator action.

Every unresolved registered-observer outcome, including failed cleanup or
persistence, emits one bounded warning and increments the shared
`CHIO_SETTLEMENT_UNRESOLVED_TOTAL` family exactly once per routing invocation.
The family is declared in `chio-metrics-spec` and exported through the existing
kernel metrics runtime; no shadow counter is introduced. Even before F69 ships,
F68 therefore provides both durable attempt-zero work and loud terminal
classification rather than a post-commit crash gap.

### F69: production settlement driver seam

Specify the intended driver so `chio settle status` reports over tables real code
writes. Ship a reference `OpsSettlementHook` in `chio-settle` implementing
`SettlementHook` over `chio-settle/ops.rs`, and a `SettlementRuntime` task that:

- drains `settle_attempts WHERE next_visible_at_ms <= now` on a tick,
- claims a bounded batch with versioned leases, loads the bound receipts,
  re-invokes the hook, and completes through the claimed-outcome CAS,
- on `Accepted` verifies that the hook atomically created or found the idempotent
  `settlement_reconciliations` work row before deleting observer work; a separate
  credit worker may mint `iou_envelope` only from a canonical obligation whose
  pre-action intent explicitly elected a credit facility, and
- is wired into the CLI runtime behind a config flag `settlement.driver = { none, ops }`
  (default `none`, so nothing changes until an operator opts in).

Add separate end-to-end cases for paid settlement retry/dead-letter and explicitly
authorized credit obligation-to-IOU flow against a real kernel. A captured or prepaid
receipt never mints an IOU for the same value. Until the driver ships, correct the two
misleading docs: `construction.rs:483`
and `hook.rs:7-9` must say routing to retry/dead-letter is wired only when a driver is
installed, not unconditionally. This finding is not on the request-serving path
(`production_path=false`); this RFC specifies the seam and the doc fix, and the driver
implementation is a follow-up tracked in the wave-3 program.

### F72: fail-closed currency mismatch in BudgetTree

Add typed mismatch and overflow denials. In `budget_hierarchy.rs`:

```rust
CurrencyMismatch {
    node: BudgetNodeId,
    node_currency: Option<String>,
    current_currency: Option<String>,
    draft_currency: Option<String>,
},
ArithmeticOverflow {
    node: BudgetNodeId,
    dimension: String,
},
```

Replace the skip at `budget_hierarchy.rs:613-637`:

```rust
if let Some(cap) = limits.max_spend_units {
    let comparable = limits.currency.as_deref().is_some_and(|currency| {
        draft.currency.as_deref() == Some(currency)
            && match current_spend.current.currency.as_deref() {
                Some(current) => current == currency,
                None => current_spend.current.spend_units == 0,
            }
    });
    if !comparable {
        offender = Some((
            idx,
            BudgetDenyReason::CurrencyMismatch {
                node: node_id.clone(),
                node_currency: limits.currency.clone(),
                current_currency: current_spend.current.currency.clone(),
                draft_currency: draft.currency.clone(),
            },
        ));
        continue;
    }
    let Some(projected_spend) = current_spend
        .current
        .spend_units
        .checked_add(draft.spend_units)
    else {
        offender = Some((
            idx,
            BudgetDenyReason::ArithmeticOverflow {
                node: node_id.clone(),
                dimension: "spend".to_string(),
            },
        ));
        continue;
    };
}
```

This realizes ADR-0006's stated fail-closed stance on cross-currency comparison at the
tree layer (the ADR notes the kernel per-invocation check already fails a USD-vs-EUR
mismatch; this closes the same gap in the hierarchy). The existing
`DimensionExceeded` branch compares `projected_spend` with `cap` only after these
checks. A present snapshot currency must match even when the current amount is zero.
An absent snapshot currency is valid only for a zero amount, which adopts the matched
draft currency for the projection.

### F73: durable SQLite EIP-3009 nonce store

Add `SqliteEip3009NonceStore` in `crates/platform/chio-store-sqlite` implementing the
existing `chio_settle::Eip3009NonceStore` trait (`payments.rs:317-344`) over:

```sql
CREATE TABLE IF NOT EXISTS eip3009_nonces (
    from_address TEXT NOT NULL,
    nonce_key    TEXT NOT NULL,
    retain_until INTEGER NOT NULL,
    PRIMARY KEY (from_address, nonce_key)
);
CREATE INDEX IF NOT EXISTS idx_eip3009_nonces_retain_until ON eip3009_nonces(retain_until);
```

`record_if_fresh` lowercases key components exactly as
`canonicalize_nonce_key_component` (`payments.rs:357-364`) does. It does NOT prune: the
trait contract (`payments.rs:311-316`) makes `gc_expired` the sole entry point that
drops entries so replay decisions stay decoupled from the wall clock, and
`record_if_fresh` has no `now` argument to prune against. `gc_expired` is a
`DELETE ... WHERE retain_until < ?`.

Duplicate detection, the hard-cap check, and insertion run in one
`TransactionBehavior::Immediate` transaction: read the canonical key first and
return `Replayed` if present; otherwise count retained rows, fail closed when the
count is at `DEFAULT_MAX_EIP3009_NONCE_ENTRIES` (65,536), and insert only below
the cap. The configured maximum is persisted and validated as nonzero; concurrent
writers cannot both pass the last-slot check. An advisory `len()` high-water
probe may call `gc_expired(now)` before insertion on the verifier's now-bearing
path, and a periodic scheduler also runs GC, but neither is the capacity safety
boundary. Pruning stays on explicit GC and never occurs inside insertion. The
lane's future wiring is gated on this durable store, and the stale
`payments.rs:366-371` doc is corrected to name it.

### F74: BudgetEnforcer durability caveat + snapshot seam

`BudgetEnforcer` has no production consumer (the sole external `chio-metering` user,
`crates/guards/chio-data-guards/src/warehouse_cost_guard.rs:55`, imports only
`CostDimension`), so the minimum viable fix is a loud caveat plus an explicit
snapshot/restore seam:

```rust
/// WARNING: counters are process-local and reset to zero on restart. This type does
/// NOT persist cumulative spend; a restart re-opens the full budget. For durable
/// enforcement use the kernel `BudgetStore` (crates/kernel/chio-kernel/src/budget_store.rs).
/// Callers requiring cross-restart continuity MUST snapshot and restore explicitly.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetEnforcerSnapshot {
    pub total_spent: u64,
    pub session_spent: HashMap<String, u64>,
    pub agent_spent: HashMap<String, u64>,
    pub tool_spent: HashMap<String, u64>,
}

impl BudgetEnforcer {
    #[must_use]
    pub fn snapshot(&self) -> BudgetEnforcerSnapshot { /* clone counters */ }

    #[must_use]
    pub fn from_snapshot(policy: BudgetPolicy, snapshot: BudgetEnforcerSnapshot) -> Self { /* seed */ }
}
```

The rustdoc caveat is the trap-defusing one-liner; the snapshot seam lets any future
adopter persist and restore counters instead of silently losing them.

### Error taxonomy (typed, fail-closed)

- `BudgetStoreError::Invariant` (existing) carries the unsupported-store and
  compare-and-set-mismatch cases for the payment journal and sweeper; a mismatched
  `advance_payment_journal` expected-state is a `Conflict`-shaped invariant, aborting
  fail-closed.
- `DeadLetterStoreError::{ Backend, Conflict }` (existing,
  `dead_letters.rs:42-50`) already covers dead-letter insert failures; the routing
  consumer maps a `Conflict` to a warn+metric, never a silent drop.
- `PaymentError::Unavailable` (existing, `payment.rs:192`) is the fail-closed return
  from the defaulted `settlement_state`, forcing a `ReconcileFailed` incident rather
  than a wrong close.
- `BudgetDenyReason::CurrencyMismatch` (new) is the fail-closed tree outcome.
- `SettlementError::InvalidBinding` (existing) remains the EIP-3009 replay/capacity
  return; the durable store preserves those semantics.

### Crates, dirs, LOC, CI tier

- `crates/platform/chio-store-sqlite`: `payment_journal` + `settle_attempts` +
  `eip3009_nonces`
  DDL and methods, `SqliteEip3009NonceStore`, `HoldDisposition::Expired`,
  recovery-gated sweeper queries, dead-letter/attempt wiring. ~520 LOC + ~360
  LOC tests.
- `crates/kernel/chio-kernel`: `PaymentJournalRecord`/`PaymentJournalState`, journal
  and sweeper trait methods, `validation.rs` wiring, claimed-observer routing and
  lease/CAS completion, `BudgetMutationKind::ExpireHold`, config, boot hooks. ~430 LOC
  + ~320 LOC tests.
- `crates/economy/chio-metering`: `BudgetDenyReason::CurrencyMismatch`, evaluate change,
  `BudgetEnforcerSnapshot`. ~90 LOC + ~120 LOC tests.
- `crates/economy/chio-settle`: `PaymentAdapter` doc/`settlement_state` amendment lives
  in the kernel crate; `OpsSettlementHook` + `SettlementRuntime` driver seam. ~260 LOC
  + ~200 LOC tests.
- `crates/products/chio-cli`: `chio budget holds list/review`, `settlement.driver`
  flag. ~120 LOC + ~90 LOC tests.
- `crates/observability/chio-metrics-spec`: descriptor declarations for
  `CHIO_SETTLEMENT_UNRESOLVED_TOTAL`, `CHIO_BUDGET_OPEN_HOLDS`, and
  `CHIO_BUDGET_HOLDS_EXPIRED_TOTAL`. ~25 LOC.
- No new crate. Unit and property tests run on the PR gate (well under a minute).
  Crash/kill-injection soak (SIGKILL between authorize and receipt commit; between
  authorize_budget_hold and reconcile) runs nightly in the load-chaos program, budgeted
  at roughly 15-25 minutes. The full power-loss and multi-restart budget-continuity
  simulation runs weekly.

## Wire, schema, and receipt impact

- Signed receipt payloads are unchanged. Settlement status stays the advisory
  `FinancialReceiptMetadata::settlement_status` field ADR-0006's no-refund model
  already defines; the journal and reconciliation never rewrite a signed receipt.
- New non-audit SQLite tables: `payment_journal`, `settle_attempts`, and
  `eip3009_nonces`, all created idempotently at store open (`CREATE TABLE IF NOT
  EXISTS`). The existing `settle_dead_letters`, `iou_envelope`, and
  `settlement_reconciliations` tables are now populated by production code
  (F68/F69), not only tests.
- `PaymentJournalRecord`, `DeadLetterRecord` (existing, schema `chio.settle.dead-letter.v2`),
  and any reconciliation report serialize as RFC 8785 canonical JSON, consistent with
  the canonical-JSON `parameter_hash` and dead-letter row bytes already in use.
- `BudgetDenyReason` gains a `CurrencyMismatch` variant. It is config-as-data JSON
  (serde `tag = "reason"`, snake_case); additive, older readers that do not expect it
  fail closed on the deny rather than silently allowing.
- New `BudgetMutationKind::ExpireHold` (`"expire_hold"`) and `HoldDisposition::Expired`
  (`"expired"`) are additive string enum values in the durable budget log.

## Migration and compatibility

- Backward compatible: every new table and enum value is additive; older binaries
  ignore the tables and treat unknown mutation kinds/dispositions as opaque. Newer
  binaries create the tables on open.
- There are no historical journal, attempt, or nonce rows. Existing holds lack a
  trustworthy `request_id` and terminal recovery proof, so they are never
  auto-expired merely because they predate the migration. They appear in the
  review command and require an explicit reconciled resolution.
- Staged rollout. The payment journal is the money-path specialization of RFC-0003's
  `DispatchIntentJournalMode`; enable it with the `Monetary` class first (highest
  consequence), gated behind the same config. The F68 routing consumer ships enabled
  (it only adds logging, metrics, and dead-letter rows). The F69 driver ships behind
  `settlement.driver = none` by default. The durable EIP-3009 store becomes the wired
  default only once the lane is exercised.
- Operator-visible behavior changes to document in release notes: newly surfaced
  dead-letter rows and `ReconcileFailed` incidents are "recovery working", not
  "new fault"; an old hold without terminal recovery remains frozen and visible
  rather than being released on age alone.

## Test and verification plan

- Unit: journal insert collision on a reused `request_id` fails closed;
  `advance_payment_journal` with a wrong `expected` state returns `Conflict`;
  final prepayment transitions directly to `Settled` and cannot enter the
  `Authorized -> release` recovery branch; capture/release reject `Pending`, `Failed`,
  and action-incompatible terminal statuses; `release_recovered_hold` rejects a
  nonterminal journal, moved-funds resolution, missing/stale recovery digest, open or
  outcome-unknown RFC-0003 intent, and wrong hold version and is idempotent by event id;
  `close_payment_journal` is idempotent;
  `settlement_state` default returns `Unavailable`.
- Property: for a random interleaving of authorize/capture/release/crash, after boot
  reconcile every `request_id` resolves to exactly one of `{ Closed with attested
  receipt, Closed with reconciliation receipt, ReconcileFailed incident }`, never a
  silent non-terminal row and never a double capture (idempotency witness).
- Property (F72): for random node/draft currency pairs, `BudgetTree::evaluate` never
  returns `Allow` when a node has `max_spend_units` and the draft currency is absent or
  differs.
- Loom: model the settlement routing consumer with concurrent `Observed`/`HookFailed`
  and a driver drain, asserting no lost attempt row and no double dead-letter, reusing
  the dead-letter idempotency (`dead_letters.rs` byte-identical replay).
- Concurrency (F73): with a file-backed database at cap minus one, two distinct
  concurrent inserts yield exactly one `Fresh` result and one fail-closed capacity
  error, leaving the retained count at the configured cap. Replaying an existing key
  at the cap still returns `Replayed` rather than a capacity error and never changes
  the count.
- Crash/chaos (load-chaos program):
  `payment_journal_crash_reconciles_every_mode` SIGKILLs after reversible-hold
  authorize, final-prepayment authorize, and capture. Restart proves final
  prepayment is never released, held state replays only its durable action, and
  every killed request ends attested-or-incident. F71's proof SIGKILLs between
  `authorize_budget_hold` and reconcile and asserts that the hold remains frozen
  while its journal/intent is nonterminal, then expires exactly once only after
  the coordinator proves and applies a terminal no-movement resolution.
- Soak: sustained priced load with periodic kills; assert every old open hold is
  either terminally proven no-movement and expired or paired with a named
  nonterminal incident, `settle_attempts` drains, and no journal row is silently
  abandoned.
- Formal-methods tie-in: the money-path invariant `moved_funds(request_id) ->
  eventually(attested_receipt XOR reconciliation_incident)` is stated as a liveness
  predicate in the formal-methods plan; the property and crash tests are its executable
  witnesses. It composes with RFC-0003's `receipt XOR open_intent` safety predicate.

## Acceptance criteria

- Killing the kernel between rail-money-movement and receipt commit and restarting
  yields, for every in-flight priced request, exactly one durable terminal outcome: an
  attested receipt, a reconciliation receipt, or a `ReconcileFailed` operator incident
  naming the `rail` and `authorization_id`. Never a charge with no record.
- After a clean run's reconcile, `list_incomplete_payment_journal` returns empty
  and every remaining open hold has a named, nonterminal incident.
- An old open hold is swept to `disposition='expired'` only after a matching
  terminal no-movement resolution. The same transaction inserts the digest-keyed
  mutation event, appends `expire_hold`, and drops `total_cost_exposed` by exactly
  the released remainder. Age alone, `ReconcileFailed`, or unknown rail state
  never releases capacity.
- A settlement hook returning `Retryable`/`Permanent`/error for a money-bearing receipt
  produces a `settle_attempts` or `settle_dead_letters` row plus a warn and a metric;
  `chio settle status` reports it. Nothing is dropped at `receipt_persistence.rs:185`.
- `BudgetTree::evaluate` returns `Deny(CurrencyMismatch)` for a spend-capped node whose
  currency is absent or differs from the draft; no `Allow` with unlimited spend.
- The EIP-3009 nonce store survives a restart (a previously recorded `(from,
  nonce)` reads `Replayed`), never exceeds its configured hard cap under
  concurrent insertion, and reopens capacity only through explicit GC of expired
  rows.
- `BudgetEnforcer` carries the durability caveat and a working `snapshot`/`from_snapshot`
  round-trip.

## Risks and alternatives

- Added latency on priced calls: one extra durable write before authorize and one
  compare-and-set per state transition. Each rides the existing budget-store `Immediate`
  transaction and is dwarfed by the external rail call; the `Monetary`-class gate bounds
  the cost, and the soak measures it before the journal becomes default.
- Idempotency is a contract, not enforcement: the amended `PaymentAdapter` doc requires
  idempotent capture/release, but an adapter that violates it could double-charge on
  replay. Mitigation: reconciliation prefers the side-effect-free `settlement_state`
  query and only replays capture/release for adapters that declare idempotency; the
  in-tree final-prepayment adapters transition directly to `Settled` and never
  rely on a local no-op capture or release for recovery.
- Sweeper aggressiveness: a short horizon can create noisy investigations but
  cannot reclaim a live hold. The sweep requires a terminal no-movement recovery
  proof and atomically excludes every nonterminal journal; the `3600s`
  default controls alert timing only.
- Alternative considered and rejected: putting the payment journal in the receipt-store
  database beside RFC-0003's `chio_dispatch_intents`. Rejected because the earliest
  durable pre-execution write is the budget hold, and co-locating lets the hold and
  journal commit in one transaction; RFC-0003's generic intent remains the complementary
  `receipt XOR open_intent` record.
- Alternative considered and rejected: reversing the budget charge automatically on
  settlement failure. Rejected because ADR-0006's no-refund model makes
  `total_cost_charged` monotone; the journal records and reconciles the rail movement
  without inventing a refund the kernel does not own.
- Alternative considered and rejected: a background thread that blind-retries dropped
  settlement outcomes without a persisted attempt counter. Rejected because it cannot
  survive restart and cannot bound retries; the `settle_attempts` table plus
  `classify_attempt` gives a durable, bounded envelope.

## Rollout and sequencing

1. RFC-0003 lands first: it provides the boot recovery orchestration, the operator
   incident sink, and the `rail`/`rail_authorization_id` substrate plus the
   `MonetaryReconciled` resolution that this RFC's reconciler satisfies.
2. F72 and the F68 routing consumer land next: both are small, self-contained,
   fail-closed corrections with no dependency on the journal.
3. The payment journal (F70) + hold sweeper (F71) land together, gated behind the
   `Monetary` journal mode, promoted to default after the nightly kill-injection soak is
   green.
4. The durable EIP-3009 store (F73) and the `BudgetEnforcer` caveat/snapshot (F74) land
   as independent hardening; the EIP-3009 store becomes the wired default only when the
   lane is exercised.
5. The F69 production driver (`OpsSettlementHook` + `SettlementRuntime`) is the
   final step, behind `settlement.driver = ops`, turning eligible F68 work into
   reconciliation rows and separately authorized credit obligations into bound
   IOU envelopes.

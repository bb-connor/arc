# PACT Agent Economy: Technical Design

Status: Phase 1 shipped in v2.0; Phases 2-4 planned
Authors: Engineering
Date: 2026-03-21 (updated 2026-03-23)

---

## 1. Overview

PACT's existing architecture -- capability tokens, delegation chains, invocation budgets, and signed receipts -- is a programmable spending authorization system. The protocol already enforces who can do what, how many times, with cryptographic proof of every decision. This document describes how to extend that architecture into a full economic substrate for the agent economy.

Three observations anchor the design:

1. **The capability token is a spending authorization.** A `CapabilityToken` already binds an issuer, a subject, a scope of permitted actions, and a time window. Adding a monetary dimension to `ToolGrant` turns it into a pre-authorized spending limit.

2. **The delegation chain is a cost-responsibility chain.** Each `DelegationLink` records who delegated what to whom, with `Attenuation` narrowing scope at each hop. Budget attenuation through delegation creates a tree of cost responsibility rooted at the original authorizer.

3. **The receipt log is a billing ledger.** Every `PactReceipt` is a signed, tamper-evident record of a decision. The existing `metadata: Option<serde_json::Value>` field is the natural insertion point for structured financial data. Receipts are already persisted in `SqliteReceiptStore` with indexed queries by capability, tool, and timestamp.

The strategy is not to bolt a payment system onto PACT. It is to recognize that PACT is already 80% of a payment authorization system and close the remaining gaps with minimal, backward-compatible extensions.

---

## 2. Current Architecture (What Exists)

### 2.1 Invocation-Count Budgets

`ToolGrant` in `crates/pact-core/src/capability.rs` carries an optional invocation cap:

```rust
pub struct ToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<Operation>,
    pub constraints: Vec<Constraint>,
    pub max_invocations: Option<u32>,
}
```

The kernel enforces this via `BudgetStore::try_increment` in `crates/pact-kernel/src/budget_store.rs`. Each budget record is keyed by `(capability_id, grant_index)`:

```rust
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
}
```

### 2.2 BudgetStore Trait

The `BudgetStore` trait (`crates/pact-kernel/src/budget_store.rs`) has two methods:

```rust
pub trait BudgetStore: Send {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;
}
```

Two implementations exist: `InMemoryBudgetStore` (HashMap-backed, for testing) and `SqliteBudgetStore` (WAL-mode SQLite with `PRAGMA synchronous = FULL`).

### 2.3 HA Replication

`SqliteBudgetStore` supports cross-node replication via a monotonic `seq` column and a `budget_replication_meta` table tracking `next_seq`. The `upsert_usage` method applies remote deltas with last-writer-wins conflict resolution:

```sql
ON CONFLICT(capability_id, grant_index) DO UPDATE SET
    invocation_count = CASE
        WHEN excluded.seq > capability_grant_budgets.seq
            THEN excluded.invocation_count
        ELSE MAX(capability_grant_budgets.invocation_count, excluded.invocation_count)
    END
```

Delta queries via `list_usages_after(limit, after_seq)` enable efficient replication polling.

### 2.4 Budget Enforcement in the Kernel

`PactKernel::check_and_increment_budget` in `crates/pact-kernel/src/lib.rs` iterates matching grants that arrive pre-sorted by specificity from `resolve_matching_grants` upstream. If all matching grants with `max_invocations` are exhausted, the method returns `KernelError::BudgetExhausted`. The calling code then passes the error message (e.g. "invocation budget exhausted for capability ...") to `build_deny_response`, which produces a signed `Decision::Deny` receipt with guard `"kernel"` and the budget-exhaustion error as the reason string.

### 2.5 Delegation Attenuation

`Attenuation::ReduceBudget` in `crates/pact-core/src/capability.rs` already supports narrowing invocation counts during delegation:

```rust
pub enum Attenuation {
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    // ...
}
```

`ToolGrant::is_subset_of` enforces that a child grant's `max_invocations` never exceeds the parent's.

### 2.6 Receipt Metadata

`PactReceipt` and `PactReceiptBody` in `crates/pact-core/src/receipt.rs` carry:

```rust
pub metadata: Option<serde_json::Value>,
```

This field is signed as part of the receipt body and is available for structured financial data without schema changes to the receipt envelope.

### 2.7 Analytics Join Gap

The current persisted receipt shape is sufficient for an audit trail, but not
yet ideal for agent-level economics or reputation analytics. `PactReceipt`
stores `capability_id`, `tool_server`, and `tool_name`, but it does not record
the matched `grant_index` or the capability subject directly. That creates two
practical gaps:

1. Agent-centric queries need a local capability lineage index keyed by
   `capability_id` so receipts can be joined to `CapabilityToken.subject`,
   issuer, and delegation metadata without replaying issuance logs.
2. Per-grant metrics need a deterministic join path from receipt to the grant
   that was charged, either by persisting the matched `grant_index` on the
   receipt or by storing an equivalent local attribution record.

This is a storage/indexing gap, not a protocol-model gap. The roadmap should
land this analytics substrate before relying on receipt data for billing
dashboards, budget-discipline scoring, or agent reputation.

---

## 3. Economic Extensions (What to Build)

### 3.1 Monetary Budget Type

**Goal:** Extend `ToolGrant` so that in addition to invocation-count limits, a grant can carry a monetary spending cap.

#### 3.1.1 New Types in `pact-core`

Add to `crates/pact-core/src/capability.rs`:

```rust
/// A monetary amount with currency denomination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryAmount {
    /// Amount in the currency's smallest unit (e.g. cents for USD,
    /// wei for ETH). Using u64 avoids floating-point precision issues.
    pub units: u64,
    /// ISO 4217 currency code or chain-specific token identifier.
    /// Examples: "USD", "EUR", "USDC", "ETH".
    pub currency: String,
}
```

Extend `ToolGrant`:

```rust
pub struct ToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<Operation>,
    pub constraints: Vec<Constraint>,
    pub max_invocations: Option<u32>,

    // --- New fields (all optional, backward-compatible via serde defaults) ---

    /// Maximum cost per single invocation. The kernel rejects tool server
    /// responses that report a cost exceeding this cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,

    /// Maximum aggregate cost across all invocations under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
}
```

All new fields use `#[serde(default, skip_serializing_if = "Option::is_none")]` so existing tokens deserialize without error. However, `ToolGrant` currently has `#[serde(deny_unknown_fields)]` (line 162 of `capability.rs`), which means old kernels will reject tokens containing the new fields. This must be addressed before the new fields ship. Options: (a) remove `deny_unknown_fields` in a prior release so that deployed kernels learn to tolerate unknown fields before new fields appear, or (b) gate the new fields behind a protocol version and add a version negotiation step. Either way, a versioning and migration strategy is required -- this is a backward-compatibility-breaking change if not sequenced carefully.

#### 3.1.2 Attenuation for Cost Budgets

Add a new `Attenuation` variant in `crates/pact-core/src/capability.rs`:

```rust
pub enum Attenuation {
    // ... existing variants ...

    /// The per-invocation cost cap was tightened.
    ReduceCostPerInvocation {
        server_id: String,
        tool_name: String,
        max_cost_per_invocation: MonetaryAmount,
    },

    /// The total cost budget was reduced.
    ReduceTotalCost {
        server_id: String,
        tool_name: String,
        max_total_cost: MonetaryAmount,
    },
}
```

`ToolGrant::is_subset_of` must be extended: if the parent has `max_total_cost`, the child must also have one with `units <= parent.units` in the same currency. Same logic for `max_cost_per_invocation`.

#### 3.1.3 Budget Store Extensions

Extend `BudgetUsageRecord` in `crates/pact-kernel/src/budget_store.rs`:

```rust
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,

    // --- New fields ---

    /// Cumulative cost charged against this grant, in the grant's currency
    /// smallest units.
    pub cost_units_charged: u64,
}
```

Add a new method to `BudgetStore`:

```rust
pub trait BudgetStore: Send {
    fn try_increment(/* ... existing ... */) -> Result<bool, BudgetStoreError>;

    /// Attempt to charge a monetary cost against a grant's budget.
    /// Returns Ok(true) if the charge was accepted, Ok(false) if the
    /// budget would be exceeded. The invocation count is also incremented.
    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    fn list_usages(/* ... existing ... */) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;
}
```

SQLite schema change for `capability_grant_budgets`:

```sql
ALTER TABLE capability_grant_budgets
    ADD COLUMN cost_units_charged INTEGER NOT NULL DEFAULT 0;
```

The `SqliteBudgetStore::try_charge_cost` implementation mirrors `try_increment` but additionally checks `cost_units_charged + cost_units <= max_total_cost_units` within the same IMMEDIATE transaction.

Replication: the existing seq-based delta protocol extends naturally. `upsert_usage` conflict resolution uses the same seq-wins strategy for `cost_units_charged`:

```sql
cost_units_charged = CASE
    WHEN excluded.seq > capability_grant_budgets.seq
        THEN excluded.cost_units_charged
    ELSE MAX(capability_grant_budgets.cost_units_charged, excluded.cost_units_charged)
END
```

### 3.2 Cost Reporting

#### 3.2.1 Tool Server Cost Response

Tool servers must be able to report the actual cost of an invocation. Extend the `ToolServerConnection` trait in `crates/pact-kernel/src/lib.rs`:

```rust
/// Cost reported by a tool server after invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationCost {
    /// Cost in the currency's smallest units.
    pub units: u64,
    /// Currency code (must match the grant's currency).
    pub currency: String,
    /// Tool-server-provided cost breakdown (opaque to the kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<serde_json::Value>,
}
```

The existing `invoke` method on `ToolServerConnection` returns `Result<serde_json::Value, KernelError>`. Rather than change its signature (which would break all existing implementations), introduce a parallel method:

```rust
pub trait ToolServerConnection: Send + Sync {
    // ... existing methods ...

    /// Invoke a tool and return the result along with an optional cost report.
    /// Default implementation delegates to `invoke` with no cost.
    fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, nested_flow_bridge)?;
        Ok((value, None))
    }
}
```

#### 3.2.2 Kernel Cost Verification

The kernel must preserve a simple invariant: **receipts describe what actually
happened**. A tool call that executed successfully may not be rewritten into a
deny just because payment capture failed afterward.

After receiving a cost report, the kernel in `evaluate_tool_call_with_session_roots`:

1. Verifies currency matches the grant's `max_cost_per_invocation.currency`.
2. Rejects the response if `cost.units > grant.max_cost_per_invocation.units`.
3. Finalizes the budget charge against the actual cost.
4. If settlement uses a pre-authorized hold, captures only the actual cost.
5. If post-execution settlement cannot be completed synchronously, records
   `pending` or `failed` settlement state in receipt metadata and emits a
   reconciliation task. The tool outcome remains `Decision::Allow`.

If the tool server does not report cost (returns `None`) and the grant has a `max_total_cost`, the kernel charges `max_cost_per_invocation.units` as the assumed worst-case cost. This is fail-closed: unlabeled invocations debit the maximum.

### 3.3 Spending Delegation

#### 3.3.1 Parent-Child Budget Suballocation

When an agent delegates a capability with `max_total_cost`, the child's budget is carved out of the parent's remaining balance. This requires the kernel to:

1. Read the parent grant's `cost_units_charged` from the budget store.
2. Verify the child's `max_total_cost.units <= parent.max_total_cost.units - parent.cost_units_charged`.
3. Pre-reserve the child's budget by charging the parent's budget store immediately.

If the child underspends, the parent can reclaim unused budget only after the child capability expires or is revoked. This avoids double-spending during the child's lifetime.

#### 3.3.2 Delegation Chain Cost Attribution

The `DelegationLink` already carries `delegator` and `delegatee` public keys and a timestamp. Cost attribution follows the chain: the root budget holder (the first issuer with no inbound delegation) is the ultimate payer. Each intermediate delegator is a cost center.

For reconciliation, the receipt log (section 3.5) records the delegation depth and root budget holder, enabling per-level cost aggregation.

### 3.4 Velocity Controls

#### 3.4.1 New Constraint Variants

Add to `Constraint` in `crates/pact-core/src/capability.rs`:

```rust
pub enum Constraint {
    // ... existing variants ...

    /// Maximum monetary spend per rolling time window.
    MaxSpendPerWindow {
        /// Maximum spend in currency smallest units.
        max_units: u64,
        /// Window duration in seconds.
        window_seconds: u64,
    },

    /// Maximum invocations per rolling time window.
    MaxInvocationsPerWindow {
        /// Maximum invocation count.
        max_count: u32,
        /// Window duration in seconds.
        window_seconds: u64,
    },

    /// Invocations exceeding this cost threshold require out-of-band approval
    /// before the kernel forwards to the tool server.
    RequireApprovalAbove {
        /// Threshold in currency smallest units.
        threshold_units: u64,
    },
}
```

#### 3.4.2 Velocity Guard

Implement a new `Guard` in `crates/pact-kernel/src/lib.rs`:

```rust
pub struct VelocityGuard {
    /// Sliding-window counters keyed by (capability_id, grant_index).
    windows: HashMap<(String, u32), VelocityWindow>,
}

struct VelocityWindow {
    events: VecDeque<(u64, u64)>,  // (timestamp_secs, cost_units)
}
```

The guard inspects `MaxSpendPerWindow` and `MaxInvocationsPerWindow` constraints on matching grants and denies the request if the sliding window would be exceeded. This is evaluated in the guard pipeline before the tool server is called, so no cost is incurred on denial.

#### 3.4.3 Human-in-the-Loop Approval

`RequireApprovalAbove` triggers a `Decision::Deny` with a structured denial reason containing an approval request token. The orchestrating system can present this to a human, obtain approval (a signed attestation), and retry with the approval attached. This keeps the kernel stateless with respect to approval workflows -- the approval is just another signed input.

### 3.5 Receipt Financial Instrumentation

#### 3.5.1 Structured Financial Metadata

Define a structured schema for the receipt `metadata` field. This does not change the `PactReceipt` type -- it specifies what goes into the existing `Option<serde_json::Value>`:

```rust
/// Financial metadata populated in PactReceipt.metadata when a grant
/// carries monetary budget fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialReceiptMetadata {
    /// Which grant matched this invocation inside the capability scope.
    pub grant_index: u32,
    /// Cost charged for this invocation, in currency smallest units.
    pub cost_charged: u64,
    /// Currency code.
    pub currency: String,
    /// Budget remaining after this invocation.
    pub budget_remaining: u64,
    /// Total budget for this grant.
    pub budget_total: u64,
    /// Delegation depth (0 = root capability, 1 = first delegate, etc.).
    pub delegation_depth: u32,
    /// Public key (hex) of the root budget holder.
    pub root_budget_holder: String,
    /// Payment or authorization reference on the external rail, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    /// Settlement state as observed by the kernel when the receipt was signed.
    /// Typical values: "not_applicable", "authorized", "captured",
    /// "settled", "pending", "failed".
    pub settlement_status: String,
    /// Optional cost breakdown from the tool server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
}
```

This struct is serialized into `receipt.metadata` as a nested object under the key `"financial"`:

```json
{
  "financial": {
    "grant_index": 0,
    "cost_charged": 1500,
    "currency": "USD",
    "budget_remaining": 8500,
    "budget_total": 10000,
    "delegation_depth": 1,
    "root_budget_holder": "a1b2c3...",
    "payment_reference": "pi_123",
    "settlement_status": "captured"
  }
}
```

The kernel populates this after the budget charge is accepted and the payment
rail reaches a known local state (`captured`, `pending`, `failed`, etc.).
Denied invocations may still include structured financial metadata when denial
occurred before execution due to budget exhaustion or payment pre-authorization
failure.

#### 3.5.2 Receipt Store Indexing

Add columns to `pact_tool_receipts` in `crates/pact-kernel/src/receipt_store.rs`:

```sql
ALTER TABLE pact_tool_receipts
    ADD COLUMN cost_charged INTEGER;
ALTER TABLE pact_tool_receipts
    ADD COLUMN cost_currency TEXT;

CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_cost
    ON pact_tool_receipts(cost_currency, cost_charged);
```

The `SqliteReceiptStore::append_pact_receipt` method extracts `financial.cost_charged` and `financial.currency` from the receipt metadata at insert time. This enables efficient billing queries without full-JSON scanning.

### 3.6 Payment Rail Integration

#### 3.6.1 PaymentAdapter Trait

Add a new module `crates/pact-kernel/src/payment.rs`:

```rust
/// Result of a payment authorization or settlement action.
#[derive(Debug, Clone)]
pub struct PaymentAuthorization {
    /// Payment rail's authorization or hold identifier.
    pub authorization_id: String,
    /// Whether the rail already considers the funds settled.
    pub settled: bool,
    /// Rail-specific metadata (idempotency keys, quote IDs, expiry, etc.).
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PaymentResult {
    /// Payment rail's transaction identifier, if a capture or settlement occurred.
    pub transaction_id: String,
    /// Local settlement state known to the kernel at the time of receipt signing.
    pub settlement_status: SettlementStatus,
    /// Rail-specific metadata (idempotency keys, network confirmations, etc.).
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementStatus {
    Authorized,
    Captured,
    Settled,
    Pending,
    Failed,
    Released,
    Refunded,
}

/// Trait for executing payments against an external rail.
///
/// PACT authorizes. The payment rail executes. Separation of concerns:
/// the kernel never holds funds or manages wallets.
pub trait PaymentAdapter: Send + Sync {
    /// Authorize or prepay up to `amount_units` before the tool executes.
    ///
    /// For prepaid rails (for example x402), this may fully settle the amount
    /// and return `settled = true`. For card-style rails, this creates a hold.
    fn authorize(
        &self,
        amount_units: u64,
        currency: &str,
        payer: &str,
        payee: &str,
        reference: &str,
    ) -> Result<PaymentAuthorization, PaymentError>;

    /// Finalize payment for the actual cost after tool execution.
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Release an unused authorization hold.
    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Refund a previously executed payment.
    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("payment declined: {0}")]
    Declined(String),

    #[error("insufficient funds")]
    InsufficientFunds,

    #[error("payment rail unavailable: {0}")]
    Unavailable(String),

    #[error("payment rail error: {0}")]
    RailError(String),
}
```

#### 3.6.2 Planned Implementations

| Adapter | Rail | Settlement | Notes |
|---------|------|-----------|-------|
| `StripePaymentAdapter` | Stripe Connected Accounts / Multi-Party Payments | Hold + capture | Uses payment intents with `transfer_data` for tool provider splits. Receipt ID maps to `idempotency_key`. |
| `X402PaymentAdapter` | x402 HTTP payment protocol | Prepaid per-request | HTTP 402 negotiation. The adapter settles before retry, so denial can still happen before execution. |
| `StablecoinPaymentAdapter` | USDC/USDT on EVM chains | Async (block confirmation) | On-chain transfer or hold model. Receipts may carry `pending` settlement state until confirmations land. |

#### 3.6.3 Integration Point

The `PaymentAdapter` is an optional dependency of `PactKernel`. When configured,
the kernel follows this rule set:

1. If the rail requires or supports pre-authorization, the kernel calls
   `authorize(...)` before invoking the tool. Authorization failure produces a
   truthful `Decision::Deny` receipt because the tool never executed.
2. The tool executes and reports the actual cost.
3. The kernel captures the actual amount, releases any unused hold, or records
   `pending` settlement state for async rails.
4. If settlement work fails after the tool already ran, the kernel still signs
   `Decision::Allow` and records the failed settlement state plus a recovery
   reference in `FinancialReceiptMetadata`. Reconciliation happens out-of-band.

```rust
pub struct PactKernel {
    // ... existing fields ...
    payment_adapter: Option<Box<dyn PaymentAdapter>>,
}
```

The payment adapter is never called on the hot path for grants without monetary budgets. The kernel checks `grant.max_total_cost.is_some() || grant.max_cost_per_invocation.is_some()` before invoking the adapter.

---

## 4. Products

The economic extensions enable four product surfaces. All are built on the same kernel and receipt infrastructure.

### 4.1 PACT Authorize

Agent spending authorization -- analogous to Brex or Ramp for autonomous agents.

- Enterprise issues capability tokens with `max_total_cost` to agent identities.
- Delegation creates sub-budgets for task-specific agents.
- Real-time budget enforcement at the kernel level (not post-hoc).
- Receipts provide a complete, signed audit trail of every charge.
- Velocity controls (`MaxSpendPerWindow`, `RequireApprovalAbove`) provide the same controls a CFO applies to corporate cards.

### 4.2 PACT Meter

Tool provider billing infrastructure.

- Tool servers report `ToolInvocationCost` on every invocation.
- Receipts accumulate per-tool-server cost data.
- `SqliteReceiptStore` cost indexes enable per-provider billing aggregation.
- Settlement queries: `SELECT tool_server, SUM(cost_charged) FROM pact_tool_receipts WHERE cost_currency = ? GROUP BY tool_server`.

### 4.3 PACT Settle

Cross-organization delegation chain settlement.

- When Org A delegates to Org B which delegates to Org C, the receipt chain records cost at each level.
- Settlement is a batch process that walks delegation chains in receipts, nets out cost attribution per org, and triggers capture, transfer, refund, or reconciliation actions against the connected payment rail.
- Dispute resolution: any party can verify any receipt's signature and delegation chain independently using only the kernel's public key.

### 4.4 PACT Watch

Spending analytics and anomaly detection.

- Real-time streaming of `FinancialReceiptMetadata` from the receipt log.
- Anomaly detection: spending velocity exceeding historical baselines, unusual tool-server cost reports, delegation depth anomalies, or growing `pending`/`failed` settlement backlogs.
- Webhook integration: notify when budget utilization exceeds configurable thresholds (50%, 80%, 95%).
- Dashboard queries against the indexed receipt store.

---

## 5. Architecture Diagram

```
                          Capability Token
                         (spending authorization)
                                |
                                v
  +-----------+         +----------------+         +----------------+
  |           |  req    |                |  invoke  |                |
  |  Agent    |-------->|  PACT Kernel   |--------->|  Tool Server   |
  | (spender) |         |  (authorizer)  |<---------|  (provider)    |
  |           |<--------|                |  result  |                |
  +-----------+  receipt|                |  + cost  +----------------+
                        +-------+--------+
                                |
                    +-----------+-----------+
                    |           |           |
                    v           v           v
              +---------+ +---------+ +-----------+
              | Budget  | | Receipt | | Payment   |
              | Store   | | Store   | | Adapter   |
              | (state) | | (audit) | | (settle)  |
              +---------+ +---------+ +-----------+
                    |           |           |
                    v           v           v
              +---------+ +---------+ +-----------+
              | HA      | | Merkle  | | Stripe /  |
              | Replica | | Log     | | x402 /    |
              |         | |         | | On-chain  |
              +---------+ +---------+ +-----------+
```

**Data flow for a monetized tool call:**

*Steps 1-3 reflect current kernel behavior. Steps 4-11 are proposed extensions.*

1. Agent presents `CapabilityToken` with `ToolGrant`. *(current)*
2. Kernel validates signature, time bounds, revocation, scope. *(current)*
3. Kernel calls `budget_store.try_increment(...)` to enforce invocation-count budgets, then evaluates guards. *(current)*
4. **[proposed]** Kernel evaluates `VelocityGuard` against velocity constraints.
5. **[proposed]** If needed, kernel obtains budget and payment pre-authorization using `max_cost_per_invocation` or a quoted amount.
6. Kernel forwards request to tool server. *(current, unchanged)*
7. **[proposed]** Tool server returns result + `ToolInvocationCost`.
8. **[proposed]** Kernel verifies reported cost against the per-invocation cap and finalizes the budget charge.
9. **[proposed]** If `PaymentAdapter` is configured, the kernel captures the actual amount, releases unused hold value, or records `pending` settlement state.
10. **[proposed]** Kernel signs `PactReceipt` with `FinancialReceiptMetadata`, including settlement status and payment reference.
11. Receipt is appended to `SqliteReceiptStore` and replicated. *(current for plain receipts; proposed financial metadata is new)*
12. **[proposed]** Failed or pending settlement follow-up is handled by a reconciliation queue, not by rewriting the receipt verdict.

---

## 6. Implementation Priorities

### Implementation Status

**Phase 1 features shipped in v2.0.** The economic primitives described in Phase 1 are implemented and available in the current codebase. Future-tense language in sections 3.1 through 3.5 describes what was designed and built; sections 3.6 (Payment Rail Integration) and Phases 2-4 remain planned.

Operational guides for v2.0 features:

- [MONETARY_BUDGETS_GUIDE.md](MONETARY_BUDGETS_GUIDE.md): configuring `max_cost_per_invocation`, `max_total_cost`, and financial receipt metadata
- [VELOCITY_GUARDS.md](VELOCITY_GUARDS.md): token-bucket rate limiting per grant
- [DPOP_INTEGRATION_GUIDE.md](DPOP_INTEGRATION_GUIDE.md): DPoP proof-of-possession setup and verification
- [RECEIPT_QUERY_API.md](RECEIPT_QUERY_API.md): `GET /v1/receipts/query` filters, pagination, and CLI usage

### Phase 1: Economic Primitives -- SHIPPED in v2.0

All Phase 1 deliverables shipped in v2.0:

- `MonetaryAmount` type in `crates/pact-core/src/capability.rs`.
- `max_cost_per_invocation` and `max_total_cost` fields on `ToolGrant`; `is_subset_of` enforces cost caps through delegation chains.
- `ReduceCostPerInvocation` and `ReduceTotalCost` attenuation variants.
- `total_cost_charged` in `BudgetUsageRecord` and `capability_grant_budgets` table.
- `try_charge_cost` on `BudgetStore` trait with atomic invocation-count + cost-units check in both `InMemoryBudgetStore` and `SqliteBudgetStore`.
- Replication delta support for cost fields (seq-based LWW merge).
- `ToolInvocationCost` struct and `invoke_with_cost` default method on `ToolServerConnection`.
- Kernel cost verification in `evaluate_tool_call_with_session_roots`.
- `FinancialReceiptMetadata` populated into receipt `metadata` field, including `grant_index`, `cost_charged`, `currency`, `budget_remaining`, `budget_total`, `delegation_depth`, `root_budget_holder`, and `settlement_status`.
- Receipt store cost indexing columns (`cost_charged`, `cost_currency`).
- `VelocityGuard` token-bucket rate limiting in `crates/pact-guards/src/velocity.rs`.
- Unit and integration tests for all of the above.

**Shipped files:**

| File | What shipped |
|------|-------------|
| `crates/pact-core/src/capability.rs` | `MonetaryAmount`, `ToolGrant` monetary fields, attenuation variants, `is_subset_of` monetary checks |
| `crates/pact-kernel/src/budget_store.rs` | `BudgetUsageRecord.total_cost_charged`, `try_charge_cost`, schema migration, replication |
| `crates/pact-kernel/src/lib.rs` | `ToolInvocationCost`, `invoke_with_cost`, kernel cost verification, receipt population |
| `crates/pact-core/src/receipt.rs` | `FinancialReceiptMetadata` (serialized into `metadata` field) |
| `crates/pact-kernel/src/receipt_store.rs` | Cost indexing columns, `RetentionConfig`, archival rotation |
| `crates/pact-guards/src/velocity.rs` | `VelocityGuard` token-bucket implementation |

### Phase 2: Observability (~3 months effort; maps to Q3 2026 in the Strategic Roadmap)

- Spending dashboard (query layer over receipt store).
- Budget utilization webhooks.
- Real-time cost streaming from receipt log.
- Design partner integrations (2-3 agent framework vendors).

### Phase 3: Payment Rail Integration (~3 months effort; maps to Q4 2026 in the Strategic Roadmap)

- `PaymentAdapter` trait and `PaymentError` in `crates/pact-kernel/src/payment.rs`.
- `StripePaymentAdapter` implementation.
- Hold-and-capture flow (authorize before invocation, capture or release after cost report).
- Kernel integration: optional adapter on `PactKernel`, with truthful receipt semantics and a reconciliation queue for post-execution settlement failures.
- `x402` adapter for prepaid per-request HTTP payments.

### Phase 4: Cross-Org Settlement (~6 months effort; maps to Q1-Q2 2027 in the Strategic Roadmap)

- Batch settlement engine walking delegation chains across receipt log.
- Net position calculation per organization.
- `StablecoinPaymentAdapter` for on-chain settlement.
- Tool provider registry with verified payment addresses.
- Multi-currency support and exchange rate snapshotting.

---

## 7. Estimated Effort

Core economic layer (Phase 1):

| Component | Estimate |
|-----------|----------|
| `MonetaryAmount` + `ToolGrant` schema + attenuation + `is_subset_of` | 1 week |
| `BudgetStore` cost tracking (both implementations + replication) | 1.5 weeks |
| `ToolInvocationCost` + `invoke_with_cost` + kernel verification | 1 week |
| `VelocityGuard` + velocity constraints | 1 week |
| `FinancialReceiptMetadata` + receipt store indexing | 0.5 weeks |
| Integration tests + conformance harness updates | 1-2 weeks |
| **Total** | **6-7 weeks** |

This estimate assumes a single engineer working full-time. The work is
structured so that each component can be merged independently behind feature
flags, with the schema-tolerance migration landing before `MonetaryAmount` and
`ToolGrant` cost fields. Those fields are only non-breaking after the
`deny_unknown_fields` compatibility work has shipped.

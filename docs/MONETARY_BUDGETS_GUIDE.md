# Monetary Budgets Guide

Monetary budgets let operators cap how much an agent can spend when invoking
cost-bearing tools. The strongest honest budget claim today is:

- **single node:** ARC enforces budgets with an atomic read-check-increment
  transaction on one SQLite store
- **clustered mode:** ARC bounds provisional authorized exposure, but does not
  claim distributed-linearizable spend truth and admits the documented overrun
  bound under split-brain conditions

An invocation is denied at the kernel boundary if it would exceed either the
per-call cap or the lifetime total for the currently selected local budget
store.

If you need the planning step that happens before budget issuance, see
[TOOL_PRICING_GUIDE.md](TOOL_PRICING_GUIDE.md). That guide covers how
advertised tool-manifest pricing informs the `max_cost_per_invocation` and
`max_total_cost` values you choose to issue.

## MonetaryAmount Type

```rust
pub struct MonetaryAmount {
    pub units: u64,
    pub currency: String,
}
```

`units` is an integer in the currency's smallest denomination. For USD that is cents (1 dollar = 100 units). For JPY it is yen (1 yen = 1 unit). The `currency` field is an ISO 4217 code such as `"USD"`, `"EUR"`, or `"JPY"`. Floating-point arithmetic is never used for monetary calculations.

## Configuring Budgets on a ToolGrant

Both budget fields are optional. Omitting a field means no cap is applied for that dimension.

```rust
pub struct ToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<Operation>,
    pub constraints: Vec<Constraint>,           // optional
    pub max_invocations: Option<u32>,           // optional
    pub max_cost_per_invocation: Option<MonetaryAmount>,  // optional
    pub max_total_cost: Option<MonetaryAmount>,           // optional
    pub dpop_required: Option<bool>,            // optional
}
```

`max_cost_per_invocation` caps the cost of a single call. If the tool reports a cost exceeding this value the kernel denies the invocation before it runs.

`max_total_cost` caps the aggregate cost across all invocations under this grant for the lifetime of the capability token. Once accumulated spend would exceed this value any further invocations are denied.

Example grant with monetary limits (USD, 100 cents = $1.00):

```json
{
  "server_id": "billing-tools",
  "tool_name": "send_invoice",
  "operations": ["invoke"],
  "max_cost_per_invocation": { "units": 500, "currency": "USD" },
  "max_total_cost": { "units": 10000, "currency": "USD" }
}
```

This allows `send_invoice` up to $5.00 per call, with a lifetime cap of $100.00 across all calls.

## Enforcement: How try_charge_cost Works

The kernel calls `BudgetStore::try_charge_cost` on every invocation of a grant that carries monetary limits. The function performs three sequential checks within a single atomic transaction:

1. `invocation_count < max_invocations` (if `max_invocations` is set)
2. `cost_units <= max_cost_per_invocation` (if `max_cost_per_invocation` is set)
3. `total_cost_charged + cost_units <= max_total_cost_units` (if `max_total_cost` is set)

If all three checks pass the function increments `invocation_count` by 1 and adds `cost_units` to `total_cost_charged`, then commits the transaction and returns `true`. If any check fails the transaction is rolled back and the function returns `false`, causing the kernel to deny the invocation.

The SQLite backend uses `TransactionBehavior::Immediate` (write-lock acquired on
BEGIN) to ensure the read and the subsequent write are atomic with respect to
concurrent requests on the same node.

## HA Overrun Bound

In a multi-node HA deployment each node maintains an independent SQLite budget store. Budget state is replicated via a last-writer-wins (LWW) seq-based merge using `upsert_usage`. In a split-brain scenario where two nodes cannot see each other's writes, each node may independently approve one invocation at the full per-invocation cap before replication converges.

The maximum possible overrun is bounded by:

```
overrun <= max_cost_per_invocation.units * active_node_count
```

When designing budgets for sensitive tools, size `max_total_cost` conservatively to account for this bound. For a two-node cluster with a $5.00 per-invocation cap the worst-case overrun is $10.00.

## FinancialReceiptMetadata on Receipts

Every allowed invocation under a monetary grant produces a `ArcReceipt` with a `"financial"` key in its `metadata` field. The value is a `FinancialReceiptMetadata` object:

```rust
pub struct FinancialReceiptMetadata {
    pub grant_index: u32,
    pub cost_charged: u64,
    pub currency: String,
    pub budget_remaining: u64,
    pub budget_total: u64,
    pub delegation_depth: u32,
    pub root_budget_holder: String,
    pub payment_reference: Option<String>,
    pub settlement_status: SettlementStatus,
    pub cost_breakdown: Option<serde_json::Value>,
    pub attempted_cost: Option<u64>,  // populated on denial receipts
}
```

`cost_charged` and `budget_remaining` are in the same minor-unit denomination as `MonetaryAmount.units`. A denial receipt due to budget exhaustion sets `cost_charged` to 0 and populates `attempted_cost` with the cost that would have been charged.

`settlement_status` uses the canonical receipt-side enum:

- `not_applicable` for pre-execution denials where no settlement applies
- `pending` for an initiated but not yet final external settlement
- `settled` for a final recorded charge
- `failed` when execution completed but settlement became invalid

## Delegation and Attenuation

When delegating a capability token, monetary caps can only be tightened, never loosened. The `Attenuation` enum records the change:

```rust
Attenuation::ReduceCostPerInvocation {
    server_id: String,
    tool_name: String,
    max_cost_per_invocation: MonetaryAmount,
}

Attenuation::ReduceTotalCost {
    server_id: String,
    tool_name: String,
    max_total_cost: MonetaryAmount,
}
```

The kernel validates `is_subset_of` on every delegated token: a child grant's monetary caps must use the same currency and be numerically less than or equal to the parent's caps. A child with no cap on a dimension whose parent has a cap is rejected.

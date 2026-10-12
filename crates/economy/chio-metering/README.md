# chio-metering

`chio-metering` models receipt cost dimensions, queries cost records, exports
billing rows, and evaluates budget hierarchies. Callers supply cost records and
spend snapshots; this crate provides the arithmetic and decision logic.

## Usage

Evaluate a token budget with a current snapshot. An empty snapshot at the
specified evaluation time represents zero spend for missing nodes.

```rust
use chio_metering::{
    AggregateSpend, BudgetDecision, BudgetLimits, BudgetNode, BudgetNodeId,
    BudgetTree, BudgetWindow, SpendSnapshot,
};

fn main() -> Result<(), chio_metering::BudgetError> {
    let mut tree = BudgetTree::new();
    tree.insert(BudgetNode::new("agent", BudgetWindow::Daily).with_limits(
        BudgetLimits { max_tokens: Some(100), ..BudgetLimits::default() },
    ))?;
    let snapshot = SpendSnapshot::new(0);
    let decision = tree.evaluate(
        &BudgetNodeId::new("agent"), AggregateSpend::with_tokens(50), &snapshot,
    );
    assert_eq!(decision, BudgetDecision::Allow);
    Ok(())
}
```

Evaluation leaves the snapshot unchanged. Runtime enforcement must atomically
reserve or record accepted usage in an authoritative store.

## Guarantees

- `BudgetTree::insert` and `deserialize` validate limits, duplicate IDs, parent
  references, and acyclic structure.
- `BudgetTree::evaluate` checks the selected node and every ancestor. It denies
  unknown/disabled nodes, stale or undated snapshots, incompatible currencies
  for capped spend, arithmetic overflow, and exceeded configured dimensions.
- `execute_cost_query` caps results at 500 and reports truncation. Totals and
  groups describe the capped records in their input order.
- `create_billing_export` suppresses the batch monetary total for mixed
  currencies. Individual rows preserve the supplied monetary totals.

## Status

The crate implements local metering models and projections. `BudgetEnforcer`
is deprecated: its counters reset on restart, and `check` and `record` are
separate operations. `BudgetTree` evaluates caller-provided state and has no
persistence. Kernel charging, durable budgets, oracle conversion, and external
settlement need their own integration; billing exports carry no signatures.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol metered evidence](../../../spec/PROTOCOL.md#64-receipt-metadata)
- [Credit](../chio-credit/README.md)
- [Kernel](../../kernel/chio-kernel/README.md)

License: [Apache-2.0](../../../LICENSE).

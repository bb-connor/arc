# chio-metering architecture

## Responsibility and boundary

The crate owns cost-record models, cost aggregation, flat budget counters,
hierarchical budget evaluation, and billing export projections. It accepts
caller-provided data and returns models or decisions. It does not load signed
receipts, authenticate measurements, persist budgets, reserve funds, or execute
settlement. Runtime consumers must establish those boundaries separately.

`CostMetadata` identifies a receipt, agent, server, tool, optional session, and
time. It carries a vector of cost dimensions and a cached monetary total.
`BudgetTree` stores policy nodes; `SpendSnapshot` supplies current usage.
`BudgetEnforcer` retains process-local counters and is deprecated.

## Structure

- `cost` defines compute-time, data-volume, API-cost, warehouse-query, and custom
  dimensions, plus record construction and resource totals.
- `query` defines filters, groups, summaries, and `execute_cost_query`.
- `export` flattens records with `create_billing_export` and formats timestamps.
- `budget` defines the deprecated flat policy and check/record counter model.
- `budget_hierarchy` defines nodes, windows, limits, snapshots, tree validation,
  evaluation, and JSON serialization.

The crate root re-exports models and budget APIs. Query execution and billing
export functions remain accessible through their module paths. There are no
optional Cargo features or oracle client dependencies.

## Data and control flow

`CostMetadata::new` creates an empty record. `add_dimension` appends a
measurement; it does not refresh the cached monetary total. Callers invoke
`compute_total_monetary_cost` explicitly after changing API-cost dimensions.
Compute-time and data-byte methods sum their matching dimensions.

`execute_cost_query` filters by session, agent, server, tool, currency, and time.
It uses an inclusive lower time bound and exclusive upper bound, retains input
order, caps matches at the requested limit up to 500, and aggregates that
capped set. Group keys are ordered through a BTreeMap. A mixed-currency summary
or group has no monetary total.

`create_billing_export` projects all supplied records, chooses the first API
provider per row, uses each record's cached monetary total, and formats time
with Chrono. Export records retain receipt IDs for correlation but carry no
source receipt envelope or signature.

Budget tree insertion validates parent relationships. JSON loading inserts
roots before dependent nodes, rejects stalled unresolved parents, and validates
the result. Evaluation walks from leaf to root, compares each current window
bucket and enabled flag, and tests spend, tokens, requests, and warehouse bytes.
A violation at a later ancestor replaces a lower-node violation in the result.

## Trust and invariants

`BudgetTree::evaluate` is a pure decision over supplied state. Missing node
usage defaults to zero when the snapshot has an evaluation time. Nonzero
monetary spend on a capped path requires matching currencies. Checked addition
denies overflow in capped dimensions. Policy nodes are inaccessible for direct
mutation through the tree's public lookup methods.

Daily windows use 86,400-second buckets. Monthly windows approximate 30 days;
rolling windows use fixed-duration buckets computed from the timestamp.
Callers must supply the intended current bucket and a fresh authoritative
snapshot, including aggregate ancestor usage.

The deprecated `BudgetEnforcer` constructor does not validate policy currency
consistency. `check` accepts units already denominated in the policy currency;
it supplies no conversion. Counters use saturating addition. `record` does not
repeat `check`, so callers must synchronize the sequence themselves. Restart
resets all counters, requiring the kernel's durable budget store for continuity.

Cost sums use saturating arithmetic. A record's monetary calculation chooses
the first API-cost currency and skips subsequent different currencies. Query
and export batch totals detect mixed cached currencies and return no total.
Warehouse estimates and custom dimensions remain descriptive fields; this
crate does not price them or verify their provider.

## Dependencies

`chio-core` supplies `MonetaryAmount`. Serde and `serde_json` supply model and
tree serialization; serialized tree order is stable by node ID without a
signature or canonical-wire check. Chrono supplies UTC timestamp formatting.
`thiserror` defines budget errors. Proptest is used only by development tests.

## Verification

`cargo test -p chio-metering` exercises resource aggregation, mixed currencies,
query filters and caps, grouped summaries, export records, and flat budgets.
`tests/budget_hierarchy.rs` checks parent caps, disabled ancestors, tree loading,
window changes, missing nodes, currency mismatch, stale/undated snapshots, and
monetary and nonmonetary overflow. Property tests exercise capped-path currency
comparability and ancestor limit enforcement.

The README sample evaluates a tree against an explicit zero-spend snapshot.
Durable reservations, concurrent spending, kernel invocation charging, and
settlement acceptance require verification in their runtime owners.

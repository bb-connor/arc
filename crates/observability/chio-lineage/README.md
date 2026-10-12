# chio-lineage

`chio-lineage` projects receipt and capability relationships into an in-memory
provenance graph for Chio inspection tools. It supplies ingest, bounded graph
queries, edge diffs, and frontier digests. Callers own input acquisition,
source authentication, tenant scoping, and persistence.

## Usage

Ingest one offline OTEL frame and follow its tool-call node to the receipt:

```rust
use chio_lineage::ingest_otel::OtelIngest;
use chio_lineage::query::{forward, receipt_nodes, QueryBounds};
use chio_lineage::schema::EvidenceClass;

let mut ingest = OtelIngest::new();
ingest.ingest_line(r#"{
    "schema_version": "otlp.grpc.trace.v1",
    "receipt_id": "receipt-1",
    "trace_id": "trace-1",
    "span_id": "span-1"
}"#)?;
let graph = ingest.into_graph();
let result = forward(&graph, &["tool:trace-1:span-1"], QueryBounds::default());
assert_eq!(receipt_nodes(&result.graph).len(), 1);
assert!(result.graph.contains_evidence(EvidenceClass::Asserted));
assert!(result.truncated.is_none());
# Ok::<(), chio_lineage::ingest_otel::OtelIngestError>(())
```

The example needs no collector, files, or feature flags. `OtelIngest::new()`
stamps the graph schema; `ingest_line` accepts the flattened frame shape above.
Replay rows use `ingest_replay_corpus::ingest_corpus`; native active-defense
receipts use `ActiveDefenseReceiptIngest` with an explicit trusted signer set.

## Guarantees

- `OtelIngest::ingest_frame` checks the exact schema version and rejects empty,
  padded, or control-containing receipt, trace, and span IDs before mutation.
  Node IDs and `(from, to, kind)` edge keys deduplicate repeated frames.
- OTEL facts start as `Asserted`. A supplied local receipt correlation marks
  its receipt node and edge `Observed`; the caller must authenticate that
  correlation. This path performs no receipt signature or store lookup.
- `ingest_corpus` checks receipt and optional projection strings for empty or
  padded values. A matching signed lineage statement can mark an edge
  `Verified`; its signer trust and endpoint receipt verification belong to
  the caller.
- `ActiveDefenseReceiptIngest::ingest_all` checks trusted signers, receipt IDs,
  signatures, action hashes, and exact active-defense body bindings before
  projecting the batch. Missing referenced parents remain `Observed` nodes.
  Their parent edges are labeled `Verified`; callers must resolve and verify
  those parent receipts before relying on protocol receipt-lineage guarantees.
- `QueryBounds` defaults to depth 20 and 10,000 visited nodes. Traversals mark
  truncation when either bound is reached; edge count has no separate cap.
- `verify_frontier_signature` requires a trusted key and a matching frontier
  digest. The frontier covers schema, node IDs, and edge keys. Evidence labels
  and other metadata are outside that projection.

## Status

Implemented as a library with unit tests and integration tests for diffs,
frontier signatures, and active-defense causal links. Graph types are publicly
constructible and support cycles; callers must validate externally supplied
projections before relying on evidence classes. The crate declares no Cargo
features and is marked `publish = false`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [OTEL receipt exporter](../chio-otel-receipt-exporter/README.md)
- [SQLite lineage storage](../../platform/chio-store-sqlite/README.md)

License: [Apache-2.0](../../../LICENSE).

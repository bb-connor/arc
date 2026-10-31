# chio-lineage architecture

## Responsibility and boundary

The public surface describes and transforms in-memory provenance graphs.
`LineageGraph` contains versioned nodes, typed edges, and an optional
`TruncationMarker`. Nodes and edges carry `Asserted`, `Observed`, or `Verified`
evidence labels alongside optional tenant, timestamp, and source metadata.
The graph structs and evidence enums are publicly constructible; a label is
meaningful only with the verification policy of its producing path.

Callers provide OTEL frame strings, typed replay rows, or native receipts.
They retain responsibility for input size limits, authenticated source feeds,
tenant and time-window selection, and persisted graph state. Library code
performs no file or network I/O and does not enforce graph acyclicity.

## Structure

| Module | Responsibility |
| --- | --- |
| `schema` | `LineageNode`, `LineageEdge`, kinds, evidence classes, graph and truncation types. |
| `ingest_otel` | Stateful `OtelIngest`, typed frames, schema and required-ID checks. |
| `ingest_replay_corpus` | One-shot `ingest_corpus` and optional signed edge projection. |
| `ingest_active_defense` | Trusted native receipt batch verification and causal projection. |
| `query` | Forward/reverse breadth-first walks and typed Finding dependency queries. |
| `diff` | Edge-key comparison with evidence-change reporting and text output. |
| `anchor` | Sorted frontier bytes, embedded SHA-256, unsigned pinning and signature checks. |

`LINEAGE_GRAPH_SCHEMA` is `chio.lineage.graph/v1`. The JSON artifact in
`schemas/lineage-graph.v1.json` describes graph serialization.
`LineageGraph::empty` stamps this version; derived `Default` leaves its
version string empty. `LineageError` combines OTEL and corpus errors;
active-defense and anchor errors have separate public types.

## Data and control flow

`OtelIngest::ingest_line` deserializes the flattened `OtelReceiptFrame` shape.
`ingest_frame` requires `schema_version = otlp.grpc.trace.v1` and validates
receipt, trace, and span IDs before updating its graph. Those IDs must be
nonempty, unpadded, and free of control characters. Optional strings receive
no equivalent validation. `parent_span_id` is accepted without projecting
an edge. Unknown JSON fields are tolerated.

OTEL tool and capability nodes are `Asserted`. A local receipt correlation
changes the receipt node ID to `rcpt:<correlation>` and marks its node and edge
`Observed`. The implementation trusts the presence of that string; it performs
no local-store join. Without correlation, receipt IDs use `rcpt:otel:<id>`.
Deduplication keeps the first node ID and first `(from, to, kind)` edge;
later metadata or evidence changes do not update the retained entry.

`ingest_corpus` validates all rows before constructing a graph. It rejects
empty or padded receipt IDs and present optional projection strings.
Its default evidence is `Observed`. For a parent edge, a lineage statement
must match parent and child IDs, carry `Verified` evidence, and pass
`verify_signature` to upgrade the edge. The statement's embedded signer is
used without a trusted signer allowlist, and endpoint receipt signatures are
outside this path. Invalid statements leave the edge `Observed`.
A verified Finding-memory relation points from dependent write to delivery.

`ActiveDefenseReceiptIngest` requires a nonempty trusted signer set. Its batch
path checks signer membership, signature, content-addressed receipt ID,
action hash, typed body, and exact envelope/metadata bindings. Conflicting
logical evidence IDs reject the batch. All receipts verify before projection.
Causal edges reference logical evidence IDs and preserve prior/trigger source
tables as separate edge keys. Referenced parents absent from the batch become
`Observed` placeholders, while their `ReceiptLineageParent` edges are labeled
`Verified`. This label authenticates the child's signed parent reference;
the absent parent's receipt has not been verified. Consumers must resolve
and verify that parent before applying protocol receipt-lineage guarantees.
Recorded active-defense times are milliseconds; other ingest paths copy
supplied timestamps without normalizing their units.

## Trust and invariants

`forward` and `reverse` visit existing seeds using a visited set, making cycles
finite. Default bounds are depth 20 and 10,000 visited nodes. Reaching a bound
marks both `QueryResult.truncated` and the returned graph. The row check occurs
after adding a node, so even a zero row limit can return a seed. Edges have no
independent cap and can reference nodes beyond the returned subgraph.
`finding_memory_dependents` filters for typed `Verified` Finding edges;
it relies on the input graph's evidence labels.

`diff` compares `(from, to, kind)` keys and evidence classes. Node metadata,
timestamps, tenant fields, and labels are outside the comparison.
`frontier_bytes` sorts node IDs and edge-key tuples and canonicalizes them with
the graph schema. Evidence and metadata are outside the digest and signature.
The artifact records `CanonicalSource::CanonicalBytes`. This is a structural
projection commitment.

`pin_frontier` always produces an unsigned state, including when a signer
hint is supplied. `pin_frontier_signed` verifies an externally supplied
signature against a trusted key over domain-prefixed frontier bytes.
`verify_frontier_signature` recomputes the digest and verifies that message.
Algorithm labels are required to be nonempty and whitespace-free; they are
not checked against the signature backend. Frontier artifact counts and
other descriptive fields are outside the signature checks.
`AnchoredFrontier::is_signed` always returns false because it has no trusted
key context. Consumers use `is_signed_by` or `verify_frontier_signature`.

## Dependencies

`chio-core-types` supplies native receipt verification, typed active-defense
bodies, signed lineage statements, and public-key/signature types.
`serde` and `serde_json` serialize graph projections and parse frame/body
inputs; `thiserror` defines ingest and anchor errors. There is no async runtime
or direct SQLite dependency. Persistent traversal is owned by
[chio-store-sqlite](../../platform/chio-store-sqlite/README.md).

## Verification

Unit tests exercise ingest schema and ID rejection, deduplication, signed
statement bindings, query cycles and truncation, typed Finding dependencies,
diff ordering, SHA-256 vectors, and malformed/wrong-key frontier signatures.
Integration files `anchor_pinning.rs`, `guard_version_diff.rs`, and
`active_defense_receipts.rs` exercise public APIs, including response causal
chains and coincident prior/trigger references.

Run `cargo test -p chio-lineage` for these checks. The schema test checks
selected marker fields and a Finding edge enum value in the artifact.
It does not validate every generated graph against the full JSON Schema.

See the [README](README.md) and
[protocol receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract).

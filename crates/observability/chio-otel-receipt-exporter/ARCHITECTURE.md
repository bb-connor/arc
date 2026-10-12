# chio-otel-receipt-exporter architecture

## Responsibility and boundary

The crate accepts decoded trace batches, constructs signed Chio observations,
and appends them to a configured receipt destination. `OtlpGrpcIngress` owns a
`BoundedOtlpGrpcIngress`; that object owns a sink, queue configuration, queue
mutex, and flow mutex. The public facade supplies synchronous methods for
export, enqueue, drain, and snapshots. The network listener and protobuf decoder
belong to its host.

`ReceiptStoreSink` owns signing configuration and an `Arc<dyn CanonicalReceiptSink>`.
`from_receipt_store` adapts a kernel `ReceiptStore`; `new_canonical` accepts a
custom sink. `CanonicalChioReceipt` keeps a receipt together with its RFC 8785
serialization. Storage durability follows the selected sink's append contract.

## Structure

| Module | Responsibility |
| --- | --- |
| `ingress` | Decoded OTLP types, byte estimates, serialized queue flow, progress |
| `sink` | Span validation, observation signing, canonical bytes, sink adapter |
| `denylist` | Exact-key attribute removal for cardinality control |
| `queue_core` | Generic `VecDeque` with drop-oldest admission and counters |

Normal builds re-export ingress/sink types and kernel drop metric names.
Under `cfg(loom)`, only the queue core is exposed, and normal Chio dependencies
and APIs are omitted. This is a modeling configuration; the manifest declares
no Cargo features.

## Data and control flow

`OtlpGrpcTraceExport` groups spans with resource attributes. `spans` flattens the
span sequence; resource attributes participate in size estimates but do not
enter receipt conversion. Attributes map to a `BTreeMap`, with duplicate keys
resolved by collection order. Individual attribute lookup selects the first
matching key, so callers should supply unique keys for predictable routing.

`ReceiptStoreSink::prepare_receipts` checks at most 4,096 resource groups,
65,536 spans, and 64 MiB of estimated input bytes before constructing all signed
receipts. Estimates count string/value lengths and timestamp field sizes rather
than allocator consumption or decoded protobuf size. `receipt_for_span` and
`canonical_receipt_for_span` validate one span directly, without batch limits.

Conversion validates trace/span IDs and optional correlation/routing fields,
then canonicalizes the original span payload for `content_hash`. A second view
strips the four denied keys for action parameters and metadata. It signs a body
with a fresh UUID-derived signing nonce, observation semantics, routing defaults,
configured tenant, and trace/span provenance. The resulting content-addressed
receipt ID and full canonical serialization are handed to the sink together.
Source receipt correlation is stored separately from sanitized attributes.

`export_traces` prepares a batch and appends receipts sequentially. `append_from`
updates a mutable index only after each successful sink call. Direct callers
that need retry identity must retain the prepared vector and progress index;
repeating conversion signs new identities.

Bounded ingress admission accounts batches, spans, and estimated bytes. Defaults
are 1,024 batches, 65,536 spans, 64 MiB, and a drain limit of 128 batches.
A zero batch capacity rejects admission; zero span/byte limits reject batches
that exceed those limits. Drain limits normalize to at least one. Admission
evicts oldest queued batches until a fitting incoming batch
can enter, and rejects an incoming batch that cannot fit alone.

During drain, signed receipts are cached on the front batch and their canonical
lengths are added to byte accounting. This addition happens after admission and
can raise the reported queue bytes above its configured threshold; admission
bounds are not a strict total memory ceiling. A flow mutex serializes enqueue
and drain operations, including sink append calls.

A `ReceiptStoreError::Pool` failure retains prepared receipts and successful
append progress for the next drain. Terminal validation/signing/store failures
remove the batch and count remaining loss. Queue-class errors are also treated
as retryable, including preparation batch-limit errors; such a batch can remain
at the queue head. `OtlpGrpcIngress::export` reports overflow as an error after
the bounded export completes, so an error can accompany successful appends.
Callers must inspect snapshots and use `drain` to resume retained work.

## Trust and invariants

Trace IDs must contain 32 lowercase hex characters and span IDs 16, with at
least one nonzero character in each. Optional source receipt IDs require 64
lowercase hex characters. Routing attributes require nonempty unpadded strings;
`chio.verdict` must be `allow`, `deny`, or `incomplete`. A matching source receipt
ID does not prove a trusted source signature, trace ownership, or mediation.

Every emitted receipt has kind `trace_observation`, boundary `detect_only`,
outcome `observed`, trust level `verified`, origin
`host_executed_provider_reported`, and no decision. Source verdict is retained
as metadata. Signing authenticates the ingesting signer's observation and
supplies no execution authorization. Tenant attribution comes exclusively from
`ReceiptStoreSinkConfig`, so hosts must authenticate that configuration.

The deny-list removes `gen_ai.tool.call.id`, `chio.receipt.id`,
`chio.replay.run_id`, and `chio.tenant.id` by exact key. It does not inspect
nested values or other keys for secrets. Trace/span IDs, selected source fields,
and optional source receipt correlation remain in provenance metadata.
The content hash commits to the original span attributes, while the signed
action uses the sanitized view. Evidence consumers need the original span
payload to recompute that content commitment.

Queue counters distinguish admission loss, append errors, completed batches,
and newly appended spans. Only admission loss increments the runtime ingress
drop family; terminal unappended loss increments the sink drop family.
Retryable failures retain work without incrementing a drop counter. The queue
and prepared state are volatile and disappear with the ingress object/process.

## Dependencies

`chio-core` supplies receipt signing, canonical JSON, keypairs, and hashing.
`chio-kernel` supplies receipt-store traits, errors, and telemetry attribute
constants. `chio-metrics-spec` supplies active runtime drop counter families.
`serde` and `serde_json` represent decoded payloads; `thiserror` defines
`OTelReceiptExportError`; `uuid` provides fresh v7 signing nonce input.
`loom` and `proptest` are development dependencies for modeled concurrency and
partial append retry tests.

## Verification

Run `cargo test -p chio-otel-receipt-exporter` for the normal configuration.
`otlp_to_receipt.rs` checks observation semantics, signatures, provenance,
invalid routing/correlation IDs, configured tenant attribution, and batch limits.
`denylist_strip.rs` checks removal from span and resource attributes.
Sink unit tests compare bytes passed to the destination with canonical receipt
serialization. Ingress tests exercise queue overflow and append-error accounting.

`otel_retry_idempotence.rs` generates partial pool-failure positions and resumes
with `drain`, asserting distinct stable IDs for successful appends.
Run `RUSTFLAGS="--cfg loom" cargo test -p chio-otel-receipt-exporter --test loom_ring_sender_vs_shutdown`
for the shared queue model. Its test-owned shutdown wrapper explores sender/drain
interleavings; the normal ingress API has no shutdown method. The model does
not execute normal signing or receipt-store integration.

# chio-otel-receipt-exporter

`chio-otel-receipt-exporter` converts decoded OTLP trace spans into signed Chio
trace-observation receipts and appends them through a caller-supplied sink.
`OtlpGrpcIngress` is a synchronous Rust facade; the host owns the network listener,
protobuf decoding, authentication, and receipt-store selection.

## Usage

Convert and append a trace receipt offline to a small in-memory sink.

```rust
use std::sync::{Arc, Mutex};
use chio_core::Keypair;
use chio_kernel::receipt_store::ReceiptStoreError;
use chio_otel_receipt_exporter::{
    CanonicalChioReceipt, CanonicalReceiptSink, OtlpGrpcTraceExport, OtlpSpan,
    ReceiptStoreSink, ReceiptStoreSinkConfig,
};

#[derive(Default)]
struct MemorySink(Mutex<Vec<CanonicalChioReceipt>>);
impl CanonicalReceiptSink for MemorySink {
    fn append_chio_receipt_canonical(
        &self, receipt: CanonicalChioReceipt,
    ) -> Result<(), ReceiptStoreError> {
        self.0.lock()
            .map_err(|_| ReceiptStoreError::Pool("memory sink lock poisoned".into()))?
            .push(receipt);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let memory = Arc::new(MemorySink::default());
    let sink = ReceiptStoreSink::new_canonical(
        memory.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let span = OtlpSpan::new(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "gen_ai.tool.call",
    ).with_attribute("chio.verdict", serde_json::json!("allow"));
    let summary = sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
    assert_eq!(summary.appended_receipts, 1);
    let stored = memory.0.lock().map_err(|_| std::io::Error::other("lock poisoned"))?;
    let canonical = stored.first().ok_or_else(|| std::io::Error::other("missing receipt"))?;
    assert!(!canonical.canonical_bytes().is_empty());
    let receipt = canonical.receipt();
    assert!(receipt.verify_integrity_embedded_key()?);
    assert_eq!(receipt.receipt_kind.as_str(), "trace_observation");
    assert_eq!(receipt.boundary_class.as_str(), "detect_only");
    assert!(receipt.decision.is_none());
    Ok(())
}
```

Use `ReceiptStoreSink::from_receipt_store` with an `Arc<dyn ReceiptStore>` for
storage, or implement `CanonicalReceiptSink` for a destination that accepts the
signed receipt and its RFC 8785 bytes together. `prepare_receipts` checks batch
limits; `append_from` advances a caller-owned progress index after each success.

## Guarantees

- `ReceiptStoreSink::canonical_receipt_for_span` checks nonzero lowercase hex
  trace/span IDs, optional receipt correlation ID, routing strings, and required
  `chio.verdict` (`allow`, `deny`, or `incomplete`). It signs `trace_observation`,
  `detect_only`, `host_executed_provider_reported` receipts with no decision.
- `ReceiptStoreSinkConfig` supplies the signing key and tenant. A span's tenant
  attribute cannot assign the receipt tenant. A source receipt ID is correlation
  data with a shape check; this API does not authenticate that source receipt.
- `BoundedOtlpGrpcIngress` caches prepared receipts and append progress across
  retryable store-pool failures, preserving IDs for retained batches. Enqueue
  summaries and snapshots expose overflow and append outcomes.
- `strip_denied_attributes` removes four exact keys for cardinality control.
  Other attribute values require caller privacy review before ingestion.

## Status

The crate implements span conversion, canonical sink integration, and a volatile
bounded queue. It has no declared Cargo features and is unpublished. `cfg(loom)`
builds expose the shared queue core for concurrency modeling and omit the normal
ingress, sink, and deny-list APIs.

`enqueue` acknowledges memory admission. Storage acknowledgment comes from the
sink's append result, with durability determined by that sink. Overflow evicts
old batches or rejects oversized incoming batches. The default limits are 1,024
queued batches, 65,536 spans, and 64 MiB of estimated bytes; each drain processes
up to 128 batches. Prepared receipt bytes are added to queue accounting after
admission. Direct repeated conversions create fresh signed identities.

Trace receipts attest the ingesting signer's recorded observation. Source verdicts
remain metadata and grant no tool authority. Resource attributes contribute to
batch sizing but are absent from the receipt body. Ingress and terminal sink drops
increment the corresponding `chio-metrics-spec` runtime counter families.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Receipt semantics](../../../spec/PROTOCOL.md#61-receipt-semantics-and-decisions)
- [Metric registry](../chio-metrics-spec/README.md)
- [License](../../../LICENSE)

# chio-siem

`chio-siem` reads Chio kernel receipt rows and exports audit views to SIEM
collectors. `ExporterManager` polls a read-only SQLite connection and dispatches
batches to `Exporter` implementations outside the kernel's decision path.
Built-in sinks share an unsigned, restricted `SiemSinkProjection`.

## Usage

Format a locally signed demonstration receipt as CEF without opening a database
or contacting a collector. Real signer pins come from operator configuration.

```rust
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};
use chio_siem::{CefExporter, SiemEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Keypair::generate();
    let receipt = ChioReceipt::sign(ChioReceiptBody {
        id: "cef-demo".into(),
        timestamp: 1_712_345_678,
        capability_id: "demo-capability".into(),
        tool_server: "files".into(),
        tool_name: "read".into(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path": "README.md"}))?,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(b"demo content"),
        policy_hash: chio_core::crypto::sha256_hex(b"demo policy"),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: key.public_key(),
        bbs_projection_version: None,
    }, &key)?;
    let event = SiemEvent::from_receipt(receipt);
    assert!(!event.is_authorized()); // No independently configured signer pin.
    let cef = CefExporter::default().format_event(&event)?;
    assert!(cef.starts_with("CEF:0|"));
    assert!(cef.contains("authorized=false"));
    assert!(cef.contains("payload_included=false"));
    Ok(())
}
```

For polling, create `ExporterManager::new(SiemConfig { .. })`, register sinks
with `add_exporter`, and await `run` with a Tokio watch receiver for cancellation.
The receipt database must already exist. Set `trusted_kernel_keys` from trusted
configuration and `cursor_db_path` to a separate writable SQLite file for
per-exporter progress.

## Guarantees

- `SiemEvent::sink_projection` reverifies receipt identity, signature, action
  parameter hash, and its privately accepted signer pin. Authorization also
  requires mediated allow semantics at a prevent boundary; public cached flags
  cannot promote a receipt.
- `SiemSinkProjection` includes hashes, closed semantic fields, verification
  flags, and selected numeric financial data. It excludes arguments, signatures,
  evidence details, actor chains, freeform reasons, and arbitrary metadata.
- `ExporterManager::new` validates nonzero polling and batch settings and requires
  `ReceiptReadBoundary::AdminAll`. Its source connection opens read-only.
- Polling uses per-exporter high-water marks in `SiemCursorStore`, captures
  malformed rows before advancing, and never advances past a failed batch.

## Status

Implemented backends include Splunk HEC, Elasticsearch bulk, Datadog Logs,
Sumo Logic, HTTPS webhook, OCSF 1.3.0, CEF, and PagerDuty/OpsGenie alerting.
CEF provides formatting only. OCSF with an empty endpoint also formats only;
registering either with the manager acknowledges formatting completion.
Network success follows each backend's response checks and does not prove
collector retention. The crate has no declared Cargo features and is unpublished.

The in-memory failure queue drops its oldest entry at capacity. Durable malformed
rows retain original JSON in the cursor database. Sink projections remain
unsigned; original evidence retrieval needs separate authorization and signer
verification. Custom exporters receive the full event and own their disclosure
policy. Metrics default to `NoopMetricsSink`; hosts install active instrumentation
with `with_metrics_sink`. Alerting needs its own trusted signer pins and backends.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt semantics](../../../spec/PROTOCOL.md#61-receipt-semantics-and-decisions)
- [HTTP egress contract](../../../spec/PROTOCOL.md#84-http-egress-contract-enforcement-w22)
- [Log redaction](../chio-log-redact/README.md)
- [License](../../../LICENSE)

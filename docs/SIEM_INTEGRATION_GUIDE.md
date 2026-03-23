# SIEM Integration Guide

The `pact-siem` crate forwards PACT tool receipts to external SIEM systems. It is an optional dependency of `pact-cli`, enabled with the `siem` Cargo feature. The crate is deliberately isolated from `pact-kernel` to keep the kernel TCB free of HTTP client dependencies.

## Building with SIEM Support

```bash
cargo build -p pact-cli --features siem
```

Without `--features siem`, the `pact-siem` crate is not compiled and the binary has no SIEM functionality. The rest of PACT operates identically.

## Architecture

`pact-siem` opens its own read-only SQLite connection to the kernel's receipt database. It never writes to the kernel store and does not link against `pact-kernel`. The `ExporterManager` pulls receipts using a seq-based cursor, builds `SiemEvent` values, and fans each batch out to all registered exporters.

```
pact-kernel (writes receipts) --> receipts.sqlite3 <-- ExporterManager (read-only)
                                                               |
                                                     +------ fan out ------+
                                                     v                     v
                                             SplunkHecExporter   ElasticsearchExporter
```

## ExporterManager Cursor Pull

`ExporterManager` is configured with `SiemConfig`:

```rust
pub struct SiemConfig {
    pub db_path: PathBuf,         // path to kernel receipt SQLite file
    pub poll_interval: Duration,  // default: 5 seconds
    pub batch_size: usize,        // default: 100 receipts per poll
    pub max_retries: u32,         // default: 3 attempts per exporter
    pub base_backoff_ms: u64,     // default: 500 ms (doubles on each retry)
    pub dlq_capacity: usize,      // default: 1000 entries
}
```

On each tick the manager opens a fresh read-only connection, queries `SELECT seq, raw_json FROM pact_tool_receipts WHERE seq > cursor ORDER BY seq ASC LIMIT batch_size`, parses receipts into `SiemEvent` values, and calls `export_batch` on each registered exporter. The cursor is advanced past the batch whether or not some events were DLQ'd.

The cursor is in-memory only and resets to 0 on restart. Both Splunk HEC (timestamp dedup) and Elasticsearch (idempotent `_id` upsert) handle duplicate events safely.

Run the manager:

```rust
let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
manager.run(cancel_rx).await;
// To stop: let _ = cancel_tx.send(true);
```

## Splunk HEC Setup

```rust
use pact_siem::exporters::splunk::{SplunkConfig, SplunkHecExporter};

let config = SplunkConfig {
    endpoint: "https://splunk.example.com:8088".to_string(),
    hec_token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".to_string(),
    sourcetype: "pact:receipt".to_string(),  // default
    index: Some("pact_audit".to_string()),   // omit to use HEC token default
    host: Some("pact-node-01".to_string()),  // optional
};
let exporter = SplunkHecExporter::new(config)?;
manager.add_exporter(Box::new(exporter));
```

The exporter POSTs newline-separated JSON event envelopes to `{endpoint}/services/collector/event`. Each envelope wraps the full `PactReceipt` JSON under the `"event"` key with `time`, `sourcetype`, and optional `index`/`host` fields.

The `Authorization` header is `Splunk {hec_token}`. TLS is handled by `reqwest` with the system's native certificate store.

## Elasticsearch Bulk Setup

```rust
use pact_siem::exporters::elastic::{ElasticAuthConfig, ElasticConfig, ElasticsearchExporter};

let config = ElasticConfig {
    endpoint: "https://es.example.com:9200".to_string(),
    index_name: "pact-receipts".to_string(),  // default
    auth: ElasticAuthConfig::ApiKey("base64encodedkey==".to_string()),
    // or: auth: ElasticAuthConfig::Basic { username: "user".to_string(), password: "pass".to_string() },
};
let exporter = ElasticsearchExporter::new(config)?;
manager.add_exporter(Box::new(exporter));
```

The exporter POSTs NDJSON to `{endpoint}/_bulk`. Each receipt produces two lines: an index action using `receipt.id` as `_id` (making the operation idempotent), and the full receipt document. Partial failures (HTTP 200 with `errors: true` in the response body) are detected and reported as `ExportError::PartialFailure`.

## Dead-Letter Queue

When all retry attempts for an exporter are exhausted, failed events go to the bounded `DeadLetterQueue`. The DLQ capacity defaults to 1000. When the queue is full, the oldest entry is silently dropped and a `tracing::error` is emitted.

```rust
let dlq_len = manager.dlq_len();
```

Events in the DLQ are not automatically retried. They are lost unless drained and reprocessed externally. Because both exporters are idempotent, re-feeding DLQ events is safe.

## FinancialReceiptMetadata in SIEM Events

`SiemEvent` wraps a full `PactReceipt` and optionally extracts `FinancialReceiptMetadata`:

```rust
pub struct SiemEvent {
    pub receipt: PactReceipt,
    pub financial: Option<FinancialReceiptMetadata>,
}
```

The `financial` field is extracted from `receipt.metadata["financial"]`. It provides direct access to `cost_charged`, `currency`, `budget_remaining`, `budget_total`, `delegation_depth`, `root_budget_holder`, `settlement_status`, and `attempted_cost` without requiring JSON path traversal in SIEM search queries.

In Splunk you can search for denied-budget events with:

```
sourcetype="pact:receipt" event.decision.deny.guard="monetary_budget"
  | stats sum(event.metadata.financial.attempted_cost) as total_attempted by event.capability_id
```

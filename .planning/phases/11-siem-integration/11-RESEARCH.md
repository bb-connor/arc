# Phase 11: SIEM Integration - Research

**Researched:** 2026-03-22
**Domain:** Rust async HTTP exporters, SIEM protocols (Splunk HEC, Elasticsearch Bulk), dead-letter queues, Cargo feature flags
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**SIEM Event Format:**
- Events use PACT-native JSON matching PactReceipt schema -- consumers map to their SIEM's schema
- Full receipt JSON included (not summary) -- SIEM teams want raw data for custom parsing/alerting
- FinancialReceiptMetadata nested under "financial" key when present, omitted when absent (matches existing receipt.metadata pattern)
- Event timestamp is receipt.timestamp (canonical, signed), not export time

**Exporter Architecture:**
- Cursor-pull from receipt store on a configurable interval -- decoupled from kernel, uses existing seq-based cursor queries
- Splunk HEC: HTTP POST to /services/collector/event with HEC token auth
- Elasticsearch bulk: POST /_bulk with index action lines (standard bulk API, highest throughput)
- Rate limiting via configurable batch size + interval per exporter, no token bucket

**Dead-Letter Queue and Reliability:**
- In-memory VecDeque with configurable max capacity (default 1000) -- bounded, no disk I/O
- Overflow drops oldest entries (front of queue) -- prevents unbounded growth
- Exponential backoff with max 3 retries per event before DLQ
- Failure reporting via tracing::warn on individual failures, tracing::error when DLQ is full

### Claude's Discretion
- pact-siem crate internal module organization
- Splunk HEC event field mapping details
- Elasticsearch index naming and document ID strategy
- ExporterManager polling loop implementation (tokio interval vs std thread)
- Configuration struct field names and defaults

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| COMP-05 | At least 2 SIEM exporters functional and tested (ported from ClawdStrike: Splunk, Elastic, Datadog, Sumo Logic, Webhooks, or Alerting) | Splunk HEC and Elasticsearch bulk APIs documented below; exporter trait, DLQ, and polling loop patterns identified |
</phase_requirements>

---

## Summary

Phase 11 creates a new `pact-siem` crate that exports PACT receipts to enterprise SIEMs via cursor-pull against the existing `SqliteReceiptStore`. The two required exporters are Splunk HEC (HTTP POST to `/services/collector/event`) and Elasticsearch bulk API (POST `/_bulk` with NDJSON index action pairs). Both are well-understood HTTP APIs with no proprietary client libraries needed -- a standard async HTTP client is sufficient.

The most critical constraint is **kernel isolation**: `pact-kernel` must gain no HTTP client dependencies. `pact-siem` depends on `pact-core` for receipt types and opens its own read-only connection to the SQLite receipt database (or accepts a `list_tool_receipts_after_seq` callback), never linking against `pact-kernel`. The feature flag strategy follows the `pact-cli` pattern: `pact-siem` is an optional workspace member gated by a Cargo feature.

The dead-letter queue is straightforward: a `VecDeque<FailedEvent>` with a bounded capacity, dropping the front entry on overflow. The exporter polling loop runs on a `tokio::time::interval` inside a detached `tokio::spawn` task. Integration tests use a mock HTTP server (either `wiremock` or a minimal `axum` listener) to verify HEC and bulk payloads without network dependencies.

**Primary recommendation:** Use `reqwest 0.12` (already in `pact-cli`'s dependencies) as the HTTP client for both exporters; gate `pact-siem` behind a `siem` Cargo feature in the workspace; drive the polling loop with `tokio::time::interval` inside a spawned task.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `reqwest` | 0.12 (workspace already has it in pact-cli) | Async HTTP client for Splunk HEC and ES bulk POSTs | Already approved in workspace; `rustls-tls` feature avoids OpenSSL; `json` feature handles content-type automatically |
| `tokio` | 1 (workspace) | Async runtime for interval loop and HTTP | Already the project runtime |
| `serde_json` | 1 (workspace) | JSON serialization for event payloads and NDJSON bulk format | Already in workspace |
| `tracing` | 0.1 (workspace) | warn/error logging for DLQ and export failures | Already in workspace |
| `thiserror` | 1 (workspace) | Error type derivation | Already in workspace |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `wiremock` | 0.6 | Mock HTTP server for integration tests | Tests only -- verifies exact HEC and bulk payload shapes without network |
| `tokio-test` | 0.4 | Async test utilities | Tests only -- if needed for interval or spawn testing |

**Version verification (2026-03-22):**
- `reqwest`: 0.13.2 is latest on crates.io, but workspace pins 0.12 in `pact-cli`; use 0.12 to stay consistent.
- `wiremock`: 0.6 is current. (Source: crates.io, March 2026)

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `reqwest` (async) | `ureq` (blocking, already in pact-cli) | ureq 3.x is blocking; fine for simple cases but ExporterManager should be async to compose with tokio interval; reqwest already used for trust service client in pact-cli |
| `wiremock` | `axum` listener in test thread | Both valid; wiremock is more declarative and avoids test-specific server boilerplate already used in pact-cli tests |
| `tokio::time::interval` | `std::thread::sleep` loop | tokio interval cooperates with the async runtime; std thread creates an additional OS thread and cannot share the tokio handle cleanly |

**Installation (new crate only, HTTP deps not needed workspace-wide):**
```bash
# pact-siem/Cargo.toml dependencies (not workspace-wide)
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }

# dev-dependencies for integration tests
wiremock = "0.6"
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
```

---

## Architecture Patterns

### Recommended Project Structure

```
crates/pact-siem/
├── Cargo.toml            # depends on pact-core, reqwest, tokio, serde_json, tracing, thiserror
├── src/
│   ├── lib.rs            # pub re-exports: ExporterManager, SiemConfig, SiemError
│   ├── event.rs          # SiemEvent: wraps PactReceipt + extracts FinancialReceiptMetadata
│   ├── exporter.rs       # Exporter trait: export_batch(&[SiemEvent]) -> Result<(), ExportError>
│   ├── manager.rs        # ExporterManager: cursor-pull loop, DLQ, retry, fan-out
│   ├── dlq.rs            # DeadLetterQueue: VecDeque<FailedEvent>, bounded drop-oldest
│   └── exporters/
│       ├── mod.rs
│       ├── splunk.rs     # SplunkHecExporter: POST /services/collector/event
│       └── elastic.rs    # ElasticsearchExporter: POST /_bulk with NDJSON
```

Workspace Cargo.toml adds `"crates/pact-siem"` to `members`.

### Pattern 1: Exporter Trait

**What:** A minimal async trait that each exporter implements. Returns `Result<usize, ExportError>` (number of events successfully exported).

**When to use:** Always -- every SIEM target implements this trait.

```rust
// Source: CLAWDSTRIKE_INTEGRATION.md section 3.4 (adapted for pact-siem)
#[async_trait::async_trait]
pub trait Exporter: Send + Sync {
    /// Export a batch of events. Returns the count of events successfully sent.
    async fn export_batch(&self, events: &[SiemEvent]) -> Result<usize, ExportError>;

    /// Exporter name for logging and health reporting.
    fn name(&self) -> &str;
}
```

Note: `async_trait` crate is needed if targeting Rust < 1.75 RPITIT. Since workspace `rust-version = "1.93"`, native async-in-trait is available and preferred over `async_trait`.

### Pattern 2: ExporterManager Cursor-Pull Loop

**What:** A background tokio task that polls `list_tool_receipts_after_seq`, builds `SiemEvent` batches, calls each exporter, and retries/DLQs on failure.

**When to use:** Single manager instance per pact-siem activation.

```rust
// Source: adapted from CLAWDSTRIKE_INTEGRATION.md manager.rs pattern
pub struct ExporterManager {
    exporters: Vec<Box<dyn Exporter>>,
    dlq: DeadLetterQueue,
    cursor: u64,           // persists the last successfully exported seq
    config: SiemConfig,
}

impl ExporterManager {
    pub async fn run(mut self, store_path: PathBuf) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        loop {
            interval.tick().await;
            let store = SqliteReceiptStore::open(&store_path)?;
            let batch = store.list_tool_receipts_after_seq(self.cursor, self.config.batch_size);
            // fan-out to each exporter with retry, DLQ on max_retries exceeded
        }
    }
}
```

**Key design decision (discretion area):** ExporterManager opens its own `SqliteReceiptStore` read connection. This avoids any dependency on pact-kernel internals; pact-siem only needs the path to the SQLite file. The store is opened per-poll or kept open across polls (keeping it open is more efficient and safe in WAL mode -- WAL readers do not block writers).

### Pattern 3: Dead-Letter Queue

**What:** Bounded in-memory queue that absorbs export failures.

**When to use:** When an exporter fails all 3 retries.

```rust
// Source: decisions from 11-CONTEXT.md
pub struct DeadLetterQueue {
    inner: VecDeque<FailedEvent>,
    max_capacity: usize,  // default 1000
}

impl DeadLetterQueue {
    pub fn push(&mut self, event: FailedEvent) {
        if self.inner.len() >= self.max_capacity {
            // drop oldest -- front of queue
            self.inner.pop_front();
            tracing::error!("DLQ full -- oldest entry dropped");
        }
        self.inner.push_back(event);
    }
}
```

### Pattern 4: Splunk HEC Event Format

**What:** Single event POST or batched event POST to `/services/collector/event`.

**When to use:** When SplunkHecExporter::export_batch is called.

```rust
// Source: Splunk HEC documentation (https://docs.splunk.com/Documentation/Splunk/latest/Data/HECexamples)
// Each event in the batch is a JSON object; multiple events are newline-concatenated (not a JSON array)
// Content-Type: application/json
// Authorization: Splunk <hec_token>

// Single event envelope:
// {"time": <unix_timestamp_f64>, "event": <full_receipt_json>, "sourcetype": "pact:receipt"}

// Batch: concatenate multiple envelopes without commas or array brackets
let payload = events.iter()
    .map(|e| {
        serde_json::json!({
            "time": e.receipt.timestamp,
            "event": e.receipt,
            "sourcetype": "pact:receipt"
        })
        .to_string()
    })
    .collect::<Vec<_>>()
    .join("\n");
```

Key HEC fields (discretion area):
- `time`: use `receipt.timestamp` (u64 seconds) as f64 for Splunk compatibility
- `event`: full `PactReceipt` JSON
- `sourcetype`: `"pact:receipt"` -- allows Splunk teams to write sourcetype-based searches
- `host`: optional; if omitted, Splunk uses the HEC endpoint's hostname
- `index`: configurable; default to exporter config or omit (uses default index)

### Pattern 5: Elasticsearch Bulk API Event Format

**What:** NDJSON pairs (action line + document line) sent to `/_bulk`.

**When to use:** When ElasticsearchExporter::export_batch is called.

```rust
// Source: Elasticsearch Bulk API docs (https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
// POST /_bulk
// Content-Type: application/x-ndjson
// Authorization: ApiKey <key> or Basic <base64>

// Each receipt becomes two NDJSON lines:
// {"index": {"_index": "<index_name>", "_id": "<receipt.id>"}}
// <full receipt JSON>

let mut body = String::new();
for event in events {
    let action = serde_json::json!({"index": {"_index": &config.index_name, "_id": &event.receipt.id}});
    body.push_str(&action.to_string());
    body.push('\n');
    body.push_str(&serde_json::to_string(&event.receipt)?);
    body.push('\n');
}
```

Key ES design decisions (discretion area):
- `_index`: configurable string in `ElasticConfig` (default `"pact-receipts"`)
- `_id`: use `receipt.id` -- idempotent re-exports (retries do not create duplicates because ES uses `index` action which is an upsert)
- Auth: support both API key (`Authorization: ApiKey <key>`) and Basic (`Authorization: Basic <b64>`) -- config selects which
- Response check: parse `{"errors": true}` in the bulk response body; individual item errors are per-item in `items[].index.error`

### Pattern 6: FinancialReceiptMetadata Enrichment

**What:** Extract `FinancialReceiptMetadata` from `receipt.metadata["financial"]` and surface it alongside the full receipt.

**When to use:** Building `SiemEvent` from a `StoredToolReceipt`.

```rust
// Source: pact-core/src/receipt.rs -- FinancialReceiptMetadata is already defined
// receipt.metadata is Option<serde_json::Value>
// Financial data is at metadata["financial"] when present

pub struct SiemEvent {
    pub receipt: PactReceipt,
    /// Extracted financial metadata, None if not a monetary receipt
    pub financial: Option<FinancialReceiptMetadata>,
}

impl SiemEvent {
    pub fn from_stored(stored: StoredToolReceipt) -> Self {
        let financial = stored.receipt.metadata.as_ref()
            .and_then(|m| m.get("financial"))
            .and_then(|f| serde_json::from_value::<FinancialReceiptMetadata>(f.clone()).ok());
        Self { receipt: stored.receipt, financial }
    }
}
```

The full receipt (including `metadata.financial`) is included in both HEC and ES payloads so SIEM teams get raw data. `SiemEvent.financial` is available for exporter-level conditional logic (e.g., routing financial events to a separate index).

### Pattern 7: Cargo Feature Flag

**What:** Gate `pact-siem` compilation behind a `siem` feature in the workspace.

**When to use:** When adding `pact-siem` to workspace members and `pact-cli` optional deps.

```toml
# workspace Cargo.toml -- add to members:
"crates/pact-siem",

# pact-cli/Cargo.toml -- optional dependency:
[dependencies]
pact-siem = { path = "../pact-siem", optional = true }

[features]
siem = ["pact-siem"]
```

The pact-siem crate itself has no feature flags internally -- all exporters ship in the crate, and users enable the crate or not. This matches the CONTEXT.md "feature flag gates pact-siem compilation" decision.

### Anti-Patterns to Avoid

- **Exporting from kernel dispatch path:** Never call SIEM exporters during `dispatch_tool_call`. Exports are async background work; blocking the kernel TCB on network I/O violates the isolation requirement.
- **Importing pact-kernel in pact-siem:** pact-siem depends on pact-core only for `PactReceipt` and `FinancialReceiptMetadata` types, and opens its own SQLite connection. Adding `pact-kernel` as a dependency would allow HTTP client crates to transitively appear in the kernel's dep graph.
- **Unbounded DLQ:** Using a `Vec` without capacity limits means a persistent SIEM outage exhausts memory. Always use `VecDeque` with a bounded capacity that drops the oldest entry.
- **Using JSON arrays for HEC batch:** Splunk HEC batch format is newline-separated JSON objects (not a JSON array). An array will cause a 400 error.
- **Omitting `_id` in ES bulk actions:** Without `_id`, retries create duplicate documents. Using `receipt.id` as `_id` makes bulk index operations idempotent.
- **Blocking the tokio runtime:** `SqliteReceiptStore::open` and `list_tool_receipts_after_seq` are synchronous (rusqlite). Wrap in `tokio::task::spawn_blocking` if the poll interval is tight and the receipt volume is high enough to block the executor.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTTP POST with retry | Manual TCP + retry loop | `reqwest` 0.12 with `.retry()` or explicit loop | Connection pooling, TLS, timeout handling are non-trivial |
| Mock HTTP server in tests | Custom TcpListener handler | `wiremock` | Request matching, body capture, response templating require significant test scaffolding |
| NDJSON serialization | Manual string concatenation | `serde_json::to_string` per line + `\n` join | One-liner; hand-rolling risks missing trailing newline in ES bulk format |
| Exponential backoff math | Custom sleep calculation | `tokio::time::sleep(Duration::from_millis(base * 2u64.pow(attempt)))` | Simple enough inline; no external crate needed for 3-retry case |

**Key insight:** Both Splunk HEC and Elasticsearch bulk are deliberately simple HTTP APIs -- no SDK is needed. The complexity is in reliability (retry, DLQ, bounded memory) not in protocol mechanics.

---

## Common Pitfalls

### Pitfall 1: pact-kernel HTTP Dep Contamination

**What goes wrong:** `pact-siem` is added as a direct or transitive dependency of `pact-kernel`, causing `reqwest`/`hyper` to appear in the kernel's `Cargo.lock` transitive dep chain.

**Why it happens:** Developer adds `pact-siem` to `pact-kernel/Cargo.toml` for convenience (e.g., to call `siem_export` from the kernel's receipt dispatch path).

**How to avoid:** `pact-siem` depends on `pact-core` only. It opens `SqliteReceiptStore` directly by path. `pact-kernel` never references `pact-siem`. Verify with `cargo tree -p pact-kernel | grep reqwest` -- must return empty.

**Warning signs:** `cargo build -p pact-kernel` begins pulling in `hyper`, `rustls`, or `reqwest`.

### Pitfall 2: DLQ Unbounded Growth on Persistent SIEM Outage

**What goes wrong:** A long SIEM outage fills the DLQ with thousands of entries, exhausting process memory.

**Why it happens:** DLQ implemented as a `Vec` without a cap, or the cap is checked after push rather than before.

**How to avoid:** Check `inner.len() >= max_capacity` BEFORE pushing; pop_front THEN push_back. Default capacity of 1000 events is well-bounded (each event is at most ~10KB, so worst case ~10MB).

**Warning signs:** Memory growth during SIEM outage test; DLQ length monotonically increasing during integration test.

### Pitfall 3: Elasticsearch Bulk Response Partial Failures

**What goes wrong:** ES bulk API returns HTTP 200 even when some documents fail to index (e.g., mapping conflict). Code checks only HTTP status and misses per-item errors.

**Why it happens:** ES bulk API uses 200 OK for the HTTP response and embeds per-item success/failure in `response.items[].index.status`.

**How to avoid:** Always parse the bulk response body. Check `response["errors"] == true` first; if true, iterate `response["items"]` and count items where `item["index"]["status"] >= 400`. Log failures; add to DLQ if error count exceeds threshold.

**Warning signs:** Export reports success but documents never appear in the index during integration test.

### Pitfall 4: Splunk HEC 400 for Wrong Batch Format

**What goes wrong:** HEC endpoint returns 400 with `"Invalid data format"` when events are sent as a JSON array instead of newline-separated objects.

**Why it happens:** Developer uses `serde_json::to_string(&events_vec)` which produces `[{...},{...}]` instead of `{...}\n{...}`.

**How to avoid:** Serialize each event envelope separately and join with `\n`. The HEC raw endpoint (`/services/collector/raw`) accepts newline-separated strings but the event endpoint (`/services/collector/event`) expects the envelope format.

**Warning signs:** 400 response with `"Invalid data format"` in mock server test.

### Pitfall 5: Cursor Not Advancing After DLQ

**What goes wrong:** When all retries fail and events go to the DLQ, the cursor does not advance. The next poll re-fetches the same events and re-retries them indefinitely, filling the DLQ faster than it drains.

**Why it happens:** Cursor is only advanced on successful export, but DLQ'd events are not dequeued from the retry buffer.

**How to avoid:** Advance the cursor past DLQ'd events after they are queued to the DLQ. The DLQ is a separate delivery channel -- the primary stream should continue forward. Log which seq range was DLQ'd for operator visibility.

**Warning signs:** DLQ fills immediately in integration test with simulated SIEM failure; export loop stalls at same seq range.

### Pitfall 6: Blocking SQLite in Async Context

**What goes wrong:** `list_tool_receipts_after_seq` blocks the tokio thread for large batches, starving other async tasks.

**Why it happens:** `rusqlite` is synchronous; calling it directly on a tokio thread blocks the executor.

**How to avoid:** Wrap the SQLite call in `tokio::task::spawn_blocking`. With default batch size of 100 and typical receipt sizes, this is low priority (sub-millisecond for 100 rows), but becomes important under load.

**Warning signs:** Slow poll intervals observed in integration test with large receipt volumes.

---

## Code Examples

Verified patterns from project source and official SIEM API docs:

### Cursor-Pull from SqliteReceiptStore

```rust
// Source: crates/pact-kernel/src/receipt_store.rs -- list_tool_receipts_after_seq
// SqliteReceiptStore::list_tool_receipts_after_seq(after_seq: u64, limit: usize)
// Returns Vec<StoredToolReceipt> where StoredToolReceipt { seq: u64, receipt: PactReceipt }
// pact-siem opens its own connection to the SQLite file

use pact_kernel::receipt_store::{SqliteReceiptStore, StoredToolReceipt};

let store = SqliteReceiptStore::open(&db_path)?;
let batch: Vec<StoredToolReceipt> = store.list_tool_receipts_after_seq(cursor, batch_size)?;
if let Some(last) = batch.last() {
    cursor = last.seq;  // advance cursor only after successful export
}
```

### Splunk HEC Batch POST

```rust
// Source: Splunk HEC docs -- https://docs.splunk.com/Documentation/Splunk/latest/Data/HECexamples
let payload: String = events.iter()
    .map(|ev| {
        serde_json::json!({
            "time": ev.receipt.timestamp as f64,
            "sourcetype": "pact:receipt",
            "event": &ev.receipt
        })
        .to_string()
    })
    .collect::<Vec<_>>()
    .join("\n");

let response = client
    .post(format!("{}/services/collector/event", config.endpoint))
    .header("Authorization", format!("Splunk {}", config.hec_token))
    .header("Content-Type", "application/json")
    .body(payload)
    .send()
    .await?;
```

### Elasticsearch Bulk NDJSON POST

```rust
// Source: ES Bulk API -- https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
let mut body = String::new();
for ev in events {
    let action = serde_json::json!({"index": {"_index": &config.index_name, "_id": &ev.receipt.id}});
    body.push_str(&action.to_string());
    body.push('\n');
    body.push_str(&serde_json::to_string(&ev.receipt)?);
    body.push('\n');
}

let response = client
    .post(format!("{}/_bulk", config.endpoint))
    .header("Content-Type", "application/x-ndjson")
    .header("Authorization", format!("ApiKey {}", config.api_key))
    .body(body)
    .send()
    .await?;

// Check partial failure
let resp_json: serde_json::Value = response.json().await?;
if resp_json.get("errors").and_then(|e| e.as_bool()).unwrap_or(false) {
    // count per-item errors from resp_json["items"]
}
```

### Exponential Backoff Retry

```rust
// Source: project pattern -- no external crate needed for 3-retry case
const MAX_RETRIES: u32 = 3;
const BASE_BACKOFF_MS: u64 = 500;

for attempt in 0..MAX_RETRIES {
    match exporter.export_batch(&batch).await {
        Ok(_) => break,
        Err(e) => {
            if attempt == MAX_RETRIES - 1 {
                tracing::warn!("exporter {} failed after {} retries: {}", exporter.name(), MAX_RETRIES, e);
                dlq.push(FailedEvent { events: batch.clone(), error: e.to_string() });
            } else {
                let backoff = BASE_BACKOFF_MS * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }
        }
    }
}
```

### FinancialReceiptMetadata Extraction

```rust
// Source: crates/pact-core/src/receipt.rs -- FinancialReceiptMetadata, PactReceipt
// receipt.metadata is Option<serde_json::Value>; financial data is at metadata["financial"]
use pact_core::receipt::FinancialReceiptMetadata;

let financial: Option<FinancialReceiptMetadata> = receipt.metadata.as_ref()
    .and_then(|m| m.get("financial"))
    .and_then(|f| serde_json::from_value(f.clone()).ok());
```

### Integration Test with wiremock Mock Server

```rust
// Pattern for 11-03 integration tests
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, header};

let server = MockServer::start().await;
Mock::given(method("POST"))
    .and(path("/services/collector/event"))
    .and(header("Authorization", "Splunk test-token"))
    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"text": "Success", "code": 0})))
    .mount(&server)
    .await;

// ... run exporter against server.uri() ...
// assert: server received the expected number of requests
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Filesystem-backed DLQ | In-memory VecDeque with bounded capacity | Phase 11 decision | Simpler, no I/O dependencies; acceptable because pact-siem is not a durability layer |
| Push-on-write SIEM export | Cursor-pull on interval | Phase 11 design | Decouples SIEM I/O from kernel execution path; kernel has zero SIEM awareness |
| Splunk HEC raw endpoint | Splunk HEC event endpoint | -- | Event endpoint provides structured envelope with time/sourcetype; raw requires Splunk-side parsing |
| Elasticsearch `create` action | `index` action | -- | `index` is upsert -- retry-safe. `create` fails on duplicate `_id` |

**Deprecated/outdated:**
- `reqwest` 0.11 and earlier: `reqwest 0.12` uses `hyper 1.x` and is current. The workspace already has 0.12 pinned in `pact-cli`.
- `async_trait` crate: not needed for Rust >= 1.75; workspace pins 1.93, so native async-in-trait applies.

---

## Open Questions

1. **pact-siem SQLite access pattern: shared path vs trait injection**
   - What we know: `SqliteReceiptStore` is in `pact-kernel`. If pact-siem depends on pact-kernel, it violates the isolation requirement.
   - What's unclear: Should pact-siem re-expose a minimal read-only store type, or accept the SQLite file path and open its own `rusqlite::Connection` directly (without going through pact-kernel's type)?
   - Recommendation: Open a `rusqlite::Connection` directly in pact-siem using the same SQL query that `list_tool_receipts_after_seq` uses. This avoids the pact-kernel dep entirely. Duplicate the query (3 lines of SQL) -- it is stable and tested.

2. **Workspace membership vs optional feature**
   - What we know: CONTEXT.md says "feature flag gates pact-siem compilation in workspace Cargo.toml." This could mean (a) `pact-siem` is always a workspace member but gated as an optional dependency of `pact-cli`, or (b) the workspace member list itself is conditional (not standard Cargo behavior).
   - Recommendation: `pact-siem` is always in `workspace.members` (unconditional); it is an optional dep of `pact-cli` behind a `siem` feature flag. This matches standard Cargo convention and the ClawdStrike integration doc's "Make the crate optional behind a `siem` feature flag in pact-cli."

3. **reqwest version: 0.12 vs 0.13**
   - What we know: `pact-cli` currently pins `reqwest = "0.12"`. Latest on crates.io is 0.13.2.
   - What's unclear: Is there a reason to upgrade to 0.13 for this phase?
   - Recommendation: Stay on 0.12 to avoid introducing a second reqwest major version in the workspace (0.12 and 0.13 are incompatible; both would appear in the dep tree). If pact-cli upgrades reqwest separately, pact-siem follows.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (`cargo test`) |
| Config file | none -- inline `#[test]` and `#[tokio::test]` |
| Quick run command | `cargo test -p pact-siem` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| COMP-05 | Splunk HEC exporter sends correct event envelope to mock server | integration | `cargo test -p pact-siem splunk` | No -- Wave 0 |
| COMP-05 | Elasticsearch bulk exporter sends correct NDJSON to mock server | integration | `cargo test -p pact-siem elastic` | No -- Wave 0 |
| COMP-05 | FinancialReceiptMetadata present in exported event when receipt carries monetary grant | unit | `cargo test -p pact-siem financial_enrichment` | No -- Wave 0 |
| COMP-05 | DLQ bounded at max_capacity; oldest entry dropped on overflow | unit | `cargo test -p pact-siem dlq_bounded_growth` | No -- Wave 0 |
| COMP-05 | Exporter failure does not panic or block ExporterManager loop | integration | `cargo test -p pact-siem exporter_failure_isolation` | No -- Wave 0 |
| COMP-05 | Cursor advances after successful export; does not re-export same receipts | integration | `cargo test -p pact-siem cursor_advance` | No -- Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p pact-siem`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/pact-siem/src/lib.rs` -- crate root (new crate)
- [ ] `crates/pact-siem/src/event.rs` -- SiemEvent type
- [ ] `crates/pact-siem/src/exporter.rs` -- Exporter trait
- [ ] `crates/pact-siem/src/manager.rs` -- ExporterManager
- [ ] `crates/pact-siem/src/dlq.rs` -- DeadLetterQueue
- [ ] `crates/pact-siem/src/exporters/splunk.rs` -- SplunkHecExporter
- [ ] `crates/pact-siem/src/exporters/elastic.rs` -- ElasticsearchExporter
- [ ] `crates/pact-siem/Cargo.toml` -- new crate Cargo.toml
- [ ] `wiremock = "0.6"` in `pact-siem` dev-dependencies for mock SIEM endpoint tests

---

## Sources

### Primary (HIGH confidence)

- `crates/pact-kernel/src/receipt_store.rs` -- `list_tool_receipts_after_seq` signature, `StoredToolReceipt` type, SQLite schema; confirmed by reading source
- `crates/pact-core/src/receipt.rs` -- `PactReceipt`, `FinancialReceiptMetadata`, `metadata: Option<serde_json::Value>` shape; confirmed by reading source
- `docs/CLAWDSTRIKE_INTEGRATION.md` -- Section 3.4: SIEM exporter module layout (`exporter.rs`, `manager.rs`, `dlq.rs`, `event.rs`, exporters/); Section 3.4 adaptations needed; confirmed by reading source
- `11-CONTEXT.md` -- all locked decisions and discretion areas; confirmed by reading source
- `Cargo.toml` (workspace) -- `reqwest = "0.12"` already approved, `tokio`, `serde_json`, `tracing`, `thiserror` all workspace-level; confirmed by reading source
- Splunk HEC documentation -- event envelope format (`time`, `event`, `sourcetype`), batch format (newline-separated objects, not JSON array), `Authorization: Splunk <token>` header
- Elasticsearch Bulk API documentation -- NDJSON format, `index` action for upsert semantics, `_id` for idempotency, `errors` field in response body

### Secondary (MEDIUM confidence)

- `wiremock 0.6` -- mock HTTP server library for integration tests; crates.io listing confirms 0.6 is current as of March 2026

### Tertiary (LOW confidence)

- `reqwest 0.13.2` as latest crates.io version -- verified via `cargo search`; workspace stays on 0.12 intentionally

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- reqwest 0.12 already approved in pact-cli; tokio, serde_json, tracing are workspace deps
- Architecture: HIGH -- module layout directly derived from CLAWDSTRIKE_INTEGRATION.md section 3.4 plus CONTEXT.md locked decisions
- Pitfalls: HIGH -- HEC batch format, ES bulk partial failure, DLQ overflow, cursor-advance-after-DLQ are documented API behaviors and logical hazards verified against source types
- Test patterns: HIGH -- wiremock approach matches existing pact-cli test style (axum server + reqwest client); all test types are cargo test compatible

**Research date:** 2026-03-22
**Valid until:** 2026-05-22 (Splunk HEC and ES bulk APIs are stable; reqwest 0.12 API is stable)

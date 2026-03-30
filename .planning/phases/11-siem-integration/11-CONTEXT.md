# Phase 11: SIEM Integration - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

New arc-siem crate behind a feature flag with Splunk HEC and Elasticsearch bulk exporters, ExporterManager with cursor-pull from receipt store, bounded in-memory dead-letter queue, and FinancialReceiptMetadata enrichment. All SIEM I/O isolated from arc-kernel TCB -- no HTTP client dependencies in the kernel.

</domain>

<decisions>
## Implementation Decisions

### SIEM Event Format
- Events use ARC-native JSON matching ArcReceipt schema -- consumers map to their SIEM's schema
- Full receipt JSON included (not summary) -- SIEM teams want raw data for custom parsing/alerting
- FinancialReceiptMetadata nested under "financial" key when present, omitted when absent (matches existing receipt.metadata pattern)
- Event timestamp is receipt.timestamp (canonical, signed), not export time

### Exporter Architecture
- Cursor-pull from receipt store on a configurable interval -- decoupled from kernel, uses existing seq-based cursor queries
- Splunk HEC: HTTP POST to /services/collector/event with HEC token auth
- Elasticsearch bulk: POST /_bulk with index action lines (standard bulk API, highest throughput)
- Rate limiting via configurable batch size + interval per exporter, no token bucket

### Dead-Letter Queue and Reliability
- In-memory VecDeque with configurable max capacity (default 1000) -- bounded, no disk I/O
- Overflow drops oldest entries (front of queue) -- prevents unbounded growth
- Exponential backoff with max 3 retries per event before DLQ
- Failure reporting via tracing::warn on individual failures, tracing::error when DLQ is full

### Claude's Discretion
- arc-siem crate internal module organization
- Splunk HEC event field mapping details
- Elasticsearch index naming and document ID strategy
- ExporterManager polling loop implementation (tokio interval vs std thread)
- Configuration struct field names and defaults

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `arc-kernel/src/receipt_store.rs` -- SqliteReceiptStore.list_tool_receipts_after_seq for cursor-pull
- `arc-core/src/receipt.rs` -- ArcReceipt, FinancialReceiptMetadata types for event serialization
- `arc-kernel/src/receipt_query.rs` -- ReceiptQuery and cursor pagination patterns

### Established Patterns
- Feature flags via Cargo.toml `[features]` section
- SQLite stores use seq-based delta queries for cursor-pull
- All signed payloads use canonical JSON (RFC 8785)
- Crate isolation: kernel has no HTTP client deps

### Integration Points
- ExporterManager reads from SqliteReceiptStore via list_tool_receipts_after_seq (existing method)
- arc-siem depends on arc-core (for receipt types) but NOT arc-kernel (isolation requirement)
- Feature flag gates arc-siem compilation in workspace Cargo.toml

</code_context>

<specifics>
## Specific Ideas

- Reference docs/CLAWDSTRIKE_INTEGRATION.md for SIEM exporter port strategy (ClawdStrike has 6 exporters)
- Only Splunk HEC and Elasticsearch bulk are in scope for this phase (2 of 6)
- The arc-kernel TCB isolation requirement is a hard gate -- verify no reqwest/hyper in arc-kernel deps
- Phase 10's receipt query API provides the cursor-pull foundation

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>

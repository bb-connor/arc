# chio-siem

chio-siem forwards Chio kernel receipts to external SIEM, alerting, and
audit-export backends. It polls the kernel's receipt database through
`chio-kernel`'s read-only, admin-scoped boundary, wraps each row as a
`SiemEvent` that recomputes its own verification state, and fans batches out
to pluggable `Exporter` backends with retry, rate limiting, and a dead-letter
queue. The dependency on `chio-kernel` is one-directional, so the SIEM
HTTP-client surface stays out of the kernel TCB.

## Responsibilities

- Poll `chio_tool_receipts` on a `seq` cursor, requiring an explicit
  `ReceiptReadContext` with `ReceiptReadBoundary::AdminAll`; a tenant-scoped
  context is rejected before the database opens.
- Wrap each row as a `SiemEvent`, independently reverifying receipt id,
  signature, and parameter hash and checking signer trust, so authorization is
  never taken on the embedded `decision`'s say-so.
- Format ordinary sink payloads from one closed `SiemSinkProjection`. Arguments,
  denial/cancellation text, evidence, actor chains and arbitrary metadata never
  enter these payloads. Freeform capability, tool, tenant and guard identifiers
  become fixed SHA-256 references.
- Fan batches out to every registered `Exporter` with exponential-backoff
  retry, and dead-letter events that exhaust retry.
- Persist a per-exporter high-water mark in a SIEM-owned `SiemCursorStore`
  when configured, so delivery is at-least-once: the read cursor holds at the
  slowest acknowledged exporter and a failing exporter forces redelivery
  instead of a silent skip.
- Ship eight `Exporter` backends: Splunk HEC, Elasticsearch bulk, Datadog
  Logs, Sumo Logic, OCSF over HTTPS, CEF text formatting, a generic HTTPS
  webhook, and PagerDuty/OpsGenie alerting.
- Derive a five-level `AlertSeverity` from receipt decision and guard
  evidence, keeping alert-dispatch accounting separate from SOC export
  accounting via `Exporter::is_soc_export_sink`.
- Enforce `https://` and a typed `HttpEgressContract` on every outbound
  exporter endpoint, and redact error text before it reaches operator logs.

## Public API

Core pipeline:

- `manager::{ExporterManager, SiemConfig, SiemError}` - construct with
  `SiemConfig`, register exporters via `add_exporter`, drive with `run(cancel)`.
- `event::SiemEvent` - a `ChioReceipt` plus verification flags
  (`authoritative`, `signature_valid`, `receipt_id_valid`,
  `parameter_hash_valid`, `signer_trusted`, `authorized`) and extracted
  `FinancialReceiptMetadata`.
- `sink_projection::SiemSinkProjection` - the Serialize-only ordinary export
  contract, built with `SiemEvent::sink_projection()`. Its private fields cannot
  be filled from external JSON. Source verification is recomputed against the
  original receipt and privately owned signer pins. Public event annotations
  and deserialized event fields cannot supply signer trust.
- `exporter::{Exporter, ExportError, ExportFuture}` - the async,
  dyn-compatible backend trait.
- `cursor_store::SiemCursorStore` - per-exporter `acked_seq` and durably
  captured malformed rows.
- `dlq::{DeadLetterQueue, FailedEvent}` - bounded, drop-oldest
  retry-exhausted queue.
- `ratelimit::{ExportRateLimiter, RateLimitConfig, RateLimitConfigError}` -
  per-exporter token-bucket batch rate limiting.
- `metrics_sink::{SiemMetricsSink, ExportOutcome, NoopMetricsSink,
  noop_metrics_sink}` - metric emission seam; defaults to no-op.
- `alerting::{AlertingExporter, AlertingConfig, AlertBackend,
  PagerDutyBackend, OpsGenieBackend, Alert, AlertSeverity, derive_severity,
  derive_event_severity}`.
- `ocsf::receipt_to_ocsf` - stateless OCSF 1.3.0 Authorization mapping
  (`ocsf::siem_event_to_ocsf` for events with privately owned signer pins).

Exporters (all implement `Exporter`):

| Module | Type | Backend |
|--------|------|---------|
| `exporters::splunk` | `SplunkHecExporter` | Splunk HTTP Event Collector |
| `exporters::elastic` | `ElasticsearchExporter` | Elasticsearch `_bulk` API |
| `exporters::datadog` | `DatadogExporter` | Datadog Log Intake v2 API |
| `exporters::sumo_logic` | `SumoLogicExporter` | Sumo Logic HTTP Source |
| `exporters::ocsf_exporter` | `OcsfExporter` | OCSF 1.3.0 JSON array or NDJSON over HTTPS |
| `exporters::cef` | `CefExporter` | CEF v0 text formatting (no transport of its own) |
| `exporters::webhook` | `WebhookExporter` | generic HTTPS JSON POST/PUT; `from_endpoint` is the production SOC-sink constructor |
| `alerting` | `AlertingExporter` | PagerDuty / OpsGenie paging, gated by `AlertSeverity` |

## Ordinary payload contract

Every built-in ordinary exporter and the retry-exhausted event DLQ use the same
projection. OCSF has no `raw_data`, request `data`, denial `status_detail` or guard
evidence enrichments. Splunk, Elasticsearch, Datadog, Sumo Logic and webhook
payloads carry the unsigned projection; CEF renders its bounded fields. Pager
summaries, tags and deduplication keys also use hashed identifiers while
preserving their independently pinned receipt verification before dispatch.

The allowlist is fixed:

- Schema/projection/signature-scope labels and payload absence markers are
  constants. `payload_included=false`, `original_retrieval_required=true` and
  `projection_signed=false` describe the export, not a mutation of the receipt.
- Canonical receipt IDs and parameter/policy/content commitments are exactly 64
  lowercase hex characters or absent. An invalid receipt ID is absent; a
  SHA-256 reference remains for diagnostic correlation. Arbitrary capability,
  tool-server, tool-name, tenant, guard and signer references are always hashed
  to 64 lowercase hex characters.
- Receipt kind, boundary, observation outcome, tool origin, trust level and
  source redaction mode are closed enums. Results and decision/severity labels
  come from fixed mappings. Verification and authorization fields are booleans
  about the original receipt. Timestamps and financial amounts are `u64`;
  grant index and delegation depth are `u32`.
- Optional financial output contains only grant index, charged/attempted cost,
  remaining/total budget and delegation depth. Null uncapped budgets remain
  null. Currency, payer/holder/payment references, breakdowns and oracle evidence
  are excluded. Numeric amounts without currency are diagnostic values and
  cannot establish currency-aware totals or settlement authority.

These exports contain no receipt signature and cannot independently authenticate
the projection. Use the canonical receipt ID to retrieve the untouched original
through an authorized evidence read, then authenticate its original body with
independent signer trust. The source receipt database and malformed-row durable
dead letters can still retain payloads. This sink repair does not establish
receipt/request retention, erasure, checkpoint inclusion, production delivery or
operational acceptance. Custom exporters must use `sink_projection()` for
ordinary delivery; full evidence export requires a separate authorized contract.

## Testing

`cargo test -p chio-siem`

Integration test files (`splunk_export`, `elastic_export`,
`datadog_export`, `sumo_logic_export`, `webhook_export`, `alerting_dispatch`,
`ocsf_mapping`, `sink_payload_privacy`) bind a local `wiremock` server; in a sandbox that denies
local TCP bind, treat their failure as environment-blocked rather than a
regression. `tests/at_least_once.rs` property-tests the cursor high-water
mark against random exporter outage patterns.

## See also

- `chio-core-types` - defines `ChioReceipt`, `Decision`, and
  `FinancialReceiptMetadata`, the source receipt shape this crate reads.
- `chio-kernel` - owns the receipt database this crate polls read-only and
  supplies `ReceiptReadContext`.
- `chio-egress-contract` - the `HttpEgressContract` every network exporter
  enforces before dispatch.
- `chio-log-redact` - redacts exporter error text before it reaches operator
  logs.
- `chio-wall` - CLI that wires `WebhookExporter::from_endpoint` and a
  registry-backed `SiemMetricsSink` into its `siem-export` command.

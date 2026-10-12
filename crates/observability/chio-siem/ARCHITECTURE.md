# chio-siem architecture

## Responsibility and boundary

`ExporterManager` owns a read-only SQLite connection to `chio_tool_receipts`,
registered `Exporter` objects, polling state, rate limiting, and an in-memory
failure queue. An optional `SiemCursorStore` owns a separate writable database.
The manager validates an admin receipt-read context but performs its own SQL
reads; it does not call the kernel's receipt-query API. It neither mediates tool
execution nor signs exported projections.

`SiemEvent` retains the complete original receipt for evidence consumers.
`SiemSinkProjection` is the ordinary export boundary: constructors and fields are
restricted, and serialization produces an unsigned reference to the original.
Custom `Exporter` implementations receive full events and must choose an
appropriate disclosure contract themselves.

## Structure

| Module | Responsibility |
| --- | --- |
| `manager` | Polling, retries, cursor advancement, exporter fan-out, metric calls |
| `event` | Original receipt, descriptive caches, privately owned signer pin |
| `sink_projection` | Closed payload schema and fresh source verification |
| `cursor_store` | Monotonic progress rows and malformed-row capture |
| `dlq` | Drop-oldest queue of failed projection JSON and diagnostic errors |
| `ratelimit` | Token buckets keyed by exporter name, one token per attempt |
| `exporter` | Dyn-compatible `Exporter` and `ExportError` contracts |
| `exporters` | Splunk, Elastic, Datadog, Sumo, webhook, OCSF, and CEF adapters |
| `ocsf` | OCSF 1.3.0 Authorization-class mapping from the closed view |
| `alerting` | Severity/filter rules, private notification projection, paging |
| `metrics_sink` | Host-installed instrumentation seam with a no-op default |
| `redaction` | Operator error formatting through `chio-log-redact` |

## Data and control flow

Construction rejects zero batch size, zero polling interval, tenant-scoped read
contexts, and invalid optional rate limits before opening the source read-only.
`run` waits on a Tokio interval and a watch cancellation channel. Each poll reads
`seq > cursor` in ascending order with a row-count limit, then releases the
connection mutex before awaiting any exporter. The row limit does not bound the
byte length of each stored JSON receipt.

Parsed receipts become events with operator-configured trusted signer keys.
Malformed rows go to `siem_dead_letters` when a cursor database is configured;
persistence must succeed before that row is skipped. The in-memory malformed
entry contains its sequence marker, while the durable table keeps raw JSON.
Capture is idempotent by source sequence.

The manager awaits exporters sequentially. It retries failed batches up to
`max_retries` after the initial attempt, with doubling delays capped at 60 seconds.
Rate limiting applies to each attempt and shares a bucket among equal exporter
names. A successful count is interpreted as an accepted prefix; a short count
leaves its tail unacknowledged in persistent cursor mode. `PartialFailure` errors
retain the entire batch for retry, so previously accepted events can repeat.

With `cursor_db_path`, acknowledged progress is stored under
`Exporter::cursor_identity()`, and the read cursor follows the slowest registered
identity. New identities start at zero. The trait default uses the bare exporter
name; only the built-in webhook overrides it with a sanitized endpoint. Callers
must distinguish multiple destinations that otherwise share the same identity.
With no cursor database, polling advances past failures and restart begins at
zero. Downstream duplicate handling remains specific to the collector.

`CefExporter::export_batch` counts formatted lines without transmitting them.
`OcsfExporter` similarly counts formatting when its endpoint is empty. These
counts can advance manager progress, so registering a formatter is not a
transport acknowledgment. HTTP exporters check their own response status/body;
Elasticsearch uses receipt references as document IDs, while Splunk checks HEC
response codes and invalid-event markers.

## Trust and invariants

`SourceVerification::new` recomputes the content-addressed receipt ID, verifies
its signature and action parameter hash, and compares the signer with the
independently accepted pin. `is_authorized` and `sink_projection` repeat these
checks against the current receipt. Pins are skipped during event serialization,
so deserialized annotations cannot introduce signer trust. An authorization label
also requires coherent mediated allow semantics at a prevent boundary.

The projection carries SHA-256 references for freeform identities, well-formed
commitments where available, closed enums, numeric financial fields, and flags.
It omits signatures, payload parameters, evidence details, freeform outcome
reasons, actor chains, and arbitrary metadata. The `authoritative` flag describes
source ID/signature/parameter verification; signer trust is a separate flag.
Numeric financial amounts omit currency and cannot support currency-aware totals.
Original receipt retrieval, content-preimage verification, checkpoint inclusion,
and independent signer trust remain responsibilities of evidence consumers.

Production network constructors require HTTPS destinations and typed
`HttpEgressContract` dispatch through `send_with_contract`. Explicit test
constructors enable local mock transport. Operator errors use pattern-based log
redaction. Full source receipts and durable malformed rows retain their original
content; sink minimization does not erase those stores.

`AlertingExporter::should_alert` independently verifies pinned source receipts,
requires a deny decision, and applies guard/severity filters. The default
threshold is High; no pins or backends means no paging. Alert dispatch has its
own metric calls and is excluded from SOC metric/DLQ accounting, but remains a
registered exporter in cursor coordination. Both manager and alerting metrics
are inactive until the host installs `SiemMetricsSink` implementations.

## Dependencies

`chio-core` is a Cargo alias for `chio-core-types`, supplying receipt semantics,
crypto verification, and financial metadata. `chio-kernel` supplies read-context
types. `rusqlite` handles source reads and cursor writes; `tokio` supplies timers,
watch cancellation, and async transport execution. `reqwest`, `url`, and
`chio-egress-contract` implement bounded destination dispatch. `serde_json`
provides backend payloads, `chio-log-redact` formats diagnostic text, and
`zeroize` protects selected owned credentials. The manifest declares no features.

## Verification

Run `cargo test -p chio-siem`. `manager_integration.rs` exercises polling,
retry, failure isolation, and rate limiting against fixture databases.
`manager.rs` unit tests cover missing cursors, identity separation, short
acknowledgments, and malformed-row metric attribution. `at_least_once.rs` tests
cursor-store reopening and models cursor progress under generated outages.

`sink_payload_privacy.rs` checks real manager-to-sink payloads and adversarial
cached flags, deserialization, and receipt replacement. `cef_emitter.rs` checks
its golden text. Backend test files use local `wiremock` servers for request
shape, response errors, authentication, timeout, and retry behavior.
`alerting_dispatch/authentication.rs` checks dispatch signer enforcement.
These network tests require local TCP binding; collector retention and host
configuration require separate operational verification.

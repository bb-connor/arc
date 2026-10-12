# chio-wall architecture

## Responsibility and boundary

`chio-wall` is a binary-only crate with three command paths: `control-path export`,
`control-path validate`, and `siem-export`. Its package path constructs one fixed
research-to-execution denied-access scenario. Its serve path reads an existing
receipt database and forwards events to operator-configured consumers.
`chio-wall-core` owns the artifact schemas; this binary owns command orchestration,
local guard evaluation, evidence construction, package files, and SIEM lifecycle.

The package path calls `McpToolGuard::is_allowed` directly and signs a receipt
itself. It does not invoke `ChioKernel` or dispatch the named execution tool.
Generated issuer, subject, and kernel keys and fixed capability/receipt timestamps
make this an offline scenario export. A production barrier needs capabilities,
guards, signed receipts, and custody from its real runtime boundary.

## Structure

- `src/main.rs` defines Clap commands, global `--json`, and dispatch.
- `src/commands.rs` builds the scenario, validates package joins, writes reports,
  configures SIEM consumers, starts the watchdog, and owns shutdown.
- `src/commands/evidence.rs` stages a temporary receipt DB and calls shared
  evidence export. `commands/siem_pins.rs` validates independent signer pins.
- `src/metrics_server.rs` exposes a minimal HTTP/1.1 scrape listener.
- `src/registry_metrics_sink.rs` implements `SiemMetricsSink` using the process
  metric registry. It connects real exporter outcomes and alert dispatches to
  SOC, lag, dead-letter, and alert families.
- `tests/cli.rs` runs the built binary and inspects package outputs.

## Offline package flow

`export_control_path` requires an empty output directory. It builds the control
profile, research tool allowlist, authorization context, guard outcome, and denied
access record, then runs each core validator. The scenario requests
`execution_oms.submit_order`, which is outside the research allowlist.
The guard configuration enables allowlist enforcement with a block default.
`build_denied_access_record` refuses an allowed outcome.

`write_chio_evidence_package` creates its SQLite staging database in a separate
`tempfile::tempdir`, keeping it outside the exported package. It generates keys,
signs a capability and receipt, appends the receipt, builds a checkpoint over
canonical stored bytes, and invokes `chio-control-plane` evidence export.
The receipt hashes canonical scenario metadata and the policy snapshot, and
binds parameters through `ToolCallAction::from_parameters`.

The package adds buyer-review and control-package JSON, then a summary.
`verify_control_path_export` reopens each JSON artifact and calls core validation.
It compares workflow, request, domain, tool and policy references across the
participating artifacts and checks package references against fixed filenames.
It rejects unexpected top-level entries and requires eight JSON files plus
nonempty `chio-evidence/`. That directory check does not recursively verify
receipt signatures or checkpoint authenticity.

`control-path validate` starts with its own empty output directory, exports
under `control-path/`, and writes `validation-report.json` plus
`expansion-decision.json`. Its report carries the built-in decision value
`proceed_chio_wall_only`. It accepts no existing package or custom policy input.
File output is sequential; a failure can leave a partial directory requiring
operator cleanup before retry. The command rejects existing symlink output
roots, but callers still own parent-path custody and concurrent filesystem access.

## SIEM serve flow and network requirements

`cmd_chio_wall_siem_export` creates a Tokio runtime. Serve configuration opens
the source receipt database read-only and supplies a separate writable cursor
store to `ExporterManager`. The manager persists per-exporter high-water marks.
The CLI currently constructs the generic webhook SOC consumer from
`CHIO_SIEM_WEBHOOK_URL` and its optional bearer token. Endpoint validation builds
a contracted HTTPS client; actual delivery requires network access and a receiver.

PagerDuty and OpsGenie run only when their routing key or API key is configured.
Their optional endpoint variables override HTTPS defaults. Alerting is a
notification overlay beside the SOC consumer. `ensure_serve_has_consumer`
refuses zero SOC consumers and alerting-only configuration before polling starts.

Manager defaults poll every 5 seconds, process batches of 100, and retry three
times with a 500-millisecond exponential base. The webhook also has its own
30-second request timeout and two retries with a 250-millisecond base.
Retries and persisted cursors provide at-least-once delivery, so receivers must
handle duplicates. Exhausted exports enter the manager's dead-letter queue;
operator monitoring must observe delivery and queue health.

Serve starts a receipt-health watchdog and scrape listener, then runs the
manager until Ctrl-C. Cancellation drains the manager, watchdog, and listener.
Watchdog sampling uses a read-only open and reports failures without creating
an absent receipt database. Scrape bind failure logs and export continues.

## Trust and listener invariants

`commands/siem_pins.rs` reads `CHIO_SIEM_TRUSTED_KERNEL_KEYS` as a JSON array of
1 through 64 unique public-key strings, bounded at 1 MiB. It rejects malformed
encoding, weak Ed25519 identities, normalized duplicates, and non-Unicode values.
Paging requires pins supplied independently by the operator. SOC-only mode may
omit pins; explicit invalid configuration still rejects startup. Algorithm-aware
wire formats are accepted subject to the verifier's compiled algorithm support.
The same pins reach ingestion configuration and the alerting exporter.

`build_serve_alerting_exporter` installs both the metric sink and independent
pins. Alert dispatch validates the original receipt through the SIEM library;
changing event annotations cannot grant signer authority. No active kernel
signer is discovered automatically from receipt data.

The scrape address defaults to `127.0.0.1:9090` and can be overridden with
`CHIO_SIEM_METRICS_ADDR`. It serves plain HTTP without TLS or authentication,
recognizes `GET /metrics`, and returns 404 for other methods and paths. Request
line collection is bounded at 2 KiB and handles fragmented socket reads. The
listener starts one task per connection with no per-connection deadline, so
network exposure and connection limits must be supplied by deployment policy.
Metrics preregistration seeds configured consumers and a disabled alert sentinel
so quiet operation produces observable zero-valued series.

## Dependencies and verification

`chio-wall-core` supplies artifact validation, `chio-guards` supplies the tool
allowlist evaluator, and `chio-core` supplies canonical hashes, capability and
receipt signing. `chio-store-sqlite` and `chio-control-plane` provide staging,
checkpoints, and shared evidence export. `chio-siem` supplies receipt ingestion,
consumer retries, alert backends, and cursor persistence. Tokio owns sockets,
cancellation and serve tasks; Clap parses the binary interface.

`cargo test -p chio-wall` runs embedded unit tests and CLI integration tests.
Package tests cover allowed/denied guard outcomes, occupied and symlink roots,
missing and unexpected artifacts, and staging isolation. Serve tests exercise
SOC-consumer gates, pins, a captured no-network exporter, alert metrics, read-only
watchdog behavior, and local socket scrapes including fragmented request lines.
These tests exercise implementation paths with local fixtures. Production
acceptance additionally needs deployed receipt/cursor custody, configured remote
receivers, independently pinned signers, and monitored listener access.

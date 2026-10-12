# chio-wall

`chio-wall` exports a fixed Chio-Wall control-path package and runs SIEM export
against a receipt database. The package describes one research agent denied
access to `execution_oms.submit_order`. Typed artifacts live in `chio-wall-core`;
this binary owns guard evaluation, signing, file reconciliation, and serve wiring.

## Usage

From the workspace root, export the built-in scenario into a temporary directory:

```sh
wall_output=$(mktemp -d "${TMPDIR:-/tmp}/chio-wall-docs.XXXXXX")
trap 'rm -rf "$wall_output"' EXIT
cargo run -p chio-wall -- --json control-path export --output "$wall_output"
```

This command needs a writable temporary filesystem and local SQLite support.
It opens no listener, contacts no upstream, and dispatches no tool. The output
contains eight JSON files and `chio-evidence/`, with a receipt and checkpoint
built using generated keys. `McpToolGuard::is_allowed` evaluates the fixed
allowlist; evidence signing is performed directly by the CLI. These generated
artifacts describe the scenario, with no live kernel invocation.

| Command | Required flags | Behavior |
| --- | --- | --- |
| `control-path export` | `--output <empty-dir>` | Writes and reconciles the scenario package. |
| `control-path validate` | `--output <empty-dir>` | Exports under `control-path/` and writes validation and decision JSON. |
| `siem-export` | `--receipt-db <path> --cursor-db <path>` | Polls receipts and delivers them to configured consumers until interrupted. |

Global `--json` controls the two package commands' stdout. `control-path validate`
generates its own package; it takes no existing package as input.

## Guarantees

`ensure_empty_directory` refuses occupied or symlink output directories.
`verify_control_path_export` re-reads artifacts, runs core validation, compares
workflow/request/domain/tool/policy joins and references, and rejects unexpected
top-level entries. Its evidence-directory check establishes presence and
nonemptiness; independent receipt/checkpoint verification remains a consumer duty.

`siem-export` opens the source receipt DB read-only and persists per-exporter
cursors in the separate writable cursor DB. Startup requires a SOC sink;
alerting alone cannot satisfy `ensure_serve_has_consumer`. The current CLI wires
a generic HTTPS webhook, with optional PagerDuty and OpsGenie notification
backends. Delivery follows the manager's at-least-once retry semantics.

## Serve configuration

| Environment variable | Effect |
| --- | --- |
| `CHIO_SIEM_WEBHOOK_URL` | HTTPS endpoint for the required SOC webhook consumer. |
| `CHIO_SIEM_WEBHOOK_BEARER_TOKEN` | Optional webhook authentication secret. |
| `CHIO_SIEM_ALERT_PAGERDUTY_ROUTING_KEY`, `CHIO_SIEM_ALERT_PAGERDUTY_ENDPOINT` | Enable PagerDuty and optionally override its endpoint. |
| `CHIO_SIEM_ALERT_OPSGENIE_API_KEY`, `CHIO_SIEM_ALERT_OPSGENIE_ENDPOINT` | Enable OpsGenie and optionally override its endpoint. |
| `CHIO_SIEM_TRUSTED_KERNEL_KEYS` | JSON array of independent signer pins, required when paging is enabled. |
| `CHIO_SIEM_METRICS_ADDR` | Plain HTTP scrape address, default `127.0.0.1:9090`. |

Signer configuration accepts 1 through 64 unique algorithm-aware public keys
within 1 MiB. Invalid explicit configuration rejects SOC-only startup too;
unset pins are allowed for SOC-only export. Pins must come from operator custody.
Algorithm support follows the compiled verifier. The metrics listener has no
TLS or authentication; deployment networking must control access when rebinding.
A scrape bind failure logs and leaves the export loop running.

## Status

Package generation, local validation, webhook export, paging configuration, and
metrics wiring are implemented. Tests exercise artifact reconciliation, the CLI,
local scrape sockets, exporter wiring, and signer rejection. The offline scenario
uses generated identities and fixed receipt timestamps. Production operation
requires a real receipt source, durable cursor custody, receiver configuration,
independent paging pins, and deployment monitoring.

## Related

- [Architecture](ARCHITECTURE.md)
- [Core artifact contracts](../chio-wall-core/README.md)
- [SIEM exporters](../../observability/chio-siem/README.md)
- [Protocol receipts](../../../spec/PROTOCOL.md#http-and-openapi-surfaces)
- [Wall operations](../../../docs/chio-wall/OPERATIONS.md)

License: [root license](../../../LICENSE).

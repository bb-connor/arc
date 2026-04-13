# Summary 275-02

Phase `275-02` closed the remaining exporter-facing SIEM test gaps without
duplicating the coverage the crate already had:

- [splunk_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-siem/tests/splunk_export.rs) now covers the missing `400 Bad Request` and `503 Service Unavailable` paths in addition to the existing `200` success, `401` rejection, and envelope-format checks
- Existing [elastic_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-siem/tests/elastic_export.rs) and [dlq_bounded.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-siem/tests/dlq_bounded.rs) coverage was kept as acceptance evidence for the already-shipped NDJSON, partial-success, and DLQ-boundary behavior required by phase 275
- The SIEM guides in [SIEM_INTEGRATION_GUIDE.md](/Users/connor/Medica/backbay/standalone/arc/docs/SIEM_INTEGRATION_GUIDE.md) and [MIGRATION_GUIDE_V2.md](/Users/connor/Medica/backbay/standalone/arc/docs/MIGRATION_GUIDE_V2.md) now reflect the new `SiemConfig.rate_limit` surface and the actual `SplunkHecExporter` configuration API

Verification:

- `cargo test -p arc-siem --test splunk_export -- --nocapture`
- `cargo test -p arc-siem --test elastic_export -- --nocapture`
- `cargo test -p arc-siem --test dlq_bounded -- --nocapture`
- `cargo test -p arc-siem -- --nocapture`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/275-arc-siem-unit-tests/275-02-PLAN.md`

# Phase 275 Context

## Goal

Close the real `arc-siem` coverage gaps so crate-owned tests catch exporter and
manager regressions before CI, including the missing per-exporter throttling
surface promised by the milestone requirements.

## Code Surface

- `crates/arc-siem/src/exporters/splunk.rs` implements Splunk HEC export using
  newline-delimited event envelopes and fail-closed HTTP status handling
- `crates/arc-siem/src/exporters/elastic.rs` implements Elasticsearch bulk
  export using NDJSON plus bulk-response partial-failure parsing
- `crates/arc-siem/src/manager.rs` owns the cursor-pull loop, exponential
  retry, exporter fan-out, and dead-letter queue handoff
- `crates/arc-siem/src/dlq.rs` and `crates/arc-siem/src/event.rs` define the
  failed-event queue and receipt-derived event model used by the manager

## Existing Tests

- `crates/arc-siem/tests/splunk_export.rs` already covers:
  correct envelope formatting, HTTPS-only construction, and `401` handling
- `crates/arc-siem/tests/elastic_export.rs` already covers:
  valid NDJSON payloads, financial metadata passthrough, and bulk partial
  failure detection
- `crates/arc-siem/tests/dlq_bounded.rs` already covers:
  bounded-growth and overflow behavior for the dead-letter queue
- `crates/arc-siem/tests/manager_integration.rs` already covers:
  cursor advancement, DLQ isolation, and restart behavior after DLQ events

## Important Constraint

Phase 275 is not a greenfield test build-out. Most of `TEST-09` and the core of
`TEST-10` already exist. The real gaps are narrower:

- Splunk response handling still lacks explicit `400` and `503` coverage
- manager coverage does not yet prove successful retry after a transient
  exporter failure
- the roadmap and original ARC SIEM design both require per-exporter rate
  limiting, but the shipped crate never landed `src/ratelimit.rs` or any
  `SiemConfig` knob for that behavior

Because `TEST-11` is explicit and the code surface is missing, phase 275 should
add the bounded rate-limiter implementation and cover it directly rather than
pretend the current retry loop is sufficient.

## Requirement Mapping

- `TEST-08`: extend Splunk HEC coverage to assert `200`, `400`, and `503`
  handling at the exporter boundary
- `TEST-09`: preserve and re-verify the existing Elasticsearch NDJSON and
  partial-success coverage without duplicating tests unnecessarily
- `TEST-10`: prove failed exports can still be retried successfully before DLQ,
  and that exhausted failures remain inspectable through the existing DLQ path
- `TEST-11`: add and cover per-exporter throttling that delays burst export
  attempts without silently dropping receipts

## Execution Direction

- Add a small crate-owned rate-limiter module that the manager can apply per
  exporter before each batch attempt
- Expand manager integration tests to cover transient retry success and
  throttled burst export without loss
- Keep Splunk additions focused on the missing response-code cases
- Reuse the existing Elasticsearch and DLQ tests as acceptance evidence where
  they already satisfy the requirement

## Files Likely In Scope

- `crates/arc-siem/src/lib.rs`
- `crates/arc-siem/src/manager.rs`
- `crates/arc-siem/src/ratelimit.rs`
- `crates/arc-siem/tests/manager_integration.rs`
- `crates/arc-siem/tests/splunk_export.rs`
- `docs/SIEM_INTEGRATION_GUIDE.md`
- `docs/MIGRATION_GUIDE_V2.md`

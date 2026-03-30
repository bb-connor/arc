---
phase: 11-siem-integration
plan: "02"
subsystem: arc-siem
tags: [siem, exporter, splunk-hec, elasticsearch-bulk, reqwest, ndjson, kernel-isolation]
dependency_graph:
  requires: [arc-core, arc-siem/exporter.rs (Exporter trait from 11-01)]
  provides: [SplunkHecExporter, ElasticsearchExporter, SplunkConfig, ElasticConfig, ElasticAuthConfig]
  affects: [crates/arc-siem/src/exporters/mod.rs, crates/arc-siem/src/lib.rs]
tech_stack:
  added: []
  patterns: [newline-separated JSON envelopes for Splunk HEC, NDJSON action+document pairs for ES bulk, reqwest::RequestBuilder::basic_auth for no-base64 Basic auth, bulk response body parsing for ES partial failure detection]
key_files:
  created:
    - crates/arc-siem/src/exporters/splunk.rs
    - crates/arc-siem/src/exporters/elastic.rs
  modified:
    - crates/arc-siem/src/exporters/mod.rs (added pub mod splunk; pub mod elastic;)
    - crates/arc-siem/src/lib.rs (re-exported SplunkHecExporter, SplunkConfig, ElasticsearchExporter, ElasticConfig, ElasticAuthConfig)
decisions:
  - SplunkConfig.sourcetype defaults to "arc:receipt" -- allows Splunk teams to write sourcetype-based searches without per-event config
  - ElasticAuthConfig is an enum (ApiKey vs Basic) rather than optional fields -- makes invalid states unrepresentable at the type level
  - ES partial failure detection iterates items array only when errors field is true -- avoids JSON traversal on the happy path
  - reqwest::RequestBuilder::basic_auth used for Basic auth -- no base64 crate needed, reqwest handles encoding internally
metrics:
  duration_seconds: 420
  completed_date: "2026-03-22"
  tasks_completed: 2
  files_created: 2
  files_modified: 2
---

# Phase 11 Plan 02: Splunk and Elasticsearch Exporters Summary

**One-liner:** SplunkHecExporter (newline-separated JSON envelopes to /services/collector/event) and ElasticsearchExporter (NDJSON /_bulk with receipt.id as _id and partial failure detection from bulk response body), both implementing the Exporter trait.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Implement SplunkHecExporter | 24bbc8b | exporters/splunk.rs, exporters/mod.rs, lib.rs |
| 2 | Implement ElasticsearchExporter | be7b700 | exporters/elastic.rs |

## Verification Results

1. `cargo build -p arc-siem` -- PASS
2. `cargo clippy -p arc-siem -- -D warnings` -- PASS (no warnings)
3. Both SplunkHecExporter and ElasticsearchExporter re-exported from lib.rs -- PASS
4. `cargo tree -p arc-kernel | grep reqwest` -- PASS (empty -- kernel isolation verified)

## Key Decisions

### SplunkConfig: enum-style optional fields

**Context:** index and host are optional Splunk fields. Options vs flattened config.

**Decision:** Use `Option<String>` for index and host. Fields present in SplunkConfig default to None; only added to envelope JSON when Some. This keeps the config struct simple and explicit.

### ElasticAuthConfig enum

**Context:** Elasticsearch supports API key auth and HTTP Basic auth. Options included: two separate fields, a string enum, or a Rust enum.

**Decision:** Use a `#[derive(Debug, Clone)] pub enum ElasticAuthConfig` with `ApiKey(String)` and `Basic { username: String, password: String }` variants. This makes invalid states (no auth, both auths) unrepresentable at compile time, and the match arm in export_batch makes each auth path explicit.

### ES partial failure detection on happy path

**Context:** Elasticsearch bulk API returns HTTP 200 even when some documents fail to index. The `errors` field in the response body is false when all succeed.

**Decision:** Check `response["errors"].as_bool()` first -- only iterate `response["items"]` when errors is true. On the happy path (all 200), no item-level traversal occurs. When errors is true, count items where `item["index"]["status"] >= 400` and return ExportError::PartialFailure with succeeded/failed counts and the first error reason.

### reqwest basic_auth vs manual base64

**Context:** HTTP Basic auth requires base64-encoded `username:password`. Options: use a base64 crate, or use reqwest's built-in.

**Decision:** Use `reqwest::RequestBuilder::basic_auth(username, Some(password))`. reqwest handles the encoding internally -- no additional dependency needed.

## Deviations from Plan

None -- plan executed exactly as written.

## Self-Check: PASSED

- `crates/arc-siem/src/exporters/splunk.rs` -- EXISTS
- `crates/arc-siem/src/exporters/elastic.rs` -- EXISTS
- Task 1 commit 24bbc8b -- VERIFIED (git log)
- Task 2 commit be7b700 -- VERIFIED (git log)

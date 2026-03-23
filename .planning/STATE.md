---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Agent Economy Foundation
status: planning
stopped_at: Completed 12-02-PLAN.md (agent-centric receipt query and lineage HTTP endpoints)
last_updated: "2026-03-23T02:28:30.015Z"
last_activity: 2026-03-21 -- v2.0 roadmap written, 22 requirements mapped to 6 phases
progress:
  total_phases: 6
  completed_phases: 5
  total_plans: 19
  completed_plans: 18
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-21)

**Core value:** PACT must provide deterministic, least-privilege agent access with auditable outcomes, and produce cryptographic proof artifacts that enable economic metering, regulatory compliance, and agent reputation.
**Current focus:** Milestone v2.0 -- Phase 7: Schema Compatibility and Monetary Foundation

## Current Position

Phase: 7 of 12 (Schema Compatibility and Monetary Foundation)
Plan: -- (not started)
Status: Ready to plan
Last activity: 2026-03-21 -- v2.0 roadmap written, 22 requirements mapped to 6 phases

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0: Starting (0/20 plans)

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- 2026-03-21: deny_unknown_fields removal (SCHEMA-01) is Phase 7 hard gate -- no new wire fields before this ships
- 2026-03-21: Monetary types (SCHEMA-02, SCHEMA-03) ship in same phase as schema migration
- 2026-03-21: Monetary enforcement, Merkle, and velocity guard parallelize in Phase 8 after schema gate
- 2026-03-21: Compliance documents (COMP-01, COMP-02) must reference passing test artifacts -- not planned features
- 2026-03-21: DPoP proof message is PACT-native (capability_id + tool_server + tool_name + arg_hash + nonce), not HTTP-shaped
- [Phase 07]: Removed all 18 deny_unknown_fields annotations: serde silent-ignore is the correct v2.0 wire posture for pact-core types
- [Phase 07]: Forward-compat tests use serde_json::Value mutation strategy over string patching for robust nested injection
- [Phase 07]: MonetaryAmount uses u64 minor-unit integers (cents for USD) -- no float precision issues, matches AGENT_ECONOMY.md reference design
- [Phase 07]: Currency matching in is_subset_of uses string equality -- mismatched currencies return false (fail-closed, no conversion logic needed at this layer)
- [Phase 08]: try_charge_cost uses IMMEDIATE SQLite transaction for atomic read-check-write monetary budget enforcement
- [Phase 08]: HA overrun bound documented: max_cost_per_invocation x node_count -- named test concurrent_charge_overrun_bound
- [Phase 08]: invoke_with_cost default returns None cost; servers that track costs override it -- no breaking changes to existing ToolServerConnection implementors
- [Phase 08]: VelocityGuard uses elapsed-time refill in try_consume (synchronous, no background thread)
- [Phase 08]: matched_grant_index defaults to None in all existing GuardContext sites; populated in plan 08-04
- [Phase 08-core-enforcement]: KernelCheckpointBody is the signed unit (canonical JSON of body is signed, not the full checkpoint)
- [Phase 08-core-enforcement]: receipts_canonical_bytes_range deserializes to PactReceipt then applies canonical_json_bytes for RFC 8785 determinism in Merkle leaves
- [Phase 08-core-enforcement]: BudgetChargeResult is a private struct; threads budget charge info from check_and_increment_budget through to receipt metadata construction
- [Phase 08-core-enforcement]: Downcast via ReceiptStore.as_any_mut() avoids adding checkpoint methods to the minimal ReceiptStore trait; only SqliteReceiptStore gets real checkpoint behavior
- [Phase 08-core-enforcement]: dispatch_tool_call removed as dead code; dispatch_tool_call_with_cost covers both monetary and non-monetary paths
- [Phase 09-02]: DPoP proof message is PACT-native (capability_id + tool_server + tool_name + action_hash + nonce) -- not HTTP-shaped
- [Phase 09-02]: DpopNonceStore uses std::sync::Mutex with LruCache keyed by (nonce, capability_id) -- synchronous, fits Guard pipeline
- [Phase 09-02]: verify_dpop_proof checks nonce replay AFTER signature verification -- invalid signatures cannot poison nonce store
- [Phase 09-02]: dpop_required: Option<bool> with serde(default, skip_serializing_if = Option::is_none) -- SCHEMA-01 forward compatibility
- [Phase 09]: SQLite ATTACH DATABASE for archive writes (zero-copy, WAL-atomic)
- [Phase 09]: retention_config: None default preserves existing kernel behavior (retention disabled by default)
- [Phase 09]: Compliance docs reference only tests confirmed passing -- no planned features cited
- [Phase 09]: docs/compliance/ directory is the canonical home for regulatory mapping documents in the PACT repository
- [Phase 10-03]: DpopProofBody fields use snake_case matching Rust serde for cross-language verifiability
- [Phase 10-03]: PactError (SDK layer) is distinct from PactInvariantError (invariant layer) -- different abstraction levels
- [Phase 10-03]: QueryError status is a positional constructor arg for typed HTTP status access (err.status)
- [Phase 10-01]: query_receipts_impl lives in receipt_store.rs (private connection), public API types and shell in receipt_query.rs
- [Phase 10-01]: total_count uses separate COUNT(*) without cursor filter -- reflects full filtered set size
- [Phase 10-01]: Financial cost filters use json_extract(raw_json, '$.metadata.financial.cost_charged') -- NULL rows excluded by >= / <= comparison
- [Phase 10]: Receipts in ReceiptQueryResponse serialized from stored.receipt (PactReceipt), not StoredToolReceipt -- StoredToolReceipt does not implement Serialize
- [Phase 10]: pact receipt list uses JSON Lines to stdout, pagination metadata to stderr -- stdout stays machine-parseable
- [Phase 11]: pact-siem Exporter trait uses Pin<Box<dyn Future>> for dyn compatibility -- impl Trait returns are not object-safe
- [Phase 11]: pact-siem cursor not persisted to disk -- restart re-exports from seq=0; Splunk HEC and Elasticsearch handle idempotent re-export
- [Phase 11]: pact-siem depends only on pact-core (not pact-kernel) -- kernel TCB has zero SIEM/HTTP transitive dependencies, verified by cargo tree
- [Phase 11]: SplunkConfig.sourcetype defaults to pact:receipt -- allows Splunk teams to write sourcetype-based searches
- [Phase 11]: ElasticAuthConfig is an enum (ApiKey vs Basic) -- makes invalid auth states unrepresentable at the type level
- [Phase 11]: ES partial failure detection iterates items array only when errors field is true -- avoids JSON traversal on happy path
- [Phase 11]: ToggleExporter removed: two-instance manager test pattern used instead (Arc-based toggle not dyn-compatible without impl-on-Arc)
- [Phase 11]: manager tests use max_retries=0/base_backoff_ms=0 to eliminate 3.5s retry delay per test
- [Phase 12]: pub(crate) on SqliteReceiptStore.connection field allows capability_lineage.rs to implement methods without a separate accessor
- [Phase 12]: snapshot_from_row free function (not closure) eliminates type annotation boilerplate across all capability_lineage query sites
- [Phase 12]: delegation_depth stored at insert time (not computed at query time) -- depth is stable, avoids recursive computation on every read
- [Phase 12]: ORDER BY level DESC in WITH RECURSIVE CTE produces root-first ordering -- root discovered at highest recursion level
- [Phase 12]: Bearer token from ?token= URL param stored in sessionStorage -- no unauthenticated config endpoint needed
- [Phase 12]: Cursor stack (push/pop array) for back-navigation with TanStack Table manualPagination: true and pageCount: -1
- [Phase 12]: Minor-unit monetary formatting uses integer arithmetic only (Math.floor + modulo) -- no float conversion
- [Phase 12]: agent_subject placed as ?9 in SQL query params; cursor moved to ?10 and limit to ?11 -- sequential numbering is more maintainable
- [Phase 12]: LEFT JOIN (not INNER JOIN) in query_receipts_impl preserves all receipts when agent_subject is None -- NULL-safe backwards-compatible filter

### Pending Todos

None yet.

### Blockers/Concerns

- Colorado AI Act deadline: June 30, 2026 -- Phase 9 COMP-01 document must ship before this date
- EU AI Act high-risk deadline: August 2, 2026 -- Phase 9 COMP-02 document must ship before this date
- Phase 7 is a hard gate: no new-field-bearing tokens can ship until deny_unknown_fields removal passes cross-version round-trip test
- Monetary HA overrun bound must be explicitly documented in Phase 8 (LWW split-brain window = max_cost_per_invocation x node_count)

## Session Continuity

Last session: 2026-03-23T02:28:30.012Z
Stopped at: Completed 12-02-PLAN.md (agent-centric receipt query and lineage HTTP endpoints)
Resume file: None

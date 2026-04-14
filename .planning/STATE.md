---
gsd_state_version: 1.0
milestone: v2.83
milestone_name: Coverage, Hardening, and Production Qualification
status: active
stopped_at: phase 317 refreshed with wave 05 verified; milestone still blocked by phase 316 coverage gap plus the remaining phase 317 signature/API gaps
last_updated: "2026-04-14T18:06:20Z"
last_activity: 2026-04-14 -- local verification blockers are closed: the JVM package now has a Gradle wrapper and passes under Gradle 8.7, Python SDK packages resolve locally via uv sources and dev extras, and the full v3.9-v3.11 remediation matrix passes across Rust, TypeScript, Go, .NET, JVM, and Python
progress:
  total_phases: 4
  completed_phases: 2
  total_plans: 10
  completed_plans: 8
  percent: 50
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-13)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v2.83 Coverage, Hardening, and Production Qualification --
raise the production bar with crate-level integration tests, higher measured
coverage, store-layer hardening, API-surface cleanup, and structured errors.

## Current Position

Phase: 317 (gaps_found refreshed)
Plan: `317-03` completed; return next to the remaining `317` API-surface /
signature cleanup or resume the `316` coverage closure lane
Status: v2.83 remains active locally because phase `316` is still
`gaps_found` at `72.42%` comparable workspace coverage and phase `317` is still
`gaps_found` with `63` remaining non-test `too_many_arguments` suppressions and
the wildcard-export audit now narrowed to `arc-core-types` / `arc-core`
compatibility facades; the `udeps` gate is satisfied locally.
Last activity: 2026-04-14 -- phase `317` wave `05` landed typed evaluator
result inputs, converted the streamable-HTTP OAuth session-auth helper to a
typed input struct, converted workflow step recording to a typed input struct,
and reduced the live non-test `too_many_arguments` inventory to `63`.

Progress: [#####-----] 50%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.11: 54 phases planned across 12 milestones
- v4.0: 4 phases planned (parallel with v2.83)

## Accumulated Context

### Decisions

- v2.80-v2.83 milestones were defined from a comprehensive five-agent codebase
  review (2026-04-13) that identified: 32K-line arc-core gravity well, five
  files exceeding 6K lines, synchronous &mut self kernel blocking concurrency,
  deprecated serde_yaml, dual reqwest versions, 12 crates with zero integration
  tests, naming confusion (ARC vs CHIO), unpublished SDKs, non-implementable
  protocol spec, and 82 too_many_arguments suppressions.
- v2.80 gates v2.81 and v2.82. v2.81 and v2.82 can execute in parallel.
  v2.83 gates on v2.81.
- The ship readiness ladder (v2.66-v2.73) is complete locally except for the
  deferred v2.71 (external web3 prerequisites).
- All prior MERCURY and ARC-core decisions from v2.65 remain in force.
- MERCURY and ARC-Wall schema expansion is explicitly paused until the protocol
  substrate is production-ready.
- `arc-core-types` stays narrow while heavyweight ARC business domains now live
  in dedicated crates and the broad consumers declare those domain crates
  directly.
- Narrow consumers can migrate without source churn by aliasing
  `package = "arc-core-types"` under the existing `arc-core` dependency key.
- `arc init` should stay self-contained: generated starter projects use a
  standalone Rust MCP stub plus the installed `arc` binary instead of depending
  on unpublished ARC crates.
- Phase `308` should keep the official SDK examples aligned to the real
  `arc trust serve` + `arc mcp serve-http --control-url ...` topology rather
  than introducing a second demo stack before the Docker milestone lands.
- Phase `310` anchored the tutorial and framework examples to the same hosted
  HTTP edge topology rather than reviving the old stdio demo path.
- v4.0 WASM Guard Runtime Completion runs in parallel with v2.83 (no code
  dependency). Design authority is `docs/guards/05-V1-DECISION.md`. ABI is raw
  core-WASM (not WIT), stateless per-call Store, HushSpec-first pipeline order.

### Pending Todos

- Close the remaining `316` coverage gap by targeting the next weakest crates
  and files until the full-workspace coverage lane exceeds `80%`.
- Continue `317`: remove more non-test `too_many_arguments` suppressions and
  finish the crate-root `pub use` surface audit now that the dependency-audit
  gate is closed locally.
- Decide whether to refresh the checked-in conformance reports as part of the
  final `v2.83` closeout, since the qualification bundle currently references
  the latest generated reports from `2026-03-19`.
- Resolve deferred `v2.71` external prerequisites if live-chain activation
  becomes active again.
- v3.9 runtime correctness remediation is now defined locally for the
  post-implementation audit findings; fold the validated fixes back into the
  v3.x planning lane once the current patch set is verified.
- v3.10 HTTP sidecar and cross-SDK contract completion is now defined locally
  for the remaining HTTP substrate gaps surfaced by the follow-up audit.
- v3.11 sidecar entrypoint and body-integrity completion is now defined
  locally for the remaining operator-surface, request-body preservation, and
  HTTP schema drift gaps surfaced by the latest audit.
- Archive or annotate the v3.9-v3.11 remediation lane in the planning docs now
  that the cross-language verification matrix is green locally.

### Blockers/Concerns

- The live planning pointers for `v2.83` are updated locally, but a clean
  closeout/tag pass is still outstanding because the top-level planning files
  carried unrelated local edits before milestone archival.
- Phase `316` remains open because the refreshed full-workspace `llvm-cov` run
  landed at `72.42%` on the comparable filtered lane, still materially below
  the `80%+` target.
- The new qualification bundle now includes one fresh `arc-core` microbenchmark
  baseline, but there is still no broader end-to-end CLI/kernel latency
  baseline captured for `v2.83`.
- The default web3-enabled graph still carries alloy's transitive hashbrown
  split; the core-path no-default-features graph is now the validated slim path.
- The planning/state pointers still describe the older `v2.83` lane as the
  active milestone even though the v3.9-v3.11 remediation patch set is now
  implemented and verified locally.

## v4.0 WASM Guard Runtime Completion

Phase: 373 (not started)
Plan: --
Status: Roadmap created; phases 373-376 defined; ready for `plan-phase 373`
Last activity: 2026-04-14 -- v4.0 roadmap created with 4 phases covering 31
requirements across runtime hardening, security/enrichment, manifest/wiring/
receipts, and benchmark validation

## Session Continuity

Last session: 2026-04-14
Stopped at: v4.0 roadmap created; phases 373-376 defined in ROADMAP.md
Next action: `/gsd:plan-phase 373` to begin WASM runtime host foundation
Resume file: None

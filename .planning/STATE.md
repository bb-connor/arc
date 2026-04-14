---
gsd_state_version: 1.0
milestone: v3.12
milestone_name: Cross-Protocol Integrity and Truth Completion
status: active
stopped_at: v3.12 roadmap and requirements created; phases 377-381 are defined while v4.0 remains parallel and v2.83 remains an unarchived local closeout lane
last_updated: "2026-04-14T18:47:52Z"
last_activity: 2026-04-14 -- created v3.12 from the cross-protocol debate findings to close ACP cryptographic enforcement, outward-edge kernel mediation, operational parity gaps, and repo-truth drift
progress:
  total_phases: 5
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-14)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v3.12 Cross-Protocol Integrity and Truth Completion --
finish ACP live-path cryptographic enforcement, kernel-mediated outward edges,
operational parity on the remaining weak surfaces, and a repo-wide truth pass
that aligns the vision narrative to shipped code.

## Current Position

Phase: 377 (not started)
Plan: --
Status: v3.12 is now the active planning lane because the cross-protocol
debate concluded ARC's kernel/substrate breakthrough is real, but the broader
vision still depends on ACP live-path cryptographic enforcement, truthful
kernel mediation at the A2A/ACP edges, operational parity on the last weak
runtime surfaces, and repo/doc reconciliation. `v4.0` remains a parallel
strategic bet, and `v2.83` remains locally unarchived rather than silently
treated as complete.
Last activity: 2026-04-14 -- defined phases 377-381 for ACP enforcement,
edge-kernel mediation, operational parity, truth reconciliation, and
claim-gate qualification.

Progress: [----------] 0%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.12: 59 phases planned across 13 milestones
- v4.0: 4 phases planned (parallel strategic lane)
- v4.1: 4 phases planned (depends on v4.0; guard SDK + CLI)

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
- v4.0 WASM Guard Runtime Completion runs in parallel with the v3.12
  corrective lane (and remains independent from the unfinished v2.83 closeout).
  Design authority is `docs/guards/05-V1-DECISION.md`. ABI is raw core-WASM
  (not WIT), stateless per-call Store, HushSpec-first pipeline order.
- The 2026-04-14 cross-protocol debate established the correct ARC claim:
  the kernel/substrate breakthrough is real, but the broader "fully realized
  universal cross-protocol governance kernel" claim still requires ACP
  cryptographic enforcement, truthful outward-edge mediation, operational
  parity, and repo-wide truth reconciliation.
- v3.12 exists specifically to close that credibility gap. It is the active
  corrective lane even though v4.0 was already planned in parallel and v2.83
  remains locally unarchived.

### Pending Todos

- Plan and execute phase `377` to wire ACP live-path capability checking all
  the way through signature verification and fail-closed enforcement.
- Plan and execute phase `378` to make the A2A/ACP outward edges truthfully
  kernel-mediated with signed receipt parity or explicitly narrowed claims.
- Plan and execute phase `379` to close sidecar receipt persistence,
  `arc-tower` body binding, and Kubernetes kernel-validation gaps.
- Plan and execute phase `380` to reconcile protocol docs, crate comments, and
  planning artifacts with what the live code actually ships.
- Plan and execute phase `381` to qualify the narrowed ARC claim with
  integration tests and operator-facing verification artifacts.
- Close or explicitly defer the remaining `v2.83` coverage / qualification
  loose ends once the repo's top-level truth narrative is stable.
- Resume `v4.0` planning/execution after the v3.12 corrective lane no longer
  competes with the repo's active truth narrative.

### Blockers/Concerns

- ACP and outward-edge surfaces still contain partial or overstated
  cryptographic/kernel claims in live code and docs; phase `380` must treat
  comment/doc truth as part of the product surface, not cleanup polish.
- `v2.83` is still locally incomplete, so it should be explicitly archived or
  deferred later instead of silently remaining the repo's "active" milestone.
- `v4.0` already reserved phases `373-376`, so `v3.12` begins at `377`; future
  v4.x placeholders must stay shifted to avoid roadmap collisions.
- The default web3-enabled graph still carries alloy's transitive hashbrown
  split; the core-path no-default-features graph remains the validated slim
  path when `v2.71` eventually resumes.

## v4.0 WASM Guard Runtime Completion

Phase: 373 (not started)
Plan: --
Status: Roadmap created; phases 373-376 defined; ready for `plan-phase 373`
Last activity: 2026-04-14 -- v4.0 roadmap created with 4 phases covering 31
requirements across runtime hardening, security/enrichment, manifest/wiring/
receipts, and benchmark validation


## v4.1 Guard SDK and Developer Experience

Phase: 377 (not started)
Plan: --
Status: Roadmap created; phases 377-380 defined; depends on v4.0 completion
Last activity: 2026-04-14 -- v4.1 roadmap created with 4 phases covering 19
requirements across guest SDK core, proc macro/examples, CLI scaffolding, and
CLI test/bench/pack/install

## Session Continuity

Last session: 2026-04-14
Stopped at: v3.12 roadmap created; phases 377-381 defined in ROADMAP.md and
REQUIREMENTS.md
Next action: `/gsd:plan-phase 377` to begin ACP live-path cryptographic
enforcement
Resume file: None

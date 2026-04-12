# Phase 165: Observability, Indexers, Reorg Recovery, and Pause/Emergency Controls - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Close the missing production-operations gap for ARC's shipped web3 runtime by
making runtime health, indexer drift, replay, and emergency posture explicit.

</domain>

<decisions>
## Implementation Decisions

### Operations Surface
- Reuse the shipped `arc-link` runtime-report contract instead of inventing a
  second oracle observability plane.
- Add matching bounded runtime-report and incident types to `arc-anchor` and
  `arc-settle`.

### Recovery Posture
- Treat reorg and indexer replay as first-class visible states rather than
  implicit retry behavior.
- Keep emergency modes authority-narrowing only; they may stop or narrow write
  paths, but they may not rewrite prior ARC truth.

### Documentation
- Freeze the cross-runtime operations boundary in one standards profile and one
  shared web3 operations runbook.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-link/src/monitor.rs` already exposed the oracle runtime-report
  boundary.
- `crates/arc-settle/src/observe.rs` already modeled finality and recovery
  actions, but it lacked a dedicated operations-report surface.
- `crates/arc-anchor/` already exposed publication and bundle semantics, but it
  lacked explicit indexer, replay, and emergency-control contracts.

</code_context>

<deferred>
## Deferred Ideas

- hosted dashboards or paging integrations
- public unauthenticated incident feeds
- multi-region or consensus-backed indexer replication

</deferred>

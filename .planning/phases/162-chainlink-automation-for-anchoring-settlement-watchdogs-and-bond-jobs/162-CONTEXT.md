# Phase 162: Chainlink Automation for Anchoring, Settlement Watchdogs, and Bond Jobs - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Add bounded declarative automation over anchor publication and settlement
watchdog flows without turning schedulers or forwarders into ambient trust.

</domain>

<decisions>
## Implementation Decisions

### Job Model
- Represent automation as reviewable job artifacts with explicit replay
  windows and state fingerprints.
- Keep operator override mandatory for the shipped anchor and watchdog jobs.

### Anchor Versus Settlement
- Let `arc-anchor` own publication scheduling and delegate-forwarder
  preparation.
- Let `arc-settle` own settlement and bond watchdog scheduling.

### Failure Semantics
- Treat duplicate suppression and delayed-but-safe execution as explicit
  outcomes.
- Reject execution when state fingerprints drift or required override posture
  disappears.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-anchor/src/evm.rs` already prepares the authoritative anchor
  publication and delegate-registration calldata.
- `crates/arc-settle/src/lib.rs` already has the dispatch identifiers and bond
  references needed to fingerprint watchdog jobs.
- `docs/research/ARC_LINK_FUTURE_TRACKS.md` explicitly calls out Automation as
  a later interop layer rather than a replacement truth source.

</code_context>

<deferred>
## Deferred Ideas

- permissionless keeper selection
- automatic settlement release without operator override
- generic arbitrary custom-logic jobs beyond the shipped bounded families

</deferred>

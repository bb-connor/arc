# Phase 186: MERCURY Live/Mirrored Workflow Intake and Proof Continuity - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Extend the same controlled release, rollback, and inquiry workflow from
replay/shadow into supervised-live intake. Reuse ARC's evidence substrate and
MERCURY's existing proof and inquiry contracts instead of inventing a new
truth path.

</domain>

<decisions>
## Implementation Decisions

### Reuse The Existing Proof Lane
- add supervised-live intake on top of the existing MERCURY receipt metadata,
  bundle-manifest, proof-package, and inquiry-package contracts
- keep ARC evidence export canonical; supervised-live intake should feed the
  same export path the pilot already uses

### One Input Contract
- introduce one explicit supervised-live capture contract that supports the
  same workflow in `live` or `mirrored` mode
- keep the input typed and repo-native so qualification can run without
  external systems

### Preserve Source Continuity
- require source identifiers, chronology continuity, and business identifiers
  to survive from supervised-live intake into proof and inquiry packages
- treat missing source continuity as a contract problem, not an optional nice
  to have

### Qualify Against The Pilot Contract
- validate the new capture path using the existing `mercury verify` surface
  and proof-package expectations
- update technical docs only enough to describe the new intake contract and
  continuity rules

</decisions>

<code_context>
## Existing Surfaces

- `crates/arc-mercury/src/commands.rs`
- `crates/arc-mercury/src/main.rs`
- `crates/arc-mercury/tests/cli.rs`
- `crates/arc-mercury-core/src/pilot.rs`
- `crates/arc-mercury-core/src/proof_package.rs`
- `crates/arc-mercury-core/src/receipt_metadata.rs`
- `docs/mercury/TECHNICAL_ARCHITECTURE.md`

</code_context>

<deferred>
## Deferred Ideas

- executable approval or interrupt controls remain phase `187`
- supervised-live qualification package and final proceed/defer/stop close-out
  remain phase `188`

</deferred>

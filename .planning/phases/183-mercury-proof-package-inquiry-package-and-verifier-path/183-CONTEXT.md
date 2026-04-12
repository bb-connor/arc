# Phase 183: MERCURY Proof Package, Inquiry Package, and Verifier Path - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Wrap ARC's existing evidence export truth into MERCURY-specific proof and
reviewed-export contracts and expose one supported verification path.

</domain>

<decisions>
## Implementation Decisions

### Package, Do Not Replace
- `Proof Package v1` wraps ARC evidence export
- `Inquiry Package v1` derives from the proof package plus disclosure and
  approval state
- ARC's receipt/checkpoint/export path remains canonical

### Start With CLI Verification
- expose the first verifier path through `arc-cli`
- keep MERCURY package validation logic in `arc-mercury-core`
- delay a dedicated verifier crate until the contract stabilizes

### Publication Contract Is Normative
- define `Publication Profile v1` over checkpoints, inclusion proofs, and
  witness/anchor expectations
- keep the profile explicit even if later witness automation lands elsewhere

### Phase Sequencing
- start only after phase `182` lands the typed metadata and extracted query
  model
- this phase defines the proof contract that phase `184` must reuse for the
  replay/shadow pilot

</decisions>

<code_context>
## Existing Surfaces

- `crates/arc-kernel/src/evidence_export.rs`
- `crates/arc-store-sqlite/src/evidence_export.rs`
- `crates/arc-cli/src/evidence_export.rs`
- `docs/mercury/VERIFIER_SDK_RESEARCH.md`
- `docs/mercury/TECHNICAL_ARCHITECTURE.md`

</code_context>

<deferred>
## Deferred Ideas

- external witness-network operation and partner-facing distribution services
  are later phases, not part of the first verifier path

</deferred>

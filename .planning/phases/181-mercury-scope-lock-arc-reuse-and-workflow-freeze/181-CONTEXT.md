# Phase 181: MERCURY Scope Lock, ARC Reuse Map, and Workflow Freeze - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Freeze the first MERCURY workflow and ARC reuse boundary before implementation
starts so the product, roadmap, and code all target the same commercial wedge.

</domain>

<decisions>
## Implementation Decisions

### Keep ARC Broad And MERCURY Narrow
- ARC remains the platform thesis and trust substrate
- MERCURY is the finance-specific product layer
- the first workflow is one controlled release, rollback, and inquiry path

### Reuse The Existing ARC Truth Contract
- reuse ARC receipts, checkpoints, evidence export, and CLI verification
- keep MERCURY-specific semantics in typed metadata, package contracts, and
  query indexing

### Freeze One Workflow Sentence
- use "controlled release, rollback, and inquiry evidence for AI-assisted
  execution workflow changes" as the first supported workflow
- force GTM, pilot, and implementation docs to reuse that same sentence

### Phase Sequencing
- this is the gating MERCURY implementation phase
- phases `182` through `184` should consume this scope lock rather than
  redefine it later

</decisions>

<code_context>
## Existing Surfaces

- `docs/mercury/PRODUCT_BRIEF.md`
- `docs/mercury/IMPLEMENTATION_ROADMAP.md`
- `docs/mercury/PHASE_0_1_BUILD_CHECKLIST.md`
- `docs/mercury/ARC_MODULE_MAPPING.md`
- `docs/STRATEGIC_ROADMAP.md`

</code_context>

<deferred>
## Deferred Ideas

- live FIX, browser UI, downstream connectors, and supervised-live deployment
  stay out of this phase

</deferred>

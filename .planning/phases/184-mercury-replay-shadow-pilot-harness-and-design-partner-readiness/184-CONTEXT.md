# Phase 184: MERCURY Replay/Shadow Pilot Harness and Design-Partner Readiness - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Make the first MERCURY workflow runnable and reviewable as a replay/shadow
pilot with one gold corpus, one demo story, and one evaluator-facing proof
flow.

</domain>

<decisions>
## Implementation Decisions

### One Workflow, One Corpus
- use one gold workflow corpus: proposal -> approval -> release -> inquiry
- keep one rollback variant for exception/recovery proof

### Pilot Readiness Means Proof Readiness
- the demo and pilot package must use the same proof and inquiry contracts as
  the implementation
- do not hand-author evaluator artifacts that the verifier cannot reproduce

### Stop Before Connector Sprawl
- close the milestone with a supervised-live bridge decision
- do not add downstream archive/surveillance/connectors in the pilot phase

### Phase Sequencing
- start only after phase `183` stabilizes `Proof Package v1`,
  `Publication Profile v1`, and `Inquiry Package v1`
- treat this phase as proof-driven pilot closure, not a place to redesign the
  product or package contract

</decisions>

<code_context>
## Existing Surfaces

- `docs/mercury/POC_DESIGN.md`
- `docs/mercury/POC_SPRINT_PLAN.md`
- `docs/mercury/EXTERNAL_PACKAGE.md`
- `docs/mercury/USE_CASES.md`
- `docs/mercury/PHASE_0_1_BUILD_CHECKLIST.md`

</code_context>

<deferred>
## Deferred Ideas

- supervised-live productionization belongs to the post-pilot bridge, not this
  milestone

</deferred>

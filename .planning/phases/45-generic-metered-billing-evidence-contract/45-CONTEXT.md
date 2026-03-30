# Phase 45 Context

## Goal

Define a payment-rail-neutral quote, cap, and post-execution evidence contract
that can describe truthful tool economics beyond x402 and ACP/shared-payment-token
flows.

## Current Code Reality

- ARC already distinguishes manifest pricing from budget enforcement and
  already separates pre-execution payment authorization from post-execution
  capture or release.
- That truthful split is strongest for payment rails. Non-rail metered tools
  still lack a canonical contract for quoted cost, settlement mode, and later
  post-execution billing evidence.
- Governed transaction intents and governed receipt metadata already carry
  seller-scoped commerce context and runtime assurance, so they are the natural
  place to add generic metered-billing context.
- Receipt query and store surfaces already preserve arbitrary metadata, which
  means phase 45 can define the contract cleanly before phase 46 adds adapter
  ingestion and reconciliation behavior.

## Decisions For This Phase

- Treat metered billing as a first-class governed intent and receipt contract,
  not as an ad hoc `cost_breakdown` blob.
- Preserve the quote-versus-enforcement distinction: quoted cost is evidence
  and planning context, not the hard stop by itself.
- Define the post-execution evidence shape now, but do not pretend adapter
  ingestion or reconciliation already exists.
- Keep the contract payment-rail-neutral so x402 and ACP remain examples, not
  the canonical semantic source.

## Risks

- If the contract collapses quote and actual cost, ARC will lose truthful cost
  semantics instead of improving them.
- If the contract is too rail-specific, later adapters will inherit the wrong
  abstraction and phase 46 will become a refactor instead of a build-out.
- If validation is too weak, operator-supplied metered billing context can
  drift into empty or misleading identifiers.

## Phase 45 Execution Shape

- 45-01: define the metered-billing intent and receipt metadata contract
- 45-02: thread the contract through governed validation and receipt building
- 45-03: document the contract and add query-facing regression coverage

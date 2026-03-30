# Phase 50 Context

## Goal

Produce bounded runtime underwriting decisions from canonical ARC evidence
rather than partner-specific ad hoc logic.

## Current Code Reality

- ARC has the evidence ingredients for underwriting, but no runtime evaluator
  that can convert them into an approve, deny, step-up, or reduce-ceiling
  decision.
- Reputation today is descriptive rather than decisional, and behavioral-feed
  exports stop short of underwriting claims.
- Runtime assurance, certification, and cost evidence already shape trust and
  economic ceilings separately, which means the evaluator should reuse those
  primitives rather than invent new trust semantics.
- Existing policy code already fails closed in many places; underwriting
  should follow that pattern rather than introduce permissive fallbacks.

## Decisions For This Phase

- Keep the evaluator deterministic and explainable: every outcome must carry
  explicit reasons and evidence references.
- Start with bounded discrete outcomes instead of unconstrained scoring so
  operator review remains legible.
- Make missing or invalid evidence degrade safely to deny, manual review, or
  reduced ceilings rather than to silent approval.

## Risks

- If the decision engine is opaque, later appeals and partner proof work will
  become documentation theater instead of auditable runtime behavior.
- If decision reasons are not normalized, downstream premium and appeal
  surfaces will drift from the actual evaluation logic.
- If fail-closed handling is inconsistent, the most sensitive economic
  decisions will be the least reliable.

## Phase 50 Execution Shape

- 50-01: implement deterministic underwriting evaluation over the phase-49
  input contract
- 50-02: expose runtime decision and explanation surfaces to operators and
  automation
- 50-03: add regression coverage for bounded outcomes and fail-closed paths

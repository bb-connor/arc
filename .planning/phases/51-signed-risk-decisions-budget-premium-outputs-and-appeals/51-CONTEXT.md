# Phase 51 Context

## Goal

Make underwriting outputs explicit signed artifacts with auditable budget,
premium, and appeal semantics that remain separate from receipt truth.

## Current Code Reality

- ARC already signs receipts, approvals, certifications, and behavioral-feed
  exports, so signed underwriting artifacts should fit the current proof
  posture rather than invent a weaker side channel.
- Economic ceilings already exist in governed approvals, but there is not yet
  one durable artifact that says why a ceiling was granted, reduced, or held
  for review.
- There is no current appeal lifecycle for underwriting because underwriting
  itself is not yet a shipped decision surface.

## Decisions For This Phase

- Keep underwriting decisions separate from receipts and from mutable operator
  notes.
- Model premiums, ceilings, manual review, and appeals as lifecycle-bearing
  underwriting artifacts rather than as ad hoc report fields.
- Preserve provenance so later qualification and partner proof can verify the
  exact evidence and policy basis for a decision.

## Risks

- If underwriting outputs mutate receipts, ARC will blur execution truth and
  risk-decision truth.
- If appeals are informal, partner-facing proof will not be able to explain
  changed outcomes cleanly.
- If signed decision artifacts omit enough provenance, the operator experience
  will look cryptographic but not actually auditable.

## Phase 51 Execution Shape

- 51-01: define signed underwriting decision artifacts and output schema
- 51-02: implement persistence, query, and lifecycle handling for decisions,
  premiums, and appeals
- 51-03: add docs and regression coverage for artifact verification and review
  semantics

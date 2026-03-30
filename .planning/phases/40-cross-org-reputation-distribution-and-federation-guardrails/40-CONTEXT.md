# Phase 40 Context

## Goal

Share trust signals conservatively, with explicit provenance and
policy-visible attenuation.

## Current Code Reality

- ARC already computes local reputation, supports reputation-gated issuance,
  and exposes operator-visible reputation comparison surfaces.
- Evidence sharing and shared remote reference reporting exist, but imported
  evidence remains deliberately isolated from local receipt truth.
- That isolation is a good safety baseline, but it also means there is not yet
  a supported contract for cross-org reputation distribution itself.
- Once phases 37-39 land, ARC will have identity provenance, passport
  lifecycle, and certification discovery contracts that can anchor conservative
  remote trust distribution.

## Decisions For This Phase

- Remote trust signals must stay evidence-backed and issuer-scoped rather than
  collapsing into one global score.
- Policy must be able to attenuate, cap, or reject imported trust explicitly.
- Operator surfaces should show provenance and drift, not just a synthesized
  reputation number.
- Cross-org distribution must not rewrite the local receipt and reputation
  truth that ARC already enforces.

## Risks

- Cross-org reputation can drift into unsupported trust inflation if
  attenuation rules are vague.
- Feedback loops between imported and local scores can create false confidence.
- Distribution/reporting code can spread across CLI, reputation, and
  trust-control if ownership is not clear.

## Phase 40 Execution Shape

- 40-01: define evidence-backed reputation sharing and attenuation
- 40-02: implement cross-org distribution, import, and reporting
- 40-03: close v2.7 docs and federation regressions

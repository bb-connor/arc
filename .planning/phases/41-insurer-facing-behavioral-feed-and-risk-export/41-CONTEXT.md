# Phase 41 Context

## Goal

Expose stable insurer/risk feed exports from receipts, reputation, and
governed action data.

## Current Code Reality

- ARC already has truthful receipts, settlement metadata, operator reports,
  governed intent data, and reputation outputs that together form the raw
  substrate for a risk-facing export.
- Those surfaces are operator-oriented, not yet a stable external contract for
  insurers, underwriters, or partner risk engines.
- The deep-research thesis depends on a legible behavioral feed before ARC can
  credibly claim a larger risk-and-liability platform story.
- Portable trust work in `v2.7` should complete first so behavioral feeds can
  include trustworthy cross-org identity and certification context.

## Decisions For This Phase

- Treat the risk feed as a signed export contract, not as an ad hoc report
  serialization of current operator output.
- Keep the feed truthful about observed behavior and evidence; it should not
  pretend to be an underwriting model itself.
- Make filtering and export scope explicit so the feed can satisfy policy and
  privacy constraints.
- Reuse receipt/operator-report data where possible instead of inventing a
  second telemetry pipeline.

## Risks

- A poorly scoped feed can leak more data than operators expect.
- Risk-facing exports can drift away from receipt truth if they summarize too
  aggressively.
- The contract can become unstable if it is not defined before implementation.

## Phase 41 Execution Shape

- 41-01: define the behavioral-feed schema and signing contract
- 41-02: implement CLI and trust-control export surfaces
- 41-03: add docs and regression coverage for insurer-facing exports

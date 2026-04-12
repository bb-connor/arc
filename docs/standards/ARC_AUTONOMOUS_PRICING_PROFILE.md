# ARC Autonomous Pricing Profile

This profile defines ARC's bounded autonomous insurance-automation lane over
existing underwriting, capital, liability-market, and official web3 truth.

## Artifact Family

- `arc.autonomous-pricing-input.v1`
- `arc.autonomous-pricing-authority-envelope.v1`
- `arc.autonomous-pricing-decision.v1`
- `arc.capital-pool-optimization.v1`
- `arc.capital-pool-simulation-report.v1`
- `arc.autonomous-execution-decision.v1`
- `arc.autonomous-rollback-plan.v1`
- `arc.autonomous-comparison-report.v1`
- `arc.autonomous-drift-report.v1`
- `arc.autonomous-qualification-matrix.v1`

## Bounded Claim

ARC may compute and execute autonomous reprice, renew, decline, and bind
decisions only when:

- the pricing input preserves explicit evidence references back to underwriting,
  exposure, scorecard, loss, capital-book, and optional web3 settlement truth
- a signed authority envelope names the subject, provider, currency, action
  set, premium and coverage ceilings, and review thresholds
- reserve and capital adjustments remain explicit optimization artifacts rather
  than hidden model side effects
- live execution remains interruptible, rollback-linked, and subordinate to the
  official web3 rail when settlement dispatch is required

## Validation Rules

- pricing inputs fail closed on missing evidence, mixed currency, zero capital,
  or stale or contradictory settlement/loss posture
- authority envelopes fail closed on empty action sets, contradictory review
  thresholds, stale windows, or bind permission outside active automation mode
- pricing decisions fail closed on out-of-envelope coverage or premium,
  unexplained factors, shadow-mode mismatch, or auto-approval beyond declared
  review thresholds
- capital-pool optimizations and simulations fail closed on mixed subject or
  currency posture, missing scenarios, or non-reviewable recommendation state
- execution, comparison, and drift reports fail closed on missing rollback,
  missing gates, or critical drift without explicit fail-safe engagement

## Qualification

`docs/standards/ARC_AUTONOMOUS_QUALIFICATION_MATRIX.json` records the bounded
claim for:

- autonomous pricing inside explicit authority envelopes
- simulation-backed capital-pool optimization
- interruptible automatic bind execution
- drift-triggered fail-safe rollback

## Non-Goals

This profile does not claim:

- open-ended insurer-network automation
- hidden model authority outside the signed envelope family
- permissionless dispatch beyond the official ARC web3 lane
- autonomous trust widening from imported evidence or external execution alone

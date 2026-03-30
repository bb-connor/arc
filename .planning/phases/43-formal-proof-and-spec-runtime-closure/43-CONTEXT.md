# Phase 43 Context

## Goal

Reduce Lean/spec debt and close the remaining spec/runtime drift to an
explicitly accepted minimum.

## Current Code Reality

- ARC already ships protocol docs, conformance waves, and `formal/diff-tests`,
  but the working state still calls out formal proof debt and spec/runtime
  drift as unresolved launch-quality risk.
- The repo has a credible release-qualification lane, yet the proof and spec
  story still needs a deliberate closure pass before launch claims can be
  defended cleanly.
- Earlier milestones prioritized product breadth, decomposition, rename,
  payment rails, and portable trust. That sequencing leaves a concentrated
  formal-closure slice for `v2.8`.
- The launch package in phase 44 depends on a concrete answer to "what is
  proven, what is verified empirically, and what is still consciously deferred?"

## Decisions For This Phase

- Inventory and scope the remaining gaps before attempting closure work.
- Close the highest-signal runtime/spec gaps first instead of chasing
  total formalization.
- Keep accepted deferrals explicit and evidence-backed.
- Make launch-facing docs describe only the proven or verified surface.

## Risks

- Formal work can sprawl if the target closure set is not pinned first.
- Spec updates can drift again if they are not tied to runtime and conformance
  changes in the same phase.
- Residual `sorry` or similar proof debt can undermine the launch package if it
  is not clearly accounted for.

## Phase 43 Execution Shape

- 43-01: inventory the remaining formal and spec gaps
- 43-02: implement the required closure work across runtime, spec, and formal assets
- 43-03: publish verification artifacts for the accepted closure state

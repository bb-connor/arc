# Phase 413 Context: Externally Operated Control Surfaces

## Why This Phase Exists

ARC already ships internal comptroller-grade primitives across `arc-kernel`,
`arc-market`, `arc-open-market`, `arc-credit`, `arc-underwriting`,
`arc-settle`, `arc-web3`, `arc-link`, and `arc-federation`. The remaining gap
is not missing logic. The gap is that these surfaces still read primarily as
repo-owned capabilities rather than explicit operator-facing products that can
be deployed, governed, observed, and recovered outside one in-process runtime.

Phase `413` externalizes the core operator surfaces before any partner or
federation proof can be honest.

## Required Outcomes

1. Define one coherent operator-facing deployment and control model for the
   ARC economic plane: budget authority, approval control, payment
   authorization, settlement control, underwriting control, and operator
   reporting.
2. Expose those surfaces in a way that is operator-consumable rather than
   crate-internal only.
3. Produce operator runbook and deployment evidence covering live actions,
   escalation, recovery, and evidence export.

## Existing Assets

- `crates/arc-kernel/src/kernel/mod.rs`
- `crates/arc-kernel/src/operator_report.rs`
- `crates/arc-credit/src/lib.rs`
- `crates/arc-underwriting/src/lib.rs`
- `crates/arc-settle/src`
- `docs/release/*RUNBOOK*.md`
- `scripts/qualify-*.sh`

## Gaps To Close

- no single explicit operator-control surface that spans the economic plane
- no unified operator deployment profile for these surfaces
- operator reports exist, but they are not yet positioned as first-class
  externally consumed control outputs for the comptroller thesis

## Requirements Mapped

- `OPS4-01`
- `OPS4-02`
- `OPS4-03`

## Exit Criteria

This phase is complete only when ARC can point to one explicit operator-facing
control-surface story that covers economic governance actions, not just a set
of internal crates and tests.

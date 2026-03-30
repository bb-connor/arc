# Phase 85: Bond Contracts, Reserve Locks, and Collateral State - Context

## Goal

Define ARC's signed bond, reserve-lock, and collateral-state artifacts as the
economic backing for autonomous execution.

## Why This Phase Exists

The research's bonded-autonomy layer cannot exist without explicit reserve and
collateral state. ARC needs typed, auditable bond and reserve artifacts before
it can gate autonomy or record economic loss and recovery.

## Scope

- bond and reserve contract schema
- collateral lock and release lifecycle
- linkage to exposure and facility state
- fail-closed reserve accounting

## Out of Scope

- autonomy-tier execution gating
- delinquency and write-off lifecycle
- provider quote or claim workflows

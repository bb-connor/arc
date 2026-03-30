# Phase 81: Exposure Ledger and Economic Position Model - Context

## Goal

Define ARC's canonical exposure ledger and signed economic-position state over
governed actions, premiums, reserves, losses, recoveries, and settlement truth.

## Why This Phase Exists

Underwriting decisions, settlement reports, and reserve-related state already
exist, but they do not yet compose into one durable economic-position model.
The research's agent-credit and capital-allocation thesis requires a canonical
exposure layer before scorecards or facilities can be made credible.

## Scope

- exposure ledger schema and lifecycle
- signed exposure artifacts and aggregation rules
- settlement, reserve, loss, and recovery position accounting
- currency, evidence, and reconciliation boundaries
- fail-closed handling for incomplete or contradictory economic position data

## Out of Scope

- credit score evaluation
- facility issuance or capital allocation
- bonded autonomy or liability-market flows

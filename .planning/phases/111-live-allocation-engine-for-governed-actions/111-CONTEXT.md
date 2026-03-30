# Phase 111: Live Allocation Engine for Governed Actions - Context

## Goal

Map governed actions to explicit live capital-allocation decisions tied to one
source of funds, one authority chain, and one bounded execution envelope.

## Why This Phase Exists

ARC can only claim live capital participation once governed approvals produce
deterministic allocation decisions rather than inferred operator joins.

## Scope

- governed-action to allocation-decision mapping
- source-of-funds selection and reserve-book impact
- simulation-first execution posture and audit traceability
- fail-closed behavior for missing capital, stale authority, or mixed currency

## Out of Scope

- regulated-role qualification closeout
- automatic slashing, pricing, or claims payout
- open-market registry and governance work

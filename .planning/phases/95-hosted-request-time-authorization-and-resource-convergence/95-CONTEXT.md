# Phase 95: Hosted Request-Time Authorization and Resource Convergence - Context

## Goal

Turn ARC's current review-oriented OAuth-family projection into a bounded live
request-time authorization contract that still derives from governed ARC truth.

## Why This Phase Exists

The full research endgame requires ARC to be legible to OAuth/OIDC style
systems at request time, not only after execution in reviewer packs and
derived reports.

## Scope

- request-time authorization-details and transaction-context mapping
- resource indicator, audience, and metadata convergence
- explicit separation of access tokens, approval artifacts, capabilities, and review evidence
- fail-closed metadata-drift handling

## Out of Scope

- sender-constrained proof profiles
- transaction-token propagation
- automatic token exchange across trusted domains

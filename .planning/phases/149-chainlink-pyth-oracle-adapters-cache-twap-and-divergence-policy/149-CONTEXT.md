# Phase 149: Chainlink/Pyth Oracle Adapters, Cache, TWAP, and Divergence Policy - Context

## Goal

Build the core `arc-link` oracle clients and policy layer for cross-currency
budget enforcement.

## Why This Phase Exists

ARC now has the official web3 contract substrate from `v2.34`, but it still
cannot read real price feeds or produce bounded conversion evidence for
cross-currency budget decisions.

## Scope

- new `arc-link` runtime crate
- Chainlink Data Feeds reader via Alloy
- Pyth Hermes fallback client
- local cache with staleness tracking and optional TWAP
- divergence detection and fail-closed policy
- Base Mainnet operator configuration and supported-feed inventory

## Out of Scope

- kernel budget enforcement wiring
- operator monitoring and circuit-breaker overrides
- failure drills, runbooks, or milestone boundary rewrites

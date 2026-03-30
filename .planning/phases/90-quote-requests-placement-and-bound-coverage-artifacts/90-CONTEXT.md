# Phase 90: Quote Requests, Placement, and Bound Coverage Artifacts - Context

## Goal

Add canonical quote-request, quote-response, placement, and bound-coverage
artifacts over one signed risk package.

## Why This Phase Exists

Once a curated provider registry exists, ARC needs provider-neutral quote and
bind semantics over canonical risk evidence. This is the first real liability-
market transaction layer.

## Scope

- quote-request and quote-response contracts
- placement and bound-coverage artifacts
- linkage to provider, jurisdiction, and risk package state
- fail-closed quote expiry and mismatch handling

## Out of Scope

- claim adjudication lifecycle
- dispute resolution over claims
- permissionless marketplace semantics

# Phase 66: Wallet / Holder Distribution Adapters - Context

## Goal

Add one reference holder adapter and wallet launch surface so ARC can prove
same-device and cross-device use without becoming a wallet vendor.

## Why This Phase Exists

Verifier transport alone is not enough. ARC needs one bounded holder-side path
that exercises the OID4VP verifier lane against a real portable credential and
proves coexistence with existing ARC-native challenge flows.

## Scope

- minimal reference holder adapter for qualification and demos
- same-device launch artifacts and cross-device QR handoff
- coexistence rules between ARC-native challenge transport and OID4VP
- optional browser-facing adapter boundary if it remains clearly experimental

## Out of Scope

- production wallet UX or long-term holder state management
- generic wallet-messaging protocols beyond the chosen OID4VP flow
- silent deprecation of ARC-native challenge flows

# Phase 99: DPoP, mTLS, and Attestation-Bound Sender-Constrained Authorization - Context

## Goal

Turn ARC's hosted authorization contract into bounded live sender-constrained
behavior over DPoP, mTLS, and one explicitly constrained attestation-bound
profile.

## Why This Phase Exists

The endgame research expects live sender-constrained authorization, but ARC
must implement that without widening authority from portable artifacts or
runtime attestation alone.

## Scope

- DPoP proof continuity over wallet and hosted authorization flows
- mTLS sender binding for verifier or resource access
- one bounded attestation-bound sender profile
- fail-closed proof continuity and authority-narrowing semantics

## Out of Scope

- end-to-end milestone qualification
- permissionless sender-constrained interoperability claims
- widening execution authority from attestation alone

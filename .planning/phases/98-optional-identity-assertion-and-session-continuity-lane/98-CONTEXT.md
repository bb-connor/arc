# Phase 98: Optional Identity Assertion and Session Continuity Lane - Context

## Goal

Add one optional identity-assertion lane that can preserve session continuity
or verifier login context without becoming mandatory for every presentation.

## Why This Phase Exists

The research endgame assumes verifier and wallet flows can optionally carry
continuity or login semantics, but ARC must keep that lane explicitly optional
and bounded to avoid turning portability into ambient identity dependence.

## Scope

- optional identity assertion envelope and continuity semantics
- verifier login or session resumption binding
- explicit opt-in policy and audience rules
- fail-closed handling for stale, mismatched, or replayed assertions

## Out of Scope

- DPoP, mTLS, or attestation-bound sender proofs
- mandatory identity providers or universal login semantics
- final milestone qualification

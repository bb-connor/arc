# Phase 106: Verifier Descriptors, Trust Bundles, and Reference-Value Distribution - Context

## Goal

Define portable verifier descriptors, trust bundles, and reference-value
distribution so external verifier ecosystems can interoperate without hiding
their measurement or signing dependencies.

## Why This Phase Exists

Cross-issuer portability is incomplete unless verifier identity, trust anchors,
and reference values are also portable and signed.

## Scope

- verifier descriptor artifacts and identity metadata
- trust-bundle structure and distribution semantics
- reference-value or measurement-set distribution contracts
- fail-closed handling for stale, ambiguous, or unverifiable bundles

## Out of Scope

- public search or transparency network behavior
- wider provider adapters beyond the current contract
- local policy import decisions from public discovery

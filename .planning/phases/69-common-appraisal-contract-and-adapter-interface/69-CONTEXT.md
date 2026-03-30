# Phase 69: Common Appraisal Contract and Adapter Interface - Context

## Goal

Define ARC's typed appraisal contract and verifier-adapter interface so raw
attestation evidence, verifier identity, normalized assertions, and
vendor-scoped claims stop being conflated.

## Why This Phase Exists

`v2.12` added concrete verifier bridges, but the current boundary is still too
Azure-shaped. The research points toward a broader verifier ecosystem, which
requires one canonical ARC appraisal contract before additional cloud adapters
can be added safely.

## Scope

- canonical appraisal types and reason codes
- verifier-adapter interface and lifecycle
- separation of raw evidence, normalized assertions, and vendor claims
- fail-closed handling for partial, unknown, or malformed appraisals
- operator-facing documentation for the normalization boundary

## Out of Scope

- shipping additional cloud verifier adapters
- changing runtime-assurance policy behavior beyond what the contract requires
- claiming global equivalence across vendor attestation vocabularies

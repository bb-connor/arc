# Phase 58: Cloud Attestation Verifier Adapters - Context

## Goal

Add concrete attestation verifier bridges so ARC can consume verified runtime
evidence from at least one real cloud or vendor attestation source.

## Why This Phase Exists

Phase 57 makes workload identity explicit. The next gap is proving ARC can
ingest attestation from a real verifier path instead of relying only on
pre-normalized upstream evidence.

## Scope

- select at least one concrete cloud or vendor attestation verifier bridge
- normalize its verified results into ARC's runtime-attestation model
- keep verifier provenance explicit and fail closed on unsupported evidence

## Out of Scope

- final trust policy composition
- economic/rights rebinding logic
- milestone qualification and operator runbooks

# Phase 147: DID/Key Binding, Verifier Discovery, and Contract-to-Artifact Parity - Context

## Goal

Tie contract behavior back to ARC identity binding, verifier discovery, and
the existing web3 artifact model.

## Why This Phase Exists

Runtime contracts are not enough unless their identity and discovery
semantics stay aligned with ARC's frozen trust boundary.

## Scope

- key-binding certificate registration flow
- DID-service and canonical-registry discovery parity
- contract event to ARC artifact projection
- negative-path validation for mismatched identity or discovery data

## Out of Scope

- broader oracle runtime implementation
- multi-chain anchoring services
- milestone-level gas/security release packaging

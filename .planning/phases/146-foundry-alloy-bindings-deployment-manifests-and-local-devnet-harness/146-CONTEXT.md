# Phase 146: Foundry/Alloy Bindings, Deployment Manifests, and Local Devnet Harness - Context

## Goal

Generate bindings and reproducible deployment flows for the official web3
contract family over the Base-first topology.

## Why This Phase Exists

The runtime crates cannot consume the contract package until deployment
manifests and generated bindings exist.

## Scope

- reproducible contract build and deployment tooling
- generated Alloy bindings and Rust integration target
- deployment manifests for Base-first and Arbitrum-secondary
- local devnet scripts and fixture environments

## Out of Scope

- deeper identity/discovery parity coverage
- gas/security release qualification
- `arc-link`, `arc-anchor`, or `arc-settle` runtime services

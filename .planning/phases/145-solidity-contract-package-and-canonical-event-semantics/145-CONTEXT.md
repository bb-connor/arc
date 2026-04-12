# Phase 145: Solidity Contract Package and Canonical Event Semantics - Context

## Goal

Realize the frozen official web3 package as compilable Solidity contracts with
canonical events and fail-closed state transitions.

## Why This Phase Exists

ARC cannot claim runtime web3 execution until the official contract family
exists as code rather than only as artifact descriptors.

## Scope

- `contracts/` project scaffold and Solidity source layout
- root registry, escrow, bond vault, identity registry, and price resolver
- canonical events, nonces, sequence numbers, and error semantics
- explicit immutability and access-control posture

## Out of Scope

- generated Alloy bindings and deployment manifests
- local devnet orchestration
- public boundary rewrites and milestone release qualification

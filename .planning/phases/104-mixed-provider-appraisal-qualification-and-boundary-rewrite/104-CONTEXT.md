# Phase 104: Mixed-Provider Appraisal Qualification and Boundary Rewrite - Context

## Goal

Qualify ARC's mixed-provider appraisal contract end to end and update the
public boundary so ARC can honestly claim portable appraisal result interop.

## Why This Phase Exists

The appraisal contract is not shippable until multi-provider inputs, imports,
exports, and negative cases are proven and documented together.

## Scope

- mixed-provider appraisal qualification matrix
- negative-path coverage for stale, contradictory, unsupported, or replayed results
- release, protocol, and partner-proof boundary rewrite
- milestone audit and closeout artifacts

## Out of Scope

- cross-issuer trust packs
- verifier discovery and public trust-bundle distribution
- new verifier families beyond the current portable appraisal contract

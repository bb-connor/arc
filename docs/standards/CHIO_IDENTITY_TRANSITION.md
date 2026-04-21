# Chio Identity and Artifact Transition

**Status:** Phase 29 contract  
**Date:** 2026-03-25

## Purpose

This document defines the compatibility contract for the Chio rename across
portable-trust identity and signed artifact families. It exists so the rename
does not strand historical PACT artifacts or create ambiguous verifier
behavior.

## Identity Decision

### `did:chio`

`did:chio` is the shipped canonical DID method for Chio. Historical `did:chio`
and `did:pact` identifiers remain verifiable for backward compatibility.

That means:

- existing `did:chio` identifiers are canonical
- resolvers and verifiers must continue to accept historical `did:chio` and
  `did:pact` identifiers for verification of older signed artifacts
- historical passports, verifier policies, certifications, and evidence
  packages referencing `did:chio` or `did:pact` do not require rewrites
- no Arc-era or Pact-era Rust aliases remain; `DidChio` is the sole Rust type

## Artifact Schema Decision

Legacy PACT and Chio artifacts remain valid as historical evidence, but the
maintained schema surface is now `chio.*`.

Current Chio behavior:

- new Chio-branded artifacts issue `chio.*` identifiers for the shipped
  checkpoint, DPoP, passport, verifier-policy, challenge/response,
  certification, and evidence-export families
- validators/importers must preserve truthful verification of historical data
- conversion tooling is optional for convenience but not required for truthful
  verification of old artifacts

## Surface Policy by Category

| Category | Legacy policy | Chio policy |
|----------|---------------|------------|
| DID methods | `DidPact` and `DidArc` Rust aliases have been removed | `did:chio` and `DidChio` are canonical |
| Native service API | `NativePactServiceBuilder` / `NativePactService` / `NativeArcServiceBuilder` / `NativeArcService` Rust aliases have been removed | `NativeChioServiceBuilder` / `NativeChioService` are canonical |
| MCP streaming extension | `pactToolStreaming` / `pactToolStream` and `arcToolStreaming` / `arcToolStream` have been removed | `chioToolStreaming` / `chioToolStream` are canonical |
| Receipt and checkpoint schemas | historical data remains verifiable | new issuance uses `chio.*` |
| Passport and verifier-policy schemas | historical data remains verifiable | new issuance uses `chio.*` |
| Certification and evidence-export schemas | historical data remains verifiable | new issuance uses `chio.*` |

## Non-Goals

- retroactively rewriting historical signed objects
- requiring a one-shot migration of all stored artifacts
- preserving broad Pact branding on maintained public APIs after the rename

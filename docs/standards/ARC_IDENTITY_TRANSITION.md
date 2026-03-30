# ARC Identity and Artifact Transition

**Status:** Phase 29 contract  
**Date:** 2026-03-25

## Purpose

This document defines the compatibility contract for the ARC rename across
portable-trust identity and signed artifact families. It exists so the rename
does not strand historical PACT artifacts or create ambiguous verifier
behavior.

## Identity Decision

### `did:arc`

`did:arc` is the shipped canonical DID method for ARC.

That means:

- existing `did:arc` identifiers remain valid
- resolvers and verifiers must continue to accept `did:arc`
- historical passports, verifier policies, certifications, and evidence
  packages referencing `did:arc` do not require rewrites
- no `did:pact` identifier remains on the maintained wire or doc surface
- the only Pact-era DID compatibility retained is the deprecated Rust alias
  `DidPact`, which maps to `DidArc`

## Artifact Schema Decision

Legacy PACT artifacts remain valid as historical evidence, but the maintained
schema surface is now `arc.*`.

Current ARC behavior:

- new ARC-branded artifacts issue `arc.*` identifiers for the shipped
  checkpoint, DPoP, passport, verifier-policy, challenge/response,
  certification, and evidence-export families
- validators/importers must preserve truthful verification of historical data
- conversion tooling is optional for convenience but not required for truthful
  verification of old artifacts

## Surface Policy by Category

| Category | Legacy policy | ARC policy |
|----------|---------------|------------|
| DID methods | deprecated Rust alias `DidPact` remains temporarily for source compatibility | `did:arc` and `DidArc` are canonical |
| Native service API | deprecated Rust aliases `NativePactServiceBuilder` / `NativePactService` remain temporarily | `NativeArcServiceBuilder` / `NativeArcService` are canonical |
| MCP streaming extension | `pactToolStreaming` / `pactToolStream` remain accepted temporarily | `arcToolStreaming` / `arcToolStream` are canonical |
| Receipt and checkpoint schemas | historical data remains verifiable | new issuance uses `arc.*` |
| Passport and verifier-policy schemas | historical data remains verifiable | new issuance uses `arc.*` |
| Certification and evidence-export schemas | historical data remains verifiable | new issuance uses `arc.*` |

## Non-Goals

- retroactively rewriting historical signed objects
- requiring a one-shot migration of all stored artifacts
- preserving broad Pact branding on maintained public APIs after the rename

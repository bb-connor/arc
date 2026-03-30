# Phase 70: AWS Nitro Verifier Adapter - Context

## Goal

Add a real AWS Nitro attestation verifier path that emits the canonical ARC
appraisal contract rather than a cloud-specific side channel.

## Why This Phase Exists

The research calls for a verifier ecosystem, not a single vendor bridge.
Nitro is the first materially different verifier family to add after the
common contract exists because it proves ARC can handle enclave-style evidence
without rewriting policy semantics.

## Scope

- AWS Nitro verifier adapter implementation
- chain, document, measurement, and freshness validation
- mapping Nitro claims into ARC appraisal assertions
- adapter-specific regression coverage and operator docs

## Out of Scope

- Google attestation support
- major policy rebinding changes across multiple adapters
- generic cloud-provider abstraction beyond the shared contract

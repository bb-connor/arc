# Phase 61: External Credential Projection and Identity Strategy - Context

## Goal

Define ARC's first standards-native external credential projection and the
identifier strategy that lets portable verifiers consume ARC passport truth
without replacing ARC-native identity semantics.

## Why This Phase Exists

`v2.11` proved one OID4VCI-compatible path, but ARC still lacks a wallet-legible
credential format and metadata strategy that can travel beyond ARC-native file
and holder-challenge flows.

## Scope

- SD-JWT VC projection over current ARC passport truth
- external issuer identity, type metadata, and signing-key strategy
- claim-selection and provenance strategy for portable fields

## Out of Scope

- full verifier-side OID4VP transport
- public wallet networks or DIDComm
- generic global `did:arc` resolution

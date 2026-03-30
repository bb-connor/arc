# Phase 65: OID4VP Verifier Profile and Request Transport - Context

## Goal

Make ARC a real OID4VP verifier for the ARC SD-JWT VC profile through one
auditable, replay-safe request and response transport profile.

## Why This Phase Exists

`v2.13` made ARC credentials wallet-legible, but ARC still lacks a generic
verifier-side standards flow. The next honest step is a narrow OID4VP
verifier lane instead of more ARC-native challenge transport.

## Scope

- OID4VP request-object creation, signing, and transaction storage
- `request_uri` distribution for by-reference request transport
- same-device redirect and cross-device QR launch artifacts
- `direct_post.jwt` response handling for the ARC SD-JWT VC profile only
- fail-closed validation for nonce, audience, state, replay, and disclosure

## Out of Scope

- generic multi-format verifier support
- DIDComm, public wallet directories, or OpenID Federation
- production wallet software

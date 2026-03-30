# Phase 56: External Verifier Interop and Compatibility Qualification - Research

**Researched:** 2026-03-28
**Domain:** external portable-credential interop proof
**Confidence:** HIGH

## Summary

The research bar for `v2.11` is not "claim the whole wallet ecosystem." It is
"show one real external path over the new issuance, lifecycle, and holder
transport layers without inventing global trust."

The narrowest defensible proof is:

1. operator creates ARC issuance or verifier state on the authenticated admin
   plane
2. an external raw-HTTP client consumes the public issuer metadata and holder
   transport surfaces directly
3. the client exchanges ARC-native JSON artifacts without ARC CLI wrappers
4. docs make clear that this is ARC-specific interop, not generic OID4VP or
   public wallet-marketplace support

## Research Basis

- `docs/research/DEEP_RESEARCH_1.md` treats DID/VC portability and OID4VCI as
  longer-horizon ecosystem bridges rather than a 2026 requirement to support
  every wallet standard immediately.
- The same document argues ARC should be adapter-first and standards-aligned,
  which favors one honest HTTP interop fixture over a broad unsupported claim.
- Phase-55 research already fixed the key trust boundary: holder transport must
  remain challenge-bound and must not silently widen authority.

## Recommended Proof

- use raw HTTP against:
  - `GET /.well-known/openid-credential-issuer`
  - `POST /v1/passport/issuance/token`
  - `POST /v1/passport/issuance/credential`
  - `GET /v1/public/passport/challenges/{challenge_id}`
  - `POST /v1/public/passport/challenges/verify`
- keep admin-state creation explicit and authenticated
- treat the raw-HTTP test plus focused docs as the compatibility qualification
  proof for `VC-04`

## Non-Goals

- generic OID4VP compatibility claim
- DIDComm or mobile push-wallet transport
- external verifier discovery or public trust registry
- any claim that ARC passports are now generic VC wallet artifacts beyond the
  documented ARC-specific transport profile

# Chio Public Identity Profile

This profile defines Chio's bounded public identity and wallet-network claim
over the existing Chio portable-trust, OID4VCI, OID4VP, discovery, federation,
and cross-issuer substrate.

## Artifact Family

- `chio.public-identity-profile.v1`
- `chio.public-wallet-directory-entry.v1`
- `chio.public-wallet-routing-manifest.v1`
- `chio.identity-interop-qualification-matrix.v1`

## Bounded Claim

Chio may describe a broader public identity and wallet network only when:

- `did:chio` remains the provenance anchor for subject and issuer mapping
- broader DID methods such as `did:web`, `did:key`, and `did:jwk` stay
  compatibility inputs rather than ambient trust roots
- wallet directory entries remain verifier-bound, reviewable, and fail closed
  on unknown or contradictory wallet-family inputs
- routing manifests require signed request objects, replay anchors, and
  mismatch rejection instead of ambient directory trust
- qualification covers supported and fail-closed multi-wallet,
  multi-issuer, and cross-operator scenarios before Chio claims broader public
  interop

## Validation Rules

- public identity profiles fail closed if they drop `did:chio`, native passport
  compatibility, the portable VC families, or the replay-safe transport set
- wallet directory entries fail closed unless verifier binding, manual subject
  review, and anti-ambient-trust guardrails stay explicit
- routing manifests fail closed unless same-device, cross-device, and relay
  transport modes are all present and replay-safe OID4VP request handling
  remains mandatory
- qualification must cover `IDMAX-01` through `IDMAX-05`

## Non-Goals

This profile does not claim:

- universal identity trust across arbitrary DID methods
- public wallet routing as ambient admission, trust, or scoring authority
- unbounded OID4VP, DIDComm, or arbitrary wallet compatibility
- automatic subject rebinding or cross-issuer admission widening
- hosted release publication without the existing external workflow gates

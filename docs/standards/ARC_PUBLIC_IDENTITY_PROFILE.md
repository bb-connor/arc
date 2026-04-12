# ARC Public Identity Profile

This profile defines ARC's bounded public identity and wallet-network claim
over the existing ARC portable-trust, OID4VCI, OID4VP, discovery, federation,
and cross-issuer substrate.

## Artifact Family

- `arc.public-identity-profile.v1`
- `arc.public-wallet-directory-entry.v1`
- `arc.public-wallet-routing-manifest.v1`
- `arc.identity-interop-qualification-matrix.v1`

## Bounded Claim

ARC may describe a broader public identity and wallet network only when:

- `did:arc` remains the provenance anchor for subject and issuer mapping
- broader DID methods such as `did:web`, `did:key`, and `did:jwk` stay
  compatibility inputs rather than ambient trust roots
- wallet directory entries remain verifier-bound, reviewable, and fail closed
  on unknown or contradictory wallet-family inputs
- routing manifests require signed request objects, replay anchors, and
  mismatch rejection instead of ambient directory trust
- qualification covers supported and fail-closed multi-wallet,
  multi-issuer, and cross-operator scenarios before ARC claims broader public
  interop

## Validation Rules

- public identity profiles fail closed if they drop `did:arc`, native passport
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

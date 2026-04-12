# ARC Credential Interop Guide

This guide explains the narrow portable-credential interop path ARC currently
ships, plus the bounded public identity-network contract layered on top of it.

## What ARC Proves Today

ARC now proves two external portability paths over the shipped portable
credential surfaces:

1. fetch ARC issuer metadata from
   `GET /.well-known/openid-credential-issuer`
2. optionally fetch portable issuer key material and type metadata from
   `GET /.well-known/jwks.json` and
   `GET /.well-known/arc-passport-sd-jwt-vc` or
   `GET /.well-known/arc-passport-jwt-vc-json`
3. redeem a pre-authorized code at
   `POST /v1/passport/issuance/token`
4. redeem either a native ARC `AgentPassport` or a projected portable
   `application/dc+sd-jwt` or `jwt_vc_json` credential at
   `POST /v1/passport/issuance/credential`
5. fetch ARC verifier metadata from
   `GET /.well-known/arc-oid4vp-verifier`
6. fetch a signed OID4VP request object from
   `GET /v1/public/passport/oid4vp/requests/{request_id}` or resolve the same
   verifier transaction through the HTTPS cross-device launch URL returned by
   the verifier
7. submit the signed `direct_post.jwt` holder response to
   `POST /v1/public/passport/oid4vp/direct-post`
8. fetch a stored ARC-native verifier challenge from
   `GET /v1/public/passport/challenges/{challenge_id}`
9. submit the signed ARC-native holder response to
   `POST /v1/public/passport/challenges/verify`

The release qualification lane proves that flow with a non-CLI raw HTTP client
against the live trust-control service.

## What The Artifacts Still Are

- issuer and subject identities remain `did:arc`
- the native delivery lane remains the ARC `AgentPassport` artifact
- the standards-native delivery lane is a signed projection over that same
  passport truth, not a second source of trust
- verifier portability now uses a narrow signed OID4VP request-object profile
  over the projected passport lane
- ARC-native challenge presentation remains a separate signed ARC challenge and
  signed ARC holder response lane
- lifecycle and replay truth remain operator-scoped mutable side state, not
  new trust roots
- ARC now also ships one bounded public identity profile over `did:arc` plus
  explicit `did:web`, `did:key`, and `did:jwk` compatibility inputs, one
  verifier-bound wallet-directory entry, one replay-safe wallet-routing
  manifest, and one qualification matrix that proves supported and fail-closed
  multi-wallet or cross-operator cases before broader interop is claimed

## Admin Versus Holder Surfaces

Admin/operator surfaces:

- `POST /v1/passport/issuance/offers`
- `POST /v1/passport/challenges`
- verifier policy CRUD
- lifecycle publish and revoke

Holder/public surfaces:

- `GET /.well-known/openid-credential-issuer`
- `GET /.well-known/arc-oid4vp-verifier`
- `GET /.well-known/jwks.json`
- `GET /.well-known/arc-passport-sd-jwt-vc`
- `GET /.well-known/arc-passport-jwt-vc-json`
- `POST /v1/passport/issuance/token`
- `POST /v1/passport/issuance/credential`
- `GET /v1/public/passport/statuses/resolve/{passport_id}`
- `GET /v1/public/passport/wallet-exchanges/{request_id}`
- `GET /v1/public/passport/oid4vp/requests/{request_id}`
- `GET /v1/public/passport/oid4vp/launch/{request_id}`
- `POST /v1/public/passport/oid4vp/direct-post`
- `GET /v1/public/passport/challenges/{challenge_id}`
- `POST /v1/public/passport/challenges/verify`

ARC keeps those surfaces separate on purpose so public transport does not
silently widen verifier admin authority.

If no portable signing key is configured, ARC omits the projected portable
profiles from issuer metadata, does not publish `jwksUri`, and returns `404`
from the portable `JWKS` and portable type-metadata endpoints.

## Portable Lifecycle Semantics

When a delivered credential carries `arcCredentialContext.passportStatus`,
that sidecar points at mutable operator lifecycle truth instead of copying
lifecycle state into the credential itself.

- each `resolveUrl` is a base endpoint; consumers resolve one passport at
  `GET {resolveUrl}/{passport_id}`
- `cacheTtlSecs` is mandatory whenever ARC advertises a public lifecycle
  `resolveUrl`, and tells consumers how long a fetched lifecycle response may
  be treated as fresh
- only `active` is a healthy portable lifecycle state

| Lifecycle state | Meaning | Portable consumer posture |
| --- | --- | --- |
| `active` | the published passport is still current | healthy |
| `stale` | the published passport is still current, but the last lifecycle update is older than `cacheTtlSecs` | fail closed |
| `superseded` | the passport was replaced by a newer published passport | fail closed |
| `revoked` | the operator revoked the published passport | fail closed |
| `notFound` | no published lifecycle truth exists for that passport id | fail closed |
| malformed or missing TTL-backed distribution metadata | lifecycle truth is unavailable or untrustworthy | fail closed |

## Compatibility Boundary

Shipped:

- one OID4VCI-compatible native issuance profile for `AgentPassport`
- two standards-native projected issuance profiles:
  `arc_agent_passport_sd_jwt_vc` with format `application/dc+sd-jwt`, and
  `arc_agent_passport_jwt_vc_json` with format `jwt_vc_json`
- one issuer `JWKS` and one portable type-metadata contract per advertised
  projected profile
- one portable lifecycle distribution and public resolution contract
- one signed public issuer-discovery document, one signed public
  verifier-discovery document, and one signed transparency snapshot over those
  metadata surfaces, each with explicit informational-only/manual-review
  import guardrails
- one narrow OID4VP verifier profile with:
  one transport-neutral wallet exchange descriptor and canonical transaction
  state,
  one optional verifier-scoped identity assertion envelope for subject and
  continuity context,
  one bounded hosted sender-constrained continuation contract over DPoP,
  mTLS thumbprint binding, and one attestation-confirmation profile,
  `client_id_scheme=redirect_uri`, `response_type=vp_token`,
  `response_mode=direct_post.jwt`, one signed request-object `request_uri`,
  one HTTPS cross-device launch URL, one ARC verifier metadata document, and
  one verifier `JWKS` trust bootstrap
- one ARC-native holder presentation transport over public challenge fetch and
  public response submit routes
- one raw-HTTP external client proof in release qualification

Not shipped:

- generic OID4VP or SIOP compatibility beyond ARC's documented verifier
  request-object profile
- DIDComm or mobile-wallet messaging stacks
- generic SD-JWT VC or JWT VC interoperability beyond ARC's documented
  passport profile family
- permissionless public issuer, verifier, identity, or wallet networks, or any
  claim that public discovery visibility widens local trust automatically
- any claim that ARC passports are generic VC wallet artifacts outside the
  documented ARC transport profile

The wallet exchange descriptor is intentionally narrower than a generic wallet
session protocol:

- `exchangeId` is aligned to the verifier `request_id`
- relay delivery reuses the same HTTPS launch URL as cross-device delivery
- transaction state is bounded to `issued`, `consumed`, or `expired`
- optional `identityAssertion` remains verifier-scoped continuity metadata
  bound to the same `exchangeId`
- contradictory or replayed exchange state fails closed instead of being
  repaired heuristically

When the verifier opts in, `identityAssertion` carries:

- `verifierId`, which must match the verifier `client_id`
- `subject` and `continuityId` for bounded session or login continuity
- optional `provider` and `sessionHint`
- `issuedAt`, `expiresAt`, and `boundRequestId`

ARC treats that object as continuity context only. It does not widen wallet or
credential authority, and stale or mismatched assertions fail closed.

When the verifier continues from the wallet exchange into ARC's hosted
authorization edge, it may also opt into one bounded sender-constrained
contract:

- `arc_sender_dpop_public_key`
- `arc_sender_mtls_thumbprint_sha256`
- `arc_sender_attestation_sha256`

ARC treats these as continuity constraints, not as independent authority
artifacts. DPoP and mTLS bind the runtime sender to the issued token, while
the attestation digest is only accepted when it matches the carried
`runtimeAssuranceEvidenceSha256` and is paired with DPoP or mTLS. Missing,
replayed, or contradictory sender proof fails closed.

## Cross-Issuer Portfolios

ARC now also supports one bounded cross-issuer composition contract over the
same passport truth:

- `arc.cross-issuer-portfolio.v1` for a visible holder or operator portfolio
- `arc.cross-issuer-trust-pack.v1` for explicit local activation policy
- `arc.cross-issuer-migration.v1` for explicit subject or issuer continuity

The important boundary is conservative:

- a portfolio is an evidence container, not a synthetic new trust root
- imported or migrated entries stay distinguishable from native local entries
- visibility does not imply admission
- trust-pack evaluation remains per entry and may activate only a subset of the
  visible portfolio
- a subject mismatch fails closed unless one signed migration artifact links
  that entry to the portfolio subject
- duplicate or contradictory migration provenance fails closed

ARC still does not claim automatic federation admission, ambient trust from
public identity or wallet discovery visibility, or a synthetic cross-issuer
trust score.

## Public Identity Network Contract

ARC's broadened public identity claim is still bounded and machine-readable.
The shipped artifact family is:

- `arc.public-identity-profile.v1`
- `arc.public-wallet-directory-entry.v1`
- `arc.public-wallet-routing-manifest.v1`
- `arc.identity-interop-qualification-matrix.v1`

The important boundary stays conservative:

- `did:arc` remains the provenance anchor even when a public profile names
  `did:web`, `did:key`, or `did:jwk` as compatibility inputs
- public wallet-directory entries remain verifier-bound references to existing
  issuer, verifier, and portable-profile state
- wallet-routing manifests require signed request objects, replay anchors, and
  explicit fail-closed handling for subject mismatch, stale routing, and
  cross-operator issuer mismatch
- qualification must cover supported and fail-closed multi-wallet,
  multi-issuer, and cross-operator cases before ARC claims broader public
  identity interoperability

## Current Portable Profile Contracts

ARC now publishes one explicit portable claim catalog and one explicit
portable identity-binding contract per projected profile.

### SD-JWT VC

For the projected `application/dc+sd-jwt` lane:

Always disclosed claims:

- `iss`
- `sub`
- `vct`
- `cnf`
- `arc_passport_id`
- `arc_subject_did`
- `arc_credential_count`

Selectively disclosable claims:

- `arc_issuer_dids`
- `arc_merkle_roots`
- `arc_enterprise_identity_provenance`

Optional portable claims:

- `arc_passport_status`

Portable identity binding is defined separately from the claim catalog:

- portable subject claim: `sub`
- subject confirmation material: `cnf.jwk`
- ARC subject provenance claim: `arc_subject_did`
- portable issuer claim: `iss`
- ARC issuer provenance claim: `arc_issuer_dids`
- ARC enterprise provenance claim: `arc_enterprise_identity_provenance`
- provenance anchor: `did:arc`

Unsupported disclosure keys or unsupported subject/issuer rebinding patterns
fail closed. ARC does not yet claim generic verifier-request negotiation
beyond this fixed profile.

### JWT VC JSON

For the projected `jwt_vc_json` lane:

- ARC keeps the same portable subject and issuer binding model:
  `sub` plus `cnf.jwk` for subject binding, `iss` for issuer binding, and
  `did:arc` provenance anchored through `vc.credentialSubject.id` and
  `vc.credentialSubject.arcIssuerDids`
- the ARC passport projection is carried in `vc.type` and
  `vc.credentialSubject.*` fields instead of `vct` and SD disclosures
- ARC publishes the same ARC portable claim catalog, but the profile declares
  `supportsSelectiveDisclosure=false`, so the ARC claims that are selectively
  disclosable in the SD-JWT VC profile are always disclosed in this JWT VC
  profile
- malformed JWT VC payloads, mismatched compact-profile formats, or missing
  holder-binding material fail closed

## Why This Is Still Useful

This interop profile is enough for:

- partner pilots that want a standards-legible issuance surface
- relying parties that can consume ARC JSON over HTTPS without embedding ARC
  CLI workflows
- wallet or verifier experiments that need one honest transport contract
  before broader ecosystem adapters exist

It is intentionally not a claim that ARC has already solved every wallet
ecosystem problem.

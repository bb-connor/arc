# ARC Portable Trust Profile

## Purpose

This document is the standards-submission draft for ARC portable trust as
currently shipped.

It defines the interoperable artifact layer for self-certifying identity,
portable reputation credentials, verifier policies, challenge/response
presentation, a narrow OID4VP verifier bridge, holder-facing public transport
over stored verifier challenges, federated evidence handoff, and
operator-scoped certification discovery.

## Scope

The profile covers:

- `did:arc`
- `arc.agent-passport.v1`
- `arc.passport-verifier-policy.v1`
- `arc.agent-passport-presentation-challenge.v1`
- `arc.agent-passport-presentation-response.v1`
- one OID4VCI-compatible pre-authorized issuance profile for
  `arc.agent-passport.v1`
- two projected portable credential profiles:
  `arc_agent_passport_sd_jwt_vc` with format `application/dc+sd-jwt`, and
  `arc_agent_passport_jwt_vc_json` with format `jwt_vc_json`
- one issuer `JWKS` publication contract plus one type-metadata document per
  projected ARC passport profile
- one operator-scoped portable passport lifecycle distribution and resolution
  contract for issued `arc.agent-passport.v1` artifacts
- one narrow OID4VP verifier profile over the projected
  `application/dc+sd-jwt` credential lane
- one operator-scoped holder presentation transport contract over stored
  `arc.agent-passport-presentation-challenge.v1` state
- `arc.evidence_export_manifest.v1`
- `arc.federation-policy.v1`
- `arc.federated-delegation-policy.v1`
- `arc.certify.check.v1`
- `arc.certify.registry.v1`
- `arc.certify.discovery-network.v1`
- optional normalized `runtimeAttestation` evidence embedded inside portable
  credential evidence records

The profile does not cover:

- a global trust registry
- public wallet distribution
- synthetic cross-issuer trust scoring
- automatic enterprise identity propagation into every artifact
- generic OID4VP, DIDComm, or public-wallet ecosystem compatibility beyond the
  explicitly documented verifier profile

## Terminology

| Term | Meaning |
| --- | --- |
| `did:arc` | Self-certifying Ed25519 DID method |
| passport | Bundle of one or more signed reputation credentials for one subject |
| verifier policy | Signed relying-party policy artifact |
| presentation challenge | Signed verifier challenge for replay-safe presentation |
| presentation response | Signed subject response carrying a filtered passport presentation |
| OID4VCI issuer metadata | HTTPS transport document that advertises ARC passport issuance endpoints |
| federation policy | Signed bilateral policy governing evidence export/import scope |
| delegation policy | Signed ceiling for federated continuation from imported upstream capability context |
| certification registry | Operator-owned mutable status layer over signed certification artifacts |
| discovery network | File-backed list of explicit certification operators queried independently |

## Normative Claims

- `did:arc` method-specific identifiers are lowercase hex Ed25519 public keys
- every shipped passport credential still binds issuer and subject as `did:arc`
- multi-issuer passport bundles are valid only when all credentials name the
  same subject and verify independently
- ARC's OID4VCI-compatible issuance profile exposes one transport shape for the
  existing passport truth: configuration id `arc_agent_passport`, format
  `arc-agent-passport+json`, plus an optional projected configuration id
  `arc_agent_passport_sd_jwt_vc` with format `application/dc+sd-jwt` and an
  optional projected configuration id `arc_agent_passport_jwt_vc_json` with
  format `jwt_vc_json`, operator-authenticated offer creation, and
  holder-facing token plus credential redemption
- when projected portable credential profiles are advertised, the issuer must
  also publish one `JWKS` document plus the matching ARC passport SD-JWT VC
  and/or ARC passport JWT VC JSON type metadata documents rooted at the same
  `credential_issuer`
- when an issuer advertises `arcProfile.passportStatusDistribution`, it is
  advertising an operator-scoped read-only lifecycle resolve plane, not a new
  trust root or public registry
- the projected `application/dc+sd-jwt` credential is derived from a verified
  ARC passport and does not replace ARC-native `did:arc` issuer or subject
  semantics as the source of truth
- the current projected SD-JWT VC claim contract keeps `iss`, `sub`, `vct`,
  `cnf`, `arc_passport_id`, `arc_subject_did`, and `arc_credential_count`
  always disclosed and only permits `arc_issuer_dids`, `arc_merkle_roots`,
  and `arc_enterprise_identity_provenance` as supported disclosures
- the current projected JWT VC JSON claim contract keeps `iss`, `sub`,
  `cnf.jwk`, `vc.type`, `vc.credentialSubject.id`,
  `vc.credentialSubject.arcPassportId`,
  `vc.credentialSubject.arcCredentialCount`,
  `vc.credentialSubject.arcIssuerDids`,
  `vc.credentialSubject.arcMerkleRoots`, and
  `vc.credentialSubject.arcEnterpriseIdentityProvenance` anchored in the
  signed JWT VC payload, and declares the ARC claim catalog with
  `supportsSelectiveDisclosure=false`
- when a delivered credential response includes
  `arcCredentialContext.passportStatus`, that sidecar is only a reference to
  mutable lifecycle truth; it does not mutate the signed passport artifact
- portable lifecycle resolution is read-only and may be exposed publicly at an
  operator URL, but publication and revocation remain explicit operator
  actions
- each `resolve_url` is a base endpoint; consumers resolve one passport at
  `GET {resolve_url}/{passport_id}`
- portable lifecycle consumers must treat `superseded`, `revoked`, `notFound`,
  malformed lifecycle responses, and stale lifecycle responses beyond the
  published cache hint as non-healthy states
- only `active` is a healthy portable lifecycle state; `superseded` must keep
  its replacement pointer instead of being silently collapsed into revocation
- the OID4VCI `credential_issuer` is a transport identifier only; it does not
  replace the delivered credential's `did:arc` issuer identity
- pre-authorized codes and issuance access tokens must be single-use and
  short-lived
- ARC's OID4VP verifier profile is intentionally narrow: one signed
  request-object `request_uri`, one `client_id_scheme=redirect_uri`,
  one `response_type=vp_token`, one `response_mode=direct_post.jwt`, one
  projected credential type `arc_agent_passport_sd_jwt_vc`, one verifier
  metadata document at `/.well-known/arc-oid4vp-verifier`, and one verifier
  `JWKS` trust bootstrap
- OID4VP verifier request signing and projected credential verification may
  trust more than one current or previous verifier key when the operator has
  explicitly published that trusted set through the verifier `JWKS`
- same-device and cross-device launch artifacts must resolve to the same
  replay-safe verifier transaction truth instead of creating a second request
  store
- verifier acceptance is per credential; no synthetic aggregate issuer or score
  is invented
- challenge/response verification must reject replay and invalid verifier
  policy bindings
- holder-facing transport may expose public read and public submit routes for
  stored verifier challenges, but those routes must remain bound to the
  original challenge id and must not expose verifier policy administration or
  other admin mutation
- public holder fetch or submit routes must fail closed when the challenge id
  is missing, the stored challenge is expired or already consumed, or the
  holder-submitted challenge state does not match the stored verifier truth
- evidence-export and delegation artifacts must carry explicit signed policy
  material rather than implicit trust assumptions
- certification discovery must preserve operator provenance instead of merging
  multiple registries into one synthetic global state
- public certification discovery may expose read-only metadata, search,
  resolve, and transparency surfaces; publication fan-out and dispute mutation
  remain explicit operator actions
- public certification listing visibility must stay separate from runtime trust
  admission; consumers must import marketplace evidence through explicit local
  policy and fail closed on stale, mismatched, revoked, superseded, or
  disputed listings
- when portable evidence carries `runtimeAttestation`, it must preserve the
  verifier identity, normalized assurance tier, validity window, and evidence
  digest used by the issuer
- when portable evidence carries `runtimeAttestation.workloadIdentity`, ARC
  currently standardizes only SPIFFE-derived `{ scheme, credentialKind, uri,
  trustDomain, path }` mappings; non-SPIFFE `runtimeIdentity` values remain
  opaque compatibility metadata
- verifier-specific attestation claims may be preserved as opaque structured
  data, but this profile does not standardize their meaning across issuers or
  verifiers
- ARC's concrete verifier bridges are Azure Attestation JWT normalization,
  AWS Nitro attestation document verification, and Google Confidential VM JWT
  normalization. They preserve vendor-specific claims under `claims.azureMaa`,
  `claims.awsNitro`, or `claims.googleAttestation`, may project typed workload
  identity only where ARC has an explicit mapping contract, and must not raise
  normalized assurance above raw `attested` before explicit
  `trusted_verifiers` policy is applied
- `trusted_verifiers` rules may additionally constrain verifier family and a
  bounded set of normalized assertion/value pairs; this profile does not
  standardize vendor claim vocabularies beyond those explicit ARC rule fields

## Compatibility Rules

- unknown schema identifiers must be rejected
- legacy `arc.*` passport, verifier-policy, challenge, response, evidence, and
  delegation schemas remain valid compatibility inputs
- `arc.certify.check.v1`, `arc.certify.registry.v1`, and
  `arc.certify.discovery-network.v1` remain the supported certification
  compatibility inputs
- additive fields are allowed where signature verification still succeeds
- consumers must not invent cross-issuer trust semantics not present in the
  artifact contract
- unsupported generic VC profiles or incompatible issuance-format requests must
  be rejected fail closed rather than silently mapped to ARC passports
- issuance flows that claim portable lifecycle support must fail closed when
  the target passport has not been published active with at least one resolve
  URL
- portable credential requests for `application/dc+sd-jwt` must fail closed if
  the issuer has not explicitly configured a signing key and published the
  corresponding metadata surfaces
- portable credential requests for `jwt_vc_json` must fail closed if the
  issuer has not explicitly configured a signing key and published the
  corresponding metadata surfaces
- if no signing key is configured, the issuer metadata must omit the projected
  portable profiles and `jwksUri`, and the portable `JWKS` plus type-metadata
  endpoints must fail closed rather than pretending a portable verifier
  surface exists
- projected SD-JWT VC verification must fail closed when holder binding is
  missing or when disclosure keys fall outside the documented ARC profile
- projected JWT VC JSON verification must fail closed when holder binding is
  missing, required ARC credentialSubject claims are absent, or a compact
  credential is requested under the wrong advertised profile format
- ARC-native holder-facing transport remains challenge-bound; consumers must
  not silently reinterpret that ARC-native lane as generic OID4VP, DIDComm, or
  another wallet protocol
- ARC's shipped OID4VP support is verifier-side and profile-bound; consumers
  must not widen it into generic wallet or verifier compatibility claims
- imported evidence must remain distinguishable from native local receipts in
  reporting and analytics
- portable consumers may preserve unknown runtime-attestation claim fields, but
  they must not reinterpret them as standardized cross-verifier semantics
- portable consumers must fail closed if an explicit
  `runtimeAttestation.workloadIdentity` conflicts with the carried raw
  `runtimeIdentity`
- vendor-specific verifier bridges such as Azure Attestation JWTs must keep
  signing-key trust, issuer binding, and attestation-type allowlists explicit
  rather than silently trusting provider defaults
- if verifier trust rules are configured, portable consumers must fail closed
  on stale or unmatched verifier evidence rather than silently falling back to
  stronger runtime-assurance semantics

## Non-Goals

- public portability marketplace or wallet network
- generic wallet qualification for non-ARC credential formats or generic
  presentation standards claims
- standardization of reputation scoring formulas across issuers
- automatic federation of all enterprise identity metadata
- guarantee that every verifier shares the same policy thresholds
- a single mutable global certification authority
- standardization of vendor-specific TEE or attestation claim vocabularies

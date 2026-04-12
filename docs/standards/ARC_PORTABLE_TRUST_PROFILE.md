# ARC Portable Trust Profile

## Purpose

This document is the standards-submission draft for ARC portable trust as
currently shipped.

It defines the interoperable artifact layer for self-certifying identity,
portable reputation credentials, verifier policies, challenge/response
presentation, a narrow OID4VP verifier bridge, holder-facing public transport
over stored verifier challenges, federated evidence handoff, one bounded
public identity-profile plus verifier-bound wallet-directory and routing
contract, and operator-scoped certification discovery.

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
- `arc.public-identity-profile.v1`
- `arc.public-wallet-directory-entry.v1`
- `arc.public-wallet-routing-manifest.v1`
- `arc.identity-interop-qualification-matrix.v1`
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
- permissionless public wallet distribution or ambient-trust routing
- synthetic cross-issuer trust scoring
- automatic enterprise identity propagation into every artifact
- generic OID4VP, DIDComm, or public-wallet ecosystem compatibility beyond the
  explicitly documented verifier profile plus bounded public identity-profile
  and wallet-routing contracts

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
- cross-issuer portfolio artifacts may make several issuers or several subject
  lineages visible at once, but that visibility must remain distinct from
  local trust activation
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
- ARC's outward-facing appraisal artifact explicitly separates `evidence`,
  `verifier`, `claims`, and `policy` sections so raw evidence identity,
  normalized ARC-visible assertions, vendor-scoped claims, and policy-facing
  conclusions do not collapse into one opaque blob
- ARC's portable normalized-claim vocabulary is explicit and versioned; the
  current shared codes are `attestation_type`, `runtime_identity`,
  `workload_identity_scheme`, `workload_identity_uri`, `module_id`,
  `measurement_digest`, `measurement_registers`, `hardware_model`, and
  `secure_boot_state`
- ARC's portable reason taxonomy is explicit and versioned; reason objects
  now carry one shared `{ code, group, disposition, description }` contract
  while the legacy flat `reasonCodes` array remains compatibility metadata
- ARC can export one signed appraisal result over the portable appraisal
  artifact boundary, but that export remains distinct from local runtime
  policy activation and from raw foreign evidence import
- imported signed appraisal results must remain subject- and
  issuer-provenanced, signer-authenticated, and explicitly mapped through one
  local import policy over trusted issuers, trusted signer keys, verifier
  family allowlists, freshness ceilings, optional tier attenuation, and
  required portable claim values
- the currently qualified appraisal-result exchange matrix is Azure
  Attestation JWT normalization, AWS Nitro attestation document verification,
  Google Confidential VM JWT normalization, and ARC's bounded
  `enterprise_verifier` signed-envelope bridge over the shared signed-result
  and local import-policy contract
- ARC's concrete verifier bridges are Azure Attestation JWT normalization,
  AWS Nitro attestation document verification, Google Confidential VM JWT
  normalization, and ARC's bounded `enterprise_verifier` envelope adapter.
  They preserve vendor-specific claims under `claims.azureMaa`,
  `claims.awsNitro`, `claims.googleAttestation`, or
  `claims.enterpriseVerifier`, may project typed workload identity only where
  ARC has an explicit mapping contract, and must not raise normalized
  assurance above raw `attested` before explicit `trusted_verifiers` policy is
  applied
- ARC now also defines one bounded verifier-metadata layer over that appraisal
  boundary:
  one signed `arc.runtime-attestation.verifier-descriptor.v1`,
  one signed `arc.runtime-attestation.reference-values.v1`,
  and one signed `arc.runtime-attestation.trust-bundle.v1`
- verifier descriptors must make verifier identity, verifier family, adapter,
  compatible attestation schemas, canonical appraisal schemas, signer-key
  fingerprints, and validity window explicit
- reference-value sets must bind to one descriptor id and one attestation
  schema, preserve one explicit lifecycle state of `active`, `superseded`, or
  `revoked`, and carry replacement or revocation metadata only when that state
  requires it
- trust bundles must be versioned and signed, and they must not blur portable
  verifier metadata into local trust activation or policy admission
- `trusted_verifiers` rules may additionally constrain verifier family and a
  bounded set of normalized assertion/value pairs; this profile does not
  standardize vendor claim vocabularies beyond those explicit ARC rule fields
- ARC now also defines one bounded cross-issuer composition layer over
  existing passport artifacts:
  one `arc.cross-issuer-portfolio.v1`,
  one signed `arc.cross-issuer-trust-pack.v1`,
  and one signed `arc.cross-issuer-migration.v1`
- cross-issuer migration remains explicit and time-bounded; consumers must not
  infer subject continuity from overlapping display claims, issuer names, or
  discovery metadata alone
- trust packs may activate issuers, profile families, entry kinds,
  certification references, migration ids, and active-lifecycle requirements,
  but they must not manufacture a universal cross-issuer trust score
- ARC now also defines one bounded public discovery layer over those issuer
  and verifier surfaces:
  one signed `arc.public-issuer-discovery.v1`,
  one signed `arc.public-verifier-discovery.v1`,
  and one signed `arc.public-discovery-transparency.v1`
- public discovery artifacts must preserve explicit import guardrails of
  informational-only visibility, explicit local policy import, and manual
  review before any activation
- stale, unsigned, malformed, contradictory, or incomplete public discovery
  artifacts must fail closed and must not be treated as local trust-admission
  signals
- ARC now also defines one bounded public identity-network overlay over those
  existing passport, projected credential, discovery, and verifier surfaces:
  one `arc.public-identity-profile.v1`,
  one `arc.public-wallet-directory-entry.v1`,
  one `arc.public-wallet-routing-manifest.v1`,
  and one `arc.identity-interop-qualification-matrix.v1`
- public identity profiles must preserve `did:arc` as the provenance anchor
  while making any broader `did:web`, `did:key`, or `did:jwk` compatibility
  input explicit
- wallet-directory entries and routing manifests must preserve explicit
  verifier binding, manual subject review, signed-request routing, replay
  anchors, and fail-closed rejection of unknown wallet families or
  cross-operator issuer mismatch
- the public identity-network overlay must not widen portable visibility into
  ambient trust, admission, or scoring authority

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
- imported or migrated passport portfolio entries must remain distinguishable
  from native local entries, and visibility of a portfolio entry must not be
  treated as admission unless one explicit local trust pack activates it
- cross-subject portfolio composition must fail closed without one explicit
  signed migration artifact that links the entry subject to the portfolio
  subject
- duplicate migration ids, empty trust-pack activation values, or mismatched
  lifecycle projections must be rejected fail closed rather than heuristically
  repaired
- portable consumers may preserve unknown runtime-attestation claim fields, but
  they must not reinterpret them as standardized cross-verifier semantics
- imported signed appraisal results must fail closed when signature
  verification fails, the exporter policy rejected the appraisal, the result
  or evidence is stale, the nested evidence schema and verifier family do not
  match ARC's bounded bridge inventory, or the local import policy cannot map
  the portable claim set truthfully
- verifier descriptors must fail closed when they are stale, unsigned, name an
  empty verifier identity, advertise empty signer-key fingerprints, or drift
  away from ARC's canonical appraisal artifact or result schemas
- trust bundles must fail closed when they are stale, unsigned, contain
  duplicate descriptor or reference-value ids, carry unknown descriptor
  references, mismatch descriptor verifier family or attestation schema, or
  present ambiguous active reference values for one
  `{descriptorId, attestationSchema}` slot
- portable consumers must not assume one-time consume or replay-registry
  semantics for imported appraisal results; ARC's current replay defense at
  that boundary is explicit signature plus freshness validation
- portable consumers must fail closed if an explicit
  `runtimeAttestation.workloadIdentity` conflicts with the carried raw
  `runtimeIdentity`
- vendor-specific verifier bridges such as Azure Attestation JWTs must keep
  signing-key trust, issuer binding, and attestation-type allowlists explicit
  rather than silently trusting provider defaults
- portable consumers may use ARC's published appraisal inventory to understand
  which current bridge maps to which vendor namespace, normalized key set,
  normalized claim codes, and default reason codes, but they must not treat
  that inventory as proof that every vendor claim is cross-verifier
  equivalent
- if verifier trust rules are configured, portable consumers must fail closed
  on stale or unmatched verifier evidence rather than silently falling back to
  stronger runtime-assurance semantics

## Non-Goals

- permissionless public portability marketplace or wallet network
- generic wallet qualification for non-ARC credential formats or generic
  presentation standards claims beyond ARC's documented public identity-
  profile and routing contract
- standardization of reputation scoring formulas across issuers
- automatic federation of all enterprise identity metadata
- guarantee that every verifier shares the same policy thresholds
- a single mutable global certification authority
- standardization of vendor-specific TEE or attestation claim vocabularies

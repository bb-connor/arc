# Post-v2.20 Portable Identity and Wallet Endgame Plan

**Project:** ARC  
**Scope:** Close the remaining portable identity, wallet, discovery, and
cross-issuer gaps beyond the shipped `v2.20` profile  
**Researched:** 2026-03-29  
**Confidence:** MEDIUM-HIGH

## Executive Position

ARC has already closed the first portability ladder:

- `v2.11` added OID4VCI-compatible portable issuance
- `v2.13` widened that lane with projected SD-JWT VC plus lifecycle
- `v2.14` added a narrow verifier-side OID4VP bridge
- `v2.17` added a governed public certification discovery surface
- `v2.20` closed the economic and liability ladder without changing the narrow
  portable identity boundary

That means the post-`v2.20` portability problem is no longer "add OID4VCI" or
"add OID4VP." ARC already ships those, but only as a tightly bounded
ARC-shaped profile.

The remaining endgame is to move from that narrow bridge to a broader,
policy-safe portable identity and wallet ecosystem without losing ARC's
current fail-closed posture.

ARC should treat that remaining work as **four milestones**, not one:

1. **v2.21 Portable Profile Expansion and Status Interop**
2. **v2.22 Wallet Exchange and Identity Assertion Adapters**
3. **v2.23 Cross-Issuer Portability and Trust Packs**
4. **v2.24 Public Issuer and Verifier Discovery Network**

This is the smallest sequence that closes the real gaps from
`docs/research/DEEP_RESEARCH_1.md`:

- broader portable credential profiles
- optional but standards-legible identity assertions where they help
- wallet exchange semantics that are not limited to one ARC request-object lane
- public issuer and verifier discovery that preserves operator provenance
- cross-issuer portability without synthetic trust inflation
- explicit compatibility guardrails and qualification evidence

## Current Shipped Boundary

As of `2026-03-29`, ARC currently ships all of the following:

- one always-available native OID4VCI credential configuration for
  `arc_agent_passport` with format `arc-agent-passport+json`
- one optional projected portable credential configuration for
  `arc_agent_passport_sd_jwt_vc` with format `application/dc+sd-jwt`
- one fixed projected claim contract where `iss`, `sub`, `vct`, `cnf`,
  `arc_passport_id`, `arc_subject_did`, and `arc_credential_count` remain
  anchored in the signed payload and only a small ARC-defined disclosure set is
  allowed
- one operator-scoped lifecycle distribution model where portable consumers
  still resolve passport status through ARC-defined HTTPS resolve URLs and only
  `active` is healthy
- one narrow verifier-side OID4VP profile with:
  `client_id_scheme=redirect_uri`, signed `request_uri` request objects,
  `response_type=vp_token`, `response_mode=direct_post.jwt`, one projected
  credential type, one ARC verifier metadata document, one verifier `JWKS`,
  same-device launch, and one HTTPS cross-device launch URL
- one separate ARC-native holder presentation transport over stored challenge
  state
- `did:arc` remaining the ARC-native issuer and subject source of truth inside
  the shipped passport truth
- public certification discovery for certification artifacts, but not yet a
  public wallet-routing, issuer-directory, or verifier-directory network

ARC does **not** currently claim any of the following:

- generic SD-JWT VC interoperability beyond the documented ARC passport
  projection
- generic `jwt_vc_json`, JSON-LD/Data Integrity VC, or universal proof-family
  support
- generic OID4VP wallet compatibility beyond the documented verifier request
  profile
- SIOP or broader OpenID identity assertion compatibility
- DIDComm or other asynchronous wallet messaging stacks
- public issuer discovery
- public verifier discovery beyond the current ARC verifier metadata document
- cross-issuer portability semantics beyond per-credential verification
- a global wallet network or permissionless trust registry

## Remaining Gap

The real gap after `v2.20` is that ARC can prove **one honest portable lane**,
but it still cannot claim the fuller portable identity and wallet endgame from
the research:

### 1. Credential and profile breadth is still too narrow

ARC supports one ARC-specific SD-JWT VC projection, not a broader portable
profile family. The disclosed claim catalog is still fixed and ARC-shaped.
Portable status is still primarily ARC lifecycle truth exposed through ARC
resolve URLs rather than a more standards-native status surface.

### 2. Portable identity assertions are still absent

ARC can transport credential presentations, but it does not yet define when a
wallet may also need to assert holder identity or session continuity through an
OpenID-style identity artifact. That keeps verifier login, pairwise holder
continuity, and delegated session bootstrap narrower than they need to be.

### 3. Wallet exchange semantics are still single-path

ARC has one OID4VP request-object bridge plus one ARC-native challenge path.
That is enough for a controlled interop profile, but not enough for a broader
wallet ecosystem that spans browser-mediated flows, mobile deep links, and
possibly asynchronous or message-based exchange adapters.

### 4. Public discovery is still missing

ARC Certify can publish certification listings, but there is no equivalent
portable issuer and verifier discovery layer with signed metadata, search,
transparency, freshness, dispute state, and explicit local consume flows.

### 5. Cross-issuer portability is still underspecified

ARC can verify multiple credentials independently, but it does not yet define
how one subject carries a multi-issuer portfolio, how issuer trust packs are
imported, how migration or supersession works across issuers, or how local
policy composes those inputs without inventing a global score.

### 6. Compatibility guardrails are not yet broad enough for ecosystem growth

The current docs are honest, but the broader endgame still needs explicit rules
for:

- profile negotiation
- subject and issuer rebinding
- transport adapter behavior
- discovery import semantics
- cross-issuer aggregation limits
- experimental versus production-grade profile claims

## What "Research Endgame Achieved" Should Mean

ARC should only claim the portable identity and wallet endgame is achieved when
all of the following are true:

1. ARC can issue and verify at least **two standards-legible portable
   credential profiles** over the same passport truth, without mutating
   canonical ARC evidence.
2. ARC supports one **optional identity-assertion lane** for verifier session
   binding or subject continuity where policy requires it, without making it a
   mandatory prerequisite for every presentation.
3. ARC supports **same-device, cross-device, and one asynchronous or
   message-oriented wallet exchange adapter** over one canonical replay-safe
   verifier transaction model.
4. ARC can evaluate a **multi-issuer subject portfolio** using explicit local
   policy, trust packs, status handling, and provenance rules, without
   inventing a synthetic cross-issuer trust score.
5. ARC can expose **public issuer and verifier discovery** through signed,
   freshness-bound, provenance-preserving metadata, search, resolve, and
   transparency surfaces.
6. ARC qualification proves at least one end-to-end path from **public
   discovery -> issuance -> wallet presentation -> verifier validation** using
   external client or wallet stacks, not only ARC-owned reference tooling.

That is the right closure line. It is materially stronger than today's narrow
profile, but still narrower and safer than "ARC is compatible with every VC
wallet."

## Program Requirements

- `PORT-END-01`: ARC supports broader portable credential profiles over one
  canonical passport truth.
- `PORT-END-02`: ARC defines a portable subject and issuer binding model that
  preserves ARC provenance while allowing broader ecosystem identifiers.
- `PORT-END-03`: ARC exposes standards-legible status, revocation, and metadata
  contracts for portable credentials.
- `PORT-END-04`: ARC defines a transport-neutral wallet exchange model with one
  canonical replay-safe verifier transaction state.
- `PORT-END-05`: ARC supports one optional OpenID-style identity assertion lane
  for holder session binding where policy requires it.
- `PORT-END-06`: ARC qualifies more than one wallet or client interaction
  pattern beyond the current narrow bridge.
- `PORT-END-07`: ARC defines cross-issuer portfolio, trust-pack, migration, and
  evaluation semantics.
- `PORT-END-08`: ARC publishes public issuer and verifier discovery surfaces
  that preserve provenance and require explicit local policy import.
- `PORT-END-09`: ARC publishes a compatibility matrix, negative-path
  qualification corpus, and explicit fail-closed guardrails for unsupported or
  experimental profiles.

## Recommended Milestone Sequence

### v2.21 Portable Profile Expansion and Status Interop

**Goal:** Broaden ARC from one ARC-shaped SD-JWT VC projection into a small,
explicit portable profile family with stable subject, issuer, and status
semantics.

**Depends on:** `v2.13`, `v2.14`, `v2.20`

**Requirements:** `PORT-END-01`, `PORT-END-02`, `PORT-END-03`, `PORT-END-09`

#### Phase 93: Portable Claim Catalog and Subject or Issuer Binding Model

**Depends on:** Phase 92

**Scope**

- Define the portable claim catalog ARC is willing to standardize across
  profile families instead of keeping the current claim contract as one fixed
  exception list.
- Separate three identity layers explicitly:
  - ARC-native provenance identity
  - portable issuer identity
  - portable holder or subject binding identity
- Preserve `did:arc` as ARC's internal provenance anchor while allowing
  portable subject or issuer identifiers to be profile-bound and ecosystem
  specific.
- Define when portable `sub` is:
  - a pairwise subject identifier,
  - a holder key binding,
  - an external DID or URI-like subject,
  - or an ARC provenance reference only.
- Define how enterprise identity, runtime assurance, certification references,
  and issuer provenance survive projection without becoming hidden new trust
  roots.

**Recommendation**

Do not make global public `did:arc` resolution the gate for broader
portability. Keep `did:arc` as the internal ARC anchor, but allow portable
profiles to expose HTTPS, pairwise, or DID-based identifiers where the profile
explicitly requires them.

#### Phase 94: Multi-Format Issuance and Verification Profiles

**Depends on:** Phase 93

**Scope**

- Add a second standards-native portable projection beside the current
  `application/dc+sd-jwt` lane.
- Broaden SD-JWT VC support from one ARC-specific request and disclosure
  contract into an explicit ARC-supported SD-JWT VC profile family.
- Add one JOSE-oriented VC profile such as `jwt_vc_json` or an equivalent JWT
  VC delivery lane where it can be projected truthfully from the same passport
  truth.
- Define one shared projection engine so ARC does not drift into multiple
  competing credential truths.
- Make all profile negotiation explicit in issuer metadata and fail closed on
  unsupported format or proof-family requests.
- If there is partner pull for mobile-native credential carriage, allow one
  experimental mdoc or COSE-oriented adapter behind an explicit experimental
  flag and separate qualification boundary.

**Recommendation**

Target broader SD-JWT VC plus one JOSE VC profile first. Keep JSON-LD or Data
Integrity VC work out of the default post-`v2.20` ladder unless an ecosystem
partner makes it necessary.

#### Phase 95: Status, Revocation, and Metadata Convergence

**Depends on:** Phase 94

**Scope**

- Add a standards-legible portable status surface for supported portable
  profiles instead of requiring external consumers to depend only on ARC's
  lifecycle resolve API.
- Map ARC lifecycle states such as `active`, `superseded`, `revoked`, and
  `notFound` into portable verifier outcomes without losing ARC's richer local
  truth.
- Define issuer metadata versioning, integrity, cache rules, and key-rotation
  expectations per profile.
- Define how replacement and supersession are communicated when the portable
  status surface is coarser than ARC lifecycle truth.
- Keep ARC's existing lifecycle API as the richer operator truth and analytics
  plane rather than deleting it.

**Recommendation**

Portable status should become more standards-native, but ARC's richer operator
status plane should remain the canonical source for lifecycle analytics and
replacement reasoning.

#### Phase 96: Profile Qualification and Compatibility Matrix

**Depends on:** Phase 95

**Scope**

- Build a profile compatibility matrix that lists, per credential profile:
  - supported issuance paths
  - supported holder-binding modes
  - supported status methods
  - supported verifier request modes
  - supported claim disclosures
  - experimental versus production-grade status
- Add raw-HTTP and SDK qualification lanes for every shipped portable profile.
- Add negative-path coverage for unsupported formats, missing metadata,
  mismatched subject binding, stale status, unsupported disclosure keys, and
  untrusted issuer material.
- Rewrite the portable docs so ARC no longer describes all non-ARC-shaped VC
  work as one undifferentiated gap.

**Milestone Acceptance Criteria**

1. ARC can issue the same passport truth through at least two
   standards-legible portable credential profiles in addition to the native ARC
   artifact.
2. Profile negotiation, subject binding, and disclosure behavior are explicit
   and fail closed.
3. Portable status and metadata behavior are documented and qualified per
   profile.
4. ARC publishes one clear compatibility matrix that separates supported,
   experimental, and unsupported profile families.

**Validation and Qualification Expectations**

- Golden fixtures proving one passport truth projects deterministically into
  every supported portable profile.
- Integration coverage for issuance, verification, status lookup, and key
  rotation across all supported profiles.
- Negative tests for unsupported proof families, malformed metadata, stale
  status, and identity mismatches.
- At least one raw-HTTP qualification path per supported portable profile.

### v2.22 Wallet Exchange and Identity Assertion Adapters

**Goal:** Make ARC's wallet interop transport-neutral enough for real browser,
mobile, and partner wallet use while keeping verifier state canonical and
auditable.

**Depends on:** `v2.21`

**Requirements:** `PORT-END-04`, `PORT-END-05`, `PORT-END-06`, `PORT-END-09`

#### Phase 97: Identity Assertion and Session Binding Model

**Depends on:** Phase 96

**Scope**

- Decide when ARC needs a holder identity assertion in addition to a presented
  credential.
- Define one optional OpenID-style identity assertion lane for:
  - verifier session bootstrap,
  - pairwise holder continuity,
  - delegated login continuity,
  - or same-device browser handoff where a pure `vp_token` is insufficient.
- Define how an identity assertion is bound to:
  - the verifier transaction,
  - the presented credential,
  - the holder key,
  - and any pairwise subject identifier.
- Define explicit verifier policy knobs for:
  - `vp_token` only,
  - presentation plus identity assertion,
  - or identity assertion disallowed.

**Recommendation**

SIOP or OpenID identity assertions are warranted only as an **optional**
session-binding and continuity tool. They should not become a universal
mandatory requirement for every ARC presentation.

#### Phase 98: Canonical Wallet Exchange Descriptor

**Depends on:** Phase 97

**Scope**

- Define one transport-neutral wallet exchange descriptor over the canonical
  verifier transaction truth.
- Represent, in one place:
  - request reference or attachment identity,
  - replay-safe nonce or transaction ids,
  - callback or response endpoints,
  - expiration,
  - supported response modes,
  - required identity assertion mode,
  - supported wallet launch methods.
- Render that same descriptor into:
  - same-device `openid4vp://` launch,
  - HTTPS cross-device launch,
  - browser-mediated credential request adapters,
  - and any future asynchronous or message-oriented adapter.

**Recommendation**

ARC should standardize one canonical verifier transaction model first and only
then add launch or messaging adapters. No adapter should get its own private
state machine.

#### Phase 99: Alternative Transport Adapters

**Depends on:** Phase 98

**Scope**

- Add at least one browser- or platform-native wallet adapter beyond the
  current ARC-owned reference holder path.
- Add one asynchronous or message-oriented transport adapter for ecosystems
  where a simple redirect or deep link is not enough.
- If DIDComm is required by a partner ecosystem, implement it as a thin
  adapter that carries ARC's canonical exchange descriptor or verifier
  transaction reference, not as a second independent verification protocol.
- If DIDComm is not required, close this phase with another explicit adapter,
  such as a browser credential API path or signed out-of-band HTTPS handoff.
- Define fail-closed rules for adapter mismatch, stale attachment state,
  divergent request ids, replay, and response-mode drift.

**Recommendation**

Do not make DIDComm the default ARC transport endgame. Treat it as an optional
adapter if a real partner ecosystem requires it. Prefer web-native and
deep-link flows first because they fit ARC's operator-deployed HTTPS model.

#### Phase 100: Multi-Wallet Interop Qualification

**Depends on:** Phase 99

**Scope**

- Qualify at least two wallet classes or client interaction modes:
  - one browser or same-device path
  - one cross-device or mobile path
- Add regression coverage for:
  - missing or invalid identity assertions,
  - nonce or transaction replay,
  - adapter divergence,
  - mismatched holder binding,
  - unsupported response modes,
  - and stale verifier metadata.
- Update docs and partner proof so ARC can claim broader wallet interoperability
  without claiming to be a consumer wallet vendor.

**Milestone Acceptance Criteria**

1. ARC supports more than one wallet launch or exchange path over one canonical
   verifier transaction model.
2. Identity assertions work when verifier policy requires them and remain
   absent when policy does not require them.
3. Any DIDComm or alternative messaging adapter reuses canonical ARC verifier
   transaction truth and fails closed on drift.
4. ARC can qualify at least two wallet or client interaction modes end to end.

**Validation and Qualification Expectations**

- End-to-end tests over same-device, cross-device, and one asynchronous or
  alternative adapter path.
- Replay, mismatched-request, and stale-metadata negative tests shared across
  all adapters.
- Qualification evidence using at least one external wallet or client stack in
  addition to ARC reference tooling.
- Partner-proof walkthrough documenting when verifier policy should require an
  identity assertion and when it should not.

### v2.23 Cross-Issuer Portability and Trust Packs

**Goal:** Let one holder or subject carry multi-issuer ARC-compatible portable
credentials and let verifiers evaluate them with explicit local policy instead
of synthetic global trust.

**Depends on:** `v2.21`, `v2.22`, `v2.17`

**Requirements:** `PORT-END-02`, `PORT-END-07`, `PORT-END-09`

#### Phase 101: Subject Continuity and Portfolio Manifest

**Depends on:** Phase 100

**Scope**

- Define a portfolio manifest for one holder or subject carrying multiple
  portable credentials from different issuers and possibly different supported
  profiles.
- Define subject continuity evidence for:
  - same-key subject continuity,
  - pairwise subject continuity,
  - enterprise-linked subject continuity,
  - or explicitly unlinked credentials in one holder portfolio.
- Require explicit proof or policy for subject linkage. Do not infer subject
  continuity from similar display claims.
- Preserve per-credential issuer provenance and per-credential status state.

**Recommendation**

A portfolio is a holder-assembled evidence set, not a new synthetic portable
identity root.

#### Phase 102: Cross-Issuer Trust Packs and Verifier Policy

**Depends on:** Phase 101

**Scope**

- Define importable trust packs that let a verifier or operator declare:
  - acceptable issuers,
  - acceptable credential profiles,
  - acceptable certification references,
  - acceptable status methods,
  - acceptable runtime assurance evidence,
  - and explicit claim-mapping rules.
- Reuse `ARC Certify` and existing enterprise IAM profile work as trust inputs
  where possible.
- Keep verifier evaluation per credential, even when a portfolio contains
  several credentials from several issuers.
- Define how derived portfolio-level summaries may be reported without becoming
  synthetic trust admission logic.

**Recommendation**

Trust packs should import external issuer and certification facts into local
policy. They should not manufacture a universal ARC trust score across issuers.

#### Phase 103: Migration, Supersession, and Portability Exchange

**Depends on:** Phase 102

**Scope**

- Define how a subject moves from one issuer to another without losing
  portability evidence or verifier clarity.
- Define explicit cross-issuer migration artifacts or linkage records that can
  reference:
  - prior credential ids,
  - prior issuer ids,
  - replacement reason,
  - continuity proof,
  - and effective time bounds.
- Keep supersession local to an issuer unless a cross-issuer migration artifact
  explicitly links the old and new states.
- Define export or import semantics for portable credential evidence packages so
  verifiers and operators can distinguish:
  - native local credentials,
  - imported external credentials,
  - migrated credentials,
  - and stale or disputed upstream evidence.

**Recommendation**

Cross-issuer migration must be explicit. ARC should never silently treat one
issuer's revocation or supersession state as a universal statement about every
other issuer.

#### Phase 104: Cross-Issuer Qualification and Analytics Boundary

**Depends on:** Phase 103

**Scope**

- Build a mixed-issuer corpus with:
  - compatible issuers,
  - unsupported issuers,
  - stale status,
  - disputed certifications,
  - conflicting subject continuity evidence,
  - and mixed portable profile families.
- Add reporting and analytics rules that preserve distinctions between:
  - local ARC-native truth,
  - imported external credentials,
  - cross-issuer portfolio summaries,
  - and verifier policy outcomes.
- Rewrite the portable boundary docs so ARC can honestly claim cross-issuer
  portability without claiming universal issuer equivalence.

**Milestone Acceptance Criteria**

1. ARC can evaluate a multi-issuer subject portfolio with explicit local
   trust-pack policy and fail-closed linkage rules.
2. ARC can model cross-issuer migration or replacement explicitly without
   collapsing all issuer lifecycle state into one global outcome.
3. Reports and verifier outputs preserve per-credential provenance and do not
   invent synthetic cross-issuer trust scores.
4. ARC publishes a clear cross-issuer compatibility boundary and qualification
   corpus.

**Validation and Qualification Expectations**

- Mixed-issuer golden corpus with deterministic policy outcomes.
- Negative tests for ambiguous subject linkage, stale migration records,
  unsupported issuers, and conflicting certification state.
- Integration tests proving imported and migrated credential evidence remains
  distinguishable from native local ARC truth.
- Partner-proof example showing one subject portfolio accepted and one rejected
  for explicit policy reasons.

### v2.24 Public Issuer and Verifier Discovery Network

**Goal:** Publish a public, provenance-preserving discovery layer for portable
issuers and verifiers that helps routing and ecosystem onboarding without
widening runtime trust from listing visibility alone.

**Depends on:** `v2.17`, `v2.22`, `v2.23`

**Requirements:** `PORT-END-06`, `PORT-END-08`, `PORT-END-09`

#### Phase 105: Portable Operator Metadata and Directory Schemas

**Depends on:** Phase 104

**Scope**

- Define portable issuer directory records carrying:
  - operator identity,
  - issuer ids and aliases,
  - supported portable credential profiles,
  - supported status methods,
  - supported holder-binding methods,
  - supported wallet launch methods,
  - key or certificate trust bootstrap metadata,
  - certification references,
  - freshness and dispute state,
  - and policy-relevant jurisdiction or usage notes.
- Define equivalent verifier directory records carrying:
  - verifier ids and aliases,
  - supported request modes,
  - supported credential profiles,
  - required identity assertion modes,
  - accepted verifier identity schemes,
  - supported wallet launch methods,
  - and trust bootstrap metadata.
- Reuse public `ARC Certify` metadata and transparency patterns where possible
  instead of inventing a second unrelated directory model.

**Recommendation**

Issuer and verifier directories should be operator metadata records with clear
provenance, not a magical global trust source.

#### Phase 106: Discovery Publication, Search, Resolve, and Transparency

**Depends on:** Phase 105

**Scope**

- Add public read-only discovery publication flows for issuer and verifier
  listings.
- Add public search and resolve endpoints with stable filtering semantics.
- Add a transparency and history surface so consumers can inspect publication,
  supersession, dispute, and removal history.
- Define key rotation, metadata freshness, signed publication, and dispute
  handling.
- Keep publication and dispute mutation explicit operator actions, not
  implicit wallet gossip.

**Recommendation**

Preserve operator provenance at every step. ARC should not flatten multiple
operators into one synthetic global registry view.

#### Phase 107: Local Policy Import and Wallet Routing Guardrails

**Depends on:** Phase 106

**Scope**

- Define explicit consume flows that import public discovery records into local
  verifier policy, wallet routing tables, or issuer allowlists.
- Define wallet-routing behavior when multiple compatible issuers or verifiers
  are discovered.
- Fail closed on stale, disputed, superseded, or mismatched discovery records.
- Keep local trust admission and public discovery listing as separate decisions.
- Define how discovery records relate to trust packs, certification records,
  and wallet UX hints without silently widening trust.

**Recommendation**

Discovery should improve routing and onboarding, but it must remain
informational until an operator or verifier imports it into local policy.

#### Phase 108: Ecosystem Qualification and Endgame Boundary Rewrite

**Depends on:** Phase 107

**Scope**

- Prove at least one full ecosystem flow:
  - discover issuer,
  - obtain portable credential,
  - discover verifier,
  - launch supported wallet flow,
  - present credential,
  - validate under local policy.
- Add negative-path coverage for stale listings, disputed listings, mismatched
  verifier identity, unsupported launch methods, and unconsumed discovery
  metadata.
- Rewrite the portable boundary docs, release boundary, and planning language
  so ARC can honestly say the broader portability endgame is achieved, while
  preserving the remaining explicit non-goals.

**Milestone Acceptance Criteria**

1. ARC publishes signed, freshness-bound issuer and verifier discovery records
   with search, resolve, and transparency surfaces.
2. Public listings do not automatically widen runtime trust or verifier
   acceptance.
3. At least one discovery-to-issuance-to-presentation ecosystem flow is
   qualified end to end using external client or wallet components.
4. ARC's public docs can truthfully claim a bounded portable identity and
   wallet ecosystem surface, not just a narrow ARC-specific bridge.

**Validation and Qualification Expectations**

- Public discovery regression suite covering search, resolve, transparency,
  dispute, stale data, and supersession cases.
- End-to-end ecosystem proof using public discovery plus at least one external
  wallet or client stack.
- Negative tests confirming that untrusted or merely listed issuers and
  verifiers are not auto-accepted.
- Updated release, standards, and partner-facing docs with explicit support and
  non-support tables.

## Cross-Cutting Compatibility Guardrails

These rules should apply throughout every milestone above:

- ARC-native `AgentPassport`, ARC-native challenge transport, and existing
  `did:arc` provenance remain supported unless a later milestone explicitly
  deprecates them.
- All broader credential formats must project from one canonical ARC passport
  truth. ARC must not create competing portable truths per format.
- Unknown formats, unknown issuer identity schemes, unknown verifier identity
  schemes, unknown disclosure keys, and unknown transport adapters must fail
  closed.
- Identity assertions must never silently replace credential subject or issuer
  truth. Their role is session binding or continuity, not hidden trust
  escalation.
- Every transport adapter must reuse one canonical verifier transaction truth.
  ARC must not create divergent replay stores or verifier states per adapter.
- Discovery records, certification listings, and trust packs are informative
  until explicitly imported into local policy.
- Cross-issuer evaluation remains per credential. Portfolio summaries may be
  derived for UX or analytics, but runtime trust admission must remain
  explainable and evidence-linked.
- Lifecycle, settlement, and mutable analytics side state must stay outside
  signed credential truth unless the profile explicitly standardizes that field.
- Every milestone must update the compatibility matrix and boundary docs so ARC
  does not overclaim support during rollout.

## Explicit Non-Goals

- No claim of universal compatibility with every VC wallet, proof family, or
  mobile identity stack.
- No default JSON-LD or Data Integrity VC rollout in this sequence.
- No requirement that DIDComm become the primary ARC wallet transport.
- No requirement that SIOP or OpenID identity assertions be mandatory for every
  presentation.
- No permissionless global trust registry or auto-trusting public wallet
  network.
- No synthetic cross-issuer trust score, passport score, or market-wide
  reputation collapse.
- No automatic portability of economic underwriting, credit, bond, or
  liability decisions across issuers.
- No automatic enterprise identity propagation into every portable artifact.
- No requirement that `did:arc` become the sole or universal public portable
  identifier before this ladder can complete.
- No attempt to replace OpenID, DIDComm, A2A, MCP, or wallet protocols at the
  ecosystem level.

## Ecosystem Caveats

- Standards churn remains real. ARC should ship broader profile support behind
  explicit support matrices and qualification gates rather than vague
  "compatible with OpenID and VC" claims.
- Privacy and portability pull in opposite directions. Pairwise subject ids,
  holder-bound keys, and limited discovery correlation should be treated as
  product features, not shortcomings.
- Wallet ecosystems may support different subsets of profile, transport, and
  status features. ARC should qualify a bounded matrix and fail closed outside
  it.
- Discovery creates governance load. ARC will need freshness, abuse handling,
  dispute semantics, and operator provenance controls before public discovery is
  trustworthy.
- Verifier policy will remain local. Even after public discovery and
  cross-issuer portability, ARC should not imply that every verifier accepts
  the same issuers, trust packs, or assurance thresholds.

## Recommended Next Activation Order

If this is converted directly into roadmap milestones, the recommended
activation order is:

1. `v2.21` phases `93-96`
2. `v2.22` phases `97-100`
3. `v2.23` phases `101-104`
4. `v2.24` phases `105-108`

That sequence preserves ARC's current strengths:

- broaden portable profiles before broadening wallet claims
- broaden wallet exchange before publishing public discovery
- define cross-issuer trust composition before letting discovery imply
  ecosystem-wide routing
- end with public discovery and ecosystem qualification, because that is the
  point where ARC's broader portability claim becomes externally visible

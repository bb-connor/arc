# Post-v2.20 OAuth/OIDC Transaction Fabric Endgame Plan

**Project:** ARC  
**Scope:** Move from the shipped bounded receipt-projection profile to a fuller
standards-native authorization and transaction-context fabric  
**Researched:** 2026-03-29  
**Overall confidence:** MEDIUM-HIGH

## Executive Recommendation

ARC should treat the remaining OAuth/OIDC gap as **four milestones**, not as
"more enterprise IAM" or "just add token exchange."

The current shipped surface is real and valuable, but it is still intentionally
bounded:

- ARC projects signed governed receipt truth into one narrow OAuth-family
  authorization profile.
- hosted discovery documents are informational and fail closed on mismatch.
- sender-constrained semantics are richer in the reviewer/reporting surface than
  in the live hosted authorization contract.
- review packs are evidence artifacts, not live authorization artifacts.

The next endgame should therefore be:

1. **v2.21 Hosted OAuth/OIDC Resource and Authorization Convergence**
   - Phases 93-96
2. **v2.22 Sender-Constrained and Attestation-Bound Authorization**
   - Phases 97-100
3. **v2.23 Transaction Tokens, Call-Chain Propagation, and Native Token Exchange**
   - Phases 101-104
4. **v2.24 Qualification, Partner Profiles, and Boundary Closure**
   - Phases 105-108

This order keeps ARC honest:

- first align the protected-resource and authorization-server contract,
- then deepen sender-constrained semantics,
- then add live transaction propagation and bounded exchange,
- and only then claim the fuller standards-native authorization fabric.

## Why This Is The Right Post-v2.20 Gap

The research in `docs/research/DEEP_RESEARCH_1.md` points to an end-state where
ARC is legible to the OAuth family not only as a post-hoc reporting profile,
but as a live authorization and call-chain context fabric:

- rights should be legible as authorization details, not only ARC-native grants
- sender-constrained semantics should align with DPoP and mTLS, not only ARC's
  internal report vocabulary
- transaction and call-chain context should propagate through a trusted domain
  instead of appearing only after execution in receipts and review packs
- attestation and workload identity should influence authorization in a bounded,
  standards-aware way

ARC already ships enough substrate to do this carefully:

- governed intents, approval tokens, call-chain context, and signed receipts
- hosted protected-resource and authorization-server metadata publication
- runtime assurance, workload identity, and attestation appraisal surfaces
- enterprise IAM federation and typed identity context
- authorization-context reports and authorization-review-pack evidence

What is missing is **the live standards-native fabric between them**.

## Current Shipped Boundary

### What ARC already ships

The current codebase and docs are explicit that ARC now ships:

- one normative receipt-derived OAuth-family authorization profile over governed
  receipt truth
- one derived `authorizationDetails` plus `transactionContext` projection for
  enterprise review
- one explicit sender-constraint report vocabulary over subject binding, proof
  requirement, runtime assurance, and delegated call-chain context
- hosted protected-resource and authorization-server metadata that publish the
  ARC profile boundary
- machine-readable authorization-profile metadata and reviewer packs
- enterprise IAM federation for hosted sessions
- runtime assurance, workload identity, and attestation appraisal inputs

### What ARC explicitly does not yet claim

The current docs also draw a hard boundary:

- ARC does **not** yet claim generic OAuth token issuance behavior.
- ARC does **not** yet claim OpenID Connect identity assertions as the
  execution-truth source.
- discovery metadata remains informational and does not bootstrap trust by
  itself.
- arbitrary mTLS semantics outside documented adapter or hosted surfaces are not
  claimed.
- the shipped authorization profile is a **derived receipt projection**, not a
  live generic authorization layer.

### Current practical meaning

Today ARC can truthfully say:

- "we can explain governed receipt truth in OAuth-family terms"

It cannot yet truthfully say:

- "we provide a complete live OAuth/OIDC transaction fabric for governed agent
  execution."

That is the post-v2.20 gap this document closes.

## Remaining Gap

The remaining gap is not one missing endpoint. It is the absence of a coherent
live contract across **authorization request**, **protected resource
admission**, **sender constraint**, **call-chain continuation**, and
**token/exchange boundaries**.

### Gap 1: Request-time semantics are weaker than review-time semantics

ARC currently projects governed execution into `authorizationDetails` and
`transactionContext` after the fact. It does not yet have one bounded,
request-time standards contract that says:

- what the client asked for,
- what the authorization server approved,
- what the protected resource admitted,
- and how that maps back to ARC governed intent and approval truth.

### Gap 2: Sender binding is stronger in the report than in the live fabric

ARC's current `senderConstraint` report vocabulary is useful, but it is mostly
review-facing. The live hosted fabric still needs:

- a common model across DPoP, mTLS, and attestation-bound client semantics,
- clearer proof continuity across exchanged or continued requests,
- and tighter alignment between discovery metadata and actual proof behavior.

### Gap 3: Call-chain context is still mostly ARC-native and post-execution

ARC already has:

- `governed_intent.call_chain`
- `transactionContext.callChain`
- reviewer-pack traceability

But it does not yet have one bounded transaction-token or protected-domain
continuation profile that carries those semantics through live downstream calls
before receipts exist.

### Gap 4: Protected-resource and authorization-server metadata are still too narrow

ARC publishes both documents today, but they are still closer to profile
advertisement than to a full resource and server alignment contract. The
remaining work includes:

- resource indicator and audience rules
- token endpoint and exchange surface bounds
- introspection and revocation semantics where ARC actually supports them
- fail-closed multi-resource and metadata-drift behavior

### Gap 5: Review-pack and native token exchange are not yet sharply separated

ARC needs a durable artifact boundary that says:

- review packs are evidence for reviewers and auditors
- access tokens are for protected-resource admission
- ARC capabilities remain execution authority
- approval tokens remain governed permission artifacts
- transaction tokens, if added, are protected-domain continuation artifacts

Without that separation ARC risks turning reviewer evidence into a de facto
authorization side channel.

## What "Endgame Achieved" Should Mean

ARC can truthfully claim the OAuth/OIDC transaction-fabric endgame is achieved
only when all of the following are true:

1. ARC can represent governed request semantics at request time in one bounded
   standards-facing contract, not only in a post-execution report.
2. Protected-resource metadata, authorization-server metadata, and actual token
   behavior align and fail closed on drift.
3. ARC supports a bounded live sender-constrained story across DPoP and mTLS,
   with attestation-bound semantics explicitly marked experimental until the
   standards stabilize.
4. ARC can propagate transaction and call-chain context through a trusted
   domain using bounded transaction-token or exchange semantics.
5. Review packs remain reviewer evidence and are not accepted as runtime
   authorization artifacts.
6. ARC's remaining proprietary surfaces are explicit, justified, and narrower
   than the standards it reuses.

## Recommended Milestone Sequence

### v2.21 Hosted OAuth/OIDC Resource and Authorization Convergence

**Goal:** Turn the current informative discovery plus receipt projection into a
bounded live hosted authorization contract.

**Why first:** ARC needs one coherent protected-resource and authorization-
server boundary before it adds richer proof or transaction propagation
semantics.

### v2.22 Sender-Constrained and Attestation-Bound Authorization

**Goal:** Make ARC's live sender-constrained story as explicit as its reviewer
story.

**Why second:** The current report semantics are already richer than the live
contract. That should be fixed before ARC adds call-chain token propagation.

### v2.23 Transaction Tokens, Call-Chain Propagation, and Native Token Exchange

**Goal:** Carry governed transaction and delegated call-chain context through a
trusted domain at runtime rather than only after execution.

**Why third:** Transaction propagation is unsafe until resource metadata and
sender binding are already explicit and fail closed.

### v2.24 Qualification, Partner Profiles, and Boundary Closure

**Goal:** Prove the full fabric end to end and rewrite the public boundary
honestly.

**Why last:** ARC should not make a broader standards-native claim until it has
qualification evidence for metadata alignment, sender constraints, and
transaction propagation.

## Proposed Requirement IDs

- `TXFAB-01`: ARC defines one bounded request-time authorization-details and
  governed-intent mapping contract for hosted OAuth/OIDC flows.
- `TXFAB-02`: Protected-resource metadata, authorization-server metadata,
  audience rules, and resource indicators align with actual token behavior and
  fail closed on mismatch.
- `TXFAB-03`: ARC supports a bounded live sender-constrained model over DPoP
  and mTLS, with explicit profile publication and replay-safe validation.
- `TXFAB-04`: ARC defines attestation-bound client and runtime-assurance
  linkage as an explicitly bounded profile without widening execution authority
  from attestation alone.
- `TXFAB-05`: ARC defines one protected-domain transaction-token and call-chain
  propagation contract tied back to governed intent and approval truth.
- `TXFAB-06`: ARC supports bounded native token exchange for configured trusted
  domains without becoming a generic open federation STS.
- `TXFAB-07`: Review packs, evidence exports, and reviewer artifacts remain
  clearly separated from access tokens, transaction tokens, and execution
  capabilities.
- `TXFAB-08`: Qualification proves the full authorization fabric end to end,
  including negative-path and metadata-drift behavior.

## Milestone Plan

### v2.21 Hosted OAuth/OIDC Resource and Authorization Convergence

**Goal:** Move from a bounded receipt-projection profile to a bounded live
hosted authorization contract that still keeps governed receipt truth
authoritative.

**Depends on:** `v2.16`, `v2.20`  
**Requirements:** `TXFAB-01`, `TXFAB-02`

#### Phase 93: Request-Time Authorization Details and Governed Intent Contract

**Depends on:** Phase 92

**Scope**

- Define one standards-facing request-time mapping from ARC governed intent and
  approval semantics into bounded `authorization_details`.
- Specify which fields are:
  - requested by the client,
  - approved by the authorization server,
  - enforced by the protected resource,
  - and later projected back into ARC receipts.
- Define how ARC handles partial approval, detail reduction, and unsupported
  authorization-detail families without silently widening governed scope.
- Keep governed intent hash and approval-token binding ARC-native even when
  request-time semantics are standards-facing.

**Why first**

ARC currently has a report-time mapping, not a request-time contract. This
phase creates the semantic bridge everything else depends on.

#### Phase 94: Protected Resource Metadata, Audience, and Resource-Indicator Rules

**Depends on:** Phase 93

**Scope**

- Define stable protected-resource identifiers for hosted execution,
  trust-control report, and review surfaces.
- Align `/.well-known/oauth-protected-resource/mcp` with actual audience,
  resource-indicator, and proof requirements.
- Define fail-closed behavior for:
  - wrong audience,
  - ambiguous multi-resource requests,
  - unsupported resource indicators,
  - and profile metadata drift.
- Separate execution resource semantics from review or report endpoints so
  reviewer surfaces do not accidentally look like runtime execution resources.

**Why second**

ARC cannot add deeper server or exchange semantics until resource identity and
audience rules are explicit.

#### Phase 95: Authorization Server Metadata and Token Contract

**Depends on:** Phase 94

**Scope**

- Publish one bounded ARC authorization-server metadata profile covering only
  supported grant, proof, exchange, introspection, and revocation behavior.
- Define which token families ARC issues or accepts for hosted admission.
- Define token claim boundaries for:
  - subject,
  - client,
  - actor or delegator,
  - resource,
  - profile version,
  - and ARC-specific extension claims.
- State explicitly that tokens are admission and propagation artifacts, not the
  final execution-truth source.

**Why third**

The authorization server contract should be derived from already-defined
request and resource semantics, not the other way around.

#### Phase 96: Hosted Alignment Qualification and Failure-Boundary Proof

**Depends on:** Phase 95

**Scope**

- Add raw-HTTP qualification for request-time authorization details,
  protected-resource metadata, and authorization-server metadata alignment.
- Add negative-path coverage for:
  - metadata mismatch,
  - wrong audience,
  - unsupported detail types,
  - partial approval confusion,
  - and incorrect resource routing.
- Update protocol, release, and operator docs so the live hosted contract is
  explicit and narrower than generic OAuth marketing language.

#### Milestone Acceptance Criteria

1. ARC has one request-time authorization-details contract aligned with its
   governed intent and receipt truth.
2. Protected-resource and authorization-server metadata describe real behavior,
   not only reviewer-facing hints.
3. Unsupported request or metadata combinations fail closed.
4. ARC docs clearly distinguish admission tokens from governed execution
   authority.

#### Validation / Qualification Expectations

- raw-HTTP integration tests for metadata, resource, and audience handling
- negative tests for profile-version mismatch and unsupported detail families
- explicit qualification proof showing request-time authorization data matches
  the later receipt projection

### v2.22 Sender-Constrained and Attestation-Bound Authorization

**Goal:** Make sender-bound semantics first-class in the live authorization
fabric instead of only in reviewer reports.

**Depends on:** `v2.21`, `v2.12`, `v2.15`  
**Requirements:** `TXFAB-03`, `TXFAB-04`

#### Phase 97: Common Sender-Constraint Vocabulary and Live Contract

**Depends on:** Phase 96

**Scope**

- Define one common sender-constraint model shared by:
  - hosted token admission,
  - protected-resource enforcement,
  - authorization-context projection,
  - and reviewer evidence.
- Normalize proof requirement, proof type, proof schema, subject key source,
  runtime-assurance binding, and delegated-call-chain binding.
- Define which sender facts are mandatory for runtime enforcement versus only
  reviewer-visible.

**Why first**

ARC already has a reviewer vocabulary. This phase turns it into one live and
report-time contract instead of two separate stories.

#### Phase 98: DPoP Continuity, Replay Domains, and Delegation Semantics

**Depends on:** Phase 97

**Scope**

- Deepen DPoP handling with explicit replay-domain, nonce, and proof-continuity
  rules across hosted requests and downstream continuations.
- Define which key continuity must survive:
  - access-token reuse,
  - token exchange,
  - and delegated child calls.
- Define actor-versus-subject semantics so DPoP does not silently collapse
  caller identity, capability subject, and delegator provenance into one field.

**Why second**

DPoP already exists in ARC. It is the fastest sender-constrained profile to
make more standards-native and more explicit.

#### Phase 99: mTLS and Certificate-Bound Token Profile

**Depends on:** Phase 98

**Scope**

- Add one bounded mTLS profile for hosted ARC protected resources and documented
  HTTPS adapter surfaces.
- Support certificate-bound access-token semantics where ARC actually operates
  as a protected resource.
- Define certificate identity, rotation, and binding visibility in reviewer and
  operator surfaces.
- Keep arbitrary transport-wide mTLS semantics out of scope.

**Why third**

mTLS should be added only after ARC already has a common sender-constraint
model and DPoP continuity rules.

#### Phase 100: Attestation-Bound Client and Runtime-Assurance Linkage

**Depends on:** Phase 99

**Scope**

- Define one bounded profile that links attested client or workload identity to
  ARC admission and runtime-assurance semantics.
- Reuse ARC's existing workload-identity and appraisal surfaces instead of
  inventing a second attestation trust model.
- Define when attestation may influence:
  - client admission,
  - token issuance or exchange,
  - runtime-assurance binding,
  - and policy-visible context.
- Keep attestation from becoming execution authority by itself.

**Why fourth**

Attestation-bound client semantics should sit on top of already-stable sender
constraints, not replace them.

#### Milestone Acceptance Criteria

1. ARC supports one common live sender-constrained contract across DPoP and
   mTLS.
2. DPoP replay and continuation rules are explicit and fail closed.
3. Attestation-bound client semantics are bounded, documented, and do not widen
   trust silently.
4. Reviewer surfaces reflect the same sender semantics the live runtime
   enforced.

#### Validation / Qualification Expectations

- nonce, replay, proof-substitution, and mixed-proof negative tests
- raw-HTTP DPoP and mTLS qualification lanes
- attestation-binding tests proving stale or mismatched workload identity is
  rejected before runtime authority widens

### v2.23 Transaction Tokens, Call-Chain Propagation, and Native Token Exchange

**Goal:** Carry governed transaction and delegated call-chain semantics through
a protected domain at runtime, not only after execution.

**Depends on:** `v2.22`, `v2.6`, `v2.20`  
**Requirements:** `TXFAB-05`, `TXFAB-06`, `TXFAB-07`

#### Phase 101: Transaction Token Profile and Call-Chain Vocabulary

**Depends on:** Phase 100

**Scope**

- Define one bounded transaction-token profile for protected-domain
  continuation.
- Bind the token to:
  - governed intent identity,
  - approval state,
  - sender subject,
  - runtime assurance,
  - and delegated call-chain context.
- Map current ARC fields such as `intent_hash`, `approval_token_id`,
  `origin_subject`, and `delegator_subject` into stable token vocabulary.
- Keep this profile explicitly bounded to trusted-domain propagation rather than
  generic external bearer portability.

**Why first**

ARC needs one canonical continuation artifact before it can define exchange and
adapter propagation rules.

#### Phase 102: Protected-Domain Call-Chain Continuation Across ARC Surfaces

**Depends on:** Phase 101

**Scope**

- Propagate transaction and call-chain context across hosted edge,
  trust-control, and adapter boundaries where ARC already owns the trust
  contract.
- Define parent and child semantics for:
  - `parent_request_id`,
  - `parent_receipt_id`,
  - origin subject,
  - delegator subject,
  - and chain identity.
- Define when call-chain context must be re-issued, truncated, or terminated at
  cross-domain boundaries.
- Add fail-closed checks for mismatched parent receipt, missing delegator, or
  self-referential continuation.

**Why second**

ARC should validate the live propagation path before it adds formal exchange.

#### Phase 103: Bounded Native Token Exchange

**Depends on:** Phase 102

**Scope**

- Define one bounded token-exchange contract for configured trusted domains.
- Support the specific exchange classes ARC actually needs:
  - external enterprise/OIDC bearer to ARC admission token,
  - ARC admission token to ARC transaction token,
  - ARC transaction token to narrower downstream protected-domain token.
- Define which claims survive exchange, which are re-derived from ARC state,
  and which are never copied.
- Keep generic third-party or open federation STS behavior out of scope.

**Why third**

Without an explicit protected-domain boundary, token exchange becomes an
unbounded federation feature instead of a control-plane primitive.

#### Phase 104: Review-Pack, Evidence Export, and Reviewer Exchange Boundary

**Depends on:** Phase 103

**Scope**

- Define a sharp artifact boundary between:
  - access tokens,
  - transaction tokens,
  - ARC capabilities,
  - approval tokens,
  - review packs,
  - and evidence exports.
- Make explicit that authorization-review-pack and similar reviewer bundles are
  never valid bearer, exchange, or execution artifacts.
- Align review-pack export and exchange audit data so reviewers can see what
  happened without ARC accepting the reviewer artifact back as authorization.
- Document when a signed evidence package may be shared with partners and what
  trust it does not convey.

**Why fourth**

This phase prevents the most dangerous category error in the whole plan:
turning reviewer evidence into runtime authority.

#### Milestone Acceptance Criteria

1. ARC defines one protected-domain transaction-token profile bound to governed
   intent and call-chain truth.
2. ARC can continue transaction context through trusted-domain hops without
   losing sender or approval semantics.
3. Token exchange is bounded to configured trusted domains and explicit exchange
   classes.
4. Review packs and evidence exports are impossible to confuse with runtime
   authorization artifacts.

#### Validation / Qualification Expectations

- continuation and chain-tamper negative tests
- exchange confusion tests proving wrong token family or reviewer artifact is
  rejected
- adapter integration tests for call-chain propagation across hosted and bridge
  surfaces

### v2.24 Qualification, Partner Profiles, and Boundary Closure

**Goal:** Turn the new fabric into a qualified, standards-facing ARC claim with
explicit residual ARC-specific boundaries.

**Depends on:** `v2.23`  
**Requirements:** `TXFAB-08`

#### Phase 105: OIDC Identity and Enterprise Federation Convergence

**Depends on:** Phase 104

**Scope**

- Define how OIDC identity and ARC enterprise federation fit into the
  transaction fabric without becoming execution authority by themselves.
- Specify how ID-token, userinfo, and provider-admin identity context may
  inform admission, review, and provenance.
- Keep ARC capability subject, approval, receipt truth, and workload identity
  separate from human or enterprise principal assertions.

**Why first**

OIDC semantics need to be explicit before ARC can publish partner-facing
profiles honestly.

#### Phase 106: Cross-Standard Conformance and Negative-Path Qualification

**Depends on:** Phase 105

**Scope**

- Build a qualification matrix across:
  - request-time authorization details,
  - protected-resource metadata,
  - authorization-server metadata,
  - DPoP,
  - mTLS,
  - transaction-token continuation,
  - token exchange,
  - and review-pack misuse rejection.
- Prefer raw-HTTP and interop-style verification over ARC-only CLI happy-path
  evidence.
- Publish explicit failure-boundary fixtures and partner-proof examples.

#### Phase 107: Partner Profiles and Adapter Contracts

**Depends on:** Phase 106

**Scope**

- Publish narrow partner profiles for:
  - generic enterprise OAuth/OIDC IAM,
  - hosted MCP protected-resource deployment,
  - A2A delegated continuation,
  - ACP and x402 economic bridges where they intersect ARC transaction
    semantics.
- Mark mandatory, optional, and experimental features per profile.
- Keep profile count intentionally small so ARC does not become a generic IAM
  meta-spec.

#### Phase 108: Boundary Rewrite and Research Closure

**Depends on:** Phase 107

**Scope**

- Update spec, release, standards, and interop docs to describe the finished
  transaction-fabric surface honestly.
- Rewrite the release candidate boundary so ARC can make a broader claim than
  "bounded receipt projection" without overstating generic OAuth coverage.
- Close the research ladder with explicit documentation of what remains
  intentionally ARC-specific and why.

#### Milestone Acceptance Criteria

1. ARC has a standards-facing proof package for the live authorization fabric,
   not only the review projection.
2. OIDC and enterprise federation semantics are documented as identity and
   provenance inputs, not execution-truth substitutes.
3. Partner profiles are explicit about mandatory versus optional behavior.
4. Public docs can state the broader fabric claim without implying generic IAM
   or open federation behavior ARC does not ship.

#### Validation / Qualification Expectations

- conformance matrix covering all milestone features and negative paths
- one partner-proof package per supported deployment profile
- release and protocol docs updated together with qualification evidence

## Cross-Cutting Qualification Gates

Regardless of milestone, the endgame should not be considered complete unless
all of the following are true:

- every standards-facing claim is covered by raw-HTTP or external-style
  qualification, not only ARC CLI happy paths
- metadata drift between protected-resource, authorization-server, and runtime
  behavior fails closed under automated tests
- DPoP, mTLS, and transaction-token misuse paths are covered by replay,
  substitution, and wrong-artifact negative tests
- review-pack and evidence-export artifacts are explicitly rejected anywhere a
  bearer, exchange, or execution artifact is expected
- protocol, release, and operator docs are updated in the same change wave as
  qualification evidence so ARC never ships a broader claim than the verified
  surface

## Artifact Boundary ARC Should Keep

ARC should stay strict about which artifact does what.

| Artifact | Primary purpose | What it is allowed to do | What it must not become |
| --- | --- | --- | --- |
| OAuth/OIDC access token | hosted protected-resource admission | carry bounded client, subject, audience, and proof context | final execution authority |
| ARC capability | execution authority inside ARC | authorize tool, resource, and prompt actions with attenuation | generic external bearer token |
| ARC approval token | governed approval over one intent hash | bind approval to subject, request, and intent | generic OAuth consent artifact |
| ARC transaction token | protected-domain continuation | carry bounded live transaction and call-chain context | public portable credential |
| authorization-review-pack | reviewer evidence bundle | prove one governed action end to end | bearer token, exchange token, or introspection response |
| ARC receipt and checkpoint | immutable evidence truth | anchor operator, reviewer, and market-layer artifacts | mutable runtime session state |

## What Should Remain ARC-Specific

ARC should intentionally keep the following surfaces ARC-specific even after the
broader OAuth/OIDC work lands:

- capability issuance, attenuation, and delegation semantics
- governed intent and approval-token artifacts
- signed receipt, checkpoint, and evidence-export truth
- runtime-attestation appraisal contract and trusted-verifier rebinding rules
- reviewer packs, provider-risk packages, and other evidence bundles
- liability-market, underwriting, credit, bond, and certification artifacts

OAuth/OIDC should make these surfaces legible and transport-compatible where
appropriate. It should **not** replace ARC's authority or evidence model.

## Standards Caveats

The following caveats should stay explicit throughout the plan:

- Transaction-token and attestation-based client-auth standards are still
  draft-level in the research input. ARC should ship them as bounded ARC
  profiles until the standards stabilize.
- OIDC identity assertions are not equivalent to ARC execution authority.
- Discovery metadata must remain informational unless and until ARC publishes a
  stronger trust-bootstrap model; metadata alone must not widen trust.
- mTLS support should be limited to documented hosted and adapter profiles, not
  claimed as arbitrary transport-wide compatibility.
- Token exchange should stay bounded to configured trusted domains and explicit
  exchange classes; ARC should not become a generic open federation STS.
- Review packages and evidence exports must remain review artifacts even when
  they share fields with live token or transaction context.

## Explicit Non-Goals

- becoming a general-purpose OAuth authorization server or OIDC identity
  provider for arbitrary applications
- replacing ARC capabilities with plain OAuth access tokens
- treating ID tokens or userinfo responses as execution authority
- open-ended cross-domain token exchange or generic third-party federation
- arbitrary sender-constrained proof families beyond the documented bounded set
- automatic trust bootstrap from discovery metadata alone
- turning reviewer packs into bearer or exchange artifacts
- generic market-layer interoperability claims beyond ARC's documented
  underwriting, certification, capital, and liability boundaries

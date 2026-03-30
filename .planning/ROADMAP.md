# Roadmap: ARC

## Milestones

- [x] **v1.0 Closing Cycle** - Phases 1-6 (shipped 2026-03-20)
- [x] **v2.0 Agent Economy Foundation** - Phases 7-12 (shipped 2026-03-24)
- [x] **v2.1 Federation and Verifier Completion** - Phases 13-16 (shipped
  2026-03-24)
- [x] **v2.2 A2A and Ecosystem Hardening** - Phases 17-20 (completed
  2026-03-25)
- [x] **v2.3 Production and Standards** - Phases 21-24 (completed
  2026-03-25)
- [x] **v2.4 Architecture and Runtime Decomposition** - Phases 25-28
  (completed 2026-03-25)
- [x] **v2.5 ARC Rename and Identity Realignment** - Phases 29-32 (completed
  2026-03-26)
- [x] **v2.6 Governed Transactions and Payment Rails** - Phases 33-36
  (completed 2026-03-26)
- [x] **v2.7 Portable Trust, Certification, and Federation Maturity** -
  Phases 37-40 (completed 2026-03-26)
- [x] **v2.8 Risk, Attestation, and Launch Closure** - Phases 41-44
  (completed 2026-03-27)
- [x] **v2.9 Economic Evidence and Authorization Context Interop** - Phases
  45-48 (completed 2026-03-27)
- [x] **v2.10 Underwriting and Risk Decisioning** - Phases 49-52 (completed
  2026-03-27)
- [x] **v2.11 Portable Credential Interop and Wallet Distribution** - Phases
  53-56 (completed 2026-03-28)
- [x] **v2.12 Workload Identity and Attestation Verification Bridges** -
  Phases 57-60 (completed 2026-03-28)
- [x] **v2.13 Portable Credential Format and Lifecycle Convergence** - Phases
  61-64 (completed 2026-03-28)
- [x] **v2.14 OID4VP Verifier and Wallet Interop** - Phases 65-68 (completed
  2026-03-29)
- [x] **v2.15 Multi-Cloud Attestation and Appraisal Contracts** - Phases 69-72
  (completed 2026-03-28)
- [x] **v2.16 Enterprise Authorization and IAM Standards Profiles** - Phases
  73-76 (completed 2026-03-28)
- [x] **v2.17 ARC Certify Public Discovery Marketplace and Governance** -
  Phases 77-80 (completed 2026-03-29)
- [x] **v2.18 Credit, Exposure, and Capital Policy** - Phases 81-84
  (completed 2026-03-29)
- [x] **v2.19 Bonded Autonomy and Facility Execution** - Phases 85-88
  (completed 2026-03-29)
- [x] **v2.20 Liability Marketplace and Claims Network** - Phases 89-92
  (completed 2026-03-29)
- [x] **v2.21 Standards-Native Authorization and Credential Fabric** - Phases
  93-96 (completed 2026-03-29)
- [x] **v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained
  Authorization** - Phases 97-100 (completed 2026-03-30)
- [ ] **v2.23 Common Appraisal Vocabulary and External Result Interop** -
  Phases 101-104 (active)
- [ ] **v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery** -
  Phases 105-108 (executable)
- [ ] **v2.25 Live Capital Allocation and Escrow Execution** - Phases 109-112
  (executable)
- [ ] **v2.26 Reserve Control, Autonomous Pricing, and Claims Payment** -
  Phases 113-116 (executable)
- [ ] **v2.27 Open Registry, Trust Activation, and Governance Network** -
  Phases 117-120 (executable)
- [ ] **v2.28 Portable Reputation, Marketplace Economics, and Endgame
  Qualification** - Phases 121-124 (executable)

## Active Milestone: v2.23 Common Appraisal Vocabulary and External Result Interop

**Milestone Goal:** Externalize ARC's appraisal semantics into a versioned
contract with normalized claims, reason taxonomy, and signed result import or
export without widening trust from raw foreign evidence.

**Why now:** ARC now has concrete Azure, AWS Nitro, and Google verifier
bridges, but ARC still cannot claim full attestation-result interop until
those outputs converge into one external contract with explicit import,
export, and policy-mapping rules.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on RATS/EAT-style result portability,
  verifier semantics, and vendor-neutral appraisal layers
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's current
  bounded multi-cloud appraisal boundary
- `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` on the normalized
  post-`v2.20` endgame sequence

**Phase Numbering:**
- Integer phases 89-92: completed `v2.20` liability-market work
- Integer phases 93-96: completed `v2.21` standards-native fabric work
- Integer phases 97-100: completed `v2.22` wallet and sender-constrained work
- Integer phases 101-104: active `v2.23` appraisal-result interop work
- Integer phases 105-108: executable `v2.24` verifier federation and
  discovery work
- Integer phases 109-112: executable `v2.25` live capital execution work
- Integer phases 113-116: executable `v2.26` reserve control and live claims
  payment work
- Integer phases 117-120: executable `v2.27` open registry and governance work
- Integer phases 121-124: executable `v2.28` open-market economics and final
  qualification work

- [ ] **Phase 101: Common Appraisal Schema Split and Artifact Inventory** -
  define the outward-facing appraisal artifact surface, schema boundaries, and
  migration inventory.
- [ ] **Phase 102: Normalized Claim Vocabulary and Reason Taxonomy** -
  standardize the portable claim and reason vocabulary shared across verifier
  families.
- [ ] **Phase 103: External Signed Appraisal Result Import/Export and Policy
  Mapping** - add signed appraisal exchange and explicit local policy mapping
  rules.
- [ ] **Phase 104: Mixed-Provider Appraisal Qualification and Boundary
  Rewrite** - qualify the mixed-provider appraisal contract and rewrite the
  public boundary honestly.
- [ ] **Phase 105: Cross-Issuer Portfolios, Trust Packs, and Migration
  Semantics** - add bounded cross-issuer composition over one portable trust
  substrate.
- [ ] **Phase 106: Verifier Descriptors, Trust Bundles, and Reference-Value
  Distribution** - define portable verifier identity, trust bundles, and
  reference material distribution.
- [ ] **Phase 107: Public Issuer/Verifier Discovery, Transparency, and Local
  Policy Import Guardrails** - publish discovery while keeping local trust
  activation explicit.
- [ ] **Phase 108: Wider Provider Support and Assurance-Aware Auth/Economic
  Policy** - widen provider coverage over the shared appraisal and federation
  substrate.
- [ ] **Phase 109: Capital Book and Source-of-Funds Ledger** - turn facility
  and bond posture into explicit live capital-book state.
- [ ] **Phase 110: Escrow and Reserve Instruction Contract** - define
  custody-neutral instruction artifacts over reserve and escrow movement.
- [ ] **Phase 111: Live Allocation Engine for Governed Actions** - map
  governed actions to explicit capital-allocation decisions.
- [ ] **Phase 112: Capital Execution Qualification and Regulated-Role
  Baseline** - qualify live capital execution and formalize regulated-role
  assumptions.
- [ ] **Phase 113: Executable Reserve Impairment, Release, and Slash
  Controls** - make reserve controls live and evidence-linked.
- [ ] **Phase 114: Delegated Pricing Authority and Automatic Coverage
  Binding** - add bounded delegated pricing and automatic bind semantics.
- [ ] **Phase 115: Automatic Claims Payment and Payout Reconciliation** -
  implement narrow automatic payout execution plus reconciliation truth.
- [ ] **Phase 116: Recovery Clearing, Reinsurance/Facility Settlement, and
  Role Topology** - close the live-money lifecycle across counterparties and
  roles.
- [ ] **Phase 117: Generic Listing Artifact and Namespace Model** - generalize
  curated discovery into one open listing substrate.
- [ ] **Phase 118: Origin, Mirror, Indexer, Search, Ranking, and Freshness
  Semantics** - define multi-operator registry mechanics and freshness rules.
- [ ] **Phase 119: Trust Activation Artifacts and Open Admission Classes** -
  keep visibility separate from explicit trust activation.
- [ ] **Phase 120: Governance Charters, Dispute Escalation, Sanctions, and
  Appeals** - define portable governance and escalation artifacts.
- [ ] **Phase 121: Portable Reputation, Negative-Event Exchange, and
  Weighting Profiles** - externalize portable reputation with local weighting.
- [ ] **Phase 122: Fee Schedules, Bonds, Slashing, and Abuse Resistance** -
  add market economics and abuse-resistance primitives.
- [ ] **Phase 123: Adversarial Multi-Operator Open-Market Qualification** -
  prove the open-market model under adversarial multi-operator conditions.
- [ ] **Phase 124: Partner Proof, Release Boundary, and Honest Endgame Claim
  Closure** - close the roadmap with final partner-proof and release-boundary
  updates.

All remaining milestones after `v2.23` are now decomposed into executable
phase detail on disk, so no further activation step is required between
milestones.

## Activated Milestones After v2.23

- `v2.24` phases `105` through `108`: verifier federation, cross-issuer
  portability, and discovery
- `v2.25` phases `109` through `112`: live capital allocation and escrow
  execution
- `v2.26` phases `113` through `116`: reserve control, autonomous pricing, and
  claims payment
- `v2.27` phases `117` through `120`: open registry, trust activation, and
  governance network
- `v2.28` phases `121` through `124`: portable reputation, marketplace
  economics, and endgame qualification

## Phase Details

### Phase 93: Portable Claim Catalog and Governed Auth Binding

**Goal**: Define ARC's broader portable claim catalog and align subject or
issuer binding with governed request-time authorization semantics.
**Depends on**: Phase 92
**Requirements**: STDFAB-01, STDFAB-02
**Why first**: ARC cannot broaden its standards claim honestly while portable
identity and request-time authorization still use separate provenance and
binding models.

**Primary surfaces:**
- portable claim catalog over ARC passport truth
- ARC provenance identity, portable issuer identity, and portable subject
  binding rules
- governed intent and request-time authorization binding semantics
- fail-closed handling for unsupported or ambiguous rebinding

**Success Criteria**:
1. ARC has one explicit portable claim catalog instead of one ad hoc
   projection exception.
2. Subject and issuer binding are machine-readable and auditable across
   portable and hosted auth surfaces.
3. Unsupported rebinding combinations fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 93-01: Define the portable claim catalog and provenance-preserving
  identity layers.
- [x] 93-02: Define request-time governed authorization binding over the same
  identity model.
- [x] 93-03: Document compatibility guardrails and migration rules for broader
  identity binding.

### Phase 94: Multi-Format Credential Profiles and Verification

**Goal**: Broaden ARC from one narrow projected credential lane into a small,
standards-legible multi-format credential family over one canonical passport
truth.
**Depends on**: Phase 93
**Requirements**: STDFAB-01, STDFAB-05
**Why second**: Broader wallet and verifier interop is unsafe until ARC can
project more than one bounded format without drifting into multiple competing
credential truths.

**Primary surfaces:**
- shared projection engine for multiple portable profiles
- explicit format negotiation and issuer metadata
- verification behavior per supported profile family
- fail-closed handling for unsupported or mixed-format requests

**Success Criteria**:
1. ARC supports more than one standards-legible portable credential profile.
2. Profile negotiation and verification are explicit and deterministic.
3. Broader format support does not create a second trust root.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 94-01: Add a shared projection engine for multiple portable credential
  profiles.
- [x] 94-02: Define verification behavior and negative-path rules for each
  supported profile.
- [x] 94-03: Preserve ARC provenance and compatibility while broadening
  portable formats.

### Phase 95: Hosted Request-Time Authorization and Resource Convergence

**Goal**: Turn ARC's current review-oriented OAuth-family projection into a
bounded live request-time authorization contract that still derives from
governed ARC truth.
**Depends on**: Phase 93
**Requirements**: STDFAB-03, STDFAB-05
**Why third**: ARC needs a coherent request-time hosted contract before it can
add richer sender-constrained, transaction-token, or wallet-exchange
semantics.

**Primary surfaces:**
- request-time authorization-details and transaction-context mapping
- resource indicator, audience, and metadata convergence
- separation of access tokens, approval artifacts, capabilities, and reviewer
  evidence
- fail-closed metadata-drift behavior

**Success Criteria**:
1. ARC can represent governed request semantics at request time in one bounded
   standards-facing contract.
2. Hosted metadata aligns with actual protected-resource behavior.
3. Reviewer evidence cannot be replayed as runtime authorization.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 95-01: Define ARC's bounded request-time authorization contract.
- [x] 95-02: Align protected-resource and authorization-server metadata with
  actual behavior.
- [x] 95-03: Sharpen runtime artifact boundaries across auth, approval, and
  evidence surfaces.

### Phase 96: Portable Status, Revocation, Metadata, and Live Discovery Alignment

**Goal**: Converge portable credential lifecycle truth and live hosted
metadata so ARC's broader standards fabric has one fail-closed status and
discovery story.
**Depends on**: Phases 94 and 95
**Requirements**: STDFAB-04, STDFAB-05
**Why last**: ARC should not widen into wallet exchange or sender-constrained
flows until credential lifecycle and live hosted metadata tell one consistent
story under rotation, revocation, and stale-state conditions.

**Primary surfaces:**
- portable status and revocation semantics
- issuer metadata and hosted authorization metadata alignment
- discovery freshness and status-drift behavior
- qualification fixtures for stale or contradictory lifecycle state

**Success Criteria**:
1. Portable consumers and hosted auth surfaces observe the same lifecycle
   truth.
2. Metadata consistency, freshness, and rotation behavior are explicit.
3. `v2.21` can close with honest standards-facing boundary docs.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 96-01: Define converged portable status and revocation behavior.
- [x] 96-02: Align issuer metadata, credential metadata, and hosted
  authorization metadata.
- [x] 96-03: Qualify drift, replay, and lifecycle-edge cases across the
  broader standards fabric.

### Phase 97: Wallet Exchange Descriptor and Transport-Neutral Transaction State

**Goal**: Define ARC's wallet exchange descriptor and canonical transaction
state so holder, verifier, and relay flows can share one replay-safe
transport-neutral contract.
**Depends on**: Phases 95 and 96
**Requirements**: WALLETX-01, WALLETX-05
**Why first**: ARC cannot add continuity or sender-constrained proofs until
wallet transactions have one canonical state machine and descriptor shape.

**Primary surfaces:**
- wallet exchange descriptor and transaction identifiers
- same-device, cross-device, and relay-capable transaction state
- replay-safe request and response correlation
- fail-closed handling for ambiguous or duplicated transaction state

**Success Criteria**:
1. ARC has one transport-neutral wallet exchange descriptor.
2. Verifier transaction state is replay-safe and explicit across transport
   modes.
3. Unsupported or contradictory exchange state fails closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 97-01: Define the wallet exchange descriptor and canonical transaction
  identifiers.
- [x] 97-02: Add transport-neutral transaction state and replay boundaries.
- [x] 97-03: Document neutral exchange behavior and failure semantics.

### Phase 98: Optional Identity Assertion and Session Continuity Lane

**Goal**: Add one optional identity-assertion lane that can preserve session
continuity or verifier login context without becoming mandatory for every
presentation.
**Depends on**: Phase 97
**Requirements**: WALLETX-02, WALLETX-05
**Why second**: Identity assertions should layer on top of the neutral
transaction model rather than creating a second session contract.

**Primary surfaces:**
- optional identity assertion envelope and continuity semantics
- verifier login or session resumption binding
- explicit opt-in policy and audience rules
- fail-closed handling for stale, mismatched, or replayed assertions

**Success Criteria**:
1. ARC supports one optional continuity lane without making identity
   assertions mandatory.
2. Session continuity stays bound to canonical wallet transaction state.
3. Invalid or unsupported assertions fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 98-01: Define the optional identity-assertion contract and binding rules.
- [x] 98-02: Add session continuity semantics and verifier login mapping.
- [x] 98-03: Document opt-in policy, replay boundaries, and incompatibilities.

### Phase 99: DPoP, mTLS, and Attestation-Bound Sender-Constrained Authorization

**Goal**: Turn ARC's hosted authorization contract into bounded live
sender-constrained behavior over DPoP, mTLS, and one explicitly constrained
attestation-bound profile.
**Depends on**: Phases 97 and 98
**Requirements**: WALLETX-03, WALLETX-04
**Why third**: Sender constraints should bind to the neutral transaction and
optional continuity model rather than preceding them.

**Primary surfaces:**
- DPoP proof continuity over wallet and hosted authorization flows
- mTLS sender binding for verifier or resource access
- one bounded attestation-bound sender profile
- fail-closed proof continuity and authority-narrowing semantics

**Success Criteria**:
1. ARC supports bounded DPoP and mTLS sender-constrained runtime behavior.
2. Any attestation-bound sender semantics remain explicitly limited and never
   widen authority from attestation alone.
3. Missing, stale, or mismatched sender proof fails closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 99-01: Add DPoP sender-constrained exchange and proof continuity.
- [x] 99-02: Add mTLS and bounded attestation-bound sender profiles.
- [x] 99-03: Document sender semantics, authority limits, and negative paths.

### Phase 100: End-to-End Wallet and Sender-Constrained Qualification

**Goal**: Close `v2.22` with qualification evidence over wallet exchange,
optional identity assertion, and sender-constrained runtime behavior.
**Depends on**: Phases 97, 98, and 99
**Requirements**: WALLETX-05
**Why last**: ARC should not claim wallet and sender-constrained interop until
the whole flow is qualified across transport modes and negative cases.

**Primary surfaces:**
- same-device and cross-device wallet qualification
- asynchronous or message-oriented exchange proof
- sender-constrained negative-path coverage
- release and partner-boundary updates

**Success Criteria**:
1. ARC has end-to-end qualification for the supported wallet exchange modes.
2. Sender-constrained failures are explicitly tested and documented.
3. `v2.22` can close with an honest public boundary.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 100-01: Qualify same-device and cross-device wallet exchange flows.
- [x] 100-02: Qualify asynchronous exchange and sender-constrained failures.
- [x] 100-03: Close the milestone with release, partner-proof, and audit docs.

### Phase 101: Common Appraisal Schema Split and Artifact Inventory

**Goal**: Define ARC's outward-facing appraisal artifact surface, separate raw
evidence from normalized appraisal truth, and inventory the migration boundary
for existing verifier families.
**Depends on**: Phase 100
**Requirements**: APPX-01
**Why first**: ARC cannot claim portable appraisal interop until it has one
shared artifact contract across the verifier families it already ships.

**Primary surfaces:**
- common appraisal artifact structure and versioning
- separation of raw evidence, verifier identity, normalized claims, and policy-facing conclusions
- provider mapping inventory for Azure, AWS Nitro, and Google
- migration and backward-compatibility guardrails

**Success Criteria**:
1. ARC has one explicit outward-facing appraisal artifact.
2. Existing verifier outputs map into the new artifact without hidden joins.
3. The schema split stays conservative and auditable.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 101-01: Define the common appraisal artifact model and schema split.
- [ ] 101-02: Inventory existing verifier outputs and map them into the common artifact.
- [ ] 101-03: Document the artifact boundary and migration guardrails.

### Phase 102: Normalized Claim Vocabulary and Reason Taxonomy

**Goal**: Standardize the portable claim vocabulary and reason taxonomy shared
across verifier families.
**Depends on**: Phase 101
**Requirements**: APPX-02
**Why second**: The common appraisal shell is not enough unless ARC also says
what its normalized claims and reason codes mean across heterogeneous
providers.

**Primary surfaces:**
- normalized appraisal claim identifiers
- portable reason-code taxonomy
- provider-specific mapping rules
- fail-closed handling for contradictory or lossy normalization

**Success Criteria**:
1. ARC has one portable claim vocabulary.
2. Reason codes are consistent enough for policy and audit use.
3. Unsupported normalization cases fail closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 102-01: Define the normalized appraisal claim vocabulary.
- [ ] 102-02: Define the reason taxonomy used by appraisal decisions and imports.
- [ ] 102-03: Map current verifier outputs into the normalized claim and reason model.

### Phase 103: External Signed Appraisal Result Import/Export and Policy Mapping

**Goal**: Add signed appraisal result import and export plus explicit local
policy mapping rules.
**Depends on**: Phases 101 and 102
**Requirements**: APPX-03, APPX-04
**Why third**: Portable appraisal results only matter once ARC can exchange
them safely and say exactly how imported results affect local trust posture.

**Primary surfaces:**
- signed appraisal export artifacts
- signed appraisal import path with provenance
- local policy mapping over imported results
- replay, staleness, and unsupported-claim rejection

**Success Criteria**:
1. ARC can export and import one bounded signed appraisal result contract.
2. Imported results only affect policy through explicit local mapping.
3. Existing verifier bridges remain compatible and conservative.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 103-01: Define the signed appraisal export and import artifacts.
- [ ] 103-02: Define local policy mapping from imported appraisal results into ARC trust posture.
- [ ] 103-03: Document import or export guardrails and compatibility behavior.

### Phase 104: Mixed-Provider Appraisal Qualification and Boundary Rewrite

**Goal**: Qualify ARC's mixed-provider appraisal contract end to end and
rewrite the public boundary honestly.
**Depends on**: Phases 101, 102, and 103
**Requirements**: APPX-05
**Why last**: `v2.23` only counts if the mixed-provider appraisal contract is
proven and documented together.

**Primary surfaces:**
- mixed-provider qualification matrix
- negative-path coverage for stale, contradictory, or replayed results
- release, protocol, and partner-boundary updates
- milestone audit and closeout

**Success Criteria**:
1. Mixed-provider appraisal interop is reproducibly qualified.
2. Contradictory or stale appraisal results fail closed.
3. `v2.23` closes with honest public docs.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 104-01: Build qualification evidence for mixed-provider appraisal interop.
- [ ] 104-02: Rewrite the public boundary for common appraisal interop honestly.
- [ ] 104-03: Close `v2.23` with milestone audit and planning-state updates.

### Phase 105: Cross-Issuer Portfolios, Trust Packs, and Migration Semantics

**Goal**: Add bounded cross-issuer portfolios and trust packs without creating
ambient federation trust.
**Depends on**: Phase 104
**Requirements**: FEDX-01
**Why first**: ARC cannot broaden issuer portability until it has one explicit
model for multi-issuer composition and migration.

**Primary surfaces:**
- cross-issuer portfolio artifacts
- trust-pack envelopes and provenance
- migration and composition semantics
- explicit local activation and attenuation rules

**Success Criteria**:
1. ARC can represent multi-issuer portfolios explicitly.
2. Trust packs preserve issuer provenance and signature boundaries.
3. Visibility never implies federation admission.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 105-01: Define cross-issuer portfolio and trust-pack artifacts.
- [ ] 105-02: Define migration and composition semantics across issuers.
- [ ] 105-03: Document trust activation guardrails for cross-issuer portfolios.

### Phase 106: Verifier Descriptors, Trust Bundles, and Reference-Value Distribution

**Goal**: Define portable verifier descriptors, trust bundles, and
reference-value distribution.
**Depends on**: Phase 105
**Requirements**: FEDX-02
**Why second**: Cross-issuer composition is incomplete unless verifier
identity and reference materials are portable too.

**Primary surfaces:**
- verifier descriptor artifacts
- trust-bundle envelopes
- reference-value distribution semantics
- freshness and divergence rejection rules

**Success Criteria**:
1. Verifier identity is machine-readable and signed.
2. Trust bundles and reference values are portable and auditable.
3. Stale or unverifiable bundle state fails closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 106-01: Define verifier descriptors and trust-bundle artifacts.
- [ ] 106-02: Define reference-value and measurement distribution semantics.
- [ ] 106-03: Document verifier descriptor and bundle consumption boundaries.

### Phase 107: Public Issuer/Verifier Discovery, Transparency, and Local Policy Import Guardrails

**Goal**: Publish issuer and verifier discovery plus transparency metadata while
keeping local policy import and runtime admission explicit.
**Depends on**: Phases 105 and 106
**Requirements**: FEDX-03, FEDX-05
**Why third**: ARC can widen discovery now, but it must keep discovery
visibility separate from trust activation.

**Primary surfaces:**
- public issuer and verifier discovery metadata
- freshness and transparency signals
- local policy import guardrails
- fail-closed handling for stale or unsigned discovery data

**Success Criteria**:
1. Issuers and verifiers have public discovery surfaces.
2. Freshness and lineage are visible to operators and reviewers.
3. Public discovery cannot silently widen runtime trust.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 107-01: Define and publish public issuer and verifier discovery artifacts.
- [ ] 107-02: Define transparency and freshness semantics for public discovery.
- [ ] 107-03: Define local policy import guardrails over public discovery.

### Phase 108: Wider Provider Support and Assurance-Aware Auth/Economic Policy

**Goal**: Widen provider coverage over the shared appraisal and federation
substrate and thread that posture into downstream policy.
**Depends on**: Phases 105, 106, and 107
**Requirements**: FEDX-04
**Why last**: `v2.24` only closes once broader provider coverage runs over the
same substrate and the policy effects are qualified.

**Primary surfaces:**
- additional provider or verifier family support
- shared appraisal and federation contracts
- assurance-aware authorization and economic policy hooks
- milestone qualification and boundary closure

**Success Criteria**:
1. ARC supports wider provider coverage on one portable substrate.
2. Imported portable assurance affects policy only through explicit local rules.
3. `v2.24` closes with honest docs and qualification evidence.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 108-01: Extend the common appraisal and federation substrate to additional providers.
- [ ] 108-02: Thread assurance posture into authorization and economic policy surfaces.
- [ ] 108-03: Close `v2.24` with qualification and public-boundary updates.

### Phase 109: Capital Book and Source-of-Funds Ledger

**Goal**: Turn ARC's facility, reserve, and bond posture into an explicit live
capital-book model with attributable sources of funds.
**Depends on**: Phase 108
**Requirements**: CAPX-01
**Why first**: Live capital allocation is impossible to claim honestly until
ARC has one deterministic capital ledger.

**Primary surfaces:**
- capital-book artifacts and balances
- source-of-funds attribution
- role-aware ledger events
- mixed-currency and missing-counterparty rejection

**Success Criteria**:
1. ARC has one explicit capital-book model.
2. Sources of funds are attributable and auditable.
3. Ledger semantics remain conservative and role-bounded.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 109-01: Define live capital-book and source-of-funds artifacts.
- [ ] 109-02: Define ledger-event semantics over capital-book state.
- [ ] 109-03: Document the live capital-book boundary and negative paths.

### Phase 110: Escrow and Reserve Instruction Contract

**Goal**: Define custody-neutral escrow and reserve instruction artifacts over
the live capital book.
**Depends on**: Phase 109
**Requirements**: CAPX-02
**Why second**: Once capital posture is explicit, ARC needs portable
instruction semantics before it can allocate funds live.

**Primary surfaces:**
- escrow and reserve instruction artifacts
- authority chains and execution windows
- intended versus executed movement state
- fail-closed reconciliation handling

**Success Criteria**:
1. ARC can express reserve and escrow intent explicitly.
2. Counterparties and execution windows are auditable.
3. Stale or mismatched execution fails closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 110-01: Define escrow and reserve instruction artifacts.
- [ ] 110-02: Define authority, timing, and reconciliation rules for instructions.
- [ ] 110-03: Document the custody-neutral instruction boundary.

### Phase 111: Live Allocation Engine for Governed Actions

**Goal**: Map governed actions to explicit live capital-allocation decisions.
**Depends on**: Phases 109 and 110
**Requirements**: CAPX-03
**Why third**: ARC can only claim live capital participation once governed
approvals produce deterministic allocation decisions.

**Primary surfaces:**
- allocation-decision artifacts
- source-of-funds selection logic
- simulation-first live allocation behavior
- audit trails and rejection semantics

**Success Criteria**:
1. Governed actions map to one explicit allocation decision.
2. Source-of-funds selection is deterministic and auditable.
3. Missing capital or stale authority fails closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 111-01: Define allocation-decision artifacts for governed actions.
- [ ] 111-02: Define the live allocation engine and simulation boundary.
- [ ] 111-03: Document operator and audit semantics for live allocation.

### Phase 112: Capital Execution Qualification and Regulated-Role Baseline

**Goal**: Qualify the live capital execution surface and formalize the
regulated-role baseline ARC assumes.
**Depends on**: Phases 109, 110, and 111
**Requirements**: CAPX-04, CAPX-05
**Why last**: `v2.25` only counts if the role topology, failure paths, and
qualification matrix are explicit and reproducible.

**Primary surfaces:**
- live-capital qualification evidence
- regulated-role baseline and authority assumptions
- release and partner-boundary updates
- milestone closeout

**Success Criteria**:
1. Live capital surfaces are qualified end to end.
2. Regulated-role assumptions are explicit and bounded.
3. `v2.25` closes with honest public docs.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 112-01: Build qualification evidence for live capital-book and allocation flows.
- [ ] 112-02: Define the regulated-role baseline for live capital execution.
- [ ] 112-03: Close `v2.25` with milestone audit and public-boundary updates.

### Phase 113: Executable Reserve Impairment, Release, and Slash Controls

**Goal**: Make reserve impairment, release, and slash controls executable under
explicit evidence, authority, and appeal rules.
**Depends on**: Phase 112
**Requirements**: LIVEX-01
**Why first**: Bonded autonomy and live money movement require reserve-control
artifacts to become executable rather than descriptive.

**Primary surfaces:**
- executable reserve-control artifacts
- evidence-linked authority and appeal semantics
- reconciliation-aware state transitions
- fail-closed reserve-control rejection rules

**Success Criteria**:
1. Reserve controls are first-class executable artifacts.
2. Every transition is evidence-linked and auditable.
3. Stale or contradictory reserve actions fail closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 113-01: Define executable reserve-control artifacts and transitions.
- [ ] 113-02: Define authority, appeal, and reconciliation rules for reserve controls.
- [ ] 113-03: Document reserve-control semantics and negative paths.

### Phase 114: Delegated Pricing Authority and Automatic Coverage Binding

**Goal**: Add bounded delegated pricing authority and automatic coverage
binding inside one explicit provider or regulated-role envelope.
**Depends on**: Phases 111 and 113
**Requirements**: LIVEX-02
**Why second**: Runtime underwriting only becomes live market infrastructure
after pricing authority and bind semantics are explicit.

**Primary surfaces:**
- delegated pricing authority artifacts
- automatic bind decision semantics
- linkage to underwriting, capital, and provider policy
- fail-closed out-of-envelope bind rejection

**Success Criteria**:
1. Delegated pricing authority is explicit and signed.
2. Automatic binding happens only inside bounded envelopes.
3. Bind decisions stay audit-linked to authority and capital state.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 114-01: Define delegated pricing authority artifacts and limits.
- [ ] 114-02: Define automatic coverage-binding behavior under delegated authority.
- [ ] 114-03: Document automatic bind guardrails and public claims.

### Phase 115: Automatic Claims Payment and Payout Reconciliation

**Goal**: Implement a narrow automatic claims-payment lane with payout
instructions, payout receipts, and reconciliation truth.
**Depends on**: Phases 113 and 114
**Requirements**: LIVEX-03
**Why third**: Coverage binding is incomplete without a bounded payout path
from approved claim to explicit payment and reconciliation artifacts.

**Primary surfaces:**
- payout instructions and payout receipts
- intended versus reconciled payout state
- authority and counterparty metadata
- duplicate or mismatched payout rejection

**Success Criteria**:
1. Claim payment intent and execution are explicit separate artifacts.
2. Payouts reconcile without mutating canonical claim truth.
3. Stale or mismatched payout state fails closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 115-01: Define payout instruction and payout receipt artifacts.
- [ ] 115-02: Define reconciliation and fail-closed behavior for automatic payouts.
- [ ] 115-03: Document the narrow automatic payout boundary.

### Phase 116: Recovery Clearing, Reinsurance/Facility Settlement, and Role Topology

**Goal**: Close the live-money lifecycle across recoveries, reinsurance or
facility settlement, and counterparty role topology.
**Depends on**: Phases 113, 114, and 115
**Requirements**: LIVEX-04, LIVEX-05
**Why last**: `v2.26` only closes once outbound and inbound money flows are
role-attributed and reconciliation-safe across counterparties.

**Primary surfaces:**
- recovery and settlement artifacts
- counterparty role topology
- clearing and reconciliation semantics
- milestone qualification and closeout

**Success Criteria**:
1. Recovery and settlement flows are explicit and auditable.
2. Counterparty disagreement and mismatch paths fail closed.
3. `v2.26` closes with honest live-money boundary docs.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 116-01: Define recovery and reinsurance settlement artifacts plus role topology.
- [ ] 116-02: Define clearing and reconciliation semantics across counterparties.
- [ ] 116-03: Close `v2.26` with qualification and public-boundary updates.

### Phase 117: Generic Listing Artifact and Namespace Model

**Goal**: Generalize ARC's curated discovery surfaces into one generic listing
and namespace model.
**Depends on**: Phase 116
**Requirements**: OPENX-01
**Why first**: The open registry endgame needs one shared listing substrate
before it can reason about mirrors, admission, or governance.

**Primary surfaces:**
- generic listing envelopes
- namespace ownership and transfer semantics
- separation of visibility, identity, and trust
- fail-closed handling for conflicting listings

**Success Criteria**:
1. ARC has one generic listing substrate for market actors.
2. Namespace ownership is explicit and auditable.
3. Listing visibility does not imply trust admission.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 117-01: Define the generic listing artifact model.
- [ ] 117-02: Define namespace ownership and publication semantics.
- [ ] 117-03: Document generic listing boundaries and publication guardrails.

### Phase 118: Origin, Mirror, Indexer, Search, Ranking, and Freshness Semantics

**Goal**: Define how origin operators, mirrors, indexers, search, ranking, and
freshness metadata behave over the generic registry substrate.
**Depends on**: Phase 117
**Requirements**: OPENX-02
**Why second**: Open publication only works if replication, freshness, and
ranking are explicit rather than hidden implementation detail.

**Primary surfaces:**
- origin, mirror, and indexer roles
- freshness and transparency metadata
- search and ranking semantics
- stale or divergent registry-state rejection

**Success Criteria**:
1. Registry replication roles are explicit and auditable.
2. Search and ranking are reproducible enough to review.
3. Stale or divergent registry data is detectable and conservative.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 118-01: Define origin, mirror, and indexer roles over generic listings.
- [ ] 118-02: Define search, ranking, and reproducibility semantics.
- [ ] 118-03: Document stale and divergent registry-state failure paths.

### Phase 119: Trust Activation Artifacts and Open Admission Classes

**Goal**: Define trust-activation artifacts and open admission classes so
registry visibility never collapses into runtime admission.
**Depends on**: Phases 117 and 118
**Requirements**: OPENX-03, OPENX-05
**Why third**: The open registry can widen publication now, but it still must
preserve local operator control over what becomes trusted.

**Primary surfaces:**
- trust-activation artifacts
- open admission classes
- separation of visibility from activation
- fail-closed handling for missing or incompatible activation state

**Success Criteria**:
1. Trust activation is explicit and auditable.
2. Admission classes are machine-readable and bounded.
3. Visibility alone never produces runtime trust.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 119-01: Define trust-activation artifacts over open listings.
- [ ] 119-02: Define open admission classes and bounded eligibility semantics.
- [ ] 119-03: Document local trust-import guardrails for the open registry.

### Phase 120: Governance Charters, Dispute Escalation, Sanctions, and Appeals

**Goal**: Define portable governance charters, dispute escalation, sanctions,
freezes, and appeal artifacts for the open registry network.
**Depends on**: Phases 117, 118, and 119
**Requirements**: OPENX-04
**Why last**: `v2.27` only closes once the open registry also has a portable
governance and dispute layer.

**Primary surfaces:**
- governance charter artifacts
- dispute, sanction, freeze, and appeal lifecycle artifacts
- cross-operator escalation semantics
- milestone audit and boundary updates

**Success Criteria**:
1. Governance actions are portable, signed, and scope-bounded.
2. Escalation and appeal behavior are explicit and reproducible.
3. `v2.27` closes with honest open-governance docs.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 120-01: Define governance-charter and case-management artifacts.
- [ ] 120-02: Define escalation, sanction, and appeal lifecycle semantics.
- [ ] 120-03: Close `v2.27` with milestone audit and open-governance boundary updates.

### Phase 121: Portable Reputation, Negative-Event Exchange, and Weighting Profiles

**Goal**: Externalize portable reputation and negative-event exchange while
preserving issuer provenance and local weighting.
**Depends on**: Phase 120
**Requirements**: ENDX-01
**Why first**: The open-market endgame needs portable market-discipline
signals, but ARC must keep them provenance-preserving and locally weighted.

**Primary surfaces:**
- portable reputation artifacts
- negative-event exchange
- local weighting and attenuation profiles
- fail-closed import rejection rules

**Success Criteria**:
1. Portable reputation has one explicit artifact family.
2. Imported reputation remains locally weighted rather than globally canonical.
3. Unverifiable or contradictory reputation inputs fail closed.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 121-01: Define portable reputation and negative-event artifacts.
- [ ] 121-02: Define local weighting and attenuation profiles for imported reputation.
- [ ] 121-03: Document portable reputation boundaries and failure modes.

### Phase 122: Fee Schedules, Bonds, Slashing, and Abuse Resistance

**Goal**: Define marketplace fee schedules, bonds, slashing, and
abuse-resistance economics over the open-market substrate.
**Depends on**: Phase 121
**Requirements**: ENDX-02
**Why second**: Open-market discipline requires explicit economics and
penalties rather than informal operator policy.

**Primary surfaces:**
- fee-schedule artifacts
- publisher and dispute bonds
- slashing and abuse-resistance controls
- authority and appeal semantics for market penalties

**Success Criteria**:
1. Marketplace economics are explicit and signed.
2. Slashing requires evidence and valid authority.
3. Abuse resistance is bounded and reproducible.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 122-01: Define marketplace fee-schedule and bond artifacts.
- [ ] 122-02: Define slashing and abuse-resistance controls over market actors.
- [ ] 122-03: Document marketplace economics and abuse-resistance boundaries.

### Phase 123: Adversarial Multi-Operator Open-Market Qualification

**Goal**: Prove the open-market model under adversarial multi-operator
conditions without collapsing visibility or imported evidence into trust.
**Depends on**: Phases 117, 118, 119, 120, 121, and 122
**Requirements**: ENDX-03
**Why third**: The endgame claim is not credible unless ARC can show the
open-market model under adversarial multi-operator behavior.

**Primary surfaces:**
- adversarial qualification matrix
- negative-path coverage across registry, governance, reputation, and economics
- partner-reviewable proof materials
- fail-closed treatment for malicious or stale operator data

**Success Criteria**:
1. Qualification covers the core adversarial open-market surfaces.
2. Visibility-versus-trust separation survives malicious external data.
3. Evidence is ready for final partner and release review.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 123-01: Build the adversarial multi-operator qualification matrix.
- [ ] 123-02: Prove visibility-versus-trust separation under adversarial conditions.
- [ ] 123-03: Prepare endgame proof materials from the adversarial qualification results.

### Phase 124: Partner Proof, Release Boundary, and Honest Endgame Claim Closure

**Goal**: Close the full research endgame with final partner proof,
release-boundary updates, and an honest claim about what ARC now supports.
**Depends on**: Phases 121, 122, and 123
**Requirements**: ENDX-04, ENDX-05
**Why last**: The roadmap only counts as complete if the public protocol,
release docs, and proof artifacts match the widened endgame claim.

**Primary surfaces:**
- final partner proof and release audit
- protocol and guide rewrites
- final milestone audits and planning-state closure
- explicit non-goals and external publication dependencies

**Success Criteria**:
1. ARC can claim the research endgame honestly and specifically.
2. Residual boundaries remain explicit and reviewable.
3. The final roadmap state closes without missing executable work.

**Status**: ready
**Plans**: 3 plans

Plans:
- [ ] 124-01: Rewrite partner-proof and release-boundary materials for the endgame claim.
- [ ] 124-02: Close milestone and roadmap state for the full endgame ladder.
- [ ] 124-03: Document the final honest endgame claim and residual boundaries.

### Phase 65: OID4VP Verifier Profile and Request Transport

**Goal**: Make ARC a real OID4VP verifier for the ARC SD-JWT VC profile using
one narrow, auditable transport and response contract.
**Depends on**: Phase 64
**Requirements**: PVP-01, PVP-03, PVP-05
**Why first**: ARC cannot honestly claim verifier portability until it can
issue signed verifier requests, persist transaction state, and verify a
standards-native presentation response without falling back to ARC-native
challenge artifacts.

**Primary surfaces:**
- OID4VP request-object creation and signing
- replay-safe verifier transaction storage
- `request_uri` publication and same-device plus cross-device launch output
- `direct_post.jwt` response handling for ARC SD-JWT VC
- fail-closed nonce, audience, state, replay, and disclosure validation

**Success Criteria**:
1. ARC can create one explicit verifier request contract for the ARC SD-JWT VC
   profile.
2. ARC can verify a standards-native response without relying on ARC-native
   holder challenge transport.
3. Replay, stale, mismatched, or unsupported responses fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 65-01: Define ARC's narrow OID4VP verifier profile and signed
  request-object contract.
- [x] 65-02: Implement replay-safe verifier transaction storage plus request
  transport.
- [x] 65-03: Implement OID4VP response handling and verifier-side validation.

### Phase 66: Wallet / Holder Distribution Adapters

**Goal**: Add one reference holder adapter and wallet launch surface so ARC
can prove same-device and cross-device use without becoming a wallet vendor.
**Depends on**: Phase 65
**Requirements**: PVP-03, PVP-04, PVP-05
**Why second**: Once verifier transport exists, ARC needs a bounded holder-side
path that exercises the supported flow against real portable credentials and
shows how OID4VP coexists with the ARC-native challenge lane.

**Primary surfaces:**
- minimal reference holder adapter for qualification and partner demos
- same-device launch artifacts
- cross-device QR handoff
- coexistence rules between ARC-native presentation and OID4VP

**Success Criteria**:
1. ARC ships one usable reference holder path for demos and tests.
2. Same-device and cross-device launches are explicit, bounded, and testable.
3. The OID4VP lane coexists with ARC-native challenge transport without
   silently widening portability claims.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 66-01: Add a reference holder adapter for the ARC SD-JWT VC profile.
- [x] 66-02: Publish same-device and cross-device launch artifacts.
- [x] 66-03: Define coexistence and fail-closed boundaries between OID4VP and
  ARC-native holder transport.

### Phase 67: Public Verifier Trust and Discovery Model

**Goal**: Define how public ARC verifier deployments authenticate themselves
and publish trust-bootstrap material without overclaiming generic federation.
**Depends on**: Phase 65
**Requirements**: PVP-02, PVP-05
**Why third**: Wallet interop is incomplete if the holder cannot evaluate
verifier identity. ARC needs one concrete verifier-authentication profile that
fits its operator-scoped web deployment model and rotation rules.

**Primary surfaces:**
- verifier identity profile selection
- verifier metadata and trust bootstrap artifacts
- verifier-key or certificate rotation rules
- explicit acceptance and rejection boundaries for verifier identity schemes

**Success Criteria**:
1. ARC has one public verifier identity model suitable for deployment.
2. Trust bootstrap and rotation behavior are explicit and auditable.
3. Unsupported verifier identity schemes fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 67-01: Choose and document ARC's first public verifier authentication
  profile.
- [x] 67-02: Implement verifier trust publication and rotation semantics.
- [x] 67-03: Add regression coverage and docs for verifier trust bootstrap and
  identity failure modes.

### Phase 68: Ecosystem Qualification and Research Closure

**Goal**: Close `v2.14` with external-wallet qualification,
portability-boundary rewrites, and milestone evidence strong enough to say
verifier-side portable interop is no longer missing.
**Depends on**: Phases 66 and 67
**Requirements**: PVP-01, PVP-02, PVP-03, PVP-04, PVP-05
**Why last**: ARC should not claim OID4VP and wallet interop until the path is
exercised end to end, the negative paths are fail-closed, and the docs stop
describing verifier portability as absent.

**Primary surfaces:**
- end-to-end issuance plus presentation qualification
- negative-path coverage for verifier trust, replay, stale status, and
  over-disclosure
- portability, protocol, release, and partner-proof doc closure
- milestone audit and planning-state advancement into `v2.15`

**Success Criteria**:
1. Qualification proves one external wallet or holder path end to end.
2. Docs reflect the supported verifier and wallet boundary truthfully.
3. `v2.14` closes with explicit audit evidence and updated planning state.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 68-01: Build qualification evidence for the supported OID4VP and wallet
  path.
- [x] 68-02: Rewrite portability, protocol, and release boundaries around
  verifier-side interop closure.
- [x] 68-03: Audit `v2.14`, close the milestone, and advance planning state.

### Phase 69: Common Appraisal Contract and Adapter Interface

**Goal**: Define ARC's typed appraisal contract and verifier-adapter
interface so raw evidence, verifier identity, normalized assertions, and
vendor-scoped claims are explicit instead of adapter-specific.
**Depends on**: Phase 60
**Requirements**: RATS-02
**Why first**: ARC cannot widen beyond Azure safely until every verifier
family emits one canonical appraisal shape and one explicit normalization
boundary.

**Primary surfaces:**
- canonical appraisal types, statuses, and reason codes
- verifier-adapter interface and metadata contract
- separation of raw evidence references, normalized assertions, and vendor
  claims
- fail-closed handling for malformed or partial appraisals

**Success Criteria**:
1. ARC has one canonical appraisal contract instead of verifier-specific
   blobs.
2. Normalized assertions are bounded and auditable.
3. Unknown or incomplete appraisal inputs fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 69-01: Define the canonical ARC appraisal contract.
- [x] 69-02: Define the verifier-adapter interface and registration boundary.
- [x] 69-03: Document and test the normalization boundary for appraisals.

### Phase 70: AWS Nitro Verifier Adapter

**Goal**: Add a real AWS Nitro verifier path that emits the canonical ARC
appraisal contract.
**Depends on**: Phase 69
**Requirements**: RATS-01
**Why second**: The shared contract only matters if ARC can prove it against a
materially different verifier family than Azure.

**Primary surfaces:**
- AWS Nitro evidence mapping
- Nitro verifier adapter implementation
- freshness, replay, and measurement validation
- adapter-specific tests and operator guidance

**Success Criteria**:
1. ARC supports one non-Azure verifier family end to end.
2. Nitro evidence is projected through the canonical appraisal contract.
3. Replay, stale, malformed, or unknown Nitro evidence fails closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 70-01: Define the AWS Nitro evidence mapping into ARC appraisal
  semantics.
- [x] 70-02: Implement the AWS Nitro verifier adapter.
- [x] 70-03: Add regression coverage and operator guidance for the Nitro
  adapter.

### Phase 71: Google Attestation Adapter and Runtime-Assurance Policy v2

**Goal**: Add a Google attestation adapter and evolve runtime-assurance policy
over canonical appraisals from multiple verifier families.
**Depends on**: Phase 69
**Requirements**: RATS-03, RATS-04, RATS-06
**Why third**: Multi-cloud support is incomplete until ARC can normalize a
second non-Azure verifier family and express explicit policy semantics over
mixed appraisal inputs.

**Primary surfaces:**
- Google attestation adapter
- conservative claim normalization rules
- runtime-assurance policy v2
- issuance, governed-execution, and underwriting integration

**Success Criteria**:
1. ARC supports a second non-Azure verifier family without pretending claim
   equivalence.
2. Trusted-verifier policy becomes adapter-aware and fail-closed.
3. Appraisals influence issuance, execution, and underwriting only through
   explicit policy and reason codes.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 71-01: Define Google attestation normalization and adapter boundaries.
- [x] 71-02: Implement runtime-assurance policy v2 over appraised verifier
  outputs.
- [x] 71-03: Integrate appraised verifier evidence into issuance, governed
  execution, and underwriting.

### Phase 72: Appraisal Export, Qualification, and Boundary Closure

**Goal**: Close `v2.15` with a signed appraisal export surface,
multi-adapter qualification evidence, and honest boundary docs.
**Depends on**: Phases 70 and 71
**Requirements**: RATS-05, RATS-07
**Why last**: ARC should not claim multi-cloud appraisal support until
operators can inspect one canonical appraisal artifact and the cross-family
failure modes are proven.

**Primary surfaces:**
- signed appraisal export or report artifact
- Azure, AWS, and Google qualification lanes
- replay, freshness, rotation, and debug-boundary coverage
- milestone audit and planning-state advancement into `v2.16`

**Success Criteria**:
1. Operators can inspect and share one canonical signed appraisal artifact.
2. Qualification proves multi-cloud appraisal behavior end to end.
3. `v2.15` closes with truthful protocol, release, and runbook boundaries.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 72-01: Define and implement the signed appraisal export surface.
- [x] 72-02: Build qualification evidence for multi-cloud appraisal behavior.
- [x] 72-03: Close `v2.15` and advance planning state.

### Phase 73: ARC OAuth Authorization Profile

**Goal**: Publish ARC's first normative enterprise-facing authorization
profile over governed intents, approvals, and transaction context.
**Depends on**: Phase 48
**Requirements**: IAM-01
**Why first**: Enterprise IAM work should start from one explicit standards
profile instead of a loose collection of implementation mappings.

**Primary surfaces:**
- normative authorization-details profile
- transaction-context mapping
- governed-intent and approval projection rules
- fail-closed profile validation

**Success Criteria**:
1. ARC has one standards-facing authorization profile.
2. Governed ARC truth remains the authoritative source behind the profile.
3. Unsupported authorization shapes fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 73-01: Define the normative ARC authorization semantics profile.
- [x] 73-02: Implement profile-bound projection and validation surfaces.
- [x] 73-03: Document the authorization profile for external reviewers.

### Phase 74: Sender-Constrained and Discovery Contracts

**Goal**: Make ARC's authorization profile legible for sender-constrained and
metadata-driven enterprise deployment.
**Depends on**: Phase 73
**Requirements**: IAM-02
**Why second**: Enterprise IAM reviewers need explicit semantics for sender
binding and metadata discovery before ARC can package reviewer evidence.

**Primary surfaces:**
- sender-constrained semantics profile
- discovery and metadata contract
- assurance-bound and delegation-bound sender behavior
- fail-closed mismatch handling

**Success Criteria**:
1. ARC has one explicit sender-binding story for the enterprise profile.
2. Discovery metadata is machine-readable and bounded.
3. Missing proof or mismatched discovery data fails closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 74-01: Define ARC's sender-constrained authorization semantics.
- [x] 74-02: Publish machine-readable discovery and metadata contracts.
- [x] 74-03: Add negative-path coverage for sender and discovery mismatch
  behavior.

### Phase 75: Enterprise IAM Adapters, Metadata, and Reviewer Packs

**Goal**: Package ARC's enterprise authorization profile into metadata and
reviewer-facing evidence bundles.
**Depends on**: Phase 74
**Requirements**: IAM-03, IAM-04
**Why third**: Once the profile and discovery semantics are stable, ARC can
turn them into reviewable artifacts that tie back to signed receipt truth.

**Primary surfaces:**
- enterprise-facing metadata artifacts
- reviewer packs tying intent, approval, auth context, and receipts together
- operator-visible reporting or adapter surfaces
- traceability and integrity regression coverage

**Success Criteria**:
1. External reviewers can trace a governed action end to end.
2. Machine-readable metadata is available for enterprise review.
3. Operators can prepare reviewer packs without bespoke work.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 75-01: Build enterprise-facing metadata and profile publication
  artifacts.
- [x] 75-02: Create reviewer packs that trace governed actions end to end.
- [x] 75-03: Add operator guidance and integration adapters for enterprise
  review.

### Phase 76: Conformance, Qualification, and Standards-Facing Proof

**Goal**: Close `v2.16` with conformance evidence, fail-closed qualification,
and a standards-facing proof package.
**Depends on**: Phase 75
**Requirements**: IAM-05
**Why last**: ARC should not claim enterprise IAM legibility until the
profile, sender semantics, metadata, and evidence packs are proven under
qualification.

**Primary surfaces:**
- conformance and negative-path qualification
- standards-facing proof artifacts
- boundary updates in protocol and release docs
- milestone audit and planning-state advancement into `v2.17`

**Success Criteria**:
1. Qualification proves the enterprise authorization profile end to end.
2. Failure boundaries are explicit for reviewers and operators.
3. `v2.16` closes with truthful docs and explicit audit evidence.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 76-01: Build conformance and qualification evidence for the enterprise
  profile.
- [x] 76-02: Publish the standards-facing proof and boundary docs.
- [x] 76-03: Close `v2.16` and advance planning state.

### Phase 77: Certification Criteria and Conformance Evidence Profiles

**Goal**: Version ARC certification criteria and evidence packages so public
discovery can rest on reproducible conformance artifacts.
**Depends on**: Phase 40
**Requirements**: CERT-01
**Why first**: Public marketplace discovery is unsafe unless the underlying
certification artifacts are versioned, comparable, and provenance-preserving.

**Primary surfaces:**
- versioned certification criteria
- reproducible evidence-package profiles
- publisher provenance semantics
- fail-closed handling for incomplete evidence

**Success Criteria**:
1. ARC Certify exposes one reproducible certification evidence contract.
2. Independent operators can publish comparable evidence packages.
3. Incomplete or unverifiable certification evidence fails closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 77-01: Define versioned certification criteria and evidence-package
  structure.
- [x] 77-02: Implement conformance evidence profiles in ARC Certify.
- [x] 77-03: Document certification-profile boundaries and failure semantics.

### Phase 78: Public Operator Identity and Discovery Metadata

**Goal**: Publish operator identity and discovery metadata for the public
certification surface without turning discovery into a runtime trust oracle.
**Depends on**: Phase 77
**Requirements**: CERT-02
**Why second**: Public discovery needs an explicit publisher identity and
metadata model before search and transparency can be widened.

**Primary surfaces:**
- public operator identity model
- discovery metadata and resolution artifacts
- provenance and rotation semantics
- fail-closed handling for stale or mismatched metadata

**Success Criteria**:
1. Public publisher identity is explicit and auditable.
2. Discovery metadata is machine-readable and provenance-preserving.
3. Identity or metadata presence never auto-grants runtime trust.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 78-01: Define the public operator identity model for certification
  publishers.
- [x] 78-02: Implement public discovery metadata and resolution artifacts.
- [x] 78-03: Add regression coverage and docs for public operator discovery.

### Phase 79: Public Search, Resolution, and Transparency Network

**Goal**: Add public search and transparency surfaces over certification
artifacts while keeping consumer admission policy evidence-backed and
operator-controlled.
**Depends on**: Phase 78
**Requirements**: CERT-03
**Why third**: Search and transparency are the point where marketplace
visibility could be confused with trust, so ARC needs an explicit consumption
boundary.

**Primary surfaces:**
- public search and comparison
- transparency feeds or logs
- listing resolution and history
- policy-bound consumption semantics

**Success Criteria**:
1. Public certifications are searchable and comparable across operators.
2. Listing state changes are transparent and auditable.
3. Public listing consumption remains policy-controlled and fail-closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 79-01: Define public search and comparison semantics for
  certifications.
- [x] 79-02: Implement transparency and resolution surfaces for public
  certifications.
- [x] 79-03: Add policy-bound consumption semantics and regression coverage.

### Phase 80: Governance, Dispute Semantics, and Marketplace Qualification

**Goal**: Close `v2.17` with explicit governance, dispute, and qualification
semantics for ARC's public certification marketplace.
**Depends on**: Phases 78 and 79
**Requirements**: CERT-04, CERT-05
**Why last**: Marketplace-grade discovery is incomplete until disputes,
supersession, revocation, and qualification are explicit and auditable.

**Primary surfaces:**
- governance and dispute state
- public evidence update, revocation, and supersession workflows
- end-to-end marketplace qualification
- milestone audit and planning-state advancement into `v2.18`

**Success Criteria**:
1. Public certification governance and disputes are explicit and auditable.
2. Qualification proves publish, discover, resolve, and consume flows end to
   end.
3. `v2.17` closes with truthful marketplace-boundary docs and audit evidence.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 80-01: Define governance and dispute semantics for public certification
  state.
- [x] 80-02: Build qualification evidence for the public certification
  marketplace path.
- [x] 80-03: Close `v2.17` and advance planning state.

### Phase 81: Exposure Ledger and Economic Position Model

**Goal**: Define ARC's canonical exposure ledger and signed economic-position
state over governed actions, premiums, reserves, losses, recoveries, and
settlement truth.
**Depends on**: Phase 52
**Requirements**: CREDIT-01
**Why first**: Credit and facility policy are not defensible unless ARC first
defines one canonical economic-position model instead of inferring exposure
from scattered underwriting, settlement, and receipt views.

**Primary surfaces:**
- exposure ledger schema and lifecycle
- signed exposure artifact and aggregation semantics
- settlement, reserve, loss, and recovery position accounting
- currency and evidence-boundary rules

**Success Criteria**:
1. ARC has one canonical exposure ledger over existing economic truth.
2. Exposure artifacts are signed, explainable, and evidence-backed.
3. Mixed, partial, or ambiguous position inputs fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 81-01: Define the exposure-ledger schema and economic-position rules.
- [x] 81-02: Implement signed exposure artifacts and query surfaces.
- [x] 81-03: Add validation, documentation, and failure-boundary coverage for
  exposure state.

### Phase 82: Credit Scorecards, Probation, and Anomaly Signals

**Goal**: Turn exposure history into one versioned credit-scorecard contract
with explicit probation, anomaly, and explanation semantics.
**Depends on**: Phase 81
**Requirements**: CREDIT-02
**Why second**: Capital policy and bonded autonomy need a stable score and
watchlist substrate before they can allocate risk or constrain execution.

**Primary surfaces:**
- scorecard dimensions and weighting model
- probation, downgrade, and anomaly signal semantics
- reason-coded score explanations
- fail-closed handling for sparse or contradictory evidence

**Success Criteria**:
1. ARC can produce one explainable scorecard over exposure truth.
2. Probation and anomaly posture are explicit instead of ad hoc operator
   interpretation.
3. Unsupported or insufficient evidence does not silently produce a confident
   score.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 82-01: Define the scorecard contract, reasons, and anomaly taxonomy.
- [x] 82-02: Implement score, probation, and anomaly evaluation over exposure
  state.
- [x] 82-03: Add regression coverage and docs for score drift and sparse
  evidence handling.

### Phase 83: Facility Terms and Capital Allocation Policy

**Goal**: Bind credit posture into signed capital-facility terms and bounded
allocation policy that can later support bonded autonomy and provider review.
**Depends on**: Phase 82
**Requirements**: CREDIT-03
**Why third**: The project cannot claim capital-allocation readiness until ARC
can issue explicit facility artifacts rather than just scoring agents.

**Primary surfaces:**
- capital-facility term schema
- bounded allocation and ceiling policy
- assurance, certification, and score prerequisites
- fail-closed issuance and supersession rules

**Success Criteria**:
1. ARC issues one signed facility-policy artifact tied to score and exposure.
2. Capital ceilings and prerequisites are explicit and bounded.
3. Missing score, assurance, or certification prerequisites fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 83-01: Define signed facility terms and allocation-policy semantics.
- [x] 83-02: Implement facility issuance, supersession, and gating behavior.
- [x] 83-03: Add provider-facing policy explanation and failure-path coverage.

### Phase 84: Credit Qualification, Backtests, and Provider Risk Package

**Goal**: Close `v2.18` with backtests, simulation, and one provider-facing
risk package strong enough to justify external capital review.
**Depends on**: Phases 81, 82, and 83
**Requirements**: CREDIT-04
**Why last**: ARC should not claim a credit-grade economic layer until the
ledger, score, and facility outputs are qualified and packaged honestly for
reviewers.

**Primary surfaces:**
- historical backtests and simulation
- provider risk package and reviewer exports
- qualification over score and facility failure modes
- milestone audit and planning-state advancement into `v2.19`

**Success Criteria**:
1. ARC can replay and inspect the credit layer under simulation or backtest.
2. External-capital reviewers get one bounded risk package over signed truth.
3. `v2.18` closes with audit evidence and truthful boundary docs.

**Status**: complete
**Plans**: 3 plans

Plans:
- [ ] 84-01: Build backtests and simulation for exposure, score, and facility
  policy.
- [ ] 84-02: Package the provider-facing risk review artifacts and docs.
- [ ] 84-03: Audit `v2.18`, close the milestone, and advance planning state.

### Phase 85: Bond Contracts, Reserve Locks, and Collateral State

**Goal**: Define ARC's signed bond, reserve-lock, and collateral-state
artifacts as the economic backing for autonomous execution.
**Depends on**: Phase 84
**Requirements**: BOND-01
**Why first**: Bonded autonomy needs explicit reserve and collateral state
before delegation, slashing, or loss recovery can be enforced truthfully.

**Primary surfaces:**
- bond and reserve contract schema
- collateral lock and release lifecycle
- linkage to exposure and facility state
- fail-closed reserve accounting

**Success Criteria**:
1. ARC has one signed bond and reserve-state contract.
2. Collateral lifecycle is explicit and auditable.
3. Reserve mismatches or unsupported lock states fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 85-01: Define bond contracts and reserve-lock lifecycle semantics.
- [x] 85-02: Implement collateral-state persistence and artifact issuance.
- [x] 85-03: Add accounting validation and reserve-boundary documentation.

### Phase 86: Delegation Bonds and Autonomy Tier Gates

**Goal**: Bind reserve-backed bond state into delegation and autonomy-tier
gates so economically sensitive execution fails closed without prerequisites.
**Depends on**: Phase 85
**Requirements**: BOND-02
**Why second**: Bond state only matters if ARC can actually use it to permit
or deny higher-risk autonomous execution paths.

**Primary surfaces:**
- delegation-bond attachment semantics
- autonomy tier prerequisites
- reserve plus assurance gating behavior
- fail-closed execution denial reasons

**Success Criteria**:
1. ARC can gate autonomy tiers on bond, reserve, and assurance state.
2. Delegation bonds are explicit rather than inferred from capability lineage.
3. Missing or stale prerequisites deny sensitive execution fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 86-01: Define delegation-bond semantics and autonomy-tier prerequisites.
- [x] 86-02: Implement runtime gating over bond, reserve, and assurance state.
- [x] 86-03: Add regression coverage and operator guidance for autonomy denial
  paths.

### Phase 87: Loss Events, Recovery, and Delinquency Lifecycle

**Goal**: Add immutable loss, recovery, delinquency, reserve-release, and
write-off state over bond-backed execution.
**Depends on**: Phases 85 and 86
**Requirements**: BOND-03
**Why third**: Bonded autonomy is incomplete until ARC can record and explain
what happens when economic backing is consumed, impaired, or restored.

**Primary surfaces:**
- loss-event and delinquency artifacts
- recovery, reserve-release, and write-off lifecycle
- linkage back to exposure and bond state
- fail-closed settlement or reserve adjustments

**Success Criteria**:
1. Loss and recovery state is immutable and auditable.
2. Reserve release or write-off decisions are explicit and reason-coded.
3. Delinquency cannot be hidden behind mutable balance updates.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 87-01: Define loss, delinquency, recovery, and write-off semantics.
- [x] 87-02: Implement immutable loss-lifecycle artifacts and accounting
  updates.
- [x] 87-03: Add explanation, audit, and failure-boundary coverage for
  delinquency state.

### Phase 88: Qualification, Operator Controls, and Sandbox Integrations

**Goal**: Close `v2.19` with qualification, simulation controls, and one
sandboxed integration path over bonded execution.
**Depends on**: Phases 86 and 87
**Requirements**: BOND-04
**Why last**: ARC should not claim bonded autonomy until the reserve, gating,
and loss-recovery paths are reproducible and operator-visible.

**Primary surfaces:**
- bonded-execution qualification and simulation
- operator controls and kill-switch semantics
- sandbox or external-capital integration proof
- milestone audit and planning-state advancement into `v2.20`

**Success Criteria**:
1. Bonded execution paths are reproducible under qualification and simulation.
2. Operators have explicit controls over reserve-backed autonomy.
3. `v2.19` closes with truthful docs and audit evidence.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 88-01: Build qualification and simulation for bonded execution flows.
- [x] 88-02: Implement operator controls and one sandbox integration proof.
- [x] 88-03: Audit `v2.19`, close the milestone, and advance planning state.

### Phase 89: Provider Registry, Coverage Classes, and Jurisdiction Policy

**Goal**: Define a curated provider registry and policy model for coverage
classes, jurisdictions, currencies, and evidence requirements.
**Depends on**: Phase 88
**Requirements**: MARKET-01
**Why first**: Liability-market orchestration requires explicit provider and
jurisdiction constraints before ARC can quote, bind, or adjudicate anything.

**Primary surfaces:**
- provider registry schema
- coverage classes and jurisdiction policy
- currency and evidence requirement declarations
- curated provider admission rules

**Success Criteria**:
1. ARC has one curated provider registry over explicit policy and evidence.
2. Coverage classes and jurisdictions are machine-readable and bounded.
3. Unsupported providers or jurisdictions fail closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 89-01: Define provider-registry, coverage-class, and jurisdiction policy
  semantics.
- [x] 89-02: Implement curated provider publication and query surfaces.
- [x] 89-03: Add validation and docs for unsupported provider or policy
  combinations.

### Phase 90: Quote Requests, Placement, and Bound Coverage Artifacts

**Goal**: Add canonical quote-request, quote-response, placement, and
bound-coverage artifacts over one signed risk package.
**Depends on**: Phase 89
**Requirements**: MARKET-02
**Why second**: Provider selection is not useful unless ARC can actually ask
for quotes and represent bound coverage over canonical evidence.

**Primary surfaces:**
- quote-request and quote-response contracts
- placement and bound-coverage artifacts
- linkage to provider, jurisdiction, and risk package state
- fail-closed quote expiry and mismatch handling

**Success Criteria**:
1. ARC can model quote and bind flows over a canonical risk package.
2. Placement semantics remain provider-neutral and auditable.
3. Expired, mismatched, or unsupported quote state fails closed.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 100-01: Qualify same-device and cross-device wallet exchange flows.
- [x] 100-02: Qualify asynchronous exchange and sender-constrained failures.
- [x] 100-03: Close the milestone with release, partner-proof, and audit docs.

Plans:
- [x] 90-01: Define quote, placement, and bound-coverage artifact semantics.
- [x] 90-02: Implement provider-neutral quote and bind workflow surfaces.
- [x] 90-03: Add validation and failure-mode coverage for quote lifecycle and
  placement mismatches.

### Phase 91: Claim Packages, Disputes, and Liability Adjudication

**Goal**: Add immutable claim packages, provider responses, dispute state, and
adjudication evidence linked back to receipts, exposure, and bond state.
**Depends on**: Phase 90
**Requirements**: MARKET-03
**Why third**: A liability-market claim is incomplete until ARC can represent
what was claimed, how a provider responded, and how disputes are adjudicated.

**Primary surfaces:**
- claim-package and provider-response artifacts
- dispute and adjudication lifecycle
- linkage to receipts, exposure, and bond events
- fail-closed evidence and jurisdiction checks

**Success Criteria**:
1. Claim packages are immutable and evidence-backed.
2. Provider responses and disputes are explicit, auditable state transitions.
3. Claim adjudication cannot drift from the underlying signed ARC evidence.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 91-01: Define claim, provider-response, and dispute adjudication
  semantics.
- [x] 91-02: Implement immutable claim-package and response workflow surfaces.
- [x] 91-03: Add audit and failure-path coverage for claim evidence and
  jurisdiction mismatches.

### Phase 92: Marketplace Qualification, Partner Proof, and Boundary Update

**Goal**: Close `v2.20` with end-to-end qualification, partner proof, and a
truthful public boundary update for the liability-market surface.
**Depends on**: Phases 89, 90, and 91
**Requirements**: MARKET-04
**Why last**: ARC should not claim liability-market orchestration until quote,
bind, claim, and dispute flows are proven and the public boundary is updated
honestly.

**Primary surfaces:**
- end-to-end marketplace qualification
- partner proof and operator runbook artifacts
- public boundary and non-goal rewrite
- final milestone audit and planning-state closeout

**Success Criteria**:
1. ARC proves one multi-provider quote, bind, claim, and dispute flow end to
   end.
2. Partner and operator artifacts explain the bounded marketplace posture
   honestly.
3. `v2.20` closes with explicit audit evidence and updated public boundaries.

**Status**: complete
**Plans**: 3 plans

Plans:
- [x] 92-01: Build end-to-end marketplace qualification and partner proof.
- [x] 92-02: Rewrite release, protocol, and partner boundary docs for the
  liability-market surface.
- [x] 92-03: Audit `v2.20`, close the remaining roadmap ladder, and finalize
  planning state.

## Previous Completed Milestone: v2.19 Bonded Autonomy and Facility Execution

**Milestone Goal:** Enforce capital-backed autonomy with reserves, delegation
bonds, delinquency state, and bounded facility execution.

**Why it mattered:** ARC already shipped signed exposure, facility, backtest,
and provider-risk-package artifacts, but the research endgame still required
those credit surfaces to become bounded runtime capital posture. `v2.19` is
the step where ARC can gate delegated or autonomous execution on reserve
state, record delinquency explicitly, and let operators simulate bonded
execution controls before runtime use.

- [x] **Phase 85: Bond Contracts, Reserve Locks, and Collateral State** -
  Define signed bond, reserve-lock, and collateral-state truth over active
  facilities and canonical exposure.
- [x] **Phase 86: Delegation Bonds and Autonomy Tier Gates** - Bind reserve
  posture into delegation and autonomy-tier runtime enforcement.
- [x] **Phase 87: Loss Events, Recovery, and Delinquency Lifecycle** - Add
  immutable delinquency, recovery, reserve-release, and write-off state.
- [x] **Phase 88: Qualification, Operator Controls, and Sandbox Integrations**
  - Qualify bonded execution, add explicit operator control policy, and close
    the milestone.

## Previous Completed Milestone: v2.18 Credit, Exposure, and Capital Policy

**Milestone Goal:** Expand certification into a public discovery and
transparency layer with explicit governance, provenance, and dispute semantics.

**Why it mattered:** ARC already shipped signed certification artifacts and
bounded operator discovery, but the research endgame still required a governed
public marketplace surface with versioned evidence profiles, provenance-aware
metadata, searchable transparency, and dispute semantics that do not silently
turn listing visibility into runtime trust.

- [x] **Phase 77: Certification Criteria and Conformance Evidence Profiles** -
  Define and enforce versioned public certification evidence bundles.
- [x] **Phase 78: Public Operator Identity and Discovery Metadata** - Publish
  public marketplace metadata with fail-closed provenance and freshness rules.
- [x] **Phase 79: Public Search, Resolution, and Transparency Network** - Add
  public search, comparison, transparency, and policy-bound consumption.
- [x] **Phase 80: Governance, Dispute Semantics, and Marketplace Qualification**
  - Ship dispute-aware governance and qualify the marketplace path end to end.

## Earlier Completed Milestone: v2.15 Multi-Cloud Attestation and Appraisal Contracts

**Milestone Goal:** Replace the current Azure-first verifier boundary with a
typed appraisal contract plus multiple concrete verifier adapters and
policy-visible normalization rules.

**Why it mattered:** `v2.12` proved ARC could bridge workload identity and
cloud attestation into runtime trust, but the verifier boundary remained too
Azure-shaped. `v2.15` added a canonical appraisal contract, AWS and Google
verifier families, and one signed appraisal export surface.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on SPIFFE, RATS, EAT, and cloud
  attestation as inputs into bounded trust decisions
- `docs/WORKLOAD_IDENTITY_RUNBOOK.md` and
  `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` on the verifier bridge
  boundary
- `.planning/research/POST_V2_12_RESEARCH_COMPLETION_SYNTHESIS.md` on the
  remaining multi-cloud appraisal gap after `v2.12`

- [x] **Phase 69: Common Appraisal Contract and Adapter Interface** - Define
  the canonical appraisal contract and verifier-adapter interface.
- [x] **Phase 70: AWS Nitro Verifier Adapter** - Add the first non-Azure
  verifier path over certificate-anchored Nitro evidence.
- [x] **Phase 71: Google Attestation Adapter and Runtime-Assurance Policy v2**
  - Add Google Confidential VM evidence and appraisal-aware trust-policy
  rebinding.
- [x] **Phase 72: Appraisal Export, Qualification, and Boundary Closure** -
  Qualify the multi-cloud verifier boundary and close the milestone honestly.

## Phase Details

### Phase 61: External Credential Projection and Identity Strategy

**Goal**: Define ARC's first standards-native external credential projection
and the identity strategy that preserves ARC truth while making portable
verification possible.
**Depends on**: Phase 60
**Requirements**: PVC-01, PVC-03, PVC-05
**Why first**: ARC cannot add standards-native issuance safely until the
external credential shape, issuer identity, and projection semantics are
explicit and bounded.

**Primary surfaces:**
- external ARC passport projection over current passport truth
- issuer identity, keying, and type-metadata strategy
- projection rules for provenance, enterprise identity, and runtime-assurance
  claims
- validation and docs for the dual-path ARC-native plus standards-native model

**Success Criteria**:
1. ARC defines one external portable credential profile without replacing the
   native `AgentPassport` lane.
2. The external identity strategy stays explicit about which semantics remain
   ARC-native only.
3. Unsupported or ambiguous projection requests fail closed.

**Plans**: 3 plans

Plans:
- [x] 61-01: Define the external ARC passport projection and identity
  strategy.
- [x] 61-02: Thread the external projection through ARC credential and
  issuance surfaces.
- [x] 61-03: Document and validate the dual-path identity boundary.

### Phase 62: SD-JWT VC Issuance and Selective Disclosure Profile

**Goal**: Add one standards-native SD-JWT VC issuance path with bounded,
policy-visible selective disclosure.
**Depends on**: Phase 61
**Requirements**: PVC-01, PVC-02, PVC-05
**Why second**: Once the external projection exists, ARC needs a real
standards-native issuance format before it can claim broader passport
portability.

**Primary surfaces:**
- SD-JWT VC issuance profile over OID4VCI
- holder binding and verifier-facing disclosure contract
- disclosure policy and claim-catalog constraints
- fail-closed validation for unsupported or over-broad requests

**Success Criteria**:
1. ARC can issue a standards-native external credential deterministically.
2. Selective disclosure is explicit, bounded, and regression-covered.
3. The SD-JWT VC path preserves ARC trust boundaries instead of widening them.

**Plans**: 3 plans

Plans:
- [x] 62-01: Implement SD-JWT VC issuance on top of the external projection.
- [x] 62-02: Define the selective-disclosure contract for ARC portable
  credentials.
- [x] 62-03: Add regression coverage for issuance and disclosure failure
  paths.

### Phase 63: Portable Status, Revocation, and Type Metadata

**Goal**: Project ARC lifecycle truth into verifier-facing portable status,
revocation, supersession, and metadata artifacts.
**Depends on**: Phase 62
**Requirements**: PVC-03, PVC-04
**Why third**: Portable issuance is incomplete until verifiers can validate
type, issuer, and lifecycle state through stable metadata and status surfaces.

**Primary surfaces:**
- issuer metadata and type metadata
- status, revocation, and supersession publication
- lifecycle projection and cache-boundary rules
- validation and docs for verifier-facing lifecycle semantics

**Success Criteria**:
1. Verifiers can discover and validate the ARC external portable profile.
2. Revocation and supersession project from ARC truth without a second mutable
   trust root.
3. Metadata and status failure cases remain explicit and fail closed.

**Plans**: 3 plans

Plans:
- [x] 63-01: Publish portable issuer and type metadata for the external
  profile.
- [x] 63-02: Map ARC lifecycle truth into portable status and revocation
  artifacts.
- [x] 63-03: Add validation and documentation for metadata and status
  handling.

### Phase 64: Portable Credential Qualification and Boundary Rewrite

**Goal**: Close `v2.13` with qualification evidence and clear boundary
language for the new standards-native credential lane.
**Depends on**: Phase 63
**Requirements**: PVC-02, PVC-03, PVC-04, PVC-05
**Why last**: ARC should not claim the portable credential gap is closed until
the new lane is externally legible, regression-covered, and clearly documented
alongside the existing native path.

**Primary surfaces:**
- raw-HTTP and verifier-facing qualification
- protocol, portability, and release doc updates
- milestone audit and closeout artifacts
- planning-state advancement into `v2.14`

**Success Criteria**:
1. Qualification proves the standards-native credential lane end to end.
2. Docs explain the new dual-path model without overstating unsupported
   ecosystems.
3. The milestone closes with explicit audit evidence and updated planning
   state.

**Plans**: 3 plans

Plans:
- [x] 64-01: Build qualification evidence for the standards-native credential
  lane.
- [x] 64-02: Rewrite the portability boundary docs around the dual-path model.
- [x] 64-03: Audit `v2.13`, close the milestone, and advance planning state.

## Milestones After v2.16

### v2.15 Multi-Cloud Attestation and Appraisal Contracts (Completed locally 2026-03-28)

**Milestone Goal:** Replace the current Azure-first verifier boundary with a
typed appraisal contract plus multiple concrete verifier adapters and
policy-visible normalization rules.

- Phase 69: Common Appraisal Contract and Adapter Interface
- Phase 70: AWS Nitro Verifier Adapter
- Phase 71: Google Attestation Adapter and Runtime-Assurance Policy v2
- Phase 72: Appraisal Export, Qualification, and Boundary Closure

### v2.16 Enterprise Authorization and IAM Standards Profiles

**Milestone Goal:** Publish a normative ARC profile for authorization details,
transaction context, sender-constrained semantics, and enterprise reviewer
evidence.

- Phase 73: ARC OAuth Authorization Profile
- Phase 74: Sender-Constrained and Discovery Contracts
- Phase 75: Enterprise IAM Adapters, Metadata, and Reviewer Packs
- Phase 76: Conformance, Qualification, and Standards-Facing Proof

### v2.17 ARC Certify Public Discovery Marketplace and Governance

**Milestone Goal:** Expand certification into a public discovery and
transparency layer with explicit governance, provenance, and dispute semantics.

- Phase 77: Certification Criteria and Conformance Evidence Profiles
- Phase 78: Public Operator Identity and Discovery Metadata
- Phase 79: Public Search, Resolution, and Transparency Network
- Phase 80: Governance, Dispute Semantics, and Marketplace Qualification

### v2.18 Credit, Exposure, and Capital Policy

**Milestone Goal:** Turn underwriting into a durable exposure, scorecard, and
capital-allocation substrate.

- Phase 81: Exposure Ledger and Economic Position Model
- Phase 82: Credit Scorecards, Probation, and Anomaly Signals
- Phase 83: Facility Terms and Capital Allocation Policy
- Phase 84: Credit Qualification, Backtests, and Provider Risk Package

### v2.19 Bonded Autonomy and Facility Execution (Completed locally 2026-03-29)

**Milestone Goal:** Enforce capital-backed autonomy with reserves, bonds,
slashing, loss, and recovery state.

- Phase 85: Bond Contracts, Reserve Locks, and Collateral State
- Phase 86: Delegation Bonds and Autonomy Tier Gates
- Phase 87: Loss Events, Recovery, and Delinquency Lifecycle
- Phase 88: Qualification, Operator Controls, and Sandbox Integrations

### v2.20 Liability Marketplace and Claims Network

**Milestone Goal:** Add provider-neutral quote, bind, claim, and dispute
workflows so ARC can orchestrate insured agent actions across organizational
boundaries.

- Phase 89 complete: Provider Registry, Coverage Classes, and Jurisdiction
  Policy
- Phase 90 complete: Quote Requests, Placement, and Bound Coverage Artifacts
- Phase 91 complete: Claim Packages, Disputes, and Liability Adjudication
- Phase 92 next: Marketplace Qualification, Partner Proof, and Boundary Update

## Archived Milestones

- `v2.1` roadmap: `.planning/milestones/v2.1-ROADMAP.md`
- `v2.1` requirements: `.planning/milestones/v2.1-REQUIREMENTS.md`
- `v2.1` audit: `.planning/milestones/v2.1-MILESTONE-AUDIT.md`
- `v2.2` roadmap: `.planning/milestones/v2.2-ROADMAP.md`
- `v2.2` requirements: `.planning/milestones/v2.2-REQUIREMENTS.md`
- `v2.2` audit: `.planning/milestones/v2.2-MILESTONE-AUDIT.md`
- `v2.3` roadmap: `.planning/milestones/v2.3-ROADMAP.md`
- `v2.3` requirements: `.planning/milestones/v2.3-REQUIREMENTS.md`
- `v2.3` audit: `.planning/milestones/v2.3-MILESTONE-AUDIT.md`
- `v2.4` roadmap: `.planning/milestones/v2.4-ROADMAP.md`
- `v2.4` requirements: `.planning/milestones/v2.4-REQUIREMENTS.md`
- `v2.4` audit: `.planning/milestones/v2.4-MILESTONE-AUDIT.md`
- `v2.5` roadmap: `.planning/milestones/v2.5-ROADMAP.md`
- `v2.5` requirements: `.planning/milestones/v2.5-REQUIREMENTS.md`
- `v2.5` audit: `.planning/milestones/v2.5-MILESTONE-AUDIT.md`
- `v2.6` roadmap: `.planning/milestones/v2.6-ROADMAP.md`
- `v2.6` requirements: `.planning/milestones/v2.6-REQUIREMENTS.md`
- `v2.6` audit: `.planning/milestones/v2.6-MILESTONE-AUDIT.md`
- `v2.10` audit: `.planning/milestones/v2.10-MILESTONE-AUDIT.md`
- `v2.9` audit: `.planning/milestones/v2.9-MILESTONE-AUDIT.md`
- `v2.8` audit: `.planning/milestones/v2.8-MILESTONE-AUDIT.md`

## Completed Milestone: v2.10 Underwriting and Risk Decisioning

**Milestone Goal:** Convert ARC from a truthful risk-evidence exporter into a
bounded runtime underwriting and risk-decisioning system.

**Why now:** `docs/research/DEEP_RESEARCH_1.md` explicitly moves from receipts
and reputation into runtime underwriting once standardized cost semantics,
authorization context, and runtime trust are in place. ARC now has those
substrates from `v2.7` through `v2.9`, but `spec/PROTOCOL.md` still states the
behavioral feed is evidence export rather than underwriting. `v2.10` is where
that product boundary changes on purpose.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on runtime underwriting, agent credit,
  and liability-market primitives
- `spec/PROTOCOL.md` on the current boundary that behavioral feeds are not
  underwriting models
- `docs/release/RELEASE_CANDIDATE.md` on the already-shipped evidence,
  runtime-assurance, and qualification substrate
- `docs/ECONOMIC_INTEROP_GUIDE.md` on the economic and authorization-context
  surfaces underwriting will consume

**Phase Numbering:**
- Integer phases 49-52: completed `v2.10` milestone work
- Integer phases 53-56: completed `v2.11` milestone work
- Integer phases 57-60: completed `v2.12` milestone work

- [x] **Phase 49: Underwriting Taxonomy and Policy Inputs** - Define the
  signed policy inputs, taxonomy, and evidence contracts for underwriting.
- [x] **Phase 50: Runtime Underwriting Decision Engine** - Produce bounded
  runtime decisions from receipts, reputation, certification, and assurance
  evidence.
- [x] **Phase 51: Signed Risk Decisions, Budget/Premium Outputs, and Appeals**
  - Separate underwriting decisions from receipts while making outputs and
  review semantics explicit.
- [x] **Phase 52: Underwriting Simulation, Qualification, and Partner Proof**
  - Add operator simulation, audit surfaces, docs, and qualification evidence
  for the underwriting story.

## Phase Details

### Phase 49: Underwriting Taxonomy and Policy Inputs

**Goal**: Define the signed underwriting policy-input contract and canonical
risk taxonomy over ARC's existing evidence surfaces.
**Depends on**: Phase 48
**Requirements**: UW-01
**Why first**: ARC cannot make underwriting decisions safely until the input
contract is explicit about which evidence counts, how risk classes are named,
and which policy constraints can influence a decision.

**Primary surfaces:**
- core underwriting taxonomy, risk reason, and policy-input types
- signed underwriting request or snapshot envelope over canonical evidence
- store and query interfaces for assembling underwriting evidence snapshots
- docs that separate underwriting policy truth from receipt truth

**Success Criteria**:
1. ARC defines one typed underwriting-input contract over receipts,
   reputation, certification, runtime assurance, and payment-side evidence.
2. Risk classes, evidence references, and decision reasons are explicit and
   bounded rather than inferred ad hoc by callers.
3. Validation fails closed when required evidence or policy fields are missing
   or inconsistent.

**Plans**: 3 plans

Plans:
- [x] 49-01: Define underwriting taxonomy, evidence references, and signed
  policy-input contracts.
- [x] 49-02: Thread underwriting input assembly and query surfaces through
  kernel, store, and operator APIs.
- [x] 49-03: Add docs and regression coverage for underwriting input
  validation and fail-closed semantics.

### Phase 50: Runtime Underwriting Decision Engine

**Goal**: Produce bounded runtime underwriting decisions from canonical ARC
evidence rather than partner-specific ad hoc logic.
**Depends on**: Phase 49
**Requirements**: UW-02
**Why second**: Once inputs are canonical, ARC needs a deterministic evaluator
that can emit explainable approve, deny, step-up, or reduce-ceiling outcomes.

**Primary surfaces:**
- underwriting evaluator and decision logic
- risk scoring or rule-aggregation over canonical evidence inputs
- operator and API surfaces for decision inspection
- fail-closed runtime behavior when evidence is stale, absent, or invalid

**Success Criteria**:
1. ARC can make bounded underwriting decisions from the phase-49 contract.
2. Every decision includes explicit reasons and evidence references.
3. Missing or invalid inputs degrade safely instead of silently granting more
   favorable outcomes.

**Plans**: 3 plans

Plans:
- [x] 50-01: Implement the deterministic underwriting evaluator over canonical
  evidence.
- [x] 50-02: Expose decision and explanation surfaces through CLI,
  trust-control, and query paths.
- [x] 50-03: Add regression coverage for approve, deny, step-up, and
  fail-closed decision paths.

### Phase 51: Signed Risk Decisions, Budget/Premium Outputs, and Appeals

**Goal**: Make underwriting outputs explicit signed artifacts with auditable
budget, premium, and appeal semantics that remain separate from receipt truth.
**Depends on**: Phase 50
**Requirements**: UW-03
**Why third**: Underwriting is not complete when a score exists in memory; ARC
needs durable signed decision artifacts that downstream operators and partners
can verify independently.

**Primary surfaces:**
- signed underwriting decision artifact types
- budget ceiling, premium, and step-up output schemas
- persistence and query/report surfaces for decisions and appeals
- review lifecycle rules that preserve canonical receipt immutability

**Success Criteria**:
1. Underwriting outputs are signed, queryable artifacts rather than transient
   runtime side effects.
2. Budget, premium, and appeal state is explicit and auditable.
3. Canonical execution receipts remain immutable even when underwriting
   decisions are revised or appealed.

**Plans**: 3 plans

Plans:
- [x] 51-01: Define signed underwriting decision artifacts and output schema.
- [x] 51-02: Implement persistence, query, and lifecycle handling for
  decisions, premiums, and appeals.
- [x] 51-03: Add docs and regression coverage for artifact verification and
  appeal semantics.

### Phase 52: Underwriting Simulation, Qualification, and Partner Proof

**Goal**: Close the milestone with simulation tooling, qualification evidence,
and partner-facing documentation for the underwriting surface.
**Depends on**: Phase 51
**Requirements**: UW-04, UW-05
**Why last**: ARC should not claim to ship underwriting until operators can
simulate and explain decisions and the release package proves the boundary
change clearly.

**Primary surfaces:**
- operator simulation and explanation tooling
- qualification lanes and release documentation
- partner-proof materials and boundary-language updates
- milestone audit and closeout artifacts

**Success Criteria**:
1. Operators can simulate, inspect, and explain underwriting decisions using
   supported tooling.
2. Qualification proves the underwriting story end-to-end.
3. Docs clearly state that ARC now ships underwriting decisioning in addition
   to truthful evidence export.

**Plans**: 3 plans

Plans:
- [x] 52-01: Add operator simulation and explanation tooling for underwriting.
- [x] 52-02: Extend qualification, release, and partner-proof artifacts for
  the underwriting story.
- [x] 52-03: Audit `v2.10`, close the milestone, and advance planning state.

## Completed Milestone: v2.9 Economic Evidence and Authorization Context Interop

**Milestone Goal:** Standardize truthful cost evidence and external
authorization context so ARC's governed approvals and receipts can participate
cleanly in IAM, billing, and partner ecosystems.

**Why now:** `docs/research/DEEP_RESEARCH_1.md` makes standardized cost
semantics and transaction context prerequisites for credible runtime
underwriting. ARC already separates quote, authorization, and post-execution
finalization, but those semantics are still strongest in payment-rail-specific
flows rather than a general interop layer.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on the two-source cost model, OAuth-family
  authorization details, transaction tokens, and underwriting prerequisites
- `docs/TOOL_PRICING_GUIDE.md` on quoted price versus enforcement truth
- `crates/arc-kernel/src/payment.rs` on pre-execution authorization and
  post-execution cost finalization
- `docs/A2A_ADAPTER_GUIDE.md` on ARC's current external auth and mutual-TLS
  interoperability surface

- [x] **Phase 45: Generic Metered Billing Evidence Contract** - Define a
  payment-rail-neutral quote, cap, and post-execution evidence contract that
  can describe truthful tool economics beyond x402 and ACP/shared-payment-token
  flows.
- [x] **Phase 46: Cost Evidence Adapters and Truthful Reconciliation** -
  Implement pluggable billing-evidence adapters plus reconciliation rules that
  preserve canonical execution receipt truth.
- [x] **Phase 47: Authorization Details and Call-Chain Context Mapping** -
  Map governed intents and approvals into external authorization context
  structures without silently widening identity, trust, or billing scope.
- [x] **Phase 48: Economic Interop Qualification and Operator Tooling** -
  Close the milestone with operator-visible reports, docs, examples, and
  qualification artifacts aimed at IAM, finance, and partner reviewers.

## Phase Details

### Phase 45: Generic Metered Billing Evidence Contract

**Goal**: Define a payment-rail-neutral quote, cap, and post-execution
evidence contract that can describe truthful tool economics beyond x402 and
ACP/shared-payment-token flows.
**Depends on**: Phase 44
**Requirements**: EEI-01
**Why first**: The rest of the interop stack needs one canonical vocabulary
for quoted cost, approved cap, measured usage, and settlement evidence before
ARC can bridge external billing systems safely.

**Primary surfaces:**
- core metered-billing evidence types and schema contracts
- governed intent and receipt fields for non-rail cost evidence
- kernel and store abstractions for quote-versus-actual cost truth
- docs that distinguish execution truth from economic truth

**Success Criteria**:
1. ARC can describe quoted cost, approved cap, observed usage, and reconciled
   cost for non-payment-rail tools without overloading existing payment-only
   structures.
2. Receipt truth stays canonical for what executed, while economic evidence
   stays canonical for what was priced and settled.
3. The contract is documented well enough to guide subsequent adapter work.

**Plans**: 3 plans

Plans:
- [x] 45-01: Define the generic metered-billing evidence model and schema
  contract.
- [x] 45-02: Thread the new evidence primitives through governed intent,
  receipts, and store interfaces.
- [x] 45-03: Document the quote-cap-actual semantics and add regression tests
  for truthful separation.

### Phase 46: Cost Evidence Adapters and Truthful Reconciliation

**Goal**: Implement pluggable billing-evidence adapters plus reconciliation
rules that preserve canonical execution receipt truth.
**Depends on**: Phase 45
**Requirements**: EEI-02
**Why second**: Once the evidence contract exists, ARC needs concrete adapter
hooks so external metering systems can produce post-execution truth without
rewriting what the kernel observed.

**Primary surfaces:**
- adapter interfaces for external metered-cost evidence
- reconciliation records and operator actions
- report/query visibility for quote-versus-actual comparisons
- regression coverage for adapter failure and replay paths

**Success Criteria**:
1. At least one non-rail adapter path can attach post-execution cost evidence
   to ARC receipts without mutating receipt truth.
2. Reconciliation semantics stay explicit and auditable for operators.
3. Failure, replay, and missing-evidence cases are documented and fail closed.

**Plans**: 3 plans

Plans:
- [x] 46-01: Add adapter contracts and persistence for external cost evidence.
- [x] 46-02: Implement truthful reconciliation flows and operator-visible
  reporting/query surfaces.
- [x] 46-03: Add docs and regression coverage for adapter ingestion, replay,
  and reconciliation failure modes.

### Phase 47: Authorization Details and Call-Chain Context Mapping

**Goal**: Map governed intents and approvals into external authorization
context structures without silently widening identity, trust, or billing
scope.
**Depends on**: Phase 46
**Requirements**: EEI-03, EEI-04
**Why third**: Only after cost truth is explicit can ARC safely export its
governed authorization semantics to external IAM systems and delegated
call-chain consumers.

**Primary surfaces:**
- authorization-details or transaction-context mapping contracts
- governed approval export/import surfaces
- delegated call-chain context representation in approval and receipt artifacts
- policy validation that rejects silent widening of authority

**Success Criteria**:
1. ARC can express governed approvals in a standards-legible external context
   form.
2. Delegated call-chain and cost context remain explicit and provenance-backed.
3. Validation prevents mappings that silently widen authority or billing scope.

**Plans**: 3 plans

Plans:
- [x] 47-01: Define external authorization-context and call-chain mapping
  contracts.
- [x] 47-02: Implement CLI, trust-control, and receipt/report surfaces for the
  mapped context.
- [x] 47-03: Add fail-closed validation, tests, and docs for identity, trust,
  and billing-boundary preservation.

### Phase 48: Economic Interop Qualification and Operator Tooling

**Goal**: Close the milestone with operator-visible reports, docs, examples,
and qualification artifacts aimed at IAM, finance, and partner reviewers.
**Depends on**: Phase 47
**Requirements**: EEI-05
**Why last**: This milestone only counts as complete if the new economic and
authorization context is understandable and defensible outside ARC's own code
and docs.

**Primary surfaces:**
- operator reporting and trust-control tooling for economic context
- qualification lane additions and partner-facing examples
- release/research docs that tie the interop story back to ARC's boundaries
- milestone closeout evidence

**Success Criteria**:
1. Operators can inspect and explain economic evidence and authorization
   context through supported tooling.
2. Qualification demonstrates the new interop story end-to-end.
3. Docs tie the shipped surface back to the research thesis without
   overclaiming.

**Plans**: 3 plans

Plans:
- [x] 48-01: Add operator tooling and reporting for economic evidence and
  authorization context.
- [x] 48-02: Extend qualification and partner-proof artifacts for interop
  review.
- [x] 48-03: Audit the milestone and publish closeout evidence.

## Completed Milestone: v2.11 Portable Credential Interop and Wallet Distribution

**Goal:** Expand ARC's portable trust into external VC, wallet, and verifier
ecosystems without inventing synthetic global trust.

**Why now:** `docs/research/DEEP_RESEARCH_1.md` calls for stronger VC,
OID4VCI, and wallet-mediated portability once ARC already has conservative
portable trust, underwriting semantics, and explicit economic boundaries.
`v2.11` is where ARC stops being only ARC-native in credential delivery and
starts proving external wallet and verifier interop on purpose.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on OID4VCI, passport portability, and
  wallet-mediated trust exchange
- `crates/arc-credentials/src/lib.rs` on the current intentionally simple
  ARC-native credential format
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` on current conservative
  portability boundaries

- [x] **Phase 53: OID4VCI-Compatible Issuance and Delivery** - Add at least
  one interoperable issuance and delivery path for external VC ecosystems.
- [x] **Phase 54: Credential Status, Revocation, and Distribution Contracts**
  - Make status and revocation portable to wallet and verifier tooling.
- [x] **Phase 55: Wallet / Holder Presentation Transport Semantics** - Define
  holder-facing transport and presentation behavior beyond file exchange.
- [x] **Phase 56: External Verifier Interop and Compatibility Qualification**
  - Prove at least one external wallet or verifier path end-to-end.

### Phase 53: OID4VCI-Compatible Issuance and Delivery

**Goal**: Add at least one interoperable credential issuance and delivery path
for ARC passports or equivalent portable credentials beyond ARC-native file
exchange.
**Depends on**: Phase 52
**Requirements**: VC-01, VC-05
**Why first**: Wallet and verifier interop cannot be evaluated until ARC can
issue credentials in a form and flow that external holders can actually
receive.

**Primary surfaces:**
- portable credential envelope and issuance-profile mapping for ARC passports
- OID4VCI-compatible offer or delivery semantics through CLI and trust-control
- operator configuration for issuance metadata, subject binding, and audience
- docs that state which external issuance expectations ARC does and does not
  satisfy

**Success Criteria**:
1. ARC supports at least one interoperable issuance and delivery flow beyond
   ARC-native direct file or API retrieval.
2. Issued credentials preserve issuer provenance, subject binding, and ARC's
   conservative trust boundaries.
3. Validation fails closed when issuance metadata, profile selection, or
   subject binding inputs are missing or inconsistent.

**Plans**: 3 plans

Plans:
- [x] 53-01: Define the interoperable credential issuance profile and ARC
  passport mapping contract.
- [x] 53-02: Implement issuance offer and delivery surfaces across CLI and
  trust-control.
- [x] 53-03: Add docs and regression coverage for issuance validation,
  delivery semantics, and fail-closed behavior.

### Phase 54: Credential Status, Revocation, and Distribution Contracts

**Goal**: Make credential status, revocation, supersession, and distribution
semantics portable to wallet and verifier ecosystems without weakening ARC's
current lifecycle guarantees.
**Depends on**: Phase 53
**Requirements**: VC-02, VC-05
**Why second**: External issuance is not trustworthy unless wallets and
verifiers can also observe truthful lifecycle state after issuance.

**Primary surfaces:**
- portable status and revocation contract for issued ARC credentials
- operator publication and query surfaces for lifecycle metadata
- supersession and holder distribution behavior aligned to external consumers
- docs that clarify how portable lifecycle state relates to ARC-native
  passport truth

**Success Criteria**:
1. ARC publishes portable status and revocation semantics that external
   wallets or verifiers can consume.
2. Supersession and revocation remain explicit and auditable without mutating
   canonical receipt or identity truth.
3. Missing, stale, or contradictory lifecycle state fails closed instead of
   silently reporting a healthier status.

**Plans**: 3 plans

Plans:
- [x] 54-01: Define portable status, revocation, and supersession artifacts or
  documents.
- [x] 54-02: Implement status publication, query, and lifecycle wiring across
  credential and trust-control surfaces.
- [x] 54-03: Add docs and regression coverage for distribution-safe lifecycle
  behavior and fail-closed status handling.

### Phase 55: Wallet / Holder Presentation Transport Semantics

**Goal**: Define holder-facing credential transport and presentation semantics
so wallets and remote relying parties can use ARC credentials beyond direct
file exchange.
**Depends on**: Phase 54
**Requirements**: VC-03, VC-05
**Why third**: Once issuance and lifecycle are portable, ARC still needs a
bounded holder presentation story before external verifier proof is credible.

**Primary surfaces:**
- wallet or holder transport contracts for importing and presenting ARC
  credentials
- holder-binding, audience, and replay-sensitive presentation metadata
- CLI and trust-control presentation request or response surfaces
- docs that explain which presentation semantics ARC supports and how they
  preserve trust boundaries

**Success Criteria**:
1. Holders can retrieve, transport, or present ARC portable credentials using
   a supported transport semantics beyond raw file delivery.
2. Presentation behavior preserves explicit audience, holder, and trust
   boundaries rather than silently widening authority.
3. Regression coverage proves success and fail-closed behavior for missing
   holder proof, unsupported transport, or stale presentation context.

**Plans**: 3 plans

Plans:
- [x] 55-01: Define holder-facing transport and presentation contracts.
- [x] 55-02: Implement presentation request and response surfaces across CLI,
  trust-control, and credential tooling.
- [x] 55-03: Add docs and regression coverage for holder transport,
  presentation, and replay-safe fail-closed behavior.

### Phase 56: External Verifier Interop and Compatibility Qualification

**Goal**: Prove at least one external wallet or verifier path end-to-end and
close the milestone with qualification and partner-facing interop proof.
**Depends on**: Phase 55
**Requirements**: VC-04, VC-05
**Why last**: `v2.11` only counts as real product progress if ARC can show one
concrete external compatibility path rather than only claiming standards
alignment on paper.

**Primary surfaces:**
- external verifier or wallet compatibility adapters, examples, or fixtures
- qualification lanes and release-proof documentation for credential interop
- partner-facing explanation of supported and intentionally unsupported
  portability behaviors
- milestone audit and closeout artifacts

**Success Criteria**:
1. ARC proves at least one external wallet or verifier interop path end to
   end.
2. Qualification and docs explain the interoperability boundary clearly
   without overclaiming global trust or unsupported flows.
3. The milestone closes with explicit audit evidence and updated planning
   state.

**Plans**: 3 plans

Plans:
- [x] 56-01: Implement at least one external wallet or verifier compatibility
  path plus regression fixtures.
- [x] 56-02: Extend qualification, release, and partner-proof materials for
  portable credential interop.
- [x] 56-03: Audit `v2.11`, close the milestone, and advance planning state.

## Completed Milestone: v2.12 Workload Identity and Attestation Verification Bridges

**Goal:** Bind ARC's runtime-assurance model to concrete workload-identity and
attestation verifier systems rather than only normalized upstream evidence.

**Why after v2.11:** This sequencing keeps ARC's outward credential and trust
interop surface clear before adding the deeper runtime-identity bridges that
feed stronger assurance into policy.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on SPIFFE/SVID, workload identity, and
  attestation-backed runtime trust
- `crates/arc-core/src/lib.rs` on current opaque handling of SPIFFE-like agent
  identifiers
- `crates/arc-core/src/capability.rs` on normalized runtime-attestation
  evidence
- `docs/A2A_ADAPTER_GUIDE.md` on current mutual-TLS support at the edge

- [x] **Phase 57: SPIFFE/SVID Workload Identity Mapping** - Map workload
  identities into ARC identity and policy surfaces explicitly.
- [x] **Phase 58: Cloud Attestation Verifier Adapters** - Add concrete cloud or
  vendor attestation verifier bridges.
- [x] **Phase 59: Attestation Trust Policy and Runtime-Assurance Rebinding** -
  Make verifier trust policy explicit and bind verified evidence back into ARC
  economic and approval decisions.
- [x] **Phase 60: Workload Identity Qualification and Operator Runbooks** -
  Close the milestone with qualification, replay/failure documentation, and
  operator guidance.

### Phase 57: SPIFFE/SVID Workload Identity Mapping

**Goal**: Map workload identities into ARC identity and policy surfaces
explicitly instead of leaving them as opaque upstream metadata.
**Depends on**: Phase 56
**Requirements**: ATTEST-01, ATTEST-04
**Why first**: ARC needs one explicit identity-binding contract before it can
trust or reason about concrete attestation verifier outputs.

**Primary surfaces:**
- typed workload-identity mapping contracts
- runtime and policy-visible identity context binding
- fail-closed validation for malformed or mismatched workload identities
- docs that explain what workload identity ARC actually interprets

**Success Criteria**:
1. ARC can map SPIFFE/SVID-style workload identity into explicit ARC identity
   context.
2. Malformed or mismatched workload identities fail closed.
3. Policy surfaces can consume mapped workload identity without silently
   widening rights.

**Plans**: 3 plans

Plans:
- [x] 57-01: Define the workload-identity mapping contract.
- [x] 57-02: Implement identity parsing and binding across runtime and policy
  surfaces.
- [x] 57-03: Add docs and regression coverage for workload-identity mapping.

### Phase 58: Cloud Attestation Verifier Adapters

**Goal**: Add at least one concrete cloud or vendor attestation verifier
bridge instead of relying only on opaque normalized evidence input.
**Depends on**: Phase 57
**Requirements**: ATTEST-02, ATTEST-03
**Why second**: After workload identity is explicit, ARC can ingest and
normalize one real verifier path with provenance intact.

**Primary surfaces:**
- concrete attestation verifier adapter contract
- normalized verifier output into ARC runtime-attestation evidence
- verifier provenance and validity semantics
- docs that explain the supported adapter boundary

**Success Criteria**:
1. ARC supports at least one concrete verifier bridge with explicit
   provenance.
2. Unsupported or malformed verifier outputs fail closed.
3. Normalized verifier output preserves enough evidence to support later trust
   policy decisions.

**Plans**: 3 plans

Plans:
- [x] 58-01: Define the first concrete attestation verifier bridge contract.
- [x] 58-02: Implement the verifier adapter and normalized evidence
  ingestion.
- [x] 58-03: Add docs and regression coverage for the verifier adapter.

### Phase 59: Attestation Trust Policy and Runtime-Assurance Rebinding

**Goal**: Make attestation trust policy explicit and rebind verified evidence
back into ARC runtime-assurance and policy decisions.
**Depends on**: Phase 58
**Requirements**: ATTEST-03, ATTEST-04
**Why third**: Real verifier inputs only matter once ARC can say which
verifiers it trusts and how that evidence changes runtime-assurance posture.

**Primary surfaces:**
- operator-configurable attestation trust policy
- verified-evidence to runtime-assurance rebinding logic
- fail-closed replay, staleness, and untrusted-verifier handling
- docs that explain how verified evidence can affect rights

**Success Criteria**:
1. Verifier trust is explicit and operator-configurable.
2. Verified evidence can change runtime-assurance posture only through
   explicit policy.
3. Replay, stale evidence, and untrusted verifiers fail closed.

**Plans**: 3 plans

Plans:
- [x] 59-01: Define attestation trust policy and verifier allow/deny
  semantics.
- [x] 59-02: Implement runtime-assurance rebinding from verified evidence.
- [x] 59-03: Add docs and regression coverage for trust policy and assurance
  rebinding.

### Phase 60: Workload Identity Qualification and Operator Runbooks

**Goal**: Close the milestone with qualification evidence, replay/failure
documentation, and operator guidance for workload identity and attestation
verifier bridges.
**Depends on**: Phase 59
**Requirements**: ATTEST-05
**Why last**: `v2.12` only counts if the shipped bridge is reproducible and
operationally legible rather than just technically present in code.

**Primary surfaces:**
- targeted qualification commands and regression lanes
- release, partner, and operator-facing runbooks
- replay and failure-mode documentation
- milestone audit and closeout artifacts

**Success Criteria**:
1. Qualification proves the workload identity and verifier bridge surfaces
   end-to-end.
2. Operators have clear runbooks for verifier failures, replay, and recovery.
3. The milestone closes with explicit audit evidence and updated planning
   state.

**Plans**: 3 plans

Plans:
- [x] 60-01: Build qualification evidence for workload identity and verifier
  bridges.
- [x] 60-02: Publish operator and partner-facing runbooks for the new trust
  boundary.
- [x] 60-03: Audit `v2.12`, close the milestone, and advance planning state.

## Progress

`v1.0` through `v2.16` are complete locally. `v2.17` is now active, phases
`77` through `80` are executable next work, and phases `81` through `92`
remain planned as the rest of the research-completion ladder.

| Phase | Milestone | Title | Status |
|------:|-----------|-------|--------|
| 45 | v2.9 | Generic Metered Billing Evidence Contract | Complete |
| 46 | v2.9 | Cost Evidence Adapters and Truthful Reconciliation | Complete |
| 47 | v2.9 | Authorization Details and Call-Chain Context Mapping | Complete |
| 48 | v2.9 | Economic Interop Qualification and Operator Tooling | Complete |
| 49 | v2.10 | Underwriting Taxonomy and Policy Inputs | Complete |
| 50 | v2.10 | Runtime Underwriting Decision Engine | Complete |
| 51 | v2.10 | Signed Risk Decisions, Budget/Premium Outputs, and Appeals | Complete |
| 52 | v2.10 | Underwriting Simulation, Qualification, and Partner Proof | Complete |
| 53 | v2.11 | OID4VCI-Compatible Issuance and Delivery | Complete |
| 54 | v2.11 | Credential Status, Revocation, and Distribution Contracts | Complete |
| 55 | v2.11 | Wallet / Holder Presentation Transport Semantics | Complete |
| 56 | v2.11 | External Verifier Interop and Compatibility Qualification | Complete |
| 57 | v2.12 | SPIFFE/SVID Workload Identity Mapping | Complete |
| 58 | v2.12 | Cloud Attestation Verifier Adapters | Complete |
| 59 | v2.12 | Attestation Trust Policy and Runtime-Assurance Rebinding | Complete |
| 60 | v2.12 | Workload Identity Qualification and Operator Runbooks | Complete |
| 61 | v2.13 | External Credential Projection and Identity Strategy | Complete |
| 62 | v2.13 | SD-JWT VC Issuance and Selective Disclosure Profile | Complete |
| 63 | v2.13 | Portable Status, Revocation, and Type Metadata | Complete |
| 64 | v2.13 | Portable Credential Qualification and Boundary Rewrite | Complete |
| 65 | v2.14 | OID4VP Verifier Profile and Request Transport | Complete |
| 66 | v2.14 | Wallet / Holder Distribution Adapters | Complete |
| 67 | v2.14 | Public Verifier Trust and Discovery Model | Complete |
| 68 | v2.14 | Ecosystem Qualification and Research Closure | Complete |
| 69 | v2.15 | Common Appraisal Contract and Adapter Interface | Complete |
| 70 | v2.15 | AWS Nitro Verifier Adapter | Complete |
| 71 | v2.15 | Google Attestation Adapter and Runtime-Assurance Policy v2 | Complete |
| 72 | v2.15 | Appraisal Export, Qualification, and Boundary Closure | Complete |
| 73 | v2.16 | ARC OAuth Authorization Profile | Complete |
| 74 | v2.16 | Sender-Constrained and Discovery Contracts | Complete |
| 75 | v2.16 | Enterprise IAM Adapters, Metadata, and Reviewer Packs | Complete |
| 76 | v2.16 | Conformance, Qualification, and Standards-Facing Proof | Complete |
| 77 | v2.17 | Certification Criteria and Conformance Evidence Profiles | Complete |
| 78 | v2.17 | Public Operator Identity and Discovery Metadata | Complete |
| 79 | v2.17 | Public Search, Resolution, and Transparency Network | Complete |
| 80 | v2.17 | Governance, Dispute Semantics, and Marketplace Qualification | Complete |
| 81 | v2.18 | Exposure Ledger and Economic Position Model | Complete |
| 82 | v2.18 | Credit Scorecards, Probation, and Anomaly Signals | Complete |
| 83 | v2.18 | Facility Terms and Capital Allocation Policy | Complete |
| 84 | v2.18 | Credit Qualification, Backtests, and Provider Risk Package | Complete |
| 85 | v2.19 | Bond Contracts, Reserve Locks, and Collateral State | Complete |
| 86 | v2.19 | Delegation Bonds and Autonomy Tier Gates | Complete |
| 87 | v2.19 | Loss Events, Recovery, and Delinquency Lifecycle | Complete |
| 88 | v2.19 | Qualification, Operator Controls, and Sandbox Integrations | Complete |
| 89 | v2.20 | Provider Registry, Coverage Classes, and Jurisdiction Policy | Complete |
| 90 | v2.20 | Quote Requests, Placement, and Bound Coverage Artifacts | Complete |
| 91 | v2.20 | Claim Packages, Disputes, and Liability Adjudication | Complete |
| 92 | v2.20 | Marketplace Qualification, Partner Proof, and Boundary Update | Complete |

# Post-v2.20 Open Trust Market and Governance Endgame

**Project:** ARC  
**Scope:** Move from the shipped curated/operator-bounded public marketplace
surface to a more open trust-and-market network without collapsing listing
visibility into runtime trust.  
**Researched:** 2026-03-29  
**Confidence:** MEDIUM-HIGH

## Executive Position

Post-`v2.20`, ARC has already proved the hard bounded substrates:

- signed receipts, budgets, governed transaction truth, and portable trust
- one governed public certification discovery surface
- one curated liability-provider registry plus quote, bind, claim, dispute,
  and adjudication orchestration
- one credit, exposure, capital-policy, and bonded-autonomy substrate

The remaining gap is not "more marketplace." The remaining gap is that ARC
still ships a **curated discovery and admission model** where:

- publication is operator-bounded,
- listing visibility is public but trust admission remains local and manual,
- dispute handling is operator-scoped,
- reputation is portable only in bounded issuer-controlled forms,
- provider admission is curated,
- and the docs explicitly reject permissionless or auto-trusting market
  semantics.

The endgame implied by the research is narrower and more defensible than a
"global trust oracle." ARC should aim for an **open registry and governance
network** where:

- anyone can publish into bounded open lanes under explicit eligibility rules,
- multi-operator mirrors and indexers can carry listings and evidence,
- local consumers still decide trust activation through explicit policy,
- portable reputation and governance evidence travel across operators,
- disputes can escalate beyond the origin operator,
- fees, bonds, and slashing deter abuse,
- and all of the above remain auditable, signed, and fail closed.

That should be the claim boundary. ARC should not target "permissionless trust"
or "universal agent scoring." It should target **open publication,
portable evidence, policy-bound trust activation, and governed market
discipline**.

## Current Shipped Boundary

Derived from `RELEASE_CANDIDATE.md`, `PARTNER_PROOF.md`, `PROTOCOL.md`, and
`ARC_PORTABLE_TRUST_PROFILE.md`, ARC currently ships:

- one governed public certification marketplace with signed certification
  artifacts, operator-scoped registry state, public metadata/search/resolve/
  transparency surfaces, explicit dispute state, and policy-bound consume
  flows
- one portable trust layer over `did:arc`, passport/verifier-policy artifacts,
  OID4VCI-compatible issuance, narrow verifier-side OID4VP, lifecycle
  distribution, and federated evidence export/import
- one curated liability-provider registry with fail-closed jurisdiction,
  coverage-class, currency, and evidence-requirement resolution
- one provider-neutral liability quote, placement, bound-coverage, claim,
  dispute, and adjudication lane over signed ARC evidence
- one exposure, scorecard, facility-policy, provider-risk-package, and
  bonded-execution substrate

The shipped boundary is explicitly constrained:

- public discovery does not widen runtime trust from visibility alone
- certification discovery preserves operator provenance and rejects stale,
  mismatched, revoked, superseded, or disputed listings
- ARC does not claim a public certification marketplace in the protocol-level
  compatibility contract
- ARC does not claim a permissionless or auto-trusting certification
  marketplace
- ARC portable trust does not claim a global trust registry or synthetic
  cross-issuer trust scoring
- ARC liability market does not claim a permissionless provider market,
  claims-payment rail, or autonomous insurer pricing

## Remaining Gap

ARC can now prove bounded marketplace and risk workflows, but it still lacks
the network semantics needed for a genuinely open trust market.

### Gap Matrix

| Area | Shipped in `v2.20` | Remaining gap to endgame |
| --- | --- | --- |
| Public discovery | Public read/search/resolve/transparency per operator and authenticated multi-operator publication | Open publication lanes, mirror/indexer roles, deterministic freshness, query/ranking semantics, and scale-safe registry replication |
| Permissioning | Operator-admin publication and curated provider admission | Explicit publisher/attestor/curator/indexer/arbiter roles plus bounded open admission classes |
| Listing vs trust | Strong separation in current consume flow | A formal trust-activation artifact and policy ladder so consumers can automate bounded imports without auto-trust |
| Governance | Operator-scoped disputes with narrow dispute states | Multi-step escalation, federated review, sanctions, freezes, appeals, reinstatement, and governance charters |
| Economics | Marketplace proof exists, but no open-market fee or anti-spam layer | Listing fees, search/index fees, dispute bonds, publisher bonds, slashing, and incentive alignment |
| Registry semantics | Certification registry and discovery network are bounded and operator-defined | Generic open listing schema family, namespaces, content addressing, supersession/tombstones, mirror proofs, and raw vs ranked query modes |
| Reputation portability | Passports and certification exist; no synthetic cross-issuer trust score | Portable reputation statements, weighting metadata, negative-event portability, and consumer-local aggregation |
| Abuse controls | Fail-closed verification and curated admission reduce risk | Sybil resistance, spam control, fraud rings, ranking manipulation, dispute griefing, stale-mirror defense, and emergency quarantine |

## Endgame Definition

ARC should treat the research idea as achieved only when all of the following
are true:

1. A publisher can self-publish a tool, provider, issuer, or verifier listing
   into an open ARC registry lane using signed artifacts and explicit metadata.
2. Mirrors and indexers can replicate and expose those listings without
   becoming implicit trust authorities.
3. A consumer can convert a listing into local trust only through an explicit
   policy-bound activation step with a recorded reason and evidence set.
4. Portable reputation, certification, runtime-assurance evidence, dispute
   history, and sanctions can travel with operator provenance intact.
5. Disputes can escalate beyond the origin operator through published
   governance rules and signed case artifacts.
6. Fees, bonds, and slashing make spam, griefing, and low-cost fraud
   expensive.
7. ARC can qualify the whole flow under adversarial multi-operator conditions
   without claiming a universal trust oracle or automatic cross-issuer score.

## Design Invariants

- Listing visibility is never equivalent to runtime admission.
- Search rank is an opinionated view, not a source-of-truth trust verdict.
- Governance overlays must not mutate immutable signed evidence.
- Cross-operator reputation must travel as attributed statements, not as one
  synthetic universal score.
- Open publication must be bounded by economics, rate limits, and identity or
  bond requirements.
- Mirror and index operators can improve availability and discovery, but local
  policy still decides what is admissible.
- Every sanction, de-rank, freeze, slash, and trust activation decision must
  be evidence-linked and replayable.
- ARC should prefer operator-published charters and local opt-in federation
  over a single global governing authority.

## Proposed Artifact Layers

To keep the boundary clean, ARC should separate the data model into five
layers:

| Layer | Purpose | Proposed artifact family |
| --- | --- | --- |
| Core evidence | Immutable execution, settlement, certification, coverage, and passport truth | existing ARC receipts, certification, liability, passport, and appraisal artifacts |
| Discovery | Public registry entries, metadata, and searchability | `arc.market.listing.v1`, `arc.market.publisher-profile.v1`, `arc.market.index-snapshot.v1` |
| Governance overlay | Disputes, sanctions, freezes, appeals, and charters | `arc.market.dispute-case.v1`, `arc.market.sanction.v1`, `arc.market.governance-charter.v1` |
| Economic overlay | Fees, bonds, slashes, reward payouts | `arc.market.fee-schedule.v1`, `arc.market.bond-account.v1`, `arc.market.slash-event.v1` |
| Local trust activation | Consumer-local decision to admit, limit, or reject a listing | `arc.market.consume-decision.v1`, `arc.market.weighting-profile.v1` |

That structure preserves the most important shipped invariant: mutable market
state must not overwrite canonical evidence truth.

## Recommended Milestone Sequence After `v2.20`

1. **`v2.21` Open Registry and Discovery Semantics**
   - Generalize the bounded certification discovery model into a generic open
     listing substrate with mirrors, indexers, freshness, and search semantics.
2. **`v2.22` Trust Activation and Permissioned Openness**
   - Introduce open admission classes and a formal local trust-activation
     contract so discovery can scale without becoming ambient trust.
3. **`v2.23` Governance and Dispute Escalation Network**
   - Add federated case handling, appeals, sanctions, and emergency freeze
     semantics.
4. **`v2.24` Portable Reputation and Trust Evidence Exchange**
   - Make reputation, adverse events, and weighting inputs portable while
     preserving issuer provenance and local aggregation.
5. **`v2.25` Marketplace Economics and Abuse Resistance**
   - Add fee schedules, bonds, slashing, reward flows, and abuse throttles for
     open-market durability.
6. **`v2.26` Open Trust Market Qualification**
   - Qualify the combined surface under honest and adversarial multi-operator
     scenarios and bound the launch claim.

## Milestone Plan

### `v2.21` Open Registry and Discovery Semantics

**Goal:** Replace the current special-case public discovery surface with a
generic open registry substrate that can represent tools, providers, issuers,
verifiers, and future ARC market actors without changing the rule that search
is not trust.

**Depends on:** `v2.17` through `v2.20`

#### Phase 81: Generic Listing Artifact and Namespace Model

**Depends on:** `v2.20`

**Scope**

- Define `arc.market.listing.v1` with:
  `listing_id`, `subject_kind`, `subject_ref`, `publisher`, `origin_operator`,
  `evidence_refs`, `declared_capabilities`, `jurisdiction`, `pricing_model`,
  `lifecycle`, `published_at`, `supersedes`, and `valid_until`.
- Support at least these `subject_kind` values:
  `tool_server`, `issuer`, `verifier`, `provider`, `policy_pack`, and
  `market_operator`.
- Make listing identifiers content-addressable or digest-linked so mirrors and
  indexers can verify what they carry.
- Keep listing truth separate from certification, passport, liability, and
  runtime-assurance artifacts by reference, not by duplication.

#### Phase 82: Origin, Mirror, and Indexer Semantics

**Depends on:** Phase 81

**Scope**

- Separate three roles:
  origin operator, mirror, and search indexer.
- Require origin-signed publication records and mirror freshness metadata.
- Add `arc.market.index-snapshot.v1` so a search operator can prove what raw
  corpus and freshness horizon a ranked result set came from.
- Make raw resolve and ranked search independent APIs so consumers can choose
  deterministic raw retrieval instead of ranking.

#### Phase 83: Search, Ranking, and Freshness Contract

**Depends on:** Phase 82

**Scope**

- Define minimum query fields: subject kind, issuer, jurisdiction, coverage
  class, evidence profile, runtime-assurance hints, dispute status, sanction
  status, freshness window, and pricing mode.
- Require search responses to return:
  origin operator, listing state, dispute state, sanction state, freshness,
  evidence refs, and ranking reason codes.
- Support two result modes:
  `canonical` and `ranked`.
- Fail closed on stale, mismatched, malformed, or unverifiable snapshot
  metadata.

#### Phase 84: Shadow-Mode Open Publish Lane

**Depends on:** Phase 83

**Scope**

- Add an open publish API lane in shadow mode that records listings and
  transparency data without making them eligible for default trust activation.
- Record publication telemetry for spam, duplicate listings, malformed
  evidence refs, and dispute initiation rate.
- Keep default consumer policies on observe-only for all shadow-mode open
  publishers.

#### Acceptance Criteria

- **OREG-01:** ARC ships one generic listing artifact that can represent all
  current marketplace actors without special-casing certification only.
- **OREG-02:** Search results are reproducible against a published index
  snapshot and return ranking reason codes plus freshness metadata.
- **OREG-03:** Mirrors and indexers never become implicit trust roots; every
  result remains attributable to an origin operator and signed evidence set.
- **OREG-04:** Open publish shadow mode is observable without widening runtime
  admission.

#### Validation / Qualification

- Fixture corpus covering tool, provider, issuer, and verifier listings.
- Replay tests proving the same raw corpus and ranking policy yield the same
  ranked result set.
- Negative tests for stale mirror data, digest mismatch, duplicate supersession
  chains, and malformed evidence refs.
- Operator telemetry report from shadow-mode publication with spam and error
  rates.

### `v2.22` Trust Activation and Permissioned Openness

**Goal:** Turn open discovery into bounded, automatable local policy by
formalizing who may publish and how a consumer converts discovery into usable
trust.

**Depends on:** `v2.21`

#### Phase 85: Publisher and Operator Role Model

**Depends on:** Phase 84

**Scope**

- Define publisher classes:
  `self_asserted`, `verified`, `bonded`, `certified_operator`,
  `federation_member`.
- Define role permissions for:
  publisher, attestor, certifier, curator, mirror, indexer, consumer,
  dispute reporter, arbiter.
- Bind role grants to existing ARC capability and portable identity semantics
  instead of inventing a second auth system.

#### Phase 86: Trust Tier and Admission Ladder

**Depends on:** Phase 85

**Scope**

- Define trust tiers separate from listing classes:
  `observe_only`, `manual_review`, `limited_runtime`, `policy_admitted`,
  `locally_preferred`.
- Require every local import path to map listing class plus evidence into one
  trust tier explicitly.
- Allow local policy to require any combination of certification, runtime
  assurance, publisher verification, bond coverage, or dispute cleanliness
  before a listing can move above `observe_only`.

#### Phase 87: Local Consume Decision Artifact

**Depends on:** Phase 86

**Scope**

- Define `arc.market.consume-decision.v1` as the explicit trust-activation
  record for a consumer.
- Require the artifact to bind:
  listing digest, evidence digests, policy version, decision tier, issuer,
  rationale codes, reviewer or policy identity, and expiry.
- Add a reversible local override path so a consumer can quarantine or remove a
  previously admitted listing without mutating origin registry state.

#### Phase 88: Runtime Binding and Safe Automation

**Depends on:** Phase 87

**Scope**

- Extend consume decisions into runtime enforcement:
  which listed tools/providers may receive governed calls, budget ceilings,
  approval thresholds, and runtime-assurance minimums.
- Make it impossible for ranked search results alone to satisfy runtime
  admission checks.
- Add automated re-evaluation when a linked dispute, sanction, revocation, or
  freshness deadline changes.

#### Acceptance Criteria

- **TOPEN-01:** ARC ships one explicit permission model for publishers,
  attestors, curators, mirrors, indexers, reporters, and arbiters.
- **TOPEN-02:** Every local admission above `observe_only` produces a signed or
  durable consume-decision artifact.
- **TOPEN-03:** Runtime mediation can enforce consume-decision outcomes without
  reading trust from raw search rank.
- **TOPEN-04:** Trust activation is reversible and re-evaluates on stale,
  disputed, sanctioned, or superseded state.

#### Validation / Qualification

- Policy fixtures proving identical listing inputs produce identical
  consume-decision outputs.
- Integration tests that reject runtime use when only search visibility exists.
- Regression tests for automatic downgrade on dispute, sanction, supersession,
  or stale freshness.
- Review-pack export showing one listing from discovery through local trust
  activation to governed runtime use.

### `v2.23` Governance and Dispute Escalation Network

**Goal:** Upgrade the current operator-scoped dispute model into a federation
governance network that can handle contested evidence, urgent freezes, and
appeals without pretending one operator governs the whole market.

**Depends on:** `v2.22`

#### Phase 89: Dispute Case and Evidence Bundle Contract

**Depends on:** Phase 88

**Scope**

- Define `arc.market.dispute-case.v1` with:
  case id, reporter, respondent, subject listing, allegation type, evidence
  bundle refs, requested remedy, filing bond, filing time, SLA deadlines, and
  decision history.
- Extend dispute states from the current narrow contract to include:
  `filed`, `triaged`, `evidence-requested`, `under-review`, `provisional-freeze`,
  `upheld`, `dismissed`, `sanctioned`, `reinstated`, `closed`.
- Support allegation types for fraud, identity mismatch, stale evidence,
  harmful behavior, ranking manipulation, collusion, and failure to honor
  bound coverage or governance obligations.

#### Phase 90: Governance Charters and Escalation Ladder

**Depends on:** Phase 89

**Scope**

- Define `arc.market.governance-charter.v1` describing:
  jurisdiction, scope, quorum, reviewer eligibility, response timelines,
  emergency powers, appeal path, and sanction limits.
- Establish escalation levels:
  origin operator review, federation panel review, final consumer-local
  override.
- Require all escalation decisions to cite evidence refs and charter clauses.

#### Phase 91: Sanctions, Freezes, and Reinstatement

**Depends on:** Phase 90

**Scope**

- Define `arc.market.sanction.v1` for de-rank, quarantine, suspend, bond slash,
  publish ban, dispute-cost award, and reinstatement actions.
- Keep sanctions as overlays on top of listing and evidence truth.
- Add emergency freeze semantics that can temporarily block new trust
  activations while preserving existing signed evidence.

#### Acceptance Criteria

- **GOV-01:** ARC ships a signed dispute-case artifact with evidence-linked
  history and explicit deadlines.
- **GOV-02:** Every non-trivial dispute can escalate beyond the origin operator
  under a published governance charter.
- **GOV-03:** Sanctions and emergency freezes do not rewrite underlying
  evidence or listing truth.
- **GOV-04:** Consumers can inspect sanction and governance provenance before
  trusting a listing.

#### Validation / Qualification

- End-to-end replay fixtures for file, respond, escalate, sanction, appeal, and
  reinstate.
- Negative tests for missing filing bonds, expired SLAs, invalid evidence refs,
  and out-of-scope arbiters.
- Adversarial tests where an origin operator attempts to suppress or delay a
  valid dispute.
- Governance transparency report showing case timelines, outcomes, and
  sanction classes.

### `v2.24` Portable Reputation and Trust Evidence Exchange

**Goal:** Make trust signals portable across operators without inventing a
single global score or silently aggregating unlike issuers.

**Depends on:** `v2.23`

#### Phase 92: Reputation Statement and Profile Schema

**Depends on:** Phase 91

**Scope**

- Define `arc.market.reputation-statement.v1` carrying:
  issuer, subject, subject kind, observation window, methodology id, factor
  breakdown, adverse events, positive milestones, evidence refs, and expiry.
- Define `arc.market.reputation-profile.v1` as a signed bundle of attributed
  statements, not a synthetic score.
- Support negative events such as slashes, disputes upheld, repeated stale
  listings, settlement failures, or revoked certification.

#### Phase 93: Weighting Profiles and Local Aggregation

**Depends on:** Phase 92

**Scope**

- Define `arc.market.weighting-profile.v1` so consumers can publish or locally
  keep weighting rules for reputation issuers, factor categories, recency, and
  adverse-event severity.
- Keep aggregation local: ARC may compute a consumer-local score, but it must
  remain attributable to the weighting profile that produced it.
- Add bounded import rules for portable reputation into passport, certification,
  liability, and provider-risk-package workflows.

#### Phase 94: Reputation-Gated Ranking and Issuance

**Depends on:** Phase 93

**Scope**

- Feed portable reputation into search ranking, listing eligibility, provider
  admission, budget ceilings, and reputation-gated issuance.
- Require ranking reason codes to identify when reputation materially affected
  result order.
- Support a no-reputation mode so consumers can still operate strictly on
  certification, assurance, and local allowlists.

#### Acceptance Criteria

- **REP-01:** ARC ships portable reputation as attributed signed statements,
  not a universal score.
- **REP-02:** Every computed local trust score or rank effect is attributable
  to a local weighting profile plus issuer-specific statements.
- **REP-03:** Negative events and sanctions are portable with issuer
  provenance and expiry.
- **REP-04:** Consumers can disable or narrow reputation use without breaking
  core discovery or runtime trust activation.

#### Validation / Qualification

- Roundtrip tests for export, import, and verification of reputation
  statements and profiles.
- Regression tests proving local weighting changes alter outputs
  deterministically.
- Adversarial fixtures for conflicting issuers, stale reputation, collusive
  positive attestations, and expired adverse events.
- Qualification examples showing reputation-gated ranking and issuance with
  clear reason codes.

### `v2.25` Marketplace Economics and Abuse Resistance

**Goal:** Make the open market durable under adversarial conditions by adding
economic friction, reward mechanisms, and hard abuse controls.

**Depends on:** `v2.24`

#### Phase 95: Fee Schedule and Metering Semantics

**Depends on:** Phase 94

**Scope**

- Define `arc.market.fee-schedule.v1` for publish, supersede, bulk-search,
  premium-index, dispute-filing, and governance-review fees.
- Keep basic resolve and evidence verification capable of operating without a
  mandatory proprietary payment rail; ARC should meter fees but remain rail
  neutral.
- Record fee assessment and settlement evidence separately from listing truth.

#### Phase 96: Bonds, Slashing, and Challenger Rewards

**Depends on:** Phase 95

**Scope**

- Define `arc.market.bond-account.v1` and `arc.market.slash-event.v1`.
- Require open-market publishers above `self_asserted` to maintain a minimum
  bond or reserve depending on listing risk class.
- Allow a portion of a slashed bond to fund dispute-cost recovery or challenger
  rewards when a case is upheld.
- Add cooldowns and release windows so publishers cannot exit immediately after
  harmful behavior.

#### Phase 97: Abuse Detection, Quarantine, and Rate Controls

**Depends on:** Phase 96

**Scope**

- Add hard controls for:
  duplicate listing floods, mirror poisoning, ranking manipulation, dispute
  griefing, sybil publisher rings, evidence withholding, and coordinated
  reputation gaming.
- Require per-class rate limits, bond floors, freshness budgets, and emergency
  quarantine triggers.
- Add anomaly reports that can feed governance review without becoming
  automatic guilt.

#### Acceptance Criteria

- **ECON-01:** ARC ships operator-published fee schedules and metering semantics
  without tying the registry to one required payment rail.
- **ECON-02:** Bond and slashing logic is explicit, auditable, and linked to
  dispute or abuse outcomes.
- **ECON-03:** Open-market abuse controls can throttle or quarantine malicious
  actors without mutating signed evidence.
- **ECON-04:** Abuse signals can trigger review or temporary controls, but not
  silent permanent sanctions without governance action.

#### Validation / Qualification

- Fee-metering tests for publish, supersede, bulk search, and dispute filing.
- Bond lifecycle tests for lock, top-up, partial slash, full slash, cooldown,
  and release.
- Red-team corpus for spam bursts, sybil clusters, ranking abuse, stale-mirror
  poisoning, and dispute spam.
- Economic simulation showing expected publisher cost, challenger reward, and
  operator exposure under honest and adversarial traffic.

### `v2.26` Open Trust Market Qualification

**Goal:** Prove the combined open-market surface in one bounded launch claim.

**Depends on:** `v2.25`

#### Phase 98: Multi-Operator Adversarial Conformance Corpus

**Depends on:** Phase 97

**Scope**

- Build a qualification corpus with at least:
  honest publisher, malicious publisher, bonded provider, mirror operator,
  malicious mirror, certifier, reputation issuer, governance panel,
  challenger, and consumer.
- Cover lifecycle scenarios from publish through discovery, consume decision,
  runtime use, dispute, sanction, reputation impact, and reinstatement.

#### Phase 99: Partner and Standards Proof Lanes

**Depends on:** Phase 98

**Scope**

- Produce partner-proof materials for marketplaces, insurers, enterprise IAM,
  and standards reviewers showing the exact open-market boundary.
- Produce one standards-facing profile draft for open registry semantics, one
  for portable reputation, and one for governance overlays.
- Prove interoperability between search, local trust activation, runtime
  mediation, and dispute evidence.

#### Phase 100: Launch Decision Contract for Open Market GA

**Depends on:** Phase 99

**Scope**

- Define the hosted and local qualification gates for the open trust market
  claim.
- Freeze the end-state non-claims and marketing language so ARC does not imply
  global trust or universal scoring.
- Require hosted workflow evidence, adversarial replay results, and governance
  transparency reports before external publication.

#### Acceptance Criteria

- **QUAL-01:** ARC can replay a full multi-operator publish-to-sanction
  lifecycle deterministically from signed evidence.
- **QUAL-02:** Search, trust activation, governance, portable reputation, and
  economics remain composable without any step silently widening runtime trust.
- **QUAL-03:** Partner-proof materials and standards drafts state the same
  bounded claim.
- **QUAL-04:** Release gates explicitly include adversarial, governance, and
  economics qualification rather than only happy-path conformance.

#### Validation / Qualification

- Full release-qualification lane across all phases above.
- Hosted workflow proof on the exact candidate commit.
- Governance transparency export with case summaries and sanction statistics.
- Abuse and economic-simulation report included in the final partner package.

## Cross-Milestone Acceptance Criteria

These are the end-state checks that should remain true across the whole ladder:

- **OTM-01:** A listing can be openly published, mirrored, and searched without
  becoming trusted by default.
- **OTM-02:** Every admission decision above observe-only is bound to an
  explicit local consume-decision artifact.
- **OTM-03:** Every dispute and sanction is evidence-linked, charter-bound, and
  attributable to a specific actor or panel.
- **OTM-04:** Portable reputation travels as attributed statements with local
  aggregation, never as a protocol-mandated universal score.
- **OTM-05:** Fees, bonds, and rate controls make mass abuse economically
  expensive.
- **OTM-06:** Raw evidence, discovery overlays, governance overlays, and local
  trust decisions remain separable and replayable.

## Validation and Qualification Expectations

ARC should not promote the open trust market claim until it has all of the
following:

- conformance fixtures for every new artifact family
- deterministic replay for search ranking, consume decisions, governance
  decisions, and local aggregation
- adversarial simulations covering spam, stale mirrors, collusion, ranking
  abuse, dispute griefing, sanction abuse, and reputation gaming
- operator telemetry from shadow mode and then bounded open mode
- partner-proof packages for at least one tool listing, one provider listing,
  one portable reputation import, and one end-to-end dispute escalation
- standards-facing drafts that preserve the same non-claims as the release
  candidate docs

## Explicit Non-Goals

- No global mutable trust registry that all ARC participants must obey.
- No automatic runtime admission from public discovery, ranking, or passport
  presence alone.
- No protocol-mandated universal trust score or synthetic cross-issuer
  reputation collapse.
- No requirement for on-chain settlement, token issuance, or one proprietary
  fee rail.
- No automatic claims payment or autonomous insurer pricing beyond ARC's
  bounded orchestration surfaces.
- No anonymous, zero-cost, zero-friction publication lane for high-risk market
  actors.
- No replacement of MCP, A2A, OAuth-family, portable credential, or payment
  protocols at their own wire level.

## Governance and Risk Caveats

- Opening publication without bonds, rate limits, and identity or assurance
  gates will convert the current high-signal registry into a spam surface.
- Reputation portability can become de facto blacklisting if expiry, adverse
  action reasons, and local weighting are not explicit.
- Governance centralization is a product and legal risk; ARC should prefer
  chartered federations and local opt-in over one global sovereign panel.
- Sanctions must remain overlays. If ARC mutates underlying evidence truth to
  express governance outcomes, it will destroy auditability.
- Ranking systems will be gamed. Every ranked result must be explainable, and
  raw canonical retrieval must remain available.
- Open market fees can create lock-in or anti-competitive behavior if basic
  resolve and verification are paywalled. Keep premium economics additive, not
  required for basic trust inspection.
- Liability and reputation data may become regulated in some jurisdictions once
  tied to real counterparties, so data-retention and appeal rules must be
  designed with legal review.

## Recommended Outcome Statement

If ARC completes this ladder, the honest end-state claim is:

"ARC operates an open, evidence-backed trust market for agent infrastructure:
publishers can list openly, discovery can scale across operators, trust
activation remains local and policy-bound, portable reputation and governance
signals travel with provenance, and abuse is contained through fees, bonds,
and auditable sanctions."

That is materially stronger than the current curated public marketplace claim,
while still avoiding the two traps the current docs correctly reject:
permissionless trust and automatic admission.

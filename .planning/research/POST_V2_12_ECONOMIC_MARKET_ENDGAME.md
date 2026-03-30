# Post-v2.12 Economic Market Endgame Plan

**Project:** ARC
**Scope:** Runtime underwriting -> agent credit -> bonded autonomy -> liability marketplace
**Researched:** 2026-03-28
**Confidence:** MEDIUM-HIGH

## Executive Position

ARC should not treat the post-`v2.12` gap as "more underwriting." That layer is
already shipped. The remaining gap is that ARC can currently explain and sign
economic risk decisions, but it cannot yet:

- maintain a canonical exposure and facility state for agent credit,
- enforce capital-backed autonomy through explicit bond and reserve mechanics,
- or place and adjudicate third-party liability coverage using one canonical
  evidence package.

The current docs are explicit about that boundary. ARC ships underwriting
inputs, deterministic underwriting decisions, persisted decision artifacts,
premiums, appeals, and simulation, but it does **not** yet claim
liability-market capital allocation or autonomous insurer pricing beyond the
underwriting surface. The next roadmap should close that boundary in three
milestones, not one.

## Recommended Milestone Sequence

1. **v2.13 Credit, Exposure, and Capital Policy**
   - Convert underwriting outputs into credit-grade state and capital-policy
     decisions.
2. **v2.14 Bonded Autonomy and Facility Execution**
   - Turn capital policy into runtime reserve, bond, and autonomy enforcement.
3. **v2.15 Liability Marketplace and Claims Network**
   - Let external providers quote, bind, and adjudicate liability using ARC
     evidence and artifacts.

**Why this order:**

- `v2.13` is analytical and state-model work. It creates the canonical
  exposure, scorecard, and facility surfaces that everything else depends on.
- `v2.14` is enforcement work. Bonding and autonomous capital use are unsafe if
  ARC has not first made exposure and facility logic explicit.
- `v2.15` is market orchestration. Provider quotes, coverage binding, and
  claims should only be added after ARC's own capital and bond semantics are
  stable enough to export.

## Current Boundary And Gap

### What ARC already ships

- signed behavioral-feed export over canonical receipts, settlement,
  reputation, and shared evidence
- signed underwriting-input snapshots
- deterministic underwriting-decision reports
- persisted signed underwriting decisions with budget recommendations, premium
  quotes, lifecycle, and appeals
- runtime-assurance-aware issuance and governed execution

### What is still missing

- exposure state beyond a one-decision premium quote
- versioned credit scorecards and capital facility terms
- bond or reserve artifacts that can be locked, released, or slashed
- delegated autonomy tiers backed by capital and assurance requirements
- provider-neutral quote/bind/claim workflows for external liability partners

### What "research idea achieved" should mean

ARC can truthfully claim the endgame is achieved only when it can do all of the
following without mutating canonical receipt truth:

1. Compute credit-grade exposure and score state from canonical ARC evidence.
2. Allocate bounded capital facilities and bonds to governed actions and
   delegated agents.
3. Enforce capital-backed autonomy at runtime with fail-closed controls.
4. Export canonical quote, coverage, and claim packages to external providers.
5. Track coverage placement, disputes, losses, and recoveries as explicit ARC
   artifacts.

That is the right claim boundary. It is materially stronger than "we have
underwriting," but narrower and safer than "ARC is an insurer."

## Milestone Plan

### v2.13 Credit, Exposure, and Capital Policy

**Goal:** Turn ARC's evidence and underwriting substrate into a canonical
credit-and-exposure layer that can support capital allocation decisions.

**Depends on:** `v2.10`, `v2.11`, `v2.12`

#### Phase 61: Exposure Ledger And Economic Position Model

**Depends on:** Phase 60

**Scope**

- Define a signed exposure artifact and ledger over governed actions,
  settlements, premiums, reversals, recoveries, write-offs, and reserves.
- Model open exposure separately from execution receipts and separately from
  underwriting decisions.
- Add deterministic joins from exposure rows to receipt ids, governed intent,
  decision ids, capability lineage, subject identity, and settlement evidence.
- Partition exposure by currency and facility so ARC never collapses unrelated
  units into a fake total.

**Why first**

Current underwriting artifacts can price or withhold exposure, but they do not
maintain a durable credit position model. ARC needs that before any facility or
bond logic is credible.

#### Phase 62: Credit Scorecards, Probation, And Anomaly Signals

**Depends on:** Phase 61

**Scope**

- Define a versioned agent-credit scorecard built from receipts, reputation,
  settlement behavior, certification, runtime assurance, and anomaly signals.
- Reuse the existing local reputation design for probationary history and
  staked delegation reputation instead of inventing a second bondless score.
- Add explainable score factors and adverse-action style reasons for every
  score downgrade.
- Distinguish provisional scores from mature scores using explicit receipt and
  time thresholds.

**Why second**

The research ladder says receipt volume and reputation come before agent credit.
ARC already has local reputation design work; now it needs a capital-facing,
versioned scorecard.

#### Phase 63: Facility Terms And Capital Allocation Policy

**Depends on:** Phase 62

**Scope**

- Define signed facility-policy artifacts: credit limit, utilization ceiling,
  reserve ratio, concentration caps, action-class restrictions, minimum
  runtime-assurance tier, certification requirements, and manual-review
  thresholds.
- Extend runtime allocation outcomes beyond `approve/reduce/step_up/deny` to
  include facility selection, reserve requirement, and capital source.
- Make capital policy provider-neutral: ARC decides the bounded facility state
  and evidence package, not the provider's internal actuarial model.
- Add operator simulation and policy delta tooling for facility policy, not
  just underwriting.

**Why third**

Facility allocation is the first point where ARC stops being only a risk engine
and becomes a capital control plane. It should sit on top of explicit exposure
and score semantics, not directly on raw receipts.

#### Phase 64: Credit Qualification, Backtests, And Provider Risk Package

**Depends on:** Phase 63

**Scope**

- Add a signed provider-facing risk package export: exposure summary,
  scorecard, supporting evidence refs, assurance state, certification state,
  and recent loss history.
- Add deterministic backtests over historical receipt and settlement corpora to
  prove score and facility behavior are reproducible.
- Publish qualification fixtures for score drift, stale evidence, mixed
  currency, and facility over-utilization.
- Publish partner-proof docs that explain the exact divide between ARC capital
  control and partner capital provision.

**Why last**

ARC should not claim agent credit until the score and facility logic can be
replayed, audited, and handed to an external provider without manual rewriting.

#### Milestone Requirements / Acceptance Criteria

- **CREDIT-01:** ARC defines one canonical exposure ledger and signed exposure
  artifact over governed actions, premiums, reserves, losses, recoveries, and
  settlement state.
- **CREDIT-02:** ARC produces a versioned, explainable credit scorecard with
  explicit probation and anomaly semantics.
- **CREDIT-03:** ARC issues signed capital-facility policies that allocate
  bounded capital based on score, exposure, assurance, and certification.
- **CREDIT-04:** ARC ships backtests, simulation, and a provider-facing risk
  package sufficient for external capital review.

#### Validation / Qualification Evidence

- Golden fixtures proving the same receipt corpus yields the same exposure
  ledger and scorecard.
- Regression tests for currency partitioning, stale evidence, over-utilization,
  and score downgrade explanations.
- Backtest report over a representative historical corpus showing false-allow,
  false-hold, and downgrade rates.
- Partner-proof package demonstrating one risk package export with inclusion
  proof references back to canonical ARC evidence.

#### Explicit Non-Goals

- No public credit score or cross-operator universal trust score.
- No consumer or human-person credit decisions.
- No direct lending balance sheet inside ARC.
- No FX conversion or cross-currency netting in this milestone.

#### Risks / Caveats

- Credit scoring tied to human-linked identities can create lending,
  discrimination, or model-governance exposure. Keep this scoped to agents and
  workloads unless separate compliance work is done.
- Poor anomaly features will create false holds and operator distrust. Every
  downgrade needs evidence refs and simulation.
- Exposure truth can drift if settlement and reserve state are allowed to
  overwrite signed execution truth. Preserve separate artifacts.

### v2.14 Bonded Autonomy And Facility Execution

**Goal:** Make capital-backed autonomy executable by introducing reserves,
bonding, and loss/recovery state machines at runtime.

**Depends on:** `v2.13`

#### Phase 65: Bond Contracts, Reserve Locks, And Collateral State

**Depends on:** Phase 64

**Scope**

- Define signed bond, reserve, collateral, and release/slash artifacts.
- Add typed bond states: proposed, locked, partially released, released,
  slashed, written_off.
- Bind bonds and reserves to one subject, one facility or delegated chain, one
  currency, and one governed action or action class.
- Track provider source, operator source, and self-funded source separately so
  ARC can support both external capital and internal reserves.

**Why first**

Bonded autonomy is not a metaphor. ARC needs explicit state transitions and
auditable artifacts before it can safely say an agent is operating "on bond."

#### Phase 66: Delegation Bonds And Autonomy Tier Gates

**Depends on:** Phase 65

**Scope**

- Extend governed execution policy so specific action classes require a minimum
  bond level, reserve level, or assurance tier before the agent may bypass a
  human approval.
- Reuse the existing staked-reputation design for delegator exposure, then
  formalize it as a capital-backed delegation bond.
- Add autonomy tiers that combine score, assurance, certification, and bond
  coverage to determine whether an action may run automatically.
- Fail closed when autonomy prerequisites are absent, stale, or mismatched.

**Why second**

The market story is "bonded autonomy," not just "stored collateral." ARC needs
runtime gates that prove autonomy was allowed because bond and assurance
conditions were met.

#### Phase 67: Loss Events, Recovery, And Delinquency Lifecycle

**Depends on:** Phase 66

**Scope**

- Define signed loss-event artifacts linked to receipts, failed settlements,
  policy violations, and claim packages.
- Add delinquency, recovery, reserve-release, and write-off state transitions.
- Distinguish reversible settlement issues from slashable policy violations.
- Make recoveries and write-offs explicit economic artifacts instead of mutable
  annotations on underwriting or settlement rows.

**Why third**

Bonding is not credible until ARC can show exactly how losses consume reserves
and how valid recovery or release paths work after the fact.

#### Phase 68: Qualification, Operator Controls, And Sandbox Integrations

**Depends on:** Phase 67

**Scope**

- Extend simulation tooling to show reserve lock, slash, release, and recovery
  outcomes across a scenario corpus.
- Add runbooks for delinquency review, false-positive slash reversal, manual
  override, and delegated-loss handling.
- Prove one self-funded operator lane and one external capital-adapter lane in
  qualification.
- Produce a bounded operator narrative for "capital-backed autonomy" that does
  not imply ARC is itself a regulated surety or insurer.

**Why last**

This milestone changes runtime product behavior. ARC should not ship it without
scenario testing and operator-proof materials.

#### Milestone Requirements / Acceptance Criteria

- **BOND-01:** ARC defines signed bond, reserve, and collateral artifacts with
  explicit lock/release/slash state.
- **BOND-02:** ARC enforces autonomy tiers using score, assurance, and bond
  prerequisites for economically sensitive actions.
- **BOND-03:** ARC tracks loss, delinquency, recovery, and write-off lifecycles
  as immutable economic artifacts.
- **BOND-04:** Qualification proves both self-funded and external-capital
  bonded-execution lanes.

#### Validation / Qualification Evidence

- End-to-end fixtures showing reserve lock before action, slash after verified
  loss, and release after successful settlement.
- Negative tests proving missing bond, stale assurance, or exceeded facility
  fails closed.
- Delegation tests proving delegator exposure is bounded and traceable through
  the delegation chain.
- Operator simulation output proving autonomy-tier policy changes before
  deployment.

#### Explicit Non-Goals

- No onchain token or permissionless staking requirement.
- No bond trading, secondary markets, or public collateral markets.
- No automatic liquidation or collections behavior outside explicit policy.
- No fully autonomous slash path without an appeal or manual-review lane.

#### Risks / Caveats

- Bond slashing can look like financial punishment if the evidence model is
  weak. Appeals and manual review are mandatory.
- Delegation-linked bonds create product and legal complexity around who is
  economically responsible. ARC should encode provenance, not claim to settle
  legal fault by itself.
- Self-funded capital and third-party capital must remain distinguishable, or
  provider reporting and accounting will drift.

### v2.15 Liability Marketplace And Claims Network

**Goal:** Let external providers quote, bind, and adjudicate liability coverage
for agent actions using ARC's canonical evidence and capital artifacts.

**Depends on:** `v2.14`

#### Phase 69: Provider Registry, Coverage Classes, And Jurisdiction Policy

**Depends on:** Phase 68

**Scope**

- Define a curated provider registry for insurers, surety providers, capital
  providers, and delegated risk engines.
- Add explicit provider metadata: supported jurisdictions, currencies,
  coverage classes, evidence requirements, SLA, and callback or polling
  endpoints.
- Define a coverage-class taxonomy aligned to governed action types and loss
  categories.
- Keep registry admission operator-curated and fail closed on unsupported
  provider, jurisdiction, or product class.

**Why first**

ARC should not begin quote orchestration until provider identity, jurisdiction,
and supported products are explicit and reviewable.

#### Phase 70: Quote Requests, Placement, And Bound Coverage Artifacts

**Depends on:** Phase 69

**Scope**

- Define canonical quote-request and quote-response artifacts over one risk
  package, one action or facility scope, and one evidence bundle.
- Support multi-provider quote collection, operator or policy selection, and
  bound coverage artifacts with explicit effective dates, limits, exclusions,
  and provider identity.
- Add placement reports so ARC can show how a governed action was covered,
  financed, or declined.
- Keep provider pricing and ARC policy recommendations separate.

**Why second**

This is the first milestone phase that makes the "liability marketplace"
visible. It must consume the canonical provider registry and risk package, not
ad hoc partner JSON.

#### Phase 71: Claim Packages, Disputes, And Liability Adjudication

**Depends on:** Phase 70

**Scope**

- Define a canonical claim package linking receipts, underwriting decisions,
  exposure rows, reserves, bonds, settlement evidence, and loss events.
- Add claim lifecycle state: filed, acknowledged, information_requested,
  accepted, denied, settled, recovered, closed.
- Add provider responses, dispute notes, and superseding claim decisions
  without mutating the original claim package or canonical ARC evidence.
- Support subrogation and recovery references as explicit follow-on economic
  artifacts.

**Why third**

The marketplace story is incomplete if ARC can place coverage but not generate
an evidence-grade claim package when something goes wrong.

#### Phase 72: Marketplace Qualification, Partner Proof, And Boundary Update

**Depends on:** Phase 71

**Scope**

- Add qualification lanes with at least two provider adapters: one insurance or
  surety style adapter and one capital facility adapter.
- Publish an end-to-end partner-proof showing quote, bind, claim, dispute, and
  recovery flows over canonical evidence.
- Update protocol, release-candidate, and partner-proof language so ARC can now
  explicitly claim liability-market orchestration within the shipped boundary.
- Close the milestone only when the current explicit non-goal language can be
  removed honestly.

**Why last**

The research idea is only "achieved" when ARC can change its external claim
boundary without hand-waving.

#### Milestone Requirements / Acceptance Criteria

- **MARKET-01:** ARC defines a curated provider registry and coverage taxonomy
  for liability and capital providers.
- **MARKET-02:** ARC produces canonical quote-request, quote-response, and
  bound-coverage artifacts over the same evidence package used for underwriting.
- **MARKET-03:** ARC produces immutable claim packages and tracks adjudication,
  disputes, settlement, and recovery explicitly.
- **MARKET-04:** Protocol, release, qualification, and partner-proof materials
  are updated so ARC can truthfully claim liability-market orchestration.

#### Validation / Qualification Evidence

- Two-provider integration harness proving quote collection and deterministic
  placement over one canonical risk package.
- End-to-end claim fixture proving claim generation, provider response,
  dispute, and closeout without rewriting receipts or prior decisions.
- Qualification tests for unsupported jurisdiction, unsupported currency,
  stale provider policy, and mismatched evidence digest.
- Release/protocol audit proving the old "not claimed" language has been
  replaced with an evidence-backed new boundary.

#### Explicit Non-Goals

- No permissionless public marketplace in the first shipped version.
- No ARC-owned underwriting balance sheet or regulated carrier role.
- No consumer insurance or natural-person claims handling.
- No silent sharing of sensitive evidence across orgs; every export remains
  policy-bounded and explicit.

#### Risks / Caveats

- Marketplace language can trigger insurance-broker, MGA, surety, or lending
  regulation depending on jurisdiction. ARC should stay an orchestration and
  evidence layer unless a separate regulated strategy is chosen.
- Claim packages may contain sensitive prompts, business data, or PII. Export
  policy and minimization are not optional.
- Providers may reject ARC's canonical risk package unless provider adapters
  support their evidence and jurisdiction requirements. Keep the registry
  curated first.

## Cross-Milestone Non-Goals

- ARC does not become a payment rail, insurer, lender of record, broker-dealer,
  or collections system.
- ARC does not invent a universal cross-operator trust score.
- ARC does not collapse legal liability into protocol-level delegation
  attribution.
- ARC does not make public-market claims until provider identity, jurisdiction,
  and qualification evidence exist.
- ARC does not relax fail-closed semantics to improve quote fill rate.

## Roadmap Implications

### Recommended phase numbering

- `v2.13`: Phases 61-64
- `v2.14`: Phases 65-68
- `v2.15`: Phases 69-72

### Suggested milestone close criteria

ARC can claim the research idea is achieved only after `v2.15` closes and all
of the following are true:

1. The protocol and release docs no longer exclude liability-market capital
   allocation within the shipped ARC boundary.
2. ARC can show an end-to-end path from canonical receipt to credit score to
   facility to bond to provider quote to bound coverage to claim package.
3. Every economic state change is represented by a signed or otherwise explicit
   artifact separate from canonical receipt truth.
4. Qualification includes at least one real partner-shaped integration lane,
   not just internal simulation.

## Key References

- `docs/research/DEEP_RESEARCH_1.md`
  - endgame sequencing and liability-market thesis
- `docs/release/RELEASE_CANDIDATE.md`
  - current shipped underwriting surfaces and explicit non-goals
- `spec/PROTOCOL.md`
  - exact underwriting/report surface and current external claim boundary
- `crates/arc-core/src/underwriting.rs`
  - current underwriting artifact vocabulary and missing facility/bond/claim
    types
- `docs/AGENT_REPUTATION.md`
  - existing probation and staked-reputation design that should feed bonded
    autonomy
- `docs/AGENT_ECONOMY.md`
  - current economic and underwriting surface, including anomaly and settlement
    context

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Sequencing | HIGH | Strongly grounded in the current shipped boundary and the research ladder. |
| Milestone definitions | HIGH | Clear gap from underwriting to credit/bond/market artifacts. |
| Regulatory boundary | MEDIUM | Product boundary is clear, but jurisdiction-specific insurance and credit rules will need counsel before launch claims widen. |
| Partner adoption assumptions | MEDIUM | ARC can define provider-neutral packages, but actual provider acceptance is still a market dependency. |

# Post-v2.20 Capital And Liability Execution Endgame Plan

**Project:** ARC  
**Scope:** Live capital allocation, executable reserve and escrow control,
slashing, autonomous insurer pricing, automatic claims payment, recovery
clearing, reinsurance and facility capital flows, and regulated-role boundary
expansion after `v2.20`  
**Researched:** 2026-03-29  
**Confidence:** MEDIUM-HIGH

## Executive Position

ARC has now shipped the bounded economic-market ladder that earlier research
described:

- `v2.18` added signed exposure, credit, facility-policy, backtest, and
  provider-risk-package surfaces.
- `v2.19` added reserve-backed autonomy gating, signed bond artifacts,
  bond-loss lifecycle artifacts, and non-mutating bonded-execution simulation.
- `v2.20` added curated liability-provider registry, quote/bind, and
  claim/dispute/adjudication orchestration over canonical evidence.

That is a real milestone, but it is still an orchestration and evidence layer.
The remaining endgame gap is not "more reporting." It is the move from bounded
evaluation and artifact issuance to controlled execution of actual capital and
liability state.

Post-`v2.20`, ARC should only widen its claim boundary in this order:

1. live capital allocation and source-of-funds control
2. executable reserve and escrow state
3. slashing and reserve impairment with appeals
4. delegated autonomous pricing and auto-bind
5. automatic claims payment for a narrow qualified lane
6. recovery clearing and reinsurance or facility settlement
7. explicit regulated-role profiles for who is allowed to price, bind, pay,
   slash, collect, or custody funds

The endgame is achieved only when ARC can show one qualified lane from
canonical receipt through facility draw, reserve hold, bond impairment or claim
payment, recovery clearing, and external capital reconciliation without
mutating canonical receipt truth and without hiding which regulated actor
authorized each step.

## Design Invariants

These invariants should remain unchanged throughout the post-`v2.20` roadmap:

- canonical receipts remain the execution ground truth
- capital, reserve, claim, recovery, and reinsurance state must be represented
  as separate signed or otherwise explicit artifacts rather than edits to prior
  receipt truth
- mixed-currency books fail closed unless ARC has an explicitly qualified
  single-book FX policy for that lane
- every live-money transition needs both an evaluated state and a reconciled
  external-state record
- regulated authority must be explicit at issuance and execution time; ARC
  must not imply that a generic operator is automatically allowed to act as a
  carrier, MGA, TPA, custodian, lender, or recovery servicer
- simulation and shadow mode come before autonomous execution for every new
  money-moving surface

## Current Shipped Boundary

### What ARC ships today

The referenced docs show that ARC already ships:

- signed exposure-ledger exports over governed receipts, settlement state, and
  underwriting decisions
- signed credit-scorecard exports with probation and anomaly semantics
- bounded facility-policy evaluation plus signed facility artifacts
- deterministic credit backtests and signed provider-facing risk packages for
  external capital review
- signed bond-policy reports and bond artifacts with reserve posture
- runtime autonomy gating that can require an active delegation bond and fail
  closed on stale assurance, lifecycle, or scope mismatch
- immutable bond-loss lifecycle artifacts over delinquency, recovery,
  reserve-release, and write-off state
- non-mutating bonded-execution simulation with operator controls
- curated liability-provider registry artifacts with fail-closed jurisdiction,
  coverage-class, currency, and evidence-resolution rules
- provider-neutral quote-request, quote-response, placement, bound-coverage,
  claim-package, provider-response, dispute, and adjudication artifacts

### What ARC explicitly does not ship today

The release and protocol docs still explicitly exclude or do not claim:

- live capital allocation beyond bounded facility-policy evaluation
- locked collateral or external escrow execution
- reserve slashing or other external collateral movement
- autonomous insurer pricing beyond the documented underwriting-policy surface
- automatic claims payment
- external recovery clearing or insurer-network messaging
- any live reinsurance or syndication capital-flow execution

### Practical interpretation of the boundary

ARC can currently prove:

- what the risk, facility, bond, and liability posture should be
- what the quote, bind, and claim artifacts should look like
- what the operator would do under bounded simulation and lifecycle policy

ARC cannot yet prove:

- that capital was actually committed or moved
- that reserve or escrow state changed at a custodian
- that a slash was executed against live funds
- that a provider-priced policy was auto-bound under delegated authority
- that a claim was automatically paid
- that recoveries, reinsurance reimbursements, or facility reimbursements were
  cleared against external counterparties

## Remaining Gap

The post-`v2.20` gap breaks into seven concrete deficits.

### 1. Capital execution gap

Facilities are currently signed policy artifacts, not live books with funded,
committed, drawn, released, repaid, and exhausted state.

### 2. Escrow and reserve execution gap

Bond and reserve posture are currently reportable and enforceable as runtime
preconditions, but not executable against a custodian or external account.

### 3. Slashing gap

ARC can record delinquency, recovery, reserve-release, and write-off artifacts,
but it cannot yet impair or slash live collateral under a bounded control
framework.

### 4. Pricing authority gap

ARC can package evidence for underwriting and liability providers, but it does
not yet run a bounded autonomous pricing lane under explicit delegated
regulatory authority.

### 5. Claims-payment gap

ARC can construct claim, dispute, and adjudication artifacts, but it does not
yet issue and reconcile payout instructions.

### 6. Recovery and reinsurance clearing gap

ARC can record recovery-related state, but it does not yet clear subrogation,
recovery, reinsurance, or facility reimbursement obligations across
counterparties.

### 7. Regulated-role gap

ARC's current claim boundary is intentionally orchestration-first. The moment
ARC starts pricing, paying, collecting, or moving custodial funds, it needs an
explicit operating model for which licensed or otherwise authorized actor is
doing what.

## What "Endgame Achieved" Means After v2.20

ARC can only claim that the capital and liability execution endgame is achieved
when all of the following are true:

1. A governed action can be assigned to one live capital source with explicit
   committed, held, drawn, and released state.
2. Reserve and escrow instructions can be issued, acknowledged, executed, and
   reconciled against an external custodian or capital provider.
3. Bond impairment and slashing can be executed under a bounded evidence and
   appeal model instead of existing only as reportable intent.
4. Pricing and binding can run automatically, but only inside one delegated
   provider envelope with explicit model version, authority window, and
   jurisdiction or product scope.
5. Low-complexity eligible claims can be paid automatically from an explicit
   source of funds, with payout receipts and reconciliation artifacts.
6. Recoveries and ceded-capital obligations can be cleared across facility,
   insurer, and reinsurance counterparties without inventing hidden state.
7. Every live execution step records which regulated role authorized it and
   which profile ARC is operating under.

## Recommended Milestone Sequence After v2.20

1. **`v2.21` Live Capital Allocation And Escrow Substrate**
   - Turn facility and bond policy into live capital-book and escrow
     instructions.
2. **`v2.22` Executable Reserve, Escrow, And Slashing Control**
   - Turn reserve posture and bond-loss artifacts into live impairment,
     release, and slash operations with appealable controls.
3. **`v2.23` Autonomous Pricing, Coverage Binding, And Automatic Claims
   Payment**
   - Add provider-authorized pricing, auto-bind, narrow straight-through claims
     adjudication, and payout execution.
4. **`v2.24` Recovery Clearing, Reinsurance, And Regulated Network Profiles**
   - Close the post-payment loop and define the exact role topology required
     for ARC to widen its launch claim honestly.

### Why this order

- ARC should not move money before it has a canonical live capital book and
  reconciled escrow instruction model.
- ARC should not slash reserves before hold, release, and impairment semantics
  are executable and reviewable.
- ARC should not auto-price or auto-pay claims before live reserve state and
  slash or release semantics are stable.
- ARC should not claim a live liability market until it can reconcile payouts,
  recoveries, and ceded-capital obligations across counterparties and can say
  which regulated actor is on the hook for each step.

## Milestone Plan

### `v2.21` Live Capital Allocation And Escrow Substrate

**Goal:** Convert bounded facility and bond outputs into live capital and
escrow instructions without yet widening into autonomous pricing or automatic
claims payment.

**Depends on:** `v2.20`

#### Phase 89: Capital Book And Source-Of-Funds Ledger

**Goal:** Create ARC's canonical live capital book for post-`v2.20` execution.

**Depends on:** `v2.20`

**Scope**

- Define signed capital-account and capital-book artifacts keyed by facility,
  provider, subject scope, and currency.
- Track typed capital states: `available`, `committed`, `held`, `drawn`,
  `disbursed`, `released`, `repaid`, `expired`, `impaired`.
- Bind every row to one facility artifact, one capital provider identity, one
  authority chain, and one evidence reference set.
- Separate self-funded operator capital, external facility capital, insurer
  reserve capital, and partner-provided escrow capital.
- Preserve a no-hidden-netting rule: ARC should report per-book and
  per-currency state rather than inventing blended capital availability.

#### Phase 90: Escrow And Reserve Instruction Contract

**Goal:** Define the custody-neutral execution contract for reserve and escrow
movement.

**Depends on:** Phase 89

**Scope**

- Define explicit instruction artifacts for `open_hold`, `increase_hold`,
  `decrease_hold`, `release_hold`, `disburse`, `cancel`, and `reconcile`.
- Bind each instruction to one capital book, one bond or claim reference, one
  authority role, one execution deadline, and one idempotency key.
- Model external execution states separately from ARC intent:
  `issued`, `acknowledged`, `pending_execution`, `executed`, `failed`,
  `reversed`, `reconciled`.
- Support callback and polling reconciliation so ARC can compare intended state
  with custodian or capital-provider state.
- Fail closed when the external counterparty cannot prove the instruction
  target, currency, or funding source.

#### Phase 91: Live Allocation Engine For Governed Actions

**Goal:** Turn facility-policy results into live capital-allocation decisions.

**Depends on:** Phase 90

**Scope**

- Extend facility selection into executable allocation outputs: selected book,
  committed amount, reserve ratio, hold amount, expiry, and fallback policy.
- Require live source-of-funds checks before ARC admits a governed action that
  claims reserve-backed autonomy.
- Support pre-execution commitment for one governed action, one action class,
  or one delegated chain with explicit utilization and concentration updates.
- Distinguish `evaluate`, `shadow_execute`, and `commit_execute` modes so ARC
  can qualify live behavior before enabling real money movement.
- Add fail-closed handling for insufficient funds, stale facility rows, stale
  custody state, duplicate commits, and unsupported source-of-funds profiles.

#### Phase 92: Qualification, Reconciliation, And Operator Controls

**Goal:** Qualify the capital and escrow substrate before later autonomy
expansion.

**Depends on:** Phase 91

**Scope**

- Add one qualified shadow lane and one qualified live lane with an external
  custodian or capital-provider adapter.
- Produce deterministic reconciliation reports that compare ARC capital-book
  state with external statements or instruction logs.
- Add dual-control thresholds, exception queues, and kill-switch behavior for
  capital execution failures.
- Add runbooks for stale holds, duplicate callbacks, partial execution, and
  forced unwind.
- Update release proof so ARC can claim "live capital allocation and escrow
  instruction execution" only for the qualified profile.

#### Milestone Requirements / Acceptance Criteria

- **CAPITAL-01:** ARC defines one canonical live capital book with explicit
  source-of-funds provenance and no hidden netting.
- **CAPITAL-02:** ARC defines executable escrow and reserve instruction
  artifacts with intent, external execution, and reconciliation state.
- **CAPITAL-03:** ARC can commit live capital for a governed action or
  delegation chain before execution proceeds.
- **CAPITAL-04:** Qualification proves external reconciliation, idempotent
  instruction handling, and fail-closed insufficient-funds behavior.

#### Validation / Qualification Expectations

- Golden fixtures proving the same facility and capital-book inputs yield the
  same allocation and hold instructions.
- Integration tests covering callback loss, delayed settlement, duplicate
  execution notice, stale state, and external rejection.
- Reconciliation tests proving ARC detects drift between internal and external
  balances.
- Shadow-mode evidence showing at least one real partner-shaped lane before
  widening external claims.

#### Explicit Non-Goals

- No reserve slashing in `v2.21`.
- No automatic claims payment in `v2.21`.
- No cross-currency collateral netting or blended multi-book allocation.
- No permissionless capital pool or public capital marketplace.

### `v2.22` Executable Reserve, Escrow, And Slashing Control

**Goal:** Turn reserve and bond-loss posture into executable hold, release,
impairment, and slash controls with bounded appeals and operator oversight.

**Depends on:** `v2.21`

#### Phase 93: Executable Bond And Escrow State Machine

**Goal:** Upgrade bond artifacts from reportable posture to executable reserve
objects.

**Depends on:** Phase 92

**Scope**

- Extend bond lifecycle to include executable states such as
  `pending_fund`, `funded`, `held`, `pending_release`, `pending_slash_review`,
  `slashed`, `reversed`, `closed`.
- Bind each bond state transition to one or more escrow instructions and
  capital-book updates.
- Preserve bond truth separately from live instruction truth so ARC can replay
  why a state change was attempted even if the custodian rejected it.
- Require explicit authority tags for who may lock, release, impair, or slash
  a bond.

#### Phase 94: Loss Trigger And Slashing Policy

**Goal:** Define what can trigger a hold, impairment, release, claim, or slash.

**Depends on:** Phase 93

**Scope**

- Introduce a bounded trigger taxonomy covering settlement default, verified
  policy violation, coverage denial, adjudicated claim liability, operator
  override, and external counterparty error.
- Distinguish reversible incidents from slash-eligible incidents.
- Define slash ceilings, proportional impairment rules, recovery offsets, and
  capital waterfall priority between reserve, deductible, facility, and
  provider-side coverage.
- Make slashing policy consume canonical receipts, bond-loss artifacts,
  claim-state artifacts, and capital-book state without rewriting them.

#### Phase 95: Appeals, Reversals, And Post-Slash Recovery

**Goal:** Make slashing governable and reversible when evidence changes.

**Depends on:** Phase 94

**Scope**

- Add explicit `appeal`, `stay`, `reversal`, `make_whole`, and `deficiency`
  artifacts linked to slash events.
- Allow disputed slash decisions to freeze further execution while preserving
  already-executed external state and its evidence trail.
- Track post-slash recovery and reimbursement rows separately from initial loss
  or claim rows.
- Support delegator or parent-facility liability trace so ARC can show who was
  economically exposed at the time of slash.

#### Phase 96: Slashing Qualification And Runtime Controls

**Goal:** Qualify slashing for a narrow live lane before later auto-pay.

**Depends on:** Phase 95

**Scope**

- Add threshold-based manual review, circuit breakers, and dual-control gates
  for slash actions above configured size or severity.
- Qualify one bounded live slash lane and one bounded reversal lane with an
  external partner adapter.
- Add scenario corpora for partial slash, full slash, false-positive appeal,
  post-recovery reimbursement, and stale-authority rejection.
- Publish runbooks for slashing incidents, operator override, and regulator or
  partner evidence requests.

#### Milestone Requirements / Acceptance Criteria

- **SLASH-01:** ARC can move a bond from policy posture into executable funded
  and held reserve state.
- **SLASH-02:** ARC can evaluate and execute a bounded hold, release, or slash
  decision over live collateral using explicit evidence and authority.
- **SLASH-03:** ARC records appeals, reversals, and post-slash recovery as
  separate immutable artifacts.
- **SLASH-04:** Qualification proves at least one bounded live slash lane with
  manual-review and circuit-breaker controls.

#### Validation / Qualification Expectations

- End-to-end fixtures showing hold before action, slash after verified loss or
  adjudicated trigger, and reversal after successful appeal.
- Negative tests proving stale authority, stale bond state, unsupported source
  of funds, or currency mismatch fails closed.
- Concurrency tests proving duplicate slash instructions do not double-impair
  the same reserve.
- Replay tests proving slash decisions remain explainable from preserved
  evidence even after external execution completes.

#### Explicit Non-Goals

- No fully autonomous slash path for high-severity events without review.
- No public slashing market or third-party liquidation layer.
- No collections or litigation automation.
- No principal-risk assumption by ARC itself in this milestone.

### `v2.23` Autonomous Pricing, Coverage Binding, And Automatic Claims Payment

**Goal:** Add provider-authorized autonomous pricing and a narrow straight-
through claims-payment lane on top of stable live capital and slashing
controls.

**Depends on:** `v2.22`

#### Phase 97: Pricing Input Contract And Provider Model Package

**Goal:** Define the bounded autonomous pricing substrate.

**Depends on:** Phase 96

**Scope**

- Define a canonical pricing-input artifact built from receipts, exposure,
  credit, facility, bond, loss, capital-book, and coverage context.
- Define signed provider model packages that include model version, effective
  interval, supported jurisdictions, coverage classes, approval thresholds, and
  explanation vocabulary.
- Require delegated authority metadata identifying which carrier, MGA, facility
  provider, or other regulated principal authorized the pricing model.
- Add drift and shadow-evaluation tooling so ARC can compare automated pricing
  outcomes against operator or partner baselines before auto-bind is enabled.

#### Phase 98: Auto-Bind And Continuous Repricing

**Goal:** Turn quote and bind from operator-driven orchestration into bounded
provider-authorized automation.

**Depends on:** Phase 97

**Scope**

- Extend quote-response and placement artifacts with pricing-model provenance,
  decision envelope, delegated authority, and bindability flags.
- Support straight-through bind for eligible scopes only when jurisdiction,
  coverage class, source of funds, and authority profile all match.
- Support repricing triggers for material evidence change, utilization change,
  assurance downgrade, or loss deterioration.
- Fail closed when ARC cannot prove that the selected pricing model and bind
  authority were valid at the moment of bind.

#### Phase 99: Straight-Through Claims Decisioning

**Goal:** Define the narrow claim classes eligible for automatic payment.

**Depends on:** Phase 98

**Scope**

- Add claim-eligibility policy for auto-payment based on severity, coverage
  certainty, evidence completeness, payout cap, dispute absence, and fraud or
  anomaly score.
- Define straight-through claim decisions:
  `pay`, `partial_pay`, `refer`, `deny`, `hold_for_review`.
- Require explicit explanation labels and evidence references for every
  automatic denial, hold, or payout decision.
- Bind claim decisions to live reserve, deductible, coverage limit, and
  recovery posture at decision time.

#### Phase 100: Claims Payment Instruction Engine

**Goal:** Execute and reconcile narrow automatic claim payouts.

**Depends on:** Phase 99

**Scope**

- Define payout instruction artifacts with payee, funding source, reserve or
  coverage allocation, payment rail metadata, idempotency, and reconciliation
  state.
- Support full payment, partial payment, split payment, and failed payment
  retry or rollback semantics.
- Link payment execution to capital-book depletion, reserve release or
  impairment, and claim lifecycle updates without mutating prior claim truth.
- Add payout failure handling for stale payee state, compliance hold, funding
  shortfall, duplicate instruction, and counterparty rejection.

#### Milestone Requirements / Acceptance Criteria

- **AUTOPRICE-01:** ARC can run deterministic provider-authorized pricing over
  one canonical input contract with explicit model and authority provenance.
- **AUTOPRICE-02:** ARC can auto-bind only within a delegated provider envelope
  and fail closed outside it.
- **CLAIMPAY-01:** ARC can classify claims into pay, partial-pay, refer, deny,
  or hold-for-review using explicit evidence and policy.
- **CLAIMPAY-02:** ARC can issue and reconcile automatic payout instructions
  for one narrow qualified lane.

#### Validation / Qualification Expectations

- Golden pricing corpora proving stable pricing outputs for the same evidence
  window and delegated model package.
- Shadow-mode comparison against human or provider-reviewed pricing and claim
  decisions before live autonomous enablement.
- Integration tests covering payout rail failures, duplicate payout callbacks,
  stale payee data, and funding shortfall.
- Release proof showing that automatic claims payment is only claimed for the
  qualified product class, jurisdiction set, and authority profile.

#### Explicit Non-Goals

- No open-ended black-box pricing with no explanation or delegated authority.
- No automatic payment for disputed, high-severity, complex, or cross-border
  claims in the first shipped lane.
- No consumer or natural-person insurance claims handling.
- No generic permissionless pricing marketplace.

### `v2.24` Recovery Clearing, Reinsurance, And Regulated Network Profiles

**Goal:** Close the post-payment loop and define the exact regulated operating
profiles needed for ARC to claim live capital and liability execution.

**Depends on:** `v2.23`

#### Phase 101: Recovery And Counterparty Clearing Ledger

**Goal:** Add the canonical post-payment clearing book.

**Depends on:** Phase 100

**Scope**

- Define recovery, reimbursement, overpayment, recapture, and counterparty
  settlement artifacts linked to claim payouts and prior reserve or slash
  state.
- Track typed recovery states:
  `booked`, `pending_counterparty`, `acknowledged`, `collected`, `failed`,
  `compromised`, `written_off`.
- Add batch and per-claim clearing views so ARC can reconcile by event or by
  settlement cycle.
- Separate recovery receivables from realized recoveries so ARC does not treat
  hoped-for collections as funded capital.

#### Phase 102: Reinsurance And Facility Capital Waterfall

**Goal:** Model and execute ceded-capital and reimbursement flows.

**Depends on:** Phase 101

**Scope**

- Define signed treaty, facultative, or facility-participation artifacts for a
  narrow supported set of capital-sharing structures.
- Model retention, attachment, exhaustion, ceded share, reinstatement, and
  reimbursement priority as explicit waterfall terms.
- Link reinsurance or facility reimbursement instructions to claim payouts,
  reserve impairment, and capital-book replenishment.
- Keep the first supported lane narrow: one or two capital-sharing patterns,
  one currency per book, and curated counterparties only.

#### Phase 103: Regulated-Role Profiles And Authority Delegation

**Goal:** Make role boundary explicit before widening ARC's external claim.

**Depends on:** Phase 102

**Scope**

- Define explicit deployment profiles such as `orchestration_only`,
  `delegated_operations`, and `principal_risk`.
- Define role types including operator, capital provider, custodian or escrow
  provider, insurer or carrier, MGA or program administrator, TPA or claims
  administrator, reinsurer, and recovery servicer.
- Require every money-moving or liability-changing artifact to record the
  acting role, licensed principal if applicable, jurisdiction scope, authority
  window, and escalation policy.
- Add fail-closed checks so a deployment cannot enable pricing, payment,
  slashing, or recovery collection without the required role bindings.

#### Phase 104: Endgame Qualification, Boundary Update, And Launch Profile

**Goal:** Qualify one full live lane and then update ARC's external claim
boundary honestly.

**Depends on:** Phase 103

**Scope**

- Qualify one end-to-end lane from governed action through facility draw,
  reserve hold, slash or payout, recovery, and ceded-capital reimbursement.
- Update release, protocol, partner-proof, and operations docs so claims are
  profile-specific instead of generic across all ARC deployments.
- Publish one launch-profile matrix that states exactly which features are
  available in each regulated-role profile and which remain non-goals.
- Close the milestone only when ARC can remove the current explicit non-goal
  language for the qualified profile without widening claims for unqualified
  profiles.

#### Milestone Requirements / Acceptance Criteria

- **CLEAR-01:** ARC can record and reconcile recoveries and reimbursements
  after claim payment.
- **CLEAR-02:** ARC can execute one bounded reinsurance or facility-capital
  waterfall over a qualified lane.
- **ROLE-01:** Every pricing, payment, slashing, and recovery action is bound
  to an explicit regulated-role profile and authority record.
- **ROLE-02:** Release and protocol claims become profile-specific and evidence
  backed rather than generic or implied.

#### Validation / Qualification Expectations

- End-to-end reconciliation proving claim payout, recovery receipt, and
  capital-provider reimbursement all line up across internal and external
  ledgers.
- Counterparty tests for stale treaty or facility terms, unsupported role
  profile, reimbursement mismatch, and delayed recovery.
- Disaster-recovery and replay tests proving ARC can reconstruct the live
  capital and liability path from preserved artifacts.
- Partner-proof package for one real counterparty lane, not only internal
  simulation.

#### Explicit Non-Goals

- No permissionless insurer or reinsurance network.
- No litigation, collections, or public claims exchange.
- No default assumption that ARC itself becomes the carrier, MGA, TPA,
  custodian, or lender of record.
- No universal cross-jurisdiction launch claim from a single qualified lane.

## Cross-Milestone Validation And Qualification Expectations

Every post-`v2.20` milestone should satisfy these shared gates before ARC
widens its public claim boundary:

- deterministic replay over canonical receipts plus downstream artifacts
- shadow-mode qualification before live autonomous execution
- external reconciliation against custodian, capital-provider, payment-rail, or
  counterparty statements
- explicit operator controls including kill-switch, dual control, exception
  queues, and stale-state recovery
- negative tests proving role mismatch, stale authority, currency mismatch,
  unsupported jurisdiction, and duplicate execution fail closed
- runbooks for incident response, unwind, appeal, and partner evidence requests
- profile-specific release language so qualified live lanes do not silently
  widen the claim for every ARC deployment

## Regulated-Role Boundary Recommendation

The post-`v2.20` roadmap should make the operating profile explicit instead of
pretending there is one generic ARC deployment.

### Recommended profiles

1. **Orchestration-only profile**
   - ARC remains an evidence, policy, and workflow layer.
   - Regulated actors externalize pricing, custody, payout, and recovery.
   - This is closest to the current shipped boundary.

2. **Delegated-operations profile**
   - ARC executes pricing, binding, claims-payment, or recovery workflows only
     under signed delegated authority from a regulated principal.
   - This should be the first profile allowed to claim autonomous pricing or
     automatic claims payment.

3. **Principal-risk profile**
   - The operator or ARC-affiliated entity carries regulated principal
     responsibility itself.
   - This is a business-model and legal-structure decision, not the default
     product path.

### Required authority fields for live execution

Every live capital or liability artifact after `v2.20` should carry at least:

- acting role
- sponsoring or licensed principal when applicable
- jurisdiction or product scope
- authority window
- model or policy version used
- manual-review and appeal policy
- counterparty or custodian identity

## Regulatory Caveats

These are design caveats, not legal advice:

- Automatic pricing, binding, claims payment, recovery collection, custody, and
  capital provision can each trigger different licensing or delegated-authority
  requirements depending on jurisdiction and product class.
- ARC should treat custody and fund movement as a partner-shaped capability by
  default rather than assuming a generic software operator may hold or move
  funds.
- Straight-through claims payment should stay narrow and policy-bounded until
  there is explicit claims-authority delegation, payout control evidence, and
  a proven appeal or exception path.
- Slashing can resemble punitive enforcement, liquidation, or collections if it
  is not bounded by explicit evidence, review thresholds, and reversal paths.
- Reinsurance, capital-facility syndication, or reimbursement clearing should
  start as curated counterparties and narrow contract patterns rather than a
  generic market.
- Cross-border data transfer, claim evidence minimization, and sensitive
  commercial data handling become more important as ARC moves from evidence
  packaging into live claims and recovery workflows.
- Any move from delegated-operations profile to principal-risk profile should
  be treated as a separate company and compliance decision, not an automatic
  product milestone.

## Cross-Milestone Non-Goals

- ARC does not become a generic payment rail.
- ARC does not become a permissionless capital, insurance, or reinsurance
  exchange.
- ARC does not collapse legal liability into protocol-level delegation
  provenance.
- ARC does not auto-net mixed-currency books to make reports or execution look
  cleaner than the actual capital state.
- ARC does not allow a new live lane to widen claims for unqualified operators
  or jurisdictions.
- ARC does not remove human review from severe, disputed, or authority-ambiguous
  events just to increase automation rates.

## Roadmap Implications

### Recommended phase numbering

- `v2.21`: Phases 89-92
- `v2.22`: Phases 93-96
- `v2.23`: Phases 97-100
- `v2.24`: Phases 101-104

### Suggested milestone close criteria

ARC should only treat this endgame as achieved once `v2.24` closes and all of
the following are true:

1. The release and protocol docs no longer exclude live capital allocation,
   executable reserve and escrow state, automatic claims payment, or recovery
   clearing for the qualified profile.
2. ARC can show one end-to-end path from canonical receipt to live capital
   commitment to reserve hold to slash or payout to recovery and ceded-capital
   settlement.
3. Every post-receipt money movement is represented by explicit artifacts plus
   external reconciliation evidence.
4. Every live execution action can be traced to an explicit regulated-role
   authority profile.
5. At least one real partner-shaped lane is qualified end to end; the claim is
   not based on internal simulation alone.

## Key References

- `docs/research/DEEP_RESEARCH_1.md`
  - endgame ladder from evidence to underwriting to credit or bonded autonomy
    to liability market
- `docs/release/RELEASE_CANDIDATE.md`
  - current `v2.18` through `v2.20` shipped boundary and explicit non-goals
- `spec/PROTOCOL.md`
  - exact shipped facility, bond, liability, and non-goal boundary
- `docs/AGENT_ECONOMY.md`
  - current economic design invariants and bounded post-`v2.18` execution
    posture
- `.planning/research/POST_V2_12_ECONOMIC_MARKET_ENDGAME.md`
  - prior ladder from underwriting to credit, bonded autonomy, and liability
    orchestration that `v2.18` through `v2.20` substantially closed

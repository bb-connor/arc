# WS7 Design: Parametric insurance (receipt-observable triggers)

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS3 for SLA-breach trigger class; WS1/WS4 for payout execution;
  a production FROST verifier plus trusted roster/key epoch before panel activation;
  trigger and evidence contracts land independently
- Claim track: implementation (not insurer-of-record; signed intent and evidence only)
- Branch: chio/ws7-parametric-insurance off main

## Goal

Add a parametric coverage tier where payout eligibility is established by a
deterministic, recomputable predicate over receipt-observable events rather than
a human adjudicator: any holder of the declared corpus recomputes the same
verdict. Dispatch still requires fresh capability, policy, guard, and ladder
authority for the payout action. The tier also adds an opt-in n-of-m
adjudication panel that supersedes the single-signer adjudicator on contested
claims, parametric and non-parametric.

## Context

chio-market already ships bound liability coverage with receipt-verified
claims. `quote_and_bind` prices a premium and binds a `BoundPolicy`
(`crates/economy/chio-market/src/insurance_flow.rs:651`); `BoundPolicy::file_claim`
re-verifies each referenced receipt against the kernel signing key, fails closed
on any unresolved or tampered receipt, and caps the payout at the coverage limit
(`insurance_flow.rs:326`). The full claim chain is a signed-artifact lineage from
claim-package to adjudication (`crates/economy/chio-market/src/claim.rs`), then
payout-instruction to settlement-receipt
(`crates/economy/chio-market/src/settlement.rs`). Every adjudicator today is a
single signer: `LiabilityClaimAdjudicationArtifact.adjudicator` is one `String`
(`claim.rs:305`), and the payout instruction hard-requires a signed adjudication
whose payable amount it copies (`settlement.rs:93,115`; `lib.rs:81`). The credit
loss lifecycle defaults `external_claim_adjudication_supported = false`
(`crates/economy/chio-credit/src/risk_reports.rs:140,151`).
`BoundPolicy::file_claim` is stateless with respect to prior claims and submits
directly to the supplied settlement sink (`insurance_flow.rs:326-332,417-444`).
Its per-call coverage cap is therefore not an aggregate policy limit or a replay
guard. The parametric path cannot reuse that method as its persistence boundary.

Three receipt-observable event families already exist to trigger on:
guard-denial and allow decisions carried in receipts; drift severity in
`AutonomousDriftReport.drift_signals[].severity` where
`AutonomousDriftSeverity` is `Warning | Critical`
(`crates/economy/chio-autonomy/src/model.rs:141,502,515`); and settlement
failure via a signed reconciliation sidecar that digest-binds the immutable
financial receipt. Settlement status is not written back into the receipt
(`spec/PROTOCOL.md:944-947`). SLA-breach artifacts arrive from WS3. The ladder
already mandates FROST n-of-m for
`settle.commitment` (`spec/CHIO_LADDER.md:707-717`, quorum semantics at
`CHIO_LADDER.md:430-448`), the precedent this workstream follows for panel
decisions. Boundary language is fixed by `spec/PROTOCOL.md:2814-2829`
(bounded liability-market claim, not an insurer network) and the
payment-lifecycle dispute fields by `spec/PROTOCOL.md:1098-1130`.

## In scope

1. `ParametricPolicy` artifact: coverage limit (`MonetaryAmount`), one typed
   trigger predicate, a declared evidence-corpus window, and a payout schedule.
2. Four v1 trigger predicate classes: guard-denial-rate over a window,
   drift-severity threshold, settlement-failure count, and SLA-breach count
   (the last gated on WS3).
3. `TriggerEvaluation` artifact: policy digest, evidence-corpus manifest,
   evaluation window, checkpoint and contiguous-range completeness proof,
   verdict with magnitude, and evaluator signature; recomputable by any holder
   of that complete corpus.
4. Auto-claim assembly: a fired trigger builds a `ClaimEvidence` bundle
   (`insurance_flow.rs:466`) over the corpus using `ReceiptFingerprint`
   linkage (`insurance_flow.rs:77`) and files it without an adjudicator.
5. Policy-declared payout mode and eligibility semantics, plus payout intent
   bound to a fresh authorized capital-execution instruction and reconciliation
   sidecar, mirroring the existing payout-instruction pattern
   (`settlement.rs:89-275`). Aggregate reserved plus reconciled payouts cannot
   exceed policy coverage, and schedule math rejects overflow. A policy or
   trigger signature alone never authorizes fund movement.
6. A durable claim/coverage ledger with deterministic claim identity, aggregate
   policy-coverage reservation, unique payout-intent binding, and a versioned
   contest lifecycle. Duplicate or concurrent evaluation cannot reserve or pay
   the same coverage twice.
7. Opt-in n-of-m adjudication-panel artifacts and verification, superseding the
   single-signer adjudicator for non-parametric disputes and parametric contests
   only after the FROST and key-epoch prerequisite is live; single-adjudicator
   remains the default.
8. Two new ladder action classes: `parametric.trigger_payout` and
   `adjudication.panel_decision`, each with a declared governance mode.
9. JSON schemas under `spec/schemas/`, schema-id constants, and conformance
   coverage for every new artifact, including `spec/schemas/registry.json`,
   `spec/schemas/MANIFEST.sha256`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive
   fixtures, and unknown-schema negatives.

## Out of scope (explicit cuts)

- Fund custody or on-chain execution. The artifact layer emits signed payout
  intent plus reconciliation binding only; movement is bounded by WS1/WS4 and
  the contract freeze. No new Solidity surface.
- Discretionary underwriting inside the trigger. Predicates are declared in the
  policy and evaluated deterministically; no model inference at evaluation time.
- New predicate classes beyond the four v1 classes (for example latency
  percentiles or oracle-price bands).
- New cross-issuer roster federation, FROST implementation, or key ceremony.
  `main` has ladder semantics but no production Rust FROST verifier. Panel
  artifacts may land disabled, but activation is hard-blocked until a production
  verifier resolves a trusted roster and key epoch. Endorsements alone never
  satisfy the quorum action.
- Any breaking change to the existing bound-liability claim chain or its
  single-adjudicator default. The panel is additive and opt-in, and the payout
  verifier gains the explicit tagged `AdjudicationAuthority::{Single, Panel}`
  extension described below while preserving the current `Single` path.

## Design

The first implementation is a pure `parametric` module beside the existing
claim chain in `chio-market` (`#![forbid(unsafe_code)]`, no I/O, serde plus
deterministic validation), per program invariant 4. It reuses
`ReceiptFingerprint`, `ClaimEvidence`, and the capital-execution-instruction
types from chio-market and chio-credit. A separate crate is allowed only if
implementation discovery proves the existing home creates a dependency cycle or
unworkable feature boundary. All money is `MonetaryAmount` (invariant 2); the
legacy `CoverageLimit.amount_cents` shape (`insurance_flow.rs:188`) is not reused.

### Trigger predicates

A predicate is a deterministic function of the declared corpus and
policy-declared parameters (thresholds, window bounds, counts); the same corpus
yields the same fired flag and tagged `TriggerMagnitude`, whose value is either
a count or an integer basis-point rate. v1 classes:

- `GuardDenialRate { window, min_events, threshold_bps }`: over deny and allow
  decision receipts in the corpus, `magnitude = denials * 10_000 / total` basis
  points; fires when `total >= min_events` and `magnitude >= threshold_bps`.
  Load rejects `min_events = 0` or `threshold_bps > 10_000`; evaluation widens
  the checked numerator to `u128`, divides before checked conversion to `u64`,
  and never relies on wrapping or saturating multiplication.
- `DriftSeverity { window, min_critical }`: over `AutonomousDriftReport` artifacts
  (`model.rs:515`), `magnitude = count of drift_signals with severity == Critical`;
  fires when `magnitude >= min_critical`. Load rejects `min_critical = 0`.
- `SettlementFailureCount { window, min_failures }`: over signed settlement
  reconciliation sidecars whose `receipt_digest` resolves to a verified
  immutable financial receipt in the same corpus, `magnitude = count where the
  sidecar outcome is Failed`; fires when `magnitude >= min_failures`. Load
  rejects `min_failures = 0`.
- `SlaBreachCount { window, min_breaches }` (WS3-gated): over WS3 SLA-breach
  artifacts, `magnitude = breach count`; fires when `magnitude >= min_breaches`.
  Load rejects `min_breaches = 0`.

Before computing any predicate, the evaluator verifies a corpus manifest with
one `SourceRange` for every collection the predicate reads: receipt store,
reconciliation sidecars, drift reports, and, once enabled, SLA artifacts. Each
source range identifies its checkpoint, inclusive first and last sequence,
subject and time window, and an authenticated index-root or range proof. The
proof derives the expected member count from the committed source rather than
trusting a count supplied by the evaluator. It also proves both query boundaries:
the predecessor is before the subject/window lower bound and the successor is
after its upper bound, or the committed index proves that either boundary is an
end of collection. The checkpoint time must be at or after the evaluation cutoff
and within the policy's maximum source-staleness bound. Resolved members must
form exactly each proven range; duplicate, missing, extra, unverifiable, stale,
or out-of-window members make the corpus incomplete. An incomplete corpus yields
`Incomplete { reason }`, not `NotFired`, reports no magnitude, and cannot
authorize payout or deny coverage. `NotFired` is reserved for a complete
verified corpus whose predicate evaluates false.

The source contract is explicit rather than assumed. Phase 1 defines an
`EvidenceCorpusSource` snapshot interface returning a source kind, trusted
signer/domain, `anchor_epoch`, checkpoint root, checkpoint time, committed query
index root, and boundary-complete proof. Phase 2 adds or reuses append-only
checkpointed stores for reconciliation, drift, and SLA artifacts. Until a source
implements that interface and its root resolves through a trusted source registry,
predicates that read it return `Incomplete`; an embedded self-signed sidecar or
evaluator-supplied root is not a completeness proof.

### Artifacts and types (schema ids chio.parametric.<artifact>.v1)

- `chio.parametric.policy.v1` -> `ParametricPolicy`: `subject_key`, coverage
  `MonetaryAmount`, effective window, `TriggerPredicate` (tagged enum above),
  `PayoutSchedule`, `PayoutMode`, bound-liability-policy digest, payer and
  beneficiary identities, funding-facility id, pre-action authority digest, and
  the evaluator authority (single evaluator key, or a panel-roster reference for
  contested tiers). Verification resolves the bound policy and facility through
  trusted local state, checks that coverage and parties match, and verifies that
  the policy signer was authorized for that payer and facility. For contestable
  mode it also names a contest-authority policy resolved from trusted local state;
  a key embedded
  only by the policy is never a trust root. `PayoutMode` is either
  `Automatic`, which removes discretionary adjudication after a deterministic
  trigger but does not replace dispatch authority, or `Contestable {
  window_seconds, panel_roster_ref }`, which prohibits dispatch until the
  durable contest window closes without a contest or a valid panel decision
  authorizes it. The authority-authenticated claim record stores
  `contest_opened_at` from the trusted runtime clock and computes
  `contest_deadline = contest_opened_at.checked_add(window_seconds)`; an
  evaluator-supplied timestamp or an old evaluation-window end cannot shorten
  the contest period. Overflow rejects. Load-time
  validation rejects a zero or mixed-currency coverage, a schedule whose
  currency differs from coverage, an inverted effective window, or a
  contestable mode without a valid panel reference and nonzero window.
- `chio.parametric.trigger-evaluation.v1` -> `TriggerEvaluation`: policy digest,
  a typed corpus manifest containing the per-source checkpoints, inclusive
  sequence ranges, expected counts, range proofs, receipt fingerprints, and
  digest-bound refs to reconciliation, drift, and SLA artifacts;
  `evaluation_window`; `verdict:
  Fired { magnitude } | NotFired | Incomplete { reason }`; and the evaluator
  signature via `SignedExportEnvelope`
  (`crates/core/chio-core-types/src/receipt/lineage.rs:407`).
- `chio.parametric.auto-claim.v1` -> `ParametricAutoClaim`: binds a Fired
  `TriggerEvaluation` to the assembled `ClaimEvidence` (`insurance_flow.rs:466`),
  proving the claim's `supporting_receipts` are exactly the corpus receipts. It
  derives `claim_id = sha256(canonical_json(["chio.parametric.claim.id.v1",
  policy_digest, trigger_evaluation_body_digest]))`; signatures are excluded
  from the identity preimage.
- `chio.parametric.contest.v1` -> `ParametricContest`: binds `claim_id`,
  policy and evaluation body digests, a bounded reason code, canonical evidence
  refs, and the authorized contestant identity and signature. The trusted
  receipt time is recorded by the claim store, not supplied as deadline
  authority by the contestant.
- `chio.parametric.payout-intent.v1` -> `ParametricPayoutIntent`: binds the
  auto-claim, a `SignedCapitalExecutionInstruction` (action `TransferFunds`,
  source `FacilityCommitment`, unreconciled), and the schedule-computed
  `payout_amount`, exactly as `LiabilityClaimPayoutInstructionArtifact` does
  (`settlement.rs:89-186`). It may be issued only after the policy's automatic
  eligibility or contestable-release condition is verified and the payout
  action carries fresh capability, policy, guard, and ladder authority. A policy
  signature or trigger evaluation by itself is not payout authority.
- `chio.parametric.payout-receipt.v1` -> `ParametricPayoutReceipt`: reconciliation
  sidecar state (`Matched | AmountMismatch`) digest-bound to the immutable
  payout instruction and execution evidence, mirroring
  `LiabilityClaimPayoutReceiptArtifact` (`settlement.rs:191-272`).

`TriggerMagnitude` is tagged as `Count { value }` or
`BasisPoints { value }`. Each predicate has exactly one declared magnitude
unit: guard-denial rate is basis points and the three count predicates are
counts. `PayoutSchedule` is `Fixed { amount }` or
`Linear { base, per_unit_minor, magnitude_unit }`. Load requires the linear
unit to equal the predicate's unit. `per_unit_minor` means minor currency units
per one event or per one basis point, with no implicit scaling. Payout is
`checked_add(base, checked_mul(per_unit_minor, magnitude.value))`, then checked
against remaining aggregate coverage as described below.
Either checked operation returning overflow is a typed evaluation error and
produces no claim or payout intent; a cap is never used to hide overflow. No
floats. The shared panel artifact
`chio.adjudication.panel-decision.v1` is defined below.

### Claim, contest, and aggregate-coverage state

`chio-market` owns a backend-neutral `ParametricClaimStore`; the SQLite
implementation shares one writer for claim, policy-coverage, contest, payout
intent, and audit-event rows. `ParametricClaimRecord` is authority-authenticated
store state keyed by the derived `claim_id`, with unique
`(policy_digest, trigger_evaluation_body_digest)`, a checked row version,
schedule-computed amount, optional panel-authorized amount, trusted
opening/deadline times, contest and panel digests, payout-intent digest, and
state:

`Ready | ContestOpen | Contested | UncontestedReleased | PanelReleased |
PanelDenied | PayoutReserved | Submitted | Reconciled | Incident`.

Creating an automatic claim inserts `Ready`; a contestable claim inserts
`ContestOpen` with `contest_opened_at` and checked `contest_deadline` from
the trusted runtime clock. Identical replay returns the existing record. A
different body for the same claim or evaluation key is a conflict.

`file_contest` resolves the policy's contest-authority rule, verifies the
signed `ParametricContest`, and before the deadline compare-and-swaps the exact
`ContestOpen` version to `Contested` while inserting the contest and audit
event in one transaction. At or after the deadline,
`release_uncontested` compare-and-swaps that same state to
`UncontestedReleased`; it cannot succeed if a contest won the race. The
boundary is exact: contest receipt time must be less than the deadline, while
uncontested release requires time greater than or equal to it. A panel decision
binds the claim and contest digests and transitions only `Contested` to
`PanelReleased` or `PanelDenied`; it never rewrites an uncontested release.
For both payable outcomes, the claim record stores the exact award returned by
the shared `LiabilityClaimAdjudicationArtifact` validator as the
panel-authorized amount. `ClaimUpheld` requires a positive same-currency award
no greater than the filed schedule-computed amount; it does not imply a full
award. `PartialSettlement` requires a positive same-currency award strictly
less than that amount. `ProviderUpheld` stores no payable amount and transitions
to `PanelDenied`. This preserves the live single-adjudicator award semantics.

One `PolicyCoverageLedger` row per policy digest stores the currency, aggregate
coverage limit, reserved units, reconciled-paid units, and version. Payout-intent
creation accepts only `Ready`, `UncontestedReleased`, or `PanelReleased`.
In one `Immediate` transaction it locks the claim and coverage versions,
recomputes the schedule amount, selects that amount for `Ready` and
`UncontestedReleased`, or requires and selects the persisted panel-authorized
amount for `PanelReleased`, then checked-adds
`reserved_units + reconciled_paid_units + payout_amount`, rejects above the
policy limit, inserts exactly one signed payout intent, increments reserved
coverage, and advances the claim to `PayoutReserved`. Identical replay is a
no-op; a different intent for the same claim conflicts. The intent is not
dispatchable unless this committed claim state and reservation verify.

Reconciliation atomically moves the exact reserved amount to paid only from
canonical execution evidence. A terminal proof that no funds moved may release
the reservation through an authenticated transition; outcome-unknown,
submission, or reconciliation failure keeps it reserved and enters
`Incident`. No retry, alternate evaluation, or second signature can exceed the
aggregate policy limit or create a second intent for the same fired evaluation.

### Auto-claim data flow

1. Evaluator resolves the policy signer, payer, facility, evaluator, and every
   source signer/root through trusted registries. It verifies every declared source checkpoint and contiguous-range
   proof, then resolves exactly those corpora through a
   `ReceiptEvidenceSource`-style
   trait (`insurance_flow.rs:152`), verifying signatures against the kernel key,
   and resolves reconciliation, drift, and SLA sidecars via signature checks
   against the trusted source key and domain, not merely each embedded key.
2. It emits `Incomplete` on any completeness or verification failure. Otherwise
   it computes the predicate and emits a signed `Fired` or `NotFired`
   `TriggerEvaluation`.
3. On `Fired`, it assembles a `ClaimEvidence` whose `supporting_receipts` are the
   corpus fingerprints, emits `ParametricAutoClaim`, and inserts or verifies the
   deterministic claim record. It never calls stateless `BoundPolicy::file_claim`
   as the replay or aggregate-coverage boundary.
4. It verifies payout eligibility from the signed policy. `Automatic` creates a
   `Ready` claim. `Contestable` atomically opens the trusted-clock contest
   state and remains non-dispatchable until either the no-contest deadline CAS or
   a FROST-authorized panel decision releases it.
5. Fresh authority for `parametric.trigger_payout` is necessary but not
   sufficient. The claim store atomically reserves remaining policy coverage and
   records the unique `ParametricPayoutIntent`; only that committed intent may
   dispatch.
6. WS1/WS4 execute the bound capital instruction; observed execution is recorded
   in the digest-bound `ParametricPayoutReceipt` sidecar and atomically reconciles
   the reserved coverage.

The automatic path does not enter discretionary adjudication because the policy
already fixes the deterministic eligibility rule. A contestable path enters the
panel chain only when contested. In both modes, trigger verification establishes
the predicate result, the signed policy establishes the schedule and mode, and a
fresh authorized action establishes payout authority.

### n-of-m adjudication panels

`chio.adjudication.panel-decision.v1` carries a digest and version reference to a
  trusted active `PanelRoster` (`members: Vec<PanelMemberRef>`, threshold `n`, size
`m`, `scope`), the digest of
  the artifact under adjudication (a `LiabilityClaimDisputeArtifact` for the
  non-parametric path, or the exact `ParametricClaimRecord` plus
  `ParametricContest` digests for a parametric contest), the
outcome (reusing `LiabilityClaimAdjudicationOutcome`, `claim.rs:46`), an optional
`awarded_amount: MonetaryAmount`, and
`endorsements: Vec<SignedPanelEndorsement>` each individually signed over the same
decision digest. Validation resolves the roster reference through the locally
trusted active roster set, verifies scope and activation window, and rejects a
roster embedded only by the decision author. It then counts distinct valid
endorsements from roster members and requires at least `n` with one consistent
outcome. The same decision digest and endorsement-set digest enter the configured
federation commit, whose FROST transcript names a qualifying participant set from
that roster and whose aggregate signature is the actual quorum authorization
required by the ladder. Both the attributable endorsements and the aggregate
authorization must verify; anything less rejects and the disputed decision
stands unadjudicated (it does not auto-approve). A valid panel decision supersedes
the single-signer `adjudicator` (`claim.rs:305`) only for a policy that opted into
that roster. Default behavior is unchanged: a policy with no roster uses the
existing single adjudicator. Because no production FROST implementation exists
on `main`, a verifier with no trusted FROST provider or no matching active key
epoch returns `UnsupportedQuorum` and cannot activate or supersede anything.

Award validation matches `LiabilityClaimAdjudicationArtifact`: `ClaimUpheld`
requires and returns its explicit positive same-currency `awarded_amount` no
greater than the filed amount, `ProviderUpheld` has no payable amount, and
`PartialSettlement` requires and returns a positive same-currency amount
strictly less than the filed amount. Both payable outcomes remain bounded by the
coverage limit. The payout verifier changes its input to a
tagged `AdjudicationAuthority::{Single, Panel}` and derives the payable amount
through one shared validator. It never fabricates a single-signer adjudication
from a panel result. The panel variant is accepted only for a policy that opted
into the resolved roster and only after FROST activation; otherwise existing
`SignedLiabilityClaimAdjudication` behavior is unchanged.

### Integration points

- Evaluation runs offline in the CLI and the `chio trust serve` comptroller
  plane, off the kernel dispatch path, like the rest of chio-market. The kernel
  contributes only the receipt corpus via its store.
- Persistence goes behind `platform/chio-store-sqlite` traits (invariant 4).
- Payout execution consumes the signed intent through the WS1 settlement hook /
  WS4 clearinghouse; the artifact layer never moves funds.
- Ladder: `parametric.trigger_payout` is `receipt_backed`, `destructive: true`,
  `co_sign: bilateral_required`; the policy signature fixes eligibility and
  payout mode, while dispatch still requires current action authority, mirroring
  `market.liability_auto_bind` (`CHIO_LADDER.md:696-705`).
  `adjudication.panel_decision` is `receipt_backed`,
  `destructive: true`, `co_sign: n_of_m`, `consistency_model: quorum-required`,
  `consistency_anchor: frost-quorum`, `co_sign_quorum { n, m, scope }`, mirroring
  `settle.commitment` (`CHIO_LADDER.md:707-717`).

### Error handling (fail-closed)

- Any invalid checkpoint, range gap, count mismatch, unresolved member, or
  unverifiable corpus member yields `Incomplete`; no payout or denial follows
  from absence of proof.
- A `NotFired` verdict is path-isolated: it never denies a filed non-parametric
  claim and never populates the adjudication chain. The two paths stay distinct.
- Zero, mixed-currency, or off-currency coverage or schedule rejects at policy
  load (invariant 3); a corpus whose window or subject mismatches the policy
  rejects.
- Schedule overflow rejects with a typed error before the coverage cap and emits
  no payout intent.
- Duplicate evaluation, stale claim version, conflicting claim body, second
  payout intent, coverage-ledger currency mismatch, checked-sum overflow, or
  aggregate reserved-plus-paid amount above policy coverage rejects before
  dispatch. Outcome-unknown execution never releases reserved coverage.
- A contest with an unauthorized signer, wrong claim/evaluation digest, or
  trusted receipt time at or after the deadline rejects. A no-contest release
  before the deadline rejects. Concurrent contest and deadline release use the
  same expected version, so at most one transition commits.
- A panel decision with fewer than `n` valid distinct endorsements, non-roster
  endorsements, inconsistent outcomes, or a missing or invalid FROST aggregate
  authorization rejects.
- A panel outcome with absent, off-currency, zero, or over-limit award semantics
  rejects, and a payout amount must equal the shared adjudication validator's
  result for either authority variant. Single and panel `ClaimUpheld` cover both
  a full award and a smaller positive award, and the exact returned amount is
  persisted, reserved, and dispatched. `PartialSettlement` equal to the filed
  amount rejects, while a smaller positive amount follows that same exact-value
  path.
- A self-signed policy, unknown facility or source root, payer/beneficiary
  mismatch, untrusted evaluator, absent FROST provider, stale key epoch, or
  roster/transcript mismatch rejects.

## Alternatives considered

1. Where the panel machinery lives. (A) Extend chio-governance case machinery
   with threshold endorsement: rejected. `GenericGovernanceCaseArtifact` is a
   single-`issued_by` artifact whose kinds are Dispute/Freeze/Sanction/Appeal
   (`crates/trust/chio-governance/src/generic.rs:17-22,209`), it lives in the
   trust layer not the economy layer, and adding n-of-m would couple insurance
   adjudication to registry governance. (B) A new shared adjudication module
   beside the existing claim chain in chio-market: recommended. It reuses the
   claim types and the `SignedExportEnvelope` pattern and serves both
   non-parametric disputes and parametric contests. (C) Reuse the FROST n-of-m
   quorum semantics from `CHIO_LADDER.md:430-448`: adopted as the ladder anchor
   and governance mode for (B) via `adjudication.panel_decision`, not as a
   separate artifact home. Recommendation: B, bound to C's quorum-required mode.

2. Where trigger evaluation runs. A kernel-side hook could fire triggers inline,
   but that adds business logic to the dispatch path (program invariant 4
   forbids it) and makes verdicts non-recomputable by third parties. Recommended:
   an offline deterministic evaluator over the receipt corpus, matching the
   economy-crate pattern and keeping verdicts independently recomputable.

3. Payout-intent shape. Reusing `LiabilityClaimPayoutInstructionArtifact` would
   force a fabricated adjudication, since it hard-requires a
   `SignedLiabilityClaimAdjudication` and copies its awarded amount
   (`settlement.rs:93,115`). Recommended: a sibling `chio.parametric.payout-intent.v1`
   authorized by the signed policy's declared payout mode after a Fired
   `TriggerEvaluation`, reusing its capital-instruction and reconciliation
   constraints.

## Claim and release framing

WS7 is implementation within the bounded release posture. The parametric tier
deterministically establishes eligibility and computes a policy-declared payout
schedule against verified receipt-observable triggers; it is not discretionary
underwriting or insurer-rate setting, and it does not itself authorize or execute
payment. Chio is not the insurer of record and this is not a regulated insurance
product: the boundary language of `spec/PROTOCOL.md:2814-2829` (a bounded
liability-market claim over canonical evidence, not an insurer network or
permissionless market) governs all external framing. A `TriggerEvaluation` is
signed intent plus recomputable evidence and does not upgrade its corpus receipts
from asserted to observed or verified (program invariant 1). Payout execution is
separately authorized through WS1/WS4 and bounded by the contract freeze; live
capital stays a separate track. Fail-closed holds both ways: no payout without
verifiable trigger evidence and fresh dispatch authority, and no coverage denial
derived from absent evidence.

## Testing strategy

- Determinism: a property test that the same corpus yields the same verdict and
  magnitude across runs and serialization round-trips.
- Fail-closed trigger: a tampered or missing corpus receipt, range gap, wrong
  checkpoint, duplicate sequence, or count mismatch yields `Incomplete` with no
  payout (mirroring `file_claim`, `insurance_flow.rs:1057-1139`), and that verdict
  produces no `ClaimDenialReason` and cannot deny a bound-liability claim.
- Settlement failure: immutable receipt plus valid reconciliation sidecar counts;
  mutation of receipt metadata, a dangling sidecar, or a digest mismatch rejects.
- Schedule integer math: fixed and linear schedules, checked and capped at
  aggregate remaining coverage, proptested over count and basis-point magnitudes
  including unit mismatch and overflow inputs; zero count thresholds and
  overflow reject without an intent.
- Claim idempotency and coverage: repeated and concurrent identical evaluations
  create one claim and one payout intent. Distinct fired evaluations may create
  distinct claims, but a file-backed concurrency test proves their combined
  reserved plus paid value never exceeds the one policy limit. A terminal
  no-movement proof releases once; an unknown outcome remains reserved.
- Payout modes: an automatic policy signature establishes deterministic
  eligibility but cannot emit a dispatchable intent without fresh capability,
  policy, guard, and ladder authority; a contestable policy additionally cannot
  emit one before the trusted deadline or a valid panel release. Boundary and
  race tests file a contest immediately before, exactly at, and after the
  deadline and concurrently run no-contest release; exactly one valid CAS wins.
- Panel award binding: payable upheld and partial outcomes persist the exact
  validator-returned award, while denied persists no amount. Both a full and a
  smaller positive `ClaimUpheld` award pass; `PartialSettlement` must be strictly
  smaller than the filed amount. Reservation and payout bytes must equal the
  persisted amount; mutating any one independently rejects.
- Panel: n-of-m counting over distinct roster members, rejection of
  under-threshold, non-roster, and inconsistent-outcome sets, and supersession of
  the single adjudicator; valid endorsements without the matching FROST aggregate
  and an aggregate over a different endorsement set both reject. With no FROST
  provider or an inactive key epoch, even a complete endorsement set returns
  `UnsupportedQuorum` and remains non-authoritative. Upheld, provider-upheld, and
  partial awards share the existing currency, filed-amount, and coverage caps;
  both tagged payout-authority variants derive exactly the same payable amount.
- Conformance: JSON schemas under `spec/schemas/`, canonical-JSON round-trips,
  and schema-id constants for every `chio.parametric.*` and
  `chio.adjudication.panel-decision.v1` artifact.
- Ladder: manifest conformance proving both new action classes carry a governance
  mode and that `adjudication.panel_decision` is `quorum-required`.
- Signed-schema gates: every new signed family is present in the schema registry,
  hash manifest, and known-schema allowlist, with positive fixtures and
  unknown-schema negatives.

## Implementation phases

1. `chio-market::parametric` contract module: `ParametricPolicy`, complete-corpus
   manifest and verification, `TriggerEvaluation`, the three non-WS3 predicate
   classes, checked `PayoutSchedule` evaluation, deterministic validation,
   schema constants, every signed-schema gate, and conformance. No payout
   execution. Extract a crate only if implementation discovery proves the
   existing home is unworkable. Lands independently of WS1/WS3/WS4.
2. Auto-claim and payout artifacts: `ParametricAutoClaim`,
   `ParametricContest`, `ParametricPayoutIntent`,
   `ParametricPayoutReceipt`, the corpus resolver trait, the backend-neutral
   claim/coverage CAS store, SQLite implementation and concurrency tests, and the
   `parametric.trigger_payout` ladder class.
3. Shared adjudication panel contract: `chio.adjudication.panel-decision.v1`,
   n-of-m endorsement verification, the `adjudication.panel_decision` ladder
   class, and disabled wiring for parametric contests and non-parametric disputes.
   It cannot supersede the single signer yet.
4. Gated activation: bind only store-reserved payout intents to the WS1/WS4
   settlement surface,
   enable the `SlaBreachCount` predicate once WS3 lands, and activate panel
   supersession only after the production FROST verifier plus trusted roster/key
   epoch gate passes. No endorsement-only fallback and no new on-chain surface.

## Resolved decisions

- The panel family is `chio.adjudication.panel-decision.v1`, matching
  `adjudication.panel_decision`. It is shared by parametric contests and
  non-parametric claim disputes, so it is not nested under the existing
  chio-market-only family.
- Discrepancy with the brief: drift severity is a per-signal field
  (`AutonomousDriftSignal.severity`, `model.rs:502`) inside
  `AutonomousDriftReport.drift_signals` (`model.rs:522`), not report-level; the
  `DriftSeverity` predicate reads signal-level severity accordingly.
- `SlaBreachCount` accepts only WS3's
  `chio.outcome.sla-breach.v1` canonical artifact through the trusted
  source/completeness contract. Unknown versions remain disabled.

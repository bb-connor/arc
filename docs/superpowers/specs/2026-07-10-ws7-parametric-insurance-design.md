# WS7 Design: Parametric insurance (receipt-observable triggers)

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS3 for SLA-breach trigger class; WS1/WS4 for payout execution; trigger and evidence machinery lands independently
- Claim track: implementation (not insurer-of-record; signed intent and evidence only)
- Branch: chio/ws7-parametric-insurance off main

## Goal

Add a parametric coverage tier where payout is authorized by a deterministic,
recomputable predicate over receipt-observable events rather than a human
adjudicator: any holder of the declared corpus recomputes the same verdict. The
tier also adds an opt-in n-of-m adjudication panel that supersedes the
single-signer adjudicator on contested claims, parametric and non-parametric.

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

Three receipt-observable event families already exist to trigger on:
guard-denial and allow decisions carried in receipts; drift severity in
`AutonomousDriftReport.drift_signals[].severity` where
`AutonomousDriftSeverity` is `Warning | Critical`
(`crates/economy/chio-autonomy/src/model.rs:141,502,515`); and settlement
failure via `FinancialReceiptMetadata.settlement_status == SettlementStatus::Failed`
(`crates/core/chio-core-types/src/receipt/economics.rs:52,123`). SLA-breach
artifacts arrive from WS3. The ladder already mandates FROST n-of-m for
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
   evaluation window, verdict with magnitude, and evaluator signature;
   recomputable by any corpus holder.
4. Auto-claim assembly: a fired trigger builds a `ClaimEvidence` bundle
   (`insurance_flow.rs:466`) over the corpus using `ReceiptFingerprint`
   linkage (`insurance_flow.rs:77`) and files it without an adjudicator.
5. Payout intent bound to a capital-execution instruction plus a reconciliation
   receipt, mirroring the existing payout-instruction pattern
   (`settlement.rs:89-275`); payout capped at coverage; schedule is integer math.
6. Opt-in n-of-m adjudication panel superseding the single-signer adjudicator,
   for non-parametric disputes and parametric contests; single-adjudicator
   remains the default.
7. Two new ladder action classes: `parametric.trigger_payout` and
   `adjudication.panel_decision`, each with a declared governance mode.
8. JSON schemas under `spec/schemas/`, schema-id constants, and conformance
   coverage for every new artifact.

## Out of scope (explicit cuts)

- Fund custody or on-chain execution. The artifact layer emits signed payout
  intent plus reconciliation binding only; movement is bounded by WS1/WS4 and
  the contract freeze. No new Solidity surface.
- Discretionary underwriting inside the trigger. Predicates are declared in the
  policy and evaluated deterministically; no model inference at evaluation time.
- New predicate classes beyond the four v1 classes (for example latency
  percentiles or oracle-price bands).
- Cross-issuer panel roster federation and FROST key-ceremony custody; roster
  curation is an operator concern (see Open questions).
- Any change to the existing bound-liability claim chain or its single-adjudicator
  default. The panel is additive and opt-in.

## Design

New pure contract crate `crates/economy/chio-parametric` (`#![forbid(unsafe_code)]`,
no I/O, serde plus deterministic validation), per program invariant 4. It reuses
`ReceiptFingerprint`, `ClaimEvidence`, and the capital-execution-instruction types
from chio-market and chio-credit. All money is `MonetaryAmount` (invariant 2); the
legacy `CoverageLimit.amount_cents` shape (`insurance_flow.rs:188`) is not reused.

### Trigger predicates

A predicate is a deterministic function of the declared corpus and
policy-declared parameters (thresholds, window bounds, counts); the same corpus
yields the same `{ fired: bool, magnitude: u64 }`, where magnitude is a count or
an integer basis-point rate. v1 classes:

- `GuardDenialRate { window, min_events, threshold_bps }`: over deny and allow
  decision receipts in the corpus, `magnitude = denials * 10_000 / max(1, total)`
  basis points; fires when `total >= min_events` and `magnitude >= threshold_bps`.
- `DriftSeverity { window, min_critical }`: over `AutonomousDriftReport` artifacts
  (`model.rs:515`), `magnitude = count of drift_signals with severity == Critical`;
  fires when `magnitude >= min_critical`.
- `SettlementFailureCount { window, min_failures }`: over financial receipts,
  `magnitude = count where settlement_status == Failed` (`economics.rs:123`);
  fires when `magnitude >= min_failures`.
- `SlaBreachCount { window, min_breaches }` (WS3-gated): over WS3 SLA-breach
  artifacts, `magnitude = breach count`; fires when `magnitude >= min_breaches`.

Every predicate fails closed: if any corpus member listed in the manifest cannot
be resolved or verified, the verdict is `NotFired` and the magnitude is not
reported. Absence of proof never fires a trigger.

### Artifacts and types (schema ids chio.parametric.<artifact>.v1)

- `chio.parametric.policy.v1` -> `ParametricPolicy`: `subject_key`, coverage
  `MonetaryAmount`, effective window, `TriggerPredicate` (tagged enum above),
  `PayoutSchedule`, and the evaluator authority (single evaluator key, or a
  panel-roster reference for contested tiers). Load-time validation rejects a
  zero or mixed-currency coverage, a schedule whose currency differs from
  coverage, and an inverted effective window.
- `chio.parametric.trigger-evaluation.v1` -> `TriggerEvaluation`: policy digest,
  `corpus_manifest: Vec<ReceiptFingerprint>` plus digest-bound refs to drift and
  SLA artifacts, `evaluation_window`, `verdict: Fired { magnitude } | NotFired`,
  and the evaluator signature via `SignedExportEnvelope`
  (`crates/core/chio-core-types/src/receipt/lineage.rs:407`).
- `chio.parametric.auto-claim.v1` -> `ParametricAutoClaim`: binds a Fired
  `TriggerEvaluation` to the assembled `ClaimEvidence` (`insurance_flow.rs:466`),
  proving the claim's `supporting_receipts` are exactly the corpus receipts.
- `chio.parametric.payout-intent.v1` -> `ParametricPayoutIntent`: binds the
  auto-claim, a `SignedCapitalExecutionInstruction` (action `TransferFunds`,
  source `FacilityCommitment`, unreconciled), and the schedule-computed
  `payout_amount`, exactly as `LiabilityClaimPayoutInstructionArtifact` does
  (`settlement.rs:89-186`) but authorized by the trigger evaluation, not an
  adjudication.
- `chio.parametric.payout-receipt.v1` -> `ParametricPayoutReceipt`: reconciliation
  state (`Matched | AmountMismatch`), mirroring `LiabilityClaimPayoutReceiptArtifact`
  (`settlement.rs:191-272`).

`PayoutSchedule` is `Fixed { amount }` or
`Linear { base, per_unit_minor, magnitude_basis }`. Payout is
`min(coverage, saturating_add(base, saturating_mul(per_unit_minor, magnitude)))`,
u64 saturating throughout, then capped at the coverage limit. No floats. The
shared panel artifact `chio.adjudication.panel-decision.v1` is defined below.

### Auto-claim data flow

1. Evaluator resolves each corpus receipt through a `ReceiptEvidenceSource`-style
   trait (`insurance_flow.rs:152`), verifying signatures against the kernel key,
   and resolves drift/SLA artifacts via `verify_signature`.
2. It computes the predicate and emits a signed `TriggerEvaluation`.
3. On `Fired`, it assembles a `ClaimEvidence` whose `supporting_receipts` are the
   corpus fingerprints and emits `ParametricAutoClaim`.
4. It computes the schedule payout and emits `ParametricPayoutIntent` bound to a
   capital instruction. WS1/WS4 execute; the observed execution is reconciled
   into `ParametricPayoutReceipt`.

The parametric path never enters the dispute/adjudication chain: a verified
trigger replaces the adjudicator, capping payout at coverage.

### n-of-m adjudication panels

`chio.adjudication.panel-decision.v1` carries a `PanelRoster`
(`members: Vec<PanelMemberRef>`, threshold `n`, size `m`, `scope`), the digest of
the artifact under adjudication (a `LiabilityClaimDisputeArtifact` for the
non-parametric path, or a `TriggerEvaluation` for a parametric contest), the
outcome (reusing `LiabilityClaimAdjudicationOutcome`, `claim.rs:46`), and
`endorsements: Vec<SignedPanelEndorsement>` each individually signed over the same
decision digest. Validation counts distinct valid endorsements from roster members
and requires at least `n` with one consistent outcome; anything less rejects and
the disputed decision stands unadjudicated (it does not auto-approve). A valid
panel decision supersedes the single-signer `adjudicator` (`claim.rs:305`). Default
behavior is unchanged: a policy with no roster uses the existing single adjudicator.

### Integration points

- Evaluation runs offline in the CLI and the `chio trust serve` comptroller
  plane, off the kernel dispatch path, like the rest of chio-market. The kernel
  contributes only the receipt corpus via its store.
- Persistence goes behind `platform/chio-store-sqlite` traits (invariant 4).
- Payout execution consumes the signed intent through the WS1 settlement hook /
  WS4 clearinghouse; the artifact layer never moves funds.
- Ladder: `parametric.trigger_payout` is `receipt_backed`, `destructive: true`,
  `co_sign: bilateral_required`, mirroring `market.liability_auto_bind`
  (`CHIO_LADDER.md:696-705`). `adjudication.panel_decision` is `receipt_backed`,
  `destructive: true`, `co_sign: n_of_m`, `consistency_model: quorum-required`,
  `consistency_anchor: frost-quorum`, `co_sign_quorum { n, m, scope }`, mirroring
  `settle.commitment` (`CHIO_LADDER.md:707-717`).

### Error handling (fail-closed)

- Any unresolved or unverifiable corpus member yields `NotFired`; no payout on
  absence of proof.
- A `NotFired` verdict is path-isolated: it never denies a filed non-parametric
  claim and never populates the adjudication chain. The two paths stay distinct.
- Zero, mixed-currency, or off-currency coverage or schedule rejects at policy
  load (invariant 3); a corpus whose window or subject mismatches the policy
  rejects.
- Schedule arithmetic saturates and is capped at coverage; it never wraps.
- A panel decision with fewer than `n` valid distinct endorsements, non-roster
  endorsements, or inconsistent outcomes rejects.

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
   authorized by the `TriggerEvaluation`, reusing its capital-instruction and
   reconciliation constraints.

## Claim and release framing

WS7 is implementation within the bounded release posture. The parametric tier
deterministically executes a policy-declared payout schedule against verified
receipt-observable triggers; it is not discretionary underwriting or insurer-rate
setting. Chio is not the insurer of record and this is not a regulated insurance
product: the boundary language of `spec/PROTOCOL.md:2814-2829` (a bounded
liability-market claim over canonical evidence, not an insurer network or
permissionless market) governs all external framing. A `TriggerEvaluation` is
signed intent plus recomputable evidence and does not upgrade its corpus receipts
from asserted to observed or verified (program invariant 1). Payout execution is
bounded by WS1/WS4 and the contract freeze; live capital stays a separate track.
Fail-closed holds both ways: no payout without verifiable trigger evidence, and
no coverage denial derived from absent evidence.

## Testing strategy

- Determinism: a property test that the same corpus yields the same verdict and
  magnitude across runs and serialization round-trips.
- Fail-closed trigger: a tampered or missing corpus receipt yields `NotFired`
  with no payout (mirroring `file_claim`, `insurance_flow.rs:1057-1139`), and that
  verdict produces no `ClaimDenialReason` and cannot deny a bound-liability claim.
- Schedule integer math: fixed and linear schedules, saturating and capped at
  coverage, proptested over magnitude including overflow inputs.
- Panel: n-of-m counting over distinct roster members, rejection of
  under-threshold, non-roster, and inconsistent-outcome sets, and supersession of
  the single adjudicator.
- Conformance: JSON schemas under `spec/schemas/`, canonical-JSON round-trips,
  and schema-id constants for every `chio.parametric.*` and
  `chio.adjudication.panel-decision.v1` artifact.
- Ladder: manifest conformance proving both new action classes carry a governance
  mode and that `adjudication.panel_decision` is `quorum-required`.

## Implementation phases

1. `chio-parametric` contract crate: `ParametricPolicy`, `TriggerEvaluation`, the
   three non-WS3 predicate classes, `PayoutSchedule` evaluation, deterministic
   validation, schema constants, JSON schemas, and conformance. No payout
   execution. Lands independently of WS1/WS3/WS4.
2. Auto-claim and payout artifacts: `ParametricAutoClaim`,
   `ParametricPayoutIntent`, `ParametricPayoutReceipt`, the corpus resolver trait,
   chio-store-sqlite persistence, and the `parametric.trigger_payout` ladder class.
3. Shared adjudication panel: `chio.adjudication.panel-decision.v1`, n-of-m
   endorsement and supersession, the `adjudication.panel_decision` ladder class,
   and wiring for both parametric contests and non-parametric disputes.
4. Gated activation: bind payout execution to the WS1/WS4 settlement surface and
   enable the `SlaBreachCount` predicate once WS3 lands. No new on-chain surface.

## Open questions

- Panel schema family. This spec uses `chio.adjudication.panel-decision.v1` to
  match the ladder class `adjudication.panel_decision`. If the panel is scoped to
  chio-market only, `chio.market.claim-panel-decision.v1` would sit beside the
  existing `chio.market.claim-adjudication.v1` (`lib.rs:49`). Program owner to
  confirm the family name.
- Panel signature model. This spec records attributable per-member endorsements
  for auditability, while the ladder's quorum-required mode mandates a
  FROST-aggregated signature at the federation-commit layer
  (`CHIO_LADDER.md:437-440`). The relationship between the intra-panel endorsement
  set and the federation co-sign needs the ladder owner's sign-off.
- Corpus completeness. A rate-based predicate (guard-denial-rate) is only sound
  over a complete window; the manifest must prove no receipts were silently
  dropped from the denominator. Whether completeness needs an anchor-epoch or
  sequence attestation is the sharpest soundness question and is unresolved.
- Discrepancy with the brief: drift severity is a per-signal field
  (`AutonomousDriftSignal.severity`, `model.rs:502`) inside
  `AutonomousDriftReport.drift_signals` (`model.rs:522`), not report-level; the
  `DriftSeverity` predicate reads signal-level severity accordingly.
- SLA-breach binding. The `SlaBreachCount` predicate needs the exact WS3 SLA-breach
  artifact schema id and type before it can be implemented.

# WS8 Design: Fiscal constitutions (governed economic parameters)

- Date: 2026-07-10
- Program: agent-economy program, wave 1 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: none
- Claim track: implementation (parameters, not custody; not token issuance; not democratic governance claims)
- Branch: chio/ws8-fiscal-constitutions off main

## Goal

Make Chio's economic parameters a governed, charter-scoped signed-artifact
family with an amendment lifecycle, while guaranteeing that pricing and
penalties can never be bricked by the new machinery. Today those parameters are
set three unrelated and ungoverned ways: hardcoded Rust constants,
operator-signed supersession artifacts, and config structs. WS8 unifies the
authority model without moving funds, issuing tokens, taking custody, or
claiming democratic governance. The honest trust model is m-of-n operator
signers plus a timelock.

## Context

Parameters live in code as constants: the credit-limit tier table
`MARKETPLACE_TIER_LIMIT_UNITS: [u64; 4]`
(`crates/economy/chio-underwriting/src/marketplace_limits.rs:41`, consumed by
`compute_marketplace_credit_limit` at line 82); the reputation-tier discount
curve `TIER_DISCOUNT_PER_HUNDRED: [u32; 4]`
(`crates/economy/chio-appraisal/src/marketplace_pricing.rs:148`, applied with
per-hundred integer math at lines 172-174); the premium basis-point schedules
in `premium_quote_for_outcome`
(`crates/economy/chio-underwriting/src/decision.rs:694`, tables at 700-712) and
the premium floors at `crates/economy/chio-underwriting/src/premium.rs:35-42`.

Parameters also live in operator-signed artifacts. `OpenMarketFeeScheduleArtifact`
(`crates/economy/chio-open-market/src/fee_schedule.rs:71`, schema constant at
line 10) carries `publication_fee`, `dispute_fee`, `market_participation_fee`,
and `bond_requirements` (lines 79-82) as a signed `SignedExportEnvelope`, scoped
to a namespace and one `governing_operator_id`, with no on-artifact supersession
lineage (a new schedule is re-issued with a later `issued_at`). The explicit
supersession precedent WS8 generalizes is the underwriting decision:
`UnderwritingDecisionArtifact` carries `supersedes_decision_id`
(`decision.rs:227`) and an `Active`/`Superseded` lifecycle
(`decision.rs:165-170`), and the store flips the predecessor only after
verifying it is currently `Active`
(`crates/platform/chio-store-sqlite/src/receipt_store/underwriting_credit.rs:34-99`).

Charters exist in `crates/trust/chio-governance/src/generic.rs`:
`GenericGovernanceCharterArtifact` (line 133, schema at line 12) declares an
authority scope and allowed case kinds but is single-operator (one
`governing_operator_id`, line 136) with no signer set or threshold; its cases
already model `supersedes_case_id` (line 208). WS8 reuses the charter concept
and generalizes the signer model to m-of-n. Signing is `SignedExportEnvelope<T>`
(`crates/core/chio-core-types/src/receipt/lineage.rs:407`), single-signer
(`sign` at 421, `verify_signature` at 431), so m-of-n is expressed as m
independent approval envelopes, not one multi-signer object. Money is
`MonetaryAmount` (`crates/core/chio-core-types/src/capability/scope.rs:54`,
integer `units: u64` plus ISO currency). The central `ChioConfig`
(`crates/platform/chio-config/src/schema.rs:11`) has no economic fields, and no
`chio-fiscal` schema directory exists yet under `spec/schemas/`.

## In scope

1. A `FiscalDomain` enum over the governed parameter domains: fee schedules,
   tier limit tables, discount curves, penalty rates, premium schedules.
2. Typed, integer-only parameter payloads per domain, mirroring the shapes of
   the constants and artifacts they replace (`u64` minor units, integer basis
   points; no floats).
3. A `FiscalCharter` artifact declaring the governed domains, an explicit
   signer set, and amendment rules (approval threshold, timelock, supersession
   lineage requirements).
4. A `FiscalSchedule` artifact: a typed parameter set bound to its charter by
   digest, with a monotonic schedule sequence, explicit validity window, and
   supersession lineage.
5. Amendment lifecycle artifacts: `FiscalProposal`, `FiscalApproval`
   (per-signer), `FiscalActivation` (aggregates m-of-n approvals, valid only
   after the timelock).
6. A pure resolver returning `Governed` or an explicit `Fallback`, plus
   consumption at the appraisal, underwriting, and open-market call sites.
7. Fail-closed verification for every transition, with the never-brick
   fallback invariant tested at each call site.
8. A `fiscal.amendment_activate` action class proposed for
   `spec/CHIO_LADDER.md` 5.2 with its governance mode.

## Out of scope (explicit cuts)

- No treasury, currency issuance, custody, or value movement. Activation
  changes parameters; it never moves or holds funds.
- No token, no on-chain surface, no kernel-side business logic, and no change to
  the kernel metered-budget path or `FinancialReceiptMetadata`. WS8 lives in a
  pure contract crate plus store and comptroller-plane wiring, offline from the
  kernel dispatch path (shared invariant 4).
- No cross-federation parameter recognition. A charter governs one operator's
  own scope; treaty-level recognition of a peer's schedule is future work.
- No rewrite of the consumer pricing formulas. WS8 supplies the inputs; each
  consumer's arithmetic is unchanged apart from reading resolved parameters
  instead of the constant.

## Design

### Artifact family (schema ids `chio.fiscal.<artifact>.v1`)

All artifacts are canonical JSON (RFC 8785), signed as `SignedExportEnvelope`,
with schema-id constants and JSON schemas under `spec/schemas/chio-fiscal/`.
Ids are deterministic `sha256` digests over the canonical body, matching the
existing builders (`fee_schedule.rs:170`, `generic.rs:416`).

- `chio.fiscal.charter.v1` (`FiscalCharter`): `charter_id`,
  `governing_operator_id`, `governed_domains: Vec<FiscalDomain>`,
  `signer_set: Vec<PublicKey>`, `approval_threshold: u32` (the n of m, where m
  is `signer_set.len()`), `timelock_epochs: u64`, `issued_at`, optional
  `expires_at`, `issued_by`. Validation: threshold in `1..=m`, signer set
  non-empty and distinct, at least one governed domain, `expires_at >
  issued_at`.
- `chio.fiscal.schedule.v1` (`FiscalSchedule`): `schedule_id`, `charter_id`,
  `charter_digest` (sha256 of the signed charter), `domain: FiscalDomain`,
  `params: FiscalParams`, `sequence: u64`, optional `supersedes_schedule_id`,
  `valid_from: u64`, optional `valid_until: u64`, `issued_at`, `issued_by`.
  `FiscalParams` is an enum whose active variant must match `domain`.

`FiscalParams` variants are integer-only, each mirroring one constant family:
`TierLimits { ceilings: [u64; 4], currency }` mirrors `MARKETPLACE_TIER_LIMIT_UNITS`
(validated monotonically non-decreasing); `DiscountCurve { basis_points: [u32; 4] }`
mirrors `TIER_DISCOUNT_PER_HUNDRED` but in basis points per shared invariant 2
(each `<= 10_000`), not the per-hundred percent of the current constant (see
Open questions for the rounding-parity obligation); `PremiumSchedule { approve_bps:
[u32; 4], reduce_bps: [u32; 4], decline_floor: u32, band_floors: [u32; 3] }`
mirrors `premium_quote_for_outcome` and the `premium.rs` floors; `FeeSchedule`
mirrors `OpenMarketFeeScheduleArtifact` (three `MonetaryAmount` fees plus bond
requirements); `PenaltyRates` mirrors the open-market penalty schedule in
`crates/economy/chio-open-market/src/penalty.rs` (integer minor units and basis
points).

### Amendment lifecycle

- `chio.fiscal.proposal.v1` (`FiscalProposal`): the candidate `FiscalSchedule`
  body, a `rationale_digest` (sha256 of an out-of-band rationale document),
  `proposed_by`, `proposed_at`. It fixes the `proposal_digest` approvals sign.
- `chio.fiscal.approval.v1` (`FiscalApproval`): `proposal_id`,
  `proposal_digest`, `approved_at`, each its own single-signer envelope whose
  signer key is a member of the charter `signer_set`. m-of-n is m distinct
  approval envelopes.
- `chio.fiscal.activation.v1` (`FiscalActivation`): `proposal_id`, the new
  `schedule_id`, the `FiscalApproval` envelopes, the computed `activation_epoch
  = proposed_at + timelock_epochs`, and the `supersedes_schedule_id` pointer. It
  is well-formed only when distinct-signer approvals reach `approval_threshold`,
  every signer is in the charter set, and schedule and charter agree by digest.

Activation is verified against a `verify_at` time and never trusted before its
timelock elapses. The store applies supersession the way the underwriting store
does: the named predecessor must be currently active before it flips to
superseded, keeping the lineage a single unbroken chain.

### Resolution and consumption

Consumers call one pure resolver that returns a two-state result whose
`Fallback` arm is a first-class variant, so each call site must decide at the
type level to use its built-in default. No `Governed` value exists without a
signature-verified, in-window, correctly superseding schedule.

```rust
pub enum FiscalResolution<P> {
    Governed { schedule_id: String, sequence: u64, params: P },
    Fallback(FiscalFallbackReason),
}

pub enum FiscalFallbackReason {
    NoCharter,
    NoScheduleForDomain,
    OutsideValidityWindow,
    CharterDigestMismatch,
    SignatureInvalid,
    LineageBroken,
    DomainNotGoverned,
}

pub fn resolve_fiscal_schedule<P: FiscalDomainParams>(
    charter: Option<&SignedFiscalCharter>,
    chain: &[SignedFiscalSchedule],
    domain: FiscalDomain,
    verify_at: u64,
) -> FiscalResolution<P>;
```

Each consumer reads resolved parameters or falls back to the exact built-in
constant. For the tier table:

```rust
let ceilings = match resolve_fiscal_schedule::<TierLimits>(charter, chain, FiscalDomain::TierLimits, now) {
    FiscalResolution::Governed { params, .. } => params.ceilings,
    FiscalResolution::Fallback(_) => MARKETPLACE_TIER_LIMIT_UNITS,
};
```

The same shape wires the discount curve in appraisal, the premium bps tables and
floors in underwriting, and the fee and penalty schedules in open-market
evaluation. Because the constant stays the fallback source of truth in code, an
absent, expired, or unverifiable schedule degrades to today's behavior, not to
none.

### Integration points

- New pure crate `crates/economy/chio-fiscal` (`#![forbid(unsafe_code)]`, no
  I/O) owns the artifacts, validation, deterministic builders, and resolver,
  depending on `chio-core-types` for signing and `MonetaryAmount` and on
  `chio-governance` for charter/authority concepts.
- Persistence behind traits in `platform/chio-store-sqlite`: `fiscal_charters`
  and `fiscal_schedules` tables with the active/superseded flip modeled on
  `underwriting_credit.rs`.
- Comptroller plane: propose, approve, activate, and resolve commands under the
  existing `chio trust serve` surface and CLI, offline from kernel dispatch.
- Consumers (`compute_marketplace_credit_limit`,
  `compute_marketplace_invocation_price`, `price_premium` /
  `premium_quote_for_outcome`, open-market fee and penalty evaluation) call the
  resolver at their current call sites. No kernel-side logic is added.
- `spec/CHIO_LADDER.md` 5.2 gains `fiscal.amendment_activate`: mode
  `receipt_backed`, `destructive: false` (it emits governance evidence and
  supersedes a signed schedule; it moves no funds), `co_sign: n_of_m` with
  `co_sign_quorum` bound to the charter `approval_threshold` (scope `charter`),
  `consistency_model: totally-ordered`, `consistency_anchor: hash-chain` over
  the schedule sequence. It does not use `frost-quorum` (reserved for
  settlement); fiscal quorum is aggregated independent approvals.

### Error handling (fail-closed)

A `FiscalError` enum separates two safe outcomes. An amendment can be rejected
(wrong charter, insufficient or duplicate or non-member approvals, timelock not
elapsed, lineage gap, schedule outside its validity window, schema mismatch),
which denies the transition and leaves the prior active schedule in force. Or no
schedule resolves, and the resolver returns `Fallback` so the consumer uses its
built-in constant. Both fail closed to different safe states, and rejection and
resolution are distinct code paths so a bad activation can never strand a
consumer without parameters.

## Alternatives considered

1. Extend `chio-governance` with fiscal charters. Rejected as the primary home:
   the generic charter is listing- and case-centric and single-operator, and the
   trust crate should not grow economy-domain payloads. Its authority and charter
   concepts are still reused by depending on it.
2. New pure crate `crates/economy/chio-fiscal` reusing `chio-governance`
   authority types. Recommended: it satisfies shared invariant 4 (new families
   are pure contract crates under `crates/economy/`), keeps the resolver and
   typed payloads beside the appraisal, underwriting, and open-market consumers,
   and isolates the m-of-n extension from the trust crate.
3. Put economic fields in `ChioConfig` / `chio.yaml`. Rejected: config is
   unsigned operator input, cannot carry m-of-n approval, timelock, or
   supersession lineage, and would violate the receipt-authority and
   schema-discipline invariants.

## Claim and release framing

Implementation track within the bounded release posture. WS8 governs
parameters, not custody; it issues no token and settles nothing. The trust model
is m-of-n operator signers plus a timelock, and the design language must never
call this democratic governance or a vote. This is the first concrete economic
brick of the programmable-sovereignty ambition, which
`docs/papers/programmable-sovereignty/paper.tex` defers to after admission
semantics; WS8 stays parameters-only and imports none of that paper's formalism
or rhetoric. No public claim widens: a fiscal schedule is signed intent scoped
to one charter, and cross-federation recognition is future work.

## Testing strategy

- Artifact validation and builder determinism per schema (stable ids, canonical
  JSON round-trip), matching the existing economy-crate test style.
- Fail-closed rejection tests, one per error class: wrong charter digest,
  approvals below threshold, duplicate signer, non-member signer, timelock not
  elapsed, lineage gap, schedule outside validity window, schema mismatch.
- The never-brick invariant as the headline proof. For every domain and every
  consumer call site, a parametrized test asserts that an empty chain, an
  expired schedule, and a wrong-charter schedule each yield `Fallback` and that
  the consumer output equals the exact built-in constant; a property test
  asserts the resolver never returns `Governed` for an unverified, expired, or
  wrong-charter schedule.
- Amendment lifecycle end to end: propose, approve to threshold, activate after
  the timelock, supersede the prior schedule, and confirm the store flip only
  succeeds against a currently-active predecessor.
- Conformance coverage under `spec/schemas/chio-fiscal/` with insta snapshots
  using sorted maps for cross-environment key-order stability.
- A genesis-parity test asserting each seed schedule equals its built-in
  constant, so the governed and fallback paths cannot silently drift. The
  workspace gate passes before any phase is declared done (shared invariant 9).

## Implementation phases

1. `chio-fiscal` crate skeleton: `FiscalDomain`, the integer-only
   `FiscalParams` variants mirroring the five constant families, `FiscalCharter`
   and `FiscalSchedule` artifacts with validation, deterministic builders,
   schema constants, and JSON schemas plus conformance. No consumers wired.
2. Amendment lifecycle artifacts (`FiscalProposal`, `FiscalApproval`,
   `FiscalActivation`) with fail-closed verification, and the pure resolver with
   the `Governed`/`Fallback` result. Full unit and property tests for the
   never-brick invariant. Still offline.
3. Persistence in `chio-store-sqlite` (charter and schedule tables, active or
   superseded flip) and comptroller-plane commands (propose, approve, activate,
   resolve) under `chio trust serve`.
4. Wire the four consumer call sites to resolve-or-fallback, add
   `fiscal.amendment_activate` to `spec/CHIO_LADDER.md` 5.2, and land the e2e
   test that a governed schedule changes a consumer output while an absent or
   rejected schedule falls back to the exact built-in constant.

## Open questions

- Discount representation. The bps `DiscountCurve` and the per-hundred fallback
  constant must be pinned to identical outputs by a rounding-parity test, or the
  fallback constant restated in basis points.
- Charter signer model. m-of-n is introduced here as fiscal-only over the
  single-operator generic charter. If another workstream later needs
  multi-signer charters, the signer-set and threshold types should move to
  `chio-governance` and be shared.
- Timelock clock source. `timelock_epochs` needs a unit that does not
  reintroduce a chain dependency under the freeze. A unix-time window or a
  monotonic sequence gate is preferred over anchor epochs, and the choice sets
  the ladder entry's `consistency_anchor`.
- Ladder destructive flag. `fiscal.amendment_activate` is proposed
  `destructive: false` (no value movement), but its downstream economic effect
  could argue for `destructive: true` and a higher assurance floor.

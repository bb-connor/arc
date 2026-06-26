# Chio M2-6 - Netting Kill-Evidence, Gated Flag-Flip, and NO-BUILD Commitment

Branch: `chio/m2-build` (off `chio/m1-launch`). This is the M2-6 docs deliverable: the
fail-closed record that the single-denomination netting benefit is realized OFF-CHAIN,
that every prudential support-boundary flag stays at its default-`false` value, and that
no on-chain credit instrument or new contract is built to obtain it. Companion to
`docs/brainstorm/CHIO-M2-BUILD-SPEC.md` (the 24-task M2 spec, where M2-6 is the
NETTING docs row) and `docs/brainstorm/CHIO-TOKEN-AND-CONTRACTS-PLAN.md` (the kill
thesis this evidence closes).

## 0. Verdict

The netting/capital-allocation benefit the token theses claimed required an on-chain
credit instrument is delivered by a read-only off-chain projection over the already-signed
per-currency exposure positions, with ZERO on-chain instrument and ZERO new contract.
The three prudential netting flags (`cross_currency_netting_supported`,
`capital_allocation_supported`, `mixed_currency_netting_supported`) remain `false` by
construction and by regression lock. This is the kill-evidence against any on-chain
credit token: the benefit is computable off-chain from Chio truth that already exists.

NO-BUILD commitment: no `ChioCreditVault`, no off-TCB ledger, no new immutable
contract is constructed for netting. The off-chain collapse is the sole realization.

## 1. What was built (M2-1, code)

Commit `d89d6b75b` `feat(chio-credit): off-chain ExposureLedger single-denomination
netting collapse (M2-1)` (merge `acef4d340`), all in `crates/economy/chio-credit/`:

- `src/netting.rs` (698 lines, new) - the read-only collapse.
- `src/lib.rs` (+97) - module wiring, re-exports, and the DO-NOT-WEAKEN regression
  extension that freezes the kill-evidence.

The entry point is [`collapse_positions_to_canonical`]
(`crates/economy/chio-credit/src/netting.rs:312`). It takes the already-signed
per-currency [`ExposureLedgerCurrencyPosition`] entries and a table of rational
conversion rates, and produces an [`ExposureLedgerNettedView`] projected into the
canonical `USDC` denomination (`CANONICAL_NETTING_CURRENCY`,
`netting.rs:41`). Each position is converted into canonical units (rounding UP via
`div_ceil` so exposure is never understated), summed component-wise into one netted
position, and the single-denomination netting benefit is computed as the difference
between the segregated (per-currency) and netted (single-denomination) outstanding
capital requirements (`netting.rs:324-332`).

Key types:

- [`SingleDenominationNettingBenefit`] (`netting.rs:165`) - `segregated_outstanding_units`,
  `netted_outstanding_units`, `capital_freed_units` (always non-negative; strictly
  positive only when a mixed-currency book lets the channels offset).
- [`ExposureLedgerNettedSupportBoundary`] (`netting.rs:186`) - carries the three
  prudential netting flags straight off their fail-closed defaults, plus the projection
  markers `read_only_projection` and `prudential_book_unchanged` (both `true`) and
  `on_chain_instrument_required` / `new_contract_required` (both `false`).
- [`ExposureLedgerNettedView`] (`netting.rs:220`) - schema
  `chio.credit.exposure-ledger-netted-view.v1` (`EXPOSURE_LEDGER_NETTED_VIEW_SCHEMA`,
  `netting.rs:44`).

Fail-closed behavior: a missing conversion rate for a non-parity currency returns
[`ExposureLedgerNettingError::MissingRate`]; a zero-denominator rate returns
[`ExposureLedgerNettingError::ZeroDenominator`] (`netting.rs:48-70`). USD and USDC
resolve to one-to-one parity by default (the USD/USDC pin); every other currency must be
supplied explicitly or the collapse refuses to guess (`netting.rs:144-157`).

## 2. The kill-evidence (the benefit is real, off-chain)

The projection is pure: it does not mutate the input, mint any IOU, write any ledger, or
flip any support-boundary flag (`netting.rs:305-306`). Yet it realizes the
single-denomination benefit the token theses claimed required an on-chain instrument.

Worked example (test `single_denomination_benefit_frees_capital_on_mixed_book`,
`netting.rs` test module): a USD position with 300 pending and an EUR position with 400
reserved, at an 11/10 EUR rate. Segregated outstanding requirement is
300 (USD) + 440 (EUR converted up) = 740. Netted outstanding requirement is
max(440 reserved, 300 unsettled) = 440. Capital freed = 740 - 440 = 300. The collapse
frees 300 canonical units of capital that per-currency segregation locks up, with no
on-chain instrument.

The benefit is strictly zero on a single-currency book (test
`single_currency_book_has_zero_netting_benefit`): there is nothing to net, and the
projection says so rather than inventing a benefit. This is the fail-closed honesty
contract: the off-chain collapse never overstates what netting delivers.

## 3. The three prudential flags stay false (gated flag-flip)

The three support-boundary flags that would, if flipped, weaken the fail-closed
obligation surface are:

| Flag | Default | Lives on |
|------|---------|----------|
| `cross_currency_netting_supported` | `false` | `ExposureLedgerSupportBoundary` (`lib.rs:244`, default at `lib.rs:255`) |
| `capital_allocation_supported` | `false` | `CreditScorecardSupportBoundary` (`lib.rs:466`, default at `lib.rs:475`) |
| `mixed_currency_netting_supported` | `false` | `CapitalBookSupportBoundary` (`credit/capital_and_execution.rs:58`, default at `:66`) |

The netted view does NOT flip any of them. [`ExposureLedgerNettedSupportBoundary::default`]
(`netting.rs:196`) reads the three flags straight off the prudential defaults rather than
setting them, so any future weakening of a default is visible in the projection and caught
by the regression locks. Test `netted_view_support_boundary_flags_stay_false` asserts all
three are `false` after a mixed-currency collapse AND that they equal their respective
prudential defaults. Test `off_chain_netting_collapse_keeps_all_three_flags_false`
(`lib.rs:1017`, in the `do_not_weaken` suite) is the DO-NOT-WEAKEN lock: it builds a
mixed-currency book, confirms `capital_freed_units > 0` (the benefit is real), then
asserts all three flags are `false` and equal to the defaults.

Gated flag-flip policy: a netting flag may be flipped to `true` ONLY per
credit-denominated book, and ONLY after the off-chain collapse is proven (per
`docs/brainstorm/CHIO-TOKEN-AND-CONTRACTS-PLAN.md:67`). The collapse is that proof.
Until a book-specific, reviewed flip lands, the flags stay `false` workspace-wide; the
DO-NOT-WEAKEN suite enforces this at the type-default level, not merely at the call site.

## 4. DO-NOT-WEAKEN regression locks (M1-7 extended for M2-6)

The `do_not_weaken` module (`lib.rs:968`) freezes three credit invariants. M2-1 added
the netting-specific lock:

1. `ExposureLedgerSupportBoundary` defaults `cross_currency_netting_supported` to
   `false` (test `exposure_ledger_boundary_does_not_support_cross_currency_netting`,
   `lib.rs:995`).
2. `CreditScorecardSupportBoundary` defaults `capital_allocation_supported` to `false`
   and `cross_currency_netting_supported` to `false` (test
   `scorecard_boundary_does_not_support_capital_allocation`, `lib.rs:1004`).
3. The off-chain netting collapse realizes the benefit WITHOUT flipping any prudential
   flag, and without requiring an on-chain instrument or new contract (test
   `off_chain_netting_collapse_keeps_all_three_flags_false`, `lib.rs:1017`).

Relaxing any flag default, or minting an IOU on a zero cost, would weaken the obligation
surface; the suite fails the build if that happens. The pre-existing zero-cost IOU
invariant (tests `zero_cost_allow_receipt_mints_no_iou` and
`non_zero_cost_allow_receipt_mints_one_iou`, `lib.rs:1132-1160`) is unchanged: IOUs only
arise from a strictly non-zero charged cost, currency pinned USD/USDC.

## 5. NO-BUILD commitment (what is NOT built)

This is a docs task by spec classification (M2-6, NETTING, `docs`, not blocked). The
commitment it records is a negative one: the netting benefit is delivered without
building the things the token theses said were required. Specifically, M2-6 records that
NO:

- `ChioCreditVault` (or any new immutable credit contract) is constructed.
- off-TCB ledger is introduced; the collapse is a pure projection over the receipt log
  the kernel already signs.
- on-chain instrument is required (`on_chain_instrument_required = false`).
- new contract of any kind is required (`new_contract_required = false`).
- prudential support-boundary flag is flipped workspace-wide.

The four immutable value contracts from M1 (ChioRootRegistry, ChioEscrow,
ChioBondVault, ChioPriceResolver) are byte-unchanged by M2-1. The netting code adds two
files to `chio-credit` and touches no contract, no ABI, and no signed-body schema other
than the new read-only `chio.credit.exposure-ledger-netted-view.v1` projection (which is
not a signed obligation surface; it is a display projection).

## 6. Relationship to the recompute-gate keystone (M2-2)

The netting collapse is a projection over the exposure ledger, which is itself built from
governed receipts. The integrity of that pipeline rests on the recompute-not-trust
keystone closed in M2-2 (commit `025a7e50d`, merge `9567e95d8`):

- `verify_anchor_inclusion_proof` (`crates/economy/chio-web3/src/anchors.rs`) takes the
  committed Merkle root ONLY from the kernel-signed checkpoint statement, recomputes the
  receipt leaf from the canonical receipt body, and re-walks the audit path. An external
  EAS/SAS attestation that merely asserts a root is not admissible (negative conformance
  test `eas_attestation_not_anchoring_inclusion_proof.rs`).
- `verify_public_settlement_proof` (`settlement_proof.rs`) binds settlement and payment
  claims ONLY; a verified settlement receipt never authorizes a tool call (negative test
  `verified_x402_settlement_receipt_does_not_authorize_tool_call`, `tests.rs`).

The recompute lane is the SOLE proof lane. The netting collapse inherits this: it never
trusts a producer-asserted exposure figure, it projects from the recomputable signed
positions. Anchoring-readback and payment-as-authorization both fail closed.

## 7. Invariants carried (DO-NOT-WEAKEN, from M0/M1)

- NO new immutable contract. All support-boundary flags default-`false`; books stay
  `mixed_currency_book` (per-currency fail-closed exposure accounting is the prudential
  safeguard).
- IOUs only from non-zero cost, currency pinned USD/USDC.
- Recompute is the SOLE proof lane (anchoring-readback and payment-as-authorization both
  fail closed).
- House rules: no em dashes; fail-closed; `clippy -D warnings`; no `unwrap`/`expect` in
  non-test code; signed bodies keep canonical-JSON digest stability.

## 8. Open blockers (NOT code-executable in M2-6)

Nothing. M2-6 is unblocked docs. The gated flag-flip (Section 3) is a policy decision
for a future per-book review, not an M2-6 blocker. The prepaid SHIP track (M2-17 code
through M2-23) remains separately gated by RG-MICA, RG-CLOSEDLOOP, a named licensed
partner, and a named high-frequency customer; that track is independent of this
netting kill-evidence, which is closed.

# WS2 Design: Chio Paper (receivables factoring)

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS1 (production IOU flow) for live money movement; artifact family lands independently
- Claim track: implementation (new bounded-artifact claim; explicitly not a regulated receivables exchange)
- Branch: chio/ws2-chio-paper off main

## Goal

A signed Chio receipt whose `FinancialReceiptMetadata.settlement_status` is
`Pending` (`crates/core/chio-core-types/src/receipt/economics.rs:52`, `:119`),
with its kernel-signed IOU envelope (`IouEnvelope`,
`crates/economy/chio-credit/src/hook.rs:94`), is a verifiable receivable: a
stated amount owed by a named obligor, provable offline. Chio Paper adds an
artifact family so the operator holding such receivables can assign them at a
discount for immediate working capital, and the buyer can verify the receipt
spine, IOU digests, exposure context, and assignment history offline before
paying. The receivable is evidence; the receipt stays the only authority.

## Context

- The IOU envelope binds `receipt_id`, the obligor `tenant_id` ("the operator
  that owes the obligation", `chio-credit/src/hook.rs:71`), `amount_units`,
  `currency`, and the kernel `issuer_key` (`hook.rs:82`, `:87`). It is minted
  only for an allowed, priced, non-zero receipt (`chio-credit/src/local_account.rs:123`,
  `:130`, `:133`) whose kernel key is in the trusted set (`local_account.rs:113`).
- The seller's owed positions are the signed exposure ledger
  `SignedExposureLedgerReport` (`chio-credit/src/lib.rs:334`, `:345`, schema
  `chio.credit.exposure-ledger.v1` at `lib.rs:62`), which already models
  per-currency positions and per-receipt `settlement_status` (`lib.rs:246`,
  `:261`, `:272`).
- Pricing inputs are signed artifacts: `UnderwritingDecisionArtifact` carries
  `risk_class` and a `UnderwritingPremiumQuote` with integer `basis_points`
  (`chio-underwriting/src/decision.rs:219`, `:157`, `:229`, `:211`); the
  reputation tier is `CreditScorecardBand` plus `resolved_tier`
  (`chio-credit/src/lib.rs:357`, `:481`). The premium schedule already computes
  money with a saturating (never wrapping) u128 intermediate (`decision.rs:744`).
- Venue primitives exist: signed listings and admissibility resolution
  (`Listing`, `is_admissible_at`, `search`, `resolve_admissible_listing`,
  `chio-listing/src/discovery.rs:203`, `:227`, `:291`, `:555`) and the
  open-market penalty machine (`OpenMarketAbuseClass`, `OpenMarketPenaltyArtifact`,
  `build_open_market_penalty_artifact`, `chio-open-market/src/penalty.rs:21`,
  `:57`, `:183`) with bond classes (`chio-open-market/src/fee_schedule.rs:14`, `:56`).
- Settlement here is an observation hook, not money movement:
  `SettlementObservation` and `SettlementHook` (`chio-settle/src/hook.rs:44`,
  `:247`, `:28`). Live payment execution is WS1's dependency (program hard
  edges, `2026-07-10-agent-economy-program-design.md:64`).
- The ladder governs financial binding: `credit.facility_bind` is
  `receipt_backed`, `destructive`, `co_sign: bilateral_required`
  (`spec/CHIO_LADDER.md:680`, `:686`); unknown classes refuse (`:618`, `:620`).
  The commerce family already specifies a monotonic, digest-chained, fail-closed
  state ledger (`spec/PROTOCOL.md:1098`, `:1108`).

## In scope

1. A pure contract crate `crates/economy/chio-factor` (`#![forbid(unsafe_code)]`,
   no I/O, serde types plus deterministic validation) holding the assignment
   artifact family.
2. `ReceivableClaim` (`chio.factor.receivable-claim.v1`): digest-binds one or
   more receipt references and IOU envelope digests plus the seller's signed
   exposure-ledger digest; states single-currency face value and obligor subject.
3. `AssignmentOffer` (`chio.factor.assignment-offer.v1`): seller-signed offer
   of a claim at an asking discount in integer basis points, with an expiry.
4. `AssignmentAgreement` (`chio.factor.assignment-agreement.v1`): bilateral
   (seller and buyer) signed transfer of beneficial interest, with supersession
   lineage.
5. A per-seller monotonic, digest-chained assignment log
   (`chio.factor.assignment-log-entry.v1`) plus an `AssignmentRegistryStore`
   trait, so a receivable cannot be assigned twice without a detectable lineage
   gap or fork.
6. A deterministic, integer-only buyer-side discount derivation
   (`chio.factor.discount-quote.v1`) from underwriting risk class, premium
   basis points, and reputation band.
7. Discovery and penalty reuse: offers discoverable through the existing
   registry/discovery transport; double-assignment punishable through the
   open-market penalty machine.
8. A new ladder action class `factor.assignment_bind` (`receipt_backed`,
   `destructive: true`, `co_sign: bilateral_required`) added to
   `spec/CHIO_LADDER.md` 5.2 in the same phase, plus a receivable-assignment
   family subsection reconciled into `spec/PROTOCOL.md` 6.3.
9. Redirection intent recorded in the agreement and reconciled against the
   existing settlement observation surface (recording only; see out of scope).

## Out of scope

- Live money movement. Paying the buyer instead of the seller when the obligor
  settles requires WS1's settlement-hook and payment-adapter wiring. v1 records
  redirection intent and reconciles it; it does not execute redirected payment.
- Partial or fractional assignment. The unit of assignment is one whole
  `receipt_id`; splitting one receivable across multiple buyers is deferred so
  the receipt id remains the double-assignment detection key.
- Secondary resale (a buyer re-factoring an acquired claim). The log models
  first assignment and mutual supersession only.
- Any new Solidity, custody, escrow of assigned value, or mainnet or
  public-testnet anchoring. Optional log-head anchoring is devnet qualification
  only and never a correctness dependency (freeze discipline, program
  invariant 6).
- Cross-currency netting of a mixed-currency claim. Mixed currency fails closed.
- A regulated exchange, order book, or matching engine. Discovery surfaces
  signed offers; agreement is bilateral and off the venue.

## Design

### Artifacts and types

All money is `MonetaryAmount` (u64 minor units, ISO-4217); discounts and rates
are integer basis points. Every artifact is canonical JSON (RFC 8785) wrapped
in `SignedExportEnvelope<T>` (`crates/core/chio-core-types/src/receipt/lineage.rs:407`,
`:421`, `:431`), with a `schema` constant.

- `ReceivableClaim` (`chio.factor.receivable-claim.v1`):
  `claim_id`, `seller_id`, `obligor_subject`, `currency`, `face_value:
  MonetaryAmount`, `receipt_refs: Vec<{ receipt_id, content_hash, policy_hash }>`
  (mirroring the receipt binding the IOU already carries and the hashes
  `SettlementObservation` carries, `chio-settle/src/hook.rs:68`),
  `iou_refs: Vec<{ iou_id, iou_digest }>` where `iou_digest` is
  `sha256_hex(canonical_json(iou_envelope_body))`, `exposure_context_digest`
  (`sha256` of the `SignedExposureLedgerReport`), `beneficiary_basis`
  (see below), `built_at`. Validation is deterministic and fail-closed:
  `face_value.units` equals the sum of bound `amount_units`; `currency` equals
  every bound IOU currency; `obligor_subject` equals every bound IOU obligor;
  every bound receipt is `Pending`. Any mismatch rejects.
- `AssignmentOffer` (`chio.factor.assignment-offer.v1`): `offer_id`,
  `receivable_claim_digest`, `seller_id`, `face_value`, `asking_discount_bps:
  u16`, `min_price: MonetaryAmount` (derived from the discount, buyer-visible),
  `issued_at`, `expires_at`. Seller-signed. `expires_at > issued_at`.
- `AssignmentAgreement` (`chio.factor.assignment-agreement.v1`): body binds
  `agreement_id`, `offer_digest`, `receivable_claim_digest`, `seller_id`,
  `buyer_id`, `agreed_discount_bps`, `agreed_price: MonetaryAmount`,
  `buyer_settlement_destination_ref` (redirection intent),
  `assignment_log_seq`, `prev_log_entry_digest`,
  `supersedes_agreement_id: Option`, `effective_at`. It is co-signed by both
  operators. The co-signature uses the bilateral tree the ladder already names
  for financial binding (`spec/CHIO_LADDER.md:399`, `:686`); the artifact
  records both operator keys. A single-signer agreement is invalid.
- `AssignmentLogEntry` (`chio.factor.assignment-log-entry.v1`): `seller_id`,
  `sequence: u64` (monotonic from 0), `prev_entry_digest: Option` (`None` only
  at sequence 0), `agreement_digest`, `receivable_claim_digest`,
  `assigned_receipt_ids: Vec<String>`, `assigned_iou_digests: Vec<String>`,
  `supersedes_entry_digest: Option`, `effective_at`. Seller-signed;
  `entry_digest = sha256(canonical_json(body))`.
- `DiscountQuote` (`chio.factor.discount-quote.v1`): the buyer-side derivation
  record. Binds `receivable_claim_digest`, the underwriting decision digest,
  the scorecard digest, `resolved_discount_bps: u16`, `quoted_price:
  MonetaryAmount`, and `refused: Option<reason>`. Deterministic and pure over
  its signed inputs.

### Data flow

1. The seller assembles a `ReceivableClaim` over Pending receipts it holds,
   binding each IOU digest and its own `SignedExposureLedgerReport` digest, and
   publishes an `AssignmentOffer` through the same registry publisher,
   freshness, and search transport that lists tool servers
   (`chio-listing/src/discovery.rs:291`, `:555`); factor offers carry their own
   `chio.factor.*` schema, not the per-call `ListingPricingHint`.
2. A buyer resolves the offer, verifies the underlying receipt signatures,
   trusted kernel keys, IOU digests, and the exposure-context signature, then
   derives a `DiscountQuote` deterministically from the obligor's
   `UnderwritingDecisionArtifact` (`risk_class`, premium `basis_points`) and
   `CreditScorecardBand`. The price is
   `face_value.units * (10_000 - resolved_discount_bps) / 10_000`, computed in
   u128 and saturated to u64 (mirroring `decision.rs:744`), floored so the
   realized discount is never below the stated basis points. Higher risk class,
   premium, and weaker band each raise the discount monotonically. A `Deny` or
   `StepUp` outcome (premium withheld or not applicable), a `Critical` risk
   class, or a `Restricted` band yields `refused`, and the offer is not biddable.
3. On agreement, both operators co-sign an `AssignmentAgreement` and the seller
   appends one `AssignmentLogEntry` at `head.sequence + 1` with
   `prev_entry_digest = sha256(head)`.
4. Before paying, the buyer walks the seller's log from the presented head back
   to sequence 0 (or a trusted anchored checkpoint), verifying each signature,
   `sequence == prev.sequence + 1`, and the `prev_entry_digest` chain. It
   collects `assigned_receipt_ids` across active (non-superseded) entries; if a
   receipt id in the new claim already appears, the assignment is a
   double-assignment and refuses. Any signature failure, sequence gap, or digest
   break refuses, mirroring the monotonic fail-closed event ledger normative for
   commerce (`spec/PROTOCOL.md:1108`).
5. When the obligor later settles an assigned receipt, reconciliation correlates
   the settled `receipt_id` (`chio-settle/src/hook.rs:44`) against the registry
   and records a redirection-intent row naming the buyer's destination. v1
   records and flags; it does not move funds (see Integration points).

### Integration points

- `crates/economy/chio-credit`: consumes `IouEnvelope` and
  `SignedExposureLedgerReport` as digest-bound evidence. No change to credit
  types; `chio-factor` depends on `chio-credit`, never the reverse.
- `crates/economy/chio-underwriting`: consumes `UnderwritingDecisionArtifact`
  and `CreditScorecardBand` for the discount schedule.
- `crates/economy/chio-listing`: reuses the discovery transport for offer
  visibility. Offers stay visibility-only; agreement happens off the venue.
- `crates/economy/chio-open-market`: double-assignment (a seller appending an
  entry that re-assigns an already-active receipt, or presenting a forked log)
  is punished through `build_open_market_penalty_artifact`
  (`penalty.rs:183`) with a slashed bond. The shipped family reuses the
  existing `FraudulentListing` abuse class to avoid a wire change; a dedicated
  `OpenMarketAbuseClass::FraudulentAssignment` variant is proposed as a
  coordinated open-market schema revision in the same phase (see Open questions).
- `platform/chio-store-sqlite`: implements `AssignmentRegistryStore` (append,
  head lookup, assigned-receipt index), idempotent on `(seller_id, sequence)`
  and returning a conflict on a fork, mirroring `IouEnvelopeStore`
  (`chio-credit/src/store_binding.rs:48`).
- `chio-settle`: the reconciliation surface reads assignment entries to emit
  redirection-intent records against `SettlementObservation`. Enforcement of
  paying the buyer is bounded by WS1 and is out of scope here.
- `spec/CHIO_LADDER.md` 5.2 and `spec/PROTOCOL.md` 6.3: new action class and
  family subsection, same phase (program invariants 5 and 8).

### Error handling (fail-closed)

A single `FactorError` enum; every arm denies. `SignatureInvalid` and
`SignerUntrusted` (an underlying receipt or IOU signed by a kernel key outside
the trusted set, mirroring `local_account.rs:113`); `ClaimDigestMismatch` (a
cited receipt or IOU does not match the bound digest); `FaceValueMismatch`
(sum of IOU amounts does not equal face value); `MixedCurrency` (invariant 3);
`ObligorMismatch`; `ReceiptNotPending` (a bound receipt is `Settled`, `Failed`,
or `NotApplicable`); `BeneficiaryUnproven` (no valid beneficiary basis);
`OfferExpired`; `DiscountRefused` (risk too high, premium withheld, or band
restricted); `LineageGap` (log sequence gap or digest break); `DoubleAssignment`
(receipt id already active); `SupersessionInvalid`; `MissingCounterSignature`;
`RegistryConflict` (fork at a sequence). No panics, no `unwrap`/`expect`.

## Alternatives considered

1. New crate `chio-factor` versus extending `chio-credit`. Extending keeps the
   IOU digest logic in one place, but `chio-credit` is already large
   (`lib.rs` plus `capital_and_execution` plus `risk_reports`) and its
   lifecycle (facilities, bonds, loss lifecycle) is unrelated to assignment
   lineage. A pure crate matches the program crate pattern (invariant 4), keeps
   the dependency edge one-way (`chio-factor -> chio-credit`), and isolates the
   assignment log. Recommendation: new crate `chio-factor`.
2. Reuse the open-market bid/ask flow versus factor-specific offer and agreement
   artifacts. `bid`/`accept` (`chio-open-market/src/bidding.rs:308`, `:439`)
   mint a scoped `CapabilityToken` against a per-call pricing hint, which does
   not model a one-shot transfer of an existing receivable. Recommendation:
   reuse the discovery transport and the penalty and bond machinery, but define
   factor-specific offer and agreement artifacts.
3. Assignment log as a per-seller digest-chained ledger versus a global
   receipt-to-owner registry. A global registry gives a single lookup but
   demands a trusted global writer, which contradicts the offline,
   operator-signed evidence model. A per-seller signed chain is verifiable
   offline by any buyer and optionally anchored for cross-operator
   tamper-evidence. Recommendation: per-seller digest-chained log with an
   optional anchored head.

## Claim and release framing

Chio Paper is signed evidence of assignment intent between consenting
operators. It is not a regulated receivables exchange, not custody of assigned
value, and not a security issuance. The receipt is the only authority; the
assignment artifacts are evidence-referential and digest-bound to receipts,
IOUs, exposure context, underwriting, and the assignment log. Nothing here
claims settlement finality: the log proves who was assigned what and detects
double-assignment, but paying the buyer on settlement is bounded by WS1. Claim
track is implementation; no public claim widens implicitly (program invariant
10). Discovery and penalties reuse the disclaimers already normative in
`spec/PROTOCOL.md` 9 and 14.

## Testing strategy

- Deterministic validation units: claim digest binding, face-value
  reconciliation, single-currency and Pending-only fail-closed rejections.
- Discount derivation: a proptest that the resolved discount is monotonic in
  risk class, premium, and band; refusal on `Deny`/`StepUp`, `Critical`, or
  `Restricted`; saturating u128 arithmetic (mirroring the regression at
  `decision.rs:837`).
- Double-assignment headline proof: `assigning_one_receipt_twice_is_rejected`,
  plus a proptest across {chain length} x {insertion point} x {fresh versus
  supersede} that any gap, digest break, or fork refuses.
- Bilateral and authority: an agreement missing the buyer counter-signature
  rejects; an underlying receipt or IOU under an untrusted kernel key refuses
  (mirroring `local_account.rs:339`); a tampered claim digest refuses.
- Reconciliation: a settled receipt with an active assignment emits a
  redirection-intent record and asserts no fund movement.
- Conformance: JSON schemas under `spec/schemas/` for each `chio.factor.*.v1`,
  with insta snapshots using `sort_maps` for key-order stability.
- Workspace gate: `cargo build --workspace && cargo test --workspace && cargo
  clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

## Implementation phases

1. Crate and artifacts. Create `chio-factor` with the five artifact types,
   deterministic validation, and the `DiscountQuote` derivation. Add JSON
   schemas and conformance coverage. Pure, no store, no venue. One PR.
2. Assignment registry and lineage. Add the `AssignmentLogEntry`, the
   `AssignmentRegistryStore` trait plus the `chio-store-sqlite` implementation,
   and the supersession-chain verifier with the double-assignment headline
   proof. Add `factor.assignment_bind` to `spec/CHIO_LADDER.md` 5.2 and the
   receivable-assignment subsection to `spec/PROTOCOL.md` 6.3.
3. Venue and reconciliation. Offer discovery through the registry transport,
   double-assignment penalties through the open-market machine (reusing
   `FraudulentListing`, proposing the dedicated variant), the CLI surface, and
   redirection-intent recording against the settlement observation surface.
4. Optional anchoring (devnet only). Include the per-seller log head in a
   `KernelCheckpoint` and anchor it through the existing checkpoint machinery
   for cross-operator tamper-evidence, never as a correctness dependency.

## Open questions

1. Beneficiary binding. The base `FinancialReceiptMetadata` plus `IouEnvelope`
   path does not name a creditor; only the richer economic envelope does
   (`EconomicPayeeReceiptMetadata`, `economics.rs:170`). The receipt spine
   proves the obligation, amount, and obligor, but not which operator owns it.
   v1 records a `beneficiary_basis` on the claim (`receipt-proven` when a payee
   envelope is present, else `exposure-context` from the seller's signed
   ledger) and fails closed when neither holds. A kernel-signed payee field on
   the base path is a stronger follow-up. Recommendation: ship the two-basis
   model and flag the exposure-context basis as the weaker one.
2. Abuse-class extension versus wire compatibility. A dedicated
   `OpenMarketAbuseClass::FraudulentAssignment` variant changes the
   `chio.registry.market-penalty.v1` surface and would break exhaustive
   consumers. Recommendation: ship on `FraudulentListing` with a factor-side
   evidence reference, and land the dedicated variant as a coordinated
   open-market revision in the same phase.
3. Bilateral primitive reuse. Whether `chio-federation`'s bilateral tree
   (`spec/CHIO_LADDER.md:399`) exposes a two-party co-signature usable by an
   economy artifact, or whether `chio-factor` needs its own two-signature
   envelope, must be settled by reading `bilateral.rs` at implementation time.
4. Anchoring under freeze. With anchoring devnet-only, v1 claims no
   cross-operator tamper-evidence beyond the per-seller signed chain. Confirm
   that the log chain alone is the shipped authority and anchoring stays
   qualification-environment defense-in-depth.

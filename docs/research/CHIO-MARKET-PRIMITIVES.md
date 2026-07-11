# Chio Market Primitives - The Canonical Taxonomy

Status: reconciliation decision doc. Author: chief economist.
Scope: reconcile the five-framework economist panel (E1 property-rights/ERTP, E2 microstructure,
E3 two-sided-platform, E4 risk/insurance, E5 information economics) plus the six market surveys into
ONE canonical taxonomy of the concrete goods, assets, rights, and services that present on Chio's
marketplaces, each grounded in shipped code on `chio/autonomous-commerce-brainstorm`.

Method: dedupe across lenses (the same primitive seen four ways becomes one entry), resolve
disagreements, and call each item a true market primitive or a derived/composite facet. Every entry
is tagged realized / designed / implied-missing.

Cross-references (read these, not repeated here):
- `docs/brainstorm/CHIO-TOKEN-COMMERCE-ALIGNMENT.md` (the SHIPPED commerce primitives the plans bind to; the single-slash-lane, single-source-capital, recompute-not-trust invariants).
- `docs/brainstorm/CHIO-BENEVOLENT-TOKEN-DESIGN.md` and `docs/brainstorm/CHIO-PASS-M0-SPEC.md` (the gift/Pass subsidy model: Half A gifted feeds, Half B metered compute, `freetier:global:<window>` pool).

Reconciliation note on "bid": the open market's `BidRequest.max_price_per_call` is NOT a competitive
bid. It is a reservation-price clamp; `bid()` always clears at the provider's posted
`advertised_price` (`crates/economy/chio-open-market/src/bidding.rs:365,429`) or fails closed
`BidCeilingTooLow` (`:369-370`). Chio has NO auction, NO order book, NO double-sided price discovery
anywhere. Read "bid/quote" throughout as RFQ-at-posted-price.

---

## 1. Executive summary: the canonical list

29 realized primitives, deduped across the five frameworks, grouped by layer. One line each. The
catalog (Section 3) grounds each in code. Implied-missing primitives are in Section 5.

### Access / capability layer (the atomic tradeable rights)
- **A1 Capability token** - the unforgeable, subject-bound, time-bounded, cost-capped right to invoke tool X on server Y N times. THE atomic market good; authority is a signed reference, not a ledger entry. (`CapabilityToken`, `chio.capability.v1`.)
- **A2 Funds/budget reservation hold** - the pre-trade margin lock that makes the buyer's exposure offer-safe before a token is accepted. (`ReservationReceipt` + `budget_reserved`.)
- **A3 Delegated spending mandate** - a capped, occurrence-limited, cross-rail authority to PAY on the principal's behalf. (`CommerceMandateAllowanceLedger`.)
- **A4 Governed approval token** - a single-shot threshold-triggered approval that converts an ambient high-value action into an explicitly minted right. (`GovernedApprovalToken`.)
- **A5 Metered consumption record** - the per-invocation true-up unit; the settlement basis and the moral-hazard resolver. (`CostMetadata`, `chio.cost-metadata.v1`.)

### Provider / service layer (discovery, admission, match)
- **P1 Provider/tool listing** - the visibility-only discovery good; being listed confers ZERO authority. (`GenericListingArtifact`; also `LiabilityProviderArtifact` for carriers.)
- **P2 Posted-price ask** - the seller-set, separately-signed standing per-call price decoupled from the listing. (`SignedListingPricingHint.price_per_call`.)
- **P3 Trust-activation / admission right** - the explicit, class-gated authority that turns a visible listing into an admitted participant. (`GenericTrustActivationArtifact`.)
- **P4 Provider selection (match/award right)** - the order-bound award to one provider, ranked by trust score. (`ProviderSelectionReport` + `TrustScorecardSnapshot`.)
- **P5 Binding priced quote + SLA commitment** - the firm, TTL-stamped priced offer carrying a service-level obligation. (`quote_*` fields + `chio.commerce.sla-commitment.v1`.)
- **P6 Venue fee tariff** - the platform take: flat publication / dispute / participation fees, not ad-valorem. (`OpenMarketFeeScheduleArtifact`.)
- **P7 Participation bond + capped slash** - refundable, slashable seller collateral that internalizes spam/fraud externalities. (`OpenMarketBondRequirement` -> `OpenMarketPenaltyArtifact`.)

### Risk / coverage layer (risk transfer as a tradeable good)
- **R1 Pricing authority (right-to-quote-and-bind)** - the capacity-capped Mint for coverage rights; you cannot underwrite beyond committed capital. (`LiabilityPricingAuthorityArtifact`.)
- **R2 Coverage quote + premium** - the priced, TTL-bound RFQ response; premium is a deterministic compliance-score band, not actuarial. (`LiabilityQuoteResponseArtifact` + `price_premium`.)
- **R3 Bound coverage policy** - the matched/sold risk-transfer right: contingent indemnity against metered-execution liability. (`LiabilityBoundCoverageArtifact`.)
- **R4 Claim / adjudication / payout chain** - the exercise of the coverage option through dispute, adjudication, and custody-neutral payout. (`LiabilityClaimPackageArtifact` -> settlement receipt.)
- **R5 Credit facility + capital book** - the committed underwriting capacity and the source-of-funds ledger that back all coverage. (`CreditFacilityArtifact` + `CapitalBookReport`.)
- **R6 Reserve + credit bond (collateral backing)** - segregated, conservation-enforced collateral that makes promises credible. (`CreditBondArtifact` + reserve lock/hold/release.)
- **R7 Slash / sanction instrument** - the single authorized lane that terminally consumes collateral on breach. (`RiskSanctionReserveLedgerEntry`, lane `market_slash` + `RiskSanctionBridge`.)
- **R8 Comptroller solvency report** - the regulator fold that proves the book is solvent and reconciled. (`RiskComptrollerReport`, folds exposure ledger, loss lifecycle, actuarial backtest, tier ceiling.)

### Trust / attestation / data layer (information goods)
- **T1 Signed receipt + anchored evidence** - the information atom every higher-order good is derived from; anchoring is the verifiability premium. (`ChioReceipt` + `AnchorProofBundle`.)
- **T2 Reputation scorecard / trust score** - the verifier-RECOMPUTED screening signal that IS the discovery-ranking score. (`LocalReputationScorecard` -> `TrustScorecardSnapshot` -> `ReputationTier`.)
- **T3 Portable reputation credential** - the only reputation object that changes hands across operators; cannot prove collateral/solvency. (`SignedPortableReputationSummary` -> `ReputationImportReport`.)
- **T4 Chio Pass / Agent Passport** - the gifted, soulbound admission credential and live metering anchor; the subsidized-side entry key. (`AgentPassport` + `TrustTier`.)
- **T5 Verified attestation** - the fail-closed provenance screen that distinguishes a genuine attested provider from a self-described one. (`VerifiedAttestation` / `VerifiedQuote`.)
- **T6 Trust-signal pheromone** - congestion-priced emission + gifted aggregate; the only genuine capacity price in the codebase. (`PheromoneDeposit` -> `PheromoneConcentration`, `PheromoneScarcityPolicy`.)
- **T7 Data-stream disclosure bundle** - own-data access whose price is denominated in bits of leakage, not money. (`DisclosureLineageBundle` + `DisclosureLeakageLedger`.)
- **T8 Gifted feed tier + metered free-compute allotment** - the two-halves subsidy: zero-mint Read/Subscribe feeds (Half A) plus a pre-funded compute grant (Half B). (Pass `ResourceGrant{Read,Subscribe}` + `ToolGrant`.)

### Settlement / capital layer (clearing and the closed loop)
- **S1 Payment lifecycle proof** - verified payment-satisfaction; payment success NEVER implies tool authorization. (`CommercePaymentLifecycle`.)
- **S2 Settlement packet + custody-neutral finality** - the cleared-transfer instrument plus the deliberate split between transfer INTENT and observed FACT. (`CommerceSettlementPacket`; `CapitalExecutionInstruction` vs `CapitalExecutionObservation`; USDC rails.)
- **S3 Order-passport** - the portable, selectively-disclosable credential that aggregates the whole chain and closes the flywheel back into T2 ("receipts are the new reputation"). (`CommerceOrderPassportReport`.)

Derived/composite facets folded into their parent primitive (NOT separate primitives): attenuated
sub-grant and first-party caveats (divisibility/restriction modifiers of A1); deterministic ranking
sort and price-dispersion index (information views over P1/P2, see Section 4); auto-bind disposition
(the matching rule of R3); exposure ledger, loss lifecycle, actuarial backtest, tier ceiling
(components of R8); carrier admission listing (P1 with `actor_kind=LiabilityProvider`).

---

## 2. The market map: what is created and tradeable at each lifecycle stage

The order/settlement spine is a hard-coded, digest-bound state machine
(`chio-commerce-order/src/replay.rs:541` `is_allowed_transition`):
`none -> intent_recorded -> provider_admitted -> quote_bound -> mandate_bound -> budget_reserved ->
payment_challenged -> payment_verified -> fulfillment_requested -> fulfillment_attested ->
settlement_packet_assembled -> settlement_dispatched -> settlement_observed -> settlement_reconciled
-> completed` (+ `disputed/refunded/failed_closed`). Each hop mints a signed artifact whose sha256 is
pinned into `CommerceOrderContext`. The risk/coverage market runs as a parallel overlay pinned via
`CommerceCoverageRequirement`.

| Lifecycle stage | Primitive created / made tradeable | Realized? |
| --- | --- | --- |
| Passport (admission) | **T4** Pass presented; **T5** attestation; **T1** receipt corpus is the priceable substrate | realized |
| Discovery | **P1** listing (visibility-only) + **P2** posted-price ask; **T2/T3/T6/T7/T8** trust+data feeds gifted to power search | realized |
| Selection | **P3** trust-activation right (admit) then **P4** selection/award right (`total_score == computed_score`) | realized |
| Quote / bid | **A1** capability token MINTED into `AskResponse.token_offer` at posted price; **P5** quote+SLA; **R1/R2** pricing authority + coverage quote on the overlay | realized |
| Mandate | **A3** spending mandate (`mandate_bound`); **A4** governed approval if over threshold | realized |
| Budget hold | **A2** reservation/budget hold (`budget_reserved`); coverage backed by **R5/R6** facility+bond | realized (atomic single-ledger reservation is a flagged gap) |
| Fulfillment | **A1** exercised; **A5** metered consumption recorded against budget | realized |
| Settlement | **S1** payment proof -> **S2** settlement packet + custody-neutral intent/observation; **P6** fee, **P7** bond settle | realized (on-chain broadcast prepare-only, off) |
| Coverage / claim | **R3** bound policy; **R4** claim->adjudication->payout; **R7** slash; **R8** comptroller fold gates solvency | realized (live multi-source capital market designed) |
| Loop close | **S3** order-passport emitted -> feeds **T1/T2** -> raises counterparty tier -> next discovery | realized |

The cleanest "actual asset listed and sold" is **A1** at quote/bid. The cleanest property-rights design
is **P3** severing discovery from authority. The load-bearing externality loop is
`ChioReceipt (T1) -> scorecard (T2) -> tier -> discovery visibility -> more receipts`, closed by **S3**.

---

## 3. Primitive catalog

Format per entry: what it is; code grounding; economic class; rivalry/excludability/fungibility/
durability; buyers/sellers; market presentation; price formation; composes with; status.

### Access / capability

#### A1. Capability token (the atomic tool-access right)
- **What.** The unforgeable, subject-bound (DPoP), time-bounded, cost-capped right to invoke tool X on server Y up to N times. Authority IS the signed reference. This is the good the bid/ask flow mints and sells.
- **Grounding.** `CapabilityToken` (`chio.capability.v1`, `crates/core/chio-core-types/src/capability/token.rs:51`), payload `ChioScope` of `ToolGrant`/`ResourceGrant`/`PromptGrant` (`scope.rs`). Divisibility via the `is_subset_of` lattice and `delegate()` -> `DelegationLink` (`attenuation.rs`), proven monotone non-amplification by proptests `delegate_strictly_weakens` / `delegate_chain_extension_monotone` / `delegate_revoked_parent_revokes_children`. First-party `Caveat`/`CaveatKind` (`caveat.rs`) are restriction modifiers carried under the signature.
- **Class.** Right / access-credential.
- **Properties.** Rival and excludable (subject-bound to one holder key, finite `max_invocations`/`max_total_cost`); unique (UUIDv7 id for revocation); perishable (`expires_at`); fungible only within an identical scope class; DIVISIBLE down a delegation chain (rights can only weaken).
- **Who.** Seller = provider / Capability Authority (issuer). Buyer = the agent named in `subject`.
- **Presents.** Minted as `AskResponse.token_offer` at quote time (`bidding.rs:430`); bound for settlement by `AcceptedBid`.
- **Price formation.** Posted price. `bid()` clears at `advertised_price` (`bidding.rs:429`); the buyer's `max_price_per_call` is only a fail-closed clamp.
- **Composes.** Wraps `ChioScope`; metered by **A5**; held safe by **A2**; spent under **A3**; gated by **A4**.
- **Status.** Realized (primary mint). Attenuated sub-grants are realized in the algebra but have NO market surface; resale to a non-subject is forbidden (`delegate()` requires delegator == parent.subject) -> secondary market implied-missing (Section 5).

#### A2. Funds/budget reservation hold (the offer-safety margin leg)
- **What.** The buyer-side pre-commitment that makes the exchange offer-safe: before a token is accepted the agent must hold a reservation covering the token's FULL aggregate liability in the matching currency.
- **Grounding.** `ReservationReceipt`/`VerifiedReservationReceipt` (`chio.marketplace.reservation-receipt.v1`, `bidding.rs:216`); `accept()` requires `reserved_amount >= token_offer_total_liability` and `acceptor == token_offer.subject` (`bidding.rs:476`). Order-side `budget_reserved` event backed by `BudgetEnforcer`/`BudgetTree`/`WorkflowBudgetPool` + kernel `budget_store`.
- **Class.** Asset (reserved exposure claim / initial margin); risk-transfer (offer-safety guarantee).
- **Properties.** Rival/excludable (specific `reserved_amount` bound to one `ask_digest`); single-use against one acceptance; perishable (consumed inside the ask validity window).
- **Who.** Buyer posts it; a reservation authority signs it; it gates the seller's `AcceptedBid`.
- **Presents.** Settlement-precondition leg checked inside `accept()`; a signed receipt, not custody.
- **Price formation.** Deterministic band (amount = recomputed `token_offer_total_liability`; under-reservation fails closed).
- **Composes.** `AskResponse.token_offer`, `AcceptedBid`; upstream of **S1/S2**.
- **Status.** Realized procedurally. NOT custodial: there is no escrow holding both legs. The atomic single-ledger reservation is the flagged launch gap (CHIO-AUTONOMOUS-COMMERCE Risk 1); see Section 5.

#### A3. Delegated spending mandate (capped cross-rail payment authority)
- **What.** A transferable right to PAY up to a bound on the agent's behalf: a capped, occurrence-limited allowance with cross-protocol payment projections. ERTP purse with a hard withdrawal limit and single-use flag.
- **Grounding.** `CommerceMandateAllowanceLedger` (`chio.commerce.mandate-allowance-ledger.v1`, `chio-commerce-order/src/mandate.rs:26`): `max_amount_minor`, `single_use`, `used_occurrences`/`max_occurrences`, `ap2_*`/`acp_delegated_payment_token_hash`/`x402_payment_requirements_hash`, `protocol_projections` (allowlist `ap2|acp-commerce|x402|chio`).
- **Class.** Right (delegated spend authority).
- **Properties.** Rival/excludable; quantity-limited; `single_use` enforces exactly-one consumption; non-fungible (bound to one order/intent).
- **Who.** Buyer-principal mints/grants to its own agent; PSP/rail consumes; never proves provider authorization on its own.
- **Presents.** `mandate_bound` stage; digest-pinned into `CommerceOrderContext`.
- **Price formation.** Deterministic band (caps the clearing price; fails closed if `max_amount_minor < quote_amount_minor` or occurrence limits exceeded).
- **Composes.** `quote_*`, **S1/S2**, X402/EIP-3009 bindings; gated by **A4** via `Constraint::RequireApprovalAbove`.
- **Status.** Realized (hashed projections). Live AP2/ACP/x402 verify transcripts designed.

#### A4. Governed approval token (single-shot threshold approval)
- **What.** A discrete, non-reusable approval bound to exactly one governed intent and one request, required when a grant's value crosses a configured threshold. The mechanism-design tripwire converting an ambient high-value action into an explicitly minted right.
- **Grounding.** `GovernedApprovalToken`/`GovernedApprovalTokenBody` (`chio-core-types/src/capability/governance.rs`); triggered by `Constraint::RequireApprovalAbove` / `GovernedIntentRequired` / `RequireDualApproval` (`scope.rs`); recorded via `GovernedApprovalReceiptMetadata`.
- **Class.** Right (authorization).
- **Properties.** Rival/excludable and linear (bound to one `governed_intent_hash` + `request_id`, cannot be replayed); perishable (`expires_at`).
- **Who.** Issued by an approver (human or governance role) to the subject agent; consumed once at execution. Not bought/sold; an internal-authority grant.
- **Presents.** An approval precondition discharged against a constraint at invocation.
- **Price formation.** Deterministic band (threshold-triggered gate; no price).
- **Composes.** `Constraint::RequireApprovalAbove` on a `ToolGrant`; **A3** for spend-side actions.
- **Status.** Realized.

#### A5. Metered consumption record (the settlement-basis true-up)
- **What.** A signed per-invocation record of what was actually consumed across cost dimensions, reconciled against the ex-ante quote/reservation. Where **T2** resolves pre-contract adverse selection, this resolves post-contract moral hazard: the provider cannot silently over-bill because the Chio verifier RECOMPUTES consumption rather than trusting the invoice.
- **Grounding.** `CostMetadata` (`chio.cost-metadata.v1`, `chio-metering/src/cost.rs`) over `CostDimension` (`ComputeTime`/`DataVolume`/`ApiCost`/`WarehouseQuery`/`Custom`); enforced by `BudgetEnforcer`/`BudgetPolicy` -> `BudgetViolation` (`budget.rs`).
- **Class.** Service / information-good (verifiable consumption record).
- **Properties.** Rival (real resource use), excludable, perishable per invocation; non-rival as a recomputable record.
- **Who.** Seller reports usage; buyer's budget enforces the ceiling; verifier recomputes.
- **Presents.** Settlement leg: per-invocation cost reconciled against quote/reservation; the (metered actual - reserved notional) delta is the settlement basis.
- **Price formation.** Posted price metered ex-post (spot usage at advertised rates), true-up against reserved notional.
- **Composes.** Trues up **A2** and **P2**; feeds **S2** reconciliation and the reliability components of **T2**.
- **Status.** Realized. The quote/actual delta is basis risk that no one prices or trades (no metering instrument).

### Provider / service

#### P1. Provider/tool listing (visibility-only discovery good)
- **What.** A discoverable provider/actor offering. The single most ERTP-correct design in the codebase: a listing confers ZERO authority. Being discoverable is non-excludable and cheap; authority must be separately, explicitly minted (**P3**). This internalizes the trust externality and enforces no-ambient-authority/POLA.
- **Grounding.** `GenericListingArtifact` (`chio.registry.listing.v1`, `chio-listing/src/listing.rs`), `GenericListingSubject.actor_kind` in {`ToolServer`,`CredentialIssuer`,`CredentialVerifier`,`LiabilityProvider`}; hard `GenericListingBoundary {visibility_only:true, explicit_trust_activation_required:true, automatic_trust_admission:false}` (`listing.rs:68-76`). Carrier variant: `LiabilityProviderArtifact` (`chio.market.provider.v1`) discovered via `LiabilityProviderListReport`/`ResolutionReport`.
- **Class.** Information-good (a discovery view).
- **Properties.** Non-rival, non-excludable within tier-0 discovery; deterministic/reproducible; the listing slot is unique per registry entry.
- **Who.** Seller = namespace owner (`GenericNamespaceOwnership`); buyer = any searching agent.
- **Presents.** Discovery: `search()` -> `ListingSearchResponse.results` ranked by `Listing.rank`; `compare()` -> `ListingComparison.price_index_bps`.
- **Price formation.** Deterministic rank (price asc, `revocation_rate_bps` asc, `recent_receipts_volume` desc, origin, listing_id). The venue performs no crossing and forms no price; competition is cross-listing only.
- **Composes.** Carries **P2**; gates into **P3** and **A1**; the carrier listing carries **R2**.
- **Status.** Realized. Deterministic ranking sort and `price_index_bps` are derived views over this primitive, not separate primitives (Section 4).

#### P2. Posted-price ask (the standing quote)
- **What.** The seller-set standing price for one tool/resource invocation, published as a signed artifact decoupled from the listing. The canonical price-formation primitive of the access market: a unilateral posted ask, no counter-quoting, no spread, no inventory.
- **Grounding.** `ListingPricingHint`/`SignedListingPricingHint` (`chio.marketplace.listing-pricing-hint.v1`, `chio-listing/src/discovery.rs`): `price_per_call: MonetaryAmount`, `ListingSla`, `revocation_rate_bps`, `recent_receipts_volume`; bound by `validate_pricing_hint_listing_authority`.
- **Class.** Right (priced access right) posted as an information-good quote; also a Spence quality-disclosure signal (`revocation_rate_bps` is realized-defect disclosure, `recent_receipts_volume` is the costly receipt-backed history signal).
- **Properties.** Non-rival as a quote; excludable good behind it; fungible per-call unit; perishable via freshness window.
- **Who.** Seller sets it; buyer reads it. No intermediary in price formation.
- **Presents.** Quote: a standing posted ask attached to a listing.
- **Price formation.** Posted price (seller-administered, take-it-or-leave-it).
- **Composes.** Binds to **P1**; consumed by the **A1** clearing and the **P1** ranking sort; clamps `BidRequest.max_price_per_call`.
- **Status.** Realized. The verifiability-graded access price (a quality premium on the access right itself) is implied-missing (Section 5).

#### P3. Trust-activation / admission right (curation good)
- **What.** The explicit activation that converts a visibility-only listing into an admitted participant, tiered by admission class. Cheap public discovery, costly explicit admission. The platform's curation lever and its no-ambient-authority enforcement.
- **Grounding.** `GenericTrustActivationArtifact` (`chio.registry.trust-activation.v1`, `chio-listing/src/trust_activation.rs`) with `GenericTrustAdmissionClass` {`PublicUntrusted`,`Reviewable`,`BondBacked`,`RoleGated`}; `evaluate_generic_trust_activation` -> `GenericTrustActivationEvaluation { admitted }`. `BondBacked` stays review-visible only until bond backing is proven.
- **Class.** Right (admission) / access-credential.
- **Properties.** The listing it sits on is non-rival; the activation right is excludable and class-gated.
- **Who.** Granted by a curator/verifier to a seller; a precondition the buyer relies on but does not purchase.
- **Presents.** Discovery -> separate explicit activation verdict; never bundled into the listing.
- **Price formation.** Deterministic band (admission rules; `BondBacked` requires proven collateral via **P7**/**R6**).
- **Composes.** Rides on **P1**; `BondBacked` composes with **P7**; bounded by `GenericListingBoundary.automatic_trust_admission=false`.
- **Status.** Realized.

#### P4. Provider selection (trust-weighted match/award right)
- **What.** The order-bound award of one provider. Matching is by trust: `RankingResult.total_score` is forced to equal the recomputed `TrustScorecardSnapshot.computed_score`; rank-1 is mandatory absent an `override_receipt_ref`. Price (the quote) is bound on a SEPARATE leg, so selection optimizes trust, not price-trust jointly.
- **Grounding.** `ProviderSelectionReport` (`chio.commerce.provider-selection-report.v1`) over `ProviderCandidate`/`ProviderDiscoverySnapshot`; `validate_selection` forces `total_score == computed_score` and binds to passport/order/discovery ids (`chio-trust-market-context/src/artifacts.rs:504`).
- **Class.** Right (award/match right).
- **Properties.** Rival award (one `selected_provider_subject` per order), excludable, unique per order.
- **Who.** Buyer/order side selects; trust scorecard supplies the ranking input.
- **Presents.** Selection stage, bound to passport/order/discovery ids.
- **Price formation.** Oracle (the recomputed trust score is the ranking key); match-price decoupled.
- **Composes.** Consumes **T2** + **T3**; binds to **P5** (`price_quote_ref`, `sla_commitment_ref`); feeds `CommerceOrderContext`.
- **Status.** Realized. Single-metric chokepoint (visibility and award both ride one composite score).

#### P5. Binding priced quote + SLA commitment
- **What.** A firm, time-limited priced offer carrying a service-level obligation. Economically the seller writes the buyer a free short-dated option (firm until `expires_at`, no option premium, no last-look).
- **Grounding.** `quote_id`/`quote_amount_minor`/`quote_currency`/`quote_sha256` in `CommerceOrderContext` + `SlaCommitment` (`chio.commerce.sla-commitment.v1`); `LiabilityQuoteTerms.expires_at` rejects `issued_at > expires_at` (`chio-market/src/placement.rs:85`); listing freshness via `GenericListingFreshnessWindow`.
- **Class.** Right (a firm-quote option held by the buyer) + service (SLA obligation).
- **Properties.** Excludable, perishable (`expires_at`); fungible within currency.
- **Who.** Seller writes the option implicitly; buyer holds it free.
- **Presents.** Quote stage (digest-bound); the richer standalone `chio.commerce.quote.v1` is designed.
- **Price formation.** Posted price with expiry.
- **Composes.** Wraps **P2** / **R2**; consumed by auto-bind and the **A1**/**A2** clearing.
- **Status.** Realized (digest-bound). Quote-option premium / last-look is implied-missing (Section 5).

#### P6. Venue fee tariff (the take-rate)
- **What.** The platform's monetization instrument: FLAT per-action fees set by the governing operator. An access tariff, not an ad-valorem commission on transacted value.
- **Grounding.** `OpenMarketFeeScheduleArtifact` (`chio.registry.market-fee-schedule.v1`, `chio-open-market/src/fee_schedule.rs:79`): `publication_fee`, `dispute_fee`, `market_participation_fee`; `governing_operator_id`, scoped by `OpenMarketEconomicsScope`.
- **Class.** Right / service (venue access fee).
- **Properties.** A price, not a good; non-rival schedule, excludable enforcement; durable.
- **Who.** Platform (intermediary) charges the seller side to publish, either side to dispute. The realized take falls asymmetrically on sellers.
- **Presents.** Posted tariff binding all participants (`mandate` stage).
- **Price formation.** Posted price (administered, governance-set).
- **Composes.** Gates **P1** publication and dispute filing; pairs with **P7**.
- **Status.** Realized as artifact; the collection rail (`FeeRouter`/`ChioTreasury`) is unbuilt. Ad-valorem GMV commission is implied-missing (Section 5).

#### P7. Participation bond + capped slash (seller skin-in-the-game)
- **What.** Refundable, slashable collateral a seller posts to publish/list/dispute, internalizing the spam/fraud externality. The asymmetric counterpart to the subsidized buyer side. Penalty pricing is bounded and governance-gated, not market-set.
- **Grounding.** `OpenMarketBondRequirement` (`OpenMarketBondClass` Publication/Listing/Dispute, `slashable`) backed by `CreditBondArtifact`; enforcement `OpenMarketPenaltyArtifact` (`OpenMarketAbuseClass`, `OpenMarketPenaltyAction` HoldBond/SlashBond/ReverseSlash); `evaluate_open_market_penalty`, capped at the bond (`PenaltyAmountExceedsBond` fail-closed). Slash routes through the single comptroller lane (**R7**).
- **Class.** Asset (refundable collateral) with embedded risk-transfer.
- **Properties.** Rival (locked capital), excludable, fungible money, durable while locked.
- **Who.** Seller posts; platform/governance holds; slashed on a proven `Sanction` case.
- **Presents.** Mandate (bond posting) -> settlement/collateral leg (slash entry).
- **Price formation.** Deterministic band (required amount from the fee schedule; slash capped at the bond).
- **Composes.** Satisfies **P3** `BondBacked`; slashed via **R7** lane `market_slash`.
- **Status.** Realized.

### Risk / coverage

#### R1. Pricing authority (right-to-quote-and-bind, the coverage Mint)
- **What.** The unforgeable, capacity-capped authority to MINT coverage rights. The ERTP Mint with a ceiling: whoever holds it can create risk-transfer rights only up to committed capital and facility credit, refusing mixed-currency books. Makes coverage supply incentive-compatible (you cannot underwrite beyond reserves). Expresses the underwriter/capital-provider as a genuine THIRD platform side.
- **Grounding.** `LiabilityPricingAuthorityArtifact` (`chio.market.pricing-authority.v1`, `chio-market/src/quote.rs:454-567`) binding `SignedCreditFacility` + `SignedUnderwritingDecision` + `SignedCapitalBookReport`; `validate()` caps `max_coverage_amount <= min(facility credit_limit, provider max, available committed capital)`, rejects `mixed_currency_book` (`:528`); envelope `ProviderDelegate | RegulatedRole`.
- **Class.** Right (mint authority / intermediation license).
- **Properties.** Rival/excludable; quantitatively bounded (its mint ceiling consumes finite committed capital); role-scoped.
- **Who.** Held seller-side by carriers/underwriters; the supply-side license that lets a quote and a bound policy exist.
- **Presents.** Mandate: an authority artifact pinned behind a quote, the precondition to **R2** and placement.
- **Price formation.** Deterministic band (min-of-caps rationing; capacity is rationed, not cleared; no pooled-capacity depth).
- **Composes.** **R5**, `SignedUnderwritingDecision`; emits **R2**; backs **R3**.
- **Status.** Realized. This supply-side offer-safety is STRONG and is the cleanest licensing primitive most agent-economy designs omit.

#### R2. Coverage quote + premium (priced RFQ with TTL)
- **What.** The request-for-quote and its priced, time-limited response. Premium is the price of risk transfer; it is a deterministic step function of an attested compliance score, not actuarial loss experience. This is the cleanest realization of "attestation makes risk priceable": receipts (**T1**) are the loss-experience table.
- **Grounding.** `LiabilityQuoteRequestArtifact` -> `LiabilityQuoteResponseArtifact` carrying `LiabilityQuoteTerms { quoted_coverage_amount, quoted_premium_amount, quoted_deductible_amount, expires_at }` (`chio-market/src/quote.rs`); priced by `price_premium` (`chio-underwriting/src/premium.rs`): bands `>900 -> 1.0x`, `700..=900 -> 2.0x`, `500..<700 -> 5.0x`, `<500` declined (`PREMIUM_DECLINE_FLOOR=500`); `quoted_cents = base_rate_cents * (1 + multiplier)`; missing score fails closed to `Declined`.
- **Class.** Risk-transfer (price) + service (perishable priced offer).
- **Properties.** Excludable, unique to the requesting subject; sharply perishable (`expires_at`, the adverse-selection control).
- **Who.** Agent (buyer) requests; authorized pricer (seller/intermediary) returns.
- **Presents.** Quote (RFQ -> priced response with TTL).
- **Price formation.** Deterministic band fed by an oracle score (notch/cliff pricing at band edges; not actuarial).
- **Composes.** Capped by **R1**; settles into **R3** (`premium_amount` must equal selected placement premium).
- **Status.** Realized (banded). Continuous experience-rated/actuarial pricing and quote-option/last-look are implied-missing (Section 5). Within-band pooling means a 705-score agent is cross-subsidized by an 895-score agent; thin-file agents fail closed to declined (cold-start exclusion).

#### R3. Bound coverage policy (the risk-transfer good)
- **What.** The matched/sold risk-transfer right: contingent indemnity against metered-execution liability, classed by line. The buyer holds a contingent claim; the seller holds the matched obligation.
- **Grounding.** `LiabilityBoundCoverageArtifact` (`chio.market.bound-coverage.v1`) via `LiabilityPlacementArtifact`; auto-match `LiabilityAutoBindDecisionArtifact` (`AutoBound`/`ManualReview`/`Denied`, `chio-market/src/placement.rs:240-285`); `LiabilityCoverageClass` (ToolExecution/DataBreach/FinancialLoss/ProfessionalLiability/RegulatoryResponse).
- **Class.** Risk-transfer / asset (contingent claim).
- **Properties.** Rival/excludable (bound to one `subject_key`, finite max coverage); unique (`policy_number`); perishable (effective window); non-fungible across classes/jurisdictions; illiquid (no novation).
- **Who.** Buyer = agent (`risk_package.body.subject_key`); seller = `LiabilityProviderType` carrier (AdmittedCarrier/SurplusLine/Captive/RiskPool).
- **Presents.** Selection/settlement leg: placement -> bound coverage; `CommerceCoverageRequirement` pins its comptroller report into the order.
- **Price formation.** Deterministic band (premium from **R2**); auto-bind is the rule-based admission, not an auction.
- **Composes.** **R1**, **R4**, **R8**, **R6**.
- **Status.** Realized. Coverage assignment/novation and risk-pool mutualization shares are implied-missing (Section 5).

#### R4. Claim / adjudication / payout chain (contingent-claim exercise)
- **What.** The instrument by which the insured exercises the coverage option, through bilateral dispute, arbitrated adjudication, and a custody-neutral payout. Adjudication is the moral-hazard/fraud control between claim and payout. The payout amount is administered/arbitrated, not market-priced.
- **Grounding.** `LiabilityClaimPackageArtifact` (`chio.market.claim-package.v1`, bundles bound coverage + `SignedExposureLedgerReport` + `SignedCreditBond` + `SignedCreditLossLifecycle`, `claim_amount <= coverage`) -> `LiabilityClaimDisputeArtifact` -> `LiabilityClaimAdjudicationArtifact` (`ClaimUpheld`/`ProviderUpheld`/`PartialSettlement`) -> payout instruction -> receipt -> `LiabilityClaimSettlementInstructionArtifact` (`RecoveryClearing`/`ReinsuranceReimbursement`/`FacilityReimbursement`) -> settlement receipt with `LiabilityClaimSettlementRoleTopology` (`chio-market/src/{claim,settlement}.rs`).
- **Class.** Right (exercise) -> risk-transfer (contingent payout).
- **Properties.** Excludable, unique (one claim per loss), rival against the reserve it draws; perishable to the coverage window.
- **Who.** Claimant (buyer) files/collects; carrier/facility/reinsurer (seller) pays; adjudicator clears.
- **Presents.** Settlement leg(s): payout instruction -> receipt -> settlement instruction -> settlement receipt.
- **Price formation.** Negotiated then adjudicated, capped by coverage; movement is custody-neutral (see **S2**).
- **Composes.** **R3**, **R6** (reserves), **R8**; `ReinsuranceReimbursement` is named in the payout path but the ceding treaty is implied-missing (Section 5).
- **Status.** Realized.

#### R5. Credit facility + capital book (risk-bearing capital capacity)
- **What.** The committed underwriting capacity that backs all coverage, plus the source-of-funds book that identifies whose money is at risk. The supply side of the coverage market.
- **Grounding.** `CreditFacilityArtifact` (`chio.credit.facility.v1`) `CreditFacilityTerms { credit_limit, utilization_ceiling_bps, reserve_ratio_bps, concentration_cap_bps }`; `CapitalBookReport` (`chio.credit.capital-book.v1`) `CapitalBookSource` of kind `FacilityCommitment`/`ReserveBook`, roles `OperatorTreasury`/`ExternalCapitalProvider`/`AgentCounterparty` (`chio-credit/src/credit/capital_and_execution.rs`).
- **Class.** Asset (risk capital).
- **Properties.** Rival (every bound policy consumes headroom), excludable, fungible within a single currency only, durable subject to lifecycle/revocation.
- **Who.** Capital provider / operator treasury / `ExternalCapitalProvider` supplies; pledged via **R1**.
- **Presents.** Mandate/backing leg referenced by **R1** and folded into **R8**.
- **Price formation.** Negotiated/granted off-market (terms); utilization/concentration enforced deterministically.
- **Composes.** **R1**, **R6**, **R8**, tier ceiling.
- **Status.** Realized but MONOLINE: the capital book fails closed on more than one facility/bond or any mixed currency, so a single facility is the entire balance sheet. Multi-source senior/first-loss/insurer/reinsurer roles are doc-06 Phase 6 designed.

#### R6. Reserve + credit bond (segregated, conservation-enforced backing)
- **What.** The staked, exclusive backing behind coverage and promises: collateral that can be locked/held/released/impaired and terminally consumed exactly once. The conservation-of-rights invariant on the capital side; reserves are the unearned-premium/loss-reserve analogue.
- **Grounding.** `CreditBondArtifact` (`chio.credit.bond.v1`) `CreditBondTerms { collateral_amount, reserve_requirement_amount, coverage_ratio_bps }`, `CreditBondDisposition` Lock/Hold/Release/Impair; reserve movement via `CapitalExecutionInstructionArtifact` actions `LockReserve`/`HoldReserve`/`ReleaseReserve`/`TransferFunds`. Tier ceilings via `compute_marketplace_credit_limit` (`MARKETPLACE_TIER_LIMIT_UNITS = [10_000, 50_000, 250_000, 1_000_000]`, `chio-underwriting/src/marketplace_limits.rs:41`; revocation = fail-closed Deny).
- **Class.** Asset (collateral) / risk-transfer backing.
- **Properties.** Strictly rival and linear (one terminal consumer per unit), excludable (bond-scoped), fungible within currency, durable until released/impaired.
- **Who.** Posted seller-side (provider/facility) as the solvency proof a buyer's coverage depends on.
- **Presents.** Settlement/backing leg folded into **R8** (`RiskFacilityState`, `RiskReserveLedgerEntry`).
- **Price formation.** Deterministic band (`coverage_ratio_bps`/`reserve_requirement`; tier ceilings [10k,50k,250k,1M]).
- **Composes.** **R5**, **R4** payout (`TransferFunds`), **R7** slash, **P3** `BondBacked`.
- **Status.** Realized. The graduated tier ceiling is the network-graduated capacity ramp (a component, not a separate primitive).

#### R7. Slash / sanction instrument (capped collateral consumption)
- **What.** The single authorized lane that terminally consumes posted collateral when an obligation is breached. What makes bonds credible ex-ante; without enforceable slashing the moral-hazard mitigant is empty.
- **Grounding.** `RiskSanctionReserveLedgerEntry` on lane `market_slash` bound by `RiskSanctionBridge` (authority_receipt_ref / jurisdiction_ref / sanction_subject / `maximum_slash_units`), passing the double-consumption guard `is_terminal_reserve_consumption` (`claim_payout|reserve_release|reserve_slash|market_slash|write_off`, `chio-risk-comptroller/src/ledger.rs`), with claim-payout priority and open-`RiskClaimAppeal` holds. The access-market penalty (**P7**) routes through this SAME lane.
- **Class.** Risk-transfer (collateral consumption + enforcement).
- **Properties.** Rival and linear (consumes one reserve/bond unit once), excludable, terminal/non-reversible except via appeal.
- **Who.** Imposed by the operator/comptroller against a sanctioned seller; proceeds clear to the harmed counterparty.
- **Presents.** Settlement leg: a terminal ledger entry, governance-gated.
- **Price formation.** Deterministic, capped at the bond requirement (fail-closed); not market-set.
- **Composes.** **R6**, **R4** claim-payout priority, governance `Sanction`/`Appeal` cases.
- **Status.** Realized. This is the SINGLE slash lane (per CHIO-TOKEN-COMMERCE-ALIGNMENT C1); no parallel slash authority is permitted.

#### R8. Comptroller solvency report (the regulator fold)
- **What.** The single deterministic fold that proves the book is solvent and reconciled. The regulator/solvency-proof primitive: a precondition pinned into the order passport.
- **Grounding.** `RiskComptrollerReport` (`chio.risk.comptroller-report.v1`) with `RiskFacilityState`/`RiskCoverageBinding`/`RiskReconciliation`/`RiskReserveLedgerEntry`; `validate_risk_actuarial_limits` (`chio-risk-comptroller/src/lib.rs:764`) gates `coverage.exposure_units <= supported_exposure_units`, `observed_loss_ratio_bps <= maximum`, backtest `status=passed`. Folds the exposure ledger, `CreditLossLifecycleArtifact`, `RiskActuarialEvidence`/`RiskBacktest`, and the tier ceiling as components.
- **Class.** Information-good (solvency proof).
- **Properties.** Non-rival proof but excludable; perishable (point-in-time fold).
- **Who.** Produced by the comptroller (intermediary/regulator role); consumed by the order context (`CommerceCoverageRequirement`).
- **Presents.** Mandate: a solvency precondition pinned into **S3**.
- **Price formation.** Deterministic gate (fail-closed on any breach); not priced.
- **Composes.** **R5**, **R6**, **R4**, **R3**; gates `CommerceCoverageRequirement`.
- **Status.** Realized as a gate. Critically, the loss-ratio/exposure data it HOLDS is used only to DENY, never to PRICE (**R2** stays banded); the actuarial feedback loop is open (Section 5).

### Trust / attestation / data

#### T1. Signed receipt + anchored evidence (the information atom)
- **What.** A signed kernel proof that a tool call was evaluated. The first-copy unit of verifiable history from which every higher-order good (scorecard, credential, disclosure stream, settlement passport, loss-experience table) is derived. Anchoring converts a cheap-talk receipt into an independently-checkable one: the `TransparencyState` ladder None->Preview->Anchored is literally a quality ladder for information.
- **Grounding.** `ChioReceipt` (`chio.receipt.v1`, `chio-core-types/src/receipt/body.rs`); anchored as `AnchorProofBundle`/`Web3CheckpointStatement` (`chio-anchor/src/bundle.rs`); `TransparencyState` (`chio-disclosure-lineage`).
- **Class.** Information-good.
- **Properties.** Non-rival (copyable at ~zero marginal cost) with a real first-copy cost (kernel evaluation); excludable via signature + tenant isolation; unique by content-addressed id; durable.
- **Who.** Seller produces it as a by-product of mediated execution; not sold loose; buyers value the derived aggregates.
- **Presents.** Evidence node, never a standalone listing; surfaces as corpus input and as digests pinned into passports; counted as `recent_receipts_volume` in **P2**.
- **Price formation.** Gifted-subsidy (own-data, zero-mint) for tier-0; the Anchored grade commands a higher trust price.
- **Composes.** Feeds **T2**, **R2**, **R8**, **S3**.
- **Status.** Realized.

#### T2. Reputation scorecard / trust score (verifier-recomputed screening signal)
- **What.** A weight-100 composite trust score the marketplace verifier does NOT trust as asserted: it RECOMPUTES it from component evidence and forces the ranking score to equal it. The discrete `ReputationTier` gates discovery visibility, making this the core data-network-effects good (every completed transaction raises a counterparty's tier).
- **Grounding.** `LocalReputationScorecard` via `compute_local_scorecard` (`chio-reputation/src/model.rs`); `TrustScorecardSnapshot.computed_score` + `recompute_score` (must equal selection ranking, `chio-trust-market-context/src/artifacts.rs:1007`); discretized `ReputationTier` (Sybil-gated by distinct-feed AND-floor).
- **Class.** Information-good (screening signal) / asset (reputational capital).
- **Properties.** Non-rival (derived from receipts), excludable by tier, Sybil-gated; perishable (freshness window, stale components rejected fail-closed).
- **Who.** Seller's reputational capital; buyers value it ranking sellers; produced by the network itself.
- **Presents.** Discovery/selection ranking input (the **P4** ranking score IS this).
- **Price formation.** Deterministic recompute (oracle-like).
- **Composes.** Consumes **T1** + **T3**; drives **P4**, `MARKETPLACE_TIER_LIMIT_UNITS` ceilings, the Pass `TrustTier`.
- **Status.** Realized.

#### T3. Portable reputation credential (the cross-operator tradable reputation good)
- **What.** An issuer-signed, exportable summary of a counterparty's cross-operator history (plus negative events), the only reputation object that actually changes hands. A relying operator buys it as a quality INPUT, weighted by an issuer-allowlist profile and attenuated. The Spence separation firewall is encoded: reputation may serve only as a scoring input and can NEVER stand in for collateral/solvency.
- **Grounding.** `SignedPortableReputationSummary`/`PortableNegativeEventArtifact` (`chio-credentials/src/portable_reputation.rs`), evaluated by `evaluate_portable_reputation` against `PortableReputationWeightingProfile`; imported as `ReputationImportReport`/`ImportedReputationSignal` (`attenuation_factor`); `validate_reputation_import` enforces `usage == "scoring_input"` ("reputation import cannot prove collateral or solvency", `artifacts.rs:342`).
- **Class.** Information-good (bought as input, not as money).
- **Properties.** Non-rival, excludable (issuer-signed, attenuated, freshness-bounded).
- **Who.** Seller = origin operator/issuer; buyer = relying operator importing it as a scoring input.
- **Presents.** Discovery/import: a capped `portable_reputation` component of **T2**.
- **Price formation.** Negotiated weighting (issuer allowlist + per-issuer weights + attenuation); blocked outright by `blocking_event_kinds`.
- **Composes.** Feeds **T2**; the deliberate anti-lock-in/multi-homing countermeasure to the data flywheel; bounded vs collateral/solvency.
- **Status.** Realized. No transfer royalty/re-import metering: the issuer captures none of the downstream value its signal creates (Section 5).

#### T4. Chio Pass / Agent Passport (gifted soulbound admission credential)
- **What.** The soulbound, non-transferable, gifted credential issued to every attested `did:chio`, bundling the recomputable scorecard, runtime attestation, and a discretized `TrustTier`. The buyer/agent-side admission key and live metering anchor: the divide-and-conquer subsidy that gives the demand side free entry to seed the network. A precondition to every trade; never a coverage/bond discount.
- **Grounding.** `AgentPassport` + `ReputationCredential` (W3C VC, subject `ReputationCredentialSubject { metrics: LocalReputationScorecard }`) + `TrustTier` (Unverified/Attested/Verified/Premier, `chio-credentials/src/trust_tier.rs`); lifecycle `PassportLifecycleRecord`/`PassportLifecycleResolution` bridged to `chio-revocation-oracle`. See CHIO-PASS-M0-SPEC.md.
- **Class.** Access-credential (information-good bundle).
- **Properties.** Non-rival content; soulbound (non-transferable/non-fungible); excludable by revocation; lifecycle-perishable.
- **Who.** Platform (trust authority) issues; agent (buyer) holds; gifted day-zero.
- **Presents.** Admission credential presented at discovery/selection; subject node of **S3**.
- **Price formation.** Gifted-subsidy (zero mint).
- **Composes.** Gates **A1** minting, unlocks **T8**, admits **T6** emission; wraps **T2** + **T5**.
- **Status.** Realized.

#### T5. Verified attestation (provenance admission screen)
- **What.** A cryptographically verified provenance claim about a provider's build or runtime. The screen that lets a buyer distinguish a genuine attested provider from a self-described one. `rekor_inclusion_verified` is the verifiability premium as a boolean: partial verification produces a strictly lower-grade good.
- **Grounding.** `VerifiedAttestation` (Sigstore Fulcio+Rekor) / `VerifiedQuote` (Nitro/SEV-SNP/TDX) gated by `ExpectedIdentity` + `TenantPolicy` (`chio-attest-verify/src/{lib.rs,quote.rs}`); Ok only on full digest+cert+inclusion verification.
- **Class.** Information-good / access-credential precondition.
- **Properties.** Non-rival claim; the verification service is excludable (pinned `ExpectedIdentity`); perishable (staleness horizon).
- **Who.** Buyer-side/verifier screening device; a precondition to admission, never authority by itself.
- **Presents.** Fail-closed precondition feeding the passport `runtime_attestation` and provider SPIFFE appraisal.
- **Price formation.** Deterministic fail-closed (no Ok on partial verification).
- **Composes.** Feeds **T4** and provider runtime appraisal.
- **Status.** Realized.

#### T6. Trust-signal pheromone (congestion-priced emission + gifted aggregate)
- **What.** Raw trust signals whose EMISSION is priced and rate-limited so signal-space cannot be flooded (a Pigouvian/congestion price defeating Sybil signal-spam), while the privacy-preserving aggregate is gifted free. The ONLY genuine capacity/congestion price in the codebase.
- **Grounding.** `PheromoneDeposit` priced via `PheromoneObservationCostStatement`/`PheromoneObservationCostLeaf` (`chio.observation.microunit.v1`), capped by `PheromoneScarcityPolicy.token_capacity` per scarcity window, Sybil-damped by `sqrt_n_passport_cap` + diversity cap + newcomer discount; aggregate `PheromoneConcentration` (`total_strength`, `distinct_origin_pairs`, `peak_confidence`); raw `query_deposits` withheld (`chio-pheromone/src/lib.rs`).
- **Class.** Information-good (signal) with a metered emission right + gifted aggregate.
- **Properties.** The signal is non-rival once emitted; the RIGHT to emit is rival/scarce (`token_capacity`) and excludable (passport-admitted signer); the aggregate is non-rival and gifted at tier-0.
- **Who.** Depositor (either side) pays to emit; the trust commons consumes the aggregate; platform subsidizes the newcomer discount.
- **Presents.** Metered cost statement gating a deposit; aggregate presents as a gifted discovery feed.
- **Price formation.** Deterministic-band quota (congestion-rationed per window, Sybil-adjusted, newcomer discount).
- **Composes.** Feeds **T2**/discovery; part of the **T8** Half-A gift.
- **Status.** Realized. Residual underprovision risk: if no one is paid to emit, the gifted aggregate may be underproduced.

#### T7. Data-stream disclosure bundle (price denominated in leakage)
- **What.** Signed, offline-verifiable disclosure of a tenant's own receipt/lineage stream. The novel metering unit is not money but an information-leakage budget: the bundle fails if it discloses more fields/predicates than allowed even when every signature verifies. The "price" of consuming the stream is denominated in bits of disclosure.
- **Grounding.** `DisclosureLineageBundle` (`DisclosureCapsule` + `DisclosureVerifierPrivacyProfile` + `SignedLineageSubgraph` + mandatory `DisclosureLeakageLedger`), verified by `verify_disclosure_lineage_bundle` (pinned `TRUSTED_LINEAGE_SIGNER_PUBLIC_KEYS`, hashed `tenant_hash`, `chio-disclosure-lineage/src/{types.rs,verifier.rs}`); budget `DisclosureProfileLeakageBudget { max_disclosed_fields, max_hidden_predicates }`.
- **Class.** Information-good / metered access-credential.
- **Properties.** Non-rival data; excludable via pinned signers + tenant/audience binding; metered by leakage budget.
- **Who.** Data subject is the buyer of its own audit/compliance stream; tier-0 baseline right.
- **Presents.** Verifiable bundle with a leakage ledger that must fully cover disclosed fields.
- **Price formation.** Deterministic leakage-budget band (excess disclosure fails closed); gifted-subsidy for own-data tier-0.
- **Composes.** Binds `TransactionPassport` + `SignedLineageSubgraph`; consumes **T1** lineage.
- **Status.** Realized. This is the privacy externality internalized as a price.

#### T8. Gifted feed tier + metered free-compute allotment (the two-halves subsidy)
- **What.** The deliberate subsidy that bootstraps the two-sided market. Half A: zero-mint Read/Subscribe feeds (reputation tier feed, listing/pricing discovery, pheromone aggregate, own-data disclosure) gifted at tier-0. Half B: a pre-funded, capped compute grant attached to the Pass that lets a newcomer run real first-party tools on the house from day zero. A loss-leader cross-subsidized: Half B is the costly half; financial surfaces are explicitly EXCLUDED from the gift (regulatory posture).
- **Grounding.** Pass `ResourceGrant{Read,Subscribe}` over the five gifted streams + `ToolGrant{max_total_cost,...}` metered down by kernel `budget_store` (`chio-kernel/src/budget_store.rs`), Deny receipt `cost_charged=0` on exhaustion. See CHIO-BENEVOLENT-TOKEN-DESIGN.md (Half A / Half B) and CHIO-PASS-M0-SPEC.md.
- **Class.** Information-good (gifted access) + service (metered compute).
- **Properties.** Half A non-rival, made non-excludable by gift; Half B rival (real fiat inference cost), excludable, perishable (depletes, expires).
- **Who.** Operator subsidizes (seller-funded); every attested `did:chio` is a buyer at price zero.
- **Presents.** Discovery: always-free tier-0 feeds + a day-zero compute allotment.
- **Price formation.** Gifted-subsidy; Half A "price" is the leakage budget (**T7**), Half B is fee-bounded rebate (Phase-1).
- **Composes.** Minted under **T4**; subsidized by **P6** fees and **T6** scarcity revenue.
- **Status.** Realized. The aggregate treasury free-tier pool ceiling (`freetier:global:<window>`) is implied-missing and is the sharpest subsidy-solvency gap: `budget_store` caps only per `(capability_id, grant_index)` with NO global term (`budget_store.rs:18-19`), so platform liability = N_passes x allotment, unbounded by runway (Section 5).

### Settlement / capital

#### S1. Payment lifecycle proof (verified payment-satisfaction)
- **What.** A verified payment-satisfaction proof. Payment success NEVER implies tool authorization; replay enforces capture-before timing.
- **Grounding.** `CommercePaymentLifecycle` (`chio.commerce.payment-lifecycle.v1`): PSP, `payment_intent_id`, authorization/capture/charge refs, fraud/dispute/refund/chargeback status.
- **Class.** Information-good (settlement claim).
- **Properties.** Non-rival proof, excludable per order, durable.
- **Who.** PSP/rail produces; the order context consumes as a precondition.
- **Presents.** `payment_verified` stage of the order machine.
- **Price formation.** N/a (a satisfaction proof, not priced).
- **Composes.** Bounded by **A3**; precedes **S2**.
- **Status.** Realized.

#### S2. Settlement packet + custody-neutral finality
- **What.** The cleared-transfer settlement instrument, plus the deliberate split between the RIGHT to move funds (a signed transfer instruction) and the FACT that funds moved (an oracle-attested observation). Offer-safety/finality is never asserted by the payer; it is proven only by a reconciled observation. The on-rail analogue of ERTP payment-safety.
- **Grounding.** `CommerceSettlementPacket` (`chio.commerce.settlement-packet.v1`: `settlement_rail`, `dispatch_receipt_ref`, `reconciliation_ref`) -> `chio.web3-settlement-dispatch.v1`. Intent vs fact: `CapitalExecutionInstructionArtifact` (`TransferFunds`, `reconciled_state=NotObserved`) vs `CapitalExecutionObservation` (`Matched`). USDC rails (`chio-settle`): `X402PaymentRequirements`/`X402SettlementMode`, `PreparedTransferWithAuthorization` + `ApprovalBinding` + `Eip3009NonceStore`, `EscrowDispatchRequest`/`PreparedEscrowCreate`, `PreparedCircleNanopayment`, `PreparedPaymasterCompatibility`.
- **Class.** Right (transfer instruction) + information-good (finality proof).
- **Properties.** The instruction is single-use/excludable; the observation is a non-rival verifiable fact once anchored; intent without observation confers no value movement.
- **Who.** Payer (facility/provider) emits intent; an oracle/reconciler attests; payee collects only against the observation.
- **Presents.** Settlement legs: instruction -> dispatch -> observed -> reconciled.
- **Price formation.** Oracle (movement recognized only on reconciled observation; broadcast prepare-only / `simulation_first`).
- **Composes.** Trues up against **A5**; consumes **A2**; reconciled into **S3**; the payout leg of **R4**.
- **Status.** Realized as artifact; on-chain broadcast prepare-only/feature-gated OFF (custody-neutral).

#### S3. Order-passport (the portable settlement credential, flywheel closer)
- **What.** The portable, selectively-disclosable audit object proving the full rights-transfer conserved value end to end: capability minted -> exercised -> paid -> settled, every leg's digest pinned. The closed-loop proof that no right was forged, amplified, or double-spent. "Receipts are the new reputation": a completed match becomes reputation input for the next match, closing the cross-side flywheel.
- **Grounding.** `CommerceOrderPassportReport` (`chio.commerce.order-passport.v1`, `chio-commerce-order/src/types.rs:299`) carrying `artifact_digests`, `selective_disclosure_policy`, `verified_claims`; emitted only after the hard-coded `is_allowed_transition` chain completes (`replay.rs:541`); subject-node eligible, anchorable in `ChioRootRegistry`.
- **Class.** Information-good / asset (portable verified history, reputation collateral).
- **Properties.** Non-rival once issued (copyable proof) but selectively excludable via disclosure policy; uniquely bound to one order; durable/anchorable.
- **Who.** Joint output of buyer + seller + intermediaries; re-enters the network as reputation evidence consumed by future counterparties.
- **Presents.** Terminal settlement credential of the order machine.
- **Price formation.** Deterministic/derived (digest-bound recompute of the event log; not priced).
- **Composes.** Aggregates every prior leg's signed artifact; its receipts feed **T1** -> **T2** -> tier.
- **Status.** Realized as report; sealed Proof Room anchoring partly designed.

---

## 4. Market structure + mechanism design

### Matching mechanisms in use (and the one that is absent)
Chio runs FIVE administered matching forms and zero competitive ones:
1. **Posted price (single-dealer ask).** The access market: `ListingPricingHint.price_per_call` (**P2**); `bid()` clears at `advertised_price` with `max_price_per_call` as a fail-closed clamp (**A1**). Also the venue tariff (**P6**) and quotes/hints (**P5**).
2. **Deterministic rank/sort.** Discovery `search()` (**P1**) and trust-weighted `ProviderSelectionReport` (**P4**), where `total_score == computed_score` fuses match and reputation. Buyers self-select; the venue forms no price. `ListingComparison.price_index_bps` is cross-listing dispersion, not a within-book bid-ask spread (there is no book, no bid side).
3. **Deterministic band / score oracle.** The 4-band premium step function (**R2**) and the banded reserve/tier ceilings (**R6**).
4. **Min-of-caps capacity rationing.** Coverage capacity is rationed by the tightest binding constraint (**R1**: `min(facility limit, provider max, committed capital)`), not cleared by price; no pooled-capacity depth or reinsurance layering.
5. **Congestion / quota price.** The only genuine capacity price: pheromone emission rationed per scarcity window by `token_capacity` (**T6**).

ABSENT (implied-missing, Section 5): any central order book / double auction, any market-maker / two-sided quote with inventory, any discovered clearing price. No buyer competes against another buyer at trade time; no seller is undercut at a cross. Liquidity is single-dealer.

### Two-sided-platform dynamics
A deliberately curated (not permissionless) two-sided-PLUS market with a divide-and-conquer pricing split:
- **Subsidized side: buyers/agents.** Gifted soulbound Pass (**T4**), zero-mint feeds (**T8** Half A), a real pre-funded compute allotment (**T8** Half B), newcomer pheromone discounts (**T6**), tier-0 default floor, all at day zero.
- **Paying side: sellers/providers.** Flat publication/participation fees (**P6**) + a slashable participation bond (**P7**). The platform subsidizes the side that generates the data network effect (agents emitting receipts) and monetizes the side that captures it (providers ranked by those receipts).
- **The third side: underwriters/capital.** A genuine third side via the pricing-authority Mint (**R1**) backed by `ExternalCapitalProvider` capital (**R5**), plus intermediary trust authorities (**P3**) and the operator's own rule-setting right (`OpenMarketEconomicsScope` + `governing_operator_id`, `LiabilityProviderSupportBoundary.curated_registry_only=true`).
- **The flywheel (the load-bearing externality).** `ChioReceipt (T1) -> LocalReputationScorecard (T2) -> ReputationTier -> discovery visibility -> more transactions -> more receipts`, closed by the order-passport (**S3**). Tier also gates graduated credit ceilings (**R6**). Winner-take-all pressure is countered by (a) Sybil resistance (distinct-feed AND-floor, `sqrt_n` passport cap, diversity cap) and (b) bounded portability/multi-homing (**T3**, which cannot prove solvency).

### The Pass / data-stream gift as a subsidy primitive
**T4 + T8** are the subsidy engine: a textbook loss-leader to seed the demand side. The economics work because trust objects are non-rival with near-zero reproduction cost (Half A is gifted at zero marginal cost; first-copy/anchoring cost is recovered off the metered Half-B allotment and **T6** scarcity revenue). The deliberate exclusion of financial surfaces (chio-market, bonds, underwriting) from the gift is a regulatory boundary (avoid security characterization) that shapes the subsidy edge. The intended failure mode is "the gift shrinks while Half A keeps running free"; the UNINTENDED failure mode today is "subsidy outruns treasury" because the global pool ceiling is missing (Section 5). One caveat: because demand is seeded at price zero, observed "demand" for feeds carries no willingness-to-pay signal that could later inform price formation.

### Fee / take-rate posture
Monetization is FLAT per-action fees (**P6**) + slashable bonds (**P7**) + the underwriting spread (**R1/R2**). There is NO ad-valorem commission on settled GMV (no `take_rate_bps` on `CommerceSettlementPacket`/`CommerceOrderContext`), and the collection rail (`FeeRouter`/`ChioTreasury`) is unbuilt. Tradeoff: flat fees dodge the ad-valorem disincentive on high-value transactions but leave surplus uncaptured on large orders and are regressive on small ones.

### Externalities and market failures, and how the primitives address them
- **Adverse selection / lemons (pre-contract).** Addressed by recompute-not-trust (**T2** verifier recomputes the scorecard and forces ranking == score), posted quality-disclosure signals (**P2** `revocation_rate_bps`, `recent_receipts_volume`), bonded screening (**P7**, **R6**), and the Spence separation firewall (**T3** `usage=="scoring_input"`, forbidding a pooling equilibrium where cheap reputation masquerades as costly solvency). The verifiability premium is realized in VERIFICATION but NOT in PRICE on the access market (lemons cleared by ranking/exclusion, not a separating price): the implied-missing verifiability-graded access price (Section 5). In coverage, banded pricing (**R2**) pools within bands and fails thin-file agents closed to declined (a cold-start exclusion at exactly the moment an agent has no receipt history).
- **Moral hazard (post-contract).** Addressed ex-ante by bonds + skin-in-the-game (**P7**, **R6**) and the single enforceable slash lane (**R7**), and post-contract by metered recompute-and-true-up (**A5**: the provider cannot silently over-bill). It is NOT priced ex-post in coverage: premiums ignore the insured's own loss lifecycle (no experience-rating/bonus-malus), so realized losses never re-rate coverage (Section 5).
- **Congestion / signal-flooding.** Addressed by pheromone congestion pricing (**T6**: metered microunit emission + scarcity-window quota + Sybil caps). The privacy externality of data-gifting is internalized by the mandatory leakage ledger (**T7**) and by gifting only aggregates while withholding raw deposits.
- **Capital-side conservation / systemic risk.** Reserve linearity (**R7** `is_terminal_reserve_consumption` with claim-payout priority and open-appeal holds) prevents the same reserve unit being both slashed and paid out. But the capital book is monoline (**R5** fails closed on >1 facility/mixed currency), there is no cross-tenant catastrophe cap, and correlated tool-execution failures (one upstream model failing across many insureds) are an unpriced accumulation externality.
- **Settlement/counterparty risk.** Mitigated by custody-neutral intent-vs-observation (**S2**), but between adjudication and observation the claimant holds an unsettled promise, not cash: residual carrier-default risk the coverage instrument does not eliminate.

---

## 5. Gaps + recommendations

### Implied-missing primitives (economically necessary, absent in code)
Ranked by leverage for a functioning marketplace.

1. **Atomic single-ledger reservation / custodial settlement escrow (Zoe-style two-sided offer-safety).** Today offer-safety is PROCEDURAL: `accept()` checks the buyer's signed `ReservationReceipt` covers `token_offer_total_liability` (**A2**), but no custodial agent holds BOTH legs (the minted right and the payment) for an atomic swap. Rights are minted fresh per bid; delegation is subject-bound (no hand-off); the atomic single-ledger reservation is the flagged launch Risk 1 (CHIO-AUTONOMOUS-COMMERCE). Nearest real types: `VerifiedReservationReceipt`, `EscrowDispatchRequest`/`PreparedEscrowCreate` (prepare-only).
2. **Aggregate treasury free-tier pool ceiling (`freetier:global:<window>`).** `budget_store` caps only per `(capability_id, grant_index)` with no global term, so Half-B subsidy liability (**T8**) is structurally unbounded (`N_passes x allotment`). The fix is a synthetic global pool debited on every per-Pass charge, fail-closed on exhaustion, namespace-isolated so it never counts as a real commerce/comptroller budget hold (per CHIO-TOKEN-COMMERCE-ALIGNMENT Sec 4).
3. **Experience-rated actuarial premium curve (loss-ratio feedback).** The comptroller (**R8**) HOLDS loss-ratio and exposure data and uses it only to GATE (deny), never to PRICE; **R2** stays a static 4-band step function. A continuous premium responding to realized loss experience closes the open actuarial loop and is required for a solvent risk market.
4. **Secondary capability market + resale/transfer surface.** The good is technically divisible/resellable (`is_subset_of`), but there is NO secondary listing/quote/transfer-settlement surface and delegation forbids hand-off to a non-subject holder. Adding a resale surface (re-list -> re-quote -> transfer-settle a held `CapabilityToken`) would create genuine price discovery the primary posted-price mint cannot.
5. **Verifiability-graded access price + quote-option/last-look.** A price differential on the access right keyed to provider verifiability grade (anchored vs preview, attested vs self-described), modeled on `price_premium`; plus an option fee or seller reject-right on the free TTL firm quote (**P5**) so buyers cannot harvest stale-price options.
6. **Risk-sharing depth: reinsurance treaty + risk-pool mutualization share + coverage novation.** `ReinsuranceReimbursement` and `RiskPool` exist as labels, but no ceding/treaty/tranche, no pool-share/contribution/distribution, and no assignment/novation type exist; the capital book fails closed on >1 facility, so risk cannot be shared, mutualized, or laid off, and policies are illiquid.
7. **Ad-valorem GMV commission + reputation-export royalty.** A success-fee on settled value (the natural two-sided-platform revenue primitive) and a per-use fee on **T3** imports (so high-value reputation issuers capture downstream value). Plus the third-party caveat discharge market (`caveat.rs` explicitly defers third-party caveats), which would create a priced, revocable, per-use discharge-token economy.

### The single highest-leverage primitive to build next
**Harden A2 into an atomic single-ledger custodial settlement escrow (gap 1).** Offer-safety is the foundational guarantee of any exchange, it is the trust backbone of EVERY primary capability and coverage trade, and it is the one flagged launch Risk. Today both sides are only PROCEDURALLY safe (a signed reservation receipt checked inside `accept()`); an escrow agent that holds the minted `CapabilityToken` and the buyer's funds and swaps them atomically (reusing `EscrowDispatchRequest`/`PreparedEscrowCreate` and the custody-neutral observation in **S2**) makes BOTH parties offer-safe simultaneously and unblocks the secondary market (gap 4) for free. The aggregate free-tier pool ceiling (gap 2) is the highest-leverage SUBSIDY-side fix and should ship in the same window, because without it the bootstrap engine can outrun the treasury before the marketplace reaches liquidity.

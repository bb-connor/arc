# Chio Benevolent Token Design (Decision)

Status: decision-oriented design doc. Author: chief protocol architect.
Scope: the benevolent, distribution-first Chio vehicle (what users get gifted, how it
stays solvent and unfarmable, and how it slots into the existing fail-closed phase gate).
Framing: fail-closed. Every utility escalation is a gate that must be PROVEN open with
evidence. Absent proof, the gate stays closed and the vehicle stays maximally benevolent
and maximally safe.

This doc RECONCILES with `docs/brainstorm/CHIO-TOKEN-AND-CONTRACTS-PLAN.md` (the roadmap).
Where the benevolent framing revises that roadmap it says so explicitly (Section 6); where
it agrees it references the roadmap rather than repeating it.

---

## 1. Recommendation

Ship the **Chio Pass**: a soulbound, non-transferable, non-redeemable verifiable credential
built on the existing `chio-credentials` crate (NOT an ERC-20, no money leg), issued to
attested `did:chio` identities, that gifts (a) free Read/Subscribe access to the aggregate
trust feeds the marketplace itself consumes and (b) a real metered free-compute allotment
that a holder spends to actually run first-party Chio tools. This is the Phase-0,
zero-external-gate, structurally-non-inflationary core (tournament champion D1 on every
safety axis), grafted with the decisive fixes the tournament surfaced: the costly half of
the gift (compute) is handed to the NEWCOMER at tier_0 on day zero rather than withheld up
the reputation ladder; an aggregate treasury pool ceiling (the budget control the kernel
does not have today) makes generosity a pre-funded, fail-closed line item; and the
"future-token wink" is amputated so the Pass confers only present consumptive utility.
Utility then graduates strictly behind the roadmap's existing gate: money-backed usage
(Phase 1, escrow-socketed, partner issuer-of-record), reputation-informed bonding economics
(Phase 2), and at most a soulbound-then-conditionally-transferable governance credential
(Phase 3) that grants Pass holders zero retroactive claim. We make a clear call: the
distribution-first vehicle is access and usage, not a tradeable asset, until and unless the
Phase-3 securities gate is independently and evidentially open.

**What the user gets gifted, from day one:** a free Chio Pass that, the moment a newcomer is
attested, unlocks Read access to Chio's reputation, listing, and pheromone-concentration
feeds AND a real, pre-funded compute allotment to run a first workload on the house, with
nothing to buy, nothing to lock up, nothing to dump, and no tax-trap asset.

---

## 2. What gets gifted and from where (and why generosity does not collapse)

The gift has two halves with two distinct sustainable funding sources. Neither is emissions;
nothing is minted; there is no token to peg or dump. The collapse mode that historically
kills giveaways (emission-funded APY where inflation outruns value and recipients dump) is
structurally impossible here.

### Half A: free Read/Subscribe over data that already exists (zero-mint, near-zero marginal)

Funding source: the data is a deterministic function of receipts that already exist, so
serving a read mints zero units. The honest residual is fiat serving opex (compute,
bandwidth, signing), which we DO meter and cap (Section 3, aggregate pool), not pretend is
zero. Gifted streams, named from the real surfaces (see `frame:data-streams`):

- **Reputation tier/score feed** (`crates/trust/chio-reputation`, `tier.rs` gating +
  signed-report publication). Aggregate, non-PII, Sybil-resistant by construction. Gifted at
  tier_0 to every attested identity. Highest value, lowest risk.
- **Marketplace listing + pricing/SLA discovery feed** (`crates/economy/chio-listing/discovery.rs`).
  Operator-signed public pricing; the gift raises result caps and unlocks compare views.
  Gifted at tier_0.
- **Pheromone aggregate-concentration feed** (`crates/trust/chio-pheromone/substrate.rs`
  `query_concentration`). Aggregate trust concentration only, never raw `query_deposits`
  (which carry origin-agent identity). Gifted at tier_0.
- **Own-tenant signed receipt / SIEM stream** (`crates/observability/chio-siem` `SiemEvent`
  via `ReceiptReadContext::authenticated_tenant`, `include_null_tenant=false`, financial
  metadata redacted unless owned). This is the user's OWN data returned legible and
  offline-verifiable. Always-free baseline right (see below), never gated.
- **Own-tenant lineage/provenance DAG views** (`crates/observability/chio-lineage/query.rs`,
  strictly the caller's own tenant subgraph, never cross-tenant). Same always-free posture.

Correction grafted from the tournament (D2/D3 mission critiques): own-tenant receipts and
lineage are the data subject's OWN footprint. They are a permanent Tier-0 baseline right,
NOT a tier-gated "reward". Gating a user's own audit trail behind earned reputation is the
textbook anti-generous move; we delete it.

EXCLUDED from the gift entirely: the liability/credit/bidding market surfaces (`chio-market`,
`chio-open-market` underwriting, `SignedCreditProviderRiskPackage`, bonds/penalties). These
are financial and e-money-adjacent; gifting them pushes the vehicle toward a security.

### Half B: a real metered free-compute allotment (the costly half, fail-closed, pre-funded)

This is the half that actually costs Chio fiat (first-party tool/agent inference), and it is
the half the mission promises to the newcomer. Funding source by phase:

- **Phase 0 (now): a board-approved, capped runway / customer-acquisition line.** We label it
  honestly. It is NOT a self-amortizing CAC and NOT a "fee rebate" (no fee rail exists yet;
  `FeeRouter`/`ChioTreasury` are unbuilt and Phase-3-gated per the roadmap). It is a stated,
  capped marketing burn with an expiry and a kill switch. Generosity cannot exceed the
  pre-funded pool because the kernel denies fail-closed when the pool empties (Section 3).
- **Phase 1+: fee-rebate, escrow-socketed.** Once a licensed partner and real non-artificial
  fee volume exist (the roadmap's M2 gate), the allotment graduates to a rebate hard-bounded
  to `<=` realized fees over the snapshot window, pre-funded into a `ChioEscrow` position with
  refund-after-deadline to the depositor (the no-cashout lever). It can never outrun revenue;
  if fees are thin (~$28k/day, ~50% artificial today) the rebate auto-shrinks toward zero
  while Half A keeps running for free.

Why generosity does not collapse at ~$28k/day: Half A mints nothing and its serving opex is
metered and capped under the same aggregate pool. Half B is a fixed pool today and a
fee-bounded rebate later; in both cases the kernel `budget_store` denies fail-closed on
exhaustion. The failure mode is "the gift shrinks", never "the treasury drains" and never
"the token inflates". The deliberate non-cosmetic choice (grafted from D1's mission critique
and D2's "newcomer gets nothing" critique): a genuinely-new identity gets a real Half-B
starter allotment at tier_0 on issuance, sized against a published cost example so the
newcomer can see they were given something that matters. Reputation tier governs the SIZE,
refill rate, and uplift of the allotment, never the existence of any allotment.

---

## 3. The utility half (generous AND useful)

The vehicle does real protocol work; it is not a badge.

- **Metering / access control.** The Pass is presented to the kernel, which mints a
  subject-bound (DPoP) `CapabilityToken` carrying a `ChioScope`
  (`crates/core/chio-core-types/src/capability/scope.rs`): `ResourceGrant{operations:[Read,
  Subscribe]}` for Half A and a `ToolGrant{max_total_cost, max_invocations,
  max_cost_per_invocation}` envelope for Half B. The kernel `budget_store`
  (`crates/kernel/chio-kernel/src/budget_store.rs`) meters the allotment down with saturating
  arithmetic and emits a Deny receipt (`cost_charged = 0`) on exhaustion. The Pass is the live
  access and metering primitive, so a holder shops and routes intelligently and runs real
  work from day one.
- **Own-tenant audit / compliance.** The gifted own receipt + lineage streams give the holder
  incident forensics, revocation-impact tracing, and SOC2-style evidence export for their own
  activity.
- **Portable reputation passport.** The Pass is a kernel-verifiable, offline-verifiable
  credential other Chio operators can verify to extend trust. (Note the load-bearing
  regulatory caveat in Section 5: we do NOT advertise this as a future "bond discount".)

Three NEW, additive utility/sustainability mechanisms the tournament proved are required.
All are inside the existing fail-closed kernel philosophy, zero new immutable contracts:

1. **Aggregate treasury pool (the missing budget control).** Today `budget_store` caps cost
   strictly per `(capability_id, grant_index)` (verified: `BudgetUsageRecord` at
   `budget_store.rs:17-19`, keyed lookups at `:263-264`). There is NO global ceiling, so the
   real liability is `N_passes x allotment`, unbounded by Chio's budget. We add a treasury-level
   monthly free-tier pool as a reserved global budget term (a synthetic
   `capability_id = "freetier:global:<YYYY-MM>"`) that every per-Pass charge also debits,
   denying fail-closed on exhaustion exactly like the per-Pass path. Liability becomes
   `min(N x allotment, POOL)`, a hard pre-funded line.
2. **Deterministic, window-scoped capability id (closes the re-mint reset).** Verified
   exploit: `budget_store` keys on the caller-supplied `CapabilityToken.id`, so re-presenting
   the Pass to mint a fresh UUIDv7 token yields a brand-new zeroed counter and resets the
   allotment. Fix: derive the token `id` deterministically as `H(subject_DID ||
   credential_AttestationWindow_id)`, pin the allotment grant to grant_index 0, and return the
   same canonical window-scoped token on every re-presentation. The `AttestationWindow` expiry
   becomes the monthly reset; re-minting cannot reset the counter.
3. **Refresh-on-genuine-use (kills the farmed annuity).** Soulbound, non-expiring Passes would
   otherwise draw allotment forever. Each window's allotment refresh is tied to fresh genuine
   receipt activity plus fresh re-attestation. Dormant or purely-extractive identities stop
   drawing; active genuine users keep their full allotment. This re-axes the kill-risk from
   "generous vs cheap-enough" to "generous to the actively-using, zero to the parked".

---

## 4. Anti-farm + distribution

Distribution is gated by ATTESTED identity and reputation, never raw wallet count, reusing
Chio's real trust machinery. Wallet-spray Sybils accomplish nothing: `chio-credentials`
binds every presentation to the subject DID (`artifact.rs:111-121`,
`PresentationHolderMismatch` / `PresentationVerificationMethodMismatch`), so the credential
is soulbound by construction.

### Distribution mechanism (exact)

Retroactive, attested, soulbound issuance; never a published farmable points formula (the
Hyperliquid lesson). A `did:chio` identity that clears a reputation floor is minted a Pass
credential signed by Chio's issuer key. Snapshots are taken retroactively over genuine
signed-receipt history at unpredictable times, with per-window admission throttled by
`chio-pheromone` `PheromoneScarcityPolicy.token_capacity` (`validation.rs`). The holder
presents the Pass (native or OID4VCI projection); the kernel mints the window-scoped
`CapabilityToken`. Issuance and revocation digests are anchored as a Merkle root in
`ChioRootRegistry` (`publishRoot` / `publishRootBatch`) so any verifier can prove
issuance/revocation offline via `verifyInclusionDetailed`.

### Anti-farm gating (with the tournament's verified hardening)

- **Tier_0 free reads for everyone** (Half A). Non-rivalrous, non-PII, no resale path; a
  successful "farm" of the read half extracts worthless reads. This is unconditionally safe to
  gift broadly, so we do.
- **Costly compute allotment (Half B) carries the real anti-farm load.** The verified
  weaknesses and their fixes:
  - **Issuer independence must be anchored, not self-declared.** Verified: `chio-federation`
    counts distinct `issuer_independence_group_id` strings, an `Option<String>` (reputation.rs:32)
    counted at `:229` against `minimum_independent_issuers` (default 2). Two free-text labels
    satisfy it; the second issuer is ~free. Fix: for the costly allotment, require each
    corroborating issuer to be a distinct `ChioIdentityRegistry` operator and (Phase 2+) hold a
    live slashable self-bond in the NEW audited vault, so over-vouching is slashable. Until
    issuer admission is anchored, `minimum_independent_issuers` gates only the read half, never
    the money-touching half.
  - **Reputation tier gates SIZE, with a real per-feed floor.** `tier.rs` tier_3 requires
    composed `>= 0.90` AND every shipped feed `>= 0.80` (`TIER_3_PER_FEED_THRESHOLD`) AND
    `distinct_feed_count >= 2`; `DEFAULT_INCIDENT_PENALTY = 0.20` claws back on misbehavior.
    Verified gap: only two feeds ship (`arena_survival`, `cross_provider_equality`), so
    "2 distinct" == "all of them". Action item: expand the feed catalog and weight history by
    distinct, independently-reputable counterparties so self-dealing plateaus below threshold
    the way single-arena floods already do.
  - **Refundable escrow activation deposit (optional, pulls the Phase-1 lever forward).** The
    compute allotment can be made to turn on only after the holder posts a small refundable
    deposit to a pre-funded `ChioEscrow` position with refund-after-deadline. Honest users get
    it back; an N-identity farm must fund N deposits, collapsing farmer ROI to `<= 0`. No new
    e-money surface (existing refund path), no minted unit.
  - **Aggregate pool + per-cluster cap.** The global pool (Section 3) bounds total leak; a
    per-issuer-corroboration-cluster cap bounds any single ring.
  - **Soulbound + access-only** means even a successfully farmed Pass has nothing to sell; the
    only harvestable value is the bounded, refresh-gated compute allotment.

---

## 5. Regulatory posture

Lowest-exposure posture on every flank, by construction, and we hold the line phase by phase.

- **Phase 0 (soulbound Pass, no money leg).** Securities: an access-only credential gifted
  for no consideration fails Howey's first prong; issuance is retroactive over past genuine
  usage, not a prospective "do X to earn", which the 2025-2026 SEC/Peirce framework treats
  most favorably; soulbound + non-redeemable blunts profit-from-others'-efforts because value
  is consumption, not appreciation. MiCA: a soulbound credential is not transferable, so it is
  excluded from MiCA scope entirely; non-pegged and non-redeemable, it is neither an e-money
  token (Art 3(1)(7)) nor an asset-referenced token. Money transmission: the Pass never
  accepts-and-transmits and never holds value; with zero `ChioEscrow`/`ChioBondVault` touch
  there is no MSB/MTL surface. Tax: framed correctly as promotional free-tier / customer-
  acquisition / no-realizable-FMV / first-party limited-network, NOT the incoherent
  "non-transferable therefore no income" theory (which conflates transferability with
  realization). The allotment is denominated in `CostDimension::Custom` non-monetary units
  (a 3-letter private-use code, e.g. `XCC`), never top-up-able with funds, never spendable
  outside first-party Chio tooling, preserving both the MiCA limited-network exclusion and the
  promotional tax character.
- **What would cross the line in Phase 0 (and is therefore severed):** any "credible-but-
  unpromised future CHIO" tease, and any "Phase-2 bond-discount onramp" / "lower bond
  requirements" language. Both are the regulatory falsifiers. A forward economic benefit tied
  to HOLDING the credential reintroduces Howey prong 3/4; a cultivated conversion expectation
  reintroduces it via totality-of-communications (Telegram / Kik). We strike both from all
  Pass documentation and issuance terms, with an explicit recital: no future value, no
  appreciation, no economic advantage, no expectation of profit. Any future reputation-to-bond
  linkage, if ever built, is a SEPARATE counsel-gated instrument evaluated on its own facts.
- **Phase 1 (money-backed usage, escrow-socketed).** Settles in USDC through the immutable
  `ChioEscrow`; refund routes to the depositor, never the holder, so the recipient never holds
  cash-redeemable funds. Closed-loop, first-party-only redemption targets the FinCEN 31 CFR
  1010.100(ff)(4) exemption; a NAMED LICENSED PARTNER is issuer of record, custodian, and
  BSA-obligated principal (the roadmap's M2 gate). What crosses the line: a USD-denominated
  balance spendable across an OPEN marketplace of third-party providers reads as stored value /
  e-money. We keep the user-facing unit non-monetary and the redemption first-party
  (per-provider curated escrow, Section 7), so the partner buys capacity rather than relaying
  user value.
- **Phase 3 (conditional governance / transferability).** Highest exposure; owned honestly.
  Transferability triggers MiCA CASP/white-paper duties and a taxable FMV event, and on a
  centrally-run network reintroduces Howey with a live secondary market. It ships only behind
  the roadmap's Phase-3 gate AND as a soulbound predecessor first, AND grants Pass holders
  ZERO retroactive claim (Section 6, M6).

**Transferability / redeemability stance:** soulbound and access-only at every phase the
benevolent vehicle actually occupies (Phase 0 through 2). Free transferability is never a
property of the gift; it is a separate, conditional, counsel-gated terminal escalation that
the gift does not entitle anyone to.

---

## 6. How it slots into the gate (phase-by-phase, and which roadmap milestones change)

Phase placement of the benevolent vehicle:

- **Phase 0: soulbound Pass + day-zero starter allotment + free aggregate-feed reads.** No
  token, no money leg, no external gate. This is a NET-NEW benevolent distribution layer the
  prior roadmap did not contemplate (the roadmap's Phase 0 was settlement-only, "no-token").
- **Phase 1: money-backed usage graduates** onto escrow-socketed prepaid, partner issuer-of-
  record. The Pass is the credential the gifted usage attaches to.
- **Phase 2: bonding economics** (USDC self-restitution bonds, then the new slashable vault)
  harden issuer independence for the costly allotment. The Pass remains a portable passport,
  but bond-discount linkage is NOT advertised as a Pass feature.
- **Phase 3: at most a soulbound-then-conditionally-transferable governance credential**, with
  no retroactive Pass entitlement.

Roadmap milestone changes (stated explicitly):

- **M0 (changes): add the benevolent Pass to the hardened tokenless launch.** The roadmap's M0
  was USDC-only settlement plus inert allowlist metadata. We ADD: issue the soulbound Chio
  Pass, gift the tier_0 aggregate-feed reads, and gift a day-zero Half-B starter allotment
  funded by a board-approved capped runway pool with the aggregate-pool ceiling, deterministic
  window-scoped capability id, and refresh-on-use controls. This is consistent with
  tokenlessness (the Pass is non-token, soulbound, access-only) but it converts the launch from
  "settlement rail" to "settlement rail PLUS distribution-first gift". New gate evidence for
  M0: the aggregate pool is pre-funded and fail-closed in tests; the deterministic-id re-mint
  reset is closed in tests.
- **M1 (unchanged): reference it.** The off-chain single-denomination netting collapse is
  orthogonal to the gift; no change.
- **M2 (changes scope, not gate): the closed-loop prepaid credit also serves the gift.** Same
  fail-closed gate (counsel sign-off on closed-loop + MiCA e-money; named licensed partner;
  measured bottleneck). The escrow-socketed prepaid now funds the Half-B rebate graduation, and
  the optional refundable activation deposit (anti-farm) reuses the same `ChioEscrow` refund
  path. Add a fee-COVERAGE test: arm the money half only when trailing realized non-artificial
  fees can fund the cohort.
- **M3 (clarifies, does not change gate): de-couple the Pass from bond marketing.** Self-
  restitution USDC bonds proceed as in the roadmap. New constraint: the Pass / reputation
  passport must NOT be marketed as lowering bonds (securities seam). Underwriting may quietly
  price bonded operators favorably; it is never a Pass-holder entitlement.
- **M4 (extends): the new `ChioSlashableBondVault` also anchors issuer independence.** Beyond
  involuntary restitution, the slashable vault gives corroborating issuers slashable skin, which
  is what makes "2 independent issuers" a real cost for the costly allotment.
- **M5 (unchanged): governance handoff** via `transferAdmin` to Governor+Timelock proceeds as
  the roadmap specifies.
- **M6 (changes framing): the Pass confers NO retroactive token claim.** The roadmap requires a
  soul-bound predecessor before any transferable CHIO. The Pass IS that predecessor in spirit,
  but we explicitly state it is NOT a claim: if CHIO ever ships it is an independent,
  counsel-gated distribution with its own fresh Howey analysis, granting Pass holders zero
  retroactive entitlement, so prior years of Pass activity can never be re-characterized as the
  consideration leg of an integrated scheme.

The roadmap's Section 7 kill-criteria are inherited unchanged and extended in Section 8 below.

---

## 7. Smart-contract + crate work

Honors the immutable spine and every verified hard constraint: no restricted-ERC20 settlement
leg, escrow-socketed prepaid, 3-letter currency codes, self-slash-only reality, NEW
deployments alongside the spine (never edits to the immutable four).

### Contract touchpoints

- **`ChioRootRegistry.sol` (IMMUTABLE, read-only compliance use):** `publishRoot` /
  `publishRootBatch` anchor a Merkle root of issued and revoked Pass digests;
  `verifyInclusionDetailed` gives offline proof a Pass is valid/revoked. No value moves.
- **`ChioIdentityRegistry.sol` (the ONE mutable contract, admin = multisig+timelock):**
  optional advisory anchoring of Pass-issuer authority via `registerOperator` /
  `registerDelegate`; in Phase 2+ the registry operator graph is what anchors issuer
  independence for the costly allotment. Non-gating metadata only.
- **`ChioEscrow.sol` (IMMUTABLE):** UNTOUCHED in Phase 0. In Phase 1+ the money-backed usage
  re-sockets onto a pre-funded position; verified, `refund` pays `terms.depositor`
  (ChioEscrow.sol:159-167, the no-cashout lever) and `_release` pays a single
  `terms.beneficiary` (`:264`). Because one position has one fixed beneficiary, the gift uses
  per-provider curated positions (depositor = partner, beneficiary = the specific provider),
  NOT a single mega-escrow with a partner-beneficiary (that variant re-creates accept-and-
  transmit money transmission and is forbidden). The optional anti-farm activation deposit
  reuses the same refund-after-deadline path.
- **`ChioBondVault.sol` (IMMUTABLE):** UNTOUCHED in Phase 0/1. Verified: `impairBondDetailed`
  (`:124-136`) is self-slash-only (`msg.sender == bond.terms.operator`). Phase 2 voluntary
  self-restitution bonds work within this. The Pass adds no bond leg.
- **`ChioPriceResolver.sol` (IMMUTABLE):** UNTOUCHED. No CHIO/USD feed is registered; no peg.
- **`ChioSlashableBondVault.sol` (NEW, audited, Phase 2/4 only):** the only new value contract,
  and only if involuntary slashing is required, because the immutable vault permits self-slash
  only. Federation-gated slasher role; licensed partner as principal-of-record. Doubles as the
  issuer-independence bond anchor.

### Crate touchpoints

- **`crates/trust/chio-credentials` (`lib.rs`, `artifact.rs`):** the soulbound Pass format
  (Ed25519 JSON-signed, `did:chio` subject-bound, `AttestationWindow` expiry); the
  presentation-holder-key == subject check (`artifact.rs:111-121`) is the non-transferability
  enforcement. Add the retroactive snapshot + Merkle-anchoring issuance pipeline here (avoid a
  discretionary marginal-contribution oracle: that was D6's unsolved kill-risk; keep
  eligibility a coarse attested-tier step function, not a constructed score).
- **`crates/core/chio-core-types/src/capability/scope.rs` and `token.rs`:** `ChioScope`,
  `ResourceGrant{operations:[Read,Subscribe]}`, `ToolGrant.max_total_cost/max_invocations`,
  `is_subset_of` attenuation; subject-bound (DPoP) `CapabilityToken`. NEW glue: derive
  `token.id = H(subject_DID || AttestationWindow_id)`, pin allotment grant_index 0.
- **`crates/kernel/chio-kernel/src/budget_store.rs`:** meters the allotment fail-closed
  (`BudgetUsageRecord`, saturating arithmetic, `BudgetStoreError::Overflow/Invariant`). NEW
  additive change: the aggregate global pool term debited by every per-Pass charge, denying
  fail-closed on exhaustion. Zero new contracts, no schema rewrite.
- **`crates/kernel/chio-kernel/src/receipt_query.rs`:** `ReceiptReadContext::authenticated_tenant`
  (`include_null_tenant=false`) gates the own-tenant data streams.
- **`crates/trust/chio-reputation/src/tier.rs`:** allotment SIZE gating (tier governs size, not
  existence). Action: expand `src/feeds/` beyond the two shipped feeds so `distinct_feed_count >= 2`
  demands genuinely independent evidence; weight by distinct counterparties.
- **`crates/trust/chio-federation/src/reputation.rs`:** replace self-declared
  `issuer_independence_group_id` trust with registry/bond-anchored independence for the costly
  allotment (keep `minimum_independent_issuers=2`, `oracle_cap_bps=4000` for the read half).
- **`crates/trust/chio-pheromone/src/validation.rs`:** `token_capacity` per-window admission +
  `newcomer_horizon`; ADD a cumulative active-Pass population cap so the pool can be sized
  deterministically.
- **`crates/economy/chio-metering/src/cost.rs`:** `CostDimension::Custom{name,value,unit}`
  denominates the allotment in non-monetary units, off any e-money peg.
- **`crates/economy/chio-listing/discovery.rs`:** the gifted listing/pricing feed and raised
  result caps.
- **`crates/observability/chio-siem` and `crates/observability/chio-lineage/query.rs`:**
  own-tenant receipt and lineage streams with financial redaction.
- **`crates/economy/chio-settle/src/payments.rs`:** Phase-1 `X402SettlementMode::EscrowBacked`
  re-sockets the money-backed half onto escrow. `chio-credit/src/hook.rs` left untouched
  (`IouEnvelopeBody` is post-consumption, cannot mint a prepayment).
- **`crates/link/chio-link` `convert.rs`:** `minor_units_for_currency` stays USDC-pinned; do
  NOT pin a CHIO code (fail-closed-at-conversion per the roadmap). Any credit sub-unit is a
  3-letter ISO private-use code (`XCC`), never `CHIOCREDIT` (`chio-underwriting/premium.rs:141`
  rejects non-3-letter codes).

---

## 8. Risks + kill-criteria (benevolent-model-specific)

Inherits the roadmap's Section 7 kill-criteria. Additional, specific to the gift:

- **Gift-farming of the costly allotment.** Kill-trigger: farmed/attested-but-extractive
  identities consume a material fraction of the pool despite the anti-farm stack (registry/
  bond-anchored independence, refresh-on-use, activation deposit, per-cluster cap). Action:
  shrink the per-Pass allotment AND tighten issuer anchoring BEFORE shrinking the newcomer
  starter grant (never erode generosity to the actively-using as the first lever). If farmer
  ROI cannot be driven `<= 0` without making the gift de minimis, gate the costly allotment
  behind the activation deposit unconditionally.
- **Generosity insolvency.** Kill-trigger: monthly aggregate-pool burn cannot be funded from
  board-approved runway (Phase 0) or trailing realized non-artificial fees (Phase 1+). Action:
  the aggregate pool denies fail-closed (gift degrades to read-only), the money half disarms;
  the vehicle collapses gracefully to the free read tier, which costs near-zero and is the
  honest floor. Generosity shrinks; the treasury never drains. This is by construction, not by
  discretion.
- **The "gift" becoming a disguised security.** Kill-trigger (any of): a secondary/OTC market
  prices the Pass or its allotment despite soulbinding; founder/influencer comms cultivate a
  future-token conversion expectation; the bond-discount linkage gets advertised as a Pass
  feature; a Phase-3 transferable token is structured to grant Pass holders retroactive claim.
  Action: treat the OTC/secondary-market event as a stop-event (the roadmap's line-116
  criterion); enforce the comms policy as binding terms; if a future-conversion expectation
  cannot be kept genuinely unformed, the only safe form is the pure soulbound access vehicle
  with no token at all.
- **Mis-aimed (regressive) generosity.** Kill-trigger: the costly half flows up the reputation
  ladder to incumbents while newcomers get only zero-marginal reads (the Matthew-effect failure
  the tournament flagged). Action: the day-zero tier_0 starter allotment is the structural fix;
  if telemetry shows the median newcomer receives nothing material, re-size the starter grant
  upward (it is the mission-critical line), not the incumbent uplift.

---

## 9. Appendix: the six tournament designs (fair summary, score, placement)

- **D1 Chio Pass (overall 8).** Soulbound, non-transferable, non-redeemable credential on
  `chio-credentials` gifting aggregate-feed reads + a bounded metered allotment. Champion on
  every safety axis (zero immutable-contract touch, no money leg, no CHIO code, fails Howey
  prong 1, outside MiCA, structurally non-inflationary, ships Phase 0 with no external gate).
  Placed first because it is the best-in-class safe benevolent onboarding vehicle and verified
  clean against the codebase. Two honest residuals (no transferable value; bounded compute is
  farmable via aged/colluding attested identities) are exactly what this design fixes by
  amputating the token wink, hardening issuer independence, adding the aggregate pool, and
  moving the costly half to the newcomer. CHOSEN as the spine.

- **D3 Chio Merit (overall 8).** Off-chain soulbound contribution points, access-only,
  spendable only for gifted reads + metered usage, with a "credible-but-unpromised future
  CHIO". Strongest pure access-only design and most faithful to the hard constraints (every
  technical claim verified). Tied for top score but placed behind D1 operationally because its
  defining hook (the token tease) is its own kill-risk: held with discipline it does no
  economic work, held loosely it reintroduces Howey-via-totality and farm pressure, and the
  Merit ledger is a centralized discretionary allocator. GRAFTED: the off-chain retroactive
  snapshot discipline; REJECTED: the token tease (amputated per Section 5).

- **D6 Commons Dividend (overall 8).** Dual-rail: a soulbound data-dividend (free premium reads
  of feeds your receipts helped build) plus a fee-funded usage rebate. Genuinely generous,
  fully constraint-compliant, verified. Tied for top score but held back by its load-bearing
  unsolved problem: marginal-contribution measurement is a constructed score that becomes a
  farm target and a discretionary-oracle capture surface, and Rail B's fungible-output +
  single-beneficiary-escrow mismatch breaks the "run guards on the house" promise. GRAFTED: the
  "return the user's own data enriched" framing as a permanent baseline right, and the per-fee-
  payer rebate discipline; REJECTED: the discretionary contribution oracle (kept eligibility a
  coarse tier step function instead).

- **D2 Welcome Socket (overall 7).** A licensed partner pre-funds escrow and gifts metered
  usage + tiered reads; refund-to-depositor. Best-in-class benevolent STRUCTURE, throttled by
  external reality (tiny rebate on a thin/artificial fee base) and hard-gated on a named
  licensed partner that does not exist today. Its mechanism contradicted its "day-1 welcome"
  story (retroactive snapshot excludes newcomers). GRAFTED: the escrow-socketed money-backed
  usage as the Phase-1 graduation, the per-provider curated-escrow fix, and the decisive
  "front-load a real starter grant to newcomers" correction. Placed fourth on ship-time and the
  partner double-bind, not on design quality.

- **D4 Anchor Bond (overall 6).** A refundable USDC bond doubles as operator collateral AND a
  membership key unlocking tiered gifts + rebates. Technically exemplary and best sustainability
  story, over-engineered Sybil resistance. Placed fifth because the bond-to-unlock fusion makes
  the gift regressive (flows to the already-capitalized, excludes small/non-operator users),
  the money half is a coupon not a gift, and the lock-USDC-get-value-back pairing is the
  e-money/Howey knife-edge. GRAFTED: bond-anchored issuer independence for the costly allotment,
  and the "sever uncapped benefits from the gameable tier until involuntary slashing exists"
  discipline; REJECTED: gating the gift itself behind a bond.

- **D5 Burn-to-Access (overall 5).** A freely transferable, fixed-supply CHIO burned for a
  soulbound access pass. Technically careful and genuinely generous, but placed last on
  regulatory safety and ship-time: free transferability with a live secondary market is the
  inverse of the least-exposure posture (full MiCA CASP/white-paper, taxable FMV airdrop,
  Howey-with-a-live-market if still centrally run), the fee-funded buyback re-imports the
  yield-switch profit-expectation, and the soulbound cap binds the wrong leg (the farmer sells
  the airdropped CHIO, never burns). KEPT ON THE SHELF as the terminal Phase-3 escalation only;
  its own honest verdict is that it must not launch until a 2027+ world of real fees and
  measurable decentralization exists, exactly the roadmap's M6 gate.

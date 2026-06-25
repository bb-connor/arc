# Chio Domain Research 2026: Tokenomics, Vaults, Settlement, and Distribution

Status: research synthesis for protocol-strategy decisions. Author: head of protocol research.
Date: 2026-06-25.

Scope: ties external domain research (the Hyperliquid playbook, EVM vault/shared-security
primitives, the Solana stack, agent-economy payment/attestation tech, and distribution /
anti-sybil / US-regulatory practice) directly to Chio's actual token, Pass, vault, and
settlement decisions as recorded in `docs/brainstorm/CHIO-TOKEN-AND-CONTRACTS-PLAN.md` (the
roadmap) and `docs/brainstorm/CHIO-BENEVOLENT-TOKEN-DESIGN.md` (the Pass decision).

How to read this document:
- Every external protocol or venue carries a US-accessibility flag: `yes`, `no`, or
  `unclear`. The founder is a US person.
- Hyperliquid is geo-blocked for US persons (confirmed: Terms 1.5, IP geofencing, VPN
  blocking, restriction follows US citizens regardless of location). It is therefore a
  DESIGN REFERENCE to copy on a US-accessible chain (Base / Arbitrum / Solana / Ethereum),
  never a venue Chio integrates or the founder transacts on. Section 2 gives the concrete
  replication path for each Hyperliquid mechanic.
- Claims the fact-check pass marked wrong, outdated, or unconfirmed are labeled inline as
  `[needs-verification]` or corrected, and are never asserted as settled fact.
- House style: no em dashes; hyphens and parentheses only.

Anchoring decisions (the fixed points everything below maps to):
- Chio is a protocol for attested, capability-based tool access for AI agents. The core is a
  signed receipt / attestation log.
- Settlement is in external stablecoins (USDC via EIP-3009 / permit) on Base / Arbitrum.
- The immutable on-chain family is `ChioRootRegistry` (Merkle-anchored receipts), `ChioEscrow`,
  `ChioBondVault` (self-slash-only), `ChioPriceResolver`. Only `ChioIdentityRegistry` is
  mutable (admin = multisig+timelock). Confirmed against `contracts/src/`.
- Launch posture is tokenless, fail-closed, with a phased gate: no-token -> credit -> staking/
  bonds -> governance.
- The launch distribution vehicle is the soulbound Chio Pass: gifts trust-feed reads plus a
  day-zero free-compute allotment; no token, no money leg.
- Future seams (designed, not deployed): `ChioSlashableBondVault`, an insurance / underwriting
  pool, a treasury / fee router, and at most a conditional transferable token in Phase 3.

---

## 1. Executive summary: highest-leverage takeaways

Each takeaway carries a stance: adopt (do it, low new surface), pilot (build a scoped
prototype behind a gate), watch (track, do not build yet), avoid (explicit do-not).

1. Distribute the Chio Pass the way Hyperliquid distributed HYPE: retroactive, usage-weighted,
   sybil-filtered, opaque-formula, push-not-claim. Stance: ADOPT. Hyperliquid's genesis
   airdrop (29 Nov 2024, ~310M HYPE = 31% of a fixed 1B supply, to over 90,000 wallets (~94k),
   zero VC / private-investor allocation, no airdrop unlock cliffs) is the confirmed gold
   standard. Chio already specifies this shape (Benevolent-Token Section 4). The external
   evidence confirms it: published live points formulas got farmed to death (zkSync) and
   churned; retroactive surprise sustained. Express it as a soulbound credential with a Merkle
   claim anchored in `ChioRootRegistry`, with no token and no money leg.

2. Build the insurance / underwriting pool on the HLP "community backs the house, keeps the
   edge, eats the losses" shape, but only behind the Phase 2 gate with a licensed insurer as
   principal of record. Stance: PILOT. HLP (community USDC vault, no performance fee, PnL and
   LOSSES socialized pro-rata, 4-day withdrawal lockup, confirmed) is the cleanest blueprint
   for the `chio-underwriting` ReserveBook. US-accessible replication exists today on Base via
   ERC-4626 / ERC-7540 plus the Symbiotic Slashing-Insurance-Vault tranching design.

3. The involuntary-slash-to-restitution flow Chio's M4 needs is now a live, US-accessible,
   audited reference: EigenLayer Redistributable Slashing (ELIP-006, mainnet 22 Jul 2025).
   Stance: ADOPT (the mechanics, into a standalone USDC vault), WATCH (depending on EigenLayer
   at runtime). The Cap Protocol pattern (slashed operator stake redistributed to protect
   stablecoin holders instead of burned) is exactly the M4 flow. Copy the mechanics
   (immutable `redistributionRecipient`, permissionless clear-and-route, safety-delay window,
   reputation-based veto committee) into `ChioSlashableBondVault`; do not bet custody on
   EigenLayer itself, whose US-accessibility for an EIGEN-staking US founder is `unclear`.

4. Issue the Chio Pass on Solana as a Token-2022 NonTransferable (soulbound) credential via
   the Solana Attestation Service, OR keep it on EVM as an EAS / ERC-8004 attestation. Stance:
   PILOT (Solana issuance), ADOPT (EVM attestation anchoring). Token-2022 NonTransferable makes
   soulbinding a protocol-enforced property (fail-closed, no contract logic to write), and a
   NonTransferable mint is automatically un-poolable on Orca. This is the strongest structural
   fit for "access, not a tradeable asset." Caveat: it is a new non-EVM runtime alongside
   Chio's EVM-canonical credential, so pilot, do not adopt wholesale.

5. Align with x402 / MCP as the external payment leg and position Chio as the attestation and
   verification layer ABOVE it; do not rebuild payments. Stance: ADOPT (verify-path alignment),
   WATCH (deeper co-design). x402 settles USDC via EIP-3009 `transferWithAuthorization`, the
   exact leg Chio already chose. A licensed facilitator (Coinbase CDP) moves money; Chio signs
   and proves. This keeps the custody-neutral, prepare-only spine.

6. Do not reinvent the attestation registry; publish Chio receipt-batch Merkle roots to EAS
   (Base) and / or Verax, and register the Pass in ERC-8004 Identity / Reputation. Stance:
   ADOPT (anchor to EAS), PILOT (ERC-8004 registration). EAS Private Data attestations are
   byte-for-byte Chio's "Merkle tree of arbitrary data, post only the 32-byte root on-chain"
   model. Keep `ChioRootRegistry` as the immutable source of truth that interoperates.

7. Do not copy the Assistance Fund's token buyback, and do not mint a native asset to enable
   bonding / slashing / underwriting. Stance: AVOID. EigenLayer, Symbiotic, and Nexus all
   deliver slashable security and underwriting with external collateral (USDC / LSTs); no
   native token is required for the mechanism. A HYPE-style fee->token buyback would manufacture
   the buy-and-stake / yield profit-expectation the token plan rejects under Howey. Copy the
   Assistance Fund's auto-routing and keyless-sink credibility, terminate value in community
   utility (underwriting reserve plus free-compute for Pass holders), never in a token bid.

---

## 2. Copying the Hyperliquid playbook on a US-accessible chain

This section is the explicit Hyperliquid-copy plan. Hyperliquid is US-accessible: `no`
(confirmed: US heads the Restricted Persons list under Terms 1.5; IP geofencing plus
VPN-blocking; the restriction follows US citizens regardless of physical location; no CFTC /
SEC registration). The founder cannot use it. Every mechanic below is therefore copied onto a
US-accessible chain. For each mechanic: what it is (with fact-checked figures), the concrete
Solana / Base / Ethereum replication path, and the Chio mapping.

### 2.1 Fair retroactive airdrop (the HYPE distribution model)

What it is (confirmed): a no-VC, no-private-sale retroactive distribution. Roughly five points
"seasons" rewarded genuine activity (perps volume, maker liquidity, deposits, HLP deposits,
referrals) with a deliberately opaque formula to defeat farmers; wash trading and linked-wallet
farming were penalized as sybil. The TGE on 29 Nov 2024 pushed ~310M HYPE (31.0% of the fixed
1B supply) to over 90,000 wallets (~94k), with ZERO VC / private-investor allocation and no
airdrop unlock cliffs (cliffs apply only to team / core contributors). Tokenomics split
(confirmed): Genesis 31.00%, Future Emissions & Community Rewards 38.89%, Core Contributors
23.80%, Hyper Foundation 6.00%, Community Grants 0.30%, HIP-2 0.01%.

Corrections folded in:
- The claim "Season 2 farming is still running into 2026" is NOT confirmed. The official points
  program ended at the Nov 2024 TGE (eco.com: "no points farming season after the snapshot").
  Ongoing staking-points exist (staked HYPE accrues points per day), and a second airdrop is
  widely speculated on SEO / airdrop-farming sites, but Hyperliquid has not officially announced
  one. Treat a "Season 2 airdrop" as `[needs-verification]` / unconfirmed.
- The claim that "~85% of new airdrops now copy Hyperliquid's weighting" has no primary source
  and is dropped. Hyperliquid is correctly described as the benchmark airdrop; the precise
  percentage is not asserted.

US-accessible replication path:
- Base / Ethereum: keep an off-chain "Chio points" ledger scoring genuine usage from the signed
  receipt log (tool-call volume, honest-provider streaks, early-provider liquidity) across
  multiple seasons; at an unpredictable snapshot, publish the eligible set as a Merkle root via
  `ChioRootRegistry.publishRoot`; users claim a soulbound credential (an ERC-721 with transfers
  disabled, plus OpenZeppelin MerkleProof) or, better for UX and the no-consideration posture,
  Chio pushes issuance with no claim transaction (see 2.1 push-not-claim).
- Solana: claim against a published Merkle root using a soulbound (NonTransferable) Token-2022
  credential (Section 4).

Push-not-claim detail (confirmed): Hyperliquid pushed tokens with no claim transaction, no
Merkle-query, no expiry, eliminating the 5-10% expired-claim loss AND avoiding a user "claim
action" that could read as consideration. Chio should auto-issue the soulbound Pass to an
attested `did:chio` the instant it enters a snapshot. This is both better UX and cleaner under
the SEC March-2026 no-consideration airdrop carve-out (Section 6).

Chio mapping: this is the Pass distribution mechanism, already chosen in Benevolent-Token
Section 4 (retroactive, attested, soulbound, never a published farmable formula, Merkle-anchored
in `ChioRootRegistry`). The external evidence confirms the choice. Stance: ADOPT.

### 2.2 HLP community-deposit vault

What it is (confirmed): a protocol-owned vault running Hyperliquid's own two-sided market-making
and liquidation strategies. Anyone with USDC on Hyperliquid can deposit; the vault is
community-owned. PnL (after fees / rebates) is socialized pro-rata; crucially there is NO
performance fee and depositors share LOSSES too (the March 2025 whale-liquidation drawdown of
roughly $4M is a real example of symmetric loss). 4-day withdrawal lockup. Positions, fills, and
balances are fully visible on the L1's public state. US-accessible: `no`.

US-accessible replication path:
- Base / Arbitrum: deploy an ERC-4626 USDC vault. Depositors pool USDC, receive pro-rata shares,
  and earn provider-bond premium income; they also share restitution payouts pro-rata (HLP's
  symmetric drawdown is the honest framing of underwriting risk). Add a withdrawal lockup
  mirroring HLP's 4 days, implemented as ERC-7540 async request-then-claim so entry / exit gates
  on an adjudication or epoch boundary and cannot be front-run around a pending slash. ERC-4626
  is US-accessible (`yes`), the mature default vault standard with OpenZeppelin (virtual-share
  inflation-attack defense) and Solady (gas-optimized) reference implementations. ERC-7540
  (async vaults, finalized June 2024 by authors from Centrifuge, Superform, Maple) is the right
  interface when mint / redeem must wait on an off-chain attestation (US-accessible: `yes`).
- Solana: a 4626-shaped Anchor program holding native USDC, with deposit / withdraw share
  accounting and SAS-attestation-gated depositor eligibility (fail-closed for non-eligible US
  persons rather than front-end geo-blocking).

Chio-specific guardrail absent from Hyperliquid: the vault must be operated by the licensed
insurer / surety partner as principal of record (Phase 2 gate), denominated strictly in USDC so
underwriters can mark to market. This is the single most important structural copy for the
insurance / underwriting-pool seam.

Chio mapping: this is the `chio-underwriting` ReserveBook (roadmap line 73,
`CapitalBookSourceKind::ReserveBook` on a licensed partner's books) plus the `bond_depth`
premium hook (larger live USDC bond -> lower `base_rate_cents`). Stance: PILOT (behind Phase 2,
named insurer as principal of record).

### 2.3 User-followable vaults (decentralized copy-trading)

What it is (confirmed): any user creates a vault others deposit into; the leader trades pooled
capital and depositor positions replicate pro-rata. Leader takes a 10% profit share
(performance-fee only), must seed >=100 USDC and maintain >=5% of the vault at all times, and
cannot withdraw below that floor (the "leader can never withdraw depositor principal" framing is
a slight gloss on the 5%-floor rule but directionally correct). Flat 10,000 USDC creation fee
routed to the protocol like trading fees. Depositors withdraw after a 1-day lockup. One tracked
leader posted ~1,021% in a month (confirmed; note the source DL News article predates
Hyperliquid's own L1 and calls it "built on Arbitrum" - cite the return, not that framing, since
Hyperliquid now runs its own L1). Influencers also publicly blew up vaults, illustrating the
symmetric risk. US-accessible: `no`.

US-accessible replication path (Base): an operator "copy-underwriting" vault where backers
deposit USDC behind that operator's `ChioBondVault` bond. The operator earns only a capped
profit / fee share, must keep a minimum self-bond percentage (HLP's >=5% maps directly), and can
never withdraw backer principal. Route a FLAT vault-creation fee to the treasury (Hyperliquid's
10k flat fee maps cleanly onto Chio's flat-fee-not-bps rule). Backing depth feeds the planned
`bond_depth` premium hook (more backing -> lower premium) without folding stake into trust
weight. Use the Morpho Vaults V2 / Yearn V3 curator framework for the manager role (Section 3).

Chio mapping: skin-in-the-game rules for `ChioBondVault` and the future `ChioSlashableBondVault`.
Pooling third-party capital behind an operator carries real securities / custody surface, so this
is gated behind the Phase 2 licensed-partner. Stance: WATCH (advance only once underwriters
confirm they price off a posted bond, roadmap research item 5).

### 2.4 Assistance Fund buyback (fee-funded value-accrual flywheel)

What it is (confirmed core): an automated on-chain mechanism that converts protocol trading fees
into HYPE on the open market and routes them to the keyless system address
`0xfefefefefefefefefefefefefefefefefefefefe`, which has no keys and no control (a credibly-neutral
keyless sink; tokens there are permanently inaccessible without a hard fork). Fees go entirely to
the community: HLP, the Assistance Fund, and deployers (spot and HIP-3 perp deployers may keep up
to 50% of fees from assets they deploy). US-accessible: `no`.

Corrections folded in:
- The Assistance Fund collects ~97-99% of protocol trading fees and uses them for open-market
  HYPE buybacks (launched Jan 2025 at 97%, raised toward 99% via a Dec 2025 vote). The earlier
  framing of "~90% to buybacks, ~10% to HLP LPs" is garbled and dropped: HLP is a SEPARATE
  deposit-any-USDC vault earning market-making PnL; it does not receive a 10% slice of the AF and
  does not buy HYPE.
- By May 2026 the AF had crossed the $2B milestone; the earlier confirmable peak was ~28.5M HYPE
  worth ~$1.5B. The "~44.4M tokens worth >$2B" exact token count is `[needs-verification]`; only
  the >$2B value is independently confirmed.
- "Buys ~$1M HYPE/day" is a stale early-2025 figure. With ~$1.3B annualized fees by mid-2026 at
  97-99%, daily buybacks are materially higher (multi-million/day). Present as a growing run-rate,
  not a fixed $1M/day.
- The Dec 2025 validator vote on AF supply PASSED (correction from "proposed"): Hyper Foundation
  reported 85% for burning, 7% against, 8% abstaining, and the AF HYPE was formally recognized as
  burned; The Defiant framed it as roughly 13% of circulating supply.
- Context figures (confirmed): July 2025 ~$320B monthly perps volume and ~$86.6M protocol revenue
  (record at the time, ~35% market share); ~$1.3B annualized revenue by mid-2026.

US-accessible replication path (Base / Ethereum), with the buyback deliberately dropped:
- Build `ChioTreasury` / `FeeRouter` to auto-split FLAT USDC fees into (a) the underwriting
  reserve pool (the HLP analog), (b) free-compute funding for Pass holders (the "give back to
  users" sink), and (c) a published, keyless lock / burn address for any closed-loop credit, so
  neutrality is provable on-chain the way Hyperliquid's keyless system address is.
- Explicitly do NOT buy back a CHIO token. A fee->token bid manufactures exactly the
  buy-and-stake / yield profit-expectation the token plan rejects as fatal under Howey (roadmap
  Section 2, P4 kill; Benevolent-Token Section 5). If a Phase 3 token ever ships, keep
  fee->reserve / utility, never fee->buyback.

Chio mapping: the treasury / fee-router future seam (roadmap Phase 3, `ChioTreasury` / `FeeRouter`
for flat fees). Copy the automation and keyless-sink credibility; terminate value in community
utility, never in a token bid. Stance: ADOPT (auto-routing + keyless sink), AVOID (token buyback).

### 2.5 Builder codes (permissionless per-order fee attribution)

What it is (confirmed): any app routing trades through Hyperliquid tags fills with its builder
address and earns an extra fee, set per-order. The user signs a one-time ApproveBuilderFee (main
wallet, capping max fee); builders claim via the referral flow. Fee caps: 10 bps (0.10%) for
perps, 100 bps (1%) for spot, with the fee parameter in tenths-of-bps (f:10 = 1bp). The decisive
design choice: NO application, NO approval committee, NO partnership negotiation; the only gate is
>=100 USDC perps account value and standard account mode. US-accessible: `no`.

Outcomes (confirmed, with one upward correction): builder codes generated over $40M total
developer revenue. The top three builders actually sum to roughly $43M (Phantom ~$20.6M,
BasedOneX ~$15.1M, PVP.trade ~$7.95M per CoinGecko), so the earlier ">$31M collectively" is a
conservative understatement and can be raised. Phantom earns roughly $100k/day from routed trades.
PVP.trade's "$7.2M lifetime" is a slightly stale snapshot (~$7.95M more recently). The headline is
that removing all gatekeeping bootstrapped an entire ecosystem of front-ends on shared liquidity.

US-accessible replication path (Base / Solana): add an optional attribution address field to the
Chio receipt / approval envelope; the `FeeRouter` splits a capped FLAT per-call integrator fee to
that address, claimable on demand. No application, no committee; the only gate is a small minimum
balance / reputation floor. Keep the fee FLAT and capped (a tenths-of-bps-style cap), consistent
with Chio's flat-fee-not-bps rule. This is Hyperliquid's growth loop expressed as receipt metadata
rather than an order-book primitive.

Chio mapping: a permissionless integrator / referrer code layer that bootstraps third-party agent
front-ends, wallets, and analytics on Chio's settlement rail. Stance: PILOT (confirm flat-fee
mechanics and abuse controls before opening fully).

### 2.6 HyperEVM / HyperBFT narrow stake-weighted governance (bonus mechanic)

What it is (confirmed): HyperEVM launched 18 Feb 2025 (Chain ID 999); consensus is HyperBFT
(HotStuff-derived); validators need >=10,000 HYPE self-stake; non-operators delegate. Governance
is deliberately narrow and stake-weighted, scoped to listings / ticker assignment / the AF supply
question, not open-ended treasury control. HIP-3 permissionless market deployment lets deployers
list assets and keep a fee share up to 50% (HIP-3 perps live on mainnet 13 Oct 2025, requiring a
500k HYPE stake plus a builder bond). The validator set grew from 16 at launch to 21 (top-21 by
stake) as of Mar 2026, with 170+ projects on HyperEVM. US-accessible: `no`.

Correction folded in: the "proposals to push 24->27 validators" detail is `[needs-verification]`;
only the 16 -> 21 growth is confirmed. Soften to "plans to expand the set further."

US-accessible replication path (Ethereum / Base): when the Phase 3 gate opens, hand
`ChioIdentityRegistry.admin` to a standard Governor + Timelock whose authority is scoped to
operator admission / deactivation (the listing / ticker analog), not open treasury control,
fronted by a reputation-gated proposer set plus a veto committee (already specified in roadmap
Phase 3). Mirror HIP-3 permissionless deployment as operator self-listing where the deployer keeps
a flat fee share via the OpenMarket fee schedule. Crucially, Chio diverges from HYPE on purpose:
the governance credential stays soulbound and non-yield (stake never enters the deterministic
reputation computation; roadmap Phase 3 crate notes).

Chio mapping: the shape for `ChioGovernor` over `ChioIdentityRegistry.admin` (roadmap M5).
Stance: WATCH (Phase 3 only, gated).

### 2.7 Why Chio copies rather than integrates

Restating the constraint for the record: Hyperliquid is geo-blocked for US persons (confirmed).
The founder is a US person and cannot transact on it. Every mechanic in this section is a design
reference replicated on Base / Arbitrum / Solana / Ethereum. Chio never integrates Hyperliquid as
a venue and the founder never transacts on it.

---

## 3. Vaults and shared security (EVM), mapped to Chio's bond / slashing / insurance roadmap

All primitives in this section are US-accessible (`yes`) unless flagged.

### 3.1 ERC-4626 and ERC-7540 (the vault interfaces)

ERC-4626 (US-accessible: `yes`) is the canonical, mature, default EVM vault standard
(deposit / mint / withdraw / redeem, totalAssets, convertToShares/Assets), with battle-tested
OpenZeppelin (virtual-share / dead-share inflation-attack defense) and Solady (gas-optimized)
implementations. Confidence note on scale: the often-cited "~$25B aggregate 4626 TVL (April
2026)" and "1,300+ stablecoin vaults / USDC ~$3B" sub-figures are soft (traced largely to
secondary vault-guide blogs, not an independent on-chain aggregate). Treat as directional
`[needs-verification]`; the standard's dominance and the security-pattern claims are solid.

ERC-7540 (US-accessible: `yes`) extends 4626 with an async request-then-claim pattern
(requestDeposit / requestRedeem, then later fulfillment), finalized June 2024 by authors from
Centrifuge, Superform, and Maple (confirmed). It is the correct interface when mint / redeem / slash
must settle only after an off-chain attestation, adjudication window, or partner approval.

Chio mapping: use plain ERC-4626 for any simple pooled position (an escrow-socketed prepaid /
credit balance); use ERC-7540 async request / claim for the slashable and insurance vaults, where
settlement must wait on the dispute window. This matches Chio's explicitly non-atomic
"slash-then-revoke (NOT atomic)" model (`chio-revocation-oracle`, roadmap line 72). Stance: ADOPT.

### 3.2 Vault-manager strategies (Morpho Vaults V2, Yearn V3)

Morpho Vaults V2 (US-accessible: `yes`): ERC-4626 + ERC-2612 vaults with a curator / sentinel /
allocator role split, risk caps, fees (perf up to 50%, mgmt up to 5%), timelocks, and optional
Gate contracts that enforce on-chain deposit / withdraw / transfer rules (KYC / allowlist). The
clearest EVM analog of an HLP-style community vault run by a professional manager. Confidence note:
"~$4B vault TVL across ~200 curated vaults" (Steakhouse, Gauntlet, MEV Capital, Re7) is consistent
with 2026 guides, but the specific "$9.5B protocol-TVL peak in H2 2025" is `[needs-verification]`
(DefiLlama shows ~$7-7.5B protocol TVL in 2026; "deposits" grew toward ~$13B, but deposits are not
TVL). Use the qualitative scale, not the peak figure.

Yearn V3 (US-accessible: `yes`): a two-layer framework where each strategy is itself a standalone
ERC-4626 vault (TokenizedStrategy) and allocator vaults route across strategies; permissionless,
launched 2023. The reference "vault-manager framework" for plugging modular, independently-audited
strategy modules behind one share token.

Chio mapping: curate the community / insurance capital vault with a Morpho V2 / Yearn V3 style
curator + Gate framework on Base, with the licensed partner acting as Curator / principal so Chio
does not custody funds. This is a US-accessible, professionally-curated, timelocked, KYC-gateable
analog of HLP without Hyperliquid's geo-restriction. Stance: PILOT (a single USDC vault before
generalizing).

### 3.3 Restaking / shared security (EigenLayer, Symbiotic, Karak)

EigenLayer / EigenCloud (US-accessible: `unclear` for an EIGEN-staking US founder; the restaking
reward regulatory status is genuinely ambiguous and EIGEN token programs have had geo-restrictions):
- Slashing went live on mainnet 17 Apr 2025 (opt-in, confirmed).
- Redistributable Slashing (ELIP-006) went live on mainnet 22 Jul 2025 (confirmed). Instead of
  burning slashed funds, an AVS creates a Redistributable Operator Set with an immutable
  `redistributionRecipient` set at creation; a permissionless `clearBurnOrRedistributableShares`
  call routes slashed shares to that recipient.
- The Cap Protocol example (confirmed) redirects slashed operator stake to protect stablecoin
  holders rather than burning it: exactly the involuntary-slash-to-restitution flow Chio's M4
  calls for.
- Redistribution-eligible assets are LSTs, USDC, and ERC-20s; native ETH and EIGEN are NOT yet
  eligible (confirmed). This directly supports a USDC-denominated Chio vault.
- Restaked TVL is roughly $15-20B point-in-time (the "~$17.5B" / "~$18B" figures are approximate;
  present as a range, not a constant). June 2025 rebrand to EigenCloud backed by $70M from a16z
  (confirmed). EigenAI and EigenCompute launched mainnet alpha together in ~late 2025 (correction:
  not "EigenCompute alpha Jan 2026").

Symbiotic (US-accessible: `yes`): a thin, immutable, permissionless shared-security layer around
Vaults; Slashing Insurance Vaults (SIVs, published 31 Jul 2025 with Re-Squared, confirmed)
structure capital into junior / mezzanine / senior tranches with ordered first-loss, coupons
versus premiums, priced by expected excess loss, explicitly modeled on MBS tranching and Lloyd's
syndicates. Funding: Pantera LED the $29M Series A (23 Apr 2025) with Coinbase Ventures
participating (correction: not "co-led"); the "~$1.7B restaked" figure is `[needs-verification]`
(only ">$1B / 14 networks" confirmed at raise time).

Karak (US-accessible: `unclear`): asset- and chain-agnostic universal restaking; V2 mainnet Phase 1
launched Oct 2024 (confirmed). Smaller and less battle-tested; a possible second stablecoin-friendly
source of slashable security.

Chio mapping:
- `ChioSlashableBondVault` has a now-proven, US-accessible blueprint in EigenLayer Redistributable
  Slashing. Copy the mechanics (immutable `redistributionRecipient`, permissionless clear-and-route,
  safety-delay window, reputation-based veto committee) into a standalone USDC-denominated vault
  rather than depending on EigenLayer at runtime, so custody / principal-of-record stays with the
  licensed partner. This validates roadmap research items 6/7 and the federation-gated slasher
  (`FederatedSybilControl` min_independent_issuers >= 2). Note the self-slash-only limit of the
  immutable `ChioBondVault` (confirmed `impairBondDetailed` requires `msg.sender == operator`,
  ChioBondVault.sol:134) is the SAME constraint EigenLayer / Symbiotic engineered around: a new
  audited vault with an external corroboration-gated slasher is required.
- The underwriting pool should adopt Symbiotic's SIV tranching for `chio-underwriting`'s ReserveBook
  and the `bond_depth` premium hook. This gives the AIUC / Lloyd's-style partner a
  capital-markets-legible structure.
- Do NOT depend on restaking for a US founder; keep self-slash-only `ChioBondVault` as the launch
  primitive and treat EigenCloud as a Phase-3 watch, US-jurisdiction permitting.

Stance: ADOPT (EigenLayer redistribution mechanics into a standalone USDC vault; Symbiotic SIV
tranching design), WATCH (depending on restaking at runtime).

### 3.4 Insurance / cover vaults (Nexus Mutual and successors) and named AI insurers

Nexus Mutual (US-accessible: `unclear`): the largest crypto-native cover provider; a discretionary
mutual where members own a shared Capital Pool. The load-bearing structural lesson (confirmed and
still accurate): BUYING cover is permissionless and non-KYC (open to US persons), but full
MEMBERSHIP (capital provision / underwriting / governance) requires KYC / AML and excludes some
jurisdictions. This is the model for keeping Chio custody-neutral: buyers transact permissionlessly,
the capital-provision and slash-to-third-party payout leg sits on the licensed partner as principal
of record.

Corrections folded in:
- "In 2025 Nexus moved to sunset its legal entity and lift KYC" is WRONG (date error). The cited
  article and the "Operation Wartortle" proposal are from April 2021, not 2025. No 2025 entity
  wind-down was found. The structural permissionless-purchase-vs-KYC-membership point remains
  accurate; the 2025 framing is dropped.
- The claims adjudication detail is updated: current Nexus V2 uses a 3-member Claims Committee with
  a 2-of-3 accept threshold, voting open >=72h plus a 24h cool-down. The earlier "36-72h window /
  resolves when staked NXM > 10x the claim" describes an older design and is dropped.
- The figures "$25M/protocol cover cap," "$6B+ protected since 2019," and "96.7% of DeFi cover TVL
  across 7 chains" are `[needs-verification]` (not independently confirmed in this pass); source to
  a live Nexus / OpenCover dashboard before relying on them.

Second-wave cover protocols (US-accessibility: `unclear`, varies per front-end): Sherlock
(audit-contests coupled with coverage), Neptune Mutual (parametric / dispute-resolution auto-pay),
InsurAce (two-pool mutual), OpenCover / Bright Union (aggregators). Parametric (Neptune) and
audit-gated (Sherlock) designs are relevant to defining objective, fast slash / restitution
triggers.

Named AI-agent liability insurers (US-accessible: `yes`), the candidate "principal of record"
partners the roadmap's Phase 2 / M4 require:
- AIUC (confirmed): out of stealth Jul 2025 with a $15M seed led by Nat Friedman; the AIUC-1
  standard plus independent audits; policies up to $50M for agent-caused harm; Lloyd's-rooted
  (first policyholder ElevenLabs). CEO Rune Kvist is ex-Anthropic (confirmed); the broader
  "ex-Lloyd's / CAIS" team descriptor is loosely accurate but not precisely sourced, so do not
  assert it as fact.
- Armilla (confirmed): wrote the first affirmative AI liability policy (underwritten by Chaucer,
  a Lloyd's syndicate) on 30 Apr 2025; available to US insureds with global territorial limits.
- Testudo (confirmed): began underwriting US mid-market generative-AI liability in January 2026;
  capacity later expanded to ~$9.25M/insured (Apollo, Atrium, QBE panel).

Chio mapping: their model (standard + audit + insurance) parallels Chio's receipt / attestation-tier
+ bond structure, so a bonded, attested Chio operator is a natural risk to underwrite. They are the
concrete candidates to answer roadmap research item 5: do underwriters price premiums against a
POSTED USDC bond, or against receipts + tiers alone? Validate this before building the slashable
vault. Stance: PILOT (engage AIUC / Armilla / Testudo to validate posted-bond pricing).

### 3.5 The token-kill confirmation

EigenLayer, Symbiotic, and Nexus all demonstrate that slashable economic security and underwriting
work with EXTERNAL collateral (LSTs, ERC-20s, USDC, NXM); none require a brand-new native asset.
This reinforces the roadmap's kill of native `$CHIO` (roadmap line 117: a USDC / ETH bond into a
slasher-gated vault delivers equal enforcement and insurance utility; the native token is cosmetic).
Chio can copy the mechanism in USDC and keep the Pass soulbound / non-financial. Stance: AVOID
(minting a native asset for bonding / slashing / underwriting). Stance: AVOID (routing restitution
payouts through a Chio-controlled contract or having Chio custody the reserve pool; keep the
capital-provision leg on the licensed partner).

---

## 4. Solana evaluation for Chio

All Solana primitives are US-accessible (`yes`) at the protocol / SDK level unless flagged; some
front-ends geo-fence (noted inline).

### 4.1 Token-2022 for the Chio Pass and gifted usage (the strongest fit)

Token-2022 / Token Extensions (US-accessible: `yes`): Solana's superset token standard, mainnet
24 Jan 2024 (confirmed). The NonTransferable extension makes a mint permanently soulbound, enforced
by the token program itself before a transfer hits the chain. This is a protocol-enforced soulbound
primitive (no contract logic to write), maximally fail-closed, removing a class of bugs. It pairs
with the Metadata / MetadataPointer extension to carry on-mint credential data and with
PermanentDelegate for issuer-side burn / revocation. A NonTransferable mint is automatically
un-poolable on Orca (confirmed), structurally enforcing "access, not a tradeable asset."

Confidential transfers (US-accessible: `no`, feature off): the ZK ElGamal Proof program was
disabled on mainnet after a Fiat-Shamir transcript vulnerability reported June 2025 (disabled at
epoch 805, ~19 Jun 2025); a Code4rena audit ran Aug 2025; it remains gated under remediation into
mid-2026; PYUSD initialized but never activated it for end users (confirmed). NOT production-ready.
Do not design any Pass or credit feature that depends on confidential balances.

Chio mapping: issue the Chio Pass as a Token-2022 NonTransferable credential (Solana variant), with
Metadata for credential fields and optional PermanentDelegate for issuer revocation. Model the
day-zero free-compute allotment as a soulbound Token-2022 balance or an in-attestation metered
counter, NEVER a tradeable SPL token (keeps the gift unfarmable and un-poolable). Stance: PILOT
(Solana issuance, on devnet first, since Chio's canonical credential is EVM / `did:chio` today),
ADOPT (model gifted credits as soulbound / non-tradeable regardless of chain), AVOID (any
confidential-transfer dependency).

### 4.2 Solana Attestation Service (SAS) for Pass issuance

SAS (US-accessible: `yes`): an open, permissionless on-chain verifiable-credential protocol, live
on mainnet May 2025 (confirmed; partners include Civic, Solid, Trusta Labs, Solana.ID, Sumsub,
RNS.ID, Range, Honeycomb). Model: Credentials (issuing authority), Schemas (field layout), and
Attestations (signed claims bound to a wallet), with revocation and freshness checks. It maps
directly onto Chio's `did:chio` attestation log (issuer authority + Chio schema + per-identity
attestations).

Correction folded in: SAS offers a tokenized-attestation path, but the specific "one instruction
merges attestation creation + Token-2022 mint" detail could not be confirmed from the primary
announcement and is `[needs-verification]`; verify against the SAS GitHub / docs before asserting
the exact instruction behavior. The tokenized-attestation feature itself and the partner list are
solid.

Chio mapping: combining the tokenized-attestation path with the NonTransferable extension yields a
soulbound, revocable, schema-typed on-chain credential, essentially a turnkey Pass issuance rail.
Bind it to `did:chio` via a mapping. Stance: PILOT.

### 4.3 Solana settlement for micropayments

Solana L1 (US-accessible: `yes`): ~400ms block time, sub-second optimistic confirmation, single-layer
finality (no optimistic-rollup challenge window), with the Alpenglow upgrade (SIMD-0326, ~98.3%
validator approval) targeting ~100-150ms finality, shipping as soon as Q3 2026. Per-tx cost
~$0.00025 (confirmed). Solana hit a record 112.6M daily non-vote transactions in Q1 2026 (confirmed,
Messari). Native (non-wrapped) USDC plus Circle CCTP V2 (V2 launched 11 Mar 2025; Solana support
added Oct 2025 as the first non-EVM CCTP V2 deployment; Fast Transfers ~8-20s; confirmed) let Chio
settle in the SAME USDC unit across Base / Arbitrum and Solana and move treasury natively
(burn-and-mint, no wrapped-asset bridge risk).

Corrections folded in:
- "USDC transfer volume on Solana surpassed Ethereum on Dec 29, 2025 and has stayed ahead" is
  softened: the specific date is unverified; by ADJUSTED monthly volume Solana now leads (Token
  Terminal, ~300% YoY growth, highest monthly stablecoin volume of any chain in Feb 2026), but the
  metric is heavily market-maker-driven and Ethereum still posts very large USDC volume (~$1.7T/mo).
  Present as "leads on adjusted velocity, with a market-maker caveat," not an unqualified flip.
- USDC share of Solana stablecoins: "just over 50% and trending down" (correction from "~55%");
  Messari Q1 2026 puts Solana stablecoin mcap at ~$14.85B (~4.5% of the ~$321B global market) with
  composition shifting toward USDT / USD1 / PYUSD.
- Native USDC balance on Solana: ~$8.6-12B mid-2026 (correction; the "$7.03B" figure is a stale
  late-2025 snapshot); Ethereum ~$45-51B (the "~$47B" figure is fine).
- Arbitrum fee comparison: typical Arbitrum fees are ~$0.01-0.03 (the "~$0.10/tx" figure is
  high-end); Solana ~$0.00025. The qualitative "Solana far cheaper" point stands.
- Mastercard adopted Solana for stablecoin settlement, announced 3 Jun 2026 (8 chains incl. Solana);
  separately Visa has settled in USDC on Solana since Dec 2025 (~$3.5B annualized).

Chio mapping: add Solana as a SECOND USDC settlement rail for per-tool-call micropayments, keeping
the signed receipt / attestation log canonical on EVM and using CCTP V2 for treasury movement. This
introduces a parallel Anchor / Rust runtime alongside the immutable EVM contract family, so scope it
to the USDC leg only at first. Stance: PILOT.

### 4.4 Orca / Whirlpools liquidity (Phase-3 only)

Orca Whirlpools (US-accessible: protocol / SDK `yes` (permissionless); the orca.so front-end has
blocked US users since 31 Mar 2023): an open-source concentrated-liquidity AMM (Uniswap-v3-style),
audited (Sec3, incl. an Aug 2025 audit, plus OtterSec; the Kudelski / Neodyme attribution is
`[needs-verification]` against the full auditor list). It added Token-2022 / Token Extensions
support on 28 May 2024 (handles TransferHook and TransferFeeConfig, gates risky extensions behind a
TokenBadge whitelist), and expanded to Eclipse (SVM L2) Oct 2024. A NonTransferable (soulbound)
mint CANNOT be pooled, which is the desired property for the Pass.

Chio mapping: Whirlpools is the price-discovery venue ONLY if Phase 3 ever ships a transferable
unit. Until then the soulbound design intentionally makes a Whirlpool listing impossible, which is
the correct fail-closed posture. No action pre-Phase-3. Stance: WATCH.

### 4.5 Solana recommendation (whether / when to add)

Recommendation: add Solana in two scoped, gated steps, not as a wholesale runtime port.
- Now / near-term (PILOT): pilot the Pass as a Token-2022 NonTransferable credential via SAS on
  devnet, because the protocol-enforced soulbinding is the cleanest fail-closed fit for the
  "access, not asset" invariant and removes a class of bugs. Keep the EVM `did:chio` credential
  canonical; SAS is a second issuance surface that needs a bridge / mapping.
- Near-to-mid term (PILOT): add Solana as a second USDC settlement rail for micropayments, scoped
  to the USDC leg, with the receipt log staying canonical on EVM and CCTP V2 moving treasury.
- Do not (AVOID): build any Pass or credit feature on confidential transfers; list anything on Orca
  pre-Phase-3; or treat Solana liquidity depth as a reason to mint a Chio-native tradeable unit.

Solana restaking (Solayer / Jito Restaking / Cambrian, US-accessible: `unclear`, younger and
token-incentive-gated; Solayer pays point-in-time rates such as ~7.65% on sSOL / ~3.9% on sUSD and
has a LAYER token) is the Solana analog of EigenLayer for securing a verifiable attestation service.
Stance: WATCH until the EVM-side (EigenLayer / Symbiotic) and the partner / legal structure are
settled.

---

## 5. Agent-economy and attestation tech, mapped to Chio's receipt-log and Pass

All primitives US-accessible (`yes`) unless flagged.

### 5.1 x402 / HTTP-402 (the payment leg Chio aligns to)

x402 (US-accessible: `yes`): an open standard reviving HTTP 402. A server returns 402 with
machine-readable payment requirements; the client retries with a signed payload (an EIP-3009
`transferWithAuthorization`); a facilitator verifies / settles. Settles in USDC (mainly Base; also
Solana), gasless, ~2s, sub-$0.001 fees, zero protocol fee. Coinbase + Cloudflare announced the x402
Foundation 23 Sep 2025; the Linux Foundation formalized it 2 Apr 2026 (both confirmed). Bazaar (the
discovery layer) exposes 10,000+ paid MCP tools.

Corrections folded in:
- Volume: "~119M tx on Base + ~35M on Solana, ~$600M annualized" are the widely-cited headline
  figures, but the $600M is contested: independent analysis (ainvest) estimates real daily volume
  near $28k, implying genuine throughput far below $600M (much is looping / test traffic, with a
  ~92% daily-volume collapse from the Dec 2025 peak). Cite $600M as promotional, not load-bearing.
- Chain split: "mainly Base" holds for cumulative tx, but Solana's 2026 share surged (some flow
  metrics put Solana at ~65% of volume). Do not anchor the dual-chain design to stale Base
  dominance.
- Wire detail (minor): the request header is `X-PAYMENT` and the 402 response carries an `accepts`
  array, not literal `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` headers. The EIP-3009 mechanism is
  described correctly.

Note on the "~$28k/day" figure: in Chio's own docs this number describes a HYPOTHETICAL future CHIO
token market (a Chio projection, not a Hyperliquid statistic). Here, separately, ainvest uses a
similar "~$28k/day" as an estimate of real x402 economic throughput. These are two different
contexts that happen to share a number; do not conflate them. HYPE itself is highly liquid
(~$320B/month perps volume).

Chio mapping: expose an x402-facilitator-compatible verify endpoint so a Chio financial receipt is
the "settled proof" attachable to any 402-paid call, while a licensed facilitator (Coinbase CDP)
moves money and Chio signs / proves. This makes Chio the verifier ABOVE x402 / ACP / AP2 rather than
a competing rail, preserving the custody-neutral, prepare-only posture. Stance: ADOPT.

### 5.2 Other agent-payment rails (context, not dependencies)

- Circle Agent Stack + Nanopayments (US-accessible: `yes`): launched ~11 May 2026; Nanopayments
  enable gas-free USDC transfers as small as $0.000001 (confirmed). USDC ~$77B circulation (+28%
  YoY), on-chain volume ~$21.5T (+263% YoY) (confirmed). Circle paired this with a $222M Arc token
  sale (confirmed). Relevant as the issuer-side micropayment rail Chio settles in.
- Skyfire KYA / KYAPay (US-accessible: `yes`): an "agent trust stack" (signed JWT identity +
  programmable spend). The Dec 2025 Consumer-Reports-to-Bose.com demo is confirmed; the F5
  partnership (18 Mar 2026) is confirmed; the "GA late April 2026" date is `[needs-verification]`.
- Visa Intelligent Commerce / TAP / Intelligent Commerce Connect and Mastercard Agent Pay (Agentic
  Tokens) (US-accessible: `yes`): card-network agent rails. Visa Intelligent Commerce Connect was
  unveiled 8 Apr 2026 and is in pilot (the four-protocol single-integration claim, TAP / MPP / ACP /
  UCP, is correct). Mastercard Agent Pay announced 29 Apr 2025.
- AP2 (Google) and ACP (Stripe / OpenAI) (US-accessible: `yes`): the checkout-layer standards a
  rail-neutral Chio receipt must verify; both launched Sept 2025. ACP powers ChatGPT Instant
  Checkout (broad US rollout 16 Feb 2026; Etsy live since Sept 2025). Correction: Walmart is
  primarily a Google UCP co-developer, not clearly an ACP merchant; drop / qualify "Walmart under
  ACP."

Chio mapping: Chio is rail-neutral; its receipt verifies what was authorized / charged regardless of
which checkout / card rail moved the money. Do not rebuild any of these. Stance: ADOPT the neutral-
verifier posture; WATCH the standards as they stabilize.

### 5.3 Account abstraction / wallet spend controls (the layer Chio sits above)

- EIP-7702 (US-accessible: `yes`): shipped in Ethereum's Pectra upgrade 7 May 2025 (confirmed);
  lets an EOA temporarily gain smart-account powers, with session keys carrying value / time /
  contract caps. ERC-4337 remains the full smart-account stack.
- Coinbase Agentic Wallets + Spend Permissions + CDP Wallet Policies (US-accessible: `yes`): Agentic
  Wallets launched 11 Feb 2026 (MPC wallet + x402 client + session / per-tx caps + gasless Base);
  CDP Server Wallets v2 GA 24 Jul 2025 (both confirmed). SpendPermissionManager authorizes spenders
  within an allowance + recurring period + window.

Chio mapping: these enforce value / time / contract caps INSIDE the agent's own wallet library.
Chio's differentiator is the OUT-OF-AGENT, fail-closed kernel that mediates the tool call before the
wallet ever signs, plus the signed receipt. Meter on top of 7702 / Spend-Permission wallets; do not
build a wallet. Stance: PILOT.

### 5.4 Cross-chain intents (ERC-7683 / Open Intents Framework)

ERC-7683 (Across + Uniswap Labs; US-accessible: `yes`): a standard for expressing / settling
cross-chain intents; the Ethereum Foundation launched the Open Intents Framework Feb 2025; 70+
projects support it (a plausible later cumulative count). The clean abstraction if Chio settles
across Base + Arbitrum, but not yet load-bearing for v1. Stance: WATCH.

### 5.5 Attestation registries (EAS, Verax, SAS) and the receipt-log decision

- EAS (US-accessible: `yes`): the dominant general-purpose attestation primitive (schema registry +
  attest); 9.5M+ attestations, 450k+ attesters as of ~May 2026 (confirmed); deployed on Ethereum and
  many L2s incl. Base. Private Data attestations build a Merkle tree of arbitrary data and post only
  the 32-byte Merkle root on-chain (selective disclosure via Merkle proofs): byte-for-byte Chio's
  `ChioRootRegistry` Merkle-anchoring model (confirmed).
- Verax (Consensys / Linea; US-accessible: `yes`): a shared, MIT-licensed on-chain attestation
  registry, live on Linea + Base mainnets, EAS-interoperable. Automata uses it for proof-of-
  machinehood (confirmed).
- SAS (Section 4.2): the Solana-side comparator.

Chio mapping: do NOT reinvent the attestation registry. Publish Chio receipt-batch roots as EAS
(Base) and / or Verax attestations to inherit explorers, SDKs, and revocation semantics, while
keeping the signed receipt log as the immutable source of truth. Position `ChioRootRegistry` as a
domain-specific anchor that interoperates with EAS / Verax / SAS, not a rival standard. Stance: ADOPT.

### 5.6 ERC-8004 Trustless Agents (the most direct trust-layer comparator)

ERC-8004 (US-accessible: `yes`): three registries (Identity = a minimal ERC-721 handle; Reputation =
standardized feedback; Validation = cryptographic + economic verification of agent work). Correction:
it is no longer merely a "Draft EIP"; audited Identity + Reputation registries went live on Ethereum
mainnet 29 Jan 2026 (45,000+ agents registered) and on additional chains (e.g. Avalanche C-Chain Feb
2026). Only the Validation Registry remains under active revision with the TEE community. The
contributor list (MetaMask / EF / Google / Coinbase) is commonly cited but not independently confirmed
here, so treat the attribution as `[needs-verification]`.

Chio mapping: register the Chio Pass / agents in ERC-8004 Identity + Reputation so the Pass is
third-party-verifiable without a Chio node, and the gifted "trust-feed reads" map onto reading a
Reputation registry. Position Chio receipts (signed, replayable, policy-hash-bound) as a Validation-
Registry evidence type: a concrete distribution path for the receipt primitive. Soulbound + benevolent
framing differentiates Chio from transferable agent NFTs. Stance: PILOT (registration), WATCH
(Validation Registry, still under revision).

### 5.7 AVS / TEE verifiable compute (the compute-provenance complement)

- EigenCloud (EigenCompute / EigenVerify / EigenAI / EigenDA; US-accessible: `unclear` for restaking
  participation): makes "Chio receipts consumed as an AVS attestation primitive" technically real
  (EigenVerify supports objective and intersubjective claims). But US-accessibility of restaking is
  unclear for a US founder, so do not depend on it.
- TEE attestation networks (Phala, Marlin Oyster, Automata, Atoma, Tinfoil; US-accessible: `yes`):
  hardware-enclave networks producing remote-attestation proofs that bind HOW / WHERE compute ran.
  Phala showed ~30k contract calls/day and ~2,000 peak workers in early 2025 (confirmed). Two caveats:
  the "law firms adopting Phala (Nov 2025)" claim is `[needs-verification]` / unconfirmed (replace with
  the documented fintech / regulated-enterprise framing); and the chip-vendor-PKI trust root is
  weakening: the WireTap attack (ACM CCS 2025) extracted Intel SGX attestation keys with sub-$1,000
  gear, and Phala is deprecating SGX for Intel TDX + NVIDIA Confidential Computing. Any
  receipt-binds-to-TEE-attestation thesis should account for SGX's weakened standing.

Chio mapping: Chio receipts prove WHAT was authorized / charged and under which policy; TEE
attestation proves HOW / WHERE the compute ran. A Chio financial receipt can embed / reference a TEE
attestation hash, yielding a single artifact binding spend-authorization + compute-provenance: a
differentiated compliance / audit SKU. Stance: WATCH (EigenCloud as a Phase-3 AVS venue,
US-jurisdiction permitting; TEE-network leg is US-accessible today, prototype-ready).

---

## 6. Distribution, anti-sybil, and US regulatory posture

This section reconciles the external evidence with the posture in
`CHIO-BENEVOLENT-TOKEN-DESIGN.md`.

### 6.1 What sustained versus what farmed to death

- Hyperliquid HYPE (US-accessible: `no`): retroactive surprise, no live points leaderboard after the
  snapshot, push-not-claim, no VC / insider allocation. The sustained model (Section 2.1). Wallet
  count best stated as "over 90,000 (~94k)."
- zkSync ZK airdrop (US-accessible: `unclear`): the anti-pattern. Polygon's Mudit Gupta called it
  "the most farmable and farmed airdrop ever" with "almost no sybil filtering" (confirmed); sybil
  rings depositing identical ETH the same day harvested ~15,000 ZK each (confirmed). The decline is
  directionally confirmed (active addresses roughly halved within 3 days; ~70% vs airdrop-day, ~40%
  vs pre-airdrop per The Block / Nansen); the precise "~78.7% fall" and "~89-90% got nothing" figures
  are `[needs-verification]` / approximate.
- friend.tech (US-accessible: `yes`): points-to-token collapse. FRIEND (3 May 2024) crashed ~$169 to
  ~$1.68 within hours (>98%); deposits fell $52M to $4M; creators exited with ~$44M; Sept 2024 the
  team relinquished contract control to a burn address (confirmed). The canonical "points built
  farming, not affinity" failure.
- EIGEN stakedrop (US-accessible for the TOKEN: `no`; correction from "unclear" - the EIGEN claim
  explicitly geoblocked US, Canada, and China users; the restaking protocol itself stayed
  US-accessible): launched non-transferable and geoblocked (May 2024). CoinDesk flagged a possible
  "demise of points"; Jake Chervinsky (Variant CLO) framed non-transferability as regulatory-risk
  mitigation (confirmed). The "~80% of EIGEN sales in the first two weeks once transferable" stat is
  `[needs-verification]`. Lesson: non-transferability is regulator-protective, but because a
  future-value / conversion expectation had been cultivated, the lock was read as a broken promise.
- Linea (US-accessible: `yes`): threshold + proof-of-humanity at scale (Sept 2025 TGE; eligibility
  required >=2,000 LXP or 15,000 LXP-L + Proof-of-Humanity + no sybil flag; ~800,000 sybils removed;
  749,662 eligible for 9.36B LINEA; confirmed). The ">50% of sybils below threshold" and ">60% of
  active wallets excluded" figures trace only to ChainCatcher and should be attributed, not asserted.
  The "~85% drop in two months" is imprecise; cite a reference point (post-airdrop rout ~49% per DL
  News, vs ~93% intraday from listing; ~$0.011 by late Nov 2025). Lesson: thresholds filter farmers
  cheaply but punish the genuine long tail and breed resentment.
- Optimism Retro Funding / RetroPGF (US-accessible: `yes`): reward-for-proven-past-impact; 60M+ OP
  cumulatively to hundreds of projects (RetroPGF 6 funded 88 projects); in 2025 shifted to ongoing
  "impact evaluation" with an Impact Chain dependency graph (confirmed). The closest public-goods
  analog to Chio's retroactive Pass issuance.

Reconciliation with the Pass decision: every datapoint confirms Benevolent-Token Section 4. Keep
retroactive, unpredictable-snapshot, no-published-formula issuance over genuine signed-receipt
history, eligibility as a coarse attested-tier step function (not a constructed marginal-contribution
score, which was the rejected D6 oracle). Crucially, Linea validates the Chio decision to give EVERY
attested newcomer tier_0 reads plus a real day-zero Half-B starter allotment and to gate only SIZE,
not existence: treat the day-zero grant as the last lever to cut. EIGEN validates keeping the
"future-token wink" amputated and enforcing the no-future-value recital as binding issuance terms.

### 6.2 Sybil resistance that works

- World ID / Worldcoin (US-accessible: `yes`): biometric proof-of-personhood; US launch 1 May 2025
  (Atlanta, Austin, LA, Miami, Nashville, SF) with the Orb Mini and a ~7,500-Orb US deployment plan
  (confirmed). Verification is US-accessible; the WLD token is withheld from New York and other
  restricted territories. Caveat: PoP stops one person spinning up many fakes but cannot stop
  coordinated real humans, bribery, or rented identities; biometric capture raises US state-law (e.g.
  BIPA) exposure.
- Human Passport (formerly Gitcoin Passport; US-accessible: `yes`, non-biometric): acquired by the
  Holonym Foundation Dec 2024, 2M+ users; by 2026 secured 120+ projects and $512M+ of capital flow,
  including protecting Story Protocol's ~$98M airdrop (confirmed). Blends PoP stamps with Trusta ML
  scoring.
- Trusta (TrustaLabs; US-accessible: `yes`): on-chain-history ML scoring. The two-phase framework
  (Phase 1 Louvain / K-Core community detection over asset-transfer graphs; Phase 2 profiling + K-means
  to cut false positives) and the MEDIA score (Monetary, Engagement, Diversity, Identity, Age) are
  confirmed verbatim from Trusta's own materials. The specific adoption list "Celestia, Starknet,
  Arbitrum, Manta, Linea" and the "570M+ wallets across EVM and TON" figure are `[needs-verification]`
  (only Arbitrum, plus Ethereum / zkSync / BNB / Optimism, appear in Trusta's documented chain
  support); soften to "adopted across multiple major L2s including Arbitrum."

Reconciliation with the Pass decision: this fixes the verified `chio-federation` weakness that two
self-declared free-text `issuer_independence_group_id` strings satisfy "two independent issuers"
(Benevolent-Token Section 4). Anchor the costly Half-B allotment's issuer-independence and attested-
identity check to at least one external US-accessible sybil layer (World ID and / or Human Passport +
Trusta graph clustering) rather than two free-text labels. Stance: PILOT one external corroborator
before wiring it into the gate; note the World ID BIPA-style exposure.

### 6.3 The US legal envelope (soulbound gift now vs transferable token later)

- SEC "Project Crypto" / proposed Regulation Crypto Assets (US-accessible context: `yes`): a series of
  2025 Corp Fin staff statements (meme coins 27 Feb, PoW mining 20 Mar, payment stablecoins 4 Apr,
  protocol staking 29 May, liquid staking 5 Aug; confirmed) and a 17 Mar 2026 interpretive release.
  Corrections: the March 2026 release is a JOINT SEC + CFTC 68-page interpretive release, and the
  taxonomy has FIVE buckets (four non-security: digital commodities, digital collectibles, digital
  tools, payment stablecoins; plus digital securities, which IS a security). It states that airdrops
  of non-security crypto assets for NO consideration fall outside securities law, while quid-pro-quo /
  required-action distributions can trigger securities obligations. Refinement worth folding in: the
  release says no-consideration airdrops stay outside securities law "even if the issuer makes
  representations and promises about its essential managerial efforts to develop profits." So the
  literal Howey trigger for an airdrop is the CONSIDERATION / quid-pro-quo element, not the
  profit-expectation element. The proposed Regulation Crypto Assets (startup exemption ~4 yrs / ~$5M
  cap; fundraising exemption ~$75M/12mo; an investment-contract safe harbor keyed to cessation of
  essential managerial efforts; descended from Hester Peirce's 2020 Token Safe Harbor) is confirmed
  still conceptual / non-binding (final rule not before late 2026).
- IRS Rev. Rul. 2019-24 (US-accessible context: `yes`): still controlling (confirmed). Ordinary
  income at FMV on the date the recipient gains dominion and control (ability to sell / exchange /
  transfer). A soulbound, non-transferable, non-redeemable credential with no realizable FMV and no
  dominion-to-sell arguably yields no income at issuance, but that breaks the moment it becomes
  cash-out-able or transferable.
- GENIUS Act + CLARITY Act (US-accessible context: `yes`): the GENIUS Act (stablecoins) was SIGNED
  18 Jul 2025 (House passed 17 Jul, Senate 17 Jun; confirmed), supporting the USDC settlement leg.
  The CLARITY Act (H.R.3633, market structure) was House-passed 17 Jul 2025 and advanced by Senate
  Banking 15-9 on 14 May 2026, but is NOT yet law (confirmed; reconciliation pending). The specific
  "Senate calendar June 1 2026, Calendar No. 423" detail is `[needs-verification]`. Net: the
  stablecoin floor is solid; token classification is still legislatively unsettled.

Reconciliation with the posture (mostly confirmed, one reframing):
- Phase 0 soulbound Pass: the March 2026 no-consideration carve-out strongly supports gifting the
  Pass for no consideration, retroactive (not "do X to earn"). REFRAME the load-bearing legal risk:
  the precise Howey trigger for an airdrop is "consideration creep" (the refresh-on-genuine-use
  mechanic and the optional refundable activation deposit), NOT cultivated profit-expectation per se.
  Keep the conservative no-future-value posture anyway (the release is non-binding, and EIGEN-style
  reputational / totality-of-communications risk is real), and document the refresh and activation
  deposit as anti-fraud metering / refundable anti-sybil friction, not "actions you take to earn the
  gift." Counsel-gate that framing before launch.
- Tax: Rev. Rul. 2019-24 means the Pass is tax-safe only while it has no realizable FMV and no
  dominion-to-sell. The decision to denominate the allotment in `CostDimension::Custom` non-monetary
  units (e.g. `XCC`), never top-up-able, spendable only inside first-party Chio tooling, is exactly
  right. The OTC-pricing kill-criterion (Benevolent-Token Section 8) is therefore a TAX trigger as
  well as a securities trigger.
- Transferable token later: keep it deferred and counsel-gated. CLARITY is not law; the SEC
  safe-harbor is conceptual. Do not launch on anticipated law.

Stance: ADOPT (retroactive no-formula issuance; day-zero newcomer grant; soulbound non-monetary
allotment; amputated future-token wink; anti-fraud framing of refresh / deposit). PILOT (external
sybil anchor). WATCH (SEC rulemaking + CLARITY Act before any transferable Phase-3 token). AVOID (any
live public points leaderboard or "complete tasks to qualify" mechanic, which is both the
farm-to-death pattern and the quid-pro-quo the carve-out excludes).

---

## 7. Concrete recommendations

### 7.1 Adopt / pilot / watch / avoid table

| # | Item | Stance | Why (one line) |
|---|------|--------|----------------|
| 1 | Retroactive, receipt-weighted, sybil-filtered, opaque-formula, push-not-claim soulbound Pass issuance, Merkle-anchored in `ChioRootRegistry` | adopt | The single most-praised Hyperliquid mechanic, fully inside the no-token / no-money-leg posture; reuses existing receipts + `chio-reputation` + FederatedSybilControl. |
| 2 | Auto-route FLAT USDC fees through `ChioTreasury` / `FeeRouter` into community sinks (underwriting reserve + free-compute for Pass holders) with a keyless sink pattern; NO token buyback | adopt | Captures the Assistance Fund's auto-routing + provable neutrality while terminating value in utility, not a Howey-triggering token bid. |
| 3 | Anchor Chio receipt-batch Merkle roots to EAS (Base) / Verax; keep `ChioRootRegistry` canonical | adopt | EAS Private Data attestations are byte-for-byte Chio's model; inherit explorers / SDKs / revocation for free. |
| 4 | x402-facilitator-compatible verify path; Chio as verifier above x402 / ACP / AP2 | adopt | x402 uses the exact EIP-3009 leg Chio chose; a licensed facilitator moves money, preserving custody-neutrality. |
| 5 | ERC-4626 for simple pooled positions; ERC-7540 async for slashable / insurance vaults | adopt | Mature US-accessible standards; 7540 request-then-claim matches Chio's non-atomic slash-then-revoke. |
| 6 | Copy EigenLayer Redistributable-Slashing mechanics into a standalone USDC `ChioSlashableBondVault` | adopt | Live (22 Jul 2025), US-accessible, audited reference for involuntary-slash-to-restitution; resolves the immutable self-slash-only gap. |
| 7 | Model gifted day-zero compute credits as soulbound (NonTransferable) / non-tradeable, never an SPL/ERC-20 token | adopt | Keeps the gift unfarmable and un-poolable; upholds "access, not asset" and the tax / securities posture. |
| 8 | HLP-style ERC-4626 USDC community insurance / underwriting vault, premium AND losses pro-rata, withdrawal lockup, behind Phase 2 with licensed insurer as principal of record | pilot | HLP proves community capital backs a risk book if PnL is shared transparently; only ships behind the Phase 2 gate. |
| 9 | Issue the Pass as a Token-2022 NonTransferable credential via SAS (devnet first) | pilot | Protocol-enforced soulbinding is fail-closed and un-poolable; new non-EVM surface needs a `did:chio` bridge. |
| 10 | Add Solana as a second USDC settlement rail (USDC leg only), receipt log canonical on EVM, CCTP V2 for treasury | pilot | Best-in-class micropayment venue (400ms, sub-cent, native USDC); introduces a parallel runtime, so scope it. |
| 11 | Permissionless, capped, FLAT integrator / referrer codes via the receipt envelope + `FeeRouter`, no approval committee | pilot | Builder codes drove $40M+ to builders by removing gatekeeping; could bootstrap agent front-ends on Chio's rail. |
| 12 | Symbiotic SIV tranching (junior / mezzanine / senior) for the `chio-underwriting` ReserveBook + `bond_depth` hook | pilot | Capital-markets-legible underwriting structure modeled on Lloyd's / MBS; gives the insurer partner a known shape. |
| 13 | Engage AIUC / Armilla / Testudo as principal-of-record; validate posted-USDC-bond premium pricing (research item 5) | pilot | US-accessible Lloyd's-rooted AI insurers whose standard+audit+insurance model parallels Chio's tiers+bond. |
| 14 | Register Pass / agents in ERC-8004 Identity + Reputation; position receipts as Validation-Registry evidence | pilot | Live audited registries (29 Jan 2026); third-party verifiability without a Chio node; Validation Registry still in revision. |
| 15 | Meter on top of EIP-7702 / Coinbase Spend-Permission wallets rather than build a wallet | pilot | Wallet-level caps already exist; Chio's wedge is the out-of-agent fail-closed kernel above the cap. |
| 16 | Anchor costly-allotment issuer-independence to an external sybil layer (World ID and / or Human Passport + Trusta) | pilot | Fixes the two-free-text-string weakness; production-grade US-accessible corroborators; note World ID BIPA exposure. |
| 17 | Operator "copy-underwriting" vaults (skin-in-the-game rules) behind the Phase 2 licensed-partner gate | watch | Excellent alignment rules, but pooling third-party capital behind an operator carries securities / custody surface. |
| 18 | Narrow stake-weighted `ChioGovernor` over `ChioIdentityRegistry.admin`, soulbound non-yield credential | watch | The HyperBFT governance shape, Phase 3 only; diverges from HYPE by keeping the credential non-yield. |
| 19 | EigenCloud AVS for receipts-as-attestation; TEE networks (Phala / Marlin / Automata) for compute provenance | watch | Technically real, but restaking US-accessibility is `unclear`; TEE leg is US-accessible and prototype-ready. |
| 20 | ERC-7683 / Open Intents Framework for multi-chain settlement; Orca Whirlpools for any Phase-3 transferable unit; Solana restaking (Solayer / Jito / Cambrian) | watch | Clean abstractions, but not load-bearing for v1; Whirlpools only post-Phase-3; Solana restaking younger / token-gated. |
| 21 | Any HYPE-style token buyback at launch; minting a native `$CHIO` for bonding / slashing / underwriting | avoid | A fee->token bid manufactures buy-and-stake / yield profit-expectation; external collateral already delivers the mechanism. |
| 22 | Using Hyperliquid as a venue / the US founder transacting on it; charging a percentage-of-value settlement take-rate; building a bespoke attestation registry; any confidential-transfer dependency; any live public points leaderboard | avoid | Hyperliquid is US-geoblocked; a value take-rate is the money-transmission trigger; EAS/Verax/SAS/ERC-8004 already exist; confidential transfers are disabled; live leaderboards farm-to-death and read as quid-pro-quo. |

### 7.2 Follow-up actions and experiments

1. Underwriter posted-bond pricing experiment (gates Phase 2; roadmap research item 5). Engage AIUC,
   Armilla, and Testudo with a concrete proposal: a USDC-denominated, EigenLayer-redistribution-style
   slashable operator bond plus Chio's receipt / tier evidence. Get written confirmation whether they
   price premiums against a POSTED USDC bond versus receipts + tiers alone. If receipts + tiers
   suffice, Phase 2 bonding is deferred (roadmap kill-criterion line 115).

2. External sybil-anchor pilot (hardens the costly allotment gate). Wire ONE external corroborator
   (start with Human Passport, non-biometric, to sidestep BIPA; add World ID as an option) into the
   Half-B issuer-independence check, replacing one free-text `issuer_independence_group_id`. Measure
   farmer ROI before / after and the genuine-newcomer exclusion rate (Linea's >60%-excluded failure
   is the metric to beat).

3. Token-2022 / SAS Pass issuance prototype on Solana devnet. Mint a NonTransferable Pass via SAS with
   Metadata + PermanentDelegate, map it to a `did:chio`, and confirm it is un-poolable on an Orca
   devnet pool. Decision output: whether the soulbinding-as-protocol-property benefit justifies the
   second non-EVM issuance surface.

4. ERC-7540 slashable-vault spike on a Base testnet. Implement the request-then-claim entry / exit gate
   around a mock adjudication window, copying the redistribution mechanics (immutable
   `redistributionRecipient`, permissionless clear-and-route, safety-delay, reputation veto). Confirm
   it cannot be front-run around a pending slash. This is the de-risking spike for `ChioSlashableBondVault`
   (roadmap M4).

5. x402 verify-endpoint integration. Stand up an x402-facilitator-compatible verify path so a Chio
   financial receipt attaches to a 402-paid call settled by Coinbase CDP. Validate the custody-neutral
   boundary (Chio signs / proves, the facilitator moves money) end to end on Base, then re-run on
   Solana to confirm the dual-rail design.

---

## 8. Sources (deduplicated, grouped by topic, with a confidence note per topic)

Confidence legend: HIGH (load-bearing claims confirmed by multiple sources or primary docs), MEDIUM
(core claims confirmed, some figures soft / point-in-time), LOW (key specifics unconfirmed; flagged
`[needs-verification]` in-text).

### Hyperliquid playbook (confidence: HIGH on mechanics and the TGE; MEDIUM on running figures, which drift and include some unconfirmed counts)
- https://www.panewslab.com/en/articles/zena4u1n
- https://coinmarketcap.com/academy/article/hyperliquid-airdrop-guide-what-is-hyperliquid-how-to-participate-and-what-it-means-for-defi
- https://tokenomist.ai/hyperliquid
- https://eco.com/support/en/articles/15039718-hyperliquid-airdrop-what-happened-and-what-s-next
- https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/vaults/protocol-vaults
- https://hyperliquid.medium.com/hyperliquidity-provider-hlp-democratizing-market-making-bb114b1dff0f
- https://www.datawallet.com/crypto/hyperliquid-hlp-explained
- https://eco.com/support/en/articles/15197987-hyperliquid-vault-strategies-2026-hlp-and-user-vaults-explained
- https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/vaults/for-vault-leaders-legacy
- https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/vaults/for-vault-depositors-legacy
- https://www.dlnews.com/articles/defi/one-hyperliquid-trades-earns-1021-return-in-one-month/
- https://crypto.news/why-hype-is-different-inside-hyperliquids-buyback/
- https://hyperliquid.gitbook.io/hyperliquid-docs/trading/fees
- https://cointelegraph.com/news/hyperliquid-validators-vote-assistance-fund-supply
- https://hyperliquid.gitbook.io/hyperliquid-docs/trading/builder-codes
- https://www.dwellir.com/blog/hyperliquid-builder-codes
- https://hyperdash.com/learn/hyperliquid-builder-codes-explained-how-third-party-apps-earn-fees-on-chain
- https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/staking
- https://messari.io/research/deep-research-reports/hyperliquid-diligence-report-fdf9486f-d978-4a6f-980e-ccadc697b120

### EVM vaults and shared security (confidence: HIGH on EigenLayer / Symbiotic / 4626 / 7540 dates and mechanics; MEDIUM on TVL figures; LOW on the Nexus dollar-figures and the 2025 Nexus-entity claim, corrected in-text)
- https://docs.openzeppelin.com/contracts/5.x/erc4626
- https://eips.ethereum.org/EIPS/eip-7540
- https://lagoon.finance/blog/state-of-onchain-vaults-2026
- https://docs.morpho.org/learn/concepts/vault-v2/
- https://docs.yearn.fi/developers/v3/overview
- https://blog.eigencloud.xyz/redistribution-is-live-on-mainnet/
- https://blog.eigencloud.xyz/slashing-goes-live/
- https://docs.eigencloud.xyz/products/eigenlayer/concepts/slashing/redistribution
- https://blog.symbiotic.fi/slashing-insurance-vaults/
- https://www.gauntlet.xyz/resources/introducing-restaking-vaults-on-symbiotic-isolated-strategies-curated-by-gauntlet
- https://dev-docs.karak.network/
- https://docs.nexusmutual.io/overview/cover-products/
- https://docs.nexusmutual.io/protocol/claims-assessment/
- https://opencover.com/sherlock/
- https://fortune.com/2025/07/23/ai-agent-insurance-startup-aiuc-stealth-15-million-seed-nat-friedman/
- https://www.armilla.ai/ai-insurance
- https://www.theinsurer.com/program-manager/news/standalone-ai-liability-market-takes-shape-with-underwriting-discipline-key-to-2026-04-24/

### Solana stack (confidence: HIGH on Token-2022 / SAS / CCTP / fees / Alpenglow; MEDIUM on stablecoin-share and volume figures, several corrected in-text; LOW on the SAS single-instruction and Orca-auditor specifics, flagged `[needs-verification]`)
- https://github.com/orca-so/whirlpools
- https://dev.orca.so/Architecture%20Overview/TokenExtensions%20Support/
- https://solana.com/solutions/token-extensions
- https://solana.com/docs/tokens/extensions/confidential-transfer
- https://solana.com/news/post-mortem-june-25-2025
- https://solana.com/news/solana-attestation-service
- https://attest.solana.com/
- https://www.circle.com/cross-chain-transfer-protocol
- https://github.com/circlefin/solana-cctp-contracts
- https://solana.com/docs/core/fees
- https://chainstack.com/solana-stablecoins-2026/
- https://defillama.com/stablecoins/solana

### Agent-economy payments and attestation tech (confidence: HIGH on x402 / EAS / Verax / EIP-7702 / Coinbase wallets / ERC-8004-live; MEDIUM on x402 volume, corrected to "promotional"; LOW on the Phala-law-firm and contributor-list claims, flagged `[needs-verification]`)
- https://www.coinbase.com/blog/coinbase-and-cloudflare-will-launch-x402-foundation
- https://blog.cloudflare.com/x402/
- https://docs.cdp.coinbase.com/x402/bazaar
- https://www.blockhead.co/2026/05/12/circle-launches-agent-stack-to-put-usdc-at-the-centre-of-machine-to-machine-payments/
- https://github.com/google-agentic-commerce/AP2
- https://github.com/agentic-commerce-protocol/agentic-commerce-protocol
- https://eco.com/support/en/articles/14796249-eip-7702-explained-account-abstraction-for-eoas
- https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets
- https://docs.cdp.coinbase.com/server-wallets/v2/evm-features/spend-permissions
- https://eips.ethereum.org/EIPS/eip-7683
- https://attest.org/
- https://www.ver.ax/
- https://eips.ethereum.org/EIPS/eip-8004
- https://blog.quicknode.com/erc-8004-a-developers-guide-to-trustless-ai-agent-identity/
- https://blog.eigencloud.xyz/ai-beyond-the-black-box-inference-labs-is-making-verifiable-decentralized-ai-a-reality-with-eigenlayer/
- https://eco.com/support/en/articles/14796365-tees-for-ai-agents-verifiable-compute
- https://phala.com/
- https://arxiv.org/pdf/2509.24257

### Distribution, anti-sybil, and US regulatory (confidence: HIGH on HYPE / friend.tech / Linea-mechanics / EIGEN-geoblock / World ID / Human Passport / SEC-2025-statements / Rev. Rul. 2019-24 / GENIUS Act; MEDIUM on the SEC March-2026 release details, corrected to joint SEC+CFTC five-bucket; LOW on the zkSync / Linea decline percentages, Trusta adoption list, "~80% EIGEN sales," and the CLARITY calendar number, all flagged `[needs-verification]`)
- https://www.dlnews.com/articles/defi/hyperliquid-airdrop-farming-among-factors-driving-hype-token/
- https://crypto.news/zksync-faces-community-backlash-over-lack-of-anti-sybil-measures-in-zk-airdrop/
- https://www.dlnews.com/articles/defi/friend-tech-shuts-down-after-revenue-and-users-plummet/
- https://www.coindesk.com/tech/2024/05/10/eigenlayer-opens-claims-for-airdrop-of-eigen-token-though-its-non-transferable
- https://www.ainvest.com/news/ethereum-news-today-linea-airdrop-threshold-filters-50-sybil-addresses-2508/
- https://www.optimism.io/blog/retro-funding-2025
- https://world.org/blog/announcements/world-launches-in-the-usa-at-last
- https://human.tech/blog/human-passport-proof-of-personhood-and-sybil-resistance-for-web3
- https://medium.com/@trustalabs.ai/trustas-ai-and-machine-learning-framework-for-robust-sybil-resistance-in-airdrops-ba17059ec5b7
- https://www.gtlaw.com/en/insights/2026/3/sec-clarifies-status-of-crypto-assets-under-federal-securities-laws-signals-potential-exemptive-and-safe-harbor-framework
- https://www.sidley.com/en/insights/newsupdates/2025/11/breaking-down-project-crypto-sec-chairman-atkins-outlines-next-phase-of-digital-asset-oversight
- https://www.irs.gov/pub/irs-drop/rr-19-24.pdf
- https://www.congress.gov/bill/119th-congress/house-bill/3633/text
- https://www.coindesk.com/policy/2026/05/09/crypto-industry-cheers-senate-clarity-act-markup-date-as-market-structure-push-resumes

### Cross-cutting US-accessibility note (confidence: HIGH)
Hyperliquid (and its HLP vault) is US-geoblocked (`no`); EigenLayer / EIGEN restaking is `unclear`
for a US founder; the EIGEN token airdrop itself was `no` (US / Canada / China geoblocked); Karak,
Nexus membership, second-wave cover protocols, and Solana restaking are `unclear`; all permissionless
EVM standards (4626 / 7540 / Morpho / Yearn / EAS / Verax / ERC-8004 / EIP-7702 / ERC-7683), x402,
Circle, the AI insurers (AIUC / Armilla / Testudo), World ID, Human Passport, Trusta, Solana L1 /
Token-2022 / SAS / CCTP, and the named US legal instruments are US-accessible (`yes`). Orca is `yes`
at the protocol / SDK level but its front-end blocks US users; Solana confidential transfers are
`no` (feature disabled).

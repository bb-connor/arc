# Chio Execution Roadmap (Integrated, Dependency-Ordered)

Status: VP-Engineering decision doc. This integrates four extracted workstream clusters
(`token-contracts`, `pass-m0`, `market-primitives`, `commerce-launch`) into ONE sequenced
execution plan. It is the routing layer over the source brainstorms; it does NOT restate their
detail. Read alongside:

- `docs/brainstorm/CHIO-PASS-M0-SPEC.md` (Pass M0 normative spec, Sections 2/4/5/6/7/8/9)
- `docs/brainstorm/CHIO-TOKEN-AND-CONTRACTS-PLAN.md` (token decision + M0..M6 + Sec 7 kill-criteria)
- `docs/brainstorm/CHIO-TOKEN-COMMERCE-ALIGNMENT.md` (the five blocking reconciliations C1..C7)
- `docs/brainstorm/CHIO-BENEVOLENT-TOKEN-DESIGN.md` (free-tier Half-A / Half-B, anti-farm)
- `docs/brainstorm/CHIO-AUTONOMOUS-COMMERCE.md` (the commerce wedge and primitives)
- doc-06 Phase 6 multi-source capital role model (gates the insurance/ReserveBook source)

Fail-closed posture throughout: no gate, no ship. Where a milestone's evidence cannot be produced,
the gate stays closed and the milestone does not advance.

---

## 1. Executive summary

### The critical path in one paragraph

The shortest path to a functioning marketplace plus a Chio Pass launch runs through ONE foundational
additive type, two XL custody/budget builds, and a single non-negotiable guardrail. Build the canonical
window-scoped capability id ([WS-PASS-T1], `crates/core/chio-core-types/src/capability/token.rs`) first
because every Pass component derives from it and there must be no rival derivation. In parallel, capture
and commit the cleanup-swarm digest baseline ([WS-CL-DIGEST-BASELINE]) before any signed body is touched,
because RR3-T07-01 is already RED at HEAD, a `cargo test --workspace` green bar masks new fixture breaks,
and EVERYTHING signed-body downstream (the escrow settlement packet, the Pass anchoring proofs) depends on
the swarm not silently re-canonicalizing a signed struct. With those two in place, the two long-pole XL
builds run concurrently: the aggregate `freetier:global` pool ceiling ([WS-PASS-T3] = [WS-MKT-POOL], one
atomic kernel closure in `crates/kernel/chio-kernel/src/kernel/validation.rs`) and the single-ledger
custodial offer-safety escrow A2 ([WS-MKT-ESCROW-LEDGER], `chio-open-market/src/bidding.rs` +
`chio-settle`). Those converge into the Pass control-plane orchestrator ([WS-PASS-T9]) and the escrow wire
into `accept()` and the commerce-order spine ([WS-MKT-ESCROW-WIRE]), executed under the digest guardrail
while the cleanup swarm ([WS-CL-SWARM-EXEC]) runs. The launch gate is the Pass M0 launch-readiness evidence
(spec Section 8.3, gates 1-7) plus the escrow conservation proptest plus a digest-diff-clean
launch-acceptance run. The legal critical path (the 50-state MTL/MSB + FinCEN CVC memo [WS-TC-RG-MTMEMO]
and the non-custody demonstration [WS-TC-RG-NONCUSTODY]) runs in parallel and gates the contract-surface
config and the Phase 0 -> 1 escalation; start the counsel engagement NOW because it has the longest external
lead time.

### The 3-5 highest-leverage first builds

1. [WS-PASS-T1] canonical `AttestationWindowId` + `window_scoped_capability_id`. Pure-additive,
   zero-regression, single source of truth that unblocks the entire Pass spine (T2/T3/T4/T5/T8). Greenlight
   immediately.
2. [WS-MKT-ESCROW-LEDGER] the offer-safety escrow A2 (CALLED OUT). Today offer-safety is only PROCEDURAL:
   `accept()` checks a signed `ReservationReceipt` covers `token_offer_total_liability` but no agent custodies
   BOTH legs. This single-ledger custodial escrow that atomically swaps token-for-funds or refunds both is
   the foundational marketplace primitive; it also makes the secondary market ([WS-MKT-SECONDARY]) and atomic
   transfer-settle safe for free. Foundational, no dependencies.
3. [WS-PASS-T3] / [WS-MKT-POOL] the `freetier:global:<window>` aggregate pool ceiling (CALLED OUT). Bounds
   Half-B subsidy liability to `min(N_passes x allotment, POOL)` instead of structurally unbounded. Kernel-local,
   one atomic `with_budget_store` closure, only depends on T1's window derivation.
4. [WS-CL-DIGEST-BASELINE] the per-crate signed-body digest baseline + guardrail extension. The keystone
   that lets the cleanup swarm and all signed-body launch work proceed without silently breaking launch-acceptance.
5. [WS-TC-M0-HYGIENE] lock the DO-NOT-WEAKEN fail-closed invariants (no-CHIO pin, `premium.rs:141`
   3-letter currency check, `ExposureLedgerSupportBoundary` defaults, bindings ABI lock) as regression tests
   before the swarm can relax them.

### Phase structure

- now: foundations, guardrails, research-gate kickoff (M0).
- phase0-launch: the tokenless marketplace + Pass M0 launch (M1).
- phase1: off-chain accounting collapse, closed-loop prepaid credit, verifiability pricing, interop ADOPT (M2).
- phase2: voluntary USDC bonds (M3) then enforceable comptroller-bound slashing (M4).
- phase3: governance handoff + ad-valorem revenue (M5).
- conditional: transferable CHIO, experience-rated curve, risk-sharing depth, Solana pilot (M6, may never fire).

---

## 2. Workstream dependency graph (by phase, with depends_on edges)

Notation: `A -> B` means B depends on A (A unblocks B). `==` marks two cluster names for the SAME build.

### now (M0 foundations, no entry deps unless noted)

```
WS-PASS-T1            (chio-core-types capability id)            -> T2,T3,T4,T5,T8
WS-MKT-ESCROW-LEDGER  (A2 single-ledger custodial escrow)        -> WS-MKT-ESCROW-WIRE, WS-MKT-SECONDARY
WS-MKT-POOL == WS-PASS-T3 (freetier:global ceiling)              -> WS-PASS-T9 (and the metered M0 gate)
WS-CL-DIGEST-BASELINE (signed-body baseline + guardrail)         -> WS-CL-SWARM-EXEC, WS-CL-EAS-VERAX-PROJ, WS-CL-PASS-PROOFPANEL
WS-CL-SCHEMA-GATE     (R-T05-16 hold + new-schema hook)          -> (future SlashInstruction/anchor schema landing)
WS-CL-RECOMPUTE-GATE  (verifier recompute-not-trust)             -> WS-CL-X402-VERIFY, WS-CL-EAS-VERAX-PROJ, WS-CL-ERC8004-REG, WS-CL-SOLANA-PASS-PILOT
WS-CL-PASS-NAMING     (naming + copy-lint)                       -> (launch copy)
WS-TC-M0-HYGIENE      (DO-NOT-WEAKEN locks)                      -> WS-TC-M1-NETTING, gates the swarm
WS-TC-RG-MTMEMO       (counsel: 50-state MTL/MSB/CVC/GENIUS)     -> WS-TC-M0-CONTRACTS, WS-TC-M0-DOCS, WS-TC-RG-CLOSEDLOOP, Phase0->1
WS-TC-RG-NONCUSTODY   (non-custody key-surface proof)            -> WS-TC-M0-CONTRACTS, Phase0->1
WS-PASS-GOV           (ChioPassConfig numbers + key provenance)  -> blocks launch-readiness SIGN-OFF, not the build
```

### phase0-launch (M1 assembly = LAUNCH)

```
WS-PASS-T1                         -> WS-PASS-T2 -> WS-PASS-T5
WS-PASS-T1                         -> WS-PASS-T4 -> WS-PASS-T7, WS-PASS-T8
WS-PASS-T2,T4,T5                   -> WS-PASS-T6 (admission assertion, closes the 3 other mint sites)
WS-PASS-T5                         -> WS-PASS-DISC (own-data gift via disclosure-lineage bundle)
WS-PASS-T7,T9                      -> WS-PASS-ELIG (eligibility bound to trust-market substrate)
WS-PASS-T2,T3,T4,T5,T7,T8         -> WS-PASS-T9 (control-plane orchestrator, XL, the long pole)
WS-MKT-ESCROW-LEDGER              -> WS-MKT-ESCROW-WIRE (into accept() + commerce-order state machine)
WS-CL-DIGEST-BASELINE            -> WS-CL-SWARM-EXEC (13 economy crates + contracts)
WS-TC-RG-MTMEMO,WS-TC-RG-NONCUSTODY -> WS-TC-M0-CONTRACTS -> (advisory allowlist, stablecoin feeds only)
WS-TC-RG-MTMEMO                  -> WS-TC-M0-DOCS (strike flat-vs-bps prose)
WS-CL-RECOMPUTE-GATE             -> WS-CL-CAPITAL-SOURCE-GATE, WS-CL-SLASH-LANE-GATE (conformance harnesses, build now, gate later)
```

Deferrable within M1 (non-blocking for the metered fail-closed M0 gate, spec Section 6.6):
`WS-PASS-T10` (anchoring job, read-only ChioRootRegistry) and `WS-CL-PASS-PROOFPANEL` (sealed proof panel),
both depend on `WS-PASS-T4`/`WS-PASS-T9` and `WS-CL-DIGEST-BASELINE`.

### phase1 (M2), entry-gated by RG-MICA + RG-CLOSEDLOOP + named licensed partner

```
WS-TC-M0-HYGIENE       -> WS-TC-M1-NETTING (off-chain ExposureLedger collapse = kill-evidence vs on-chain credit)
WS-TC-M1-NETTING + RG-MICA + RG-CLOSEDLOOP + partner -> WS-TC-M2-PREPAID (escrow-socketed prepaid VIEW)
WS-MKT-ESCROW-WIRE     -> WS-MKT-VGRADE (verifiability-graded price + quote-option/last-look)
WS-CL-RECOMPUTE-GATE   -> WS-CL-X402-VERIFY -> (carries x402/ACP/AP2 as envelope projections)
WS-CL-RECOMPUTE-GATE + WS-CL-DIGEST-BASELINE -> WS-CL-EAS-VERAX-PROJ (display-only root projection)
WS-CL-SLASH-LANE-GATE   (conformance harness; GATES M4 before any vault is built)
WS-CL-CAPITAL-SOURCE-GATE (single-source fail-closed guard; GATES M3 bond_depth + Phase-2 pool)
```

### phase2 (M3 voluntary bonds, then M4 enforceable slashing)

```
# M3 (no new contract; existing ChioBondVault self-slash), gated by RG-UNDERWRITER
WS-TC-M0-CONTRACTS + RG-UNDERWRITER -> WS-TC-M3-SELFBOND
WS-TC-M3-SELFBOND + RG-UNDERWRITER  -> WS-TC-M3-BONDDEPTH (gated by WS-CL-CAPITAL-SOURCE-GATE)
WS-TC-M3-SELFBOND                   -> WS-TC-M3-ADMISSION (binary admission gate, NO trust-weight fold)
WS-MKT-ESCROW-LEDGER                -> WS-MKT-SECONDARY (resale/transfer-settle rides the escrow)
WS-CL-RECOMPUTE-GATE + Pass M0      -> WS-CL-ERC8004-REG (Identity/Reputation registration, PILOT)

# M4 (new immutable ChioSlashableBondVault), gated by RG-UNDERWRITER(named insurer) + RG-SLASHADJ + RG-BONDSIZE + audit + partner
WS-TC-M3-BONDDEPTH + RG-UNDERWRITER + RG-SLASHADJ + RG-BONDSIZE -> WS-TC-M4-SLASHVAULT
WS-TC-M4-SLASHVAULT + RG-SLASHADJ   -> WS-TC-M4-SLASHINSTR (register schema or hit R-T05-16)
WS-TC-M4-SLASHINSTR + WS-TC-M4-SLASHVAULT -> WS-TC-M4-COMPTROLLER-BIND (single slash lane)
WS-TC-M4-COMPTROLLER-BIND           -> WS-TC-M4-FEDGATE-REVOKE, WS-TC-M4-RELAYER, WS-TC-M4-RESERVE-BONDSPLIT
WS-CL-SLASH-LANE-GATE               (must be GREEN before WS-TC-M4-SLASHVAULT build starts)
```

### phase3 (M5), gated by RG-DECENTRAL + durable fee volume above ~$28k/day

```
WS-TC-M4-SLASHVAULT,COMPTROLLER-BIND,RELAYER + RG-DECENTRAL -> WS-TC-M5-GOVERNANCE
FeeRouter/ChioTreasury (in WS-TC-M5-GOVERNANCE) + WS-MKT-ESCROW-WIRE -> WS-MKT-REVENUE (ad-valorem GMV + royalty + caveat-discharge)
WS-TC-M5-GOVERNANCE evidence -> WS-TC-RG-DECENTRAL (decentralization metric + securities opinion)
```

### conditional (M6, may never fire)

```
WS-TC-M5-GOVERNANCE + RG-DECENTRAL -> WS-TC-M6-CHIO (soul-bound credential FIRST, then maybe transferable CHIO)
passing chio.risk.actuarial-backtest + WS-MKT-ESCROW-WIRE -> WS-MKT-XRATE (experience-rated curve)
doc-06 Phase 6 + named reinsurer/surety -> WS-MKT-RISKSHARE (treaty/pool/novation)
Pass M0 + WS-CL-RECOMPUTE-GATE -> WS-CL-SOLANA-PASS-PILOT (Token-2022 NonTransferable, devnet, display-only)
```

### Cross-cluster dependency resolutions (the contested seams)

- Pool vs escrow both "touch budget/escrow" but are DISTINCT seams. The `freetier:global` pool
  ([WS-PASS-T3] = [WS-MKT-POOL]) is a synthetic aggregate term in `budget_store` debited inside ONE
  `with_budget_store` closure in `kernel/validation.rs`; the offer-safety escrow ([WS-MKT-ESCROW-LEDGER])
  is a separate two-leg custodial ledger over `chio-settle` + `ChioEscrow.sol`. They must NOT be merged.
  The `freetier:global:` prefix is namespace-isolated so aggregate budget projections and the
  `chio.risk.comptroller-report.v1` reserve view NEVER count it as a real commerce/capability hold, and the
  escrow ledger never co-debits the pool. One build, two ledgers, hard isolation tests both ways.
- The slash workstream is bound to the comptroller, never parallel. Every M4 slash routes
  `SlashInstruction -> transfer_funds capital instruction (pending_execution/not_observed) -> vault impair as the
  OBSERVED leg -> RiskSanctionReserveLedgerEntry(lane market_slash) bound by a RiskSanctionBridge`, passing
  `validate_risk_sanction_reserve_ledger`, the double-consumption guard (`ledger.rs`), and the pre-observed gate
  (`lib.rs`). The conformance harness [WS-CL-SLASH-LANE-GATE] (built in M2) MUST be green before
  [WS-TC-M4-SLASHVAULT] build starts. The vault impair is NOT an independent slash authority
  (alignment C1).
- Everything signed-body depends on the swarm not breaking digests. [WS-CL-DIGEST-BASELINE] is the keystone
  of the whole program: it precedes [WS-CL-SWARM-EXEC] AND any signed-body change downstream
  ([WS-MKT-ESCROW-WIRE]'s `CommerceSettlementPacket`, Pass anchoring, the M4 SlashInstruction). The acceptance
  bar is a per-crate digest-diff against the recorded RED baseline, NOT cargo-test-green (alignment C5).

---

## 3. Sequenced milestones M0..M6

Each milestone: bundled workstreams, entry dependencies, the fail-closed launch-readiness gate (proof/evidence
required), and parallel vs serial work inside it.

### M0 - Foundations and guardrails (NOW, pre-launch)

- Bundles: [WS-PASS-T1], [WS-MKT-ESCROW-LEDGER], [WS-PASS-T3]/[WS-MKT-POOL], [WS-CL-DIGEST-BASELINE],
  [WS-CL-SCHEMA-GATE], [WS-CL-RECOMPUTE-GATE], [WS-CL-PASS-NAMING], [WS-TC-M0-HYGIENE]; kickoff (non-code,
  long-lead) of [WS-TC-RG-MTMEMO], [WS-TC-RG-NONCUSTODY], [WS-PASS-GOV].
- Entry deps: none. This is the start line.
- Parallelizable: every item above is independent and additive; assign to separate owners. [WS-PASS-T1],
  [WS-MKT-ESCROW-LEDGER], [WS-PASS-T3]/[WS-MKT-POOL], and the three `commerce-launch` gates run fully concurrently.
- Serial within: [WS-CL-DIGEST-BASELINE] must LAND (baseline captured and committed) before [WS-CL-SWARM-EXEC]
  in M1 and before any signed-body edit; it is serial-ahead of all M1 signed-body work.
- Gate (fail-closed): digest baseline captured + committed and a per-crate digest-diff run is clean; T1
  determinism + RFC8785 byte-stability + window-sensitivity + fail-closed-window unit tests green; escrow
  single-ledger conservation proptest (both legs swap atomically or both refund, never one-sided; funds move
  ONLY against a reconciled `CapitalExecutionObservation::Matched`); pool liability `== min(N x allotment, POOL)`
  with exhaustion denying `cost_charged=0` and namespace-isolation proven both directions; M0-HYGIENE
  DO-NOT-WEAKEN regression suite green (no-CHIO pin, `premium.rs:141`, `ExposureLedgerSupportBoundary`
  defaults, `chio-web3-bindings` ABI lock byte-identical to `contracts/src/*.sol`); R-T05-16 and recompute
  negative tests green; copy-lint green.

### M1 - Phase-0 launch assembly (tokenless marketplace + Pass M0) = LAUNCH

- Bundles: Pass spine [WS-PASS-T2], [WS-PASS-T4], [WS-PASS-T5], [WS-PASS-T6], [WS-PASS-T7], [WS-PASS-T8],
  [WS-PASS-T9], [WS-PASS-DISC], [WS-PASS-ELIG]; marketplace [WS-MKT-ESCROW-WIRE]; cleanup [WS-CL-SWARM-EXEC];
  contracts [WS-TC-M0-CONTRACTS], [WS-TC-M0-DOCS]. Deferrable: [WS-PASS-T10], [WS-CL-PASS-PROOFPANEL].
- Entry deps: M0 complete; for the contract-surface config specifically, [WS-TC-RG-MTMEMO] and
  [WS-TC-RG-NONCUSTODY] signed (non-custody demonstration recorded). The Pass software gate does not need the
  contracts deployed (on-chain leg is prepare-only; anchoring is read-only), so the build can reach
  launch-readiness while the legal sign-off closes in parallel.
- Parallelizable: two independent spines run concurrently. Pass spine fans out from T1 into
  (T2 -> T5) and (T4 -> T7, T8), converging at T9. Marketplace spine is ESCROW-LEDGER -> ESCROW-WIRE.
  The cleanup swarm runs as a third lane under the digest guardrail. Contracts config + docs are a fourth lane.
- Serial within: [WS-PASS-T9] is the long pole (XL, high risk) and serializes behind T2/T3/T4/T5/T7/T8;
  [WS-PASS-T6] needs T2+T4+T5; [WS-PASS-DISC] needs T5; [WS-PASS-ELIG] needs T7+T9. [WS-MKT-ESCROW-WIRE] needs
  ESCROW-LEDGER and must land its `CommerceSettlementPacket` AFTER the digest baseline.
- Gate (fail-closed): Pass M0 launch-readiness evidence per spec Section 8.3, gates 1-7 (pool ceiling denial
  at the 4th distinct-subject XCC charge; deterministic window-scoped id accumulating on ONE row; baseline-read
  parity across all 5 tier_0 streams; WithheldDormant denies first metered charge; anchoring round-trip via
  `verifyInclusionDetailed` with NO value transfer); own-data gift emitted as a verified `DisclosureLineageBundle`
  (alignment C2, not the bare 3-key strip); [WS-MKT-ESCROW-WIRE] order-passport replay green with the escrow
  digest pinned into `CommerceOrderContext`; `cargo xtask verify launch-acceptance` + the proof-room and
  transaction-passport scripts DIFF-clean vs the M0 baseline (zero canonical-JSON digest drift); each swarm crate
  diffs clean with commerce-aware reviewer sign-off for the six signed-body crates; non-custody demonstration on
  file; only stablecoin feeds registered (no CHIO/USD feed).

### M2 - Phase 1: off-chain accounting + closed-loop prepaid + verifiability pricing + interop ADOPT

- Bundles: [WS-TC-M1-NETTING], [WS-TC-M2-PREPAID], [WS-MKT-VGRADE], [WS-CL-X402-VERIFY],
  [WS-CL-EAS-VERAX-PROJ], [WS-CL-SLASH-LANE-GATE], [WS-CL-CAPITAL-SOURCE-GATE], [WS-CL-PASS-PROOFPANEL].
- Entry deps: M1 launched; [WS-TC-RG-MICA] (MiCA e-money opinion) + [WS-TC-RG-CLOSEDLOOP] (31 CFR
  1010.100(ff)(4) sign-off + named high-frequency customer with a MEASURED permit/gas bottleneck) + named
  licensed partner as issuer of record for [WS-TC-M2-PREPAID].
- Parallelizable: [WS-TC-M1-NETTING], the two conformance harnesses, and the interop ADOPT items
  (x402, EAS/Verax) are mutually independent. [WS-MKT-VGRADE] needs ESCROW-WIRE from M1.
- Serial within: [WS-TC-M1-NETTING] before [WS-TC-M2-PREPAID] (the netting collapse is itself the kill-evidence
  against an on-chain credit token; PREPAID never builds the restricted-ERC20 ChioCreditVault).
  [WS-CL-X402-VERIFY] needs [WS-CL-RECOMPUTE-GATE] first.
- Gate (fail-closed): netting fully realized off-chain with support-boundary flags still default-false;
  prepaid refund-after-deadline non-transferability proven in tests with zero new immutable contract;
  verifiability grade deterministic and monotone (partial verification yields a strictly LOWER grade);
  quote-option/last-look cannot be exercised after `expires_at`; x402 end-to-end on Base testnet with CDP moving
  money and Chio signing (custody-neutral), payment-success-does-not-authorize negative test passes; EAS/Verax
  carried only as `chio.agent-web-proof-envelope.v1` projections with recompute as the sole proof lane; the two
  conformance harnesses green (single slash lane; single-source capital book denies on >1 facility/bond or mixed
  currency).

### M3 - Phase 2a: voluntary USDC self-restitution bonds (no new contract) + secondary market

- Bundles: [WS-TC-M3-SELFBOND], [WS-TC-M3-BONDDEPTH], [WS-TC-M3-ADMISSION], [WS-MKT-SECONDARY],
  [WS-CL-ERC8004-REG].
- Entry deps: M0-CONTRACTS live; [WS-TC-RG-UNDERWRITER] (underwriter confirms premium reduction against a
  POSTED bond); [WS-CL-CAPITAL-SOURCE-GATE] green (gates the bond_depth hook).
- Parallelizable: [WS-TC-M3-ADMISSION] (binary admission gate) and [WS-MKT-SECONDARY] (resale on the escrow)
  are independent of the premium work. [WS-CL-ERC8004-REG] is independent (PILOT).
- Serial within: [WS-TC-M3-SELFBOND] -> [WS-TC-M3-BONDDEPTH] (bond_depth is a deterministic compliance-score
  band, never an actuarial-adequacy claim).
- Gate (fail-closed): bond_depth -> base_rate_cents proven a deterministic band that still requires a passing
  `chio.risk.actuarial-backtest` (cannot imply reserve adequacy); admission gate resolves against a live USDC
  bond tier with tests proving stake NEVER raises `peer_weight`/`weight_bps` or lowers the tier-3 floor (capital
  buys admission/slashing, never trust); secondary resale atomic via escrow with transferred scope a strict
  subset and the monotone non-amplification proptests green; documented that self-slash does NOT close the Sybil
  re-spawn loophole (needs M4).

### M4 - Phase 2b: enforceable comptroller-bound slashing (new immutable, audited)

- Bundles: [WS-TC-M4-SLASHVAULT], [WS-TC-M4-SLASHINSTR], [WS-TC-M4-COMPTROLLER-BIND],
  [WS-TC-M4-FEDGATE-REVOKE], [WS-TC-M4-RELAYER], [WS-TC-M4-RESERVE-BONDSPLIT].
- Entry deps: M3 done; [WS-CL-SLASH-LANE-GATE] GREEN; [WS-TC-RG-UNDERWRITER] with a NAMED insurer/surety as
  principal of record; [WS-TC-RG-SLASHADJ] (due-process onto the RiskClaimAppeal family); [WS-TC-RG-BONDSIZE]
  (bond >= per-session MEV); full external audit of the new value contract; partner contractually committed
  BEFORE build starts.
- Parallelizable: nothing until SLASHVAULT exists. After COMPTROLLER-BIND, the three downstream
  (FEDGATE-REVOKE, RELAYER, RESERVE-BONDSPLIT) can run concurrently.
- Serial within: SLASHVAULT -> SLASHINSTR (register schema or hit R-T05-16) -> COMPTROLLER-BIND -> the rest.
- Gate (fail-closed): external audit clean; written MT/insurance opinion that the partner is principal of
  record; veto committee live; SlashInstruction + anchor schema registered in `spec/schemas/registry.json` +
  `KNOWN_SIGNED_ARTIFACT_SCHEMAS` + claim-registry + proof-room spine (R-T05-16 closed); slash routes ONLY
  through the comptroller (double-consumption + pre-observed gate green; claim-payout-priority + open-appeal holds
  enforced; admission-stake bond cannot consume claim-reserve); relayer prepare-only and rejects any non-partner
  caller; ReserveBook source stays DISABLED while the capital book is single-source fail-closed.

### M5 - Phase 3: governance handoff + ad-valorem revenue

- Bundles: [WS-TC-M5-GOVERNANCE], [WS-MKT-REVENUE].
- Entry deps: M4 done; [WS-TC-RG-DECENTRAL] (measurable decentralization metric + securities opinion +
  evidence of durable non-artificial fee volume materially above the ~$28k/day baseline).
- Parallelizable: the FeeRouter/ChioTreasury collection rail in GOVERNANCE unblocks the ad-valorem
  [WS-MKT-REVENUE] basis; the royalty and caveat-discharge sub-items run concurrently once the rail exists.
- Serial within: deploy Governor + Timelock + Treasury/FeeRouter, then `transferAdmin(timelock)` (a literal
  zero-Solidity-edit handoff on the one mutable contract), then bind Governor outcomes to charter issuance on the
  kernel-key signer (a TimelockController cannot sign canonical JSON; Governor stays advisory).
- Gate (fail-closed): counsel-certified measurable decentralization; durable fee volume above baseline;
  reputation-gated proposer set + veto verified; charter signing kept on the kernel-key signer; new contracts
  audited; flat fees only (never bps); stake kept entirely out of the deterministic reputation computation.

### M6 - Conditional: transferable CHIO + experience-rated curve + risk-sharing depth + Solana pilot

- Bundles: [WS-TC-M6-CHIO], [WS-MKT-XRATE], [WS-MKT-RISKSHARE], [WS-CL-SOLANA-PASS-PILOT].
- Entry deps: M5 gates hold AND every Phase-3 condition true; for [WS-MKT-XRATE] a passing
  `chio.risk.actuarial-backtest`; for [WS-MKT-RISKSHARE] doc-06 Phase 6 + a named reinsurer/surety.
- Gate (fail-closed): securities opinion placing CHIO in the digital-commodity bucket; no yield / no
  buy-and-stake switch; MiCA CASP/white-paper compliance executed; soul-bound predecessor shipped FIRST;
  March-2026 framework survives intact. Kill-criteria (token plan Sec 7): abandon entirely if demand stays
  thin/artificial, decentralization is unverifiable/gameable, or the framework is narrowed.

---

## 4. The first 2-week slice (start NOW)

Concrete, low-risk, high-leverage tasks. The kernel/core foundational items are pure-additive
(zero-regression); the escrow item is design-plus-proptest before full build. Each task names files/crates and
an acceptance test.

1. [WS-PASS-T1] Canonical window-scoped capability id (foundational additive core).
   - Crates/files: `crates/core/chio-core-types/src/capability/token.rs` (additive),
     `crates/core/chio-core-types/src/error.rs` (`Error::InvalidAttestationWindow`).
   - Build: `AttestationWindowId{window_ym,since,until}` + `validate()`, `WindowScopedCapabilityIdInput`,
     `window_scoped_capability_id(subject_did,&window) = "chiopass:" + sha256_hex(canonical_json_bytes(...))`,
     consts `CHIO_PASS_CAPABILITY_ID_DOMAIN`/`_PREFIX`.
   - Acceptance test: id stable across repeated calls, always `chiopass:`-prefixed, distinct on distinct
     `window_ym`/subject, RFC8785 byte-stable independent of field order; `validate` rejects empty `window_ym` and
     `until <= since`; any canonicalization error returns `Err` (fail-closed).

2. [WS-CL-DIGEST-BASELINE] Capture the pre-swarm digest baseline + extend the guardrail (THE keystone).
   - Crates/files: `xtask/src/launch_acceptance.rs`, `scripts/check-chio-transaction-passport.sh`,
     `scripts/check-chio-proof-room-release-truth.sh`, the signed-body crate list across
     `crates/economy/{chio-anchor,chio-credit,chio-market,chio-underwriting,chio-open-market,chio-appraisal,chio-settle}/src`,
     `crates/economy/chio-web3-bindings/src/interfaces.rs`, `fixtures/proof-room/**`.
   - Build: record the RED RR3-T07-01 baseline; replace the chio-web3-only field-stability guardrail with a
     per-crate DO-NOT-reorder/rename/retype list; make the acceptance bar a digest-diff against the captured
     baseline.
   - Acceptance test: baseline committed; `cargo xtask verify launch-acceptance` + the two scripts run per-crate
     and DIFF clean (no net-new failing fixture / digest mismatch); cargo-test-workspace-green explicitly declared
     INSUFFICIENT for signed-body crates. Fail-closed: if the baseline cannot be established, the swarm does not start.

3. [WS-MKT-ESCROW-LEDGER] Offer-safety escrow A2 design + conservation proptest (foundational, CALLED OUT).
   - Crates/files: `crates/economy/chio-open-market/src/bidding.rs` (`ReservationReceipt`,
     `VerifiedReservationReceipt`, `accept`, `token_offer_total_liability`); `crates/economy/chio-settle/src/evm/types.rs`
     (`EscrowDispatchRequest`, `PreparedEscrowCreate`), `prepare.rs`, `finalize.rs`;
     `crates/economy/chio-settle/src/observe.rs` (`CapitalExecutionObservation::Matched`);
     `contracts/src/ChioEscrow.sol` (read-only `deriveEscrowId`/`createEscrow`/`releaseWithProof`/`refund`).
   - Build (this slice): the single-ledger module skeleton + signed escrow artifact + the conservation proptest
     harness; on-chain leg prepare-only.
   - Acceptance test: single-ledger conservation proptest (both legs swap atomically OR both refund, never
     one-sided; funds release ONLY against a reconciled `CapitalExecutionObservation::Matched`, never on pending
     intent); `accept()` fails closed on under-reservation (`reserved_amount < token_offer_total_liability`) and on
     `acceptor != token_offer.subject`; broadcast stays prepare-only.

4. [WS-PASS-T3]/[WS-MKT-POOL] `freetier:global` pool-ceiling scaffolding (foundational additive kernel, CALLED OUT).
   - Crates/files: `crates/kernel/chio-kernel/src/kernel/mod.rs`, `construction.rs`,
     `crates/kernel/chio-kernel/src/kernel/validation.rs` (single `try_debit_freetier_pool` closure +
     symmetric reversal), `error.rs` (`InvalidFreeTierPoolConfig`); `crates/kernel/chio-kernel/src/budget_store.rs`.
   - Build (this slice): additive `FreeTierPoolConfig` (+`validate`), `FreeTierPoolHold`,
     `FREETIER_GLOBAL_GRANT_INDEX`, fallible `with_free_tier_pool` builder (keeps `new()` infallible, avoids ~46
     KernelConfig literal sites), and the one-closure per-Pass-debit-then-pool-debit-then-compensating-reversal.
   - Acceptance test: liability `== min(N x allotment, POOL)`; 4th distinct-subject XCC charge returns
     `Deny`/`cost_charged=0` with the per-Pass row UNCHANGED (hold reversed in-closure); pool-disabled byte-identical
     no-op replay; namespace-isolation test proving aggregate projections + comptroller reserve view EXCLUDE every
     `freetier:global:<m>` row; monthly roll yields a fresh zero row.

5. Low-effort guardrails + hygiene (parallel, S effort): [WS-CL-SCHEMA-GATE] (R-T05-16 hold + VC families
   confirmed OUT), [WS-CL-RECOMPUTE-GATE] (EAS/SAS-as-anchoring fails closed; x402-success-does-not-authorize),
   [WS-CL-PASS-NAMING] (copy-lint green), [WS-TC-M0-HYGIENE] (no-CHIO pin, `premium.rs:141`,
   `ExposureLedgerSupportBoundary` defaults, bindings ABI lock as regression tests).

6. Long-lead, non-code (kick off day 1): [WS-TC-RG-MTMEMO] engage outside fintech regulatory counsel;
   [WS-TC-RG-NONCUSTODY] protocol security lead begins the key-surface demonstration; [WS-PASS-GOV] convene the
   board to fix the single `ChioPassConfig` source of truth and pin `accepted_kernel_keys` to RR2-TM-01.

---

## 5. Risks, gates, and external dependencies

- Cleanup-swarm fleet reliability (GLM / Hermes fleet). The swarm runs across 13 economy crates + contracts
  via a worker fleet. A flaky model that silently re-canonicalizes a signed body is the TOP launch risk because
  `cargo test --workspace` stays green while embedded launch-acceptance fixtures break. Blocks: M1
  [WS-CL-SWARM-EXEC]. Mitigation: [WS-CL-DIGEST-BASELINE] first; commerce-aware (not docs/format-only) reviewer
  for the six signed-body crates; per-crate digest-diff acceptance. Founder decision required on the HERMES_MODEL
  switch before dispatch (Section 6).
- Money-transmission legal opinion [WS-TC-RG-MTMEMO] (HIGH, external counsel, longest lead). Blocks:
  contract-surface config [WS-TC-M0-CONTRACTS], regulatory prose [WS-TC-M0-DOCS], the Phase 0 -> 1 escalation,
  and (transitively) [WS-TC-RG-CLOSEDLOOP]. Fail-closed: unresolved = the gate stays closed.
- Non-custody demonstration [WS-TC-RG-NONCUSTODY] (MEDIUM, internal security lead). Blocks:
  [WS-TC-M0-CONTRACTS]. More tractable than the 50-state memo; produce early to de-risk the contracts lane.
- Named licensed partner (issuer / custodian / insurer / surety of record). Blocks: [WS-TC-M2-PREPAID]
  (issuer of record), all of M4 (insurer/surety as principal of record), [WS-MKT-RISKSHARE] (reinsurer).
  Kill-criteria (token plan Sec 7): if NO partner will be principal of record, kill the credit program (Phase 1)
  and involuntary slashing (Phase 2) rather than custody value.
- MiCA + closed-loop opinions [WS-TC-RG-MICA] / [WS-TC-RG-CLOSEDLOOP]. Gate M2 prepaid. Closed-loop also
  requires a named high-frequency customer with a MEASURED (not assumed) permit/gas bottleneck.
- Underwriter pricing validation [WS-TC-RG-UNDERWRITER]. Gates M3 and M4. Kill-criteria: if underwriters
  price off receipts + tiers WITHOUT a posted bond, defer Phase-2 bonding entirely.
- Slash-adjudication / AB-316 due process [WS-TC-RG-SLASHADJ] + bond sizing [WS-TC-RG-BONDSIZE]. Gate M4.
- Decentralization metric + securities opinion [WS-TC-RG-DECENTRAL] + durable fee volume above ~$28k/day.
  Gate M5/M6. Kill-criteria: thin/artificial demand or unverifiable decentralization abandons the token program.
- Single-source capital book. Until doc-06 Phase 6 ships and a licensed insurer holds a SEPARATE book,
  the `CapitalBookSourceKind::ReserveBook` source stays DISABLED ([WS-CL-CAPITAL-SOURCE-GATE]); the capital book
  fails closed on >1 live facility/bond or mixed currency.

---

## 6. Open decisions for the founder

1. Start M0 Pass implementation NOW? Recommendation: YES. [WS-PASS-T1] and the pool/escrow scaffolding are
   pure-additive and zero-regression; there is no reason to hold them behind the legal gates, which only gate the
   contract-surface config and the Phase 0 -> 1 escalation, not the metered fail-closed M0 software gate.
2. HERMES_MODEL switch (cleanup-swarm fleet). Decide which model the worker fleet runs BEFORE dispatching
   [WS-CL-SWARM-EXEC], and gate dispatch on [WS-CL-DIGEST-BASELINE] being committed. A fleet that silently
   rewrites a signed body is the single highest launch risk; pick reliability over speed for the six signed-body
   crates and require commerce-aware review there.
3. Which marketplace ships first? Recommendation: the PRIMARY posted-price capability market backed by the
   custodial offer-safety escrow ships at M1 launch; the SECONDARY resale/transfer market ([WS-MKT-SECONDARY])
   ships at M3 (it rides the same escrow for free); the ad-valorem GMV revenue rail ([WS-MKT-REVENUE]) waits for
   the FeeRouter/ChioTreasury collection rail at M5.
4. Engage outside regulatory counsel NOW for [WS-TC-RG-MTMEMO]? Recommendation: YES (longest external lead;
   gates the contract config and Phase 0 -> 1). Pair it with the internal [WS-TC-RG-NONCUSTODY] demonstration.
5. POOL sizing + HA posture (WS-PASS-GOV Open Q2). Commit single-node `budget_store_lock` vs shared-SQLite
   soft ceiling; if multi-process shares one SQLite file the pool ceiling is SOFT (overrun bounded by
   `max_cost_per_invocation x node_count`), so size POOL below runway and state the tolerance.
6. `accepted_kernel_keys` provenance + `ChioPassConfig` numbers (WS-PASS-GOV, Open Q1/Q3). Approve the single
   board-pinned config (tier->units default 1000/1000/2500/5000, POOL, window/population caps,
   MIN_GENUINE_USE_RECEIPTS, board_approval_ref) and pin keys to RR2-TM-01 with rotation epochs. Blocks
   launch-readiness SIGN-OFF, not the build.
7. Confirm tenant-id derivation = raw `did:chio` verbatim (WS-PASS-GOV / spec Open Q4). Any
   normalization/hashing mismatch against the SQL `r.tenant_id` guard silently denies ALL own-stream reads.
8. Defer the Pass anchoring job + proof panel? [WS-PASS-T10] and [WS-CL-PASS-PROOFPANEL] are explicitly
   non-blocking for the metered fail-closed M0 gate (spec Section 6.6). Decide whether to ship them at M1 for
   auditability optics or defer to M2.

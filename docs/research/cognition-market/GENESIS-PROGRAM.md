# Genesis Coverage Program ("Chio mining"): bootstrap mechanism design

- Status: research draft (branch `research/genesis-program`, forked from
  `research/cognition-market`)
- Basis: the cognition-market design set (memo, ADR-0017, ARCHITECTURE,
  MECHANISMS, THREAT-MODEL, PLAN) is the settled substrate; this program
  designs the adoption bootstrap that runs ON TOP of it, inside the same
  evidence discipline
- Companions in this program: [GENESIS-ARCHITECTURE.md](GENESIS-ARCHITECTURE.md),
  [ADR-0018](../../adr/ADR-0018-genesis-coverage-program-surfaces.md) (Proposed),
  [GENESIS-PLAN.md](GENESIS-PLAN.md), plus additions to
  [THREAT-MODEL.md](THREAT-MODEL.md)
- Discipline (carried from #1025): every codebase claim cites a real path;
  speculative content is labeled `[speculative]`; load-bearing claims carry a
  confidence level (high/moderate/low/unknown); numbers are modeling
  assumptions with sensitivity notes, never asserted facts; where a design
  input conflicts with repo reality or with the modeling, it is redesigned and
  the conflict recorded.
- Naming: builder-facing materials say "mining"; consortium-facing and repo
  materials say "Genesis Coverage Program". One mechanism, two labels. This
  document and all repo docs use the Genesis name.

---

## 0. Baseline conflict found on orientation (read first)

The brief states the execution baseline is "post-#974 main" carrying a
`fiscal_adapter`/`chio_fiscal` surface and an invocation-capture lifecycle.
**That baseline has not landed.** Verified 2026-07-21:

- [PR #974](https://github.com/bb-connor/arc/pull/974) is **OPEN, not merged**
  (`gh pr view 974`: `state: OPEN`, `mergedAt: null`).
- The merge-base of this branch with `origin/main` is `1825f853ee` (`#1023`).
  Neither `fiscal_adapter.rs` nor `capture_invocation` exists on `main`
  (repo-wide `git grep` on `origin/main` returns nothing).
- `Constraint::RequireCumulativeApprovalAbove` (cited in #1025 PLAN section 0
  as an in-place precedent from #974's open head, not shipped) appears ONLY
  inside the research docs, never in
  code.

Consequence for this program (confidence: high): the mines that depend on real
fee collection (coverage-mining royalties, operator-seat fee shares,
audit-mining top-ups paid from collected fees) sit on top of a surface that is
still declarative today AND on top of #974, which is unmerged. This program is
therefore designed against the CURRENT surface (pre-#974) and states its
dependency on #974 and on the cognition-market fee-collection milestones
(M2/M5) explicitly wherever it bites. The economics do not assume collection
exists; they assume it must be built, and treat that build as a gating
dependency (Q7, [GENESIS-PLAN.md](GENESIS-PLAN.md)).

---

## 1. Constraint register: settled #1025 decisions this program must design within

Task-1 deliverable. Each row is a decision already ratified in the
cognition-market set that the Genesis program touches; the program is designed
to respect it, not relax it. Citations are to the settled docs.

| # | Settled constraint | Source | How Genesis respects it |
|---|---|---|---|
| K1 | Fee collection is declarative today; real collection is M2 (publication fee) and M5 (dispute fee). Nothing charges a fee at runtime, and the shipped fee taxonomy contains NO per-clearing venue fee. | MECHANISMS 6; re-verified: `chio-open-market/src/fee_schedule.rs:79-81` fees are validated + echoed only (`evaluation.rs:468-470`), never charged | The royalty/seat denominator is introduced by the ratified sibling `chio.registry.market-clearing-fee-schedule.v1` at G5; the existing schedule remains unchanged and royalties have zero live flow until sibling collection lands (Q2) |
| K2 | v1 settlement has NO revenue clawback: release and reconcile are immediate; bonds are sized to finalized fraud exposure over a published detection horizon. | MECHANISMS 4; `chio-settle` releases on proof, `dispute_window_secs` observes but does not custody (`config.rs:122`) | Royalties are FORWARD-flowing only (paid from future clearing fees, never reaching back into settled trades); the pool never claws back a paid floor (Q2) |
| K3 | Cross-org escrow REQUIRES a neutral mediating operator; with a seller-aligned mediator, paid non-delivery (attest-and-withhold) is HIGH residual. | ARCHITECTURE F6; THREAT-MODEL O5/S7 | Operator seats (Q5) bind the F6 neutrality obligation as a seat condition; a neutrality violation is a seat-revocation trigger |
| K4 | `evidence_cost` is verifiable only in full-receipt mode (mode A); projected-mode values are seller assertions until audit. Money must never gate on unverifiable cost. | MECHANISMS 1; ARCHITECTURE 4.1, F2 | The bounty floor (Q1) is gated on mode-A proof-of-burn; a mode-B `evidence_cost` gates NOTHING and earns no floor until audited |
| K5 | No exclusive first-commit listing slots; duplicate-context findings coexist with informational anchored-commitment ordering; nobody is paid for duplication. | MECHANISMS 3 | Coverage mining pays at most one floor per demanded descriptor (an inventory unit), never per listing; duplicates earn neither floor nor a second royalty stream (Q1, Q6) |
| K6 | Challenge exposure is bounded by the finding's advertised guarantee class. | ADR-0017 D3/D4 | Audit mining (Q4) audits within the guarantee class; the r statistic is stratified BY guarantee class so a class's reliability is never averaged across classes |
| K7 | Reveal is a governed tool call; delivery-vs-payment is the kernel digest gate. No new settlement rail, escrow contract, or atomic swap. | ADR-0017 D2; ARCHITECTURE 6 | V1 royalties open ordinary legs on the existing rail. Optional batching is additive fee-distribution contract/router surface, not a new rail, and requires separate review (Q2) |
| K8 | Proof claims stay inside the verifier boundary (`ChioProofClaims`); evidence classes never upgraded (P10). | ARCHITECTURE 2; THREAT-MODEL 6 | The r feed is a signed statistic, NOT a proof; it never upgrades a finding's evidence class, and buyers weight it, they do not treat it as verification |
| K9 | No job daemon exists; epoch/audit/anchor cadence runs on operator cron with after-the-fact assessment. | ARCHITECTURE 8.2; re-verified `chio-anchor/src/automation.rs`, `chio-revocation-oracle/src/epoch.rs` (no scheduler) | The audit scheduler and r-feed epoch ticking are operator-cron conventions, not new daemons (Q4, Q7) |
| K10 | Slash destinations are constrained to harmed parties or a registered community fund (ADR-0015 D4), and no discretionary settlement path exists. | ADR-0017 D4; THREAT-MODEL C2 | Audit bounties and slash shares ride the existing constrained distribution; the pool never becomes a discretionary payee (Q4, Q6). See the honest-limit in section 9: D4's recipient allowlist is prose, not code, today |

Two of these registers surfaced a gap during verification that the register
must flag honestly, not paper over:

- **K1/K10 gap (confidence: high).** ADR-0015 D4's "harmed parties or a
  registered community fund" recipient rule is NOT enforced in code. The
  comptroller's `market_slash` lane binds the sanctioned SUBJECT and caps the
  amount (`chio-risk-comptroller/src/ledger.rs:280-315`), and the settle
  distribution enforces exact-sum, non-zero-address, at-most-16 beneficiaries
  (`chio-settle/src/evm/prepare.rs:989-1017`), but neither restricts WHO
  receives; `impairBondDetailed` routes shares to any non-zero addresses that
  sum to the slash amount (`contracts/src/ChioBondVault.sol:215-247`).
  ADR-0015's own Follow-up A (the on-chain recipient allowlist) is explicitly
  deferred because `ChioBondVault` is immutable. Genesis payout destinations
  therefore rely on the SAME (currently prose-level) discipline the wider
  program relies on; the program does not add its own trustless allowlist and
  says so in section 9.

---

## 2. The problem, stated as a fixed point

Cold start is a transaction-opportunity fixed point. Coverage requires sellers;
sellers require expected revenue; and no buyer can clear when no matching
inventory exists. The pay-on-hit market prices a confirmed match, so coverage
does not multiply the price of that hit. It multiplies how often a priced hit
exists:

```
B_hit        = (C + W) - (1 - r) * (V - dB)
Q_net(p)     = h * (B_hit - p) - c_q
p_max_hit    = max(B_hit - c_q / h, 0)  for h > 0
```

- `h` = coverage = probability the book contains a finding matching the query
- `r` = hit reliability = probability a matched finding is correct/useful
- `C` = re-derivation cost (buyer's outside option: solve it yourself)
- `W` = redeployed-budget value (value of the compute/time freed by not
  re-deriving)
- `V` = decision stakes (what the finding informs)
- `dB` = expected bond recovery if the finding is wrong
- `c_q` = marginal query/discovery cost paid whether or not a hit exists

`p_max_hit` is the maximum all-in price after accounting for the expected cost
of misses. When `c_q = 0` or discovery cost is sunk, it reduces to
`max(B_hit, 0)` and coverage cancels from the per-hit ceiling. When `c_q > 0`,
coverage also raises the rational hit bid by spreading query friction across
more successful searches. At `h = 0` there is no finite clearing price: there is
literally nothing to buy, so no seller earns and coverage stays zero. The
program's job is to create transaction opportunities on descriptors buyers
actually demand, cheaply enough that organic clearing and security funding take
over before a bounded pool is exhausted.

Constraints on how (from the brief, treated as hard):

1. **No token.** Rewards are exactly three things: (a) money from a bounded,
   pre-funded subsidy pool in the settlement numeraire, (b) royalty rights on
   future clearing fees, (c) position (reputation, coverage share, capped
   operator seats). No protocol-native transferable reward unit. If a
   mechanism needs a token, it is out of scope.
2. **Subsidies buy inventory or security, never behavior or volume.** Never
   pay per listing count.
3. **Consortium-first.** The launch profile is the governed-fleet install
   base (permissioned); permissionless is a later profile, not the launch.

---

## 3. Pricing model: separating hit price from coverage value

Confidence: the algebra is high; the parameter magnitudes are labeled modeling
assumptions with ranges.

### 3.1 Pay-on-hit isolates the per-hit ceiling when query friction is negligible

The current market charges `ListingPricingHint.price_per_call` after a matching
listing is found (`chio-listing/src/discovery.rs:48,61`). A buyer facing a
decision with stakes `V` has a reliable
outside option: re-derive at cost `C`, which also foregoes redeployed value
`W`. Conditional on a hit:

- Buying a hit avoids the immediate re-derivation cost `C` and frees budget
  worth `W` regardless of whether the answer later proves correct.
- With probability `(1 - r)` the finding is wrong: the buyer acts on wrong
  information, incurs decision damage up to `V`, and recovers `dB` from the
  bond. Define `0 <= dB <= V`, so the incremental wrong-answer loss is
  `(V - dB)` and the model does not assume profitable over-insurance.

The conditional net benefit is `B_hit`. If the hit price is `p`, expected
payment is `h * p`, so the buyer's ex-ante participation condition is
`h * (B_hit - p) >= c_q`. For `h > 0`, `p <= B_hit - c_q/h`. Coverage therefore
always changes served-query frequency and aggregate transaction opportunity;
it leaves the confirmed-match ceiling unchanged only in the pay-on-hit,
negligible-query-friction case. The conservative alternative
that credits the saved work only on correct hits uses
`B_hit = r(C + W) - (1 - r)(V - dB)`; it is retained as a sensitivity case.

Once D7 exists, `p` means the buyer's ALL-IN charge:
`seller_price_per_call + D7_clearing_fee`. The seller receives the full listed
price; the D7 fee is additive and is the only royalty/seat denominator. A
listing clears only when this all-in amount is at or below `p_max_hit`.

### 3.2 The wedge clears; the R&D null often does not (quantified)

The reliability penalty `(1 - r)(V - dB)` is measured relative to the reliable
outside option. This term is where the coding wedge and the R&D instance
diverge, and it explains the #1025 wedge-first recommendation numerically
rather than by assertion.

Modeling assumptions (coding wedge, "make this failing suite pass at commit C",
`deterministic_replay`), all order-of-magnitude with wide ranges:

- `C + W` (re-run and re-derive the fix, plus freed agent-budget value): $4 to
  $40 per finding. Sensitivity: dominated by suite runtime and model cost.
- `r` for `deterministic_replay`: 0.97 to 0.999 (the claim is re-checkable by a
  mediated re-run; residual is replay-recipe drift).
- `V` (stakes of acting on a wrong "fix"): $50 to $500 (developer-hours or CI
  time lost).
- `dB` (bond recovery): high, because the wedge bond is sized to finalized
  exposure (K2); assume `dB` covers 60 to 90 percent of `V`.

Then the penalty `(1 - r)(V - dB)` is roughly `0.02 * (0.2 * 200) = $0.8` at
the midpoints, against `C + W ~= $15`, so the zero-query-friction ceiling is
`p_max_hit ~= $14.2`. Any non-zero `c_q/h` is deducted from that ceiling. The wedge
clears at any seller ask below about $14. Coverage determines how many such
clearings are available, not that price ceiling.

Modeling assumptions (R&D null, "this experiment shows no effect",
`metered_attested`, not replay-checkable):

- `r`: 0.5 to 0.8 (no mechanical re-check; the honest-cost-fabrication residual
  is real, THREAT-MODEL S2).
- `V`: large (avoiding a dead end is high-stakes) and `dB` small (a bond cannot
  cover semantic wrongness), so `(V - dB) ~= V`.

Then the penalty `(1 - r) * V` can approach or exceed `(C + W)`, driving
`B_hit` toward or below zero: for `r = 0.65`, `V = $300`, `C + W = $30`,
penalty `= 0.35 * 300 = $105 >> $30`, so `B_hit < 0` and no rational buyer
purchases. This is the adverse-selection-on-exhaust residual (section 9),
falling straight out of the model: the R&D null is structurally the hard case,
which is why the wedge (verified fixes and failing-test findings for major OSS
ecosystems, plus ML non-convergence sweeps ONLY where the recipe is pinned
deterministic; the launch determinism rule in 4.1 makes this a floor-admission
condition, not an aspiration) launches first. The program still ships the
R&D-null descriptor, royalty-only, guarantee-class, and reliability semantics
from the start. It withholds only the treasury floor for claims whose semantic
correctness the audit lane cannot adjudicate. That is a security boundary, not
a demand-validation gate.

### 3.3 Coverage creates served demand and can amortize query friction

Pooled coverage composes as `h_pool = 1 - Prod_i (1 - h_i)`. In the wedge's
exact-context regime (`descriptor.context_sha256` equality,
ARCHITECTURE 4.1), a finding matches its exact descriptor with `h_i ~= 1` and
nothing else, so for a query on descriptor `d`, `h_pool(d) = 1` if any admitted
finding covers `d`, else `0`. Aggregate coverage `h` is then the query-weighted
mass of covered descriptors ("covered demand mass").

The original unconditional claim that coverage raises every buyer's ceiling is
false. In the shipped pay-on-hit case with negligible `c_q`, coverage creates
the inventory against which a demand curve can clear. With non-negligible
query friction it also raises the ceiling from `B_hit - c_q/h` toward `B_hit`:

- Subsidizing the FIRST finding on a demanded, currently-uncovered descriptor
  `d` flips `h_pool(d)` from 0 to 1. The conditional bid remains
  `p_max_hit` (and reaches the zero-friction ceiling when `c_q` is negligible),
  but query demand can now become a paid clearing. The investment
  buys durable served-demand capacity rather than temporary buyer behavior.
- Subsidizing a SECOND finding on an already-covered `d` adds `h_i` to a
  saturated `h_pool(d) ~= 1`: near-zero new transaction opportunity. Pure
  waste for the floor program (duplication).
- Subsidizing any finding on an UN-demanded `d` (no query mass) yields coverage
  with zero realized clearing opportunity: dead inventory. Also waste (adverse
  selection on exhaust).

This boundary is the reason two mechanism rules exist:

- The **procurement list** (Q3) gates admission to demanded descriptors, so the
  pool cannot fund dead inventory.
- **No-duplication-payout** (K5, MECHANISMS 3) denies a floor to the second
  finding on a covered descriptor, so the pool cannot fund duplication.

These rules make the subsidy an investment in covered demand mass and durable
transaction opportunity, not a claim that coverage changes the conditional
value of a hit.

**Why the SUPPLY side is the subsidy side (the objection this model answers).**
The obvious alternative bootstrap is buyer-side coupons (subsidize purchases
instead of listings). The model says no, twice over. First, with `h = 0` on a
descriptor there is nothing to buy at any coupon size: coverage is the binding
constraint, and only supply-side subsidy relaxes it. Second, a covered demanded
descriptor creates a sale opportunity for every future buyer of that context.
An additional buyer also creates seller revenue through the existing
`price_per_call`, so the asymmetry is not absolute; at genesis, however, supply
is the prerequisite side and has the stronger cross-side effect. This is the
two-sided-market reason to subsidize supply first (8.5). Coupons also pay for
BEHAVIOR (purchases), which hard constraint
2 forbids and which is Goodhartable into wash volume, whereas floors buy
durable inventory. Buyer-side subsidy is therefore rejected as a launch
mechanism, not merely unchosen.

---

## 4. The three mines (design, each pressure-tested against the input)

### 4.1 Coverage mining (Q1): two-part tariff, floor gated on burn, royalty on value

**Design input:** sellers list bonded findings against a published procurement
list; a two-part tariff pays a small bounty floor at listing (gated on mode-A
proof-of-burn, descriptor match, audit sampling) plus a royalty share on future
query hits.

**Pressure test and adopted design.** A fixed-plus-use-contingent supplier
payment is the correct shape. Oi 1971 is only a structural analogy because it
prices consumers, while this program compensates suppliers (section 8.2). Two
input details break against the constraints and are redesigned:

1. **The floor must not be a function of claimed production cost.** If
   `floor = evidence_cost`, the program pays full production cost, which (a)
   subsidizes behavior/volume (violates hard constraint 2), and (b) invites
   burn-farming: run expensive useless work to farm a cost-proportional floor
   (THREAT-MODEL GA1). Redesign: the floor is driven by the descriptor's
   demand-and-coverage priority on the procurement list, capped by a fraction
   of VERIFIED cost, never driven by cost.

   ```
   floor(d) = min( schedule(d), kappa * evidence_cost_verified )
   ```

   where `schedule(d)` is a published declining amount per demanded-uncovered
   descriptor (the land-grab clock, section 6), `kappa` in [0.1, 0.5] (modeling
   assumption), and `evidence_cost_verified` is the cost the buyer/auditor can
   check in mode A. Critically, reconciling K4: a mode-B (projected) finding's
   `evidence_cost` is a seller assertion, so it enters this cap as ZERO
   (`kappa * 0 = 0`) and earns NO floor until an audit upgrades it to verified.
   Money is gated on verifiable cost only; the schedule sets the amount; the
   verified cost is only an anti-triviality cap. The floor covers the seller's
   marginal LISTING cost (sealing the payload, publishing, bond opportunity
   cost), not the production cost, which is sunk exhaust of a metered run.
   This formula therefore governs HARVEST admission. If the program commissions
   a new run against the procurement list, verified production cost is
   contracted and budgeted separately; it is never hidden inside the listing
   floor or described as sunk exhaust (section 9.1).

2. **The floor is per covered demanded descriptor, not per listing.** One
   floor per descriptor per coverage epoch (K5 intent; the ordering paragraph
   below defines the epoch rule and the contested-descriptor tie-break). This
   is the "buys inventory, not volume" guarantee made mechanical: you cannot
   farm floors by listing many findings, because only demanded-uncovered
   descriptors admit a floor and each admits at most one while covered.

**Admission gate for a floor payment (all five required):**

- descriptor match against the procurement list: the entry is demanded,
  currently uncovered (`h_pool(d) < saturation`), and the finding matches the
  entry's PINNED context digest AND passes the entry's VENUE-AUTHORED
  acceptance recipe under audit (review finding GA-R4: the seller's own
  `replay_recipe_sha256` commits a seller-authored verdict predicate,
  ARCHITECTURE 4.1, which is fine for organic buyers who inspect recipes but
  wrong for money: a trivially-satisfiable seller predicate would pass its own
  replay, capture the floor, and flip the descriptor to covered, locking the
  real finding out of subsidy. Floor-bearing entries therefore pin
  `context_sha256` and an `acceptance_recipe_sha256` the venue authors, which
  is also what makes the AMC lesson in 8.3, spec under buyer-coalition
  control, actually true of this design);
- mode-A proof-of-burn: the finding's evidence receipts verify fail-closed and
  the metered cost is checkable (ARCHITECTURE F2 mode A);
- the finding is `BondBacked` and slashable (F1 admission, `slashable: true`);
- **the finding's guarantee class is audit-verifiable at launch**, i.e.
  `deterministic_replay`: the floor path samples audits, and an audit can
  mechanically verify only a replayable claim. This settles the "ML
  non-convergence sweeps" launch-wedge input against the settled
  guarantee-class taxonomy (ADR-0017 D3; ARCHITECTURE 10 classes R&D nulls as
  mostly `metered_attested` with replay "only when re-runnable"): a
  non-convergence sweep earns a floor ONLY when its recipe is pinned
  deterministic (seeds, framework determinism flags, committed replay recipe).
  Otherwise it may still take the ROYALTY-ONLY admission door (same
  descriptor-match, burn, and bond gates, no floor and no audit-release):
  royalty rights mint at either door, floors only at this one. Floors never
  pay for claims the audit lane cannot check;
- it survives the sampled-audit window (Q4): the floor is escrowed at
  admission and RELEASES BY DEFAULT at the audit-window end; a venue-scheduled
  sampled audit that proves the finding incorrect blocks release (deadline
  refund to the pool) and feeds the slash lane. Auditor absence, timeout, or
  invalid audit evidence is SYSTEM-INCOMPLETE, not seller fraud: it prevents
  early release but the floor releases at the deadline against the assignment
  and incomplete-outcome receipts, while lowering the conservative reliability
  bound and firing the operator SLA. Release-by-default is deliberate (review finding
  GA-R2): gating every release on a passed audit would either make the floor a
  lottery for honest sellers (an unsampled floor could never release,
  destroying the floor's purpose of covering certain listing cost) or force
  100 percent audit whose cost exceeds the floor itself. Junk stays
  negative-EV WITHOUT per-floor audits because of the `kappa` cap: extracting
  a floor requires metered burn of at least `floor / kappa >= 2x` the floor
  (`kappa <= 0.5`), so the sampled audit's job is fraud-slashing and
  r-manufacturing, not floor deterrence.

**Floor ordering on a contested descriptor (review finding GA-R9).** At most
one floor per descriptor PER COVERAGE EPOCH: a descriptor that goes stale and
returns to uncovered (the model's `mu` churn, 9.1) may earn a new floor;
never a second floor while covered (the K5 no-duplication intent). When two
findings on the same descriptor are concurrently admissible, the floor goes to
the earlier ANCHORED COMMITMENT, with the anchor's own order as the tie rule.
This reuses MECHANISMS 3's settled ordering verbatim (it exists precisely
because kernel timestamps are not a cross-operator order and timestamp races
invite clock gaming); the ordering is informational for listings and
allocative only for the subsidy, so no exclusive LISTING slot is created and
K5 is respected: losers still list, still sell, and still earn royalties.

**Floor custody rides the existing escrow terminal states (no new custody
primitive).** Verified against the contract: `ChioEscrow` releases either
against Merkle-proven receipt evidence or against an operator settlement
signature whose signed digest BINDS a `receiptHash` consumed single-use
(`releaseWithSignature`, `contracts/src/ChioEscrow.sol:199-228`), and refunds
the depositor after the deadline (`refund`, `ChioEscrow.sol:268`). The floor
escrow is exactly this shape: depositor = the pool operator, beneficiary = the
seller, `maxAmount` = the floor, `deadline` = audit-window end plus the
checkpoint-cadence margin (the F6 timing lesson). Release semantics follow the
release-by-default rule above: at window end the operator signs the release
digest binding the ADMISSION receipt hash (unsampled floors) or the passed
audit's receipt hash (sampled floors, releasable early); a sampled audit that
proves incorrect means no signature and a deadline refund. A system-incomplete
audit releases only at deadline, binding both admission and incomplete-outcome
receipts. Two predeclared price-free terminal states, unchanged
(ADR-0015 D2). The trust residual (an operator that withholds a due release
signature) is T5, receipt-visible. In the non-EVM consortium profile the same
contract shape runs as a settle-mediated hold; the mapping, not the chain, is
the design.

The royalty is reward type (b) and is designed in Q2. It pays for value: a
finding that gets hits earns a share of the clearing fees those hits generate;
junk gets no hits, so junk earns no royalty. The royalty is self-funded from
real clearing fees, never from the pool. That limits treasury exposure but is
not the wash-trade defense: a controlled ring can recover parts of the fee, so
the signed related-party exclusion in section 7 remains primary.

### 4.2 Audit mining (Q4): manufacturing the r statistic, and sizing its bounties

**Design input:** challenge agents (consortium members at launch, permissionless
later) run against public commitments; income is slashed bonds plus protocol
bounties, topped up for subsidized findings specifically; beyond security,
audit mining manufactures the public hit-reliability statistic `r` that buyer
pricing consumes, via a new r-feed related to the status-oracle/SignedEpochRoot
machinery.

**Pressure test and adopted design.**

- The audit-as-settlement-grade-deterrent logic is already ratified
  (MECHANISMS 5, 8.3: buyer-initiated challenges alone cannot deter fabrication
  of rarely re-checked claims; limited random ground-truth audits dominate).
  The deterrence inequality is inherited: `audit_rate * slash >= expected
  fabrication profit`, with `expected fabrication profit ~= price * expected
  sales in window`. The Genesis addition is the TOP-UP: subsidized findings
  have weak organic-challenger incentive (a floor-funded finding nobody has
  bought yet attracts no burned buyer to challenge it), so the pool funds
  audits of subsidized inventory specifically, at the published rate, to
  establish `r` on inventory that would otherwise be un-sampled.

- **Top-up sizing needs a JOINT bound, and top-ups pay only ASSIGNED
  auditors.** A ring that plays both sides (list a fraudulent finding under
  one identity, audit-challenge it under another) pays the listing bond
  `B_bond`, publication fees, and the metered burn, and forfeits the escrowed
  floor (its own scheme requires the audit to fail, which refunds the floor
  to the pool, 4.1). But it does NOT collect "only the top-up" (review
  finding GA-R1): under the settled challenge economics the successful
  challenger ALSO receives a predeclared bounty share `s` of the slash
  (MECHANISMS 5), so the ring's take is `(s + beta) * B_bond` against a loss
  of `B_bond` plus costs, and for a subsidized-but-unsold finding there are
  NO harmed buyers, which makes MECHANISMS 5's harmed-parties-first bound on
  `s` vacuous: the zero-harmed-party case is exactly the genesis program's
  dominant state. A `beta` cap alone therefore closes nothing. Two program
  rules close it:
  (1) the pool's top-up is paid ONLY to the venue-ASSIGNED auditor of a
  scheduled random audit, where assignment is drawn from the published
  randomized schedule using the first external finalized checkpoint after the
  frozen population cutoff (GENESIS-ARCHITECTURE 3.3); a voluntary
  self-selected challenger gets
  the ordinary MECHANISMS 5 economics but NO top-up, so a ring cannot
  appoint itself auditor of its own listing and collects `beta` only with
  probability equal to its share of the assigned-auditor pool;
  (2) the JOINT bound `s + beta <= 0.8` (margin 0.2; modeling default) is
  published with the schedule, binding SPECIFICALLY for zero-harmed-party
  slashes where `s` is otherwise unconstrained, so even a ring that wins the
  assignment lottery nets `(s + beta - 1) * B_bond - costs < 0`. The top-up
  additionally never exceeds the auditor's metered replay cost plus a
  bounded premium. The related self-CHALLENGE analysis (a seller
  fake-challenging itself to farm failed-challenge forfeits) is already in
  MECHANISMS 9 item 5 and carries over unchanged (THREAT-MODEL GA9).

- **The audit budget is the pool's structural tail risk, not a rounding
  item.** The standing published-rate surveillance of the LIVE corpus scales
  with the coverage the program itself builds, and the runway model (9.1,
  conclusion 2) shows it, not the floor line, is what exhausts pools:
  self-sustain requires the security-self-funding inequality
  `(1 - o) * (1 - carve) * f * X >=
  (alpha_new * a + alpha_corpus * C) * c_a`, where `o` is operator spread and
  `carve` is the combined genesis carve-out (effective royalty share plus seat
  `fee_share_bps`) on the post-spread base (review finding GA-R3: during genesis
  nearly every clearing is a hit on subsidized inventory, so nearly all of
  `f * X` carries splits; counting the gross fee double-counts the same
  dollar). The program therefore publishes a combined genesis carve-out CAP:
  royalty and seat schedules must fit under it jointly. The 25 percent figure
  is a modeling ceiling to test, not an approved default; the executable runway
  model and owned cost inputs must justify the adopted cap. Audit-rate schedules
  must therefore be published WITH their step-down conditions (accumulating
  per-class reliability evidence lets `alpha_corpus` fall), exactly as the
  floor publishes its decay.

- **The r feed cannot reuse the revocation oracle's tree (confirmed,
  confidence: high).** The status-oracle machinery
  (`chio-revocation-oracle`) is a set-membership accumulator: the leaf preimage
  is the key alone (`sparse_merkle.rs:89-97`, `SHA256(len || subject_id ||
  epoch_nonce)`), `LeafRecord` stores only `{ index, hash }`
  (`sparse_merkle.rs:11-15`), and `EpochRoot` carries only
  `{ epoch, root_hash, leaf_count, issued_at }` (`api.rs:85-91`). There is no
  per-key value slot, and non-inclusion is an oracle-attested re-query, not a
  cryptographic path (`sparse_merkle.rs:77-79`). It cannot carry a per-key
  numeric `r` without a leaf-schema change.

- **What the r feed DOES reuse (confidence: high).** It reuses the signed,
  windowed-aggregate pattern, not the existing reliability calculation.
  `SignedPortableReputationSummary = SignedExportEnvelope<...>`
  (`chio-credentials/src/portable_reputation.rs:224`) is already a signed,
  windowed, receipt-derived numeric aggregate (`effective_score: f64`,
  `window: AttestationWindow`). The r feed is the same PATTERN, re-keyed:
  a signed statistic over audit/challenge outcomes, stratified by
  `(corpus, seller, guarantee_class)` rather than by subject only, published on
  the control-plane surface pattern and anchored by the existing
  `AnchorAutomationJob` cron (K9). It is a new signed-statistic artifact, not a
  reuse of the membership oracle, and the architecture says so (section 3.3 of
  GENESIS-ARCHITECTURE).

  Naming note (from verification): `chio-reputation` already uses "feed" to mean
  a pure observation-to-delta function summed into a tier (`ReputationFeed`,
  `src/feed.rs`). To avoid a conceptual collision, the r-feed artifact is named
  the **reliability epoch** (`chio.genesis.reliability-epoch.v1`; the genesis
  namespace matches its owning program and schema root, and a successor under
  `chio.finding.*` can be ratified if the finding-market owners adopt it
  post-genesis), not a
  "feed", in ADR-0018 and GENESIS-ARCHITECTURE.

**How `r` is computed, attested, and made independently auditable:** each
epoch freezes a population and publishes `population_root`,
`sampling_policy_sha256`, `checkpoint_policy_sha256`, `checkpoint_ref`,
`assignment_seed`, `assigned_audits_root`, and `audit_receipts_root`. The seed
hashes a canonical structured preimage containing the population root and the
first finalized checkpoint accepted by a source, network, finality rule, and
maximum-wait policy ratified before cutoff. The checkpoint must be unpredictable
and not authored by the reliability operator. This prevents the operator from choosing a favorable
sample after seeing outcomes. The
window is fixed and non-overlapping; there is no time decay or fractional
effective sample. Every assigned audit must have a terminal receipt. Missing,
timed-out, or integrity-invalid audit outcomes count as `incomplete` trials in
the buyer-facing denominator and as operator SLA failures, not as evidence of
seller fraud.

Each row publishes `{ corpus, seller, guarantee_class, correct, incorrect,
incomplete, n_assigned, r_bps, r_lcb_bps }`. `r_bps` is
`correct / n_assigned`; `r_lcb_bps` is the Wilson lower bound at the epoch's
published `confidence_bps`. Consumers key off the lower bound, never the point
estimate. A verifier can recompute the sample from the frozen population and
seed, prove every assignment against `assigned_audits_root`, prove every
terminal receipt against `audit_receipts_root`, and reproduce every row. The
statistic
feeds the `guarantee_class_bps` and the elicitation ceiling (MECHANISMS 2),
never a proof (K8): buyers weight it, they do not treat it as verification.

**Manipulation of `r` itself (catalog in THREAT-MODEL GA-series; summary):**

- Auditor-seller collusion (auditor always passes): for `deterministic_replay`,
  the audit is a mediated re-run whose receipt is independently checkable, so a
  colluding pass requires forging a mediated receipt, which is the S1 fabricated
  evidence attack, slashable. For `metered_attested` (non-replayable), the audit
  cannot mechanically verify, so `r` for that class is inherently weaker and
  carried as residual (section 9).
- Selective challenging (challengers cherry-pick winnable targets): `r` is
  computed over the committed, externally seeded assignment set, not over
  challenger-chosen challenges or an operator-selected completion subset.
- Audit-rate gaming (flood cheap findings to dilute per-finding audit
  probability): the audit rate is per-listing-class and the publication fee plus
  per-listing bond make flooding costly (S6); `n` is published so diluted (low-
  `n`) `r` values are visibly weak.

### 4.3 Operator mining (Q5): capped genesis seats, and what the surface actually supports

**Design input:** capped genesis operator seats per vertical (mediating kernel,
registry, status oracle) carrying a clearing-fee share, subject to the F6
neutrality requirement.

**Pressure test against the real surface (confidence: high).** The verification
found the surface supports much less than "operator seat carrying a fee share"
implies today:

- There is no per-request operator identity: a control-plane deployment
  authenticates with a single shared `service_token`
  (`chio-control-plane/src/trust_control/report_validation.rs:403`)
  and derives the operator identity server-side from config
  (`config.advertise_url`), so one deployment == one operator. There is no
  multi-operator seat table inside a control plane.
- There is no signed operator-roster-with-roles primitive. `validate_against_roster`
  takes a plaintext `&[String]` roster (`chio-market/src/claim.rs:409`), sourced
  from an UNSIGNED `RosterPolicy` config file
  (`chio-control-plane/src/trust_control/capital_and_liability/liability.rs:11`), and its
  `roster_anchor` points at a `chio-trust-market-context::AdjudicationJurisdictionReceipt`
  type that DOES exist but is crate-internal (`pub(super)`,
  `chio-trust-market-context/src/artifacts.rs:239`), so the anchor cannot be
  validated at its consumption site (correction of an earlier draft claim that
  the type was absent). The only roles that
  exist are registry-publishing roles `GenericRegistryPublisherRole { Origin,
  Mirror, Indexer }` (`chio-listing/src/listing.rs:51`).
- There is no capped-seat / genesis-slot primitive anywhere.
- Fee collection is declarative-only (K1), so a "share of clearing fees" has no
  collection plumbing to attach to yet.
- The escrow `operator` field (`EscrowTerms.operator` + `operatorKeyHash`,
  `contracts/src/interfaces/IChioEscrow.sol:7`) IS the F6 conflict surface: it
  names the release-authorizing party, with no neutrality flag or enforcement.

**Adopted design (honest about what is new).** The fourth signed artifact is a
NEW epoch-linked roster, `chio.genesis.operator-seat-roster.v1`, rather than an
individually signed seat. A local validator cannot prove a global cap from one
grant, but it can verify the complete roster. Each epoch binds the charter,
per-vertical caps, the full active/revoked seat set, `previous_roster_id`, issue
and expiry times, signer key, and inline signature. Each seat entry binds the
seat id, vertical, operator identity, fee share, neutrality and
change-of-control rules, state, and evidence references. Validation rejects
duplicate ids, duplicate active `(vertical, operator)` pairs, cap overflow,
invalid state transitions, and combined fee shares above the published carve
policy.

A seat earns on a clearing only when the clearing receipt references signed
service evidence for that exact `(vertical, operator_id)` and the entry was
active at clearing time. A clearing can name at most one paid operator for each
of the mediating-kernel, registry, status-oracle, and reliability-oracle
verticals. Merely holding a seat does not earn every market fee. The settlement
validator loads the royalty right, roster epoch, and referenced service
receipts, selects eligible entries, then enforces the transaction-level carve
cap. An individual royalty validator can enforce only its schedule ceiling; it
cannot prove the joint cap alone.

The roster is:

- signed by an authority authorized by the consortium governance charter
  (which already carries `allowed_listing_operator_ids`,
  `chio-open-market/src/fee_schedule.rs:32`); issuance, revocation, lapse, or
  expiry publishes the next monotone roster epoch;
- NON-transferable: the seat is bound to the operator identity and cannot be
  sold. A transferable seat carrying a fee share is a security-like transferable
  reward unit, which is exactly the token the hard constraint forbids. Seats are
  position (reward type c), and position does not trade. Because identity
  binding alone cannot prevent selling the ORG that holds the seat (review
  finding GA-R6), seat validity is conditioned on continuity of control:
  change of control LAPSES the seat unless the charter re-grants it, and the
  lapse trigger is named in the seat's rule refs alongside the neutrality
  revocation rule.
- revocable by a new signed roster epoch. An existing governance
  `Sanction`/`Freeze` decision can be evidence authorizing that transition, but
  it does not itself revoke an arbitrary seat. If the operator has an on-chain
  settlement key, `deactivateOperator`
  (`contracts/src/ChioIdentityRegistry.sol:89`) is a separate required side
  effect. Both receipts are referenced from the roster transition.

The fee share each active roster entry carries denominates in the D7 clearing fee and is
realized only once D7 lands (G5) on the M2/M5 collection machinery (K1). Until
then the seat is a signed claim on a declared split with zero live flow,
exactly like the royalty (Q2). The seat is thus a reputation-and-fee-
share POSITION with a neutrality covenant, which is what "operator mining"
reduces to on the real surface.

---

## 5. Q2: royalty plumbing (the make-or-break architecture question)

Can `chio-settle` and the fee surface carry forward-flowing fee splits at all?
Verified directly (confidence: high).

**What settle can move today:**

- A single-beneficiary full release: `prepare_dual_sign_release` is "bounded to
  full settlement" (`chio-settle/src/evm/prepare.rs:1049-1053`); `ChioEscrow`
  binds exactly one `beneficiary` per escrow
  (`contracts/src/interfaces/IChioEscrow.sol:7`), with terminal states
  `{released, refunded}` only.
- A multi-beneficiary exact-sum distribution, but ONLY on the one-shot bond-
  impair (slash) path: `bond_distribution_hash(beneficiaries, shares)` +
  `validate_bond_impair_distribution` require `sum(shares) == slash_amount`,
  at most `MAX_IMPAIR_BENEFICIARIES = 16`, non-zero addresses
  (`chio-settle/src/evm/prepare.rs:971-1020`;
  `contracts/src/ChioBondVault.sol:215-247`). It consumes evidence single-use
  and draws from one non-replenishable bond. It is not a recurring-payout
  engine.

**What settle cannot do today (the honest limit):** there is NO recurring,
forward-flowing, per-clearing-event fan-out to multiple beneficiaries on the
happy path, and NO pooled balance that pays later-discovered recipients (the
subsidy pool is net-new custody; every existing construct holds the poster's own
funds and pays parties named at open time). A royalty as a live on-chain revenue
stream does not exist and cannot be assembled from these parts without new
contract surface, which K7 forbids.

**The denominator has to be created first (review finding GA-R2c; the
category error this section originally contained).** The settled fee taxonomy
(MECHANISMS 6, `OpenMarketFeeScheduleArtifact`) contains publication, dispute,
and participation fees only; M2 collects the publication fee and M5 the
dispute fee, and NO per-clearing venue fee exists or is planned by any
finding-market milestone. A royalty defined as a share of "the clearing fee"
is therefore a claim on a category nothing collects. The program fixes this
honestly rather than by implication: ADR-0018 D7 INTRODUCES the clearing fee
through the ratified sibling `chio.registry.market-clearing-fee-schedule.v1`.
The existing market-fee schedule remains byte- and meaning-stable and implies
no D7 fee without the sibling. D7 is a small ad-valorem venue take on each
finding purchase, collected at reveal settlement by the mediating operator,
using the same metered/settled-charge machinery pattern M2 establishes for
the publication fee, with `operator_spread` as the operator-retained portion
and the remainder the splittable base. Its owning milestone is G5; the
finding-market owners must ratify it as an additive fee-schedule sibling, and until
it lands the royalty and seat shares denominate in a fee that does not exist
(zero live flow, as the register already required for other reasons).

The charge and split are integer minor-unit arithmetic, with checked
multiplication and floor division:

```
gross_fee       = floor(seller_price * clearing_fee_bps / 10_000)
buyer_total     = seller_price + gross_fee
operator_spread = floor(gross_fee * operator_spread_bps / 10_000)
splittable_base = gross_fee - operator_spread
royalty_leg     = floor(splittable_base * effective_royalty_bps / 10_000)
seat_leg_i      = floor(splittable_base * eligible_seat_bps_i / 10_000)
venue_residual  = splittable_base - royalty_leg - sum(seat_leg_i)
```

The seller principal is never haircut. `effective_royalty_bps +
sum(eligible_seat_bps_i)` must be at or below the carve policy cap; overflow,
currency mismatch, arithmetic overflow, stale schedules, or missing service
evidence fail closed. Floor-division dust remains in `venue_residual`, which
funds audits before becoming venue surplus.

**Minimal representation that respects the constraints (adopted):** the royalty
right is a **signed fee-split table bound at admission time**, applied by the
clearing operator at fee-collection time. Concretely:

- A `chio.genesis.royalty-right.v1` artifact (ADR-0018) binds the finding,
  venue and fee-schedule ids, beneficiary identity and settlement binding,
  settlement currency, an explicit time-keyed step-down schedule, carve policy,
  change-of-control rule, issuer, signer key, and expiry. It is signed by a key
  authorized by the venue governance charter. Keyed by
  `finding_id` ONLY (an earlier draft said "or descriptor"; a
  descriptor-keyed royalty would be a different economic object, a share of a
  whole topic's fees, and is not designed). It is a CLAIM on a fraction of
  the D7 clearing fee that future hits to that finding generate, not a
  transfer. Rights mint at EITHER genesis admission door (4.1): floor
  admission (deterministic_replay, full gate) mints floor plus royalty;
  royalty-only admission (descriptor match, mode-A burn, bond; no floor)
  mints the royalty alone, which is how a non-replayable finding
  participates without subsidized money it cannot audit-release. This royalty
  is ADDITIONAL to the seller's existing `price_per_call` sale revenue. It pays
  for the early contributor's coverage-bootstrap externality, not for the
  finding's ordinary per-hit value a second time.
- When the D7 fee exists (G5) and its collection machinery has landed (the
  M2/M5 pattern, K1), the operator collecting a clearing fee splits it per
  the royalty table before remitting the venue's residual, paying each
  royalty leg as a separately opened, ordinary receipt-backed
  single-beneficiary release. N royalty holders means N ordinary settlement
  legs in v1. A later batched payout may reuse the bond-distribution
  invariants (exact sum, non-zero recipients, bounded fan-out), but bond impair
  itself cannot move collected venue fees. A batch therefore needs a distinct
  fee-distribution action and may require an additive EVM router or contract
  entry point. That is still the existing settlement rail, but it is new
  contract surface and must be reviewed as such.
- **Forward-flowing only (K2):** the fee being split is a NEW fee on a NEW hit,
  never a clawback of the seller's already-settled revenue. Immediate-release
  settlement is untouched. This is why the royalty is compatible with the
  no-clawback posture: it never reaches backward.
- **Exact denominator:** every fee receipt binds gross D7 fee, operator spread,
  splittable base, currency, venue, fee-schedule revision, royalty schedule
  revision, and seat-roster epoch. Royalty plus seat shares may not exceed the
  published carve cap. Integer rounding dust goes deterministically to the
  venue residual; no participant can select a rounding order.
- **Step-down schedule:** reuse the shipped discount-table idiom
  (`TIER_DISCOUNT_PER_HUNDRED: [u32; 4]`,
  `chio-appraisal/src/marketplace_pricing.rs:148`), a small published array of
  basis-point steps keyed by elapsed genesis time, so the royalty share declines
  on a public schedule (section 6).
- **Transferability:** default NON-transferable, and this is load-bearing, not a
  preference. A transferable royalty right that pays a fee stream is a
  transferable financial reward unit, i.e. the token the hard constraint
  forbids; it would also drift toward a secondary market the consortium profile
  does not want. The right is bound to the issuer key and to the finding; it
  cannot be sold. Because "no transfer operation" cannot prevent selling the
  KEY or the ORG that holds it (review finding GA-R6), the right additionally
  carries a change-of-control condition: validity is conditioned on
  continuity of control of the beneficiary org, change of control LAPSES the
  right unless the granting charter re-grants it, and lapse-on-transfer is a
  named trigger alongside the revocation rule. Off-protocol side-contracts on
  the income stream remain unpreventable and are acknowledged: the operator
  pays only the bound beneficiary, so a side-buyer holds unsecured
  counterparty risk with no protocol recourse, which is deliberate hostility
  to a secondary market, the same device the Homestead Act used
  (anti-alienation conditions on un-proved claims, 8.4). If a future profile
  ever wants transfer, that is a separate ADR and a separate (token)
  conversation, explicitly out of scope here.
- **Dispute surface:** a royalty payout is an ordinary settlement leg, so it
  inherits the existing dispute window and the challenge/slash lane; a royalty
  paid on a finding later retracted (F5) simply stops accruing forward (no
  clawback of past legs, K2). Disputes over the SPLIT itself (did the operator
  apply the table correctly?) are checkable: the table is signed and the fee
  receipt is signed, so a mis-split is evidence-invalid and challengeable.

**Verdict on Q2:** the settle surface cannot carry a royalty as native recurring
value movement, and the settled fee taxonomy does not even contain the fee a
royalty would split; the program must first INTRODUCE the clearing fee (ADR-0018
D7, owning milestone G5) and can then carry the royalty as an operator-applied
split at collection time, gated on the M2/M5 collection machinery and on #974.
The representation that fits is a signed split table, keyed by finding id,
non-transferable with a change-of-control lapse, forward-only. This is recorded
as an honest limit in section 9 and drives the sequencing in Q7.

---

## 6. Decay schedule and reputation-as-difficulty (the land-grant clock)

**Published declining schedule (the land-grab clock).** Both the floor
`schedule(d)` and the effective royalty share step down on a published calendar,
and genesis seats/terms expire on a fixed date `T_g`. The schedule is
a small published array (the `TIER_DISCOUNT_PER_HUNDRED` idiom), so it is
auditable and non-discretionary. The economic purpose (prior art: Homestead Act
proving-up, section 8.4; declining emissions, section 8.1) is to convert the
cold-start into a time-boxed race: early coverage of demanded descriptors earns
the high floor and the high royalty step; late coverage earns less; after `T_g`
the subsidy is zero and the market is organic. The clock is what makes coverage
mining a land grab rather than a standing entitlement.

**Reputation as difficulty (early-adopter premium with natural decay).** No new
protocol action is required: reputation is already cheap to accumulate when the
book is thin (few sellers, receipts count for more relative to the corpus) and
expensive later (Tier-3 requires two distinct evidence feeds,
`chio-reputation/src/tier.rs:98-139`, and the corpus a newcomer must out-signal
grows over time). This is documented as the early-adopter premium: genesis
sellers accumulate coverage share and reputation tier cheaply during the thin-
book window, and that position has natural decay because the same reputation
becomes harder to earn as the corpus thickens. Position (reward type c) is thus
front-loaded by construction, with no emissions and no token; it is a
consequence of the existing scorecard math, not a new lever.

---

## 7. Q8: genesis liquidity and the CCV metric (self-dealing boundary)

**Seeding with our own swarms.** The program seeds the book by running our own
producer swarms against the procurement list, so demanded descriptors are
covered before organic sellers arrive. These are COMMISSIONED runs, not
near-zero-cost exhaust, and their verified production cost is an explicit
treasury line in section 9.1. The hazard is that self-produced
inventory, if bought by our own buyer swarms, is wash volume. The boundary:

- Genesis inventory we LIST and no one buys = coverage (inventory). It raises
  `h`, it is the point of the exercise, and it is NOT counted as CCV.
- Genesis inventory we LIST and an arm's-length EXTERNAL buyer buys = real CCV.
- Genesis inventory we LIST and WE buy = wash = excluded from CCV.

**Cleared Cognition Volume (CCV), wash-trade-resistant methodology (published
from day one):**

```
CCV[currency, window] = sum of gross finding purchase principal over all
                        arm's-length paid clearings in the reporting window.
```

CCV is volume, so its unit is the gross purchase principal, not venue revenue.
The report partitions by settlement currency and never silently converts or
adds currencies. Alongside CCV it reports `clearing_fee_revenue`,
`genesis_carve_payouts`, `external_clearings`, and
`unique_external_buyer_finding_pairs`. D7 is required for the two revenue
measures and live royalty flow, but gross CCV can exist as soon as paid
clearings exist.

- **No permanent deduplication.** Every arm's-length paid clearing in the
  window counts. Unique buyer-finding pairs are a separate adoption measure;
  collapsing repeat purchases would make the volume metric cease to be volume.
- **Related-party exclusion.** Trades within a related-party cluster are
  excluded using signed consortium organization/member identity plus disclosed
  common control, common funding, and operator relationships.
  `root_budget_holder` / `delegation_depth` are useful same-capability-root
  signals, not proof of beneficial ownership.
- **Fees do not make wash trading safe.** A controlled ring may recover venue,
  royalty, or seat portions of a fee; nothing here calls those transfers
  "burned." Related-party exclusion is the primary defense. Irrecoverable fees
  paid to independent parties are only a secondary cost signal.
- **Reproducible report boundary.** Each report pins methodology, window,
  currency, settlement-receipt root, relationship-snapshot root, included and
  excluded roots, and exclusion counts by reason. Unclassifiable relationships
  go to a separately reported `unclassified_volume`, never CCV. The report body
  is content-addressed and its root can be anchored through the existing
  `AnchorAutomationJob`; this does not add a fifth registered artifact family.
- CCV is a new metric: no `cleared_volume` / `CCV` / `market_volume` primitive
  exists in the repo today (verified: empty grep), so the methodology is
  defined here before any number is reported, which is the point.

**The scripted first agent-to-agent trade.** The first end-to-end trade (our
seller swarm lists a finding, our buyer swarm buys it, the delivery receipt and
settlement are public) is a verifiable, receipt-backed public event: anyone can
verify the finding signature, the delivery receipt's digest gate, and the
settlement leg. But it is self-dealing, so it is labeled explicitly as the
GENESIS DEMONSTRATION, not CCV. CCV begins counting at the first arm's-length
external clearing. Announcing the demonstration as a milestone while starting
CCV only at external trade is the honest way to have both a public first trade
and an untainted headline metric.

---

## 8. Prior art and external evidence

Survey run 2026-07-21 for the Genesis-specific questions (liquidity-mining
failure history, two-part tariff, land-grant/homesteading; the bug-bounty and
agent-commerce prior art is in MECHANISMS section 8 and is referenced, not
duplicated). Labels follow the MECHANISMS section-10 convention: [paper]
peer-reviewed, [preprint], [report] institutional/analyst, [vendor] company,
[pr] press/self-reported, [news] journalism, [tertiary] encyclopedic. Self-
reported and single-source figures are flagged inline.

### 8.1 Liquidity mining and the mercenary-capital failure (why not to pay for behavior)

- Liquidity mining reliably attracts capital that leaves when rewards stop.
  The best available measurement is Nansen's June 2021 on-chain study of
  MasterChef-style farms: 42 percent of addresses entering a farm on launch
  day exit within 24 hours, and roughly 70 percent are gone by day three
  [report; analyst measurement over on-chain data, single firm]. The SushiSwap
  "vampire attack" on Uniswap (August 2020) is the canonical land-grab: an
  aggressive per-block token emission (rewards reported up to ~1000 percent APR)
  drained a reported ~55 percent (~$810M) of a rival's liquidity in under two
  weeks, after which mercenary capital rotated onward [news/vendor, self-reported
  figures, FLAGGED]. The lesson this program takes: emissions that pay for the
  BEHAVIOR of showing up buy volume that evaporates in days. The Genesis floor
  pays for INVENTORY (a covered demanded descriptor, a durable asset), gated on burn
  and the sampled-audit admission gate, one floor per descriptor per coverage
  epoch; there is no per-participation or
  per-volume emission and no token to rotate. This is the hard-constraint-2
  discipline with a measured cautionary tale attached.

### 8.2 Two-part tariff (the floor-plus-royalty structure)

- Oi (1971), "A Disneyland Dilemma: Two-Part Tariffs for a Mickey Mouse
  Monopoly," QJE 85(1):77-96 [paper]. This is a structural analogy for a fixed
  payment plus use-contingent payment, not a literal mapping: Oi prices consumer
  access and use, while Genesis compensates suppliers. The seller already earns
  `price_per_call`; the additional royalty rewards the bootstrap externality.
  Procurement contracts, advance commitments, and revenue-sharing agreements
  are closer precedents for the actual supplier-side instrument.

### 8.3 Advance market commitments (the procurement list's closest precedent)

- The Advance Market Commitment literature proposed the mechanism; donors later
  committed $1.5B to the pneumococcal pilot, whose design and implementation
  work spanned the late 2000s. Under the mechanism, donors pledge a BOUNDED fund from which a
  specified per-unit subsidy is paid on delivered supply meeting a published
  specification, until the fund exhausts, with suppliers keeping a long-run
  per-unit revenue tail [paper/report; $1.5B pilot, launched 2007]. The
  structural mapping to the Genesis coverage mine is close but not exact:
  bounded pool =
  AMC fund; procurement-list entry = the published product specification;
  floor paid on gate-passed delivery (venue acceptance recipe, burn proof,
  sampled-audit window) = the per-unit subsidy on verified supply; royalty = the long-run tail; pool exhaustion = the AMC's designed
  end state. The closest faithful implementation also needs committed buyer
  demand, independent qualification, fiduciary custody, and explicit long-term
  obligations. Genesis currently proposes operator custody, unlike the pilot's
  independent financial administration, so that trust difference remains
  material. Two AMC design lessons adopted: pay on VERIFIED DELIVERY against
  a pre-published spec (never on effort or claims), and keep the demanded
  spec under the buyer coalition's control, not suppliers' (the pilot's
  target product profile), which is the Q3 anti-Goodhart governance rule.
  The pilot's choice to fund MULTIPLE suppliers rather than an exclusive
  winner (competition against supply interruption) is echoed in the ROYALTY
  layer, where every admitted supplier on a descriptor earns forward shares
  and listings coexist per K5; the FLOOR is per-unit-exclusive by budget
  necessity (one bounded subsidy per inventory unit), ordered by the settled
  anchored-commitment rule (4.1) rather than by any timestamp race.

### 8.4 Land grants, homesteading, and the railroad fraud (grant on verified output, and its failure mode)

- Homestead Act of 1862 [tertiary/report]. Free grants of up to 160 acres
  conditioned on "proving up": five years of residency plus IMPROVEMENT
  (cultivation), then a deed. Government histories record that many claimants
  did not remain long enough to fulfill the claim, but the cited sources do not
  establish a precise national abandonment count. Three lessons adopted directly: (1) grant on proof-of-improvement,
  not on claim-staking, which maps to the floor gated on mode-A proof-of-burn
  plus the venue acceptance recipe plus the sampled-audit window (you get paid
  for improving a demanded
  descriptor, not for filing a listing); (2) vest the durable reward on
  demonstrated use, which maps to the royalty vesting only on hits; (3) a public
  time-boxed clock (the genesis window `T_g`) with a real abandonment rate is
  expected and healthy, not a failure, because it prices the risk onto the
  claimant. A fourth lesson, adopted on review (GA-R6): the Act coupled its
  grants with anti-alienation conditions (un-proved claims could not simply be
  sold onward), which is the precedent for the change-of-control lapse on
  royalties and seats (sections 4.3 and 5). The abandonment statistic is the
  cautionary quantity: a program that grants without a proving-up requirement
  gets dead claims, which is the adverse-selection residual (section 9).
- Pacific Railway Act of 1862 and Credit Mobilier [tertiary/report]. The
  transcontinental subsidy was OUTPUT-VERIFIED (government bonds per completed
  mile of track, terrain-tiered at $16k/$32k/$48k per mile) and was still
  farmed: Union Pacific routed construction through Credit Mobilier, a
  RELATED-PARTY construction company its own promoters owned, paying it
  roughly $93.5M for work later estimated near $50M, extracting the subsidy
  through self-dealing prices rather than fake track. The lesson is the
  sharpest one in this survey: verifying the OUTPUT is not enough; the
  subsidy must also police WHO is on both sides of the priced transaction and
  what the claimed cost is. That is precisely why the Genesis design pairs
  its output gates with related-party clustering (GA2/GA8, shared
  `root_budget_holder` detection) and caps the floor by VERIFIED cost with
  `kappa < 1` rather than reimbursing claimed cost (GA1). Credit Mobilier is
  the Genesis program's canonical failure to design against.

### 8.5 Two-sided markets and the chicken-and-egg launch (which side to subsidize)

- Caillaud and Jullien (2003) analyze exactly this launch problem for
  intermediaries: with indirect network externalities, the equilibrium entry
  strategy is "divide and conquer", subsidize one side (possibly below cost)
  to recruit it, then monetize the other side once cross-side value exists
  [paper]. Rochet and Tirole (2003) generalize the price-structure result:
  platforms optimally skew pricing toward the side with the larger cross-side
  externality and the more elastic participation [paper]. The Genesis mapping
  is direct: coverage is the subsidized side because it creates served-query
  capacity and transaction opportunities (section 3.3), while clearing is the
  monetized side. The
  divide-and-conquer literature also carries the program's discipline
  warning: the subsidy must END (the genesis clock `T_g`), because a platform
  that never flips to monetization is the zombie regime (9.1).

### 8.6 References

All URLs retrieved 2026-07-21.

1. [paper] Oi, W. "A Disneyland Dilemma: Two-Part Tariffs for a Mickey Mouse
   Monopoly." Quarterly Journal of Economics 85(1), 1971.
   https://academic.oup.com/qje/article-abstract/85/1/77/1861193
2. [tertiary] Homestead Act (1862), overview and proving-up requirements.
   https://www.nps.gov/articles/the-homestead-act.htm ;
   https://www.archives.gov/education/lessons/homestead-act
3. [report] Nansen. "All Hail MasterChef: Analysing Yield Farming Activity."
   June 2021 (42 percent day-one exit within 24h; ~70 percent by day three).
   Archived 2021-06-18 because the live route no longer serves the report:
   https://web.archive.org/web/20210618041016/https://www.nansen.ai/research/all-hail-masterchef-analysing-yield-farming-activity
4. [news] SushiSwap vampire attack, mechanics and liquidity-migration figures
   (self-reported/analyst, FLAGGED). https://finematics.com/vampire-attack-sushiswap-explained/
5. [paper] Kremer, Levin, Snyder. "Advance Market Commitments: Insights from
   Theory and Experience." AEA Papers and Proceedings, 2020 (NBER w26775).
   https://www.nber.org/papers/w26775
6. [paper] Kremer, Levin, Snyder. "Designing Advance Market Commitments for
   New Vaccines." Management Science, 2021 (NBER w28168).
   https://www.nber.org/papers/w28168
7. [tertiary/report] Pacific Railway Act (1862): per-mile subsidy structure.
   https://www.archives.gov/milestone-documents/pacific-railway-act ;
   Credit Mobilier payments vs estimated cost: Gilder Lehrman Institute,
   "Financing the Transcontinental Railroad."
   https://www.gilderlehrman.org/history-resources/essays/financing-transcontinental-railroad
8. [paper] Caillaud, B., Jullien, B. "Chicken & Egg: Competition among
   Intermediation Service Providers." RAND Journal of Economics 34(2), 2003,
   309-328. https://econpapers.repec.org/RePEc:rje:randje:v:34:y:2003:i:2:p:309-28
9. [paper] Rochet, J.-C., Tirole, J. "Platform Competition in Two-Sided
   Markets." Journal of the European Economic Association 1(4), 2003,
   990-1029. https://academic.oup.com/jeea/article-abstract/1/4/990/2280902
10. Bug-bounty economics, agent-payment rails, credence-goods markets, peer-
    prediction, and data-market prior art: see MECHANISMS section 10 (items
    8-45), referenced here rather than duplicated. The load-bearing ones for the
   Genesis program are Gao-Wright-Leyton-Brown (limited-ground-truth audits
   dominate, item 18), Walshe-Simpson bug-bounty triage economics (item 29), and
   Erlei-Meub (bonds load-bearing for agent credence goods, item 44).

Novelty note (bounded, honest): the combination this program adds on top of the
#1025 novelty claim is "cold-start bootstrap of a verified-cognition market by
inventory-and-security subsidy without a token, on a bounded treasury, consortium-
first." The components (liquidity-mining land grabs, two-part tariffs, homestead
proving-up, bonded bug bounties) are all well-precedented individually; the
absence-of-evidence claim is only about the specific combination applied to a
bonded verified-cognition market, and is bounded by the 2026-07-21 survey date.

---

## 9. Honest limits (mandatory sections)

### 9.1 The exhaustion boundary (Q1): three regimes, and which cost actually drives it

Modeled as a monthly recurrence (every parameter a labeled modeling
assumption; the value of the model is the STRUCTURE of the boundary, not the
numbers). State: demanded-uncovered descriptors `U(t)`, covered live corpus
`C(t)`, pool balance `B(t)`. Flows: demand inflow `lambda_d`; staleness `mu` on
`C`; queries `q(t) = query_capacity * logistic((t - t_d)/s_d)` (a ramp delayed by
`t_d`); cleared seller-principal volume
`X = q * (C/(C+U)) * p_clear`; ad-valorem venue fee fraction `f`;
seller price `~4f`. Supply has two distinct modes: HARVEST admits pre-existing
exhaust, whose production cost is sunk; COMMISSIONED runs new work against the
procurement list, whose verified production cost is a treasury expense. Let
`rho_h` be the harvested share and `c_g` the commissioned production cost per
admission. Genesis capacity is `cap_g` while the pool is solvent; organic
listings respond to lifetime value versus listing cost. Spend is floors
`admissions * b0 * decay^t`, commissioned production
`admissions * (1 - rho_h) * c_g`, and audits
`(alpha_new * admissions + alpha_corpus * C) * c_a`, where `alpha_corpus` is
the PUBLISHED-RATE STANDING SURVEILLANCE of the live corpus (MECHANISMS 5
audits listed findings, not only new admissions); fee inflow funds audits
first, the pool tops up the shortfall, and floors always come from the pool.
Consistency notes: `f` is the D7 clearing fee (a genesis-introduced category,
section 5; a modeling parameter until G5 lands), the fee available for audits
is net of the genesis carve-out (conclusion 2), and the floor line charges
EVERY admission because floors release by default at window end (4.1); only
the sampled `alpha_new` fraction incurs audit cost, so mechanism and model
agree. The pool recurrence is:

```
B(t+1) = B(t)
       - floor_spend(t)
       - commissioned_production_spend(t)
       - max(audit_spend(t) - spread_and_carve_net_fee_inflow(t), 0)
```

The executable model deliberately replaces the unknown response functions with
explicit per-month assumptions for genesis admissions, organic admissions,
demanded-descriptor inflow, and paid clearings. It declares self-sustain only
after both takeover inequalities hold for `sustain_months` consecutive periods;
organic admissions are included in the new-audit bill. This keeps the model
honest until measured response curves exist.

The recurrence admits THREE regimes, not two:

- **SELF-SUSTAIN**: organic supply covers demand inflow (`a_o >= lambda_d`)
  AND spread-and-carve-net fees cover the security bill
  (`(1 - o) * (1 - carve) * f * X >=
  (alpha_new * a + alpha_corpus * C) * c_a`, conclusion 2), sustained. The
  program exits.
- **EXHAUST**: `B(t)` hits the month's committed spend before self-sustain.
- **ZOMBIE**: the pool survives the horizon but organic supply and fees never
  take over; coverage is high, the market is permanently subsidy-dependent.
  The exit criterion is organic takeover, NOT pool solvency.

The earlier precise 36-month scenario table is removed because the prose
recurrence did not define its organic-supply response, logistic width, scenario
overrides, or initial conditions, and it omitted commissioned production. It
was not reproducible evidence. The minimal executable recurrence now lives at
[`models/genesis_runway.py`](models/genesis_runway.py) with every assumption in
one immutable input record and explicit harvest, commissioned, fee-offset,
organic-takeover, exhaustion, and zombie paths. It is a structural sensitivity
tool, not a forecast. No pool amount or default carve cap is approved until its
inputs are replaced with owned estimates. This is a parameterization gate, not
a gate on building the mechanisms.

Three structural conclusions, which survive parameter variation and are the
actual content of this section:

1. **The floor is self-bounding by schedule construction.** With a geometric
   step-down, worst-case cumulative floor outlay is bounded by
   `b0 * admission_capacity / (1 - decay)` for a fixed per-period admission
   capacity. The declining schedule is a hard cap on floor exposure. It does
   not bound commissioned production or standing surveillance.
2. **Standing audit and commissioned-production costs are the tail risks.**
   The audit line scales with the program's own success, and commissioned work
   is not exhaust. `alpha_corpus * C * c_a` grows with the covered corpus the
   program builds. Self-sustain therefore requires the
   SECURITY-SELF-FUNDING INEQUALITY
   `(1 - o) * (1 - carve) * f * X >= (alpha_new * a + alpha_corpus * C) * c_a`,
   where `o` is operator spread and `carve` is the combined genesis carve-out
   (royalty plus seat shares of the same fee; review finding GA-R3, which
   caught the gross-fee double count). That inequality, together with the
   commissioned-production line, sizes the pool, fee, and carve cap jointly.
   The current 25 percent value is a modeling ceiling to test, not an approved
   default. The corpus audit rate must be tunable downward as per-class
   reliability data accumulates, or the fee must price it.
3. **The zombie regime is a real failure the two-outcome framing misses.** A
   pool that survives while nothing organic happens is not success; it is
   subsidy-dependence. The stop-loss gates and indicator 3 below exist for it.

No dollar pool range is decision-grade yet. Harvest-mode pricing may treat
production as sunk; commissioned mode may not. Funding approval requires the
executable model to report both modes and sensitivity across `rho_h`, `c_g`,
audit cost, carve, demand arrival, and organic-supply response.

Leading indicators (observable from receipts and telemetry; alarm thresholds
are modeling assumptions to be tuned on data). ALL indicators compute over the
arm's-length receipt set (related-party-excluded, section 7);
unfiltered variants are gameable by exactly the wash trades the stop-loss
exists to catch (review finding GA-R7):

1. Hit-conversion of subsidized findings = (subsidized findings that ever clear)
   / (subsidized findings admitted). Alarm if below ~10 to 20 percent after a 4
   to 8 week warm-up: the pool is buying dead inventory.
2. Coverage-to-CCV elasticity dCCV/dg. Alarm if coverage-of-demand `g` rises
   while CCV stays flat: coverage is not converting to demand; the per-hit bid
   is not clearing.
3. Organic listing share = (unsubsidized admitted) / (total admitted). Alarm if
   flat or declining: the market is not becoming self-sustaining. This is the
   ZOMBIE-regime detector: high coverage with a flat organic share is
   subsidy-dependence, not success.
4. Conversion efficiency eta = (organic clearing-fee inflow) / (pool floor
   outflow). Alarm if eta stays near 0 while `B/B0` falls below a runway
   threshold: runway is burning without conversion.
5. Repeat-buyer rate (distinct returning buyer clusters). Alarm if one-and-done
   buyers dominate: the modeled per-hit value is not producing repeat demand.
6. Runway months = `B(t)` / current outflow. Cross-reference against the `T(g*)`
   estimate; alarm if runway < estimated time-to-self-sustaining.
7. Security-self-funding ratio = (fee inflow) / (total audit spend at the
   published rates). Alarm while below 1 with the corpus still growing: the
   standing audit bill (the actual exhaustion driver, conclusion 2 above) is
   uncovered, and either the corpus audit rate must step down on reliability
   evidence or the participation fee must rise.

The boundary is real and the program can hit it. The mitigation is not a
guarantee of success; it is early detection plus stop-loss (GENESIS-PLAN gates
every mine independently so a failing mine can be halted without unwinding the
others).

### 9.2 The adverse-selection residual (Q6)

The exhaust that seeds the book is biased. The coding wedge is chosen precisely
because its correctness is replay-checkable. The R&D-null exhaust is the
residual: its `B_hit` is often negative (section 3.2), and proof-of-burn proves
cost rather than semantic value. This is documented, not hand-waved. The
program implements R&D-null procurement, listing, royalty-only admission,
guarantee-class separation, and reliability reporting from the start. It does
not pay the treasury floor until the configured guarantee profile has an
adjudicable correctness rule; doing so earlier would violate the floor's own
security invariant. The procurement list remains the relevance defense, but it
cannot distinguish durable demand from an outlier nomination. Abandonment is
therefore expected and residual adverse selection remains in the register.

### 9.3 The r-manipulation residual (Q4)

`r` for `deterministic_replay` is well-defended (audits are re-runs whose
receipts are checkable; collusion reduces to slashable fabrication). `r` for
`metered_attested` (the R&D-null class) is NOT mechanically verifiable: an audit
cannot re-check a non-replayable claim, so `r` there rests on the metering floor
and reputation, both of which an honest-cost fabricator defeats (THREAT-MODEL
S2). Consequently the r feed must publish `r` STRATIFIED by guarantee class and
must never let a `metered_attested` `r` masquerade as `deterministic_replay`
reliability (K6). Buyers weighting `r` for a `metered_attested` finding are
weighting a softer signal, and the guarantee-class discount (MECHANISMS 2) is
their self-insurance. The residual is the same one #1025 already carries; the r
feed does not remove it, it makes it legible.

### 9.4 What Q2 reveals the settle surface cannot carry

Recorded in full in section 5: the settle surface cannot carry a royalty as
native recurring value movement (single-beneficiary release; one-shot slash-only
multi-party split; no pooled balance for later-discovered recipients; no fee-
split or royalty primitive of any kind, confirmed by grep; and no per-clearing
fee CATEGORY in the settled taxonomy for a royalty to split, the D7 gap). The
royalty works only as an operator-applied split at fee-collection time, which
(a) does not exist until the D7 clearing fee is introduced (G5) on the M2/M5
collection machinery, and (b) trusts the operator to apply the signed table
correctly (mitigated: the table and the fee receipt are both signed, so a
mis-split is challengeable, but the trust is real and is an F6-neutrality
dependency, K3). The subsidy pool itself is net-new off-chain operator-custodied
custody (no treasury/pool primitive exists), and the ADR-0015 D4 recipient
allowlist that would constrain where pool and slash money goes is prose, not
code (K1/K10 gap). None of these is fatal; all are honest limits that shape the
sequencing (Q7) and the threat model.

### 9.5 Anti-token is an architecture boundary, not a legal conclusion

Binding royalties and seats to identities, forbidding protocol transfer, and
omitting a secondary market are deliberate product constraints. They do not by
themselves determine whether a fee-bearing right is a security, compensation,
property, a taxable instrument, or a regulated revenue-sharing arrangement.
Change-of-control and off-protocol side contracts make that especially clear.
Before any external grant, counsel and accounting owners must approve the
instrument, disclosures, tax treatment, custody, and jurisdictional launch
profile. The protocol design must not market "non-transferable" as a legal safe
harbor.

---

## 10. Summary: what the protocol pays for, from what pool, on what schedule

- **Coverage mining** pays a small **floor** (from the bounded, off-chain,
  operator-custodied **subsidy pool**, settlement numeraire) per covered
  demanded descriptor per coverage epoch, gated on the venue-authored
  acceptance recipe plus mode-A proof-of-burn plus an audit-verifiable
  guarantee class (`deterministic_replay` at launch), escrowed on the existing
  two-terminal-state escrow (release by default at the audit-window end; a
  sampled incorrect audit refunds to the pool; system-incomplete releases at
  deadline and fires the operator SLA), ordered by anchored commitment
  on contested descriptors, on a **published declining schedule** expiring at
  `T_g`; plus a **royalty** (reward type b, from the **D7 clearing fee** in the
  ratified market-clearing-fee schedule, never the pool),
  non-transferable with a change-of-control lapse, forward-only, stepping
  down on schedule, minted at either admission door (floor or royalty-only).
- **Audit mining** pays **slashed bonds plus protocol bounties** (pool top-up
  for subsidized findings), and its output is the signed **reliability epoch**
  (`r`) that buyer pricing consumes.
- **Operator mining** grants **capped, non-transferable genesis seats** (reward
  type c) carrying a **D7 clearing-fee share** (realized only once D7 lands at
  G5 on the M2/M5 collection machinery), bound to the F6 neutrality covenant,
  lapsing on change of control, and revocable on violation. A seat earns only
  when the clearing references that operator's signed service evidence.

Every subsidy unit becomes inventory (a covered demanded descriptor) or security
(an audit that establishes `r`), never rented behavior: the floor is per-
descriptor and burn-gated, the royalty is value-gated (hits only), the audit is
security, the seat is position. Where the program fails is the exhaustion
boundary (9.1); the leading indicators (9.1) are the instrument panel. The first
executable mine is coverage mining's floor path, gated on the cognition-market
milestones it depends on (Q7, [GENESIS-PLAN.md](GENESIS-PLAN.md)).

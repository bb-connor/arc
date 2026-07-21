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
| K1 | Fee collection is declarative today; real collection is M2 (publication fee) and M5 (dispute fee). Nothing charges a fee at runtime, and the shipped fee taxonomy contains NO per-clearing venue fee. | MECHANISMS 6; re-verified: `chio-open-market/src/fee_schedule.rs:79-81` fees are validated + echoed only (`evaluation.rs:468-470`), never charged | The royalty/seat denominator (a per-clearing fee) is NOT an M2/M5 fee: it is a genesis-INTRODUCED category (ADR-0018 D7) whose collection reuses the M2/M5 machinery pattern and lands at G5; royalties accrue against a declared split table with zero live flow until then (Q2) |
| K2 | v1 settlement has NO revenue clawback: release and reconcile are immediate; bonds are sized to finalized fraud exposure over a published detection horizon. | MECHANISMS 4; `chio-settle` releases on proof, `dispute_window_secs` observes but does not custody (`config.rs:122`) | Royalties are FORWARD-flowing only (paid from future clearing fees, never reaching back into settled trades); the pool never claws back a paid floor (Q2) |
| K3 | Cross-org escrow REQUIRES a neutral mediating operator; with a seller-aligned mediator, paid non-delivery (attest-and-withhold) is HIGH residual. | ARCHITECTURE F6; THREAT-MODEL O5/S7 | Operator seats (Q5) bind the F6 neutrality obligation as a seat condition; a neutrality violation is a seat-revocation trigger |
| K4 | `evidence_cost` is verifiable only in full-receipt mode (mode A); projected-mode values are seller assertions until audit. Money must never gate on unverifiable cost. | MECHANISMS 1; ARCHITECTURE 4.1, F2 | The bounty floor (Q1) is gated on mode-A proof-of-burn; a mode-B `evidence_cost` gates NOTHING and earns no floor until audited |
| K5 | No exclusive first-commit listing slots; duplicate-context findings coexist with informational anchored-commitment ordering; nobody is paid for duplication. | MECHANISMS 3 | Coverage mining pays at most one floor per demanded descriptor (an inventory unit), never per listing; duplicates earn neither floor nor a second royalty stream (Q1, Q6) |
| K6 | Challenge exposure is bounded by the finding's advertised guarantee class. | ADR-0017 D3/D4 | Audit mining (Q4) audits within the guarantee class; the r statistic is stratified BY guarantee class so a class's reliability is never averaged across classes |
| K7 | Reveal is a governed tool call; delivery-vs-payment is the kernel digest gate. No new settlement rail, escrow contract, or atomic swap. | ADR-0017 D2; ARCHITECTURE 6 | Genesis adds no settlement rail; the royalty is an operator-applied split at fee-collection time on the existing release path, not a new value-movement contract (Q2) |
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

Cold start is a coverage fixed point. Buyer willingness-to-pay per query is
increasing in coverage; coverage requires sellers; sellers require paying
buyers. The pricing context the brief supplies (treated as design input,
re-derived in section 3) makes the dependency explicit:

```
P_max(query) = h * [ (C + W) - (1 - r) * (V - dB) ]
```

- `h` = coverage = probability the book contains a finding matching the query
- `r` = hit reliability = probability a matched finding is correct/useful
- `C` = re-derivation cost (buyer's outside option: solve it yourself)
- `W` = redeployed-budget value (value of the compute/time freed by not
  re-deriving)
- `V` = decision stakes (what the finding informs)
- `dB` = expected bond recovery if the finding is wrong

When `h = 0` the ceiling is `0`: there is literally nothing to buy, so no
price clears, so no seller earns, so `h` stays `0`. The program's whole job is
to move the system off `h = 0` on the descriptors buyers actually query,
cheaply enough and fast enough that organic clearing takes over before a
bounded pool is exhausted.

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

## 3. Pricing model: re-deriving the ceiling and the demand-curve claim

Confidence: the algebra is high; the parameter magnitudes are labeled modeling
assumptions with ranges.

### 3.1 The ceiling survives re-derivation, with one modeling choice named

Derive `P_max` as a buyer's per-query expected ceiling. A buyer facing a
decision with stakes `V` has a reliable outside option: re-derive at cost `C`,
which also frees no budget (you spent it) so the redeployed value `W` is
foregone. Buying instead:

- With probability `h` a matching finding exists (else the decision proceeds
  without a purchase, contributing nothing to willingness-to-pay).
- Given a hit, with probability `r` the finding is correct: the buyer saves
  the re-derivation cost `C` and gains redeployed-budget value `W`. Benefit
  relative to re-deriving: `(C + W)`.
- Given a hit, with probability `(1 - r)` the finding is wrong: the buyer acts
  on wrong information, incurs decision damage up to `V`, recovers `dB` from
  the bond. Net loss relative to a reliable answer: `(V - dB)`.

Taking the expectation over correctness and scaling by coverage yields exactly
the input form `P_max = h[(C + W) - (1 - r)(V - dB)]`. The one modeling choice
worth naming: this form credits the buyer with `(C + W)` on every hit, not
`r(C + W)`. That is defensible (you pay to avoid the work regardless of whether
the answer later proves wrong; the wrongness shows up separately in the
`(1 - r)(V - dB)` penalty), and the `r`-scaled variant
`P_max = h[r(C + W) - (1 - r)(V - dB)]` is the sensitivity case: at the wedge
midpoints used in 3.2 it moves the ceiling from $14.20 to $13.90 (about 2
percent, immaterial), and for the unpinned R&D null it deepens an already
negative ceiling ($-75 to $-85.50). Both forms agree on every qualitative
conclusion in this section, so the choice of form is not load-bearing.

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
the midpoints, against `C + W ~= $15`, so `P_max ~= h * $14.2`. With coverage
`h ~= 1` on the exact context, the wedge clears at any seller ask below ~$14
against near-zero marginal delivery cost. The wedge works.

Modeling assumptions (R&D null, "this experiment shows no effect",
`metered_attested`, not replay-checkable):

- `r`: 0.5 to 0.8 (no mechanical re-check; the honest-cost-fabrication residual
  is real, THREAT-MODEL S2).
- `V`: large (avoiding a dead end is high-stakes) and `dB` small (a bond cannot
  cover semantic wrongness), so `(V - dB) ~= V`.

Then the penalty `(1 - r) * V` can approach or exceed `(C + W)`, driving
`P_max` toward or below zero: for `r = 0.65`, `V = $300`, `C + W = $30`,
penalty `= 0.35 * 300 = $105 >> $30`, so `P_max < 0` and no rational buyer
purchases. This is the adverse-selection-on-exhaust residual (section 9),
falling straight out of the model: the R&D null is structurally the hard case,
which is why the wedge (verified fixes and failing-test findings for major OSS
ecosystems, plus ML non-convergence sweeps ONLY where the recipe is pinned
deterministic; the launch determinism rule in 4.1 makes this a floor-admission
condition, not an aspiration) launches first. The program does not solve
R&D-null pricing; it sequences around it.

### 3.3 The demand-curve-investment claim, pressure-tested and corrected

Pooled coverage composes as `h_pool = 1 - Prod_i (1 - h_i)`. In the wedge's
exact-context regime (`descriptor.context_sha256` equality,
ARCHITECTURE 4.1), a finding matches its exact descriptor with `h_i ~= 1` and
nothing else, so for a query on descriptor `d`, `h_pool(d) = 1` if any admitted
finding covers `d`, else `0`. Aggregate coverage `h` is then the query-weighted
mass of covered descriptors ("covered demand mass").

The brief's claim: "every subsidized finding raises `h`, which raises every
buyer's ceiling across the whole book; subsidy is demand-curve investment, not
marketing spend." Modeled precisely, the claim is TRUE with a sharp boundary:

- Subsidizing the FIRST finding on a demanded, currently-uncovered descriptor
  `d` flips `h_pool(d)` from 0 to 1, moving `P_max` on every query to `d` from
  `0` (nothing to buy) to the positive ceiling. This is not moving down an
  existing demand curve (marketing); it is bringing the demand curve on `d`
  into existence. Demand-curve investment, exactly as claimed. (Scope
  condition, review finding GA-R10: the `h`-scaled ceiling is an EX-ANTE
  per-query quantity, correct in the launch regime where exact-context
  matching makes `h(d)` an indicator in {0, 1}; a buyer that has already
  inspected a confirmed descriptor match must not discount its bid by `h`.
  Fractional `h` applies only to aggregate demand mass, never to an
  inspected match.)
- Subsidizing a SECOND finding on an already-covered `d` adds `h_i` to a
  saturated `h_pool(d) ~= 1`: near-zero coverage gain, near-zero
  demand-curve investment. Pure waste (duplication).
- Subsidizing any finding on an UN-demanded `d` (no query mass) yields coverage
  with zero realized `P_max * query_mass`: dead inventory. Also waste (adverse
  selection on exhaust).

So the input claim is false AS STATED ("every subsidized finding") and true in
its corrected form ("every subsidized finding ON A DEMANDED, UNCOVERED
DESCRIPTOR"). The correction is not a footnote; it is the reason two mechanism
rules exist:

- The **procurement list** (Q3) gates admission to demanded descriptors, so the
  pool cannot fund dead inventory.
- **No-duplication-payout** (K5, MECHANISMS 3) denies a floor to the second
  finding on a covered descriptor, so the pool cannot fund duplication.

These two rules are precisely what make "subsidy is demand-curve investment"
true rather than aspirational. The program buys covered demand mass, and only
covered demand mass.

---

## 4. The three mines (design, each pressure-tested against the input)

### 4.1 Coverage mining (Q1): two-part tariff, floor gated on burn, royalty on value

**Design input:** sellers list bonded findings against a published procurement
list; a two-part tariff pays a small bounty floor at listing (gated on mode-A
proof-of-burn, descriptor match, audit sampling) plus a royalty share on future
query hits.

**Pressure test and adopted design.** The two-part tariff is the correct shape
(prior art: Oi 1971, section 8.2). The floor is the lump-sum access fee; the
royalty is the per-use charge. But two input details break against the
constraints and are redesigned:

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

2. **The floor is per covered demanded descriptor, not per listing.** One floor
   per descriptor, ever (K5). This is the "buys inventory, not volume"
   guarantee made mechanical: you cannot farm floors by listing many findings,
   because only demanded-uncovered descriptors admit a floor and each admits at
   most one.

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
  sampled audit that FAILS blocks release (deadline refund to the pool) and
  feeds the slash lane. Release-by-default is deliberate (review finding
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
FAILS means the operator signs nothing and the deadline refund returns the
floor to the pool. Two predeclared price-free terminal states, unchanged
(ADR-0015 D2). The trust residual (an operator that withholds a due release
signature) is T5, receipt-visible. In the non-EVM consortium profile the same
contract shape runs as a settle-mediated hold; the mapping, not the chain, is
the design.

The royalty is reward type (b) and is designed in Q2. It pays for value: a
finding that gets hits earns a share of the clearing fees those hits generate;
junk gets no hits, so junk earns no royalty. The royalty is self-funded from
real clearing fees, never from the pool, which is the wash-trade defense
(Q6/C1): to fake royalty income you would have to pay real clearing fees to
yourself.

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
  randomized schedule (seeded from the epoch-root randomness the cron
  cadence already produces, K9); a voluntary self-selected challenger gets
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
  `(1 - carve) * f * X >= (alpha_new * a + alpha_corpus * C) * c_a`, where
  `carve` is the combined genesis carve-out (royalty `share_bps` plus seat
  `fee_share_bps`) on the same fee (review finding GA-R3: during genesis
  nearly every clearing is a hit on subsidized inventory, so nearly all of
  `f * X` carries splits; counting the gross fee double-counts the same
  dollar). The program therefore publishes a combined genesis carve-out CAP:
  modeling the base scenario, self-sustain slips from month 13 to 15 to 18 as
  `carve` rises 0 to 15 to 25 percent and degrades to the zombie regime at 40
  percent (9.1), so the cap defaults to 25 percent and the royalty and seat
  schedules must fit under it jointly. Audit-rate schedules
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

- **What the r feed DOES reuse (confidence: high).** Two shipped primitives:
  (1) `chio-reputation` already computes a time-decayed reliability rate over
  integrity-gated receipts: `ReliabilityMetrics { completion_rate,
  cancellation_rate, incompletion_rate, receipts_observed }`
  (`chio-reputation/src/model.rs:250-257`) via `compute_reliability`
  (`src/compare.rs:160-212`), where `completion_rate = allow_weight / total`
  over receipts whose kernel key is in a trusted set. (2)
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

**How `r` is computed, attested, published (design):** `r(corpus, seller,
class) = correct_audits / total_audits` over a published window, time-decayed
like `compute_reliability`, computed only over integrity-gated audit receipts
(the audit is a mediated re-run; its receipt is checkable exactly as claim
evidence is, `chio-market/src/insurance_flow.rs:390-414`). Each epoch publishes
`(r, n, window, class)` rows: `n` (sample size) is mandatory so a small-sample
`r` is discounted by buyers, which defuses audit-rate gaming. The statistic
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
  computed over VENUE-SCHEDULED RANDOM AUDITS, not over challenger-chosen
  challenges, so selection is controlled by the random schedule, not by
  challengers.
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

**Adopted design (honest about what is new).** An operator seat is therefore a
NEW signed artifact (`chio.genesis.operator-seat.v1`, ADR-0018), not a reuse.
It is:

- a signed grant from the consortium governance charter (which already carries
  `allowed_listing_operator_ids`, `chio-open-market/src/fee_schedule.rs:32`, and
  is `SignedGenericGovernanceCharter`), binding: the vertical
  (`mediating_kernel` / `registry` / `status_oracle` / `reliability_oracle`),
  the operator identity, a fee-share basis-points entry, the F6 neutrality
  obligation, and an expiry (the genesis clock);
- capped by the charter: the cap is a governance parameter (a published integer
  per vertical), enforced at seat-issue time by the charter's issuer, not a new
  on-chain slot machine. This is the minimal representation that is not a token
  (see below);
- NON-transferable: the seat is bound to the operator identity and cannot be
  sold. A transferable seat carrying a fee share is a security-like transferable
  reward unit, which is exactly the token the hard constraint forbids. Seats are
  position (reward type c), and position does not trade. Because identity
  binding alone cannot prevent selling the ORG that holds the seat (review
  finding GA-R6), seat validity is conditioned on continuity of control:
  change of control LAPSES the seat unless the charter re-grants it, and the
  lapse trigger is named in the seat's rule refs alongside the neutrality
  revocation rule.
- revocable on neutrality violation through the EXISTING levers: a governance
  `Sanction`/`Freeze` case (`chio-governance/src/generic.rs:20`,
  `evaluation.rs:304-317`) against the seat, and, for the on-chain settlement
  key, admin `deactivateOperator` (`contracts/src/ChioIdentityRegistry.sol:89`).
  The seat artifact names the decision rule that fires revocation, so revocation
  is predeclared, not discretionary.

The fee share the seat carries is realized only once fee collection exists
(K1, M2/M5). Until then the seat is a signed claim on a declared split with zero
live flow, exactly like the royalty (Q2). The seat is thus a reputation-and-fee-
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
as a new, genesis-owned fee category (a small ad-valorem venue take on each
finding purchase, collected at reveal settlement by the mediating operator,
using the same metered/settled-charge machinery pattern M2 establishes for
the publication fee), with `operator_spread` as the operator-retained portion
and the remainder the splittable base. Its owning milestone is G5; the
finding-market owners must ratify it as a fee-schedule extension, and until
it lands the royalty and seat shares denominate in a fee that does not exist
(zero live flow, as the register already required for other reasons).

**Minimal representation that respects the constraints (adopted):** the royalty
right is a **signed fee-split table bound at admission time**, applied by the
clearing operator at fee-collection time. Concretely:

- A `chio.genesis.royalty-right.v1` artifact (ADR-0018) binds
  `{ finding_id, beneficiary (issuer key), share_bps, schedule (step-down),
  expiry }`, signed by the venue governance charter that granted it. Keyed by
  `finding_id` ONLY (an earlier draft said "or descriptor"; a
  descriptor-keyed royalty would be a different economic object, a share of a
  whole topic's fees, and is not designed). It is a CLAIM on a fraction of
  the D7 clearing fee that future hits to that finding generate, not a
  transfer. Rights mint at EITHER genesis admission door (4.1): floor
  admission (deterministic_replay, full gate) mints floor plus royalty;
  royalty-only admission (descriptor match, mode-A burn, bond; no floor)
  mints the royalty alone, which is how a non-replayable finding
  participates without subsidized money it cannot audit-release.
- When the D7 fee exists (G5) and its collection machinery has landed (the
  M2/M5 pattern, K1), the operator collecting a clearing fee splits it per
  the royalty table before remitting the venue's residual, paying each
  royalty leg as an ordinary receipt-backed transfer on the existing
  single-beneficiary release path. N royalty holders = N ordinary transfers,
  or a batched epoch settlement using the existing exact-sum distribution
  shape generalized beyond impair (a G6-gated settle extension,
  GENESIS-PLAN). Either way, no new value-movement contract.
- **Forward-flowing only (K2):** the fee being split is a NEW fee on a NEW hit,
  never a clawback of the seller's already-settled revenue. Immediate-release
  settlement is untouched. This is why the royalty is compatible with the
  no-clawback posture: it never reaches backward.
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
`schedule(d)` and the royalty `share_bps` step down on a published calendar
schedule, and genesis seats/terms expire on a fixed date `T_g`. The schedule is
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
covered before organic sellers arrive. The hazard is that self-produced
inventory, if bought by our own buyer swarms, is wash volume. The boundary:

- Genesis inventory we LIST and no one buys = coverage (inventory). It raises
  `h`, it is the point of the exercise, and it is NOT counted as CCV.
- Genesis inventory we LIST and an arm's-length EXTERNAL buyer buys = real CCV.
- Genesis inventory we LIST and WE buy = wash = excluded from CCV.

**Cleared Cognition Volume (CCV), wash-trade-resistant methodology (published
from day one):**

```
CCV = sum over arm's-length clearings of (D7 clearing fee net of operator
      spread), deduplicated by (finding_id, buyer_cluster),
      excluding trades where buyer and seller share a related-party cluster.
```

CCV denominates in the D7 clearing fee (section 5), which is introduced at the
SAME milestone as the CCV methodology (G5): the fee and the metric land
together, because without a per-clearing fee a self-buy costs only metering
and the "wash trading burns real fees" defense below would be vacuous (review
finding GA-R2c). There is no CCV before the D7 fee exists.

- **Net-of-spread, not gross.** CCV counts the clearing fee net of operator
  spread, not the round-tripped principal. Wash trading to inflate CCV would
  require paying real fees to yourself, which nets to a pure loss and earns no
  CCV credit (the fee is burned, the principal round-trips out).
- **Related-party exclusion.** Trades within a related-party cluster are
  excluded, detected by shared `root_budget_holder` / `delegation_depth` on the
  receipt financial metadata (the C1 wash-trading signal,
  `chio-core-types/src/receipt/economics.rs:33`) and shared operator/funding.
- **Deduplication.** CCV counts unique `(finding_id, buyer_cluster)` clearings,
  so repeated self-buys of the same finding by the same cluster count once (and
  are excluded anyway by related-party filtering).
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
  pays for INVENTORY (a covered demanded descriptor, a durable asset), gated on
  burn and audit, one floor per descriptor; there is no per-participation or
  per-volume emission and no token to rotate. This is the hard-constraint-2
  discipline with a measured cautionary tale attached.

### 8.2 Two-part tariff (the floor-plus-royalty structure)

- Oi (1971), "A Disneyland Dilemma: Two-Part Tariffs for a Mickey Mouse
  Monopoly," QJE 85(1):77-96 [paper]. The origin of the lump-sum-access-fee-
  plus-per-use-charge structure the coverage mine adopts: the floor is the
  access fee (paid to bring inventory into existence), the royalty is the per-
  use charge (paid for realized value). Oi's central result, that the optimal
  split depends on demand heterogeneity, is why the floor is small and the
  royalty carries the value: buyers' `P_max` is heterogeneous (section 3), so a
  large fixed floor would exclude low-`P_max` demanded descriptors, while a
  royalty-heavy split lets value sort itself.

### 8.3 Advance market commitments (the procurement list's closest precedent)

- Kremer and Glennerster proposed, and the 2007 pneumococcal pilot deployed,
  the Advance Market Commitment: donors pledge a BOUNDED fund from which a
  specified per-unit subsidy is paid on delivered supply meeting a published
  specification, until the fund exhausts, with suppliers keeping a long-run
  per-unit revenue tail [paper/report; $1.5B pilot, launched 2007]. The
  structural mapping to the Genesis coverage mine is exact: bounded pool =
  AMC fund; procurement-list entry = the published product specification;
  floor paid on audit-passed delivery = the per-unit subsidy on verified
  supply; royalty = the long-run tail; pool exhaustion = the AMC's designed
  end state. Two AMC design lessons adopted: pay on VERIFIED DELIVERY against
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
  (cultivation), then a deed. Over one million claims were abandoned without
  proving up. Three lessons adopted directly: (1) grant on proof-of-improvement,
  not on claim-staking, which maps to the floor gated on mode-A proof-of-burn
  plus descriptor match plus audit (you get paid for improving a demanded
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

### 8.5 References

All URLs retrieved 2026-07-21.

1. [paper] Oi, W. "A Disneyland Dilemma: Two-Part Tariffs for a Mickey Mouse
   Monopoly." Quarterly Journal of Economics 85(1), 1971.
   https://academic.oup.com/qje/article-abstract/85/1/77/1861193
2. [tertiary] Homestead Act (1862), overview and proving-up requirements.
   https://www.nps.gov/articles/the-homestead-act.htm ;
   https://www.archives.gov/education/lessons/homestead-act
3. [report] Nansen. "All Hail MasterChef: Analysing Yield Farming Activity."
   June 2021 (42 percent day-one exit within 24h; ~70 percent by day three).
   https://www.nansen.ai/research/all-hail-masterchef-analysing-yield-farming-activity
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
8. Bug-bounty economics, agent-payment rails, credence-goods markets, peer-
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
`C`; queries `q(t) = Q_max * logistic((t - t_d)/s_d)` (a ramp delayed by
`t_d`); clearings `X = q * (C/(C+U)) * p_clear`; venue fee `f` per clearing;
seller price `~4f`. Supply: genesis capacity `cap_g` while the pool is solvent;
organic listings respond to per-finding lifetime value vs listing cost
(threshold response with capacity `A_o`). Spend: floors
`(admissions) * b0 * decay^t`, and audits
`(alpha_new * admissions + alpha_corpus * C) * c_a`, where `alpha_corpus` is
the PUBLISHED-RATE STANDING SURVEILLANCE of the live corpus (MECHANISMS 5
audits listed findings, not only new admissions); fee inflow funds audits
first, the pool tops up the shortfall, and floors always come from the pool.
Consistency notes: `f` is the D7 clearing fee (a genesis-introduced category,
section 5; a modeling parameter until G5 lands), the fee available for audits
is net of the genesis carve-out (conclusion 2), and the floor line charges
EVERY admission because floors release by default at window end (4.1); only
the sampled `alpha_new` fraction incurs audit cost, so mechanism and model
agree.

The recurrence admits THREE regimes, not two:

- **SELF-SUSTAIN**: organic supply covers demand inflow (`a_o >= lambda_d`)
  AND fees cover the security bill (`f * X >= (alpha_new * a + alpha_corpus *
  C) * c_a`), sustained. The program exits.
- **EXHAUST**: `B(t)` hits the month's committed spend before self-sustain.
- **ZOMBIE**: the pool survives the horizon but organic supply and fees never
  take over; coverage is high, the market is permanently subsidy-dependent.
  The exit criterion is organic takeover, NOT pool solvency.

Simulation results (36-month horizon; base parameters: `B0 = $75k`,
`N0 = 2,000` demanded descriptors, `lambda_d = 150`/month, `mu = 5%`/month,
`cap_g = 300`/month, `b0 = $6` with `decay = 0.93`, `alpha_new = 20%`,
`alpha_corpus = 1%`/month, `c_a = $10`, `Q_max = 6,000` queries/month ramping
at `t_d = 8` months, `p_clear = 0.35`, `f = $0.40`; reproducible from the
recurrence above):

| Scenario | Verdict | Coverage g(12) | Cumulative floors (36m) | Pool-funded audits (36m) |
|---|---|---|---|---|
| base (carve 0) | SELF-SUSTAIN month 13 | 95% | $20.5k | $6.5k |
| base, carve 25% | SELF-SUSTAIN month 18 | 95% | $20.5k | $7.3k |
| base, carve 40% | ZOMBIE | 95% | $20.5k | $10.3k |
| optimistic (early, strong demand) | SELF-SUSTAIN month 6 | 94% | $22.0k | $4.4k |
| pessimistic (demand at month 16, weak clearing) | ZOMBIE | 95% | $19.9k | $20.4k |
| no-demand | ZOMBIE | 95% | $19.9k | $20.3k |
| half pool ($37.5k) | SELF-SUSTAIN month 13 | 95% | $20.5k | $6.5k |
| tenth pool ($7.5k) | EXHAUST month 2 | 87% | $5.7k | $2.1k |
| costly audit (c_a $40, corpus rate 2%) | EXHAUST month 17 | 95% | $18.0k | $58.0k |
| no floor decay | SELF-SUSTAIN month 13 | 95% | $43.5k | $6.5k |
| big book (N0 10k, lambda_d 600) | EXHAUST month 20 | 40% | $43.5k | $33.7k |

(Rows without a carve label assume `carve = 0`; the carve rows are the GA-R3
re-run and feed the published carve-out cap.)

Three structural conclusions, which survive parameter variation and are the
actual content of this section:

1. **The floor is self-bounding by schedule construction.** With a geometric
   step-down, worst-case cumulative floor outlay is bounded by
   `b0 * admission_capacity / (1 - decay)` regardless of duration (~$20k at
   base; only ~2x that even with NO decay). The declining schedule is not just
   a land-grab clock; it is a hard cap on floor exposure. Floors are never the
   exhaustion driver.
2. **The standing audit cost is the exhaustion driver, and it scales with the
   program's own success.** `alpha_corpus * C * c_a` grows with the covered
   corpus the program builds; the better coverage mining works, the bigger the
   monthly security bill the pool carries until fees arrive. The costly-audit
   scenario exhausts even the base pool. Self-sustain therefore requires the
   SECURITY-SELF-FUNDING INEQUALITY `(1 - carve) * f * X >= (alpha_new * a +
   alpha_corpus * C) * c_a`, where `carve` is the combined genesis carve-out
   (royalty plus seat shares of the same fee; review finding GA-R3, which
   caught the gross-fee double count). The carve-out is material: re-running
   the base scenario, self-sustain slips 13 -> 15 -> 18 months as `carve`
   rises 0 -> 15 -> 25 percent, and at 40 percent the base case degrades to
   ZOMBIE (fees never clear the audit bill). Hence the published combined
   carve-out cap (default 25 percent, 4.2). That inequality (not the floor
   schedule) is what sizes the pool, the ongoing fee, and the carve-out cap
   jointly. The corpus audit rate must be tunable downward as per-class
   reliability data accumulates, or the fee must price it.
3. **The zombie regime is a real failure the two-outcome framing misses.** A
   pool that survives while nothing organic happens is not success; it is
   subsidy-dependence. The stop-loss gates and indicator 3 below exist for it.

Pool sizing consistent with the model: a wedge genesis pool on the order of
`$30k` to `$150k` (deliberately small, because negatives are exhaust: production
cost is sunk and the floor pays only the listing margin), with the caveat that
the pool's tail exposure is the audit line, not the floor line. The real
`N_demand`, floor, and audit-cost parameters come from the telemetry the
M-gates produce; the sizing must be recomputed against that telemetry before
any pool is funded.

Leading indicators (observable from receipts and telemetry; alarm thresholds
are modeling assumptions to be tuned on data). ALL indicators compute over the
CCV-FILTERED receipt set (arm's-length, related-party-excluded, section 7);
unfiltered variants are gameable by exactly the wash trades the stop-loss
exists to catch (review finding GA-R7):

1. Hit-conversion of subsidized findings = (subsidized findings that ever clear)
   / (subsidized findings admitted). Alarm if below ~10 to 20 percent after a 4
   to 8 week warm-up: the pool is buying dead inventory.
2. Coverage-to-CCV elasticity dCCV/dg. Alarm if coverage-of-demand `g` rises
   while CCV stays flat: coverage is not converting to demand; the `P_max` cap
   is not clearing.
3. Organic listing share = (unsubsidized admitted) / (total admitted). Alarm if
   flat or declining: the market is not becoming self-sustaining. This is the
   ZOMBIE-regime detector: high coverage with a flat organic share is
   subsidy-dependence, not success.
4. Conversion efficiency eta = (organic clearing-fee inflow) / (pool floor
   outflow). Alarm if eta stays near 0 while `B/B0` falls below a runway
   threshold: runway is burning without conversion.
5. Repeat-buyer rate (distinct returning buyer clusters). Alarm if one-and-done
   buyers dominate: `P_max` is not real for buyers.
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
because its exhaust is high-value (failing suites map to real developer demand)
and replay-checkable. The R&D-null exhaust is the residual: its exhaust may be
low-demand (nobody queries most dead ends) and its `P_max` is often negative
(section 3.2), so subsidizing R&D-null coverage risks buying dead inventory the
model predicts nobody will buy. This is documented, not solved: the program
launches the coding wedge, defers R&D-null coverage to a later gate contingent
on wedge telemetry (does coverage there actually convert?), and treats the
Homestead abandonment rate as the expected shape of the risk. The procurement
list (demanded-only admission) is the primary defense, but it cannot fully
distinguish "demanded and uncovered" from "queried once by an outlier"; residual
adverse selection remains and is carried in the register.

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

---

## 10. Summary: what the protocol pays for, from what pool, on what schedule

- **Coverage mining** pays a small **floor** (from the bounded, off-chain,
  operator-custodied **subsidy pool**, settlement numeraire) per covered
  demanded descriptor per coverage epoch, gated on the venue-authored
  acceptance recipe plus mode-A proof-of-burn plus an audit-verifiable
  guarantee class (`deterministic_replay` at launch), escrowed on the existing
  two-terminal-state escrow (release by default at the audit-window end; a
  sampled failing audit refunds to the pool), ordered by anchored commitment
  on contested descriptors, on a **published declining schedule** expiring at
  `T_g`; plus a **royalty** (reward type b, from the **D7 clearing fee**, a
  genesis-introduced per-clearing fee category, never the pool),
  non-transferable with a change-of-control lapse, forward-only, stepping
  down on schedule, minted at either admission door (floor or royalty-only).
- **Audit mining** pays **slashed bonds plus protocol bounties** (pool top-up
  for subsidized findings), and its output is the signed **reliability epoch**
  (`r`) that buyer pricing consumes.
- **Operator mining** grants **capped, non-transferable genesis seats** (reward
  type c) carrying a **clearing-fee share** (realized only once collection
  exists, M2/M5), bound to the F6 neutrality covenant and revocable on
  violation.

Every subsidy unit becomes inventory (a covered demanded descriptor) or security
(an audit that establishes `r`), never rented behavior: the floor is per-
descriptor and burn-gated, the royalty is value-gated (hits only), the audit is
security, the seat is position. Where the program fails is the exhaustion
boundary (9.1); the leading indicators (9.1) are the instrument panel. The first
executable mine is coverage mining's floor path, gated on the cognition-market
milestones it depends on (Q7, [GENESIS-PLAN.md](GENESIS-PLAN.md)).

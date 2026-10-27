# Chio + Copley Kernel-as-Decision-Model: Wave 2 (grounded, 20261025-003139) Synthesis

- Date: Sun Oct 25, 2026, ~12:50 AM ET
- Source: `/Users/connor/.codex/monitoring/chio-oracles/20261025-003139-fable51-chio-grounded-max/` (summary.json)
- Model: `claude-fable-5-1 --effort max`, all 4 angles exit 0 / success, observed_models = [claude-fable-5-1], apiKeySource = none (Claude Max OAuth, $0 API). Total wall 943 s.
- Words: A1 crate plan 6,571 | A2 proofs 6,125 | A3 OS enforcement 1,799 (partial) | A4 relying-party/positioning 5,255
- Claude Max usage at check: 5h 39%, 7d 78% (allowed_warning, crossed 75%).

## Angle 1: Slices P1/P2/P3 crate plan
- Dependency order: P1 `Envelope<A>`/`FeasibilityMap` inside `chio-kernel-core` (modules incl. `decide.rs`), then P2.0 new `crates/core/chio-fixed` (Q16.16 in i32, Q32.32 exact products in i64, saturating accumulation), then in parallel P2.1 `crates/economy/chio-micro-model` and P3 `crates/security/chio-predicate-dag`. All `no_std`, no `alloc`.
- P3 does not depend on P2.1: the 19.3M Copley encoder never runs in-kernel; a sidecar quantises it and exports 537 Q16.16 logits plus an attestation; the kernel consumes logits and sealed thresholds only.
- Lint posture: deny unsafe_code, unwrap/expect, indexing_slicing, panic, as_conversions, arithmetic side effects. True no_std CI gate on `thumbv7em-none-eabi` plus wasm32 targets.
- P1 theorems: P1.1 non-vacuity (bot always in mask, by constructor audit), P1.2 shield soundness, P1.3 idempotence/transparency of projection, P1.4 witness encoding injectivity. Apalache `EnvelopeDecisionReceipt.tla` (ChosenInFeasible, WitnessBeforeAllow) with negative mutant `EnvelopeNoBot.tla` required to produce a trace.
- Risk P1-R4: a second decision path bypassing `decide`; mitigation is gating `Verdict::Allow` behind `Decision<Verdict>` plus an xtask `formal-mirrors` grep check.

## Angle 2: Lean 4 / Aeneas / Kani / Loom / Apalache
- Aeneas extracts `Chio/Aeneas/VerifiedCore/Funs.lean`; hand proofs in `Chio/Proofs/EnvelopeShield.lean`. Example obligation O11: Q16.16 sat_mul saturation fallbacks are dead code (~80 Lean lines, ~3 days; blocker is the `i64::from` trait instance in extraction).
- Kani harnesses treat the policy as `kani::any()`; Loom models the control-plane publish / hot-path read of shadow prices.
- TLA+ `EnvelopedDecision`: inductive invariant checked by Apalache (base + one-step consecution), bounded liveness lasso to depth 14 (`EveryProposalTerminates`), full liveness by TLC at N=3, Cap=2, MaxInv=2. Four negative mutants: NoShield, EffectBeforeReceipt, StopNotChecked, NoRoundRobin.
- Open gap: pooled swarm budgets (`SwarmBudgetPool`) break inductiveness of `AttestedIsFeasible` because a concurrent Attest can invalidate another child's arithmetic; spec currently uses disjoint ledgers.

## Angle 3: Linux / macOS enforcement (PARTIAL)
- Response begins at section 3.4; Linux BPF-LSM / Landlock sections 1 to 3.3 are missing from response.md (likely truncation). Needs a re-run.
- Recovered: macOS ES client with watchdog at deadline minus margin (20 ms), exactly-one-response slot claim, ES cache always false (cache is keyed by file, not responsible process), Pending cells denied immediately on ES (no pause primitive). NE data provider: ungoverned flows allow in microseconds, pause cap 30 s.
- Budgets: Linux BPF-LSM hook p50 0.8 us / p99 3 us, WCET <= 10 us; ring buffer receipt 0.2/0.5 us; ES AUTH 150 us / 2 ms; revocation 50 us / 1 ms; table recompile + swap 400 us / 2 ms.
- Theorems 1-6 + Lemma 1: shield soundness, macOS deadline-miss safety, epoch isolation under generation flip (grace G >= W), receipt-before-allow with detectable loss (ringbuf reserve fails rather than overwrites), static envelope via Landlock intersection, staleness bound (revocation within Delta_rho independent of recompilation), hysteresis bounding epoch rate. Kani/Loom harness names mapped for `formal/MAPPING.md`.

## Angle 4: Relying-party wedge and OpenShell positioning
- Verification tiers V0 (signatures + Merkle inclusion) to V3 (full replay of C(x) and the boolean DAG from escrowed evidence, no model weights needed). Costs: receipt id recompute < 10 us, Ed25519 < 60 us (hybrid ML-DSA-65 < 250 us), inclusion at 2^24 < 25 us, structural < 1 us.
- Theorems: relying-party soundness; verification cost independent of agents, models, and swarm size; safe graduation from Shadow mode via Bernoulli bound; bounded aggregate exposure under pooled swarm budgets (`reserve_swarm_budget_fanout` / `release_swarm_budget_fanin`).
- Buyer table includes insurers (premium + bond sizing) and enterprise IT (receipts auto-close change records; per-kernel license plus Copley predicate packs). Framing: integrate with OpenShell-style sandboxed runtimes rather than compete; receipts are the cost of market access.

## Cross-angle takeaways
1. The pooled swarm budget is the one place where A2's proofs (non-inductive) and A4's economics (Theorem 5) meet; it is the highest-value next proof target.
2. Build order is concrete and mergeable: P1 then chio-fixed then (micro-model || predicate-dag).
3. A3 must be re-run for the Linux half.

## Suggested next wave
- Re-run A3 Linux BPF-LSM / Landlock / ringbuf sections in full.
- Inductive invariant for `SwarmBudgetPool` (reservation-ledger refinement) in TLA+ and Lean.
- P1 PR skeleton: `decide.rs` + Kani harnesses + `EnvelopeNoBot.tla` mutant.

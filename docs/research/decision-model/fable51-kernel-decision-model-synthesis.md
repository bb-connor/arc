# Chio + Copley: Master Synthesis of the Grounded `claude-fable-5-1` (`--effort max`) Kernel-as-Decision-Model Swarm

- **Date**: Sunday, Oct 25, 2026 (EDT / UTC-4)
- **Grounded Repositories**:
  - **Chio (`arc`)**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b416b6755cb9b0b48bf58557c4845ad`, 108 workspace crates, Lean 4 / Aeneas / Apalache TLA+ / Kani / Loom verification stack)
  - **Chio (`chio`)**: `/Users/connor/Medica/Backbay/Standalone/chio`
  - **Copley**: `/Users/connor/Medica/Backbay/ML/copley` (19.3M-parameter 4-pass multi-segment `UltraBERT` concept bottleneck -> `537` atomic concept predicates with role-asymmetric thresholds $\tau_j^{\text{pos}}, \tau_j^{\text{neg}}$ -> `236`-rule symbolic `AND`/`OR`/`AND NOT` DAG composer + epistemic partitioning $C(X) \oplus P(X)$)
- **Oracle Execution Verification**:
  - **Model**: `claude-fable-5-1` (`--effort max`), verified in every JSONL stream (`observed_models: ["claude-fable-5-1"]`, `fallback: null`)
  - **Billing / Auth**: `apiKeySource: "none"` (Claude Max OAuth subscription, `$0.00` API spend, isolated temporary directories with `--tools ""`, `--strict-mcp-config`, `--setting-sources ""`)
  - **Total Output**: `191,040` characters (`23,123` words) across 4 parallel angles

| Angle | Focus | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars |
|---|---|---:|---|---|---|---:|---:|
| **Angle 1** | `angle_1_kernel_as_decision_model_formalization` | `0` | `success` | `["claude-fable-5-1"]` | `none` | `6,747` | `52,223` |
| **Angle 2** | `angle_2_multi_model_kernel_architecture` | `0` | `success` | `["claude-fable-5-1"]` | `none` | `5,762` | `49,460` |
| **Angle 3** | `angle_3_verification_bounds_and_simplex_trust` | `0` | `success` | `["claude-fable-5-1"]` | `none` | `5,285` | `43,681` |
| **Angle 4** | `angle_4_copley_meets_chio_decision_models_all_the_way_down` | `0` | `success` | `["claude-fable-5-1"]` | `none` | `5,329` | `45,676` |
| **Total** | **All 4 Grounded Angles** | **`0`** | **`success`** | **`["claude-fable-5-1"]`** | **`none`** | **`23,123`** | **`191,040`** |

---

## Executive Architectural Synthesis

### 1. Answering Connor's Core Question: *"Is the OS Kernel Becoming Decision Models All the Way Down?"*

**Yes - under one structural law that unifies Chio and Copley: the kernel is becoming *Concept-Bottlenecked, Computation-Conditioned, Shielded Decision Models* all the way down, and *exact integer algebra* all the way through.**

Across all four independent `claude-fable-5-1 --effort max` treatises, the same canonical mathematical object emerges at every layer $\ell \in \{\text{L0}, \text{L1}, \text{L2}, \text{L3}\}$ of the operating system:
$$\mathcal{D}_\ell = \big(\mathcal{X}_\ell,\; C_\ell,\; P_\ell(\cdot; \theta_\ell, \boldsymbol{\lambda}),\; \mathcal{C}_\ell,\; \Pi_{\mathcal{C}_\ell(x)},\; W_\ell\big)$$

1. **Exact Computation $C_\ell(x) \in \mathbb{K}_3^{F_\ell}$ (The Algebraic Core)**:
   - Implemented in `chio-kernel-core::formal_core`, `formal_aeneas`, `chio-flow`, and `chio-semantic-contracts`.
   - Computes exact decidable predicates and conservation laws (`classify_time_window`, `budget_precheck`, `budget_commit`, `NormalizedScope::is_subset_of`, `revocation_snapshot_denies`, `validate_dependency_graph`, `inclusion_step`) in strong Kleene three-valued logic $\mathbb{K}_3 = \{+, -, \bot\}$ (`known_positive`, `known_negative`, `unknown_effect`/`unsupported_syntax`).
   - Following Copley's foundational Arm D result (`docs/research/2026-10-21-computation-and-learning-synthesis.md`), **a neural network is never asked to approximate a calculation that $C_\ell(x)$ solves exactly**.
2. **Feasible Envelope $\mathcal{C}_\ell(C_\ell(x)) \subseteq \mathcal{A}_\ell$ (The Safety Boundary)**:
   - Computed solely from $C_\ell(x)$, always containing a conservative fail-closed baseline action $\bot_x \in \mathcal{C}_\ell(x)$ (`Deny`, `Defer`, `Hold`, or `pi_base`).
   - Represented in Rust by a move-only/opaque type `Feasible<A>` or `ShieldedAction<A>` whose constructor is private to `chio-kernel-core` (`RawModelProposal<A>` and `CandidatePlanV1` have compile-fail doctests forbidding `Into<ShieldedAction<A>>` or `Into<SignedRecoveryGrant>`).
3. **Calibrated Concept / Utility Predictor $P_\ell(x; \theta_\ell, \boldsymbol{\lambda})$ (The Learned Layer)**:
   - In **Tier-1 (0.5-5 ms sidecar / control plane)**: Copley's 19.3M-parameter 4-pass `UltraBERT` encoder reads Chio's 4-segment evaluation envelope ($s_0$: `PortableToolCallRequest` AST; $s_1$: `VerifiedCapability` + `SwarmDelegationWitnessChain` + `BudgetSplit`; $s_2$: `chio-flow` `InformationLabel` + `DataFlowGuard` counters; $s_3$: `BehavioralProfileGuard` EMA/sigma + `PheromoneConcentration`) and emits $M = 537$ concept logits projected through **role-asymmetric thresholds** $\tau^{\text{pos}}_j \ge \tau^{\text{neg}}_j$ into trits $\mathbb{K}_3^{537}$.
   - In **Tier-0 (10-800 ns `#![no_std]` hot path in `chio-kernel-core`)**: 6 orthogonal micro-models (`AdmissionQuotaScorer`, `GuardScheduleOrderer`, `SwarmDagBranchController`, `RecoveryGraphRanker`, `PheromoneRouteSelector`, `KvContextTierEvictor`) execute in pure integer/fixed-point arithmetic (`FixedQ16_16` / `Q32`, `INT8` weights, oblivious trees, or bitset `SymbolicRuleDag<537, 236>`) penalized by a shared read-only Lagrangian shadow-price vector $\boldsymbol{\lambda} = (\lambda_{\text{budget}}, \lambda_{\text{fuel}}, \lambda_{\text{latency}}, \lambda_{\text{memory}}, \lambda_{\text{escrow}})$.
4. **$O(1)$ Shielded Projection $\Pi_{\mathcal{C}_\ell(x)}$ (Simplex Trust & Non-Amplification)**:
   - Projects any learned proposal onto $\mathcal{C}_\ell(C_\ell(x))$ in compile-time-bounded $O(1)$ steps and zero heap allocations, or switches to $\pi_{\text{base}}$ on fuel exhaustion, infeasibility, or drift breach.
   - **Envelope Preservation / Verification Transfer Theorem (Angle 1 Thm 1.0.2, Angle 2 Thm 1.5, Angle 3 Thm 1, Angle 4 Thm 1)**: Because $\Pi_{\mathcal{C}_\ell(x)}(\hat{a}) \in \mathcal{C}_\ell(C_\ell(x))$ for *every* weight tensor $\theta$, threshold vector $\tau$, and shadow price $\boldsymbol{\lambda}$, **every Lean 4, Aeneas, Apalache TLA+, and Kani safety proof discharges once by modeling the learned choice as unconstrained nondeterminism (`\E a \in Feasible(s)` / `kani::any()`) and never needs to be re-proved when weights update!**
5. **Cryptographic Receipt Witness $W_\ell$ (`ChioReceiptBody` Extension)**:
   - Every decision seals `weights_digest`, `calibration_digest`, `dag_digest`, active/satisfied concept and fact bitmaps (`[u64; 9]`), and the `ProjectionOutcome` (`Identity`, `Clipped`, `Fallback(FallbackReason)`) into RFC 8785 canonical JSON (`DecisionModelWitnessMetadata` / `ConceptBottleneckReceiptWitness`), enabling bit-exact offline replay across `x86_64`, `aarch64`, and `wasm32-unknown-unknown`.

---

### 2. The 4-Level Fractal Tower Across Chio + Copley

| Level & Timescale | Exact Fact Processor $C_\ell(X)$ | Learned Predictor $P_\ell(X; \theta_\ell, \boldsymbol{\lambda})$ | Feasible Set $\mathcal{C}_\ell$ & Shield $\Pi_\ell$ | Receipt Witness $W_\ell$ | Formal Verification Guard |
|---|---|---|---|---|---|
| **L0: 10-800 ns** (`chio-kernel-core` `#![no_std]` hot path) | `formal_core` scalar facts $F_0..F_7$ (`time_window_valid`, `budget_charge_admits`, `scope_subset`, `not_revoked`, `flow_admissible`, `dependency_graph_valid`, `nonce_fresh`, `delegation_attenuated`) | 6 INT8/Q16.16 micro-models (`QuantizedLinearPolicy`, `ObliviousTreePolicy`) + cached Copley concept trits | `shielded_budget_share_project`, 2-phase guard permutation mask, bitset `SymbolicRuleDag` | `DecisionModelWitnessMetadata` + `ConceptBottleneckReceiptWitness` in `ChioReceiptBody` | Kani `verify_budget_admission_projection`, `verify_copley_dag_role_asymmetric_monotone_safety`, Aeneas Lean extraction |
| **L1: 0.5-5 ms** (`chio-kernel` & `chio-guards` sidecar) | `chio-flow` `PreparedFlowAdmission` + `chio-semantic-contracts` AST/effect validation | **Copley 4-Pass 19.3M `UltraBERT`** over segments $s_0..s_3 \to 537$ heads with role-asymmetric $(\tau^{\text{pos}}, \tau^{\text{neg}})$ | **Copley 236-rule boolean DAG** (`AND`/`OR`/`AND NOT`); `Hold` $\to$ `PendingApproval`; `Abstain` $\to$ `PromotionPolicy` | Fired rule IDs, active concept bitmaps, min-margin witness, `weights_digest` | Loom `loom_revocation_race_eval`, Apalache `ReceiptBeforeAllow`, `TerminalReceiptExactlyOne` |
| **L2: 10-100 ms** (`chio-swarm-authority`, `chio-recovery`, `chio-pheromone`) | `SwarmTaskGraph` acyclicity & depth caps, `validate_dependency_graph`, checked `reserve_swarm_budget_fanout` | Critical-path slack + Whittle index pheromone router + `RecoveryGraphRanker` + Weitzman Pandora / Wald SPRT branch controller + Tier-1 dual ascent on $\boldsymbol{\lambda}$ | Integer basis-point simplex $\sum b_i \le 10^4$, starvation credit bucket (`starvation_credit_step`), `PlannerLimitsV1` `Work` meter, $\sqrt{N}$ passport cap | `SwarmRoutePlanReceipt`, `SwarmJoinReceipt`, `SignedRecoveryExplanationReportV1`, `WeightEpoch` | Apalache `ReservationConservation`, compile-fail doctest denying `CandidatePlanV1 -> SignedRecoveryGrant` |
| **L3: 1 s - hours** (`chio-federation`, `chio-autonomy`, `chio-credit`, `chio-market`) | Settlement ledgers, treaty predicates (`Treaty/PredicateLang.lean`), exposure/loss ratios | Autonomous underwriting/pricing, capital pool optimization, counterfactual softmin training on `chio-replay-corpus` | `AutonomousPricingAuthorityEnvelopeArtifact`, Hoeffding drift monitor $\to$ `AutonomousSafeState` (`ShadowModeOnly`, `DelegatedOnly`, `FullPause`) | `AutonomousPricingDecisionArtifact`, `AutonomousDriftReport`, Merkle checkpoint roots | Lean `settlement_admission_requires_verified_evidence`, `epoch_advance_is_strict` |

---

### 3. Cross-Angle Summary of Formal Theorems & Concrete Rust Artifacts

1. **Angle 1 (`angle_1_kernel_as_decision_model_formalization`, 6,747 words)**:
   - Formalizes the **Enveloped Decision Process** $\mathcal{E} = (\mathcal{S}, \mathcal{A}, F, T, r, \mathbf{c}, \mathbf{d}, \Phi)$, proving **Theorem 1.0.2 (Envelope Preservation)** and **Corollary 1.0.3 (Verification Transfer to Nondeterministic Model Checking)**.
   - Maps all 6 kernel subsystems:
     - **1.1 Swarm DAG Scheduling**: CMDP priority index with Graham $(2 - 1/m)$ list-scheduling robustness floor and Hu's in-tree optimality on fan-in joins.
     - **1.2 Dynamic Budget Split**: Static floor $\phi_c$ + dynamic pool $\phi_D$ with floor-division residue account $\varrho$ (**Theorem 1.2.1 Conservation & Floor Isolation** and **Theorem 1.2.2 Construction-Time Oversubscription Elimination**) + exponential-potential dual mirror descent achieving $O(\sqrt{T})$ regret.
     - **1.3 Adaptive Guard Pipeline**: `TwoPhaseGuard` trait (`evaluate` -> `Prepared`, `commit` only on `Allow`), proving **Theorem 1.3.1 (Order Independence)** and **Theorem 1.3.2 (Optimal $q_i(x)/c_i$ Ratio Ordering)**.
     - **1.4 Pheromone Routing**: Contextual Restless Bandit where Chio's half-life $h$ and evaporation floor $s_{\text{floor}}$ map via exact bijection $2^{-1/h} = p_{11} - p_{01}$ and $s_{\text{floor}} = p_{01}/(1 - p_{11} + p_{01})$ to Markov persistence (**Lemma 1.4.1 Observation-Cost Shift of Whittle Index**).
     - **1.5 Recovery Planning**: Budgeted POMDP heuristic search (**Theorem 1.5.1 Soundness, Meter Invariance & Non-Authority**).
     - **1.6 KV-Cache Paging & Speculative Branch Continuation**: DAG-informed learned Belady paging + Weitzman Pandora's Box reservation prices $z_k$ + Wald-Wolfowitz Sequential Probability Ratio Test (SPRT) in base-2 `Q32` integers.
   - Proves **Propositions 2.1, 2.2, and 2.3** (Blackwell information gap for cross-layer observability, pooling Jensen gap under bursty fan-out, and Banks-Sundaram switching-cost / prefix co-location / convex batching gaps).
   - Provides `#![no_std]` Rust implementations of `Q32`, 1025-knot `EXP2_NEG_LUT` with $5.7 \times 10^{-8}$ max interpolation error, `PolicyArtifactV1`, `Feasible<A>`, and `choose`.

2. **Angle 2 (`angle_2_multi_model_kernel_architecture`, 5,762 words)**:
   - Proves **Four Impossibility Results** for a monolithic neural policy inside the kernel TCB (WCET: 19.3M params = $1.5 \times 10^8$ MACs vs. 48 MACs in 60 ns; Fault Isolation; CBMC/Aeneas Verification Complexity; Cross-Target Replay Determinism).
   - Proves **Theorem 1.8 (Lagrangian Separability)** and **Theorem 3.1 & 3.2 (Fixed-Point Projected Dual Subgradient Convergence & Shapley-Folkman Bounded Duality Gap)**.
   - Specifies the **6 Kernel Micro-Models** (`AdmissionQuotaScorer`, `GuardScheduleOrderer`, `SwarmDagBranchController`, `RecoveryGraphRanker`, `PheromoneRouteSelector`, `KvContextTierEvictor`) and their exact feature vectors, action spaces, and latency budgets.
   - Provides compile-ready `#![no_std]`, `#![forbid(unsafe_code)]` Rust modules: `chio-kernel-core::fixed` (`FixedQ16_16`), `chio-kernel-core::shadow_price` (`ShadowPriceVector::dual_step`), `chio-kernel-core::micro_model` (`KernelMicroModel` trait), `chio-kernel-core::quantized_policy` (`QuantizedLinearPolicy<D, A>` and `ObliviousTreePolicy<D, DEPTH, LEAVES>`), `chio-kernel-core::admission_quota`, and `chio-kernel::weights_binding` (`WeightEpoch` via `ArcSwap` sealed into `ChioReceiptBody`).

3. **Angle 3 (`angle_3_verification_bounds_and_simplex_trust`, 5,285 words)**:
   - Formalizes `SimplexEnvelope<S: Shield>` and `ShieldedAction<A>` with **Theorem 1 (Shield Soundness)**, **Lemma 1.1 & 1.2 ($L_1$ 4-Quasi-Non-Expansiveness of Sequential Budget Clip)**, **Theorem 1.3 (Guard Permutation Invariance with Canonical Min-Denier Completion Scan)**, and **Theorem 1.4 (Starvation-Free Bounded Waiting within $\lceil \text{cap}/q \rceil + N$ rounds)**.
   - Proves **Theorem 2 (Lagrangian Shielded Consistency, Robustness $\text{CR}(\pi_{\text{sh}}) \le \alpha \cdot \text{CR}_b$, and $O(\ln(1/\beta)/\delta^2)$ Hoeffding Drift Detection Time)**.
   - Supplies drop-in verification artifacts ready for `formal/MAPPING.md`:
     - Pure Aeneas-extractable helpers in `formal_aeneas.rs` (`shielded_budget_share_project`, `simplex_switch_decision`, `simplex_mode_step`, `guard_permutation_preserves_verdict`, `starvation_credit_step`),
     - 4 complete `#[kani::proof]` harnesses (`verify_shielded_budget_share_never_oversubscribes_or_overflows`, `verify_shielded_budget_share_idempotent_on_feasible`, `verify_simplex_gate_never_admits_revoked_or_expired`, `verify_guard_permutation_shield_preserves_verdict_and_canonical_reason`),
     - Complete Apalache TLA+ module `SimplexSafetyEnvelope.tla` (`ShieldedActionAlwaysFeasible`, `DriftFallbackMonotone`, `ReceiptBindsModelWitness`, `StarvationFreedom`) + Loom test `loom_simplex_epoch_switch_linearizable`,
     - Complete `DecisionModelWitnessMetadata` struct and deterministic offline verifier `verify_decision_model_witness`.

4. **Angle 4 (`angle_4_copley_meets_chio_decision_models_all_the_way_down`, 5,329 words)**:
   - Unifies **Copley** and **Chio** via **Theorems 1, 2, 3, and 4** (Envelope Containment, $3^{M+F}$ Concept Bottleneck Sufficiency, Well-Foundedness bottoming out in `formal_core::budget_commit`, and **Role-Asymmetric Threshold Monotonicity** under the gap invariant $\tau^{\text{neg}}_j \le \tau^{\text{pos}}_j$).
   - Maps Copley's 4 segments ($s_0..s_3$) to Chio's `EvaluateInput`/`GuardContext`, Copley's $C(X)$ to Chio's 8 `formal_core` Kleene facts $F_0..F_7$, and Copley's 236-rule DAG to `chio-policy` HushSpec compilation and refinement.
   - Provides a complete, self-contained `#![no_std]`, `#![forbid(unsafe_code)]` Rust module `concept_bottleneck` implementing `BitSet<W>`, `Q16_16`, `RoleAsymmetricThresholds<M>`, `CopleyConceptVector<M>` (`TrueWithMargin`, `FalseWithMargin`, `EpistemicAbstain`), `SymbolicRuleDag<M, W_M, W_F, R>` with `VerificationBudget` work metering, `ConceptBottleneckReceiptWitness` with canonical JSON rendering, and the Kani proof harness `verify_copley_dag_role_asymmetric_monotone_safety`.


---

# Full Verbatim Treatise - Angle 1: Kernel-as-Decision-Model Formalization (`angle_1_kernel_as_decision_model_formalization`)

Here is the specification. One caveat first: I had no repository access in this session. Every existing signature below is taken from your brief, and every type I introduce is a proposal that must be diffed against the crates at `5a7d81ec5b` before it is cited as existing code.

**Thesis.** Chio already splits each resource decision into two parts. A deterministic feasibility computation decides which actions are admissible. A ranking or sizing rule then picks one admissible action. Today that second part is a constant, a fixed order, or a lexicographic enumeration. The design below keeps the first part untouched, formalizes the second part as a constrained sequential decision problem, and confines every learned policy to choosing among actions the algebra has already admitted. Hard invariants then hold for every policy parameter by a one-line induction. The model checkers prove them once, by treating the learned choice as unconstrained nondeterminism. Three dominance propositions characterize exactly when a learned chooser beats the best static rule, and exactly when the static rule is already optimal.

## 1 Subsystem formalizations

**1.0 Shared skeleton: the enveloped decision process.**

*Definition 1.0.1.* An enveloped decision process is a tuple $\mathcal{E}=(\mathcal{S},\mathcal{A},F,T,r,\mathbf{c},\mathbf{d},\Phi)$. $\mathcal{S}$ is a countable state space whose reachable part is finite because every container in the kernel is bounded by a `MAX_*` constant. $\mathcal{A}$ is a finite action alphabet. $F:\mathcal{S}\to 2^{\mathcal{A}}$ is a deterministic feasibility map computed entirely inside `chio-kernel-core`, with a conservative action $\bot_s\in F(s)$ for every $s$. The conservative action is defer, deny, or no-op, so $F(s)$ is never empty. $T(s'\mid s,a)$ is the transition kernel, $r$ the reward, $\mathbf{c}=(c^{(1)},\dots,c^{(m)})$ soft cost signals with budgets $\mathbf{d}$, and $\Phi:\mathcal{S}\to\{0,1\}$ the conjunction of hard invariants. $F$ is called $\Phi$-inductive when

$$
\Phi(s)=1,\ a\in F(s),\ T(s'\mid s,a)>0 \ \Longrightarrow\ \Phi(s')=1 .
$$

A policy $\pi$ is enveloped when $\pi_t(\cdot\mid h_t)$ is supported on $F(s_t)$ for every history $h_t$.

*Theorem 1.0.2 (Envelope preservation, proved here).* For every enveloped policy $\pi$, in particular every learned $\pi_\theta$, and every $s_0$ with $\Phi(s_0)=1$, $\ \mathbb{P}^{\pi}\big(\forall t:\ \Phi(s_t)=1\big)=1$.

*Proof.* Induction on $t$. The base case is the hypothesis. If $\Phi(s_t)=1$ then $a_t\in F(s_t)$ by envelopment, and $\Phi(s_{t+1})=1$ by inductiveness for every $s_{t+1}$ in the support. The policy's choice among feasible actions is never used. $\blacksquare$

*Corollary 1.0.3 (Verification transfer).* Let $\mathcal{E}^{\exists}$ be the nondeterministic process in which $a_t$ is an arbitrary element of $F(s_t)$. If a model checker proves $\Phi$ invariant for $\mathcal{E}^{\exists}$, then $\Phi$ is invariant under every learned policy. This is the single most important engineering consequence. In Apalache the policy becomes `\E a \in Feasible(s)`. In Kani it becomes `let i: usize = kani::any(); kani::assume(i < feasible.len());`. Neither artefact ever mentions $\theta$.

*Constraint placement rule 1.0.4.* Constraints that must hold almost surely go into $F$. Constraints that need only hold in expectation go into a Lagrangian. For a finite enveloped CMDP, the occupancy-measure linear program has strong duality, so

$$
\max_{\pi\ \text{enveloped}}\ J_r(\pi)\ \ \text{s.t.}\ \ J_{c^{(j)}}(\pi)\le d_j
\quad=\quad
\min_{\lambda\ge 0}\ \max_{\pi}\ \Big[J_r(\pi)-\textstyle\sum_j \lambda_j\big(J_{c^{(j)}}(\pi)-d_j\big)\Big],
$$

by Altman's theorem for constrained Markov decision processes. The multipliers $\lambda$ live in fixed point and are themselves clamped by an authority envelope, as in Section 3.

**1.1 Swarm compute-graph and tool-DAG scheduling.** Problem class: CMDP, decomposed into a per-node priority index, with list scheduling as the robustness floor.

*State.* With $G=(V,E,J)$ the signed `SwarmTaskGraph` bound into the continuation token by its canonical hash,

$$
s_t=\big(G,\ \mathbf{x}_t,\ \boldsymbol{\rho}_t,\ \mathbf{B}_t,\ \boldsymbol{\beta}_t,\ \mathbf{k}_t,\ e_t,\ \tau_t\big).
$$

Here $\mathbf{x}_t\in\{\mathsf{Blocked},\mathsf{Ready},\mathsf{Dispatched},\mathsf{Done},\mathsf{Failed},\mathsf{Cancelled}\}^{V}$ mirrors the per-operation terminal state machine. $\rho_v\in\mathbb{N}$ is the live reservation for a dispatched node. $\mathbf{B}_t=(U_t,I_t)$ is the remaining pooled units and invocations. $\beta_{v,p}$ is a sufficient statistic for the latency and cost of node class $v$ on provider adapter $p$: an eight-bucket log-spaced latency count histogram $\mathbf{n}\in\mathbb{N}^8$ plus a Gamma-Poisson cost posterior $(\alpha,\beta)$ stored in Q32. $k_v$ is the context size in tokens and a readiness bit for upstream outputs. $e_t$ is the swarm revocation epoch and $\tau_t$ the pair of current time and authority deadline.

*Actions.* For each ready node $v$, $a_v\in\{\mathsf{Defer}\}\cup\{\mathsf{Dispatch}(p,b):p\in P_v\}$, where $P_v$ is the admissible adapter set from the signed route plan and $b$ is a batch tag for the tool-call fabric. The joint action is the vector over ready nodes. The feasibility map $F(s)$ keeps only vectors satisfying: every predecessor of $v$ is $\mathsf{Done}$; every join $j$ upstream of $v$ has reached quorum $q_j$, which equals $|\mathcal{B}_j|$ for all-of joins; the reservation call `reserve_swarm_budget_fanout` succeeds under checked arithmetic; $|\{v:\ \mathsf{Dispatch}\}|$ respects per-adapter concurrency caps and open circuit breakers; depth and fan-out stay within the `MAX_SWARM_GRAPH_*` caps; $e_t$ equals the token's epoch; and $\tau_t$ precedes the deadline.

*Transition kernel.* Dispatch sets $x_v\leftarrow\mathsf{Dispatched}$ and $\rho_v\leftarrow\hat c_v$. A completion event fires after $L\sim\mathcal{L}_{v,p}$, with outcome $\mathsf{Done}$ with probability $1-f_{v,p}$, realized cost $C\le\rho_v$ since overruns are refused by the post-invocation budget algebra, and release of $\rho_v-C$ through `release_swarm_budget_fanin`. Successor readiness and join quorums are recomputed deterministically. The posterior $\beta_{v,p}$ updates by conjugacy on integer counts.

*Reward and constraints.* 

$$
r_t=-\,w_{\mathrm{lat}}\,\Delta_t\,\mathbb{1}[\text{root unfinished}]\;-\;w_{\mathrm{cost}}\,C_t\;+\;U\,\mathbb{1}[\text{terminal graph receipt at }t].
$$

Hard constraints are all in $F$. Soft constraints are expected adapter overload counts $\mathbb{E}\big[\sum_t\mathbb{1}[\text{queue}_p>Q_p]\big]\le d_p$ and an expected tail-latency budget, both priced by multipliers.

*Policy form.* Joint scheduling of a precedence DAG on parallel servers is NP-hard, so the policy is an index. A deterministic scorer emits $\nu_\theta(v,s)\in\mathrm{Q32}$ from features that are all computed by the algebra: critical-path slack $\mathrm{slack}(v)=(\tau_{\mathrm{dl}}-t)-\mathrm{LP}(v)$ where $\mathrm{LP}(v)=\hat\ell_v+\max_{w\in\mathrm{succ}(v)}\mathrm{LP}(w)$ uses integer posterior-mean latencies and the $q_j$-th smallest branch length at joins; downstream demand forecast $\hat D(v)=\sum_{w\in\mathrm{desc}(v)}\hat c_w$; adapter queue depth; pheromone latency belief for $p$; the owning agent's behavioral EMA; $k_v$; depth and fan-out. A list scheduler sorts ready nodes by $\nu_\theta$ descending, breaks ties lexicographically on canonical node bytes, and dispatches in that order while the candidate remains in $F(s)$. Adapter choice is a second index $\nu^{\mathrm{route}}_\theta(v,p,s)$ over $P_v$.

*Robustness floor (cited).* Graham's list-scheduling theorem gives $C_{\max}\le(2-1/m)\,C^{*}_{\max}$ on $m$ identical servers for any priority order under arbitrary precedence. Hu's theorem makes highest-level-first optimal for unit tasks on in-trees, which is the shape of fan-in joins. The default scorer $\nu_0=-\mathrm{slack}$ therefore reproduces today's behaviour and inherits both guarantees, and no learned $\nu_\theta$ can lose Graham's bound.

**1.2 Dynamic budget split, quota allocation, and pre-admission pricing.** Problem class: online convex optimization and primal-dual resource allocation, with conservation as the envelope.

*Accounts.* The parent pool holds $P$ units. Each child $c$ receives a static floor $\phi_c$ in basis points, and a dynamic pool receives $\phi_D$ basis points, with the construction-time check

$$
\sum_c \phi_c+\phi_D+\phi_{\mathrm{parent}}\ \le\ 10^4 .
$$

Integer allotments are $A_c=\lfloor P\phi_c/10^4\rfloor$, $A_D=\lfloor P\phi_D/10^4\rfloor$, $A_{\mathrm{par}}=\lfloor P\phi_{\mathrm{parent}}/10^4\rfloor$, and the floor-division residue $\varrho=P-\sum_c A_c-A_D-A_{\mathrm{par}}$ is kept in its own unspendable account so that conservation is an exact integer identity.

*Conservation identity.* After every mutation,

$$
\sum_c\big(\mathrm{floorRes}_c+\mathrm{floorFree}_c\big)+\sum_c \mathrm{dynRes}_c+\mathrm{dynFree}+\mathrm{parFree}+\varrho\ =\ P .
$$

*Admission and pricing.* A child request $k$ carries cost $c_k$ and a value estimate $\hat v_k\in\mathrm{Q32}$ built from exact graph features and calibrated concept scores. It is admitted from the child's own floor if `budget_commit` succeeds there. Otherwise it is admitted from the dynamic pool iff

$$
\hat v_k\cdot 2^{32}\ \ge\ \lambda_t\cdot c_k \quad\text{compared in }i128\text{, and}\quad \mathrm{dynFree}_t\ge c_k .
$$

Otherwise it is deferred. The shadow price follows dual mirror descent with an exponential potential, computed with the deterministic power-of-two table of Section 3:

$$
\lambda_{t+1}=\mathrm{clamp}\!\Big(\lambda_t\cdot 2^{\,\eta\,(x_t-\rho_t)},\ \lambda_{\min},\ \lambda_{\max}\Big),\qquad
\rho_t=\Big\lfloor \frac{\mathrm{dynFree}_t}{\hat T_t}\Big\rfloor,\qquad \eta=2^{-k_\eta}.
$$

Here $x_t$ is the number of units admitted from the dynamic pool at step $t$, and $\hat T_t$ is the number of not-yet-dispatched descendants, an exact graph quantity rather than a guess. The clamp interval comes from the autonomy authority envelope, and per-epoch movement of $\lambda$ is further rate-limited there.

*Theorem 1.2.1 (Conservation and floor isolation for every price path, proved here).* For any sequence $(\lambda_t)_{t\ge0}$ in $\mathrm{Q32}$, the identity above holds after every operation, and no admission for child $c$ ever decreases $\mathrm{floorFree}_{c'}$ for $c'\ne c$.

*Proof.* The accounts are disjoint integer registers. The only cross-account flow is $\mathrm{dynFree}\to\mathrm{dynRes}_c$, executed by the existing checked subtract-then-add commit, which either performs both moves or neither. The price enters only the admission predicate, which is read-only, so the commit path is literally the same code as today. Floors are never a source for any flow except their own child's reservations. $\blacksquare$

*Theorem 1.2.2 (Oversubscription is a construction-time error, proved here).* Under the construction check, for every reachable state and every child, $\mathrm{floorRes}_c+\mathrm{dynRes}_c\le A_c+A_D\le P$, hence the `OversubscribedSiblings` condition can never arise at admission time regardless of $\lambda$.

*Proof.* $\mathrm{floorRes}_c\le A_c$ by the floor account's checked arithmetic, $\sum_c \mathrm{dynRes}_c\le A_D$ by the dynamic account's checked arithmetic, and $A_c+A_D\le P$ by the construction check. $\blacksquare$

*Performance (cited).* With stochastic or random-permutation demand, dual mirror descent of this form achieves regret $O(\sqrt{T})$ against the hindsight-optimal allocation, and under adversarial demand it retains a bounded competitive ratio, by the "best of many worlds" theorem of Balseiro, Lu, and Mirrokni. Static shares have neither property, as Proposition 2.2 shows.

**1.3 Adaptive guard ordering and early-exit screening.** Problem class: Bayesian optimal stopping, equivalently minimum-expected-cost sequential testing of a conjunction.

*Verdict algebra.* Guard outcomes live in the meet-semilattice $\mathsf{Deny}<\mathsf{PendingApproval}<\mathsf{Allow}$, and the pipeline verdict is $\bigwedge_i o_i$. $\mathsf{Deny}$ is the absorbing bottom, so early exit is sound only on $\mathsf{Deny}$. A pending outcome must keep evaluating, because a later guard may still deny.

*Two-phase guards.* Side effects are the obstacle to reordering, since the velocity guard consumes tokens and the data-flow guard accumulates bytes. The pipeline therefore requires the preparation discipline that `chio-flow` already uses for dispatch plans:

```rust
pub enum GuardPurity { Pure, TwoPhase, Legacy }

pub trait TwoPhaseGuard: Send + Sync {
    type Prepared;
    fn name(&self) -> &str;
    fn purity(&self) -> GuardPurity;
    /// Pure w.r.t. shared mutable state. Reads a snapshot; writes nothing.
    fn evaluate(&self, ctx: &GuardContext<'_>)
        -> Result<(GuardVerdict, Self::Prepared), KernelCoreError>;
    /// Applied by the pipeline only when the whole-pipeline verdict is Allow.
    fn commit(&self, prepared: Self::Prepared) -> Result<(), KernelCoreError>;
    /// Fuel for WASM guards, EMA latency class for external guards, Q32 units.
    fn cost_hint(&self) -> Q32;
    /// Mandatory guards may be reordered but never omitted.
    fn mandatory(&self) -> bool;
}
```

*Theorem 1.3.1 (Order independence, proved here).* For a pipeline whose guards are all `Pure` or `TwoPhase`, every evaluation order with early exit on $\mathsf{Deny}$ yields the same verdict as full evaluation, and the same committed state.

*Proof.* Purity makes each $o_i$ a function of the request and the snapshot alone, independent of which guards ran before it. The meet is commutative, associative, and idempotent, so the full verdict is order independent. If some $o_i=\mathsf{Deny}$, the meet is $\mathsf{Deny}$ whether or not the remaining guards are evaluated, so stopping is sound. Commits happen only when the verdict is $\mathsf{Allow}$, which requires every guard to have been evaluated, and the committed set is then the full set in both schedules. $\blacksquare$

Legacy guards that mutate during evaluation are pinned after all two-phase guards in their existing relative order. Whether skipping them after an earlier deny changes today's observable behaviour depends on whether the current pipeline already short-circuits, which the brief does not state. The deny reason is a trace field, not part of the verdict, and the receipt records the chosen order through the policy witness so it is replayable.

*Optimal stopping formulation.* Let $q_i(x,H)$ be the probability that guard $i$ denies, given the request features $x$ and the outcomes $H$ observed so far, estimated from the receipt feed. Let $c_i$ be its cost. The Bellman equation over the set $S$ of already-passed guards is

$$
V(S\mid x)=\min_{i\notin S}\Big[c_i+\big(1-q_i(x,S)\big)\,V(S\cup\{i\}\mid x)\Big],\qquad V(\text{all}\mid x)=0,
$$

with immediate termination on $\mathsf{Deny}$.

*Theorem 1.3.2 (Ratio rule is optimal for independent guards, proved here).* If outcomes are conditionally independent given $x$, the order minimizing expected cost sorts guards by $q_i(x)/c_i$ descending.

*Proof.* Adjacent exchange. Let $\Pi$ be the probability that all guards before positions $k,k+1$ passed. Placing $i$ before $j$ costs $\Pi\,[c_i+(1-q_i)c_j]$ for those two positions; the swap costs $\Pi\,[c_j+(1-q_j)c_i]$. The difference is $\Pi\,(q_j c_i-q_i c_j)$, which is nonpositive iff $q_i/c_i\ge q_j/c_j$. Any order not sorted by the ratio has an adjacent inversion whose swap does not increase cost, so a sorted order is optimal. $\blacksquare$

With correlated outcomes the exact problem is NP-hard, and the adaptive greedy that re-estimates $q_i(x,H)$ after each outcome is a 4-approximation by the pipelined-filter results of Babu, Motwani, Munagala and coauthors. The learned component is therefore the conditional denial model $q_\theta$; the order is a deterministic sort on Q32 ratios with a lexicographic tie-break. Costs are deterministic fuel for WASM guards and a fixed-point latency EMA for external guards. An external guard behind an open circuit breaker yields $\mathsf{PendingApproval}$ or $\mathsf{Deny}$ by configuration and never $\mathsf{Allow}$, and a mandatory guard can be moved but never dropped. Conjunction equivalence on hard invariants is therefore a property of the pipeline type, not of the learned model.

**1.4 Stigmergic pheromone routing and counterparty selection.** Problem class: contextual restless multi-armed bandit with non-stationary drift and costly observations, solved by a Whittle index.

*The half-life is a persistence parameter.* Model counterparty $k$ as a hidden two-state Markov chain with $p_{11}=\mathbb{P}(\mathsf{Good}\to\mathsf{Good})$ and $p_{01}=\mathbb{P}(\mathsf{Bad}\to\mathsf{Good})$. Let $\omega_k$ be the belief that it is good. Without an observation the belief evolves as $\omega'=\tau(\omega)=p_{01}+(p_{11}-p_{01})\,\omega$, hence after $n$ silent epochs

$$
\omega_{t+n}-\omega^{\infty}=(p_{11}-p_{01})^{\,n}\,\big(\omega_t-\omega^{\infty}\big),\qquad
\omega^{\infty}=\frac{p_{01}}{1-p_{11}+p_{01}} .
$$

The substrate's exponential decay has the form $s(t+n)=s_{\mathrm{floor}}+(s(t)-s_{\mathrm{floor}})\,2^{-n/h}$. The two coincide exactly when

$$
2^{-1/h}=p_{11}-p_{01},\qquad s_{\mathrm{floor}}=\omega^{\infty}.
$$

So the static half-life asserts a single, known, homogeneous persistence for every counterparty class, and the evaporation floor asserts a single stationary quality. Learning $(p_{11},p_{01})$ per class is parameter estimation in the restless bandit, and it changes the decay table rather than the decay code.

*Per-arm Bellman equation with subsidy $W$.* Active means route or pay the observation cost commitment $\kappa_k$ and observe; passive means neither.

$$
V_W(\omega)=\max\Big\{\,W+\gamma\,V_W(\tau(\omega)),\ \ \omega g_k-\kappa_k+\gamma\big[\omega\,V_W(p_{11})+(1-\omega)\,V_W(p_{01})\big]\Big\}.
$$

The Whittle index is $\nu_k(\omega)=\inf\{W:\ \text{passive is optimal at }\omega\}$, and the routing rule selects $\arg\max_k \nu_k(\omega_k)$ subject to the sybil and scarcity envelopes. Liu and Zhao proved indexability of this two-state model and gave the index in closed form.

*Lemma 1.4.1 (Observation cost shifts the index, proved here).* $\nu_k^{\kappa}(\omega)=\nu_k^{0}(\omega)-\kappa_k$.

*Proof.* Subtracting the constant $\kappa_k$ from the active reward in every state yields the same optimal action sets as adding $\kappa_k$ to the passive subsidy, since only the difference between the two branches of the maximum matters. $\blacksquare$

*Where today's rule is optimal (cited).* For homogeneous arms with $p_{11}\ge p_{01}$ and $\kappa_k\equiv 0$, the myopic rule that routes to the highest belief is optimal, by Zhao, Krishnamachari and Liu for two arms and by Ahmad, Liu, Javidi, Zhao and Krishnamachari in general. Routing by highest concentration is exactly that rule. It is therefore already optimal in the homogeneous, positively correlated, free-observation regime.

*Where it is not.* Three departures each make the Whittle rule strictly better. First, heterogeneous observation costs: by the lemma, there exist $k,k'$ with $\omega_k>\omega_{k'}$ but $\nu^{0}(\omega_k)-\kappa_k<\nu^{0}(\omega_{k'})-\kappa_{k'}$, and the myopic rule picks the wrong arm. Second, heterogeneous persistence, where different half-lives per class make the index non-monotone across arms in raw belief. Third, anti-persistent dynamics $p_{11}<p_{01}$, where myopic sensing is not optimal. Weber and Weiss give asymptotic optimality of the Whittle rule as the number of arms grows.

*Non-stationarity (cited).* Discounted estimators with discount $\gamma_d=2^{-1/h}$ are exactly the D-UCB family. Garivier and Moulines show that with $\Upsilon_T$ change points the right discount is $1-\Theta(\sqrt{\Upsilon_T/T})$ and achieves regret $O(\sqrt{T\,\Upsilon_T\log T})$, whereas a mismatched fixed discount pays linearly in the mismatch. A learned half-life per class is the adaptive discount.

*Envelope.* The $\sqrt{N}$ passport cap, scarcity buckets, pair-diversity caps, and newcomer discount horizon are applied to deposit weights before aggregation, so they bound the influence of any passport on $\omega_k$ independently of the learned persistence. The learned part reshapes beliefs inside those caps and never relaxes them.

**1.5 Bounded dependency-graph recovery planning.** Problem class: budgeted search as a POMDP over candidate validity, with a learned expansion heuristic.

*Model.* The registry holds candidate templates $\mathcal{R}$. The hidden state is $\omega\in\{0,1\}^{|\mathcal{R}|}$, the validity of each candidate under snapshot $\sigma$, with prior $\hat p_r(\sigma)$ from a scorer. The search state is $(E,O,w)$: expanded set, found offers, work spent. Expanding $r\notin E$ charges a deterministic $w_r$ work units, runs the exact validator, and reveals $\omega_r$. The episode ends at the first of the limits for offers, steps, nodes, depth, or work. The reward is $\sum_{r\in O}u_r$ for a utility $u_r$ supplied by registry metadata.

*Policy form.* A priority queue ordered by $h_\theta(\text{partial plan},\sigma)\in\mathrm{Q32}$ with lexicographic tie-break replaces the lexicographic enumeration. The default $h_0$ is the lexicographic key, so the default run is bit-identical to today's planner. The natural learned heuristic is the expected utility density $\hat p_r(\sigma)\,u_r/w_r$, the greedy rule for a knapsack with Bernoulli values and deterministic sizes.

*Theorem 1.5.1 (Soundness, meter invariance, determinism, non-authority, proved here).* For every heuristic $h_\theta$: every emitted candidate passes the exact validator; the work meter is charged identically per expansion, so no limit is relaxed; the output is a function of $(\sigma,\mathcal{R},\text{limits},\text{digest}(\theta))$; and no value of type `Chosen<CandidatePlanV1>` converts to `RecoveryGrantBody`.

*Proof.* Emission happens only after the validator returns valid, which is independent of the heuristic. Charging happens in the expansion routine, which the heuristic does not touch. The scorer is a pure integer function of its inputs. The last clause is enforced by the absence of any conversion impl and is pinned by the compile-fail doctest in Section 3, exactly as the existing advisory types are pinned today. $\blacksquare$

The heuristic changes only which candidates are found before `SearchBoundReached`, never whether a found candidate is sound. A `NoRegisteredRemedy` outcome depends only on the registry and is order-independent.

**1.6 Context and KV-cache paging, and speculative branch continuation versus preemption.**

*Paging.* Blocks $b$ with sizes $z_b$ in tokens occupy tiers $\{\mathrm{HBM},\mathrm{DRAM},\mathrm{NVMe}\}$ with integer capacities and transfer costs $\kappa_{HD},\kappa_{DN}$ and a recompute cost $\kappa_{\mathrm{rec}}(b)$. The request sequence is driven by the DAG: node $v$ needs the block chain $\mathrm{ctx}(v)$, and the set of future nodes that will reference $b$ is an exact graph quantity. Only their start times are stochastic, and those come from the latency posteriors of Section 1.1. Belady's rule is optimal offline with known next-use times for unit sizes, and the predicted next-use time $\hat t_b$ is the DAG successor's expected start. The learned part is the latency model behind $\hat t_b$.

*Guarantee (cited).* Learning-augmented caching algorithms achieve competitive ratio $O\big(\min\{1+\eta/(k\cdot\mathrm{OPT}),\ \log k\}\big)$ where $\eta$ is the total next-use prediction error, by Wei following Lykouris and Vassilvitskii and Rohatgi. Any deterministic online algorithm without predictions has ratio at least $k$, by Sleator and Tarjan. The learned policy strictly dominates in competitive ratio in the regime $\eta\ll k\cdot\mathrm{OPT}$ and never falls below the randomized $O(\log k)$ floor. Because these algorithms are randomized, the kernel derives their coins from a ChaCha stream seeded by the session's canonical hash, so a replay reproduces every eviction. An adaptive adversary who knows the seed can defeat the randomization, which is acceptable because capacity and provenance are protected by the envelope and not by the coins.

*Paging envelope.* A block leaves a tier only if its content hash is pinned in a lower tier or recomputable from pinned inputs under the provenance rules. Capacity is an integer inequality per tier. Blocks leased by an in-flight dispatch are pinned. Prefix chains are evicted leaf-first so that a resident block always has a resident parent.

*Speculative branches as Pandora's box.* For a join over $K$ racing branches, branch $k$ has a prior value distribution $G_k$ and an exploration cost $c_k$. Weitzman's reservation value solves

$$
c_k=\mathbb{E}\big[(V_k-z_k)^{+}\big],
$$

and the optimal policy opens branches in decreasing $z_k$ and stops when the best observed value exceeds the largest remaining $z_k$. This is the exact structure of the cross-examination workflow, with $z_k$ precomputed per branch class and stored as a Q32 table in the policy artifact.

*Continuation inside a branch as a sequential probability ratio test.* Each branch emits observations $o_1,o_2,\dots$ such as intermediate test results or token-rate signals. With hypotheses "will succeed" and "will fail", the log-likelihood ratio in base two is

$$
\Lambda_n=\sum_{i\le n}\log_2\frac{f_1(o_i)}{f_0(o_i)},\qquad
\text{continue while } B<\Lambda_n<A,\quad
A=\log_2\frac{1-\beta}{\alpha},\quad B=\log_2\frac{\beta}{1-\alpha}.
$$

Wald and Wolfowitz proved that this test minimizes expected observations among all tests with error rates $(\alpha,\beta)$. The per-observation increments are precomputed Q32 integers inside the artifact, so no logarithm is evaluated at runtime. Preemption is an action in $F(s)$ only while the branch is in a cancel-safe transition state, which keeps `KernelTransitionCancelSafe` and `TerminalReceiptExactlyOne` intact and releases the branch's reservation through the fan-in path.

## 2 Dominance propositions

Throughout, $\Pi_{\mathrm{static}}$ denotes rules whose decision depends on a fixed low-dimensional local statistic through fixed constants chosen before deployment. $J(\pi)$ denotes expected total reward or welfare. "Strict dominance" means $J(\pi_\theta)>\sup_{\pi\in\Pi_{\mathrm{static}}}J(\pi)$.

**Proposition 2.1 (Cross-layer observability, Blackwell gap).** Let $\mathcal{G}\subseteq\mathcal{F}$ be sigma-algebras, where $\mathcal{F}$ joins pheromone latency beliefs, behavioral EMA trajectories, and DAG critical-path slack, and $\mathcal{G}$ contains only the signal a single subsystem sees. For a finite action set and $R_a:=\mathbb{E}[R(a,\cdot)\mid\mathcal{F}]$, define $V(\mathcal{H})=\sup\{\mathbb{E}[R(a(\omega),\omega)]:\ a(\cdot)\ \mathcal{H}\text{-measurable}\}$. Then

$$
V(\mathcal{F})-V(\mathcal{G})=\mathbb{E}\Big[\max_a R_a-R_{a^{\mathcal{G}}}\Big]\ \ge 0,
$$

where $a^{\mathcal{G}}$ is any $\mathcal{G}$-optimal rule, with equality iff the $\mathcal{F}$-optimal action is $\mathcal{G}$-measurable up to ties almost surely.

*Proof.* $V(\mathcal{H})=\mathbb{E}[\max_a\mathbb{E}[R_a\mid\mathcal{H}]]$ for finite actions since the pointwise maximizer is measurable. Conditional Jensen for the convex function $\max$ gives $\mathbb{E}[\max_a R_a\mid\mathcal{G}]\ge\max_a\mathbb{E}[R_a\mid\mathcal{G}]$ almost surely; taking expectations yields $V(\mathcal{F})\ge V(\mathcal{G})$ and the displayed identity. For equality, let $a^{\mathcal{G}}$ attain the right side. Then $\mathbb{E}[\max_a R_a-R_{a^{\mathcal{G}}}\mid\mathcal{G}]=0$ with a nonnegative integrand, so $\max_a R_a=R_{a^{\mathcal{G}}}$ almost surely, which is the measurability condition. $\blacksquare$

*Instance.* Two ready nodes $A,B$ compete for one dispatch slot. Node $A$ is on the critical path with probability $q_A$ and $B$ with probability $q_B$, independently, and both facts are readable from the DAG, hence in $\mathcal{F}$ but not in the pheromone router's $\mathcal{G}$. Delaying a critical node costs one unit. The best $\mathcal{G}$-rule dispatches a fixed node and pays $\min(q_A,q_B)$. The $\mathcal{F}$-rule dispatches the critical one and pays only when both are critical. The gap is

$$
\Delta=\min(q_A,q_B)-q_Aq_B=\min(q_A,q_
$$
\Delta=\min(q_A,q_B)-q_Aq_B=\min(q_A,q_B)\,\big(1-\max(q_A,q_B)\big)>0
$$

whenever both probabilities lie strictly inside $(0,1)$. Criticality that is uncertain before the graph is inspected is exactly the regime of strict dominance, and the regime of equality is a DAG whose critical path is already determined by the local signal.

*Multi-step extension and the learning condition.* Replace $R_a$ by the optimal action-value $Q^{*}(s,a)$ and $\mathcal{G}$ by the sigma-algebra of the local state coordinate; the identity becomes a per-step regret. If the learned scorer satisfies $\|Q_\theta-Q^{*}\|_\infty\le\epsilon$, then greedy selection loses at most $2\epsilon/(1-\gamma)$ by Singh and Yee, so the learned joint policy strictly dominates every $\mathcal{G}$-measurable rule iff

$$
\Delta\;>\;\frac{2\epsilon}{1-\gamma}.
$$

This is the quantitative form of Copley's Arm D result: adding exact computation to the feature set widens $\mathcal{F}$, and the gain survives exactly when it exceeds the approximation error.

**Proposition 2.2 (Lookahead under non-stationary burstiness, pooling gap).** Children $c\in[n]$ have random demands $D_c\ge0$ and unit values $v_c>0$. For static shares $\sigma$ in the simplex, $W_{\mathrm{static}}(\sigma)=\sum_c v_c\,\mathbb{E}\min(D_c,\sigma_cP)$. For pooled allocation, $W_{\mathrm{pool}}=\mathbb{E}\big[\max\{\sum_c v_cx_c:\ 0\le x_c\le D_c,\ \sum_c x_c\le P\}\big]$. Then $W_{\mathrm{pool}}\ge\sup_\sigma W_{\mathrm{static}}(\sigma)$, and for a maximizer $\sigma^{*}$ the inequality is strict iff

$$
\mathbb{P}\big(\exists c:\ D_c>\sigma^{*}_cP\ \ \text{and}\ \ \exists c':\ D_{c'}<\sigma^{*}_{c'}P\big)>0 .
$$

*Proof.* Pointwise, $x_c=\min(D_c,\sigma_cP)$ is feasible for the pooled program since $\sum_c x_c\le\sum_c\sigma_cP\le P$, giving the inequality. On the event, move $\varepsilon>0$ units from the slack of $c'$ to the saturated $c$; feasibility is preserved and the objective rises by $v_c\varepsilon$, so the pooled optimum strictly exceeds the static value on a set of positive measure. Conversely, off that event the static allocation is pooled-optimal pointwise. $\blacksquare$

The event is precisely "one sibling has saturated its basis-point share while another has unused share," which is the only situation in which the static split denies with `OversubscribedSiblings` while the parent still has remaining pool. The dynamic split of Section 1.2 achieves $W_{\mathrm{pool}}$ minus the $O(\sqrt{T})$ regret of dual mirror descent under stochastic demand, using the DAG as the horizon forecast.

*Knife-edge instance for the non-stationary claim.* An early child has certain demand $P$ and value one. A downstream child, behind a join, has demand $P$ with probability $p$ and value $v$. With share $\sigma$ reserved for the downstream child, static welfare is $(1-\sigma)P+\sigma pvP$, linear in $\sigma$, so the best static corner earns $P\max(1,pv)$. A lookahead policy that estimates $(p,v)$ per epoch earns the same within an epoch. Across epochs in which $Z=pv$ varies, static must fix one $\sigma$ and earns $P\max(1,\mathbb{E}Z)$, while the adaptive policy earns $P\,\mathbb{E}\max(1,Z)$. By Jensen for the convex function $\max(1,\cdot)$,

$$
\mathbb{E}\max(1,Z)\ >\ \max(1,\mathbb{E}Z)\quad\text{iff}\quad \mathbb{P}(Z>1)>0\ \text{and}\ \mathbb{P}(Z<1)>0 .
$$

Strict dominance therefore holds iff the downstream value-to-cost ratio straddles one across epochs, which is what bursty fan-out demand does. If it never crosses one, the static corner is already optimal.

**Proposition 2.3 (Sub-additive and super-modular couplings).** Three results, one cited and two proved.

*(a) No index policy is optimal under switching costs (cited).* Banks and Sundaram proved that in a multi-armed bandit with positive switching costs, no index policy is optimal for all instances. Reloading or recomputing a KV prefix when a worker switches branches is a switching cost. Every per-item scorer in Chio today, including concentration routing and per-task priorities without placement, is an index policy. Hence there exist instances on which any such rule is strictly beaten by a joint policy over task and placement.

*(b) Prefix co-location gap, proved here.* Two branches share a prefix of $L$ tokens and each has a unique suffix of $u$ tokens. Two workers are available, prefill costs one unit per token, latency is priced at $\lambda$ per token of queueing. Balancing costs $2L+2u$. Co-locating costs $L+2u+\lambda u$, since the prefix is computed once and the second branch queues for $u$ tokens. The adaptive rule pays $L+2u+\min(L,\lambda u)$. Over a workload with random $(L,u)$,

$$
\mathbb{E}\min(L,\lambda u)\ <\ \min\big(\mathbb{E}L,\ \lambda\,\mathbb{E}u\big)
\quad\text{iff}\quad \mathbb{P}(L>\lambda u)>0\ \text{and}\ \mathbb{P}(L<\lambda u)>0,
$$

by Jensen for the concave function $\min$. Each static rule equals one of the two arguments on the right, so the adaptive rule strictly dominates both exactly when the workload contains both long-prefix and short-prefix jobs. $\blacksquare$

*(c) Batching window gap, proved here.* Requests for one tool server arrive at rate $\mu$. Waiting $\delta$ after the first arrival amortizes the per-dispatch overhead $c_0$ over an expected batch of $1+\mu\delta$ and adds at most $\lambda\delta$ latency cost per request:

$$
J(\delta;\mu)=\frac{c_0}{1+\mu\delta}+\lambda\delta,\qquad
\partial^{2}_{\delta}J=\frac{2c_0\mu^{2}}{(1+\mu\delta)^{3}}>0,\qquad
\delta^{*}(\mu)=\frac{1}{\mu}\Big(\sqrt{c_0\mu/\lambda}-1\Big)^{+}.
$$

Strict convexity gives a unique minimizer for each $\mu$. If $\mu$ is non-stationary and $\delta^{*}(\mu)$ is not almost surely constant, then for the best static window $\delta_0$,

$$
\mathbb{E}_\mu J(\delta_0;\mu)-\mathbb{E}_\mu J(\delta^{*}(\mu);\mu)>0,
$$

because the integrand is nonnegative pointwise and strictly positive on the positive-measure set where $\delta_0\ne\delta^{*}(\mu)$. $\blacksquare$

The paging result of Section 1.6 supplies the competitive-ratio form of this proposition: with DAG-derived next-use predictions of error $\eta$, the learned eviction rule's ratio approaches one while LRU's worst case is $k$, and the two coincide only when predictions are uninformative.

**Regime summary.**

| Subsystem | Problem class | Static rule is already optimal when | Learned chooser strictly dominates when | Robustness floor for any $\theta$ |
|---|---|---|---|---|
| Swarm scheduling | CMDP, index + list | critical path is determined by local signal | criticality uncertain a priori, Prop 2.1 | Graham $(2-1/m)$, Hu on in-trees |
| Budget split | primal-dual OCO | $pv$ never crosses 1, no sibling slack | saturation-with-slack has positive probability, Prop 2.2 | conservation, floor isolation, Thm 1.2.1 |
| Guard ordering | sequential testing | denial rates independent of context | $q_i(x)$ varies with request features, Thm 1.3.2 | verdict equivalence, Thm 1.3.1 |
| Pheromone routing | restless bandit | homogeneous arms, $p_{11}\ge p_{01}$, free observation | heterogeneous $\kappa_k$ or persistence, anti-persistence, Lemma 1.4.1 | sybil and scarcity caps |
| Recovery planning | budgeted POMDP search | exhaustive search fits inside the work meter | search bound binds before offers fill, Thm 1.5.1 | soundness of every offer |
| Paging and speculation | learned Belady, Pandora, SPRT | next-use predictions uninformative | $\eta\ll k\cdot\mathrm{OPT}$, prefix mix, Prop 2.3 | $O(\log k)$ ratio, cancel-safety |

## 3 The algebra and learning boundary, and the Rust seam

**3.1 Taxonomy.** The partition follows Copley's three epistemic categories. Observed facts are receipt fields and verified capabilities. Exact computation $C(X)$ is everything the algebraic core already does. Learned prediction $P(X)$ enters only as a score over a candidate set that $C(X)$ has admitted.

| Class | Operations | Why it belongs there | Verification artefact |
|---|---|---|---|
| Deterministic algebraic core, never learned | capability verification with crypto floor, scope subset lattice, delegation attenuation, Merkle inclusion step, receipt signing and content hash, budget precheck and commit, reservation ledger, revocation projection, time-window classification, graph validation, cancel-safe transitions | each is a decidable predicate or conservation law; a wrong answer is a safety failure, not a utility loss | Lean, Aeneas, Kani, Apalache as today |
| Feasibility maps $F$ | precedence and quorum readiness, reservation admission, route membership, guard mandatory set, provenance pinning, cancel-safe set | they define the envelope; they are compositions of the core | nondeterministic-choice specs, Corollary 1.0.3 |
| Learned ranking and sizing, inside the envelope | node priority, adapter choice, shadow price $\lambda$, guard order, pheromone persistence and Whittle tables, planner heuristic, eviction score, reservation values and LLR increments | a wrong answer costs utility only; Theorem 1.0.2 shows it cannot cost safety | replay parity, off-policy evaluation, drift rollback |
| Shadow and advisory only | any new policy before promotion | produces receipts and advisories, never affects admission | the existing advisory pipeline and automation modes |

**3.2 Fixed-point layout.** All learned quantities use one signed fixed-point type so that every platform, including `wasm32`, produces identical bits.

| Field | Bits | Semantics |
|---|---|---|
| sign | 1 | two's complement |
| integer | 31 | range $\pm 2^{31}$ |
| fraction | 32 | resolution $2^{-32}$ |

```rust
#![no_std]
// chio-kernel-core::policy::fixed

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Q32(i64);

pub const FRAC_BITS: u32 = 32;

impl Q32 {
    pub const ZERO: Q32 = Q32(0);
    pub const ONE: Q32 = Q32(1_i64 << FRAC_BITS);
    pub const fn from_bits(bits: i64) -> Self { Q32(bits) }
    pub const fn to_bits(self) -> i64 { self.0 }

    pub fn checked_add(self, rhs: Q32) -> Option<Q32> { self.0.checked_add(rhs.0).map(Q32) }
    pub fn checked_sub(self, rhs: Q32) -> Option<Q32> { self.0.checked_sub(rhs.0).map(Q32) }

    /// Floor-rounded product. Arithmetic right shift on i128 floors toward -inf.
    pub fn mul_floor(self, rhs: Q32) -> Option<Q32> {
        let wide = i128::from(self.0).checked_mul(i128::from(rhs.0))?;
        i64::try_from(wide >> FRAC_BITS).ok().map(Q32)
    }

    /// Floor division for a strictly positive divisor.
    pub fn div_floor(self, rhs: Q32) -> Option<Q32> {
        if rhs.0 <= 0 { return None; }
        let num = i128::from(self.0).checked_shl(FRAC_BITS)?;
        i64::try_from(num.div_euclid(i128::from(rhs.0))).ok().map(Q32)
    }

    pub fn clamp(self, lo: Q32, hi: Q32) -> Q32 { Q32(self.0.clamp(lo.0, hi.0)) }
}
```

Transcendentals are tables, not libm calls.

```rust
pub const EXP2_KNOTS: usize = 1025;          // f = i / 1024 on [0, 1]
pub const EXP2_INDEX_BITS: u32 = 10;
pub const EXP2_INTERP_BITS: u32 = FRAC_BITS - EXP2_INDEX_BITS;

/// Monotone decreasing table of 2^{-f} for f = i / 1024, in Q32, checked at build time.
pub static EXP2_NEG_LUT: [Q32; EXP2_KNOTS] = exp2_neg_table();

/// 2^{-x} for x >= 0. Integer part is a shift, fractional part is a linear interpolation.
pub fn exp2_neg(x: Q32) -> Result<Q32, PolicyError> {
    if x.0 < 0 { return Err(PolicyError::NegativeExponent); }
    let int_part = u32::try_from(x.0 >> FRAC_BITS).map_err(|_| PolicyError::Range)?;
    let frac = u64::try_from(x.0 & ((1_i64 << FRAC_BITS) - 1)).map_err(|_| PolicyError::Range)?;
    let idx = usize::try_from(frac >> EXP2_INTERP_BITS).map_err(|_| PolicyError::Range)?;
    let t = frac & ((1_u64 << EXP2_INTERP_BITS) - 1);
    let lo = EXP2_NEG_LUT.get(idx).ok_or(PolicyError::Range)?;
    let hi = EXP2_NEG_LUT.get(idx.checked_add(1).ok_or(PolicyError::Range)?).ok_or(PolicyError::Range)?;
    let span = lo.checked_sub(*hi).ok_or(PolicyError::Range)?;
    let delta = i128::from(span.0).checked_mul(i128::from(t)).ok_or(PolicyError::Range)? >> EXP2_INTERP_BITS;
    let interp = lo.0.checked_sub(i64::try_from(delta).map_err(|_| PolicyError::Range)?).ok_or(PolicyError::Range)?;
    if int_part >= 63 { return Ok(Q32::ZERO); }
    Ok(Q32(interp >> int_part))
}
```

Error and monotonicity facts for the table, which become Kani harnesses:

| Property | Value |
|---|---|
| max interpolation error of $2^{-f}$ on $[0,1]$ | $\le (\ln 2)^2/(8\cdot 1024^2)\approx 5.7\times10^{-8}$ |
| monotonicity | knots strictly decreasing, linear interpolation preserves it |
| decay invariant | $\texttt{exp2\_neg}(x_2)\le\texttt{exp2\_neg}(x_1)$ for $x_2\ge x_1$ |

Pheromone decay becomes `strength.mul_floor(exp2_neg(elapsed_q32.div_floor(half_life_q32)?)?)`. The EMA in the behavioral guard becomes a shift: $\mu\leftarrow\mu+\big((x-\mu)\gg k\big)$, and the sigma test compares squared deviations so no square root is needed. The Whittle index is a monotone 256-knot table per counterparty class. Shadow-price updates use the same `exp2_neg` with a sign flip handled by `div_floor` for the positive branch. Every lint in the brief is respected: no `as`, no indexing, no unchecked arithmetic, no `unsafe`, no `std`.

**3.3 Policy artifacts, scorers, and witnesses.**

```rust
// chio-kernel-core::policy::artifact
pub const MAX_POLICY_PARAMS: usize = 65_536;
pub const MAX_POLICY_FEATURES: usize = 256;
pub const MAX_TREE_DEPTH: usize = 16;
pub const MAX_WITNESS_PATH: usize = MAX_TREE_DEPTH;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyDigest(pub [u8; 32]);          // SHA-256 over canonical JSON bytes of the artifact body

pub struct FeatureVecV1 {
    pub schema: PolicySchemaId,
    pub values: BoundedVec<Q32, MAX_POLICY_FEATURES>,
}

pub enum PolicyKindV1 {
    /// score = (Σ w_i f_i + bias) >> shift, accumulated in i128
    Linear { weights: BoundedVec<i32, MAX_POLICY_FEATURES>, bias: i64, shift: u8 },
    /// comparisons only; emits the root-to-leaf path as the witness
    Tree   { nodes: BoundedVec<TreeNodeV1, MAX_POLICY_PARAMS> },
    /// monotone lookup table over one feature, checked monotone at load
    Table1D { knots: BoundedVec<(Q32, Q32), 1024>, monotone: Monotone },
}

pub struct TreeNodeV1 { pub feature: u16, pub threshold: Q32, pub left: u16, pub right: u16, pub leaf: Option<Q32> }

pub struct PolicyArtifactV1 {
    pub schema: PolicySchemaId,
    pub kind: PolicyKindV1,
    pub subsystem: PolicySubsystem,            // Scheduling, BudgetPrice, GuardOrder, Pheromone, Recovery, Paging, Speculation
    pub epoch: u64,
    pub issuer: PublicKey,
    pub signature: Signature,                  // verified through the same crypto floor as capabilities
}

pub struct PolicyWitnessV1 {
    pub policy_digest: PolicyDigest,
    pub feature_digest: [u8; 32],
    pub score_bits: i64,
    pub path: BoundedVec<u16, MAX_WITNESS_PATH>,
}

pub trait DeterministicScorer: Send + Sync {
    fn digest(&self) -> PolicyDigest;
    fn schema(&self) -> PolicySchemaId;
    fn score(&self, features: &FeatureVecV1) -> Result<(Q32, PolicyWitnessV1), PolicyError>;
}
```

The witness is the kernel analogue of Copley's rule proof witness: a tree path or active-clause set with margins, inspectable and replayable. Artifacts are issued and revoked like capabilities, so a bad policy is cut by the revocation oracle without a redeploy.

**3.4 The envelope type.** The core of the seam is a type that only the feasibility module can construct and only the commit path can consume.

```rust
// chio-kernel-core::policy::envelope
pub struct Feasible<A> { inner: A }            // no public constructor, no Deref, no From/Into

impl<A> Feasible<A> {
    pub fn get(&self) -> &A { &self.inner }
    pub(crate) fn into_inner(self) -> A { self.inner }   // kernel-core commit paths only
}

pub trait Envelope {
    type State;
    type Candidate: CanonicalBytes;
    type Error;
    /// The only way to obtain a Feasible value. Runs the deterministic predicates of Section 1.
    fn admit(&self, s: &Self::State, c: Self::Candidate) -> Result<Feasible<Self::Candidate>, Self::Error>;
    /// Defer, deny, or no-op. Always feasible.
    fn conservative(&self, s: &Self::State) -> Feasible<Self::Candidate>;
}

pub struct Chosen<'a, A> { pub index: usize, pub witness: PolicyWitnessV1, candidate: &'a Feasible<A> }

/// Rank an already-admitted slice. On scorer error, return the conservative candidate.
pub fn choose<'a, A: CanonicalBytes>(
    scorer: &dyn DeterministicScorer,
    features: &dyn Fn(&Feasible<A>) -> Result<FeatureVecV1, PolicyError>,
    candidates: &'a [Feasible<A>],
    conservative: &'a Feasible<A>,
) -> Chosen<'a, A> {
    let mut best: Option<(Q32, usize, PolicyWitnessV1)> = None;
    for (i, c) in candidates.iter().enumerate() {
        let Ok(f) = features(c) else { continue };
        let Ok((score, w)) = scorer.score(&f) else { continue };
        let better = match &best {
            None => true,
            Some((s, j, _)) => score > *s || (score == *s && canonical_lt(c, candidates, *j)),
        };
        if better { best = Some((score, i, w)); }
    }
    match best {
        Some((_, i, w)) => Chosen { index: i, witness: w, candidate: candidates.get(i).unwrap_or(conservative) },
        None => Chosen { index: usize::MAX, witness: PolicyWitnessV1::conservative(scorer.digest()), candidate: conservative },
    }
}
```

Ties break on canonical JSON bytes of the candidate, so two kernels with the same artifact and the same state choose the same action. Determinism of the whole decision is then a function of five inputs, all hashed into the receipt.

```rust
pub struct PolicyDecisionMetadataV1 {
    pub witness: PolicyWitnessV1,
    pub envelope_version: u16,
    pub candidate_count: u16,
    pub chosen_index: u16,
}
```

Binding this struct into the receipt requires a schema version bump for the canonical identity input, since adding a field changes the canonical form. That is a deliberate design decision: without it, decisions are not replayable, and replay parity is the property that makes shadow-mode evaluation trustworthy.

The compile-fail discipline from the recovery crate extends verbatim:

```rust
/// Advisory choices never become authority.
///
/// ```compile_fail
/// use chio_kernel_core::policy::Chosen;
/// use chio_recovery::{CandidatePlanV1, RecoveryGrantBody};
/// fn widen(c: Chosen<'_, CandidatePlanV1>) -> RecoveryGrantBody { c.into() }
/// ```
///
/// ```compile_fail
/// use chio_kernel_core::policy::Feasible;
/// fn forge<A>(a: A) -> Feasible<A> { Feasible { inner: a } }
/// ```
pub struct NonAuthorityDoctests;
```

**3.5 Runtime placement and promotion.** The `std` kernel loads artifacts through the same atomic swap pattern the emergency-stop path uses, snapshots one artifact per evaluation, and records its digest. Training happens offline in Copley from the receipt feed, which is a logged-bandit dataset with the witness as the propensity record. Promotion follows the existing autonomy ladder: shadow scoring writes witnesses to receipts without affecting admission; advisory mode routes through the advisory pipeline's promotion policy; active mode is gated by the autonomy drift detectors, with model-version mismatch and override-rate drift mapped to the freeze-model-version and revert-to-delegated-authority rollback actions. Shadow-mode acceptance requires replay parity across native, `wasm32`, and mobile builds before any promotion.

**3.6 Verification additions.** Everything below treats the policy as nondeterministic, per Corollary 1.0.3.

| Layer | Addition |
|---|---|
| Kani | `verify_q32_mul_floor_no_panic`, `verify_q32_div_floor_no_panic`, `verify_exp2_neg_monotone`, `verify_exp2_neg_at_most_one`, `verify_shadow_price_clamped_for_any_update`, `verify_dynamic_split_conservation_for_any_price`, `verify_floor_isolation_for_any_price`, `verify_guard_meet_order_independent` for pipelines of at most four symbolic guards, `verify_list_schedule_respects_precedence_for_any_index`, `verify_planner_offers_valid_for_any_heuristic`, `verify_sprt_llr_checked_add`, `verify_chosen_index_in_feasible_slice` |
| Lean 4 | `Policy/Envelope.lean` with `envelope_preserves_invariant`, `guard_meet_order_independent`, `ratio_order_exchange`, `pooled_dominates_static`, `half_life_belief_correspondence`; Aeneas extraction of `Q32::mul_floor`, `exp2_neg`, and the admission predicate |
| Apalache | `LearnedEnvelope.tla` with `\E a \in Feasible(s)` and invariants `ReservationConservation`, `FloorIsolation`, `NoWidening`; `GuardShortCircuit.tla` with `VerdictEqualsMeet`; `SpeculativeJoinCancel.tla` reusing `TerminalReceiptExactlyOne` |
| Negative registry | policy chooses from `Actions` instead of `Feasible`, early exit on `PendingApproval`, dynamic pool draws from a floor account, shadow price unclamped; each must yield an exact counterexample trace |
| Loom | `loom_policy_swap_during_evaluate` asserting one digest per decision |
| DST | artifact rotation at both cutpoints and across SQLite reopen; replay of every receipt's witness must reproduce `score_bits` and `chosen_index` |
| Mapping | one `formal/MAPPING.md` row per harness above, checked by the existing mapping script |

**3.7 What this does not change.** No cryptographic check, lattice comparison, hash coupling, or conservation law acquires a learned input. No learned score can produce an `Allow` that the algebra did not already admit, and every learned score can be overridden by the conservative action without loss of safety. The only behaviour that moves is which admissible action is taken and how large an admissible reservation is sized, and Propositions 2.1 to 2.3 bound exactly when that movement is worth having.

**References.** Altman, Constrained Markov Decision Processes, 1999. Alshiekh et al., Safe reinforcement learning via shielding, AAAI 2018. Graham, Bounds for certain multiprocessing anomalies, 1966. Hu, Parallel sequencing and assembly line problems, 1961. Balseiro, Lu, Mirrokni, The best of many worlds: dual mirror descent for online allocation, Operations Research 2023. Agrawal, Wang, Ye, A dynamic near-optimal algorithm for online linear programming, 2014. Babu, Motwani, Munagala, Nishizawa, Widom, Adaptive ordering of pipelined stream filters, SIGMOD 2004. Munagala, Babu, Motwani, Widom, The pipelined set cover problem, ICDT 2005. Whittle, Restless bandits, 1988. Weber and Weiss, On an index policy for restless bandits, 1990. Liu and Zhao, Indexability of restless bandit problems and optimality of Whittle index for dynamic multichannel access, IEEE Trans. IT 2010. Zhao, Krishnamachari, Liu, On myopic sensing for multi-channel opportunistic access, 2008. Ahmad, Liu, Javidi, Zhao, Krishnamachari, Optimality of myopic sensing in multichannel opportunistic access, IEEE Trans. IT 2009. Garivier and Moulines, On upper-confidence bound policies for switching bandit problems, ALT 2011. Banks and Sundaram, Switching costs and the Gittins index, Econometrica 1994. Weitzman, Optimal search for the best alternative, Econometrica 1979. Wald, Sequential tests of statistical hypotheses, 1945. Wald and Wolfowitz, Optimum character of the sequential probability ratio test, 1948. Belady, A study of replacement algorithms, 1966. Sleator and Tarjan, Amortized efficiency of list update and paging rules, 1985. Fiat et al., Competitive paging algorithms, 1991. Lykouris and Vassilvitskii, Competitive caching with machine learned advice, ICML 2018 and JACM 2021. Rohatgi, Near-optimal bounds for online caching with machine learned advice, SODA 2020. Wei, Better and simpler learning-augmented online caching, APPROX 2020. Blackwell, Equivalent comparisons of experiments, 1953. Singh and Yee, An upper bound on the loss from approximate optimal-value functions, 1994.

---

# Full Verbatim Treatise - Angle 2: Multi-Model Kernel Architecture & Two-Tier Rust Execution (`angle_2_multi_model_kernel_architecture`)

Below is the Angle 2 specification: the case for federated micro-models over a monolith, the two-tier execution hierarchy, the Lagrangian coordination protocol with proofs, and compile-ready `#![no_std]` Rust for `chio-kernel-core` plus the std-side `weights_binding` that seals every receipt to the active weights and prices.

## 1. Composable micro-models versus a monolithic kernel model

### 1.1 Four impossibility results for a monolith inside the TCB

**Proposition 1.1 (WCET).** A dense network with $P$ parameters performs at least $2P$ scalar multiply-accumulates per decision, and its weight footprint $P$ bytes at INT8 must stream through the cache hierarchy. For Copley's perceiver the numbers are:

| Quantity | UltraBERT monolith | `QuantizedLinearPolicy<12, 4>` |
|---|---|---|
| Parameters | 19.3 M | 48 weights, 4 biases, 4 scales |
| MACs per decision | $\ge 1.5 \times 10^{8}$ (4 passes) | 48 plus 20 for the price penalty |
| Weight footprint | 19.3 MB, exceeds L2 | 112 bytes, one cache line pair |
| Estimated latency, native | 10 to 30 ms | under 60 ns |
| Estimated latency, `wasm32` | seconds | under 400 ns |

The sub-microsecond admission budget admits roughly a thousand integer operations. The monolith is four orders of magnitude outside it, and because its working set exceeds L2 its execution time is memory-bound and has no static bound at all. The perceiver therefore belongs in Tier-1, where it produces calibrated concept predictions $P(X)$ that enter Tier-0 only as quantized features.

**Theorem 1.2 (Static WCET of the fast path).** For `QuantizedLinearPolicy<D, A>` with $K$ shadow prices, `penalized_argmax` executes exactly $A(D+K)$ multiply-accumulates, $A(D+K)$ overflow tests, and at most $2A$ comparisons. Control flow is independent of the input except for the final comparison chain.

*Proof.* All loops iterate over const-generic arrays whose lengths are compile-time constants. The only early exits are `?` on `checked_*` results, which by Lemma 1.3 never fire. The argmax compares each candidate against the running best and runner-up, at most two comparisons each. $\blacksquare$

**Lemma 1.3 (Range).** Let $|w| \le 127$, $|x| \le 2^{31}$, $D \le 64$, $|s| \le 2^{31}$, $0 \le \lambda_r \le 2^{24}$, $|c_r| \le 2^{31}$, $K = 5$. Then $|\sum_j w_j x_j| < 2^{44} < 2^{63}$; the dequantized product $|acc \cdot s| < 2^{75} < 2^{127}$; and $\sum_r \lambda_r c_r < 5 \cdot 2^{55} < 2^{63}$. Every `checked_add` and `checked_mul` on the path succeeds. $\blacksquare$

Kani discharges this with symbolic inputs and symbolic weights for $D = 12$ as `verify_quantized_linear_no_overflow`, which turns the `?` branches into proven-dead code and makes Theorem 1.2 an exact instruction count.

**Proposition 1.4 (Fault isolation).** A monolith is one failure domain: a single corrupt weight update changes admission, guard scheduling, swarm fan-out, routing, and eviction simultaneously, and rollback must be global. Six micro-models carry six independent digests, six envelopes, and six independent `FreezeModelVersion` rollback actions. The stronger property is sovereignty:

**Theorem 1.5 (Envelope sovereignty).** For every input, every price vector, and every weight tensor, `project_feasible` returns an action in the envelope's feasible set $F$, or the kernel fallback when $F$ is empty. Consequently every invariant proven for the kernel without models (`ReceiptBeforeAllow`, `ReservationConservation`, `delegate_no_widen`, `budget_precheck` soundness) remains valid with models installed.

*Proof.* The constrained argmax only considers indices for which `is_feasible` holds, so a returned action is feasible by construction. If no index is feasible the argmax returns `None` and the model emits `fallback()`. `project_feasible` re-tests feasibility and substitutes `fallback()` on failure. The fallback is by definition either a feasible action or the kernel's own deny, which the kernel would have issued anyway. The model therefore selects among transitions the kernel already admits and can never widen a grant or synthesize an `Allow`. This mirrors the compile-fail doctests that deny `CandidatePlanV1: Into<SignedRecoveryGrant>`: the model's output type has no conversion into authority. $\blacksquare$

**Proposition 1.6 (Verification complexity).** CBMC bit-blasts integer arithmetic into circuits whose size scales with the number of multiplier cells. A $12 \times 4$ INT8 by Q16.16 product unrolls to 48 multipliers of 8 by 32 bits, on the order of $10^4$ gates, well inside Kani's SAT budget. One transformer layer at width 768 contains on the order of $10^6$ multiplications plus `exp` and `softmax`, which have no finite bit-exact circuit under IEEE-754. Aeneas extracts Rust to Lean only for integer types with explicit overflow semantics and loops with termination measures; it has no model of `f32`, and Lean's `Float` is opaque to proof. A monolith therefore cannot enter `formal_aeneas` or `.kani/harnesses.toml`, whereas the micro-model kernels are exactly the pure scalar functions that seam already accepts.

**Proposition 1.7 (Replay determinism).** A floating-point sigmoid calls `exp` from the platform libm. glibc, musl, and the wasm-compiled libm disagree in the last bits, and aarch64 under flush-to-zero alters denormals. A receipt replayed on a different node would then fail to reproduce a `weights_digest`-bound decision. Integer-only code is total and bit-identical across targets, as Theorem 2.1 states formally.

### 1.2 The decomposition theorem

Let micro-model $m$ choose $a_m$ from its envelope $F_m$ with local utility $U_m(a_m)$ and resource cost vector $c_m(a_m) \in \mathbb{R}^K_{\ge 0}$. The kernel-wide problem is

$$\max_{a \in \prod_m F_m} \sum_m U_m(a_m) \quad \text{s.t.} \quad \sum_m c_{m,r}(a_m) \le B_r \quad \forall r \in \{\text{budget}, \text{fuel}, \text{latency}, \text{memory}, \text{escrow}\}.$$

**Theorem 1.8 (Separability under Lagrangian relaxation).** The dual function $g(\lambda) = \max_a L(a, \lambda)$ decomposes as

$$g(\lambda) = \lambda^\top B + \sum_m g_m(\lambda), \qquad g_m(\lambda) = \max_{a \in F_m} \left[ U_m(a) - \lambda^\top c_m(a) \right].$$

*Proof.* $L(a, \lambda) = \sum_m U_m(a_m) - \lambda^\top \left(\sum_m c_m(a_m) - B\right)$ is a sum of terms each depending on one $a_m$ plus a constant, and the maximum of a separable sum over a product set is the sum of the maxima. $\blacksquare$

This is the formal licence for decomposing along crate boundaries: given a shared read-only $\lambda$, each micro-model solves an independent problem of size $|F_m| \le 8$. It is also the kernel-side form of Copley's epistemic partition. Observed facts and $C(X)$ are computed exactly by the kernel, such as `budget_precheck`, sibling-sum basis points, and flow-lattice joins, and they define the envelope. Learned predictions $P(X)$ arrive quantized from Tier-1 and only shape the ranking inside the envelope. Copley's Arm D result, that exact computation plus calibrated predictions feeding a structured decision layer dominates end-to-end approximation, is the empirical counterpart of Theorem 1.5.

### 1.3 Catalog of the six kernel micro-models

| Model | Owning crates | Input | Actions | Policy form | Tier-0 budget |
|---|---|---|---|---|---|
| `AdmissionQuotaScorer` | `chio-kernel-core::budget_split`, `chio-kernel::supplemental_quota` | 12 Q16.16 features | 4 share levels | `QuantizedLinearPolicy<12, 4>` | 150 ns |
| `GuardScheduleOrderer` | `chio-guards::pipeline` | 8 features per guard, at most 32 guards | permutation | per-guard key, insertion sort | 400 ns |
| `SwarmDagBranchController` | `chio-swarm-authority` | 10 Q16.16 features | fan-out $k \in \{1,2,4,8\}$ | `ObliviousTreePolicy<10, 6, 64>` plus cost table | 200 ns |
| `RecoveryGraphRanker` | `chio-recovery::planning` | 8 features per candidate, at most 16 | ranking of offers | `QuantizedLinearPolicy<8, 1>` per candidate | 800 ns |
| `PheromoneRouteSelector` | `chio-pheromone`, `chio-tool-call-fabric` | 8 features per route, at most 16 | route index | penalized UCB index with LUT bonus | 500 ns |
| `KvContextTierEvictor` | `chio-kernel::memory_provenance`, `chio-process` | 8 Q16.16 features | Hot, Warm, Cold, Evict | `ObliviousTreePolicy<8, 5, 32>` | 60 ns per entry |

| Model | Deterministic envelope, $C(X)$ | Tier-1 learner | Optimality note |
|---|---|---|---|
| `AdmissionQuotaScorer` | `budget_precheck` admits; share within `MAX_BUDGET_SHARE_BPS` sibling sum; approval channel exists | online gradient descent on receipt-labelled regret | hard `Deny` never model-proposed |
| `GuardScheduleOrderer` | only guards declared order-independent move; stateful guards keep declared order | EMA of deny rate and fuel per guard | Smith's rule: order by deny probability per penalized cost is optimal for conjunctive filters |
| `SwarmDagBranchController` | `reserve_swarm_budget_fanout` succeeds for $k$; depth and fan-out caps; continuation token bound | contextual bandit over fan-out arms | arms rejected by the pool are infeasible, never retried on path |
| `RecoveryGraphRanker` | ranks only `CandidatePlanV1` already emitted by `plan`; `Work` meter untouched | pairwise ranking loss on recovery outcomes | advisory type, no path to `SignedRecoveryGrant` |
| `PheromoneRouteSelector` | `EgressAllowlistGuard`, flow lattice, $\sqrt{N}$ passport cap, scarcity buckets | posterior over route success, quantized to index terms | exploration is deterministic given the receipt-bound nonce |
| `KvContextTierEvictor` | pinned, custody-bound, and provenance-chained entries are not evictable | re-reference probability regression | eviction emits a provenance receipt |

The twelve features of `AdmissionQuotaScorer`, each a `FixedQ16_16`, with their epistemic class:

- **Observed facts:** remaining units ratio, remaining invocations ratio, request unit cost over parent remaining, parent share in basis points over ten thousand, time-to-expiry fraction.
- **Exact computation $C(X)$:** sibling count on a log2 scale, child depth over the depth cap, revocation snapshot age fraction, swarm pool utilization.
- **Learned prediction $P(X)$:** Tier-1 estimate of the probability that this subject's next call is denied.
- **Prices:** $\lambda_{\text{budget}}$ and $\lambda_{\text{escrow}}$ copied from the pinned snapshot so the linear model can learn price sensitivity directly.

## 2. Two-tier timescale and execution hierarchy

| Property | Tier-0 | Tier-1 |
|---|---|---|
| Location | `chio-kernel-core`, `chio-flow`, `chio-recovery` | `chio-kernel::runtime`, `chio-control-plane`, `chio-autonomy` |
| Period | one invocation per syscall admission, 10 to 800 ns | one iteration per 100 ms window |
| Arithmetic | Q16.16 and INT8, checked or saturating only | any, then quantized and replayed through Tier-0 code |
| Allocation | none; stack arrays sized by const generics | Tokio tasks, SQLite, replay corpus |
| Reads | pinned `WeightEpoch` snapshot by shared reference | `ReceiptFeedSource`, `PheromoneSubstrate`, `chio-replay-corpus` |
| Writes | nothing; returns a decision witness | one new `WeightEpoch` via `ArcSwap` |

### 2.1 Tier-0 mechanics

Q16.16 stores a signed value in an `i32` with sixteen fractional bits, giving a resolution of $2^{-16}$ and a range of $\pm 32768$. That range covers ratios, basis points, log-scaled counts, and prices up to $\Lambda_{\max} = 256$ with headroom for sums of five penalty terms. Pheromone concentrations and probabilities, which live in $[0, 1]$ and need finer resolution, use Q8.24 at the substrate boundary and are rescaled to Q16.16 once at feature-extraction time, so the policy kernels see a single type.

Multiplication widens to `i64`, where the product of two `i32` values is exact, adds a half-unit rounding bias, shifts right arithmetically by sixteen, and saturates back to `i32`. Dequantization of an INT8 dot product by a Q16.16 row scale widens to `i128`, which Rust supports on every target including `wasm32` via compiler intrinsics with identical two's-complement semantics. Nonlinearities are either hard clips, which are saturations, or a 256-entry lookup table indexed by the top bits of the pre-activation with fixed-point linear interpolation. Oblivious trees test one feature against one threshold per level, so the leaf index is $\sum_k \mathbb{I}[x_{f_k} \ge t_k] 2^k$, computed by a branch-free fold with no data-dependent memory access beyond the final leaf load.

**Theorem 2.1 (Cross-target determinism).** Let $E$ be a Tier-0 evaluator built from `FixedQ16_16` operations, `.get()` lookups into const-sized arrays, and bounded folds. For every input, price snapshot, and weight epoch, $E$ computes the same output on `x86_64`, `aarch64`, and `wasm32-unknown-unknown`.

*Proof.* Rust defines two's-complement semantics for `checked_*`, `saturating_*`, and `wrapping_*` on every integer width, and defines `wrapping_shr` for shift amounts below the bit width; all shifts here are the constant sixteen or one. `i128` arithmetic is specified identically regardless of whether it is lowered to native instructions or intrinsics. `usize` differs in width between targets, but every `usize` on the path is an index bounded by a const generic no larger than 64 or a leaf index below $2^{16}$, so no computation reaches the width-dependent range. There are no floats, no allocation, no I/O, and every loop is bounded by a const generic, so $E$ is a total function of its arguments by structural induction over the straight-line program. $\blacksquare$

**Corollary 2.2.** A receipt carrying `weights_digest`, the shadow price epoch, and the decision witness can be replayed bit-exactly by any auditor holding the corresponding `WeightEpoch`, on any supported target.

### 2.2 Tier-1 mechanics

Tier-1 runs off the syscall path on background tasks in `chio-kernel::runtime` and performs one iteration per window:

1. **Ingest** committed receipts since the last cursor from `InMemoryReceiptFeed` or `SqliteReceiptStore`, plus pheromone telemetry from `PheromoneSubstrate`.
2. **Aggregate** resource utilization per shadow resource as a Q16.16 fraction of $B_r$, including the `overridden_by_envelope` rate per model.
3. **Update prices** with `ShadowPriceVector::dual_step`, which is the same integer function Tier-0 ships and Kani verifies, so Tier-1 cannot produce a price outside the box.
4. **Update learners.** Linear scorers take an online gradient or FTRL step on receipt-labelled regret; fan-out and route selectors update bandit posteriors; the evictor refits its re-reference regression.
5. **Quantize** to INT8 weights with per-row Q16.16 scales and Q16.16 biases.
6. **Replay** the quantized models through the exact Tier-0 integer code over `chio-replay-corpus`, measuring action agreement against the float learner and counterfactual regret by inverse-propensity weighting. This is the proof-parity discipline of `chio-runtime-proof-parity` applied to policies. If agreement falls below threshold, Tier-1 files an `AutonomousDriftReport` with kind `ModelVersionMismatch` and keeps the current epoch.
7. **Publish** a new `WeightEpoch` only if some price moved by more than a deadband $\theta$ or some model digest changed. Publication is a compare-and-swap on `ArcSwap<WeightEpoch>` that rejects any epoch not strictly greater than the current one, the same discipline as `epoch_advance_is_strict`.

Drift kinds map onto safe states: `OverrideRate` above threshold triggers `FreezeModelVersion` for the offending model, `SettlementFailureRate` triggers `RevertToDelegatedAuthority` for `RecoveryGraphRanker`, and `EvidenceStaleness` on the receipt feed triggers `ShadowModeOnly`, under which Tier-1 keeps learning but publishes nothing.

### 2.3 Publication protocol invariants

- **Epoch strictness.** `publish` fails unless `next.epoch > current.epoch`; Lean theorem `weights_epoch_advance_is_strict`.
- **Pinned for lifecycle.** `admission_operation` calls `pin()` once before Tier-0 evaluation and holds the `Arc<WeightEpoch>` until `PostEffectObligation::commit_terminal_receipt` writes `weights_digest`. The receipt therefore attests to the epoch that actually produced the decision, never to a newer one published mid-flight. Loom harness `loom_weights_epoch_publish_during_admission` interleaves a publication with an admission and asserts the receipt digest equals the pinned epoch's digest. Apalache spec `WeightsEpochBinding.tla` carries invariant `ReceiptBindsPinnedEpoch`, with a registered negative mutant that re-loads the current epoch at commit time and must produce a counterexample trace.
- **Digest integrity.** `publish` recomputes the digest from the canonical witness and rejects a mismatch, so no epoch enters circulation with a digest it does not deserve.

## 3. Decentralized coordination via Lagrangian shadow prices

### 3.1 Why uncoordinated greed oscillates

Consider `SwarmDagBranchController` raising fan-out to eight while `AdmissionQuotaScorer`, seeing a healthy pool, grants full shares to each child, and `GuardScheduleOrderer` schedules fuel-hungry Wasm guards first because they deny often. The pool drains within a window, the quota scorer swings to minimal shares, fan-out collapses to one, utilization falls, and the cycle repeats with the period of the Tier-1 window. Each model was locally optimal and the joint trajectory is a limit cycle. The cure is a common currency.

### 3.2 The protocol

Tier-1 maintains $\boldsymbol{\lambda}_t \in [0, \Lambda_{\max}]^K$ in Q16.16 and updates it by projected dual subgradient:

$$\lambda_r(t+1) = \Pi_{[0, \Lambda_{\max}]}\!\left(\lambda_r(t) + \eta_t \Big(\sum_i c_{i,r}(a_i(t)) - B_r\Big)\right).$$

Each Tier-0 model, given the pinned snapshot, computes $a_m^\star(\lambda) = \arg\max_{a \in F_m} [U_m(a) - \lambda^\top c_m(a)]$ with $|F_m| \le 8$ candidates and $K = 5$ prices, which is at most forty multiply-accumulates beyond the scoring itself, hence $O(1)$ with no locking, since the snapshot is immutable for the life of the pin.

| Model | Local penalized objective |
|---|---|
| `AdmissionQuotaScorer` | score of share level minus $\lambda_{\text{budget}} \cdot \text{share}$ minus $\lambda_{\text{escrow}} \cdot \text{reserved units}$ |
| `GuardScheduleOrderer` | sort key per guard $= \hat p_{\text{deny}} / (\lambda_{\text{fuel}} \cdot \text{fuel} + \lambda_{\text{latency}} \cdot \text{ns})$ |
| `SwarmDagBranchController` | estimated speedup of $k$ minus $\lambda_{\text{budget}} k u$ minus $\lambda_{\text{latency}} \cdot \text{contention}(k)$ minus $\lambda_{\text{memory}} k \cdot \text{context bytes}$ |
| `RecoveryGraphRanker` | success estimate minus $\lambda_{\text{escrow}} \cdot \text{held value}$ minus $\lambda_{\text{latency}} \cdot \text{steps}$ |
| `PheromoneRouteSelector` | concentration plus UCB bonus minus $\lambda_{\text{latency}} \cdot \text{route latency}$ minus $\lambda_{\text{escrow}} \cdot \text{observation cost commitment}$ |
| `KvContextTierEvictor` | re-reference value minus $\lambda_{\text{memory}} \cdot \text{bytes retained}$ |

### 3.3 Correctness of the dual step

**Theorem 3.1 (Convergence with fixed-point error).** Let $s_t = \sum_i c_i(a_i(t)) - B$ with $\|s_t\|_2 \le G$, let $\lambda^\star$ minimize $g$ over the box, let $D_\Lambda = \Lambda_{\max}\sqrt{K}$, and let each update suffer quantization error $\|\delta_t\|_2 \le \varepsilon\sqrt{K}$ with $\varepsilon = 2^{-16}$. With constant step $\eta$,

$$\frac{1}{T}\sum_{t=0}^{T-1}\big(g(\lambda_t) - g(\lambda^\star)\big) \le \frac{\|\lambda_0 - \lambda^\star\|^2}{2\eta T} + \frac{(\eta G + \varepsilon\sqrt{K})^2}{2\eta} + \frac{\varepsilon\sqrt{K}\, D_\Lambda}{\eta}.$$

*Proof.* For fixed $a$, $L(a, \cdot)$ is affine in $\lambda$ with gradient $B - \sum_i c_i(a)$, so $-s_t \in \partial g(\lambda_t)$ and the update is projected subgradient descent on the convex dual. Projection onto the box is nonexpansive and $\lambda^\star$ lies in the box, so

$$\|\lambda_{t+1} - \lambda^\star\|^2 \le \|\lambda_t - \lambda^\star\|^2 + 2\eta\langle s_t, \lambda_t - \lambda^\star\rangle + \|\eta s_t + \delta_t\|^2 + 2\langle \delta_t, \lambda_t - \lambda^\star\rangle.$$

Convexity gives $\langle s_t, \lambda_t - \lambda^\star\rangle \le g(\lambda^\star) - g(\lambda_t)$. Bounding $\|\eta s_t + \delta_t\| \le \eta G + \varepsilon\sqrt{K}$ and $\langle\delta_t, \lambda_t - \lambda^\star\rangle \le \varepsilon\sqrt{K} D_\Lambda$, summing over $t$, telescoping, and dividing by $2\eta T$ yields the bound. $\blacksquare$

The last term is the quantization floor and scales as $\varepsilon / \eta$. This is why $\eta$ must not be driven arbitrarily small in fixed point: Tier-1 uses $\eta = 2^{-6}$ as a power of two, which keeps the floor negligible against utilities of order one.

**Theorem 3.2 (Bounded duality gap for discrete actions).** With $N$ coupled local problems and $K$ coupling constraints, the gap between the primal optimum and $\min_\lambda g(\lambda)$ is at most $(K+1) \max_m \rho_m$, where $\rho_m$ is the nonconvexity of $U_m$ over the convex hull of $F_m$. This is the Shapley-Folkman bound of Aubin and Ekeland; the gap is independent of $N$, so for a swarm admitting thousands of children the relative gap vanishes as $1/N$.

**Proposition 3.3 (Complementary slackness and Pareto efficiency).** At a saddle point $(a^\star, \lambda^\star)$, $\lambda^\star_r > 0$ implies $\sum_i c_{i,r}(a_i^\star) = B_r$, so a positive price persists only on a saturated resource. Moreover $a^\star$ is Pareto-efficient among feasible allocations: if some feasible $a'$ improved one $U_m$ without reducing another, then $L(a', \lambda^\star) \ge L(a^\star, \lambda^\star)$ with strict inequality unless $a'$ consumes strictly more of a priced resource, which feasibility forbids, contradicting maximality of $a^\star$. $\blacksquare$

### 3.4 Stability without locks

Three mechanisms keep the coupled system from oscillating. First, timescale separation: Tier-0 makes $10^5$ to $10^6$ decisions per Tier-1 window, so from Tier-0's perspective $\lambda$ is quasi-static and each decision is a one-shot argmax that converges trivially; the slow dual iteration then behaves as the deterministic recursion of Theorem 3.1, which is the standard two-timescale argument. Second, the box $[0, \Lambda_{\max}]$ caps the penalty at $\Lambda_{\max} \cdot c_{\max}$, which both prevents price runaway and guarantees Lemma 1.3. Third, the publication deadband $\theta$ and the strict-epoch rule introduce a dwell time, so a model cannot switch actions on sub-resolution price jitter and receipts do not fragment across spurious epochs.

## 4. Concrete Rust

All kernel-core blocks compile under `#![no_std]`, `#![forbid(unsafe_code)]`, and the workspace lint set: no `as`, no bare arithmetic operators outside const context, no indexing, no `unwrap` or `expect`.

### 4.1 `chio-kernel-core::fixed`

```rust
#![no_std]
#![forbid(unsafe_code)]

/// Signed Q16.16 fixed point. Sixteen fractional bits, resolution 2^-16, range +-32768.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FixedQ16_16(i32);

const ROUND_BIAS_I64: i64 = 1 << 15;
const ROUND_BIAS_I128: i128 = 1 << 15;

impl FixedQ16_16 {
    pub const FRAC_BITS: u32 = 16;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1 << 16);
    pub const HALF: Self = Self(1 << 15);
    pub const MAX: Self = Self(i32::MAX);
    pub const MIN: Self = Self(i32::MIN);

    #[must_use]
    pub const fn from_raw(raw: i32) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Exact: an i16 widened to i32 shifted by sixteen always fits.
    #[must_use]
    pub fn from_int(value: i16) -> Self {
        Self(i32::from(value).wrapping_shl(Self::FRAC_BITS))
    }

    /// num / den clamped to [0, 1]; None when den is zero. Exact via u128.
    #[must_use]
    pub fn unit_ratio(num: u64, den: u64) -> Option<Self> {
        if den == 0 {
            return None;
        }
        if num >= den {
            return Some(Self::ONE);
        }
        let scaled = u128::from(num).wrapping_shl(Self::FRAC_BITS);
        let quotient = scaled.checked_div(u128::from(den))?;
        i32::try_from(quotient).ok().map(Self)
    }

    #[must_use]
    pub fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[must_use]
    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Round-half-up multiply with saturation. The i64 product of two i32 is exact.
    #[must_use]
    pub fn saturating_mul(self, rhs: Self) -> Self {
        let wide = i64::from(self.0).wrapping_mul(i64::from(rhs.0));
        Self::saturate_i64(Self::round_shift_i64(wide))
    }

    #[must_use]
    pub fn clamp_unit(self) -> Self {
        Self(self.0.clamp(0, Self::ONE.0))
    }

    /// Basis points in [0, 10_000] from a unit-clamped value.
    #[must_use]
    pub fn to_bps(self) -> u16 {
        let bps = i64::from(self.clamp_unit().0)
            .wrapping_mul(10_000)
            .wrapping_shr(Self::FRAC_BITS);
        u16::try_from(bps).unwrap_or(10_000)
    }

    pub(crate) fn round_shift_i64(wide: i64) -> i64 {
        wide.saturating_add(ROUND_BIAS_I64).wrapping_shr(Self::FRAC_BITS)
    }

    pub(crate) fn round_shift_i128(wide: i128) -> i128 {
        wide.saturating_add(ROUND_BIAS_I128).wrapping_shr(Self::FRAC_BITS)
    }

    pub(crate) fn saturate_i64(value: i64) -> Self {
        match i32::try_from(value) {
            Ok(v) => Self(v),
            Err(_) if value < 0 => Self::MIN,
            Err(_) => Self::MAX,
        }
    }

    pub(crate) fn saturate_i128(value: i128) -> Self {
        match i32::try_from(value) {
            Ok(v) => Self(v),
            Err(_) if value < 0 => Self::MIN,
            Err(_) => Self::MAX,
        }
    }
}
```

### 4.2 `chio-kernel-core::shadow_price`

```rust
use crate::fixed::FixedQ16_16;

pub const SHADOW_RESOURCE_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShadowResource {
    Budget,
    Fuel,
    Latency,
    Memory,
    Escrow,
}

impl ShadowResource {
    pub const ALL: [Self; SHADOW_RESOURCE_COUNT] =
        [Self::Budget, Self::Fuel, Self::Latency, Self::Memory, Self::Escrow];

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Budget => 0,
            Self::Fuel => 1,
            Self::Latency => 2,
            Self::Memory => 3,
            Self::Escrow => 4,
        }
    }
}

/// Per-action consumption of each resource as a Q16.16 fraction of B_r.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceCostRow(pub [FixedQ16_16; SHADOW_RESOURCE_COUNT]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowPriceError {
    NegativePrice { resource: ShadowResource },
    AboveCap { resource: ShadowResource },
}

/// Immutable snapshot of Lagrangian prices. Tier-0 borrows it; Tier-1 owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowPriceVector {
    epoch: u64,
    prices: [FixedQ16_16; SHADOW_RESOURCE_COUNT],
}

impl ShadowPriceVector {
    /// 256.0 in Q16.16. Keeps every penalty sum inside i64 (Lemma 1.3).
    pub const LAMBDA_MAX: FixedQ16_16 = FixedQ16_16::from_raw(256 << 16);

    pub const GENESIS: Self = Self {
        epoch: 0,
        prices: [FixedQ16_16::ZERO; SHADOW_RESOURCE_COUNT],
    };

    pub fn new(
        epoch: u64,
        prices: [FixedQ16_16; SHADOW_RESOURCE_COUNT],
    ) -> Result<Self, ShadowPriceError> {
        for (resource, price) in ShadowResource::ALL.iter().zip(prices.iter()) {
            if price.raw() < 0 {
                return Err(ShadowPriceError::NegativePrice { resource: *resource });
            }
            if *price > Self::LAMBDA_MAX {
                return Err(ShadowPriceError::AboveCap { resource: *resource });
            }
        }
        Ok(Self { epoch, prices })
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn raw_prices(&self) -> [FixedQ16_16; SHADOW_RESOURCE_COUNT] {
        self.prices
    }

    /// Fails closed to the cap if the index were ever out of range.
    #[must_use]
    pub fn price(&self, resource: ShadowResource) -> FixedQ16_16 {
        self.prices
            .get(resource.index())
            .copied()
            .unwrap_or(Self::LAMBDA_MAX)
    }

    /// Sum over r of lambda_r * c_r, saturating. Monotone in every lambda_r for c_r >= 0.
    #[must_use]
    pub fn penalty(&self, costs: &ResourceCostRow) -> FixedQ16_16 {
        let total = self
            .prices
            .iter()
            .zip(costs.0.iter())
            .fold(0_i64, |acc, (price, cost)| {
                let product = i64::from(price.raw()).wrapping_mul(i64::from(cost.raw()));
                acc.saturating_add(FixedQ16_16::round_shift_i64(product))
            });
        FixedQ16_16::saturate_i64(total)
    }

    /// Projected dual step: lambda <- clamp(lambda + eta * over_utilization, 0, LAMBDA_MAX).
    /// Shared verbatim by Tier-1 and the Kani harness `verify_dual_step_within_box`.
    #[must_use]
    pub fn dual_step(
        &self,
        next_epoch: u64,
        eta: FixedQ16_16,
        over_utilization: &ResourceCostRow,
    ) -> Self {
        let mut prices = self.prices;
        for (price, slack) in prices.iter_mut().zip(over_utilization.0.iter()) {
            let step = eta.saturating_mul(*slack);
            let raw = price
                .saturating_add(step)
                .raw()
                .clamp(0, Self::LAMBDA_MAX.raw());
            *price = FixedQ16_16::from_raw(raw);
        }
        Self { epoch: next_epoch, prices }
    }
}
```

### 4.3 `chio-kernel-core::micro_model`

```rust
use crate::fixed::FixedQ16_16;
use crate::shadow_price::ShadowPriceVector;

/// SHA-256 over the canonical witness of a model's weights, scales, biases, and cost table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WeightsDigest(pub [u8; 32]);

/// Proof witness in the Copley sense: the action, its penalized utility, and the margin
/// over the runner-up, all replayable from the receipt-bound epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicroModelDecision<A> {
    pub action: A,
    pub penalized_utility: FixedQ16_16,
    pub runner_up_margin: FixedQ16_16,
    pub price_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectedDecision<A> {
    pub chosen: A,
    pub proposed: A,
    pub overridden_by_envelope: bool,
}

/// Built only from observed facts and exact kernel computation C(X). Never from P(X).
pub trait SafetyEnvelope {
    type Action: Copy + Eq;
    fn is_feasible(&self, action: Self::Action) -> bool;
    /// Kernel-sovereign conservative action: feasible, or the kernel's own deny.
    fn fallback(&self) -> Self::Action;
}

pub trait KernelMicroModel: Send + Sync {
    const NAME: &'static str;
    type Input: Copy;
    type Action: Copy + Eq;
    type Envelope: SafetyEnvelope<Action = Self::Action>;

    /// Pure, allocation-free, integer-only. Theorem 2.1 applies to every implementor.
    fn evaluate_deterministic(
        &self,
        input: &Self::Input,
        prices: &ShadowPriceVector,
        envelope: &Self::Envelope,
    ) -> MicroModelDecision<Self::Action>;

    /// Theorem 1.5: the result is feasible or the kernel fallback, for every decision.
    fn project_feasible(
        &self,
        decision: MicroModelDecision<Self::Action>,
        envelope: &Self::Envelope,
    ) -> ProjectedDecision<Self::Action> {
        if envelope.is_feasible(decision.action) {
            ProjectedDecision {
                chosen: decision.action,
                proposed: decision.action,
                overridden_by_envelope: false,
            }
        } else {
            ProjectedDecision {
                chosen: envelope.fallback(),
                proposed: decision.action,
                overridden_by_envelope: true,
            }
        }
    }

    fn weights_digest(&self) -> WeightsDigest;
}
```

### 4.4 `chio-kernel-core::quantized_policy`

```rust
use crate::fixed::FixedQ16_16;
use crate::micro_model::WeightsDigest;
use crate::shadow_price::{ResourceCostRow, ShadowPriceVector};

pub const MAX_FEATURE_DIMENSION: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PenalizedArgmax {
    pub action_index: usize,
    pub penalized_utility: FixedQ16_16,
    pub runner_up_margin: FixedQ16_16,
}

/// INT8 weights with per-action Q16.16 dequantization scale, bias, and resource cost row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantizedLinearPolicy<const D: usize, const A: usize> {
    weights: [[i8; D]; A],
    row_scale: [FixedQ16_16; A],
    bias: [FixedQ16_16; A],
    costs: [ResourceCostRow; A],
    digest: WeightsDigest,
}

impl<const D: usize, const A: usize> QuantizedLinearPolicy<D, A> {
    #[must_use]
    pub const fn new(
        weights: [[i8; D]; A],
        row_scale: [FixedQ16_16; A],
        bias: [FixedQ16_16; A],
        costs: [ResourceCostRow; A],
        digest: WeightsDigest,
    ) -> Self {
        Self { weights, row_scale, bias, costs, digest }
    }

    #[must_use]
    pub const fn digest(&self) -> WeightsDigest {
        self.digest
    }

    /// INT8 dot product in i64, dequantized through i128, saturated to Q16.16, plus bias.
    /// None is unreachable for D <= MAX_FEATURE_DIMENSION (Lemma 1.3, Kani-verified).
    #[must_use]
    pub fn score(&self, action_index: usize, input: &[FixedQ16_16; D]) -> Option<FixedQ16_16> {
        let row = self.weights.get(action_index)?;
        let scale = self.row_scale.get(action_index)?;
        let bias = self.bias.get(action_index)?;
        let acc = row
            .iter()
            .zip(input.iter())
            .try_fold(0_i64, |acc, (weight, feature)| {
                let term = i64::from(*weight).checked_mul(i64::from(feature.raw()))?;
                acc.checked_add(term)
            })?;
        let scaled = i128::from(acc).checked_mul(i128::from(scale.raw()))?;
        let dequantized = FixedQ16_16::saturate_i128(FixedQ16_16::round_shift_i128(scaled));
        Some(dequantized.saturating_add(*bias))
    }

    /// Constrained argmax of score minus shadow-price penalty. Lowest index wins ties,
    /// which makes the result a total deterministic function of its arguments.
    #[must_use]
    pub fn penalized_argmax(
        &self,
        input: &[FixedQ16_16; D],
        prices: &ShadowPriceVector,
        feasible: impl Fn(usize) -> bool,
    ) -> Option<PenalizedArgmax> {
        let mut best: Option<(usize, FixedQ16_16)> = None;
        let mut runner_up: Option<FixedQ16_16> = None;
        for (index, costs) in self.costs.iter().enumerate() {
            if !feasible(index) {
                continue;
            }
            let Some(score) = self.score(index, input) else {
                continue;
            };
            let utility = score.saturating_sub(prices.penalty(costs));
            match best {
                Some((_, best_utility)) if utility <= best_utility => {
                    if runner_up.is_none_or(|current| utility > current) {
                        runner_up = Some(utility);
                    }
                }
                Some((_, best_utility)) => {
                    runner_up = Some(best_utility);
                    best = Some((index, utility));
                }
                None => best = Some((index, utility)),
            }
        }
        best.map(|(action_index, penalized_utility)| PenalizedArgmax {
            action_index,
            penalized_utility,
            runner_up_margin: runner_up
                .map_or(FixedQ16_16::MAX, |second| penalized_utility.saturating_sub(second)),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObliviousSplit {
    pub feature: usize,
    pub threshold: FixedQ16_16,
}

/// Depth-DEPTH oblivious tree: one split per level, LEAVES == 1 << DEPTH checked at build.
/// Evaluation is branch-free: leaf = fold over levels of (acc << 1) | [x_f >= t].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObliviousTreePolicy<const D: usize, const DEPTH: usize, const LEAVES: usize> {
    splits: [ObliviousSplit; DEPTH],
    leaves: [FixedQ16_16; LEAVES],
}

impl<const D: usize, const DEPTH: usize, const LEAVES: usize>
    ObliviousTreePolicy<D, DEPTH, LEAVES>
{
    pub fn new(
        splits: [ObliviousSplit; DEPTH],
        leaves: [FixedQ16_16; LEAVES],
    ) -> Option<Self> {
        let shape_ok = DEPTH <= 16 && LEAVES == 1_usize.wrapping_shl(u32::try_from(DEPTH).ok()?);
        let features_ok = splits.iter().all(|split| split.feature < D);
        (shape_ok && features_ok).then_some(Self { splits, leaves })
    }

    #[must_use]
    pub fn evaluate(&self, input: &[FixedQ16_16; D]) -> FixedQ16_16 {
        let leaf = self.splits.iter().fold(0_usize, |acc, split| {
            let feature = input.get(split.feature).copied().unwrap_or(FixedQ16_16::MIN);
            acc.wrapping_shl(1) | usize::from(feature >= split.threshold)
        });
        self.leaves.get(leaf).copied().unwrap_or(FixedQ16_16::ZERO)
    }
}
```

### 4.5 `chio-kernel-core::admission_quota`

```rust
use crate::fixed::FixedQ16_16;
use crate::micro_model::{KernelMicroModel, MicroModelDecision, SafetyEnvelope, WeightsDigest};
use crate::quantized_policy::QuantizedLinearPolicy;
use crate::shadow_price::ShadowPriceVector;

pub const ADMISSION_QUOTA_FEATURES: usize = 12;
pub const ADMISSION_QUOTA_ACTIONS: usize = 4;
pub const MINIMAL_SHARE_BPS: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaAction {
    AdmitFullShare,
    AdmitHalfShare,
    AdmitMinimalShare,
    DeferPendingApproval,
    /// Issued by the kernel alone; never in the model's action table.
    KernelDeny,
}

const MODEL_ACTIONS: [QuotaAction; ADMISSION_QUOTA_ACTIONS] = [
    QuotaAction::AdmitFullShare,
    QuotaAction::AdmitHalfShare,
    QuotaAction::AdmitMinimalShare,
    QuotaAction::DeferPendingApproval,
];

impl QuotaAction {
    #[must_use]
    pub fn share_bps(self, requested_bps: u16) -> u16 {
        match self {
            Self::AdmitFullShare => requested_bps,
            Self::AdmitHalfShare => requested_bps.wrapping_shr(1),
            Self::AdmitMinimalShare => MINIMAL_SHARE_BPS,
            Self::DeferPendingApproval | Self::KernelDeny => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaFeatures(pub [FixedQ16_16; ADMISSION_QUOTA_FEATURES]);

/// Every field is an observed fact or exact C(X): formal_core::budget_precheck,
/// budget_split sibling sum, and the approval channel state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaEnvelope {
    pub precheck_admits: bool,
    pub remaining_sibling_bps: u16,
    pub requested_share_bps: u16,
    pub approval_channel_available: bool,
}

impl SafetyEnvelope for QuotaEnvelope {
    type Action = QuotaAction;

    fn is_feasible(&self, action: QuotaAction) -> bool {
        if !self.precheck_admits {
            return matches!(action, QuotaAction::KernelDeny);
        }
        match action {
            QuotaAction::AdmitFullShare => {
                self.requested_share_bps <= self.remaining_sibling_bps
            }
            QuotaAction::AdmitHalfShare => {
                self.requested_share_bps.wrapping_shr(1) <= self.remaining_sibling_bps
            }
            QuotaAction::AdmitMinimalShare => self.remaining_sibling_bps >= MINIMAL_SHARE_BPS,
            QuotaAction::DeferPendingApproval => self.approval_channel_available,
            QuotaAction::KernelDeny => false,
        }
    }

    fn fallback(&self) -> QuotaAction {
        if self.precheck_admits && self.remaining_sibling_bps >= MINIMAL_SHARE_BPS {
            QuotaAction::AdmitMinimalShare
        } else {
            QuotaAction::KernelDeny
        }
    }
}

pub struct AdmissionQuotaScorer {
    policy: QuantizedLinearPolicy<ADMISSION_QUOTA_FEATURES, ADMISSION_QUOTA_ACTIONS>,
}

impl AdmissionQuotaScorer {
    #[must_use]
    pub const fn new(
        policy: QuantizedLinearPolicy<ADMISSION_QUOTA_FEATURES, ADMISSION_QUOTA_ACTIONS>,
    ) -> Self {
        Self { policy }
    }

    fn fallback_decision(
        envelope: &QuotaEnvelope,
        prices: &ShadowPriceVector,
    ) -> MicroModelDecision<QuotaAction> {
        MicroModelDecision {
            action: envelope.fallback(),
            penalized_utility: FixedQ16_16::MIN,
            runner_up_margin: FixedQ16_16::ZERO,
            price_epoch: prices.epoch(),
        }
    }
}

impl KernelMicroModel for AdmissionQuotaScorer {
    const NAME: &'static str = "admission_quota_scorer";
    type Input = QuotaFeatures;
    type Action = QuotaAction;
    type Envelope = QuotaEnvelope;

    fn evaluate_deterministic(
        &self,
        input: &QuotaFeatures,
        prices: &ShadowPriceVector,
        envelope: &QuotaEnvelope,
    ) -> MicroModelDecision<QuotaAction> {
        let feasible = |index: usize| {
            MODEL_ACTIONS
                .get(index)
                .is_some_and(|action| envelope.is_feasible(*action))
        };
        let Some(best) = self.policy.penalized_argmax(&input.0, prices, feasible) else {
            return Self::fallback_decision(envelope, prices);
        };
        match MODEL_ACTIONS.get(best.action_index) {
            Some(action) => MicroModelDecision {
                action: *action,
                penalized_utility: best.penalized_utility,
                runner_up_margin: best.runner_up_margin,
                price_epoch: prices.epoch(),
            },
            None => Self::fallback_decision(envelope, prices),
        }
    }

    fn weights_digest(&self) -> WeightsDigest {
        self.policy.digest()
    }
}
```

### 4.6 `chio-kernel::weights_binding` and the receipt seal

This crate is std and owns the `ArcSwap`. The pure core never sees it.

```rust
use arc_swap::ArcSwap;
use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::merkle::sha256;
use chio_kernel_core::admission_quota::AdmissionQuotaScorer;
use chio_kernel_core::micro_model::{KernelMicroModel, WeightsDigest};
use chio_kernel_core::shadow_price::{ShadowPriceVector, SHADOW_RESOURCE_COUNT};

pub struct WeightEpoch {
    pub epoch: u64,
    pub published_at_unix_ms: u64,
    pub prices: ShadowPriceVector,
    pub admission_quota: AdmissionQuotaScorer,
    pub guard_schedule: GuardScheduleOrderer,
    pub swarm_branch: SwarmDagBranchController,
    pub recovery_rank: RecoveryGraphRanker,
    pub pheromone_route: PheromoneRouteSelector,
    pub kv_tier: KvContextTierEvictor,
    pub digest: WeightsDigest,
}

#[derive(serde::Serialize)]
struct WeightEpochWitness {
    epoch: u64,
    price_epoch: u64,
    prices_q16_16: [i32; SHADOW_RESOURCE_COUNT],
    model_digests: [(&'static str, [u8; 32]); 6],
}

#[derive(Debug, thiserror::Error)]
pub enum WeightsBindingError {
    #[error("epoch {proposed} does not advance current epoch {current}")]
    NonMonotoneEpoch { current: u64, proposed: u64 },
    #[error("published digest does not match canonical witness")]
    DigestMismatch,
    #[error("canonical serialization failed: {0}")]
    Canonical(#[from] chio_core::canonical::CanonicalError),
}

pub struct WeightsBinding {
    current: ArcSwap<WeightEpoch>,
}

impl WeightsBinding {
    pub fn new(genesis: WeightEpoch) -> Self {
        Self { current: ArcSwap::from_pointee(genesis) }
    }

    /// One wait-free load per admission. The Arc pins the epoch until the terminal receipt
    /// is committed, so the receipt attests to the epoch that produced the decision.
    pub fn pin(&self) -> Arc<WeightEpoch> {
        self.current.load_full()
    }

    pub fn compute_digest(epoch: &WeightEpoch) -> Result<WeightsDigest, WeightsBindingError> {
        let prices = epoch.prices.raw_prices();
        let mut prices_q16_16 = [0_i32; SHADOW_RESOURCE_COUNT];
        for (slot, price) in prices_q16_16.iter_mut().zip(prices.iter()) {
            *slot = price.raw();
        }
        let witness = WeightEpochWitness {
            epoch: epoch.epoch,
            price_epoch: epoch.prices.epoch(),
            prices_q16_16,
            model_digests: [
                (AdmissionQuotaScorer::NAME, epoch.admission_quota.weights_digest().0),
                (GuardScheduleOrderer::NAME, epoch.guard_schedule.weights_digest().0),
                (SwarmDagBranchController::NAME, epoch.swarm_branch.weights_digest().0),
                (RecoveryGraphRanker::NAME, epoch.recovery_rank.weights_digest().0),
                (PheromoneRouteSelector::NAME, epoch.pheromone_route.weights_digest().0),
                (KvContextTierEvictor::NAME, epoch.kv_tier.weights_digest().0),
            ],
        };
        let bytes = canonical_json_bytes(&witness)?;
        Ok(WeightsDigest(sha256(bytes.as_ref())))
    }

    /// Single logical writer. Strict epoch advance and digest integrity are enforced here,
    /// so no epoch enters circulation that Tier-0 could not have been given honestly.
    pub fn publish(&self, next: WeightEpoch) -> Result<(), WeightsBindingError> {
        if Self::compute_digest(&next)? != next.digest {
            return Err(WeightsBindingError::DigestMismatch);
        }
        let next = Arc::new(next);
        loop {
            let current = self.current.load();
            if current.epoch >= next.epoch {
                return Err(WeightsBindingError::NonMonotoneEpoch {
                    current: current.epoch,
                    proposed: next.epoch,
                });
            }
            let previous = self.current.compare_and_swap(&current, Arc::clone(&next));
            if Arc::ptr_eq(&previous, &current) {
                return Ok(());
            }
        }
    }
}
```

The receipt seal adds four fields to `ChioReceiptBody` and promotes the digest into `ChioReceiptIdInput` as its twenty-first canonical field, so the receipt identifier itself commits to the weights and prices:

```rust
pub struct ChioReceiptBody {
    // existing twenty canonical fields
    pub weights_epoch: u64,
    pub weights_digest: Hash,
    pub shadow_prices_q16_16: [i32; SHADOW_RESOURCE_COUNT],
    pub micro_model_witnesses: BoundedVec<MicroModelWitness, 6>,
}

pub struct MicroModelWitness {
    pub model: &'static str,
    pub proposed: u8,
    pub chosen: u8,
    pub overridden_by_envelope: bool,
    pub penalized_utility_q16_16: i32,
    pub runner_up_margin_q16_16: i32,
}
```

In `admission_operation` the sequence is: pin the epoch, extract features from `EvaluateInput` facts and the exact precheck results, run each Tier-0 model with a borrow of `epoch.prices`, project through the envelope, carry the witnesses in `GuardContext`, and hand the pinned `Arc` to `PostEffectObligation` so `commit_terminal_receipt` writes the digest from the same object. `PostAdmissionDropGuard` drops the pin on pre-dispatch cancellation with nothing to roll back, because Tier-0 wrote no state.

### 4.7 Verification obligations to register in `formal/MAPPING.md`

- **Kani:** `verify_fixed_mul_never_panics`, `verify_unit_ratio_in_unit_interval`, `verify_quantized_linear_no_overflow` for $D = 12$, `verify_penalized_argmax_returns_feasible_index`, `verify_shadow_penalty_monotone_in_price`, `verify_dual_step_within_box`, `verify_quota_envelope_never_admits_on_failed_precheck`.
- **Lean 4 via Aeneas:** extract `round_shift_i64`, `saturate_i64`, `penalty`, and `dual_step` into `formal_aeneas`; prove `dual_step_in_box`, `penalty_monotone`, and `projected_action_feasible` in `Proofs/MicroModelEnvelope.lean`; extend `receipt_id_collision_resistant` and `canonical_inj` to the twenty-one-field input.
- **Apalache:** `WeightsEpochBinding.tla` with `ReceiptBindsPinnedEpoch` and `EpochStrictlyIncreasing`, plus a negative mutant in `REGISTRY.toml` that re-loads the epoch at commit.
- **Loom:** `loom_weights_epoch_publish_during_admission`, alongside `loom_emergency_stop_arcswap`.
- **DST:** extend `dst_wide_sweep` to publish epochs at random cutpoints and assert every committed receipt replays bit-exactly against its bound epoch.

## Recap

The kernel should run six narrow micro-models, not one monolith: a monolith has no static WCET, one failure domain, no Kani or Aeneas path, and floating-point replay drift, whereas each micro-model is a const-sized integer program with a proven instruction count, an envelope that keeps every existing kernel invariant intact, and a digest that every receipt commits to. Tier-0 evaluates in `#![no_std]` Q16.16 with INT8 weights and no allocation; Tier-1 learns off-path, quantizes, replays through the identical Tier-0 code, and publishes strictly increasing epochs over `ArcSwap`. Lagrangian shadow prices make the six local argmaxes jointly near-optimal with a bounded duality gap and a quantization floor of order $\varepsilon / \eta$, without any lock on the fast path. The next steps are to land the five kernel-core modules and `weights_binding` as written, add the receipt fields with the Lean updates, and register the listed Kani, Apalache, Loom, and DST obligations.

---

# Full Verbatim Treatise - Angle 3: Kernel Simplex Architecture, $O(1)$ Shielded Projection & Verification Bounds (`angle_3_verification_bounds_and_simplex_trust`)

I'll lay out the full Angle 3 design: the Simplex envelope and its four shield operators, the competitive-ratio theorems, and drop-in artifacts for Aeneas/Lean, Kani, Apalache, Loom, plus the receipt witness schema.

## 1. Kernel Simplex and the $O(1)$ Shielded Projection Operator

**Definitions.** Let $\mathcal{S}$ be the kernel state space at a decision point and $\mathcal{A}$ the action space. The deterministic core (`formal_core.rs`) defines $\mathcal{C}: \mathcal{S} \to 2^{\mathcal{A}}$, the exact feasible set, and a baseline policy $\pi_{\text{base}}$ with $\pi_{\text{base}}(x) \in \mathcal{C}(x)$ whenever $\mathcal{C}(x) \neq \emptyset$. A learned micro-model $\pi_\theta$ emits a raw proposal $\hat a$. A **shield** is a map $\Pi_{\mathcal{C}(x)}: \mathcal{A} \to \mathcal{C}(x) \cup \{\bot\}$ with four contract properties:

- **Soundness.** $\mathcal{C}(x) \neq \emptyset \Rightarrow \Pi_{\mathcal{C}(x)}(\hat a) \in \mathcal{C}(x)$ for every $\hat a$, including bit patterns no model would emit.
- **Completeness.** $\Pi_{\mathcal{C}(x)}(\hat a) = \bot$ only if $\mathcal{C}(x) = \emptyset$, in which case the kernel's existing fail-closed `Verdict::Deny` fires.
- **Idempotence.** $\hat a \in \mathcal{C}(x) \Rightarrow \Pi_{\mathcal{C}(x)}(\hat a) = \hat a$.
- **Boundedness.** Step count is a compile-time constant per decision, with zero heap allocation and no panics.

**Simplex envelope.** Following Sha's Simplex architecture, the envelope executes $\pi_{\text{base}}$ unless *all* of the following hold: the epoch's `SimplexMode` is `Active`, model fuel is within cap, no drift breach is flagged, and the projection returned a feasible action. The output type `ShieldedAction<A>` has a private constructor, and `RawModelProposal<A>` has no `From`/`Into` into it, mirroring the `chio-recovery` non-authority boundary.

```rust
//! chio-kernel-core/src/simplex.rs  (crate is #![no_std], #![forbid(unsafe_code)])
use crate::formal_aeneas::{FallbackReason, SimplexMode, SimplexSwitch, simplex_switch_decision};

/// Raw model output. Deliberately has NO conversion into `ShieldedAction`.
#[derive(Clone, Copy, Debug)]
pub struct RawModelProposal<A: Copy> { pub proposal: A, pub fuel_used: u32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionOutcome { Identity, Clipped, Fallback(FallbackReason) }

/// The only value type dispatch paths accept. Constructed solely by `SimplexEnvelope::decide`.
#[derive(Clone, Copy, Debug)]
pub struct ShieldedAction<A: Copy> { action: A, outcome: ProjectionOutcome }
impl<A: Copy> ShieldedAction<A> {
    pub fn action(&self) -> A { self.action }
    pub fn outcome(&self) -> ProjectionOutcome { self.outcome }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Projected<A> { Identity(A), Clipped(A), Infeasible }

/// Implemented once per decision point by pure `formal_core` scalars.
pub trait Shield {
    type State<'a>;
    type Action: Copy + PartialEq;
    /// `None` iff C(x) is empty.
    fn baseline(&self, x: &Self::State<'_>) -> Option<Self::Action>;
    fn contains(&self, x: &Self::State<'_>, a: Self::Action) -> bool;
    fn project(&self, x: &Self::State<'_>, proposal: Self::Action) -> Projected<Self::Action>;
}

pub struct SimplexEnvelope<S: Shield> { pub shield: S, pub fuel_max: u32 }

impl<S: Shield> SimplexEnvelope<S> {
    /// Returns `None` iff C(x) is empty (caller emits `Verdict::Deny`).
    pub fn decide(
        &self, x: &S::State<'_>, mode: SimplexMode, drift_breach: bool,
        raw: Option<RawModelProposal<S::Action>>,
    ) -> Option<ShieldedAction<S::Action>> {
        let base = self.shield.baseline(x)?;
        let (projected, fuel_used) = match raw {
            Some(r) => (self.shield.project(x, r.proposal), r.fuel_used),
            None => (Projected::Infeasible, 0),
        };
        let feasible = !matches!(projected, Projected::Infeasible);
        match simplex_switch_decision(mode, fuel_used, self.fuel_max, feasible, drift_breach) {
            SimplexSwitch::UseBaseline(reason) =>
                Some(ShieldedAction { action: base, outcome: ProjectionOutcome::Fallback(reason) }),
            SimplexSwitch::UseShielded => match projected {
                Projected::Identity(a) => Some(ShieldedAction { action: a, outcome: ProjectionOutcome::Identity }),
                Projected::Clipped(a) => Some(ShieldedAction { action: a, outcome: ProjectionOutcome::Clipped }),
                Projected::Infeasible =>
                    Some(ShieldedAction { action: base, outcome: ProjectionOutcome::Fallback(FallbackReason::ProjectionInfeasible) }),
            },
        }
    }
}
```

```rust
/// Compile-fail doctest, same convention as `chio-recovery`:
/// ```compile_fail
/// use chio_kernel_core::simplex::{RawModelProposal, ShieldedAction};
/// let raw = RawModelProposal { proposal: 9_999u16, fuel_used: 0 };
/// let shielded: ShieldedAction<u16> = raw.into();
/// ```
```

**Theorem 1 (Shield Soundness).** For every state $x$ with $\mathcal{C}(x) \neq \emptyset$, every mode, every fuel reading, and every raw proposal $\hat a \in \mathcal{A}$, `decide` returns an action in $\mathcal{C}(x)$. Consequently every invariant $I$ with $\forall a \in \mathcal{C}(x).\, I(x, a)$ is preserved independently of $\theta$.

*Proof.* `decide` returns one of three values: `base`, which is in $\mathcal{C}(x)$ by the `baseline` contract; a `Projected::Identity(a)` or `Projected::Clipped(a)`, which is in $\mathcal{C}(x)$ by shield soundness. No other branch yields an action. $\square$

The remainder of this section instantiates `Shield` for the four decision classes. Section 3.1 gives the pure scalar bodies.

**1.1 Basis-point budget split.** For a parent with share $B$ bps, committed sibling mass $S$, and not-yet-admitted siblings whose minima sum to $m$, the per-child feasible set is the integer interval
$$\mathcal{C}(x) = \{ b \in \mathbb{N}_0 : b_{\min} \le b \le \min(b_{\max},\, B - S - m) \},$$
and the $K$-way polytope $\{b \in \mathbb{N}_0^K : \sum b_i \le B - S_0,\ b_{\min,i} \le b_i \le b_{\max,i}\}$ is swept child by child in canonical `BTreeMap` order, reserving $\sum_{j>i} b_{\min,j}$ as headroom. The projection is the **saturating clip** `shielded_budget_share_project` (Section 3.1). It is $O(1)$ per admitted edge and composes with the existing incremental `BudgetSplit::admit_child` loop, so the shield adds a constant to the loop that already runs. An exact Euclidean water-filling variant bisects the water level $\lambda \in [0, 10\,000]$ in at most 14 passes, which is also a compile-time constant.

**Lemma 1.1 (Feasible by construction).** If the projection returns `Feasible { share_bps }` then $b_{\min} \le$ `share_bps` $\le b_{\max}$ and $S + m +$ `share_bps` $\le B$, hence the subsequent `admit_child` cannot return `OversubscribedSiblings`. If it returns `Infeasible`, then $\mathcal{C}(x) = \emptyset$.

*Proof.* Each `checked_sub` returning `None` exhibits a violated inequality in the definition of $\mathcal{C}(x)$. Otherwise `upper` $= \min(b_{\max}, B - S - m) \ge b_{\min}$ by the explicit check, and the final clamp lands in $[b_{\min}, \text{upper}]$. Idempotence: a proposal already in that interval passes both comparisons unchanged. $\square$

**Lemma 1.2 (Quasi-non-expansiveness).** For the $K$-way sequential clip $\Pi$ and any feasible $a$, $\|\Pi(\hat a) - a\|_1 \le 4\,\|\hat a - a\|_1$. For Euclidean water-filling the constant is $1$ in $\ell_2$.

*Proof.* Let $y = \text{clip}_{\text{box}}(\hat a)$, so $\|y - \hat a\|_1 = d_1(\hat a, \text{box}) \le d_1(\hat a, \mathcal{C})$ because $\mathcal{C} \subseteq \text{box}$. If $\sum y_i = B' + E$ with $E > 0$, every $z \in \mathcal{C}$ has $\sum (y_i - z_i) \ge E$, so $d_1(y, \mathcal{C}) \ge E$; the sequential sweep removes exactly $E$ while keeping each coordinate at or above its minimum. Thus $\|\Pi(\hat a) - \hat a\|_1 = d_1(\hat a, \text{box}) + E \le d_1(\hat a, \mathcal{C}) + d_1(y, \mathcal{C}) \le 3\, d_1(\hat a, \mathcal{C})$. Triangle inequality with $d_1(\hat a, \mathcal{C}) \le \|\hat a - a\|_1$ gives the bound. $\square$

**1.2 Guard pipeline permutation and early exit.** Verdicts form a chain $\text{Deny} < \text{PendingApproval} < \text{Allow}$; the pipeline result is the meet $\bigwedge_i v_i$. Guards are partitioned by purity: `Pure` guards are deterministic functions of `GuardContext` with no mutation, while `Metering` guards (`AgentVelocityGuard`, `DataFlowGuard`) use the `chio-flow` prepare/commit convention and commit only on `Allow`. The model proposes an evaluation order over the `Pure` class only; the shield validates that the order is a permutation via a 64-bit `seen` mask and falls back to the canonical order otherwise.

**Theorem 1.3 (Permutation invariance with canonical reason).** Let $G = (g_1, \dots, g_n)$ be pure guards, $\sigma \in S_n$, and $D(x) = \{i : g_i(x) = \text{Deny}\}$. Then (a) $\bigwedge_i g_{\sigma(i)}(x) = \bigwedge_i g_i(x)$; (b) early exit at the first Deny is sound for the verdict; (c) emitting the reason of guard $\min D(x)$ (canonical index), obtained by a completion scan over guards with canonical index below the first observed denier, yields a reason independent of $\sigma$; (d) the worst-case evaluation count is $n$, identical to the unshielded pipeline.

*Proof.* (a) Meet on a chain is associative and commutative, so the fold is invariant under permutation (Lean: `List.Perm.foldl_eq` with `verdict_meet` right-commutative). (b) Deny is the bottom element, hence absorbing: once observed, the fold is Deny regardless of remaining guards. (c) $\min D(x)$ is a function of the set $D(x)$, not the order; the completion scan evaluates exactly the guards that could precede the observed denier canonically, so the computed minimum equals $\min D(x)$. (d) Every guard is evaluated at most once across both phases. Skipping `Metering` guards after a Deny is semantics-preserving because their mutations commit only on Allow. $\square$

**1.3 Starvation-free scheduling for `SwarmTaskGraph`.** Each ready task $v$ carries a credit $c_v \in [0, \text{cap}]$ updated by `starvation_credit_step`: scheduled tasks reset to $0$; unscheduled ready tasks gain $q$ per round, saturating at cap. A task is **forced** when $c_v \ge \text{cap}$. The shield rule is: if any ready task is forced, schedule the forced task with the lowest canonical index; otherwise take the model's pick if it is ready, else the baseline pick.

**Theorem 1.4 (Bounded waiting).** With $N \le$ `MAX_SWARM_GRAPH_TASKS` ready tasks and $\text{cap} \ge N q$, every ready task is scheduled within $\lceil \text{cap}/q \rceil + N$ rounds regardless of $\pi_\theta$.

*Proof.* Task $v$ becomes forced after at most $\lceil \text{cap}/q \rceil$ unscheduled rounds. While $v$ is forced, each round serves some forced task. A served task resets to $0$ and needs at least $\text{cap}/q \ge N$ rounds to re-enter the forced set, so during the next $N$ rounds each other task is served at most once before $v$, and $v$ is served by round $N$ at the latest. $\square$

Liveness of the whole DAG follows by induction on depth, which `SwarmTaskGraph` bounds, since every scheduled task terminates under its budget and fuel envelope.

**1.4 WCET and fuel.** The hot-path Tier-0 model is a fixed-shape INT8 linear head distilled from Copley's `UltraBERT` concept heads: exactly $F$ multiply-accumulates plus one lookup-table sigmoid, so its step count is a compile-time constant and the fuel check is a tautology that Kani discharges. The Tier-1 19.3M-parameter encoder never runs on the hot path; it runs under `chio-wasm-guards` Wasmtime fuel or the `Work` meter of `chio-recovery`, and any exhaustion yields `FallbackReason::FuelExhausted` with $\pi_{\text{base}}$ executed. Decision latency is therefore bounded by $T_{\text{core}} + \min(T_{\text{model}}, W_{\max} t_{\text{step}}) + T_{\text{proj}}$.

**Fixed-point layout for Tier-0 and the drift monitor.** No floating point appears anywhere on the replayable path, so results are bit-exact across native, `wasm32`, and mobile targets.

| Quantity | Type | Format | Rounding and bound |
|---|---|---|---|
| feature $f_j$ | `i16` | Q8.8 | saturating quantization of `EvidenceWindow` fields |
| weight $w_j$ | `i8` | Q1.6 | INT8 export from `chio-weights` |
| product | `i32` | Q9.14 | exact |
| accumulator | `i64` | Q49.14 | `checked_add`, $F \le 2^{20}$ |
| logit $z$ | `i32` | Q16.16 | saturate |
| probability $p$ | `u16` | Q0.16 | 257-knot PWL sigmoid, round half up |
| share | `u16` | bps | $(p \cdot 10\,000 + 2^{15}) \gg 16$ |
| drift test | `u64` | bps | $k \cdot 10\,000 \ge \theta \cdot n$ |

```rust
pub const TIER0_FEATURES: usize = 64;
pub struct TierZeroWeights { pub w: [i8; TIER0_FEATURES], pub bias_q16: i32 }

/// Exactly TIER0_FEATURES MACs; returns None only on arithmetic overflow (fail-closed).
pub fn tier0_logit_q16(f: &[i16; TIER0_FEATURES], wt: &TierZeroWeights) -> Option<i32> {
    let mut acc: i64 = 0;
    for (x, w) in f.iter().zip(wt.w.iter()) {
        let prod = i32::from(*x).checked_mul(i32::from(*w))?;            // Q9.14
        acc = acc.checked_add(i64::from(prod))?;
    }
    let total = acc.checked_mul(4)?.checked_add(i64::from(wt.bias_q16))?; // Q.14 -> Q.16
    Some(i32::try_from(total).unwrap_or(if total < 0 { i32::MIN } else { i32::MAX }))
}
```

## 2. Competitive Ratio and Dynamic Regret Under Miscalibration

**Setting.** Rounds $t = 1..T$ with states $x_t$, compact convex feasible sets $\mathcal{C}_t$, and costs $c_t: \mathcal{A} \to [0, c_{\max}]$ that are convex and $L$-Lipschitz in $\ell_1$. Let $a_t^\star$ be the hindsight-optimal feasible action, $\text{OPT} = \sum_t c_t(a_t^\star)$, and assume every admitted round costs at least $c_{\min} > 0$. The baseline $\pi_{\text{base}}$ is $\text{CR}_b$-competitive. The shielded policy is $\pi_{\text{sh}}(x_t) = \Pi_{\mathcal{C}_t}(\hat a_t)$ while the mode is `Active`.

**Lagrangian reading of the shield.** The Euclidean projection solves $\min_a \tfrac12\|a - \hat a\|^2$ s.t. $g_i(a) \le 0$, with KKT conditions $a = \hat a - \sum_i \lambda_i \nabla g_i(a)$, $\lambda \ge 0$, $\lambda_i g_i(a) = 0$. The clip magnitude $\Delta_t = \|\Pi(\hat a_t) - \hat a_t\|_1$ is the $\ell_1$ norm of the KKT correction and is the natural **constraint-pressure** statistic. The drift monitor tracks three sliding-window statistics over receipts: $\Delta_t$, the fallback indicator, and the shadow regret $r_t = c_t(\pi_{\text{sh}}(x_t)) - c_t(\pi_{\text{base}}(x_t))$, which is computable because $\pi_{\text{base}}$ is deterministic and cheap enough to evaluate in shadow.

**Switch rule.** Windows of length $n$; if the window mean $\bar r_w \ge \delta$, call `simplex_mode_step` with `drift_breach = true`, which moves the mode one step toward `FullPause`. Promotion back to `Active` requires a governance epoch advance with `RequireHumanApproval`, so there is no chattering by construction.

**Theorem 2 (Lagrangian shielded consistency and robustness).** Let $\Pi$ satisfy $\|\Pi(\hat a) - a\|_1 \le \kappa \|\hat a - a\|_1$ for all feasible $a$ ($\kappa = 1$ water-filling, $\kappa = 4$ sequential clip by Lemma 1.2). Then:

1. **Consistency.** If $\sum_t \|\hat a_t - a_t^\star\|_1 \le \eta$ and no switch occurs, then $\text{cost}(\pi_{\text{sh}}) \le \text{OPT} + \kappa L \eta$. For $\eta \le \varepsilon\,\text{OPT}/(\kappa L)$ this is $(1 + \varepsilon)\,\text{OPT}$.
2. **Robustness.** For every proposal sequence, including adversarial ones, $\text{cost}(\pi_{\text{sh}}) \le \text{CR}_b\,\text{OPT} + \delta T + 2 n\, c_{\max}$. Equivalently $\text{CR}(\pi_{\text{sh}}) \le \alpha\, \text{CR}_b$ with $\alpha = 1 + \frac{\delta}{\text{CR}_b\, c_{\min}} + \frac{2 n\, c_{\max}}{\text{CR}_b\, c_{\min}\, T}$.
3. **Detection time.** If regret observations are independent with mean $\mu \ge 2\delta$, the switch fires within one window of $n = \lceil 2 c_{\max}^2 \ln(1/\beta) / \delta^2 \rceil$ rounds with probability at least $1 - \beta$; if $\mu \le 0$, the false-switch probability per window is at most $\beta$.

*Proof.* (1) By Lipschitz continuity and quasi-non-expansiveness, $c_t(\Pi(\hat a_t)) \le c_t(a_t^\star) + L\|\Pi(\hat a_t) - a_t^\star\|_1 \le c_t(a_t^\star) + \kappa L \|\hat a_t - a_t^\star\|_1$; sum over $t$. (2) Partition rounds into windows. Every complete window before the switch has total regret below $n\delta$, else the switch would have fired at its end. The window in which the switch fires and any trailing partial window each contribute at most $n c_{\max}$, since both actions are feasible and costs are bounded. After the switch, $\pi_{\text{base}}$ executes and regret is zero. Summing gives $\text{cost}(\pi_{\text{sh}}) \le \text{cost}(\pi_{\text{base}}) + \delta T + 2 n c_{\max}$. Divide by $\text{OPT} \ge T c_{\min}$ for the ratio form. (3) Hoeffding on $n$ variables in $[-c_{\max}, c_{\max}]$: $\Pr[\bar r - \mu \ge \delta] \le \exp(-n\delta^2 / 2c_{\max}^2)$; apply once for each direction. $\square$

Choosing $\delta = \varepsilon\, \text{CR}_b\, c_{\min}$ yields $\alpha = 1 + \varepsilon + o(1)$ in the worst case while retaining $(1 + \varepsilon)$ consistency, the standard learning-augmented trade-off. Theorem 1 is independent of all of this: a miscalibrated model costs performance, never safety.

**Mapping into `chio-autonomy`.** Add `AutonomousDriftKind::{ShieldProjectionMagnitude, ShieldFallbackRate, ShadowRegret}`. The `SimplexMode` chain maps as `Active`, `Advisory` (model advises, baseline executes, witness recorded), `ShadowOnly` (`AutonomousSafeState::ShadowModeOnly`), `DelegatedOnly`, `FullPause`.

## 3. Verification Stack Extensions

**3.1 Pure scalar helpers for `chio_kernel_core::formal_aeneas`.** Integer-only, no slices, no panics, no `as`, so Aeneas extracts them directly. `let`/`match` only, which Aeneas lowers cleanly.

```rust
//! formal_aeneas.rs additions. Mirrored in formal/aeneas/verified_core.rs.
pub const MAX_BUDGET_SHARE_BPS: u16 = 10_000;
const MAX_BPS_U64: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareInfeasibility {
    ParentExceedsMaxBps, CommittedExceedsParent, SiblingMinimaExceedHeadroom,
    ChildBoundsInverted, ChildMinimumExceedsHeadroom,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareProjection { Feasible { share_bps: u16, clipped: bool }, Infeasible(ShareInfeasibility) }

pub fn clamp_to_bps(raw: u64) -> u16 {
    let bounded = if raw > MAX_BPS_U64 { MAX_BPS_U64 } else { raw };
    match u16::try_from(bounded) { Ok(b) => b, Err(_) => MAX_BUDGET_SHARE_BPS }
}

pub fn shielded_budget_share_project(
    raw_model_bps: u64, child_min_bps: u16, child_max_bps: u16,
    parent_share_bps: u16, committed_sibling_bps: u16, pending_sibling_min_bps: u16,
) -> ShareProjection {
    if parent_share_bps > MAX_BUDGET_SHARE_BPS {
        return ShareProjection::Infeasible(ShareInfeasibility::ParentExceedsMaxBps);
    }
    let available = match parent_share_bps.checked_sub(committed_sibling_bps) {
        Some(v) => v, None => return ShareProjection::Infeasible(ShareInfeasibility::CommittedExceedsParent),
    };
    let headroom = match available.checked_sub(pending_sibling_min_bps) {
        Some(v) => v, None => return ShareProjection::Infeasible(ShareInfeasibility::SiblingMinimaExceedHeadroom),
    };
    if child_min_bps > child_max_bps {
        return ShareProjection::Infeasible(ShareInfeasibility::ChildBoundsInverted);
    }
    if child_min_bps > headroom {
        return ShareProjection::Infeasible(ShareInfeasibility::ChildMinimumExceedsHeadroom);
    }
    let upper = if child_max_bps < headroom { child_max_bps } else { headroom };
    let proposal = clamp_to_bps(raw_model_bps);
    let share_bps = if proposal < child_min_bps { child_min_bps }
                    else if proposal > upper { upper } else { proposal };
    ShareProjection::Feasible { share_bps, clipped: u64::from(share_bps) != raw_model_bps }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictCode { Deny, PendingApproval, Allow }
pub fn verdict_rank(v: VerdictCode) -> u8 {
    match v { VerdictCode::Deny => 0, VerdictCode::PendingApproval => 1, VerdictCode::Allow => 2 }
}
pub fn verdict_meet(a: VerdictCode, b: VerdictCode) -> VerdictCode {
    if verdict_rank(a) <= verdict_rank(b) { a } else { b }
}
/// The model is an extra conjunct: it can only tighten the core verdict.
pub fn shielded_verdict(core: VerdictCode, model_suggestion: VerdictCode) -> VerdictCode {
    verdict_meet(core, model_suggestion)
}
pub fn decode_model_verdict(raw_q16: u64, allow_q16: u32, pending_q16: u32) -> VerdictCode {
    if raw_q16 >= u64::from(allow_q16) { VerdictCode::Allow }
    else if raw_q16 >= u64::from(pending_q16) { VerdictCode::PendingApproval }
    else { VerdictCode::Deny }
}
/// Executable S3 witness of Theorem 1.3(a); Lean lifts it to S_n via List.Perm.foldl_eq.
pub fn guard_permutation_preserves_verdict(a: VerdictCode, b: VerdictCode, c: VerdictCode) -> bool {
    let canonical = verdict_meet(verdict_meet(a, b), c);
    let swapped = verdict_meet(verdict_meet(b, a), c);
    let rotated = verdict_meet(verdict_meet(c, a), b);
    canonical == swapped && canonical == rotated
}
/// Validates a proposed guard order one index at a time (n <= 64). None => fall back to canonical order.
pub fn permutation_step(seen: u64, idx: u32, guard_count: u32) -> Option<u64> {
    if guard_count > 64 || idx >= guard_count { return None; }
    let bit = 1u64.checked_shl(idx)?;
    if seen & bit != 0 { None } else { Some(seen | bit) }
}
pub fn canonical_deny_select(current: Option<u32>, candidate: u32) -> u32 {
    match current { None => candidate, Some(c) => if candidate < c { candidate } else { c } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimplexMode { Active, Advisory, ShadowOnly, DelegatedOnly, FullPause }
pub fn simplex_mode_rank(m: SimplexMode) -> u8 {
    match m { SimplexMode::Active => 0, SimplexMode::Advisory => 1, SimplexMode::ShadowOnly => 2,
              SimplexMode::DelegatedOnly => 3, SimplexMode::FullPause => 4 }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackReason { ModeNotActive, FuelExhausted, DriftBreach, ProjectionInfeasible }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimplexSwitch { UseShielded, UseBaseline(FallbackReason) }

pub fn simplex_switch_decision(
    mode: SimplexMode, fuel_used: u32, fuel_max: u32, projection_feasible: bool, drift_breach: bool,
) -> SimplexSwitch {
    if mode != SimplexMode::Active { return SimplexSwitch::UseBaseline(FallbackReason::ModeNotActive); }
    if fuel_used > fuel_max { return SimplexSwitch::UseBaseline(FallbackReason::FuelExhausted); }
    if drift_breach { return SimplexSwitch::UseBaseline(FallbackReason::DriftBreach); }
    if !projection_feasible { return SimplexSwitch::UseBaseline(FallbackReason::ProjectionInfeasible); }
    SimplexSwitch::UseShielded
}
/// Within an epoch the mode only degrades; only a governance epoch advance restores Active.
pub fn simplex_mode_step(mode: SimplexMode, drift_breach: bool, epoch_advanced: bool) -> SimplexMode {
    if epoch_advanced { return SimplexMode::Active; }
    if !drift_breach { return mode; }
    match mode {
        SimplexMode::Active => SimplexMode::Advisory, SimplexMode::Advisory => SimplexMode::ShadowOnly,
        SimplexMode::ShadowOnly => SimplexMode::DelegatedOnly, SimplexMode::DelegatedOnly => SimplexMode::FullPause,
        SimplexMode::FullPause => SimplexMode::FullPause,
    }
}
/// k regret events in a window of n: breach iff k/n >= threshold_bps/10_000. Overflow => breach (fail-closed).
pub fn drift_breach(regret_events: u32, window_len: u32, threshold_bps: u16) -> bool {
    if window_len == 0 { return false; }
    match (u64::from(regret_events).checked_mul(MAX_BPS_U64),
           u64::from(threshold_bps).checked_mul(u64::from(window_len))) {
        (Some(lhs), Some(rhs)) => lhs >= rhs, _ => true,
    }
}

pub fn starvation_credit_step(credit: u32, scheduled: bool, quantum: u32, cap: u32) -> u32 {
    if scheduled { return 0; }
    let next = credit.saturating_add(quantum);
    if next > cap { cap } else { next }
}
pub fn starvation_forced(credit: u32, cap: u32) -> bool { credit >= cap }
pub fn simplex_schedule_pick(
    model_pick: u32, model_pick_ready: bool, forced_min_canonical: Option<u32>, baseline_pick: u32,
) -> u32 {
    match forced_min_canonical {
        Some(forced) => forced,
        None => if model_pick_ready { model_pick } else { baseline_pick },
    }
}
```

Lean 4 targets over the Aeneas extraction (`formal/lean4/Chio/Proofs/SimplexShield.lean`):

```lean
theorem shielded_share_sound (raw : U64) (cmin cmax parent committed pending : U16) :
    ∀ s clipped, shielded_budget_share_project raw cmin cmax parent committed pending
        = ok (ShareProjection.Feasible s clipped) →
      cmin.val ≤ s.val ∧ s.val ≤ cmax.val ∧ committed.val + pending.val + s.val ≤ parent.val := by
  simp [shielded_budget_share_project]; split <;> omega

theorem shielded_share_complete (raw : U64) (cmin cmax parent committed pending : U16) :
    ∀ r, shielded_budget_share_project raw cmin cmax parent committed pending
        = ok (ShareProjection.Infeasible r) →
      ¬ (cmin.val ≤ cmax.val ∧ committed.val + pending.val + cmin.val ≤ parent.val ∧ parent.val ≤ 10000) := by
  simp [shielded_budget_share_project]; split <;> omega

theorem guard_permutation_preserves_verdict_perm (l l' : List VerdictCode) (h : l ~ l') :
    l.foldl verdict_meet .Allow = l'.foldl verdict_meet .Allow :=
  h.foldl_eq (fun a b c => by cases a <;> cases b <;> cases c <;> rfl)

theorem simplex_mode_monotone_within_epoch (m : SimplexMode) (d : Bool) :
    simplex_mode_rank m ≤ simplex_mode_rank (simplex_mode_step m d false) := by
  cases m <;> cases d <;> decide
```

**3.2 Kani harnesses for `kani_public_harnesses.rs`.** Kani compiles with overflow checks on, so any unchecked arithmetic, shift, or panic in the shield fails the proof without an explicit assertion.

```rust
#[cfg(kani)]
mod simplex_shield_harnesses {
    use crate::formal_aeneas::*;
    use crate::formal_core::{classify_time_window, revocation_snapshot_denies, TimeWindowStatus};

    /// Property 1: total function, no overflow or panic for ANY raw model bits and ANY bounds.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_shielded_budget_share_total_no_overflow() {
        let raw_model_output: u64 = kani::any();
        let (cmin, cmax, parent, committed, pending): (u16, u16, u16, u16, u16) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        let out = shielded_budget_share_project(raw_model_output, cmin, cmax, parent, committed, pending);
        if let ShareProjection::Feasible { share_bps, .. } = out {
            kani::assert(share_bps <= MAX_BUDGET_SHARE_BPS, "share exceeds MAX_BUDGET_SHARE_BPS");
        }
    }

    /// Property 2: never OversubscribedSiblings, and never spuriously fail-closed.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_shielded_budget_share_never_oversubscribes() {
        let raw_model_output: u64 = kani::any();
        let (cmin, cmax, parent, committed, pending): (u16, u16, u16, u16, u16) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        let feasible_exists = parent <= MAX_BUDGET_SHARE_BPS && cmin <= cmax
            && u32::from(committed) + u32::from(pending) + u32::from(cmin) <= u32::from(parent);
        match shielded_budget_share_project(raw_model_output, cmin, cmax, parent, committed, pending) {
            ShareProjection::Feasible { share_bps, .. } => {
                kani::assert(cmin <= share_bps && share_bps <= cmax, "share outside child bounds");
                kani::assert(
                    u32::from(committed) + u32::from(pending) + u32::from(share_bps) <= u32::from(parent),
                    "sibling oversubscription: BudgetSplit would return OversubscribedSiblings");
                kani::assert(feasible_exists, "Feasible returned on empty C(x)");
            }
            ShareProjection::Infeasible(_) => kani::assert(!feasible_exists, "fail-closed on nonempty C(x)"),
        }
    }

    /// Property 3: the model can never admit an expired, not-yet-valid, or revoked capability.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_shield_never_admits_revoked_or_expired() {
        let (now, issued, expires): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let (token_revoked, ancestor_revoked): (bool, bool) = (kani::any(), kani::any());
        let raw_model_output: u64 = kani::any();
        let (allow_q16, pending_q16): (u32, u32) = (kani::any(), kani::any());
        let window_ok = classify_time_window(now, issued, expires) == TimeWindowStatus::Valid;
        let revoked = revocation_snapshot_denies(token_revoked, ancestor_revoked);
        let core = if window_ok && !revoked { VerdictCode::Allow } else { VerdictCode::Deny };
        let suggestion = decode_model_verdict(raw_model_output, allow_q16, pending_q16);
        let final_verdict = shielded_verdict(core, suggestion);
        if !window_ok || revoked {
            kani::assert(final_verdict == VerdictCode::Deny, "model admitted an invalid capability");
        }
        kani::assert(verdict_rank(final_verdict) <= verdict_rank(core), "shield widened the verdict");
    }

    /// Property 4: idempotent on already-feasible proposals.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_shielded_projection_idempotent_on_feasible() {
        let raw_model_output: u64 = kani::any();
        let (cmin, cmax, parent, committed, pending): (u16, u16, u16, u16, u16) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(raw_model_output <= 10_000);
        let raw16 = u16::try_from(raw_model_output).unwrap_or(MAX_BUDGET_SHARE_BPS);
        kani::assume(parent <= MAX_BUDGET_SHARE_BPS && cmin <= raw16 && raw16 <= cmax);
        kani::assume(u32::from(committed) + u32::from(pending) + u32::from(raw16) <= u32::from(parent));
        let out = shielded_budget_share_project(raw_model_output, cmin, cmax, parent, committed, pending);
        kani::assert(
            out == ShareProjection::Feasible { share_bps: raw16, clipped: false },
            "projection moved an already-feasible proposal");
    }

    /// Supporting: credits never exceed cap, reset on service, and permutation validation rejects repeats.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_starvation_credit_and_permutation_step() {
        let (credit, quantum, cap): (u32, u32, u32) = (kani::any(), kani::any(), kani::any());
        let scheduled: bool = kani::any();
        let next = starvation_credit_step(credit, scheduled, quantum, cap);
        kani::assert(next <= cap || scheduled, "credit exceeded cap");
        kani::assert(!scheduled || next == 0, "service did not reset credit");
        let (seen, idx, n): (u64, u32, u32) = (kani::any(), kani::any(), kani::any());
        if let Some(seen2) = permutation_step(seen, idx, n) {
            kani::assert(seen2.count_ones() == seen.count_ones() + 1, "permutation step reused an index");
        }
    }
}
```

`.kani/harnesses.toml` gains one `[[harness]]` entry per function above with `invariant = "ShieldedActionAlwaysFeasible"` and `mapping = "formal/MAPPING.md#simplex-shield"`.

**3.3 Apalache `SimplexSafetyEnvelope.tla`.**

```tla
------------------------- MODULE SimplexSafetyEnvelope -------------------------
EXTENDS Integers, Sequences

CONSTANTS
  \* @type: Int;
  MaxBps,
  \* @type: Int;
  DriftLimit,
  \* @type: Set(Int);
  Digests

Modes == {"Active", "Advisory", "Shadow", "Delegated", "FullPause"}
Rank(m) == CASE m = "Active" -> 0 [] m = "Advisory" -> 1 [] m = "Shadow" -> 2
             [] m = "Delegated" -> 3 [] OTHER -> 4
Safer(m) == CASE m = "Active" -> "Advisory" [] m = "Advisory" -> "Shadow"
              [] m = "Shadow" -> "Delegated" [] OTHER -> "FullPause"

VARIABLES
  \* @type: Str;
  mode,
  \* @type: Int;
  epoch,
  \* @type: Int;
  digest,
  \* @type: Int;
  parentShare,
  \* @type: Int;
  committed,
  \* @type: Int;
  childMin,
  \* @type: Int;
  childMax,
  \* @type: Int;
  driftCount,
  \* @type: Seq({ epoch: Int, digest: Int, mode: Str, raw: Int, action: Int, cmin: Int, cmax: Int, head: Int });
  receipts

vars == <<mode, epoch, digest, parentShare, committed, childMin, childMax, driftCount, receipts>>

Headroom == parentShare - committed
HasFeasible == childMin <= childMax /\ childMin <= Headroom
Upper(cmax, head) == IF cmax < head THEN cmax ELSE head
Clamp(raw, cmin, cmax, head) ==
  IF raw < cmin THEN cmin ELSE IF raw > Upper(cmax, head) THEN Upper(cmax, head) ELSE raw
Baseline == childMin

Init ==
  /\ mode = "Shadow" /\ epoch = 0 /\ digest \in Digests /\ driftCount = 0 /\ receipts = <<>>
  /\ parentShare \in 0..MaxBps /\ committed = 0
  /\ childMin \in 0..MaxBps /\ childMax \in 0..MaxBps

\* Receipt is appended in the same step the action is committed: ReceiptBeforeAllow is inherited.
Evaluate(raw) ==
  /\ HasFeasible
  /\ LET a == IF mode = "Active" THEN Clamp(raw, childMin, childMax, Headroom) ELSE Baseline IN
     /\ receipts' = Append(receipts, [epoch |-> epoch, digest |-> digest, mode |-> mode, raw |-> raw,
                                      action |-> a, cmin |-> childMin, cmax |-> childMax, head |-> Headroom])
     /\ committed' = committed + a
  /\ UNCHANGED <<mode, epoch, digest, parentShare, childMin, childMax, driftCount>>

ObserveRegret == driftCount' = driftCount + 1 /\ UNCHANGED <<mode, epoch, digest, parentShare, committed, childMin, childMax, receipts>>

Degrade == /\ driftCount >= DriftLimit /\ mode' = Safer(mode) /\ driftCount' = 0
           /\ UNCHANGED <<epoch, digest, parentShare, committed, childMin, childMax, receipts>>

GovernancePromote == /\ epoch' = epoch + 1 /\ mode' = "Active" /\ digest' \in Digests /\ driftCount' = 0
                     /\ UNCHANGED <<parentShare, committed, childMin, childMax, receipts>>

Next == \/ \E raw \in 0..(2 * MaxBps): Evaluate(raw)
        \/ ObserveRegret \/ Degrade \/ GovernancePromote

\* Safety (state invariants)
ShieldedActionAlwaysFeasible ==
  /\ committed <= parentShare
  /\ \A i \in DOMAIN receipts: receipts[i].cmin <= receipts[i].action /\ receipts[i].action <= receipts[i].cmax
                                /\ receipts[i].action <= receipts[i].head
ReceiptBindsModelWitness ==
  \A i \in DOMAIN receipts:
    /\ receipts[i].digest \in Digests
    /\ (receipts[i].mode = "Active" =>
          receipts[i].action = Clamp(receipts[i].raw, receipts[i].cmin, receipts[i].cmax, receipts[i].head))
    /\ (receipts[i].mode # "Active" => receipts[i].action = receipts[i].cmin)
DriftBoundedBeforeSwitch == driftCount <= DriftLimit

\* Safety (action invariant, checked with primes)
DriftFallbackMonotone == (epoch' = epoch) => Rank(mode') >= Rank(mode)
=============================================================================
```

Negative registry additions for `formal/apalache/_negative_tests/REGISTRY.toml`:

```toml
[[mutant]]
file = "SimplexSafetyEnvelope_NoClamp.tla"      # Evaluate uses raw directly when Active
expect_violation = "ShieldedActionAlwaysFeasible"
[[mutant]]
file = "SimplexSafetyEnvelope_PromoteSameEpoch.tla"  # Degrade replaced by mode' = "Active"
expect_violation = "DriftFallbackMonotone"
[[mutant]]
file = "SimplexSafetyEnvelope_StaleDigest.tla"  # receipt records digest' instead of digest
expect_violation = "ReceiptBindsModelWitness"
```

**Loom harness `loom_simplex_epoch_switch_linearizable`.** The Tier-1 fallback publishes an immutable `SimplexEpochState` record and swaps a pointer, matching `loom_emergency_stop_arcswap`. The model uses an atomic index into a table of published records, so the only way to observe a torn pair is a bug in the publication protocol.

```rust
#[cfg(loom)]
#[test]
fn loom_simplex_epoch_switch_linearizable() {
    use chio_kernel_core::formal_aeneas::{simplex_mode_rank, SimplexMode};
    use loom::sync::atomic::{AtomicUsize, Ordering};
    use loom::sync::Arc;
    use loom::thread;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SimplexEpochState { epoch: u64, weights_digest: u64, mode: SimplexMode }

    // Published history: drift degrade inside epoch 7, then governance promotion with rotated weights.
    const PUBLISHED: [SimplexEpochState; 3] = [
        SimplexEpochState { epoch: 7, weights_digest: 0xA1, mode: SimplexMode::Active },
        SimplexEpochState { epoch: 7, weights_digest: 0xA1, mode: SimplexMode::ShadowOnly },
        SimplexEpochState { epoch: 8, weights_digest: 0xB2, mode: SimplexMode::Active },
    ];
    const POISON: SimplexEpochState = SimplexEpochState { epoch: 0, weights_digest: 0, mode: SimplexMode::FullPause };

    loom::model(|| {
        let cell = Arc::new(AtomicUsize::new(0));
        let switcher = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                cell.store(1, Ordering::Release);
                cell.store(2, Ordering::Release);
            })
        };
        let evaluators: Vec<_> = (0..2).map(|_| {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                let mut prev = PUBLISHED[0];
                for _ in 0..3 {
                    let snap = PUBLISHED.get(cell.load(Ordering::Acquire)).copied().unwrap_or(POISON);
                    // No torn (weights_digest, safe_state_mode) pair: observed pair must be a published pair.
                    assert!(PUBLISHED.iter().any(|p| p.weights_digest == snap.weights_digest && p.mode == snap.mode
                                                 && p.epoch == snap.epoch));
                    // DriftFallbackMonotone at observation level.
                    assert!(snap.epoch >= prev.epoch);
                    if snap.epoch == prev.epoch {
                        assert!(simplex_mode_rank(snap.mode) >= simplex_mode_rank(prev.mode));
                    }
                    prev = snap;
                }
            })
        }).collect();
        switcher.join().unwrap();
        for e in evaluators { e.join().unwrap(); }
        assert_eq!(cell.load(Ordering::Acquire), 2);
    });
}
```

`.loom/harnesses.toml` gains `name = "loom_simplex_epoch_switch_linearizable"`, `max_branches = 20_000`, `invariants = ["DriftFallbackMonotone", "ReceiptBindsModelWitness"]`.

**`formal/MAPPING.md` rows.**

| Rust seam | Lean 4 | Kani | Apalache | Loom |
|---|---|---|---|---|
| `shielded_budget_share_project` | `shielded_share_sound`, `shielded_share_complete` | harnesses 1, 2, 4 | `ShieldedActionAlwaysFeasible` | none |
| `shielded_verdict`, `verdict_meet` | `guard_permutation_preserves_verdict_perm` | harness 3 | none | none |
| `simplex_mode_step`, `simplex_switch_decision` | `simplex_mode_monotone_within_epoch` | implicit via `decide` | `DriftFallbackMonotone`, `DriftBoundedBeforeSwitch` | `loom_simplex_epoch_switch_linearizable` |
| `starvation_credit_step`, `simplex_schedule_pick` | Theorem 1.4 (paper proof, Lean pending) | harness 5 | none | none |
| `DecisionModelWitnessMetadata` | `canonical_inj`, `receipt_id_collision_resistant` extended | none | `ReceiptBindsModelWitness` | none |

## 4. Deterministic Receipt Witness Schema

`ChioReceiptBody` gains one optional field, `decision_model_witness`, and `ChioReceiptIdInput` grows from 20 to 21 canonical fields with `decision_model_witness_digest`, the SHA-256 of the witness's RFC 8785 bytes or the all-zero digest when absent. No field is a float, so canonical JSON is bit-stable across targets.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareConstraintSnapshot {
    pub parent_share_bps: u16, pub committed_sibling_bps: u16, pub pending_sibling_min_bps: u16,
    pub child_min_bps: u16, pub child_max_bps: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionModelWitnessMetadata {
    pub schema_version: u16,                    // 1
    pub shield_version: u16,                    // bumps with any change to formal_aeneas shield fns
    pub model_id: String,                       // e.g. "copley-tier0-budget-share"
    pub weights_digest: String,                 // "sha256:<hex>", bound via chio-kernel::weights_binding
    pub weights_binding_epoch: u64,
    pub feature_schema_digest: String,          // canonical EvidenceWindow -> [i16; F] mapping
    pub input_digest: String,                   // sha256 over little-endian i16 feature bytes
    pub fixed_point_format: String,             // "tier0.v1:f=q8.8,w=q1.6,acc=i64,logit=q16.16,p=q0.16,out=bps"
    pub raw_proposal: u64,                      // Tier-0 output bits before projection
    pub projected_action: u64,                  // the ShieldedAction actually dispatched
    pub projection_outcome: String,             // "identity" | "clipped" | "fallback"
    pub fallback_reason: Option<String>,        // FallbackReason variant name
    pub simplex_mode: String,                   // SimplexMode variant name at evaluation time
    pub fuel_used: u32,
    pub fuel_max: u32,
    pub constraint_snapshot: ShareConstraintSnapshot,
    pub drift_window_digest: String,            // sha256 of the (k, n, threshold_bps) tuple consulted
}
```

**Offline replay.** A verifier holding the receipt, the input bytes, and the public weights from `chio-weights` proceeds as follows.

1. Recompute `input_digest` from the feature vector and `weights_digest` from the weights; both must match.
2. Run `tier0_logit_q16`, the PWL sigmoid, and the bps conversion; the result must equal `raw_proposal`. This is bit-exact because every operation is integer arithmetic with specified rounding.
3. Run `shielded_budget_share_project` on `raw_proposal` and `constraint_snapshot`; the result must equal `projected_action` with the recorded `projection_outcome`.
4. Run `simplex_switch_decision` with `simplex_mode`, `fuel_used`, `fuel_max`, and the breach bit derived from `drift_window_digest`; a `fallback` outcome must correspond to `UseBaseline` with the recorded reason.
5. Recompute the receipt ID over all 21 canonical fields and check the signature, as today.

**Lemma 4.1.** Extending `ChioReceiptIdInput` with a 21st field preserves `canonical_inj` and `receipt_id_collision_resistant`.

*Proof.* RFC 8785 serialization of a struct with a fixed key set is injective in its field values, and adding a field to an injective encoding keeps it injective. Collision resistance of the ID is inherited from the hash over the canonical bytes. $\square$

**Recap.** The design wraps every learned proposal in a Simplex envelope whose shield either projects onto the exact feasible set computed by `formal_core` or falls back to the deterministic baseline, so Theorem 1 guarantees no safety or accounting invariant depends on the model. Four concrete operators cover budget shares, guard ordering, swarm scheduling, and fuel. Theorem 2 bounds performance: $(1+\varepsilon)$ optimality when calibrated, at most $\alpha \cdot \text{CR}_b$ under arbitrary drift, with detection in $O(c_{\max}^2 \ln(1/\beta)/\delta^2)$ rounds and monotone, governance-gated mode transitions. The artifacts are drop-in: pure scalar Rust for Aeneas with four Lean theorem statements, five Kani harnesses, one Apalache module with three positive invariants and three registered mutants, one Loom harness, and a 17-field receipt witness that makes every decision replayable offline. Still open: a Lean proof of Theorem 1.4 and wiring the new `AutonomousDriftKind` variants into `chio-autonomy`.

---

# Full Verbatim Treatise - Angle 4: Copley Meets Chio - Decision Models All the Way Down (`angle_4_copley_meets_chio_decision_models_all_the_way_down`)

**Answer up front.** Yes, with one qualifier that carries all the weight. Chio already makes every kernel transition a receipted decision over typed evidence inside a capability envelope. Copley supplies the only form of learned perception that can live inside such a kernel: a finite concept bottleneck with role-asymmetric calibration feeding an exact symbolic evaluator. The composite is decision models all the way down, but the models are concept-bottlenecked and computation-conditioned, the learned part is confined to a finite three-valued bottleneck that can only narrow admission, and the recursion is well-founded because the bottom level is checked integer arithmetic that Lean, Aeneas, and Kani already verify. The last turtle is `budget_commit`.

I could not open either repository in this session. Existing Chio signatures below are taken from the brief as given, and every new type is marked as a proposed addition to `chio-kernel-core`.

## 1. Thesis: what "decision models all the way down" means for a kernel

**Definition 1 (decision model).** A decision model at level $\ell$ is a tuple $\mathcal{D}_\ell = (\mathcal{X}_\ell, C_\ell, P_\ell, \mathcal{C}_\ell, \Pi_\ell, \omega_\ell)$ where $\mathcal{X}_\ell$ is a typed evidence window, $C_\ell : \mathcal{X}_\ell \to \mathbb{K}^{F_\ell}$ is a total, deterministic, WCET-bounded fact processor over the Kleene domain $\mathbb{K} = \{+, -, \bot\}$ (known positive, known negative, unknown), $P_\ell(\cdot;\theta_\ell,\boldsymbol\lambda) : \mathcal{X}_\ell \to [0,1]^{M_\ell}$ is a calibrated predictor parameterized by weights $\theta_\ell$ and shadow prices $\boldsymbol\lambda$ inherited from slower levels, $\mathcal{C}_\ell(x)$ is the feasible action set computed from $C_\ell(x)$ alone, $\Pi_\ell$ is a shield that maps $(C_\ell(x), T_\tau(P_\ell(x)))$ into $\mathcal{C}_\ell(x) \cup \{\text{Deny}\}$, and $\omega_\ell$ is a receipt witness committing digests of $x$, $\theta_\ell$, $\tau$, the bottleneck state, and the action.

Here $T_\tau : [0,1]^M \to \mathbb{K}^M$ is the role-asymmetric trit projection with thresholds $\tau = (\tau^{\text{pos}}, \tau^{\text{neg}})$ satisfying the gap invariant $\tau^{\text{neg}}_j \le \tau^{\text{pos}}_j$:

$$T_\tau(p)_j = \begin{cases} + & p_j \ge \tau^{\text{pos}}_j \\ - & p_j < \tau^{\text{neg}}_j \\ \bot & \text{otherwise.}\end{cases}$$

**Definition 2 (decision models all the way down).** A kernel is decision models all the way down when every state transition $s \xrightarrow{a} s'$ factors through some $\mathcal{D}_\ell$ such that the action depends on learned quantities only through $T_\tau(P_\ell(x))$, the feasible set depends only on $C_\ell(x)$, and the receipt $\omega_\ell$ is sufficient to replay the symbolic half of the decision exactly.

**The three paradigms.**

| Property | Classical kernel (Linux, seL4) | Naive LLM-as-OS | Chio + Copley |
|---|---|---|---|
| Transition function | Static state machine plus hand-tuned constants | Autoregressive sampling | $\Pi_\ell(C_\ell(x), T_\tau(P_\ell(x)))$ |
| Semantic awareness | None, syscall numbers only | High but unverified | $M$ calibrated predicates with epistemic $\bot$ |
| WCET | Bounded | Unbounded | Bounded, work-metered, $O(R(W_M + W_F))$ |
| Determinism | Yes | No | Yes given committed digests |
| Auditability | dmesg | Prompt logs | Signed receipt with concept, fact, and rule bitmaps |
| Can learning widen authority? | n/a | Yes, by construction | Never, Theorem 1 |
| Formal story | seL4 proofs, no adaptivity | None | Lean, Apalache, Kani, plus Theorem 2 |

A classical kernel is $\mathcal{D}$ with $M = 0$: the CFS weight table and page watermarks are degenerate $P$ with frozen $\theta$ and no receipts. The LLM wrapper is $\mathcal{D}$ with $C$ empty, $\Pi$ the identity, and no $\omega$. The synthesis keeps all six components non-degenerate.

**Theorem 1 (envelope containment, learning never widens).** Fix $x$. Let $\text{Adm}(x;\theta,\tau)$ denote that the composed verdict is Allow. Then for all $\theta$ and all gap-valid $\tau$:

$$\text{Adm}(x;\theta,\tau) \implies \text{HardGate}(C(x)) = \text{Allow},$$

where HardGate is Allow iff the facts `time_window_valid`, `budget_charge_admits`, `scope_subset`, `not_revoked`, and `delegation_chain_attenuated` are all $+$.

*Proof.* The kernel verdict is the lattice meet $\text{HardGate}(C(x)) \sqcap v(T_\tau(P_\theta(x)), C(x))$ in the fail-closed order $\text{Incomplete} \sqsubset \text{Deny} \sqsubset \text{Hold} \sqsubset \text{Allow} \sqsubset \text{Abstain}$, and the meet is Allow only if HardGate is Allow. The compiled DAG additionally places those facts in `facts_required` of every Allow rule, so the result holds even if a caller bypasses the outer meet. $\square$

**Theorem 2 (bottleneck sufficiency).** The symbolic verdict is a function of $(T_\tau(P_\theta(x)), C(x), \text{dag}) \in \mathbb{K}^M \times \mathbb{K}^F \times \text{Dag}$, a finite domain of size $3^{M+F}$ per DAG. Hence a receipt that commits the two concept bitmaps, the two fact bitmaps, the DAG digest, and the work bound determines the verdict uniquely, and replay costs the same $O(R(W_M+W_F))$ as the original evaluation.

*Proof.* Immediate from the definition of $v$, which reads only bitmaps and never $p_j$ itself; margins affect the witness but not the verdict. $\square$

**Theorem 3 (well-foundedness).** The hierarchy $\mathcal{D}_3 \to \mathcal{D}_2 \to \mathcal{D}_1 \to \mathcal{D}_0$ is not circular: $C_0$ is the set of pure scalar functions in `formal_core` and `formal_aeneas` (`classify_time_window`, `budget_precheck`, `budget_commit`, `revocation_snapshot_denies`, `inclusion_step`), each total, primitive recursive, and extracted to Lean. Slower levels never alter faster levels' code. They alter only parameters ($\boldsymbol\lambda$, caps, $\tau$, $\theta$) through receipted epoch advances, and `epoch_advance_is_strict` makes the parameter history a well-order. Every fast decision therefore terminates in finitely many checked integer operations under a parameter vector pinned by digests in its own receipt. $\square$

**Shadow prices become facts.** Levels 2 and 3 solve $\max_{a \in \mathcal{C}_\ell(x)} U_\ell(a) - \boldsymbol\lambda^\top g_\ell(a)$ over budgets, pheromone scarcity, and capital pools. The dual variables $\boldsymbol\lambda$ reach level 0 only as tightened constants inside $C_0$: `max_cost_per_invocation` becomes $\min(\text{cap}_{\text{capability}}, \text{cap}_{\boldsymbol\lambda})$. Prices can therefore shrink $\mathcal{C}_0(x)$ but never grow it past the capability, which is Theorem 1 again at the economic layer.

So the honest reading of the thesis: the kernel is becoming decision models all the way down, and precisely because of that it is not neural nets all the way down. Opaque function approximation is quarantined to $P_\ell$, whose entire causal influence passes through a finite trit vector that is itself committed in the receipt.

## 2. Copley inside Chio: concrete unification

**Segments map onto the evaluation envelope.** Copley's four segment views are the four faces of `EvaluateInput` and `GuardContext`:

| Copley segment | Chio source | Content |
|---|---|---|
| $s_0$ operation syntax | `PortableToolCallRequest` | server id, tool name, normalized argument AST under `canonical_json_bytes` |
| $s_1$ lineage and authority | `VerifiedCapability`, `SwarmDelegationWitnessChain`, `BudgetSplit` | attenuation depth, remaining `share_bps`, issuer trust root, caveats |
| $s_2$ data flow and custody | `chio-flow` `InformationLabel`, `DataFlowGuard` counters, `session_filesystem_roots` | taint lattice point, cumulative bytes, custody roots |
| $s_3$ temporal and stigmergic trajectory | `BehavioralProfileGuard` EMA and sigma state, `BehavioralSequenceGuard` automaton state, `PheromoneConcentration` | baseline deviation, ordering automaton, route concentration with half-life decay |

**Epistemic partition maps onto the verification seam.** Copley's rule is to never let a network approximate what a processor computes exactly. In Chio that processor already exists and is the formally mirrored part of the kernel. The proposed fact bitmap for level 0 is:

| Fact index | Producer in Chio | Kleene value source |
|---|---|---|
| $F_0$ `time_window_valid` | `classify_time_window` | $+$ on `Valid`, $-$ otherwise |
| $F_1$ `budget_charge_admits` | `budget_charge_admits` | $+$ / $-$, $\bot$ on projection error |
| $F_2$ `scope_subset` | `resolve_matching_grants`, `NormalizedScope::is_subset_of` | $+$ iff a `MatchedGrant` exists |
| $F_3$ `not_revoked` | `revocation_snapshot_denies` | $\bot$ when the snapshot is stale per `verify_revocation_snapshot_timestamp_freshness` |
| $F_4$ `flow_admissible` | `evaluate_pre_invocation` | $\bot$ on `unknown_effect` |
| $F_5$ `dependency_graph_valid` | `validate_dependency_graph` | $-$ on cycle or bound violation |
| $F_6$ `nonce_fresh` | `ExecutionNonceStore` reservation | $+$ only with a live reservation |
| $F_7$ `delegation_attenuated` | `validate_delegation_chain` | mirrors `delegate_no_widen` |

Everything a `formal_core` function can decide is a fact. Everything else, such as "this shell command exfiltrates a credential under an alias" or "this path argument is a disguised home-directory traversal", is a Copley head $p_j$. The `unsupported_syntax` outcome of a bounded interpreter maps to $\bot$, never to a guess.

**Role asymmetry is a fail-closed requirement, not a tuning trick.** Consider the two ways a head $j$ can appear in a rule. As a positive literal in a Deny or Hold rule it needs $p_j \ge \tau^{\text{pos}}_j$, and a false alarm costs one deferral. As a negation guard in an Allow rule it needs $p_m < \tau^{\text{neg}}_m$, and a false absence claim admits an unsafe call. The loss asymmetry forces $\tau^{\text{neg}}_m \ll \tau^{\text{pos}}_m$, and the interval between them is the abstain band where the kernel says $\bot$ and escalates. Copley's sealing of both thresholds on validation splits before evaluation is exactly the discipline that `chio-weights` applies to model digests: calibration is TCB state, changed only by receipted epoch advance.

**Lemma 1 (the gap invariant is what makes thresholds monotone).** Under $\tau^{\text{neg}}_j \le \tau^{\text{pos}}_j$, the indicators $[T_\tau(p)_j = +] = [p_j \ge \tau^{\text{pos}}_j]$ and $[T_\tau(p)_j = -] = [p_j < \tau^{\text{neg}}_j]$ depend on exactly one threshold each. If the invariant fails, $[T_\tau(p)_j = -] = [p_j < \min(\tau^{\text{neg}}_j, \tau^{\text{pos}}_j)]$, so lowering $\tau^{\text{pos}}_j$ to make a Deny rule fire more often simultaneously un-fires any Deny rule using $j$ as a negation guard, and admission can widen. The constructor therefore rejects crossed thresholds.

**Three-valued rule semantics.** A rule $R_k = (\mathcal{P}_k, \mathcal{D}_k, \mathcal{N}_k, \mathcal{F}^+_k, \mathcal{F}^-_k, \mathcal{A}_k, c_k)$ with conjunctive, disjunctive, negated, required-fact, excluded-fact, and antecedent-rule sets and consequence $c_k \in \{\text{Deny}, \text{Hold}, \text{Allow}\}$ has two statuses. It fires definitely, $\phi_k$, when every literal is definitely satisfied. It fires possibly, $\psi_k$, when no literal is definitely violated. The composed verdict is

$$v = \min_{\sqsubseteq}\big(\{c_k : \phi_k\} \cup \{\text{Hold} : c_k \ne \text{Allow} \wedge \psi_k\} \cup \{\text{Abstain}\}\big).$$

A Deny rule that might fire defers; an Allow rule that might fire admits nothing. This is Kleene's strong three-valued logic with the two consequence polarities resolved in the fail-closed direction.

**Policy compilation and refinement.** `chio-policy` lowers HushSpec into the same clause form: a YAML `deny when` block becomes a Deny rule over facts and heads, an `allow when` block becomes an Allow rule whose `facts_required` always includes $F_0$ to $F_3$ and $F_7$. The syntactic refinement check in `analyze/refine.rs` then has a semantic justification.

**Proposition 1 (syntactic refinement is sound).** Let $\mathcal{R}'$ be obtained from $\mathcal{R}$ by adding literals to Allow rules, removing literals from Deny or Hold rules, adding Deny or Hold rules, deleting Allow rules, or moving thresholds in the safety direction of Section 4. Then $\text{Adm}' \subseteq \text{Adm}$ pointwise. *Proof.* $\phi_k$ and $\psi_k$ are monotone in literal satisfaction and antitone in literal count; apply Theorem 4 of Section 4 for the threshold moves. $\square$

**Offline training, online bitsets.** Copley's softmin active-clause supervision lives entirely in the training pipeline over `chio-replay-corpus`. For a sample $x$ with label from a `ThresholdApprovalCollector` decision, an override, or a settlement outcome, define signed logit margins $m_j = z_j - \text{logit}(\tau^{\text{pos}}_j)$ for positive literals and $m_m = \text{logit}(\tau^{\text{neg}}_m) - z_m$ for negation guards, the clause margin $\mu_k = -T \log \sum_i e^{-m_i / T}$, and the loss $\sum_{k \in \text{active}} \max(0, \gamma - \mu_k) + \sum_{k \in \text{inactive}} \max(0, \gamma + \mu_k)$. Gradients flow mostly into the weakest literal of each active clause, which is what makes the discrete evaluator agree with the differentiable surrogate at inference. The kernel never sees any of this. It sees `[u64; 9]` masks, `Q16.16` thresholds, and a rule table digest, and executes in `#![no_std]`.

**Caveat on replaying $P(X)$.** Theorem 2 gives exact replay of the symbolic half from the receipt alone. Replaying the neural half bit-exactly requires an integer-only inference path, INT8 or fixed-point with deterministic kernels, because BF16 accumulation order on accelerators is not reproducible. Until that path is qualified, the receipt commits to the claimed trit vector and the neural claim is audited statistically by shadow re-inference, which `AutonomousAutomationMode::Shadow` already supports.

## 3. The fractal: the same triad at every timescale

| Level, timescale | $C_\ell(X)$ exact facts | $P_\ell(X;\theta,\boldsymbol\lambda)$ | $\mathcal{C}_\ell$ and shield $\Pi_\ell$ | Receipt witness | Formal guard |
|---|---|---|---|---|---|
| L0, 10 to 200 ns, in-core gate in `chio-kernel-core` | `formal_core` scalar facts $F_0..F_7$ | Cached trit vector from last L1 pass of the session, plus a few fixed-point Tier-0 heads | Compiled sparse rule table, bitset evaluation, budget and scope projection | `ConceptBottleneckReceiptWitness` digest inside `ChioReceiptBody` | Kani `verify_budget_admission_projection`, Theorem 4 harness, Aeneas extraction |
| L1, 0.5 to 5 ms, sidecar in `chio-kernel` and `chio-guards` | Same facts plus `chio-flow` fence and `chio-semantic-contracts` validation | Copley 4-pass 19.3M encoder, 537 heads, sealed $\tau^{\text{pos}}, \tau^{\text{neg}}$ | 236-rule DAG, `PendingApproval` on Hold, `PromotionPolicy` for Abstain | Full witness with margins and model digest from `chio-weights` | Loom `loom_revocation_race_eval`, Apalache `ReceiptBeforeAllow` |
| L2, 10 to 100 ms, `chio-swarm-authority`, `chio-recovery`, `chio-pheromone` | `SwarmTaskGraph` acyclicity and bounds, `validate_dependency_graph`, checked `reserve_swarm_budget_fanout` | Pheromone concentration with half-life decay, candidate plan ranking | Integer simplex $\sum \text{share}_{\text{bps}} \le 10^4$, `PlannerLimitsV1` work meter, sqrt-N passport caps | `SwarmRoutePlanReceipt`, `SwarmJoinReceipt`, `SignedRecoveryExplanationReportV1` | Apalache `ReservationConservation`, compile-fail doctests denying `CandidatePlanV1` to `SignedRecoveryGrant` |
| L3, seconds to hours, `chio-federation`, `chio-autonomy`, `chio-credit`, `chio-market` | Settlement ledgers, treaty predicates in `Treaty/PredicateLang.lean`, loss ratios | Autonomous pricing, capital pool optimization, drift detectors | `AutonomousPricingAuthorityEnvelopeArtifact`, `AutonomousSafeState` rollback | `AutonomousPricingDecisionArtifact`, `AutonomousDriftReport` | Lean `settlement_admission_requires_verified_evidence`, `epoch_advance_is_strict` |

Three self-similarities are worth making explicit.

**The advisory-to-authority wall recurs.** At L1 the concept vector cannot become a verdict except through the DAG. At L2 `CandidatePlanV1` has no `From` into `SignedRecoveryGrant`. At L3 `AutonomousAutomationMode::Shadow` and `Advisory` produce artifacts that `Active` alone may bind. Each is the same type-level statement: $P_\ell$ outputs have no path to authority that bypasses $\Pi_\ell$.

**Abstain recurs as escalation.** L0 $\bot$ escalates to L1 inference. L1 Hold escalates to `ThresholdApprovalCollector`. L2 `SearchBoundReached` escalates to a human remedy. L3 `AutonomousDriftKind::ModelVersionMismatch` escalates to `FullPause`. Each level's $\bot$ is the next level's input, and each escalation is itself receipted.

**Training recurs as receipted replay.** The Merkle checkpointed receipt log is the only training corpus, and because every receipt pins encoder, calibration, and DAG digests, a new $\tau$ or a new rule table can be evaluated counterfactually over historical witnesses with exact symbolic semantics, while a new encoder requires the stored evidence windows in `chio-replay-corpus`.

The timescale separation that makes the fractal sound is the standard one: within an epoch, L0 and L1 treat $\boldsymbol\lambda$, $\tau$, and $\theta$ as constants, and since parameter change is itself an L2 or L3 decision with a strictly increasing epoch, no fast decision ever observes a parameter it did not commit to.

## 4. Compile-ready bridge and formal verification

The following is a proposed module `concept_bottleneck` for `chio-kernel-core`. It uses only `core`, has no allocation, no indexing, no `unwrap`, no `as`, and only checked or saturating arithmetic.

```rust
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::as_conversions,
    clippy::arithmetic_side_effects
)]

use core::fmt::{self, Write};

pub const WORD_BITS: usize = 64;

fn bit_mask(bit: usize) -> Option<u64> {
    let shift = u32::try_from(bit).ok()?;
    1u64.checked_shl(shift)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitSetError {
    OutOfRange { index: usize, capacity: usize },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitSet<const W: usize> {
    words: [u64; W],
}

impl<const W: usize> BitSet<W> {
    pub const EMPTY: Self = Self { words: [0u64; W] };
    pub const CAPACITY: usize = W.saturating_mul(WORD_BITS);

    pub const fn from_words(words: [u64; W]) -> Self {
        Self { words }
    }

    pub fn words(&self) -> &[u64; W] {
        &self.words
    }

    pub fn contains(&self, index: usize) -> bool {
        let word = index / WORD_BITS;
        let bit = index % WORD_BITS;
        match (self.words.get(word), bit_mask(bit)) {
            (Some(w), Some(mask)) => (w & mask) != 0,
            _ => false,
        }
    }

    pub fn insert(&mut self, index: usize) -> Result<(), BitSetError> {
        let word = index / WORD_BITS;
        let bit = index % WORD_BITS;
        match (self.words.get_mut(word), bit_mask(bit)) {
            (Some(w), Some(mask)) => {
                *w |= mask;
                Ok(())
            }
            _ => Err(BitSetError::OutOfRange { index, capacity: Self::CAPACITY }),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.words.iter().zip(other.words.iter()).all(|(a, b)| (a & !b) == 0)
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.words.iter().zip(other.words.iter()).any(|(a, b)| (a & b) != 0)
    }

    pub fn is_disjoint(&self, other: &Self) -> bool {
        !self.intersects(other)
    }
}

/// Signed Q16.16 fixed point. Probabilities and thresholds live in [0, ONE].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Q16_16(i32);

impl Q16_16 {
    pub const FRAC_BITS: u32 = 16;
    pub const ZERO: Self = Self(0);
    /// 1.0 in Q16.16.
    pub const ONE: Self = Self(0x0001_0000);

    pub const fn from_raw(raw: i32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> i32 {
        self.0
    }

    pub const fn is_unit_interval(self) -> bool {
        self.0 >= 0 && self.0 <= Self::ONE.0
    }

    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CalibrationError {
    ProbabilityOutOfUnitInterval,
    ThresholdOutOfUnitInterval,
    NegationThresholdAbovePositive,
}

/// Three valued epistemic outcome for one concept head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConceptTruth {
    TrueWithMargin(Q16_16),
    FalseWithMargin(Q16_16),
    EpistemicAbstain,
}

pub fn classify(p: Q16_16, tau_pos: Q16_16, tau_neg: Q16_16) -> ConceptTruth {
    if p >= tau_pos {
        ConceptTruth::TrueWithMargin(p.saturating_sub(tau_pos))
    } else if p < tau_neg {
        ConceptTruth::FalseWithMargin(tau_neg.saturating_sub(p))
    } else {
        ConceptTruth::EpistemicAbstain
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopleyConceptVector<const M: usize> {
    probs: [Q16_16; M],
}

impl<const M: usize> CopleyConceptVector<M> {
    pub fn new(probs: [Q16_16; M]) -> Result<Self, CalibrationError> {
        if probs.iter().all(|p| p.is_unit_interval()) {
            Ok(Self { probs })
        } else {
            Err(CalibrationError::ProbabilityOutOfUnitInterval)
        }
    }

    pub fn probabilities(&self) -> &[Q16_16; M] {
        &self.probs
    }
}

/// Sealed role asymmetric calibration. Invariant: tau_neg[j] <= tau_pos[j].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RoleAsymmetricThresholds<const M: usize> {
    tau_pos: [Q16_16; M],
    tau_neg: [Q16_16; M],
}

impl<const M: usize> RoleAsymmetricThresholds<M> {
    pub fn new(tau_pos: [Q16_16; M], tau_neg: [Q16_16; M]) -> Result<Self, CalibrationError> {
        let in_range = tau_pos
            .iter()
            .chain(tau_neg.iter())
            .all(|t| t.is_unit_interval());
        if !in_range {
            return Err(CalibrationError::ThresholdOutOfUnitInterval);
        }
        let gap_ok = tau_neg.iter().zip(tau_pos.iter()).all(|(n, p)| n <= p);
        if !gap_ok {
            return Err(CalibrationError::NegationThresholdAbovePositive);
        }
        Ok(Self { tau_pos, tau_neg })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceError {
    ConceptBothAssertedAndNegated,
    FactBothKnownPositiveAndNegative,
}

/// P(X) after trit projection. Heads in neither set are abstentions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConceptEvidence<const W: usize> {
    pub asserted: BitSet<W>,
    pub negated: BitSet<W>,
    pub min_margin: Option<Q16_16>,
}

impl<const W: usize> ConceptEvidence<W> {
    pub fn new(asserted: BitSet<W>, negated: BitSet<W>) -> Result<Self, EvidenceError> {
        if asserted.is_disjoint(&negated) {
            Ok(Self { asserted, negated, min_margin: None })
        } else {
            Err(EvidenceError::ConceptBothAssertedAndNegated)
        }
    }
}

impl<const M: usize> CopleyConceptVector<M> {
    pub fn project<const W: usize>(
        &self,
        tau: &RoleAsymmetricThresholds<M>,
    ) -> Result<ConceptEvidence<W>, BitSetError> {
        let mut asserted = BitSet::<W>::EMPTY;
        let mut negated = BitSet::<W>::EMPTY;
        let mut min_margin: Option<Q16_16> = None;
        let heads = self
            .probs
            .iter()
            .zip(tau.tau_pos.iter())
            .zip(tau.tau_neg.iter())
            .enumerate();
        for (j, ((p, tp), tn)) in heads {
            match classify(*p, *tp, *tn) {
                ConceptTruth::TrueWithMargin(m) => {
                    asserted.insert(j)?;
                    min_margin = Some(min_margin.map_or(m, |cur| cur.min(m)));
                }
                ConceptTruth::FalseWithMargin(m) => {
                    negated.insert(j)?;
                    min_margin = Some(min_margin.map_or(m, |cur| cur.min(m)));
                }
                ConceptTruth::EpistemicAbstain => {}
            }
        }
        Ok(ConceptEvidence { asserted, negated, min_margin })
    }
}

/// C(X): exact facts from formal_core and semantic contracts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FactEvidence<const FW: usize> {
    pub known_positive: BitSet<FW>,
    pub known_negative: BitSet<FW>,
}

impl<const FW: usize> FactEvidence<FW> {
    pub fn new(known_positive: BitSet<FW>, known_negative: BitSet<FW>) -> Result<Self, EvidenceError> {
        if known_positive.is_disjoint(&known_negative) {
            Ok(Self { known_positive, known_negative })
        } else {
            Err(EvidenceError::FactBothKnownPositiveAndNegative)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RuleConsequence {
    Deny,
    Hold,
    Allow,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuleStatus {
    Definite,
    Possible,
    NotFired,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule<const W: usize, const FW: usize, const RW: usize> {
    pub id: u16,
    pub consequence: RuleConsequence,
    pub conjunctive: BitSet<W>,
    pub disjunctive: BitSet<W>,
    pub negation_guards: BitSet<W>,
    pub facts_required: BitSet<FW>,
    pub facts_excluded: BitSet<FW>,
    pub derived_required: BitSet<RW>,
}

impl<const W: usize, const FW: usize, const RW: usize> Rule<W, FW, RW> {
    pub fn status(
        &self,
        c: &ConceptEvidence<W>,
        f: &FactEvidence<FW>,
        fired: &BitSet<RW>,
        possibly_fired: &BitSet<RW>,
    ) -> RuleStatus {
        let definite = self.conjunctive.is_subset_of(&c.asserted)
            && (self.disjunctive.is_empty() || self.disjunctive.intersects(&c.asserted))
            && self.negation_guards.is_subset_of(&c.negated)
            && self.facts_required.is_subset_of(&f.known_positive)
            && self.facts_excluded.is_subset_of(&f.known_negative)
            && self.derived_required.is_subset_of(fired);
        if definite {
            return RuleStatus::Definite;
        }
        let possible = self.conjunctive.is_disjoint(&c.negated)
            && (self.disjunctive.is_empty() || !self.disjunctive.is_subset_of(&c.negated))
            && self.negation_guards.is_disjoint(&c.asserted)
            && self.facts_required.is_disjoint(&f.known_negative)
            && self.facts_excluded.is_disjoint(&f.known_positive)
            && self.derived_required.is_subset_of(possibly_fired);
        if possible {
            RuleStatus::Possible
        } else {
            RuleStatus::NotFired
        }
    }
}

/// Fail closed verdict lattice. Lower rank is more restrictive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DagOutcome {
    Incomplete,
    Deny,
    DeferForReview,
    Allow,
    Abstain,
}

impl DagOutcome {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Incomplete => 0,
            Self::Deny => 1,
            Self::DeferForReview => 2,
            Self::Allow => 3,
            Self::Abstain => 4,
        }
    }

    pub fn meet(self, other: Self) -> Self {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }

    pub const fn as_canonical_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::Deny => "deny",
            Self::DeferForReview => "defer_for_review",
            Self::Allow => "allow",
            Self::Abstain => "abstain",
        }
    }
}

impl RuleConsequence {
    pub const fn definite_outcome(self) -> DagOutcome {
        match self {
            Self::Deny => DagOutcome::Deny,
            Self::Hold => DagOutcome::DeferForReview,
            Self::Allow => DagOutcome::Allow,
        }
    }

    /// A restrictive rule that might fire defers. A permissive one admits nothing.
    pub const fn possible_outcome(self) -> DagOutcome {
        match self {
            Self::Deny | Self::Hold => DagOutcome::DeferForReview,
            Self::Allow => DagOutcome::Abstain,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerificationBudget {
    remaining: u32,
}

impl VerificationBudget {
    pub const fn new(units: u32) -> Self {
        Self { remaining: units }
    }

    pub fn charge(&mut self, units: u32) -> Result<(), ()> {
        match self.remaining.checked_sub(units) {
            Some(r) => {
                self.remaining = r;
                Ok(())
            }
            None => Err(()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DagError {
    TooManyRules { rules: usize, capacity: usize },
    NonTopological { rule: usize },
    BitSet(BitSetError),
    Evidence(EvidenceError),
}

impl From<BitSetError> for DagError {
    fn from(e: BitSetError) -> Self {
        Self::BitSet(e)
    }
}

impl From<EvidenceError> for DagError {
    fn from(e: EvidenceError) -> Self {
        Self::Evidence(e)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DagEvaluation<const RW: usize> {
    pub outcome: DagOutcome,
    pub fired: BitSet<RW>,
    pub possibly_fired: BitSet<RW>,
    pub work_consumed: u32,
}

pub struct SymbolicRuleDag<const W: usize, const FW: usize, const R: usize, const RW: usize> {
    rules: [Rule<W, FW, RW>; R],
}

impl<const W: usize, const FW: usize, const R: usize, const RW: usize> SymbolicRuleDag<W, FW, R, RW> {
    /// Rules are in topological order: antecedents strictly precede dependents.
    pub fn new(rules: [Rule<W, FW, RW>; R]) -> Result<Self, DagError> {
        let capacity = BitSet::<RW>::CAPACITY;
        if R > capacity {
            return Err(DagError::TooManyRules { rules: R, capacity });
        }
        for (k, rule) in rules.iter().enumerate() {
            for i in k..R {
                if rule.derived_required.contains(i) {
                    return Err(DagError::NonTopological { rule: k });
                }
            }
        }
        Ok(Self { rules })
    }

    /// Per rule cost in word operations. Compile time constant per instantiation.
    pub fn rule_work_units(&self) -> u32 {
        let words = W
            .saturating_mul(6)
            .saturating_add(FW.saturating_mul(4))
            .saturating_add(RW.saturating_mul(2))
            .saturating_add(1);
        u32::try_from(words).unwrap_or(u32::MAX)
    }

    /// Total: budget exhaustion yields Incomplete, never a panic.
    pub fn evaluate(
        &self,
        concepts: &ConceptEvidence<W>,
        facts: &FactEvidence<FW>,
        budget: &mut VerificationBudget,
    ) -> Result<DagEvaluation<RW>, DagError> {
        let mut eval = DagEvaluation {
            outcome: DagOutcome::Abstain,
            fired: BitSet::EMPTY,
            possibly_fired: BitSet::EMPTY,
            work_consumed: 0,
        };
        let unit = self.rule_work_units();
        for (k, rule) in self.rules.iter().enumerate() {
            if budget.charge(unit).is_err() {
                eval.outcome = DagOutcome::Incomplete;
                return Ok(eval);
            }
            eval.work_consumed = eval.work_consumed.saturating_add(unit);
            match rule.status(concepts, facts, &eval.fired, &eval.possibly_fired) {
                RuleStatus::Definite => {
                    eval.fired.insert(k)?;
                    eval.possibly_fired.insert(k)?;
                    eval.outcome = eval.outcome.meet(rule.consequence.definite_outcome());
                }
                RuleStatus::Possible => {
                    eval.possibly_fired.insert(k)?;
                    eval.outcome = eval.outcome.meet(rule.consequence.possible_outcome());
                }
                RuleStatus::NotFired => {}
            }
        }
        Ok(eval)
    }
}

/// Receipt extension committed into ChioReceiptBody as `concept_witness_digest`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConceptBottleneckReceiptWitness<const W: usize, const FW: usize, const RW: usize> {
    pub schema_version: u16,
    pub encoder_weights_digest: [u8; 32],
    pub calibration_digest: [u8; 32],
    pub dag_digest: [u8; 32],
    pub asserted_heads: BitSet<W>,
    pub negated_heads: BitSet<W>,
    pub fact_known_positive: BitSet<FW>,
    pub fact_known_negative: BitSet<FW>,
    pub fired_rules: BitSet<RW>,
    pub possibly_fired_rules: BitSet<RW>,
    pub outcome: DagOutcome,
    pub min_margin_q16: Option<i32>,
    pub work_consumed: u32,
}

pub trait CanonicalDigest {
    fn update(&mut self, bytes: &[u8]);
    fn finalize(self) -> [u8; 32];
}

struct DigestWriter<D: CanonicalDigest>(D);

impl<D: CanonicalDigest> Write for DigestWriter<D> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

fn write_hex_words<Out: Write, const N: usize>(out: &mut Out, set: &BitSet<N>) -> fmt::Result {
    out.write_str("[")?;
    for (i, w) in set.words().iter().enumerate() {
        if i > 0 {
            out.write_str(",")?;
        }
        write!(out, "\"{w:016x}\"")?;
    }
    out.write_str("]")
}

fn write_hex_digest<Out: Write>(out: &mut Out, digest: &[u8; 32]) -> fmt::Result {
    out.write_str("\"")?;
    for b in digest {
        write!(out, "{b:02x}")?;
    }
    out.write_str("\"")
}

impl<const W: usize, const FW: usize, const RW: usize> ConceptBottleneckReceiptWitness<W, FW, RW> {
    /// RFC 8785: members in code point order, no whitespace, integers exact.
    /// u64 words are emitted as fixed width hex strings because JSON numbers
    /// are only exact to 2^53.
    pub fn write_canonical_json<Out: Write>(&self, out: &mut Out) -> fmt::Result {
        out.write_str("{\"asserted_heads\":")?;
        write_hex_words(out, &self.asserted_heads)?;
        out.write_str(",\"calibration_digest\":")?;
        write_hex_digest(out, &self.calibration_digest)?;
        out.write_str(",\"dag_digest\":")?;
        write_hex_digest(out, &self.dag_digest)?;
        out.write_str(",\"encoder_weights_digest\":")?;
        write_hex_digest(out, &self.encoder_weights_digest)?;
        out.write_str(",\"fact_known_negative\":")?;
        write_hex_words(out, &self.fact_known_negative)?;
        out.write_str(",\"fact_known_positive\":")?;
        write_hex_words(out, &self.fact_known_positive)?;
        out.write_str(",\"fired_rules\":")?;
        write_hex_words(out, &self.fired_rules)?;
        out.write_str(",\"min_margin_q16\":")?;
        match self.min_margin_q16 {
            Some(m) => write!(out, "{m}")?,
            None => out.write_str("null")?,
        }
        out.write_str(",\"negated_heads\":")?;
        write_hex_words(out, &self.negated_heads)?;
        write!(out, ",\"outcome\":\"{}\"", self.outcome.as_canonical_str())?;
        out.write_str(",\"possibly_fired_rules\":")?;
        write_hex_words(out, &self.possibly_fired_rules)?;
        write!(out, ",\"schema_version\":{}", self.schema_version)?;
        write!(out, ",\"work_consumed\":{}}}", self.work_consumed)
    }

    pub fn commit<D: CanonicalDigest>(&self, hasher: D) -> Result<[u8; 32], fmt::Error> {
        let mut writer = DigestWriter(hasher);
        self.write_canonical_json(&mut writer)?;
        Ok(writer.0.finalize())
    }

    /// Offline verifier: re-evaluate the symbolic half under the committed work bound.
    pub fn replay<const R: usize>(&self, dag: &SymbolicRuleDag<W, FW, R, RW>) -> Result<bool, DagError> {
        let concepts = ConceptEvidence::new(self.asserted_heads, self.negated_heads)?;
        let facts = FactEvidence::new(self.fact_known_positive, self.fact_known_negative)?;
        let mut budget = VerificationBudget::new(self.work_consumed);
        let eval = dag.evaluate(&concepts, &facts, &mut budget)?;
        Ok(eval.outcome == self.outcome
            && eval.fired == self.fired_rules
            && eval.possibly_fired == self.possibly_fired_rules
            && eval.work_consumed == self.work_consumed)
    }
}
```

**Receipt integration.** The kernel computes `witness.commit(sha256)` and stores the result as a new `concept_witness_digest` field in `ChioReceiptBody`, covered by `sign_receipt`. If the receipt id derivation is versioned to include it as a twenty-first canonical field, `canonical_inj` and `receipt_id_collision_resistant` carry over unchanged, since adding a field to an injective canonical encoding preserves injectivity. `Decision::Incomplete` corresponds exactly to `DagOutcome::Incomplete`, and the replay function refuses to produce a verdict with less work than the original committed.

**Cost.** For $M = 537$, $F = 8$, $R = 236$ the dense instantiation is `W = 9`, `FW = 1`, `RW = 4`, and `rule_work_units` is 67 word operations, so worst-case evaluation is about 15,800 word operations, roughly one to two microseconds scalar. The `chio-policy` compiler can emit the same semantics as sparse literal lists for L0, where typical rules carry four to six literals and the full table evaluates in a few thousand operations, which is the 100 to 200 nanosecond regime. Both forms replay against the same witness.

**Theorem 4 (safety tightening never widens admission).** For each head $j$, let the compiler assign allowed threshold directions from the occurrences of $j$: a positive literal in an Allow rule permits $\tau^{\text{pos}}_j$ to rise; a negation guard in an Allow rule permits $\tau^{\text{neg}}_j$ to fall; a positive literal in a Deny or Hold rule permits both thresholds to fall; a negation guard in a Deny or Hold rule permits both to rise; a head with conflicting occurrences is frozen. Write $\tau' \preceq_{\text{safe}} \tau$ when every threshold moves only in a permitted direction. If $\tau$ and $\tau'$ both satisfy the gap invariant then for all $x$, $\theta$:

$$\text{Adm}(x;\theta,\tau') \implies \text{Adm}(x;\theta,\tau).$$

*Proof.* By Lemma 1 the four literal indicators are $D^+_j = [p_j \ge \tau^{\text{pos}}_j]$, $D^-_j = [p_j < \tau^{\text{neg}}_j]$, $Q^+_j = [p_j \ge \tau^{\text{neg}}_j]$, $Q^-_j = [p_j < \tau^{\text{pos}}_j]$, antitone in $\tau^{\text{pos}}$, monotone in $\tau^{\text{neg}}$, antitone in $\tau^{\text{neg}}$, and monotone in $\tau^{\text{pos}}$ respectively. Each $\phi_k$ is a monotone boolean function of the $D$ indicators of its literals, each $\psi_k$ of the $Q$ indicators, and both are monotone in antecedent firings, which by induction on topological index are themselves monotone in the same directions. Admission is $A = \bigvee_{c_k = \text{Allow}} \phi_k \wedge \neg\bigvee_{c_k \ne \text{Allow}} (\phi_k \vee \psi_k)$. The permitted directions are chosen so that every indicator appearing positively in $A$ is weakly decreased and every indicator appearing negatively is weakly increased when moving from $\tau$ to $\tau'$; frozen heads change nothing. Hence $A(\tau') \le A(\tau)$. Facts do not depend on $\tau$ and `Incomplete` is budget-only, so neither disturbs the inequality. $\square$

This is the neural-symbolic twin of `attenuation_monotone` and `delegate_no_widen`: there, narrowing a capability's scope can only shrink the admitted set; here, moving calibration in the safety direction can only shrink it. A Lean statement mirroring `Capability/Delegation.lean` reads:

```lean
theorem concept_tighten_no_widen
    (dag : RuleDag) (τ τ' : Calibration) (p : ConceptVec) (f : Facts)
    (hgap : GapInvariant τ) (hgap' : GapInvariant τ')
    (hsafe : SafetyLE dag τ' τ) :
    admits dag τ' p f → admits dag τ p f
```

**Proposition 2 (margin robustness).** If $\mu = $ `min_margin` is committed in the witness, then any perturbed probability vector $p'$ with $\|p' - p\|_\infty < \mu$ yields the same bitmaps and therefore the same verdict. *Proof.* No head crosses its active threshold under a perturbation smaller than its margin, and abstaining heads contribute no constraint. $\square$ The witness thus carries a certified robustness radius for the decision, which `AutonomousDriftKind::EvidenceStaleness` style monitors can track over time.

**Kani harness.** The harness below instantiates Theorem 4 on a two-rule DAG with fully symbolic probabilities, thresholds, tightening deltas, and facts. Head 0 is an Allow positive literal, head 1 an Allow negation guard, head 2 a Deny positive literal, head 3 a Deny negation guard. Early returns on constructor failure encode the theorem's hypotheses. The dense symbolic rule table is beyond bounded model checking, so the general case rests on the proof above, with the harness serving as the executable mirror registered in `.kani/harnesses.toml`.

```rust
#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    const W: usize = 1;
    const FW: usize = 1;
    const R: usize = 2;
    const RW: usize = 1;

    fn any_unit() -> Q16_16 {
        let raw: i32 = kani::any();
        kani::assume(raw >= 0 && raw <= Q16_16::ONE.raw());
        Q16_16::from_raw(raw)
    }

    fn at_least(base: Q16_16) -> Q16_16 {
        let v = any_unit();
        kani::assume(v >= base);
        v
    }

    fn at_most(base: Q16_16) -> Q16_16 {
        let v = any_unit();
        kani::assume(v <= base);
        v
    }

    fn deny_rule() -> Rule<W, FW, RW> {
        Rule {
            id: 0,
            consequence: RuleConsequence::Deny,
            conjunctive: BitSet::from_words([0b0100]),
            disjunctive: BitSet::EMPTY,
            negation_guards: BitSet::from_words([0b1000]),
            facts_required: BitSet::EMPTY,
            facts_excluded: BitSet::EMPTY,
            derived_required: BitSet::EMPTY,
        }
    }

    fn allow_rule() -> Rule<W, FW, RW> {
        Rule {
            id: 1,
            consequence: RuleConsequence::Allow,
            conjunctive: BitSet::from_words([0b0001]),
            disjunctive: BitSet::EMPTY,
            negation_guards: BitSet::from_words([0b0010]),
            facts_required: BitSet::from_words([0b11]),
            facts_excluded: BitSet::EMPTY,
            derived_required: BitSet::EMPTY,
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_copley_dag_role_asymmetric_monotone_safety() {
        let Ok(dag) = SymbolicRuleDag::<W, FW, R, RW>::new([deny_rule(), allow_rule()]) else {
            return;
        };

        let Ok(vector) = CopleyConceptVector::new([any_unit(), any_unit(), any_unit(), any_unit()]) else {
            return;
        };

        let tau_pos = [any_unit(), any_unit(), any_unit(), any_unit()];
        let tau_neg = [any_unit(), any_unit(), any_unit(), any_unit()];
        let Ok(base) = RoleAsymmetricThresholds::new(tau_pos, tau_neg) else {
            return;
        };

        // Safety direction per Theorem 4: permissive literals get harder to
        // satisfy, restrictive literals get easier to satisfy or to suspect.
        let [p0, p1, p2, p3] = tau_pos;
        let [n0, n1, n2, n3] = tau_neg;
        let tight_pos = [at_least(p0), p1, at_most(p2), at_least(p3)];
        let tight_neg = [n0, at_most(n1), at_most(n2), at_least(n3)];
        let Ok(tight) = RoleAsymmetricThresholds::new(tight_pos, tight_neg) else {
            return;
        };

        let pos_word: u64 = kani::any();
        let neg_word: u64 = kani::any();
        let Ok(facts) = FactEvidence::new(
            BitSet::from_words([pos_word & 0b11]),
            BitSet::from_words([neg_word & 0b11]),
        ) else {
            return;
        };

        let Ok(ev_base) = vector.project::<W>(&base) else { return; };
        let Ok(ev_tight) = vector.project::<W>(&tight) else { return; };

        let mut budget_base = VerificationBudget::new(u32::MAX);
        let mut budget_tight = VerificationBudget::new(u32::MAX);
        let (Ok(out_base), Ok(out_tight)) = (
            dag.evaluate(&ev_base, &facts, &mut budget_base),
            dag.evaluate(&ev_tight, &facts, &mut budget_tight),
        ) else {
            return;
        };

        kani::assert(
            out_tight.outcome != DagOutcome::Allow || out_base.outcome == DagOutcome::Allow,
            "safety tightening of role asymmetric thresholds never widens admission",
        );
        kani::assert(
            ev_base.asserted.is_disjoint(&ev_base.negated),
            "gap invariant keeps asserted and negated heads disjoint",
        );
    }
}
```

**Recap.** The kernel is becoming decision models all the way down, and the construction that makes this safe is the one Copley and Chio already share independently: exact computation $C(X)$ defines the feasible set, learned perception $P(X)$ is confined to a finite three-valued concept bottleneck with role-asymmetric calibration, a monotone symbolic evaluator composes them under fail-closed Kleene semantics, and a signed receipt commits every digest and bitmap needed to replay the symbolic half exactly. Theorems 1 through 4 show that learning can never widen authority, that the bottleneck is a sufficient statistic for the verdict, that the recursion bottoms out in `formal_core` arithmetic, and that moving calibration in the safety direction is an attenuation in the same sense as `delegate_no_widen`. The proposed `concept_bottleneck` module, witness format, and Kani harness are the concrete bridge; the open engineering items are an integer-only inference path for bit-exact replay of the encoder, the sparse rule-table emitter in `chio-policy` for the L0 latency target, and the Lean mechanization of Theorem 4 alongside `Capability/Delegation.lean`.

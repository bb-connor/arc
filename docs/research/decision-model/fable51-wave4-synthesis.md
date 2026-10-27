# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 4 Synthesis

- **Timestamp**: `20261025-013112 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `960.75s` across 4 parallel passes
- **Total Output**: `175,877` characters (`21,941` words)
- **Claude Max Quota Before Wave 4**: 5-hour `58.0%` | 7-day `82.0%`
- **Claude Max Quota After Wave 4**: 5-hour `71.0%` | 7-day `84.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave4_angle_1_swarm_authority_and_x402_escrow_calculus` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,622` | `44,541` | `780.41` |
| `wave4_angle_2_pheromone_restless_bandit_and_federation` | `1` | `error_max_budget_usd` | `['claude-fable-5-1']` | `none` | `5,188` | `38,267` | `960.74` |
| `wave4_angle_3_counterfactual_replay_and_drift_rollback` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,745` | `49,009` | `746.98` |
| `wave4_angle_4_end_to_end_pr_roadmap_and_benchmark_suite` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,386` | `44,060` | `793.53` |

---

# Verbatim Treatise - `wave4_angle_1_swarm_authority_and_x402_escrow_calculus`

I'll lay out the swarm-layer decision model, then give the additive Rust modules for critical-path and Pandora scheduling in `chio-swarm-authority`, the escrow hold calculus in `chio-settle`, and the Lean, Kani, and Apalache artifacts with proofs.

## 1. Decision Model and Scheduling Calculus

**Tuple instantiation.** The swarm layer instantiates the Wave 1 law as $\mathcal{D}_{\text{swarm}} = (\mathcal{X}, C, P, \mathcal{C}, \Pi, W)$ with:

- $\mathcal{X} = \mathcal{G} \times \mathcal{B} \times \mathcal{L} \times \mathbb{N} \times \Lambda$. A state is a `SwarmTaskGraph`, a `SwarmBudgetPool`, a `ReservationLedger`, the clock, and the shadow-price vector $\boldsymbol{\lambda}$.
- $C(x) = (ES, LS, \mathrm{slack}, \{\sigma_i\}_i, q^\star)$. Earliest and latest starts, slack, Weitzman reservation prices, and the newsvendor fractile are all computed exactly in integer or `FixedQ16_16` arithmetic. Every value lands in $\mathbb{K}_3$ as $+$ or $-$, with $\bot$ reserved for a missing predictor output.
- $P(x)$ is two Tier-0 `FixedQ16_16` heads. One emits a discrete reward distribution $\hat F_i$ per ready task, the other a discrete settlement distribution $\hat F_S$ per delivery contract. Either head may return $\bot$.
- $\mathcal{C}(x)$ is the dispatch envelope $\{\mathrm{Hold}\} \cup \{\mathrm{Open}(i) : i \text{ ready},\ b_i \le \text{open pool},\ t \le LS_i\}$ and, for escrow, the interval $[h_{\min}, h_{\max}]$.
- $\Pi$ is bit-set membership for dispatch and `clamp` for holds. Both are $O(1)$.
- $W$ is the `SwarmRoutePlanReceipt` carrying the slack vector hash, the $\sigma$ vector, the fractile, and the hold, chained through `SwarmDelegationWitnessChain`.

**Critical path over the DAG.** Let $G = (V, E)$ with $|V| \le 1024$, $|E| \le 4096$, durations $d_v \in \mathbb{N}$. A `SwarmGraphJoin` $(v, k)$ says $v$ may start once $k$ of its predecessors have finished. Define, in topological order,

$$ES_v = \begin{cases} 0 & \deg^-(v) = 0 \\ \max_{(u,v)\in E} EF_u & \text{AND-join} \\ \mathrm{kth}\{EF_u : (u,v) \in E\} & k\text{-of-}n \text{ join} \end{cases}, \qquad EF_v = ES_v + d_v,$$

$H = \max_v EF_v$, and in reverse topological order $LF_v = \min(\{H\} \cup \{LS_s : (v,s) \in E,\ EF_v \le ES_s\})$, $LS_v = LF_v - d_v$, $\mathrm{slack}_v = LS_v - ES_v$. The binding condition $EF_v \le ES_s$ is the only departure from the textbook backward pass. It is always true under AND-joins and is what makes quorum joins sound.

**Theorem 1 (well-definedness).** For every $v$, $LF_v \ge EF_v$, hence $LS_v \ge ES_v$ and $\mathrm{slack}_v \ge 0$. Both `checked_sub` calls in the backward pass therefore never fail on a valid graph.

*Proof.* Reverse induction on topological index. For a sink, $LF_v = H \ge EF_v$ by definition of $H$. Otherwise each term in the minimum is either $H \ge EF_v$ or $LS_s$ for a binding successor $s$. By the inductive hypothesis $LS_s = LF_s - d_s \ge EF_s - d_s = ES_s$, and binding gives $ES_s \ge EF_v$. A non-binding successor $s$ has $EF_v > ES_s$, meaning $v$ was not among the $k$ earliest predecessors of $s$. Delaying $v$ then cannot change the $k$-th order statistic, so $s$ imposes no constraint on $v$, and omitting it is exact rather than a relaxation. $\square$

**Hu's priority falls out for free.** The longest path from $v$ to a sink equals $H - LS_v$. For in-forest segments with unit durations, Hu's highest-level-first list is optimal on $m$ identical workers. Since the level is part of $C(x)$, the learned head may only reorder tasks of equal level there, and projection preserves Hu optimality on those segments.

**Theorem 2 (Graham bound, transfer form).** For any list order $\pi$, including one produced by a learned head, the list schedule on $m$ workers satisfies $C_{\max}(\pi) \le (2 - \tfrac{1}{m})\, C^\star_{\max}$.

*Proof sketch.* Let $j_1$ be the last job to finish. Whenever a worker is idle before $j_1$ starts, some predecessor of the currently waiting chain job is running. Walk predecessors backwards to build a chain $j_r \prec \dots \prec j_1$ such that every idle slot overlaps a chain job. Then $m\,C_{\max} \le \sum_j d_j + (m-1)\sum_{\text{chain}} d_j \le m\,C^\star + (m-1)\,C^\star$. The argument never inspects $\pi$, which is exactly why the proof discharges once with the learned choice modeled as nondeterminism. $\square$

Graham also showed list schedules are not monotone in $m$, in priorities, or in durations. That anomaly is the reason the swarm never trusts a learned order to *improve* makespan. The envelope guarantees the bound, the predictor only picks inside it.

**Pandora's box over ready tasks.** Each ready task $i$ is a box with inspection cost $c_i$ and reward $X_i \sim F_i$. The shadow-priced cost is

$$c_i = \lambda_{\text{budget}}\, b_i + \lambda_{\text{latency}}\, d_i + \lambda_{\text{escrow}}\, h_i .$$

Weitzman's reservation price $\sigma_i$ is the unique root of $g_i(\sigma) = \mathbb{E}[(X_i - \sigma)^+] - c_i$.

**Theorem 3 (Weitzman, exact form).** Opening boxes in decreasing $\sigma_i$ and stopping when the best realized reward exceeds the highest remaining $\sigma_i$ maximizes expected reward net of inspection costs. For a discrete $F_i$ with sorted support $x_0 \le \dots \le x_{n-1}$ and weights $w_k$, let $j$ be the least index with $\mathbb{E}[(X - x_j)^+] \le c_i$. Then

$$\sigma_i = \frac{\sum_{k \ge j} w_k x_k - c_i}{\sum_{k \ge j} w_k}.$$

*Proof.* Optimality is Weitzman's 1979 theorem. For the closed form, $g$ is continuous, strictly decreasing on $(-\infty, x_{n-1}]$, and $g(x_{n-1}) = -c_i < 0$, so $j$ exists. On $[x_{j-1}, x_j]$ the positive part is active exactly for $k \ge j$, so $g$ is affine there with slope $-\sum_{k\ge j} w_k$. Solving $g(\sigma) = 0$ gives the formula. Minimality of $j$ gives $g(x_{j-1}) > 0$, so the root lies in the interval. $\square$

The Rust floors the quotient. A lower $\sigma$ dispatches less, which is the conservative direction.

**Proposition 4 (calibration bracket).** If the predicted CDF $\hat F$ is within Kolmogorov distance $\epsilon$ of the true $F$, then $|g_F(\sigma) - g_{\hat F}(\sigma)| \le \epsilon\,(x_{\max} - \sigma)$ for all $\sigma \le x_{\max}$.

*Proof.* Integration by parts gives $\mathbb{E}[(X-\sigma)^+] = \int_\sigma^{x_{\max}} (1 - F(t))\,dt$. Subtract the two integrals and bound the integrand by $\epsilon$. $\square$

So a miscalibrated head shifts the index by a controlled amount, while the envelope holds regardless of $\epsilon$.

**Pool conservation.** For a node $v$ with children $\mathrm{ch}(v)$ the fan-out rule is $\sum_{u \in \mathrm{ch}(v)} b_u \le b_v$, the exact analogue of the basis-point rule in `budget_split.rs`. At a join with inputs $\mathrm{in}(j)$ the fan-in rule reclaims $\sum_{u \in \mathrm{in}(j)} (b_u - \mathrm{spent}_u)$ with $\mathrm{spent}_u \le b_u$. Together they give the global invariant $\sum_v \mathrm{spent}_v + \mathrm{free} = \mathrm{total}$.

**Rust: scheduling module.** New file, no changes to `types.rs`. The crate root carries `#![no_std]`, `#![forbid(unsafe_code)]`, and `#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]`.

```rust
//! crates/kernel/chio-swarm-authority/src/schedule.rs  (additive)
use crate::types::{MAX_SWARM_GRAPH_EDGES, MAX_SWARM_GRAPH_JOINS, MAX_SWARM_GRAPH_TASKS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwarmScheduleError {
    TooManyTasks { count: usize },
    TooManyEdges { count: usize },
    TooManyJoins { count: usize },
    EdgeOutOfRange { index: usize },
    JoinOutOfRange { index: usize },
    SelfLoop { task: usize },
    QuorumOutOfRange { task: usize },
    Cycle { unscheduled: usize },
    MissingTask { task: usize },
    MissingEdge { index: usize },
    MissingJoin { index: usize },
    DurationOverflow { task: usize },
    FanOutOversubscribed { parent_units: u64, requested_units: u64 },
    FanInExceedsAllocation { index: usize },
    Overflow,
    Internal,
}

/// Read-only view implemented for the existing `SwarmTaskGraph`.
pub trait SwarmGraphView {
    fn task_count(&self) -> usize;
    fn duration_units(&self, task: usize) -> Option<u64>;
    fn edge_count(&self) -> usize;
    fn edge(&self, index: usize) -> Option<(usize, usize)>;
    fn join_count(&self) -> usize;
    /// `(target, required)`: target starts once `required` predecessors finished.
    fn join(&self, index: usize) -> Option<(usize, u16)>;
}

pub struct CriticalPath {
    pub earliest_start: [u64; MAX_SWARM_GRAPH_TASKS],
    pub earliest_finish: [u64; MAX_SWARM_GRAPH_TASKS],
    pub latest_start: [u64; MAX_SWARM_GRAPH_TASKS],
    pub slack: [u64; MAX_SWARM_GRAPH_TASKS],
    pub topo_order: [u16; MAX_SWARM_GRAPH_TASKS],
    pub makespan: u64,
    pub task_count: usize,
}

impl CriticalPath {
    pub const fn empty() -> Self {
        Self {
            earliest_start: [0; MAX_SWARM_GRAPH_TASKS],
            earliest_finish: [0; MAX_SWARM_GRAPH_TASKS],
            latest_start: [0; MAX_SWARM_GRAPH_TASKS],
            slack: [0; MAX_SWARM_GRAPH_TASKS],
            topo_order: [0; MAX_SWARM_GRAPH_TASKS],
            makespan: 0,
            task_count: 0,
        }
    }
    pub fn is_critical(&self, task: usize) -> bool {
        task < self.task_count && self.slack.get(task).copied() == Some(0)
    }
    /// Opening `task` at `now` does not extend the makespan.
    pub fn deadline_feasible(&self, task: usize, now: u64) -> bool {
        task < self.task_count && self.latest_start.get(task).map_or(false, |ls| now <= *ls)
    }
}

fn get(arr: &[u64], i: usize) -> Result<u64, SwarmScheduleError> {
    arr.get(i).copied().ok_or(SwarmScheduleError::Internal)
}
fn put(arr: &mut [u64], i: usize, v: u64) -> Result<(), SwarmScheduleError> {
    *arr.get_mut(i).ok_or(SwarmScheduleError::Internal)? = v;
    Ok(())
}
fn edge_at<G: SwarmGraphView>(g: &G, k: usize) -> Result<(usize, usize), SwarmScheduleError> {
    g.edge(k).ok_or(SwarmScheduleError::MissingEdge { index: k })
}
fn push_ready(order: &mut [u16], tail: &mut usize, v: usize) -> Result<(), SwarmScheduleError> {
    *order.get_mut(*tail).ok_or(SwarmScheduleError::Internal)? =
        u16::try_from(v).map_err(|_| SwarmScheduleError::Internal)?;
    *tail = tail.checked_add(1).ok_or(SwarmScheduleError::Overflow)?;
    Ok(())
}

/// Exact k-th smallest earliest finish among predecessors of `target`.
fn quorum_start<G: SwarmGraphView>(
    g: &G, finish: &[u64], target: usize, k: u16, m: usize,
) -> Result<u64, SwarmScheduleError> {
    let mut best: Option<u64> = None;
    for a in 0..m {
        let (p, t) = edge_at(g, a)?;
        if t != target { continue; }
        let ef_p = get(finish, p)?;
        let mut count: u16 = 0;
        for b in 0..m {
            let (q, t2) = edge_at(g, b)?;
            if t2 == target && get(finish, q)? <= ef_p {
                count = count.checked_add(1).ok_or(SwarmScheduleError::Overflow)?;
            }
        }
        if count >= k && best.map_or(true, |x| ef_p < x) { best = Some(ef_p); }
    }
    best.ok_or(SwarmScheduleError::Internal)
}

pub fn compute_critical_path<G: SwarmGraphView>(
    g: &G, out: &mut CriticalPath,
) -> Result<(), SwarmScheduleError> {
    let n = g.task_count();
    if n > MAX_SWARM_GRAPH_TASKS { return Err(SwarmScheduleError::TooManyTasks { count: n }); }
    let m = g.edge_count();
    if m > MAX_SWARM_GRAPH_EDGES { return Err(SwarmScheduleError::TooManyEdges { count: m }); }
    let joins = g.join_count();
    if joins > MAX_SWARM_GRAPH_JOINS { return Err(SwarmScheduleError::TooManyJoins { count: joins }); }

    let mut indeg = [0u16; MAX_SWARM_GRAPH_TASKS];
    for k in 0..m {
        let (u, v) = edge_at(g, k)?;
        if u >= n || v >= n { return Err(SwarmScheduleError::EdgeOutOfRange { index: k }); }
        if u == v { return Err(SwarmScheduleError::SelfLoop { task: u }); }
        let d = indeg.get_mut(v).ok_or(SwarmScheduleError::Internal)?;
        *d = d.checked_add(1).ok_or(SwarmScheduleError::Overflow)?;
    }
    let mut quorum = [0u16; MAX_SWARM_GRAPH_TASKS]; // 0 encodes an AND-join
    for k in 0..joins {
        let (t, required) = g.join(k).ok_or(SwarmScheduleError::MissingJoin { index: k })?;
        if t >= n { return Err(SwarmScheduleError::JoinOutOfRange { index: k }); }
        let deg = indeg.get(t).copied().ok_or(SwarmScheduleError::Internal)?;
        if required == 0 || required > deg { return Err(SwarmScheduleError::QuorumOutOfRange { task: t }); }
        *quorum.get_mut(t).ok_or(SwarmScheduleError::Internal)? = required;
    }

    // Kahn's algorithm over a bounded ready ring.
    let mut remaining = indeg;
    let (mut head, mut tail) = (0usize, 0usize);
    for v in 0..n {
        if remaining.get(v).copied() == Some(0) { push_ready(&mut out.topo_order, &mut tail, v)?; }
    }
    while head < tail {
        let u = usize::from(*out.topo_order.get(head).ok_or(SwarmScheduleError::Internal)?);
        head = head.checked_add(1).ok_or(SwarmScheduleError::Overflow)?;
        for k in 0..m {
            let (a, b) = edge_at(g, k)?;
            if a != u { continue; }
            let r = remaining.get_mut(b).ok_or(SwarmScheduleError::Internal)?;
            *r = r.checked_sub(1).ok_or(SwarmScheduleError::Internal)?;
            if *r == 0 { push_ready(&mut out.topo_order, &mut tail, b)?; }
        }
    }
    if tail != n {
        return Err(SwarmScheduleError::Cycle {
            unscheduled: n.checked_sub(tail).ok_or(SwarmScheduleError::Internal)?,
        });
    }

    // Forward pass.
    let mut makespan: u64 = 0;
    for idx in 0..n {
        let v = usize::from(*out.topo_order.get(idx).ok_or(SwarmScheduleError::Internal)?);
        let d = g.duration_units(v).ok_or(SwarmScheduleError::MissingTask { task: v })?;
        let q = quorum.get(v).copied().ok_or(SwarmScheduleError::Internal)?;
        let es = if indeg.get(v).copied() == Some(0) {
            0
        } else if q == 0 {
            let mut es = 0u64;
            for k in 0..m {
                let (p, t) = edge_at(g, k)?;
                if t == v { es = es.max(get(&out.earliest_finish, p)?); }
            }
            es
        } else {
            quorum_start(g, &out.earliest_finish, v, q, m)?
        };
        let ef = es.checked_add(d).ok_or(SwarmScheduleError::DurationOverflow { task: v })?;
        put(&mut out.earliest_start, v, es)?;
        put(&mut out.earliest_finish, v, ef)?;
        makespan = makespan.max(ef);
    }

    // Backward pass; a successor binds `v` only if `v` finished by its quorum start.
    for idx in (0..n).rev() {
        let v = usize::from(*out.topo_order.get(idx).ok_or(SwarmScheduleError::Internal)?);
        let d = g.duration_units(v).ok_or(SwarmScheduleError::MissingTask { task: v })?;
        let ef_v = get(&out.earliest_finish, v)?;
        let mut lf = makespan;
        for k in 0..m {
            let (a, s) = edge_at(g, k)?;
            if a == v && ef_v <= get(&out.earliest_start, s)? {
                lf = lf.min(get(&out.latest_start, s)?);
            }
        }
        let ls = lf.checked_sub(d).ok_or(SwarmScheduleError::Internal)?;
        let slack = ls.checked_sub(get(&out.earliest_start, v)?).ok_or(SwarmScheduleError::Internal)?;
        put(&mut out.latest_start, v, ls)?;
        put(&mut out.slack, v, slack)?;
    }
    out.makespan = makespan;
    out.task_count = n;
    Ok(())
}

/// Fan-out: children may not oversubscribe the parent. Returns the remainder.
pub fn fan_out_remainder(parent_units: u64, child_units: &[u64]) -> Result<u64, SwarmScheduleError> {
    let mut requested: u64 = 0;
    for c in child_units {
        requested = requested.checked_add(*c).ok_or(SwarmScheduleError::Overflow)?;
    }
    parent_units.checked_sub(requested).ok_or(SwarmScheduleError::FanOutOversubscribed {
        parent_units, requested_units: requested,
    })
}

/// Fan-in: reclaim exactly the unspent allocation of every joined child.
pub fn fan_in_reclaim(allocated: &[u64], spent: &[u64]) -> Result<u64, SwarmScheduleError> {
    if allocated.len() != spent.len() { return Err(SwarmScheduleError::Internal); }
    let mut reclaimed: u64 = 0;
    for (i, (a, s)) in allocated.iter().zip(spent).enumerate() {
        let unspent = a.checked_sub(*s).ok_or(SwarmScheduleError::FanInExceedsAllocation { index: i })?;
        reclaimed = reclaimed.checked_add(unspent).ok_or(SwarmScheduleError::Overflow)?;
    }
    Ok(reclaimed)
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    #[kani::unwind(5)]
    fn fan_out_conserves_units() {
        let parent: u64 = kani::any();
        let children: [u64; 3] = kani::any();
        if let Ok(rest) = fan_out_remainder(parent, &children) {
            let sum = children[0].checked_add(children[1]).and_then(|s| s.checked_add(children[2]));
            assert_eq!(sum.and_then(|s| s.checked_add(rest)), Some(parent));
        }
    }
}
```

Complexity is $O(n\,m + \sum_v \deg(v)\,m)$, which is bounded by $O(m^2)$ at the caps. This runs at admission time, not on the Tier-0 hot path, and uses no heap.

**Rust: Pandora module.** `FixedQ16_16` is spelled out so the file is self-contained. At integration the Tier-0 crate's type is re-exported instead.

```rust
//! crates/kernel/chio-swarm-authority/src/pandora.rs  (additive)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(pub i64);

impl FixedQ16_16 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(65_536);
    pub fn from_units(v: u64) -> Option<Self> {
        i64::try_from(v).ok()?.checked_mul(Self::ONE.0).map(Self)
    }
    pub fn checked_add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(Self) }
    pub fn checked_sub(self, o: Self) -> Option<Self> { self.0.checked_sub(o.0).map(Self) }
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        let wide = i128::from(self.0).checked_mul(i128::from(o.0))?;
        i64::try_from(wide.checked_shr(16)?).ok().map(Self)
    }
}

pub const MAX_SUPPORT_POINTS: usize = 16;
pub const WEIGHT_ONE_Q16: u32 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PandoraError { BadSupport, Unsorted, BadWeights, NonPositiveCost, Overflow, Internal }

/// Tier-0 head output: sorted support with Q0.16 weights summing to one.
#[derive(Clone, Copy, Debug)]
pub struct DiscreteDistribution {
    pub values: [FixedQ16_16; MAX_SUPPORT_POINTS],
    pub weights_q16: [u32; MAX_SUPPORT_POINTS],
    pub len: usize,
}

impl DiscreteDistribution {
    fn point(&self, k: usize) -> Result<(FixedQ16_16, u32), PandoraError> {
        let v = *self.values.get(k).ok_or(PandoraError::BadSupport)?;
        let w = *self.weights_q16.get(k).ok_or(PandoraError::BadSupport)?;
        Ok((v, w))
    }

    pub fn validate(&self) -> Result<(), PandoraError> {
        if self.len == 0 || self.len > MAX_SUPPORT_POINTS { return Err(PandoraError::BadSupport); }
        let mut total: u32 = 0;
        let mut prev: Option<FixedQ16_16> = None;
        for k in 0..self.len {
            let (v, w) = self.point(k)?;
            if prev.map_or(false, |p| v < p) { return Err(PandoraError::Unsorted); }
            prev = Some(v);
            total = total.checked_add(w).ok_or(PandoraError::BadWeights)?;
        }
        if total != WEIGHT_ONE_Q16 { return Err(PandoraError::BadWeights); }
        Ok(())
    }

    /// Exact E[(X - sigma)^+], floored to Q16.16.
    pub fn expected_overshoot(&self, sigma: FixedQ16_16) -> Result<FixedQ16_16, PandoraError> {
        let mut acc: i128 = 0;
        for k in 0..self.len {
            let (v, w) = self.point(k)?;
            if v > sigma {
                let diff = v.checked_sub(sigma).ok_or(PandoraError::Overflow)?;
                let term = i128::from(w).checked_mul(i128::from(diff.0)).ok_or(PandoraError::Overflow)?;
                acc = acc.checked_add(term).ok_or(PandoraError::Overflow)?;
            }
        }
        let scaled = acc.checked_shr(16).ok_or(PandoraError::Overflow)?;
        i64::try_from(scaled).map(FixedQ16_16).map_err(|_| PandoraError::Overflow)
    }

    /// Weitzman reservation price, closed form of Theorem 3, floored.
    pub fn reservation_price(&self, cost: FixedQ16_16) -> Result<FixedQ16_16, PandoraError> {
        self.validate()?;
        if cost.0 <= 0 { return Err(PandoraError::NonPositiveCost); }
        let mut j = self.len;
        for k in 0..self.len {
            let (xk, _) = self.point(k)?;
            if self.expected_overshoot(xk)? <= cost { j = k; break; }
        }
        if j == self.len { return Err(PandoraError::Internal); }
        let (mut tail_w, mut tail_wx): (i128, i128) = (0, 0);
        for k in j..self.len {
            let (x, w) = self.point(k)?;
            tail_w = tail_w.checked_add(i128::from(w)).ok_or(PandoraError::Overflow)?;
            let wx = i128::from(w).checked_mul(i128::from(x.0)).ok_or(PandoraError::Overflow)?;
            tail_wx = tail_wx.checked_add(wx).ok_or(PandoraError::Overflow)?;
        }
        let scaled_cost = i128::from(cost.0).checked_shl(16).ok_or(PandoraError::Overflow)?;
        let numer = tail_wx.checked_sub(scaled_cost).ok_or(PandoraError::Overflow)?;
        let sigma = numer.checked_div_euclid(tail_w).ok_or(PandoraError::Internal)?;
        i64::try_from(sigma).map(FixedQ16_16).map_err(|_| PandoraError::Overflow)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShadowPrices {
    pub budget: FixedQ16_16,
    pub fuel: FixedQ16_16,
    pub latency: FixedQ16_16,
    pub memory: FixedQ16_16,
    pub escrow: FixedQ16_16,
}

/// c_i = lambda_budget * b_i + lambda_latency * d_i + lambda_escrow * h_i
pub fn inspection_cost(
    lambda: &ShadowPrices, budget_units: u64, duration_units: u64, hold_units: u64,
) -> Option<FixedQ16_16> {
    let b = lambda.budget.checked_mul(FixedQ16_16::from_units(budget_units)?)?;
    let d = lambda.latency.checked_mul(FixedQ16_16::from_units(duration_units)?)?;
    let h = lambda.escrow.checked_mul(FixedQ16_16::from_units(hold_units)?)?;
    b.checked_add(d)?.checked_add(h)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatch { Open(u16), Hold }

/// Only `project` and `weitzman_select` can construct this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedDispatch(Dispatch);
impl ShieldedDispatch { pub fn get(&self) -> Dispatch { self.0 } }

/// Feasible set over at most 1_024 tasks; `Hold` is always feasible.
pub struct DispatchEnvelope { bits: [u64; 16], len: usize }

impl DispatchEnvelope {
    pub fn new(len: usize) -> Option<Self> {
        (len <= 1_024).then_some(Self { bits: [0; 16], len })
    }
    pub fn admit(&mut self, task: usize) -> Option<()> {
        if task >= self.len { return None; }
        let word = self.bits.get_mut(task.checked_shr(6)?)?;
        *word |= 1u64.checked_shl(u32::try_from(task & 63).ok()?)?;
        Some(())
    }
    pub fn contains(&self, task: usize) -> bool {
        task < self.len
            && task.checked_shr(6).and_then(|w| self.bits.get(w)).map_or(false, |word| {
                u32::try_from(task & 63).ok().and_then(|s| word.checked_shr(s)).map_or(false, |b| b & 1 == 1)
            })
    }
}

pub fn project(env: &DispatchEnvelope, proposed: Dispatch) -> ShieldedDispatch {
    match proposed {
        Dispatch::Open(t) if env.contains(usize::from(t)) => ShieldedDispatch(proposed),
        _ => ShieldedDispatch(Dispatch::Hold),
    }
}

/// Weitzman index policy over the envelope. A `None` entry is the predictor's bottom
/// value and excludes the task. Stops with `Hold` once the best realized reward wins.
pub fn weitzman_select(
    env: &DispatchEnvelope, sigma: &[Option<FixedQ16_16>], best_realized: FixedQ16_16,
) -> ShieldedDispatch {
    let mut best: Option<(usize, FixedQ16_16)> = None;
    for (t, s) in sigma.iter().enumerate().take(env.len) {
        if let Some(s) = s {
            if env.contains(t) && best.map_or(true, |(_, b)| *s > b) { best = Some((t, *s)); }
        }
    }
    match best {
        Some((t, s)) if s > best_realized => u16::try_from(t)
            .map(|t| project(env, Dispatch::Open(t)))
            .unwrap_or(ShieldedDispatch(Dispatch::Hold)),
        _ => ShieldedDispatch(Dispatch::Hold),
    }
}
```

The envelope is populated by the authority from three exact predicates per ready task: `deadline_feasible`, `fan_out_remainder` succeeding for its budget, and the `SwarmBudgetPool` having open units. The head never sees the envelope and cannot widen it.

## 2. Reversible Escrow Calculus

**Ledger algebra.** Write a `ReservationLedger` as $\ell = (R, c, r, t)$ and define $S(\ell) = c + r + t$. The conservation invariant is $I(\ell) \equiv S(\ell) \le R$. Terminal means $S(\ell) = R$, matching `ledger_is_terminal`. The op codes of `ledger_apply` act as: reserve adds to $R$ and is accepted only while $S = 0$; commit, release, and retain add to $c$, $r$, $t$ respectively and are accepted only if the result keeps $I$. A rejected op leaves the state unchanged. These are the properties the Kani harness below checks against the existing function, so the harness is the oracle for the actual implementation.

**Theorem 5 (conservation and reversibility frontier).** (a) $I$ is preserved by every accepted op. (b) Once terminal, every commit, release, or retain with positive amount is rejected. (c) If $c = t = 0$, a single release of $R - r$ reaches the terminal state. (d) In general the maximal releasable amount is $R - S(\ell)$, so the irreversible part of a hold is exactly $c + t$.

*Proof.* (a) Reserve requires $S = 0 \le R + n$. The other ops are accepted only under $S + n \le R$, which is the invariant of the successor. (b) Terminal gives $S + n = R + n > R$. (c) From $I$ and $c = t = 0$ we get $r \le R$, so $r + (R - r) = R$ is accepted and terminal. (d) Open units are $R - S$ by definition and every op is additive. $\square$

The `LocalReversibleHold` mode is precisely the regime of Theorem 5(c). The hold is fully reversible until the first commit or retain, and the commit amount is the irreversibility that the delivery receipt buys.

**Shadow-price-optimal hold sizing.** A hold $h$ locks capital for expected duration $T$ at shadow price $\lambda_{\text{escrow}}$ and risks a shortfall against the settled amount $S \sim F_S$, penalized at $\kappa$ per unit. The objective is

$$J(h) = \lambda_{\text{escrow}}\, T\, h + \kappa\, \mathbb{E}[(S - h)^+].$$

**Theorem 6 (fractile rule).** $J$ is convex. Let $q^\star = 1 - \lambda_{\text{escrow}} T / \kappa$. If $q^\star \le 0$ the minimizer is the smallest admissible hold. Otherwise the minimizer is the smallest support point $h$ with $F_S(h) \ge q^\star$.

*Proof.* $\mathbb{E}[(S-h)^+]$ is convex in $h$ as an expectation of convex functions, and the first term is linear. The right derivative is $\lambda_{\text{escrow}} T - \kappa (1 - F_S(h))$, nondecreasing in $h$. It is nonnegative exactly when $F_S(h) \ge q^\star$, so the first such support point minimizes $J$. If $q^\star \le 0$ the derivative is nonnegative everywhere. $\square$

**Envelope-bounded regret.** The projected hold lies in $[h_{\min}, h_{\max}]$ regardless of the head. Hence $J(\Pi(\hat h)) \le \lambda_{\text{escrow}} T h_{\max} + \kappa\, \mathbb{E}[(S - h_{\min})^+]$ for any head output, calibrated or not. If the head returns $\bot$, the projection returns $h_{\max}$, the full hold, which is the conservative fallback $\bot_x$ of the law. Under Kolmogorov error $\epsilon$ the same argument as Proposition 4 bounds $|J'(\hat h)| \le \kappa \epsilon$, so by convexity $J(\hat h) - J(h^\star) \le \kappa\,\epsilon\,(h_{\max} - h_{\min})$.

**Lemma 7 (hold covers commit).** If `budget_precheck(inv, units, 1, h)` passed at reservation and the settled amount satisfies $s \le h$, then `budget_commit(inv, units, 1, s)` is accepted at commit time, provided the hold is the only reservation against those units.

*Proof.* The precheck is monotone in cost: passing at unit cost $h$ and $s \le h$ implies passing at $s$. The hold itself serializes concurrent debits, so the remaining units at commit are those checked at reservation. $\square$

**Coupling to delivery.** For `FindingDeliverySettlementMode::LocalReversibleHold` the `DeliveryContract` drives the ledger as a state machine gated by `classify_time_window_code`:

- **Not yet valid.** No op is permitted.
- **Valid.** Reserve is permitted while nothing is settled. Commit requires `receipt_fields_coupled` to return true for all five fields of the delivery receipt. Retain is permitted on a sticky `PendingApproval` from the `GuardPipeline`. Release is always permitted.
- **Expired.** Only release is permitted, so an abandoned hold unwinds to terminal.

The guard pipeline's `validate_output_before_release` runs before commit. A `Deny` releases the open balance. `PendingApproval` retains the priced amount until a later guard or approver resolves it, and a later `Deny` in the same pass still wins because the pipeline keeps iterating. `requires_exact_released_output` forces the commit amount to equal the priced units of the exact released output.

**Metadata.** `RESERVED_RECEIPT_METADATA_KEYS` has type `[&str; 35]`, so adding a key changes the array type and breaks the pinned proofs. The escrow witness is therefore nested under the existing `FINDING_DELIVERY_METADATA_KEY` as an `escrow_hold_v1` object holding the hold, the fractile, $\lambda_{\text{escrow}}$, and the four ledger fields. The `LoadedWeights` hash of the Tier-0 head goes under the existing `model_metadata` key, which lets `evaluate_weights_binding` tie the fractile to the weights that produced $\hat F_S$.

**Rust: escrow module.**

```rust
//! crates/economy/chio-settle/src/escrow.rs  (additive)
//! Crate root: #![no_std] #![forbid(unsafe_code)]
//! #![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use chio_kernel_core::formal_aeneas::{ledger_apply, ReservationLedger};
use chio_kernel_core::formal_core::{budget_precheck, classify_time_window_code, receipt_fields_coupled};
use chio_swarm_authority::pandora::{FixedQ16_16, WEIGHT_ONE_Q16};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EscrowOp { Reserve = 0, Commit = 1, Release = 2, Retain = 3 }

impl EscrowOp {
    pub fn from_code(code: u8) -> Option<Self> {
        match code { 0 => Some(Self::Reserve), 1 => Some(Self::Commit), 2 => Some(Self::Release), 3 => Some(Self::Retain), _ => None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowError {
    NotYetValid,
    Expired { op: EscrowOp },
    ReceiptNotCoupled,
    UnknownWindowCode(u8),
    Rejected { op: EscrowOp, amount: u64 },
    ConservationViolated,
    BudgetPrecheckFailed,
    HoldOutsideEnvelope,
    Overflow,
}

pub fn settled(l: &ReservationLedger) -> Option<u64> {
    l.committed.checked_add(l.released)?.checked_add(l.retained)
}
pub fn conserved(l: &ReservationLedger) -> bool {
    settled(l).map_or(false, |s| s <= l.reserved)
}
pub fn open_units(l: &ReservationLedger) -> Option<u64> {
    l.reserved.checked_sub(settled(l)?)
}
/// Irreversible part of the hold: Theorem 5(d).
pub fn irreversible_units(l: &ReservationLedger) -> Option<u64> {
    l.committed.checked_add(l.retained)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HoldEnvelope { pub floor_units: u64, pub cap_units: u64 }

/// Tier-0 settlement head output: sorted support in units, Q0.16 weights.
#[derive(Clone, Copy, Debug)]
pub struct SettlementDistribution {
    pub values: [u64; 16],
    pub weights_q16: [u32; 16],
    pub len: usize,
}

/// q* = 1 - lambda_escrow * T / kappa, clamped to [0, 1], in Q0.16.
pub fn critical_fractile_q16(
    lambda_escrow: FixedQ16_16, lock_duration: FixedQ16_16, shortfall_penalty: FixedQ16_16,
) -> Option<u32> {
    if shortfall_penalty.0 <= 0 { return Some(0); }
    let carrying = lambda_escrow.checked_mul(lock_duration)?;
    if carrying.0 <= 0 { return Some(WEIGHT_ONE_Q16); }
    let ratio = i128::from(carrying.0).checked_shl(16)?.checked_div(i128::from(shortfall_penalty.0))?;
    let fractile = i128::from(WEIGHT_ONE_Q16).checked_sub(ratio)?;
    if fractile <= 0 { Some(0) } else { u32::try_from(fractile).ok() }
}

/// Theorem 6 projected onto the envelope. Bottom from the head yields the full hold.
pub fn size_hold(
    dist: Option<&SettlementDistribution>, fractile_q16: u32, env: HoldEnvelope,
) -> Result<u64, EscrowError> {
    if env.floor_units > env.cap_units { return Err(EscrowError::HoldOutsideEnvelope); }
    let Some(d) = dist else { return Ok(env.cap_units) };
    let mut cumulative: u32 = 0;
    let mut hold = env.cap_units;
    for k in 0..d.len.min(16) {
        let w = *d.weights_q16.get(k).ok_or(EscrowError::Overflow)?;
        cumulative = cumulative.checked_add(w).ok_or(EscrowError::Overflow)?;
        if cumulative >= fractile_q16 {
            hold = *d.values.get(k).ok_or(EscrowError::Overflow)?;
            break;
        }
    }
    Ok(hold.clamp(env.floor_units, env.cap_units))
}

/// Window gate: 0 = Valid, 1 = NotYetValid, 2 = Expired (classify_time_window_code).
pub fn escrow_permitted(window_code: u8, op: EscrowOp, receipt_coupled: bool) -> Result<(), EscrowError> {
    match (window_code, op) {
        (1, _) => Err(EscrowError::NotYetValid),
        (2, EscrowOp::Release) => Ok(()),
        (2, op) => Err(EscrowError::Expired { op }),
        (0, EscrowOp::Commit) if !receipt_coupled => Err(EscrowError::ReceiptNotCoupled),
        (0, _) => Ok(()),
        (code, _) => Err(EscrowError::UnknownWindowCode(code)),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DeliveryCommitWitness {
    pub capability_matches: bool,
    pub request_matches: bool,
    pub verdict_matches: bool,
    pub policy_hash_matches: bool,
    pub evidence_class_matches: bool,
}
impl DeliveryCommitWitness {
    pub fn coupled(&self) -> bool {
        receipt_fields_coupled(
            self.capability_matches, self.request_matches, self.verdict_matches,
            self.policy_hash_matches, self.evidence_class_matches,
        )
    }
}

/// One ledger transition through the existing `ledger_apply`, re-checked for conservation.
pub fn escrow_step(
    ledger: ReservationLedger, op: EscrowOp, amount: u64,
    now: u64, issued_at: u64, expires_at: u64, receipt_coupled: bool,
) -> Result<ReservationLedger, EscrowError> {
    let window = classify_time_window_code(now, issued_at, expires_at);
    escrow_permitted(window, op, receipt_coupled)?;
    let (next, accepted) = ledger_apply(ledger, op as u8, amount);
    if !accepted { return Err(EscrowError::Rejected { op, amount }); }
    if !conserved(&next) { return Err(EscrowError::ConservationViolated); }
    Ok(next)
}

/// Contract acceptance: budget precheck at the full hold, then reserve.
pub fn open_hold(
    hold_units: u64, remaining_invocations: u64, remaining_units: u64,
    now: u64, issued_at: u64, expires_at: u64,
) -> Result<ReservationLedger, EscrowError> {
    if !budget_precheck(remaining_invocations, remaining_units, 1, hold_units) {
        return Err(EscrowError::BudgetPrecheckFailed);
    }
    let empty = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
    escrow_step(empty, EscrowOp::Reserve, hold_units, now, issued_at, expires_at, false)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn ledger_apply_preserves_conservation_and_rejects_atomically() {
        let (reserved, committed, released, retained): (u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let before = ReservationLedger { reserved, committed, released, retained };
        kani::assume(conserved(&before));
        let op: u8 = kani::any();
        kani::assume(op <= 3);
        let amount: u64 = kani::any();
        let (after, accepted) = ledger_apply(before, op, amount);
        assert!(conserved(&after));
        if !accepted {
            assert!(after.reserved == reserved && after.committed == committed
                && after.released == released && after.retained == retained);
        } else if op != 0 {
            assert_eq!(after.reserved, reserved);
            assert!(after.committed >= committed && after.released >= released && after.retained >= retained);
        }
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn hold_never_leaves_envelope() {
        let floor: u64 = kani::any();
        let cap: u64 = kani::any();
        kani::assume(floor <= cap);
        let env = HoldEnvelope { floor_units: floor, cap_units: cap };
        let fractile: u32 = kani::any();
        let d = SettlementDistribution { values: kani::any(), weights_q16: kani::any(), len: kani::any() };
        if let Ok(h) = size_hold(Some(&d), fractile, env) { assert!(floor <= h && h <= cap); }
        assert_eq!(size_hold(None, fractile, env), Ok(cap));
    }

    #[kani::proof]
    fn window_gate_matches_state_machine() {
        let code: u8 = kani::any();
        kani::assume(code <= 3);
        let coupled: bool = kani::any();
        let op = EscrowOp::from_code(code).unwrap();
        assert!(escrow_permitted(1, op, coupled).is_err());
        assert_eq!(escrow_permitted(2, op, coupled).is_ok(), op == EscrowOp::Release);
        if op == EscrowOp::Commit { assert_eq!(escrow_permitted(0, op, coupled).is_ok(), coupled); }
    }
}
```

The first harness quantifies over every ledger satisfying $I$, every op code, and every amount, and it calls the pinned `ledger_apply` unchanged. That is the "Kani conservation proof" of the task, and it is strictly additive to `formal/proof-manifest.toml`.

## 3. Formal Artifacts and Proof Transfer

**Lean 4.** The model mirrors `ledger_apply`, with `none` standing for the rejected branch, and proves Theorem 5(a), (b), and (c).

```lean
-- formal/lean4/Chio/SwarmEscrow.lean  (additive; registered in formal/proof-manifest.toml)
namespace Chio.SwarmEscrow

structure ReservationLedger where
  reserved  : Nat
  committed : Nat
  released  : Nat
  retained  : Nat
  deriving Repr, DecidableEq

inductive Op where
  | reserve | commit | release | retain
  deriving Repr, DecidableEq

def settled (l : ReservationLedger) : Nat := l.committed + l.released + l.retained
def Conserved (l : ReservationLedger) : Prop := settled l ≤ l.reserved
def Terminal (l : ReservationLedger) : Prop := settled l = l.reserved

def apply (l : ReservationLedger) (op : Op) (n : Nat) : Option ReservationLedger :=
  match op with
  | .reserve => if settled l = 0 then some { l with reserved := l.reserved + n } else none
  | .commit  => if settled l + n ≤ l.reserved then some { l with committed := l.committed + n } else none
  | .release => if settled l + n ≤ l.reserved then some { l with released := l.released + n } else none
  | .retain  => if settled l + n ≤ l.reserved then some { l with retained := l.retained + n } else none

/-- Theorem 5(a): every accepted step preserves conservation. -/
theorem apply_conserved {l l' : ReservationLedger} {op : Op} {n : Nat}
    (h : Conserved l) (hap : apply l op n = some l') : Conserved l' := by
  unfold Conserved settled at h ⊢
  cases op <;> simp only [apply, settled] at hap <;> split at hap <;> cases hap <;> simp only <;> omega

/-- Theorem 5(b): a terminal ledger rejects any positive commit. -/
theorem terminal_blocks_commit {l : ReservationLedger} {n : Nat}
    (ht : Terminal l) (hn : 0 < n) : apply l .commit n = none := by
  unfold Terminal settled at ht
  simp only [apply, settled]
  rw [if_neg]
  omega

/-- Theorem 5(c): before any commit or retain, one release unwinds to terminal. -/
theorem reversible_before_commit {l : ReservationLedger}
    (h : Conserved l) (hc : l.committed = 0) (hr : l.retained = 0) :
    ∃ l', apply l .release (l.reserved - l.released) = some l' ∧ Terminal l' := by
  refine ⟨{ l with released := l.released + (l.reserved - l.released) }, ?_, ?_⟩
  · unfold Conserved settled at h
    simp only [apply, settled]
    rw [if_pos]
    omega
  · unfold Terminal settled
    simp only
    omega

end Chio.SwarmEscrow
```

**Apalache TLA+.** The hold sizer and every settlement amount are existential choices inside the envelope, so the invariant covers any head.

```tla
----------------------------- MODULE SwarmEscrow -----------------------------
EXTENDS Integers

CONSTANTS
  \* @type: Int;
  HoldCap
ASSUME HoldCap >= 0

VARIABLES
  \* @type: Int;
  reserved,
  \* @type: Int;
  committed,
  \* @type: Int;
  released,
  \* @type: Int;
  retained,
  \* @type: Int;
  window,      \* 1 = NotYetValid, 0 = Valid, 2 = Expired
  \* @type: Bool;
  coupled      \* receipt_fields_coupled(...) for the pending delivery

vars == <<reserved, committed, released, retained, window, coupled>>

Settled == committed + released + retained
Open    == reserved - Settled

Conservation == /\ 0 <= committed /\ 0 <= released /\ 0 <= retained
                /\ Settled <= reserved /\ reserved <= HoldCap
Terminal == Settled = reserved

Init == /\ reserved = 0 /\ committed = 0 /\ released = 0 /\ retained = 0
        /\ window \in {0, 1} /\ coupled \in BOOLEAN

\* The learned hold sizer is unconstrained nondeterminism inside [0, HoldCap].
Reserve == /\ window = 0 /\ Settled = 0
           /\ \E h \in 0..HoldCap : reserved' = h
           /\ UNCHANGED <<committed, released, retained, window, coupled>>

Commit  == /\ window = 0 /\ coupled
           /\ \E a \in 0..Open : committed' = committed + a
           /\ UNCHANGED <<reserved, released, retained, window, coupled>>

Retain  == /\ window = 0
           /\ \E a \in 0..Open : retained' = retained + a
           /\ UNCHANGED <<reserved, committed, released, window, coupled>>

Release == /\ window \in {0, 2}
           /\ \E a \in 0..Open : released' = released + a
           /\ UNCHANGED <<reserved, committed, retained, window, coupled>>

Unwind  == /\ window = 2 /\ Open > 0
           /\ released' = released + Open
           /\ UNCHANGED <<reserved, committed, retained, window, coupled>>

Tick    == /\ \/ window = 1 /\ window' = 0
              \/ window = 0 /\ window' = 2
           /\ UNCHANGED <<reserved, committed, released, retained, coupled>>

Couple  == /\ coupled' \in BOOLEAN
           /\ UNCHANGED <<reserved, committed, released, retained, window>>

Next == Reserve \/ Commit \/ Retain \/ Release \/ Unwind \/ Tick \/ Couple
Spec == Init /\ [][Next]_vars /\ WF_vars(Unwind)

InvConservation == Conservation
ExpiredUnwinds  == [](window = 2 => <>Terminal)
=============================================================================
```

Apalache checks `InvConservation` inductively. `ExpiredUnwinds` is a liveness property and is checked with TLC under the weak-fairness assumption on `Unwind`, which the runtime realizes by the expiry sweep that releases the open balance.

**Corollary (verification transfer for this angle).** Every artifact above quantifies over the learned choice as `kani::any()`, a Lean variable, or a TLA+ existential. The Graham bound in Theorem 2 quantifies over all lists, the Weitzman closed form in Theorem 3 takes the distribution as given, and the fractile rule in Theorem 6 is projected onto a fixed interval. Replacing or retraining either Tier-0 head therefore changes no proof obligation. What changes is only the quality of the choice inside the envelope, which Proposition 4 and the regret bound after Theorem 6 quantify in terms of calibration error.

**Recap.** The swarm layer now has an exact critical-path computation over `SwarmTaskGraph` that handles AND and quorum joins with a sound backward pass, a closed-form Weitzman reservation price in `FixedQ16_16` with shadow-priced inspection costs, and a bit-set dispatch envelope whose projection is constant time. Budget pool fan-out and fan-in are checked arithmetic with a Kani conservation harness. On the settlement side, the reversible hold is sized by the newsvendor fractile against $\lambda_{\text{escrow}}$, clamped to the contract envelope, and stepped through the pinned `ledger_apply` under the time-window gate and the five-field receipt coupling. Conservation and the reversibility frontier are proved in Lean, checked symbolically in Kani against the existing function, and model-checked in Apalache. All code paths are `no_std`, forbid unsafe code, and use checked arithmetic. The metadata witness nests under the existing finding-delivery key so the pinned receipt-key array and all current proofs are untouched. Remaining integration work is wiring `SwarmGraphView` onto the concrete `SwarmTaskGraph`, replacing the local `FixedQ16_16` with the Tier-0 re-export, and registering the new Lean file and Kani harnesses in the proof manifest.

---

# Verbatim Treatise - `wave4_angle_2_pheromone_restless_bandit_and_federation`

I will set out the decay law and the Whittle derivation first, then the two crates as `#![no_std]` Rust, then the Lean, Kani and Apalache obligations and the manifest wiring.

# Wave 4 Angle 2: Stigmergic Restless-Bandit Routing and the Sybil-Resistant Federation Shield

Both crates instantiate the Wave 1 tuple $\mathcal{D}_\ell$. The split is strict. The pheromone crate is predictor-side only and never gates anything. The federation crate owns the exact computation, the feasible envelope, the fallback and the projection. A bug in the index can only make routing worse, never unsafe.

| Component | `crates/trust/chio-pheromone` | `crates/trust/chio-federation` |
|---|---|---|
| $\mathcal{X}_\ell$ | per-peer trail $(s_a, a, H_a, n)$ | passport registry, epoch, ranked candidates |
| $C_\ell$ | integer decay ledger, closed-form index | time window, $\lceil\sqrt{N}\rceil$ cap, pair mask |
| $P_\ell$ | Whittle index with $\boldsymbol{\lambda}$-priced observation cost | consumes any signed score |
| $\mathcal{C}_\ell$ | none | valid, pair-diverse routes of fan-out at most $M$ |
| $\bot_x$ | none | `Hold` |
| $\Pi$ | none | greedy prefix projection, O(1) per candidate |

## 1. Pheromone decay and the closed-form Whittle index

**Decay law.** A trail has a floor $f \in [0,1)$ and a half-life of $h$ epochs. Its strength after $a$ passive epochs since the last reinforcement is

$$s_a = f + (1-f)\,\rho^{a}, \qquad \rho = 2^{-1/h},$$

so $s_{qh} = f + (1-f)2^{-q}$ exactly at multiples of the half-life. The staleness cost at age $a$ is $h(a) = 1 - s_a$, which is non-decreasing in $a$ and bounded by $1-f$. The cumulative staleness is $H_a = \sum_{j=1}^{a} h(j)$.

The integer law replaces $\rho$ by $\rho_Q = \lfloor 2^{16}\rho \rfloor$ and iterates $S_{a+1} = F + \lfloor (S_a - F)\rho_Q / 2^{16} \rfloor$ in raw Q16.16 units. Half-lives are pinned to a small set so that every $\rho_Q$ is a compile-time constant.

**Lemma 1 (floor domination).** For every $a$, $f \le S^Q_{a+1} \le S^Q_a$ and $S^Q_a \le s_a$.

*Proof.* The excess $E_a = S^Q_a - F$ satisfies $E_{a+1} = \lfloor E_a \rho_Q / 2^{16}\rfloor \le E_a$ because $\rho_Q \le 2^{16}$, and $E_{a+1} \ge 0$. For the comparison with the real law, induct: $E_{a+1} \le E_a \rho_Q 2^{-16} \le E_a \rho \le (S_a - F)\rho$, using $\rho_Q 2^{-16} \le \rho$ from floor rounding. $\square$

**Lemma 2 (saturation).** $S^Q_a = F$ for every $a \ge 16h + 1$, and once the excess is zero it stays zero.

*Proof.* The real excess is $(1-f)2^{16}\rho^{a} \le 2^{16 - a/h} < 1$ raw unit when $a > 16h$. By Lemma 1 the integer excess is at most the real excess, and it is an integer, so it is zero. Zero is a fixed point of the recursion. $\square$

Lemma 2 is what makes lazy advancement bounded. A trail that has been passive for a million epochs is advanced with at most $16h+1$ iterations and then a closed form for the remainder. The remainder adds exactly $(1-f)$ staleness per epoch because the strength is pinned to the floor.

**Lemma 3 (one-sided discretization).** Let $e_a = s_a - S^Q_a 2^{-16} \ge 0$ be the error in real units. Then $e_a < 2 \cdot 2^{-16}/(1-\rho)$ for all $a$.

*Proof.* In raw units, $e_{a+1} \le \rho e_a + E_a(\rho - \rho_Q 2^{-16}) + 1 < \rho e_a + 2$, since $E_a \le 2^{16}$ and $\rho - \rho_Q 2^{-16} < 2^{-16}$. Unrolling from $e_0 = 0$ gives $e_a < 2/(1-\rho)$ raw units. $\square$

**Restless-bandit model.** Each peer is an arm. Epochs are slotted. In every epoch every arm pays its staleness cost $h(a_i)$. Activating an arm means routing one probe or request to that peer. Activation costs $c$ and refreshes the trail, so the next age is $1$. Passive arms age by one. The federation can activate at most $M$ arms per epoch, where $M$ is the route fan-out admitted by the budget. The objective is to minimise the long-run average of $\sum_i h(a_i(t)) + c\,u_i(t)$ subject to $\sum_i u_i(t) \le M$. Relaxing the per-epoch constraint to a long-run average and attaching a Lagrange multiplier $W$ decouples the problem into one arm each, where $W$ is a subsidy paid for every passive epoch. This is exactly the Lagrangian structure of Wave 1: $W$ is the shadow price of fan-out, and $c$ is priced by the existing vector $\boldsymbol{\lambda}$.

**Observation cost.** The cost statement lists the resources one probe consumes. Its price is the inner product with the shadow prices:

$$c = \lambda_{\text{budget}}\,\text{units} + \lambda_{\text{fuel}}\,\text{fuel} + \lambda_{\text{latency}}\,\text{latency} + \lambda_{\text{memory}}\,\text{memory} + \lambda_{\text{escrow}}\,\text{escrow}.$$

Every term is a Q16.16 price times an integer quantity, so $c$ is itself in Q16.16 raw units and is computed exactly.

**Theorem 1 (closed-form Whittle index).** For the single-arm problem with subsidy $W$, average-reward criterion, non-decreasing staleness cost, activation cost $c$, and full refresh on activation, the Whittle index at age $a$ is

$$W(a) = a\,h(a+1) - H_a - c.$$

Under the exact exponential law this is

$$W(a) = (1-f)\left[\rho\,\frac{1-\rho^{a}}{1-\rho} - a\,\rho^{a+1}\right] - c, \qquad \lim_{a\to\infty} W(a) = \frac{(1-f)\rho}{1-\rho} - c.$$

*Proof.* Under a stationary policy the arm regenerates at every activation, so by the renewal-reward theorem its gain is a cycle ratio. For monotone staleness costs the optimal single-arm policy is a threshold policy that activates exactly when the age reaches some $k$; this is the classical structure for age-of-information costs and we use it as given. Such a policy cycles through ages $1,\dots,k$, pays $H_k + c$, and collects $(k-1)W$ in subsidy, so its average cost is $C_k(W) = (H_k + c - (k-1)W)/k$. The index at age $a$ is the subsidy that makes activating now and waiting one more epoch equally good, that is $C_a(W) = C_{a+1}(W)$. Clearing denominators,

$$(a+1)\big(H_a + c - (a-1)W\big) = a\big(H_a + h(a+1) + c - aW\big).$$

The $a^2 W$ terms cancel and what remains is $H_a + c + W = a\,h(a+1)$, which is the claim. Substituting $h(j) = (1-f)(1-\rho^{j})$ and summing the geometric series gives the closed form. $\square$

**Theorem 2 (indexability).** $W(a+1) - W(a) = (a+1)\big(h(a+2) - h(a+1)\big) \ge 0$. Hence the passive set $\{a : W(a) \le W\}$ grows monotonically with $W$, the arm is indexable, and $C_k(W)$ is unimodal in $k$ with minimiser $\min\{k : W(k) > W\}$.

*Proof.* Expand $W(a+1) - W(a) = (a+1)h(a+2) - H_{a+1} - a\,h(a+1) + H_a$ and use $H_{a+1} - H_a = h(a+1)$. Monotonicity of $h$ gives the sign. From the indifference identity, $C_{k+1}(W) \le C_k(W)$ exactly when $W \ge W(k)$, so the set of $k$ where the cycle average still decreases is a prefix. $\square$

Two consequences matter for the integer router. First, beyond saturation $h$ is constant, so $W(a)$ is constant for $a \ge 16h+1$ and the stored index never overflows a signed 64-bit word. Second, by Lemma 3 the integer index differs from the real closed form by $O\!\big(a_{\text{sat}}/(1-\rho)\big)$ raw units uniformly in $a$, which only affects ranking quality.

**Newcomer discount.** A peer with tenure $n$ epochs below the horizon $H_{\text{new}}$ has the positive part of its index scaled by $n/H_{\text{new}}$. A freshly minted identity therefore needs $H_{\text{new}}$ epochs before it competes at full weight, which bounds the ramp rate of a Sybil before the federation shield ever sees it.

**Activation outcomes.** The index model assumes full refresh. The ledger rule on a served request is exactly that. On a failed request the trail evaporates to the floor and the cycle statistics reset. The failure branch lies outside the single-arm model and only changes the predictor's ranking, never feasibility.

```rust
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! chio-pheromone: restless-bandit trails with an exact Q16.16 Whittle index.
//! Predictor layer only. Nothing in this crate is a safety shield.

pub const DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS: u32 = 8;
/// Keeps `a * h(a+1)` below 2^40 so the i64 index arithmetic cannot overflow.
pub const MAX_PHEROMONE_AGE_EPOCHS: u32 = 1 << 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PheromoneError { FloorNotBelowOne, AgeBoundExceeded, SaturationBoundViolated, Overflow }

/// Unsigned Q16.16 restricted to the unit interval. `ONE` is 1.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Q16(u32);

impl Q16 {
    pub const ZERO: Q16 = Q16(0);
    pub const ONE: Q16 = Q16(1 << 16);
    pub const fn new(raw: u32) -> Option<Q16> { if raw <= Self::ONE.0 { Some(Q16(raw)) } else { None } }
    pub const fn raw(self) -> u32 { self.0 }
    /// Truncating product. Both operands are at most 2^16, so the product is at most 2^32.
    pub fn mul_trunc(self, rhs: Q16) -> Result<Q16, PheromoneError> {
        let p = u64::from(self.0)
            .checked_mul(u64::from(rhs.0))
            .and_then(|p| p.checked_shr(16))
            .ok_or(PheromoneError::Overflow)?;
        u32::try_from(p).map(Q16).map_err(|_| PheromoneError::Overflow)
    }
}

/// Pinned half-lives so that rho_Q = floor(2^(-1/h) * 2^16) is a constant (Lemma 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalfLife { E1, E2, E4, E8, E16, E32 }

impl HalfLife {
    pub const fn epochs(self) -> u32 {
        match self { Self::E1 => 1, Self::E2 => 2, Self::E4 => 4, Self::E8 => 8, Self::E16 => 16, Self::E32 => 32 }
    }
    pub const fn rho(self) -> Q16 {
        Q16(match self {
            Self::E1 => 32_768, Self::E2 => 46_340, Self::E4 => 55_108,
            Self::E8 => 60_096, Self::E16 => 62_757, Self::E32 => 64_131,
        })
    }
    /// 16h + 1 (Lemma 2).
    pub const fn saturation_epochs(self) -> u32 {
        match self { Self::E1 => 17, Self::E2 => 33, Self::E4 => 65, Self::E8 => 129, Self::E16 => 257, Self::E32 => 513 }
    }
}

/// Wave 1 shadow-price vector, Q16.16 each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowPrices {
    pub lambda_budget: Q16, pub lambda_fuel: Q16, pub lambda_latency: Q16,
    pub lambda_memory: Q16, pub lambda_escrow: Q16,
}

/// Resources consumed by one observation, i.e. one routed probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PheromoneObservationCostStatement {
    pub units: u32, pub fuel: u32, pub latency_us: u32, pub memory_bytes: u32, pub escrow_units: u32,
}

impl PheromoneObservationCostStatement {
    /// c = <lambda, cost> in Q16.16 raw units. Five terms below 2^48 each, so below 2^51.
    pub fn priced(&self, lambda: &ShadowPrices) -> Result<u64, PheromoneError> {
        let term = |l: Q16, c: u32| u64::from(l.raw()).checked_mul(u64::from(c));
        [term(lambda.lambda_budget, self.units), term(lambda.lambda_fuel, self.fuel),
         term(lambda.lambda_latency, self.latency_us), term(lambda.lambda_memory, self.memory_bytes),
         term(lambda.lambda_escrow, self.escrow_units)]
            .into_iter()
            .try_fold(0u64, |acc, t| t.and_then(|t| acc.checked_add(t)))
            .ok_or(PheromoneError::Overflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WhittleIndex(pub i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome { Served, Failed }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PheromoneTrail {
    strength: Q16,
    floor: Q16,
    half_life: HalfLife,
    age_epochs: u32,
    cumulative_staleness: u64,
    tenure_epochs: u32,
}

impl PheromoneTrail {
    pub fn new(floor: Q16, half_life: HalfLife) -> Result<Self, PheromoneError> {
        if floor >= Q16::ONE { return Err(PheromoneError::FloorNotBelowOne); }
        Ok(Self { strength: floor, floor, half_life, age_epochs: 0, cumulative_staleness: 0, tenure_epochs: 0 })
    }
    pub const fn strength(&self) -> Q16 { self.strength }
    pub const fn age_epochs(&self) -> u32 { self.age_epochs }

    /// S_{a+1} = F + trunc((S_a - F) * rho_Q).
    pub fn next_strength(&self) -> Result<Q16, PheromoneError> {
        let excess = self.strength.raw().checked_sub(self.floor.raw()).ok_or(PheromoneError::Overflow)?;
        let decayed = Q16::new(excess).ok_or(PheromoneError::Overflow)?.mul_trunc(self.half_life.rho())?;
        let raw = self.floor.raw().checked_add(decayed.raw()).ok_or(PheromoneError::Overflow)?;
        Q16::new(raw).ok_or(PheromoneError::Overflow)
    }

    /// One passive epoch of restless evolution.
    pub fn tick(&mut self) ->
```rust
    pub fn tick(&mut self) -> Result<(), PheromoneError> {
        if self.age_epochs >= MAX_PHEROMONE_AGE_EPOCHS { return Err(PheromoneError::AgeBoundExceeded); }
        let s = self.next_strength()?;
        let staleness = Q16::ONE.raw().checked_sub(s.raw()).ok_or(PheromoneError::Overflow)?;
        self.cumulative_staleness = self.cumulative_staleness
            .checked_add(u64::from(staleness)).ok_or(PheromoneError::Overflow)?;
        self.age_epochs = self.age_epochs.checked_add(1).ok_or(PheromoneError::Overflow)?;
        self.tenure_epochs = self.tenure_epochs.saturating_add(1);
        self.strength = s;
        Ok(())
    }

    /// Advance by `epochs` passive epochs in O(min(epochs, 16h + 1)) by Lemma 2.
    pub fn advance(&mut self, epochs: u32) -> Result<(), PheromoneError> {
        let bounded = epochs.min(self.half_life.saturation_epochs());
        let mut applied: u32 = 0;
        while applied < bounded && self.strength != self.floor {
            self.tick()?;
            applied = applied.checked_add(1).ok_or(PheromoneError::Overflow)?;
        }
        let rem = epochs.checked_sub(applied).ok_or(PheromoneError::Overflow)?;
        if rem == 0 { return Ok(()); }
        if self.strength != self.floor { return Err(PheromoneError::SaturationBoundViolated); }
        let new_age = self.age_epochs.checked_add(rem).ok_or(PheromoneError::Overflow)?;
        if new_age > MAX_PHEROMONE_AGE_EPOCHS { return Err(PheromoneError::AgeBoundExceeded); }
        let per_epoch = u64::from(Q16::ONE.raw().checked_sub(self.floor.raw()).ok_or(PheromoneError::Overflow)?);
        let added = per_epoch.checked_mul(u64::from(rem)).ok_or(PheromoneError::Overflow)?;
        self.cumulative_staleness = self.cumulative_staleness.checked_add(added).ok_or(PheromoneError::Overflow)?;
        self.age_epochs = new_age;
        self.tenure_epochs = self.tenure_epochs.saturating_add(rem);
        Ok(())
    }

    /// Activation outcome. `Served` is the full refresh of the index model.
    /// `Failed` evaporates to the floor. Both reset the cycle statistics.
    pub fn observe(&mut self, outcome: Outcome) {
        self.strength = match outcome { Outcome::Served => Q16::ONE, Outcome::Failed => self.floor };
        self.age_epochs = 0;
        self.cumulative_staleness = 0;
    }

    /// h(a+1) = 1 - S_{a+1} in raw units.
    fn staleness_next(&self) -> Result<u64, PheromoneError> {
        let s = self.next_strength()?;
        Ok(u64::from(Q16::ONE.raw().checked_sub(s.raw()).ok_or(PheromoneError::Overflow)?))
    }

    /// W(a) = a * h(a+1) - H_a - c (Theorem 1), then the newcomer discount on the positive part.
    pub fn whittle_index(
        &self,
        cost: &PheromoneObservationCostStatement,
        lambda: &ShadowPrices,
    ) -> Result<WhittleIndex, PheromoneError> {
        let to_i64 = |v: u64| i64::try_from(v).map_err(|_| PheromoneError::Overflow);
        let gross = u64::from(self.age_epochs)
            .checked_mul(self.staleness_next()?).ok_or(PheromoneError::Overflow)?;
        let c = to_i64(cost.priced(lambda)?)?;
        let w = to_i64(gross)?
            .checked_sub(to_i64(self.cumulative_staleness)?)
            .and_then(|w| w.checked_sub(c))
            .ok_or(PheromoneError::Overflow)?;
        let horizon = DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS;
        if w > 0 && self.tenure_epochs < horizon {
            let scaled = w.checked_mul(i64::from(self.tenure_epochs))
                .and_then(|v| v.checked_div(i64::from(horizon)))
                .ok_or(PheromoneError::Overflow)?;
            return Ok(WhittleIndex(scaled));
        }
        Ok(WhittleIndex(w))
    }
}
```

The Whittle policy sorts arms by index and hands the ordered list to the federation shield as ranked candidates. Sorting lives in `core`, so no allocation is needed. The bounds are simple. The gross term is below $2^{40}$ by the age cap, the cumulative staleness is below $2^{40}$ for the same reason, and the priced cost is below $2^{51}$, so every intermediate fits a signed 64-bit word with room for the discount multiply.

## 2. Sybil-resistant passport cap and pair-diversity shield

**Objects.** A passport binds an Iroh node identity to two bucket keys and a validity window. The scarcity bucket names a scarce resource such as an autonomous system or a relay region. The pair bucket names the finer resource across which two peers in one route must differ. Both keys are dense indices assigned deterministically by the compiled semantic registry, which is what makes every lookup a bounded array access rather than a hash probe.

Let $N$ be the number of live passports and $\kappa(N) = \lceil\sqrt{N}\rceil$ the cap. Let $\text{count}_b$ be the number of live passports in scarcity bucket $b$.

**Theorem 3 (admission invariant).** Define $I(R) :\equiv \forall b.\ \text{count}_b \le \kappa(N)$. Admission of a passport in bucket $b$ is permitted only when $\text{count}_b + 1 \le \kappa(N+1)$. Under this guard admission preserves $I$.

*Proof.* For the admitted bucket the guard is the claim. For any other bucket $b'$, $\text{count}_{b'}$ is unchanged and $\kappa(N) \le \kappa(N+1)$ because the ceiling of the square root is monotone. $\square$

Revocation shrinks $N$ and may leave some bucket above $\kappa(N)$. The shield does not evict, because eviction is destructive and the invariant is not what route safety rests on. What is preserved across arbitrary churn is the action property that no admission ever enters a bucket at or above the cap, since $\text{count}_b + 1 \le \kappa(N+1) \le \kappa(N) + 1$ forces $\text{count}_b \le \kappa(N)$ before the admission. An over-cap bucket therefore drains monotonically until it is under the cap again. The Apalache model checks exactly this action invariant.

**Theorem 4 (route shield).** Let the ranked candidate sequence be arbitrary. It may be adversarially ordered, contain duplicates, point at empty or expired slots, or claim a node that does not occupy the slot it names. The greedy prefix projection returns a route such that every selected node holds a passport valid at the current epoch, the pair buckets of selected nodes are pairwise distinct, the fan-out is at most $M$, and `Hold` is returned exactly when no candidate is feasible. Each candidate costs one slot read, one time-window comparison, and one bit test-and-set.

*Proof.* Validity and node agreement are checked before anything is recorded. The pair mask is set only for accepted candidates and tested before acceptance, so a second candidate in an occupied pair bucket is rejected. Two candidates with the same node have the same passport and therefore the same pair bucket, so pairwise distinct pair buckets imply pairwise distinct nodes. The loop stops at $M$ accepted entries. The fallback route is the initial state and is only departed from on acceptance. $\square$

When the ranked sequence is sorted by score, the output is the lexicographically first feasible route in prefix order. That is the sense in which the greedy pass is the projection $\Pi_{\mathcal{C}_\ell(x)}$ of the learned choice onto the envelope.

**Theorem 5 (Sybil bound).** An adversary who can occupy $B$ scarcity buckets and $P$ pair buckets holds at most $B\,\kappa(N)$ passports by Theorem 3 and occupies at most $\min(P, M)$ slots in any route by Theorem 4. Both bounds hold for every learned ranking. The passport share is therefore at most $B(1/\sqrt{N} + 1/N)$, and the route share is at most $\min(P,M)/M$.

The route bound is the operative one. It converts the number of distinct scarce resources the adversary controls into a hard cap on route presence, independent of how well the adversary has learned to game the predictor.

```rust
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! chio-federation: exact admission cap and O(1) route projection shield.

pub const MAX_SCARCITY_BUCKETS: usize = 4_096;
pub const MAX_PAIR_BUCKETS: usize = 4_096;
pub const MAX_ROUTE_FANOUT: usize = 64;
const PAIR_MASK_WORDS: usize = MAX_PAIR_BUCKETS / 64;

#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 32]);

/// Dense index assigned by `CompiledSemanticRegistryV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScarcityBucketKey(u16);
impl ScarcityBucketKey {
    pub const fn new(dense: u16) -> Option<Self> {
        if (dense as usize) < MAX_SCARCITY_BUCKETS { Some(Self(dense)) } else { None }
    }
    pub const fn dense(self) -> usize { self.0 as usize }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PairBucketKey(u16);
impl PairBucketKey {
    pub const fn new(dense: u16) -> Option<Self> {
        if (dense as usize) < MAX_PAIR_BUCKETS { Some(Self(dense)) } else { None }
    }
    pub const fn dense(self) -> usize { self.0 as usize }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Passport {
    pub node: NodeId,
    pub scarcity: ScarcityBucketKey,
    pub pair: PairBucketKey,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Mirror of `classify_time_window_code` (0 Valid, 1 NotYetValid, 2 Expired).
/// Definitional equality with the pinned kernel function is a manifest obligation.
pub const fn time_window_code(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at { 1 } else if now >= expires_at { 2 } else { 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FederationError {
    SqrtNPassportCapExceeded { bucket: ScarcityBucketKey, count: u32, cap: u32, live: u32 },
    RegistryCapacityExhausted,
    DuplicateNode,
    UnknownNode,
    PassportNotValidAt { code: u8 },
    BucketOutOfRange,
    Overflow,
}

/// Smallest k with k*k >= n. Exact for every u32 because 65_536^2 = 2^32 >= n.
pub fn isqrt_ceil(n: u32) -> u32 {
    let n64 = u64::from(n);
    let (mut lo, mut hi): (u64, u64) = (0, 65_536);
    while lo < hi {
        let half = hi.checked_sub(lo).and_then(|d| d.checked_shr(1)).unwrap_or(0);
        let mid = lo.checked_add(half).unwrap_or(hi);
        let sq = mid.checked_mul(mid).unwrap_or(u64::MAX);
        if sq >= n64 { hi = mid; } else { lo = mid.checked_add(1).unwrap_or(hi); }
    }
    u32::try_from(lo).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionWitness { pub slot: usize, pub live: u32, pub cap: u32 }

pub struct PassportRegistry<const CAP: usize> {
    slots: [Option<Passport>; CAP],
    live: u32,
    scarcity_counts: [u32; MAX_SCARCITY_BUCKETS],
}

impl<const CAP: usize> PassportRegistry<CAP> {
    pub const fn new() -> Self {
        Self { slots: [None; CAP], live: 0, scarcity_counts: [0; MAX_SCARCITY_BUCKETS] }
    }
    pub const fn live(&self) -> u32 { self.live }
    pub fn scarcity_count(&self, b: ScarcityBucketKey) -> u32 {
        self.scarcity_counts.get(b.dense()).copied().unwrap_or(0)
    }

    /// Admission is not hot-path; the duplicate scan is O(CAP).
    pub fn admit(&mut self, p: Passport, now: u64) -> Result<AdmissionWitness, FederationError> {
        let code = time_window_code(now, p.issued_at, p.expires_at);
        if code != 0 { return Err(FederationError::PassportNotValidAt { code }); }
        let mut free: Option<usize> = None;
        for (i, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(q) if q.node == p.node => return Err(FederationError::DuplicateNode),
                None if free.is_none() => free = Some(i),
                _ => {}
            }
        }
        let slot = free.ok_or(FederationError::RegistryCapacityExhausted)?;
        let live = self.live.checked_add(1).ok_or(FederationError::Overflow)?;
        let cap = isqrt_ceil(live);
        let count = self.scarcity_counts.get(p.scarcity.dense()).copied()
            .ok_or(FederationError::BucketOutOfRange)?;
        let next = count.checked_add(1).ok_or(FederationError::Overflow)?;
        if next > cap {
            return Err(FederationError::SqrtNPassportCapExceeded { bucket: p.scarcity, count, cap, live });
        }
        if let Some(c) = self.scarcity_counts.get_mut(p.scarcity.dense()) { *c = next; }
        if let Some(s) = self.slots.get_mut(slot) { *s = Some(p); }
        self.live = live;
        Ok(AdmissionWitness { slot, live, cap })
    }

    pub fn revoke(&mut self, node: NodeId) -> Result<(), FederationError> {
        let slot = self.slots.iter()
            .position(|s| matches!(s, Some(q) if q.node == node))
            .ok_or(FederationError::UnknownNode)?;
        let p = self.slots.get(slot).copied().flatten().ok_or(FederationError::UnknownNode)?;
        if let Some(c) = self.scarcity_counts.get_mut(p.scarcity.dense()) {
            *c = c.checked_sub(1).ok_or(FederationError::Overflow)?;
        }
        self.live = self.live.checked_sub(1).ok_or(FederationError::Overflow)?;
        if let Some(s) = self.slots.get_mut(slot) { *s = None; }
        Ok(())
    }

    /// Pi: greedy prefix projection of an arbitrary ranking onto the envelope (Theorem 4).
    pub fn project_route<const M: usize>(&self, ranked: &[RankedCandidate], now: u64) -> ShieldedRoute<M> {
        let mut route = ShieldedRoute::<M>::hold();
        let mut mask = PairMask::new();
        for c in ranked {
            if route.len >= M { break; }
            let Some(Some(p)) = self.slots.get(c.slot) else {
                route.rejected = route.rejected.saturating_add(1);
                continue;
            };
            let valid = p.node == c.node && time_window_code(now, p.issued_at, p.expires_at) == 0;
            if !valid || mask.test_and_set(p.pair) {
                route.rejected = route.rejected.saturating_add(1);
                continue;
            }
            if let Some(cell) = route.nodes.get_mut(route.len) { *cell = Some(p.node); }
            route.len = route.len.saturating_add(1);
        }
        route
    }
}

#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RankedCandidate { pub slot: usize, pub node: NodeId, pub score: i64 }

struct PairMask([u64; PAIR_MASK_WORDS]);
impl PairMask {
    const fn new() -> Self { Self([0; PAIR_MASK_WORDS]) }
    /// Returns true when the bucket was already present. O(1).
    fn test_and_set(&mut self, k: PairBucketKey) -> bool {
        let word = k.dense().checked_div(64).unwrap_or(0);
        let bit = u32::try_from(k.dense().checked_rem(64).unwrap_or(0)).unwrap_or(63);
        let mask = 1u64.checked_shl(bit).unwrap_or(0);
        match self.0.get_mut(word) {
            Some(w) => { let present = (*w & mask) != 0; *w |= mask; present }
            None => true,
        }
    }
}

/// Private constructor. The only producer is `project_route`; `fan_out() == 0` is `Hold`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedRoute<const M: usize> { nodes: [Option<NodeId>; M], len: usize, rejected: u32 }

impl<const M: usize> ShieldedRoute<M> {
    const fn hold() -> Self { Self { nodes: [None; M], len: 0, rejected: 0 } }
    pub const fn is_hold(&self) -> bool { self.len == 0 }
    pub const fn fan_out(&self) -> usize { self.len }
    pub const fn rejected(&self) -> u32 { self.rejected }
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.nodes.iter().take(self.len).flatten().copied()
    }
}
```

The registry is a plain value with no interior allocation, so a host without `alloc` places it in a static. The dense bucket keys bound every array index by construction, and every access still goes through `get` so that no path can panic.

## 3. Mechanized obligations and manifest integration

**Kani.** The harnesses model the learned ranking as unconstrained nondeterminism, exactly as the Wave 1 transfer theorem prescribes.

```rust
#[cfg(kani)]
mod harness {
    use super::*;

    #[kani::proof]
    fn isqrt_ceil_is_ceil_sqrt() {
        let n: u32 = kani::any();
        let k = u64::from(isqrt_ceil(n));
        kani::assert(k.saturating_mul(k) >= u64::from(n), "k^2 >= n");
        kani::assert(k == 0 || k.saturating_sub(1).saturating_mul(k.saturating_sub(1)) < u64::from(n), "(k-1)^2 < n");
    }

    #[kani::proof]
    fn time_window_mirror_agrees() {
        let (now, iss, exp): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        kani::assert(
            time_window_code(now, iss, exp) == chio_kernel_core::formal_aeneas::classify_time_window_code(now, iss, exp),
            "mirror equals pinned kernel function",
        );
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn route_is_valid_and_pair_diverse() {
        let mut reg = PassportRegistry::<4>::new();
        let now: u64 = kani::any();
        for _ in 0..4 {
            let p = Passport {
                node: NodeId(kani::any()),
                scarcity: ScarcityBucketKey::new(kani::any()).unwrap_or(ScarcityBucketKey(0)),
                pair: PairBucketKey::new(kani::any()).unwrap_or(PairBucketKey(0)),
                issued_at: kani::any(),
                expires_at: kani::any(),
            };
            let _ = reg.admit(p, now);
        }
        let ranked: [RankedCandidate; 5] = kani::any();
        let route = reg.project_route::<3>(&ranked, now);
        let mut seen: [Option<PairBucketKey>; 3] = [None; 3];
        let mut i = 0usize;
        for node in route.nodes() {
            let p = reg.slots.iter().flatten().find(|p| p.node == node).expect("selected node holds a passport");
            kani::assert(time_window_code(now, p.issued_at, p.expires_at) == 0, "valid at now");
            kani::assert(!seen.contains(&Some(p.pair)), "pair buckets pairwise distinct");
            if let Some(cell) = seen.get_mut(i) { *cell = Some(p.pair); }
            i = i.saturating_add(1);
        }
        kani::assert(route.fan_out() <= 3, "fan-out bounded");
    }
}
```

**Lean 4.** The file `formal/lean4/Chio/Federation.lean` carries the cap arithmetic, the admission theorem, and the greedy projection theorems. The cap is written as $\lfloor\sqrt{N-1}\rfloor + 1$, which equals $\lceil\sqrt{N}\rceil$ for $N \ge 1$ and makes monotonicity immediate.

```lean
import Mathlib

namespace Chio.Federation

def sqrtCap (n : Nat) : Nat := Nat.sqrt (n - 1) + 1

theorem sqrtCap_mono {m n : Nat} (h : m ≤ n) : sqrtCap m ≤ sqrtCap n := by
  unfold sqrtCap
  exact Nat.succ_le_succ (Nat.sqrt_le_sqrt (Nat.sub_le_sub_right h 1))

/-- sqrtCap n is the ceiling square root for n ≥ 1; matches `isqrt_ceil`. -/
theorem sqrtCap_spec {n : Nat} (hn : 1 ≤ n) :
    (sqrtCap n - 1) ^ 2 < n ∧ n ≤ sqrtCap n ^ 2 := by
  unfold sqrtCap
  refine ⟨?_, ?_⟩
  · rw [Nat.add_sub_cancel]
    exact Nat.lt_of_le_of_lt (Nat.sqrt_le' (n - 1)) (Nat.sub_lt hn Nat.one_pos)
  · have h := Nat.succ_le_of_lt (Nat.lt_succ_sqrt' (n - 1))
    rwa [Nat.succ_eq_add_one, Nat.sub_add_cancel hn] at h

structure Reg where
  live  : Nat
  count : Nat → Nat

def Inv (r : Reg) : Prop := ∀ b, r.count b ≤ sqrtCap r.live
def admitOk (r : Reg) (b : Nat) : Prop := r.count b + 1 ≤ sqrtCap (r.live + 1)
def admit (r : Reg) (b : Nat) : Reg :=
  { live := r.live + 1, count := fun b' => if b' = b then r.count b + 1 else r.count b' }

/-- Theorem 3. -/
theorem admit_preserves (r : Reg) (b : Nat) (hI : Inv r) (hok : admitOk r b) :
    Inv (admit r b) := by
  unfold Inv at hI ⊢
  intro b'
  simp only [admit]
  split
  · exact hok
  · exact le_trans (hI b') (sqrtCap_mono (Nat.le_succ r.live))

structure Cand where
  pair  : Nat
  valid : Bool

/-- Greedy prefix projection with fuel M; the candidate order is arbitrary. -/
def project : List Cand → Finset Nat → Nat → List Cand
  | [], _, _ => []
  | _ :: _, _, 0 => []
  | c :: cs, used, fuel + 1 =>
    if c.valid = true ∧ c.pair ∉ used then c :: project cs (insert c.pair used) fuel
    else project cs used (fuel + 1)

theorem project_fresh : ∀ (cs : List Cand) (used : Finset Nat) (fuel : Nat),
    ∀ d ∈ project cs used fuel, d.pair ∉ used ∧ d.valid = true
  | [], _, _ => by simp [project]
  | _ :: _, _, 0 => by simp [project]
  | c :: cs, used, fuel + 1 => by
    intro d hd
    simp only [project] at hd
    split at hd
    · rename_i h
      rcases List.mem_cons.mp hd with rfl | hd'
      · exact ⟨h.2, h.1⟩
      · have ih := project_fresh cs (insert c.pair used) fuel d hd'
        exact ⟨fun hm => ih.1 (Finset.mem_insert_of_mem hm), ih.2⟩
    · exact project_fresh cs used (fuel + 1) d hd

/-- Theorem 4, pair-diversity clause. -/
theorem project_nodup : ∀ (cs : List Cand) (used : Finset Nat) (fuel : Nat),
    ((project cs used fuel).map Cand.pair).Nodup
  | [], _, _ => by simp [project]
  | _ :: _, _, 0 => by simp [project]
  | c :: cs, used, fuel + 1 => by
    simp only [project]
    split
    · rw [List.map_cons, List.nodup_cons]
      refine ⟨?_, project_nodup cs _ fuel⟩
      intro hmem
      rcases List.mem_map.mp hmem with ⟨d, hd, hdp⟩
      exact (project_fresh cs (insert c.pair used) fuel d hd).1
        (by rw [hdp]; exact Finset.mem_insert_self _ _)
    · exact project_nodup cs used (fuel + 1)

end Chio.Federation
```

A companion `Chio/Pheromone.lean` discharges Lemma 1 at the integer level.

```lean
theorem decay_le (e r : Nat) (hr : r ≤ 65536) : e * r / 65536 ≤ e := by
  calc e * r / 65536 ≤ e * 65536 / 65536 := Nat.div_le_div_right (Nat.mul_le_mul_left e hr)
    _ = e := Nat.mul_div_cancel e (by norm_num)
```

**Apalache TLA+.** The protocol model checks interleavings of admission, revocation and routing. The cap is tabulated for the bounded instance; the general arithmetic is owned by Lean and Kani above. The learned ranker is the existential over subsets.

```tla
------------------------------ MODULE ChioFederation ------------------------------
EXTENDS Integers, FiniteSets
CONSTANTS
  \* @type: Set(Str);
  Nodes,
  \* @type: Str -> Int;
  Scarcity,
  \* @type: Str -> Int;
  Pair,
  \* @type: Int;
  M
VARIABLES
  \* @type: Set(Str);
  live,
  \* @type: Set(Str);
  route

Cap(n) == IF n <= 1 THEN 1 ELSE IF n <= 4 THEN 2 ELSE IF n <= 9 THEN 3 ELSE 4
Count(S, b) == Cardinality({n \in S : Scarcity[n] = b})

Init == live = {} /\ route = {}

Admit(n) ==
  /\ n \notin live
  /\ Count(live, Scarcity[n]) + 1 <= Cap(Cardinality(live) + 1)
  /\ live' = live \union {n}
  /\ UNCHANGED route

Revoke(n) ==
  /\ n \in live
  /\ live' = live \ {n}
  /\ route' = route \ {n}

Route ==
  \E S \in SUBSET live :
    /\ Cardinality(S) <= M
    /\ \A x, y \in S : x /= y => Pair[x] /= Pair[y]
    /\ route' = S
    /\ UNCHANGED live

Next == \E n \in Nodes : Admit(n) \/ Revoke(n) \/ Route

PairDiversityInv == \A x, y \in route : x /= y => Pair[x] /= Pair[y]
RouteLiveInv     == route \subseteq live
\* Action invariant: no admission ever enters a bucket at or above the cap.
AdmitCapAction ==
  \A n \in Nodes : (n \in live' /\ n \notin live) =>
    Count(live', Scarcity[n]) <= Cap(Cardinality(live'))
===================================================================================
```

**Manifest wiring.** Every addition is a new entry; no pinned signature changes.

```toml
[[obligation]]
id   = "federation.sqrt_cap.spec"
lean = "Chio/Federation.lean#Chio.Federation.sqrtCap_spec"
kani = "chio-federation::harness::isqrt_ceil_is_ceil_sqrt"

[[obligation]]
id   = "federation.admission.preserves_cap"
lean = "Chio/Federation.lean#Chio.Federation.admit_preserves"
tla  = "ChioFederation.tla#AdmitCapAction"

[[obligation]]
id   = "federation.route.pair_diverse"
lean = "Chio/Federation.lean#Chio.Federation.project_nodup"
kani = "chio-federation::harness::route_is_valid_and_pair_diverse"
tla  = "ChioFederation.tla#PairDiversityInv"

[[obligation]]
id   = "federation.time_window.mirror"
kani = "chio-federation::harness::time_window_mirror_agrees"
```

**Kernel coupling.** Three existing surfaces are reused unchanged. The fan-out $M$ for an epoch is admitted through `budget_precheck` with the invocation cost set to the number of probes and the unit cost to their summed statement, and committed through `budget_commit`. Each dispatched probe reserves on the ledger, commits on a served outcome, and releases on a failed outcome, which is the same moment the trail is reinforced or evaporated. The route receipt couples the registry size, the cap, the fan-out, the rejected count and a digest of the pair mask, and is checked with the pinned coupling predicate. Its metadata key is namespaced as a new key rather than appended to the pinned array of reserved keys, so the array's length and type stay untouched. The federation shield plugs into the guard pipeline as one guard that returns a denial with the existing evidence shape when the projection yields `Hold`.

**Recap.** The pheromone law is an integer half-life decay with a floor whose per-step rounding is one-sided, saturates within $16h+1$ epochs, and tracks the real exponential to a bounded number of raw units. The Whittle index for maintaining trail freshness under a fan-out budget has the closed form $W(a) = a\,h(a+1) - H_a - c$, is indexable because staleness is monotone, and is computed exactly in O(1) from three stored integers with the observation cost priced by the Wave 1 shadow prices. The federation registry enforces a $\lceil\sqrt{N}\rceil$ per-bucket passport cap at admission, provably preserved by admission and never bypassed after shrinkage, and the route projection rejects or accepts each candidate in O(1) while guaranteeing validity, pair diversity and bounded fan-out for every possible ranking. Those two exact facts bound a Sybil adversary by the scarce resources it controls rather than by anything the predictor learned. The obligations are discharged in Lean for the arithmetic and projection, in Kani for the integer implementation and the kernel mirror, and in Apalache for the admission and routing protocol, and the manifest entries are strictly additive.

---

# Verbatim Treatise - `wave4_angle_3_counterfactual_replay_and_drift_rollback`

Specifying the Wave 4 Angle 3 layer for `crates/economy/chio-autonomy` now: receipt-exact envelope and propensity reconstruction, doubly-robust softmin policy optimization for the two artifact families, and integer-only anytime-valid drift monitors with monotone safe-state rollback.

# 1. Decision model instantiation and receipt-exact reconstruction

**Instantiation of $\mathcal{D}_{L3}$.** The autonomy layer instantiates the canonical tuple with $|\mathcal{A}_{L3}| \le 16$ actions. The state $x$ is exactly what a signed `ChioReceipt` already records: the `ReservationLedger`, the time-window code, the budget remainders, the shadow-price vector $\boldsymbol\lambda \in \mathbb{Q}^5$, and the Copley concept vector $\kappa(x) \in \mathbb{K}_3^{537}$. The exact computation $C_{L3}(x)$ is a conjunction of the pinned `formal_core` and `formal_aeneas` functions, and it emits a 16-bit mask plus a fallback index:

$$
\mathcal{C}_{L3}(x) = \{a : \text{budget\_precheck}(\cdot) \wedge \text{classify\_time\_window\_code}(\cdot) = 0 \wedge \neg\,\text{ledger\_is\_terminal}(\cdot) \wedge \text{admissible}_a(x)\} \cup \{\bot_x\},
$$

with $\bot_x = \texttt{Hold}$ when the window is valid and $\bot_x = \texttt{Deny}$ otherwise. Because every clause is a pinned exact function, the mask is a deterministic function of receipt fields, which is what makes historical envelopes reconstructible bit for bit.

The predictor supplies a cost vector, the Lagrangian penalty is added exactly, and the shielded projection is a softmin over the mask mixed with the uniform law on the mask:

$$
J_\theta(x,a;\boldsymbol\lambda) = c_\theta(x,a) + \boldsymbol\lambda^{\top} g(a), \qquad
\pi_\theta(a \mid x) = (1-\epsilon)\,\frac{\exp(-\eta J_\theta(x,a))}{\sum_{a' \in \mathcal{C}(x)} \exp(-\eta J_\theta(x,a'))} + \frac{\epsilon}{|\mathcal{C}(x)|}, \quad a \in \mathcal{C}(x),
$$

and $\pi_\theta(a \mid x) = 0$ off the envelope. The sampled index is passed through $\Pi_{\mathcal{C}(x)}$ regardless, so the learned component is modeled downstream as unconstrained nondeterminism inside the mask.

**Definition 1 (fixed-point softmin).** The logging propensity is *defined* as the output of `softmin_q16` below, not as the real-valued softmin it approximates. Validity of everything downstream depends only on three properties the code enforces: feasible entries sum to exactly $2^{16}$, infeasible entries are exactly zero, and every feasible entry is at least $\lfloor \epsilon / |\mathcal{C}(x)| \rfloor$ in Q16.16 units.

```rust
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub mod fixed {
    /// Q16.16 fixed point in an `i64`; every operation is checked.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub struct FixedQ16_16(pub i64);

    impl FixedQ16_16 {
        pub const FRAC_BITS: u32 = 16;
        pub const ONE: Self = Self(1 << 16);
        pub const ZERO: Self = Self(0);
        /// ceil(ln 2 · 2^16). Rounding up is the conservative direction for every threshold below.
        pub const LN2_CEIL: Self = Self(45_427);

        pub fn checked_add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(Self) }
        pub fn checked_sub(self, o: Self) -> Option<Self> { self.0.checked_sub(o.0).map(Self) }
        /// floor(a·b / 2^16)
        pub fn checked_mul(self, o: Self) -> Option<Self> {
            let p = i128::from(self.0).checked_mul(i128::from(o.0))?;
            i64::try_from(p.checked_shr(Self::FRAC_BITS)?).ok().map(Self)
        }
        /// floor(a·2^16 / b); `None` when b = 0.
        pub fn checked_div(self, o: Self) -> Option<Self> {
            if o.0 == 0 { return None; }
            let n = i128::from(self.0).checked_shl(Self::FRAC_BITS)?;
            i64::try_from(n.checked_div(i128::from(o.0))?).ok().map(Self)
        }
    }

    /// ceil(x / 2^s) for x ≥ 0.
    pub fn ceil_shr(x: i128, s: u32) -> Option<i128> {
        if x < 0 { return None; }
        let mask = 1i128.checked_shl(s)?.checked_sub(1)?;
        x.checked_add(mask)?.checked_shr(s)
    }
    /// ceil(a / b) for a ≥ 0, b > 0.
    pub fn ceil_div(a: i128, b: i128) -> Option<i128> {
        if a < 0 || b <= 0 { return None; }
        a.checked_add(b.checked_sub(1)?)?.checked_div(b)
    }
}

pub mod k3 {
    /// Kleene three-valued predicate outcome, packed two bits per concept.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum K3 { Pos, Neg, Bot }
    impl K3 {
        pub fn from_bits(b: u8) -> Self { match b & 0b11 { 0b01 => K3::Pos, 0b10 => K3::Neg, _ => K3::Bot } }
        /// Signed embedding for the linear artifact: ⊥ contributes nothing.
        pub fn signed(self) -> i64 { match self { K3::Pos => 1, K3::Neg => -1, K3::Bot => 0 } }
        /// Split test for the oblivious tree: ⊥ routes to the "not asserted" branch.
        pub fn asserted(self) -> bool { matches!(self, K3::Pos) }
    }
    pub const N_CONCEPTS: usize = 537;
    pub const CONCEPT_BYTES: usize = 135; // ceil(537·2 / 8)

    #[derive(Clone, Copy, Debug)]
    pub struct ConceptVector { pub packed: [u8; CONCEPT_BYTES] }
    impl ConceptVector {
        pub fn get(&self, j: usize) -> Option<K3> {
            if j >= N_CONCEPTS { return None; }
            let byte = *self.packed.get(j.checked_div(4)?)?;
            let shift = u32::try_from(j.checked_rem(4)?.checked_mul(2)?).ok()?;
            Some(K3::from_bits(byte.checked_shr(shift)?))
        }
    }
}

pub mod envelope {
    pub const MAX_ACTIONS: usize = 16;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FeasibleMask(u16);
    impl FeasibleMask {
        pub fn contains(self, a: u8) -> bool {
            1u16.checked_shl(u32::from(a)).map_or(false, |bit| self.0 & bit != 0)
        }
        pub fn len(self) -> u32 { self.0.count_ones() }
        pub fn bits(self) -> u16 { self.0 }
    }

    /// Envelope reconstructed from a witness. The only constructor checks that ⊥_x is
    /// feasible, so `project` is total and never leaves the envelope.
    #[derive(Clone, Copy, Debug)]
    pub struct FeasibleSlice { mask: FeasibleMask, fallback: u8 }
    impl FeasibleSlice {
        pub fn reconstruct(bits: u16, fallback: u8) -> Option<Self> {
            let mask = FeasibleMask(bits);
            if usize::from(fallback) >= MAX_ACTIONS || !mask.contains(fallback) { return None; }
            Some(Self { mask, fallback })
        }
        pub fn mask(&self) -> FeasibleMask { self.mask }
        pub fn fallback(&self) -> u8 { self.fallback }
        /// Shielded projection Π_{C(x)} in O(1).
        pub fn project(&self, proposed: u8) -> ShieldedAction {
            if self.mask.contains(proposed) { ShieldedAction(proposed) } else { ShieldedAction(self.fallback) }
        }
    }

    /// Only `FeasibleSlice::project` can build one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ShieldedAction(u8);
    impl ShieldedAction { pub fn index(self) -> u8 { self.0 } }
}

pub mod softmin {
    use crate::envelope::{FeasibleSlice, MAX_ACTIONS};
    use crate::fixed::FixedQ16_16 as Fx;

    pub const MAX_EPSILON_SHIFT: u8 = 12;     // guarantees ε ≥ |C(x)| so the floor is ≥ 1 ulp
    pub const MAX_TEMPERATURE_SHIFT: u8 = 32;

    /// 2^{-x} for x ≥ 0, cubic on the fraction. Approximation quality is irrelevant to
    /// validity: the policy is defined as this procedure.
    pub fn exp2_neg(x: Fx) -> Option<Fx> {
        if x.0 < 0 { return None; }
        let int_part = x.0.checked_shr(16)?;
        if int_part >= 32 { return Some(Fx::ZERO); }
        let f = Fx(x.0 & 0xFFFF);
        const C1: Fx = Fx(45_426); // floor(ln2 · 2^16)
        const C2: Fx = Fx(15_743); // floor(ln2²/2 · 2^16)
        const C3: Fx = Fx(3_637);  // floor(ln2³/6 · 2^16)
        let f2 = f.checked_mul(f)?;
        let f3 = f2.checked_mul(f)?;
        let poly = Fx::ONE.checked_sub(C1.checked_mul(f)?)?
            .checked_add(C2.checked_mul(f2)?)?
            .checked_sub(C3.checked_mul(f3)?)?;
        Some(Fx(poly.0.checked_shr(u32::try_from(int_part).ok()?)?))
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Propensities { pub p: [Fx; MAX_ACTIONS] }

    pub fn propensity_floor(k: u32, epsilon_shift: u8) -> Option<Fx> {
        Fx::ONE.0.checked_shr(u32::from(epsilon_shift))?.checked_div(i64::from(k)).map(Fx)
    }

    pub fn softmin_q16(costs: &[Fx; MAX_ACTIONS], env: &FeasibleSlice,
                       temperature_shift: u8, epsilon_shift: u8) -> Option<Propensities> {
        if epsilon_shift > MAX_EPSILON_SHIFT || temperature_shift > MAX_TEMPERATURE_SHIFT { return None; }
        let mask = env.mask();
        let fb = usize::from(env.fallback());
        let mut min = i64::MAX;
        for a in 0..MAX_ACTIONS {
            if mask.contains(a as u8) && costs[a].0 < min { min = costs[a].0; }
        }
        // Unnormalised weights; the arg-min has weight exactly ONE, so total ≥ ONE.
        let mut u = [Fx::ZERO; MAX_ACTIONS];
        let mut total: i64 = 0;
        for a in 0..MAX_ACTIONS {
            if !mask.contains(a as u8) { continue; }
            let d = costs[a].0.checked_sub(min)?.checked_shr(u32::from(temperature_shift))?;
            u[a] = exp2_neg(Fx(d))?;
            total = total.checked_add(u[a].0)?;
        }
        // Normalise with floor division; the deficit goes to ⊥_x.
        let mut p = [Fx::ZERO; MAX_ACTIONS];
        let mut acc: i64 = 0;
        for a in 0..MAX_ACTIONS {
            if !mask.contains(a as u8) { continue; }
            let q = i128::from(u[a].0).checked_shl(16)?.checked_div(i128::from(total))?;
            p[a] = Fx(i64::try_from(q).ok()?);
            acc = acc.checked_add(p[a].0)?;
        }
        p[fb] = Fx(p[fb].0.checked_add(Fx::ONE.0.checked_sub(acc)?)?);
        // ε-mixing with the uniform law on the envelope, ε = 2^{-epsilon_shift}.
        let eps = Fx::ONE.0.checked_shr(u32::from(epsilon_shift))?;
        let floor = eps.checked_div(i64::from(mask.len()))?;
        let one_minus_eps = Fx::ONE.0.checked_sub(eps)?;
        let mut acc2: i64 = 0;
        for a in 0..MAX_ACTIONS {
            if !mask.contains(a as u8) { continue; }
            let scaled = i128::from(p[a].0).checked_mul(i128::from(one_minus_eps))?.checked_shr(16)?;
            p[a] = Fx(i64::try_from(scaled).ok()?.checked_add(floor)?);
            acc2 = acc2.checked_add(p[a].0)?;
        }
        p[fb] = Fx(p[fb].0.checked_add(Fx::ONE.0.checked_sub(acc2)?)?);
        Some(Propensities { p })
    }
}
```

**Lemma 1 (exact normalization and floor).** For every valid input, `softmin_q16` returns $p$ with (i) $p_a = 0$ for $a \notin \mathcal{C}(x)$, (ii) $\sum_{a \in \mathcal{C}(x)} p_a = 2^{16}$, (iii) $p_a \ge \lfloor 2^{16-e} / k \rfloor \ge 1$ for every feasible $a$, where $k = |\mathcal{C}(x)|$ and $e$ is the epsilon shift.

*Proof.* (i) Infeasible slots are never written. (ii) After the first pass $\sum_a \lfloor u_a 2^{16} / U \rfloor \le 2^{16}$ because $\sum_a u_a = U$, so the deficit added to $\bot_x$ is nonnegative and the sum becomes exactly $2^{16}$. After mixing, $\sum_a \lfloor p_a (2^{16} - \varepsilon) / 2^{16} \rfloor \le 2^{16} - \varepsilon$ and $k \lfloor \varepsilon / k \rfloor \le \varepsilon$, so again the deficit is nonnegative and the fallback absorbs it. (iii) Every feasible slot receives the additive term $\lfloor \varepsilon / k \rfloor$, and $k \le 16 \le 2^{16 - e}$ when $e \le 12$. $\square$

**Definition 2 (witness metadata).** The pinned `RESERVED_RECEIPT_METADATA_KEYS: [&str; 35]` array is not touched. Both witnesses live as sub-objects under the already reserved key `model_metadata`, with discriminators `decision_model_witness_v2` and `copley_witness_v1`, so the change is strictly additive.

```rust
pub mod witness {
    use crate::envelope::MAX_ACTIONS;
    use crate::fixed::FixedQ16_16;
    use crate::k3::ConceptVector;

    pub const MODEL_METADATA_SUBKEYS: [&str; 2] = ["decision_model_witness_v2", "copley_witness_v1"];
    pub const DECISION_MODEL_WITNESS_SCHEMA_V2: u16 = 2;
    pub const SHADOW_PRICE_DIMS: usize = 5; // budget, fuel, latency, memory, escrow

    #[derive(Clone, Copy, Debug)]
    pub struct DecisionModelWitnessMetadata {
        pub schema: u16,
        pub layer: u8,
        pub envelope_bits: u16,
        pub fallback_index: u8,
        pub chosen_index: u8,
        pub temperature_shift: u8,
        pub epsilon_shift: u8,
        pub shadow_prices: [FixedQ16_16; SHADOW_PRICE_DIMS],
        pub costs: [FixedQ16_16; MAX_ACTIONS],
        pub propensity: FixedQ16_16,
        pub policy_artifact_hash: [u8; 32],
    }

    #[derive(Clone, Copy, Debug)]
    pub struct CopleyWitnessReceiptMetadata {
        pub model_card_hash: [u8; 32],
        pub loaded_weights_hash: [u8; 32],
        pub threshold_table_hash: [u8; 32],
        pub concepts: ConceptVector,
    }
}
```

The threshold-table hash commits the role-asymmetric pairs $(\tau_j^{\text{pos}}, \tau_j^{\text{neg}})$ with $\tau_j^{\text{neg}} \le \tau_j^{\text{pos}}$, so a concept vector is only comparable across receipts that share it. The loaded-weights hash is the same value `evaluate_weights_binding` checks against the `ModelCard`.

**Theorem 1 (exact reconstruction).** Let a receipt carry a `DecisionModelWitnessMetadata` that passes `reconstruct` in Section 2. Then the recomputed envelope equals the logged envelope and the recomputed behavior propensity equals the logged propensity, both as dyadic rationals with denominator $2^{16}$.

*Proof.* The envelope is a pure function of the two witness fields consumed by `FeasibleSlice::reconstruct`. The propensity vector is a pure, total function of the witness fields consumed by `softmin_q16`, with no floating point, no global state, and no platform-dependent operation. Acceptance requires the recomputed value at the chosen index to equal the logged value, so any accepted row satisfies the claim and any row where the live path diverged is rejected with `PropensityMismatch`. $\square$

# 2. Doubly-robust counterfactual softmin optimization

**Rewards from exact computation.** A learned model is never asked to approximate what $C_\ell$ solves exactly, and the same discipline applies to rewards. The outcome of an autonomous decision is a conjunction of pinned exact predicates evaluated on the follow-up receipt chain:

$$
r_i = \tfrac14\Big(\mathbb{1}[\text{receipt\_fields\_coupled}] + \mathbb{1}[\text{BudgetCommitResult.accepted}] + \mathbb{1}[\text{ledger\_is\_terminal} \wedge \text{retained} = 0] + \mathbb{1}[\text{classify\_time\_window\_code} = 0]\Big) \in \{0, \tfrac14, \tfrac12, \tfrac34, 1\}.
$$

In Q16.16 every reward is a multiple of $2^{14}$, so no rounding enters at this stage.

**Definition 3 (doubly-robust term).** For an accepted row with envelope $\mathcal{C}_i$, logged action $a_i$, behavior propensities $\pi_\beta(\cdot \mid x_i)$ from Theorem 1, a target policy $\pi$, and a predictable reward model $\hat q(x_i, \cdot) \in [0,1]^{\mathcal{C}_i}$ fixed before the corpus was logged,

$$
\hat\phi_i(\pi) = \sum_{a \in \mathcal{C}_i} \pi(a \mid x_i)\,\hat q(x_i, a) + w_i\,\big(r_i - \hat q(x_i, a_i)\big), \qquad w_i = \frac{\pi(a_i \mid x_i)}{\pi_\beta(a_i \mid x_i)}, \qquad \hat V_{DR}(\pi) = \frac1n \sum_{i=1}^n \hat\phi_i(\pi).
$$

**Theorem 2 (conditional unbiasedness and boundedness).** Under the logged behavior policy, $\mathbb{E}[\hat\phi_i(\pi) \mid x_i, \mathcal{F}_{i-1}] = \sum_{a \in \mathcal{C}_i} \pi(a \mid x_i)\, q(x_i, a)$ for *any* predictable $\hat q$, where $q$ is the true conditional reward. Moreover $|\hat\phi_i(\pi)| \le B := 1 + W_{\max}$ with $W_{\max} = 1 / \lfloor \varepsilon / k \rfloor_{\text{Q16}} \le 16 \cdot 2^{e}$.

*Proof.* Conditioning on $x_i$ and the past, $a_i \sim \pi_\beta(\cdot \mid x_i)$ exactly by Theorem 1, so $\mathbb{E}[w_i (r_i - \hat q(x_i,a_i))] = \sum_{a \in \mathcal{C}_i} \pi_\beta(a \mid x_i) \frac{\pi(a \mid x_i)}{\pi_\beta(a \mid x_i)} (q(x_i,a) - \hat q(x_i,a)) = \sum_a \pi(a \mid x_i)(q - \hat q)(x_i, a)$. Adding the direct term cancels $\hat q$. The sum ranges over $\mathcal{C}_i$ only because both policies vanish off the envelope by Lemma 1(i). For the bound, the direct term lies in $[0,1]$, $|r_i - \hat q| \le 1$, and $w_i \le 1 / \min_a \pi_\beta(a \mid x_i) \le W_{\max}$ by Lemma 1(iii). $\square$

Exactness of the propensities is what makes the first identity hold without any modeling assumption. The reward model only reduces variance.

**Theorem 3 (zero off-support extrapolation).** For every parameter $\theta$ of either artifact family, $\operatorname{supp} \pi_\theta(\cdot \mid x) \subseteq \mathcal{C}(x)$, and $\hat V_{DR}(\pi_\theta)$ is a function only of quantities indexed by $a \in \mathcal{C}_i$. Coverage, usually an assumption, is a theorem here: $\pi_\beta(a \mid x_i) \ge \lfloor \varepsilon / k \rfloor$ for every $a \in \mathcal{C}_i$.

*Proof.* $\pi_\theta$ is produced by the same `softmin_q16` applied to the artifact's cost vector and the *logged* envelope, so Lemma 1(i) gives the support inclusion. The code for `dr_term` below reads $\hat q$, $\pi_\theta$, and $\pi_\beta$ only at masked indices. The floor is Lemma 1(iii). $\square$

```rust
pub mod policy {
    use crate::envelope::MAX_ACTIONS;
    use crate::fixed::FixedQ16_16 as Fx;
    use crate::k3::{ConceptVector, N_CONCEPTS};
    use crate::witness::SHADOW_PRICE_DIMS;

    pub trait ScoredPolicy {
        /// Base cost c_θ(x,·) for all slots; infeasible slots are ignored by the projection.
        fn base_costs(&self, x: &ConceptVector) -> Option<[Fx; MAX_ACTIONS]>;
    }

    /// Resource usage g(a) per action, priced by the Lagrangian shadow-price vector λ.
    pub struct ResourceTable { pub usage: [[Fx; SHADOW_PRICE_DIMS]; MAX_ACTIONS] }

    pub fn lagrangian_costs<P: ScoredPolicy>(p: &P, x: &ConceptVector,
        lambda: &[Fx; SHADOW_PRICE_DIMS], res: &ResourceTable) -> Option<[Fx; MAX_ACTIONS]> {
        let mut c = p.base_costs(x)?;
        for a in 0..MAX_ACTIONS {
            for d in 0..SHADOW_PRICE_DIMS {
                c[a] = c[a].checked_add(lambda[d].checked_mul(res.usage[a][d])?)?;
            }
        }
        Some(c)
    }

    /// Row-major i16 weights, MAX_ACTIONS × N_CONCEPTS, scaled by 2^{-weight_shift}.
    pub struct QuantizedLinearPolicy<'a> { pub weights: &'a [i16], pub bias: [Fx; MAX_ACTIONS], pub weight_shift: u8 }
    impl ScoredPolicy for QuantizedLinearPolicy<'_> {
        fn base_costs(&self, x: &ConceptVector) -> Option<[Fx; MAX_ACTIONS]> {
            if self.weights.len() != MAX_ACTIONS.checked_mul(N_CONCEPTS)? || self.weight_shift > 32 { return None; }
            let mut out = self.bias;
            for a in 0..MAX_ACTIONS {
                let row = a.checked_mul(N_CONCEPTS)?;
                let mut acc: i64 = 0;
                for j in 0..N_CONCEPTS {
                    let w = i64::from(*self.weights.get(row.checked_add(j)?)?);
                    acc = acc.checked_add(w.checked_mul(x.get(j)?.signed())?)?;
                }
                let q = if self.weight_shift <= 16 {
                    acc.checked_shl(u32::from(16u8.checked_sub(self.weight_shift)?))?
                } else {
                    acc.checked_shr(u32::from(self.weight_shift.checked_sub(16)?))?
                };
                out[a] = out[a].checked_add(Fx(q))?;
            }
            Some(out)
        }
    }

    pub const MAX_TREE_DEPTH: usize = 8;
    /// Oblivious tree: one split predicate per level, 2^depth leaves × MAX_ACTIONS costs.
    pub struct ObliviousTreePolicy<'a> { pub depth: u8, pub split_feature: [u16; MAX_TREE_DEPTH], pub leaves: &'a [Fx] }
    impl ScoredPolicy for ObliviousTreePolicy<'_> {
        fn base_costs(&self, x: &ConceptVector) -> Option<[Fx; MAX_ACTIONS]> {
            let depth = usize::from(self.depth);
            if depth > MAX_TREE_DEPTH { return None; }
            let n_leaves = 1usize.checked_shl(u32::from(self.depth))?;
            if self.leaves.len() != n_leaves.checked_mul(MAX_ACTIONS)? { return None; }
            let mut leaf: usize = 0;
            for lvl in 0..depth {
                let bit = usize::from(x.get(usize::from(self.split_feature[lvl]))?.asserted());
                leaf = leaf.checked_shl(1)?.checked_add(bit)?;
            }
            let base = leaf.checked_mul(MAX_ACTIONS)?;
            let mut out = [Fx::ZERO; MAX_ACTIONS];
            for a in 0..MAX_ACTIONS { out[a] = *self.leaves.get(base.checked_add(a)?)?; }
            Some(out)
        }
    }
}

pub mod dr {
    use crate::envelope::{FeasibleSlice, MAX_ACTIONS};
    use crate::fixed::{ceil_div, ceil_shr, FixedQ16_16 as Fx};
    use crate::softmin::{softmin_q16, Propensities, MAX_EPSILON_SHIFT};
    use crate::witness::{CopleyWitnessReceiptMetadata, DecisionModelWitnessMetadata, DECISION_MODEL_WITNESS_SCHEMA_V2};

    pub struct CorpusRow { pub dm: DecisionModelWitnessMetadata, pub copley: CopleyWitnessReceiptMetadata, pub reward: Fx }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CorpusReject { BadSchema, WeightsBindingMismatch, EnvelopeInvalid, ChosenInfeasible,
                            EpsilonTooSmall, Arithmetic, PropensityMismatch, RewardOutOfRange }

    pub struct Reconstructed { pub env: FeasibleSlice, pub behavior: Propensities }

    pub fn reconstruct(row: &CorpusRow, expected_weights_hash: &[u8; 32]) -> Result<Reconstructed, CorpusReject> {
        if row.dm.schema != DECISION_MODEL_WITNESS_SCHEMA_V2 { return Err(CorpusReject::BadSchema); }
        if &row.copley.loaded_weights_hash != expected_weights_hash { return Err(CorpusReject::WeightsBindingMismatch); }
        let env = FeasibleSlice::reconstruct(row.dm.envelope_bits, row.dm.fallback_index).ok_or(CorpusReject::EnvelopeInvalid)?;
        if !env.mask().contains(row.dm.chosen_index) { return Err(CorpusReject::ChosenInfeasible); }
        if row.dm.epsilon_shift > MAX_EPSILON_SHIFT { return Err(CorpusReject::EpsilonTooSmall); }
        let behavior = softmin_q16(&row.dm.costs, &env, row.dm.temperature_shift, row.dm.epsilon_shift).ok_or(CorpusReject::Arithmetic)?;
        if behavior.p[usize::from(row.dm.chosen_index)] != row.dm.propensity { return Err(CorpusReject::PropensityMismatch); }
        if row.reward.0 < 0 || row.reward.0 > Fx::ONE.0 { return Err(CorpusReject::RewardOutOfRange); }
        Ok(Reconstructed { env, behavior })
    }

    /// φ̂_i: at most 18 floor roundings of one ulp each.
    pub const DR_ROUNDING_ULPS: i64 = 18;

    pub fn dr_term(rec: &Reconstructed, target: &Propensities, qhat: &[Fx; MAX_ACTIONS], chosen: u8, reward: Fx) -> Option<Fx> {
        let mask = rec.env.mask();
        let mut direct = Fx::ZERO;
        for a in 0..MAX_ACTIONS {
            if mask.contains(a as u8) { direct = direct.checked_add(target.p[a].checked_mul(qhat[a])?)?; }
        }
        let ai = usize::from(chosen);
        let w = target.p[ai].checked_div(rec.behavior.p[ai])?;   // denominator ≥ floor ≥ 1 ulp
        direct.checked_add(w.checked_mul(reward.checked_sub(qhat[ai])?)?)
    }

    /// Smallest r with r² ≥ x.
    pub fn isqrt_ceil(x: u128) -> Option<u128> {
        let (mut lo, mut hi): (u128, u128) = (0, 1u128.checked_shl(64)?);
        while lo < hi {
            let mid = lo.checked_add(hi.checked_sub(lo)?.checked_div(2)?)?;
            if mid.checked_mul(mid).map_or(true, |m| m >= x) { hi = mid; } else { lo = mid.checked_add(1)?; }
        }
        Some(lo)
    }

    /// Maurer–Pontil empirical-Bernstein lower confidence bound for Z ∈ [0, ONE], δ = 2^-delta_shift.
    /// Inputs: Σz (Q16), Σz² (Q32), n. Every rounding is in the conservative direction.
    pub fn eb_lcb_q16(sum_q16: i64, sum_sq_q32: i128, n: u64, delta_shift: u8) -> Option<Fx> {
        if n < 2 { return None; }
        let n_i = i128::from(n);
        let mean = i128::from(sum_q16).checked_div(n_i)?;
        let nmean2 = mean.checked_mul(mean)?.checked_mul(n_i)?;
        let var_q32 = sum_sq_q32.checked_sub(nmean2)?.max(0).checked_div(n_i.checked_sub(1)?)?;
        let l = i128::from(delta_shift).checked_add(1)?.checked_mul(i128::from(Fx::LN2_CEIL.0))?; // ≥ ln(2/δ), Q16
        let a_q32 = ceil_shr(var_q32.checked_mul(2)?.checked_mul(l)?, 16)?.checked_div(n_i)?.checked_add(1)?;
        let term1 = i128::try_from(isqrt_ceil(u128::try_from(a_q32).ok()?)?).ok()?;        // sqrt(Q32) = Q16
        let term2 = ceil_div(l.checked_mul(7)?, n_i.checked_sub(1)?.checked_mul(3)?)?;
        let lcb = mean.checked_sub(term1)?.checked_sub(term2)?.checked_sub(i128::from(DR_ROUNDING_ULPS))?;
        i64::try_from(lcb.max(0)).ok().map(Fx)
    }
}
```

**Pessimistic objective and the certification gate.** Training runs offline in the `std` crate `chio-autonomy-train` and never touches the kernel. It minimizes the counterfactual risk with variance regularization,

$$
\theta^\star = \arg\max_\theta \; \hat V_{DR}(\pi_\theta) - \kappa \sqrt{\widehat{\operatorname{Var}}_n[\hat\phi(\pi_\theta)] / n},
$$

by gradient ascent on the real-valued softmin surrogate, then quantizes to the `i16` or Q16.16 artifact. The surrogate is only a search heuristic. The certificate is computed by the `no_std` evaluator on the *quantized bits*, so there is no train-serve skew: the kernel reconstructs the corpus committed under a Merkle root, computes $Z_i = (\hat\phi_i + B) / 2B \in [0,1]$ with `dr_term`, and promotes the candidate only if its empirical-Bernstein lower bound exceeds the incumbent's point estimate by a configured margin. The artifact hash, corpus root, and bound are written into a `PolicyCertificationReceipt`. The rounding allowance subtracted inside `eb_lcb_q16` covers the at most eighteen one-ulp floors in `dr_term`, so the certificate is sound against fixed-point error, not only against sampling error. Per-row work is bounded by a constant, which lets the reconstruction pass be metered by the existing `VerificationBudget` type.

# 3. Anytime-valid drift monitors and monotone rollback

The drift monitors must be valid at every stopping time, because the safe-state machine reads them continuously. The construction is a nonnegative test supermartingale with a fixed dyadic bet, which makes the log-wealth *linear in the data* and therefore exactly computable in integers.

**Lemma 4 (Fan, Grama, Liu).** Let $\psi_E(\lambda) = -\ln(1-\lambda) - \lambda$. For $\lambda \in [0,1)$ and $\xi \ge -1$: $\exp(\lambda \xi - \psi_E(\lambda)\xi^2) \le 1 + \lambda\xi$.

**Theorem 5 (empirical-Bernstein test supermartingale).** Let $Z_t \in [0,1]$ be adapted to $\mathcal{F}_t$ with $\mathbb{E}[Z_t \mid \mathcal{F}_{t-1}] \le \mu_0$, let $\hat\mu_{t-1} \in [0,1]$ be $\mathcal{F}_{t-1}$-measurable, and fix $\lambda \in (0,1)$. Then $M_t = \prod_{i \le t} \exp\big(\lambda (Z_i - \mu_0) - \psi_E(\lambda)(Z_i - \hat\mu_{i-1})^2\big)$ is a nonnegative supermartingale with $M_0 = 1$, and by Ville's inequality $\Pr[\exists t : M_t \ge 1/\alpha] \le \alpha$.

*Proof.* Write $\xi_i = Z_i - \hat\mu_{i-1} \ge -1$ and $\mu_i = \mathbb{E}[Z_i \mid \mathcal{F}_{i-1}] \le \mu_0$. The $i$-th factor equals $\exp(\lambda\xi_i - \psi_E\xi_i^2)\exp(-\lambda(\mu_0 - \hat\mu_{i-1}))$. By Lemma 4 its conditional expectation is at most $(1 + \lambda(\mu_i - \hat\mu_{i-1}))\exp(-\lambda(\mu_0 - \hat\mu_{i-1})) \le (1 + \lambda(\mu_i - \hat\mu_{i-1}))\exp(-\lambda(\mu_i - \hat\mu_{i-1})) \le 1$, using $\mu_i \le \mu_0$ and $1 + u \le e^u$. Ville's inequality applies to any nonnegative supermartingale. $\square$

**Theorem 6 (Hoeffding test supermartingale).** Under the same conditions, $H_t = \prod_{i\le t}\exp(\lambda(Z_i - \mu_0) - \lambda^2/8)$ is a nonnegative supermartingale, by Hoeffding's lemma applied conditionally.

**Corollary 7 (fixed-point conservativeness).** In Q16.16 the log-wealth of Theorem 5 is $\lambda S_t - \psi_E(\lambda) V_t$ with $S_t = \sum_i (Z_i - \mu_0)$ and $V_t = \sum_i (Z_i - \hat\mu_{i-1})^2$. Replacing $\psi_E$ by any $\psi' \ge \psi_E$, computing $\lambda S_t$ by an arithmetic right shift, rounding $V_t$ and the product up, and replacing $\ln(1/\alpha)$ by any larger constant each produce a statistic no larger than the exact one, so the rejection event is a subset of the exact rejection event and Theorem 5's guarantee is preserved. Using $\lambda = 2^{-k}$ turns the only multiplication by $\lambda$ into a shift. The required constants are precomputed and rounded up:

| $\lambda$ | $\psi_E(\lambda)$ | Q16.16 ceil |
|---|---|---|
| $2^{-1}$ | 0.193147 | 12 659 |
| $2^{-2}$ | 0.037682 | 2 470 |
| $2^{-3}$ | 0.008531 | 560 |
| $2^{-4}$ | 0.002039 | 134 |
| $2^{-5}$ | 0.000499 | 33 |

The conditional-mean form of the null is what makes this robust to the dependence between consecutive autonomous decisions. For the off-policy value stream, $Z_t$ is the normalized `dr_term` of the deployed policy on each fresh receipt, and conditional unbiasedness given the past follows from Theorem 2 because $\hat q$ was frozen before deployment.

```rust
pub mod drift {
    use crate::fixed::{ceil_shr, FixedQ16_16 as Fx};
    use crate::witness::SHADOW_PRICE_DIMS;

    pub const MAX_MONITOR_SAMPLES: u64 = 1 << 40;
    const PSI_E_CEIL_Q16: [i64; 5] = [12_659, 2_470, 560, 134, 33]; // λ = 2^-1 … 2^-5

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BetKind { EmpiricalBernstein, Hoeffding }

    /// One-sided monitor for H0: E[Z_t | past] ≤ μ0, Z_t ∈ [0, ONE].
    #[derive(Clone, Copy, Debug)]
    pub struct EbMonitor {
        kind: BetKind, mu0: i64, lambda_shift: u8, psi_e_q16: i64, threshold_q16: i64,
        t: u64, s_q16: i64, v_q16: i64, running_sum_q16: i64,
    }

    impl EbMonitor {
        /// `threshold_q16` ≥ ln(1/α) in Q16.16, e.g. `log_inv_alpha(alpha_shift, bonferroni_log2)`.
        pub fn new(kind: BetKind, mu0: Fx, lambda_shift: u8, threshold_q16: i64) -> Option<Self> {
            if mu0.0 < 0 || mu0.0 > Fx::ONE.0 { return None; }
            let psi_e_q16 = *PSI_E_CEIL_Q16.get(usize::from(lambda_shift.checked_sub(1)?))?;
            Some(Self { kind, mu0: mu0.0, lambda_shift, psi_e_q16, threshold_q16, t: 0, s_q16: 0, v_q16: 0, running_sum_q16: 0 })
        }
        /// (alpha_shift + bonferroni_log2) · ceil(ln 2 · 2^16) ≥ ln(2^bonferroni / α).
        pub fn log_inv_alpha(alpha_shift: u8, bonferroni_log2: u8) -> Option<i64> {
            i64::from(alpha_shift.checked_add(bonferroni_log2)?).checked_mul(Fx::LN2_CEIL.0)
        }
        pub fn threshold_q16(&self) -> i64 { self.threshold_q16 }
        pub fn samples(&self) -> u64 { self.t }

        /// Returns the conservatively rounded log-wealth after absorbing `z`.
        pub fn observe(&mut self, z: Fx) -> Option<i64> {
            if z.0 < 0 || z.0 > Fx::ONE.0 || self.t >= MAX_MONITOR_SAMPLES { return None; }
            // Predictable plug-in mean μ̂_{t-1} = (μ0 + Σ_{i<t} z_i) / t ∈ [0, ONE].
            let denom = i64::try_from(self.t.checked_add(1)?).ok()?;
            let hat_mu = self.mu0.checked_add(self.running_sum_q16)?.checked_div(denom)?;
            let dev = i128::from(z.0.checked_sub(hat_mu)?);
            let dev2 = ceil_shr(dev.checked_mul(dev)?, 16)?;
            self.v_q16 = self.v_q16.checked_add(i64::try_from(dev2).ok()?)?;
            self.s_q16 = self.s_q16.checked_add(z.0.checked_sub(self.mu0)?)?;
            self.running_sum_q16 = self.running_sum_q16.checked_add(z.0)?;
            self.t = self.t.checked_add(1)?;
            let lam_s = self.s_q16.checked_shr(u32::from(self.lambda_shift))?; // floor of λ·S_t
            let penalty = match self.kind {
                BetKind::EmpiricalBernstein =>
                    ceil_shr(i128::from(self.psi_e_q16).checked_mul(i128::from(self.v_q16))?, 16)?,
                BetKind::Hoeffding => {
                    let s = u32::from(self.lambda_shift).checked_mul(2)?.checked_add(3)?; // t·λ²/8
                    ceil_shr(i128::from(self.t).checked_shl(16)?, s)?
                }
            };
            lam_s.checked_sub(i64::try_from(penalty).ok()?)
        }
    }

    /// Two one-sided monitors at α/2 each; the lower side observes ONE − z against ONE − μ0.
    #[derive(Clone, Copy, Debug)]
    pub struct TwoSided { pub up: EbMonitor, pub down: EbMonitor }
    impl TwoSided {
        pub fn observe(&mut self, z: Fx) -> Option<(i64, i64, u64)> {
            let up = self.up.observe(z)?;
            let down = self.down.observe(Fx::ONE.checked_sub(z)?)?;
            Some((up.max(down), self.up.threshold_q16(), self.up.samples()))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AutonomousDriftKind {
        OffPolicyValueDrift,
        FallbackRateDrift,
        EnvelopeSupportDrift,
        ShadowPriceDrift { dim: u8 },
        CopleyConceptDrift { concept: u16 },
        PropensityFloorViolation,
        WeightsBindingMismatch,
        WitnessIntegrityFailure,
    }

    /// Totally ordered safety lattice; transitions within an epoch only move up.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum AutonomousSafeState { Nominal, ShadowModeOnly, DelegatedOnly, BindDisabled, FullPause }
    impl AutonomousSafeState {
        pub fn join(self, o: Self) -> Self { if self >= o { self } else { o } }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AutonomousRollbackAction {
        None,
        RevertToIncumbentPolicy { incumbent_artifact_hash: [u8; 32] },
        RequireRecertification,
        DisableBind,
        PauseAll,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AutonomousDriftReport {
        pub kind: AutonomousDriftKind,
        pub log_wealth_q16: i64,
        pub threshold_q16: i64,
        pub samples: u64,
        pub triggered: bool,
    }

    pub fn minimum_safe_state(kind: AutonomousDriftKind) -> AutonomousSafeState {
        use AutonomousDriftKind::*;
        match kind {
            CopleyConceptDrift { .. } | ShadowPriceDrift { .. } | EnvelopeSupportDrift => AutonomousSafeState::ShadowModeOnly,
            FallbackRateDrift => AutonomousSafeState::DelegatedOnly,
            OffPolicyValueDrift | PropensityFloorViolation => AutonomousSafeState::BindDisabled,
            WeightsBindingMismatch | WitnessIntegrityFailure => AutonomousSafeState::FullPause,
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct SafeStateMachine { state: AutonomousSafeState, epoch: u64, incumbent_artifact_hash: [u8; 32] }
    impl SafeStateMachine {
        pub fn new(incumbent_artifact_hash: [u8; 32]) -> Self {
            Self { state: AutonomousSafeState::Nominal, epoch: 0, incumbent_artifact_hash }
        }
        pub fn state(&self) -> AutonomousSafeState { self.state }
        pub fn epoch(&self) -> u64 { self.epoch }

        /// Monotone within an epoch: `state' = state ⊔ minimum_safe_state(kind)`.
        pub fn absorb(&mut self, report: &AutonomousDriftReport) -> AutonomousRollbackAction {
            if !report.triggered { return AutonomousRollbackAction::None; }
            self.state = self.state.join(minimum_safe_state(report.kind));
            match self.state {
                AutonomousSafeState::Nominal => AutonomousRollbackAction::None,
                AutonomousSafeState::ShadowModeOnly =>
                    AutonomousRollbackAction::RevertToIncumbentPolicy { incumbent_artifact_hash: self.incumbent_artifact_hash },
                AutonomousSafeState::DelegatedOnly => AutonomousRollbackAction::RequireRecertification,
                AutonomousSafeState::BindDisabled => AutonomousRollbackAction::DisableBind,
                AutonomousSafeState::FullPause => AutonomousRollbackAction::PauseAll,
            }
        }

        /// The only downward path: an operator-signed restore opens a new epoch and
        /// requires a fresh `PolicyCertificationReceipt` before any artifact binds.
        pub fn restore(&mut self, restore_signature_verified: bool) -> Option<()> {
            if !restore_signature_verified { return None; }
            self.epoch = self.epoch.checked_add(1)?;
            self.state = AutonomousSafeState::Nominal;
            Some(())
        }
    }

    /// One monitor per drift kind; concept monitors are supplied as a slice of length N_CONCEPTS.
    pub struct DriftBank<'a> {
        pub value_down: EbMonitor,          // H0: E[ONE − Z] ≤ ONE − z_cert, i.e. value has not fallen
        pub fallback_rate: TwoSided,
        pub envelope_size: TwoSided,
        pub shadow: [TwoSided; SHADOW_PRICE_DIMS],
        pub concepts: &'a mut [TwoSided],
        pub machine: SafeStateMachine,
    }

    impl DriftBank<'_> {
        pub fn observe(&mut self, kind: AutonomousDriftKind, z: Fx) -> Option<(AutonomousDriftReport, AutonomousRollbackAction)> {
            use AutonomousDriftKind::*;
            let (log_wealth, threshold, samples) = match kind {
                OffPolicyValueDrift => {
                    let w = self.value_down.observe(Fx::ONE.checked_sub(z)?)?;
                    (w, self.value_down.threshold_q16(), self.value_down.samples())
                }
                FallbackRateDrift => self.fallback_rate.observe(z)?,
                EnvelopeSupportDrift => self.envelope_size.observe(z)?,
                ShadowPriceDrift { dim } => self.shadow.get_mut(usize::from(dim))?.observe(z)?,
                CopleyConceptDrift { concept } => self.concepts.get_mut(usize::from(concept))?.observe(z)?,
                // Exact, non-statistical signals: a single occurrence is conclusive.
                PropensityFloorViolation | WeightsBindingMismatch | WitnessIntegrityFailure => (i64::MAX, 0, 1),
            };
            let report = AutonomousDriftReport { kind, log_wealth_q16: log_wealth, threshold_q16: threshold, samples, triggered: log_wealth >= threshold };
            let action = self.machine.absorb(&report);
            Some((report, action))
        }
    }
}
```

**Bank sizing and the family-wise level.** The bank holds two concept monitors per predicate, five two-sided shadow-price monitors, two two-sided envelope monitors, and one value monitor. The family has fewer than $2^{11}$ members, so every threshold is built with `log_inv_alpha(alpha_shift, 11)`, and the Bonferroni union bound gives a family-wise false-rollback probability of at most $\alpha$ over the entire epoch at every stopping time. Streams are formed exactly: the fallback-rate stream is $\mathbb{1}[a_i = \bot_{x_i}]$, the envelope stream is $|\mathcal{C}_i| / 16$, each shadow-price stream is the component clipped to a declared range, each concept stream is $\mathbb{1}[\kappa_j(x_i) = +]$, and the value stream is the normalized `dr_term` of the deployed artifact with the null set at the certified lower bound relaxed by one ulp to absorb the normalization floor.

**Semantics of the safe states.** `ShadowModeOnly` keeps evaluating the candidate and logging its costs but acts with the incumbent artifact. `DelegatedOnly` permits autonomous action only through `BudgetSplit` children already admitted, so new authority cannot be minted. `BindDisabled` makes `evaluate_weights_binding` refuse every new `ModelCard` and freezes artifact promotion. `FullPause` sets the acting policy to the constant cost vector that makes $\bot_x$ the unique minimizer, so every decision resolves to `Hold` or `Deny`.

**Theorem 8 (monotonicity and envelope preservation).** Within an epoch the safe state is nondecreasing under any sequence of reports. In every safe state the emitted action is $\Pi_{\mathcal{C}(x)}(a)$ for some index $a$, hence lies in $\mathcal{C}(x)$.

*Proof.* `absorb` replaces the state by its join with a constant, and the join is an upper bound of its left argument in a total order. For the second claim, every safe state changes only which cost vector feeds `softmin_q16`, never the mask or the projection, and `ShieldedAction` has no public constructor other than `project`. $\square$

Theorem 8 is exactly the Envelope Preservation & Verification Transfer Theorem applied to rollback: a proof that quantified over a nondeterministic cost vector already covers the incumbent, the candidate, and the pause constant.

**Kani harnesses** (`#[cfg(kani)] mod proofs` in the crate):

```rust
#[cfg(kani)]
mod proofs {
    use super::drift::*;
    use super::envelope::{FeasibleSlice, MAX_ACTIONS};
    use super::fixed::FixedQ16_16 as Fx;
    use super::softmin::{propensity_floor, softmin_q16, MAX_EPSILON_SHIFT, MAX_TEMPERATURE_SHIFT};

    #[kani::proof]
    fn softmin_sums_to_one_and_respects_floor() {
        let (bits, fb, ts, es): (u16, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(ts <= MAX_TEMPERATURE_SHIFT && es <= MAX_EPSILON_SHIFT);
        let costs: [Fx; MAX_ACTIONS] = kani::any();
        for c in costs.iter() { kani::assume(c.0 >= -(1 << 40) && c.0 <= (1 << 40)); }
        if let Some(env) = FeasibleSlice::reconstruct(bits, fb) {
            let p = softmin_q16(&costs, &env, ts, es).expect("total on valid inputs");
            let floor = propensity_floor(env.mask().len(), es).unwrap();
            let mut sum: i64 = 0;
            for a in 0..MAX_ACTIONS {
                if env.mask().contains(a as u8) { assert!(p.p[a].0 >= floor.0 && floor.0 >= 1); sum += p.p[a].0; }
                else { assert!(p.p[a].0 == 0); }
            }
            assert!(sum == Fx::ONE.0);
        }
    }

    #[kani::proof]
    fn projection_never_leaves_envelope() {
        let (bits, fb, proposed): (u16, u8, u8) = (kani::any(), kani::any(), kani::any());
        if let Some(env) = FeasibleSlice::reconstruct(bits, fb) {
            assert!(env.mask().contains(env.project(proposed).index()));
        }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn safe_state_monotone_within_epoch() {
        let mut m = SafeStateMachine::new([0u8; 32]);
        for _ in 0..8 {
            let before = m.state();
            let report: AutonomousDriftReport = AutonomousDriftReport {
                kind: kani::any(), log_wealth_q16: kani::any(), threshold_q16: kani::any(), samples: kani::any(), triggered: kani::any(),
            };
            let _ = m.absorb(&report);
            assert!(m.state() >= before);
        }
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn monitor_is_total_on_bounded_streams() {
        let mut mon = EbMonitor::new(BetKind::EmpiricalBernstein, Fx(kani::any()), kani::any(), kani::any());
        if let Some(ref mut mon) = mon {
            for _ in 0..16 {
                let z: i64 = kani::any();
                kani::assume(z >= 0 && z <= Fx::ONE.0);
                assert!(mon.observe(Fx(z)).is_some());
            }
        }
    }
}
```

The drift-kind enum derives `kani::Arbitrary` under `cfg_attr(kani, ...)`, matching the pattern used on `FixedQ16_16`.

**Lean 4** (`formal/lean4/Chio/Autonomy/SafeState.lean` and `formal/lean4/Chio/Autonomy/Bernstein.lean`):

```lean
import Mathlib.Analysis.SpecialFunctions.Log.Basic

namespace Chio.Autonomy

inductive SafeState | nominal | shadowModeOnly | delegatedOnly | bindDisabled | fullPause
  deriving DecidableEq, Repr

def SafeState.rank : SafeState → Nat
  | .nominal => 0 | .shadowModeOnly => 1 | .delegatedOnly => 2 | .bindDisabled => 3 | .fullPause => 4

def SafeState.join (a b : SafeState) : SafeState := if a.rank ≥ b.rank then a else b

theorem join_mono_left (a b : SafeState) : a.rank ≤ (a.join b).rank := by
  unfold SafeState.join; split <;> omega

/-- Any finite sequence of absorbed reports never lowers the safe state within an epoch. -/
theorem foldl_join_mono (s : SafeState) (rs : List SafeState) :
    s.rank ≤ (rs.foldl SafeState.join s).rank := by
  induction rs generalizing s with
  | nil => simp
  | cons r rs ih => exact le_trans (join_mono_left s r) (ih (s.join r))

/-- ψ_E(λ) = −log(1−λ) − λ. -/
noncomputable def psiE (l : ℝ) : ℝ := -Real.log (1 - l) - l

/-- Fan–Grama–Liu inequality: the analytic core of the empirical-Bernstein supermartingale. -/
theorem fan_grama_liu (l ξ : ℝ) (hl0 : 0 ≤ l) (hl1 : l < 1) (hξ : -1 ≤ ξ) :
    Real.exp (l * ξ - psiE l * ξ ^ 2) ≤ 1 + l * ξ := by
  sorry -- obligation autonomy.eb.fan_grama_liu, status = pending

/-- Rounding ψ_E upward only shrinks the wealth factor (fixed-point conservativeness). -/
theorem wealth_factor_anti_mono (l ξ ψ ψ' : ℝ) (h : ψ ≤ ψ') :
    Real.exp (l * ξ - ψ' * ξ ^ 2) ≤ Real.exp (l * ξ - ψ * ξ ^ 2) := by
  apply Real.exp_le_exp.mpr
  nlinarith [sq_nonneg ξ]

end Chio.Autonomy
```

The two lattice lemmas and the conservativeness lemma are closed. The Fan–Grama–Liu lemma is registered as a pending obligation, and the manifest's sorry-free gate blocks artifact promotion until it is discharged. Until then the Rust monitors are still sound by the published proof, but the kernel-level claim is not yet machine-checked.

**Apalache TLA+** (`formal/tla/AutonomySafeState.tla`):

```tla
---------------------------- MODULE AutonomySafeState ----------------------------
EXTENDS Integers, FiniteSets

CONSTANTS
  \* @type: Set(Int);
  Actions,
  \* @type: Int;
  Fallback

VARIABLES
  \* @type: Int;
  state,
  \* @type: Set(Int);
  envelope,
  \* @type: Int;
  chosen,
  \* @type: Int;
  epoch

vars == <<state, envelope, chosen, epoch>>
Nominal == 0  ShadowModeOnly == 1  DelegatedOnly == 2  BindDisabled == 3  FullPause == 4
Kinds == {"concept", "shadow", "envelope", "fallbackRate", "value", "floor", "weights", "witness"}

MinState(k) ==
  CASE k \in {"concept", "shadow", "envelope"} -> ShadowModeOnly
    [] k = "fallbackRate"                      -> DelegatedOnly
    [] k \in {"value", "floor"}                -> BindDisabled
    [] OTHER                                   -> FullPause

Init == state = Nominal /\ Fallback \in Actions /\ envelope \in SUBSET Actions
        /\ Fallback \in envelope /\ chosen = Fallback /\ epoch = 0

\* The learned choice is unconstrained nondeterminism inside the envelope.
Decide == /\ \E e \in SUBSET Actions : Fallback \in e /\ envelope' = e
          /\ chosen' \in envelope'
          /\ UNCHANGED <<state, epoch>>

Drift == /\ \E k \in Kinds : state' = IF state >= MinState(k) THEN state ELSE MinState(k)
         /\ UNCHANGED <<envelope, chosen, epoch>>

Restore == /\ state' = Nominal /\ epoch' = epoch + 1 /\ UNCHANGED <<envelope, chosen>>

Next == Decide \/ Drift \/ Restore

Inv_Feasible == chosen \in envelope /\ Fallback \in envelope
Inv_Monotone == [][state' >= state \/ epoch' > epoch]_vars
================================================================================
```

Apalache checks `Inv_Feasible` as a state invariant and `Inv_Monotone` as an action invariant, matching the Kani harness and the Lean lemma for the same property at three granularities.

**Manifest additions** (`formal/proof-manifest.toml`, appended, no existing entry modified):

```toml
[[obligation]]
id = "autonomy.softmin.exact_normalization"
kind = "kani"
harness = "chio_autonomy::proofs::softmin_sums_to_one_and_respects_floor"
status = "required"

[[obligation]]
id = "autonomy.envelope.projection_closed"
kind = "kani"
harness = "chio_autonomy::proofs::projection_never_leaves_envelope"
status = "required"

[[obligation]]
id = "autonomy.safe_state.monotone"
kind = "lean4"
decl = "Chio.Autonomy.foldl_join_mono"
status = "required"

[[obligation]]
id = "autonomy.eb.fan_grama_liu"
kind = "lean4"
decl = "Chio.Autonomy.fan_grama_liu"
status = "pending"

[[obligation]]
id = "autonomy.safe_state.tla"
kind = "apalache"
module = "AutonomySafeState"
invariants = ["Inv_Feasible"]
action_invariants = ["Inv_Monotone"]
status = "required"
```

Recap. The autonomy layer logs a `DecisionModelWitnessMetadata` and a `CopleyWitnessReceiptMetadata` under the existing `model_metadata` receipt key, so the pinned reserved-key array and all existing proofs are untouched. Because the envelope comes from pinned exact functions and the propensity is defined as a deterministic Q16.16 procedure, both are reconstructed bit for bit from historical receipts, and rows that fail reconstruction are rejected rather than estimated. The doubly-robust estimator over those rows is conditionally unbiased for any frozen reward model, bounded by a known constant, and never touches an action outside the logged envelope, so the two artifact families are trained and certified with zero off-support extrapolation and the certificate is computed on the quantized bits. Drift protection uses fixed-bet empirical-Bernstein and Hoeffding test supermartingales whose log-wealth is linear in the data, giving integer-only anytime-valid monitors whose every rounding is provably conservative. Triggered reports move the safe state monotonically up a five-element lattice, each state maps to one rollback action, and only an operator-signed restore that opens a new epoch moves it down. Four Kani harnesses, three closed Lean lemmas, and one Apalache module are specified, with the Fan–Grama–Liu real-analysis lemma left as the single pending manifest obligation that gates promotion.

---

# Verbatim Treatise - `wave4_angle_4_end_to_end_pr_roadmap_and_benchmark_suite`

I'll lay out the eight-PR landing order first, then the deterministic simulation harness, then the Criterion suite with its analytical latency model and the gate thresholds that `cargo xtask` enforces.

## 1. Sequenced PR stack and the dependency law

**Dependency law.** Every hot-path crate stays `#![no_std]` and depends only downward. The table is the whole rule; `cargo xtask gate manifest` fails a PR that adds any other edge.

| Crate | Mode | May depend on |
|---|---|---|
| `chio-core-types` | std + alloc | nothing in-tree |
| `chio-kernel-core` (`formal_*`, `budget_split`) | `no_std` modules | `chio-core-types` |
| `copley-concepts` (new, PR 2) | `no_std`, `forbid(unsafe_code)` | `chio-kernel-core` |
| `chio-semantic-contracts` | `no_std` | the two above |
| `chio-guards` | std | all above |
| `chio-kernel`, `chio-swarm-authority` | std | all above |
| `copley-tier1` (new, PR 6) | std, optional `onnx` | `chio-core-types`, `copley-concepts`; nothing on the hot path depends on it |
| `chio-dst` (new, PR 7) | std, dev-only | everything; nothing depends on it |

**Manifest law.** Every row of `formal/proof-manifest.toml` that exists at `5a7d81ec5b` is frozen. New rows are appended under `[[proof]]` with a `pr = N` field. The pinned signatures in `formal_core.rs` and `formal_aeneas.rs` are never edited; new behaviour lives in new modules that call them. I assume leaf guards expose `fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, GuardError>` with `GuardDecision { verdict, evidence }`. If the real leaf signature differs, only the glue in PR 4 changes.

**PR 1: envelope primitives.** Touches `crates/kernel/chio-kernel-core/src/formal_envelope.rs` (new), one `pub mod` line in `lib.rs`, `formal/lean4/Chio/Envelope.lean`, `formal/kani/envelope.rs`. No feature flag. This is the whole shielded-projection machinery; everything later is an instance.

```rust
//! formal_envelope.rs - PR 1. Additive. formal_core.rs / formal_aeneas.rs untouched.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    /// Strong Kleene conjunction: Neg absorbs, Bot dominates Pos.
    pub const fn and(self, rhs: K3) -> K3 {
        match (self, rhs) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Bot, _) | (_, K3::Bot) => K3::Bot,
            (K3::Pos, K3::Pos) => K3::Pos,
        }
    }
}

/// Q16.16 fixed point. Every operation is checked; `None` means overflow, never a wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(i32);

impl FixedQ16_16 {
    const ONE_RAW_I64: i64 = 1 << 16;
    pub const ZERO: Self = FixedQ16_16(0);
    pub const ONE: Self = FixedQ16_16(1 << 16);
    pub const fn from_raw(raw: i32) -> Self { FixedQ16_16(raw) }
    pub const fn raw(self) -> i32 { self.0 }
    pub fn checked_add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(FixedQ16_16) }
    pub fn checked_sub(self, o: Self) -> Option<Self> { self.0.checked_sub(o.0).map(FixedQ16_16) }
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(o.0))?;
        i32::try_from(wide.checked_div(Self::ONE_RAW_I64)?).ok().map(FixedQ16_16)
    }
}

/// A feasible envelope C_ℓ(x) with distinguished fallback ⊥_x.
/// Law (Lean `Chio.Envelope.fallback_mem`): `self.contains(&self.fallback())` holds.
pub trait Feasible<A> {
    fn contains(&self, a: &A) -> bool;
    fn fallback(&self) -> A;
}

/// Only `project` constructs this; the field is private so no caller can forge a member.
pub struct ShieldedAction<A> { action: A, projected: bool }

impl<A> ShieldedAction<A> {
    pub fn action(&self) -> &A { &self.action }
    pub fn was_projected(&self) -> bool { self.projected }
}

/// Π_{C_ℓ(x)}: a learned proposal is accepted iff it is a member, else ⊥_x.
pub fn project<A, F: Feasible<A>>(env: &F, proposal: Option<A>) -> ShieldedAction<A> {
    match proposal {
        Some(a) if env.contains(&a) => ShieldedAction { action: a, projected: false },
        _ => ShieldedAction { action: env.fallback(), projected: true },
    }
}
```

The Lean side states the transfer theorem once. Every later proof uses it by instantiating `feasible` and never modelling the predictor.

```lean
namespace Chio.Envelope

structure Envelope (α : Type) where
  feasible : α → Prop
  fallback : α
  fallback_mem : feasible fallback

variable {α : Type} (E : Envelope α) [DecidablePred E.feasible]

def project : Option α → α
  | some a => if E.feasible a then a else E.fallback
  | none   => E.fallback

theorem project_mem (p : Option α) : E.feasible (project E p) := by
  cases p with
  | none => exact E.fallback_mem
  | some a =>
    show E.feasible (if E.feasible a then a else E.fallback)
    by_cases h : E.feasible a
    · rw [if_pos h]; exact h
    · rw [if_neg h]; exact E.fallback_mem

/-- Verification transfer: a property proved for every feasible point holds for the
    projection of any proposal, including an adversarial one. -/
theorem transfer (P : α → Prop) (hP : ∀ a, E.feasible a → P a) (p : Option α) :
    P (project E p) := hP _ (project_mem E p)

end Chio.Envelope
```

Manifest rows appended by PR 1:

```toml
[[proof]]
rust   = "chio_kernel_core::formal_envelope::project"
lean   = "Chio.Envelope.project_mem"
kani   = "kani_range_envelope_project_is_member"
pr     = 1
status = "discharged"
```

**PR 2: `copley-concepts`.** New crate at `crates/copley/copley-concepts` with `src/{lib,concept,threshold,tier0}.rs`, `formal/lean4/Copley/Concept.lean`. Depends only on `chio-kernel-core`. The role cardinalities are compile-time constants so the Lean file and the Rust file disagree only if the build breaks.

| Role | Predicates |
|---|---|
| `CommandLine` | 345 |
| `Image` | 97 |
| `OriginalFileName` | 57 |
| `ParentImage` | 38 |
| total | 537 |

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConceptRole { CommandLine, Image, OriginalFileName, ParentImage }

impl ConceptRole {
    pub const fn cardinality(self) -> u16 {
        match self { Self::CommandLine => 345, Self::Image => 97,
                     Self::OriginalFileName => 57, Self::ParentImage => 38 }
    }
}
pub const CONCEPT_COUNT: u16 = 537;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConceptId { role: ConceptRole, index: u16 }
impl ConceptId {
    pub const fn new(role: ConceptRole, index: u16) -> Option<Self> {
        if index < role.cardinality() { Some(Self { role, index }) } else { None }
    }
}

/// Role-asymmetric thresholds; the constructor enforces τ_neg ≤ τ_pos.
#[derive(Clone, Copy, Debug)]
pub struct Thresholds { pos: FixedQ16_16, neg: FixedQ16_16 }
impl Thresholds {
    pub fn new(pos: FixedQ16_16, neg: FixedQ16_16) -> Option<Self> {
        if neg <= pos { Some(Self { pos, neg }) } else { None }
    }
    /// Total and monotone in `p`; Lean `Copley.Concept.classify_mono`.
    pub fn classify(&self, p: FixedQ16_16) -> K3 {
        if p >= self.pos { K3::Pos } else if p <= self.neg { K3::Neg } else { K3::Bot }
    }
}

pub const SHADOW_PRICES: usize = 5; // budget, fuel, latency, memory, escrow
#[derive(Clone, Copy, Debug)]
pub struct ShadowPrices { pub lambda: [FixedQ16_16; SHADOW_PRICES] }

/// Tier-0 linear micro-model: score = bias + θ·φ(x) − λ·r(x). 10–800 ns, integer only.
pub struct MicroModel<const F: usize> { pub theta: [FixedQ16_16; F], pub bias: FixedQ16_16 }
impl<const F: usize> MicroModel<F> {
    pub fn score(&self, phi: &[FixedQ16_16; F], cost: &[FixedQ16_16; SHADOW_PRICES],
                 prices: &ShadowPrices) -> Option<FixedQ16_16> {
        let mut acc = self.bias;
        for (t, x) in self.theta.iter().zip(phi) { acc = acc.checked_add(t.checked_mul(*x)?)?; }
        for (l, r) in prices.lambda.iter().zip(cost) { acc = acc.checked_sub(l.checked_mul(*r)?)?; }
        Some(acc)
    }
}
pub struct Tier0 { pub models: [MicroModel<16>; 6] }
```

**PR 3: `BudgetSplit` dynamic pool.** Touches `budget_split.rs` additively with `child_share_bps`, `total_child_bps`, and `rebalance_child`, plus a new `budget_pool.rs` that pairs the split with per-child `ReservationLedger` values driven only through `ledger_apply`. Adds `formal/tla/BudgetSplitPool.tla`, `formal/lean4/Chio/BudgetPool.lean`, Kani `kani_rebalance_conserves`. A dual-ascent step on `λ_budget` proposes new shares; the exact check below is the only thing that can change state, and an `Err` means `Hold`.

```rust
impl BudgetSplit {
    pub fn total_child_bps(&self) -> u32 {
        self.children.values().fold(0u32, |acc, c| acc.saturating_add(u32::from(c.share_bps)))
    }
    /// Exact admission of a learned/dual proposal. On Err the split is unchanged (⊥_x = Hold).
    pub fn rebalance_child(&mut self, child_id: &str, new_share_bps: u16) -> Result<(), BudgetSplitError> {
        if new_share_bps > MAX_BUDGET_SHARE_BPS {
            return Err(BudgetSplitError::ChildShareExceedsCap { child_id: child_id.to_string(), share_bps: new_share_bps });
        }
        let current = self.children.get(child_id)
            .ok_or_else(|| BudgetSplitError::UnknownChild { child_id: child_id.to_string() })?.share_bps;
        let overflow = || BudgetSplitError::ShareTotalOverflow { parent_token_id: self.parent_token_id.clone() };
        let without = self.total_child_bps().checked_sub(u32::from(current)).ok_or_else(overflow)?;
        let proposed = without.checked_add(u32::from(new_share_bps)).ok_or_else(overflow)?;
        if proposed > u32::from(self.parent_share_bps) {
            return Err(BudgetSplitError::OversubscribedSiblings { child_id: child_id.to_string(),
                share_bps: new_share_bps, current_total_child_bps: without, parent_share_bps: self.parent_share_bps });
        }
        if let Some(c) = self.children.get_mut(child_id) { c.share_bps = new_share_bps; }
        Ok(())
    }
}
```

`UnknownChild` is added as a new variant only if the elided part of the enum lacks one. The Apalache model treats the proposal as pure nondeterminism, exactly as the law requires:

```tla
---------------------------- MODULE BudgetSplitPool ----------------------------
EXTENDS Integers, Apalache
CONSTANTS
  \* @type: Set(Str);  Children,
  \* @type: Int;       ParentShareBps,
  \* @type: Int;       MaxBps
VARIABLES
  \* @type: Str -> Int;  share,
  \* @type: Int;         lambdaBudget

\* @type: (Str -> Int) => Int;
Total(s) == ApaFoldSet(LAMBDA acc, c: acc + s[c], 0, Children)

CInit == Children = {"a", "b", "c"} /\ ParentShareBps = 8000 /\ MaxBps = 10000
Init  == share = [c \in Children |-> 0] /\ lambdaBudget = 0

\* Learned proposal (c, t) is unconstrained; admission is the exact guard.
Rebalance(c, t) ==
  /\ Total([share EXCEPT ![c] = t]) <= ParentShareBps
  /\ share' = [share EXCEPT ![c] = t]
  /\ lambdaBudget' \in 0..MaxBps
Hold == UNCHANGED share /\ lambdaBudget' \in 0..MaxBps
Next == (\E c \in Children, t \in 0..MaxBps : Rebalance(c, t)) \/ Hold

TypeOK   == (\A c \in Children : share[c] \in 0..MaxBps) /\ lambdaBudget \in 0..MaxBps
Conserve == Total(share) <= ParentShareBps
Inv      == TypeOK /\ Conserve
================================================================================
```

Checked with `apalache-mc check --cinit=CInit --inv=Inv --length=12` and the one-step inductive form `--init=Inv --inv=Inv --length=1`. Inductiveness is immediate: `Rebalance` admits only successors satisfying `Conserve`, and `Hold` leaves `share` fixed. The Lean file carries the utilization theorem used in section 3:

```lean
theorem sum_zipWith_min_le_left : ∀ (d s : List Nat), (List.zipWith min d s).sum ≤ d.sum
  | [], _ => Nat.zero_le _
  | _ :: _, [] => Nat.zero_le _
  | a :: d, b :: s => by
      simp only [List.zipWith_cons_cons, List.sum_cons]
      exact Nat.add_le_add (Nat.min_le_left a b) (sum_zipWith_min_le_left d s)
-- symmetric lemma `sum_zipWith_min_le_right` elided
theorem pooled_ge_static (d s : List Nat) :
    (List.zipWith min d s).sum ≤ min d.sum s.sum :=
  Nat.le_min.mpr ⟨sum_zipWith_min_le_left d s, sum_zipWith_min_le_right d s⟩
```

Read `d` as child demands and `s` as static shares. A static split commits the left-hand side. A pooled split commits the right-hand side, which the exact admission caps at the parent share. So pooling never commits less, for every realization and not only in expectation.

**PR 4: `TwoPhaseGuardPipeline`.** Touches `crates/guards/chio-guards/src/two_phase.rs` (new), a `pub fn guards(&self) -> &[Box<dyn Guard>]` accessor on `GuardPipeline`, and one defaulted method on the `Guard` trait: `fn exact_relevance(&self, ctx: &GuardContext) -> K3 { K3::Bot }`. The default keeps every existing implementor compiling. Feature `two-phase` ships off and is flipped on in PR 8. The contract a guard accepts by overriding the default: `Neg` means the guard certifies, by exact computation, that it would return `Allow` on this context. The pipeline then does two things. Phase one skips `Neg` guards. Phase two evaluates the rest in a learned order, projected onto the envelope of permutations, with the identity order as `⊥_x`. The verdict kind is unchanged by either step because the fold in `pipeline.rs` is commutative with `Allow` as identity, which the Lean file below proves.

```rust
//! two_phase.rs - PR 4. Semantics of pipeline.rs preserved; see Chio/TwoPhase.lean.
use chio_kernel_core::formal_envelope::{project, Feasible, K3, ShieldedAction};
pub const MAX_PIPELINE_GUARDS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Order { idx: [u8; MAX_PIPELINE_GUARDS], len: usize }
impl Order {
    pub fn identity(len: usize) -> Option<Order> {
        if len > MAX_PIPELINE_GUARDS { return None; }
        let mut idx = [0u8; MAX_PIPELINE_GUARDS];
        for (i, slot) in idx.iter_mut().enumerate().take(len) { *slot = u8::try_from(i).ok()?; }
        Some(Order { idx, len })
    }
    pub fn as_slice(&self) -> &[u8] { self.idx.get(..self.len).unwrap_or(&[]) }
}

/// Exact envelope: bijections on 0..len. Membership is one pass with a bitset; fallback is O(1).
pub struct PermutationEnvelope { identity: Order }
impl PermutationEnvelope {
    pub fn new(len: usize) -> Option<Self> { Order::identity(len).map(|identity| Self { identity }) }
}
fn bit(i: u8) -> u64 { 1u64.checked_shl(u32::from(i)).unwrap_or(0) }
impl Feasible<Order> for PermutationEnvelope {
    fn contains(&self, o: &Order) -> bool {
        if o.len != self.identity.len { return false; }
        let mut seen = 0u64;
        for &i in o.as_slice() {
            if usize::from(i) >= o.len || seen & bit(i) != 0 { return false; }
            seen |= bit(i);
        }
        true
    }
    fn fallback(&self) -> Order { self.identity }
}

/// The learned component. It may return anything; `project` makes that harmless.
pub trait GuardScheduler { fn propose(&self, ctx: &GuardContext, len: usize) -> Option<Order>; }

pub struct TwoPhaseWitness { pub skipped_mask: u64, pub order: Order, pub projected: bool }

pub struct TwoPhaseGuardPipeline<S: GuardScheduler> { inner: GuardPipeline, scheduler: S }

impl<S: GuardScheduler> TwoPhaseGuardPipeline<S> {
    pub fn new(inner: GuardPipeline, scheduler: S) -> Option<Self> {
        (inner.guards().len() <= MAX_PIPELINE_GUARDS).then_some(Self { inner, scheduler })
    }

    pub fn evaluate_with_witness(&self, ctx: &GuardContext) -> Result<(GuardDecision, TwoPhaseWitness), GuardError> {
        let guards = self.inner.guards();
        let mut evidence = Vec::new();
        let mut live = [0u8; MAX_PIPELINE_GUARDS];
        let mut live_len = 0usize;
        let mut skipped_mask = 0u64;
        // Phase 1: exact relevance. len ≤ 64 is guaranteed by `new`, so the u8 range cannot overflow.
        for (i, g) in (0u8..).zip(guards) {
            if g.exact_relevance(ctx) == K3::Neg {
                skipped_mask |= bit(i);
                evidence.push(GuardEvidence { guard_name: g.name().to_string(), verdict: true,
                    details: Some("action=skip; reason=exact-prefilter certified allow".to_string()) });
            } else if let Some(slot) = live.get_mut(live_len) {
                *slot = i;
                live_len = live_len.saturating_add(1);
            }
        }
        // Phase 2: learned order, shielded. Fallback is the canonical order.
        let env = PermutationEnvelope::new(live_len).unwrap_or_else(|| PermutationEnvelope { identity: Order { idx: live, len: 0 } });
        let shielded: ShieldedAction<Order> = project(&env, self.scheduler.propose(ctx, live_len));
        let witness = TwoPhaseWitness { skipped_mask, order: *shielded.action(), projected: shielded.was_projected() };
        let mut final_verdict = Verdict::Allow;
        for &pos in witness.order.as_slice() {
            let Some(guard) = live.get(usize::from(pos)).and_then(|&gi| guards.get(usize::from(gi))) else { continue };
            match guard.evaluate(ctx) {
                Ok(d) => {
                    evidence.extend(d.evidence);
                    match d.verdict {
                        Verdict::Allow => {}
                        Verdict::PendingApproval => final_verdict = Verdict::PendingApproval,
                        Verdict::Deny => {
                            evidence.push(GuardEvidence { guard_name: guard.name().to_string(), verdict: false,
                                details: Some("action=deny; reason=guard denied request".to_string()) });
                            return Ok((GuardDecision::deny(evidence), witness));
                        }
                    }
                }
                Err(e) => {
                    evidence.push(GuardEvidence { guard_name: guard.name().to_string(), verdict: false,
                        details: Some(format!("action=deny; reason=guard error: {e}")) });
                    return Ok((GuardDecision::deny(evidence), witness));
                }
            }
        }
        Ok((GuardDecision::with_verdict(final_verdict, evidence), witness))
    }
}
```

The `impl Guard for TwoPhaseGuardPipeline<S>` forwards `requires_dispatch_revalidation`, `revalidate_before_dispatch`, `validate_output_before_release`, and the rest to `inner` unchanged. The soundness proof models each guard by the outcome it would return on `ctx`, with `Err` mapped to `deny` as `pipeline.rs` does:

```lean
namespace Chio.TwoPhase
inductive Outcome | allow | pending | deny deriving DecidableEq
open Outcome

def combine : Outcome → Outcome → Outcome
  | deny, _ => deny | _, deny => deny
  | pending, _ => pending | _, pending => pending
  | allow, allow => allow

theorem combine_allow_right : ∀ a, combine a allow = a := by intro a; cases a <;> rfl
theorem combine_rcomm : ∀ a b c, combine (combine a b) c = combine (combine a c) b := by
  intro a b c; cases a <;> cases b <;> cases c <;> rfl

/-- The loop in pipeline.rs: Deny short-circuits, Pending is sticky, Allow continues. -/
def pipeline (init : Outcome) (l : List Outcome) : Outcome := l.foldl combine init

theorem pipeline_perm (init : Outcome) {l₁ l₂ : List Outcome} (h : l₁.Perm l₂) :
    pipeline init l₁ = pipeline init l₂ := by
  induction h generalizing init with
  | nil => rfl
  | cons x _ ih => exact ih (combine init x)
  | swap x y l =>
      show List.foldl combine (combine (combine init y) x) l
         = List.foldl combine (combine (combine init x) y) l
      rw [combine_rcomm]
  | trans _ _ ih₁ ih₂ => exact (ih₁ init).trans (ih₂ init)

def prune : List Outcome → List Outcome
  | [] => [] | allow :: t => prune t | o :: t => o :: prune t

theorem pipeline_prune : ∀ (init : Outcome) (l : List Outcome), pipeline init (prune l) = pipeline init l
  | _, [] => rfl
  | init, allow :: t => by
      show pipeline init (prune t) = pipeline (combine init allow) t
      rw [combine_allow_right]; exact pipeline_prune init t
  | init, pending :: t => pipeline_prune (combine init pending) t
  | init, deny :: t => pipeline_prune (combine init deny) t

/-- `live` is `l` with some Allow-certified guards removed; `l'` is any learned order of `live`. -/
theorem two_phase_sound (init : Outcome) (l live l' : List Outcome)
    (hlive : prune live = prune l) (h : live.Perm l') :
    pipeline init l' = pipeline init l := by
  rw [← pipeline_perm init h, ← pipeline_prune init live, hlive, pipeline_prune init l]
end Chio.TwoPhase
```

The Kani harness closes the Rust side of the envelope. The scheduler is `kani::any()` and the assertion is membership, which is exactly what `two_phase_sound` consumes as `h`.

```rust
#[cfg(kani)]
mod verification {
    use super::*;
    #[kani::proof] #[kani::unwind(9)]
    fn kani_order_projection_is_bijection() {
        let len: usize = kani::any();
        kani::assume(len <= 8);
        let Some(env) = PermutationEnvelope::new(len) else { return };
        let mut idx = [0u8; MAX_PIPELINE_GUARDS];
        for slot in idx.iter_mut().take(len) { *slot = kani::any(); }
        let shielded = project(&env, Some(Order { idx, len: kani::any() }));
        assert!(env.contains(shielded.action()));
    }
}
```

**PR 5: `CopleyWitnessReceiptMetadata`.** Touches `crates/core/chio-core-types/src/receipt/copley_witness.rs` (new) and `metadata.rs`. The existing `RESERVED_RECEIPT_METADATA_KEYS: [&str; 35]` is not touched. Instead PR 5 adds `COPLEY_WITNESS_METADATA_KEY = "copley_witness_v1"`, a one-element `COPLEY_RESERVED_RECEIPT_METADATA_KEYS`, and `pub fn is_reserved_receipt_metadata_key(key: &str) -> bool` that consults both arrays. Call sites in `metadata.rs` switch to the function. The witness binds the model that ran to the receipt through `LoadedWeights::loaded_weights_hash` and `evaluate_weights_binding`, and it carries everything needed to replay the decision bit for bit.

```rust
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CopleyWitnessReceiptMetadata {
    pub schema: u16,                       // 1
    pub tier0_params_hash: String,         // hash of the six MicroModel parameter blocks
    pub tier1_weights_hash: Option<String>,// LoadedWeights::loaded_weights_hash, provider "copley-ultrabert-19m"
    pub thresholds_hash: String,
    pub shadow_prices_raw: [i32; 5],       // FixedQ16_16::raw, order budget/fuel/latency/memory/escrow
    pub concept_k3: Vec<u8>,               // 537 entries: 0 = Neg, 1 = Bot, 2 = Pos
    pub guard_order: Vec<u8>,
    pub skipped_mask: u64,
    pub projected: bool,
    pub verdict_kind: u8,                  // 0 = Deny, 1 = PendingApproval, 2 = Allow
}
```

Replay re-runs the canonical `GuardPipeline` on the stored context and compares `verdict_kind`; a mismatch is a hard DST failure. Coupling of the witness hash into `receipt_fields_coupled` is done by a new wrapper in `formal_envelope.rs` that takes the five existing booleans plus `witness_hash_matches`, so the pinned function keeps its arity.

**PR 6: Tier-1 adapter and swarm bridge.** New crate `copley-tier1` with feature `onnx`, excluded from `wasm32` through a `cfg(not(target_arch = "wasm32"))` dependency table. It implements `LoadedWeights` for `CopleyTier1Weights`, publishes a four-segment `ModelCard`, and runs as an asynchronous oracle that fills `concept_k3` after the hot path has returned. `chio-swarm-authority` gains `pool_bridge.rs`, which backs `SwarmBudgetPool` with `BudgetPool` and prices escrow through `λ_escrow`, plus a `with_copley_witness` builder on `SwarmRoutePlanReceipt`. `formal/tla/SwarmBudgetPool.tla` instantiates `BudgetSplitPool` with join receipts; Apalache runs it with the graph limits scaled to a small `CInit`, with the full `MAX_SWARM_GRAPH_*` constants covered by Kani bounds rather than model checking.

**PR 7: `chio-dst`.** Section 2 in full.

**PR 8: gates, benchmarks, CI.** Section 3 in full, plus `formal/MAPPING.md` finalised and the `two-phase` default flipped on.

## 2. Deterministic simulation and differential replay

**Design.** The harness lives in `crates/testing/chio-dst`. It has a seeded `SplitMix64`, a single-threaded executor over explicit state-machine tasks, and a fault plan that drops a task between steps with a seed-derived probability. Dropping a task is the async cancellation model: the task's `on_drop` runs with whatever partial state exists, and the invariants must still hold. Every seed produces a trace digest. The same digest must appear on `x86_64`, `aarch64`, and `wasm32-unknown-unknown`, which is what makes the fixed-point and bitset code honest across targets.

Five invariants are checked after every step of every seed:

- **I1, parity.** The two-phase verdict kind equals the canonical `GuardPipeline` verdict kind. Zero mismatches over all seeds.
- **I2, conservation.** Total child basis points never exceed the parent share, and `retained_child_id_bytes` never exceeds its cap.
- **I3, ledger.** After any accepted `ledger_apply`, committed plus released plus retained is at most reserved, and a rejected op returns the input state unchanged.
- **I4, replay.** Replaying the witness reproduces the stored verdict kind and order.
- **I5, pooling.** Committed units under the dynamic pool are at least those under a static equal split with the same demands, per seed, which is `pooled_ge_static` observed rather than assumed.

```rust
//! tests/dst_drop_simulation.rs - PR 7. Runs on all three targets.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use chio_dst::{DetExecutor, FaultPlan, SplitMix64, TraceDigest, World};
use chio_dst::fixtures::{SynthGuard, AdversarialScheduler, equal_static_split};
use chio_guards::{GuardPipeline, two_phase::TwoPhaseGuardPipeline, Verdict};
use chio_kernel_core::{budget_pool::BudgetPool, formal_aeneas::{ledger_apply, ReservationLedger}};

const SEEDS: u64 = 10_000;
const STEPS: u32 = 256;
const GOLDEN: &[u8] = include_bytes!("../dst/golden/seed_digests.bin");

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ten_thousand_seeds_hold_all_invariants() {
    for seed in 0..SEEDS {
        let mut rng = SplitMix64::new(seed);
        let n = 1 + usize::try_from(rng.below(64)).unwrap_or(0);
        // SynthGuard::draw enforces the prefilter contract: certified_allow ⇒ outcome == Allow and no Err.
        let guards: Vec<SynthGuard> = (0..n).map(|i| SynthGuard::draw(&mut rng, i)).collect();
        let canonical = GuardPipeline::from_guards(guards.iter().cloned().map(SynthGuard::boxed).collect());
        let two_phase = TwoPhaseGuardPipeline::new(
            GuardPipeline::from_guards(guards.iter().cloned().map(SynthGuard::boxed).collect()),
            AdversarialScheduler::new(seed)).expect("n <= 64");
        let mut world = World::new(seed, BudgetPool::draw(&mut rng), ReservationLedger::default());
        let mut exec = DetExecutor::new(seed, FaultPlan::drop_permille(rng.below(200)));
        exec.spawn(world.rebalance_task());  // proposes shares via dual ascent on λ_budget
        exec.spawn(world.ledger_task());     // reserve/commit/release/retain through ledger_apply
        exec.spawn(world.request_task());    // builds GuardContext values from the seed
        let mut digest = TraceDigest::new();

        for _ in 0..STEPS {
            exec.step(&mut world);
            let ctx = world.current_ctx();
            let (tp, witness) = two_phase.evaluate_with_witness(&ctx).expect("two-phase never errors");
            let canon = canonical.evaluate(&ctx).expect("canonical never errors");
            assert_eq!(tp.verdict, canon.verdict, "I1 seed={seed}");                       // I1
            assert!(world.pool.split().total_child_bps() <= u32::from(world.pool.split().parent_share_bps), "I2 seed={seed}");
            let l = world.ledger;
            let spent = l.committed.checked_add(l.released).and_then(|s| s.checked_add(l.retained)).expect("I3 overflow");
            assert!(spent <= l.reserved, "I3 seed={seed}");                               // I3
            let (same, accepted) = ledger_apply(l, u8::try_from(rng.below(4)).unwrap_or(0), rng.below(1 << 20));
            if !accepted { assert_eq!(same, l, "I3 rejected-op must not mutate"); }
            assert!(witness.replays(&canonical, &ctx), "I4 seed={seed}");                   // I4
            assert!(world.pool.committed_units() >= equal_static_split(&world).committed_units(), "I5 seed={seed}"); // I5
            digest.absorb_verdict(tp.verdict).absorb_order(witness.order.as_slice())
                  .absorb_u32(world.pool.split().total_child_bps()).absorb_bool(witness.projected);
        }
        let want = u64::from_le_bytes(GOLDEN[usize::try_from(seed * 8).unwrap_or(0)..][..8].try_into().expect("8 bytes"));
        assert_eq!(digest.finish(), want, "cross-target digest drift at seed {seed}");
    }
}

/// Oracle self-test: a guard that lies about `exact_relevance` must be caught by I1.
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn parity_oracle_detects_prefilter_violation() {
    let mut rng = SplitMix64::new(0xC0FFEE);
    let liar = SynthGuard::lying_neg_that_denies(&mut rng);
    let canonical = GuardPipeline::from_guards(vec![liar.clone().boxed()]);
    let two_phase = TwoPhaseGuardPipeline::new(GuardPipeline::from_guards(vec![liar.boxed()]), AdversarialScheduler::new(1)).expect("1 guard");
    let ctx = chio_dst::fixtures::ctx_from_seed(1);
    assert_ne!(two_phase.evaluate(&ctx).expect("ok").verdict, canonical.evaluate(&ctx).expect("ok").verdict);
}
```

The adversarial scheduler returns garbage on a seed-derived fraction of calls, including out-of-range indices and duplicates, so `witness.projected` is exercised and the identity fallback path appears in the digests. The oracle self-test is a mutation test: it guarantees that I1 is not vacuous.

**SQLite crash recovery.** This harness is `cfg(not(target_arch = "wasm32"))`. A faithful crash must skip `sqlite3_close`, so the writer runs in a child process that terminates with `std::process::exit`, which does not run destructors. The parent then truncates the write-ahead log only at offsets beyond the last committed frame, because bytes an `fsync` already persisted cannot vanish in a real crash.

```rust
//! tests/dst_sqlite_recovery.rs - PR 7.
#![cfg(not(target_arch = "wasm32"))]
#![forbid(unsafe_code)]
use rusqlite::{params, Connection};
use chio_dst::SplitMix64;
use chio_kernel_core::formal_core::receipt_fields_coupled;

#[test]
fn child_entry() {
    let Ok(seed) = std::env::var("CHIO_DST_CHILD").map(|s| s.parse::<u64>().unwrap_or(0)) else { return };
    let path = std::env::var("CHIO_DST_DB").expect("db path");
    let mut rng = SplitMix64::new(seed);
    let conn = Connection::open(&path).expect("open");
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS receipt(id INTEGER PRIMARY KEY, kind INTEGER NOT NULL, witness BLOB NOT NULL);").expect("schema");
    let mut committed = 0u64;
    for _ in 0..(1 + rng.below(8)) {
        let tx = conn.unchecked_transaction().expect("tx");
        let rows = 1 + rng.below(16);
        for _ in 0..rows {
            tx.execute("INSERT INTO receipt(kind, witness) VALUES (?1, ?2)",
                params![i64::try_from(rng.below(3)).unwrap_or(0), vec![0u8; 64]]).expect("insert");
        }
        if rng.below(4) == 0 {
            let wal_len = std::fs::metadata(format!("{path}-wal")).map(|m| m.len()).unwrap_or(0);
            println!("{committed} {wal_len}");
            std::process::exit(0); // crash: no rollback, no close, uncommitted frames may be on disk
        }
        tx.commit().expect("commit");
        committed = committed.checked_add(rows).expect("count");
    }
    let wal_len = std::fs::metadata(format!("{path}-wal")).map(|m| m.len()).unwrap_or(0);
    println!("{committed} {wal_len}");
    std::process::exit(0);
}

#[test]
fn receipts_survive_crash_and_torn_wal() {
    let seeds: u64 = std::env::var("CHIO_DST_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000);
    for seed in 0..seeds {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("r.sqlite");
        let out = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args(["--exact", "child_entry", "--nocapture"])
            .env("CHIO_DST_CHILD", seed.to_string()).env("CHIO_DST_DB", &db).output().expect("spawn");
        let text = String::from_utf8_lossy(&out.stdout);
        let mut it = text.split_whitespace().filter_map(|t| t.parse::<u64>().ok());
        let (committed, safe_len) = (it.next().expect("rows"), it.next().expect("wal len"));
        let mut rng = SplitMix64::new(seed ^ 0xD57);
        let wal = format!("{}-wal", db.display());
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&wal) {
            let cur = f.metadata().map(|m| m.len()).unwrap_or(safe_len);
            let cut = safe_len.checked_add(rng.below(cur.saturating_sub(safe_len).saturating_add(1))).unwrap_or(safe_len);
            f.set_len(cut).expect("torn tail");
        }
        let conn = Connection::open(&db).expect("reopen");
        let ok: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0)).expect("ic");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM receipt", [], |r| r.get(0)).expect("count");
        assert_eq!(ok, "ok", "seed {seed}");
        assert_eq!(u64::try_from(n).unwrap_or(u64::MAX), committed, "durability oracle, seed {seed}");
        assert!(receipt_fields_coupled(true, true, true, true, true));
    }
}
```

The last assertion is a placeholder for the per-row coupling check, which decodes each witness blob and feeds the five comparisons into `receipt_fields_coupled`. The PR gate runs one thousand seeds of this harness because each seed is a process spawn; the nightly gate runs the full ten thousand.

## 3. Benchmarks, analytical model, and `cargo xtask` gates

**Criterion suite.** `benches/two_phase_latency.rs` compares canonical and two-phase pipelines on the same reference fixtures at three sizes, and times the three Tier-0 primitives in isolation.

```rust
//! benches/two_phase_latency.rs - PR 8
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use chio_dst::fixtures::{reference_ctx, reference_pipeline, RefKind};
use chio_guards::two_phase::{IndexScheduler, Order, PermutationEnvelope, TwoPhaseGuardPipeline};
use chio_kernel_core::formal_envelope::project;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("guard_pipeline");
    g.sample_size(2_000);
    for &n in &[4usize, 16, 64] {
        let canonical = reference_pipeline(n, RefKind::Mixed);
        let two_phase = TwoPhaseGuardPipeline::new(reference_pipeline(n, RefKind::Mixed), IndexScheduler::from_fixture(n)).expect("n <= 64");
        let ctx = reference_ctx(n);
        g.bench_with_input(BenchmarkId::new("canonical", n), &ctx, |b, ctx| b.iter(|| canonical.evaluate(black_box(ctx))));
        g.bench_with_input(BenchmarkId::new("two_phase", n), &ctx, |b, ctx| b.iter(|| two_phase.evaluate(black_box(ctx))));
    }
    g.finish();
    let mut t = c.benchmark_group("tier0");
    let env = PermutationEnvelope::new(64).expect("64");
    let proposal = Order::identity(64);
    t.bench_function("order_projection_64", |b| b.iter(|| project(&env, black_box(proposal))));
    t.bench_function("micro_model_score_16", |b| b.iter(|| chio_dst::fixtures::tier0().models[0].score(black_box(&chio_dst::fixtures::phi16()), &chio_dst::fixtures::cost5(), &chio_dst::fixtures::prices())));
    t.bench_function("pool_rebalance_8", |b| b.iter(|| chio_dst::fixtures::pool8().rebalance_child(black_box("c3"), 900)));
    t.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
```

Criterion reports means and medians, but the gate needs tails. `benches/percentiles.rs` is a plain binary that records one million per-iteration timings, subtracts the empty-loop timer floor measured the same way, sorts, and writes `target/bench/percentiles.json`.

```rust
/// Nearest-rank quantile. permille: 500 = p50, 990 = p99, 999 = p99.9.
pub fn quantile_ns(sorted: &[u64], permille: u64) -> Option<u64> {
    let n = u64::try_from(sorted.len()).ok()?;
    let rank = n.checked_sub(1)?.checked_mul(permille)?.checked_div(1000)?;
    sorted.get(usize::try_from(rank).ok()?).copied()
}
```

**Analytical latency model.** Index the live guards by evaluation order with cost `c_i` in nanoseconds and deny probability `d_i`, treated as independent. Both pipelines stop at the first deny, so the expected canonical cost is the sum over the fixed order of `c_i` times the probability that no earlier guard denied. The two-phase cost adds an exact prefilter of `π` per guard and one scheduler call of `σ`, then evaluates only the live guards. Ordering live guards by decreasing `d_i / c_i` minimises the expected sum. The proof is an adjacent exchange: placing `i` before `j` costs `c_i + (1 - d_i) c_j`, placing `j` first costs `c_j + (1 - d_j) c_i`, and the first is no larger exactly when `d_i / c_i ≥ d_j / c_j`. The scheduler learns `d_i`; the kernel measures `c_i` exactly as an exponentially weighted cycle count. A wrong `d_i` therefore costs latency and nothing else.

| Parameter | Value |
|---|---|
| guards `n` | 16 |
| mean guard cost `c` | 1,200 ns |
| prefilter `π` per guard | 12 ns |
| Tier-0 scheduler `σ` | 350 ns |
| exact-skip fraction | 0.45 |
| deny probability per live guard | 0.03 |

| Quantity | Canonical | Two-phase |
|---|---|---|
| expected cost | 15,428 ns | 10,132 ns |
| worst case, nothing skipped, no deny | 19,200 ns | 19,742 ns |
| expected saving | | 34.3% |
| worst-case overhead | | +542 ns |

The worst-case row is the tail model. Tier-1 never sits on the hot path, and the projection fallback costs no more than the identity order, so the two-phase tail is the canonical tail plus `nπ + σ`. The bench gate asserts exactly that bound with a small margin.

**Budget utilization model.** Define utilization as committed units divided by the parent reservation. With eight children whose demands are uniform between zero and twice their equal share, the static split truncates each child independently while the pool truncates only the sum. The table below comes from the closed-form expectation of a truncated uniform and a normal approximation of the sum; the DST reports the measured pair per seed and asserts the inequality from `pooled_ge_static`.

| Policy | Model utilization |
|---|---|
| static equal split | 75.0% |
| dynamic pool with `λ_budget` | 91.9% |

**Concept bottleneck metrics.** The AUROC gate uses an exact rank-sum computation so that the baseline comparison is bit-reproducible across targets. Ties receive half credit, which the doubled numerator keeps in integers.

```rust
/// Exact Mann–Whitney AUROC as (numerator, denominator). Ties count one half.
pub fn auroc_exact(scored: &mut [(i32, bool)]) -> Option<(u128, u128)> {
    scored.sort_by_key(|&(s, _)| s);
    let (mut neg_below, mut num, mut n_pos, mut n_neg) = (0u128, 0u128, 0u128, 0u128);
    let mut i = 0usize;
    while i < scored.len() {
        let s = scored.get(i)?.0;
        let (mut p, mut q) = (0u128, 0u128);
        while let Some(&(t, label)) = scored.get(i) {
            if t != s { break; }
            if label { p = p.checked_add(1)?; } else { q = q.checked_add(1)?; }
            i = i.checked_add(1)?;
        }
        num = num.checked_add(p.checked_mul(neg_below.checked_mul(2)?.checked_add(q)?)?)?;
        neg_below = neg_below.checked_add(q)?;
        n_pos = n_pos.checked_add(p)?;
        n_neg = n_neg.checked_add(q)?;
    }
    Some((num, n_pos.checked_mul(n_neg)?.checked_mul(2)?))
}
```

Composer parity is the second ML gate. On the frozen calibration set, a sample is confident when all of its concept classifications are `Pos` or `Neg`. The symbolic composer run on predicted concepts must agree with the composer run on gold concepts on every confident sample. The thresholds are chosen on the calibration set so that this count is zero, and coverage, the confident fraction, is reported as the price. Any nonzero count fails the gate, as does any I1 mismatch in the DST.

**Gates.** `xtask/src/main.rs` dispatches on a `Gate` trait with one file per gate under `xtask/src/gates/`. The CI workflow runs the matrix below on `ubuntu-latest`, `macos-14` for `aarch64`, and `wasm32-unknown-unknown` through `wasm-bindgen-test-runner`.

| Gate | Command | Pass condition |
|---|---|---|
| formal | `cargo xtask gate formal` | `lake build` in `formal/lean4` succeeds; every manifest `kani` harness passes; both Apalache invariants hold at depth 12 and inductively |
| manifest | `cargo xtask gate manifest` | every `#[kani::proof]` and every `pub fn` in `formal_*.rs` has a row; no frozen row changed; every row's symbols resolve |
| dst | `cargo xtask gate dst --seeds 10000` | zero invariant violations; digests match the golden file on all three targets; oracle self-test fails as expected |
| sqlite | `cargo xtask gate sqlite --seeds 1000` | integrity check `ok`; row count equals the committed oracle on every seed |
| bench | `cargo xtask gate bench` | p50 regression at most 5%; two-phase p99.9 at most canonical p99.9 plus 600 ns; expected saving at least 25% on the mixed fixture |
| ml | `cargo xtask gate ml` | each role AUROC at least baseline minus 0.005; composer mismatches zero; coverage at least baseline minus two points |
| cross | `cargo xtask gate cross` | `cargo build` and `cargo test` succeed on all three targets with `copley-tier1` excluded on wasm |

```rust
pub trait Gate { fn name(&self) -> &'static str; fn run(&self, args: &GateArgs) -> Result<(), GateFailure>; }

fn bench_passes(base: &Percentiles, cur: &Percentiles) -> bool {
    let p50_ok = cur.two_phase_p50.checked_mul(100).is_some_and(|v| v <= base.two_phase_p50.saturating_mul(105));
    let tail_ok = cur.two_phase_p999 <= cur.canonical_p999.saturating_add(600);
    let saving_ok = cur.canonical_p50.saturating_mul(75) >= cur.two_phase_p50.saturating_mul(100);
    p50_ok && tail_ok && saving_ok
}
```

**`formal/MAPPING.md` final table.** Each row is one line of the file and the manifest gate cross-checks it against `proof-manifest.toml`.

| Rust symbol | Lean theorem | TLA+ / Kani | PR |
|---|---|---|---|
| `formal_envelope::project` | `Chio.Envelope.project_mem`, `transfer` | `kani_range_envelope_project_is_member` | 1 |
| `copley_concepts::Thresholds::classify` | `Copley.Concept.classify_total`, `classify_mono` | `kani_classify_total` | 2 |
| `BudgetSplit::rebalance_child` | `Chio.BudgetPool.pooled_ge_static` | `BudgetSplitPool.Inv`, `kani_rebalance_conserves` | 3 |
| `two_phase::evaluate_with_witness` | `Chio.TwoPhase.two_phase_sound` | `kani_order_projection_is_bijection` | 4 |
| `copley_witness::coupled_with_witness` | `Chio.Receipt.coupled_and` | `kani_witness_coupling` | 5 |
| `pool_bridge::SwarmBudgetPool` | refines row 3 | `SwarmBudgetPool.Inv` | 6 |
| `ledger_apply`, `budget_commit`, `receipt_fields_coupled` | existing, frozen | existing, frozen | 0 |

Recap. The eight PRs land in dependency order, with every learned component introduced behind a projection whose fallback is the current canonical behaviour, so each commit compiles and the frozen proofs stay untouched. The soundness argument is a single Lean theorem about the guard fold being permutation-invariant with `Allow` as identity, a single Apalache invariant for pool conservation, and Kani harnesses that turn the scheduler and dual-ascent proposals into unconstrained nondeterminism. The DST harness runs ten thousand seeds on three targets with five per-step invariants and byte-identical digests, backed by a process-kill SQLite recovery test. The benchmark gate enforces a modelled expected saving above a quarter with a bounded tail overhead, the pooling inequality per seed, and zero composer mismatches at non-regressing AUROC. Next step is PR 1, which is small enough to review in one sitting and unblocks everything else.
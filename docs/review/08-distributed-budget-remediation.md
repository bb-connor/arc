# Hole 08 Remediation Memo: Distributed Budgets, Spend Invariants, and Truthful Exposure

## Problem

ARC currently describes monetary-budget enforcement as if it remains atomic and
truthful under HA, concurrency, and partitions. The implementation does not yet
support that claim.

Today the money path is built around a per-node mutable counter:

- `BudgetStore::try_charge_cost` explicitly documents an HA overrun bound of
  `max_cost_per_invocation * node_count` under split brain in
  `crates/arc-kernel/src/budget_store.rs:37-62`.
- The SQLite implementation performs a local transactional read-check-write in
  `crates/arc-store-sqlite/src/budget_store.rs:218-304`.
- Replication merges budget rows with seq-based LWW plus `MAX(...)` resolution
  in `crates/arc-store-sqlite/src/budget_store.rs:61-104`.
- The kernel pre-debits the worst-case per-invocation amount before execution
  in `crates/arc-kernel/src/lib.rs:2624-2679`, then reconciles later against a
  tool-reported actual cost in `crates/arc-kernel/src/lib.rs:3940-4028`.

That design gives useful single-node enforcement and a bounded split-brain
story. It does not give a distributed spending invariant, truthful global
exposure accounting, or a defensible "atomic under HA" claim.

To make the claim true, ARC needs a real budget-authorization protocol, not a
replicated counter.

## Current Evidence

The repo already contains several useful building blocks:

- Single-node local atomicity is real. The SQLite budget store uses
  `TransactionBehavior::Immediate` and checks invocation count, per-call cap,
  and total cap in one local transaction in
  `crates/arc-store-sqlite/src/budget_store.rs:218-304`.
- The kernel already treats money differently from plain invocation counts by
  pre-charging a provisional amount and later reducing or settling it in
  `crates/arc-kernel/src/lib.rs:2624-2679` and
  `crates/arc-kernel/src/lib.rs:3940-4028`.
- ARC already has a remote budget-store abstraction:
  `crates/arc-cli/src/trust_control.rs:6350-6407` and
  `crates/arc-control-plane/src/lib.rs:283-305`.
- The trust-control service already fail-closes minority writes in the cluster
  tests. A minority partition receives HTTP 503 for `/v1/budgets/increment` in
  `crates/arc-cli/tests/trust_cluster.rs:1296-1310`.
- The trust-control write path already forwards writes to a designated leader
  and only returns success once the write is visible there in
  `crates/arc-cli/src/trust_control.rs:11118-11220` and
  `crates/arc-cli/src/trust_control.rs:12693-12760`.

Those are useful foundations. They show ARC is not starting from zero.

The repo also openly records the current boundary:

- `docs/MONETARY_BUDGETS_GUIDE.md:68-78` documents the HA overrun bound rather
  than claiming strict distributed exclusion.
- `docs/release/RISK_REGISTER.md:8-13` admits cluster replication is still
  deterministic leader/follower and not consensus-based.

That honesty in the code and release notes is the right starting point for a
real remediation plan.

## Why Claims Overreach

### 1. Local atomicity is not distributed linearizability

The current monetary guide says budgets are enforced using an atomic
read-check-increment transaction and denied if they would exceed the lifetime
total in `docs/MONETARY_BUDGETS_GUIDE.md:3-4` and `:56-66`. That statement is
true only on one node.

In HA mode, the implementation still depends on per-node mutable SQLite state.
Once multiple writers exist without a consensus-backed commit path, the global
history is no longer linearizable.

### 2. LWW and `MAX(...)` are the wrong merge operators for money

Money is additive exposure, not last-writer state.

`upsert_usage` merges:

- `invocation_count` with seq preference or `MAX`
- `updated_at` with seq preference or `MAX`
- `total_cost_charged` with seq preference or `MAX`

in `crates/arc-store-sqlite/src/budget_store.rs:61-104`.

That can preserve a conservative upper bound for one row under some merge
orders, but it does not represent the true sum of independently authorized
spend across partitions. More importantly, it discards the individual
authorization decisions that created the exposure in the first place.

If ARC wants truthful exposure accounting, it must stop merging counters and
start committing immutable authorization events.

### 3. The current implementation tracks a collapsed scalar, not the budget state machine

Today one mutable row mixes at least four economically different concepts:

- invocation count
- provisional reserved amount
- realized captured amount
- post-execution reconciliation result

Those are not the same thing. A correct distributed system must distinguish:

- available budget
- open holds / authorizations
- captured / settled spend
- released / expired holds
- pre-allocated partition escrows

Without those states, ARC cannot tell an operator the truthful current
exposure, only a best-effort counter snapshot.

### 4. Pre-debit plus post-hoc self-report is not enough for strong spend claims

The kernel authorizes against `max_cost_per_invocation` before execution in
`crates/arc-kernel/src/lib.rs:2636-2660`, and tools may later return actual cost
through `invoke_with_cost` in `crates/arc-kernel/src/runtime.rs:219-236`. The
default implementation returns `None`, and the streaming path returns `None`
unconditionally in `crates/arc-kernel/src/lib.rs:3630-3655`.

If the tool later reports an overrun, ARC marks settlement failed after the
side effect in `crates/arc-kernel/src/lib.rs:3941-4028`.

That means the honest claim today is:

"ARC bounds provisional authorized exposure on the local budget store."

It is not:

"ARC proves actual realized spend cannot exceed the budget."

To make the stronger claim true, ARC needs supported metering profiles where
actual execution is cryptographically or operationally bound to the authorized
amount.

### 5. The current HA control plane is not a consensus budget authority

The trust-control service already has a remote budget path and quorum gating,
but the cluster algorithm chooses the lexicographically smallest reachable URL
as leader in `crates/arc-cli/src/trust_control.rs:12384-12416`. Writes are then
forwarded to that leader in `crates/arc-cli/src/trust_control.rs:12693-12760`.

That is better than unconstrained multi-writer replication, but it is still not
a replicated state machine with durable quorum commit, fencing, and a committed
log index. The repo itself says so in `docs/release/RISK_REGISTER.md:8-13`.

ARC cannot honestly market "atomic HA budget enforcement" until the budget
authority itself has linearizable commit semantics.

### 6. Truthful exposure accounting is impossible while the system underreports reserved partition capacity

Under the current model, a node can approve locally during split brain, and the
eventual merged row tells you some observed total after the fact. It does not
tell you the worst-case still-authorized exposure while a partition is active.

If ARC wants to remain available during partitions without overspending, it must
reserve budget explicitly to partitions or nodes ahead of time. That reserved
but not yet spent capacity must count against the global available balance.

### 7. Retry, replay, and stale-leader behavior are not modeled as budget-safety properties

The current API returns `allowed` plus a counter snapshot. It does not expose a
first-class immutable authorization decision id, hold id, budget version, or
fencing term. Without those, ARC cannot guarantee:

- retry idempotence
- no double authorization on ambiguous timeout
- no stale-leader commits after failover
- capture or release only against a previously authorized hold

Those are mandatory properties for a real distributed money-control plane.

## Target End-State

ARC should target three explicit deployment profiles and only make the strongest
claims for those profiles.

### Profile A: Strict Linearizable Budget Authority

This is the default profile for any claim that uses words like:

- atomic under HA
- no overspend under concurrency
- failover preserves budget invariants
- truthful exposure accounting

Semantics:

- every monetary authorization, capture, release, lease, and expiry is decided
  by one linearizable budget authority
- if the authority loses quorum, new monetary authorizations fail closed
- the authoritative state is an immutable event log plus derived aggregates
- no LWW or `MAX(...)` merge is used for authoritative money decisions

This profile trades partition availability for invariant strength. That is the
correct trade for strong claims.

### Profile B: Partition-Tolerant Escrow Budgets

This is the optional profile for deployments that require bounded monetary
availability during partitions.

Semantics:

- the linearizable authority pre-allocates signed, time-bounded budget leases
  to specific nodes or shards
- a node may authorize locally while partitioned only within its remaining
  lease balance
- unspent lease balance counts against global availability until explicit return
  or lease expiry
- the global hard cap still holds because the authority never allocates more
  lease balance than the available budget

This profile allows limited availability under partition without violating the
global budget invariant. The cost is reduced utilization efficiency: unused
lease balance remains reserved.

### Profile C: Standalone / Legacy Local SQLite

Keep this mode for:

- dev
- tests
- single-node deployments
- non-HA compatibility

Do not attach strong HA claims to it. Its honest description is:

"Single-node atomic budget enforcement with optional remote synchronization,
not a distributed spend-invariant system."

## Required Budget/Accounting Changes

### 1. Replace counter replication with an authoritative budget event log

Introduce a real monetary state machine. At minimum ARC needs:

- `BudgetAccount`
  - `budget_id`
  - `capability_id`
  - `grant_index`
  - `currency`
  - `hard_limit`
  - `profile` (`strict`, `escrow`, `standalone`)
  - `version`
- `BudgetEvent`
  - `event_id`
  - `budget_id`
  - `event_type`
  - `amount`
  - `request_id`
  - `hold_id`
  - `lease_id`
  - `node_id`
  - `term`
  - `commit_index`
  - `created_at`
- `BudgetHold`
  - `hold_id`
  - `reserved_amount`
  - `captured_amount`
  - `released_amount`
  - `expires_at`
  - `state`
- `BudgetLease`
  - `lease_id`
  - `node_id`
  - `allocated_amount`
  - `spent_amount`
  - `returned_amount`
  - `expires_at`
  - `state`

Authoritative balance becomes a derived view from events, not the source of
truth itself.

This is the core fix. Without immutable events, no amount of merge logic will
make the claims true.

### 2. Define the correct conserved quantity: authorized exposure

The conserved quantity is not just `total_cost_charged`. The conserved quantity
for safety is worst-case authorized exposure:

```text
authorized_exposure
  = captured_settled
  + open_hold_reserved
  + outstanding_lease_balance
```

Then define:

```text
available_headroom
  = hard_limit - authorized_exposure
```

This is the number that must never go negative.

Important consequence:

- unspent escrowed balance still reduces `available_headroom`
- released or expired holds restore `available_headroom`
- a node partition with a live lease does not create hidden exposure because the
  lease is already counted

Expose these quantities in APIs and receipts separately instead of collapsing
them into a single mutable counter.

### 3. Make HA monetary authorization linearizable

For `strict` and `escrow` profiles, replace the current lexicographic
leader/follower budget authority with one of:

- a Raft-backed ARC budget-authority service
- another consensus-backed replicated state machine with durable quorum commit
- a linearizable transactional substrate used through a strict ARC state machine

Minimum required properties:

- one leader at a time for writes
- durable quorum commit before success is returned
- monotonically increasing leader term / fencing epoch
- commit index attached to each decision
- no stale leader can commit after a higher term exists
- read paths used for authorization observe committed state

Practical implication for ARC:

- `--control-url` plus remote budget store becomes mandatory for any HA budget
  claim
- local `--budget-db` in multi-node deployments must be treated as unsupported
  for strong monetary guarantees

### 4. Add first-class hold / capture / release semantics

Stop treating a monetary authorization as a direct increment of lifetime spend.

ARC should perform:

1. `AuthorizeHold`
   - reserve `requested_amount`
   - returns `hold_id`, `budget_version`, `commit_index`, `expires_at`
2. tool executes only against that authorized hold
3. `CaptureHold`
   - converts part or all of the hold into captured spend
4. `ReleaseHold`
   - returns unused amount to availability
5. `ExpireHold`
   - authority-driven cleanup for abandoned or timed-out holds

Why this matters:

- retries become idempotent around `hold_id`
- partial capture becomes first-class
- truthful exposure accounting becomes possible
- payment authorization and budget authorization can align cleanly

### 5. Introduce idempotency keys and exactly-once decision semantics

Every monetary authorization attempt must carry an idempotency key, ideally the
tool `request_id` plus a caller-stable retry scope. The authority must persist:

- the idempotency key
- the resulting decision
- the associated `hold_id`
- the amount and term used

Repeated `AuthorizeHold` for the same key must return the same decision, not
consume more budget.

Similarly:

- `CaptureHold` must be idempotent on `(hold_id, capture_id)`
- `ReleaseHold` must be idempotent on `(hold_id, release_id)`
- `LeaseSpend` must be idempotent on `(lease_id, spend_id)`

This closes the classic distributed-systems hole where a timeout causes the
client to replay a request and double-charge the budget.

### 6. Add fencing and term-aware write tokens

All authority-side mutable operations must be fenced by the current consensus
term or lease epoch.

Required behavior:

- each successful write returns the current authority term and commit index
- followers and old leaders reject writes from a lower term
- escrow leases are signed with a lease epoch and cannot be extended or reused
  after supersession
- replayed captures or releases against an invalidated term fail closed

This prevents stale-leader authorizations from surviving failover.

### 7. Add escrow leases for partition-tolerant spending

If ARC wants any claim of bounded monetary availability during partitions, use
lease-based escrow.

Recommended protocol:

1. The linearizable authority allocates a lease of amount `L` to node `N`.
2. The lease reduces global `available_headroom` immediately.
3. Node `N` can authorize locally only while `lease_remaining >= requested`.
4. Each local authorization emits a signed `LeaseSpend` event.
5. When connected, the node reports `LeaseSpend` and optional `LeaseReturn`
   events back to the authority.
6. Unspent lease balance returns only on explicit return or expiry.

Invariant:

```text
captured_settled
+ open_holds
+ sum(outstanding_lease_remaining)
<= hard_limit
```

That invariant holds even if every partitioned node simultaneously spends its
entire remaining lease.

This is the correct way to get partition-tolerant availability without hidden
overspend.

### 8. Split authorization truth from settlement truth, but account for both honestly

ARC already distinguishes receipt truth from mutable reconciliation truth in the
protocol. The budget system should do the same for money, but with explicit
names and formulas.

Operator-visible accounting should report at least:

- `hard_limit`
- `captured_settled`
- `captured_unsettled`
- `open_hold_reserved`
- `outstanding_lease_remaining`
- `available_headroom`
- `worst_case_authorized_exposure`
- `realized_spend`
- `disputed_or_failed_capture_amount`

The system must never hide exposure by collapsing these into one field.

Strong claim boundary:

- ARC may claim a hard bound on `worst_case_authorized_exposure`
- ARC may only claim a hard bound on `realized_spend` for supported metering
  profiles

### 9. Add supported metering profiles and reject unsupported ones from strong claims

ARC cannot make universal "actual spend cannot exceed budget" claims while tool
pricing remains advisory in `docs/TOOL_PRICING_GUIDE.md:3-18`, streaming tools
return no actual cost in `crates/arc-kernel/src/lib.rs:3642-3647`, and tools may
self-report cost after execution.

Define explicit metering profiles:

- `ExactQuoted`
  - exact price known before execution
  - hold equals final charge
- `ReserveAndCapture`
  - authority reserves a maximum amount
  - tool or payment rail may capture only up to reserved amount
- `RailBound`
  - external payment processor enforces the hold and capture bounds
- `AdvisoryOnly`
  - tool self-reports cost after the fact

Claim policy:

- only `ExactQuoted`, `ReserveAndCapture`, and `RailBound` support the strongest
  spend-bounding claims
- `AdvisoryOnly` supports only bounded provisional exposure claims

### 10. Bind kernel execution to hold semantics

Refactor the kernel money path from "check and increment budget" to
"authorize hold, execute against hold, finalize hold."

Required changes:

- replace `check_and_increment_budget` with `authorize_budget_hold`
- carry `hold_id` through the execution path
- include `hold_id`, `hold_amount`, `capture_amount`, and `budget_commit_index`
  in financial receipt metadata
- require nested/delegated monetary calls to reference parent hold lineage when
  applicable
- prevent execution if hold acquisition fails or expires

The current `BudgetChargeResult` is too small for a real distributed money
protocol.

### 11. Make budget APIs and receipts explicit about profile and guarantee level

Every budget response and receipt should include:

- `budget_profile`
- `metering_profile`
- `guarantee_level`
- `budget_term`
- `budget_commit_index`

Examples:

- `guarantee_level = "single_node_atomic"`
- `guarantee_level = "ha_linearizable"`
- `guarantee_level = "partition_escrowed"`
- `guarantee_level = "advisory_posthoc"`

That lets docs and downstream systems state exactly what was guaranteed on each
decision.

### 12. Narrow or remove the current counter-based replication path from release claims

After the new system exists:

- keep the current SQLite counter store only for `standalone`
- remove the HA overrun-bound story from strong-product docs
- document the old path as a compatibility backend, not the basis for monetary
  correctness claims

This is as important as the engineering. Otherwise the repo will continue to
mix incompatible trust models.

## Proof/Test Plan

### 1. Write a formal distributed budget spec

Use a model checker designed for concurrent protocols, not just unit tests.

Recommended artifacts:

- TLA+ or PlusCal model for `strict` budget holds
- TLA+ or PlusCal model for `escrow` leases
- state-machine model for:
  - `AuthorizeHold`
  - `CaptureHold`
  - `ReleaseHold`
  - `ExpireHold`
  - `GrantLease`
  - `SpendLease`
  - `ReturnLease`
  - leader failover
  - duplicate delivery
  - partition and heal

Core invariants:

- `authorized_exposure <= hard_limit`
- no two successful distinct holds with the same idempotency key
- no capture exceeds the reserved hold amount
- no lease spend exceeds the lease remaining amount
- no stale-term write changes authoritative state
- available headroom is derived exactly from event state

### 2. Add linearizability tests for the authority API

For the HA authority, run a history checker such as Porcupine-style
linearizability validation on:

- `AuthorizeHold`
- `CaptureHold`
- `ReleaseHold`
- `GrantLease`
- `ReturnLease`

Scenarios:

- concurrent identical requests
- concurrent disjoint requests against tight budgets
- failover during request processing
- duplicate responses
- lost ACK after commit
- retry after timeout

ARC should not claim HA atomicity without passing these histories.

### 3. Add adversarial partition tests

The current tests prove minority write denial for one trust-control path in
`crates/arc-cli/tests/trust_cluster.rs:1296-1310`. Expand this into a real
fault-injection lane:

- stale leader isolated after issuing but before commit acknowledgment
- split network with concurrent retries to old and new leaders
- partitioned escrow node spending to lease exhaustion
- heal with duplicate `LeaseSpend` reports
- restart during replay of captured holds
- clock skew around hold and lease expiry

Success criteria:

- no overspend
- no hidden authorized exposure
- no double capture
- deterministic recovery to the same derived balances

### 4. Add budget-state property tests

At the pure state-machine layer, use property-based tests to generate long
operation traces with:

- partial captures
- zero-cost captures
- release before capture
- duplicate capture
- duplicate release
- lease return after expiry
- overlapping holds near the hard limit

Validate both exact balances and invariants after every step.

### 5. Add metering-profile qualification lanes

Qualification must differentiate:

- exact-priced native tools
- reserve-and-capture tools
- streaming tools
- advisory-only tools

Strong spend claims should be gated on passing the supported profiles only.

### 6. Gate docs and release claims on qualification artifacts

Before any README or protocol text says "atomic under HA" or equivalent, require:

- passing HA linearizability lane
- passing partition/escrow lane if that profile is claimed
- proof artifact checked in and linked from the release audit
- doc snippets generated from capability flags rather than hand-written prose

## Milestones

### Milestone 0: Claim Hygiene

- Rewrite budget docs to distinguish:
  - single-node atomic
  - HA linearizable
  - partition-escrowed
  - advisory post-hoc
- Remove or narrow any claim that implies the current SQLite replication path is
  globally atomic.

This should ship immediately, before code changes.

### Milestone 1: Event-Sourced Single-Authority Budget Core

- Add immutable `BudgetEvent`, `BudgetHold`, and derived-balance model
- Refactor kernel to `AuthorizeHold -> Capture/Release`
- Add idempotency keys
- Preserve current single-node behavior on one authority instance

Goal:

- truthful local exposure accounting
- no counter-only budget logic left on the monetary path

### Milestone 2: HA Linearizable Budget Authority

- Replace lexicographic leader selection for the monetary path with consensus
- Add term fencing and commit index
- Make remote budget store mandatory for HA monetary guarantees
- Add linearizability and failover tests

Goal:

- truthful "atomic under HA" claim for `strict` profile

### Milestone 3: Escrow Lease Protocol

- Add `GrantLease`, `SpendLease`, `ReturnLease`, and lease expiry
- Implement signed lease objects for partitioned nodes
- Add authoritative accounting for outstanding lease balance
- Add partition fault-injection tests

Goal:

- truthful bounded-availability claim under partition without overspend

### Milestone 4: Metering and Settlement Binding

- Implement metering profiles
- Bind reserve-and-capture to payment adapters where supported
- Disallow strong spend claims for unsupported advisory-only tools
- Expose realized vs reserved vs escrowed amounts separately

Goal:

- truthful actual-spend claims for supported tool/payment classes

### Milestone 5: Release Qualification and Spec Lock

- Publish formal spec and qualification artifacts
- Lock receipt/API fields for guarantee level and commit metadata
- Update README, protocol spec, and guides to use the new claim vocabulary

Goal:

- no unsupported money claim remains in public-facing docs

## Acceptance Criteria

ARC can honestly claim distributed monetary budget enforcement only when all of
the following are true.

### Strict HA profile

- Every successful monetary authorization is committed by a linearizable
  authority before success is returned.
- For every history of concurrent requests, retries, failovers, and partitions,
  `authorized_exposure <= hard_limit` always holds.
- Duplicate requests with the same idempotency key never consume extra budget.
- Stale leaders cannot mutate budget state after failover.
- Receipt and admin APIs expose:
  - captured spend
  - open reserved holds
  - outstanding lease reserves
  - available headroom
  - authority term / commit index
- No README, guide, or spec text attributes HA atomicity to standalone SQLite
  replication.

### Escrow profile

- The authority never grants total live lease balance above available headroom.
- A partitioned node can authorize locally only within a valid lease.
- Across all nodes and partitions,
  `captured + open_holds + outstanding_lease_remaining <= hard_limit`.
- Lease expiry or return deterministically restores headroom.
- Duplicate or delayed `LeaseSpend` reports do not double-count exposure.

### Metering truthfulness

- Strong actual-spend claims are limited to supported metering profiles.
- Advisory-only tools are explicitly labeled as provisional or post-hoc.
- Streaming monetary flows are either upgraded to a supported profile or
  excluded from strong spend-bounding claims.

## Risks/Non-Goals

- ARC cannot simultaneously guarantee zero overspend and unrestricted write
  availability under arbitrary partitions. The choices are:
  - fail closed without quorum
  - or pre-allocate bounded escrow
- This memo does not solve universal trust in tool-reported costs. It defines
  where ARC can make strong claims and where it cannot.
- Cross-currency exposure, FX oracle design, and accounting-policy questions are
  separate from the core distributed budget invariant.
- This memo does not argue for removing local SQLite. It argues for confining
  SQLite to honest deployment profiles.
- This memo does not make ARC a bank, PSP, or regulated ledger by itself. It
  makes ARC's authorization and exposure claims technically defensible.

## Recommended Claim Language After Remediation

Once Milestones 1-5 ship, ARC can say something like:

> In `ha_linearizable` mode, ARC enforces monetary holds and captures through a
> consensus-backed budget authority. Under concurrent requests, retries,
> failover, and network partitions, total authorized exposure cannot exceed the
> configured budget limit. In `partition_escrowed` mode, ARC can continue to
> authorize during partitions only within pre-reserved budget leases, while
> preserving the same global hard cap.

Until then, the repo should say the narrower truth:

> ARC currently provides single-node atomic budget enforcement and a bounded
> split-brain overrun model for the legacy replicated SQLite path. Strong HA
> spend-invariant claims remain future work.

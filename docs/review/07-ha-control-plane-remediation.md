# Hole 07 Remediation Memo: HA Control Plane and Authority Key Management

## Problem

ARC currently describes its trust-control service as an HA clustered control
plane for capability issuance, revocation, receipt ingestion, and budget
accounting. The implementation does not yet justify strong distributed-trust
claims.

Today the cluster behaves like a single-writer service with:

- deterministic leader selection by lexicographic URL order
- best-effort leader forwarding
- local durability on the chosen leader
- background anti-entropy repair
- service-token-protected internal replication endpoints
- authority snapshot replication that includes the private signing seed

That is a useful failover-oriented operational mode. It is not a
consensus-backed replicated control plane with linearizable commit semantics,
safe failover, stale-leader fencing, or defensible authority-key custody.

The authority-key issue is the most serious part of the gap. If the control
plane claims to be the trust root for issuance and verification, then
replicating `seed_hex` across peers under a shared bearer token collapses the
trust model. A node compromise becomes a CA compromise.

## Current Evidence

The repo already exposes the current architecture clearly.

- `README.md` says `arc trust serve` "supports HA clustering with deterministic
  leader election and background repair-sync."
- `docs/research/03-gap-analysis.md` says the current HA model is
  "deterministic leader plus repair-sync rather than consensus."
- `docs/release/RISK_REGISTER.md` explicitly says consensus-based replication is
  out of scope for the current release.
- `crates/arc-cli/src/trust_control.rs` implements
  `compute_cluster_consensus_locked`, which chooses the lexicographically
  smallest reachable URL as leader once a reachability quorum exists.
- `forward_post_to_leader` forwards writes to that leader and returns success
  after the write is visible on the leader. The response surface includes
  `visibleAtLeader=true`.
- `run_cluster_sync_loop` performs periodic background synchronization by
  pulling snapshots and deltas from peers.
- `AuthoritySnapshotView` contains `seed_hex`, and
  `handle_internal_authority_snapshot` returns that snapshot over an internal
  endpoint guarded by the cluster `service_token`.
- `apply_cluster_snapshot` applies authority, revocation, receipt, lineage, and
  budget snapshots into local stores after the fact.
- The gap analysis and tests show useful failover and convergence behavior for
  supported scenarios, but they do not establish linearizable replication or
  stale-leader safety under adversarial partitions.

This is enough to support a modest claim:

> ARC has a failover-friendly replicated operational control service with
> eventual repair.

It is not enough to support a stronger claim:

> ARC has a distributed trust-control plane with HA safety properties comparable
> to a consensus-backed authority service.

## Why Claims Overreach

### 1. Leader election is not consensus

`compute_cluster_consensus_locked` does not run a voting protocol. It counts
reachable peers, sorts URLs, and chooses the first one. There is no persistent
term voting, no replicated log, no lease proof, no leader completeness
guarantee, and no commit index. Reachability quorum is being used as if it were
state-machine quorum. Those are not the same thing.

### 2. Acknowledged writes are leader-local, not quorum-committed

`forward_post_to_leader` and `respond_after_leader_visible_write` acknowledge
success when the state is visible on the current leader. That means a client can
observe success for a mutation that has not been durably replicated to a quorum.
If the leader fails before repair-sync, the cluster can elect a different
leader that does not contain the acknowledged write.

That is the opposite of the property needed for strong HA claims:

- no acknowledged write is lost after failover
- every acknowledged write is part of the committed prefix

### 3. Repair-sync is anti-entropy, not commit

`run_cluster_sync_loop` periodically pulls snapshots and deltas from peers.
That is a standard repair mechanism. It is not a substitute for ordered
replicated commit. It cannot provide:

- linearizable writes
- linearizable reads
- leader completeness
- exactly-once mutation semantics
- stale-leader exclusion

### 4. There is no fencing story for stale leaders

Strong HA claims require a stale leader to lose the power to mutate trust state
or sign authority-bearing artifacts once it is no longer current.

The current design does not provide a fencing token or lease-bound external
authority. A previously healthy leader that becomes partitioned can continue to
operate on its local state until another part of the system notices otherwise.
If a design has any external side effect surface, "best effort redirect to the
new leader" is not enough.

### 5. The authority private key is being replicated as cluster state

`AuthoritySnapshotView` includes `seed_hex`. `handle_internal_authority_snapshot`
serves it to peers protected only by the shared `service_token`, and
`apply_cluster_snapshot` applies it into the peer's local authority store.

That means the trust root is not a protected signing service. It is a shared
secret copied around the cluster. Compromise one node, one peer channel, or one
service token, and the authority root is gone.

### 6. Shared bearer service auth is too weak for cluster root operations

The internal cluster RPCs are authenticated by `validate_service_auth`, which
checks a shared bearer token. That is not enough for operations that carry:

- authority snapshots
- revocation deltas
- budget state
- receipt history
- cluster partition controls

Strong distributed-trust claims require authenticated node identity, scoped peer
authorization, transport integrity, and auditability stronger than a flat
shared bearer token.

### 7. Failover correctness is underspecified for externalized trust decisions

The control plane drives issuance, revocation, budgets, and eventually stronger
economic and identity surfaces. For those domains, failover correctness is not
just "the next request still works." It requires:

- monotonic authority generations
- monotonic revocation visibility under the chosen consistency model
- monotonic budget accounting
- no rollback of acknowledged trust decisions
- no double-issuance from split-brain leaders

The current cluster design does not enforce those invariants.

## Target End-State

The target end-state is a real replicated trust-control service with explicit
safety boundaries.

### Safety properties ARC must be able to claim

ARC should only revive strong HA/distributed-trust language once the control
plane can honestly claim all of the following:

- every acknowledged control-plane write is durably committed on a quorum before
  the client sees success
- leader election is based on a real consensus protocol, not URL ordering
- stale leaders are fenced and cannot continue mutating or signing after losing
  authority
- failover preserves the committed prefix and never loses acknowledged writes
- reads can be requested as linearizable or explicitly stale
- cluster membership changes are coordinated and safe
- the authority private key is never replicated in plaintext as online cluster
  state
- compromise of a single node is not automatically compromise of the authority
  root

### Architectural end-state

The clean architecture is:

- one replicated state machine for trust-control metadata
- one consensus-backed ordering surface for all trust mutations
- one fenced active signing authority or threshold-signing quorum
- one authenticated internal transport using node identity, not a shared bearer
- one explicit distinction between committed state, follower-observed state, and
  offline backup material

The strongest honest claim after this work would be:

> ARC provides a consensus-backed trust-control cluster with quorum-committed
> control-plane mutations, fenced failover, linearizable authority state, and
> non-exportable or threshold-protected authority signing custody.

## Required Distributed-Systems Changes

### 1. Replace deterministic leader selection with a real consensus protocol

ARC needs a replicated log protocol. The most natural fit is Raft because the
current architecture is already leader-oriented.

Required properties:

- persistent `term`, `voted_for`, and replicated log
- randomized election timeout
- quorum-based leader election
- leader completeness
- durable write-ahead logging before commit acknowledgement
- joint-consensus or equivalent safe membership change protocol

Do not hand-roll a "lighter" election variant. If the system is going to make
authority and budget claims, it needs real state-machine replication.

### 2. Introduce a first-class command log for all trust mutations

Every mutating operation must become a replicated command with:

- `command_id`
- `term`
- `log_index`
- command payload
- client or request idempotency key
- optional causal references

At minimum, the replicated command set should include:

- authority rotation and activation
- capability issuance
- revocation writes
- budget increments, charges, reversals, and reductions
- receipt append metadata
- lineage writes
- cluster membership changes

Current snapshot-plus-delta repair can remain as an optimization for catch-up,
but only for committed state machine snapshots.

### 3. Change write acknowledgement semantics

Delete the idea that `visibleAtLeader=true` is a meaningful distributed commit
signal.

Write success must mean:

- the command was appended to the leader log
- replicated to a quorum
- committed in the consensus sense
- durably applied to the state machine

The response should expose something like:

- `leaderTerm`
- `commitIndex`
- `appliedIndex`
- `consistency: "quorum_committed"`

That gives clients and operators a real handle on safety.

### 4. Add linearizable-read and stale-read modes

Trust-control reads need explicit consistency semantics.

Required modes:

- `linearizable`: leader or read-index backed, reflects the committed prefix
- `follower_stale_ok`: may serve a lagging but authenticated follower snapshot

The default for issuance, revocation checks, budget state, and authority status
should be linearizable. Anything weaker must be opt-in and visibly marked.

### 5. Add exactly-once and replay-safe mutation handling

Consensus does not by itself eliminate duplicate client submission. The control
plane needs an idempotency layer keyed by durable request ids.

Requirements:

- every external mutating RPC carries an idempotency key
- the replicated state machine records completion for those keys
- retry after timeout returns the original committed result
- budget mutations are not double-applied on retry
- authority rotations and revocations cannot be replayed into multiple effects

### 6. Introduce fencing for every externalized side effect

Consensus only solves internal ordering. ARC also needs stale-leader exclusion
for external side effects.

Required fencing model:

- every leader term owns a fencing token or lease epoch
- every side-effecting subsystem validates that token
- once a node loses leadership or quorum, its token becomes unusable
- any attempt by a stale leader to issue, rotate, or sign fails closed

This applies to:

- authority signing
- any external KMS signer session
- any mutable backing store that can accept writes outside the consensus path
- any future settlement or identity-issuance side effect

### 7. Move all replication traffic to mutually authenticated node identity

The cluster must stop treating peers as "whoever knows the bearer token."

Required changes:

- mTLS between trust-control nodes
- cluster node certificates or SPIFFE-like identities
- per-node authorization policy
- cluster-membership allowlist anchored in replicated config
- rotation of peer credentials independent of operator service tokens

The service token can remain for CLI-to-service admin paths if needed, but not
as the sole root for cluster-internal replication and snapshot exchange.

### 8. Split snapshots into committed state snapshots and disaster-recovery material

A committed-state snapshot should contain only replicated public or operational
state needed to reconstruct the state machine:

- authority public metadata
- trusted-key history
- revocations
- receipts
- lineage
- budgets
- cluster config

It must not contain the live private signing seed.

Disaster recovery of private authority material is a different problem and must
be handled separately from peer replication.

### 9. Clarify the consistency model for budgets

Monetary and invocation budgets are safety-critical. Once the control plane is
consensus-backed, budget mutations must be linearizable state-machine updates.

Required result:

- no split-brain overspend from concurrent leaders
- one total order of charges and reversals
- retry-safe accounting
- budget read state tied to a committed index

If ARC later wants budget reservations or escrow semantics, that should be
built on top of this replicated state machine, not beside it.

### 10. Consider whether receipts belong in the same replicated log

For strong system claims, trust-control metadata and receipt ordering should not
silently diverge.

There are two acceptable models:

- one unified consensus log for trust mutations and receipt metadata
- one consensus log for trust mutations plus a separate explicitly weaker audit
  log with clearly narrowed claims

If ARC keeps receipts weaker than the trust-control log, the docs must say so.

## Key-Management Plan

### Principle

The authority private key is not ordinary replicated state. It is signing
custody. It must not be replicated the same way revocations or receipts are
replicated.

### What must stop immediately

The following pattern cannot survive into the strong-claim architecture:

- encode the full private seed as `seed_hex`
- expose it in cluster snapshots
- protect it with a shared bearer token
- copy it into peer-local authority stores

That is not HA key management. It is online secret duplication.

### Recommended near-term target: fenced external signer

The fastest path to a defensible HA story is:

- keep one logical authority key
- store it in a non-exportable KMS or HSM-backed signer
- let only the current consensus leader obtain a short-lived signing lease
- bind every signing request to the current `term` and fencing epoch
- fail closed if the leader loses quorum or lease refresh

Benefits:

- peers never receive the raw seed
- failover does not require copying the secret
- stale leaders can be fenced at the signer boundary
- the custody story becomes auditable

Requirements:

- a signer adapter interface in ARC
- support for term-bound signing sessions or an equivalent external lease
- audit records for sign operations
- public-key and key-version metadata replicated through consensus

### Stronger long-term target: threshold signing

If ARC wants the strongest possible distributed-trust story, it should move to
threshold signing rather than a single active signer.

That means:

- no node ever reconstructs the full private key
- signing requires quorum participation
- compromise of one node is insufficient to sign
- failover is inherent in the threshold design

For Ed25519, this likely means a threshold protocol such as FROST or a move to
a signer backend that offers equivalent threshold support.

This is a significantly larger project. It should be treated as a second-phase
upgrade after consensus-backed state replication exists.

### Can private seeds ever be replicated safely?

Not in the sense currently implied by the code.

The defensible answer is:

- raw online replication of a full private seed to peers is not acceptable for
  strong trust-root claims
- encrypted offline backup is acceptable if wrapped under split control and not
  automatically used as peer-replication state
- online threshold shares may be acceptable if each share is independently
  protected and no single node compromise reveals the full key
- HSM- or KMS-managed non-exportable custody is acceptable if the failover
  mechanism is fenced and auditable

So the rule should be:

> Never replicate a live full authority seed as ordinary cluster state.

### Rotation plan

Authority rotation must become a consensus-governed lifecycle:

- propose new key version
- commit rotation intent in the replicated log
- provision signer or threshold shares
- activate at a committed index and effective timestamp
- retain old public verification metadata for historical artifact validation
- retire signing access only after all nodes observe the committed activation

Verification material should include:

- authority key id
- activation index
- activation time
- retirement index or time
- signer backend metadata

### Recovery plan

Disaster recovery must be separate from peer replication.

Recommended recovery options:

- HSM/KMS native backup and restore
- offline wrapped backup with dual control
- secret sharing for emergency recovery

None of these should travel over routine cluster snapshot APIs.

## Validation Plan

### 1. Model the protocol before coding it

ARC should produce a small formal or model-checked spec for the control plane.
TLA+ is a good fit here.

Model:

- elections
- log replication
- leader failover
- fencing
- authority rotation activation
- budget charge idempotency

Properties:

- no two leaders commit conflicting entries for the same log position
- committed prefix is preserved across failover
- stale leaders cannot continue signing after losing lease
- acknowledged writes are never lost
- budget state remains linearizable

### 2. Add linearizability testing

Use a history checker such as Porcupine or Knossos on trust-control APIs.

Target surfaces:

- issue capability
- revoke capability
- budget charge/reverse/reduce
- authority rotate
- receipt append metadata if it remains in the strong path

Every test run should generate concurrent histories under crash and partition
faults and verify that observed behavior is linearizable with respect to the
specified state machine.

### 3. Build Jepsen-style chaos tests

ARC needs adversarial distributed testing, not only happy-path failover tests.

Required fault cases:

- leader crash after local append but before quorum commit
- leader crash after quorum commit but before client ack
- network partition that isolates the old leader with a minority
- network partition that creates competing reachability views
- slow follower, delayed snapshot install, and out-of-order delta delivery
- restart with stale local disk state
- duplicate client retries and timeout-driven replay
- clock skew and lease-expiry edge cases

Assertions:

- no acknowledged mutation disappears
- no stale leader mutation is accepted
- no split-brain double issuance
- no budget overrun beyond the sequential specification

### 4. Pen-test the key-custody path

Security validation should assume a node compromise.

Required checks:

- compromising one trust-control node does not reveal the authority root
- stealing one peer credential does not enable full-cluster authority extraction
- stale leaders cannot keep signing with a cached signer session
- authority rotation cannot be bypassed or rolled back

### 5. Validate backup and recovery procedures

Run operator drills for:

- total leader loss
- quorum loss and recovery
- signer outage
- key rotation rollback
- disaster recovery from offline material

These need documented RTO and RPO expectations.

### 6. Gate claims on validation artifacts

Strong HA claims should be release-gated on:

- passing chaos suite
- passing linearizability suite
- completed key-custody review
- updated threat model
- published consistency model in the spec

## Milestones

### Milestone 0: Claim correction and mode split

Before any deep implementation work:

- rename the current cluster mode to something like `repair-sync HA` or
  `failover replication`
- remove strong distributed-trust wording from public docs
- explicitly say the current mode is not consensus-backed
- document that authority seed replication is transitional and not a final
  custody architecture

This is not the end-state, but it prevents further claim debt.

### Milestone 1: Consensus core

Build or integrate a Raft-based replicated log for trust-control mutations.

Deliverables:

- durable WAL
- quorum election
- command log
- membership model
- leader redirects with term metadata
- committed write acknowledgement semantics

### Milestone 2: Linearizable trust state

Move authority metadata, revocations, budgets, and lineage onto the replicated
state machine.

Deliverables:

- linearizable reads
- idempotent write handling
- removal of `visibleAtLeader` semantics
- committed snapshots
- follower catch-up from committed snapshots only

### Milestone 3: Fencing and failover correctness

Introduce leader lease and fencing semantics.

Deliverables:

- stale-leader step-down behavior
- side-effect fencing tokens
- explicit write rejection on lost quorum
- failover tests for crash, restart, and partition

### Milestone 4: Authority custody overhaul

Remove seed replication and integrate a real signing-custody design.

Preferred first delivery:

- external signer interface
- non-exportable KMS/HSM-backed authority key
- term-bound signing lease
- rotation flow committed through consensus

Future delivery:

- threshold-signing design and prototype

### Milestone 5: Validation and qualification

Deliverables:

- TLA+ or equivalent protocol model
- linearizability checker in CI
- chaos harness in CI or gated nightly runs
- security review of key custody
- updated operator runbooks and public claims

## Acceptance Criteria

ARC can truthfully claim a strong HA/distributed-trust control plane only when
all of the following are true.

- Acknowledged writes are quorum-committed, not merely leader-visible.
- No acknowledged mutation is lost across crash, restart, or failover tests.
- Leader election is consensus-backed and does not depend on URL ordering.
- Reads used for authority, revocation, and budget enforcement are linearizable
  by default.
- Stale leaders are fenced and cannot continue mutating or signing after losing
  leadership.
- The cluster no longer exposes or replicates raw authority `seed_hex` over
  peer APIs.
- Compromise of a single node does not reveal the live authority root and does
  not by itself permit arbitrary authority signing.
- Authority rotation is monotonic, committed, and preserved across failover.
- Budget accounting is linearizable and no longer admits split-brain overspend
  under the strong HA mode.
- Internal cluster communication uses authenticated node identity and encrypted
  transport, not only a shared bearer token.
- The consistency model is documented in the spec and enforced in the APIs.
- Chaos, linearizability, and custody tests pass continuously.

## Risks / Non-Goals

### Risks

- Consensus will reduce write availability during quorum loss. That is the
  correct tradeoff for a trust root.
- Throughput and latency will worsen relative to leader-local writes.
- External signer integration adds operational complexity and a new dependency.
- Threshold signing is materially harder than ordinary KMS integration.
- The migration from current stores to a replicated log will be invasive.

### Non-goals

- Byzantine fault tolerance is not required for the first strong HA version.
  Crash fault tolerance plus authenticated transport is enough.
- Multi-region active-active without consensus is not a goal. If ARC wants
  multi-region trust claims, it must preserve the same consensus and fencing
  invariants across regions.
- Routine peer replication of full private keys is not a goal and should never
  return as an optimization.
- Availability during total quorum loss is not a goal. Safety must win.
- This memo does not require receipts to become a full public transparency log.
  That is Hole 5. It only requires that whatever receipt semantics remain in the
  trust-control plane be honestly aligned with the replicated consistency model.

## Bottom Line

To make the HA/distributed-trust claims true, ARC has to stop treating
reachability, leader-local durability, background repair, and copied private
seeds as if they added up to a consensus-backed authority service.

They do not.

The repair path is conceptually clean:

- consensus for state
- fencing for failover
- linearizable semantics for trust decisions
- non-exportable or threshold-protected custody for authority signing

Until those exist, ARC should describe the current trust-control cluster as a
repair-sync operational HA mode, not a strong distributed trust root.

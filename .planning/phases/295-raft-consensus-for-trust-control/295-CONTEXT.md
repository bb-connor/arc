# Phase 295 Context

## Goal

Upgrade the existing clustered trust-control lane into a bounded consensus
surface that can run as a 3-node cluster with leader election, majority-gated
writes, partition healing, and snapshot-based catch-up.

## Constraints

- The current shipped cluster implementation already exposes clustered
  trust-control behavior from `crates/arc-cli/src/trust_control.rs`; phase 295
  must harden that surface rather than invent a second trust-control runtime.
- Trust-control state still lives in SQLite stores (`authority`, `receipts`,
  `revocations`, `budgets`, and capability lineage), so the consensus work must
  preserve those stores and use their existing replication-friendly sequence
  metadata.
- The phase must stay bounded to the real operator surface: `arc trust serve`
  and the existing trust-cluster integration lane in
  `crates/arc-cli/tests/trust_cluster.rs`.

## Findings

- The current cluster is not Raft. Leadership is derived by choosing the
  lexicographically smallest healthy URL, and background peer sync replays
  deltas from SQLite-backed stores.
- Current coverage already proves useful HA behavior:
  - follower writes forward to a leader
  - authority, receipt, lineage, revocation, and budget state replicate
  - a 2-node cluster survives leader loss
- The current implementation does not express majority quorum, partition
  healing, snapshot transfer for a new node, or any compaction boundary for the
  replication replay path.
- The store layer already exposes the primitives needed for bounded catch-up:
  - authority snapshots
  - monotonic receipt/budget/lineage sequences
  - full list/read APIs for revocations and budgets

## Implementation Direction

- Extend the existing cluster runtime with explicit consensus metadata:
  quorum size, leader role, and write-admission rules that fail closed when a
  node cannot establish a majority-backed leader.
- Add snapshot-based catch-up for joining or far-behind peers so replication can
  compact to the latest materialized state instead of depending on replay from
  the beginning of history.
- Add internal operator/test controls to simulate a one-node partition and prove
  that the majority side continues, the isolated node stops accepting writes,
  and the healed node converges back to the elected leader's state.
- Prove the bounded consensus contract with a new 3-node integration lane that
  covers leader election, partition healing, log compaction through snapshots,
  and new-node snapshot transfer.

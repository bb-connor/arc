# Phase 298 Context

## Goal

Qualify the clustered trust-control runtime as a bounded 3-region deployment by
proving consistency during partition/heal scenarios and documenting measured
replication lag percentiles.

## Constraints

- Phase 295 already implemented the clustered runtime behavior: majority-backed
  writes, minority fail-closed behavior, snapshot catch-up, and compaction.
  Phase 298 must build on that runtime instead of introducing a second
  replication mechanism.
- The repo does not contain real cloud-region deployment infrastructure or a
  managed WAN testbed. This phase therefore needs an honest simulated
  3-region qualification lane over the existing 3-node trust-control cluster.
- The roadmap requirement is about qualification evidence, not new business
  functionality. The output should be proving coverage plus an artifact that
  records measured lag numbers and the exact scenario exercised.
- The phase must not overclaim. Any measured p50/p95/p99 values need to be
  clearly labeled as local/simulated-region qualification numbers, not hosted
  cross-region production latencies.

## Findings

- `crates/arc-cli/tests/trust_cluster.rs` already has the core 3-node proving
  seams needed for this phase:
  - leader convergence across three nodes
  - majority/minority partition behavior
  - healed minority catch-up via snapshot
  - late-join snapshot transfer and compaction
- `trust_control.rs` already exposes the observability surfaces needed to
  measure lag without changing the runtime contract:
  - `/v1/internal/cluster/status`
  - per-node replication heads
  - per-peer snapshot application counts and timestamps
  - deterministic leader-forwarded write metadata on mutating responses
- There is no existing artifact that records percentile latency numbers for
  partition-heal replication. That is the main missing deliverable for
  `DIST-07` and `DIST-08`.

## Implementation Direction

- Reuse the existing trust-cluster harness to run a named simulated 3-region
  lane (`region-a`, `region-b`, `region-c`) over three local trust-control
  nodes.
- Add one qualification test that:
  - proves no split-brain decisions during an induced minority partition
  - performs repeated partition/heal cycles
  - measures post-heal replication visibility latency to the isolated node
  - optionally records steady-state all-node replication latency for context
- Compute p50, p95, and p99 latency summaries from the collected samples and
  persist them as a machine-readable qualification artifact under `target/`.
- Write a phase report summarizing the qualification scenario, the measured
  latency numbers, and the fact that the results come from a local simulated
  3-region cluster rather than external cloud regions.

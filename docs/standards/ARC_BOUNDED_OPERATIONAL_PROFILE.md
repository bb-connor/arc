# ARC Bounded Operational Profile

**Profile ID:** `arc-bounded-release-profile-v1`  
**Version:** `2026-04-15`  
**Status:** current bounded ARC ship profile

This profile defines the strongest honest operational contract for the current
bounded ARC release. Anything stronger stays out of the ship-facing claim.

## Guarantee Classes

| Surface | Guarantee class | Shipped truth | Explicit non-claim |
| --- | --- | --- | --- |
| Governed `call_chain` | `compatibility-only` | preserved caller context inside approval-bound intent | no authenticated recursive upstream provenance |
| Authorization-context / reviewer-pack | `informational-only` | derived projection over signed receipt metadata | does not upgrade asserted call-chain fields into verified upstream truth |
| Trust-control writes | `leader-local` | deterministic leader selection, single-writer local truth, eventual repair | no consensus, quorum commit, or stale-leader fencing claim |
| Trust-control reads | `leader-local` | bounded clustered visibility over local SQLite-backed state | no globally linearizable control-plane view |
| Monetary budgets | `local-only` | single-node atomic budget enforcement on one SQLite store | no distributed-linearizable budget truth |
| Clustered monetary budgets | `leader-local` | bounded provisional authorized exposure with documented overrun bound | no actual realized-spend `<=` budget guarantee under split brain |
| Receipt and checkpoint plane | `local-only` | signed local audit evidence, local durable storage, checkpoint export, inclusion proofs | no public transparency-log or strong non-repudiation semantics |
| Discovery / certify transparency | `informational-only` | signed snapshot/feed visibility metadata for review | no automatic trust activation or transparency-log semantics |
| Hosted auth with `cnf` and dedicated sessions | `local-only` | bounded request-time authorization and protected-resource admission | no cross-node auth-code failover or restart-safe replay guarantee |
| Static bearer / non-`cnf` / `shared_hosted_owner` | `compatibility-only` | supported interoperability and migration path | not part of the recommended bounded security profile |

## Recommended Bounded Hosted/Auth Profile

- dedicated-per-session hosting
- explicit sender-constrained access tokens with `cnf`
- explicit `resource` binding
- request-time `authorization_details` plus `arc_transaction_context`
- stable subject derivation only when `--identity-federation-seed-file` is
  configured

## Bounded Receipt And Provenance Semantics

- signed receipts and checkpoints are the authoritative ARC evidence layer
- authorization-context and reviewer-pack exports are derived views over signed
  receipt metadata
- delegated `call_chain` fields remain asserted caller context unless another
  system independently verifies them

## Non-Claims

This profile explicitly excludes:

- consensus-grade HA
- distributed-linearizable budget enforcement
- authenticated recursive delegation ancestry beyond the preserved presented
  chain
- public transparency-log semantics
- theorem-prover completion for every protocol claim

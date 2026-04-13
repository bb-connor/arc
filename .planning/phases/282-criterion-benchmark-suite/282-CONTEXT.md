# Phase 282 Context

## Goal

Create the first Criterion benchmark suite for the release-critical primitives
already concentrated in `arc-core`.

## Existing Surface

- there is no `benches/` directory in the repo today
- `arc-core` owns all four benchmark targets the roadmap named:
  - Ed25519 signature verification in `crypto.rs`
  - canonical JSON serialization in `canonical.rs`
  - Merkle proof generation and verification in `merkle.rs`
  - capability validation primitives in `capability.rs`

## Important Constraint

The roadmap asks for capability validation latency, but the repo does not have
one single "validate capability" function. The benchmark needs to compose the
real validation pieces that matter on the hot path: signature verification,
time-bounds checking, delegation-chain validation, and attenuation validation.

## Execution Direction

- add `criterion` as a dev-dependency in `arc-core`
- create a single benchmark target under `crates/arc-core/benches/` with four
  benchmark groups
- make the benchmark runnable in local development with Criterion's `--quick`
  mode so verification stays feasible

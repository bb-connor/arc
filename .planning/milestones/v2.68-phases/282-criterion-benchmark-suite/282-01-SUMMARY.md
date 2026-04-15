# Summary 282-01

Phase `282-01` added the first crate-owned Criterion benchmark lane for ARC's
release-critical primitives:

- [core_primitives.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core/benches/core_primitives.rs) now benchmarks signature verification, canonical JSON serialization, Merkle tree build/proof generation/proof verification, and capability validation on representative ARC-sized inputs
- `criterion` is now wired into the workspace and [crates/arc-core/Cargo.toml](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core/Cargo.toml) declares the `core_primitives` bench target so `cargo bench -p arc-core --bench core_primitives` is a stable repo entrypoint
- The initial baseline recorded by the milestone run was approximately `33.4-34.2 us` for signature verification, `4.86-5.00 us` for canonical JSON bytes, `790-813 us` for Merkle build over 1024 leaves, `~120 ns` for Merkle proof generation, `4.22-4.26 us` for Merkle proof verification, and `120-139 us` for capability validation

Verification:

- `cargo bench -p arc-core --bench core_primitives -- --sample-size 10 --measurement-time 0.1 --warm-up-time 0.1 --noplot`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/282-criterion-benchmark-suite/282-01-PLAN.md`

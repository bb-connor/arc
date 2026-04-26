//! Chio deterministic-replay gate: binary entry point.
//!
//! In later tickets this binary becomes the replay-gate runner. It will
//! enumerate the fixture corpus under `tests/replay/fixtures/`, drive each
//! scenario through the kernel surface, and compare the produced receipts,
//! anchor checkpoint, and Merkle root against the goldens under
//! `tests/replay/goldens/`.
//!
//! T1 lands a no-op `main` so that the crate has a buildable binary entry
//! point. The runner logic arrives in M04 P1 T2-T7 and the `--bless` flag
//! arrives in M04 P2 T1 (see `.planning/trajectory/04-deterministic-replay.md`).

fn main() {
    // Intentionally empty: skeleton for M04.P1.T1. Subsequent tickets wire
    // the corpus driver, golden writer / reader, and bless flag in here.
}

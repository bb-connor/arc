//! UniFFI scaffolding generator.
//!
//! Runs at build time to read `src/arc_kernel_mobile.udl` and emit the
//! `extern "C"` shim that `include_scaffolding!` slots into the crate.
//! The generated code is written into `$OUT_DIR`; Cargo's normal build
//! tree invalidation handles re-running this script whenever the UDL
//! changes.
//!
//! The single `unwrap()` below is the standard Cargo `build.rs`
//! convention: scaffolding failure is a compile-time error we want
//! the compiler to surface loudly rather than a runtime branch. The
//! workspace `clippy::unwrap_used = "deny"` lint exempts build scripts
//! per Cargo idiom.

#[allow(clippy::unwrap_used)]
fn main() {
    uniffi::generate_scaffolding("src/arc_kernel_mobile.udl").unwrap();
}

//! Fail-closed native-tool admission and deterministic cage-plan compilation.
//!
//! Admission starts from a non-forgeable authorization issued by the live
//! verified-manifest registry. That authorization binds the complete registry
//! snapshot, exact signed manifest, server and tools, and runtime topology. On
//! Linux, filesystem names are resolved once with `openat2` and become owned
//! descriptors. Compilation consumes those descriptors and produces a
//! deny-all plan. Linux launch applies Landlock and an independent seccomp-BPF
//! filter in a fresh single-threaded helper, then requires a parent-observed
//! target exec transition before reporting observed enforcement.

#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(all(feature = "enforcement-mutants", not(debug_assertions)))]
compile_error!("enforcement-mutants is a test-only feature and cannot be built for release");

mod enforcement;
mod execution_identity;
mod launch;
#[cfg(target_os = "linux")]
mod linux;
mod receipt;

pub use execution_identity::{
    validate_cage_execution_identity_binding, ExecutionIdentity, MAX_SUPPLEMENTARY_GIDS,
};

include!("lib_parts/part_01.rs");
include!("lib_parts/part_02.rs");

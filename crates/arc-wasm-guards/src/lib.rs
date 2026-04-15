//! WASM Guard Runtime for ARC.
//!
//! This crate allows operators to author guards in any language that compiles
//! to WebAssembly (Rust, AssemblyScript, Go, C) and load them into the ARC
//! kernel at runtime via `arc.yaml` configuration.
//!
//! # Architecture
//!
//! Each `.wasm` guard module exports a single function:
//!
//! ```text
//! evaluate(request_ptr: i32, request_len: i32) -> i32
//! ```
//!
//! The host serializes the guard request as JSON into guest memory, calls
//! `evaluate`, and interprets the return value:
//!
//! - `0` = Allow
//! - `1` = Deny (guard-specific reason returned through shared memory)
//! - any negative value = error (fail-closed)
//!
//! Fuel metering limits CPU consumption. When fuel runs out the guard is
//! treated as denied (fail-closed).
//!
//! # Feature flags
//!
//! - **`wasmtime-runtime`**: Enables the `wasmtime`-backed runtime. Without
//!   this feature only the trait-based abstractions are available, which is
//!   useful for testing or providing alternative backends.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod abi;
pub mod config;
pub mod error;
#[cfg(feature = "wasmtime-runtime")]
pub mod component;
#[cfg(feature = "wasmtime-runtime")]
pub mod host;
pub mod manifest;
pub mod runtime;
#[cfg(feature = "wasmtime-runtime")]
pub mod wiring;

pub use abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
pub use config::WasmGuardConfig;
pub use error::WasmGuardError;
#[cfg(feature = "wasmtime-runtime")]
pub use component::ComponentBackend;
#[cfg(feature = "wasmtime-runtime")]
pub use host::WasmHostState;
pub use manifest::{GuardManifest, MANIFEST_FILENAME, SUPPORTED_ABI_VERSIONS};
pub use runtime::{WasmGuard, WasmGuardRuntime};
#[cfg(feature = "wasmtime-runtime")]
pub use wiring::{build_guard_pipeline, load_wasm_guards};

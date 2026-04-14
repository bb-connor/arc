//! Guest-side SDK for writing ARC WASM guards.
//!
//! This crate is the primary dependency for guard authors. It provides:
//!
//! - **Types** ([`types`]): `GuardRequest`, `GuardVerdict`, `GuestDenyResponse`
//!   with serde annotations matching the host ABI exactly.
//! - **Host bindings** ([`host`]): safe wrappers for `arc.log`, `arc.get_config`,
//!   and `arc.get_time_unix_secs` host imports.
//! - **ABI glue** ([`glue`]): `read_request` to deserialize from linear memory,
//!   `encode_verdict` to produce the ABI return code, and the `arc_deny_reason`
//!   export for structured deny reasons.
//! - **Allocator** ([`alloc`]): `arc_alloc`/`arc_free` exports that the host
//!   runtime probes for dynamic memory allocation in guest linear memory.
//!
//! The crate compiles to `wasm32-unknown-unknown` for production guards. On
//! native targets it compiles with no-op fallbacks for host imports, allowing
//! `cargo test` to run without a WASM runtime.
//!
//! The `#[arc_guard]` proc macro (Phase 383) will generate the `evaluate`
//! export automatically. Until then, guard authors wire the pieces together
//! manually.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use arc_guard_sdk::prelude::*;
//!
//! fn evaluate(req: GuardRequest) -> GuardVerdict {
//!     if req.tool_name == "dangerous_tool" {
//!         GuardVerdict::deny("tool is blocked by policy")
//!     } else {
//!         GuardVerdict::allow()
//!     }
//! }
//! ```

pub mod alloc;
pub mod glue;
pub mod host;
pub mod types;

// Top-level re-exports for convenience.
pub use glue::{encode_verdict, read_request};
pub use host::{get_config, get_time, log, log_level};
pub use types::{GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW, VERDICT_DENY};

/// Prelude module re-exporting the complete guard-author API.
///
/// Import with `use arc_guard_sdk::prelude::*;` to get all types, host
/// bindings, and glue functions needed to write a guard.
pub mod prelude {
    pub use crate::glue::{encode_verdict, read_request};
    pub use crate::host::{get_config, get_time, log, log_level};
    pub use crate::types::{GuardRequest, GuardVerdict, VERDICT_ALLOW, VERDICT_DENY};
}

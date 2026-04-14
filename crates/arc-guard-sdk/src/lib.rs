//! Guest-side SDK for writing ARC WASM guards.
//!
//! Guard authors import this crate to get typed Rust structs that deserialize
//! identically to the host's JSON schema, and an allocator the host runtime
//! can call to place request data in guest linear memory.
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
pub mod host;
pub mod types;

// Top-level re-exports for convenience.
pub use types::{
    GuestDenyResponse, GuardRequest, GuardVerdict, VERDICT_ALLOW, VERDICT_DENY,
};

/// Prelude module re-exporting the core types a guard author needs.
pub mod prelude {
    pub use crate::types::{
        GuardRequest, GuardVerdict, VERDICT_ALLOW, VERDICT_DENY,
    };
}

//! Protocol-agnostic HTTP security types for the ARC kernel.
//!
//! This crate defines the shared types that every HTTP substrate adapter uses:
//! request model, caller identity, session context, HTTP receipts, and verdicts.
//! It is the foundation for `arc-openapi`, `arc-config`, `arc api protect`,
//! and all language-specific middleware crates.

mod identity;
mod method;
mod receipt;
mod request;
mod session;
mod verdict;

pub use identity::{AuthMethod, CallerIdentity};
pub use method::HttpMethod;
pub use receipt::{HttpReceipt, HttpReceiptBody};
pub use request::ArcHttpRequest;
pub use session::SessionContext;
pub use verdict::Verdict;

// Re-export types from arc-core-types that HTTP adapters commonly need.
pub use arc_core_types::canonical::{canonical_json_bytes, canonical_json_string};
pub use arc_core_types::crypto::{Keypair, PublicKey, Signature};
pub use arc_core_types::receipt::GuardEvidence;
pub use arc_core_types::{sha256_hex, Error, Result};

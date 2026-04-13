//! Shared ARC substrate types extracted from `arc-core`.
//!
//! This crate holds the protocol-wide types that should remain stable while
//! heavier domain crates split away from the compatibility facade.

pub mod canonical;
pub mod capability;
pub mod crypto;
pub mod error;
pub mod hashing;
pub mod manifest;
pub mod merkle;
pub mod message;
pub mod oracle;
pub mod receipt;
pub mod runtime_attestation;
pub mod session;

pub use canonical::{canonical_json_bytes, canonical_json_string, canonicalize};
pub use capability::*;
pub use crypto::{sha256_hex, Keypair, PublicKey, Signature};
pub use error::{Error, Result};
pub use hashing::*;
pub use manifest::*;
pub use merkle::*;
pub use message::*;
pub use oracle::*;
pub use receipt::*;
pub use runtime_attestation::*;
pub use session::*;

/// Opaque agent identifier. In practice this is a hex-encoded Ed25519 public key
/// or a SPIFFE URI, but the core treats it as an opaque string.
pub type AgentId = String;

/// Opaque tool server identifier.
pub type ServerId = String;

/// UUIDv7 capability identifier (time-ordered).
pub type CapabilityId = String;

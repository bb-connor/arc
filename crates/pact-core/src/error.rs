//! Error types for pact-core.

/// All errors produced by pact-core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("canonical JSON error: {0}")]
    CanonicalJson(String),

    #[error("capability expired at {expires_at}")]
    CapabilityExpired { expires_at: u64 },

    #[error("capability not yet valid (not_before: {not_before})")]
    CapabilityNotYetValid { not_before: u64 },

    #[error("capability revoked: {id}")]
    CapabilityRevoked { id: String },

    #[error("delegation chain broken: {reason}")]
    DelegationChainBroken { reason: String },

    #[error("attenuation violation: {reason}")]
    AttenuationViolation { reason: String },

    #[error("scope mismatch: {reason}")]
    ScopeMismatch { reason: String },

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("delegation depth {depth} exceeds maximum {max}")]
    DelegationDepthExceeded { depth: u32, max: u32 },

    #[error("invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    #[error("merkle proof verification failed")]
    MerkleProofFailed,

    #[error("empty tree: cannot compute root")]
    EmptyTree,

    #[error("invalid proof: leaf index {index} out of bounds for tree with {leaves} leaves")]
    InvalidProofIndex { index: usize, leaves: usize },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

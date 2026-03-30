use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidPublicKey,
    InvalidHex,
    InvalidSignature,
    Json,
    CanonicalJson,
    CapabilityExpired,
    CapabilityNotYetValid,
    CapabilityRevoked,
    DelegationChainBroken,
    AttenuationViolation,
    ScopeMismatch,
    SignatureVerificationFailed,
    DelegationDepthExceeded,
    InvalidHashLength,
    MerkleProofFailed,
    EmptyTree,
    InvalidProofIndex,
    EmptyManifest,
    DuplicateToolName,
    UnsupportedSchema,
    ManifestVerificationFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] arc_core::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Manifest(#[from] arc_manifest::ManifestError),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Core(error) => match error {
                arc_core::Error::InvalidPublicKey(_) => ErrorCode::InvalidPublicKey,
                arc_core::Error::InvalidHex(_) => ErrorCode::InvalidHex,
                arc_core::Error::InvalidSignature(_) => ErrorCode::InvalidSignature,
                arc_core::Error::Json(_) => ErrorCode::Json,
                arc_core::Error::CanonicalJson(_) => ErrorCode::CanonicalJson,
                arc_core::Error::CapabilityExpired { .. } => ErrorCode::CapabilityExpired,
                arc_core::Error::CapabilityNotYetValid { .. } => ErrorCode::CapabilityNotYetValid,
                arc_core::Error::CapabilityRevoked { .. } => ErrorCode::CapabilityRevoked,
                arc_core::Error::DelegationChainBroken { .. } => ErrorCode::DelegationChainBroken,
                arc_core::Error::AttenuationViolation { .. } => ErrorCode::AttenuationViolation,
                arc_core::Error::ScopeMismatch { .. } => ErrorCode::ScopeMismatch,
                arc_core::Error::SignatureVerificationFailed => {
                    ErrorCode::SignatureVerificationFailed
                }
                arc_core::Error::DelegationDepthExceeded { .. } => {
                    ErrorCode::DelegationDepthExceeded
                }
                arc_core::Error::InvalidHashLength { .. } => ErrorCode::InvalidHashLength,
                arc_core::Error::MerkleProofFailed => ErrorCode::MerkleProofFailed,
                arc_core::Error::EmptyTree => ErrorCode::EmptyTree,
                arc_core::Error::InvalidProofIndex { .. } => ErrorCode::InvalidProofIndex,
            },
            Self::Json(_) => ErrorCode::Json,
            Self::Manifest(error) => match error {
                arc_manifest::ManifestError::Signing(source) => match source {
                    arc_core::Error::InvalidPublicKey(_) => ErrorCode::InvalidPublicKey,
                    arc_core::Error::InvalidHex(_) => ErrorCode::InvalidHex,
                    arc_core::Error::InvalidSignature(_) => ErrorCode::InvalidSignature,
                    arc_core::Error::Json(_) => ErrorCode::Json,
                    arc_core::Error::CanonicalJson(_) => ErrorCode::CanonicalJson,
                    arc_core::Error::CapabilityExpired { .. } => ErrorCode::CapabilityExpired,
                    arc_core::Error::CapabilityNotYetValid { .. } => {
                        ErrorCode::CapabilityNotYetValid
                    }
                    arc_core::Error::CapabilityRevoked { .. } => ErrorCode::CapabilityRevoked,
                    arc_core::Error::DelegationChainBroken { .. } => {
                        ErrorCode::DelegationChainBroken
                    }
                    arc_core::Error::AttenuationViolation { .. } => ErrorCode::AttenuationViolation,
                    arc_core::Error::ScopeMismatch { .. } => ErrorCode::ScopeMismatch,
                    arc_core::Error::SignatureVerificationFailed => {
                        ErrorCode::SignatureVerificationFailed
                    }
                    arc_core::Error::DelegationDepthExceeded { .. } => {
                        ErrorCode::DelegationDepthExceeded
                    }
                    arc_core::Error::InvalidHashLength { .. } => ErrorCode::InvalidHashLength,
                    arc_core::Error::MerkleProofFailed => ErrorCode::MerkleProofFailed,
                    arc_core::Error::EmptyTree => ErrorCode::EmptyTree,
                    arc_core::Error::InvalidProofIndex { .. } => ErrorCode::InvalidProofIndex,
                },
                arc_manifest::ManifestError::EmptyManifest => ErrorCode::EmptyManifest,
                arc_manifest::ManifestError::DuplicateToolName(_) => ErrorCode::DuplicateToolName,
                arc_manifest::ManifestError::UnsupportedSchema(_) => ErrorCode::UnsupportedSchema,
                arc_manifest::ManifestError::VerificationFailed => {
                    ErrorCode::ManifestVerificationFailed
                }
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Error, ErrorCode};

    #[test]
    fn codes_map_core_errors() {
        let error = Error::from(arc_core::Error::CapabilityExpired { expires_at: 42 });
        assert_eq!(error.code(), ErrorCode::CapabilityExpired);
    }

    #[test]
    fn codes_map_manifest_errors() {
        let error = Error::from(arc_manifest::ManifestError::DuplicateToolName(
            "echo".to_string(),
        ));
        assert_eq!(error.code(), ErrorCode::DuplicateToolName);
    }
}

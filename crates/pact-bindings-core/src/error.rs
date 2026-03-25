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
    Core(#[from] pact_core::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Manifest(#[from] pact_manifest::ManifestError),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Core(error) => match error {
                pact_core::Error::InvalidPublicKey(_) => ErrorCode::InvalidPublicKey,
                pact_core::Error::InvalidHex(_) => ErrorCode::InvalidHex,
                pact_core::Error::InvalidSignature(_) => ErrorCode::InvalidSignature,
                pact_core::Error::Json(_) => ErrorCode::Json,
                pact_core::Error::CanonicalJson(_) => ErrorCode::CanonicalJson,
                pact_core::Error::CapabilityExpired { .. } => ErrorCode::CapabilityExpired,
                pact_core::Error::CapabilityNotYetValid { .. } => ErrorCode::CapabilityNotYetValid,
                pact_core::Error::CapabilityRevoked { .. } => ErrorCode::CapabilityRevoked,
                pact_core::Error::DelegationChainBroken { .. } => ErrorCode::DelegationChainBroken,
                pact_core::Error::AttenuationViolation { .. } => ErrorCode::AttenuationViolation,
                pact_core::Error::ScopeMismatch { .. } => ErrorCode::ScopeMismatch,
                pact_core::Error::SignatureVerificationFailed => {
                    ErrorCode::SignatureVerificationFailed
                }
                pact_core::Error::DelegationDepthExceeded { .. } => {
                    ErrorCode::DelegationDepthExceeded
                }
                pact_core::Error::InvalidHashLength { .. } => ErrorCode::InvalidHashLength,
                pact_core::Error::MerkleProofFailed => ErrorCode::MerkleProofFailed,
                pact_core::Error::EmptyTree => ErrorCode::EmptyTree,
                pact_core::Error::InvalidProofIndex { .. } => ErrorCode::InvalidProofIndex,
            },
            Self::Json(_) => ErrorCode::Json,
            Self::Manifest(error) => match error {
                pact_manifest::ManifestError::Signing(source) => match source {
                    pact_core::Error::InvalidPublicKey(_) => ErrorCode::InvalidPublicKey,
                    pact_core::Error::InvalidHex(_) => ErrorCode::InvalidHex,
                    pact_core::Error::InvalidSignature(_) => ErrorCode::InvalidSignature,
                    pact_core::Error::Json(_) => ErrorCode::Json,
                    pact_core::Error::CanonicalJson(_) => ErrorCode::CanonicalJson,
                    pact_core::Error::CapabilityExpired { .. } => ErrorCode::CapabilityExpired,
                    pact_core::Error::CapabilityNotYetValid { .. } => {
                        ErrorCode::CapabilityNotYetValid
                    }
                    pact_core::Error::CapabilityRevoked { .. } => ErrorCode::CapabilityRevoked,
                    pact_core::Error::DelegationChainBroken { .. } => {
                        ErrorCode::DelegationChainBroken
                    }
                    pact_core::Error::AttenuationViolation { .. } => {
                        ErrorCode::AttenuationViolation
                    }
                    pact_core::Error::ScopeMismatch { .. } => ErrorCode::ScopeMismatch,
                    pact_core::Error::SignatureVerificationFailed => {
                        ErrorCode::SignatureVerificationFailed
                    }
                    pact_core::Error::DelegationDepthExceeded { .. } => {
                        ErrorCode::DelegationDepthExceeded
                    }
                    pact_core::Error::InvalidHashLength { .. } => ErrorCode::InvalidHashLength,
                    pact_core::Error::MerkleProofFailed => ErrorCode::MerkleProofFailed,
                    pact_core::Error::EmptyTree => ErrorCode::EmptyTree,
                    pact_core::Error::InvalidProofIndex { .. } => ErrorCode::InvalidProofIndex,
                },
                pact_manifest::ManifestError::EmptyManifest => ErrorCode::EmptyManifest,
                pact_manifest::ManifestError::DuplicateToolName(_) => ErrorCode::DuplicateToolName,
                pact_manifest::ManifestError::UnsupportedSchema(_) => ErrorCode::UnsupportedSchema,
                pact_manifest::ManifestError::VerificationFailed => {
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
        let error = Error::from(pact_core::Error::CapabilityExpired { expires_at: 42 });
        assert_eq!(error.code(), ErrorCode::CapabilityExpired);
    }

    #[test]
    fn codes_map_manifest_errors() {
        let error = Error::from(pact_manifest::ManifestError::DuplicateToolName(
            "echo".to_string(),
        ));
        assert_eq!(error.code(), ErrorCode::DuplicateToolName);
    }
}

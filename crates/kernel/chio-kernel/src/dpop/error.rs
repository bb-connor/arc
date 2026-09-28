//! Input-independent DPoP refusal rules for signed evidence.
#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    #[error("DPoP reservation ownership unconfirmed at commit; marker retained")]
    ReservationOwnership,
    #[error("unsupported DPoP schema or replay domain")]
    Schema,
    #[error("DPoP sender constraint mismatch")]
    Sender,
    #[error("DPoP capability binding mismatch")]
    Capability,
    #[error("DPoP server binding mismatch")]
    Server,
    #[error("DPoP tool binding mismatch")]
    Tool,
    #[error("DPoP action binding mismatch")]
    Action,
    #[error("DPoP proof validity window overflows Unix seconds")]
    WindowOverflow,
    #[error("DPoP proof issued too far in the future")]
    NotYetValid,
    #[error("DPoP proof expired")]
    Expired,
    #[error("DPoP signature verification failed")]
    Signature,
    #[error("DPoP nonce replayed")]
    Replayed,
    #[error("DPoP nonce store capacity exhausted")]
    Capacity,
    #[error("DPoP nonce store per-capability quota exhausted")]
    CapabilityCapacity,
    #[error("DPoP replay identity exceeds the 4096-byte limit")]
    IdentityLimit,
    #[error("DPoP replay identity byte count overflow")]
    IdentityOverflow,
    #[error("DPoP nonce store identity byte capacity exhausted")]
    IdentityCapacity,
    #[error("DPoP nonce store accounting invariant failed")]
    Accounting,
    #[error("DPoP nonce store unavailable")]
    Unavailable,
    #[error("required DPoP proof missing")]
    MissingProof,
    #[error("DPoP nonce store not configured")]
    MissingStore,
    #[error("DPoP verification policy not configured")]
    MissingConfiguration,
    #[error("DPoP canonical encoding failed: {0}")]
    Encoding(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("DPoP signing failed: {0}")]
    Signing(#[source] Box<dyn std::error::Error + Send + Sync>),
}
impl DpopError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ReservationOwnership => "urn:chio:error:kernel:dpop-reservation-ownership",
            Self::Schema => "urn:chio:error:kernel:dpop-schema",
            Self::Sender => "urn:chio:error:kernel:dpop-sender",
            Self::Capability => "urn:chio:error:kernel:dpop-capability",
            Self::Server => "urn:chio:error:kernel:dpop-server",
            Self::Tool => "urn:chio:error:kernel:dpop-tool",
            Self::Action => "urn:chio:error:kernel:dpop-action",
            Self::WindowOverflow => "urn:chio:error:kernel:dpop-window-overflow",
            Self::NotYetValid => "urn:chio:error:kernel:dpop-not-yet-valid",
            Self::Expired => "urn:chio:error:kernel:dpop-expired",
            Self::Signature => "urn:chio:error:kernel:dpop-signature",
            Self::Replayed => "urn:chio:error:kernel:dpop-replayed",
            Self::Capacity => "urn:chio:error:kernel:dpop-capacity",
            Self::CapabilityCapacity => "urn:chio:error:kernel:dpop-capability-capacity",
            Self::IdentityLimit => "urn:chio:error:kernel:dpop-identity-limit",
            Self::IdentityOverflow => "urn:chio:error:kernel:dpop-identity-overflow",
            Self::IdentityCapacity => "urn:chio:error:kernel:dpop-identity-capacity",
            Self::Accounting => "urn:chio:error:kernel:dpop-accounting",
            Self::Unavailable => "urn:chio:error:kernel:dpop-unavailable",
            Self::MissingProof => "urn:chio:error:kernel:dpop-missing-proof",
            Self::MissingStore => "urn:chio:error:kernel:dpop-missing-store",
            Self::MissingConfiguration => "urn:chio:error:kernel:dpop-missing-configuration",
            Self::Encoding(..) => "urn:chio:error:kernel:dpop-encoding",
            Self::Signing(..) => "urn:chio:error:kernel:dpop-signing",
        }
    }
}

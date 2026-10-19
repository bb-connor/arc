#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Web3ContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate id or value: {0}")]
    DuplicateValue(String),

    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("invalid binding: {0}")]
    InvalidBinding(String),

    #[error("invalid binding: {0}")]
    BindingSignatureInvalid(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid settlement: {0}")]
    InvalidSettlement(String),

    #[error("invalid proof: {0}")]
    ProofDigestMismatch(String),

    #[error("invalid settlement: {0}")]
    SettlementDigestMismatch(String),

    #[error("invalid proof: {0}")]
    ProofSignatureInvalid(String),

    #[error("invalid settlement: {0}")]
    SettlementSignatureInvalid(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}

impl Web3ContractError {
    pub(crate) fn invalid_settlement(message: impl Into<String>) -> Self {
        Self::InvalidSettlement(message.into())
    }

    pub(crate) fn settlement_signature_invalid(message: impl Into<String>) -> Self {
        Self::SettlementSignatureInvalid(message.into())
    }
}

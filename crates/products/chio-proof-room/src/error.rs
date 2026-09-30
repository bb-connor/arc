//! Typed local verification failures. HTTP surfaces project stable public codes.

#[derive(Debug, thiserror::Error)]
pub enum ProofRoomError {
    #[error("proof-room.input.task-failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("{0}")]
    Input(#[from] chio_core_types::canonical::UntrustedJsonError),
    #[error("{0}")]
    Validation(String),
    #[error("{context}: {source}")]
    Verification {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("proof-room.listen.invalid: {0}")]
    ListenAddress(std::net::AddrParseError),
    #[error("proof-room.serve: {0}")]
    Serve(std::io::Error),
}

impl From<String> for ProofRoomError {
    fn from(message: String) -> Self {
        Self::Validation(message)
    }
}
impl From<&str> for ProofRoomError {
    fn from(message: &str) -> Self {
        Self::Validation(message.to_owned())
    }
}

impl ProofRoomError {
    pub(crate) fn verification(
        context: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Verification {
            context,
            source: Box::new(source),
        }
    }

    /// Owner-defined public reasons; no input-derived detail is exposed.
    pub fn public_reason(&self) -> Option<&'static str> {
        if let Self::Validation(message) = self {
            return (message == "proof-room.commerce-invalid: CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS must pin trusted commerce event authority receipt kernel keys")
                .then_some("CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS must pin trusted commerce event authority receipt kernel keys");
        }
        let Self::Verification { source, .. } = self else {
            return None;
        };
        if let Some(error) =
            source.downcast_ref::<chio_runtime_proof_parity::RuntimeProofParityError>()
        {
            return (error.code() == "runtime_proof_regeneration_report_hash_mismatch")
                .then_some("runtime proof regeneration report hash mismatch");
        }
        if let Some(error) = source.downcast_ref::<chio_commerce_order::CommerceOrderError>() {
            use chio_commerce_order::CommerceOrderError;
            return match error {
                CommerceOrderError::ReplayFailed(reason)
                    if reason.starts_with("authority receipt kernel key untrusted: ") =>
                {
                    Some("authority receipt kernel key untrusted")
                }
                CommerceOrderError::PaymentFailed(reason)
                    if reason == "payment signer untrusted" =>
                {
                    Some("payment signer untrusted")
                }
                CommerceOrderError::PaymentFailed(reason)
                    if reason == "payment transfer group mismatch" =>
                {
                    Some("payment transfer group mismatch")
                }
                _ => None,
            };
        }
        if let Some(
            chio_transaction_passport::TransactionPassportError::RiskComptrollerClaimFailed(reason),
        ) = source.downcast_ref::<chio_transaction_passport::TransactionPassportError>()
        {
            return match reason.as_str() {
                "risk facility lifecycle authority missing" => {
                    Some("risk facility lifecycle authority missing")
                }
                "risk facility lifecycle evidence missing" => {
                    Some("risk facility lifecycle evidence missing")
                }
                "risk reserve ledger receipt missing" => {
                    Some("risk reserve ledger receipt missing")
                }
                "risk claim outside coverage" => Some("risk claim outside coverage"),
                _ => None,
            };
        }
        None
    }
}

pub(crate) fn source_runtime_regeneration_error(
    error: chio_runtime_proof_parity::RuntimeProofParityError,
) -> ProofRoomError {
    let context = if error.code() == "runtime_proof_regeneration_workflow_step_evidence_mismatch" {
        "proof-room.runtime-regeneration.source-record-workflow-step-mismatch"
    } else {
        "proof-room.runtime-regeneration.invalid"
    };
    ProofRoomError::verification(context, error)
}

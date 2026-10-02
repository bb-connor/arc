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
            return validation_public_reason(message);
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
        if let Some(error) = source.downcast_ref::<chio_web3::error::Web3ContractError>() {
            use chio_web3::error::Web3ContractError;
            return match error {
                Web3ContractError::InvalidProof(reason)
                    if reason == "public settlement independent head missing" =>
                {
                    Some("public settlement independent head missing")
                }
                Web3ContractError::InvalidSettlement(reason)
                    if reason == "public settlement independent head block hash mismatch" =>
                {
                    Some("public settlement independent head block hash mismatch")
                }
                _ => None,
            };
        }
        if let Some(error) =
            source.downcast_ref::<chio_transaction_passport::TransactionPassportError>()
        {
            use chio_transaction_passport::TransactionPassportError;
            return match error {
                TransactionPassportError::Input(_) => Some("proof-room.schema-violation: artifact"),
                TransactionPassportError::AgentWebClaimFailed(reason)
                    if reason == "missing Standard Webhooks verifier secret" =>
                {
                    Some("missing Standard Webhooks verifier secret")
                }
                TransactionPassportError::RiskComptrollerClaimFailed(reason) => {
                    match reason.as_str() {
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
                    }
                }
                _ => None,
            };
        }
        None
    }
}

fn validation_public_reason(message: &str) -> Option<&'static str> {
    // The settlement RPC adapter still carries a string cause. Recognize only
    // its complete owner-defined context and reason; never return the host.
    if message.starts_with("proof-room.public-settlement-invalid: CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL eth_blockNumber rejected by HttpEgressContract: loopback egress target denied: ") {
        return Some("loopback egress target denied");
    }
    match message {
        "proof-room.commerce-invalid: CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS must pin trusted commerce event authority receipt kernel keys" => Some("CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS must pin trusted commerce event authority receipt kernel keys"),
        "proof-room.commerce-invalid: CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS must pin trusted commerce provider keys" => Some("CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS must pin trusted commerce provider keys"),
        "proof-room.disclosure-lineage-invalid: CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS must pin trusted disclosure lineage signer keys" => Some("CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS must pin trusted disclosure lineage signer keys"),
        "proof-room.public-settlement-invalid: CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS must pin trusted public settlement chain IDs" => Some("CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS must pin trusted public settlement chain IDs"),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_reasons_require_the_expected_owner_and_complete_literal() {
        for (message, reason) in [
            ("proof-room.commerce-invalid: CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS must pin trusted commerce provider keys", "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS must pin trusted commerce provider keys"),
            ("proof-room.disclosure-lineage-invalid: CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS must pin trusted disclosure lineage signer keys", "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS must pin trusted disclosure lineage signer keys"),
        ] {
            assert_eq!(
                ProofRoomError::Validation(message.into()).public_reason(),
                Some(reason)
            );
            for unknown in [
                format!("{message}: private-marker"),
                format!("private-marker: {message}"),
            ] {
                assert_eq!(ProofRoomError::Validation(unknown).public_reason(), None);
            }
        }
        let reason = "public settlement independent head block hash mismatch";
        let valid = ProofRoomError::verification(
            "proof-room.source-verifier.failed",
            chio_web3::error::Web3ContractError::InvalidSettlement(reason.into()),
        );
        assert_eq!(valid.public_reason(), Some(reason));
        let wrong_variant = ProofRoomError::verification(
            "proof-room.source-verifier.failed",
            chio_web3::error::Web3ContractError::InvalidProof(reason.into()),
        );
        assert_eq!(wrong_variant.public_reason(), None);
        let injected_detail = ProofRoomError::verification(
            "proof-room.source-verifier.failed",
            chio_web3::error::Web3ContractError::InvalidSettlement(format!(
                "{reason}: private-marker"
            )),
        );
        assert_eq!(injected_detail.public_reason(), None);
    }
}

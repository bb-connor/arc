//! Independent feature-resolution fixture for portable recovery consumers.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use chio_recovery::{advise_workflow, WorkflowDirective};
use chio_security_types::recovery::{ContractError, RecoveryObservationV1};

pub fn decode_advice(bytes: &[u8]) -> Result<WorkflowDirective, ContractError> {
    let observation: RecoveryObservationV1 = chio_core_types::recovery::decode_contract(bytes)?;
    Ok(advise_workflow(&observation))
}

pub fn verify_budget_is_portable() -> Result<(), ContractError> {
    chio_semantic_contracts::VerificationBudget::new(1)?.charge(1)
}

/// confinement signatures and descriptions remain usable without host effect crates.
pub fn verify_confined_disclosure(bytes: &[u8]) -> Result<bool, ContractError> {
    let proof: chio_core_types::recovery::SignedConfinedDisclosureV1 =
        chio_core_types::recovery::decode_contract(bytes)?;
    proof
        .verify_signature()
        .map_err(|_| ContractError::BindingMismatch)
}

/// Portable durable knowledge certificate verification receives time and selected roots as data.
pub fn verify_knowledge_certificate(
    bytes: &[u8],
    root: &chio_core_types::PublicKey,
    metadata: &chio_security_types::knowledge::ArtifactVersionV1,
    now_unix_ms: u64,
) -> Result<(), ContractError> {
    let certificate: chio_core_types::recovery::SignedArtifactCertificateV1 =
        chio_core_types::recovery::decode_contract(bytes)?;
    chio_core_types::recovery::verify_artifact_certificate(
        &certificate,
        root,
        metadata,
        now_unix_ms,
    )
    .map_err(|_| ContractError::BindingMismatch)
}
